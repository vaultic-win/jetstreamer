//! Diagnostic-only, bounded collection of an entire flat RocksDB archive.
//!
//! Unlike an SST prefix scan, this preserves every archived regular member,
//! including CURRENT, MANIFEST and WAL files. It does not authenticate a cloud
//! generation, prove the original backup was complete, resolve LSM state, decode
//! shreds, or authorize runtime promotion or publication. No production caller
//! exists. A caller must independently bind the complete compressed input and
//! apply fresh admission before spending its collection budget.

use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeSet,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Component, Path},
    },
};

/// Independent bounds for one collection; these are not resource admission.
#[derive(Clone, Copy, Debug)]
pub struct CollectionLimits {
    /// Maximum number of archived regular files.
    pub maximum_files: usize,
    /// Maximum length of any one archived file.
    pub maximum_file_bytes: u64,
    /// Maximum aggregate length of all collected files.
    pub maximum_total_bytes: u64,
    /// Maximum zero trailer after the tar end marker.
    pub maximum_trailer_bytes: u64,
}

/// One preserved member, mechanically bound to its complete content.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedFile {
    /// Exact flat basename within the independently specified archive root.
    pub name: String,
    /// Complete regular-file length.
    pub bytes: u64,
    /// Lowercase SHA-256 of the collected content.
    pub sha256: String,
}

/// Complete tar-member census, never a live-state or source-completeness proof.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticCollection {
    /// True only when every member was retained and fsynced, not merely counted.
    pub files_retained: bool,
    /// The exact, independently supplied root prefix in the input tar.
    pub archive_root: String,
    /// Sorted census of every regular member, including ancillary files.
    pub files: Vec<CollectedFile>,
    /// Sum of every regular-file length.
    pub total_bytes: u64,
    /// Exact nonempty manifest referenced by CURRENT.
    pub current_manifest: String,
    /// Every archived WAL basename, sorted. Empty is not proof no WAL was owed.
    pub wal_files: Vec<String>,
    /// Always false: original backup completeness needs independent evidence.
    pub source_completeness_proven: bool,
    /// Always false: a native complete-CF read-only resolution remains required.
    pub live_state_resolved: bool,
    /// Always false: archived bytes are private diagnostic inputs only.
    pub publication_authorized: bool,
}

fn plain_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn numbered(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|n| n.strip_suffix(suffix))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

fn manifest_name(current: &[u8]) -> Result<String> {
    ensure!(current.len() <= 4096, "CURRENT exceeds metadata bound");
    let text = std::str::from_utf8(current).context("CURRENT is not UTF-8")?;
    let name = text
        .strip_suffix('\n')
        .context("CURRENT lacks final newline")?;
    ensure!(
        numbered(name, "MANIFEST-", ""),
        "invalid CURRENT manifest basename"
    );
    Ok(name.to_owned())
}

struct PositionReader<R> {
    inner: R,
    bytes: u64,
}

impl<R: Read> Read for PositionReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| std::io::Error::other("tar stream position overflow"))?;
        Ok(count)
    }
}

/// Collect every regular member of an explicitly rooted, flat RocksDB tar.
///
/// The canonical absolute destination must be an empty owner-only directory,
/// owned by the effective user. Reject links, devices, sparse entries, duplicate
/// names, nested/foreign members and invalid CURRENT bindings. File names are
/// otherwise deliberately not filtered: unknown CF or ancillary files must not
/// silently disappear from the generation census. Preserve partial output on
/// failure for diagnosis; never reuse that tree as a completed collection.
///
/// Files are created no-clobber, hashed while copying, made read-only and fsynced;
/// the destination directory is fsynced before success. A tar success does not
/// supply missing WALs, prove CF completeness or grant publication authority.
pub fn collect_rocksdb_tar<R: Read>(
    reader: R,
    archive_root: &Path,
    destination: &Path,
    limits: CollectionLimits,
) -> Result<DiagnosticCollection> {
    inspect_rocksdb_tar(reader, archive_root, Some(destination), limits)
}

/// Hash and census every member without creating or retaining any output files.
///
/// This consumes the complete tar, including its bounded zero trailer. It uses
/// the same parser, CURRENT binding and content bounds as collection, but cannot
/// supply native database inputs or establish backup completeness/live state.
pub fn census_rocksdb_tar<R: Read>(
    reader: R,
    archive_root: &Path,
    limits: CollectionLimits,
) -> Result<DiagnosticCollection> {
    inspect_rocksdb_tar(reader, archive_root, None, limits)
}

fn inspect_rocksdb_tar<R: Read>(
    reader: R,
    archive_root: &Path,
    destination: Option<&Path>,
    limits: CollectionLimits,
) -> Result<DiagnosticCollection> {
    ensure!(
        plain_relative(archive_root),
        "archive root must be plain relative components"
    );
    ensure!(
        limits.maximum_files > 0
            && limits.maximum_file_bytes > 0
            && limits.maximum_total_bytes > 0
            && (512..=16 * 1024 * 1024).contains(&limits.maximum_trailer_bytes),
        "invalid collection limits"
    );
    let retained = if let Some(destination) = destination {
        ensure!(
            destination.is_absolute() && destination.canonicalize()? == destination,
            "destination must be canonical and absolute"
        );
        let before = fs::symlink_metadata(destination)?;
        ensure!(
            before.is_dir()
                && before.uid() == unsafe { libc::geteuid() }
                && before.mode() & 0o077 == 0,
            "destination must be owned and private"
        );
        ensure!(
            fs::read_dir(destination)?.next().is_none(),
            "destination is not empty"
        );
        Some((before, File::open(destination)?))
    } else {
        None
    };
    let mut archive = tar::Archive::new(PositionReader {
        inner: reader,
        bytes: 0,
    });
    let mut names = BTreeSet::new();
    let mut files = Vec::new();
    let mut total = 0_u64;
    let mut current = None;
    let mut seen_directory = false;
    let mut padded_end = 0_u64;
    // Raw iteration rejects GNU/PAX metadata before it can allocate an
    // attacker-declared long-name/extension body. Flat RocksDB basenames need
    // no such extension. Supporting one later requires an independent bound.
    for item in archive.entries()?.raw(true) {
        let mut entry = item.context("invalid or truncated tar entry")?;
        padded_end = entry
            .raw_file_position()
            .checked_add(entry.size().checked_add(511).context("tar size overflow")? & !511)
            .context("tar member position overflow")?;
        let path = entry.path()?.into_owned();
        ensure!(plain_relative(&path), "unsafe tar member path");
        if entry.header().entry_type() == tar::EntryType::Directory {
            ensure!(
                path == archive_root && !seen_directory,
                "foreign, nested or duplicate tar directory"
            );
            ensure!(entry.size() == 0, "nonempty directory entry");
            seen_directory = true;
            continue;
        }
        ensure!(
            entry.header().entry_type() == tar::EntryType::Regular,
            "non-regular tar member"
        );
        let relative = path
            .strip_prefix(archive_root)
            .context("foreign archive member")?;
        ensure!(
            relative.components().count() == 1 && plain_relative(relative),
            "nested or empty RocksDB member"
        );
        let name = relative
            .to_str()
            .context("non-UTF-8 member name")?
            .to_owned();
        ensure!(
            name.len() <= 255 && names.insert(name.clone()),
            "duplicate or oversized member name"
        );
        ensure!(
            files.len() < limits.maximum_files,
            "file-count bound exceeded"
        );
        let bytes = entry.size();
        ensure!(
            bytes <= limits.maximum_file_bytes,
            "individual file bound exceeded"
        );
        total = total
            .checked_add(bytes)
            .context("aggregate size overflow")?;
        ensure!(
            total <= limits.maximum_total_bytes,
            "aggregate file bound exceeded"
        );
        if name == "CURRENT" {
            ensure!(bytes <= 4096, "CURRENT exceeds metadata bound");
        }
        let mut output = destination
            .map(|destination| {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(destination.join(&name))
            })
            .transpose()?;
        let mut digest = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 65536];
        let mut current_bytes = Vec::new();
        loop {
            let count = entry.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied = copied
                .checked_add(count as u64)
                .context("copy count overflow")?;
            ensure!(copied <= bytes, "member exceeds declared length");
            if let Some(output) = &mut output {
                output.write_all(&buffer[..count])?;
            }
            digest.update(&buffer[..count]);
            if name == "CURRENT" {
                current_bytes.extend_from_slice(&buffer[..count]);
            }
        }
        ensure!(copied == bytes, "truncated tar member");
        if name == "CURRENT" {
            current = Some(manifest_name(&current_bytes)?);
        }
        if let Some(output) = output {
            output.set_permissions(fs::Permissions::from_mode(0o444))?;
            output.sync_all()?;
        }
        files.push(CollectedFile {
            name,
            bytes,
            sha256: format!("{:x}", digest.finalize()),
        });
    }
    // tar stops at its end marker. Do not silently ignore a second archive or
    // arbitrary trailing data, even when the first archive looked complete.
    let reader = archive.into_inner();
    ensure!(
        reader.bytes
            >= padded_end
                .checked_add(512)
                .context("tar end offset overflow")?,
        "tar lacks its first zero end marker"
    );
    let mut remainder = reader.take(limits.maximum_trailer_bytes + 1);
    let mut trailer = Vec::new();
    remainder.read_to_end(&mut trailer)?;
    ensure!(
        trailer.len() as u64 <= limits.maximum_trailer_bytes,
        "tar trailer bound exceeded"
    );
    ensure!(trailer.len() >= 512, "tar lacks its second zero end marker");
    ensure!(
        trailer.iter().all(|b| *b == 0),
        "nonzero data after tar end marker"
    );
    let current_manifest = current.context("CURRENT is missing")?;
    ensure!(
        files
            .iter()
            .any(|f| f.name == current_manifest && f.bytes > 0),
        "CURRENT references an absent or empty manifest"
    );
    ensure!(
        files
            .iter()
            .any(|f| numbered(&f.name, "", ".sst") && f.bytes > 0),
        "archive has no nonempty numbered SST"
    );
    if let (Some(destination), Some((before, directory))) = (destination, retained) {
        let after = fs::symlink_metadata(destination)?;
        ensure!(
            (before.dev(), before.ino(), before.uid(), before.mode())
                == (after.dev(), after.ino(), after.uid(), after.mode()),
            "destination changed"
        );
        directory.sync_all()?;
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    let wal_files = files
        .iter()
        .filter(|f| numbered(&f.name, "", ".log"))
        .map(|f| f.name.clone())
        .collect();
    Ok(DiagnosticCollection {
        files_retained: destination.is_some(),
        archive_root: archive_root
            .to_str()
            .context("non-UTF-8 archive root")?
            .to_owned(),
        files,
        total_bytes: total,
        current_manifest,
        wal_files,
        source_completeness_proven: false,
        live_state_resolved: false,
        publication_authorized: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn limits() -> CollectionLimits {
        CollectionLimits {
            maximum_files: 16,
            maximum_file_bytes: 8192,
            maximum_total_bytes: 32768,
            maximum_trailer_bytes: 4096,
        }
    }

    fn fixture(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, kind, bytes) in entries {
            assert!(name.len() < 100);
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o777); // Source permissions are never installed.
            header.set_size(bytes.len() as u64);
            header.set_entry_type(*kind);
            header.as_mut_bytes()[..100].fill(0);
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            builder.append(&header, *bytes).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn ordinary() -> Vec<(&'static str, tar::EntryType, &'static [u8])> {
        vec![
            ("rocksdb", tar::EntryType::Directory, b""),
            ("rocksdb/CURRENT", tar::EntryType::Regular, b"MANIFEST-1\n"),
            (
                "rocksdb/MANIFEST-1",
                tar::EntryType::Regular,
                b"manifest-fixture",
            ),
            (
                "rocksdb/000001.sst",
                tar::EntryType::Regular,
                b"sst-fixture",
            ),
            (
                "rocksdb/000002.log",
                tar::EntryType::Regular,
                b"wal-fixture",
            ),
            ("rocksdb/OPTIONS-3", tar::EntryType::Regular, b"cf-options"),
            (
                "rocksdb/unknown-ancillary",
                tar::EntryType::Regular,
                b"preserve-me",
            ),
        ]
    }

    fn output() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn collect(
        bytes: &[u8],
        destination: &Path,
        bounds: CollectionLimits,
    ) -> Result<DiagnosticCollection> {
        collect_rocksdb_tar(
            Cursor::new(bytes),
            Path::new("rocksdb"),
            destination,
            bounds,
        )
    }

    #[test]
    fn preserves_entire_flat_census_without_claiming_live_state() {
        let dir = output();
        let census = collect(&fixture(&ordinary()), dir.path(), limits()).unwrap();
        assert!(census.files_retained);
        assert_eq!(census.files.len(), 6);
        assert_eq!(census.current_manifest, "MANIFEST-1");
        assert_eq!(census.wal_files, ["000002.log"]);
        assert!(!census.source_completeness_proven);
        assert!(!census.live_state_resolved);
        assert!(!census.publication_authorized);
        assert_eq!(
            census.total_bytes,
            census.files.iter().map(|f| f.bytes).sum::<u64>()
        );
        for file in &census.files {
            let path = dir.path().join(&file.name);
            let bytes = fs::read(&path).unwrap();
            assert_eq!(bytes.len() as u64, file.bytes);
            assert_eq!(format!("{:x}", Sha256::digest(bytes)), file.sha256);
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o444);
        }
        assert_eq!(
            fs::read(dir.path().join("unknown-ancillary")).unwrap(),
            b"preserve-me"
        );
    }

    #[test]
    fn census_reads_every_byte_without_retaining_files() {
        let bytes = fixture(&ordinary());
        let dir = output();
        let mut retained =
            serde_json::to_value(collect(&bytes, dir.path(), limits()).unwrap()).unwrap();
        let census =
            census_rocksdb_tar(Cursor::new(&bytes), Path::new("rocksdb"), limits()).unwrap();
        assert!(!census.files_retained);
        retained["files_retained"] = false.into();
        assert_eq!(serde_json::to_value(census).unwrap(), retained);
        let mut changed = bytes;
        // Alter the last ancillary member without changing its length/header.
        let offset = changed
            .windows(11)
            .position(|w| w == b"preserve-me")
            .unwrap();
        changed[offset] ^= 1;
        let changed =
            census_rocksdb_tar(Cursor::new(changed), Path::new("rocksdb"), limits()).unwrap();
        let original = collect(&fixture(&ordinary()), output().path(), limits()).unwrap();
        assert_ne!(
            changed.files.last().unwrap().sha256,
            original.files.last().unwrap().sha256
        );
    }

    #[test]
    fn census_keeps_all_structural_and_expansion_gates() {
        let bytes = fixture(&ordinary());
        for end in [1, 511, 512, 600, bytes.len() - 1024, bytes.len() - 512] {
            assert!(
                census_rocksdb_tar(Cursor::new(&bytes[..end]), Path::new("rocksdb"), limits())
                    .is_err()
            );
        }
        let mut duplicate = ordinary();
        duplicate.push(("rocksdb/CURRENT", tar::EntryType::Regular, b"MANIFEST-1\n"));
        let mut nested = ordinary();
        nested.push(("rocksdb/sub/file", tar::EntryType::Regular, b"x"));
        let mut nonzero = bytes.clone();
        nonzero.push(1);
        let mut excess = bytes.clone();
        excess.extend([0; 4096]);
        for bad in [
            fixture(&duplicate),
            fixture(&nested),
            nonzero,
            excess,
            fixture(&[("rocksdb/link", tar::EntryType::Symlink, b"")]),
        ] {
            assert!(census_rocksdb_tar(Cursor::new(bad), Path::new("rocksdb"), limits()).is_err());
        }
        assert!(
            census_rocksdb_tar(
                Cursor::new(fixture(&ordinary()[1..])),
                Path::new("rocksdb"),
                limits()
            )
            .is_ok()
        );
        for bounds in [
            CollectionLimits {
                maximum_files: 1,
                ..limits()
            },
            CollectionLimits {
                maximum_file_bytes: 2,
                ..limits()
            },
            CollectionLimits {
                maximum_total_bytes: 20,
                ..limits()
            },
        ] {
            assert!(census_rocksdb_tar(Cursor::new(&bytes), Path::new("rocksdb"), bounds).is_err());
        }
        for omitted in [
            "rocksdb/CURRENT",
            "rocksdb/MANIFEST-1",
            "rocksdb/000001.sst",
        ] {
            let entries: Vec<_> = ordinary().into_iter().filter(|e| e.0 != omitted).collect();
            assert!(
                census_rocksdb_tar(
                    Cursor::new(fixture(&entries)),
                    Path::new("rocksdb"),
                    limits()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_links_devices_extensions_foreign_and_nested_members() {
        for kind in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::Fifo,
            tar::EntryType::GNUSparse,
            tar::EntryType::GNULongName,
            tar::EntryType::XHeader,
            tar::EntryType::XGlobalHeader,
        ] {
            let dir = output();
            assert!(
                collect(
                    &fixture(&[("rocksdb/bad", kind, b"")]),
                    dir.path(),
                    limits()
                )
                .is_err()
            );
        }
        for name in [
            "other/CURRENT",
            "rocksdb/sub/file",
            "rocksdb/../escape",
            "/rocksdb/CURRENT",
        ] {
            let dir = output();
            assert!(
                collect(
                    &fixture(&[(name, tar::EntryType::Regular, b"x")]),
                    dir.path(),
                    limits()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_duplicate_names_and_retains_failed_output() {
        let dir = output();
        let mut entries = ordinary();
        entries.push(("rocksdb/CURRENT", tar::EntryType::Regular, b"replacement"));
        assert!(collect(&fixture(&entries), dir.path(), limits()).is_err());
        assert_eq!(
            fs::read(dir.path().join("CURRENT")).unwrap(),
            b"MANIFEST-1\n"
        );
        assert!(collect(&fixture(&ordinary()), dir.path(), limits()).is_err());
    }

    #[test]
    fn requires_current_nonempty_manifest_and_numbered_sst() {
        for omitted in [
            "rocksdb/CURRENT",
            "rocksdb/MANIFEST-1",
            "rocksdb/000001.sst",
        ] {
            let dir = output();
            let entries: Vec<_> = ordinary().into_iter().filter(|e| e.0 != omitted).collect();
            assert!(collect(&fixture(&entries), dir.path(), limits()).is_err());
        }
        for current in [
            b"MANIFEST-1".as_slice(),
            b"../MANIFEST-1\n",
            b"MANIFEST-1\nextra\n",
            b"MANIFEST-x\n",
        ] {
            let dir = output();
            let mut entries = ordinary();
            entries[1].2 = current;
            assert!(collect(&fixture(&entries), dir.path(), limits()).is_err());
        }
        let dir = output();
        let mut entries = ordinary();
        entries[2].2 = b"";
        assert!(collect(&fixture(&entries), dir.path(), limits()).is_err());
    }

    #[test]
    fn enforces_independent_member_count_file_total_and_current_limits() {
        for bounds in [
            CollectionLimits {
                maximum_files: 1,
                ..limits()
            },
            CollectionLimits {
                maximum_file_bytes: 2,
                ..limits()
            },
            CollectionLimits {
                maximum_total_bytes: 20,
                ..limits()
            },
        ] {
            let dir = output();
            assert!(collect(&fixture(&ordinary()), dir.path(), bounds).is_err());
        }
        let dir = output();
        let current = vec![b'x'; 4097];
        let entries = [(
            "rocksdb/CURRENT",
            tar::EntryType::Regular,
            current.as_slice(),
        )];
        assert!(collect(&fixture(&entries), dir.path(), limits()).is_err());
    }

    #[test]
    fn rejects_truncation_missing_end_markers_and_nonzero_or_excess_trailers() {
        let bytes = fixture(&ordinary());
        for end in [1, 511, 512, 600, bytes.len() - 1024, bytes.len() - 512] {
            let dir = output();
            assert!(
                collect(&bytes[..end], dir.path(), limits()).is_err(),
                "accepted end {end}"
            );
        }
        let dir = output();
        let mut changed = bytes.clone();
        changed.push(1);
        assert!(collect(&changed, dir.path(), limits()).is_err());
        let dir = output();
        changed = bytes;
        changed.extend([0; 4096]);
        assert!(collect(&changed, dir.path(), limits()).is_err());
    }

    #[test]
    fn rejects_oversized_extension_before_reading_its_body() {
        let mut header = tar::Header::new_gnu();
        header.set_path("rocksdb/extension").unwrap();
        header.set_entry_type(tar::EntryType::GNULongName);
        header.set_size(1 << 50);
        header.set_cksum();
        let dir = output();
        let error = collect(header.as_bytes(), dir.path(), limits()).unwrap_err();
        assert!(error.to_string().contains("non-regular"));
    }

    #[test]
    fn refuses_nonprivate_or_nonempty_destination_without_overwrite() {
        let dir = output();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(collect(&fixture(&ordinary()), dir.path(), limits()).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.path().join("keep"), b"original").unwrap();
        assert!(collect(&fixture(&ordinary()), dir.path(), limits()).is_err());
        assert_eq!(fs::read(dir.path().join("keep")).unwrap(), b"original");
    }
}
