//! Digest-bound private collection of an already retained bzip 2 RocksDB tar.
//!
//! This is a diagnostic library, not a downloader or admission mechanism. The
//! caller must independently authenticate the expected digest against the exact
//! cloud generation, admit the complete resource peak and provide a runtime
//! guard. No real ledger or publication route is qualified by this module.

use {
    crate::horizon_ledger_tar::{
        CollectionLimits, DiagnosticCollection, census_rocksdb_tar, collect_rocksdb_tar,
    },
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        fs::{self, Metadata, OpenOptions},
        io::{Read, Seek, SeekFrom},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
    },
};

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<&Metadata> for Identity {
    fn from(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            size: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}

struct HashReader<R> {
    inner: R,
    digest: Sha256,
    count: u64,
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(bytes)?;
        self.count = self
            .count
            .checked_add(n as u64)
            .ok_or_else(|| std::io::Error::other("compressed byte count overflow"))?;
        self.digest.update(&bytes[..n]);
        Ok(n)
    }
}

/// A complete private collection bound to an independently supplied digest.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundBzipCollection {
    /// SHA-256 verified before decompression and again over consumed input.
    pub compressed_sha256: String,
    /// Exact complete compressed input length.
    pub compressed_bytes: u64,
    /// Retained input device identity.
    pub input_device: u64,
    /// Retained input inode identity.
    pub input_inode: u64,
    /// Complete archived file census, not a native live-state proof.
    pub collection: DiagnosticCollection,
    /// Always false: digest provenance is a separate caller obligation.
    pub cloud_generation_authenticated: bool,
    /// Always false: this library does not perform fresh admission.
    pub resource_admission_proven: bool,
    /// Always false: collected bytes remain private diagnostic input.
    pub publication_authorized: bool,
}

/// Collect a complete bzip 2 tar from an immutable, digest-bound local input.
///
/// Require a canonical absolute, singly linked, non-writable regular input owned
/// by root or the effective user. Hash the complete input before touching the
/// destination, then hash all compressed bytes consumed by the multistream
/// decoder and compare the open descriptor and named path identities again.
/// Truncation, extra compressed garbage, a second tar, input mutation and any
/// tar/member bound violation fail closed. Partial output remains diagnostic.
/// The destination rules and independent decompressed bounds are those of
/// [`collect_rocksdb_tar`]. `maximum_compressed_bytes` is an explicit input bound,
/// not a disk reservation; time, memory and actual-free-space guards are owed by
/// the caller. No cloud authentication, resume or receipt writer is provided.
pub fn collect_bound_bzip2(
    input: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
    maximum_compressed_bytes: u64,
    archive_root: &Path,
    destination: &Path,
    limits: CollectionLimits,
) -> Result<BoundBzipCollection> {
    collect_bound_bzip2_guarded(
        input,
        expected_bytes,
        expected_sha256,
        maximum_compressed_bytes,
        archive_root,
        destination,
        limits,
        || Ok(()),
    )
}

/// Retain every member with the same input-read guard as the complete census.
/// Partial output is preserved on any failure, never a successful collection.
/// A persistent caller still owes fresh full-peak admission and independent
/// wall-time/memory limits; the callback cannot interrupt a blocked syscall.
#[allow(clippy::too_many_arguments)]
pub fn collect_bound_bzip2_guarded(
    input: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
    maximum_compressed_bytes: u64,
    archive_root: &Path,
    destination: &Path,
    limits: CollectionLimits,
    guard: impl FnMut() -> Result<()>,
) -> Result<BoundBzipCollection> {
    inspect_bound_bzip2(
        input,
        expected_bytes,
        expected_sha256,
        maximum_compressed_bytes,
        archive_root,
        Some(destination),
        limits,
        guard,
    )
}

/// Bind and decode the complete input without retaining decompressed members.
///
/// Every compressed and decompressed integrity gate is identical to collection.
/// The returned census explicitly has `files_retained: false`; native resolution,
/// fresh admission, durable receipts and all recovery gates remain separate.
pub fn census_bound_bzip2(
    input: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
    maximum_compressed_bytes: u64,
    archive_root: &Path,
    limits: CollectionLimits,
) -> Result<BoundBzipCollection> {
    inspect_bound_bzip2(
        input,
        expected_bytes,
        expected_sha256,
        maximum_compressed_bytes,
        archive_root,
        None,
        limits,
        || Ok(()),
    )
}

/// Census with a caller guard checked before each compressed-input read.
///
/// The guard also runs before work and after complete decoding. Any failure
/// aborts without a successful census. Callers must provide independent wall-time
/// and memory limits; this callback cannot interrupt an in-progress blocking read.
pub fn census_bound_bzip2_guarded(
    input: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
    maximum_compressed_bytes: u64,
    archive_root: &Path,
    limits: CollectionLimits,
    guard: impl FnMut() -> Result<()>,
) -> Result<BoundBzipCollection> {
    inspect_bound_bzip2(
        input,
        expected_bytes,
        expected_sha256,
        maximum_compressed_bytes,
        archive_root,
        None,
        limits,
        guard,
    )
}

struct GuardReader<R, G> {
    inner: R,
    guard: G,
}

impl<R: Read, G: FnMut() -> Result<()>> Read for GuardReader<R, G> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        (self.guard)().map_err(std::io::Error::other)?;
        self.inner.read(bytes)
    }
}

#[allow(clippy::too_many_arguments)]
fn inspect_bound_bzip2(
    input: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
    maximum_compressed_bytes: u64,
    archive_root: &Path,
    destination: Option<&Path>,
    limits: CollectionLimits,
    mut guard: impl FnMut() -> Result<()>,
) -> Result<BoundBzipCollection> {
    guard()?;
    ensure!(
        expected_bytes > 0 && expected_bytes <= maximum_compressed_bytes,
        "invalid compressed length bound"
    );
    ensure!(
        expected_sha256.len() == 64
            && expected_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected digest must be lowercase SHA-256"
    );
    ensure!(
        input.is_absolute() && input.canonicalize()? == input,
        "input must be canonical and absolute"
    );
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(input)
        .context("open compressed input")?;
    let metadata = source.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && (metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() }),
        "input must be singly linked, trusted-owner and non-writable"
    );
    let identity = Identity::from(&metadata);
    let probe_limit = expected_bytes
        .checked_add(1)
        .context("compressed bound overflow")?;
    ensure!(
        metadata.len() == expected_bytes,
        "compressed length mismatch"
    );
    ensure!(
        Identity::from(&fs::symlink_metadata(input)?) == identity,
        "input path identity mismatch"
    );
    let mut prehash = Sha256::new();
    let count = std::io::copy(
        &mut GuardReader {
            inner: &mut source,
            guard: &mut guard,
        }
        .take(probe_limit),
        &mut DigestSink(&mut prehash),
    )?;
    ensure!(
        count == expected_bytes && format!("{:x}", prehash.finalize()) == expected_sha256,
        "compressed pre-read digest mismatch"
    );
    ensure!(
        Identity::from(&source.metadata()?) == identity,
        "input changed during pre-read"
    );
    source.seek(SeekFrom::Start(0))?;
    let mut reader = HashReader {
        inner: GuardReader {
            inner: &mut source,
            guard: &mut guard,
        }
        .take(probe_limit),
        digest: Sha256::new(),
        count: 0,
    };
    let mut decoder = bzip2::read::MultiBzDecoder::new(&mut reader);
    let collection = match destination {
        Some(destination) => collect_rocksdb_tar(&mut decoder, archive_root, destination, limits)?,
        None => census_rocksdb_tar(&mut decoder, archive_root, limits)?,
    };
    // The tar collector drains through decoded EOF; require the decoder to have
    // validated every bzip 2 member, including its checksum and stream footer.
    let mut end = [0_u8; 1];
    ensure!(decoder.read(&mut end)? == 0, "decoder did not reach EOF");
    drop(decoder);
    ensure!(
        reader.count == expected_bytes
            && format!("{:x}", reader.digest.finalize()) == expected_sha256,
        "compressed decode-read digest mismatch"
    );
    guard()?;
    ensure!(
        Identity::from(&source.metadata()?) == identity
            && Identity::from(&fs::symlink_metadata(input)?) == identity,
        "input changed during collection"
    );
    Ok(BoundBzipCollection {
        compressed_sha256: expected_sha256.to_owned(),
        compressed_bytes: expected_bytes,
        input_device: identity.device,
        input_inode: identity.inode,
        collection,
        cloud_generation_authenticated: false,
        resource_admission_proven: false,
        publication_authorized: false,
    })
}

struct DigestSink<'a>(&'a mut Sha256);

impl std::io::Write for DigestSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        os::unix::fs::{PermissionsExt, symlink},
    };

    fn tar_bytes() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in [
            ("rocksdb/CURRENT", b"MANIFEST-1\n".as_slice()),
            ("rocksdb/MANIFEST-1", b"manifest".as_slice()),
            ("rocksdb/000001.sst", b"table".as_slice()),
            ("rocksdb/000002.log", b"wal".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            builder.append_data(&mut header, name, data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn limits() -> CollectionLimits {
        CollectionLimits {
            maximum_files: 4,
            maximum_file_bytes: 4096,
            maximum_total_bytes: 8192,
            maximum_trailer_bytes: 4096,
        }
    }

    fn install(dir: &Path, bytes: &[u8]) -> std::path::PathBuf {
        let input = dir.join("ledger.tar.bz2");
        fs::write(&input, bytes).unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o444)).unwrap();
        input
    }

    fn collect(input: &Path, bytes: &[u8], destination: &Path) -> Result<BoundBzipCollection> {
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
        collect_bound_bzip2(
            input,
            bytes.len() as u64,
            &format!("{:x}", Sha256::digest(bytes)),
            bytes.len() as u64,
            Path::new("rocksdb"),
            destination,
            limits(),
        )
    }

    fn census(input: &Path, bytes: &[u8]) -> Result<BoundBzipCollection> {
        census_bound_bzip2(
            input,
            bytes.len() as u64,
            &format!("{:x}", Sha256::digest(bytes)),
            bytes.len() as u64,
            Path::new("rocksdb"),
            limits(),
        )
    }

    #[test]
    fn complete_multistream_census_matches_retained_collection_without_output() {
        let tar = tar_bytes();
        let mut bytes = compress(&tar[..777]);
        bytes.extend(compress(&tar[777..]));
        let root = tempfile::tempdir().unwrap();
        let input = install(root.path(), &bytes);
        let measured = census(&input, &bytes).unwrap();
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        assert!(!measured.collection.files_retained);
        let output = tempfile::tempdir().unwrap();
        let mut retained =
            serde_json::to_value(collect(&input, &bytes, output.path()).unwrap()).unwrap();
        retained["collection"]["files_retained"] = false.into();
        assert_eq!(serde_json::to_value(measured).unwrap(), retained);
        assert_eq!(fs::read(&input).unwrap(), bytes);
    }

    #[test]
    fn guarded_retention_preserves_input_and_fails_without_a_success_result() {
        let bytes = compress(&tar_bytes());
        let root = tempfile::tempdir().unwrap();
        let input = install(root.path(), &bytes);
        let output = tempfile::tempdir().unwrap();
        fs::set_permissions(output.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut complete_calls = 0;
        let result = collect_bound_bzip2_guarded(
            &input,
            bytes.len() as u64,
            &format!("{:x}", Sha256::digest(&bytes)),
            bytes.len() as u64,
            Path::new("rocksdb"),
            output.path(),
            limits(),
            || {
                complete_calls += 1;
                Ok(())
            },
        )
        .unwrap();
        assert!(result.collection.files_retained);
        assert!(complete_calls >= 4);
        for stop_at in 1..=complete_calls {
            let destination = tempfile::tempdir().unwrap();
            fs::set_permissions(destination.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let mut calls = 0;
            let error = collect_bound_bzip2_guarded(
                &input,
                bytes.len() as u64,
                &format!("{:x}", Sha256::digest(&bytes)),
                bytes.len() as u64,
                Path::new("rocksdb"),
                destination.path(),
                limits(),
                || {
                    calls += 1;
                    ensure!(calls < stop_at, "retention guard stop");
                    Ok(())
                },
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("retention guard stop"));
            assert_eq!(calls, stop_at);
            assert_eq!(fs::read(&input).unwrap(), bytes);
            if stop_at == complete_calls {
                // Even a complete private file tree is not a successful result
                // when the final guard fails. Never silently discard it.
                assert_eq!(fs::read_dir(destination.path()).unwrap().count(), 4);
                assert!(collect(&input, &bytes, destination.path()).is_err());
            }
        }
    }

    #[test]
    fn census_guard_aborts_before_work_during_hash_and_during_decode() {
        let bytes = compress(&tar_bytes());
        let root = tempfile::tempdir().unwrap();
        let input = install(root.path(), &bytes);
        for stop_at in [1, 2, 4] {
            let mut calls = 0;
            let error = census_bound_bzip2_guarded(
                &input,
                bytes.len() as u64,
                &format!("{:x}", Sha256::digest(&bytes)),
                bytes.len() as u64,
                Path::new("rocksdb"),
                limits(),
                || {
                    calls += 1;
                    ensure!(calls < stop_at, "test guard stopped");
                    Ok(())
                },
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("test guard stopped"));
            assert_eq!(calls, stop_at);
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn binds_complete_multistream_input_and_preserves_every_member() {
        let tar = tar_bytes();
        let mut bytes = compress(&tar[..777]);
        bytes.extend(compress(&tar[777..]));
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let input = install(root.path(), &bytes);
        let result = collect(&input, &bytes, output.path()).unwrap();
        assert_eq!(result.collection.files.len(), 4);
        assert_eq!(result.collection.wal_files, ["000002.log"]);
        assert!(!result.cloud_generation_authenticated);
        assert!(!result.resource_admission_proven);
        assert!(!result.publication_authorized);
        assert_eq!(fs::read(output.path().join("000002.log")).unwrap(), b"wal");
        assert_eq!(fs::read(&input).unwrap(), bytes);
        assert_eq!(
            fs::metadata(input).unwrap().permissions().mode() & 0o777,
            0o444
        );
    }

    #[test]
    fn wrong_digest_and_length_do_not_touch_output() {
        let bytes = compress(&tar_bytes());
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let input = install(root.path(), &bytes);
        for (len, hash, bound) in [
            (bytes.len() as u64, "0".repeat(64), bytes.len() as u64),
            (
                bytes.len() as u64 + 1,
                format!("{:x}", Sha256::digest(&bytes)),
                bytes.len() as u64 + 1,
            ),
            (
                bytes.len() as u64,
                format!("{:x}", Sha256::digest(&bytes)),
                bytes.len() as u64 - 1,
            ),
        ] {
            assert!(
                collect_bound_bzip2(
                    &input,
                    len,
                    &hash,
                    bound,
                    Path::new("rocksdb"),
                    output.path(),
                    limits()
                )
                .is_err()
            );
            assert_eq!(fs::read_dir(output.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn rejects_writable_symlink_hardlink_and_nonregular_inputs() {
        let bytes = compress(&tar_bytes());
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let input = install(root.path(), &bytes);
        fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(census(&input, &bytes).is_err());
        assert!(collect(&input, &bytes, output.path()).is_err());
        fs::set_permissions(&input, fs::Permissions::from_mode(0o444)).unwrap();
        let link = root.path().join("link");
        symlink(&input, &link).unwrap();
        assert!(census(&link, &bytes).is_err());
        assert!(collect(&link, &bytes, output.path()).is_err());
        fs::hard_link(&input, root.path().join("hardlink")).unwrap();
        assert!(census(&input, &bytes).is_err());
        assert!(census(root.path(), &bytes).is_err());
        assert!(collect(&input, &bytes, output.path()).is_err());
        assert!(collect(root.path(), &bytes, output.path()).is_err());
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 0);
    }

    #[test]
    fn rejects_truncated_corrupt_and_extra_compressed_bytes_even_with_matching_digest() {
        let bytes = compress(&tar_bytes());
        let mut corrupt = bytes.clone();
        let n = corrupt.len();
        corrupt[n - 3] ^= 0x40;
        let mut garbage = bytes.clone();
        garbage.extend_from_slice(b"not another bzip2 stream");
        for bad in [bytes[..bytes.len() - 7].to_vec(), corrupt, garbage] {
            let root = tempfile::tempdir().unwrap();
            let output = tempfile::tempdir().unwrap();
            let input = install(root.path(), &bad);
            assert!(census(&input, &bad).is_err());
            assert!(collect(&input, &bad, output.path()).is_err());
        }
    }

    #[test]
    fn rejects_second_tar_and_expansion_bound_but_retains_diagnostics() {
        let mut bytes = compress(&tar_bytes());
        bytes.extend(compress(&tar_bytes()));
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let input = install(root.path(), &bytes);
        assert!(census(&input, &bytes).is_err());
        assert!(collect(&input, &bytes, output.path()).is_err());
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 4);

        let bytes = compress(&tar_bytes());
        let root = tempfile::tempdir().unwrap();
        let input = install(root.path(), &bytes);
        let output = tempfile::tempdir().unwrap();
        let mut small = limits();
        fs::set_permissions(output.path(), fs::Permissions::from_mode(0o700)).unwrap();
        small.maximum_total_bytes = 12;
        assert!(
            collect_bound_bzip2(
                &input,
                bytes.len() as u64,
                &format!("{:x}", Sha256::digest(&bytes)),
                bytes.len() as u64,
                Path::new("rocksdb"),
                output.path(),
                small
            )
            .is_err()
        );
        assert!(output.path().join("CURRENT").exists());
        assert!(!output.path().join("000001.sst").exists());
    }
}
