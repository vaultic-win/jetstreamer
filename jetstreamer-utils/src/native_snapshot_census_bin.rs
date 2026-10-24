//! Read-only census of two closed, already-sealed native bootstrap snapshots.
//! No Bank, extraction, replay, network, resource observation or admission path.
use {
    anyhow::{Context, Result, bail, ensure},
    serde::Serialize,
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeSet,
        env,
        fs::{self, File, Metadata, OpenOptions},
        io::{self, BufReader, Read, Seek, SeekFrom, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    },
    tar::{Archive, EntryType, Header},
};

struct Profile {
    epoch: u64,
    snapshot: &'static str,
    compressed_bytes: u64,
    sha256: &'static str,
    slot: &'static str,
}

fn profile(epoch: &str) -> Result<Profile> {
    match epoch {
        "210" => Ok(Profile {
            epoch: 210,
            snapshot: "/var/lib/jetstreamer/horizon-focused-210-complete-span-store8-ca2e38b-v1/snapshot-90719638-3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ.tar.zst",
            compressed_bytes: 8_579_041_139,
            sha256: "3f67f416d254d7fb795bc902d5c47a6ae374fa36c173c00411d4b541fc610ccd",
            slot: "90719638",
        }),
        "227" => Ok(Profile {
            epoch: 227,
            snapshot: "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst",
            compressed_bytes: 10_261_480_487,
            sha256: "77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07",
            slot: "98063464",
        }),
        _ => bail!("only exact epoch210 and epoch227 input profiles are admitted"),
    }
}
const GIB: u64 = 1024 * 1024 * 1024;
const MAX_ENTRIES: u64 = 524_288;
const MAX_MEMBER: u64 = 32 * GIB;
const MAX_LOGICAL: u64 = 8 * MAX_MEMBER;
const MAX_STREAM: u64 = MAX_LOGICAL + (MAX_ENTRIES + 1) * 1024;
const BLOCK: u64 = 4096;

#[derive(Debug, Default, Serialize)]
struct Census {
    entries: u64,
    regular_files: u64,
    directories: u64,
    sparse_files: u64,
    stored_payload_bytes: u64,
    logical_file_bytes: u64,
    dense_4096_rounded_file_bytes: u64,
    max_member_stored_bytes: u64,
    max_member_logical_bytes: u64,
    account_files: u64,
    account_stored_bytes: u64,
    account_logical_bytes: u64,
    bank_logical_bytes: u64,
    status_cache_logical_bytes: u64,
    decompressed_tar_bytes: u64,
    metadata_allowance_bytes: u64,
    twice_dense_plus_metadata_plus_one_gib_bytes: u64,
}

#[derive(Serialize)]
struct Receipt {
    schema: &'static str,
    epoch: u64,
    recorded_unix_seconds: u64,
    snapshot: &'static str,
    snapshot_sha256: &'static str,
    snapshot_compressed_bytes: u64,
    snapshot_device: u64,
    snapshot_inode: u64,
    auditor_sha256: String,
    census: Census,
    envelope_is_experiment_only: bool,
    loader_or_consensus_changed: bool,
    snapshot_extracted: bool,
    bank_constructed: bool,
    native_execution_authorized: bool,
    replay_launch_authorized: bool,
    admission_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn checked_add(target: &mut u64, value: u64) -> Result<()> {
    *target = target
        .checked_add(value)
        .context("census byte/count overflow")?;
    Ok(())
}

fn rounded(bytes: u64) -> Result<u64> {
    Ok(bytes.checked_add(BLOCK - 1).context("rounding overflow")? / BLOCK * BLOCK)
}

fn layout(path: &Path, kind: EntryType, slot: &str) -> Result<u64> {
    let mut parts = Vec::new();
    for part in path.components() {
        match part {
            Component::Normal(value) => parts.push(value.to_str().context("non UTF-8 path")?),
            _ => bail!("noncanonical snapshot member path"),
        }
    }
    let directory = parts == ["accounts"] || parts == ["snapshots"] || parts == ["snapshots", slot];
    if directory {
        ensure!(kind.is_dir(), "directory member has wrong type");
        return Ok(0);
    }
    ensure!(
        kind.is_file() || kind.is_gnu_sparse(),
        "unsupported raw entry type"
    );
    if parts == ["version"] {
        Ok(64)
    } else if parts == ["snapshots", "status_cache"] || parts == ["snapshots", slot, slot] {
        Ok(MAX_MEMBER)
    } else if parts.len() == 2 && parts[0] == "accounts" {
        let mut numbers = parts[1].split('.');
        let left = numbers.next().unwrap_or_default();
        let right = numbers.next().unwrap_or_default();
        ensure!(
            !left.is_empty()
                && !right.is_empty()
                && numbers.next().is_none()
                && left.bytes().all(|b| b.is_ascii_digit())
                && right.bytes().all(|b| b.is_ascii_digit()),
            "invalid AppendVec name"
        );
        Ok(16 * GIB)
    } else {
        bail!("unexpected snapshot member path")
    }
}

// Raw tar iteration avoids eager GNU/PAX extension parsing and allocation. Check
// the same four-descriptor sparse format accepted by the unchanged loader.
fn sparse_map(header: &Header, stored: u64, logical: u64) -> Result<()> {
    if !header.entry_type().is_gnu_sparse() {
        ensure!(stored == logical, "regular file has inconsistent sizes");
        return Ok(());
    }
    let gnu = header.as_gnu().context("non-GNU sparse header")?;
    ensure!(!gnu.is_extended(), "extended sparse maps are forbidden");
    let mut previous_end = 0u64;
    let mut data_bytes = 0u64;
    for block in &gnu.sparse {
        if block.is_empty() {
            continue;
        }
        let offset = block.offset()?;
        let length = block.length()?;
        ensure!(
            offset >= previous_end,
            "overlapping/out-of-order sparse map"
        );
        ensure!(
            length == 0 || data_bytes.is_multiple_of(512),
            "unaligned sparse payload"
        );
        previous_end = offset
            .checked_add(length)
            .context("sparse extent overflow")?;
        checked_add(&mut data_bytes, length)?;
        ensure!(
            previous_end <= logical && data_bytes <= stored,
            "oversized sparse map"
        );
    }
    ensure!(
        data_bytes == stored && previous_end == logical,
        "incomplete sparse map"
    );
    Ok(())
}

struct BoundedReader<R> {
    inner: R,
    count: u64,
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let remaining = MAX_STREAM.saturating_sub(self.count);
        if remaining == 0 {
            let mut extra = [0u8; 1];
            return match self.inner.read(&mut extra)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tar stream limit exceeded",
                )),
            };
        }
        let limit = buffer.len().min(remaining as usize);
        let read = self.inner.read(&mut buffer[..limit])?;
        self.count += read as u64;
        Ok(read)
    }
}

fn census<R: Read>(source: R, slot: &str) -> Result<Census> {
    let mut archive = Archive::new(BoundedReader {
        inner: source,
        count: 0,
    });
    let mut result = Census::default();
    let mut names = BTreeSet::new();
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        checked_add(&mut result.entries, 1)?;
        ensure!(
            result.entries <= MAX_ENTRIES,
            "entry count exceeds loader limit"
        );
        let kind = entry.header().entry_type();
        let path = entry.path()?.into_owned();
        let limit = layout(&path, kind, slot)?;
        ensure!(names.insert(path.clone()), "duplicate snapshot member");
        let stored = entry.header().entry_size()?;
        let logical = entry.header().size()?;
        ensure!(
            stored <= limit && logical <= limit,
            "snapshot member exceeds layout limit"
        );
        sparse_map(entry.header(), stored, logical)?;
        checked_add(&mut result.stored_payload_bytes, stored)?;
        checked_add(&mut result.logical_file_bytes, logical)?;
        ensure!(
            result.logical_file_bytes <= MAX_LOGICAL,
            "aggregate exceeds loader limit"
        );
        checked_add(&mut result.dense_4096_rounded_file_bytes, rounded(logical)?)?;
        result.max_member_stored_bytes = result.max_member_stored_bytes.max(stored);
        result.max_member_logical_bytes = result.max_member_logical_bytes.max(logical);
        if kind.is_dir() {
            checked_add(&mut result.directories, 1)?;
        } else {
            checked_add(&mut result.regular_files, 1)?;
            if kind.is_gnu_sparse() {
                checked_add(&mut result.sparse_files, 1)?;
            }
            if path.starts_with("accounts") {
                checked_add(&mut result.account_files, 1)?;
                checked_add(&mut result.account_stored_bytes, stored)?;
                checked_add(&mut result.account_logical_bytes, logical)?;
            } else if path == Path::new("snapshots/status_cache") {
                result.status_cache_logical_bytes = logical;
            } else if path == Path::new("snapshots").join(slot).join(slot) {
                result.bank_logical_bytes = logical;
            }
        }
        ensure!(
            io::copy(&mut entry, &mut io::sink())? == stored,
            "truncated member payload"
        );
    }
    let bank_path = format!("snapshots/{slot}/{slot}");
    for required in ["version", "snapshots/status_cache", bank_path.as_str()] {
        ensure!(
            names.contains(Path::new(required)),
            "required snapshot member missing: {required}"
        );
    }
    ensure!(result.account_files > 0, "no AppendVec members");
    // tar stops at its first zero header. Finish the decoder to validate the
    // entire compressed input and reject nonzero trailing or hidden tar members.
    let mut remainder = archive.into_inner();
    let mut buffer = [0u8; 65536];
    loop {
        let read = remainder.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        ensure!(
            buffer[..read].iter().all(|byte| *byte == 0),
            "nonzero trailing tar data"
        );
    }
    result.decompressed_tar_bytes = remainder.count;
    // Allow four 4KiB units per inode/directory for metadata. This is a stated
    // experiment margin, not a filesystem-independent physical upper bound.
    result.metadata_allowance_bytes = result
        .entries
        .checked_mul(4 * BLOCK)
        .context("metadata overflow")?;
    result.twice_dense_plus_metadata_plus_one_gib_bytes = result
        .dense_4096_rounded_file_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(result.metadata_allowance_bytes))
        .and_then(|n| n.checked_add(GIB))
        .context("envelope overflow")?;
    Ok(result)
}

fn identity_unchanged(before: &Metadata, after: &Metadata) -> Result<()> {
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.nlink() == after.nlink()
            && before.uid() == after.uid()
            && before.gid() == after.gid()
            && before.mode() == after.mode()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "immutable input identity changed"
    );
    Ok(())
}

fn hash(file: &mut File) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn secure_ancestors(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "noncanonical path"
    );
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "path or ancestor is not root-owned and protected"
        );
    }
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(
        args.len() == 6
            && args[0] == "--epoch"
            && args[2] == "--self-sha256"
            && args[4] == "--receipt",
        "usage: jetstreamer-native-snapshot-census --epoch 210|227 --self-sha256 SHA --receipt ABSOLUTE_NEW_FILE"
    );
    let profile = profile(&args[1])?;
    ensure!(unsafe { libc::geteuid() } == 0, "run as root");
    let self_sha = &args[3];
    ensure!(
        self_sha.len() == 64
            && self_sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid self digest"
    );
    let mut executable = File::open("/proc/self/exe")?;
    let executable_before = executable.metadata()?;
    ensure!(
        executable_before.is_file()
            && executable_before.uid() == 0
            && executable_before.mode() & 0o022 == 0,
        "unsealed auditor"
    );
    ensure!(&hash(&mut executable)? == self_sha, "auditor SHA mismatch");
    identity_unchanged(&executable_before, &executable.metadata()?)?;
    let output = PathBuf::from(&args[5]);
    ensure!(
        output.is_absolute() && output.file_name().is_some(),
        "receipt must be absolute"
    );
    let parent = output.parent().context("missing receipt parent")?;
    secure_ancestors(parent)?;
    let parent_meta = fs::symlink_metadata(parent)?;
    ensure!(
        parent_meta.is_dir() && parent_meta.mode() & 0o077 == 0,
        "receipt parent must be root-private"
    );
    ensure!(
        fs::symlink_metadata(&output).is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
        "receipt already exists or is not accessible"
    );
    secure_ancestors(Path::new(profile.snapshot))?;
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(profile.snapshot)?;
    let before = input.metadata()?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.len() == profile.compressed_bytes
            && before.mode() & 0o222 == 0,
        "snapshot is not exact immutable regular input"
    );
    ensure!(hash(&mut input)? == profile.sha256, "snapshot SHA mismatch");
    identity_unchanged(&before, &input.metadata()?)?;
    input.seek(SeekFrom::Start(0))?;
    let decoder = zstd::stream::read::Decoder::new(BufReader::new(&mut input))?;
    let measured = census(decoder, profile.slot)?;
    identity_unchanged(&before, &input.metadata()?)?;
    identity_unchanged(&before, &fs::symlink_metadata(profile.snapshot)?)?;
    let receipt = Receipt {
        schema: "jetstreamer-native-readonly-snapshot-census-v1",
        epoch: profile.epoch,
        recorded_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        snapshot: profile.snapshot,
        snapshot_sha256: profile.sha256,
        snapshot_compressed_bytes: before.len(),
        snapshot_device: before.dev(),
        snapshot_inode: before.ino(),
        auditor_sha256: self_sha.clone(),
        census: measured,
        envelope_is_experiment_only: true,
        loader_or_consensus_changed: false,
        snapshot_extracted: false,
        bank_constructed: false,
        native_execution_authorized: false,
        replay_launch_authorized: false,
        admission_authorized: false,
        publication_authorized: false,
        remote_mutations: false,
        r2_mutations: false,
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt)?;
    bytes.push(b'\n');
    ensure!(bytes.len() < 16 * 1024, "unexpected large receipt");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("native snapshot census refused: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(extra: Option<(&str, EntryType, &[u8])>, slot: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let slot_dir = format!("snapshots/{slot}");
        for path in ["accounts", "snapshots", slot_dir.as_str()] {
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o700);
            header.set_cksum();
            builder.append_data(&mut header, path, io::empty()).unwrap();
        }
        let bank = format!("snapshots/{slot}/{slot}");
        let account = format!("accounts/{slot}.0");
        for path in [
            "version",
            "snapshots/status_cache",
            bank.as_str(),
            account.as_str(),
        ] {
            let mut header = Header::new_gnu();
            header.set_size(5);
            header.set_mode(0o600);
            header.set_cksum();
            builder
                .append_data(&mut header, path, &b"hello"[..])
                .unwrap();
        }
        if let Some((path, kind, data)) = extra {
            let mut header = Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(data.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            builder.append_data(&mut header, path, data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn exact_layout_counts_payload_logical_and_dense_bytes() {
        let report = census(&archive(None, "90719638")[..], "90719638").unwrap();
        assert_eq!(report.entries, 7);
        assert_eq!(report.regular_files, 4);
        assert_eq!(report.stored_payload_bytes, 20);
        assert_eq!(report.dense_4096_rounded_file_bytes, 4 * BLOCK);
        assert_eq!(report.account_files, 1);
        assert_eq!(report.bank_logical_bytes, 5);
    }

    #[test]
    fn rejects_duplicate_extension_link_and_unexpected_paths() {
        for (path, kind) in [
            ("version", EntryType::Regular),
            ("accounts/1.2", EntryType::GNULongName),
            ("accounts/1.2", EntryType::Link),
            ("accounts/other", EntryType::Regular),
        ] {
            assert!(
                census(
                    &archive(Some((path, kind, b"x")), "90719638")[..],
                    "90719638"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_truncated_payload_or_hidden_trailing_archive() {
        let bytes = archive(None, "90719638");
        assert!(census(&bytes[..bytes.len() - 1200], "90719638").is_err());
        let mut hidden = bytes;
        hidden.extend(archive(None, "90719638"));
        assert!(census(&hidden[..], "90719638").is_err());
    }

    #[test]
    fn sparse_maps_are_bounded_and_do_not_materialize_holes() {
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::GNUSparse);
        header.set_size(512);
        let gnu = header.as_gnu_mut().unwrap();
        gnu.set_real_size(4096);
        gnu.sparse[0].set_offset(3584);
        gnu.sparse[0].set_length(512);
        sparse_map(&header, 512, 4096).unwrap();
        header.as_gnu_mut().unwrap().isextended[0] = 1;
        assert!(sparse_map(&header, 512, 4096).is_err());
        header.as_gnu_mut().unwrap().isextended[0] = 0;
        header.as_gnu_mut().unwrap().sparse[1].set_offset(0);
        header.as_gnu_mut().unwrap().sparse[1].set_length(512);
        assert!(sparse_map(&header, 1024, 4096).is_err());
    }

    #[test]
    fn closed_profiles_do_not_accept_another_epochs_layout() {
        let p210 = profile("210").unwrap();
        let p227 = profile("227").unwrap();
        assert_ne!(p210.sha256, p227.sha256);
        assert_eq!(p227.compressed_bytes, 10_261_480_487);
        assert_eq!(
            census(&archive(None, p227.slot)[..], p227.slot)
                .unwrap()
                .account_files,
            1
        );
        assert!(census(&archive(None, p227.slot)[..], p210.slot).is_err());
        for epoch in ["209", "228", "0210", "all"] {
            assert!(profile(epoch).is_err());
        }
    }
}
