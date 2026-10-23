//! Native1.2.0 packaging only. Never invokes a host packager or retention helper.
use super::{
    MAX_APPEND_VEC_FILE_SIZE, MAX_HANDOFF_ARCHIVE_ENTRIES, MAX_HANDOFF_ARCHIVE_EXTRACTED_SIZE,
};
use bzip2::{write::BzEncoder, Compression};
use serde::Serialize;
use sha2::{Digest, Sha256};
use solana_runtime::{
    bank::Bank,
    snapshot_utils::{add_snapshot, serialize_status_cache, SnapshotVersion},
};
use solana_sdk::hash::Hash;
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, BufWriter, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

const MAX_ARCHIVE_BYTES: u64 =
    MAX_HANDOFF_ARCHIVE_EXTRACTED_SIZE + MAX_HANDOFF_ARCHIVE_ENTRIES * 1024 + 4096;

pub struct ExportedSnapshot {
    pub archive_path: PathBuf,
    pub archive_size: u64,
    pub archive_sha256: [u8; 32],
}
#[derive(Serialize)]
struct Member {
    relative_path: String,
    length: u64,
    sha256: [u8; 32],
}
#[derive(Serialize)]
struct Manifest {
    schema: String,
    slot: u64,
    bank_hash: Vec<u8>,
    accounts_hash: Vec<u8>,
    last_blockhash: Vec<u8>,
    capitalization: u64,
    transaction_count: u64,
    tick_height: u64,
    slot_complete: bool,
    next_write_version: u64,
    rooted_slots: Vec<u64>,
    members: Vec<Member>,
    selected_sources: Vec<SelectedSource>,
    archive_name: String,
    archive_size: u64,
    archive_sha256: [u8; 32],
}
#[derive(Serialize)]
struct SelectedSource {
    path: String,
    device: u64,
    inode: u64,
    logical_length: u64,
    physical_bytes: u64,
    archive_name: String,
    sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheSeal {
    roots: Vec<u64>,
    digest: [u8; 32],
}
struct HashWriter {
    hash: Sha256,
    bytes: u64,
}
impl Write for HashWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(b.len() as u64)
            .ok_or_else(|| io_error("status cache size overflow"))?;
        if next > solana_runtime::serde_snapshot::MAX_SNAPSHOT_DATA_FILE_SIZE {
            return Err(io_error("status cache size cap exceeded"));
        }
        self.hash.input(b);
        self.bytes = next;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn cache_seal(bank: &Bank) -> Result<CacheSeal, String> {
    let mut roots = bank.src.roots();
    roots.sort_unstable();
    if roots.last() != Some(&bank.slot())
        || roots.len() > solana_runtime::status_cache::MAX_CACHE_ENTRIES
        || roots.windows(2).any(|w| w[0] >= w[1])
    {
        return Err("rooted status cache does not end at the checkpoint".into());
    }
    let mut output = HashWriter {
        hash: Sha256::new(),
        bytes: 0,
    };
    bincode::serialize_into(&mut output, &bank.src.slot_deltas(&roots))
        .map_err(|e| e.to_string())?;
    let mut digest = [0; 32];
    digest.copy_from_slice(&output.hash.result());
    Ok(CacheSeal { roots, digest })
}

fn io_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn stable_contents(a: &Metadata, b: &Metadata) -> io::Result<()> {
    if a.dev() != b.dev()
        || a.ino() != b.ino()
        || a.len() != b.len()
        || a.mtime() != b.mtime()
        || a.mtime_nsec() != b.mtime_nsec()
        || a.uid() != b.uid()
        || a.gid() != b.gid()
        || a.mode() != b.mode()
        || b.nlink() != 1
        || !b.is_file()
    {
        return Err(io_error("snapshot member changed"));
    }
    Ok(())
}
fn stable(a: &Metadata, b: &Metadata) -> io::Result<()> {
    stable_contents(a, b)?;
    if a.ctime() != b.ctime() || a.ctime_nsec() != b.ctime_nsec() {
        return Err(io_error("snapshot member metadata changed"));
    }
    Ok(())
}
fn source(path: &Path, maximum: u64) -> io::Result<(File, Metadata)> {
    let m = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || path.canonicalize()? != path
        || !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o022 != 0
        || m.len() > maximum
    {
        return Err(io_error("unsafe or oversized snapshot member"));
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    stable(&m, &f.metadata()?)?;
    Ok((f, m))
}
fn hash_file(f: &mut File, expected: u64) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .ok_or_else(|| io_error("snapshot length overflow"))?;
        if bytes > expected {
            return Err(io_error("snapshot member grew"));
        }
        hash.input(&buffer[..n]);
    }
    if bytes != expected {
        return Err(io_error("snapshot member truncated"));
    }
    let mut digest = [0; 32];
    digest.copy_from_slice(&hash.result());
    Ok(digest)
}
fn measure(stage: &Path, path: &Path, maximum: u64) -> io::Result<Member> {
    let (mut f, m) = source(path, maximum)?;
    let digest = hash_file(&mut f, m.len())?;
    stable(&m, &fs::symlink_metadata(path)?)?;
    f.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(Member {
        relative_path: path
            .strip_prefix(stage)
            .map_err(|_| io_error("snapshot member outside stage"))?
            .to_str()
            .ok_or_else(|| io_error("snapshot name is not UTF-8"))?
            .to_string(),
        length: m.len(),
        sha256: digest,
    })
}
fn copy_selected(
    stage: &Path,
    path: &Path,
    name: &str,
    length: u64,
    selected_identity: &Metadata,
) -> io::Result<Member> {
    let (mut input, before) = source(path, MAX_APPEND_VEC_FILE_SIZE)?;
    stable(selected_identity, &before)?;
    if before.len() != length {
        return Err(io_error("selected AppendVec length changed"));
    }
    let destination = stage.join("accounts").join(name);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&destination)?;
    let copied = io::copy(&mut Read::by_ref(&mut input).take(length + 1), &mut output)?;
    if copied != length {
        return Err(io_error("selected AppendVec copy length changed"));
    }
    output.sync_all()?;
    stable(&before, &fs::symlink_metadata(path)?)?;
    let member = measure(stage, &destination, MAX_APPEND_VEC_FILE_SIZE)?;
    let (mut reread, after) = source(path, MAX_APPEND_VEC_FILE_SIZE)?;
    stable(&before, &after)?;
    if hash_file(&mut reread, length)? != member.sha256 {
        return Err(io_error("selected AppendVec bytes changed"));
    }
    stable(&before, &fs::symlink_metadata(path)?)?;
    Ok(member)
}
struct MaximumWriter<W> {
    inner: W,
    bytes: u64,
    maximum: u64,
}
impl<W: Write> Write for MaximumWriter<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() as u64 > self.maximum.saturating_sub(self.bytes) {
            return Err(io_error("snapshot archive byte cap exceeded"));
        }
        let n = self.inner.write(b)?;
        self.bytes += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn publish_no_clobber(source: &Path, destination: &Path) -> io::Result<()> {
    let a = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io_error("invalid snapshot source path"))?;
    let b = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| io_error("invalid snapshot destination path"))?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    File::open(source.parent().unwrap())?.sync_all()?;
    File::open(destination.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn add_bytes(total: &mut u64, n: u64) -> io::Result<()> {
    *total = total
        .checked_add(n)
        .ok_or_else(|| io_error("snapshot aggregate overflow"))?;
    if *total > MAX_HANDOFF_ARCHIVE_EXTRACTED_SIZE {
        return Err(io_error("snapshot extracted byte cap exceeded"));
    }
    Ok(())
}

pub fn export_archive<F>(
    bank: &Bank,
    output: &Path,
    expected_hash: Hash,
    mut validate_seal: F,
) -> Result<ExportedSnapshot, String>
where
    F: FnMut() -> Result<(), String>,
{
    let mut retained = None;
    let result = (|| -> Result<ExportedSnapshot, String> {
        validate_seal()?;
        let m = fs::symlink_metadata(output).map_err(|e| e.to_string())?;
        if !output.is_absolute()
            || output.canonicalize().map_err(|e| e.to_string())? != output
            || !m.is_dir()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o777 != 0o700
        {
            return Err("snapshot output must be a canonical owner-only private directory".into());
        }
        if !bank.is_frozen()
            || !bank.is_complete()
            || bank.parent().is_some()
            || bank.get_accounts_hash() != expected_hash
        {
            return Err("snapshot Bank is not the sealed frozen rooted checkpoint".into());
        }
        let final_name = format!("snapshot-{}-{}.tar.bz2", bank.slot(), expected_hash);
        let final_path = output.join(&final_name);
        match fs::symlink_metadata(&final_path) {
            Ok(_) => return Err("refusing to replace an existing snapshot path".into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        // Hold the exact storage Arcs through flush, serialize, copy and publication.
        let storages = bank.get_snapshot_storages();
        let mut names = BTreeSet::new();
        let mut selected = Vec::new();
        let mut selected_bytes = 0;
        for storage in storages.iter().flatten() {
            storage.flush().map_err(|e| e.to_string())?;
            let path = storage.get_path();
            let (_, identity) =
                source(&path, MAX_APPEND_VEC_FILE_SIZE).map_err(|e| e.to_string())?;
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| "invalid AppendVec filename".to_string())?
                .to_string();
            // The loader admits exactly slot.id numeric AppendVec identities.
            let parts: Vec<_> = name.split('.').collect();
            if parts.len() != 2
                || parts
                    .iter()
                    .any(|p| p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()))
                || !names.insert(name.clone())
            {
                return Err("duplicate or invalid selected AppendVec identity".into());
            }
            add_bytes(&mut selected_bytes, identity.len()).map_err(|e| e.to_string())?;
            selected.push((path, name, identity));
            if selected.len() as u64 + 3 > MAX_HANDOFF_ARCHIVE_ENTRIES {
                return Err("snapshot member count cap exceeded".into());
            }
        }
        let cache = cache_seal(bank)?;
        let roots = cache.roots.clone();
        let stage = tempfile::Builder::new()
            .prefix("jetstreamer-native-export-")
            .tempdir_in(output)
            .map_err(|e| e.to_string())?
            .into_path();
        retained = Some(stage.clone());
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        File::open(&stage)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())?;
        File::open(output)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())?;
        let run = (|| -> io::Result<ExportedSnapshot> {
            let snapshots = stage.join("snapshots");
            fs::create_dir(&snapshots)?;
            fs::create_dir(stage.join("accounts"))?;
            fs::create_dir(snapshots.join(bank.slot().to_string()))?;
            File::open(&snapshots)?.sync_all()?;
            File::open(&stage)?.sync_all()?;
            // Pinned native helpers serialize schema1.2.0. Their native32GiB
            // serialization bound is checked after streaming; see source-review limitation.
            let bank_file = add_snapshot(&snapshots, bank, &storages, SnapshotVersion::V1_2_0)
                .map_err(|e| io_error(&e.to_string()))?
                .snapshot_file_path;
            let status = snapshots.join("status_cache");
            serialize_status_cache(bank.slot(), &bank.src.slot_deltas(&roots), &status)
                .map_err(|e| io_error(&e.to_string()))?;
            let version = stage.join("version");
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&version)?;
            f.write_all(b"1.2.0")?;
            f.sync_all()?;
            let maximum = solana_runtime::serde_snapshot::MAX_SNAPSHOT_DATA_FILE_SIZE;
            let mut members = vec![
                measure(&stage, &bank_file, maximum)?,
                measure(&stage, &status, maximum)?,
                measure(&stage, &version, 64)?,
            ];
            if members[1].sha256 != cache.digest {
                return Err(io_error("serialized rooted cache differs from seal"));
            }
            let mut total = 0;
            for member in &members {
                add_bytes(&mut total, member.length)?;
            }
            // Admit every selected copy before it starts, including serialized metadata.
            add_bytes(&mut total, selected_bytes)?;
            let mut selected_sources = Vec::with_capacity(selected.len());
            for (path, name, identity) in &selected {
                let member = copy_selected(&stage, path, name, identity.len(), identity)?;
                selected_sources.push(SelectedSource {
                    path: path
                        .to_str()
                        .ok_or_else(|| io_error("selected source path is not UTF-8"))?
                        .to_string(),
                    device: identity.dev(),
                    inode: identity.ino(),
                    logical_length: identity.len(),
                    physical_bytes: identity
                        .blocks()
                        .checked_mul(512)
                        .ok_or_else(|| io_error("source physical size overflow"))?,
                    archive_name: member.relative_path.clone(),
                    sha256: member.sha256,
                });
                members.push(member);
            }
            if bank.src.roots().iter().copied().collect::<BTreeSet<_>>()
                != roots.iter().copied().collect::<BTreeSet<_>>()
            {
                return Err(io_error("rooted cache changed during export"));
            }
            members.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
            let part = stage.join("archive.part");
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&part)?;
            let bounded = MaximumWriter {
                inner: file,
                bytes: 0,
                maximum: MAX_ARCHIVE_BYTES,
            };
            let encoder = BzEncoder::new(BufWriter::new(bounded), Compression::Fastest);
            let mut tar = tar::Builder::new(encoder);
            for member in &members {
                let path = stage.join(&member.relative_path);
                let (mut f, m) = source(&path, member.length)?;
                if m.len() != member.length
                    || measure(&stage, &path, member.length)?.sha256 != member.sha256
                {
                    return Err(io_error("staged snapshot member changed"));
                }
                let mut header = tar::Header::new_gnu();
                header.set_size(member.length);
                header.set_mode(0o600);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();
                tar.append_data(&mut header, &member.relative_path, &mut f)?;
                stable(&m, &fs::symlink_metadata(&path)?)?;
            }
            let mut compressed = tar.into_inner()?.finish()?;
            compressed.flush()?;
            compressed.get_ref().inner.sync_all()?;
            drop(compressed);
            let (mut persisted, identity) = source(&part, MAX_ARCHIVE_BYTES)?;
            let digest = hash_file(&mut persisted, identity.len())?;
            persisted.sync_all()?;
            File::open(&stage)?.sync_all()?;
            let manifest = Manifest {
                schema: "v1425-native-export-manifest-v1".into(),
                slot: bank.slot(),
                bank_hash: bank.hash().as_ref().to_vec(),
                accounts_hash: expected_hash.as_ref().to_vec(),
                last_blockhash: bank.last_blockhash().as_ref().to_vec(),
                capitalization: bank.capitalization(),
                transaction_count: bank.transaction_count(),
                tick_height: bank.tick_height(),
                slot_complete: bank.is_complete(),
                next_write_version: bank.accounts().accounts_db.next_write_version(),
                rooted_slots: roots.clone(),
                members,
                selected_sources,
                archive_name: final_name.clone(),
                archive_size: identity.len(),
                archive_sha256: digest,
            };
            let mut proof = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(stage.join("export-manifest.bin"))?;
            bincode::serialize_into(&mut proof, &manifest).map_err(|e| io_error(&e.to_string()))?;
            proof.sync_all()?;
            File::open(&stage)?.sync_all()?;
            validate_seal().map_err(|e| io_error(&e))?;
            if cache_seal(bank).map_err(|e| io_error(&e))? != cache {
                return Err(io_error("rooted cache changed before snapshot publication"));
            }
            stable(&identity, &fs::symlink_metadata(&part)?)?;
            publish_no_clobber(&part, &final_path)?;
            // rename may legitimately change ctime, while the descriptor/data
            // identity, length and mtime must remain exact.
            stable_contents(&identity, &fs::symlink_metadata(&final_path)?)?;
            Ok(ExportedSnapshot {
                archive_path: final_path,
                archive_size: identity.len(),
                archive_sha256: digest,
            })
        })();
        run.map_err(|e| e.to_string())
    })();
    result.map_err(|e| match retained {
        Some(path) => format!(
            "{}; retained native export evidence at {}",
            e,
            path.display()
        ),
        None => e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_clobber_and_aliases_preserve_existing_bytes() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        fs::write(&a, b"new").unwrap();
        fs::write(&b, b"old").unwrap();
        assert!(publish_no_clobber(&a, &b).is_err());
        assert_eq!(fs::read(&a).unwrap(), b"new");
        assert_eq!(fs::read(&b).unwrap(), b"old");
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&a, &alias).unwrap();
        assert!(source(&alias, 10).is_err());
        let hard = d.path().join("hard");
        fs::hard_link(&a, &hard).unwrap();
        assert!(source(&a, 10).is_err());
        let fifo = d.path().join("fifo");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(source(&fifo, 10).is_err());
    }
    #[test]
    fn bounded_writer_and_aggregate_refuse_overflow() {
        let mut w = MaximumWriter {
            inner: Vec::new(),
            bytes: 0,
            maximum: 3,
        };
        w.write_all(b"abc").unwrap();
        assert!(w.write_all(b"d").is_err());
        assert_eq!(w.inner, b"abc");
        let mut overflow = u64::MAX;
        assert!(add_bytes(&mut overflow, 1).is_err());
        let mut full = MAX_HANDOFF_ARCHIVE_EXTRACTED_SIZE;
        assert!(add_bytes(&mut full, 1).is_err());
    }
    #[test]
    fn selected_copy_detects_length_and_duplicate_destination_without_clobber() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("accounts")).unwrap();
        let input = d.path().join("0.0");
        fs::write(&input, b"selected").unwrap();
        let identity = fs::symlink_metadata(&input).unwrap();
        assert!(copy_selected(d.path(), &input, "0.0", 7, &identity).is_err());
        let member = copy_selected(d.path(), &input, "0.0", 8, &identity).unwrap();
        assert_eq!(member.length, 8);
        assert!(copy_selected(d.path(), &input, "0.0", 8, &identity).is_err());
        assert_eq!(
            fs::read(d.path().join("accounts/0.0")).unwrap(),
            b"selected"
        );
        fs::rename(&input, d.path().join("original-0.0")).unwrap();
        fs::write(&input, b"selected").unwrap();
        assert!(copy_selected(d.path(), &input, "0.1", 8, &identity).is_err());
        assert!(!d.path().join("accounts/0.1").exists());
    }
}
