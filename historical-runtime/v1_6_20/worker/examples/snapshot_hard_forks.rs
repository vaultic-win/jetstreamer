//! Read-only native snapshot metadata audit. No restore, replay or publication.
#[allow(dead_code)]
#[path = "../src/snapshot.rs"]
mod snapshot;
// Reuse the actual worker modules for its existing snapshot tests; no stubs or
// skipped restoration tests are introduced by the metadata example.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../src/leader_schedule.rs"]
mod leader_schedule;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../src/poh_backend.rs"]
mod poh_backend;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../src/runtime.rs"]
mod runtime;
use sha2_fast::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
#[derive(PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    mode: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn identity(m: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: m.dev(),
        inode: m.ino(),
        bytes: m.len(),
        uid: m.uid(),
        mode: m.mode(),
        links: m.nlink(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    }
}
fn hash<R: Read>(r: &mut R) -> Result<String, String> {
    let mut h = Sha256::new();
    let mut b = vec![0; 1024 * 1024];
    loop {
        let n = r.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn run() -> Result<(), String> {
    let a: Vec<_> = env::args().collect();
    if a.len() != 6 || a[4] != "--self-sha256" {
        return Err("usage: SNAPSHOT SHA256 OUTPUT --self-sha256 HEX".into());
    }
    let mut exe = File::open("/proc/self/exe").map_err(|e| e.to_string())?;
    if hash(&mut exe)? != a[5] {
        return Err("wrong running executable".into());
    }
    let path = Path::new(&a[1]);
    if path.canonicalize().map_err(|e| e.to_string())? != path
        || !a[2]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || a[2].len() != 64
    {
        return Err("noncanonical input or digest".into());
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let before = f.metadata().map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o222 != 0
        || before.len() > 20 * 1024 * 1024 * 1024
    {
        return Err("unsafe immutable snapshot".into());
    }
    if hash(&mut f)? != a[2] {
        return Err("snapshot SHA256 mismatch".into());
    }
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("snapshot name")?;
    let parts: Vec<_> = name.split('-').collect();
    if parts.len() != 3 || parts[0] != "snapshot" || !parts[2].ends_with(".tar.zst") {
        return Err("wrong snapshot filename".into());
    }
    let slot: u64 = parts[1].parse().map_err(|_| "invalid snapshot slot")?;
    let decoder = zstd::stream::read::Decoder::new(BufReader::new(f)).map_err(|e| e.to_string())?;
    let metadata = snapshot::snapshot_hard_forks(decoder, slot)?;
    if identity(&before) != identity(&fs::symlink_metadata(path).map_err(|e| e.to_string())?) {
        return Err("snapshot changed during metadata read".into());
    }
    let output = Path::new(&a[3]);
    let parent = output.parent().ok_or("output parent")?;
    let pm = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !output.is_absolute()
        || parent.canonicalize().map_err(|e| e.to_string())? != parent
        || !pm.is_dir()
        || pm.uid() != 0
        || pm.mode() & 0o077 != 0
    {
        return Err("output parent must be root-private".into());
    }
    let value = serde_json::json!({"schema":"jetstreamer-private-v1620-snapshot-hard-fork-metadata-v1","snapshot":a[1],"snapshot_sha256":a[2],"snapshot_bytes":before.len(),"slot":metadata.slot,"bank_hash":metadata.bank_hash.to_string(),"parent_slot":metadata.parent_slot,"hard_forks":metadata.hard_forks,"self_sha256":a[5],"accounts_restored":false,"bank_frozen":false,"snapshot_verified":false,"replay_authorized":false,"publication_authorized":false,"remote_mutations":false});
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)
        .map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut out, &value).map_err(|e| e.to_string())?;
    out.write_all(b"\n").map_err(|e| e.to_string())?;
    out.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|e| e.to_string())?;
    out.sync_all().map_err(|e| e.to_string())?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("snapshot metadata failed closed: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod metadata_tests {
    #[test]
    fn whole_file_hasher_uses_canonical_sha256() {
        assert_eq!(
            super::hash(&mut std::io::Cursor::new(b"abc")).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
