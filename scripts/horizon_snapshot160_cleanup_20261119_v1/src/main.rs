//! Exact retirement of one obsolete private epoch 160 snapshot copy.
//! The legacy immutable deployment snapshot remains the retained input.
//! Its original checksums are authenticated explicitly, without claiming a normal seal.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const DEPLOYED: &str = "/usr/local/lib/jetstreamer/horizon-snapshot160-cleanup-20261119-v1/retire";
const RECEIPTS: &str = "/var/lib/jetstreamer/snapshot160-private-retire-20261119-v1";
const SNAP160: &str = "snapshot-69119821-BbTHV1PRmaBoqFSxKi1qGwwvsf6SeZPSW9KJj9wcDwEV.tar.zst";
const SHA160: &str = "7b9b9ca426c75b7c87b8b8441a2dbfdd99581b8d8cf6e38b77d8ce5928792316";
const RETAINED160: &str = "/usr/local/lib/jetstreamer/deploy-epoch160-singleton-20261020-v2/snapshot-69119821-BbTHV1PRmaBoqFSxKi1qGwwvsf6SeZPSW9KJj9wcDwEV.tar.zst";
const SUMS_SHA: &str = "15764186cf0f0e8f53a2623d4e85c2e9475c96e373688c03c748c664dc807ee2";
const MUTATION_LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";

#[derive(Clone, Copy)]
struct Target {
    path: &'static str,
    inode: u64,
    blocks: u64,
    epoch: u64,
}

const TARGETS: [Target; 1] = [Target {
    path: "/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1/bootstrap/inputs/snapshot-69119821-BbTHV1PRmaBoqFSxKi1qGwwvsf6SeZPSW9KJj9wcDwEV.tar.zst",
    inode: 99942493,
    blocks: 3538752,
    epoch: 160,
}];

fn epoch_info(epoch: u64) -> Result<(&'static str, &'static str, &'static str, u64)> {
    match epoch {
        160 => Ok((RETAINED160, SHA160, SNAP160, 1_811_832_913)),
        _ => anyhow::bail!("foreign epoch"),
    }
}

fn digest_file(path: &Path, expected: &fs::Metadata) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        same_inode(expected, &file.metadata()?),
        "file changed before hashing"
    );
    let mut hash = Sha256::new();
    let mut buf = [0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    ensure!(
        same_inode(expected, &file.metadata()?)
            && same_inode(expected, &fs::symlink_metadata(path)?),
        "file changed during hashing"
    );
    Ok(format!("{:x}", hash.finalize()))
}

fn same_inode(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
        && a.blocks() == b.blocks()
        && a.mode() == b.mode()
        && a.nlink() == b.nlink()
}

fn metadata_identity(md: &fs::Metadata) -> Value {
    json!([
        md.dev(),
        md.ino(),
        md.len(),
        md.mtime(),
        md.mtime_nsec(),
        md.ctime(),
        md.ctime_nsec(),
        md.blocks(),
        md.uid(),
        md.gid(),
        md.mode(),
        md.nlink()
    ])
}

fn exact_target(path: &Path, target: Target, length: u64) -> Result<fs::Metadata> {
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.file_type().is_file()
            && md.dev() == 64512
            && md.ino() == target.inode
            && md.len() == length
            && md.blocks() == target.blocks
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1,
        "target identity, permissions or allocation changed"
    );
    Ok(md)
}

fn manifest_entry(bytes: &[u8], name: &str, digest: &str) -> Result<()> {
    let text = std::str::from_utf8(bytes)?;
    let rows: Vec<_> = text
        .lines()
        .filter_map(|line| line.split_once("  "))
        .filter(|(_, member)| *member == name)
        .collect();
    ensure!(
        rows.len() == 1 && rows[0].0 == digest,
        "legacy manifest must bind the exact retained member once"
    );
    Ok(())
}

fn root_custody(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical retained ancestry"
    );
    for parent in path.ancestors().skip(1) {
        let md = fs::symlink_metadata(parent)?;
        ensure!(
            md.is_dir() && md.uid() == 0 && md.mode() & 0o022 == 0,
            "retained ancestor is writable or foreign-owned: {}",
            parent.display()
        );
    }
    Ok(())
}

fn retained_source(target: Target) -> Result<Value> {
    let (path, sha, name, length) = epoch_info(target.epoch)?;
    let path = Path::new(path);
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.file_type().is_file()
            && md.dev() == 2304
            && md.ino() == 6163778
            && md.len() == length
            && md.uid() == 0
            && md.gid() == 0
            && md.mode() & 0o7777 == 0o444
            && md.nlink() == 1,
        "retained legacy input changed"
    );
    root_custody(path)?;
    let manifest_path = path.parent().context("retained parent")?.join("SHA256SUMS");
    let manifest_md = fs::symlink_metadata(&manifest_path)?;
    ensure!(
        manifest_md.file_type().is_file()
            && manifest_md.dev() == 2304
            && manifest_md.ino() == 6163781
            && manifest_md.uid() == 0
            && manifest_md.gid() == 0
            && manifest_md.mode() & 0o7777 == 0o444
            && manifest_md.nlink() == 1
            && manifest_md.len() == 681,
        "legacy manifest custody changed"
    );
    let mut manifest_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&manifest_path)?;
    ensure!(
        same_inode(&manifest_md, &manifest_file.metadata()?),
        "manifest changed before read"
    );
    let mut manifest_bytes = Vec::new();
    Read::by_ref(&mut manifest_file)
        .take((1 << 20) + 1)
        .read_to_end(&mut manifest_bytes)?;
    ensure!(
        same_inode(&manifest_md, &manifest_file.metadata()?)
            && same_inode(&manifest_md, &fs::symlink_metadata(&manifest_path)?)
            && manifest_bytes.len() as u64 == manifest_md.len(),
        "manifest changed during read"
    );
    ensure!(
        format!("{:x}", Sha256::digest(&manifest_bytes)) == SUMS_SHA,
        "legacy manifest digest changed"
    );
    manifest_entry(&manifest_bytes, name, sha)?;
    ensure!(
        digest_file(path, &md)? == sha,
        "retained legacy input digest differs"
    );
    Ok(json!({"path":path,"sha256":sha,"length":length,
        "custody":"legacy root-owned immutable deployment plus pinned original SHA256SUMS and full file hash",
        "normal_deployment_seal_claimed":false,
        "manifest":manifest_path,"manifest_sha256":SUMS_SHA,
        "source_identity":metadata_identity(&md),"manifest_identity":metadata_identity(&manifest_md)}))
}

fn retained_unchanged(retained: &Value) -> Result<()> {
    let source = Path::new(retained["path"].as_str().context("retained source path")?);
    let manifest = Path::new(
        retained["manifest"]
            .as_str()
            .context("retained manifest path")?,
    );
    root_custody(source)?;
    ensure!(
        metadata_identity(&fs::symlink_metadata(source)?) == retained["source_identity"]
            && metadata_identity(&fs::symlink_metadata(manifest)?) == retained["manifest_identity"],
        "retained legacy source or manifest changed"
    );
    Ok(())
}

fn reference_scope(path: &Path) -> Result<&Path> {
    // The bootstrap owner can reopen any input by directory. Protect its full
    // exact root, including the quarantine path, rather than just a filename.
    let root = path
        .parent()
        .and_then(Path::parent)
        .context("bootstrap parent")?;
    ensure!(
        root == Path::new(
            "/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1/bootstrap"
        ) && path.parent() == Some(root.join("inputs").as_path()),
        "unexpected snapshot parent layout"
    );
    Ok(root)
}

fn no_references(path: &Path) -> Result<Value> {
    let run_root = reference_scope(path)?;
    let process =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), run_root)?;
    ensure!(
        process.references.is_empty(),
        "target has live process references"
    );
    let staged =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(run_root)?;
    ensure!(
        staged["references"] == json!([]),
        "target has staged systemd references: {}", staged["references"]
    );
    Ok(json!({"scope":run_root,"process":process,"staged":staged}))
}

fn private_dir(path: &Path) -> Result<()> {
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_dir() && md.uid() == 0 && md.mode() & 0o7777 == 0o700 && path.canonicalize()? == path,
        "unsafe receipt directory"
    );
    Ok(())
}

fn durable(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    private_dir(parent)?;
    ensure!(
        fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "retirement marker already exists"
    );
    let mut tmp = tempfile::Builder::new()
        .prefix(".snapshot-retire.")
        .tempfile_in(parent)?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), value)?;
    tmp.as_file_mut().write_all(b"\n")?;
    tmp.as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    tmp.as_file_mut().sync_all()?;
    let dest = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let source = std::ffi::CString::new(tmp.path().as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                dest.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "retirement marker collision: {}",
        std::io::Error::last_os_error()
    );
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn receipt_sha(path: &Path) -> Result<String> {
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.file_type().is_file()
            && md.uid() == 0
            && md.nlink() == 1
            && md.mode() & 0o7777 == 0o400
            && md.len() <= 1 << 20,
        "unsafe transition receipt"
    );
    digest_file(path, &md)
}

fn prepared_root() -> Result<PathBuf> {
    let root = PathBuf::from(RECEIPTS);
    if fs::symlink_metadata(&root).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        File::open(root.parent().context("receipt root parent")?)?.sync_all()?;
    }
    private_dir(&root)?;
    Ok(root)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn quarantine(path: &Path, target: Target) -> Result<PathBuf> {
    let parent = path.parent().context("target parent")?;
    Ok(parent.join(format!(
        ".snapshot-{}-inode{}-retiring",
        target.epoch, target.inode
    )))
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 5
            && matches!(args[1].as_str(), "--check-only" | "--retire")
            && args[3] == "--self-sha256",
        "usage: retire (--check-only|--retire) INDEX --self-sha256 SHA"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let exe = fs::read_link("/proc/self/exe")?;
    ensure!(exe == Path::new(DEPLOYED), "sealed cleanup image required");
    let executable = fs::symlink_metadata(&exe)?;
    ensure!(
        executable.is_file() && executable.uid() == 0 && executable.mode() & 0o222 == 0,
        "mutable cleanup executable"
    );
    ensure!(
        digest_file(&exe, &executable)? == args[4],
        "cleanup image digest differs"
    );
    let selected: usize = args[2].parse()?;
    let target = *TARGETS.get(selected).context("unknown target index")?;
    let (sealed, sha, _, length) = epoch_info(target.epoch)?;
    let shared_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(MUTATION_LOCK)?;
    let shared_md = shared_lock.metadata()?;
    ensure!(
        shared_md.is_file()
            && shared_md.dev() == 64512
            && shared_md.ino() == 101135013
            && shared_md.uid() == 1001
            && shared_md.gid() == 1003
            && shared_md.mode() & 0o7777 == 0o600
            && shared_md.nlink() == 1,
        "shared mutation lock changed"
    );
    ensure!(
        unsafe { libc::flock(shared_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "shared mutation lock busy"
    );
    let root = prepared_root()?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join("transition.lock"))?;
    let lock_md = lock.metadata()?;
    ensure!(
        lock_md.is_file() && lock_md.uid() == 0 && lock_md.mode() & 0o7777 == 0o600,
        "unsafe cleanup lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another cleanup transition is active"
    );
    let path = Path::new(target.path);
    ensure!(
        path.is_absolute() && path.starts_with("/home/sol/.jetstreamer-private"),
        "target path changed"
    );
    let md = exact_target(path, target, length)?;
    let retained = retained_source(target)?;
    ensure!(retained["path"] == sealed, "retained source changed");
    ensure!(
        digest_file(path, &md)? == sha,
        "private copy differs from retained immutable input"
    );
    let references = no_references(path)?;
    let before = json!({"schema":"horizon-private-snapshot160-retirement-before-v1",
        "index":selected,"epoch":target.epoch,"target":path,
        "dev":md.dev(),"inode":md.ino(),"length":md.len(),
        "allocated_bytes":md.blocks()*512,"sha256":sha,"retained_legacy_input":retained,
        "shared_mutation_lock":{"path":MUTATION_LOCK,"identity":metadata_identity(&shared_md)},
        "references":references,"recorded_unix_seconds":now()?,
        "remote_mutations":false,"r2_mutations":false});
    if args[1] == "--check-only" {
        println!("{}", serde_json::to_string(&before)?);
        return Ok(());
    }
    let base = format!("target-{selected}");
    let intent = root.join(format!("{base}-before.json"));
    let moved = root.join(format!("{base}-moved.json"));
    let unlink_intent = root.join(format!("{base}-unlink-intent.json"));
    let completion = root.join(format!("{base}-completion.json"));
    for marker in [&intent, &moved, &unlink_intent, &completion] {
        ensure!(
            fs::symlink_metadata(marker).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "existing transition requires manual recovery: {}",
            marker.display()
        );
    }
    durable(&intent, &before)?;
    let before_sha = receipt_sha(&intent)?;
    let q = quarantine(path, target)?;
    ensure!(
        fs::symlink_metadata(&q).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "quarantine path already exists"
    );
    let src = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let dst = std::ffi::CString::new(q.as_os_str().as_encoded_bytes())?;
    ensure!(
        same_inode(&md, &fs::symlink_metadata(path)?),
        "target changed before quarantine"
    );
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                src.as_ptr(),
                libc::AT_FDCWD,
                dst.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "quarantine rename failed: {}",
        std::io::Error::last_os_error()
    );
    File::open(path.parent().unwrap())?.sync_all()?;
    let qmd = exact_target(&q, target, length).context("quarantined target changed")?;
    durable(
        &moved,
        &json!({"schema":"horizon-private-snapshot160-retirement-moved-v1",
        "before_sha256":before_sha,"quarantine":q,"recorded_unix_seconds":now()?}),
    )?;
    let moved_sha = receipt_sha(&moved)?;
    ensure!(
        digest_file(&q, &qmd)? == sha,
        "quarantined copy digest differs"
    );
    let _ = no_references(&q)?;
    retained_unchanged(&retained)?;
    durable(
        &unlink_intent,
        &json!({"schema":"horizon-private-snapshot160-retirement-unlink-intent-v1",
        "target":path,"quarantine":q,"inode":target.inode,
        "retained_legacy_input":sealed,"sha256":sha,"moved_sha256":moved_sha,
        "recorded_unix_seconds":now()?}),
    )?;
    let unlink_sha = receipt_sha(&unlink_intent)?;
    let _ = no_references(&q)?;
    retained_unchanged(&retained)?;
    ensure!(
        same_inode(&shared_md, &fs::symlink_metadata(MUTATION_LOCK)?),
        "shared lock changed before unlink"
    );
    ensure!(
        same_inode(&qmd, &fs::symlink_metadata(&q)?),
        "quarantine changed before unlink"
    );
    fs::remove_file(&q)?;
    File::open(path.parent().unwrap())?.sync_all()?;
    ensure!(
        fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            && fs::symlink_metadata(&q).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "target or quarantine remains"
    );
    retained_unchanged(&retained)?;
    durable(
        &completion,
        &json!({"schema":"horizon-private-snapshot160-retirement-completion-v1",
        "index":selected,"epoch":target.epoch,"target":path,"sha256":sha,
        "retired_allocated_bytes":target.blocks*512,"retained_legacy_input":sealed,
        "unlink_intent_sha256":unlink_sha,
        "source_absent":true,"quarantine_absent":true,"recorded_unix_seconds":now()?,
        "actual_free_delta_claimed":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("{}", completion.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_target_is_private_and_has_a_distinct_inode() {
        let mut ids = std::collections::BTreeSet::new();
        for target in TARGETS {
            assert!(target.path.starts_with("/home/sol/.jetstreamer-private/"));
            assert!(target.path.ends_with(epoch_info(target.epoch).unwrap().2));
            assert!(ids.insert(target.inode));
            assert!(target.blocks > 0);
        }
        assert_eq!(ids.len(), 1);
        assert!(epoch_info(151).is_err());
        assert!(epoch_info(183).is_err());
    }
    #[test]
    fn reference_scope_preserves_bootstrap_and_rejects_foreign_paths() {
        let original = Path::new(TARGETS[0].path);
        let scope = reference_scope(original).unwrap();
        assert_eq!(
            reference_scope(&quarantine(original, TARGETS[0]).unwrap()).unwrap(),
            scope
        );
        assert!(reference_scope(Path::new("/home/sol/.jetstreamer-private/epoch161-singleton-20261020-v1/bootstrap/inputs/snapshot")).is_err());
        assert!(reference_scope(Path::new("/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1/other/inputs/snapshot")).is_err());
    }
    #[test]
    fn manifest_rejects_missing_foreign_and_duplicate_member() {
        let correct = format!("{SHA160}  {SNAP160}\n");
        manifest_entry(correct.as_bytes(), SNAP160, SHA160).unwrap();
        assert!(manifest_entry(b"", SNAP160, SHA160).is_err());
        assert!(manifest_entry(correct.as_bytes(), "other", SHA160).is_err());
        assert!(manifest_entry(correct.as_bytes(), SNAP160, "wrong").is_err());
        assert!(manifest_entry(format!("{correct}{correct}").as_bytes(), SNAP160, SHA160).is_err());
    }
    #[test]
    fn stable_hash_rejects_changed_file_and_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("snapshot");
        fs::write(&file, b"before").unwrap();
        let before = fs::symlink_metadata(&file).unwrap();
        assert_eq!(
            digest_file(&file, &before).unwrap(),
            format!("{:x}", Sha256::digest(b"before"))
        );
        fs::write(&file, b"after-longer").unwrap();
        assert!(digest_file(&file, &before).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(digest_file(&link, &fs::symlink_metadata(&file).unwrap()).is_err());
    }
    #[test]
    fn quarantine_stays_in_exact_input_directory() {
        for target in TARGETS {
            let original = Path::new(target.path);
            let q = quarantine(original, target).unwrap();
            assert_eq!(q.parent(), original.parent());
            assert_eq!(
                q.file_name().unwrap().to_str().unwrap(),
                format!(".snapshot-160-inode{}-retiring", target.inode)
            );
        }
    }
    #[test]
    #[ignore = "native read-only consumer census; requires root and this host"]
    fn inspect_native_consumers() {
        let retained = retained_source(TARGETS[0]).unwrap();
        for (index, target) in TARGETS.iter().enumerate() {
            let path = Path::new(target.path);
            let md = exact_target(path, *target, 1_811_832_913).unwrap();
            assert_eq!(digest_file(path, &md).unwrap(), SHA160);
            println!("target {index}: {}", no_references(path).unwrap());
        }
        retained_unchanged(&retained).unwrap();
        println!("retained={retained}");
    }
}
