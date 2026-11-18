//! Exact retirement of one obsolete private epoch 183 snapshot copy.
//! The sealed readerfix deployment snapshot remains the retained input.
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

const DEPLOYED: &str = "/usr/local/lib/jetstreamer/horizon-snapshot183-cleanup-20261118-v1/retire";
const RECEIPTS: &str = "/var/lib/jetstreamer/snapshot183-private-retire-20261118-v1";
const SNAP183: &str = "snapshot-79055145-5e31BTDw97vHrceMBBfs3LxxRDfgbDs4HeANxoJpB5VJ.tar.zst";
const SHA183: &str = "b70c5fe64956234181ecfb87d285b0cb09372a66d5ea5fab5a75cfc63dd15f00";
const SEALED183: &str = "/usr/local/lib/jetstreamer/deploy-epochs183-184-readerfix-20261020-v1/snapshot-79055145-5e31BTDw97vHrceMBBfs3LxxRDfgbDs4HeANxoJpB5VJ.tar.zst";

#[derive(Clone, Copy)]
struct Target {
    path: &'static str,
    inode: u64,
    blocks: u64,
    epoch: u64,
}

const TARGETS: [Target; 1] = [Target {
    path: "/home/sol/.jetstreamer-private/epochs175-200-20260922-v1/lane-k/private/destination-16846c94af4b82e80535dc5708f1da16a10dd2ec60011ca6aa20fc96a2b8a7ff/work/root-cohort-183-184/run-3093079-1791383571339178490/inputs/snapshot-79055145-5e31BTDw97vHrceMBBfs3LxxRDfgbDs4HeANxoJpB5VJ.tar.zst",
    inode: 103033905,
    blocks: 13754008,
    epoch: 183,
}];

fn epoch_info(epoch: u64) -> Result<(&'static str, &'static str, &'static str, u64)> {
    match epoch {
        183 => Ok((SEALED183, SHA183, SNAP183, 7_042_035_825)),
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

fn sealed_source(target: Target) -> Result<Value> {
    let (path, sha, name, length) = epoch_info(target.epoch)?;
    let path = Path::new(path);
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.file_type().is_file()
            && md.dev() != 64512
            && md.len() == length
            && md.uid() == 0
            && md.gid() == 0
            && md.mode() & 0o7777 == 0o444
            && md.nlink() == 1,
        "retained sealed input changed"
    );
    let seal_path = path
        .parent()
        .context("sealed parent")?
        .join("deployment-seal-receipt.json");
    let seal_md = fs::symlink_metadata(&seal_path)?;
    ensure!(
        seal_md.file_type().is_file()
            && seal_md.uid() == 0
            && seal_md.mode() & 0o222 == 0
            && seal_md.nlink() == 1
            && seal_md.len() <= 1 << 20,
        "sealed source receipt unsafe"
    );
    let mut seal_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&seal_path)?;
    ensure!(
        same_inode(&seal_md, &seal_file.metadata()?),
        "seal changed before read"
    );
    let mut seal_bytes = Vec::new();
    Read::by_ref(&mut seal_file)
        .take((1 << 20) + 1)
        .read_to_end(&mut seal_bytes)?;
    ensure!(
        same_inode(&seal_md, &seal_file.metadata()?)
            && same_inode(&seal_md, &fs::symlink_metadata(&seal_path)?)
            && seal_bytes.len() as u64 == seal_md.len(),
        "seal changed during read"
    );
    let seal: Value = serde_json::from_slice(&seal_bytes)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == path.parent().unwrap().to_str().unwrap()
            && seal["members"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|m| m["name"] == name
                    && m["sha256"] == sha
                    && m["bytes"] == length
                    && m["mode"] == "0444")),
        "sealed source receipt does not bind retained input"
    );
    ensure!(
        digest_file(path, &md)? == sha,
        "retained sealed input digest differs"
    );
    Ok(json!({"path":path,"sha256":sha,"length":length,
        "seal_receipt":seal_path,"seal_sha256":format!("{:x}", Sha256::digest(&seal_bytes)),
        "source_identity":metadata_identity(&md),"seal_identity":metadata_identity(&seal_md)}))
}

fn retained_unchanged(retained: &Value) -> Result<()> {
    let source = Path::new(retained["path"].as_str().context("retained source path")?);
    let seal = Path::new(
        retained["seal_receipt"]
            .as_str()
            .context("retained seal path")?,
    );
    ensure!(
        metadata_identity(&fs::symlink_metadata(source)?) == retained["source_identity"]
            && metadata_identity(&fs::symlink_metadata(seal)?) == retained["seal_identity"],
        "retained sealed source or receipt changed"
    );
    Ok(())
}

fn no_references(path: &Path) -> Result<Value> {
    let process = jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), path)?;
    ensure!(
        process.references.is_empty(),
        "target has live process references"
    );
    let staged = jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(path)?;
    ensure!(
        staged["references"] == json!([]),
        "target has staged systemd references"
    );
    Ok(json!({"process":process,"staged":staged}))
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
    let retained = sealed_source(target)?;
    ensure!(retained["path"] == sealed, "retained source changed");
    ensure!(
        digest_file(path, &md)? == sha,
        "private copy differs from sealed input"
    );
    let references = no_references(path)?;
    let before = json!({"schema":"horizon-private-snapshot183-retirement-before-v1",
        "index":selected,"epoch":target.epoch,"target":path,
        "dev":md.dev(),"inode":md.ino(),"length":md.len(),
        "allocated_bytes":md.blocks()*512,"sha256":sha,"retained_sealed":retained,
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
        &json!({"schema":"horizon-private-snapshot183-retirement-moved-v1",
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
        &json!({"schema":"horizon-private-snapshot183-retirement-unlink-intent-v1",
        "target":path,"quarantine":q,"inode":target.inode,
        "retained_sealed":sealed,"sha256":sha,"moved_sha256":moved_sha,
        "recorded_unix_seconds":now()?}),
    )?;
    let unlink_sha = receipt_sha(&unlink_intent)?;
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
        &json!({"schema":"horizon-private-snapshot183-retirement-completion-v1",
        "index":selected,"epoch":target.epoch,"target":path,"sha256":sha,
        "retired_allocated_bytes":target.blocks*512,"retained_sealed":sealed,
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
    }
    #[test]
    #[ignore = "native read-only consumer census; requires root and this host"]
    fn inspect_native_consumers() {
        for (index, target) in TARGETS.iter().enumerate() {
            println!(
                "target {index}: {:?}",
                no_references(Path::new(target.path))
            );
        }
    }
}
