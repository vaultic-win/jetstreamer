//! One closed failed-test tree relocation. No production archive or remote authority.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process::Command,
};
const ROOT: &str = "/var/lib/jetstreamer-checkpoint-fixtures/native-v1425-capped-20261023-v1";
const STATE: &str = "/var/lib/jetstreamer-v1425-native-fixture-retained-20261023-v2";
const NAME: &str = "attempt-132ade3e847047038dcca907dfe3c2ee";
const UNIT: &str = "horizon-v1425-native-portability-fixture-20261023-v1.service";
const IID: &str = "132ade3e847047038dcca907dfe3c2ee";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn private(p: &Path) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p && m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "unsafe private custody directory"
    );
    Ok(())
}
fn persist(p: &Path, v: &Value) -> Result<()> {
    private(p.parent().context("receipt parent")?)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    f.write_all(&serde_json::to_vec_pretty(v)?)?;
    f.sync_all()?;
    f.set_permissions(fs::Permissions::from_mode(0o400))?;
    f.sync_all()?;
    File::open(p.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn record(p: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(m) => {
            ensure!(
                p.canonicalize()? == p
                    && m.is_file()
                    && m.uid() == 0
                    && m.nlink() == 1
                    && m.mode() & 0o222 == 0
                    && m.len() <= 1 << 20,
                "unsafe custody record"
            );
            Ok(Some(serde_json::from_slice(&fs::read(p)?)?))
        }
    }
}
fn closed() -> Result<Value> {
    let o=Command::new("/usr/bin/systemctl").args(["show",UNIT,"--no-pager","--property=Id,InvocationID,MainPID,ActiveState,SubState,NRestarts,Result,ExecMainStatus,ControlGroup,Job"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 8192,
        "failed owner proof unavailable"
    );
    let mut m = serde_json::Map::new();
    for l in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = l.split_once('=').context("owner property")?;
        m.insert(k.into(), json!(v));
    }
    let v = Value::Object(m);
    ensure!(
        v["Id"] == UNIT
            && v["InvocationID"] == IID
            && v["MainPID"] == "0"
            && v["ActiveState"] == "failed"
            && v["SubState"] == "failed"
            && v["NRestarts"] == "0"
            && v["Result"] == "exit-code"
            && v["ExecMainStatus"] == "101"
            && v["ControlGroup"] == ""
            && v["Job"] == "",
        "failed fixture owner changed or not closed"
    );
    Ok(v)
}
fn id(p: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_dir()
            && m.dev() == 2304
            && m.uid() == 1001
            && m.gid() == 1001
            && m.mode() & 0o777 == 0o700,
        "wrong fixture root identity"
    );
    Ok(json!({"device":m.dev(),"inode":m.ino()}))
}
fn inventory(root: &Path) -> Result<Value> {
    let mut queue = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    let mut physical = 0u64;
    while let Some(p) = queue.pop() {
        ensure!(entries.len() < 65536, "fixture member bound");
        let before = fs::symlink_metadata(&p)?;
        ensure!(
            p.canonicalize()? == p
                && before.dev() == 2304
                && before.uid() == 1001
                && !before.file_type().is_symlink(),
            "foreign fixture member or alias"
        );
        physical = physical
            .checked_add(
                before
                    .blocks()
                    .checked_mul(512)
                    .context("physical overflow")?,
            )
            .context("physical sum")?;
        ensure!(physical <= 10 << 30, "failed fixture exceeds10GiB");
        let relative = p
            .strip_prefix(root)?
            .to_str()
            .context("fixture path encoding")?;
        let digest = if before.is_dir() {
            for e in fs::read_dir(&p)? {
                queue.push(e?.path());
            }
            File::open(&p)?.sync_all()?;
            Value::Null
        } else {
            ensure!(
                before.is_file() && before.nlink() == 1,
                "fixture nonregular member/hardlink"
            );
            let mut f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&p)?;
            ensure!(f.metadata()?.ino() == before.ino(), "fixture file changed");
            let mut h = Sha256::new();
            let mut b = [0u8; 65536];
            loop {
                let n = f.read(&mut b)?;
                if n == 0 {
                    break;
                }
                h.update(&b[..n]);
            }
            f.sync_all()?;
            let after = f.metadata()?;
            ensure!(
                before.len() == after.len()
                    && before.mtime() == after.mtime()
                    && before.mtime_nsec() == after.mtime_nsec()
                    && fs::symlink_metadata(&p)?.ino() == before.ino(),
                "fixture bytes changed during hash"
            );
            json!(format!("{:x}", h.finalize()))
        };
        entries.push(json!({"path":relative,"directory":before.is_dir(),"device":before.dev(),"inode":before.ino(),"uid":before.uid(),"gid":before.gid(),"mode":before.mode()&0o7777,"length":before.len(),"physical_bytes":before.blocks()*512,"mtime":before.mtime(),"mtime_nsec":before.mtime_nsec(),"sha256":digest}));
    }
    entries.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    ensure!(entries.len() > 1, "empty fixture is not failed evidence");
    Ok(json!({"entries":entries,"physical_bytes":physical}))
}
fn relocate(source: &Path, destination: &Path) -> Result<()> {
    let a = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let b = std::ffi::CString::new(destination.as_os_str().as_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "no-clobber failed fixture relocation: {}",
        std::io::Error::last_os_error()
    );
    File::open(source.parent().unwrap())?.sync_all()?;
    File::open(destination.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn empty_root(root: &Path) -> Result<Value> {
    match fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(root)?;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
            let c = std::ffi::CString::new(root.as_os_str().as_bytes())?;
            ensure!(
                unsafe { libc::chown(c.as_ptr(), 1001, 1001) } == 0,
                "fixture root chown failed"
            );
            File::open(root.parent().unwrap())?.sync_all()?;
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let identity = id(root)?;
    ensure!(
        fs::read_dir(root)?.next().is_none(),
        "new fixture root is not empty; preserve it"
    );
    Ok(identity)
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "retention requires root");
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 3 && a[1] == "--self-sha256" && sha(&fs::read("/proc/self/exe")?) == a[2],
        "retention executable binding"
    );
    let root = Path::new(ROOT);
    let state = Path::new(STATE);
    private(state)?;
    ensure!(
        fs::metadata(state)?.dev() == 2304 && fs::metadata(root.parent().unwrap())?.dev() == 2304,
        "retention must stay on OS device2304"
    );
    let destination = state.join(NAME);
    let intent = state.join("intent.json");
    let moved = state.join("moved.json");
    let completion = state.join("completion.json");
    let owner = closed()?;
    let descriptor = if let Some(old) = record(&intent)? {
        ensure!(
            old["schema"] == "jetstreamer-v1425-failed-fixture-retention-intent-v2"
                && old["source"] == ROOT
                && old["destination"] == destination.to_str().unwrap()
                && old["unit"] == UNIT
                && old["invocation_id"] == IID,
            "foreign retention intent"
        );
        old
    } else {
        ensure!(!destination.try_exists()?, "retained destination occupied");
        let original = id(root)?;
        let inv = inventory(root)?;
        let manifest_sha = sha(&serde_json::to_vec(&inv)?);
        let d = json!({"schema":"jetstreamer-v1425-failed-fixture-retention-intent-v2","source":ROOT,"destination":destination,"unit":UNIT,"invocation_id":IID,"original_root_identity":original,"inventory":inv,"inventory_sha256":manifest_sha,"stopped_owner":owner,"r2_mutations":false,"production_resume_qualified":false});
        persist(&intent, &d)?;
        d
    };
    if !destination.try_exists()? {
        ensure!(
            id(root)? == descriptor["original_root_identity"]
                && inventory(root)? == descriptor["inventory"],
            "source differs from closed inventory"
        );
        closed()?;
        relocate(root, &destination)?;
    }
    ensure!(
        id(&destination)? == descriptor["original_root_identity"]
            && inventory(&destination)? == descriptor["inventory"],
        "retained bytes/identity differ"
    );
    let moved_descriptor = json!({"intent_sha256":sha(&fs::read(&intent)?),"retained":destination,"inventory_sha256":descriptor["inventory_sha256"],"whole_tree_rehashed":true});
    match record(&moved)? {
        Some(old) => ensure!(old == moved_descriptor, "moved frontier conflicts"),
        None => persist(&moved, &moved_descriptor)?,
    };
    closed()?;
    let recreated = empty_root(root)?;
    ensure!(
        recreated != descriptor["original_root_identity"],
        "old root identity unexpectedly returned"
    );
    let done = json!({"schema":"jetstreamer-v1425-failed-fixture-local-custody-v2","source":ROOT,"retained":destination,"original_root_identity":descriptor["original_root_identity"],"new_empty_root_identity":recreated,"inventory_sha256":descriptor["inventory_sha256"],"retained_physical_bytes":descriptor["inventory"]["physical_bytes"],"same_filesystem_relocation":true,"source_and_destination_parents_fsynced":true,"whole_tree_rehashed":true,"old_invocation_id":IID,"original_bytes_deleted":false,"disk_space_reclaimed":false,"runtime_checkpoint_qualified":false,"production_resume_qualified":false,"r2_mutations":false});
    match record(&completion)? {
        Some(old) => ensure!(old == done, "retention completion conflicts"),
        None => persist(&completion, &done)?,
    };
    println!("{}", completion.display());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_fixture_tree_rehash_survives_same_device_no_clobber_move() {
        let parent = tempfile::Builder::new()
            .prefix("retain-fixture-")
            .tempdir_in("/var/lib/jetstreamer-v1425-os-guard-bootstrap-20261023-v1")
            .unwrap();
        let source = parent.path().join("source");
        let dest = parent.path().join("retained");
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(source.join("evidence"), b"exact failed evidence").unwrap();
        let before = inventory(&source).unwrap();
        let identity = id(&source).unwrap();
        relocate(&source, &dest).unwrap();
        assert_eq!(inventory(&dest).unwrap(), before);
        assert_eq!(id(&dest).unwrap(), identity);
        fs::create_dir(&source).unwrap();
        fs::write(source.join("new"), b"preserve").unwrap();
        assert!(relocate(&source, &dest).is_err());
        assert_eq!(fs::read(source.join("new")).unwrap(), b"preserve");
    }
    #[test]
    fn fixture_aliases_external_hardlinks_and_empty_roots_are_not_custody() {
        let parent = tempfile::Builder::new()
            .prefix("retain-reject-")
            .tempdir_in("/var/lib/jetstreamer-v1425-os-guard-bootstrap-20261023-v1")
            .unwrap();
        let root = parent.path().join("source");
        fs::create_dir(&root).unwrap();
        assert!(inventory(&root).is_err());
        fs::write(root.join("member"), b"native").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("alias")).unwrap();
        assert!(inventory(&root).is_err());
        fs::remove_file(root.join("alias")).unwrap();
        fs::hard_link(root.join("member"), parent.path().join("outside")).unwrap();
        assert!(inventory(&root).is_err());
    }
}
