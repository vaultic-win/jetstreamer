//! No-clobber preservation of the positively stopped first native 227 attempt.
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
const SOURCE: &str = "/home/ubuntu/.jetstreamer-private/native-input227-v1620-capped-v1";
const DEST: &str =
    "/home/ubuntu/.jetstreamer-private/native-input227-attempt1-216c2d0e-retained-v1";
const EVIDENCE: &str = "/var/lib/jetstreamer/horizon-227-native-attempt1-failure-v1/attempt.json";
const EVIDENCE_SHA: &str = "c5eed6075c38e3952a93032dd8efae053786427cc6275e31aba160206d14a219";
fn stopped() -> Result<()> {
    let o = Command::new("/usr/bin/systemctl").args(["show", "horizon-native-input-227-capped-710f6523-v1.service", "--property=ActiveState,MainPID,ControlGroup,InvocationID,Restart,NRestarts,Job,Triggers,TriggeredBy"]).output()?;
    ensure!(o.status.success(), "manager query failed");
    let s = std::str::from_utf8(&o.stdout)?;
    for line in [
        "ActiveState=inactive",
        "MainPID=0",
        "ControlGroup=",
        "InvocationID=",
        "Restart=no",
        "NRestarts=0",
        "Job=",
        "Triggers=",
        "TriggeredBy=",
    ] {
        ensure!(s.lines().any(|l| l == line), "not stopped: {line}");
    }
    let cgroup = Path::new(
        "/sys/fs/cgroup/system.slice/horizon-native-input-227-capped-710f6523-v1.service/cgroup.procs",
    );
    match fs::read_to_string(cgroup) {
        Ok(pids) => ensure!(pids.trim().is_empty(), "cgroup not empty"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn rename_no_clobber(source: &Path, dest: &Path) -> Result<()> {
    let a = CString::new(source.as_os_str().as_encoded_bytes())?;
    let b = CString::new(dest.as_os_str().as_encoded_bytes())?;
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
        "rename refused: {}",
        std::io::Error::last_os_error()
    );
    File::open(source.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 3 && args[1] == "--self-sha256",
        "root and self digest required"
    );
    ensure!(
        format!("{:x}", Sha256::digest(fs::read("/proc/self/exe")?)) == args[2],
        "self digest differs"
    );
    ensure!(
        format!("{:x}", Sha256::digest(fs::read(EVIDENCE)?)) == EVIDENCE_SHA,
        "attempt evidence differs"
    );
    let source = Path::new(SOURCE);
    let dest = Path::new(DEST);
    let parent = source.parent().unwrap();
    ensure!(parent.canonicalize()? == parent, "noncanonical parent");
    stopped()?;
    let intent_path = parent.join("native-input227-attempt1-retain-intent-v1.json");
    let intent = serde_json::to_vec(
        &serde_json::json!({"schema":"jetstreamer-private-epoch227-retain-intent-v1","source":SOURCE,"retained":DEST,"inode":71249982u64,"device":66305u64,"owner_invocation_id":"216c2d0e7d5b4bd6bc843063255251f1","attempt_evidence_sha256":EVIDENCE_SHA}),
    )?;
    if intent_path.exists() {
        ensure!(fs::read(&intent_path)? == intent, "intent differs");
    } else {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&intent_path)?;
        f.write_all(&intent)?;
        f.sync_all()?;
        File::open(parent)?.sync_all()?;
    }
    let source_meta = fs::symlink_metadata(source).ok();
    let retained_meta = fs::symlink_metadata(dest).ok();
    let m = match (source_meta, retained_meta) {
        (Some(m), None) => {
            ensure!(
                m.is_dir()
                    && m.uid() == 1000
                    && m.mode() & 0o077 == 0
                    && m.ino() == 71249982
                    && m.dev() == 66305,
                "source identity changed"
            );
            stopped()?;
            rename_no_clobber(source, dest)?;
            m
        }
        (None, Some(m)) => {
            ensure!(
                m.is_dir() && m.ino() == 71249982 && m.dev() == 66305 && m.uid() == 1000,
                "retained identity changed"
            );
            m
        }
        _ => anyhow::bail!("source/destination ambiguity"),
    };
    stopped()?;
    let receipt = serde_json::to_vec(
        &serde_json::json!({"schema":"jetstreamer-private-epoch227-retained-attempt-v1", "source":SOURCE,"retained":DEST,"inode":m.ino(),"device":m.dev(),"attempt_evidence":{"path":EVIDENCE,"sha256":EVIDENCE_SHA},"owner_invocation_id":"216c2d0e7d5b4bd6bc843063255251f1","active_owner":false,"replay_launch_authorized":false,"r2_mutations":false,"scratch_deleted":false}),
    )?;
    let receipt_path = parent.join("native-input227-attempt1-retained-receipt-v1.json");
    if receipt_path.exists() {
        ensure!(fs::read(&receipt_path)? == receipt, "receipt differs");
    } else {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&receipt_path)?;
        f.write_all(&receipt)?;
        f.sync_all()?;
        File::open(parent)?.sync_all()?;
    }
    println!("{}", String::from_utf8(receipt)?);
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
    fn rename_preserves_existing_target() {
        let t = tempfile::tempdir().unwrap();
        let a = t.path().join("a");
        let b = t.path().join("b");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        assert!(rename_no_clobber(&a, &b).is_err());
        assert!(a.is_dir() && b.is_dir());
        fs::remove_dir(&b).unwrap();
        rename_no_clobber(&a, &b).unwrap();
        assert!(!a.exists() && b.is_dir());
    }
}
