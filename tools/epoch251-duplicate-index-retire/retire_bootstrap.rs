//! Retire the original epoch 251 bootstrap copy after the external owner and
//! scheduled-reader census. The separate, sealed production snapshot stays local.
#[path = "../native266-stopped-scratch/src/journal.rs"]
mod journal;

use std::ffi::CString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DIRECTORY: i32 = 0o200000;
const NOFOLLOW: i32 = 0o400000;
const DIR: &str = "/home/ubuntu/.jetstreamer-private/qualification-251-source-20261118-v1/input";
const KEEP: &str = "/var/lib/jetstreamer/horizon251-native-input-20261118-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon251-raw-bootstrap-retire-state-v174";
const NAME: &str = "snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst";
const QUARANTINE: &str = ".snapshot-108431365-inode-17816708-quarantine";
const DIGEST: &str = "b7af2058dd498bdf8c0f7e2a717a0d7c8153c20027eca2c3c2de15351b87b311";
const BYTES: u64 = 13_928_359_507;
const INTENT: &str = "251 66305 17816708 25590232 13928359507 b7af2058dd498bdf8c0f7e2a717a0d7c8153c20027eca2c3c2de15351b87b311\n";

unsafe extern "C" {
    fn renameat2(old: i32, from: *const i8, new: i32, to: *const i8, flags: u32) -> i32;
    fn unlinkat(dir: i32, name: *const i8, flags: i32) -> i32;
}

fn need(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn open(p: &Path, flags: i32) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(flags | NOFOLLOW)
        .open(p)
}
fn checked_dir(p: &str, inode: u64, mode: u32) -> io::Result<File> {
    let path = Path::new(p);
    need(path.canonicalize()? == path, "directory alias")?;
    let f = open(path, DIRECTORY)?;
    let m = f.metadata()?;
    need(
        (m.dev(), m.ino(), m.uid(), m.gid(), m.mode()) == (66305, inode, 0, 0, mode),
        "directory identity",
    )?;
    Ok(f)
}
fn child(dir: &File, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name)
}
fn ns(sec: i64, nsec: i64) -> i128 {
    i128::from(sec) * 1_000_000_000 + i128::from(nsec)
}
fn identity(m: &Metadata, raw: bool, quarantined: bool) -> io::Result<()> {
    let (ino, mode, mtime, ctime) = if raw {
        (17816708, 0o100400, 1794966334888919871, 1794966374072045002)
    } else {
        (25590232, 0o100444, 1794983008128161549, 1794983008128161549)
    };
    need(
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
        ) == (66305, ino, BYTES, mode, 0, 0, 1)
            && ns(m.mtime(), m.mtime_nsec()) == mtime
            && (quarantined || ns(m.ctime(), m.ctime_nsec()) == ctime),
        "snapshot identity",
    )
}
fn full(p: &Path, raw: bool, quarantined: bool) -> io::Result<()> {
    let f = open(p, 0)?;
    let before = f.metadata()?;
    identity(&before, raw, quarantined)?;
    let out = Command::new("/usr/bin/sha256sum")
        .env_clear()
        .stdin(Stdio::from(f.try_clone()?))
        .output()?;
    need(
        out.status.success() && out.stdout == format!("{DIGEST}  -\n").as_bytes(),
        "whole-file digest",
    )?;
    for m in [f.metadata()?, fs::symlink_metadata(p)?] {
        identity(&m, raw, quarantined)?;
        need(
            (m.ctime(), m.ctime_nsec()) == (before.ctime(), before.ctime_nsec()),
            "changed during hash",
        )?;
    }
    Ok(())
}
fn present(p: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
#[derive(Debug, PartialEq)]
enum Step {
    Move,
    Remove,
    Finish,
}
fn step(raw: bool, quarantined: bool, intent: bool, fenced: bool) -> io::Result<Step> {
    match (raw, quarantined, intent, fenced) {
        (true, false, _, false) => Ok(Step::Move),
        (false, true, true, _) => Ok(Step::Remove),
        (false, false, true, true) => Ok(Step::Finish),
        _ => Err(io::Error::other("unexpected retirement state")),
    }
}
fn run() -> io::Result<()> {
    need(
        std::env::args_os().collect::<Vec<_>>().get(1..)
            == Some(&[std::ffi::OsString::from("--retire")]),
        "expected --retire",
    )?;
    let iid = std::env::var("INVOCATION_ID").map_err(io::Error::other)?;
    need(
        iid.len() == 32 && iid.bytes().all(|v| v.is_ascii_hexdigit()),
        "invalid invocation",
    )?;
    let cg = fs::read_to_string("/proc/self/cgroup")?;
    let uid = cg
        .trim()
        .strip_prefix("0::/system.slice/horizon251-raw-bootstrap-retire-v174-a")
        .and_then(|x| x.strip_suffix(".service"))
        .ok_or_else(|| io::Error::other("wrong service"))?;
    need(
        !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()),
        "wrong service",
    )?;
    let state = journal::Journal::new(Path::new(STATE), 0)?;
    need(
        state.get(&format!("checked-{iid}"))?.as_deref() == Some(INTENT),
        "missing current locked reader and custody check",
    )?;
    let src = checked_dir(DIR, 17815016, 0o40700)?;
    let keep = checked_dir(KEEP, 25590231, 0o40555)?;
    let retained = child(&keep, NAME);
    full(&retained, false, false)?;
    let original = child(&src, NAME);
    let quarantine = child(&src, QUARANTINE);
    let from = CString::new(NAME)?;
    let to = CString::new(QUARANTINE)?;
    loop {
        let intent = state.get("intent")?;
        let fence = state.get("verified-quarantine")?;
        need(
            [intent.as_deref(), fence.as_deref()]
                .into_iter()
                .flatten()
                .all(|v| v == INTENT),
            "foreign receipt",
        )?;
        match step(
            present(&original)?,
            present(&quarantine)?,
            intent.is_some(),
            fence.is_some(),
        )? {
            Step::Move => {
                full(&original, true, false)?;
                state.put("intent", INTENT)?;
                identity(&fs::symlink_metadata(&original)?, true, false)?;
                if unsafe {
                    renameat2(
                        src.as_raw_fd(),
                        from.as_ptr(),
                        src.as_raw_fd(),
                        to.as_ptr(),
                        1,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                src.sync_all()?;
            }
            Step::Remove => {
                src.sync_all()?;
                full(&quarantine, true, true)?;
                state.put("verified-quarantine", INTENT)?;
                let f = open(&quarantine, 0)?;
                identity(&f.metadata()?, true, true)?;
                identity(&fs::symlink_metadata(&retained)?, false, false)?;
                identity(&fs::symlink_metadata(&quarantine)?, true, true)?;
                if unsafe { unlinkat(src.as_raw_fd(), to.as_ptr(), 0) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                need(f.metadata()?.nlink() == 0, "original inode still linked")?;
                src.sync_all()?;
            }
            Step::Finish => {
                src.sync_all()?;
                identity(&fs::symlink_metadata(&retained)?, false, false)?;
                state.put("complete", INTENT)?;
                println!("retired 66305:17816708; retained 66305:25590232 {DIGEST}");
                return Ok(());
            }
        }
    }
}
fn main() -> io::Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retries_each_durable_boundary() {
        assert_eq!(step(true, false, false, false).unwrap(), Step::Move);
        assert_eq!(step(true, false, true, false).unwrap(), Step::Move);
        assert_eq!(step(false, true, true, false).unwrap(), Step::Remove);
        assert_eq!(step(false, true, true, true).unwrap(), Step::Remove);
        assert_eq!(step(false, false, true, true).unwrap(), Step::Finish);
    }
    #[test]
    fn unexplained_names_or_missing_witness_stop() {
        for (raw, q, i, f) in [
            (false, false, false, false),
            (false, false, true, false),
            (false, true, false, false),
            (true, true, true, true),
            (true, false, true, true),
        ] {
            assert!(step(raw, q, i, f).is_err());
        }
    }
}
