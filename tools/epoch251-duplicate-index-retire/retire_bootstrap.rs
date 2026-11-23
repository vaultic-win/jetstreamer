//! Retire an enrolled bootstrap acquisition copy after the external owner and
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
const DEVICE: u64 = 66305;

struct Snapshot {
    directory: &'static str,
    directory_inode: u64,
    inode: u64,
    mode: u32,
    mtime: i128,
    ctime: i128,
}

struct Profile {
    epoch: u32,
    acquisition: Snapshot,
    retained: Snapshot,
    state: &'static str,
    unit_prefix: &'static str,
    name: &'static str,
    quarantine: &'static str,
    digest: &'static str,
    bytes: u64,
}

const EPOCH_251: Profile = Profile {
    epoch: 251,
    acquisition: Snapshot {
        directory: "/home/ubuntu/.jetstreamer-private/qualification-251-source-20261118-v1/input",
        directory_inode: 17815016,
        inode: 17816708,
        mode: 0o100400,
        mtime: 1794966334888919871,
        ctime: 1794966374072045002,
    },
    retained: Snapshot {
        directory: "/var/lib/jetstreamer/horizon251-native-input-20261118-v1",
        directory_inode: 25590231,
        inode: 25590232,
        mode: 0o100444,
        mtime: 1794983008128161549,
        ctime: 1794983008128161549,
    },
    state: "/var/lib/jetstreamer/horizon251-raw-bootstrap-retire-state-v174",
    unit_prefix: "horizon251-raw-bootstrap-retire-v174-a",
    name: "snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst",
    quarantine: ".snapshot-108431365-inode-17816708-quarantine",
    digest: "b7af2058dd498bdf8c0f7e2a717a0d7c8153c20027eca2c3c2de15351b87b311",
    bytes: 13_928_359_507,
};

const EPOCH_223: Profile = Profile {
    epoch: 223,
    acquisition: Snapshot {
        directory: "/var/lib/jetstreamer/horizon-223-bootstrap-stage-ab8b843-v1/download",
        directory_inode: 230564162,
        inode: 230564163,
        mode: 0o100400,
        mtime: 1792610485253419684,
        ctime: 1792610486237416761,
    },
    retained: Snapshot {
        directory: "/var/lib/jetstreamer/horizon-223-singleton-postcount-ad1d65a-v1",
        directory_inode: 230564216,
        inode: 230564220,
        mode: 0o100444,
        mtime: 1792611457988548390,
        ctime: 1792611457989548387,
    },
    state: "/var/lib/jetstreamer/horizon223-raw-bootstrap-retire-state-v236",
    unit_prefix: "horizon223-raw-bootstrap-retire-v236-a",
    name: "snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst",
    quarantine: ".snapshot-96335538-inode-230564163-quarantine",
    digest: "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665",
    bytes: 9_815_262_303,
};

impl Profile {
    fn intent(&self) -> String {
        format!(
            "{} {DEVICE} {} {} {} {}\n",
            self.epoch, self.acquisition.inode, self.retained.inode, self.bytes, self.digest
        )
    }
}

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
fn checked_dir(snapshot: &Snapshot, mode: u32) -> io::Result<File> {
    let path = Path::new(snapshot.directory);
    need(path.canonicalize()? == path, "directory alias")?;
    let f = open(path, DIRECTORY)?;
    let m = f.metadata()?;
    need(
        (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())
            == (DEVICE, snapshot.directory_inode, 0, 0, mode),
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
fn identity(m: &Metadata, snapshot: &Snapshot, bytes: u64, quarantined: bool) -> io::Result<()> {
    need(
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
        ) == (DEVICE, snapshot.inode, bytes, snapshot.mode, 0, 0, 1)
            && ns(m.mtime(), m.mtime_nsec()) == snapshot.mtime
            && (quarantined || ns(m.ctime(), m.ctime_nsec()) == snapshot.ctime),
        "snapshot identity",
    )
}
fn full(p: &Path, expected: &Snapshot, profile: &Profile, quarantined: bool) -> io::Result<()> {
    let f = open(p, 0)?;
    let before = f.metadata()?;
    identity(&before, expected, profile.bytes, quarantined)?;
    let out = Command::new("/usr/bin/sha256sum")
        .env_clear()
        .stdin(Stdio::from(f.try_clone()?))
        .output()?;
    need(
        out.status.success() && out.stdout == format!("{}  -\n", profile.digest).as_bytes(),
        "whole-file digest",
    )?;
    for m in [f.metadata()?, fs::symlink_metadata(p)?] {
        identity(&m, expected, profile.bytes, quarantined)?;
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
fn run(profile: &Profile) -> io::Result<()> {
    let iid = std::env::var("INVOCATION_ID").map_err(io::Error::other)?;
    need(
        iid.len() == 32 && iid.bytes().all(|v| v.is_ascii_hexdigit()),
        "invalid invocation",
    )?;
    let cg = fs::read_to_string("/proc/self/cgroup")?;
    let uid = cg
        .trim()
        .strip_prefix("0::/system.slice/")
        .and_then(|x| x.strip_prefix(profile.unit_prefix))
        .and_then(|x| x.strip_suffix(".service"))
        .ok_or_else(|| io::Error::other("wrong service"))?;
    need(
        !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()),
        "wrong service",
    )?;
    let state = journal::Journal::new(Path::new(profile.state), 0)?;
    let expected = profile.intent();
    need(
        state.get(&format!("checked-{iid}"))?.as_deref() == Some(expected.as_str()),
        "missing current locked reader and custody check",
    )?;
    let src = checked_dir(&profile.acquisition, 0o40700)?;
    let keep = checked_dir(&profile.retained, 0o40555)?;
    let retained = child(&keep, profile.name);
    full(&retained, &profile.retained, profile, false)?;
    let original = child(&src, profile.name);
    let quarantine = child(&src, profile.quarantine);
    let from = CString::new(profile.name)?;
    let to = CString::new(profile.quarantine)?;
    loop {
        let intent = state.get("intent")?;
        let fence = state.get("verified-quarantine")?;
        need(
            [intent.as_deref(), fence.as_deref()]
                .into_iter()
                .flatten()
                .all(|v| v == expected),
            "foreign receipt",
        )?;
        match step(
            present(&original)?,
            present(&quarantine)?,
            intent.is_some(),
            fence.is_some(),
        )? {
            Step::Move => {
                full(&original, &profile.acquisition, profile, false)?;
                state.put("intent", &expected)?;
                identity(
                    &fs::symlink_metadata(&original)?,
                    &profile.acquisition,
                    profile.bytes,
                    false,
                )?;
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
                full(&quarantine, &profile.acquisition, profile, true)?;
                state.put("verified-quarantine", &expected)?;
                let f = open(&quarantine, 0)?;
                identity(&f.metadata()?, &profile.acquisition, profile.bytes, true)?;
                identity(
                    &fs::symlink_metadata(&retained)?,
                    &profile.retained,
                    profile.bytes,
                    false,
                )?;
                identity(
                    &fs::symlink_metadata(&quarantine)?,
                    &profile.acquisition,
                    profile.bytes,
                    true,
                )?;
                if unsafe { unlinkat(src.as_raw_fd(), to.as_ptr(), 0) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                need(f.metadata()?.nlink() == 0, "original inode still linked")?;
                src.sync_all()?;
            }
            Step::Finish => {
                src.sync_all()?;
                identity(
                    &fs::symlink_metadata(&retained)?,
                    &profile.retained,
                    profile.bytes,
                    false,
                )?;
                state.put("complete", &expected)?;
                println!(
                    "retired {DEVICE}:{}; retained {DEVICE}:{} {}",
                    profile.acquisition.inode, profile.retained.inode, profile.digest
                );
                return Ok(());
            }
        }
    }
}
fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let profile = match args.as_slice() {
        [mode] if mode == "--retire" => &EPOCH_251,
        [mode] if mode == "--retire-223" => &EPOCH_223,
        _ => return Err(io::Error::other("expected --retire or --retire-223")),
    };
    run(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acquisition_profiles_keep_distinct_durable_witnesses() {
        assert_eq!(
            EPOCH_251.intent(),
            "251 66305 17816708 25590232 13928359507 b7af2058dd498bdf8c0f7e2a717a0d7c8153c20027eca2c3c2de15351b87b311\n"
        );
        assert_eq!(
            EPOCH_223.intent(),
            "223 66305 230564163 230564220 9815262303 301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665\n"
        );
        assert_ne!(EPOCH_223.state, EPOCH_251.state);
        assert_ne!(EPOCH_223.unit_prefix, EPOCH_251.unit_prefix);
    }
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
