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
    directory_mode: u32,
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
        directory_mode: 0o40700,
        inode: 17816708,
        mode: 0o100400,
        mtime: 1794966334888919871,
        ctime: 1794966374072045002,
    },
    retained: Snapshot {
        directory: "/var/lib/jetstreamer/horizon251-native-input-20261118-v1",
        directory_inode: 25590231,
        directory_mode: 0o40555,
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
        directory_mode: 0o40700,
        inode: 230564163,
        mode: 0o100400,
        mtime: 1792610485253419684,
        ctime: 1792610486237416761,
    },
    retained: Snapshot {
        directory: "/var/lib/jetstreamer/horizon-223-singleton-postcount-ad1d65a-v1",
        directory_inode: 230564216,
        directory_mode: 0o40555,
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

const fn sealed_snapshot(
    directory: &'static str,
    directory_inode: u64,
    inode: u64,
    mtime: i128,
    ctime: i128,
) -> Snapshot {
    Snapshot {
        directory,
        directory_inode,
        directory_mode: 0o40555,
        inode,
        mode: 0o100444,
        mtime,
        ctime,
    }
}

const EPOCH_228_CACHE: Profile = Profile {
    epoch: 228,
    acquisition: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-contiguous-228-230-cached-602556d-v1",
        70497457,
        70497461,
        1791622250934387206,
        1791622250945387172,
    ),
    retained: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-contiguous-228-230-current-46b4b4a-v1",
        12293477,
        12294366,
        1792002794398077847,
        1792002794398077847,
    ),
    state: "/var/lib/jetstreamer/horizon-bootstrap-cache228-retire-v239",
    unit_prefix: "horizon-bootstrap-cache228-retire-v239-a",
    name: "snapshot-98495291-GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq.tar.zst",
    quarantine: ".snapshot-98495291-inode-70497461-quarantine",
    digest: "da26bd1b4b3b93be74c9dae28d1d982f821474333aa06e87f32dfa83342915f3",
    bytes: 10_510_540_911,
};

const EPOCH_231_CACHE: Profile = Profile {
    epoch: 231,
    acquisition: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-contiguous-231-232-cached-602556d-v1",
        70497463,
        70497468,
        1791622259117361976,
        1791622259130361936,
    ),
    retained: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-contiguous-231-232-current-46b4b4a-v1",
        12293159,
        12293295,
        1792002806903012631,
        1792002806904012626,
    ),
    state: "/var/lib/jetstreamer/horizon-bootstrap-cache231-retire-v239",
    unit_prefix: "horizon-bootstrap-cache231-retire-v239-a",
    name: "snapshot-99791404-Hn6PFpfb4b63XELLfqGYLbFk8c8hJtujeQbFR1WmNW84.tar.zst",
    quarantine: ".snapshot-99791404-inode-70497468-quarantine",
    digest: "2992a8234c790c0feb836b933b68665b223107b0838c23eee32219ce5dc4f9ca",
    bytes: 10_615_540_172,
};

const EPOCH_223_CLOSED_TAIL: Profile = Profile {
    epoch: 223,
    acquisition: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-focused-223-v1625-tail-b364126a-v3",
        230570718,
        230570721,
        1792708227025104847,
        1792708227026104843,
    ),
    retained: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-contiguous-224-227-current-46b4b4a-bootstrap-v1",
        12293606,
        12293656,
        1792001863506735345,
        1792001863506735345,
    ),
    state: "/var/lib/jetstreamer/horizon-bootstrap-tail223-retire-v239",
    unit_prefix: "horizon-bootstrap-tail223-retire-v239-a",
    name: "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst",
    quarantine: ".snapshot-96767522-inode-230570721-quarantine",
    digest: "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1",
    bytes: 9_705_551_147,
};

const EPOCH_223_CLOSED_WORKER: Profile = Profile {
    acquisition: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-focused-223-v1625-tail-bd60006d-v1",
        230570207,
        230570210,
        1792699731116429797,
        1792699731116429797,
    ),
    state: "/var/lib/jetstreamer/horizon-bootstrap-worker223-retire-v239",
    unit_prefix: "horizon-bootstrap-worker223-retire-v239-a",
    quarantine: ".snapshot-96767522-inode-230570210-quarantine",
    ..EPOCH_223_CLOSED_TAIL
};

const EPOCH_223_CLOSED_WARMUP: Profile = Profile {
    acquisition: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-223-v1620-prefix-warmup-63ece8f4-v1",
        230574456,
        230574459,
        1792773024578531571,
        1792773024578531571,
    ),
    retained: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1",
        230570916,
        230570920,
        1792711126060793646,
        1792711126061793642,
    ),
    state: "/var/lib/jetstreamer/horizon-bootstrap-warmup223-retire-v239",
    unit_prefix: "horizon-bootstrap-warmup223-retire-v239-a",
    quarantine: ".snapshot-96335538-inode-230574459-quarantine",
    ..EPOCH_223
};

const EPOCH_223_CLOSED_PREFLIGHT: Profile = Profile {
    acquisition: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-223-prefix-preflight-a928381d-v1",
        230571131,
        230571134,
        1792714831603580264,
        1792714831610580237,
    ),
    state: "/var/lib/jetstreamer/horizon-bootstrap-preflight223-retire-v239",
    unit_prefix: "horizon-bootstrap-preflight223-retire-v239-a",
    quarantine: ".snapshot-96335538-inode-230571134-quarantine",
    ..EPOCH_223_CLOSED_WARMUP
};

const EPOCH_224_CLOSED_SPAN: Profile = Profile {
    epoch: 224,
    acquisition: sealed_snapshot(
        "/var/lib/jetstreamer/horizon-focused-224-complete-span-v1-6-25-01879c4-v1",
        9069136,
        9069144,
        1792420459661248828,
        1792420459662248825,
    ),
    state: "/var/lib/jetstreamer/horizon-bootstrap-span224-retire-v239",
    unit_prefix: "horizon-bootstrap-span224-retire-v239-a",
    quarantine: ".snapshot-96767522-inode-9069144-quarantine",
    ..EPOCH_223_CLOSED_TAIL
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
fn checked_dir(snapshot: &Snapshot) -> io::Result<File> {
    let path = Path::new(snapshot.directory);
    need(path.canonicalize()? == path, "directory alias")?;
    let f = open(path, DIRECTORY)?;
    let m = f.metadata()?;
    need(
        (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())
            == (
                DEVICE,
                snapshot.directory_inode,
                0,
                0,
                snapshot.directory_mode,
            ),
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
    let src = checked_dir(&profile.acquisition)?;
    let keep = checked_dir(&profile.retained)?;
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
        [mode] if mode == "--retire-cached-228" => &EPOCH_228_CACHE,
        [mode] if mode == "--retire-cached-231" => &EPOCH_231_CACHE,
        [mode] if mode == "--retire-superseded-223-tail" => &EPOCH_223_CLOSED_TAIL,
        [mode] if mode == "--retire-superseded-223-worker" => &EPOCH_223_CLOSED_WORKER,
        [mode] if mode == "--retire-superseded-223-warmup" => &EPOCH_223_CLOSED_WARMUP,
        [mode] if mode == "--retire-superseded-223-preflight" => &EPOCH_223_CLOSED_PREFLIGHT,
        [mode] if mode == "--retire-superseded-224-span" => &EPOCH_224_CLOSED_SPAN,
        _ => {
            return Err(io::Error::other(
                "expected an enrolled bootstrap retirement mode",
            ));
        }
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
    fn closed_copies_keep_their_exact_successor_and_separate_journals() {
        let profiles = [
            EPOCH_228_CACHE,
            EPOCH_231_CACHE,
            EPOCH_223_CLOSED_TAIL,
            EPOCH_223_CLOSED_WORKER,
            EPOCH_223_CLOSED_WARMUP,
            EPOCH_223_CLOSED_PREFLIGHT,
            EPOCH_224_CLOSED_SPAN,
        ];
        for (i, profile) in profiles.iter().enumerate() {
            assert_ne!(profile.acquisition.directory, profile.retained.directory);
            assert_eq!(profile.acquisition.directory_mode, 0o40555);
            for earlier in &profiles[..i] {
                assert_ne!(profile.intent(), earlier.intent());
                assert_ne!(profile.state, earlier.state);
                assert_ne!(profile.unit_prefix, earlier.unit_prefix);
            }
        }
        assert_eq!(
            EPOCH_223_CLOSED_TAIL.retained.inode,
            EPOCH_223_CLOSED_WORKER.retained.inode
        );
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
