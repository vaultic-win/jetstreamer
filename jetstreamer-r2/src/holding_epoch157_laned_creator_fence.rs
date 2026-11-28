//! Existing seven-controller lease fence, derived from the qualified157 inspector.
use super::*;
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::Component,
};
const PINS_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-private152-hash-source-20261113-v4/creator-pins.json";
const PINS_SHA: &str = "559778bcebc7c7e0ca63c894d4e5004fd578518ae1650436c3f8b7693812d645";
const REVIEW_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-private152-hash-source-20261113-v4/creator-review.json";
const REVIEW_SHA: &str = "93423facc65a6693e18625a2e397d60874221b5e8962d52296ce0eb966cbc5ec";
fn sha(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}
fn stamp(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode()&0o7777,"length":m.len(),"links":m.nlink(),"mtime_seconds":m.mtime(),"mtime_nanoseconds":m.mtime_nsec(),"ctime_seconds":m.ctime(),"ctime_nanoseconds":m.ctime_nsec()})
}
fn directory(path: &Path) -> Result<File> {
    ensure!(path.is_absolute(), "absolute directory required");
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(
                    fd >= 0,
                    "directory anchor failed: {}",
                    std::io::Error::last_os_error()
                );
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => anyhow::bail!("noncanonical directory"),
        }
    }
    Ok(dir)
}
fn file_at(dir: &File, name: &str) -> Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    ensure!(
        fd >= 0,
        "anchored file unavailable: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(super) struct Lease {
    pin: Value,
    dir: File,
    lock: File,
}
impl Lease {
    fn acquire(pin: &Value) -> Result<Self> {
        let dir = directory(Path::new(pin["root"].as_str().context("controller root")?))?;
        ensure!(
            stamp(&dir.metadata()?) == pin["root_identity"],
            "controller root changed"
        );
        let lock = file_at(&dir, "controller.lock")?;
        ensure!(
            stamp(&lock.metadata()?) == pin["lock_identity"],
            "controller lock changed"
        );
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "existing creator lease occupied"
        );
        let lease = Self {
            pin: pin.clone(),
            dir,
            lock,
        };
        lease.check()?;
        Ok(lease)
    }
    fn check(&self) -> Result<()> {
        let p = Path::new(self.pin["root"].as_str().context("controller root")?);
        ensure!(
            stamp(&directory(p)?.metadata()?) == self.pin["root_identity"]
                && stamp(&self.dir.metadata()?) == self.pin["root_identity"],
            "controller root replacement"
        );
        ensure!(
            stamp(&self.lock.metadata()?) == self.pin["lock_identity"]
                && stamp(&file_at(&self.dir, "controller.lock")?.metadata()?)
                    == self.pin["lock_identity"],
            "controller lock replacement"
        );
        let mut state = file_at(&self.dir, "state.json")?;
        ensure!(
            stamp(&state.metadata()?) == self.pin["state_identity"],
            "controller state identity changed"
        );
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut state)
            .take((1 << 20) + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 1 << 20
                && sha(&bytes) == self.pin["state"]["sha256"]
                && stamp(&state.metadata()?) == self.pin["state_identity"]
                && stamp(&file_at(&self.dir, "state.json")?.metadata()?)
                    == self.pin["state_identity"],
            "controller state changed"
        );
        let value: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            value["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3"
                && value["manifest_fingerprint"]
                    == "sha256:e3234f4207c549525edf9c85a867bba8dbb30eea667a188184aecbdef94d58e5",
            "original family state changed"
        );
        if p.ends_with("jetstreamer-root-sweep-epochs151-173-20260923-v91")
            || p.ends_with("jetstreamer-root-sweep-epochs151-173-20261001-v92-r2")
        {
            let a = &value["assignments"]["lane-d"];
            ensure!(
                a["unit"] == PRODUCER
                    && a["pid"] == 642701
                    && a["pid_start_time"] == 353584446
                    && a["first_epoch"] == 157
                    && a["last_epoch"] == 157
                    && a["phase"] == "producer",
                "exact157 producer assignment changed"
            );
        }
        Ok(())
    }
}
pub(super) fn original_absent() -> Result<()> {
    match fs::read("/proc/642701/stat") {
        Ok(bytes) => {
            ensure!(bytes.len() <= 65536, "proc stat bound");
            let s = std::str::from_utf8(&bytes)?;
            let ticks = s
                .rsplit_once(')')
                .context("proc framing")?
                .1
                .split_whitespace()
                .nth(19)
                .context("start ticks")?
                .parse::<u64>()?;
            ensure!(ticks != 353584446, "original producer survives");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    match fs::symlink_metadata(Path::new("/sys/fs/cgroup/system.slice").join(PRODUCER)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => anyhow::bail!("original cgroup reappeared"),
    }
}

fn creators() -> Result<()> {
    let v = bound(&binding(REVIEW_PATH, REVIEW_SHA))?;
    let rows = v["creators"].as_array().context("creator protocol rows")?;
    ensure!(
        rows.len() == 9 && v["historical_invocation_not_inferred"] == true,
        "creator review changed"
    );
    for row in rows {
        ensure!(
            row["lock_before_controller"] == true && row["lock_held_through_run_and_close"] == true,
            "creator protocol no longer fenced"
        );
        let b: Bound = serde_json::from_value(json!({"path":row["path"],"sha256":row["sha256"]}))?;
        let md = fs::symlink_metadata(&b.path)?;
        ensure!(
            md.is_file()
                && md.uid() == 0
                && md.mode() & 0o7777 == 0o555
                && hex_lower(&Sha256::digest(read_stable_bounded(
                    &b.path,
                    2 << 20,
                    "immutable creator"
                )?)) == b.sha256,
            "creator source changed"
        );
    }
    Ok(())
}
pub(super) fn acquire() -> Result<Vec<Lease>> {
    creators()?;
    let pins = bound(&binding(PINS_PATH, PINS_SHA))?;
    let rows = pins["controllers"]
        .as_array()
        .context("seven controllers")?;
    ensure!(rows.len() == 7, "all original family leases required");
    let leases = rows
        .iter()
        .map(Lease::acquire)
        .collect::<Result<Vec<_>>>()?;
    original_absent()?;
    Ok(leases)
}
pub(super) fn check(leases: &[Lease]) -> Result<()> {
    ensure!(leases.len() == 7, "creator lease set changed");
    for lease in leases {
        lease.check()?;
    }
    original_absent()?;
    creators()
}
