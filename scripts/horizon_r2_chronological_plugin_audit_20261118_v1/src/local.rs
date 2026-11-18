use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
pub fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = open_read(path)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0; 4 * 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hex(&hash.finalize()))
}
pub fn open_read(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "not a regular file: {}",
        path.display()
    );
    Ok(file)
}
pub fn create(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}
pub fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

pub fn private_dir(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        let mut b = fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(path)?;
        sync_dir(path.parent().context("directory needs parent")?)?;
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "directory must be owned by this UID, private, and not a symlink: {}",
        path.display()
    );
    Ok(())
}
pub fn validate_absolute(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "path must be absolute and normalized"
    );
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part);
        match fs::symlink_metadata(&prefix) {
            Ok(m) => ensure!(
                !m.file_type().is_symlink(),
                "symlink ancestor: {}",
                prefix.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let file = open_read(path)?;
    ensure!(
        file.metadata()?.len() <= 16 * 1024 * 1024,
        "JSON exceeds bound"
    );
    Ok(serde_json::from_reader(file)?)
}
pub fn write_json(path: &Path, value: &impl Serialize, replace: bool) -> Result<()> {
    let temp = path.with_extension(format!("tmp-{}", nonce()));
    let mut file = create(&temp)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    if replace {
        fs::rename(&temp, path)?;
    } else {
        // hard_link provides atomic no-clobber publication on this filesystem.
        fs::hard_link(&temp, path)?;
        fs::remove_file(&temp)?;
    }
    sync_dir(path.parent().context("JSON needs parent")?)
}
pub fn lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.uid() == unsafe { libc::geteuid() },
        "invalid lock file"
    );
    ensure!(
        unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } == 0,
        "another audit process owns this state"
    );
    Ok(file)
}
pub fn free_bytes(path: &Path) -> Result<u64> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), info.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let info = unsafe { info.assume_init() };
    info.f_bavail
        .checked_mul(info.f_frsize)
        .context("free byte overflow")
}
pub fn require_space(path: &Path, floor: u64, additional: u64) -> Result<()> {
    let needed = floor
        .checked_add(additional)
        .context("space calculation overflow")?;
    let free = free_bytes(path)?;
    ensure!(
        free >= needed,
        "disk reserve blocks audit: free={free}, required={needed}"
    );
    Ok(())
}
pub fn working_bytes(state: &Path) -> Result<u64> {
    fn count(path: &Path) -> Result<u64> {
        let meta = fs::symlink_metadata(path)?;
        let mut bytes = meta
            .blocks()
            .checked_mul(512)
            .context("allocation overflow")?;
        if meta.is_dir() {
            for item in fs::read_dir(path)? {
                bytes = bytes
                    .checked_add(count(&item?.path())?)
                    .context("allocation overflow")?;
            }
        }
        Ok(bytes)
    }
    let mut total = 0_u64;
    for entry in fs::read_dir(state)? {
        let entry = entry?;
        if entry.file_name() == "scratch" {
            continue;
        }
        total = total
            .checked_add(count(&entry.path())?)
            .context("allocation overflow")?;
    }
    // Production's dedicated immutable reader generations are on the same
    // filesystem but outside the unprivileged state so the root sealer can
    // enforce its entire destination ancestry. Charge all those generations.
    let readers = Path::new(crate::source::READER_ROOT);
    if state.join("accepted-config.json").try_exists()? && readers.try_exists()? {
        total = total
            .checked_add(count(readers)?)
            .context("reader allocation overflow")?;
    }
    Ok(total)
}
pub fn remaining_working_budget(state: &Path, budget: u64) -> Result<u64> {
    budget
        .checked_sub(working_bytes(state)?)
        .context("audit source/build/log allocation exceeds budget")
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
}
impl Identity {
    pub fn from_file(file: &File) -> Result<Self> {
        let m = file.metadata()?;
        ensure!(
            m.is_file() && m.nlink() == 1 && m.uid() == unsafe { libc::geteuid() },
            "unsafe owned file"
        );
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
        })
    }
    pub fn check(&self, path: &Path) -> Result<()> {
        ensure!(
            *self == Self::from_file(&open_read(path)?)?,
            "owned scratch inode changed"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedScratch {
    pub key: String,
    pub identity: Identity,
    pub created_at: u64,
}

pub fn scratch_path(state: &Path, owned: &OwnedScratch) -> Result<PathBuf> {
    ensure!(
        crate::canonical_epoch(&owned.key).is_some(),
        "unsafe scratch key"
    );
    Ok(state.join("scratch").join(&owned.key))
}
pub fn cleanup_scratch(state: &Path) -> Result<()> {
    let journal = state.join("scratch-owner.json");
    if journal.try_exists()? {
        let owned: OwnedScratch = read_json(&journal)?;
        let path = scratch_path(state, &owned)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                owned.identity.check(&path)?;
                fs::remove_file(path)?;
                sync_dir(&state.join("scratch"))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        fs::remove_file(journal)?;
        sync_dir(state)?;
    }
    // Unknown or unjournaled files are NEVER guessed to be disposable.
    ensure!(
        fs::read_dir(state.join("scratch"))?.next().is_none(),
        "unowned scratch file; inspect manually"
    );
    Ok(())
}

pub fn clean_command(program: &Path) -> Command {
    let mut c = Command::new(program);
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("RUST_LOG", "info")
        .env("RUST_MIN_STACK", "67108864");
    c.stdin(Stdio::null());
    c
}

struct ChildGroup {
    child: std::process::Child,
    reaped: bool,
}
impl ChildGroup {
    fn stop(&mut self) {
        if !self.reaped {
            // Each direct child is its own process-group leader. Its PID is
            // retained until wait(), so this group cannot be confused with a
            // recycled process group while we terminate its descendants.
            let pgid = self.child.id() as libc::pid_t;
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}
impl Drop for ChildGroup {
    fn drop(&mut self) {
        self.stop();
    }
}

// Child logs are bounded while the process runs. This is a local audit guard,
// not an observation of or admission authority over campaign replay lanes.
pub fn run_logged(
    mut command: Command,
    log: &Path,
    timeout: u64,
    max_log: u64,
    state: &Path,
    floor: u64,
    working_budget: u64,
) -> Result<bool> {
    let file = create(log)?;
    command.stdout(file.try_clone()?).stderr(file.try_clone()?);
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    // If the controller dies, its direct child receives SIGKILL. The service
    // additionally MUST use KillMode=control-group for compiler grandchildren.
    unsafe {
        command.pre_exec(|| {
            let parent = libc::getppid();
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if parent == 1 || libc::getppid() != parent {
                return Err(std::io::Error::other("controller exited"));
            }
            Ok(())
        });
    }
    let mut owned = ChildGroup {
        child: command.spawn().context("start audit subprocess")?,
        reaped: false,
    };
    let child_pid = owned.child.id();
    let start = Instant::now();
    let started_at = now();
    let mut last_allocation_check = Instant::now().checked_sub(Duration::from_secs(30)).unwrap();
    loop {
        if let Some(exit) = owned.child.try_wait()? {
            owned.reaped = true;
            file.sync_all()?;
            write_json(
                &state.join("child.json"),
                &serde_json::json!({"pid":child_pid,"started_at":started_at,"updated_at":now(),
                "log":log,"running":false,"exit_code":exit.code(),"success":exit.success(),"log_bytes":file.metadata()?.len()}),
                true,
            )?;
            ensure!(
                file.metadata()?.len() <= max_log,
                "subprocess log exceeds bound"
            );
            ensure!(
                working_bytes(state)? <= working_budget,
                "audit source/build/log allocation exceeds budget"
            );
            return Ok(exit.success());
        }
        let guard = (|| -> Result<()> {
            ensure!(
                start.elapsed() <= Duration::from_secs(timeout),
                "subprocess timeout"
            );
            ensure!(
                file.metadata()?.len() <= max_log,
                "subprocess log exceeds bound"
            );
            if last_allocation_check.elapsed() >= Duration::from_secs(30) {
                ensure!(
                    working_bytes(state)? <= working_budget,
                    "audit source/build/log allocation exceeds budget"
                );
                last_allocation_check = Instant::now();
                write_json(
                    &state.join("child.json"),
                    &serde_json::json!({"pid":child_pid,"started_at":started_at,"updated_at":now(),
                    "log":log,"running":true,"elapsed_seconds":start.elapsed().as_secs(),"log_bytes":file.metadata()?.len()}),
                    true,
                )?;
            }
            require_space(state, floor, 0)
        })();
        if let Err(error) = guard {
            owned.stop();
            file.sync_all()?;
            write_json(
                &state.join("child.json"),
                &serde_json::json!({"pid":child_pid,"started_at":started_at,"updated_at":now(),
                "log":log,"running":false,"stopped_by_guard":true,"error":error.to_string(),"log_bytes":file.metadata()?.len()}),
                true,
            )?;
            bail!("audit subprocess stopped: {error}");
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

pub fn set_readonly(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    open_read(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_refuses_substitution_and_paths() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path();
        private_dir(&state.join("scratch")).unwrap();
        let path = state.join("scratch/epoch-3.jet");
        let f = create(&path).unwrap();
        let owned = OwnedScratch {
            key: "epoch-3.jet".into(),
            identity: Identity::from_file(&f).unwrap(),
            created_at: now(),
        };
        write_json(&state.join("scratch-owner.json"), &owned, false).unwrap();
        fs::rename(&path, state.join("original")).unwrap();
        create(&path).unwrap();
        assert!(cleanup_scratch(state).is_err());
        assert!(path.exists());
        let bad = OwnedScratch {
            key: "../epoch-3.jet".into(),
            ..owned
        };
        assert!(scratch_path(state, &bad).is_err());
    }
    #[test]
    fn cleanup_recovers_partial_and_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path();
        private_dir(&state.join("scratch")).unwrap();
        let path = state.join("scratch/epoch-0.jet");
        let mut f = create(&path).unwrap();
        let owned = OwnedScratch {
            key: "epoch-0.jet".into(),
            identity: Identity::from_file(&f).unwrap(),
            created_at: now(),
        };
        write_json(&state.join("scratch-owner.json"), &owned, false).unwrap();
        f.write_all(b"partial").unwrap();
        f.sync_all().unwrap();
        cleanup_scratch(state).unwrap();
        cleanup_scratch(state).unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn no_clobber_receipt_and_exclusive_owner() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("receipt.json");
        write_json(&p, &1, false).unwrap();
        assert!(write_json(&p, &2, false).is_err());
        assert_eq!(read_json::<u8>(&p).unwrap(), 1);
        let _first = lock(&d.path().join("lock")).unwrap();
        assert!(lock(&d.path().join("lock")).is_err());
    }
    #[test]
    fn unknown_and_symlink_scratch_survive_cleanup() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path();
        private_dir(&state.join("scratch")).unwrap();
        let outside = state.join("do-not-delete");
        fs::write(&outside, b"archive").unwrap();
        let path = state.join("scratch/epoch-4.jet");
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(cleanup_scratch(state).is_err());
        assert!(outside.exists());
        assert!(path.symlink_metadata().is_ok());
    }
    #[test]
    fn command_children_do_not_receive_credentials_and_failed_exit_is_false() {
        let d = tempfile::tempdir().unwrap();
        private_dir(&d.path().join("scratch")).unwrap();
        let mut command = clean_command(Path::new("/bin/sh"));
        command.args(["-c", "test -z \"$HORIZON_ACCESS_KEY_ID\" && test -z \"$HORIZON_SECRET_ACCESS_KEY\" && exit 7"]);
        assert!(
            !run_logged(
                command,
                &d.path().join("child.log"),
                5,
                1024,
                d.path(),
                0,
                1024 * 1024
            )
            .unwrap()
        );
    }
    #[test]
    fn guard_kills_compiler_style_descendant_group() {
        let d = tempfile::tempdir().unwrap();
        private_dir(&d.path().join("scratch")).unwrap();
        let descendant = d.path().join("descendant.pid");
        let mut command = clean_command(Path::new("/bin/sh"));
        command
            .args([
                "-c",
                "sleep 30 & printf '%s' \"$!\" > \"$1\"; wait",
                "audit-test",
            ])
            .arg(&descendant);
        let error = run_logged(
            command,
            &d.path().join("group.log"),
            1,
            1024,
            d.path(),
            0,
            1024 * 1024,
        )
        .unwrap_err();
        assert!(error.to_string().contains("timeout"));
        let pid: u32 = fs::read_to_string(descendant).unwrap().parse().unwrap();
        for _ in 0..100 {
            match fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
                Ok(stat)
                    if stat.rsplit_once(')').is_some_and(|(_, tail)| {
                        matches!(tail.trim_start().chars().next(), Some('Z' | 'X'))
                    }) =>
                {
                    return;
                }
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        panic!("descendant {pid} survived its audit guard");
    }
}
