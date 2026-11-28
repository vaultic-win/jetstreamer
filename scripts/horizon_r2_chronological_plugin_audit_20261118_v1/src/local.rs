use crate::{Config, ExternalScratch};
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

// Ordinary controller/native report JSONs share the existing reader limit.
// Cargo metadata is a subprocess log and has its separate 32 MiB bound.
pub const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_SOURCE_METADATA_LOG_BYTES: u64 = 32 * 1024 * 1024;

pub fn operation_metadata_growth(max_log_bytes: u64) -> Result<u64> {
    // One bounded subprocess log, one native report, and one atomic controller
    // JSON publication. Existing records are already reflected in free bytes.
    max_log_bytes
        .checked_add(2 * MAX_JSON_BYTES)
        .context("operation metadata reservation overflow")
}

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
        file.metadata()?.len() <= MAX_JSON_BYTES,
        "JSON exceeds bound"
    );
    Ok(serde_json::from_reader(std::io::BufReader::new(file))?)
}
pub fn write_json(path: &Path, value: &impl Serialize, replace: bool) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() as u64 <= MAX_JSON_BYTES,
        "JSON exceeds publication bound"
    );
    let temp = path.with_extension(format!("tmp-{}", nonce()));
    let mut file = create(&temp)?;
    file.write_all(&bytes)?;
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
    require_available(free_bytes(path)?, floor, additional)
}
pub fn require_available(free: u64, floor: u64, additional: u64) -> Result<()> {
    let needed = floor
        .checked_add(additional)
        .context("space calculation overflow")?;
    ensure!(
        free >= needed,
        "disk reserve blocks audit: free={free}, required={needed}"
    );
    Ok(())
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum AllocationStage {
    BeforeMetadata,
    BeforeReadDirectory,
}

// The callback is a no-op in production. Tests use it to reproduce removal
// precisely between directory enumeration, metadata, and directory opening.
fn count_allocation(
    path: &Path,
    visit: &mut impl FnMut(&Path, AllocationStage) -> Result<()>,
) -> Result<u64> {
    visit(path, AllocationStage::BeforeMetadata)?;
    // Cargo creates and removes temporary files while this guard walks its
    // owned build tree. An entry that has vanished contributes no retained
    // allocation; all other inspection errors still stop the operation.
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = meta
        .blocks()
        .checked_mul(512)
        .context("allocation overflow")?;
    if meta.is_dir() {
        visit(path, AllocationStage::BeforeReadDirectory)?;
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        for item in entries {
            bytes = bytes
                .checked_add(count_allocation(&item?.path(), visit)?)
                .context("allocation overflow")?;
        }
    }
    Ok(bytes)
}

pub fn working_bytes(state: &Path) -> Result<u64> {
    let mut total = 0_u64;
    for entry in fs::read_dir(state)? {
        let entry = entry?;
        if entry.file_name() == "scratch" {
            continue;
        }
        total = total
            .checked_add(count_allocation(&entry.path(), &mut |_, _| Ok(()))?)
            .context("allocation overflow")?;
    }
    // Production's dedicated immutable reader generations are on the same
    // filesystem but outside the unprivileged state so the root sealer can
    // enforce its entire destination ancestry. Charge all those generations.
    let readers = Path::new(crate::source::READER_ROOT);
    if state.join("accepted-config.json").try_exists()? && readers.try_exists()? {
        total = total
            .checked_add(count_allocation(readers, &mut |_, _| Ok(()))?)
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
    /// Old same-filesystem journals omit this. External scratch must bind the
    /// full accepted directory identity so recovery cannot unlink elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_scratch: Option<ExternalScratch>,
}

pub fn validate_external_scratch(scratch: &ExternalScratch, state: &Path) -> Result<()> {
    validate_absolute(&scratch.directory)?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "external scratch requires root custody"
    );
    for ancestor in scratch.directory.ancestors() {
        let meta = fs::symlink_metadata(ancestor)?;
        ensure!(
            meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "external scratch ancestry is writable or foreign-owned: {}",
            ancestor.display()
        );
    }
    let meta = fs::symlink_metadata(&scratch.directory)?;
    ensure!(
        meta.mode() & 0o077 == 0
            && meta.dev() == scratch.device
            && meta.ino() == scratch.inode
            && meta.dev() != fs::symlink_metadata(state)?.dev(),
        "external scratch identity or separate filesystem changed"
    );
    Ok(())
}

fn lock_directory(path: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&directory),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } == 0,
        "another audit owns the external scratch directory"
    );
    Ok(directory)
}

pub fn lock_external_scratch(cfg: &Config) -> Result<Option<File>> {
    let Some(scratch) = &cfg.external_scratch else {
        return Ok(None);
    };
    validate_external_scratch(scratch, &cfg.state_directory)?;
    let directory = lock_directory(&scratch.directory)?;
    let meta = directory.metadata()?;
    ensure!(
        meta.dev() == scratch.device && meta.ino() == scratch.inode,
        "external scratch changed during lock acquisition"
    );
    Ok(Some(directory))
}

/// A relocation is allowed only while this state's exclusive lock is held and
/// neither configuration owns a download. No archive or evidence is migrated.
pub fn require_idle_scratch_change(old: &Config, new: &Config) -> Result<()> {
    if old.external_scratch == new.external_scratch {
        return Ok(());
    }
    ensure!(
        !old.state_directory
            .join("scratch-owner.json")
            .try_exists()?,
        "scratch relocation requires no owned in-flight download"
    );
    for cfg in [old, new] {
        if let Some(scratch) = &cfg.external_scratch {
            validate_external_scratch(scratch, &cfg.state_directory)?;
        }
        let directory = cfg.scratch_directory();
        let meta = fs::symlink_metadata(&directory)?;
        ensure!(
            meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "scratch relocation requires private directories"
        );
        ensure!(
            fs::read_dir(&directory)?.next().is_none(),
            "scratch relocation requires empty old and new directories"
        );
    }
    Ok(())
}

pub fn scratch_path(cfg: &Config, owned: &OwnedScratch) -> Result<PathBuf> {
    ensure!(
        crate::canonical_epoch(&owned.key).is_some(),
        "unsafe scratch key"
    );
    ensure!(
        owned.external_scratch == cfg.external_scratch,
        "owned scratch journal belongs to another directory or allocation"
    );
    if let Some(scratch) = &cfg.external_scratch {
        validate_external_scratch(scratch, &cfg.state_directory)?;
    }
    Ok(cfg.scratch_directory().join(&owned.key))
}
pub fn cleanup_scratch(cfg: &Config) -> Result<()> {
    let state = &cfg.state_directory;
    if let Some(scratch) = &cfg.external_scratch {
        validate_external_scratch(scratch, state)?;
    }
    let journal = state.join("scratch-owner.json");
    if journal.try_exists()? {
        let owned: OwnedScratch = read_json(&journal)?;
        let path = scratch_path(cfg, &owned)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                owned.identity.check(&path)?;
                fs::remove_file(path)?;
                sync_dir(&cfg.scratch_directory())?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        fs::remove_file(journal)?;
        sync_dir(state)?;
    }
    // Unknown or unjournaled files are NEVER guessed to be disposable.
    ensure!(
        fs::read_dir(cfg.scratch_directory())?.next().is_none(),
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
    command: Command,
    log: &Path,
    timeout: u64,
    max_log: u64,
    cfg: &Config,
) -> Result<bool> {
    run_logged_observed(
        command,
        log,
        timeout,
        max_log,
        cfg,
        &cfg.state_directory.join("child.json"),
        |_| Ok(()),
    )
}

pub fn run_logged_observed(
    mut command: Command,
    log: &Path,
    timeout: u64,
    max_log: u64,
    cfg: &Config,
    heartbeat: &Path,
    mut on_progress: impl FnMut(Option<bool>) -> Result<()>,
) -> Result<bool> {
    let state = &cfg.state_directory;
    // Establish both filesystem floors before the child can do useful work.
    cfg.require_operation_capacity(max_log)?;
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
            on_progress(Some(exit.success()))?;
            owned.reaped = true;
            file.sync_all()?;
            write_json(
                heartbeat,
                &serde_json::json!({"pid":child_pid,"started_at":started_at,"updated_at":now(),
                "log":log,"running":false,"exit_code":exit.code(),"success":exit.success(),"log_bytes":file.metadata()?.len()}),
                true,
            )?;
            ensure!(
                file.metadata()?.len() <= max_log,
                "subprocess log exceeds bound"
            );
            ensure!(
                working_bytes(state)? <= cfg.build_reserve_bytes,
                "audit source/build/log allocation exceeds budget"
            );
            return Ok(exit.success());
        }
        let guard = (|| -> Result<()> {
            on_progress(None)?;
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
                    working_bytes(state)? <= cfg.build_reserve_bytes,
                    "audit source/build/log allocation exceeds budget"
                );
                last_allocation_check = Instant::now();
                write_json(
                    heartbeat,
                    &serde_json::json!({"pid":child_pid,"started_at":started_at,"updated_at":now(),
                    "log":log,"running":true,"elapsed_seconds":start.elapsed().as_secs(),"log_bytes":file.metadata()?.len()}),
                    true,
                )?;
            }
            cfg.require_runtime_space(0)
        })();
        if let Err(error) = guard {
            owned.stop();
            file.sync_all()?;
            write_json(
                heartbeat,
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
    fn config(state: &Path) -> Config {
        let mut cfg: Config = serde_json::from_str(include_str!("../config.example.json")).unwrap();
        cfg.state_directory = state.to_owned();
        cfg.reserve_bytes = 0;
        cfg.max_log_bytes = 1024;
        cfg.build_reserve_bytes = 128 * 1024 * 1024;
        cfg
    }
    #[test]
    fn oversized_json_never_creates_or_replaces_evidence() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("receipt.json");
        write_json(&path, &"retained", false).unwrap();
        let oversized = "x".repeat(MAX_JSON_BYTES as usize);
        assert!(write_json(&path, &oversized, true).is_err());
        assert_eq!(read_json::<String>(&path).unwrap(), "retained");
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }
    #[test]
    fn allocation_walk_tolerates_cargo_removal_after_enumeration() {
        let d = tempfile::tempdir().unwrap();
        let build = d.path().join("build");
        fs::create_dir(&build).unwrap();
        let temporary = build.join(".tmp-rustc-object");
        let retained = build.join("retained.rlib");
        fs::write(&temporary, vec![1; 65536]).unwrap();
        fs::write(&retained, vec![2; 32768]).unwrap();
        let mut removed = false;
        let observed = count_allocation(&build, &mut |path, stage| {
            if path == temporary && stage == AllocationStage::BeforeMetadata {
                // The parent read_dir yielded this path; Cargo removes it
                // before the guard can call symlink_metadata, reproducing ENOENT.
                fs::remove_file(path)?;
                removed = true;
            }
            Ok(())
        })
        .unwrap();
        assert!(removed);
        let expected = (fs::metadata(&build).unwrap().blocks()
            + fs::metadata(&retained).unwrap().blocks())
            * 512;
        assert_eq!(observed, expected);
        assert!(
            observed >= 32768,
            "the retained compiler artifact must still be charged"
        );
    }
    #[test]
    fn allocation_walk_tolerates_directory_removal_after_metadata() {
        let d = tempfile::tempdir().unwrap();
        let temporary = d.path().join(".tmp-cargo-dir");
        fs::create_dir(&temporary).unwrap();
        let mut removed = false;
        let observed = count_allocation(&temporary, &mut |path, stage| {
            if stage == AllocationStage::BeforeReadDirectory {
                fs::remove_dir(path)?;
                removed = true;
            }
            Ok(())
        })
        .unwrap();
        assert!(removed);
        assert_eq!(observed, 0);
    }
    #[test]
    fn allocation_walk_still_rejects_other_errors_and_missing_state() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("file");
        fs::write(&file, b"x").unwrap();
        let error =
            count_allocation(&file.join("not-a-directory"), &mut |_, _| Ok(())).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ENOTDIR)
        );
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Other,
        ] {
            let error = count_allocation(d.path(), &mut |_, _| {
                Err(std::io::Error::new(kind, "injected inspection failure").into())
            })
            .unwrap_err();
            assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(), kind);
        }
        assert!(working_bytes(&d.path().join("missing-state")).is_err());
    }
    #[test]
    fn allocation_walk_never_follows_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let archive = d.path().join("external-archive");
        fs::write(&archive, vec![1; 65536]).unwrap();
        let link = d.path().join("build-link");
        std::os::unix::fs::symlink(&archive, &link).unwrap();
        let observed = count_allocation(&link, &mut |_, _| Ok(())).unwrap();
        assert_eq!(
            observed,
            fs::symlink_metadata(&link).unwrap().blocks() * 512
        );
        assert!(observed < fs::metadata(archive).unwrap().blocks() * 512);
    }
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
            external_scratch: None,
        };
        write_json(&state.join("scratch-owner.json"), &owned, false).unwrap();
        fs::rename(&path, state.join("original")).unwrap();
        create(&path).unwrap();
        assert!(cleanup_scratch(&config(state)).is_err());
        assert!(path.exists());
        let bad = OwnedScratch {
            key: "../epoch-3.jet".into(),
            ..owned
        };
        assert!(scratch_path(&config(state), &bad).is_err());
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
            external_scratch: None,
        };
        write_json(&state.join("scratch-owner.json"), &owned, false).unwrap();
        f.write_all(b"partial").unwrap();
        f.sync_all().unwrap();
        cleanup_scratch(&config(state)).unwrap();
        cleanup_scratch(&config(state)).unwrap();
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
    fn legacy_scratch_journal_cannot_delete_from_relocated_directory() {
        let d = tempfile::tempdir().unwrap();
        private_dir(&d.path().join("scratch")).unwrap();
        let file = create(&d.path().join("scratch/epoch-74.jet")).unwrap();
        let owned = OwnedScratch {
            key: "epoch-74.jet".into(),
            identity: Identity::from_file(&file).unwrap(),
            created_at: now(),
            external_scratch: None,
        };
        let mut cfg = config(d.path());
        cfg.external_scratch = Some(ExternalScratch {
            directory: PathBuf::from("/var/lib/jetstreamer/horizon_runtime_data/audit"),
            device: 64512,
            inode: 123,
            reserve_bytes: 100,
        });
        let error = scratch_path(&cfg, &owned).unwrap_err();
        assert!(error.to_string().contains("another directory"));
        assert!(d.path().join("scratch/epoch-74.jet").exists());
    }
    #[test]
    fn scratch_relocation_rejects_inflight_owner_without_touching_journal() {
        let d = tempfile::tempdir().unwrap();
        private_dir(&d.path().join("scratch")).unwrap();
        let old = config(d.path());
        let mut new = old.clone();
        new.external_scratch = Some(ExternalScratch {
            directory: PathBuf::from("/unprovisioned-scratch"),
            device: 64512,
            inode: 123,
            reserve_bytes: 100,
        });
        let journal = d.path().join("scratch-owner.json");
        fs::write(&journal, b"preserve even malformed ownership evidence").unwrap();
        assert!(
            require_idle_scratch_change(&old, &new)
                .unwrap_err()
                .to_string()
                .contains("in-flight")
        );
        assert_eq!(
            fs::read(journal).unwrap(),
            b"preserve even malformed ownership evidence"
        );
    }
    #[test]
    fn directory_lock_excludes_other_state_owners_without_creating_archive_files() {
        let d = tempfile::tempdir().unwrap();
        let first = lock_directory(d.path()).unwrap();
        assert!(lock_directory(d.path()).is_err());
        assert!(fs::read_dir(d.path()).unwrap().next().is_none());
        drop(first);
        assert!(lock_directory(d.path()).is_ok());
    }
    #[test]
    fn old_journal_deserializes_without_external_scratch_authority() {
        let legacy = serde_json::json!({"key":"epoch-1.jet", "identity":{"device":1,"inode":2,"uid":0},"created_at":3});
        let owned: OwnedScratch = serde_json::from_value(legacy).unwrap();
        assert!(owned.external_scratch.is_none());
    }
    #[test]
    fn external_scratch_failure_stops_child_before_spawn() {
        let d = tempfile::tempdir().unwrap();
        let mut cfg = config(d.path());
        cfg.external_scratch = Some(ExternalScratch {
            directory: d.path().join("unprovisioned"),
            device: 64512,
            inode: 123,
            reserve_bytes: 1,
        });
        let marker = d.path().join("child-started");
        let mut command = clean_command(Path::new("/usr/bin/touch"));
        command.arg(&marker);
        assert!(run_logged(command, &d.path().join("child.log"), 5, 1024, &cfg).is_err());
        assert!(!marker.exists());
        assert!(!d.path().join("child.log").exists());
    }
    #[test]
    #[ignore = "requires parent-admitted root-owned private parents on two filesystems"]
    fn external_scratch_full_roundtrip_on_two_admitted_filesystems() {
        ensure_root_test();
        let state_parent =
            std::env::var_os("AUDIT_STORAGE_TEST_STATE_PARENT").expect("state test parent");
        let scratch_parent =
            std::env::var_os("AUDIT_STORAGE_TEST_SCRATCH_PARENT").expect("scratch test parent");
        let state = tempfile::tempdir_in(state_parent).unwrap();
        let scratch = tempfile::tempdir_in(scratch_parent).unwrap();
        // tempfile follows the invoking umask; qualify the same explicit private
        // directory custody required by the production external-scratch route.
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700)).unwrap();
        private_dir(&state.path().join("scratch")).unwrap();
        let mut cfg = config(state.path());
        cfg.reserve_bytes = 1;
        cfg.max_archive_bytes = 8192;
        let meta = fs::symlink_metadata(scratch.path()).unwrap();
        cfg.external_scratch = Some(ExternalScratch {
            directory: scratch.path().to_owned(),
            device: meta.dev(),
            inode: meta.ino(),
            reserve_bytes: 1,
        });
        let legacy = config(state.path());
        validate_external_scratch(cfg.external_scratch.as_ref().unwrap(), state.path()).unwrap();
        require_idle_scratch_change(&legacy, &cfg).unwrap();
        let owner = lock_external_scratch(&cfg).unwrap();
        assert!(lock_external_scratch(&cfg).is_err());
        cfg.require_download_capacity(8192).unwrap();
        assert!(cfg.require_download_capacity(8193).is_err());
        let path = scratch.path().join("epoch-74.jet");
        let mut file = create(&path).unwrap();
        let journal = OwnedScratch {
            key: "epoch-74.jet".into(),
            identity: Identity::from_file(&file).unwrap(),
            created_at: now(),
            external_scratch: cfg.external_scratch.clone(),
        };
        write_json(&state.path().join("scratch-owner.json"), &journal, false).unwrap();
        file.write_all(b"interrupted authenticated download fixture")
            .unwrap();
        file.sync_all().unwrap();
        assert!(require_idle_scratch_change(&cfg, &legacy).is_err());
        let mut changed = cfg.clone();
        changed.external_scratch.as_mut().unwrap().inode += 1;
        assert!(cleanup_scratch(&changed).is_err());
        assert!(path.exists());
        drop(file);
        cleanup_scratch(&cfg).unwrap();
        cleanup_scratch(&cfg).unwrap();
        assert!(!path.exists());
        assert!(!state.path().join("scratch-owner.json").exists());
        let unknown = scratch.path().join("unknown-evidence");
        fs::write(&unknown, b"must remain").unwrap();
        assert!(cleanup_scratch(&cfg).is_err());
        assert!(require_idle_scratch_change(&cfg, &legacy).is_err());
        assert_eq!(fs::read(&unknown).unwrap(), b"must remain");
        fs::remove_file(&unknown).unwrap();
        require_idle_scratch_change(&cfg, &legacy).unwrap();
        drop(owner);
    }
    fn ensure_root_test() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "this ignored integration test requires root"
        );
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
        assert!(cleanup_scratch(&config(state)).is_err());
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
                &config(d.path())
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
            &config(d.path()),
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
