//! Exact independently supervised protective guard; no fleet observation or R2.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd};

pub(super) struct Custody {
    directory: File,
    device: u64,
    inode: u64,
}
impl Custody {
    pub(super) fn open(actor: &Actor) -> Result<Self> {
        observe(actor)?;
        let path = Path::new("/sys/fs/cgroup").join(actor.cgroup.trim_start_matches('/'));
        ensure!(path.canonicalize()? == path, "223 guard redirected cgroup");
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&path)?;
        let metadata = directory.metadata()?;
        let actual = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.dev() == actual.dev() && metadata.ino() == actual.ino(),
            "223 guard cgroup changed"
        );
        observe(actor)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            directory,
        })
    }
    pub(super) fn file(&self, name: &str, write: bool) -> Result<File> {
        let metadata = self.directory.metadata()?;
        ensure!(
            metadata.dev() == self.device && metadata.ino() == self.inode,
            "223 guard lost cgroup custody"
        );
        let name = std::ffi::CString::new(name)?;
        let flags = (if write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        }) | libc::O_NOFOLLOW
            | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(self.directory.as_raw_fd(), name.as_ptr(), flags) };
        ensure!(fd >= 0, "223 guard cannot open original cgroup control");
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn read(&self, name: &str) -> Result<String> {
        let mut bytes = Vec::new();
        self.file(name, false)?
            .take(1 << 20)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() < 1 << 20, "223 guard cgroup reply bound");
        Ok(String::from_utf8(bytes)?)
    }
    fn stop(&self) -> Result<()> {
        // Directory-FD-relative controls cannot address a replacement service.
        self.file("cgroup.freeze", true)?.write_all(b"1\n")?;
        self.file("cgroup.kill", true)?.write_all(b"1\n")?;
        Ok(())
    }
}
struct RunRoot {
    directory: File,
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}
impl RunRoot {
    fn open(path: &Path, uid: u32) -> Result<Self> {
        ensure!(path.canonicalize()? == path, "223 guard root redirected");
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = directory.metadata()?;
        let root = Self {
            directory,
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid,
        };
        root.validate()?;
        Ok(root)
    }
    fn validate(&self) -> Result<()> {
        for m in [
            self.directory.metadata()?,
            fs::symlink_metadata(&self.path)?,
        ] {
            ensure!(
                m.is_dir()
                    && m.uid() == self.uid
                    && m.mode() & 0o077 == 0
                    && m.dev() == self.device
                    && m.ino() == self.inode,
                "223 guard original run-root replaced"
            );
        }
        ensure!(
            self.path.canonicalize()? == self.path,
            "223 guard run-root redirected"
        );
        Ok(())
    }
}
fn stable_measure(root: &RunRoot, mut measurement: impl FnMut() -> Result<Value>) -> Result<Value> {
    // Compaction may unlink a child after lstat and before traversal. Retry only
    // ENOENT against the same pinned root, at most twice; no new campaign sample.
    for attempt in 0..3 {
        root.validate()?;
        match measurement() {
            Ok(value) => {
                root.validate()?;
                return Ok(value);
            }
            Err(error) => {
                let disappeared = error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                });
                if !disappeared || attempt == 2 {
                    return Err(error);
                }
            }
        }
    }
    anyhow::bail!("223 guard stable measurement retry exhausted")
}
fn inspect(plan: &GuardPlan, custody: &Custody, root: &RunRoot) -> Result<Value> {
    observe(&plan.watched_runner)?;
    let total = stable_measure(root, || scratch_with_limit(&plan.run_root, 471_798_691_840))?;
    let bytes = total["physical_bytes"]
        .as_u64()
        .context("223 guard physical bytes")?;
    let scratch_root = plan.run_root.join("scratch");
    let scratch = stable_measure(root, || scratch(&scratch_root))?;
    let free = free_bytes(&plan.run_root)?;
    ensure!(
        free >= plan.protected_floor_bytes,
        "223 guard protected disk floor reached"
    );
    let map_limit = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    let mut maps = BTreeMap::new();
    for pid in custody.read("cgroup.procs")?.lines() {
        let pid: u32 = pid.parse()?;
        ensure!(
            fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::{}", plan.watched_runner.cgroup),
            "223 guard process cgroup changed"
        );
        let count = BufReader::new(File::open(format!("/proc/{pid}/maps"))?)
            .lines()
            .try_fold(0u64, |n, line| -> Result<u64> {
                line?;
                Ok(n + 1)
            })?;
        ensure!(
            count <= map_limit.saturating_mul(9) / 10,
            "223 guard VMA headroom exhausted"
        );
        maps.insert(pid, count);
    }
    observe(&plan.watched_runner)?;
    Ok(
        json!({"physical_private_bytes":bytes,"scratch":scratch,"free_bytes":free,"vma_counts":maps}),
    )
}
pub(super) fn run(binding: &BoundFile, executable: &BoundFile) -> Result<()> {
    let plan: GuardPlan = read_bound(binding)?;
    let runtime: RuntimePlan = read_bound(&plan.runtime_plan)?;
    ensure!(
        plan.schema == "jetstreamer-epoch223-demotion-guard-plan-v1"
            && runtime.schema == "jetstreamer-epoch223-demotion-runtime-plan-v3"
            && runtime.mode == "bracket"
            && plan.run_root == runtime.plan.run_root
            && plan.watched_runner.unit == runtime.plan.unit
            && plan.worker_sha256 == WORKER
            && plan.target_slot == TERMINAL
            && plan.maximum_scratch_bytes == MAX_SCRATCH
            && plan.protected_floor_bytes > 0
            && plan.protected_floor_bytes == runtime.plan.minimum_free_bytes,
        "223 guard exact scope differs"
    );
    let prerequisites = runtime
        .prerequisites
        .context("223 guard prerequisites missing")?;
    ensure!(
        prerequisites.guard_executable == *executable
            && prerequisites.admission_policy == plan.admission_policy,
        "223 guard executable/policy differs"
    );
    let actor = roles::own_role(
        &plan.guard_unit,
        "guard-epoch223-demotion",
        binding,
        executable,
    )?;
    ensure!(
        actor.pid != plan.watched_runner.pid
            && actor.invocation_id != plan.watched_runner.invocation_id,
        "223 guard must be an independent actor"
    );
    verify_reference(&plan.admission_policy)?;
    let own_cgroup = Path::new("/sys/fs/cgroup").join(actor.cgroup.trim_start_matches('/'));
    for (name, expected) in [
        ("memory.max", 1u64 << 30),
        ("memory.high", 768u64 << 20),
        ("memory.swap.max", 0),
    ] {
        ensure!(
            fs::read_to_string(own_cgroup.join(name))?
                .trim()
                .parse::<u64>()?
                == expected,
            "223 independent guard kernel envelope differs"
        );
    }
    check_control_kernel(&runtime.plan)?;
    let custody = Custody::open(&plan.watched_runner)?;
    // Verify that the independently sandboxed guard can open both original
    // controls without changing the producer during qualification/startup.
    custody.file("cgroup.freeze", true)?;
    custody.file("cgroup.kill", true)?;
    let root = RunRoot::open(&plan.run_root, 1000)?;
    inspect(&plan, &custody, &root)?;
    issuance::published(
        &plan.ready_output,
        &json!({"schema":"jetstreamer-epoch223-demotion-guard-ready-v1",
        "actor":actor,"watched_runner":plan.watched_runner,"guard_plan":binding,
        "admission_policy":plan.admission_policy,"run_root":plan.run_root,"worker_sha256":WORKER,
        "target_slot":TERMINAL,"protective_guard_proven":true,"producer_stop_enabled":true,
        "recorded_unix_millis":millis()?,"publication_authorized":false,"r2_mutations":false}),
    )?;
    loop {
        thread::sleep(Duration::from_secs(15));
        // An empty original cgroup is terminal, never a reason to follow a new invocation.
        if custody.read("cgroup.procs")?.trim().is_empty() {
            return Ok(());
        }
        if let Err(error) = inspect(&plan, &custody, &root).and_then(|_| observe(&actor)) {
            persist(
                &plan.stop_output,
                &json!({"schema":"jetstreamer-epoch223-demotion-guard-stop-v1",
                "actor":actor,"target":plan.watched_runner,"guard_plan":binding,"reason":format!("{error:#}"),
                "recorded_unix_millis":millis()?,"original_cgroup_inode":custody.inode,
                "preserve_all_files":true,"publication_authorized":false,"r2_mutations":false}),
            )?;
            custody.stop()?;
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> (tempfile::TempDir, RunRoot) {
        let directory = tempfile::tempdir().unwrap();
        let root = RunRoot::open(directory.path(), unsafe { libc::geteuid() }).unwrap();
        (directory, root)
    }
    #[test]
    fn renamed_same_owner_root_cannot_hide_original_open_files() {
        let (directory, root) = root();
        fs::write(directory.path().join("original"), b"retained").unwrap();
        let held = File::open(directory.path().join("original")).unwrap();
        let old = directory.path().with_extension("old");
        fs::rename(directory.path(), &old).unwrap();
        fs::create_dir(directory.path()).unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(root.validate().is_err());
        assert!(stable_measure(&root, || scratch(directory.path())).is_err());
        assert!(held.metadata().unwrap().len() > 0);
        drop(held);
        fs::remove_dir_all(old).unwrap();
    }
    #[test]
    fn compaction_disappearance_retries_same_root_and_measures_remaining_files() {
        let (directory, root) = root();
        let file = directory.path().join("old-appendvec");
        fs::write(&file, b"old").unwrap();
        let mut attempts = 0;
        let value = stable_measure(&root, || {
            attempts += 1;
            if attempts == 1 {
                fs::remove_file(&file)?;
                fs::write(directory.path().join("compacted-appendvec"), b"new")?;
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
            }
            scratch(directory.path())
        })
        .unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(value["regular_files"], 1);
        let mut failures = 0;
        assert!(
            stable_measure(&root, || {
                failures += 1;
                Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
            })
            .is_err()
        );
        assert_eq!(failures, 3);
    }
    #[test]
    fn failed_protective_guard_cannot_strand_an_owned_native_child() {
        // Disposable process only: the production runner returns its guard
        // error before receipt writes; ChildGroup is the final stop backstop.
        let child = Command::new("/bin/sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let owned = ChildGroup(child, false);
        let unavailable = tempfile::tempdir().unwrap();
        // A directory cannot be published as a file: deterministic receipt failure.
        let destination = unavailable.path().join("not-a-receipt");
        fs::create_dir(&destination).unwrap();
        assert!(persist(&destination, &json!({"guard_failure":true})).is_err());
        drop(owned);
        let start = Instant::now();
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
            if result == pid as i32
                || (result == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
            {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "owned native process survived guard failure"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}
