//! Exact independently supervised protective guard; no fleet observation or R2.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd};

struct Custody {
    directory: File,
    device: u64,
    inode: u64,
}
impl Custody {
    fn open(actor: &Actor) -> Result<Self> {
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
    fn file(&self, name: &str, write: bool) -> Result<File> {
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
fn inspect(plan: &GuardPlan, custody: &Custody) -> Result<Value> {
    observe(&plan.watched_runner)?;
    let root = fs::symlink_metadata(&plan.run_root)?;
    ensure!(
        root.is_dir()
            && root.uid() == 1000
            && root.mode() & 0o077 == 0
            && plan.run_root.canonicalize()? == plan.run_root,
        "223 guard scratch root changed"
    );
    let mut pending = vec![(plan.run_root.clone(), 0u32)];
    let (mut bytes, mut entries) = (0u64, 0u64);
    let started = Instant::now();
    while let Some((path, depth)) = pending.pop() {
        entries += 1;
        ensure!(
            depth <= 64
                && entries + pending.len() as u64 <= 4_000_000
                && started.elapsed() < Duration::from_secs(120),
            "223 guard scratch scan bound"
        );
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.dev() == root.dev() && !m.file_type().is_symlink() && (m.is_dir() || m.is_file()),
            "223 guard scratch escaped filesystem"
        );
        bytes = bytes
            .checked_add(
                m.blocks()
                    .checked_mul(512)
                    .context("223 guard block overflow")?,
            )
            .context("223 guard byte overflow")?;
        ensure!(
            bytes <= 471_798_691_840,
            "223 guard total private disk envelope exceeded"
        );
        if m.is_dir() {
            for child in fs::read_dir(path)? {
                pending.push((child?.path(), depth + 1));
            }
        }
    }
    let scratch_root = plan.run_root.join("scratch");
    let scratch = scratch(&scratch_root)?;
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
            && plan.protected_floor_bytes >= 2_000_000_000_000,
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
    inspect(&plan, &custody)?;
    persist(
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
        if let Err(error) = inspect(&plan, &custody).and_then(|_| observe(&actor)) {
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
