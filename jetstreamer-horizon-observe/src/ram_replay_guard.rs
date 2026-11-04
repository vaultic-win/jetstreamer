//! Owned-canary safety guard. It never observes another replay, launches a
//! process, signals a process, removes an artifact, or accesses remote storage.
//! The caller retains an unreaped child/group handle and performs termination
//! only after `check` has persisted its exact private stop intent.
use {
    anyhow::{Context, Result, ensure},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeSet,
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};

const GIB: u64 = 1 << 30;
const START_MEMORY: u64 = 864 * GIB;
const STOP_MEMORY: u64 = 544 * GIB;
const MEMORY_MAX: u64 = 320 * GIB;
const MEMORY_HIGH: u64 = 304 * GIB;
const TMPFS_SIZE: u64 = 768 * GIB;
const RAM_FILES_MAX: u64 = 224 * GIB;
const ARCHIVE_MAX: u64 = 16 * GIB;
const CENTURY_FLOOR: u64 = 231_874_716_783;
const VMA_MAX: u64 = 500_000;
const INTERVAL: Duration = Duration::from_secs(15);

/// Must additionally be bound by the supervisor's sealed plan, input checks,
/// actual sandbox proof and fresh complete-fleet admission. This is not a lease.
#[derive(Clone, Debug)]
pub struct Binding {
    pub unit: String,
    pub invocation_id: String,
    pub run_root: PathBuf,
    pub node: PathBuf,
    pub worker_sha256: String,
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    host_available: u64,
    ram_available: u64,
    memory_current: u64,
    memory_limit_events: u64,
    archive_physical: u64,
}

fn check_sample(s: Sample, startup: bool) -> Result<()> {
    ensure!(
        s.host_available >= if startup { START_MEMORY } else { STOP_MEMORY },
        "host-memory-reserve"
    );
    ensure!(
        s.ram_available <= TMPFS_SIZE && s.ram_available >= CENTURY_FLOOR,
        "tmpfs-century-floor"
    );
    ensure!(
        TMPFS_SIZE - s.ram_available <= RAM_FILES_MAX,
        "aggregate-ram-file-budget"
    );
    ensure!(
        s.memory_current <= MEMORY_MAX && s.memory_limit_events == 0,
        "cgroup-memory-limit-event"
    );
    ensure!(s.archive_physical <= ARCHIVE_MAX, "archive-budget");
    Ok(())
}

fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "bounded kernel read exceeded");
    Ok(bytes)
}

fn text(path: &Path) -> Result<String> {
    Ok(String::from_utf8(read(path, 65536)?)?)
}
fn number(path: &Path) -> Result<u64> {
    Ok(text(path)?.trim().parse()?)
}

fn available_memory(raw: &str) -> Result<u64> {
    let found: Vec<_> = raw
        .lines()
        .filter_map(|s| s.strip_prefix("MemAvailable:"))
        .collect();
    ensure!(found.len() == 1, "missing/duplicate available memory");
    let parts: Vec<_> = found[0].split_whitespace().collect();
    ensure!(parts.len() == 2 && parts[1] == "kB", "invalid memory units");
    parts[0]
        .parse::<u64>()?
        .checked_mul(1024)
        .context("memory overflow")
}

fn memory_events(raw: &str) -> Result<u64> {
    let mut found = BTreeSet::new();
    let mut total = 0u64;
    for line in raw.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        ensure!(
            parts.len() == 2 && found.insert(parts[0]),
            "malformed/duplicate memory event"
        );
        let n: u64 = parts[1].parse()?;
        if matches!(parts[0], "max" | "oom" | "oom_kill" | "oom_group_kill") {
            total = total.checked_add(n).context("memory event overflow")?;
        }
    }
    ensure!(
        ["high", "max", "oom", "oom_kill"]
            .iter()
            .all(|s| found.contains(s)),
        "missing memory events"
    );
    Ok(total)
}

type FileIdentity = (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64);

fn stat_identity(m: &fs::Metadata) -> FileIdentity {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn private_dir(path: &Path, dev: Option<u64>) -> Result<u64> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o7777 == 0o700
            && dev.is_none_or(|d| d == m.dev()),
        "unsafe private RAM directory"
    );
    Ok(m.dev())
}

fn private_evidence(path: &Path, dev: u64, limit: u64) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && before.is_file()
            && before.uid() == 1000
            && before.nlink() == 1
            && before.dev() == dev
            && before.mode() & 0o777 == 0o400
            && before.len() <= limit,
        "unsafe guard handoff evidence"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        stat_identity(&file.metadata()?) == stat_identity(&before),
        "handoff changed at open"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && stat_identity(&file.metadata()?) == stat_identity(&before)
            && stat_identity(&fs::symlink_metadata(path)?) == stat_identity(&before),
        "handoff changed at read"
    );
    Ok(bytes)
}

fn ram_available(root: &Path) -> Result<u64> {
    let path = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statfs(path.as_ptr(), &mut s) } == 0 && s.f_type == 0x01021994,
        "guard root is not tmpfs"
    );
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), &mut v) } == 0
            && v.f_blocks.checked_mul(v.f_frsize) == Some(TMPFS_SIZE),
        "RAM geometry changed"
    );
    v.f_bavail
        .checked_mul(v.f_frsize)
        .context("RAM free overflow")
}

fn archive_bytes(root: &Path, dev: u64) -> Result<u64> {
    let path = root.join("output");
    private_dir(&path, Some(dev))?;
    let mut physical = 0u64;
    let mut count = 0;
    for entry in fs::read_dir(path)? {
        count += 1;
        ensure!(count <= 2, "unexpected output census");
        let entry = entry?;
        let name = entry.file_name();
        ensure!(
            matches!(
                name.to_str(),
                Some("epoch-203-canary.jet" | "epoch-203-canary.jet.segment.json")
            ),
            "unexpected/canonical output in private canary"
        );
        let m = fs::symlink_metadata(entry.path())?;
        ensure!(
            m.is_file()
                && m.uid() == 1000
                && m.nlink() == 1
                && m.dev() == dev
                && m.mode() & 0o077 == 0,
            "unsafe canary output"
        );
        physical = physical
            .checked_add(
                m.blocks()
                    .checked_mul(512)
                    .context("archive block overflow")?,
            )
            .context("archive length overflow")?;
    }
    Ok(physical)
}

fn process_group(raw: &str) -> Result<u32> {
    let (_, tail) = raw.rsplit_once(')').context("malformed process stat")?;
    Ok(tail
        .split_whitespace()
        .nth(2)
        .context("missing group")?
        .parse()?)
}

fn vma_count(path: &Path) -> Result<u64> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut buf = [0u8; 131072];
    let mut total = 0u64;
    let start = Instant::now();
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(buf[..n].iter().filter(|b| **b == b'\n').count() as u64)
            .context("VMA overflow")?;
        ensure!(
            total <= VMA_MAX && start.elapsed() < Duration::from_secs(10),
            "VMA/time ceiling"
        );
    }
    ensure!(total > 0, "empty worker maps");
    Ok(total)
}

fn worker_digest(path: &Path, proc_exe: &Path, expected: &str, dev: u64) -> Result<FileIdentity> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && before.is_file()
            && before.uid() == 1000
            && before.nlink() == 1
            && before.dev() == dev
            && before.len() <= 256 << 20,
        "unsafe private worker executable"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 131072];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .context("worker size overflow")?;
        ensure!(count <= 256 << 20, "worker grew");
        hash.update(&buf[..n]);
    }
    let id = stat_identity(&before);
    ensure!(
        format!("{:x}", hash.finalize()) == expected
            && count == before.len()
            && stat_identity(&file.metadata()?) == id
            && stat_identity(&fs::symlink_metadata(path)?) == id
            && stat_identity(&fs::metadata(proc_exe)?) == id,
        "worker executable changed"
    );
    Ok(id)
}

struct Worker {
    pid: u32,
    path: PathBuf,
    identity: FileIdentity,
}

/// Call `check` from the bounded runner, before reaping its owned child.
pub struct OwnedRamGuard {
    binding: Binding,
    dev: u64,
    root_inode: u64,
    started: Instant,
    next: Instant,
    worker: Option<Worker>,
    stop_pin: Option<(String, Instant)>,
    first_worker_proof_written: bool,
}

impl OwnedRamGuard {
    pub fn start(binding: Binding) -> Result<Self> {
        ensure!(
            binding.unit.starts_with("horizon-203-ram-resource-")
                && binding.unit.ends_with(".service")
                && binding
                    .unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && hex(&binding.invocation_id, 32)
                && hex(&binding.worker_sha256, 64),
            "invalid RAM guard binding"
        );
        ensure!(
            binding.run_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
                && binding
                    .run_root
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.starts_with("ram-resource-203-"))
                && binding.node.is_absolute()
                && binding.node.canonicalize()? == binding.node,
            "wrong RAM/node scope"
        );
        let dev = private_dir(&binding.run_root, None)?;
        let root_inode = fs::symlink_metadata(&binding.run_root)?.ino();
        let node = fs::symlink_metadata(&binding.node)?;
        ensure!(
            node.is_file() && node.uid() == 0 && node.nlink() == 1 && node.mode() & 0o222 == 0,
            "node is not immutable root-owned input"
        );
        let g = Self {
            binding,
            dev,
            root_inode,
            started: Instant::now(),
            next: Instant::now(),
            worker: None,
            stop_pin: None,
            first_worker_proof_written: false,
        };
        g.authenticate()?;
        check_sample(g.sample()?, true)?;
        ensure!(
            number(Path::new("/proc/sys/vm/max_map_count"))? >= VMA_MAX + 100_000,
            "host VMA ceiling"
        );
        g.write_metadata(
            "ram-guard-start.json",
            &json!({
                "schema":"jetstreamer-private-epoch203-ram-guard-start-v1",
                "unit":g.binding.unit,"invocation_id":g.binding.invocation_id,
                "supervisor_pid":std::process::id(),"maximum_startup_grace_seconds":60,
                "root_device":g.dev,"root_inode":g.root_inode,
                "replay_launch_authorized":false,"retirement_authorized":false,
                "remote_mutations":false,"r2_mutations":false
            }),
        )?;
        Ok(g)
    }

    fn cgroup(&self) -> PathBuf {
        Path::new("/sys/fs/cgroup/system.slice").join(&self.binding.unit)
    }
    fn authenticate(&self) -> Result<()> {
        ensure!(
            env::var("INVOCATION_ID").as_deref() == Ok(self.binding.invocation_id.as_str())
                && text(Path::new("/proc/self/cgroup"))?.trim()
                    == format!("0::/system.slice/{}", self.binding.unit),
            "guard owner/cgroup changed"
        );
        ensure!(
            private_dir(&self.binding.run_root, Some(self.dev))? == self.dev
                && fs::symlink_metadata(&self.binding.run_root)?.ino() == self.root_inode,
            "RAM mount changed"
        );
        let root = self.cgroup();
        for (name, value) in [
            ("memory.max", MEMORY_MAX),
            ("memory.high", MEMORY_HIGH),
            ("memory.swap.max", 0),
            ("memory.oom.group", 1),
            ("pids.max", 512),
        ] {
            ensure!(
                number(&root.join(name))? == value,
                "cgroup safety limit changed"
            );
        }
        let quota = text(&root.join("cpu.max"))?;
        let fields: Vec<_> = quota.split_whitespace().collect();
        ensure!(fields.len() == 2, "invalid CPU quota");
        let period: u64 = fields[1].parse()?;
        ensure!(
            period > 0
                && fields[0].parse::<u64>()?
                    == period.checked_mul(16).context("CPU quota overflow")?,
            "CPU quota changed"
        );
        Ok(())
    }
    fn sample(&self) -> Result<Sample> {
        Ok(Sample {
            host_available: available_memory(&text(Path::new("/proc/meminfo"))?)?,
            ram_available: ram_available(&self.binding.run_root)?,
            memory_current: number(&self.cgroup().join("memory.current"))?,
            memory_limit_events: memory_events(&text(&self.cgroup().join("memory.events"))?)?,
            archive_physical: archive_bytes(&self.binding.run_root, self.dev)?,
        })
    }

    fn worker_census(&mut self, child: u32, elapsed: Duration, draining: bool) -> Result<u64> {
        let raw = text(&self.cgroup().join("cgroup.procs"))?;
        let mut pids = BTreeSet::new();
        let mut found = None;
        let me = std::process::id();
        let self_exe = fs::read_link("/proc/self/exe")?;
        for line in raw.lines() {
            let pid: u32 = line.parse()?;
            ensure!(
                pid > 1 && pids.insert(pid) && pids.len() <= 512,
                "invalid process census"
            );
            let proc = Path::new("/proc").join(pid.to_string());
            let exe = match fs::read_link(proc.join("exe")) {
                Ok(p) => p,
                Err(e)
                    if draining && matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            if pid == me {
                ensure!(exe == self_exe, "guard executable changed");
                continue;
            }
            ensure!(
                text(&proc.join("cgroup"))?.trim()
                    == format!("0::/system.slice/{}", self.binding.unit)
                    && process_group(&text(&proc.join("stat"))?)? == child,
                "foreign process/group in canary"
            );
            if pid == child {
                ensure!(exe == self.binding.node, "owned node executable differs");
                continue;
            }
            ensure!(
                exe.starts_with(self.binding.run_root.join("scratch"))
                    && exe.file_name().is_some_and(|s| s == "historical-worker")
                    && found.is_none(),
                "foreign/multiple workers"
            );
            if let Some(w) = &self.worker {
                ensure!(
                    pid == w.pid
                        && exe == w.path
                        && stat_identity(&fs::metadata(proc.join("exe"))?) == w.identity
                        && stat_identity(&fs::symlink_metadata(&exe)?) == w.identity,
                    "worker identity changed"
                );
            } else {
                let identity = worker_digest(
                    &exe,
                    &proc.join("exe"),
                    &self.binding.worker_sha256,
                    self.dev,
                )?;
                self.worker = Some(Worker {
                    pid,
                    path: exe,
                    identity,
                });
            }
            found = Some(vma_count(&proc.join("maps"))?);
        }
        ensure!(pids.contains(&me), "guard absent from cgroup");
        ensure!(
            draining || found.is_none() || pids.contains(&child),
            "owned node absent during positive pre-target worker sample"
        );
        match found {
            Some(vmas) => Ok(vmas),
            None if draining
                || (self.worker.is_none()
                    && elapsed < Duration::from_secs(60)
                    && self.started.elapsed() < Duration::from_secs(60)) =>
            {
                Ok(0)
            }
            None => anyhow::bail!("missing pre-target worker"),
        }
    }

    fn write_metadata(&self, name: &str, value: &Value) -> Result<()> {
        ensure!(
            matches!(
                name,
                "ram-guard-start.json" | "ram-guard-stop.json" | "ram-guard-first-worker.json"
            ),
            "invalid guard metadata name"
        );
        let parent = self.binding.run_root.join("receipts");
        private_dir(&parent, Some(self.dev))?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW)
            .open(parent.join(name))?;
        serde_json::to_writer_pretty(&mut f, value)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    // Called only after the complete owned-cgroup/resource/VMA checks pass.
    // Grace and drainage checks never prove the first live worker fire. This
    // fsync is tmpfs retention, not durable root-storage or launch authority.
    fn record_first_worker_sample(
        &mut self,
        child: u32,
        elapsed: Duration,
        draining: bool,
        vmas: u64,
        sample: Sample,
    ) -> Result<()> {
        if self.first_worker_proof_written || draining || vmas == 0 {
            return Ok(());
        }
        check_sample(sample, false)?;
        ensure!(vmas <= VMA_MAX, "first worker exceeds VMA ceiling");
        let worker = self
            .worker
            .as_ref()
            .context("positive sample lacks owned worker")?;
        ensure!(
            child > 1
                && child != std::process::id()
                && worker.pid > 1
                && worker.pid != child
                && worker.pid != std::process::id()
                && worker
                    .path
                    .starts_with(self.binding.run_root.join("scratch"))
                && worker
                    .path
                    .file_name()
                    .is_some_and(|s| s == "historical-worker"),
            "first worker identity is not the owned private worker"
        );
        let millis: u64 = elapsed
            .as_millis()
            .try_into()
            .context("guard elapsed overflow")?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let proof = json!({
            "schema":"jetstreamer-private-epoch203-ram-guard-first-worker-v1",
            "unit":self.binding.unit,"invocation_id":self.binding.invocation_id,
            "supervisor_pid":std::process::id(),"child_pid":child,
            "worker_pid":worker.pid,"worker_executable":worker.path,
            "worker_sha256":self.binding.worker_sha256,"worker_file_identity":worker.identity,
            "node":self.binding.node,"run_root":self.binding.run_root,
            "root_device":self.dev,"root_inode":self.root_inode,
            "written_unix_seconds":now,"elapsed_millis":millis,
            "worker_vmas":vmas,"host_available_bytes":sample.host_available,
            "tmpfs_available_bytes":sample.ram_available,"memory_current_bytes":sample.memory_current,
            "memory_limit_events":sample.memory_limit_events,"archive_physical_bytes":sample.archive_physical,
            "owned_process_census_verified":true,"pre_target_worker_observed":true,
            "grace_only":false,"draining":false,"guard_trip":false,
            "durable_root_copy_verified":false,"replay_launch_authorized":false,
            "full_cold_epoch_peak_qualified":false,"retirement_authorized":false,
            "runtime_promotion_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        });
        self.write_metadata("ram-guard-first-worker.json", &proof)?;
        self.first_worker_proof_written = true;
        Ok(())
    }

    fn intent(&self, child: u32, reason: &str) -> Result<()> {
        self.write_metadata("ram-guard-stop.json",&json!({"schema":"jetstreamer-private-epoch203-ram-guard-stop-v1",
            "unit":self.binding.unit,"invocation_id":self.binding.invocation_id,"child_pid":child,
            "reason":reason,"producer_signals_sent_by_guard":false,"replay_restart_authorized":false,
            "retirement_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}))
    }

    fn validate_drain(&mut self, child: u32) -> Result<()> {
        let path = self.binding.run_root.join("receipts/target-stop.json");
        let bytes = private_evidence(&path, self.dev, 65536)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let stop: Value = serde_json::from_slice(&bytes)?;
        validate_target_stop(&stop, &self.binding.invocation_id, child, now)?;
        let capture_path = self.binding.run_root.join("receipts/target-capture.json");
        ensure!(
            stop["capture_path"].as_str() == capture_path.to_str(),
            "capture path differs"
        );
        let capture: Value =
            serde_json::from_slice(&private_evidence(&capture_path, self.dev, 16 << 20)?)?;
        let capture_sha = format!("{:x}", Sha256::digest(serde_json::to_vec(&capture)?));
        ensure!(
            stop["capture_canonical_json_sha256"] == capture_sha
                && capture["scratch"]["physical_bytes"]
                    .as_u64()
                    .is_some_and(|n| n <= 192 * GIB)
                && capture["accounts_state"]["regular_files"]
                    .as_u64()
                    .is_some_and(|n| n > 0)
                && capture["cgroup"].is_object(),
            "capture hash or bounded content differs"
        );
        let sha = format!("{:x}", Sha256::digest(&bytes));
        if let Some((pinned, at)) = &self.stop_pin {
            ensure!(
                *pinned == sha && at.elapsed() <= Duration::from_secs(180),
                "drain proof renewed/expired"
            );
        } else {
            self.stop_pin = Some((sha, Instant::now()));
        }
        Ok(())
    }

    pub fn check(
        &mut self,
        child: u32,
        elapsed: Duration,
        draining: bool,
    ) -> Result<Option<Value>> {
        ensure!(
            child > 1 && child <= i32::MAX as u32 && child != std::process::id(),
            "invalid owned child"
        );
        if Instant::now() < self.next {
            return Ok(None);
        }
        self.next = Instant::now() + INTERVAL;
        let result = (|| -> Result<Value> {
            self.authenticate()?;
            let s = self.sample()?;
            check_sample(s, false)?;
            if draining {
                self.validate_drain(child)?;
            }
            let vmas = self.worker_census(child, elapsed, draining)?;
            self.authenticate()?;
            self.record_first_worker_sample(child, elapsed, draining, vmas, s)?;
            Ok(
                json!({"host_available_bytes":s.host_available,"tmpfs_available_bytes":s.ram_available,
                "memory_current_bytes":s.memory_current,"archive_physical_bytes":s.archive_physical,"worker_vmas":vmas}),
            )
        })();
        match result {
            Ok(v) => Ok(Some(v)),
            Err(e) => {
                self.intent(child, &format!("{e:#}"))?;
                Err(e)
            }
        }
    }
}

fn validate_target_stop(v: &Value, inv: &str, child: u32, now: u64) -> Result<()> {
    let at = v["written_unix_seconds"]
        .as_u64()
        .context("handoff timestamp missing")?;
    ensure!(
        v["schema"] == "jetstreamer-private-epoch203-canary-target-stop-v1"
            && v["invocation_id"] == inv
            && v["child_pid"] == child
            && v["target_slot"] == 87_720_000
            && v["observed_slot"]
                .as_u64()
                .is_some_and(|s| (87_720_000..=87_721_000).contains(&s))
            && v["scratch_snapshot_captured"] == true
            && v["external_signal"] == 0
            && at <= now
            && now - at <= 180,
        "invalid/expired target drainage proof"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Filesystem policy fixture only: no process is executed and none of these
    // temporary bytes is an operational guard/capability attestation.
    fn proof_fixture(root: &Path) -> OwnedRamGuard {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["scratch", "receipts"] {
            let path = root.join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = root.join("scratch/historical-worker");
        fs::write(&path, b"not an executable; policy fixture only").unwrap();
        let identity = stat_identity(&fs::metadata(&path).unwrap());
        OwnedRamGuard {
            binding: Binding {
                unit: "horizon-203-ram-resource-baseline-fixture.service".into(),
                invocation_id: "a".repeat(32),
                run_root: root.into(),
                node: "/sealed/node".into(),
                worker_sha256: "b".repeat(64),
            },
            dev: fs::metadata(root).unwrap().dev(),
            root_inode: fs::metadata(root).unwrap().ino(),
            started: Instant::now(),
            next: Instant::now(),
            stop_pin: None,
            first_worker_proof_written: false,
            worker: Some(Worker {
                pid: 125,
                path,
                identity,
            }),
        }
    }

    #[test]
    fn first_worker_proof_excludes_grace_and_drain_and_requires_bounded_owned_identity() {
        let t = tempfile::tempdir().unwrap();
        let mut guard = proof_fixture(t.path());
        guard
            .record_first_worker_sample(123, Duration::from_secs(1), false, 0, sample())
            .unwrap();
        guard
            .record_first_worker_sample(123, Duration::from_secs(1), true, 10, sample())
            .unwrap();
        assert!(!guard.first_worker_proof_written);
        assert!(
            !t.path()
                .join("receipts/ram-guard-first-worker.json")
                .exists()
        );
        let mut bad = sample();
        bad.memory_limit_events = 1;
        assert!(
            guard
                .record_first_worker_sample(123, Duration::from_secs(1), false, 10, bad)
                .is_err()
        );
        assert!(
            guard
                .record_first_worker_sample(
                    123,
                    Duration::from_secs(1),
                    false,
                    VMA_MAX + 1,
                    sample()
                )
                .is_err()
        );
        guard.worker.as_mut().unwrap().pid = 123;
        assert!(
            guard
                .record_first_worker_sample(123, Duration::from_secs(1), false, 10, sample())
                .is_err()
        );
        guard.worker = None;
        assert!(
            guard
                .record_first_worker_sample(123, Duration::from_secs(1), false, 10, sample())
                .is_err()
        );
        assert!(!guard.first_worker_proof_written);
        assert!(
            !t.path()
                .join("receipts/ram-guard-first-worker.json")
                .exists()
        );
    }

    #[test]
    fn first_worker_proof_is_private_no_clobber_and_does_not_renew_or_grant_authority() {
        let t = tempfile::tempdir().unwrap();
        let mut guard = proof_fixture(t.path());
        let result = guard.record_first_worker_sample(
            123,
            Duration::from_millis(12345),
            false,
            10,
            sample(),
        );
        if unsafe { libc::geteuid() } != 1000 || unsafe { libc::getegid() } != 1000 {
            assert!(result.is_err());
            assert!(!guard.first_worker_proof_written);
            return;
        }
        result.unwrap();
        assert!(guard.first_worker_proof_written);
        let path = t.path().join("receipts/ram-guard-first-worker.json");
        let bytes = fs::read(&path).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["invocation_id"], "a".repeat(32));
        assert_eq!(v["child_pid"], 123);
        assert_eq!(v["worker_pid"], 125);
        assert_eq!(v["elapsed_millis"], 12345);
        assert_eq!(v["worker_vmas"], 10);
        for key in [
            "grace_only",
            "draining",
            "guard_trip",
            "durable_root_copy_verified",
            "replay_launch_authorized",
            "full_cold_epoch_peak_qualified",
            "retirement_authorized",
            "runtime_promotion_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            assert_eq!(v[key], false, "{key}");
        }
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
        guard
            .record_first_worker_sample(123, Duration::from_secs(60), false, 20, sample())
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        // Even an interrupted/recreated guard must not overwrite earlier bytes.
        guard.first_worker_proof_written = false;
        assert!(
            guard
                .record_first_worker_sample(123, Duration::from_secs(61), false, 30, sample())
                .is_err()
        );
        assert!(!guard.first_worker_proof_written);
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    fn sample() -> Sample {
        Sample {
            host_available: START_MEMORY,
            ram_available: TMPFS_SIZE,
            memory_current: MEMORY_MAX,
            memory_limit_events: 0,
            archive_physical: ARCHIVE_MAX,
        }
    }
    #[test]
    fn complete_guard_geometry_preserves_unchanged_host_reserve() {
        check_sample(sample(), true).unwrap();
        assert_eq!(START_MEMORY - MEMORY_MAX, STOP_MEMORY);
        assert_eq!(STOP_MEMORY - MEMORY_MAX, 224 * GIB);
        const {
            assert!(TMPFS_SIZE - RAM_FILES_MAX > CENTURY_FLOOR);
        }
    }
    #[test]
    fn every_resource_stop_is_fail_closed() {
        for i in 0..6 {
            let mut s = sample();
            match i {
                0 => s.host_available = STOP_MEMORY - 1,
                1 => s.ram_available = CENTURY_FLOOR - 1,
                2 => s.ram_available = TMPFS_SIZE - RAM_FILES_MAX - 1,
                3 => s.memory_current += 1,
                4 => s.memory_limit_events = 1,
                _ => s.archive_physical += 1,
            }
            assert!(check_sample(s, false).is_err(), "accepted violation{i}");
        }
        let mut s = sample();
        s.host_available = START_MEMORY - 1;
        assert!(check_sample(s, true).is_err());
        check_sample(s, false).unwrap();
    }
    #[test]
    fn kernel_parsers_reject_missing_duplicate_overflow_and_wrong_units() {
        assert_eq!(available_memory("MemAvailable: 123 kB\n").unwrap(), 125952);
        for bad in [
            "",
            "MemAvailable: 1 MB",
            "MemAvailable: 1 kB\nMemAvailable: 2 kB",
            "MemAvailable: 18446744073709551615 kB",
        ] {
            assert!(available_memory(bad).is_err());
        }
        let raw = "low 0\nhigh 20\nmax 0\noom 0\noom_kill 0\n";
        assert_eq!(memory_events(raw).unwrap(), 0);
        assert_eq!(memory_events(&raw.replace("max 0", "max 1")).unwrap(), 1);
        assert!(memory_events(&format!("{raw}high 0\n")).is_err());
        assert!(memory_events("max 0\n").is_err());
    }
    #[test]
    fn proc_group_parser_handles_parentheses_and_never_uses_parent_pid() {
        assert_eq!(process_group("123 (a)b(c) T 456 789 0").unwrap(), 789);
        assert!(process_group("invalid").is_err());
    }
    #[test]
    fn bounded_reads_refuse_symlinks_and_vma_limit() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("maps");
        fs::write(&p, b"x\ny\n").unwrap();
        assert_eq!(vma_count(&p).unwrap(), 2);
        assert!(read(&p, 3).is_err());
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(vma_count(&link).is_err());
        fs::write(&p, vec![b'\n'; VMA_MAX as usize + 1]).unwrap();
        assert!(vma_count(&p).is_err());
    }
    #[test]
    fn target_drain_requires_exact_child_invocation_window_and_no_external_signal() {
        let good = json!({"schema":"jetstreamer-private-epoch203-canary-target-stop-v1",
            "written_unix_seconds":1000,"invocation_id":"a".repeat(32),"child_pid":123,
            "target_slot":87720000,"observed_slot":87720000,"scratch_snapshot_captured":true,"external_signal":0});
        validate_target_stop(&good, &"a".repeat(32), 123, 1180).unwrap();
        assert!(validate_target_stop(&good, &"a".repeat(32), 123, 1181).is_err());
        assert!(validate_target_stop(&good, &"a".repeat(32), 123, 999).is_err());
        assert!(validate_target_stop(&good, &"b".repeat(32), 123, 1100).is_err());
        assert!(validate_target_stop(&good, &"a".repeat(32), 124, 1100).is_err());
        for (key, v) in [
            ("target_slot", json!(87719999)),
            ("observed_slot", json!(87719999)),
            ("observed_slot", json!(87721001)),
            ("external_signal", json!(2)),
            ("scratch_snapshot_captured", json!(false)),
            ("schema", json!("foreign")),
        ] {
            let mut bad = good.clone();
            bad[key] = v;
            assert!(
                validate_target_stop(&bad, &"a".repeat(32), 123, 1100).is_err(),
                "accepted{key}"
            );
        }
    }
    #[test]
    fn retained_capture_hash_and_nonrenewable_pin_are_required_for_zero_worker_drain() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let receipts = root.join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let dev = fs::metadata(root).unwrap().dev();
        let mut guard = OwnedRamGuard {
            binding: Binding {
                unit: "horizon-203-ram-resource-fixture.service".into(),
                invocation_id: "a".repeat(32),
                run_root: root.into(),
                node: "/sealed/node".into(),
                worker_sha256: "b".repeat(64),
            },
            dev,
            root_inode: fs::metadata(root).unwrap().ino(),
            started: Instant::now(),
            next: Instant::now(),
            worker: None,
            stop_pin: None,
            first_worker_proof_written: false,
        };
        let capture = json!({"scratch":{"physical_bytes":4096},"accounts_state":{"regular_files":1},"cgroup":{}});
        let cp = receipts.join("target-capture.json");
        fs::write(&cp, serde_json::to_vec_pretty(&capture).unwrap()).unwrap();
        fs::set_permissions(&cp, fs::Permissions::from_mode(0o400)).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let stop = json!({"schema":"jetstreamer-private-epoch203-canary-target-stop-v1","written_unix_seconds":now,
            "invocation_id":"a".repeat(32),"child_pid":123,"target_slot":87720000,"observed_slot":87720000,
            "scratch_snapshot_captured":true,"external_signal":0,"capture_path":cp,
            "capture_canonical_json_sha256":format!("{:x}",Sha256::digest(serde_json::to_vec(&capture).unwrap()))});
        let sp = receipts.join("target-stop.json");
        fs::write(&sp, serde_json::to_vec(&stop).unwrap()).unwrap();
        fs::set_permissions(&sp, fs::Permissions::from_mode(0o400)).unwrap();
        if unsafe { libc::geteuid() } != 1000 {
            assert!(guard.validate_drain(123).is_err());
            return;
        }
        guard.validate_drain(123).unwrap();
        guard.validate_drain(123).unwrap();
        fs::set_permissions(&sp, fs::Permissions::from_mode(0o600)).unwrap();
        let mut changed = stop.clone();
        changed["observed_slot"] = json!(87720001);
        fs::write(&sp, serde_json::to_vec(&changed).unwrap()).unwrap();
        fs::set_permissions(&sp, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(guard.validate_drain(123).is_err());
        fs::set_permissions(&sp, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&sp, serde_json::to_vec(&stop).unwrap()).unwrap();
        fs::set_permissions(&sp, fs::Permissions::from_mode(0o400)).unwrap();
        guard.validate_drain(123).unwrap();
        guard.stop_pin.as_mut().unwrap().1 = Instant::now() - Duration::from_secs(181);
        assert!(guard.validate_drain(123).is_err());
        guard.stop_pin = None;
        fs::set_permissions(&cp, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&cp, b"{}").unwrap();
        fs::set_permissions(&cp, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(guard.validate_drain(123).is_err());
        assert!(!receipts.join("ram-guard-stop.json").exists());
    }

    #[test]
    fn guard_intent_never_overwrites_existing_metadata_or_grants_authority() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let receipts = root.join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let guard = OwnedRamGuard {
            binding: Binding {
                unit: "horizon-203-ram-resource-fixture.service".into(),
                invocation_id: "a".repeat(32),
                run_root: root.into(),
                node: "/sealed/node".into(),
                worker_sha256: "b".repeat(64),
            },
            dev: fs::metadata(root).unwrap().dev(),
            root_inode: fs::metadata(root).unwrap().ino(),
            started: Instant::now(),
            next: Instant::now(),
            worker: None,
            stop_pin: None,
            first_worker_proof_written: false,
        };
        if unsafe { libc::geteuid() } != 1000 || unsafe { libc::getegid() } != 1000 {
            assert!(guard.intent(123, "fixture").is_err());
            return;
        }
        guard.intent(123, "fixture").unwrap();
        let path = receipts.join("ram-guard-stop.json");
        let bytes = fs::read(&path).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["child_pid"], 123);
        assert_eq!(v["producer_signals_sent_by_guard"], false);
        assert_eq!(v["retirement_authorized"], false);
        assert_eq!(v["replay_restart_authorized"], false);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
        assert!(guard.intent(124, "replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn worker_hash_identity_rejects_wrong_bytes_and_aliases() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("historical-worker");
        fs::write(&p, b"immutable worker fixture").unwrap();
        let dev = fs::metadata(&p).unwrap().dev();
        let sha = format!("{:x}", Sha256::digest(b"immutable worker fixture"));
        if unsafe { libc::geteuid() } != 1000 {
            assert!(worker_digest(&p, &p, &sha, dev).is_err());
            return;
        }
        worker_digest(&p, &p, &sha, dev).unwrap();
        assert!(worker_digest(&p, &p, &"0".repeat(64), dev).is_err());
        let link = t.path().join("alias");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(worker_digest(&link, &p, &sha, dev).is_err());
        fs::hard_link(&p, t.path().join("hard-link")).unwrap();
        assert!(worker_digest(&p, &p, &sha, dev).is_err());
    }

    #[test]
    fn private_output_census_rejects_sidecars_and_unexpected_files() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let output = t.path().join("output");
        fs::create_dir(&output).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        let dev = fs::metadata(&output).unwrap().dev();
        if unsafe { libc::geteuid() } != 1000 || unsafe { libc::getegid() } != 1000 {
            assert!(archive_bytes(t.path(), dev).is_err());
            return;
        }
        assert_eq!(archive_bytes(t.path(), dev).unwrap(), 0);
        let archive = output.join("epoch-203-canary.jet");
        fs::write(&archive, b"private diagnostic").unwrap();
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(archive_bytes(t.path(), dev).unwrap() > 0);
        fs::write(
            output.join("epoch-203-canary.jet.sha256"),
            b"never canonical",
        )
        .unwrap();
        assert!(archive_bytes(t.path(), dev).is_err());
    }
}
