// Private resource measurement with a binary-local sealed scope.
// This wrapper never imports archives or creates canonical checksum sidecars.
use {
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        env, fs,
        fs::{File, OpenOptions},
        io::{BufRead, BufReader, Read, Write},
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::{
            atomic::{AtomicI32, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};

use crate::profile::*;
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
static EXTERNAL_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoundFile {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub(crate) schema: String,
    pub(crate) unit: String,
    pub(crate) node: BoundFile,
    pub(crate) worker: PathBuf,
    pub(crate) snapshot: PathBuf,
    pub(crate) ledger_directory: PathBuf,
    pub(crate) epoch_hashes: BoundFile,
    pub(crate) run_root: PathBuf,
    pub(crate) target_slot: u64,
    pub(crate) terminal_slot: u64,
    pub(crate) minimum_free_bytes: u64,
    pub(crate) maximum_runtime_seconds: u64,
}

/// Compile-bound extension points for a separately reviewed storage sandbox.
/// Plans cannot select an implementation. Existing binaries use DiskStorage;
/// no RAM path, mount operation or relaxed resource gate is introduced here.
pub(crate) trait StorageHooks {
    fn capability_only(&self)->bool {false}
    fn capability_result(&self,_p:&Plan,_invocation:&str,_bindings:&Value,_command:&Command)->Result<()> {
        anyhow::bail!("storage capability path is unsupported")
    }
    fn decode_plan(&self, bytes: &[u8]) -> Result<Plan> {
        Ok(serde_json::from_slice(bytes)?)
    }
    fn prepare(&self, _plan: &Plan) -> Result<()> { Ok(()) }
    fn configure_command(&self, _plan: &Plan, _command: &mut Command) -> Result<()> { Ok(()) }
    fn before_spawn(&self, _plan: &Plan, _invocation: &str) -> Result<Value> { Ok(Value::Null) }
    // A safety check, not a new routine observer. Implementations must enforce
    // their own guard cadence and persist any stop intent before returning Err.
    fn guard(&self, _plan: &Plan, _invocation: &str, _child: u32,
        _elapsed: Duration, _draining: bool) -> Result<()> { Ok(()) }
}
struct DiskStorage;
impl StorageHooks for DiskStorage {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(crate) fn bound_file(path: &Path, expected: &str, maximum: u64) -> Result<()> {
    ensure!(
        digest(expected) && path.is_absolute() && path.canonicalize()? == path,
        "invalid bound file"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= maximum,
        "unsafe immutable input"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "input replaced at open"
    );
    let mut sha = Sha256::new();
    let mut buf = [0u8; 128 * 1024];
    let mut bytes = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .context("input length overflow")?;
        ensure!(bytes <= maximum, "input grew beyond bound");
        sha.update(&buf[..n]);
    }
    let after = fs::symlink_metadata(path)?;
    ensure!(
        bytes == before.len()
            && hex(&sha.finalize()) == expected
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "input digest or identity changed"
    );
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "unsafe private directory"
    );
    Ok(())
}

pub(crate) fn persist(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    private_directory(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(temp.as_file_mut(), value)?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("receipt already exists or cannot publish: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == PLAN_SCHEMA
            && p.unit.starts_with(UNIT_PREFIX)
            && p.unit.ends_with(".service")
            && p.unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "wrong canary scope"
    );
    ensure!(
        p.run_root.parent() == Some(Path::new(if EPOCH == 186 {
            "/home/sol/.jetstreamer-private"
        } else { "/home/ubuntu/.jetstreamer-private" }))
            && p.run_root
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(ROOT_PREFIX)),
        "wrong private root"
    );
    ensure!(
        p.target_slot == TARGET
            && p.terminal_slot == TERMINAL
            && p.minimum_free_bytes >= MINIMUM_FREE
            && (600..=MAX_RUNTIME).contains(&p.maximum_runtime_seconds),
        "work or resource bounds changed"
    );
    ensure!(
        p.snapshot.file_name().and_then(|n| n.to_str()) == Some(SNAPSHOT_NAME),
        "wrong snapshot"
    );
    ensure!(
        digest(&p.node.sha256) && digest(&p.epoch_hashes.sha256),
        "invalid input digest"
    );
    ensure!(
        PARENT_SHA.is_empty() || p.node.sha256 == PARENT_SHA,
        "parent differs from the exact capability-bound build"
    );
    Ok(())
}

fn command(p: &Plan) -> Command {
    let mut c = Command::new(&p.node.path);
    c.arg(EPOCH.to_string())
        .arg(p.run_root.join("ledger"))
        .args(["--verify"])
        .arg(format!("--qualification-end-slot={TERMINAL}"))
        .arg(format!("--snapshot-archive={}", p.snapshot.display()))
        .arg(format!("--epoch-hashes={}", p.epoch_hashes.path.display()))
        .arg(format!(
            "--horizon-output={}",
            p.run_root.join("output").join(ARCHIVE_NAME).display()
        ))
        .arg(format!(
            "--replay-scratch={}",
            p.run_root.join("scratch").display()
        ))
        .env("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1")
        // Private diagnostic only: preserve voted/parent/SlotHashes evidence
        // on Custom(2), without changing runtime or transaction semantics.
        .env("JETSTREAMER_HISTORICAL_TRACE", "1")
        .env("RUST_LOG", "info")
        .env("SOLANA_RAYON_THREADS", RAYON_THREADS.to_string())
        .env_remove("JETSTREAMER_HISTORICAL_WORKER_V1_6_15")
        .env_remove("JETSTREAMER_HISTORICAL_WORKER_V1_6_16")
        .env_remove("JETSTREAMER_HISTORICAL_WORKER_V1_6_20")
        .env_remove("JETSTREAMER_HISTORICAL_WORKER_V1_6_25")
        .env(WORKER_ENV, &p.worker)
        .env_remove("HORIZON_S3_ENDPOINT")
        .env_remove("HORIZON_ACCESS_KEY_ID")
        .env_remove("HORIZON_SECRET_ACCESS_KEY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    c
}

// Optional counters must never control target detection. Only the parent's
// own progress record (not a program log or another logger) is recognized.
fn progress_slot(line: &str) -> Option<u64> {
    let (prefix, rest) = line.split_once(" jetstreamer_node] progress slot ")?;
    if !prefix.starts_with('[') || !prefix.contains(" INFO ") {
        return None;
    }
    let (slot, terminal) = rest.split_once('/')?;
    let terminal = terminal.split_whitespace().next()?.parse::<u64>().ok()?;
    if terminal != TERMINAL || slot.is_empty() || !slot.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let slot = slot.parse::<u64>().ok()?;
    (INITIAL_REPLAY..=TERMINAL).contains(&slot).then_some(slot)
}

fn progress_counters(line: &str) -> Option<Value> {
    let slot = progress_slot(line)?;
    let counter = |prefix: &str| {
        line.split_whitespace()
            .find_map(|s| s.strip_prefix(prefix))
            .and_then(|n| n.parse::<u64>().ok())
    };
    Some(
        json!({"slot":slot,"transactions":counter("txs=")?,"account_updates":counter("accounts=")?}),
    )
}

fn metrics(cgroup: &Path) -> Result<Value> {
    let mut map = serde_json::Map::new();
    for name in [
        "memory.current",
        "memory.peak",
        "memory.events",
        "memory.stat",
        "cpu.stat",
        "io.stat",
        "memory.pressure",
        "io.pressure",
    ] {
        map.insert(name.into(), json!(fs::read_to_string(cgroup.join(name))?));
    }
    Ok(Value::Object(map))
}

fn scratch(root: &Path) -> Result<Value> {
    let dev = fs::symlink_metadata(root)?.dev();
    let mut pending = vec![(root.to_path_buf(), 0)];
    let (mut physical, mut apparent, mut files, mut dirs) = (0u64, 0u64, 0u64, 0u64);
    let mut account_roots = Vec::new();
    let mut histogram = std::collections::BTreeMap::<u64, u64>::new();
    let started = Instant::now();
    while let Some((path, depth)) = pending.pop() {
        ensure!(
            depth <= 64
                && files + dirs + pending.len() as u64 <= 4_000_000
                && started.elapsed() < Duration::from_secs(120),
            "scratch scan bound"
        );
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.dev() == dev && !m.file_type().is_symlink(),
            "scratch escaped filesystem or contains symlink"
        );
        physical = physical
            .checked_add(m.blocks().checked_mul(512).context("block overflow")?)
            .context("size overflow")?;
        apparent = apparent.checked_add(m.len()).context("apparent overflow")?;
        ensure!(physical <= MAX_SCRATCH, "scratch exceeds sealed profile limit of {MAX_SCRATCH} bytes");
        if m.is_dir() {
            dirs += 1;
            if path.file_name().is_some_and(|n| n == "accounts-state") {
                account_roots.push(path.clone());
            }
            for entry in fs::read_dir(path)? {
                pending.push((entry?.path(), depth + 1));
            }
        } else {
            ensure!(m.is_file(), "unexpected scratch object");
            files += 1;
            *histogram.entry(m.len()).or_default() += 1;
        }
    }
    Ok(
        json!({"path":root,"physical_bytes":physical,"apparent_bytes":apparent,"regular_files":files,"directories":dirs,"file_size_histogram_bytes":histogram,"accounts_state_roots":account_roots}),
    )
}

fn capture_resources(scratch_root: &Path, cgroup: &Path) -> Result<Value> {
    let tree = scratch(scratch_root)?;
    let roots = tree["accounts_state_roots"]
        .as_array()
        .context("accounts-state census")?;
    ensure!(roots.len() == 1, "expected one live accounts-state");
    let account_root = Path::new(roots[0].as_str().context("accounts-state path")?);
    Ok(json!({"scratch":tree,"accounts_state":scratch(account_root)?,"cgroup":metrics(cgroup)?}))
}

fn free_bytes(path: &Path) -> Result<u64> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), v.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let v = unsafe { v.assume_init() };
    v.f_bavail.checked_mul(v.f_frsize).context("free overflow")
}

extern "C" fn signal_handler(signal: libc::c_int) {
    EXTERNAL_SIGNAL.store(signal, Ordering::SeqCst);
}
fn install_signals() -> Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = signal_handler as *const () as usize;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        ensure!(
            unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0,
            "cannot install signal handler"
        );
    }
    Ok(())
}

fn group_signal(pid: u32, signal: i32) -> Result<()> {
    ensure!(pid > 1 && pid <= i32::MAX as u32, "unsafe child pid");
    let result = unsafe { libc::kill(-(pid as i32), signal) };
    if result != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(e.into());
        }
    }
    Ok(())
}

fn stat_group_state(stat: &str) -> Result<(u32, char)> {
    let (_, suffix) = stat.rsplit_once(')').context("malformed process stat")?;
    let fields = suffix.split_whitespace().collect::<Vec<_>>();
    ensure!(fields.len() >= 3, "short process stat");
    Ok((
        fields[2].parse()?,
        fields[0].chars().next().context("missing state")?,
    ))
}

fn group_stopped(leader: u32) -> Result<bool> {
    let mut saw_leader = false;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match fs::read_to_string(entry.path().join("stat")) {
            Ok(s) => s,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => continue,
            Err(e) => return Err(e.into()),
        };
        if stat_group_state(&stat)?.0 != leader {
            continue;
        }
        if pid == leader {
            saw_leader = true;
        }
        for task in fs::read_dir(entry.path().join("task"))? {
            let stat = fs::read_to_string(task?.path().join("stat"))?;
            let (group, state) = stat_group_state(&stat)?;
            ensure!(group == leader, "child group changed during freeze");
            if !matches!(state, 'T' | 't') {
                return Ok(false);
            }
        }
    }
    Ok(saw_leader)
}

fn freeze_group(leader: u32) -> Result<()> {
    group_signal(leader, libc::SIGSTOP)?;
    let started = Instant::now();
    loop {
        if group_stopped(leader)? {
            return Ok(());
        }
        ensure!(
            started.elapsed() < Duration::from_secs(10),
            "child group did not freeze"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

struct ChildGroup(Child, bool);
impl Drop for ChildGroup {
    fn drop(&mut self) {
        // Never strand a frozen child on an error. SIGKILL is confined to this
        // wrapper-created process group, including temporary legacy descendants.
        // An unreaped owned child pins the process-group leader PID. Once
        // reaped, never signal that numeric PGID again: it could be reused.
        if !self.1 {
            let _ = group_signal(self.0.id(), libc::SIGCONT);
            let _ = group_signal(self.0.id(), libc::SIGKILL);
            let _ = self.0.try_wait();
        }
    }
}

fn reader<R: Read + Send + 'static>(input: R, tx: mpsc::SyncSender<Result<String, String>>) {
    thread::spawn(move || {
        let mut reader = BufReader::new(input);
        loop {
            let mut bytes = Vec::new();
            let read = reader.by_ref().take(65537).read_until(b'\n', &mut bytes);
            let message = match read {
                Ok(0) => break,
                Ok(_) if bytes.len() > 65536 => Err("child log line exceeds64KiB".into()),
                Ok(_) => String::from_utf8(bytes).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let failed = message.is_err();
            if tx.send(message).is_err() || failed {
                break;
            }
        }
    });
}

fn controlled_success(target: bool, external: i32, code: Option<i32>) -> bool {
    target && external == 0 && matches!(code, Some(0 | 1))
}

fn validate_checkpoint_names(hashes: &str) -> Result<()> {
    let names = hashes
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        names == CHECKPOINT_NAMES,
        "wrong canonical checkpoint set"
    );
    Ok(())
}

fn run(storage: &dyn StorageHooks) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "run as isolated replay user"
    );
    let args: Vec<_> = env::args().collect();
    let capability=storage.capability_only();
    ensure!(
        args.len() == if capability {7}else{6} && args[2] == "--plan-sha256" && args[4] == "--self-sha256"
            && (!capability || args[6]=="--storage-capability"),
        "usage: canary PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    bound_file(&fs::read_link("/proc/self/exe")?, &args[5], 256 << 20)?;
    bound_file(Path::new(&args[1]), &args[3], 1 << 20)?;
    let p = storage.decode_plan(&fs::read(&args[1])?)?;
    validate_plan(&p)?;
    let invocation = env::var("INVOCATION_ID")?;
    ensure!(identity(&invocation), "missing canonical invocation");
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    ensure!(
        membership.trim() == format!("0::/system.slice/{}", p.unit),
        "foreign cgroup"
    );
    let cgroup = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
    for name in ["", "scratch", "output", "receipts", "ledger"] {
        let dir = p.run_root.join(name);
        private_directory(&dir)?;
        if !name.is_empty() {
            ensure!(
                fs::read_dir(dir)?.next().is_none(),
                "canary directory not empty"
            );
        }
    }
    bound_file(&p.node.path, &p.node.sha256, 512 << 20)?;
    bound_file(&p.worker, WORKER, 256 << 20)?;
    bound_file(&p.snapshot, SNAPSHOT, 11 << 30)?;
    ensure!(
        fs::metadata(&p.snapshot)?.len() == SNAPSHOT_SIZE,
        "snapshot length"
    );
    bound_file(&p.epoch_hashes.path, &p.epoch_hashes.sha256, 1 << 20)?;
    let hashes = fs::read_to_string(&p.epoch_hashes.path)?;
    validate_checkpoint_names(&hashes)?;
    bound_file(
        &p.ledger_directory.join("genesis.tar.bz2"),
        GENESIS,
        10 << 20,
    )?;
    let ledger = fs::symlink_metadata(&p.ledger_directory)?;
    ensure!(
        p.ledger_directory.canonicalize()? == p.ledger_directory
            && ledger.is_dir()
            && ledger.uid() == 0
            && ledger.mode() & 0o222 == 0,
        "ledger not immutable"
    );
    ensure!(
        fs::symlink_metadata(p.ledger_directory.join("genesis.bin"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "genesis shadow"
    );
    storage.prepare(&p)?;
    // The parent may unpack genesis beside its ledger. Keep immutable evidence
    // read-only and give this one diagnostic its own no-clobber ledger copy.
    let genesis = p.run_root.join("ledger/genesis.tar.bz2");
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p.ledger_directory.join("genesis.tar.bz2"))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&genesis)?;
    std::io::copy(&mut source, &mut output)?;
    output.sync_all()?;
    output.set_permissions(fs::Permissions::from_mode(0o400))?;
    File::open(p.run_root.join("ledger"))?.sync_all()?;
    let mut cmd = command(&p);
    storage.configure_command(&p, &mut cmd)?;
    execute_prepared(storage,&p,&invocation,&cgroup,&mut cmd,
        &json!({"plan_path":args[1],"plan_sha256":args[3],"self_sha256":args[5]}))
}

fn execute_prepared(storage:&dyn StorageHooks,p:&Plan,invocation:&str,cgroup:&Path,cmd:&mut Command,bindings:&Value)->Result<()> {
    if storage.capability_only() {return storage.capability_result(p,invocation,bindings,cmd);}
    let execute = if NATURAL_ROOT_FINISH {
        measure_root
    } else {
        measure
    };
    execute(
        p,
        invocation,
        cgroup,
        cmd,
        bindings,
        storage,
    )
}

fn root_manifest_valid(m: &Value) -> Result<()> {
    ensure!(
        NATURAL_ROOT_FINISH && matches!(EPOCH, 186 | 203 | 204 | 205 | 223) && TARGET == TERMINAL,
        "root completion is not a target-stop profile"
    );
    // Compile-bound scopes, never plan-selectable runtime/checkpoint policy.
    // Each epoch has independently bound snapshots and canonical-root coverage.
    let scope_matches = match EPOCH {
        186 => {
            m["output_slot_start"] == 80_352_000u64
                && m["output_slot_count"] == 431_540u64
                && m["runtime"]["runtime_profile"] == "solana-v1.6.15"
                && m["bootstrap"]["slot"] == 80_351_283u64
                && m["bootstrap"]["accounts_hash"] == "Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8"
                && m["terminal"]["slot"] == 80_783_539u64
                && m["terminal"]["accounts_hash"] == "EWu2G86akFM3CKJ8D4YZzi8ASZeaPKm2WXLG239Zjnj9"
        }
        203 => {
            m["output_slot_start"] == 87_696_000u64
                && m["output_slot_count"] == 431_581u64
                && m["runtime"]["runtime_profile"] == "solana-v1.6.16"
                && m["bootstrap"]["slot"] == 87_695_515u64
                && m["terminal"]["slot"] == 88_127_580u64
                && m["terminal"]["accounts_hash"] == "4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"
        }
        204 => {
            m["output_slot_start"] == 88_128_000u64
                && m["output_slot_count"] == 431_362u64
                && m["runtime"]["runtime_profile"] == "solana-v1.6.16"
                && m["bootstrap"]["slot"] == 88_127_580u64
                && m["bootstrap"]["accounts_hash"] == "4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"
                && m["terminal"]["slot"] == 88_559_361u64
                && m["terminal"]["accounts_hash"] == "83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA"
        }
        205 => {
            m["output_slot_start"] == 88_560_000u64
                && m["output_slot_count"] == 431_051u64
                && m["runtime"]["runtime_profile"] == "solana-v1.6.16"
                && m["bootstrap"]["slot"] == 88_559_361u64
                && m["bootstrap"]["accounts_hash"] == "83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA"
                && m["terminal"]["slot"] == 88_991_050u64
                && m["terminal"]["accounts_hash"] == "BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp"
        }
        223 => {
            m["output_slot_start"] == 96_336_000u64
                && m["output_slot_count"] == 431_523u64
                && m["runtime"]["runtime_profile"] == "solana-v1.6.25"
                && m["bootstrap"]["slot"] == 96_335_538u64
                && m["bootstrap"]["accounts_hash"] == "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE"
                && m["bootstrap"]["bank_hash"] == "8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"
                && m["terminal"]["slot"] == 96_767_522u64
                && m["terminal"]["accounts_hash"] == "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7"
                && m["terminal"]["bank_hash"] == "EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB"
        }
        _ => false,
    };
    ensure!(
        scope_matches && m["schema_version"] == 1
            && m["epoch"] == EPOCH
            && m["worker_executable_sha256"] == WORKER
            && m["bootstrap"]["slot_complete"] == true
            && m["terminal"]["slot_complete"] == true
            && m["archive_sha256"]
                .as_str()
                .is_some_and(|s| digest(s) && s != "0".repeat(64)),
        "producer segment does not bind the exact complete canonical-root prefix"
    );
    Ok(())
}

fn root_checkpoint_marker(line: &str) -> bool {
    let Some((prefix, body)) =
        line.split_once(" jetstreamer_node::historical_replay] historical checkpoint slot=")
    else {
        return false;
    };
    prefix.starts_with('[')
        && prefix.contains(" INFO ")
        && body.split_whitespace().next() == Some(TERMINAL.to_string().as_str())
        && body.split_whitespace().any(|s| s == "complete=true")
}

fn read_private_manifest(path: &Path) -> Result<(Value, String)> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical manifest"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == unsafe { libc::geteuid() }
            && before.nlink() == 1
            && before.mode() & 0o077 == 0
            && before.len() <= 1 << 20,
        "unsafe producer manifest"
    );
    let mut bytes = Vec::new();
    (&mut f).take((1 << 20) + 1).read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && after.len() == before.len(),
        "producer manifest changed"
    );
    Ok((
        serde_json::from_slice(&bytes)?,
        hex(&Sha256::digest(&bytes)),
    ))
}

/// Natural, verified parent completion is mandatory for this distinct profile.
/// Reaching a progress marker never sends SIGINT or declares a prefix complete.
fn measure_root(
    p: &Plan,
    invocation: &str,
    cgroup: &Path,
    cmd: &mut Command,
    bindings: &Value,
    storage: &dyn StorageHooks,
) -> Result<()> {
    ensure!(
        NATURAL_ROOT_FINISH && TARGET == TERMINAL,
        "not a natural root profile"
    );
    let free_before = free_bytes(&p.run_root)?;
    ensure!(free_before >= p.minimum_free_bytes, "fresh free-space gate");
    let before = metrics(cgroup)?;
    install_signals()?;
    let storage_evidence = storage.before_spawn(p, invocation)?;
    let mut child = ChildGroup(cmd.spawn()?, false);
    let pid = child.0.id();
    let (tx, rx) = mpsc::sync_channel(64);
    reader(child.0.stdout.take().context("stdout")?, tx.clone());
    reader(child.0.stderr.take().context("stderr")?, tx);
    let started = Instant::now();
    let mut capture = Value::Null;
    let mut capture_error: Option<String> = None;
    let mut first_progress = Value::Null;
    let mut last_progress = Value::Null;
    let mut manifest = Value::Null;
    let mut manifest_sha = String::new();
    let mut archive_length = 0;
    let mut code = None;
    let outcome = (|| -> Result<()> {
        loop {
            storage.guard(p, invocation, pid, started.elapsed(), false)?;
            ensure!(
                EXTERNAL_SIGNAL.load(Ordering::SeqCst) == 0,
                "external signal"
            );
            ensure!(
                started.elapsed().as_secs() < p.maximum_runtime_seconds,
                "runtime bound"
            );
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Ok(line)) => {
                    print!("{line}");
                    std::io::stdout().flush()?;
                    if let Some(mut counters) = progress_counters(&line) {
                        counters["elapsed_millis"] = json!(started.elapsed().as_millis());
                        if first_progress.is_null() {
                            first_progress = counters.clone();
                        }
                        last_progress = counters;
                    }
                    if capture.is_null()
                        && capture_error.is_none()
                        && (root_checkpoint_marker(&line) || progress_slot(&line) == Some(TERMINAL))
                    {
                        freeze_group(pid)?;
                        let measured = capture_resources(&p.run_root.join("scratch"), cgroup);
                        group_signal(pid, libc::SIGCONT)?;
                        match measured {
                            Ok(value) => {
                                ensure!(
                                    value["scratch"]["physical_bytes"]
                                        .as_u64()
                                        .is_some_and(|bytes| bytes <= MAX_SCRATCH),
                                    "terminal scratch bound"
                                );
                                persist(&p.run_root.join("receipts/root-capture.json"), &value)?;
                                capture = value;
                            }
                            // Optional telemetry cannot discard a valid parent result.
                            Err(e) => capture_error = Some(format!("{e:#}")),
                        }
                    }
                }
                Ok(Err(e)) => anyhow::bail!("child log: {e}"),
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {}
            }
            if let Some(status) = child.0.try_wait()? {
                child.1 = true;
                code = status.code();
                ensure!(status.success(), "root-prefix parent failed: {status}");
                break;
            }
        }
        let archive = p.run_root.join("output").join(ARCHIVE_NAME);
        let sidecar = PathBuf::from(format!("{}.sha256", archive.display()));
        ensure!(
            fs::symlink_metadata(&sidecar).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "private prefix acquired a canonical sidecar"
        );
        let metadata = fs::symlink_metadata(&archive)?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0
                && metadata.len() > 0,
            "unsafe private prefix archive"
        );
        archive_length = metadata.len();
        let pair = read_private_manifest(&PathBuf::from(format!(
            "{}.segment.json",
            archive.display()
        )))?;
        root_manifest_valid(&pair.0)?;
        manifest = pair.0;
        manifest_sha = pair.1;
        Ok(())
    })();
    if !child.1 {
        group_signal(pid, libc::SIGCONT)?;
        group_signal(pid, libc::SIGKILL)?;
    }
    let external = EXTERNAL_SIGNAL.load(Ordering::SeqCst);
    let outcome = outcome.and_then(|()| {
        ensure!(external == 0, "external signal after parent completion");
        Ok(())
    });
    let success = outcome.is_ok();
    let error = outcome.as_ref().err().map(|e| format!("{e:#}"));
    let payload = json!({"schema":RESULT_SCHEMA,"epoch":EPOCH,"unit":p.unit,
        "invocation_id":invocation,"plan":{"path":bindings["plan_path"],"sha256":bindings["plan_sha256"]},
        "runner_sha256":bindings["self_sha256"],"node_sha256":p.node.sha256,"worker_sha256":WORKER,
        "snapshot_sha256":SNAPSHOT,"target_slot":TARGET,"terminal_root_slot":TERMINAL,
        "natural_parent_completion_required":true,"child_return_code":code,
        "external_signal":external,"elapsed_millis":started.elapsed().as_millis(),
        "solana_rayon_threads":RAYON_THREADS,"first_progress":first_progress,"last_progress":last_progress,
        "capture":capture,"capture_error":capture_error,"capture_is_peak_proof":false,
        "cgroup_before":before,"cgroup_after":metrics(cgroup)?,"archive_length":archive_length,
        "producer_segment_manifest":manifest,"producer_segment_manifest_sha256":manifest_sha,
        "free_before":free_before,"free_after":free_bytes(&p.run_root)?,"success":success,"error":error,
        "storage_evidence":storage_evidence,
        "producer_canonical_root_prefix_present":success,
        "authority":{"canonical_prefix_independently_qualified":false,"full_cold_epoch_peak_qualified":false,
            "ordinary_replay_authorized":false,"runtime_promotion_authorized":false,
            "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}});
    persist(
        &p.run_root.join(if success {
            "receipts/root-prefix.json"
        } else {
            "receipts/failure.json"
        }),
        &payload,
    )?;
    outcome
}

fn measure(
    p: &Plan,
    invocation: &str,
    cgroup: &Path,
    cmd: &mut Command,
    bindings: &Value,
    storage: &dyn StorageHooks,
) -> Result<()> {
    let free_before = free_bytes(&p.run_root)?;
    ensure!(free_before >= p.minimum_free_bytes, "fresh free-space gate");
    let before = metrics(cgroup)?;
    install_signals()?;
    let storage_evidence = storage.before_spawn(p, invocation)?;
    let mut child = ChildGroup(cmd.spawn()?, false);
    let pid = child.0.id();
    let (tx, rx) = mpsc::sync_channel(64);
    reader(child.0.stdout.take().context("stdout")?, tx.clone());
    reader(child.0.stderr.take().context("stderr")?, tx);
    let started = Instant::now();
    let mut observed = None;
    let mut stop_at = None;
    let mut target = false;
    let mut capture = Value::Null;
    let mut error = None;
    let mut exit = None;
    let mut first_progress: Option<Value> = None;
    let mut last_progress: Option<Value> = None;
    let outcome = (|| -> Result<()> {
        loop {
            storage.guard(p, invocation, pid, started.elapsed(), stop_at.is_some())?;
            let external = EXTERNAL_SIGNAL.load(Ordering::SeqCst);
            if stop_at.is_none()
                && (external != 0 || started.elapsed().as_secs() >= p.maximum_runtime_seconds)
            {
                error = Some(
                    if external != 0 {
                        "external-signal"
                    } else {
                        "runtime-bound"
                    }
                    .to_owned(),
                );
                freeze_group(pid)?;
                capture = capture_resources(&p.run_root.join("scratch"), cgroup)?;
                group_signal(pid, libc::SIGCONT)?;
                group_signal(pid, libc::SIGINT)?;
                stop_at = Some(Instant::now());
            }
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Ok(line)) => {
                    print!("{line}");
                    std::io::stdout().flush()?;
                    if let Some(mut counters) = progress_counters(&line) {
                        counters["elapsed_millis"] = json!(started.elapsed().as_millis());
                        if first_progress.is_none() {
                            first_progress = Some(counters.clone());
                        }
                        last_progress = Some(counters);
                    }
                    if let Some(slot) = progress_slot(&line) {
                        observed = Some(observed.unwrap_or(slot).max(slot));
                        if stop_at.is_none() && slot >= p.target_slot {
                            ensure!(
                                slot <= p.target_slot + 1000,
                                "target overshoot exceeds sealed bound"
                            );
                            freeze_group(pid)?;
                            capture = capture_resources(&p.run_root.join("scratch"), cgroup)?;
                            let external = EXTERNAL_SIGNAL.load(Ordering::SeqCst);
                            ensure!(external == 0, "external signal during target capture");
                            let capture_path = p.run_root.join("receipts/target-capture.json");
                            let capture_sha256 =
                                hex(&Sha256::digest(serde_json::to_vec(&capture)?));
                            persist(&capture_path, &capture)?;
                            persist(
                                &p.run_root.join("receipts/target-stop.json"),
                                &json!({"schema":STOP_SCHEMA,"invocation_id":invocation,"target_slot":p.target_slot,"observed_slot":slot,"child_pid":pid,"written_unix_seconds":now()?,"scratch_snapshot_captured":true,"external_signal":0,"capture_path":capture_path,"capture_canonical_json_sha256":capture_sha256}),
                            )?;
                            target = true;
                            group_signal(pid, libc::SIGCONT)?;
                            group_signal(pid, libc::SIGINT)?;
                            stop_at = Some(Instant::now());
                        }
                    }
                }
                Ok(Err(message)) => anyhow::bail!("child log: {message}"),
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {}
            }
            if let Some(status) = child.0.try_wait()? {
                child.1 = true;
                exit = Some(status);
                break;
            }
            if stop_at.is_some_and(|t| t.elapsed() > Duration::from_secs(120)) {
                anyhow::bail!("controlled child drainage timed out");
            }
        }
        Ok(())
    })();
    if let Err(e) = outcome {
        error = Some(format!("{e:#}"));
    }
    // Stop/reap only our own diagnostic group; a failed measurement never
    // grants retirement or replay-retry authority.
    if exit.is_none() {
        group_signal(pid, libc::SIGCONT)?;
        group_signal(pid, libc::SIGKILL)?;
        exit = child.0.try_wait()?;
        if exit.is_some() {
            child.1 = true;
        }
    }
    let external = EXTERNAL_SIGNAL.load(Ordering::SeqCst);
    let code = exit.as_ref().and_then(|s| s.code());
    let sidecar_seen = fs::read_dir(p.run_root.join("output"))?.try_fold(
        false,
        |found, entry| -> Result<bool> {
            Ok(found || entry?.file_name().to_string_lossy().ends_with(".sha256"))
        },
    )?;
    if sidecar_seen {
        error = Some("unexpected checksum sidecar in diagnostic output".to_owned());
    }
    let success = error.is_none() && controlled_success(target, external, code);
    let payload = json!({"schema":RESULT_SCHEMA,"epoch":EPOCH,"unit":p.unit,"invocation_id":invocation,"plan":{"path":bindings["plan_path"],"sha256":bindings["plan_sha256"]},"runner_sha256":bindings["self_sha256"],"node_sha256":p.node.sha256,"worker_sha256":WORKER,"snapshot_sha256":SNAPSHOT,"target_slot":p.target_slot,"observed_slot":observed,"target_reached":target,"first_progress":first_progress,"last_progress":last_progress,"child_pid":pid,"child_return_code":code,"external_signal":external,"elapsed_millis":started.elapsed().as_millis(),"capture":capture,"cgroup_before":before,"cgroup_after":metrics(cgroup)?,"free_before":free_before,"free_after":free_bytes(&p.run_root)?,"success":success,"error":error,"authority":{"ordinary_replay_authorized":false,"full_cold_epoch_peak_qualified":false,"publication_authorized":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"remote_mutations":false,"r2_mutations":false}});
    let mut payload = payload;
    payload["storage_evidence"] = storage_evidence;
    payload["solana_rayon_threads"] = json!(RAYON_THREADS);
    persist(
        &p.run_root.join(if success {
            "receipts/resource.json"
        } else {
            "receipts/failure.json"
        }),
        &payload,
    )?;
    ensure!(
        success,
        "bounded replay did not complete its diagnostic target"
    );
    Ok(())
}

#[allow(dead_code)] // Custom compile-bound storage entrypoints use main_with_storage.
pub(crate) fn main() {
    main_with_storage(&DiskStorage);
}

pub(crate) fn main_with_storage(storage: &dyn StorageHooks) {
    if let Err(e) = run(storage) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[allow(unused_macros)]
macro_rules! root_profile_tests {
() => {
mod root_tests {
    use super::*;
    fn manifest() -> Value {
        json!({"schema_version":1,"epoch":203,"output_slot_start":87696000,
            "output_slot_count":431581,"worker_executable_sha256":WORKER,
            "runtime":{"runtime_profile":"solana-v1.6.16"},
            "bootstrap":{"slot":87695515,"slot_complete":true},
            "terminal":{"slot":88127580,"slot_complete":true,
                "accounts_hash":"4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"},
            "archive_sha256":"a".repeat(64)})
    }
    fn plan(root: PathBuf) -> Plan {
        Plan {
            schema: PLAN_SCHEMA.into(),
            unit: format!("{UNIT_PREFIX}test.service"),
            node: BoundFile {
                path: "/sealed/node".into(),
                sha256: PARENT_SHA.into(),
            },
            worker: "/sealed/worker".into(),
            snapshot: PathBuf::from(format!("/sealed/{SNAPSHOT_NAME}")),
            ledger_directory: "/sealed".into(),
            epoch_hashes: BoundFile {
                path: "/sealed/hashes".into(),
                sha256: "b".repeat(64),
            },
            run_root: root,
            target_slot: TARGET,
            terminal_slot: TERMINAL,
            minimum_free_bytes: MINIMUM_FREE,
            maximum_runtime_seconds: MAX_RUNTIME,
        }
    }
    #[test]
    fn fixed_root_scope_and_parent_cannot_be_widened() {
        let root = PathBuf::from(format!(
            "/home/ubuntu/.jetstreamer-private/{ROOT_PREFIX}test"
        ));
        let p = plan(root.clone());
        validate_plan(&p).unwrap();
        assert!(NATURAL_ROOT_FINISH && TARGET == TERMINAL);
        assert_eq!(TARGET, 88127580);
        assert_eq!(MAX_SCRATCH, 768 << 30);
        for which in 0..5 {
            let mut p = plan(root.clone());
            match which {
                0 => p.target_slot += 1,
                1 => p.terminal_slot += 1,
                2 => p.minimum_free_bytes -= 1,
                3 => p.node.sha256 = "c".repeat(64),
                _ => p.maximum_runtime_seconds = MAX_RUNTIME + 1,
            }
            assert!(validate_plan(&p).is_err());
        }
    }
    #[test]
    fn exact_root_prefix_is_not_a_full_epoch_or_successor_tail() {
        root_manifest_valid(&manifest()).unwrap();
        for (key, v) in [
            ("epoch", json!(204)),
            ("output_slot_start", json!(87695516)),
            ("output_slot_count", json!(432000)),
            ("schema_version", json!(2)),
            ("worker_executable_sha256", json!("b".repeat(64))),
            ("archive_sha256", json!("0".repeat(64))),
        ] {
            let mut m = manifest();
            m[key] = v;
            assert!(root_manifest_valid(&m).is_err(), "accepted {key}");
        }
        for key in ["slot", "slot_complete", "accounts_hash"] {
            let mut m = manifest();
            m["terminal"][key] = Value::Null;
            assert!(root_manifest_valid(&m).is_err());
        }
    }
    #[test]
    fn checkpoint_marker_is_parent_only_and_does_not_finish_the_attempt() {
        let good = "[2026 INFO  jetstreamer_node::historical_replay] historical checkpoint slot=88127580 bank_hash=foo complete=true writes=0";
        assert!(root_checkpoint_marker(good));
        for bad in [
            good.replace("INFO", "ERROR"),
            good.replace("88127580", "88127579"),
            good.replace("complete=true", "complete=false"),
            good.replace("jetstreamer_node::historical_replay", "program_log"),
        ] {
            assert!(!root_checkpoint_marker(&bad));
        }
    }
    #[test]
    fn private_command_retains_full_verification_and_exact_root() {
        let p = plan(PathBuf::from(format!(
            "/home/ubuntu/.jetstreamer-private/{ROOT_PREFIX}test"
        )));
        let c = command(&p);
        let args = c
            .get_args()
            .map(|s| s.to_str().unwrap())
            .collect::<Vec<_>>();
        assert!(args.contains(&"--verify"));
        assert!(args.contains(&"--qualification-end-slot=88127580"));
        assert!(
            args.iter()
                .any(|s| s.ends_with("/output/epoch-203-prefix.jet"))
        );
        assert!(
            !args
                .iter()
                .any(|s| s.contains("publish") || s.contains("root-checkpoint-cohort"))
        );
    }
    #[test]
    fn manifest_reader_rejects_symlinks_and_insecure_metadata() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("manifest.json");
        fs::write(&p, serde_json::to_vec(&manifest()).unwrap()).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        root_manifest_valid(&read_private_manifest(&p).unwrap().0).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(read_private_manifest(&link).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_manifest(&p).is_err());
    }
    #[test]
    fn natural_success_requires_zero_exit_and_manifest_not_a_progress_line() {
        let t = tempfile::tempdir().unwrap();
        for name in ["scratch", "output", "receipts", "cgroup"] {
            fs::create_dir(t.path().join(name)).unwrap();
            fs::set_permissions(t.path().join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        for name in [
            "memory.current",
            "memory.peak",
            "memory.events",
            "memory.stat",
            "cpu.stat",
            "io.stat",
            "memory.pressure",
            "io.pressure",
        ] {
            fs::write(t.path().join("cgroup").join(name), b"0\n").unwrap();
        }
        let mut p = plan(t.path().to_path_buf());
        p.minimum_free_bytes = 0;
        let bindings = json!({"plan_path":"/sealed/plan","plan_sha256":"b".repeat(64),"self_sha256":"c".repeat(64)});
        let mut cmd = Command::new("/bin/true");
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        assert!(
            measure_root(
                &p,
                &"a".repeat(32),
                &t.path().join("cgroup"),
                &mut cmd,
                &bindings,
                &DiskStorage
            )
            .is_err()
        );
        let failure: Value =
            serde_json::from_slice(&fs::read(t.path().join("receipts/failure.json")).unwrap())
                .unwrap();
        assert_eq!(failure["producer_canonical_root_prefix_present"], false);
        assert_eq!(
            failure["authority"]["canonical_prefix_independently_qualified"],
            false
        );
    }
}

mod root_success_tests {
    use super::*;
    #[test]
    fn natural_zero_exit_with_complete_manifest_still_denies_independent_qualification() {
        let t = tempfile::tempdir().unwrap();
        for name in ["scratch", "output", "receipts", "cgroup"] {
            fs::create_dir(t.path().join(name)).unwrap();
            fs::set_permissions(t.path().join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        for name in [
            "memory.current",
            "memory.peak",
            "memory.events",
            "memory.stat",
            "cpu.stat",
            "io.stat",
            "memory.pressure",
            "io.pressure",
        ] {
            fs::write(t.path().join("cgroup").join(name), b"0\n").unwrap();
        }
        let archive = t.path().join("output").join(ARCHIVE_NAME);
        fs::write(
            &archive,
            b"private fixture; independent archive validation still required",
        )
        .unwrap();
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o600)).unwrap();
        let m = json!({"schema_version":1,"epoch":203,"output_slot_start":87696000,
            "output_slot_count":431581,"worker_executable_sha256":WORKER,
            "runtime":{"runtime_profile":"solana-v1.6.16"},"bootstrap":{"slot":87695515,"slot_complete":true},
            "terminal":{"slot":88127580,"slot_complete":true,"accounts_hash":"4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"},
            "archive_sha256":"a".repeat(64)});
        let side = PathBuf::from(format!("{}.segment.json", archive.display()));
        fs::write(&side, serde_json::to_vec(&m).unwrap()).unwrap();
        fs::set_permissions(&side, fs::Permissions::from_mode(0o600)).unwrap();
        let p = Plan {
            schema: PLAN_SCHEMA.into(),
            unit: format!("{UNIT_PREFIX}test.service"),
            node: BoundFile {
                path: "/sealed/node".into(),
                sha256: PARENT_SHA.into(),
            },
            worker: "/sealed/worker".into(),
            snapshot: "/sealed/snapshot".into(),
            ledger_directory: "/sealed".into(),
            epoch_hashes: BoundFile {
                path: "/sealed/hashes".into(),
                sha256: "b".repeat(64),
            },
            run_root: t.path().to_path_buf(),
            target_slot: TARGET,
            terminal_slot: TERMINAL,
            minimum_free_bytes: 0,
            maximum_runtime_seconds: 600,
        };
        let bindings = json!({"plan_path":"/sealed/plan","plan_sha256":"b".repeat(64),"self_sha256":"c".repeat(64)});
        let mut cmd = Command::new("/bin/true");
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        measure_root(
            &p,
            &"a".repeat(32),
            &t.path().join("cgroup"),
            &mut cmd,
            &bindings,
            &DiskStorage,
        )
        .unwrap();
        let r: Value =
            serde_json::from_slice(&fs::read(t.path().join("receipts/root-prefix.json")).unwrap())
                .unwrap();
        assert_eq!(r["child_return_code"], 0);
        assert_eq!(r["producer_canonical_root_prefix_present"], true);
        assert_eq!(r["capture_is_peak_proof"], false);
        assert!(
            r["authority"]
                .as_object()
                .unwrap()
                .values()
                .all(|v| v == false)
        );
        assert!(!PathBuf::from(format!("{}.sha256", archive.display())).exists());
    }
}

};
}

#[cfg(test)]
#[allow(unused_macros)]
macro_rules! legacy_profile_tests {
() => {
mod tests {
    use super::*;
    fn fixture_plan() -> Plan {
        serde_json::from_value(json!({
            "schema":PLAN_SCHEMA,
            "unit":format!("{UNIT_PREFIX}test.service"),
            "node":{"path":"/sealed/node","sha256":if PARENT_SHA.is_empty() {"a".repeat(64)} else {PARENT_SHA.to_owned()}},
            "worker":"/sealed/worker",
            "snapshot":format!("/sealed/{SNAPSHOT_NAME}"),
            "ledger_directory":"/sealed","epoch_hashes":{"path":"/sealed/hashes","sha256":"b".repeat(64)},
            "run_root":format!("/home/ubuntu/.jetstreamer-private/{ROOT_PREFIX}test"),
            "target_slot":TARGET,"terminal_slot":TERMINAL,"minimum_free_bytes":MINIMUM_FREE,"maximum_runtime_seconds":MAX_RUNTIME
        })).unwrap()
    }
    #[test]
    fn plan_cannot_expand_epoch_target_runtime_or_resource_scope() {
        validate_plan(&fixture_plan()).unwrap();
        if !PARENT_SHA.is_empty() {
            let mut p = fixture_plan();
            p.node.sha256 = "0".repeat(64);
            assert!(validate_plan(&p).is_err());
        }
        let mut p = fixture_plan();
        p.target_slot += 1;
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.terminal_slot += 1;
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.minimum_free_bytes -= 1;
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.maximum_runtime_seconds = MAX_RUNTIME + 1;
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.unit = "horizon-qualify-226-bounded-resource-test.service".into();
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.run_root = "/home/ubuntu/horizon".into();
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.schema = if EPOCH == 203 {
            "jetstreamer-private-epoch225-bounded-resource-plan-v1"
        } else {
            "jetstreamer-private-epoch203-bounded-resource-plan-v1"
        }
        .into();
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.snapshot = PathBuf::from(format!("/sealed/{TERMINAL_NAME}"));
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn command_is_private_focused_and_pins_exact_runtime() {
        let p = fixture_plan();
        let c = command(&p);
        let args = c
            .get_args()
            .map(|a| a.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            &args[..2],
            [
                EPOCH.to_string(),
                format!("/home/ubuntu/.jetstreamer-private/{ROOT_PREFIX}test/ledger")
            ]
        );
        assert!(args.contains(&"--verify"));
        assert!(args.contains(&format!("--qualification-end-slot={TERMINAL}").as_str()));
        assert!(
            !args
                .iter()
                .any(|a| a.contains("root-checkpoint-cohort") || a.contains("publish-through"))
        );
        assert!(args.iter().any(|a| {
            a.starts_with("--horizon-output=/home/ubuntu/.jetstreamer-private/")
                && a.ends_with(&format!("/output/epoch-{EPOCH}-canary.jet"))
        }));
        let env = c
            .get_envs()
            .map(|(k, v)| (k.to_str().unwrap(), v.and_then(|s| s.to_str())))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(env[WORKER_ENV], Some("/sealed/worker"));
        assert_eq!(
            env["SOLANA_RAYON_THREADS"],
            Some(RAYON_THREADS.to_string().as_str())
        );
        for key in [
            "JETSTREAMER_HISTORICAL_WORKER_V1_6_16",
            "JETSTREAMER_HISTORICAL_WORKER_V1_6_20",
            "JETSTREAMER_HISTORICAL_WORKER_V1_6_25",
        ] {
            if key != WORKER_ENV {
                assert_eq!(env[key], None);
            }
        }
        assert_eq!(env["JETSTREAMER_HISTORICAL_TRACE"], Some("1"));
        assert_eq!(env["HORIZON_SECRET_ACCESS_KEY"], None);
    }
    #[test]
    fn checkpoints_are_exact_not_an_arbitrary_same_epoch_file() {
        let exact = format!("{}\n", CHECKPOINT_NAMES.join("\n"));
        validate_checkpoint_names(&exact).unwrap();
        for omitted in 0..CHECKPOINT_NAMES.len() {
            let reduced = CHECKPOINT_NAMES.iter().enumerate()
                .filter_map(|(index, name)| (index != omitted).then_some(*name))
                .collect::<Vec<_>>().join("\n");
            assert!(validate_checkpoint_names(&reduced).is_err());
        }
        let mut reversed = CHECKPOINT_NAMES.to_vec();
        reversed.reverse();
        assert!(validate_checkpoint_names(&reversed.join("\n")).is_err());
        assert!(
            validate_checkpoint_names(
                &exact.replace(&TERMINAL.to_string(), &(TERMINAL - 1).to_string())
            )
            .is_err()
        );
        assert!(validate_checkpoint_names(&format!("{exact}snapshot-1-fake.tar.zst\n")).is_err());
    }
    #[test]
    fn target_detection_does_not_require_optional_counters() {
        let line = format!(
            "[2026-10-19T00:00:00Z INFO  jetstreamer_node] progress slot {TARGET}/{TERMINAL} (0.6%)"
        );
        assert_eq!(progress_slot(&line), Some(TARGET));
        assert_eq!(
            progress_slot(&line.replace("jetstreamer_node]", "other_module]")),
            None
        );
        assert_eq!(
            progress_slot(&line.replace(&TERMINAL.to_string(), &(TARGET + 1).to_string())),
            None
        );
        assert_eq!(
            progress_slot(&line.replace(&format!("{TARGET}/"), "garbage/")),
            None
        );
        assert_eq!(
            progress_slot("program log: progress slot 97202500/97631459"),
            None
        );
        assert!(progress_counters(&line).is_none());
        assert_eq!(
            progress_counters(&format!("{line} txs=123 accounts=456")).unwrap(),
            json!({"slot":TARGET,"transactions":123,"account_updates":456})
        );
    }
    #[test]
    fn only_our_posttarget_zero_or_one_exit_can_succeed() {
        for target in [false, true] {
            for external in [0, libc::SIGTERM] {
                for code in [None, Some(0), Some(1), Some(2)] {
                    assert_eq!(
                        controlled_success(target, external, code),
                        target && external == 0 && matches!(code, Some(0 | 1))
                    );
                }
            }
        }
    }
    #[test]
    fn scratch_is_bounded_and_never_follows_symlinks() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("file"), b"abc").unwrap();
        let measured = scratch(t.path()).unwrap();
        assert_eq!(measured["regular_files"], 1);
        std::os::unix::fs::symlink("/", t.path().join("escape")).unwrap();
        assert!(scratch(t.path()).is_err());
    }
    #[test]
    fn capture_requires_one_live_accounts_state_and_keeps_both_measurements() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(
            scratch(t.path()).unwrap()["accounts_state_roots"],
            json!([])
        );
        let account = t.path().join("accounts-state");
        fs::create_dir(&account).unwrap();
        fs::write(account.join("1.0"), b"account").unwrap();
        let all = scratch(t.path()).unwrap();
        assert_eq!(all["accounts_state_roots"], json!([account]));
        let narrow = scratch(&account).unwrap();
        assert_eq!(narrow["regular_files"], 1);
        assert_eq!(narrow["file_size_histogram_bytes"]["7"], 1);
    }
    #[test]
    fn log_reader_caps_line_allocation_and_reports_failure() {
        let (tx, rx) = mpsc::sync_channel(1);
        reader(std::io::Cursor::new(vec![b'x'; 65537]), tx);
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_err());
    }
    #[test]
    fn process_stat_parser_handles_parentheses_inside_comm() {
        assert_eq!(
            stat_group_state("123 (a)b(c) T 1 123 456").unwrap(),
            (123, 'T')
        );
        assert!(stat_group_state("not a stat").is_err());
    }
    #[test]
    fn freezing_an_owned_group_does_not_stop_another_group() {
        let mut own = ChildGroup(
            Command::new("/bin/sleep")
                .arg("20")
                .process_group(0)
                .spawn()
                .unwrap(),
            false,
        );
        let mut other = ChildGroup(
            Command::new("/bin/sleep")
                .arg("20")
                .process_group(0)
                .spawn()
                .unwrap(),
            false,
        );
        freeze_group(own.0.id()).unwrap();
        assert!(group_stopped(own.0.id()).unwrap());
        assert!(!group_stopped(other.0.id()).unwrap());
        for child in [&mut own, &mut other] {
            group_signal(child.0.id(), libc::SIGCONT).unwrap();
            group_signal(child.0.id(), libc::SIGKILL).unwrap();
            child.0.wait().unwrap();
            child.1 = true;
        }
    }
    #[test]
    fn immutable_input_binding_checks_root_ownership_mode_digest_and_symlinks() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("sealed");
        fs::write(&path, b"evidence").unwrap();
        let sha = hex(&Sha256::digest(b"evidence"));
        assert!(bound_file(&path, &sha, 100).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        bound_file(&path, &sha, 100).unwrap();
        assert!(bound_file(&path, &"0".repeat(64), 100).is_err());
        assert!(bound_file(&path, &sha, 7).is_err());
        let link = t.path().join("alias");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(bound_file(&link, &sha, 100).is_err());
    }
    // Separate test-harness process; production accepts no fake-node override.
    #[test]
    fn canary_child_fixture() {
        let Ok(root) = env::var("JETSTREAMER_TEST_225_RESOURCE_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        assert!(
            root.starts_with(env::temp_dir())
                && root
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("epoch225-resource-fixture-")
        );
        if env::var("JETSTREAMER_TEST_225_PRETARGET_EXIT").is_ok() {
            std::process::exit(1);
        }
        let accounts = root.join("scratch/runtime/accounts-state");
        fs::create_dir_all(&accounts).unwrap();
        fs::write(accounts.join("1.0"), b"live account state").unwrap();
        install_signals().unwrap();
        eprintln!(
            "[2026-10-19T00:00:00Z INFO  jetstreamer_node] progress slot {TARGET}/{TERMINAL} (0.6%)"
        );
        while EXTERNAL_SIGNAL.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(10));
        }
        fs::remove_dir_all(&accounts).unwrap();
        std::process::exit(1);
    }

    fn exercise_child(pretarget: bool) -> (tempfile::TempDir, Result<()>) {
        exercise_child_with_storage(pretarget, &DiskStorage)
    }

    fn exercise_child_with_storage(pretarget: bool, storage: &dyn StorageHooks) -> (tempfile::TempDir, Result<()>) {
        let temp = tempfile::Builder::new()
            .prefix("epoch225-resource-fixture-")
            .tempdir()
            .unwrap();
        let mut p = fixture_plan();
        p.run_root = temp.path().to_path_buf();
        p.minimum_free_bytes = 0;
        for name in ["scratch", "output", "receipts", "cgroup"] {
            let d = temp.path().join(name);
            fs::create_dir(&d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let cgroup = temp.path().join("cgroup");
        for name in [
            "memory.current",
            "memory.peak",
            "memory.events",
            "memory.stat",
            "cpu.stat",
            "io.stat",
            "memory.pressure",
            "io.pressure",
        ] {
            fs::write(cgroup.join(name), "0\n").unwrap();
        }
        let mut cmd = Command::new(env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "bounded_resource_runner::tests::canary_child_fixture",
            "--nocapture",
        ])
        .env("JETSTREAMER_TEST_225_RESOURCE_ROOT", temp.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
        if pretarget {
            cmd.env("JETSTREAMER_TEST_225_PRETARGET_EXIT", "1");
        }
        let result = measure(
            &p,
            &"a".repeat(32),
            &cgroup,
            &mut cmd,
            &json!({"plan_path":"/sealed/test","plan_sha256":"b".repeat(64),"self_sha256":"c".repeat(64)}),
            storage,
        );
        (temp, result)
    }

    #[test]
    fn storage_admission_rejection_prevents_child_start() {
        struct Reject;
        impl StorageHooks for Reject {
            fn before_spawn(&self, _p: &Plan, _inv: &str) -> Result<Value> {
                anyhow::bail!("fixture storage admission rejected")
            }
        }
        let (t, outcome) = exercise_child_with_storage(false, &Reject);
        assert!(outcome.unwrap_err().to_string().contains("storage admission rejected"));
        assert!(!t.path().join("scratch/runtime/accounts-state").exists());
        assert!(fs::read_dir(t.path().join("receipts")).unwrap().next().is_none());
    }

    #[test]
    fn no_entry_capability_dispatch_never_reaches_replay_or_guard() {
        struct Capability;
        impl StorageHooks for Capability {
            fn capability_only(&self)->bool {true}
            fn capability_result(&self,_p:&Plan,_inv:&str,_bindings:&Value,_cmd:&Command)->Result<()> {Ok(())}
            fn before_spawn(&self,_p:&Plan,_inv:&str)->Result<Value> {panic!("capability reached spawn gate")}
            fn guard(&self,_p:&Plan,_inv:&str,_child:u32,_elapsed:Duration,_draining:bool)->Result<()> {panic!("capability reached guard")}
        }
        let p=fixture_plan();let mut cmd=command(&p);
        execute_prepared(&Capability,&p,&"a".repeat(32),Path::new("/not-a-cgroup"),&mut cmd,&json!({})).unwrap();
        assert!(!DiskStorage.capability_only());
        assert!(DiskStorage.capability_result(&p,&"a".repeat(32),&json!({}),&cmd).is_err());
    }

    #[test]
    fn storage_guard_intent_precedes_owned_child_failure() {
        struct Reject;
        impl StorageHooks for Reject {
            fn before_spawn(&self, _p: &Plan, _inv: &str) -> Result<Value> {
                Ok(json!({"storage_scope":"fixture-only","publication_authorized":false}))
            }
            fn guard(&self, p: &Plan, inv: &str, child: u32, _elapsed: Duration, _draining: bool) -> Result<()> {
                persist(&p.run_root.join("receipts/storage-guard-stop.json"),
                    &json!({"invocation_id":inv,"child_pid":child,"reason":"fixture-stop"}))?;
                anyhow::bail!("fixture storage guard stop")
            }
        }
        let (t, outcome) = exercise_child_with_storage(false, &Reject);
        assert!(outcome.is_err());
        let stop: Value = serde_json::from_slice(&fs::read(t.path().join("receipts/storage-guard-stop.json")).unwrap()).unwrap();
        let failure: Value = serde_json::from_slice(&fs::read(t.path().join("receipts/failure.json")).unwrap()).unwrap();
        assert_eq!(failure["child_pid"],stop["child_pid"]);
        assert_eq!(failure["invocation_id"],stop["invocation_id"]);
        assert_eq!(failure["success"],false);
        assert_eq!(failure["storage_evidence"]["storage_scope"],"fixture-only");
        assert_eq!(failure["authority"]["publication_authorized"],false);
        assert!(!t.path().join("receipts/resource.json").exists());
    }

    #[test]
    fn real_target_stop_captures_live_state_before_child_retires_it() {
        let (temp, result) = exercise_child(false);
        result.unwrap();
        let receipt: Value =
            serde_json::from_slice(&fs::read(temp.path().join("receipts/resource.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["success"], true);
        assert_eq!(receipt["epoch"], EPOCH);
        assert_eq!(receipt["schema"], RESULT_SCHEMA);
        assert_eq!(receipt["solana_rayon_threads"], json!(RAYON_THREADS));
        assert_eq!(receipt["worker_sha256"], WORKER);
        assert_eq!(receipt["snapshot_sha256"], SNAPSHOT);
        assert_eq!(receipt["child_return_code"], 1);
        assert_eq!(receipt["capture"]["accounts_state"]["regular_files"], 1);
        assert_eq!(
            receipt["authority"]["full_cold_epoch_peak_qualified"],
            false
        );
        assert_eq!(receipt["authority"]["publication_authorized"], false);
        assert!(!temp.path().join("scratch/runtime/accounts-state").exists());
        let intent: Value = serde_json::from_slice(
            &fs::read(temp.path().join("receipts/target-stop.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(intent["target_slot"], TARGET);
        assert_eq!(intent["schema"], STOP_SCHEMA);
        assert_eq!(intent["external_signal"], 0);
        assert_eq!(intent["scratch_snapshot_captured"], true);
        assert!(temp.path().join("receipts/target-capture.json").is_file());
    }

    #[test]
    fn real_pretarget_failure_is_not_normalized_and_keeps_counters() {
        let (temp, result) = exercise_child(true);
        assert!(result.is_err());
        let receipt: Value =
            serde_json::from_slice(&fs::read(temp.path().join("receipts/failure.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["success"], false);
        assert_eq!(receipt["target_reached"], false);
        assert_eq!(receipt["child_return_code"], 1);
        assert!(!receipt["cgroup_before"].is_null() && !receipt["cgroup_after"].is_null());
        assert!(!temp.path().join("receipts/resource.json").exists());
    }

    #[test]
    fn receipts_are_owner_only_and_never_clobbered() {
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let p = t.path().join("receipt.json");
        persist(&p, &json!({"original":true})).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o077, 0);
        assert!(persist(&p, &json!({"replacement":true})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(p).unwrap()).unwrap(),
            json!({"original":true})
        );
    }
}
};
}
