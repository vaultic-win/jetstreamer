//! Standalone compiler/copy and fixed scan203 retirement guard.
//! Use pinned rustc --edition=2021, without Cargo dependencies.
//!
//! This is deliberately separate from the historical-worker guard. Executable names
//! beneath a Cargo target directory carry no replay-worker meaning here. Admission,
//! immutable sealing, first-fire protection and runtime qualification remain external.
//!
//! Every flag below is required exactly once:
//! --unit NAME --expected-invocation-id HEX --self-sha256 HEX
//! --root PATH --root-uid UID --root-device DEV --root-inode INO
//! --receipt-directory PATH --minimum-free-bytes N --maximum-root-bytes N
//! --expected-memory-max-bytes N --expected-memory-swap-max-bytes N
//! --expected-tasks-max N --expected-cpu-quota-usec N --expected-max-run-usec N
//!
//! max-run binds TimeoutStartUSec for Type=oneshot, RuntimeMaxUSec otherwise.
//! Free space is measured on the descriptor of --root, not on a guessed filesystem.
//! Main must qualify the fixed checksum utility and systemctl/loader closure and
//! serialize actor relaunches against the final IID check / systemctl stop request.

#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
compile_error!("horizon_build_guard requires GNU Linux x86_64");

use std::{
    collections::BTreeMap,
    env,
    ffi::CString,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::{
        raw::{c_char, c_int, c_uint, c_ulong},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawFd,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const O_DIRECTORY: c_int = 0x10000;
const O_NOFOLLOW: c_int = 0x20000;
const O_CLOEXEC: c_int = 0x80000;
const O_PATH: c_int = 0x200000;
const MAX_ENTRIES: u64 = 8_000_000;
const MAX_DEPTH: u32 = 128;
const MAX_RECEIPT: u64 = 16_384;
const HASHER: &str = "/usr/lib/cargo/bin/coreutils/sha256sum";
// Its authenticity is independently established by the sealed deployment, not by
// asking an untrusted hasher to authenticate itself.
const HASHER_SHA256: &str = "27a7d8f6a005702618e92c88f20b829d38247ad3369e0c35b1ff219d15194bd1";
const PROPERTIES: &str = "Id,InvocationID,Type,LoadState,ActiveState,SubState,Result,MainPID,ControlPID,NRestarts,Restart,KillMode,Delegate,ControlGroup,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,TimeoutStartUSec,RuntimeMaxUSec";
const SCAN203_RETIREMENT_UNIT: &str = "horizon-scan203-retirement-v1.service";
const SCAN203_STATE: &str = "/var/lib/jetstreamer/horizon-scan203-retirement-v1";
const SCAN203_GUARD_STATE: &str = "/var/lib/jetstreamer/horizon-scan203-retirement-guard-v1";

macro_rules! require {
    ($condition:expr, $message:expr) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
}
fn io(error: std::io::Error) -> String {
    error.to_string()
}

#[repr(C)]
#[derive(Default)]
struct StatVfs {
    bsize: c_ulong,
    frsize: c_ulong,
    blocks: c_ulong,
    bfree: c_ulong,
    bavail: c_ulong,
    files: c_ulong,
    ffree: c_ulong,
    favail: c_ulong,
    fsid: c_ulong,
    flag: c_ulong,
    namemax: c_ulong,
    fs_type: c_uint,
    spare: [c_int; 5],
}
extern "C" {
    fn geteuid() -> c_uint;
    fn fstatvfs(fd: c_int, out: *mut StatVfs) -> c_int;
    fn renameat2(
        oldfd: c_int,
        old: *const c_char,
        newfd: c_int,
        new: *const c_char,
        flags: c_uint,
    ) -> c_int;
}
const _: [(); 112] = [(); std::mem::size_of::<StatVfs>()];

#[derive(Clone, Debug)]
struct Config {
    unit: String,
    iid: String,
    self_sha: String,
    root: PathBuf,
    receipt: PathBuf,
    uid: u32,
    dev: u64,
    ino: u64,
    floor: u64,
    cap: u64,
    memory: u64,
    swap: u64,
    tasks: u64,
    cpu: u64,
    run_usec: u64,
}
fn hex_id(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn number(value: &str) -> Result<u64> {
    require!(
        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
        "nondecimal integer"
    );
    require!(
        value == "0" || !value.starts_with('0'),
        "noncanonical integer"
    );
    value.parse().map_err(|_| "integer overflow".into())
}
fn positive(value: &str) -> Result<u64> {
    let n = number(value)?;
    require!(n > 0 && n < (1_u64 << 60), "positive finite bound required");
    Ok(n)
}
fn purpose_unit(unit: &str) -> bool {
    if !unit.starts_with("horizon-qualify-")
        || !unit.ends_with(".service")
        || unit.len() > 200
        || !unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return false;
    }
    let name = unit.trim_end_matches(".service");
    let denied = ["replay", "adaptive", "shrink", "general", "cohort"];
    if denied.iter().any(|bad| name.contains(*bad)) {
        return false;
    }
    name.split('-').any(|part| {
        ["tests", "build", "copy"].iter().any(|purpose| {
            part.strip_prefix(*purpose)
                .is_some_and(|tail| tail.is_empty() || tail.bytes().all(|b| b.is_ascii_digit()))
        })
    })
}
fn lexical_path(value: &str) -> Result<PathBuf> {
    require!(
        value.len() <= 512 && value.starts_with('/') && value.len() > 1 && !value.ends_with('/'),
        "bounded absolute leaf path required"
    );
    require!(
        value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b)),
        "unsafe path characters"
    );
    require!(
        value
            .split('/')
            .skip(1)
            .all(|v| !v.is_empty() && v != "." && v != ".."),
        "noncanonical path components"
    );
    let p = PathBuf::from(value);
    require!(
        p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "unsafe path"
    );
    Ok(p)
}
fn parse(args: &[String]) -> Result<Config> {
    const FLAGS: [&str; 15] = [
        "--unit",
        "--expected-invocation-id",
        "--self-sha256",
        "--root",
        "--root-uid",
        "--root-device",
        "--root-inode",
        "--receipt-directory",
        "--minimum-free-bytes",
        "--maximum-root-bytes",
        "--expected-memory-max-bytes",
        "--expected-memory-swap-max-bytes",
        "--expected-tasks-max",
        "--expected-cpu-quota-usec",
        "--expected-max-run-usec",
    ];
    require!(
        args.len() == FLAGS.len() * 2,
        "all explicit flags required exactly once"
    );
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        require!(FLAGS.contains(&pair[0].as_str()), "unknown flag");
        require!(
            values.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
            "duplicate flag"
        );
    }
    require!(values.len() == FLAGS.len(), "missing flag");
    let get = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| "missing flag".to_string())
    };
    let unit = get("--unit")?.to_string();
    let iid = get("--expected-invocation-id")?.to_string();
    let self_sha = get("--self-sha256")?.to_string();
    require!(
        purpose_unit(&unit) || unit == SCAN203_RETIREMENT_UNIT,
        "unit is outside compiler/copy or fixed scan203 stop namespace"
    );
    require!(
        hex_id(&iid, 32) && hex_id(&self_sha, 64),
        "invalid invocation or executable digest"
    );
    let root = lexical_path(get("--root")?)?;
    let receipt = lexical_path(get("--receipt-directory")?)?;
    require!(
        !root.starts_with(&receipt) && !receipt.starts_with(&root),
        "receipt and worker roots must be disjoint"
    );
    require!(
        receipt.starts_with("/var/lib/jetstreamer"),
        "receipt must use private Root state"
    );
    require!(
        [
            "/home/ubuntu/workspace",
            "/home/ubuntu/.jetstreamer-private",
            "/var/lib/jetstreamer",
            "/run"
        ]
        .iter()
        .any(|p| root.starts_with(*p) && root != Path::new(*p)),
        "worker root outside admitted private namespaces"
    );
    let uid = u32::try_from(number(get("--root-uid")?)?).map_err(|_| "uid overflow")?;
    let config = Config {
        unit,
        iid,
        self_sha,
        root,
        receipt,
        uid,
        dev: positive(get("--root-device")?)?,
        ino: positive(get("--root-inode")?)?,
        floor: positive(get("--minimum-free-bytes")?)?,
        cap: positive(get("--maximum-root-bytes")?)?,
        memory: positive(get("--expected-memory-max-bytes")?)?,
        swap: number(get("--expected-memory-swap-max-bytes")?)?,
        tasks: positive(get("--expected-tasks-max")?)?,
        cpu: positive(get("--expected-cpu-quota-usec")?)?,
        run_usec: positive(get("--expected-max-run-usec")?)?,
    };
    require!(
        config.swap < (1_u64 << 60) && config.run_usec <= 86_400_000_000,
        "unbounded swap/runtime policy"
    );
    if config.unit == SCAN203_RETIREMENT_UNIT {
        require!(
            config.root == Path::new(SCAN203_STATE)
                && config.receipt == Path::new(SCAN203_GUARD_STATE)
                && config.uid == 0
                && config.cap == 64 * 1024 * 1024
                && config.memory == 4 * 1024 * 1024 * 1024
                && config.swap == 0
                && config.tasks == 512
                && config.cpu == 2_000_000
                && config.run_usec == 7_200_000_000,
            "fixed scan203 retirement guard profile mismatch"
        );
    }
    Ok(config)
}

fn open_dir(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        .open(path)
        .map_err(io)
}
fn same_inode(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
fn private_dir(path: &Path, uid: u32) -> Result<File> {
    require!(
        path.canonicalize().map_err(io)? == path,
        "private directory has an alias"
    );
    let f = open_dir(path)?;
    let m = f.metadata().map_err(io)?;
    require!(
        m.is_dir() && m.uid() == uid && m.mode() & 0o7777 == 0o700,
        "private directory custody mismatch"
    );
    require!(
        uid != 0 || m.gid() == 0,
        "Root private directory group mismatch"
    );
    require!(
        same_inode(&m, &fs::symlink_metadata(path).map_err(io)?),
        "private directory changed"
    );
    Ok(f)
}
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)
        .map_err(io)?;
    let mut out = Vec::new();
    f.take(limit + 1).read_to_end(&mut out).map_err(io)?;
    require!(out.len() as u64 <= limit, "metadata output too large");
    Ok(out)
}
fn native(program: &str, args: &[&str]) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(io)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(io)? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("native metadata command timed out".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    child
        .stdout
        .take()
        .ok_or("missing native stdout")?
        .take(65_537)
        .read_to_end(&mut out)
        .map_err(io)?;
    child
        .stderr
        .take()
        .ok_or("missing native stderr")?
        .take(65_537)
        .read_to_end(&mut err)
        .map_err(io)?;
    require!(
        out.len() <= 65_536 && err.len() <= 65_536,
        "oversize native output"
    );
    require!(
        status.success() && err.is_empty(),
        "native metadata command failed"
    );
    String::from_utf8(out).map_err(|_| "non-UTF8 native output".into())
}
fn hash_fd(file: &File) -> Result<String> {
    let tool = fs::symlink_metadata(HASHER).map_err(io)?;
    require!(
        tool.is_file() && tool.uid() == 0 && tool.mode() & 0o022 == 0,
        "unsafe qualified checksum tool"
    );
    let path = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
    let out = native(HASHER, &["--binary", "--", &path])?;
    let (digest, name) = out
        .trim_end_matches('\n')
        .split_once(" *")
        .ok_or("invalid checksum output")?;
    require!(
        out.ends_with('\n') && out.lines().count() == 1 && name == path && hex_id(digest, 64),
        "checksum output binding mismatch"
    );
    Ok(digest.to_string())
}
fn self_proof(expected: &str) -> Result<()> {
    // The child must open this process's descriptor: its /proc/self/exe would
    // name sha256sum itself. Keep the original executable descriptor open.
    let f = File::open("/proc/self/exe").map_err(io)?;
    let m = f.metadata().map_err(io)?;
    require!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.nlink() == 1,
        "unsafe deployed executable"
    );
    require!(
        hash_fd(&f)? == expected,
        "running executable SHA-256 mismatch"
    );
    let after = f.metadata().map_err(io)?;
    require!(
        same_inode(&m, &fs::metadata("/proc/self/exe").map_err(io)?)
            && m.len() == after.len()
            && m.mtime() == after.mtime()
            && m.mtime_nsec() == after.mtime_nsec()
            && m.ctime() == after.ctime()
            && m.ctime_nsec() == after.ctime_nsec(),
        "running executable changed"
    );
    Ok(())
}
fn properties(text: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or("invalid systemctl row")?;
        require!(
            map.insert(key.to_string(), value.to_string()).is_none(),
            "duplicate native property"
        );
    }
    Ok(map)
}
fn duration_usec(text: &str) -> Result<u64> {
    for (suffix, factor) in [
        ("us", 1),
        ("ms", 1000),
        ("min", 60_000_000),
        ("h", 3_600_000_000),
        ("s", 1_000_000),
    ] {
        if let Some(value) = text.strip_suffix(suffix) {
            return number(value)?
                .checked_mul(factor)
                .ok_or_else(|| "duration overflow".into());
        }
    }
    Err("unsupported or infinite native duration".into())
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Owner {
    values: BTreeMap<String, String>,
}
impl Owner {
    fn get(&self, key: &str) -> Result<&str> {
        self.values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("missing native property {key}"))
    }
    fn num(&self, key: &str) -> Result<u64> {
        number(self.get(key)?)
    }
    fn terminal(&self) -> Result<bool> {
        Ok(["inactive", "failed"].contains(&self.get("ActiveState")?)
            && self.num("MainPID")? == 0
            && self.num("ControlPID")? == 0)
    }
}
fn owner(unit: &str) -> Result<Owner> {
    let out = native(
        "/usr/bin/systemctl",
        &["show", unit, "--all", &format!("--property={PROPERTIES}")],
    )?;
    let values = properties(&out)?;
    let result = Owner { values };
    require!(
        result.get("Id")? == unit && result.get("LoadState")? == "loaded",
        "unit not loaded under exact name"
    );
    Ok(result)
}
fn stop_owner(config: &Config, current: &Owner) -> Result<()> {
    require!(
        current.get("Id")? == config.unit && current.get("InvocationID")? == config.iid,
        "changed invocation: no stop authority"
    );
    require!(
        current.get("Restart")? == "no"
            && current.num("NRestarts")? == 0
            && current.get("KillMode")? == "control-group"
            && current.get("Delegate")? == "no",
        "unsafe restart/stop/delegation policy"
    );
    Ok(())
}
// A systemd startup handoff invalidates the observation, not the invocation.
// Retry only this declared monotonic transition and still demand a subsequent
// complete observation with unchanged PIDs, state, identity and limits.
fn startup_transition(config: &Config, before: &Owner, after: &Owner) -> Result<bool> {
    if stop_owner(config, before).is_err() || stop_owner(config, after).is_err() {
        return Ok(false);
    }
    const CHANGING: [&str; 4] = ["ActiveState", "SubState", "MainPID", "ControlPID"];
    if before.values.len() != after.values.len()
        || before.values.iter().any(|(key, value)| {
            !CHANGING.contains(&key.as_str()) && after.values.get(key) != Some(value)
        })
    {
        return Ok(false);
    }
    let stage = |owner: &Owner| -> Result<Option<u8>> {
        Ok(
            match (
                owner.get("ActiveState")?,
                owner.get("SubState")?,
                owner.num("MainPID")?,
                owner.num("ControlPID")?,
            ) {
                ("activating", "start-pre", 0, control) if control > 0 => Some(0),
                ("activating", "start", main, 0) if main > 0 => Some(1),
                ("active", "running", main, 0) if main > 0 => Some(2),
                _ => None,
            },
        )
    };
    Ok(match (stage(before)?, stage(after)?) {
        (Some(0), Some(0)) => before.num("ControlPID")? != after.num("ControlPID")?,
        (Some(0), Some(1 | 2)) => true,
        (Some(1), Some(2)) => before.num("MainPID")? == after.num("MainPID")?,
        _ => false,
    })
}
fn startup_retry(
    config: &Config,
    before: &Owner,
    after: &Owner,
    retries: u64,
    deadline: Instant,
) -> Result<bool> {
    Ok(retries < 2 && Instant::now() < deadline && startup_transition(config, before, after)?)
}
fn limits(config: &Config, current: &Owner) -> Result<()> {
    stop_owner(config, current)?;
    require!(
        current.num("MemoryMax")? == config.memory
            && current.num("MemorySwapMax")? == config.swap
            && current.num("TasksMax")? == config.tasks
            && duration_usec(current.get("CPUQuotaPerSecUSec")?)? == config.cpu,
        "native resource policy changed"
    );
    let property = match current.get("Type")? {
        "oneshot" => "TimeoutStartUSec",
        "simple" | "exec" => "RuntimeMaxUSec",
        _ => return Err("unsupported compiler unit type".into()),
    };
    require!(
        duration_usec(current.get(property)?)? == config.run_usec,
        "finite native execution bound changed"
    );
    Ok(())
}
fn kernel_limits(config: &Config, current: &Owner) -> Result<()> {
    limits(config, current)?;
    let cg = current.get("ControlGroup")?;
    let path = lexical_path(cg)?;
    require!(
        path.file_name().and_then(|s| s.to_str()) == Some(config.unit.as_str()),
        "unexpected actor cgroup"
    );
    let root = PathBuf::from(format!("/sys/fs/cgroup{cg}"));
    require!(
        root.canonicalize().map_err(io)? == root,
        "actor cgroup alias"
    );
    let read = |name: &str| -> Result<String> {
        String::from_utf8(read_bounded(&root.join(name), 1024)?)
            .map_err(|_| "invalid cgroup scalar".into())
    };
    require!(
        number(read("memory.max")?.trim())? == config.memory
            && number(read("memory.swap.max")?.trim())? == config.swap
            && number(read("pids.max")?.trim())? == config.tasks,
        "kernel memory/swap/tasks policy mismatch"
    );
    let cpu = read("cpu.max")?;
    let fields: Vec<_> = cpu.split_whitespace().collect();
    require!(fields.len() == 2, "invalid kernel cpu.max");
    let quota = positive(fields[0])?;
    let period = positive(fields[1])?;
    require!(
        u128::from(quota) * 1_000_000 == u128::from(config.cpu) * u128::from(period),
        "kernel CPU quota mismatch"
    );
    for key in ["MainPID", "ControlPID"] {
        let pid = current.num(key)?;
        if pid != 0 {
            let actual = read_bounded(&PathBuf::from(format!("/proc/{pid}/cgroup")), 4096)?;
            require!(
                actual == format!("0::{cg}\n").as_bytes(),
                "actor PID escaped bound cgroup"
            );
        }
    }
    Ok(())
}
fn guard_invocation() -> Result<String> {
    let iid = env::var("INVOCATION_ID").map_err(|_| "missing genuine guard INVOCATION_ID")?;
    require!(hex_id(&iid, 32), "invalid guard invocation id");
    let cg = String::from_utf8(read_bounded(Path::new("/proc/self/cgroup"), 4096)?)
        .map_err(|_| "invalid own cgroup")?;
    let group = cg
        .strip_prefix("0::")
        .and_then(|s| s.strip_suffix('\n'))
        .ok_or("nonunified guard cgroup")?;
    let name = Path::new(group)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("missing guard service name")?;
    require!(
        (name.starts_with("horizon-monitor-") || name.starts_with("horizon-guard-"))
            && name.ends_with(".service"),
        "guard must run in its own Horizon service"
    );
    let native = owner(name)?;
    require!(
        native.get("InvocationID")? == iid
            && native.get("ControlGroup")? == group
            && native.num("NRestarts")? == 0
            && native.get("Restart")? == "no"
            && native.get("KillMode")? == "control-group"
            && native.get("Delegate")? == "no"
            && [native.num("MainPID")?, native.num("ControlPID")?]
                .contains(&u64::from(std::process::id())),
        "guard invocation is not current native owner"
    );
    Ok(iid)
}

#[derive(Default, Clone, Debug)]
struct Scan {
    bytes: u64,
    entries: u64,
    vanished: u64,
    symlinks: u64,
}
fn mount_id(file: &File) -> Result<u64> {
    let text = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).map_err(io)?;
    let rows: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:"))
        .collect();
    require!(rows.len() == 1, "missing or duplicate descriptor mount ID");
    positive(rows[0].trim())
}
fn account(m: &Metadata, dev: u64, scan: &mut Scan) -> Result<()> {
    require!(m.dev() == dev, "tree filesystem escape");
    scan.entries = scan.entries.checked_add(1).ok_or("entry overflow")?;
    require!(scan.entries <= MAX_ENTRIES, "entry bound exceeded");
    // Double counting hardlinks is intentional conservative accounting. It is
    // neither unique allocation proof nor admission/retirement credit.
    scan.bytes = scan
        .bytes
        .checked_add(m.blocks().checked_mul(512).ok_or("block overflow")?)
        .ok_or("physical total overflow")?;
    Ok(())
}
fn walk(
    dir: &File,
    dev: u64,
    mount: u64,
    depth: u32,
    deadline: Instant,
    scan: &mut Scan,
) -> Result<()> {
    require!(
        depth <= MAX_DEPTH && Instant::now() < deadline,
        "tree scan depth/time bound exceeded"
    );
    require!(mount_id(dir)? == mount, "tree directory mount escape");
    let metadata = dir.metadata().map_err(io)?;
    require!(metadata.is_dir(), "non-directory traversal descriptor");
    account(&metadata, dev, scan)?;
    let anchor = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    for entry in fs::read_dir(anchor).map_err(io)? {
        require!(Instant::now() < deadline, "tree scan time bound exceeded");
        let path = entry.map_err(io)?.path();
        let first = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                scan.vanished += 1;
                continue;
            }
            Err(e) => return Err(io(e)),
        };
        let flags = O_NOFOLLOW | O_CLOEXEC | if first.is_dir() { O_DIRECTORY } else { O_PATH };
        let child = match OpenOptions::new().read(true).custom_flags(flags).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                scan.vanished += 1;
                continue;
            }
            Err(e) => return Err(io(e)),
        };
        let actual = child.metadata().map_err(io)?;
        require!(
            same_inode(&first, &actual) && first.file_type() == actual.file_type(),
            "tree entry identity raced"
        );
        require!(mount_id(&child)? == mount, "tree child mount escape");
        if actual.is_dir() {
            walk(&child, dev, mount, depth + 1, deadline, scan)?;
        } else {
            account(&actual, dev, scan)?;
            if actual.file_type().is_symlink() {
                scan.symlinks += 1;
            }
        }
    }
    Ok(())
}
fn observe(root: &Path, descriptor: &File, dev: u64, ino: u64) -> Result<(Scan, Scan)> {
    observe_until(
        root,
        descriptor,
        dev,
        ino,
        Instant::now() + Duration::from_secs(30),
    )
}
fn observe_until(
    root: &Path,
    descriptor: &File,
    dev: u64,
    ino: u64,
    deadline: Instant,
) -> Result<(Scan, Scan)> {
    let start = descriptor.metadata().map_err(io)?;
    require!(
        start.dev() == dev && start.ino() == ino,
        "unexpected bound root inode"
    );
    let mount = mount_id(descriptor)?;
    let mut first = Scan::default();
    let mut second = Scan::default();
    walk(descriptor, dev, mount, 0, deadline, &mut first)?;
    walk(descriptor, dev, mount, 0, deadline, &mut second)?;
    let end = fs::symlink_metadata(root).map_err(io)?;
    require!(
        same_inode(&start, &end) && end.is_dir() && root.canonicalize().map_err(io)? == root,
        "root changed during scan"
    );
    Ok((first, second))
}
fn free_bytes(root: &File) -> Result<u64> {
    let mut value = StatVfs::default();
    // repr(C) is pinned to glibc's GNU Linux x86_64 statvfs ABI above.
    require!(
        unsafe { fstatvfs(root.as_raw_fd(), &mut value) } == 0,
        "fstatvfs failed"
    );
    require!(value.frsize > 0, "zero filesystem fragment size");
    value
        .bavail
        .checked_mul(value.frsize)
        .ok_or_else(|| "filesystem free-byte overflow".into())
}
fn trip_reason(free: u64, physical: u64, config: &Config) -> Option<&'static str> {
    if free < config.floor {
        Some("filesystem-floor")
    } else if physical > config.cap {
        Some("whole-root-cap")
    } else {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Text(String),
    Number(u64),
    Bool(bool),
}
type Record = BTreeMap<String, Value>;
fn text(map: &mut Record, key: &str, value: &str) {
    map.insert(key.into(), Value::Text(value.into()));
}
fn num(map: &mut Record, key: &str, value: u64) {
    map.insert(key.into(), Value::Number(value));
}
fn boolean(map: &mut Record, key: &str, value: bool) {
    map.insert(key.into(), Value::Bool(value));
}
fn safe_text(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/_-.:".contains(&b))
}
fn encode(map: &Record) -> Result<Vec<u8>> {
    let mut rows = Vec::new();
    for (key, value) in map {
        require!(safe_text(key), "unsafe receipt key");
        let value = match value {
            Value::Text(s) => {
                require!(safe_text(s), "unsafe receipt string");
                format!("\"{s}\"")
            }
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
        };
        rows.push(format!("  \"{key}\": {value}"));
    }
    let bytes = format!("{{\n{}\n}}\n", rows.join(",\n")).into_bytes();
    require!(bytes.len() as u64 <= MAX_RECEIPT, "receipt bound exceeded");
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> Result<Record> {
    let input = std::str::from_utf8(bytes).map_err(|_| "invalid receipt encoding")?;
    require!(
        input.starts_with("{\n") && input.ends_with("\n}\n"),
        "invalid receipt framing"
    );
    let inner = &input[2..input.len() - 3];
    let rows: Vec<_> = inner.split('\n').collect();
    let mut result = Record::new();
    for (index, row) in rows.iter().enumerate() {
        let row = if index + 1 < rows.len() {
            row.strip_suffix(',').ok_or("missing receipt comma")?
        } else {
            row
        };
        let (key, raw) = row
            .strip_prefix("  \"")
            .and_then(|s| s.split_once("\": "))
            .ok_or("invalid receipt member")?;
        require!(safe_text(key), "invalid receipt key");
        let value = if let Some(s) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            require!(safe_text(s), "invalid receipt text");
            Value::Text(s.to_string())
        } else if raw == "true" || raw == "false" {
            Value::Bool(raw == "true")
        } else {
            Value::Number(number(raw)?)
        };
        require!(
            result.insert(key.to_string(), value).is_none(),
            "duplicate receipt member"
        );
    }
    require!(encode(&result)? == bytes, "noncanonical receipt");
    Ok(result)
}
struct Receipts {
    path: PathBuf,
    dir: File,
}
impl Receipts {
    fn check(&self) -> Result<()> {
        let path = fs::symlink_metadata(&self.path).map_err(io)?;
        let fd = self.dir.metadata().map_err(io)?;
        require!(
            same_inode(&path, &fd)
                && path.uid() == 0
                && path.gid() == 0
                && path.mode() & 0o7777 == 0o700
                && self.path.canonicalize().map_err(io)? == self.path,
            "receipt directory changed"
        );
        Ok(())
    }
    fn anchored(&self, name: &str) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}/{}", self.dir.as_raw_fd(), name))
    }
    fn read(&self, name: &str) -> Result<Option<Record>> {
        self.check()?;
        let path = self.anchored(name);
        let mut f = match OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let before = f.metadata().map_err(io)?;
        require!(
            before.is_file()
                && before.uid() == 0
                && before.mode() & 0o7777 == 0o600
                && before.nlink() == 1
                && before.len() <= MAX_RECEIPT,
            "unsafe receipt identity"
        );
        let mut data = Vec::new();
        (&mut f)
            .take(MAX_RECEIPT + 1)
            .read_to_end(&mut data)
            .map_err(io)?;
        let after = f.metadata().map_err(io)?;
        let path_after = fs::symlink_metadata(path).map_err(io)?;
        require!(
            data.len() as u64 == before.len()
                && same_inode(&before, &after)
                && same_inode(&before, &path_after)
                && before.mtime_nsec() == after.mtime_nsec()
                && before.mtime() == after.mtime()
                && before.ctime_nsec() == after.ctime_nsec()
                && before.ctime() == after.ctime(),
            "receipt changed while read"
        );
        self.check()?;
        Ok(Some(decode(&data)?))
    }
    fn publish(&self, name: &str, guard_iid: &str, record: &Record) -> Result<()> {
        self.check()?;
        require!(
            safe_text(name) && !name.contains('/') && hex_id(guard_iid, 32),
            "unsafe receipt name"
        );
        let bytes = encode(record)?;
        let temporary = format!(".pending-{guard_iid}-{name}");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open(self.anchored(&temporary))
            .map_err(io)?;
        let identity = file.metadata().map_err(io)?;
        require!(
            identity.uid() == 0
                && identity.gid() == 0
                && identity.mode() & 0o7777 == 0o600
                && identity.nlink() == 1
                && identity.len() == 0,
            "wrong new-receipt custody or umask"
        );
        file.write_all(&bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        self.check()?;
        let old = CString::new(temporary).map_err(|_| "invalid temporary name")?;
        let new = CString::new(name).map_err(|_| "invalid receipt name")?;
        // Atomic publication with no replacement, including existing symlinks.
        // A failure leaves its private pending file as diagnostic evidence.
        require!(
            unsafe {
                renameat2(
                    self.dir.as_raw_fd(),
                    old.as_ptr(),
                    self.dir.as_raw_fd(),
                    new.as_ptr(),
                    1,
                )
            } == 0,
            "receipt publication failed or destination already exists"
        );
        self.dir.sync_all().map_err(io)?;
        self.check()?;
        Ok(())
    }
}
fn authority(config: &Config) -> Record {
    let mut r = Record::new();
    for (key, value) in [
        ("unit", config.unit.as_str()),
        ("actor_invocation_id", config.iid.as_str()),
        ("self_sha256", config.self_sha.as_str()),
        ("qualified_hasher_sha256", HASHER_SHA256),
        ("root", config.root.to_str().unwrap_or("")),
    ] {
        text(&mut r, key, value);
    }
    for (key, value) in [
        ("root_device", config.dev),
        ("root_inode", config.ino),
        ("root_uid", u64::from(config.uid)),
        ("minimum_free_bytes", config.floor),
        ("maximum_root_bytes", config.cap),
        ("memory_max_bytes", config.memory),
        ("memory_swap_max_bytes", config.swap),
        ("tasks_max", config.tasks),
        ("cpu_quota_usec", config.cpu),
        ("maximum_run_usec", config.run_usec),
    ] {
        num(&mut r, key, value);
    }
    for key in [
        "remote_mutations",
        "replay_authority",
        "publication_authority",
        "local_retirement_authority",
    ] {
        boolean(&mut r, key, false);
    }
    r
}
fn bind_authority(config: &Config, r: &Record, schema: &str) -> Result<()> {
    for (key, value) in authority(config) {
        require!(r.get(&key) == Some(&value), "receipt authority mismatch");
    }
    require!(
        r.get("schema") == Some(&Value::Text(schema.into())),
        "receipt schema mismatch"
    );
    match r.get("guard_invocation_id") {
        Some(Value::Text(s)) if hex_id(s, 32) => (),
        _ => return Err("invalid original guard binding".into()),
    }
    Ok(())
}
fn event(config: &Config, guard_iid: &str, schema: &str, current: &Owner) -> Result<Record> {
    let mut r = authority(config);
    text(&mut r, "schema", schema);
    text(&mut r, "guard_invocation_id", guard_iid);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock precedes epoch")?
        .as_millis();
    num(
        &mut r,
        "recorded_unix_millis",
        u64::try_from(millis).map_err(|_| "clock overflow")?,
    );
    for key in ["Type", "ActiveState", "SubState", "Result", "ControlGroup"] {
        text(&mut r, &format!("native_{key}"), current.get(key)?);
    }
    num(&mut r, "native_MainPID", current.num("MainPID")?);
    num(&mut r, "native_ControlPID", current.num("ControlPID")?);
    num(&mut r, "native_NRestarts", current.num("NRestarts")?);
    Ok(r)
}
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn request_stop(
    config: &Config,
    guard_iid: &str,
    receipts: &Receipts,
    intent: &Record,
) -> Result<()> {
    bind_authority(
        config,
        intent,
        "jetstreamer-horizon-build-guard-stop-intent-v1",
    )?;
    let current = owner(&config.unit)?;
    stop_owner(config, &current)?; // Immediately before any stop, never a new owner.
    if current.terminal()? {
        let mut done = event(
            config,
            guard_iid,
            "jetstreamer-horizon-build-guard-stop-completion-v1",
            &current,
        )?;
        done.insert(
            "intent_guard_invocation_id".into(),
            intent
                .get("guard_invocation_id")
                .ok_or("missing intent guard")?
                .clone(),
        );
        receipts.publish("stop-completion.json", guard_iid, &done)?;
        return Ok(());
    }
    require!(
        ["active", "activating", "deactivating"].contains(&current.get("ActiveState")?),
        "unknown actor stop state"
    );
    native("/usr/bin/systemctl", &["stop", "--no-block", &config.unit])?;
    let after = owner(&config.unit)?;
    stop_owner(config, &after)?;
    let mut requested = event(
        config,
        guard_iid,
        "jetstreamer-horizon-build-guard-stop-request-v1",
        &after,
    )?;
    boolean(&mut requested, "nonblocking_stop_accepted", true);
    receipts.publish(
        &format!("stop-request-{guard_iid}.json"),
        guard_iid,
        &requested,
    )?;
    // No blocking kill wait and no retry loop. The same-IID next guard invocation
    // may finish closure; a collected/changed owner requires operator evidence.
    if after.terminal()? {
        let mut done = event(
            config,
            guard_iid,
            "jetstreamer-horizon-build-guard-stop-completion-v1",
            &after,
        )?;
        done.insert(
            "intent_guard_invocation_id".into(),
            intent
                .get("guard_invocation_id")
                .ok_or("missing intent guard")?
                .clone(),
        );
        receipts.publish("stop-completion.json", guard_iid, &done)?;
    }
    Ok(())
}
fn run(config: Config) -> Result<()> {
    require!(unsafe { geteuid() } == 0, "compiler guard must run as root");
    self_proof(&config.self_sha)?;
    let guard_iid = guard_invocation()?;
    let dir = private_dir(&config.receipt, 0)?;
    let receipts = Receipts {
        path: config.receipt.clone(),
        dir,
    };
    let first = owner(&config.unit)?;
    stop_owner(&config, &first)?;
    if let Some(done) = receipts.read("stop-completion.json")? {
        bind_authority(
            &config,
            &done,
            "jetstreamer-horizon-build-guard-stop-completion-v1",
        )?;
        let intent = receipts
            .read("stop-intent.json")?
            .ok_or("completion has no bound stop intent")?;
        bind_authority(
            &config,
            &intent,
            "jetstreamer-horizon-build-guard-stop-intent-v1",
        )?;
        require!(
            done.get("intent_guard_invocation_id") == intent.get("guard_invocation_id")
                && done.get("native_MainPID") == Some(&Value::Number(0))
                && done.get("native_ControlPID") == Some(&Value::Number(0)),
            "invalid completion closure binding"
        );
        require!(
            first.terminal()?,
            "completion no longer matches terminal original owner"
        );
        println!("original bound stop already complete");
        return Ok(());
    }
    if let Some(intent) = receipts.read("stop-intent.json")? {
        return request_stop(&config, &guard_iid, &receipts, &intent);
    }
    let observation = (|| -> Result<(Scan, Scan, u64, Owner, u64)> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut current = first.clone();
        let mut retries = 0;
        loop {
            require!(
                Instant::now() < deadline,
                "shared observation budget exhausted"
            );
            kernel_limits(&config, &current)?;
            require!(
                ["active", "activating"].contains(&current.get("ActiveState")?),
                "actor is not running"
            );
            let root = private_dir(&config.root, config.uid)?;
            let root_meta = root.metadata().map_err(io)?;
            require!(
                root_meta.dev() == config.dev && root_meta.ino() == config.ino,
                "unexpected bound root inode"
            );
            let before_free = free_bytes(&root)?;
            // An already-breached filesystem floor does not wait for a whole tree
            // scan. Preserve the same owner checks; zero entries explicitly means
            // this emergency observation did not measure the tree.
            if before_free < config.floor {
                let after = owner(&config.unit)?;
                require!(
                    after == current,
                    "actor changed across immediate floor observation"
                );
                kernel_limits(&config, &after)?;
                return Ok((
                    Scan::default(),
                    Scan::default(),
                    before_free,
                    current,
                    retries,
                ));
            }
            let (a, b) = observe_until(&config.root, &root, config.dev, config.ino, deadline)?;
            let free = before_free.min(free_bytes(&root)?);
            let after = owner(&config.unit)?;
            if after != current {
                // Never retry away a positively observed floor/cap breach.
                if trip_reason(free, a.bytes.max(b.bytes), &config).is_none()
                    && startup_retry(&config, &current, &after, retries, deadline)?
                {
                    kernel_limits(&config, &after)?;
                    current = after;
                    retries += 1;
                    continue;
                }
                return Err("actor identity/PIDs/state/policy changed across observation".into());
            }
            kernel_limits(&config, &after)?;
            require!(
                Instant::now() < deadline,
                "shared observation budget exhausted"
            );
            return Ok((a, b, free, current, retries));
        }
    })();
    let reason = match &observation {
        Ok((a, b, free, _, _)) => {
            trip_reason(*free, a.bytes.max(b.bytes), &config).map(str::to_string)
        }
        Err(error) => Some(format!("observation-failure:{error}")),
    };
    if let Some(reason) = reason {
        let mut intent = event(
            &config,
            &guard_iid,
            "jetstreamer-horizon-build-guard-stop-intent-v1",
            &first,
        )?;
        text(&mut intent, "reason_hex", &hex_bytes(reason.as_bytes()));
        boolean(&mut intent, "measurement_available", observation.is_ok());
        if let Ok((a, b, free, _, _)) = &observation {
            num(&mut intent, "available_bytes", *free);
            boolean(
                &mut intent,
                "tree_measured",
                a.entries != 0 && b.entries != 0,
            );
            num(
                &mut intent,
                "conservative_physical_bytes",
                a.bytes.max(b.bytes),
            );
        }
        receipts.publish("stop-intent.json", &guard_iid, &intent)?;
        return request_stop(&config, &guard_iid, &receipts, &intent);
    }
    let (a, b, free, accepted, retries) = observation?;
    let mut sample = event(
        &config,
        &guard_iid,
        "jetstreamer-horizon-build-guard-sample-v1",
        &accepted,
    )?;
    num(&mut sample, "startup_observation_retries", retries);
    num(
        &mut sample,
        "original_native_MainPID",
        first.num("MainPID")?,
    );
    num(
        &mut sample,
        "original_native_ControlPID",
        first.num("ControlPID")?,
    );
    text(
        &mut sample,
        "original_native_ActiveState",
        first.get("ActiveState")?,
    );
    text(
        &mut sample,
        "original_native_SubState",
        first.get("SubState")?,
    );
    num(&mut sample, "available_bytes", free);
    num(&mut sample, "first_physical_bytes", a.bytes);
    num(&mut sample, "second_physical_bytes", b.bytes);
    num(
        &mut sample,
        "conservative_physical_bytes",
        a.bytes.max(b.bytes),
    );
    num(&mut sample, "first_entries", a.entries);
    num(&mut sample, "second_entries", b.entries);
    num(&mut sample, "vanished_entries", a.vanished + b.vanished);
    num(&mut sample, "symlinks", a.symlinks.max(b.symlinks));
    boolean(&mut sample, "trip", false);
    boolean(&mut sample, "native_owner_stable", true);
    receipts.publish(&format!("sample-{guard_iid}.json"), &guard_iid, &sample)?;
    println!("healthy compiler guard sample {guard_iid}");
    Ok(())
}
fn main() {
    let result = parse(&env::args().skip(1).collect::<Vec<_>>()).and_then(run);
    if let Err(error) = result {
        eprintln!("compiler guard failed closed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = env::temp_dir().join(format!(
                "horizon-build-guard-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn args() -> Vec<String> {
        let pairs = [
            ("--unit", "horizon-qualify-234-arena-tests-v3.service"),
            (
                "--expected-invocation-id",
                "11111111111111111111111111111111",
            ),
            (
                "--self-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("--root", "/home/ubuntu/workspace/private-build"),
            ("--root-uid", "1000"),
            ("--root-device", "1"),
            ("--root-inode", "2"),
            (
                "--receipt-directory",
                "/var/lib/jetstreamer/build-guard-test-state",
            ),
            ("--minimum-free-bytes", "4096"),
            ("--maximum-root-bytes", "8192"),
            ("--expected-memory-max-bytes", "2147483648"),
            ("--expected-memory-swap-max-bytes", "0"),
            ("--expected-tasks-max", "256"),
            ("--expected-cpu-quota-usec", "2000000"),
            ("--expected-max-run-usec", "600000000"),
        ];
        pairs
            .iter()
            .flat_map(|(k, v)| [k.to_string(), v.to_string()])
            .collect()
    }
    fn replace(mut a: Vec<String>, key: &str, value: &str) -> Vec<String> {
        let i = a.iter().position(|v| v == key).unwrap();
        a[i + 1] = value.into();
        a
    }
    #[test]
    fn cli_requires_all_flags_once_and_denies_replay_stop_authority() {
        assert!(parse(&args()).is_ok());
        let mut duplicate = args();
        duplicate[0] = duplicate[2].clone();
        assert!(parse(&duplicate).is_err());
        let mut unknown = args();
        unknown[0] = "--overwrite-existing".into();
        assert!(parse(&unknown).is_err());
        for unit in [
            "horizon-qualify-236-general-shrink-debt-budget506-v1.service",
            "horizon-qualify-replay-build-v1.service",
            "horizon-qualify-import-v1.service",
            "other-tests.service",
        ] {
            assert!(parse(&replace(args(), "--unit", unit)).is_err());
        }
        for bad in [
            "",
            "0",
            "00000000000000000000000000000000",
            "ABCDEF0123456789abcdef0123456789",
        ] {
            assert!(parse(&replace(args(), "--expected-invocation-id", bad)).is_err());
        }
        for bad in ["0", "-1", "infinity", "01", "18446744073709551616"] {
            assert!(parse(&replace(args(), "--minimum-free-bytes", bad)).is_err());
        }
    }
    #[test]
    fn scan203_retirement_requires_its_exact_state_and_resource_profile() {
        let mut a = args();
        for (key, value) in [
            ("--unit", SCAN203_RETIREMENT_UNIT),
            ("--root", SCAN203_STATE),
            ("--root-uid", "0"),
            ("--receipt-directory", SCAN203_GUARD_STATE),
            ("--maximum-root-bytes", "67108864"),
            ("--expected-memory-max-bytes", "4294967296"),
            ("--expected-tasks-max", "512"),
            ("--expected-max-run-usec", "7200000000"),
        ] {
            a = replace(a, key, value);
        }
        assert!(parse(&a).is_ok());
        for (key, value) in [
            ("--unit", "horizon-scan204-retirement-v1.service"),
            ("--unit", "horizon-scan203-retirement-v2.service"),
            ("--root", "/var/lib/jetstreamer/other-state"),
            ("--root-uid", "1000"),
            ("--receipt-directory", "/var/lib/jetstreamer/other-guard"),
            ("--maximum-root-bytes", "67108865"),
            ("--expected-memory-max-bytes", "4294967297"),
            ("--expected-memory-swap-max-bytes", "1"),
            ("--expected-tasks-max", "513"),
            ("--expected-cpu-quota-usec", "2000001"),
            ("--expected-max-run-usec", "7200000001"),
        ] {
            assert!(parse(&replace(a.clone(), key, value)).is_err(), "{key}");
        }
        // Ordinary build profiles keep their existing independent namespace.
        assert!(parse(&args()).is_ok());
    }
    #[test]
    fn unsafe_or_overlapping_paths_are_denied() {
        for bad in [
            "relative",
            "/home/ubuntu/workspace/../else",
            "/home/ubuntu//workspace/build",
            "/home/ubuntu/workspace/build/",
            "/home/ubuntu/workspace/a b",
            "/",
        ] {
            assert!(parse(&replace(args(), "--root", bad)).is_err());
        }
        let a = replace(
            args(),
            "--root",
            "/var/lib/jetstreamer/build-guard-test-state/build",
        );
        assert!(parse(&a).is_err());
    }
    #[test]
    fn floor_and_cap_thresholds_are_distinct_and_inclusive() {
        let c = parse(&args()).unwrap();
        assert_eq!(trip_reason(4096, 8192, &c), None);
        assert_eq!(trip_reason(4095, 8192, &c), Some("filesystem-floor"));
        assert_eq!(trip_reason(4096, 8193, &c), Some("whole-root-cap"));
    }
    #[test]
    fn changed_owner_and_restart_policy_never_authorize_stop() {
        let c = parse(&args()).unwrap();
        let mut native = Owner {
            values: [
                ("Id", c.unit.as_str()),
                ("InvocationID", c.iid.as_str()),
                ("Restart", "no"),
                ("NRestarts", "0"),
                ("KillMode", "control-group"),
                ("Delegate", "no"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        };
        assert!(stop_owner(&c, &native).is_ok());
        native.values.insert(
            "InvocationID".into(),
            "22222222222222222222222222222222".into(),
        );
        assert!(stop_owner(&c, &native).is_err());
        native.values.insert("InvocationID".into(), c.iid.clone());
        native.values.insert("Restart".into(), "on-failure".into());
        assert!(stop_owner(&c, &native).is_err());
        assert!(properties("Id=a\nId=b\n").is_err());
    }
    fn startup_owner(c: &Config, active: &str, sub: &str, main: u64, control: u64) -> Owner {
        Owner {
            values: [
                ("Id", c.unit.clone()),
                ("InvocationID", c.iid.clone()),
                ("Restart", "no".into()),
                ("NRestarts", "0".into()),
                ("KillMode", "control-group".into()),
                ("Delegate", "no".into()),
                ("ActiveState", active.into()),
                ("SubState", sub.into()),
                ("MainPID", main.to_string()),
                ("ControlPID", control.to_string()),
                ("Result", "success".into()),
                ("Type", "exec".into()),
                ("ControlGroup", format!("/system.slice/{}", c.unit)),
                ("MemoryMax", c.memory.to_string()),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect(),
        }
    }
    #[test]
    fn only_declared_monotonic_startup_transitions_can_be_reobserved() {
        let c = parse(&args()).unwrap();
        let pre = startup_owner(&c, "activating", "start-pre", 0, 101);
        let pre_test = startup_owner(&c, "activating", "start-pre", 0, 102);
        let start = startup_owner(&c, "activating", "start", 103, 0);
        let running = startup_owner(&c, "active", "running", 103, 0);
        for (a, b) in [
            (&pre, &pre_test),
            (&pre, &start),
            (&pre, &running),
            (&start, &running),
        ] {
            assert!(startup_transition(&c, a, b).unwrap());
        }
        assert!(!startup_transition(&c, &pre, &pre).unwrap());
        for (a, b) in [
            (&running, &pre),
            (&running, &start),
            (&start, &pre),
            (&running, &running),
        ] {
            assert!(!startup_transition(&c, a, b).unwrap());
        }
        assert!(
            !startup_transition(&c, &start, &startup_owner(&c, "active", "running", 104, 0))
                .unwrap()
        );
        assert!(
            !startup_transition(&c, &pre, &startup_owner(&c, "deactivating", "stop", 103, 0))
                .unwrap()
        );
    }
    #[test]
    fn startup_retry_does_not_normalize_changed_owner_or_policy() {
        let c = parse(&args()).unwrap();
        let pre = startup_owner(&c, "activating", "start-pre", 0, 101);
        let running = startup_owner(&c, "active", "running", 103, 0);
        for (key, value) in [
            ("InvocationID", "22222222222222222222222222222222"),
            ("NRestarts", "1"),
            ("MemoryMax", "999"),
            ("ControlGroup", "/system.slice/foreign.service"),
            ("Restart", "on-failure"),
            ("Type", "oneshot"),
            ("Result", "exit-code"),
        ] {
            let mut changed = running.clone();
            changed.values.insert(key.into(), value.into());
            assert!(!startup_transition(&c, &pre, &changed).unwrap(), "{key}");
        }
        let mut changed = running.clone();
        changed.values.remove("MemoryMax");
        assert!(!startup_transition(&c, &pre, &changed).unwrap());
    }
    #[test]
    fn startup_retries_share_a_finite_budget_and_never_authorize_an_unstable_sample() {
        let c = parse(&args()).unwrap();
        let pre = startup_owner(&c, "activating", "start-pre", 0, 101);
        let running = startup_owner(&c, "active", "running", 103, 0);
        let deadline = Instant::now() + Duration::from_secs(1);
        assert!(startup_retry(&c, &pre, &running, 0, deadline).unwrap());
        assert!(startup_retry(&c, &pre, &running, 1, deadline).unwrap());
        assert!(!startup_retry(&c, &pre, &running, 2, deadline).unwrap());
        assert!(!startup_retry(
            &c,
            &pre,
            &running,
            0,
            Instant::now() - Duration::from_millis(1)
        )
        .unwrap());
        // Permission to discard a raced observation is not a stable result.
        assert_ne!(pre, running);
        assert!(!startup_retry(&c, &running, &running, 0, deadline).unwrap());
        let sample = event(&c, "22222222222222222222222222222222", "fixture", &running).unwrap();
        assert_eq!(sample.get("native_MainPID"), Some(&Value::Number(103)));
        assert_eq!(sample.get("native_ControlPID"), Some(&Value::Number(0)));
        assert_eq!(
            sample.get("native_ActiveState"),
            Some(&Value::Text("active".into()))
        );
    }
    #[test]
    fn descriptor_walk_counts_hardlinks_without_following_symlink_escape() {
        let t = Temp::new();
        let root = t.0.join("root");
        fs::create_dir(&root).unwrap();
        let file = root.join("one");
        fs::write(&file, vec![3; 16_384]).unwrap();
        fs::hard_link(&file, root.join("two")).unwrap();
        let outside = t.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("large"), vec![1; 1_048_576]).unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        symlink(&root, root.join("cycle")).unwrap();
        let fd = open_dir(&root).unwrap();
        let m = fd.metadata().unwrap();
        let (a, b) = observe(&root, &fd, m.dev(), m.ino()).unwrap();
        assert_eq!(a.symlinks, 2);
        assert_eq!(a.entries, 5);
        assert_eq!(a.bytes, b.bytes);
        assert!(a.bytes >= fs::metadata(file).unwrap().blocks() * 512 * 2);
        assert!(a.bytes < 1_048_576);
        assert!(open_dir(&root.join("escape")).is_err());
        assert!(observe(&root, &fd, m.dev(), m.ino() + 1).is_err());
    }
    #[test]
    fn cargo_build_script_executable_is_accounted_without_worker_classification() {
        let t = Temp::new();
        let script = t.0.join("target/debug/build/example/build-script-build");
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::write(&script, b"\x7fELFfixture-never-executed").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let fd = open_dir(&t.0).unwrap();
        let root = fd.metadata().unwrap();
        let (a, b) = observe(&t.0, &fd, root.dev(), root.ino()).unwrap();
        assert!(a.entries >= 6 && a.bytes >= fs::metadata(script).unwrap().blocks() * 512);
        assert_eq!(a.bytes, b.bytes);
    }
    #[test]
    fn unexpected_mount_or_entry_budget_fails_closed() {
        let t = Temp::new();
        let fd = open_dir(&t.0).unwrap();
        let m = fd.metadata().unwrap();
        assert!(walk(
            &fd,
            m.dev(),
            mount_id(&fd).unwrap() + 1,
            0,
            Instant::now() + Duration::from_secs(1),
            &mut Scan::default()
        )
        .is_err());
        assert!(walk(
            &fd,
            m.dev(),
            mount_id(&fd).unwrap(),
            MAX_DEPTH + 1,
            Instant::now() + Duration::from_secs(1),
            &mut Scan::default()
        )
        .is_err());
        let mut full = Scan {
            entries: MAX_ENTRIES,
            ..Scan::default()
        };
        assert!(account(&m, m.dev(), &mut full).is_err());
    }
    #[test]
    fn canonical_receipts_deny_duplicates_and_bind_exact_policy() {
        let c = parse(&args()).unwrap();
        let mut r = authority(&c);
        text(
            &mut r,
            "schema",
            "jetstreamer-horizon-build-guard-stop-intent-v1",
        );
        text(
            &mut r,
            "guard_invocation_id",
            "22222222222222222222222222222222",
        );
        assert_eq!(decode(&encode(&r).unwrap()).unwrap(), r);
        assert!(decode(b"{\n  \"a\": 1,\n  \"a\": 2\n}\n").is_err());
        assert!(bind_authority(&c, &r, "jetstreamer-horizon-build-guard-stop-intent-v1").is_ok());
        num(&mut r, "maximum_root_bytes", 8193);
        assert!(bind_authority(&c, &r, "jetstreamer-horizon-build-guard-stop-intent-v1").is_err());
    }
    #[test]
    fn atomic_publication_never_overwrites_receipts_or_symlinks() {
        // Fixture-only filesystem writes; no service, native command or remote mutation.
        let t = Temp::new();
        let dir = open_dir(&t.0).unwrap();
        // publish's custody gate intentionally requires Root. Test the same atomic
        // no-replace primitive independently under the test's current UID.
        let write = |old: &str, new: &str| {
            let old = CString::new(old).unwrap();
            let new = CString::new(new).unwrap();
            unsafe {
                renameat2(
                    dir.as_raw_fd(),
                    old.as_ptr(),
                    dir.as_raw_fd(),
                    new.as_ptr(),
                    1,
                )
            }
        };
        fs::write(t.0.join("first"), b"original").unwrap();
        assert_eq!(write("first", "receipt"), 0);
        fs::write(t.0.join("second"), b"replacement").unwrap();
        assert_ne!(write("second", "receipt"), 0);
        assert_eq!(fs::read(t.0.join("receipt")).unwrap(), b"original");
        symlink(t.0.join("outside"), t.0.join("link")).unwrap();
        assert_ne!(write("second", "link"), 0);
        assert!(fs::symlink_metadata(t.0.join("link"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
