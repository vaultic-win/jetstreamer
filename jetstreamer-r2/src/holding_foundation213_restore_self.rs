//! Opaque self-accounting for one already-admitted resumable byte restoration.
//! Never a general own-PID exemption or a replay/retirement admission.
use super::*;
use anyhow::Context as _;
use std::{
    collections::BTreeSet,
    os::fd::AsRawFd,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};
const ACTION: &str = "holding-foundation213-restore-resumable";
const UNIT: &str = "horizon-foundation-holding213-maintenance-v1.service";
const MAX_MEMORY: u64 = 6 << 30;
const MAX_TASKS: u64 = 256;
const MAX_SECONDS: u64 = 14400;
const MAX_CPU: u64 = 8_000_000;
const HOOKS: [&str; 5] = [
    "ExecStartPre",
    "ExecStartPost",
    "ExecCondition",
    "ExecStop",
    "ExecStopPost",
];
const ALLOWED_CAPS: u64 = (1 << 1) | (1 << 2) | (1 << 19);
#[derive(Clone, Debug, PartialEq)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl Identity {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
#[derive(Clone, Debug, PartialEq)]
struct Facts {
    unit: Value,
    hook_arrays: Value,
    kernel: Value,
    process_status: Value,
    mounts: Value,
    start: String,
    executable: PathBuf,
    executable_identity: Identity,
    lock_identity: Identity,
}
/// Private fields and a constructor restricted to the Foundation dispatcher.
/// The held descriptor is the exact transition flock acquired by that dispatcher.
pub(crate) struct Context<'a> {
    lock: &'a File,
    spec: Bound,
    mapping: Bound,
    custody: Bound,
    admission: Bound,
    spec_value: Value,
    custody_value: Value,
    admission_value: Value,
    pid: u32,
    iid: String,
    self_sha: String,
    initial: Facts,
    entry_clock: u64,
    started: Instant,
    entered: AtomicBool,
    floor: AtomicU64,
}
fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "oversized self-restore kernel/process metadata"
    );
    Ok(bytes)
}
fn property_object(bytes: &[u8]) -> Result<Value> {
    ensure!(
        bytes.len() <= 65536,
        "oversized self-restore manager properties"
    );
    let mut values = serde_json::Map::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let (k, v) = line
            .split_once('=')
            .context("self-restore property shape")?;
        ensure!(
            values.insert(k.into(), json!(v)).is_none(),
            "duplicate self-restore property"
        );
    }
    Ok(Value::Object(values))
}
fn unit() -> Result<Value> {
    let out=std::process::Command::new("/usr/bin/systemctl").env("LC_ALL","C").args(["show",UNIT,"--no-pager","--property=Id,LoadState,Type,User,Group,ActiveState,SubState,MainPID,InvocationID,NRestarts,Restart,KillMode,Delegate,ControlGroup,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,ExecStop,ExecStopPost,OnSuccess,OnFailure,Triggers,TriggeredBy,NoNewPrivileges,ProtectSystem,ProtectHome,ReadWritePaths,CapabilityBoundingSet,AmbientCapabilities,RootDirectory,RootImage,Result,ExecMainStatus"]).output()?;
    ensure!(out.status.success(), "self-restore manager query failed");
    property_object(&out.stdout)
}
// systemctl show can omit empty command arrays. Its omission is preserved;
// actual typed D-Bus replies, queried independently for all five exact hooks,
// are mandatory even when show prints an empty string.
fn hook_arrays() -> Result<Value> {
    let mut replies = serde_json::Map::new();
    for name in HOOKS {
        let out = std::process::Command::new("/usr/bin/busctl")
            .args([
                "--system",
                "get-property",
                "org.freedesktop.systemd1",
                &bus_path(UNIT),
                "org.freedesktop.systemd1.Service",
                name,
            ])
            .output()?;
        ensure!(
            out.status.success() && out.stdout.len() <= 1024,
            "self-restore typed hook array unavailable: {name}"
        );
        replies.insert(name.into(), json!(std::str::from_utf8(&out.stdout)?));
    }
    Ok(Value::Object(replies))
}
fn validate_hook_arrays(show: &Value, replies: &Value) -> Result<()> {
    let values = replies
        .as_object()
        .context("self-restore typed hook replies missing")?;
    ensure!(
        values.len() == HOOKS.len() && values.keys().all(|k| HOOKS.contains(&k.as_str())),
        "self-restore typed hook reply roster differs"
    );
    for name in HOOKS {
        let raw = values
            .get(name)
            .and_then(Value::as_str)
            .context("self-restore typed hook reply missing or malformed")?;
        ensure!(
            matches!(raw, "a(sasbttttuii) 0" | "a(sasbttttuii) 0\n"),
            "self-restore typed hook array is not exactly empty: {name}"
        );
        ensure!(
            show.get(name)
                .is_none_or(|value| value.as_str() == Some("")),
            "self-restore show hook disagrees with the actual empty typed array: {name}"
        );
    }
    Ok(())
}
fn bus_path(unit: &str) -> String {
    let mut result = "/org/freedesktop/systemd1/unit/".to_owned();
    for c in unit.bytes() {
        if c.is_ascii_alphanumeric() {
            result.push(c as char)
        } else {
            result.push_str(&format!("_{c:02x}"));
        }
    }
    result
}
fn raw_usec(name: &str) -> Result<u64> {
    let out = std::process::Command::new("/usr/bin/busctl")
        .args([
            "--system",
            "get-property",
            "org.freedesktop.systemd1",
            &bus_path(UNIT),
            "org.freedesktop.systemd1.Service",
            name,
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1024,
        "self-restore raw manager bound unavailable"
    );
    let parts = std::str::from_utf8(&out.stdout)?
        .split_whitespace()
        .collect::<Vec<_>>();
    ensure!(
        parts.len() == 2 && parts[0] == "t",
        "malformed self-restore raw bound"
    );
    Ok(parts[1].parse()?)
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("missing self-restore property: {key}"))
}
fn numeric(v: &Value, key: &str) -> Result<u64> {
    Ok(text(v, key)?.parse()?)
}
fn high(v: &Value) -> Result<Option<u64>> {
    let s = text(v, "MemoryHigh")?;
    if s == "infinity" {
        Ok(None)
    } else {
        Ok(Some(s.parse()?))
    }
}
fn caps(value: &str) -> Result<u64> {
    let mut mask = 0u64;
    let mut seen = BTreeSet::new();
    for name in value.split_whitespace() {
        ensure!(seen.insert(name), "duplicate self-restore capability");
        mask |= match name {
            "cap_dac_override" => 1 << 1,
            "cap_dac_read_search" => 1 << 2,
            "cap_sys_ptrace" => 1 << 19,
            _ => anyhow::bail!("unreviewed self-restore capability:{name}"),
        };
    }
    Ok(mask)
}
fn bare_command(actual: &str) -> Option<&str> {
    if !actual.contains(" ; start_time=") {
        return actual.strip_suffix(" }");
    }
    let (identity, metadata) = actual.split_once(" ; start_time=")?;
    let fields = metadata
        .strip_suffix(" }")?
        .split(" ; ")
        .collect::<Vec<_>>();
    (identity.starts_with("{ path=")
        && identity.matches(" ; argv[]=").count() == 1
        && identity.ends_with(" ; ignore_errors=no")
        && fields.len() == 5
        && fields[0].starts_with('[')
        && fields[0].ends_with(']')
        && fields[1].starts_with("stop_time=[")
        && fields[1].ends_with(']')
        && fields[2]
            .strip_prefix("pid=")
            .is_some_and(|s| s.parse::<u32>().is_ok())
        && fields[3].starts_with("code=")
        && fields[4].starts_with("status="))
    .then_some(identity)
}
fn command(exe: &Path, spec: &Bound, self_sha: &str) -> String {
    format!(
        "{{ path={} ; argv[]={} {ACTION} {} --spec-sha256 {} --self-sha256 {} ; ignore_errors=no }}",
        exe.display(),
        exe.display(),
        spec.path.display(),
        spec.sha256,
        self_sha
    )
}
struct Binding<'a> {
    pid: u32,
    iid: &'a str,
    exe: &'a Path,
    spec: &'a Bound,
    self_sha: &'a str,
}
#[derive(Clone, Copy)]
struct ManagerLimits {
    timeout: u64,
    runtime: u64,
    quota: u64,
}
fn validate_unit(v: &Value, b: &Binding<'_>, limits: ManagerLimits, hooks: &Value) -> Result<()> {
    validate_hook_arrays(v, hooks)?;
    let Binding {
        pid,
        iid,
        exe,
        spec,
        self_sha,
    } = *b;
    let ManagerLimits {
        timeout,
        runtime,
        quota,
    } = limits;
    for (key, expected) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("RootDirectory", ""),
        ("RootImage", ""),
        ("OnSuccess", ""),
        ("OnFailure", ""),
        ("Triggers", ""),
        ("TriggeredBy", ""),
    ] {
        ensure!(
            v[key] == expected,
            "unqualified self-restore unit property:{key}"
        );
    }
    ensure!(
        ["", "root", "0"].contains(&text(v, "User")?)
            && ["", "root", "0"].contains(&text(v, "Group")?),
        "self-restore manager user/group is not explicit or default root"
    );
    ensure!(
        pid > 1
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && iid.bytes().any(|b| b != b'0')
            && v["InvocationID"] == iid
            && numeric(v, "MainPID")? == u64::from(pid)
            && v["ControlGroup"] == format!("/system.slice/{UNIT}"),
        "self-restore is not this exact actual PID/invocation/cgroup"
    );
    ensure!(
        (v["Type"] == "oneshot"
            && v["ActiveState"] == "activating"
            && v["SubState"] == "start"
            && timeout > 0
            && timeout <= MAX_SECONDS * 1_000_000)
            || (v["Type"] == "exec"
                && v["ActiveState"] == "active"
                && v["SubState"] == "running"
                && runtime > 0
                && runtime <= MAX_SECONDS * 1_000_000),
        "self-restore lacks a real bounded active service deadline"
    );
    ensure!(
        (1..=MAX_MEMORY).contains(&numeric(v, "MemoryMax")?)
            && high(v)?.is_none_or(|h| h > 0 && h <= numeric(v, "MemoryMax").unwrap_or(0))
            && numeric(v, "MemorySwapMax")? == 0
            && (1..=MAX_TASKS).contains(&numeric(v, "TasksMax")?)
            && (1..=MAX_CPU).contains(&quota),
        "self-restore memory/swap/tasks/CPU envelope is not bounded"
    );
    let writable = text(v, "ReadWritePaths")?
        .split_whitespace()
        .collect::<Vec<_>>();
    ensure!(
        writable == [STATE] || writable == ["/home/ubuntu/.jetstreamer-private"],
        "self-restore writable scope differs from the reviewed holding sandbox"
    );
    let bounding = caps(text(v, "CapabilityBoundingSet")?)?;
    let ambient = caps(text(v, "AmbientCapabilities")?)?;
    ensure!(
        bounding & !ALLOWED_CAPS == 0 && ambient & !bounding == 0,
        "self-restore capability envelope differs"
    );
    ensure!(
        bare_command(text(v, "ExecStart")?) == command(exe, spec, self_sha).strip_suffix(" }"),
        "self-restore manager command is not the exact immutable resumable spec/self binding"
    );
    Ok(())
}
fn process_status(bytes: &[u8], v: &Value) -> Result<Value> {
    let source = std::str::from_utf8(bytes)?;
    let mut out = serde_json::Map::new();
    for key in [
        "Uid",
        "Gid",
        "NoNewPrivs",
        "CapEff",
        "CapPrm",
        "CapBnd",
        "CapAmb",
    ] {
        let matches = source
            .lines()
            .filter_map(|l| l.strip_prefix(&format!("{key}:")))
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "missing/duplicate actual self-restore status field:{key}"
        );
        out.insert(key.into(), json!(matches[0].trim()));
    }
    let result = Value::Object(out);
    ensure!(
        result["Uid"] == "0\t0\t0\t0"
            && result["Gid"] == "0\t0\t0\t0"
            && result["NoNewPrivs"] == "1",
        "self-restore actual process UID/GID/privilege state differs"
    );
    for key in ["CapEff", "CapPrm", "CapBnd", "CapAmb"] {
        let actual = u64::from_str_radix(result[key].as_str().unwrap(), 16)?;
        ensure!(
            actual & !ALLOWED_CAPS == 0,
            "self-restore actual process retained extra capabilities"
        );
    }
    ensure!(
        u64::from_str_radix(text(&result, "CapBnd")?, 16)?
            == caps(text(v, "CapabilityBoundingSet")?)?,
        "actual self-restore capability bounding set differs from manager"
    );
    Ok(result)
}
fn mount_scope(bytes: &[u8]) -> Result<Value> {
    let mut mounts = Vec::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() >= 10 && fields.contains(&"-") && fields[4].starts_with('/'),
            "malformed self-restore mount namespace"
        );
        mounts.push((fields[4], fields[5], fields[0]));
    }
    let mut proof = serde_json::Map::new();
    for (path, expected) in [
        ("/", "ro"),
        ("/home/ubuntu/horizon", "ro"),
        ("/var/lib/jetstreamer", "ro"),
        (STATE, "rw"),
    ] {
        let selected = mounts
            .iter()
            .filter(|(m, _, _)| {
                *m == "/"
                    || path == *m
                    || path
                        .strip_prefix(*m)
                        .is_some_and(|tail| tail.starts_with('/'))
            })
            .max_by_key(|(m, _, _)| m.len())
            .context("self-restore effective mount omitted")?;
        ensure!(
            selected.1.split(',').any(|v| v == expected),
            "self-restore actual mount protection differs:{path}"
        );
        proof.insert(path.into(),json!({"mount_point":selected.0,"options":selected.1,"mount_id":selected.2,"required":expected}));
    }
    Ok(Value::Object(proof))
}
fn owned_flock(bytes: &[u8], pid: u32, dev: u64, ino: u64) -> Result<()> {
    let rows = std::str::from_utf8(bytes)?
        .lines()
        .filter_map(|l| l.strip_prefix("lock:"))
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1,
        "self-restore does not own exactly one transition descriptor flock"
    );
    let fields = rows[0].split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() == 8
            && fields[0]
                .strip_suffix(':')
                .is_some_and(|s| s.parse::<u64>().is_ok())
            && fields[1] == "FLOCK"
            && fields[2] == "ADVISORY"
            && fields[3] == "WRITE"
            && fields[4].parse::<u32>()? == pid
            && fields[6] == "0"
            && fields[7] == "EOF",
        "self-restore transition flock is foreign/unowned"
    );
    let id = fields[5].split(':').collect::<Vec<_>>();
    ensure!(
        id.len() == 3
            && u64::from_str_radix(id[0], 16)? == u64::from(libc::major(dev))
            && u64::from_str_radix(id[1], 16)? == u64::from(libc::minor(dev))
            && id[2].parse::<u64>()? == ino,
        "self-restore transition flock inode differs"
    );
    Ok(())
}
fn lock_identity(lock: &File, pid: u32) -> Result<Identity> {
    let m = lock.metadata()?;
    let path = Path::new(STATE).join("transition.lock");
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o600
            && Identity::of(&fs::symlink_metadata(path)?) == Identity::of(&m),
        "self-restore transition-lock path/descriptor is unsafe or replaced"
    );
    owned_flock(
        &bounded_read(
            &PathBuf::from(format!("/proc/self/fdinfo/{}", lock.as_raw_fd())),
            16384,
        )?,
        pid,
        m.dev(),
        m.ino(),
    )?;
    Ok(Identity::of(&m))
}
fn running_deadline(elapsed_seconds: u64) -> Result<()> {
    ensure!(
        elapsed_seconds < MAX_SECONDS,
        "self-restore original bounded invocation deadline elapsed"
    );
    Ok(())
}
fn start_time() -> Result<String> {
    let bytes = bounded_read(Path::new("/proc/self/stat"), 65536)?;
    Ok(std::str::from_utf8(&bytes)?
        .rsplit_once(')')
        .context("self stat shape")?
        .1
        .split_whitespace()
        .nth(19)
        .context("self start time")?
        .into())
}
fn executable(self_sha: &str) -> Result<(PathBuf, Identity)> {
    let path = fs::read_link("/proc/self/exe")?;
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "self-restore executable is not canonical"
    );
    let mut mapped = File::open("/proc/self/exe")?;
    let m = mapped.metadata()?;
    let initial = Identity::of(&m);
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= 128 << 20
            && Identity::of(&fs::symlink_metadata(&path)?) == initial,
        "self-restore actual mapped executable is not sealed/root-bound"
    );
    let mut digest = Sha256::new();
    let mut bytes = [0u8; 128 << 10];
    loop {
        let n = mapped.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        digest.update(&bytes[..n]);
    }
    ensure!(
        hex_lower(&digest.finalize()) == self_sha
            && Identity::of(&mapped.metadata()?) == initial
            && Identity::of(&fs::symlink_metadata(&path)?) == initial,
        "self-restore sealed executable changed or has another self digest"
    );
    Ok((path, initial))
}
#[derive(Clone, Copy)]
struct KernelValues<'a> {
    page: u64,
    maximum: u64,
    high: &'a str,
    swap: u64,
    tasks: u64,
    quota: u64,
    period: u64,
    requested_quota: u64,
    pids: &'a [u32],
}
fn validate_kernel(v: &Value, pid: u32, a: &KernelValues<'_>) -> Result<()> {
    let KernelValues {
        page,
        maximum,
        high,
        swap,
        tasks,
        quota: q,
        period,
        requested_quota: quota,
        pids,
    } = *a;
    ensure!(
        page >= 4096 && page.is_power_of_two(),
        "self-restore kernel page size differs"
    );
    ensure!(
        pids == [pid]
            && maximum == numeric(v, "MemoryMax")? / page * page
            && maximum > 0
            && match self::high(v)? {
                Some(h) => high.parse::<u64>()? == h / page * page,
                None => high == "max",
            }
            && swap == 0
            && tasks == numeric(v, "TasksMax")?
            && period > 0
            && u128::from(q) * 1_000_000 == u128::from(quota) * u128::from(period),
        "self-restore actual enforced kernel controls/sole process differ from the bound sandbox"
    );
    Ok(())
}
fn kernel(v: &Value, pid: u32, timeout: u64, runtime: u64, quota: u64) -> Result<Value> {
    let expected = format!("0::/system.slice/{UNIT}");
    let cg = bounded_read(Path::new("/proc/self/cgroup"), 16384)?;
    ensure!(
        std::str::from_utf8(&cg)?.trim() == expected,
        "self-restore actual process escaped its tracked cgroup"
    );
    let root = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    ensure!(
        root.canonicalize()? == root && fs::symlink_metadata(&root)?.is_dir(),
        "self-restore cgroup is redirected"
    );
    let read = |key: &str| -> Result<String> {
        Ok(std::str::from_utf8(&bounded_read(&root.join(key), 16384)?)?
            .trim()
            .into())
    };
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(
        page >= 4096 && (page as u64).is_power_of_two(),
        "self-restore host page size invalid"
    );
    let page = page as u64;
    let maximum = read("memory.max")?.parse::<u64>()?;
    let high = read("memory.high")?;
    let swap = read("memory.swap.max")?.parse::<u64>()?;
    let tasks = read("pids.max")?.parse::<u64>()?;
    let cpu = read("cpu.max")?;
    let fields = cpu.split_whitespace().collect::<Vec<_>>();
    ensure!(fields.len() == 2, "self-restore CPU kernel bound shape");
    let q = fields[0].parse::<u64>()?;
    let period = fields[1].parse::<u64>()?;
    let mut pids = read("cgroup.procs")?
        .lines()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    pids.sort_unstable();
    pids.dedup();
    validate_kernel(
        v,
        pid,
        &KernelValues {
            page,
            maximum,
            high: &high,
            swap,
            tasks,
            quota: q,
            period,
            requested_quota: quota,
            pids: &pids,
        },
    )?;
    Ok(
        json!({"memory_max_bytes":maximum,"memory_high":high,"memory_swap_max_bytes":swap,"tasks_max":tasks,"cpu_quota_usec":q,"cpu_period_usec":period,"cpu_quota_usec_per_second":quota,"timeout_start_usec":timeout,"runtime_max_usec":runtime,"page_size_bytes":page,"cgroup_processes":pids}),
    )
}
impl<'a> Context<'a> {
    pub(super) fn begin(
        action: &str,
        p: &RestoreSpec,
        spec: &Bound,
        lock: &'a File,
    ) -> Result<Self> {
        ensure!(
            action == ACTION && p.schema == "jetstreamer-foundation213-resumable-restore-plan-v1",
            "self-accounting is restricted to exact resumable restoration"
        );
        mapping_binding(&p.mapping)?;
        let c = receipt_bound(&p.custody)?;
        ensure!(
            custody(&c)? == Artifact::Prefix213,
            "self-restore context has foreign custody artifact"
        );
        let a = receipt_bound(&p.admission)?;
        let entry_clock = clock()?;
        admission_scope_at(&a, &p.custody, Artifact::Prefix213, entry_clock)?;
        let spec_value = bound(spec)?;
        ensure!(
            spec_value
                == json!({"schema":p.schema,"mapping":p.mapping,"custody":p.custody,"admission":p.admission}),
            "self-restore exact immutable spec differs"
        );
        let args = env::args().collect::<Vec<_>>();
        ensure!(
            args.len() == 7
                && args[1] == ACTION
                && args[2] == spec.path.to_str().context("non-UTF8 restore spec")?
                && args[3] == "--spec-sha256"
                && args[4] == spec.sha256
                && args[5] == "--self-sha256"
                && digest(&args[6]),
            "self-restore command-line/spec/self binding differs"
        );
        let iid = env::var("INVOCATION_ID")
            .context("self-restore requires actual tracked service invocation")?;
        let pid = std::process::id();
        let self_sha = args[6].clone();
        let floor = a["capacity"]["minimum_free_bytes"]
            .as_u64()
            .filter(|n| *n > 0)
            .context("admitted self-restore floor")?;
        let initial = Self::facts(lock, pid, &iid, spec, &self_sha)?;
        Ok(Self {
            lock,
            spec: spec.clone(),
            mapping: p.mapping.clone(),
            custody: p.custody.clone(),
            admission: p.admission.clone(),
            spec_value,
            custody_value: c,
            admission_value: a,
            pid,
            iid,
            self_sha,
            initial,
            entry_clock,
            started: Instant::now(),
            entered: AtomicBool::new(false),
            floor: AtomicU64::new(floor),
        })
    }
    fn facts(lock: &File, pid: u32, iid: &str, spec: &Bound, self_sha: &str) -> Result<Facts> {
        ensure!(
            unsafe { libc::geteuid() } == 0 && pid == std::process::id(),
            "self-restore context must authenticate the actual root process"
        );
        let start = start_time()?;
        let (executable, executable_identity) = executable(self_sha)?;
        let command_line = bounded_read(Path::new("/proc/self/cmdline"), 65536)?;
        let expected = vec![
            executable
                .to_str()
                .context("non-UTF8 self executable")?
                .to_owned(),
            ACTION.to_owned(),
            spec.path.to_str().context("non-UTF8 self spec")?.to_owned(),
            "--spec-sha256".to_owned(),
            spec.sha256.clone(),
            "--self-sha256".to_owned(),
            self_sha.to_owned(),
        ];
        let mut expected_bytes = Vec::new();
        for arg in expected {
            expected_bytes.extend_from_slice(arg.as_bytes());
            expected_bytes.push(0);
        }
        ensure!(
            command_line == expected_bytes,
            "actual self-restore kernel argv differs from bound executable/spec/action"
        );
        let unit = unit()?;
        let hook_arrays = hook_arrays()?;
        let timeout = raw_usec("TimeoutStartUSec")?;
        let runtime = raw_usec("RuntimeMaxUSec")?;
        let quota = raw_usec("CPUQuotaPerSecUSec")?;
        validate_unit(
            &unit,
            &Binding {
                pid,
                iid,
                exe: &executable,
                spec,
                self_sha,
            },
            ManagerLimits {
                timeout,
                runtime,
                quota,
            },
            &hook_arrays,
        )?;
        let status = process_status(&bounded_read(Path::new("/proc/self/status"), 65536)?, &unit)?;
        let kernel = kernel(&unit, pid, timeout, runtime, quota)?;
        let mounts = mount_scope(&bounded_read(Path::new("/proc/self/mountinfo"), 256 << 10)?)?;
        let lock_identity = lock_identity(lock, pid)?;
        ensure!(
            start_time()? == start && fs::read_link("/proc/self/exe")? == executable,
            "self-restore process changed during authentication"
        );
        Ok(Facts {
            unit,
            hook_arrays,
            kernel,
            process_status: status,
            mounts,
            start,
            executable,
            executable_identity,
            lock_identity,
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture_for_owner_tests(lock: &'a File, unit: Value) -> Self {
        let b = Bound {
            path: "/not-a-production-spec".into(),
            sha256: "a".repeat(64),
        };
        let id = Identity::of(&lock.metadata().unwrap());
        Self {
            lock,
            spec: b.clone(),
            mapping: b.clone(),
            custody: b.clone(),
            admission: b,
            spec_value: Value::Null,
            custody_value: Value::Null,
            admission_value: Value::Null,
            pid: 4242,
            iid: "1".repeat(32),
            self_sha: "b".repeat(64),
            entry_clock: 0,
            started: Instant::now(),
            entered: AtomicBool::new(false),
            floor: AtomicU64::new(100),
            initial: Facts {
                unit,
                hook_arrays: json!({}),
                kernel: Value::Null,
                process_status: Value::Null,
                mounts: Value::Null,
                start: "fixture".into(),
                executable: "/fixture".into(),
                executable_identity: id.clone(),
                lock_identity: id,
            },
        }
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        ensure!(
            bound(&self.spec)? == self.spec_value
                && receipt_bound(&self.custody)? == self.custody_value
                && receipt_bound(&self.admission)? == self.admission_value,
            "self-restore immutable spec/custody/admission changed"
        );
        mapping_binding(&self.mapping)?;
        admission_scope_at(
            &self.admission_value,
            &self.custody,
            Artifact::Prefix213,
            self.entry_clock,
        )?;
        running_deadline(self.started.elapsed().as_secs())?;
        ensure!(
            Self::facts(self.lock, self.pid, &self.iid, &self.spec, &self.self_sha)?
                == self.initial,
            "self-restore actual identity/sandbox/kernel/flock changed"
        );
        Ok(())
    }
    pub(crate) fn entry_clock(&self) -> u64 {
        self.entry_clock
    }
    pub(crate) fn entered(&self) -> bool {
        self.entered.load(Ordering::Acquire)
    }
    pub(crate) fn protected_floor(&self) -> u64 {
        self.floor.load(Ordering::Acquire)
    }
    pub(crate) fn require_basis(&self, value: &Value) -> Result<()> {
        ensure!(
            *value == self.admission_value["resource_basis"],
            "typed continuation cannot replace its immutable admitted resource basis"
        );
        Ok(())
    }
    pub(super) fn complete_capacity_check(&self, minimum: u64) -> Result<()> {
        ensure!(minimum > 0, "invalid continuation protected floor");
        if !self.entered() {
            ensure!(
                minimum <= self.protected_floor(),
                "Foundation protected reserve increased before initial restoration entry"
            );
        }
        self.floor.fetch_max(minimum, Ordering::AcqRel);
        self.entered.store(true, Ordering::Release);
        Ok(())
    }
    pub(crate) fn match_row(&self, name: &str, row: &Value) -> Result<()> {
        ensure!(
            name == UNIT,
            "typed self-restoration cannot account for another maintenance owner"
        );
        for key in [
            "Id",
            "LoadState",
            "Type",
            "ActiveState",
            "SubState",
            "InvocationID",
            "NRestarts",
            "ControlGroup",
            "MainPID",
            "Result",
            "ExecMainStatus",
        ] {
            ensure!(
                row[key] == self.initial.unit[key],
                "tracked self-restore census identity changed:{key}"
            );
        }
        ensure!(
            crate::pipeline_status::same_exec_start(
                text(&self.initial.unit, "ExecStart")?,
                text(row, "ExecStart")?
            ),
            "tracked self-restore census command changed"
        );
        Ok(())
    }
    pub(crate) fn unit_name(&self) -> &'static str {
        UNIT
    }
    pub(crate) fn evidence(&self) -> Value {
        json!({"schema":"jetstreamer-foundation213-resumable-self-accounting-v1","unit":UNIT,"pid":self.pid,"invocation_id":self.iid,"self_sha256":self.self_sha,"spec":self.spec,"mapping":self.mapping,"custody":self.custody,"admission":self.admission,"unit_at_start":self.initial.unit,"typed_empty_hook_arrays":self.initial.hook_arrays,"kernel_controls":self.initial.kernel,"actual_process_privilege_status":self.initial.process_status,"actual_mount_scope":self.initial.mounts,"process_start_time":self.initial.start,"transition_flock_owned":true,"already_admitted_restore_only":true,"entry_recorded_unix_seconds":self.entry_clock,"entry_capacity_validated":self.entered(),"minimum_free_bytes":self.protected_floor(),"entry_age_gate_seconds":900,"maximum_execution_seconds":MAX_SECONDS,"freshness_policy":"fresh at entry; same bounded invocation and live protected guards/reserve thereafter","replay_competitor_comparison_only":true,"raw_censuses_preserved":true,"memory_credit_bytes":0,"disk_credit_bytes":0,"replay_launch_authorized":false,"retirement_authorized":false,"r2_mutations":false})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn empty_hooks() -> Value {
        Value::Object(
            HOOKS
                .into_iter()
                .map(|k| {
                    (
                        k.into(),
                        json!(include_str!(
                            "fixtures/foundation213-empty-hooks/empty-array-reply.txt"
                        )),
                    )
                })
                .collect(),
        )
    }
    #[test]
    fn retained_actual_manager_evidence_omits_hooks_but_typed_replies_are_empty() {
        let actual = property_object(include_bytes!(
            "fixtures/foundation213-empty-hooks/manager-show.txt"
        ))
        .unwrap();
        for name in HOOKS {
            assert!(actual.get(name).is_none(), "{name}");
        }
        validate_hook_arrays(&actual, &empty_hooks()).unwrap();
        assert_eq!(actual["InvocationID"], "dc6b1b8b8de44050a2b95c15c0b3602f");
        assert_eq!(actual["ExecMainStatus"], "1");
        // Authentic empty hooks cannot make a failed/terminal invocation live.
        let (_, spec, exe, limits) = fixture();
        let binding = Binding {
            pid: 803491,
            iid: "dc6b1b8b8de44050a2b95c15c0b3602f",
            exe: &exe,
            spec: &spec,
            self_sha: &"b".repeat(64),
        };
        assert!(validate_unit(&actual, &binding, limits, &empty_hooks()).is_err());
    }
    #[test]
    fn actual_omitted_show_hooks_require_every_exact_typed_empty_array() {
        let (mut show, spec, exe, limits) = fixture();
        for key in HOOKS {
            show.as_object_mut().unwrap().remove(key);
        }
        let original = show.clone();
        let raw = empty_hooks();
        let binding = Binding {
            pid: 4242,
            iid: &"1".repeat(32),
            exe: &exe,
            spec: &spec,
            self_sha: &"b".repeat(64),
        };
        validate_unit(&show, &binding, limits, &raw).unwrap();
        assert_eq!(show, original);
        for key in HOOKS {
            assert!(show.get(key).is_none());
            let mut missing = raw.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(validate_unit(&show, &binding, limits, &missing).is_err());
            for wrong in [
                json!("a(sasbttttuii) 1"),
                json!("as 0\n"),
                json!("a(sasbttttuii) 00\n"),
                json!("a(sasbttttuii) 0 extra\n"),
                json!(""),
                Value::Null,
                json!(false),
            ] {
                let mut changed = raw.clone();
                changed[key] = wrong;
                assert!(
                    validate_unit(&show, &binding, limits, &changed).is_err(),
                    "{key}"
                );
            }
            for wrong in [Value::Null, json!("/unbound/hook"), json!([])] {
                let mut changed = show.clone();
                changed[key] = wrong;
                assert!(
                    validate_unit(&changed, &binding, limits, &raw).is_err(),
                    "{key}"
                );
            }
        }
        let mut extra = raw.clone();
        extra["UnrequestedHook"] = json!("a(sasbttttuii) 0\n");
        assert!(validate_unit(&show, &binding, limits, &extra).is_err());
        // Only the five authenticated arrays can be absent from show.
        for key in [
            "Id",
            "LoadState",
            "Result",
            "ExecMainStatus",
            "Type",
            "User",
            "Group",
            "ActiveState",
            "SubState",
            "MainPID",
            "InvocationID",
            "NRestarts",
            "Restart",
            "KillMode",
            "Delegate",
            "ControlGroup",
            "MemoryMax",
            "MemoryHigh",
            "MemorySwapMax",
            "TasksMax",
            "NoNewPrivileges",
            "ProtectSystem",
            "ProtectHome",
            "ReadWritePaths",
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "RootDirectory",
            "RootImage",
            "OnSuccess",
            "OnFailure",
            "Triggers",
            "TriggeredBy",
            "ExecStart",
        ] {
            let mut changed = show.clone();
            changed.as_object_mut().unwrap().remove(key);
            assert!(
                validate_unit(&changed, &binding, limits, &raw).is_err(),
                "{key}"
            );
        }
    }
    fn fixture() -> (Value, Bound, PathBuf, ManagerLimits) {
        let b = Bound {
            path: "/var/lib/jetstreamer/exact-restore/restore-plan.json".into(),
            sha256: "a".repeat(64),
        };
        let exe = PathBuf::from("/var/lib/jetstreamer/exact-tools/jetstreamer-r2");
        let mut v = json!({"Id":UNIT,"LoadState":"loaded","Type":"oneshot","User":"root","Group":"root","ActiveState":"activating","SubState":"start","MainPID":"4242","InvocationID":"1".repeat(32),"NRestarts":"0","Restart":"no","KillMode":"control-group","Delegate":"no","ControlGroup":format!("/system.slice/{UNIT}"),"MemoryMax":MAX_MEMORY.to_string(),"MemoryHigh":"infinity","MemorySwapMax":"0","TasksMax":"256","NoNewPrivileges":"yes","ProtectSystem":"strict","ProtectHome":"read-only","ReadWritePaths":"/home/ubuntu/.jetstreamer-private","CapabilityBoundingSet":"cap_dac_override cap_dac_read_search cap_sys_ptrace","AmbientCapabilities":"cap_dac_override cap_dac_read_search cap_sys_ptrace","Result":"success","ExecMainStatus":"0"});
        for key in [
            "RootDirectory",
            "RootImage",
            "ExecStartPre",
            "ExecStartPost",
            "ExecCondition",
            "ExecStop",
            "ExecStopPost",
            "OnSuccess",
            "OnFailure",
            "Triggers",
            "TriggeredBy",
        ] {
            v[key] = json!("");
        }
        let command = command(&exe, &b, &"b".repeat(64));
        v["ExecStart"] = json!(format!(
            "{} ; start_time=[] ; stop_time=[] ; pid=4242 ; code=(null) ; status=0 }}",
            command.strip_suffix(" }").unwrap()
        ));
        (
            v,
            b,
            exe,
            ManagerLimits {
                timeout: MAX_SECONDS * 1_000_000,
                runtime: u64::MAX,
                quota: 1_000_000,
            },
        )
    }
    #[test]
    fn only_exact_live_self_command_pid_iid_and_reviewed_sandbox_are_eligible() {
        let (v, spec, exe, l) = fixture();
        let sha = "b".repeat(64);
        let iid = "1".repeat(32);
        let binding = Binding {
            pid: 4242,
            iid: &iid,
            exe: &exe,
            spec: &spec,
            self_sha: &sha,
        };
        validate_unit(&v, &binding, l, &empty_hooks()).unwrap();
        for (key, value) in [
            ("Id", json!("horizon-other-maintenance.service")),
            ("InvocationID", json!("2".repeat(32))),
            ("MainPID", json!("4243")),
            ("User", json!("ubuntu")),
            ("Group", json!("ubuntu")),
            ("NRestarts", json!("1")),
            ("Restart", json!("always")),
            ("KillMode", json!("process")),
            ("Delegate", json!("yes")),
            ("MemoryMax", json!((MAX_MEMORY + 1).to_string())),
            ("MemorySwapMax", json!("1")),
            ("TasksMax", json!("257")),
            ("NoNewPrivileges", json!("no")),
            ("ProtectSystem", json!("no")),
            ("ProtectHome", json!("no")),
            (
                "ReadWritePaths",
                json!("/home/ubuntu/.jetstreamer-private /home/ubuntu/horizon"),
            ),
            ("ExecStopPost", json!("/unbound/helper")),
            ("CapabilityBoundingSet", json!("cap_sys_admin")),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(
                validate_unit(&bad, &binding, l, &empty_hooks()).is_err(),
                "{key}"
            );
        }
        for from_to in [
            (ACTION, "holding-foundation213-maintain"),
            (spec.sha256.as_str(), "wrong-spec"),
            (sha.as_str(), "wrong-self"),
        ] {
            let mut bad = v.clone();
            bad["ExecStart"] = json!(text(&v, "ExecStart").unwrap().replace(from_to.0, from_to.1));
            assert!(validate_unit(&bad, &binding, l, &empty_hooks()).is_err());
        }
        for wrong in [
            ManagerLimits { timeout: 0, ..l },
            ManagerLimits {
                timeout: MAX_SECONDS * 1_000_000 + 1,
                ..l
            },
            ManagerLimits { quota: 0, ..l },
            ManagerLimits {
                quota: MAX_CPU + 1,
                ..l
            },
        ] {
            assert!(validate_unit(&v, &binding, wrong, &empty_hooks()).is_err());
        }
        let mut exec = v.clone();
        exec["Type"] = json!("exec");
        exec["ActiveState"] = json!("active");
        exec["SubState"] = json!("running");
        validate_unit(
            &exec,
            &binding,
            ManagerLimits {
                runtime: MAX_SECONDS * 1_000_000,
                ..l
            },
            &empty_hooks(),
        )
        .unwrap();
        assert!(validate_unit(&exec, &binding, l, &empty_hooks()).is_err());
    }
    #[test]
    fn real_kernel_rounding_cpu_ratio_and_whole_exact_process_membership_are_checked() {
        let (v, _, _, _) = fixture();
        let pids = [4242];
        let good = KernelValues {
            page: 4096,
            maximum: MAX_MEMORY,
            high: "max",
            swap: 0,
            tasks: 256,
            quota: 100000,
            period: 100000,
            requested_quota: 1_000_000,
            pids: &pids,
        };
        validate_kernel(&v, 4242, &good).unwrap();
        for bad in [
            KernelValues {
                maximum: MAX_MEMORY + 4096,
                ..good
            },
            KernelValues { high: "0", ..good },
            KernelValues { swap: 1, ..good },
            KernelValues { tasks: 257, ..good },
            KernelValues {
                quota: 100001,
                ..good
            },
            KernelValues { period: 0, ..good },
            KernelValues {
                pids: &[4242, 4243],
                ..good
            },
            KernelValues {
                pids: &[4243],
                ..good
            },
        ] {
            assert!(validate_kernel(&v, 4242, &bad).is_err());
        }
    }
    #[test]
    fn actual_mount_namespace_protects_public_and_sealed_paths_while_state_is_writable() {
        let mounts=b"1 0 0:1 / / ro - ext4 /dev/root ro\n2 1 0:1 /home /home ro - ext4 /dev/root ro\n3 2 0:1 /home/ubuntu/.jetstreamer-private /home/ubuntu/.jetstreamer-private rw - ext4 /dev/root rw\n";
        mount_scope(mounts).unwrap();
        let mut public = mounts.to_vec();
        public.extend_from_slice(
            b"4 2 0:1 /home/ubuntu/horizon /home/ubuntu/horizon rw - ext4 /dev/root rw\n",
        );
        assert!(mount_scope(&public).is_err());
        assert!(
            mount_scope(
                String::from_utf8(mounts.to_vec())
                    .unwrap()
                    .replace(".jetstreamer-private", ".jetstreamer-private-other")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(mount_scope(b"malformed mount line").is_err());
    }
    #[test]
    fn actual_root_uid_gid_no_new_privileges_and_capability_bounding_are_required() {
        let (v, _, _, _) = fixture();
        let status=b"Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nNoNewPrivs:\t1\nCapEff:\t0000000000080006\nCapPrm:\t0000000000080006\nCapBnd:\t0000000000080006\nCapAmb:\t0000000000080006\n";
        process_status(status, &v).unwrap();
        for (from, to) in [
            ("Uid:\t0", "Uid:\t1000"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ("CapEff:\t0000000000080006", "CapEff:\t0000000000280006"),
        ] {
            assert!(
                process_status(
                    String::from_utf8(status.to_vec())
                        .unwrap()
                        .replace(from, to)
                        .as_bytes(),
                    &v
                )
                .is_err()
            );
        }
    }
    #[test]
    fn actual_descriptor_flock_must_still_belong_to_the_same_pid_and_inode() {
        let file = tempfile::tempfile().unwrap();
        let pid = std::process::id();
        let m = file.metadata().unwrap();
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let fdinfo = PathBuf::from(format!("/proc/self/fdinfo/{}", file.as_raw_fd()));
        let bytes = fs::read(&fdinfo).unwrap();
        owned_flock(&bytes, pid, m.dev(), m.ino()).unwrap();
        assert!(owned_flock(&bytes, pid + 1, m.dev(), m.ino()).is_err());
        assert!(owned_flock(&bytes, pid, m.dev(), m.ino() + 1).is_err());
        assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
        assert!(owned_flock(&fs::read(fdinfo).unwrap(), pid, m.dev(), m.ino()).is_err());
    }
    #[test]
    fn only_entry_is_freshness_gated_and_the_original_service_deadline_is_never_renewed() {
        let b = Bound {
            path: "/fixture/custody.json".into(),
            sha256: "a".repeat(64),
        };
        let a = json!({"schema":"jetstreamer-foundation-holding-restore-admission-v1","host":review::HOST,"prefix":review::PREFIX,"artifact":"prefix213","custody":b,"restore_only":true,"local_retirement_authorized":false,"recorded_unix_seconds":100,"admissions_must_be_serialized_until_restore_complete":true,"metadata_budget":metadata_budget()});
        admission_scope_at(&a, &b, Artifact::Prefix213, 1000).unwrap();
        assert!(admission_scope_at(&a, &b, Artifact::Prefix213, 1001).is_err());
        let file = tempfile::tempfile().unwrap();
        let mut c = Context::fixture_for_owner_tests(&file, Value::Null);
        c.entry_clock = 1000;
        c.complete_capacity_check(100).unwrap();
        admission_scope_at(&a, &b, Artifact::Prefix213, c.entry_clock()).unwrap();
        // Much later wall-clock time is not supplied as a new entry timestamp.
        assert!(admission_scope_at(&a, &b, Artifact::Prefix213, 8200).is_err());
        assert_eq!(c.entry_clock(), 1000);
        running_deadline(MAX_SECONDS - 1).unwrap();
        assert!(running_deadline(MAX_SECONDS).is_err());
    }
    #[test]
    fn continuation_can_only_hold_or_raise_the_admitted_reserve() {
        let file = tempfile::tempfile().unwrap();
        let c = Context::fixture_for_owner_tests(&file, Value::Null);
        assert!(!c.entered());
        assert!(c.complete_capacity_check(101).is_err());
        assert!(!c.entered());
        c.complete_capacity_check(90).unwrap();
        assert!(c.entered());
        assert_eq!(c.protected_floor(), 100);
        c.complete_capacity_check(150).unwrap();
        c.complete_capacity_check(80).unwrap();
        assert_eq!(c.protected_floor(), 150);
        assert_eq!(c.entry_clock(), 0);
        assert!(c.require_basis(&json!({"replaced":true})).is_err());
    }
    #[test]
    fn tracked_census_row_is_identity_bound_and_test_context_cannot_pass_runtime_revalidation() {
        let (v, _, _, _) = fixture();
        let file = tempfile::tempfile().unwrap();
        let c = Context::fixture_for_owner_tests(&file, v.clone());
        c.match_row(UNIT, &v).unwrap();
        assert!(c.revalidate().is_err());
        for (key, value) in [
            ("InvocationID", json!("2".repeat(32))),
            ("MainPID", json!("4243")),
            ("ActiveState", json!("inactive")),
            ("ExecStart", json!("/another-command")),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(c.match_row(UNIT, &bad).is_err(), "{key}");
        }
        assert!(c.match_row("other.service", &v).is_err());
    }
}
