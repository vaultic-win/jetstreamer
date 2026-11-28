//! Isolated freezer/rescue qualification. Deliberately cannot target replay units.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const WRITER: &str = "horizon-qualify-allocation-fixture-writer944-v1.service";
const WORK: &str = "/home/ubuntu/.jetstreamer-private/allocation-freeze-fixture944-v1";
const CG: &str =
    "/sys/fs/cgroup/system.slice/horizon-qualify-allocation-fixture-writer944-v1.service";
const DATA_LEN: u64 = 8 << 20;
const FLOOR: u64 = 1_773_047_165_973;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    Normal,
    Kill,
    WrongInvocation,
    WrongCgroup,
    MissingRescue,
    ReusedCgroup,
    PendingKill,
    Deactivating,
    IntentKill,
}
impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Kill => "kill",
            Self::WrongInvocation => "wrong-invocation",
            Self::WrongCgroup => "wrong-cgroup",
            Self::MissingRescue => "missing-rescue",
            Self::ReusedCgroup => "reused-cgroup",
            Self::PendingKill => "pending-kill",
            Self::Deactivating => "deactivating",
            Self::IntentKill => "intent-kill",
        }
    }
    fn role(self, role: &str) -> String {
        format!(
            "horizon-allocation-fixture944-{}-{role}-v1.service",
            self.name()
        )
    }
    fn timer(self) -> String {
        self.role("rescue").replace(".service", ".timer")
    }
    fn state(self) -> PathBuf {
        format!(
            "/var/lib/jetstreamer/horizon-allocation-fixture944-{}-state-v1",
            self.name()
        )
        .into()
    }
}
fn require_freezing_case(mode: Mode) -> Result<()> {
    ensure!(
        matches!(
            mode,
            Mode::Normal | Mode::Kill | Mode::PendingKill | Mode::Deactivating | Mode::IntentKill
        ),
        "negative fixture unexpectedly passed its rejection gate; freezing prohibited"
    );
    Ok(())
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Writer {
    unit: String,
    invocation_id: String,
    pid: u32,
    start_ticks: u64,
    cgroup_device: u64,
    cgroup_inode: u64,
}
fn work_directory(iid: &str) -> Result<PathBuf> {
    ensure!(hex(iid, 32), "invalid fixture generation directory");
    Ok(Path::new(WORK).join(iid))
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mode: Mode,
    issued_unix_millis: u64,
    expires_unix_millis: u64,
    writer: Writer,
    replay_or_admission_authorized: bool,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    schema: String,
    plan_sha256: String,
    writer: Writer,
    driver_unit: String,
    driver_iid: String,
    driver_pid: u32,
    driver_start_ticks: u64,
    rescue_timer_iid: String,
}
fn validate_lease(s: &Spec, plan: &str, lease: &Lease) -> Result<()> {
    ensure!(
        lease.schema == "horizon-allocation-fixture-freeze-lease-v1"
            && lease.plan_sha256 == plan
            && lease.writer == s.writer
            && lease.driver_unit == s.mode.role("driver")
            && hex(&lease.driver_iid, 32)
            && hex(&lease.rescue_timer_iid, 32)
            && lease.driver_pid > 1
            && lease.driver_start_ticks > 0,
        "foreign freeze lease"
    );
    Ok(())
}
// This control covers death after durable intent but before the first request.
// It deliberately makes no requested=1/frozen=0-at-cancel claim. Check its
// expected observation only AFTER unconditional cancellation and thaw so a
// failed control cannot prevent the independent rescue from doing its job.
fn qualify_pre_request_observation(
    mode: Mode,
    requested: bool,
    frozen: bool,
    owner: RescueOwner,
) -> Result<()> {
    ensure!(
        mode != Mode::IntentKill || (!requested && !frozen && owner == RescueOwner::Running),
        "intent-kill did not observe the pre-request crash window"
    );
    Ok(())
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn log(phase: &str) {
    println!(
        "{}",
        json!({"at_unix_millis":now().ok(),"phase":phase,"pid":std::process::id(),"fixture_only":true})
    );
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}
fn digest(mut f: impl Read) -> Result<String> {
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn ticks(pid: u32) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s[s.rfind(')').context("proc stat delimiter")? + 2..]
        .split_whitespace()
        .nth(19)
        .context("start ticks")?
        .parse()?)
}
fn read_small(path: &Path, uid: u32) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "aliased input"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let a = f.metadata()?;
    ensure!(
        a.is_file()
            && a.uid() == uid
            && a.nlink() == 1
            && a.mode() & 0o022 == 0
            && a.len() <= 262144,
        "unsafe small input"
    );
    let mut b = Vec::new();
    (&mut f).take(262145).read_to_end(&mut b)?;
    let z = f.metadata()?;
    ensure!(
        a.dev() == z.dev()
            && a.ino() == z.ino()
            && a.len() == z.len()
            && a.mode() == z.mode()
            && a.mtime_nsec() == z.mtime_nsec()
            && a.mtime() == z.mtime()
            && a.ctime() == z.ctime()
            && a.ctime_nsec() == z.ctime_nsec()
            && b.len() as u64 == a.len(),
        "small input changed"
    );
    Ok(b)
}
fn save(state: &Path, name: &str, d: &impl Serialize) -> Result<()> {
    let m = fs::symlink_metadata(state)?;
    ensure!(
        state.canonicalize()? == state
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700,
        "unsafe private state"
    );
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state.join(name))?;
    f.write_all(&serde_json::to_vec_pretty(d)?)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(state)?.sync_all()?;
    Ok(())
}
fn validate(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == "horizon-allocation-freezer-fixture-plan-v1"
            && !s.replay_or_admission_authorized,
        "fixture scope only"
    );
    ensure!(
        s.writer.unit == WRITER
            && hex(&s.writer.invocation_id, 32)
            && s.writer.pid > 1
            && s.writer.start_ticks > 0
            && s.writer.cgroup_device > 0
            && s.writer.cgroup_inode > 0,
        "foreign fixture owner"
    );
    ensure!(
        s.expires_unix_millis > s.issued_unix_millis
            && s.expires_unix_millis - s.issued_unix_millis <= 300000,
        "unbounded fixture plan"
    );
    Ok(())
}
fn parse_scalars(s: &str) -> Result<BTreeMap<String, String>> {
    let mut d = BTreeMap::new();
    for line in s.lines() {
        let (k, v) = line.split_once('=').context("malformed scalar")?;
        ensure!(
            !k.is_empty() && d.insert(k.to_owned(), v.to_owned()).is_none(),
            "duplicate scalar"
        );
    }
    Ok(d)
}
fn command(program: &str, args: &[&str]) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("bounded metadata command expired");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let o = child.wait_with_output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 262144 && o.stderr.len() < 262144,
        "metadata command failed"
    );
    Ok(String::from_utf8(o.stdout)?)
}
fn show(unit: &str) -> Result<BTreeMap<String, String>> {
    parse_scalars(&command(
        "/usr/bin/systemctl",
        &[
            "show",
            unit,
            "--property=Id,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,ControlGroup,Job,MemoryMax,MemorySwapMax,Result",
        ],
    )?)
}
fn validate_manager(w: &Writer, d: &BTreeMap<String, String>) -> Result<()> {
    validate_manager_identity(w, d)?;
    for (key, value) in [
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("Job", ""),
    ] {
        ensure!(
            d.get(key).is_some_and(|v| v == value),
            "fixture manager mismatch:{key}"
        );
    }
    Ok(())
}
fn validate_manager_identity(w: &Writer, d: &BTreeMap<String, String>) -> Result<()> {
    for (k, v) in [
        ("Id", w.unit.clone()),
        ("InvocationID", w.invocation_id.clone()),
        ("MainPID", w.pid.to_string()),
        ("ControlPID", "0".into()),
        ("NRestarts", "0".into()),
        (
            "ControlGroup",
            CG.strip_prefix("/sys/fs/cgroup").unwrap().into(),
        ),
        ("MemoryMax", "536870912".into()),
        ("MemorySwapMax", "0".into()),
    ] {
        ensure!(d.get(k) == Some(&v), "fixture manager mismatch:{k}");
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum RescueOwner {
    Running,
    Deactivating,
    Terminal,
}
fn rescue_owner(w: &Writer, d: &BTreeMap<String, String>) -> Result<RescueOwner> {
    if d.get("ActiveState").is_some_and(|v| v == "inactive") {
        for (key, value) in [
            ("Id", WRITER),
            ("SubState", "dead"),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("NRestarts", "0"),
            ("Job", ""),
            ("ControlGroup", ""),
            ("MemoryMax", "536870912"),
            ("MemorySwapMax", "0"),
            ("Result", "success"),
        ] {
            ensure!(
                d.get(key).is_some_and(|v| v == value),
                "terminal fixture mismatch:{key}"
            );
        }
        ensure!(
            d.get("InvocationID")
                .is_some_and(|v| v.is_empty() || v == &w.invocation_id),
            "terminal fixture invocation replaced"
        );
        return Ok(RescueOwner::Terminal);
    }
    validate_manager_identity(w, d)?;
    if d.get("ActiveState").is_some_and(|v| v == "active") {
        validate_manager(w, d)?;
        return Ok(RescueOwner::Running);
    }
    ensure!(
        d.get("ActiveState").is_some_and(|v| v == "deactivating")
            && d.get("SubState")
                .is_some_and(|v| ["stop-sigterm", "stop-sigkill"].contains(&v.as_str()))
            && d.get("Job")
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|v| v > 0),
        "unqualified fixture shutdown state"
    );
    Ok(RescueOwner::Deactivating)
}
fn verify_writer(w: &Writer) -> Result<()> {
    validate_manager(w, &show(WRITER)?)?;
    verify_writer_process(w)
}
fn verify_writer_process(w: &Writer) -> Result<()> {
    ensure!(ticks(w.pid)? == w.start_ticks, "fixture PID replaced");
    ensure!(
        fs::read_to_string(format!("/proc/{}/cgroup", w.pid))?
            == format!("0::{}\n", CG.strip_prefix("/sys/fs/cgroup").unwrap()),
        "fixture PID escaped bound cgroup"
    );
    let exe = fs::read_link(format!("/proc/{}/exe", w.pid))?;
    ensure!(
        exe == fs::read_link("/proc/self/exe")?,
        "fixture executable differs"
    );
    let m = fs::symlink_metadata(CG)?;
    ensure!(
        m.is_dir()
            && m.dev() == w.cgroup_device
            && m.ino() == w.cgroup_inode
            && Path::new(CG).canonicalize()? == Path::new(CG),
        "fixture cgroup replaced"
    );
    let ready: serde_json::Value = serde_json::from_slice(&read_small(
        &work_directory(&w.invocation_id)?.join("ready.json"),
        1000,
    )?)?;
    ensure!(
        ready["pid"] == w.pid
            && ready["start_ticks"] == w.start_ticks
            && ready["invocation_id"] == w.invocation_id,
        "fixture readiness not bound"
    );
    Ok(())
}
fn own_role(unit: &str) -> Result<String> {
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(hex(&iid, 32), "missing genuine own invocation");
    ensure!(
        fs::read_to_string("/proc/self/cgroup")? == format!("0::/system.slice/{unit}\n"),
        "wrong own native scope"
    );
    let native = show(unit)?;
    let pid = std::process::id().to_string();
    ensure!(
        native.get("InvocationID") == Some(&iid)
            && ["MainPID", "ControlPID"]
                .iter()
                .any(|key| native.get(*key) == Some(&pid)),
        "own invocation environment does not match manager PID/IID"
    );
    Ok(iid)
}
fn bus_path(unit: &str) -> String {
    let mut s = String::from("/org/freedesktop/systemd1/unit/");
    for b in unit.bytes() {
        if b.is_ascii_alphanumeric() {
            s.push(char::from(b));
        } else {
            s.push_str(&format!("_{b:02x}"));
        }
    }
    s
}
fn validate_rescue_command(value: &serde_json::Value, expected: &[String]) -> Result<()> {
    ensure!(
        value["type"] == "a(sasbttttuii)",
        "unexpected ExecStart D-Bus type"
    );
    let rows = value["data"]
        .as_array()
        .context("missing ExecStart array")?;
    ensure!(rows.len() == 1, "rescue needs exactly one command");
    let row = rows[0].as_array().context("invalid ExecStart tuple")?;
    ensure!(
        row.len() == 10 && !expected.is_empty(),
        "invalid ExecStart shape"
    );
    ensure!(
        row[0] == expected[0] && row[1] == json!(expected) && row[2] == false,
        "rescue executable, argv or ignore-errors differs"
    );
    Ok(())
}
fn timer(mode: Mode, expected_rescue: &[String]) -> Result<String> {
    let service = mode.role("rescue");
    let owner = parse_scalars(&command(
        "/usr/bin/systemctl",
        &[
            "show",
            &service,
            "--property=ActiveState,SubState,MainPID,ControlPID,NRestarts,Job,Type,Restart,User,MemoryMax,MemorySwapMax",
        ],
    )?)?;
    for (key, expected) in [
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("Job", ""),
        ("Type", "oneshot"),
        ("Restart", "no"),
        ("User", "root"),
        ("MemoryMax", "134217728"),
        ("MemorySwapMax", "0"),
    ] {
        ensure!(
            owner.get(key).is_some_and(|v| v == expected),
            "rescue native policy mismatch:{key}"
        );
    }
    let raw = command(
        "/usr/bin/busctl",
        &[
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            &bus_path(&service),
            "org.freedesktop.systemd1.Service",
            "ExecStart",
        ],
    )?;
    validate_rescue_command(&serde_json::from_str(&raw)?, expected_rescue)?;
    let timeout = command(
        "/usr/bin/busctl",
        &[
            "--system",
            "get-property",
            "org.freedesktop.systemd1",
            &bus_path(&service),
            "org.freedesktop.systemd1.Service",
            "TimeoutStartUSec",
        ],
    )?;
    ensure!(
        timeout.trim() == "t 15000000",
        "rescue execution bound differs"
    );
    let name = mode.timer();
    let d = parse_scalars(&command(
        "/usr/bin/systemctl",
        &[
            "show",
            &name,
            "--property=ActiveState,SubState,InvocationID,Unit",
        ],
    )?)?;
    ensure!(
        d.get("ActiveState").is_some_and(|v| v == "active")
            && d.get("SubState").is_some_and(|v| v == "waiting")
            && d.get("Unit") == Some(&mode.role("rescue")),
        "independent rescue not armed"
    );
    let iid = d.get("InvocationID").context("timer iid")?.clone();
    ensure!(hex(&iid, 32), "invalid rescue timer iid");
    let path = bus_path(&name);
    let raw = command(
        "/usr/bin/busctl",
        &[
            "--system",
            "get-property",
            "org.freedesktop.systemd1",
            &path,
            "org.freedesktop.systemd1.Timer",
            "NextElapseUSecMonotonic",
        ],
    )?;
    let parts: Vec<_> = raw.split_whitespace().collect();
    ensure!(
        parts.len() == 2 && parts[0] == "t",
        "wrong typed timer deadline"
    );
    let due: u64 = parts[1].parse()?;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0,
        "monotonic clock"
    );
    let current = ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1000;
    ensure!(
        due >= current + 3_000_000 && due <= current + 12_000_000,
        "rescue window insufficient or unbounded"
    );
    Ok(iid)
}
struct Frozen {
    dir: File,
    active: bool,
}
impl Frozen {
    fn new(w: &Writer) -> Result<Self> {
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(CG)?;
        let m = dir.metadata()?;
        ensure!(
            m.dev() == w.cgroup_device && m.ino() == w.cgroup_inode,
            "cgroup descriptor differs"
        );
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::fstatfs(dir.as_raw_fd(), &mut filesystem) } == 0
                && filesystem.f_type == 0x63677270,
            "fixture cgroup must use actual cgroup v2 filesystem"
        );
        Ok(Self { dir, active: false })
    }
    fn file(&self, name: &str, write: bool) -> Result<File> {
        ensure!(
            ["cgroup.freeze", "cgroup.events", "cpu.stat"].contains(&name)
                && (!write || name == "cgroup.freeze"),
            "unknown cgroup interface"
        );
        let name = std::ffi::CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                (if write {
                    libc::O_WRONLY
                } else {
                    libc::O_RDONLY
                }) | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW,
            )
        };
        ensure!(
            fd >= 0,
            "cgroup interface open:{}",
            std::io::Error::last_os_error()
        );
        Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) })
    }
    fn frozen(&self) -> Result<bool> {
        let mut text = String::new();
        self.file("cgroup.events", false)?
            .take(4096)
            .read_to_string(&mut text)?;
        let rows: Vec<_> = text
            .lines()
            .filter_map(|l| l.strip_prefix("frozen "))
            .collect();
        ensure!(
            rows.len() == 1 && ["0", "1"].contains(&rows[0]),
            "invalid frozen interface"
        );
        Ok(rows[0] == "1")
    }
    fn set(&mut self, freeze: bool) -> Result<()> {
        self.request(freeze)?;
        self.wait(freeze)
    }
    fn request(&mut self, freeze: bool) -> Result<()> {
        // Set the RAII obligation before a freeze write can succeed.
        if freeze {
            self.active = true;
        }
        self.file("cgroup.freeze", true)?
            .write_all(if freeze { b"1" } else { b"0" })?;
        Ok(())
    }
    fn requested(&self) -> Result<bool> {
        let mut value = String::new();
        self.file("cgroup.freeze", false)?
            .take(4097)
            .read_to_string(&mut value)?;
        ensure!(
            value.len() <= 4096 && ["0", "1"].contains(&value.trim()),
            "invalid freeze request"
        );
        Ok(value.trim() == "1")
    }
    fn recent_throttle(&self) -> Result<()> {
        let read = || -> Result<u64> {
            let mut text = String::new();
            self.file("cpu.stat", false)?
                .take(4097)
                .read_to_string(&mut text)?;
            ensure!(text.len() <= 4096, "fixture cpu.stat bound");
            let mut found = None;
            for line in text.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                ensure!(fields.len() == 2, "invalid cpu.stat row");
                let value: u64 = fields[1].parse()?;
                if fields[0] == "nr_throttled" {
                    ensure!(found.replace(value).is_none(), "duplicate throttle counter");
                }
            }
            found.context("missing throttle counter")
        };
        let first = read()?;
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            let value = read()?;
            ensure!(value >= first, "fixture throttle counter reset");
            if value > first {
                return Ok(());
            }
            ensure!(Instant::now() < end, "fixture throttle witness expired");
            thread::sleep(Duration::from_millis(1));
        }
    }
    fn wait(&mut self, freeze: bool) -> Result<()> {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            if self.frozen()? == freeze {
                if !freeze {
                    self.active = false;
                }
                return Ok(());
            }
            ensure!(Instant::now() < end, "frozen transition expired");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Frozen {
    fn drop(&mut self) {
        if self.active {
            if let Err(e) = self.set(false) {
                eprintln!(
                    "RAII thaw failed; independently armed rescue remains responsible: {e:#}"
                );
            }
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Extent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved: [u32; 3],
}
#[repr(C)]
struct Fiemap {
    start: u64,
    length: u64,
    flags: u32,
    mapped: u32,
    count: u32,
    reserved: u32,
    extents: [Extent; 128],
}
fn extent_bytes(extents: &[Extent], size: u64) -> Result<u64> {
    let mut ranges = Vec::new();
    let mut logical = 0;
    for e in extents {
        ensure!(
            e.length > 0 && e.physical > 0 && e.flags & !(1 | 0x800) == 0 && e.logical >= logical,
            "unsupported/unstable FIEMAP extent"
        );
        logical = e
            .logical
            .checked_add(e.length)
            .context("logical overflow")?;
        ensure!(logical <= size, "extent beyond fixture");
        let end = e
            .physical
            .checked_add(e.length)
            .context("physical overflow")?;
        ensure!(
            e.physical % 4096 == 0 && e.length % 4096 == 0,
            "unaligned fixture extent"
        );
        ranges.push((e.physical, end));
    }
    ranges.sort_unstable();
    let mut end = 0;
    let mut bytes = 0u64;
    for (a, b) in ranges {
        ensure!(a >= end, "shared/overlapping physical extents");
        bytes = bytes.checked_add(b - a).context("allocated overflow")?;
        end = b;
    }
    Ok(bytes)
}
fn allocation_fixture(w: &Writer) -> Result<u64> {
    let path = work_directory(&w.invocation_id)?.join("data");
    ensure!(path.canonicalize()? == path, "fixture file alias");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 1000 && m.nlink() == 1 && m.len() == DATA_LEN,
        "fixture file identity"
    );
    let mut fsinfo: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(f.as_raw_fd(), &mut fsinfo) } == 0 && fsinfo.f_type == 0xef53,
        "fixture requires actual ext4"
    );
    let mut map = Fiemap {
        start: 0,
        length: DATA_LEN,
        flags: 0,
        mapped: 0,
        count: 128,
        reserved: 0,
        extents: [Extent::default(); 128],
    };
    ensure!(
        unsafe { libc::ioctl(f.as_raw_fd(), 0xc020660b_u64, &mut map) } == 0,
        "FIEMAP failed:{}",
        std::io::Error::last_os_error()
    );
    ensure!(
        map.mapped > 0 && map.mapped <= 128 && map.extents[map.mapped as usize - 1].flags & 1 == 1,
        "incomplete bounded fixture FIEMAP"
    );
    let bytes = extent_bytes(&map.extents[..map.mapped as usize], DATA_LEN)?;
    let z = f.metadata()?;
    ensure!(
        m.dev() == z.dev()
            && m.ino() == z.ino()
            && m.len() == z.len()
            && m.blocks() == z.blocks()
            && m.mtime() == z.mtime()
            && m.mtime_nsec() == z.mtime_nsec()
            && m.ctime() == z.ctime()
            && m.ctime_nsec() == z.ctime_nsec(),
        "fixture allocation changed"
    );
    ensure!(bytes == DATA_LEN, "fixture allocation incomplete");
    Ok(bytes)
}
fn counter(w: &Writer) -> Result<u64> {
    let b = read_small(&work_directory(&w.invocation_id)?.join("counter"), 1000)?;
    ensure!(b.len() == 8, "counter size");
    Ok(u64::from_le_bytes(b.try_into().unwrap()))
}
fn resumed(w: &Writer, before: u64) -> Result<u64> {
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        let n = counter(w)?;
        if n > before {
            return Ok(n);
        }
        ensure!(Instant::now() < end, "writer did not resume");
        thread::sleep(Duration::from_millis(20));
    }
}
fn drive(s: &Spec, plan: &str, spec_path: &str, self_sha: &str) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "driver requires Root");
    let own = own_role(&s.mode.role("driver"))?;
    verify_writer(&s.writer)?;
    let expected = vec![
        fs::read_link("/proc/self/exe")?
            .into_os_string()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF-8 executable"))?,
        "rescue".into(),
        spec_path.into(),
        "--spec-sha256".into(),
        plan.into(),
        "--self-sha256".into(),
        self_sha.into(),
        "--fixture-only".into(),
    ];
    let rescue = timer(s.mode, &expected)?;
    // Native rejection controls must fail at their specific earlier gate.
    // Even a regression accepting a bad binding cannot freeze in those modes.
    require_freezing_case(s.mode)?;
    let mut freeze = Frozen::new(&s.writer)?;
    ensure!(!freeze.frozen()?, "fixture already frozen");
    let lease = Lease {
        schema: "horizon-allocation-fixture-freeze-lease-v1".into(),
        plan_sha256: plan.into(),
        writer: s.writer.clone(),
        driver_unit: s.mode.role("driver"),
        driver_iid: own,
        driver_pid: std::process::id(),
        driver_start_ticks: ticks(std::process::id())?,
        rescue_timer_iid: rescue,
    };
    save(&s.mode.state(), "freeze-intent.json", &lease)?;
    log("freeze-intent-durable-rescue-armed");
    // Arming and validating rescue performs manager calls. Reauthenticate the
    // original writer after that work and before any controlled crash/freeze.
    verify_writer(&s.writer)?;
    if s.mode == Mode::IntentKill {
        let requested = freeze.requested()?;
        let frozen = freeze.frozen()?;
        qualify_pre_request_observation(s.mode, requested, frozen, RescueOwner::Running)?;
        save(
            &s.mode.state(),
            "pre-request-driver-death.json",
            &json!({"schema":"horizon-allocation-fixture-pre-request-death-v1","plan_sha256":plan,"writer":s.writer,"driver_unit":lease.driver_unit,"driver_iid":lease.driver_iid,"driver_pid":lease.driver_pid,"driver_start_ticks":lease.driver_start_ticks,"requested":requested,"frozen":frozen,"freeze_one_written":false,"live_replay_or_admission_authorized":false}),
        )?;
        log("deliberate-fixture-driver-SIGKILL-after-intent-before-freeze-request");
        ensure!(unsafe { libc::raise(libc::SIGKILL) } == 0, "raise SIGKILL");
        bail!("SIGKILL unexpectedly returned");
    }
    if s.mode == Mode::Deactivating {
        command("/usr/bin/systemctl", &["stop", "--no-block", WRITER])?;
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            if rescue_owner(&s.writer, &show(WRITER)?)? == RescueOwner::Deactivating {
                break;
            }
            ensure!(Instant::now() < end, "fixture did not enter shutdown");
            thread::sleep(Duration::from_millis(5));
        }
        verify_writer_process(&s.writer)?;
    }
    if s.mode == Mode::PendingKill {
        freeze.recent_throttle()?;
        freeze.request(true)?;
        let pending = !freeze.frozen()?;
        save(
            &s.mode.state(),
            "pending-freeze.json",
            &json!({"writer":s.writer,"requested":freeze.requested()?,"pending_observed":pending}),
        )?;
        ensure!(
            pending,
            "pending freeze not observed; control is unqualified"
        );
        log("deliberate-fixture-driver-SIGKILL-before-freeze-completion");
        ensure!(unsafe { libc::raise(libc::SIGKILL) } == 0, "raise SIGKILL");
        bail!("SIGKILL unexpectedly returned");
    }
    freeze.set(true)?;
    if s.mode == Mode::Deactivating {
        ensure!(
            rescue_owner(&s.writer, &show(WRITER)?)? == RescueOwner::Deactivating,
            "shutdown identity changed before freeze"
        );
        verify_writer_process(&s.writer)?;
    } else {
        verify_writer(&s.writer)?;
    }
    log("fixture-frozen");
    if matches!(s.mode, Mode::Kill | Mode::Deactivating) {
        log("deliberate-fixture-driver-SIGKILL");
        ensure!(unsafe { libc::raise(libc::SIGKILL) } == 0, "raise SIGKILL");
        bail!("SIGKILL unexpectedly returned");
    }
    let before = counter(&s.writer)?;
    thread::sleep(Duration::from_millis(200));
    ensure!(
        counter(&s.writer)? == before && freeze.frozen()?,
        "writer advanced during frozen capture"
    );
    let bytes = allocation_fixture(&s.writer)?;
    verify_writer(&s.writer)?;
    ensure!(freeze.frozen()?, "freeze changed before capture complete");
    freeze.set(false)?;
    let after = resumed(&s.writer, before)?;
    verify_writer(&s.writer)?;
    save(
        &s.mode.state(),
        "driver-completion.json",
        &json!({"schema":"horizon-allocation-fixture-driver-completion-v1","plan_sha256":plan,"writer":s.writer,"counter_frozen":before,"counter_resumed":after,"fiemap_unique_data_bytes":bytes,"thawed":true,"live_replay_or_admission_authorized":false}),
    )?;
    log("frozen-capture-thaw-resume-complete");
    Ok(())
}
fn rescue(s: &Spec, plan: &str) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "rescue requires Root");
    own_role(&s.mode.role("rescue"))?;
    let lease: Lease =
        serde_json::from_slice(&read_small(&s.mode.state().join("freeze-intent.json"), 0)?)?;
    validate_lease(s, plan, &lease)?;
    if rescue_owner(&s.writer, &show(WRITER)?)? == RescueOwner::Terminal {
        ensure!(
            !Path::new(CG).try_exists()?,
            "terminal original cgroup still present/reused"
        );
        save(
            &s.mode.state(),
            "rescue-completion.json",
            &json!({
                "schema":"horizon-allocation-fixture-rescue-completion-v1", "plan_sha256":plan,
                "writer":s.writer,"owner_before":RescueOwner::Terminal,"already_closed":true,
                "thaw_zero_written":false,"thawed":true,"live_replay_or_admission_authorized":false
            }),
        )?;
        ensure!(
            s.mode != Mode::IntentKill,
            "intent-kill writer closed before independent pre-request cancellation"
        );
        return Ok(());
    }
    let mut freeze = Frozen::new(&s.writer)?;
    verify_writer_process(&s.writer)?;
    let owner_before = rescue_owner(&s.writer, &show(WRITER)?)?;
    ensure!(
        owner_before != RescueOwner::Terminal,
        "original fixture already ended"
    );
    let was = freeze.frozen()?;
    let requested = freeze.requested()?;
    let before = counter(&s.writer)?;
    // A durable original lease owns cancellation even when frozen=0: the
    // kernel may still be processing a requested freeze. Always write zero.
    freeze.active = true;
    log("independent-rescue-cancel-original-freeze");
    freeze.request(false)?;
    if let Err(error) = freeze.wait(false) {
        if rescue_owner(&s.writer, &show(WRITER)?)? != RescueOwner::Terminal
            || Path::new(CG).try_exists()?
        {
            return Err(error);
        }
        freeze.active = false;
    }
    let after = if owner_before == RescueOwner::Running {
        let after = resumed(&s.writer, before)?;
        verify_writer(&s.writer)?;
        after
    } else {
        let owner_after = rescue_owner(&s.writer, &show(WRITER)?)?;
        ensure!(
            matches!(
                owner_after,
                RescueOwner::Deactivating | RescueOwner::Terminal
            ),
            "fixture shutdown was replaced or cancelled"
        );
        counter(&s.writer)?
    };
    let thawed = match freeze.frozen() {
        Ok(frozen) => !frozen,
        Err(error) => {
            if rescue_owner(&s.writer, &show(WRITER)?)? != RescueOwner::Terminal
                || Path::new(CG).try_exists()?
            {
                return Err(error);
            }
            true
        }
    };
    save(
        &s.mode.state(),
        "rescue-completion.json",
        &json!({"schema":"horizon-allocation-fixture-rescue-completion-v1","plan_sha256":plan,"writer":s.writer,"owner_before":owner_before,"was_requested":requested,"was_frozen":was,"counter_before":before,"counter_after":after,"thaw_zero_written":true,"thawed":thawed,"pre_request_control":s.mode==Mode::IntentKill,"pre_request_observation_qualified":s.mode==Mode::IntentKill&&!requested&&!was&&owner_before==RescueOwner::Running,"strict_pending_at_cancel_qualified":false,"live_replay_or_admission_authorized":false}),
    )?;
    qualify_pre_request_observation(s.mode, requested, was, owner_before)?;
    log("independent-rescue-complete");
    Ok(())
}
fn writer() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1000,
        "fixture writer requires Ubuntu UID1000"
    );
    let iid = own_role(WRITER)?;
    let base = Path::new(WORK);
    let m = fs::symlink_metadata(base)?;
    ensure!(
        base.canonicalize()? == base && m.is_dir() && m.uid() == 1000 && m.mode() & 0o777 == 0o700,
        "unsafe fixture root"
    );
    let root = work_directory(&iid)?;
    // A new real invocation has its own no-clobber data generation. This lets
    // native tests recreate the cgroup without overwriting the original input.
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    File::open(base)?.sync_all()?;
    let mut fsinfo: libc::statvfs = unsafe { std::mem::zeroed() };
    let c = std::ffi::CString::new(WORK)?;
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), &mut fsinfo) } == 0
            && fsinfo.f_bavail.saturating_mul(fsinfo.f_frsize) >= FLOOR + DATA_LEN,
        "fixture free-space gate"
    );
    let path = root.join("data");
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let block = [0u8; 65536];
    for _ in 0..DATA_LEN / 65536 {
        f.write_all(&block)?;
    }
    f.sync_all()?;
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            DATA_LEN as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            f.as_raw_fd(),
            0,
        )
    };
    ensure!(map != libc::MAP_FAILED, "fixture mmap");
    fs::write(root.join("counter"), 0u64.to_le_bytes())?;
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = fixture_term as *const () as usize;
    action.sa_flags = libc::SA_RESTART;
    ensure!(
        unsafe { libc::sigemptyset(&mut action.sa_mask) } == 0
            && unsafe { libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) } == 0,
        "fixture SIGTERM handler"
    );
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut busy = Vec::new();
    for _ in 0..32 {
        let done = done.clone();
        busy.push(thread::spawn(move || {
            let mut value = 1u64;
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                for _ in 0..1000 {
                    value = std::hint::black_box(value.wrapping_mul(3).wrapping_add(1));
                }
            }
        }));
    }
    let mut ready = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("ready.json"))?;
    ready.write_all(&serde_json::to_vec(&json!({"unit":WRITER,"invocation_id":iid,"pid":std::process::id(),"start_ticks":ticks(std::process::id())?}))?)?;
    ready.sync_all()?;
    File::open(&root)?.sync_all()?;
    log("fixture-writer-ready");
    let deadline = Instant::now() + Duration::from_secs(150);
    let mut stopping = None;
    let mut n = 0u64;
    while Instant::now() < deadline {
        if FIXTURE_TERM.load(std::sync::atomic::Ordering::Relaxed) {
            let since = stopping.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_secs(20) {
                break;
            }
        }
        n += 1;
        unsafe { (map as *mut u8).write_volatile(n as u8) };
        let mut c = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(root.join("counter-next"))?;
        c.write_all(&n.to_le_bytes())?;
        c.sync_all()?;
        fs::rename(root.join("counter-next"), root.join("counter"))?;
        thread::sleep(Duration::from_millis(20));
    }
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    for handle in busy {
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("fixture busy thread panicked"))?;
    }
    ensure!(
        unsafe { libc::munmap(map, DATA_LEN as usize) } == 0,
        "fixture munmap"
    );
    log("fixture-writer-bound-complete");
    Ok(())
}
static FIXTURE_TERM: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn fixture_term(_: libc::c_int) {
    FIXTURE_TERM.store(true, std::sync::atomic::Ordering::Relaxed);
}
fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let is_writer = a.len() == 3 && a[0] == "writer" && a[1] == "--self-sha256";
    let control = a.len() == 7
        && ["drive", "rescue"].contains(&a[0].as_str())
        && a[2] == "--spec-sha256"
        && a[4] == "--self-sha256"
        && a[6] == "--fixture-only";
    ensure!(
        is_writer || control,
        "usage: writer --self-sha256 SHA | drive/rescue SPEC --spec-sha256 SHA --self-sha256 SHA --fixture-only"
    );
    let expected = if is_writer { &a[2] } else { &a[5] };
    ensure!(hex(expected, 64), "self digest shape");
    let exe = File::open("/proc/self/exe")?;
    let m = exe.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "unsealed fixture executable"
    );
    ensure!(digest(exe)? == *expected, "self digest mismatch");
    if is_writer {
        return writer();
    }
    ensure!(
        unsafe { libc::geteuid() } == 0 && hex(&a[3], 64),
        "Root controller/spec digest required"
    );
    let b = read_small(Path::new(&a[1]), 0)?;
    ensure!(digest(b.as_slice())? == a[3], "spec digest mismatch");
    let s: Spec = serde_json::from_slice(&b)?;
    validate(&s)?;
    let t = now()?;
    ensure!(
        t >= s.issued_unix_millis && t < s.expires_unix_millis,
        "fixture spec expired/not yet valid"
    );
    if a[0] == "drive" {
        drive(&s, &a[3], &a[1], &a[5])
    } else {
        rescue(&s, &a[3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negative_controls_cannot_reach_a_freeze_write() {
        for mode in [
            Mode::WrongInvocation,
            Mode::WrongCgroup,
            Mode::MissingRescue,
            Mode::ReusedCgroup,
        ] {
            assert!(require_freezing_case(mode).is_err());
            assert_ne!(mode.state(), Mode::Normal.state());
            assert_ne!(mode.state(), Mode::Kill.state());
            assert!(
                mode.role("driver")
                    .starts_with("horizon-allocation-fixture944-")
            );
        }
        require_freezing_case(Mode::Normal).unwrap();
        require_freezing_case(Mode::Kill).unwrap();
        require_freezing_case(Mode::PendingKill).unwrap();
        require_freezing_case(Mode::Deactivating).unwrap();
        require_freezing_case(Mode::IntentKill).unwrap();
    }
    fn spec() -> Spec {
        Spec {
            schema: "horizon-allocation-freezer-fixture-plan-v1".into(),
            mode: Mode::Normal,
            issued_unix_millis: 1,
            expires_unix_millis: 300001,
            writer: Writer {
                unit: WRITER.into(),
                invocation_id: "a".repeat(32),
                pid: 2,
                start_ticks: 1,
                cgroup_device: 1,
                cgroup_inode: 2,
            },
            replay_or_admission_authorized: false,
        }
    }
    fn manager_for(w: &Writer) -> BTreeMap<String, String> {
        parse_scalars(&format!("Id={WRITER}\nActiveState=active\nSubState=running\nInvocationID={}\nMainPID={}\nControlPID=0\nNRestarts=0\nControlGroup={}\nJob=\nMemoryMax=536870912\nMemorySwapMax=0\nResult=success\n",w.invocation_id,w.pid,CG.strip_prefix("/sys/fs/cgroup").unwrap())).unwrap()
    }
    #[test]
    fn rescue_authenticates_original_shutdown_without_relaxing_reuse_checks() {
        let w = spec().writer;
        let mut d = manager_for(&w);
        assert_eq!(rescue_owner(&w, &d).unwrap(), RescueOwner::Running);
        d.insert("ActiveState".into(), "deactivating".into());
        d.insert("SubState".into(), "stop-sigterm".into());
        d.insert("Job".into(), "42".into());
        assert!(validate_manager(&w, &d).is_err());
        assert_eq!(rescue_owner(&w, &d).unwrap(), RescueOwner::Deactivating);
        for (key, value) in [
            ("InvocationID", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ("MainPID", "3"),
            ("ControlPID", "9"),
            ("NRestarts", "1"),
            ("Job", ""),
            ("SubState", "stop-post"),
            ("ControlGroup", "/other"),
            ("MemorySwapMax", "1"),
        ] {
            let mut bad = d.clone();
            bad.insert(key.into(), value.into());
            assert!(rescue_owner(&w, &bad).is_err(), "{key}");
        }
    }
    #[test]
    fn terminal_original_is_nonacting_and_rejects_replacement_or_pending_jobs() {
        let w = spec().writer;
        let mut d = manager_for(&w);
        for (k, v) in [
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("MainPID", "0"),
            ("ControlGroup", ""),
            ("InvocationID", ""),
        ] {
            d.insert(k.into(), v.into());
        }
        assert_eq!(rescue_owner(&w, &d).unwrap(), RescueOwner::Terminal);
        for (key, value) in [
            ("InvocationID", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ("MainPID", "3"),
            ("Job", "4"),
            ("Result", "signal"),
            ("ControlGroup", "/reused"),
            ("NRestarts", "1"),
            ("MemoryMax", "1"),
        ] {
            let mut bad = d.clone();
            bad.insert(key.into(), value.into());
            assert!(rescue_owner(&w, &bad).is_err(), "{key}");
        }
    }
    #[test]
    fn real_invocations_get_separate_closed_fixture_paths() {
        let a = work_directory(&"a".repeat(32)).unwrap();
        let b = work_directory(&"b".repeat(32)).unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with(WORK));
        assert!(b.starts_with(WORK));
        for invalid in ["../other", WRITER, "", &"0".repeat(32)] {
            assert!(work_directory(invalid).is_err());
        }
    }
    #[test]
    fn only_disposable_writer_can_qualify() {
        let mut s = spec();
        validate(&s).unwrap();
        for unit in [
            "horizon-qualify-236-general-shrink-debt-budget506-e3f15eb2-v1.service",
            "horizon-qualify-allocation-fixture-writer930-v2.service",
            "",
        ] {
            s.writer.unit = unit.into();
            assert!(validate(&s).is_err());
        }
    }
    #[test]
    fn invalid_owner_and_replay_authority_reject() {
        for k in 0..6 {
            let mut s = spec();
            match k {
                0 => s.writer.pid = 0,
                1 => s.writer.start_ticks = 0,
                2 => s.writer.cgroup_device = 0,
                3 => s.writer.cgroup_inode = 0,
                4 => s.writer.invocation_id = "0".repeat(32),
                _ => s.replay_or_admission_authorized = true,
            };
            assert!(validate(&s).is_err());
        }
    }
    #[test]
    fn lifetime_and_unknown_fields_reject() {
        let mut s = spec();
        s.expires_unix_millis += 1;
        assert!(validate(&s).is_err());
        let mut v = serde_json::to_value(spec()).unwrap();
        v["extra"] = json!(true);
        assert!(serde_json::from_value::<Spec>(v).is_err());
    }
    #[test]
    fn scalar_duplicates_and_malformed_reject() {
        assert!(parse_scalars("MainPID=1\nMainPID=2\n").is_err());
        assert!(parse_scalars("MainPID\n").is_err());
        assert_eq!(parse_scalars("Job=\n").unwrap()["Job"], "");
    }
    #[test]
    fn native_owner_replacement_and_missing_census_reject() {
        let w = spec().writer;
        assert!(validate_manager(&w, &BTreeMap::new()).is_err());
        let text = format!(
            "Id={WRITER}\nActiveState=active\nSubState=running\nInvocationID={}\nMainPID=2\nControlPID=0\nNRestarts=0\nControlGroup={}\nJob=\nMemoryMax=536870912\nMemorySwapMax=0\n",
            w.invocation_id,
            CG.strip_prefix("/sys/fs/cgroup").unwrap()
        );
        let d = parse_scalars(&text).unwrap();
        validate_manager(&w, &d).unwrap();
        for (k, v) in [
            ("MainPID", "3"),
            ("InvocationID", "b"),
            ("NRestarts", "1"),
            ("Job", "12"),
            ("ControlGroup", "/other"),
        ] {
            let mut bad = d.clone();
            bad.insert(k.into(), v.into());
            assert!(validate_manager(&w, &bad).is_err());
        }
    }
    #[test]
    fn fiemap_layout_and_unique_allocation() {
        assert_eq!(std::mem::size_of::<Extent>(), 56);
        assert_eq!(std::mem::size_of::<Fiemap>(), 32 + 128 * 56);
        let e = Extent {
            logical: 0,
            physical: 4096,
            length: 8192,
            flags: 1,
            ..Default::default()
        };
        assert_eq!(extent_bytes(&[e], 8192).unwrap(), 8192);
    }
    #[test]
    fn shared_delalloc_unknown_and_alias_extents_reject() {
        let e = Extent {
            logical: 0,
            physical: 4096,
            length: 4096,
            flags: 1,
            ..Default::default()
        };
        for flags in [2, 4, 0x2000, 0x1000, 0x10000] {
            assert!(extent_bytes(&[Extent { flags, ..e }], 4096).is_err());
        }
        assert!(extent_bytes(&[e, Extent { logical: 4096, ..e }], 8192).is_err());
        assert!(
            extent_bytes(
                &[Extent {
                    physical: u64::MAX - 4095,
                    ..e
                }],
                4096
            )
            .is_err()
        );
    }
    #[test]
    fn exact_bus_escape_and_disjoint_roles() {
        assert_eq!(
            bus_path("a-b.timer"),
            "/org/freedesktop/systemd1/unit/a_2db_2etimer"
        );
        assert_ne!(Mode::Normal.state(), Mode::Kill.state());
        assert_ne!(Mode::Normal.role("driver"), Mode::Normal.role("rescue"));
    }
    #[test]
    fn timer_name_alone_cannot_authorize_wrong_rescue() {
        let expected = vec![
            "/sealed/fixture".to_string(),
            "rescue".into(),
            "/sealed/spec.json".into(),
            "--fixture-only".into(),
        ];
        let valid =
            json!({"type":"a(sasbttttuii)","data":[[expected[0],expected,false,0,0,0,0,0,0,0]]});
        validate_rescue_command(&valid, &expected).unwrap();
        for (pointer, replacement) in [
            ("/type", json!("s")),
            ("/data/0/0", json!("/usr/bin/true")),
            ("/data/0/1/1", json!("drive")),
            ("/data/0/1/2", json!("/other/spec.json")),
            ("/data/0/2", json!(true)),
        ] {
            let mut bad = valid.clone();
            *bad.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                validate_rescue_command(&bad, &expected).is_err(),
                "accepted {pointer}"
            );
        }
        let mut multiple = valid.clone();
        multiple["data"]
            .as_array_mut()
            .unwrap()
            .push(valid["data"][0].clone());
        assert!(validate_rescue_command(&multiple, &expected).is_err());
    }
    #[test]
    fn pre_request_control_never_promotes_pending_or_completed_freeze_observations() {
        qualify_pre_request_observation(Mode::IntentKill, false, false, RescueOwner::Running)
            .unwrap();
        for (requested, frozen) in [(false, true), (true, false), (true, true)] {
            assert!(
                qualify_pre_request_observation(
                    Mode::IntentKill,
                    requested,
                    frozen,
                    RescueOwner::Running
                )
                .is_err()
            );
        }
        for owner in [RescueOwner::Deactivating, RescueOwner::Terminal] {
            assert!(
                qualify_pre_request_observation(Mode::IntentKill, false, false, owner).is_err()
            );
        }
        // The old pending control is still a different experiment. Its rescue
        // must not acquire a new frozen=0 requirement that could block thaw.
        qualify_pre_request_observation(Mode::PendingKill, true, true, RescueOwner::Running)
            .unwrap();
    }
    #[test]
    fn pre_request_crash_has_distinct_fixed_paths_and_no_live_owner_authority() {
        let mut s = spec();
        s.mode = Mode::IntentKill;
        validate(&s).unwrap();
        assert_eq!(serde_json::to_value(s.mode).unwrap(), json!("intent-kill"));
        assert_eq!(
            s.mode.role("driver"),
            "horizon-allocation-fixture944-intent-kill-driver-v1.service"
        );
        for mode in [
            Mode::Normal,
            Mode::Kill,
            Mode::WrongInvocation,
            Mode::WrongCgroup,
            Mode::MissingRescue,
            Mode::ReusedCgroup,
            Mode::PendingKill,
            Mode::Deactivating,
        ] {
            assert_ne!(s.mode.state(), mode.state());
            assert_ne!(s.mode.role("driver"), mode.role("driver"));
            assert_ne!(s.mode.timer(), mode.timer());
        }
        s.writer.unit =
            "horizon-qualify-236-general-shrink-debt-budget506-e3f15eb2-v1.service".into();
        assert!(validate(&s).is_err());
    }
    #[test]
    fn pre_request_rescue_requires_the_exact_durable_original_lease() {
        let mut s = spec();
        s.mode = Mode::IntentKill;
        let plan = "b".repeat(64);
        let lease = Lease {
            schema: "horizon-allocation-fixture-freeze-lease-v1".into(),
            plan_sha256: plan.clone(),
            writer: s.writer.clone(),
            driver_unit: s.mode.role("driver"),
            driver_iid: "c".repeat(32),
            driver_pid: 3,
            driver_start_ticks: 4,
            rescue_timer_iid: "d".repeat(32),
        };
        validate_lease(&s, &plan, &lease).unwrap();
        for (pointer, replacement) in [
            ("/schema", json!("other")),
            ("/plan_sha256", json!("e".repeat(64))),
            ("/writer/invocation_id", json!("e".repeat(32))),
            ("/writer/pid", json!(99)),
            ("/writer/start_ticks", json!(99)),
            ("/writer/cgroup_inode", json!(99)),
            ("/driver_unit", json!(Mode::PendingKill.role("driver"))),
            ("/driver_iid", json!("0".repeat(32))),
            ("/driver_pid", json!(1)),
            ("/driver_start_ticks", json!(0)),
            ("/rescue_timer_iid", json!("0".repeat(32))),
        ] {
            let mut changed = serde_json::to_value(&lease).unwrap();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            let changed: Lease = serde_json::from_value(changed).unwrap();
            assert!(validate_lease(&s, &plan, &changed).is_err(), "{pointer}");
        }
    }
}
