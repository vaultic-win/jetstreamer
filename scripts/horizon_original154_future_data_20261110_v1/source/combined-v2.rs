//! SOURCE ONLY. Amalgamate with checker, ending and independently reviewed actual ancestry.
#![recursion_limit = "512"]
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-original154-future-data-tools-20261110-v2/check";
fn save(path: &Path, value: &Value) -> checker::R<()> {
    let parent = path.parent().ok_or("check output parent")?;
    checker::need(
        parent.is_absolute() && parent.canonicalize()? == parent,
        "canonical result parent",
    )?;
    let m = fs::symlink_metadata(parent)?;
    checker::need(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "private Root result parent",
    )?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(0x20000 | 0x80000)
        .open(path)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn helper(operation: &str) -> checker::R<Value> {
    let name = format!("horizon-original154-future-data-{operation}-20261110-v2.service");
    let n = checker::native(&name)?;
    checker::need(
        n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && checker::string(&n,"MainPID")?.parse::<u32>()? == std::process::id()
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["Type"] == "exec"
            && n["User"] == "root"
            && n["Group"] == "root"
            && n["MemoryMax"] == "536870912"
            && n["MemorySwapMax"] == "0"
            && n["RuntimeMaxUSec"] == "3min"
            && n["CPUQuotaPerSecUSec"] == "2s"
            && n["Job"] == ""
            && n["ControlGroup"] == format!("/system.slice/{name}")
            && n["InvocationID"] == std::env::var("INVOCATION_ID")?,
        "exact finite512MiB own helper required",
    )?;
    checker::need(
        fs::read_to_string("/proc/self/cgroup")? == format!("0::/system.slice/{name}\n"),
        "own cgroup differs",
    )?;
    Ok(n)
}
fn run() -> checker::R<()> {
    let a = std::env::args().collect::<Vec<_>>();
    checker::need(
        a.len() == 8
            && matches!(a[1].as_str(), "check" | "end")
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && a[7] == "--no-additional-authority",
        "exact argv required",
    )?;
    checker::need(
        fs::read_link("/proc/self/exe")? == Path::new(IMAGE)
            && checker::sha(&checker::bytes(Path::new(IMAGE), 32 << 20)?) == a[6],
        "normally sealed exact helper image required",
    )?;
    let plan = checker::bound(&json!({"path":a[2],"sha256":a[4]}))?;
    let before = helper(&a[1])?;
    let booking = checker::bound(&plan["native16_suballocation"])?;
    checker::need(
        booking["native_pool_bytes"] == 16u64 << 30
            && booking["all_committed_existing_native_bytes"] == 13_757_317_120u64
            && booking["one_serial_compiler_or_native_bytes"] == 512u64 << 20
            && booking["total_native_with_callback_bytes"] == 14_294_188_032u64
            && booking["new_hard_memory_or_DATA_promise_bytes"] == 0,
        "retained native16 serial512MiB booking required",
    )?;
    let value = if a[1] == "check" {
        checker::check(&plan, ancestry::verify)?
    } else {
        ending::end(&plan, ancestry::verify)?
    };
    checker::need(helper(&a[1])? == before, "own finite helper changed")?;
    save(Path::new(checker::string(&plan, "output")?), &value)?;
    println!(
        "{}",
        json!({"output":plan["output"],"original_invocation_id":checker::IID,"operation":a[1],"replay_admission_authorized":false,"Root_selection_pending_actual_actor_drain":true})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("original154 future DATA rejected: {e}");
        std::process::exit(1);
    }
}

mod checker {
//! Exact failed original154 future-DATA qualification. No deletion or memory credit.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub type R<T> = Result<T, Box<dyn std::error::Error>>;
pub type AncestryVerifier = fn(&Value) -> R<Value>;
pub const IID: &str = "edc1d1915dcb4c2785d2cf24cdaa10c2";
pub const OLD_DATA: u64 = 360 << 30;
pub const RETAINED_DATA: u64 = 32 << 30;
pub const ENDED_DATA: u64 = OLD_DATA - RETAINED_DATA;
pub const BASE_DATA: u64 = 6_582_025_928_498;
pub const BASE_MEMORY: u64 = 759_789_531_136;
pub const HEAD: &str = "/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/ROOT_CONSERVATIVE_DUPLICATE722_ADD_BACK_CURRENT_AUTHORITY.json";
pub const HEAD_SHA: &str = "ee31a884f0cbbb0f58f045eaaf9d9dd823fe8ec8852f560d0f5c21f79aa004d8";
pub const ACTOR: &str = "horizon-qualify-154-checkpoint-continuation-20261029-v1.service";
const CONTROL: &str = "horizon-native154-suffix-control-20261029-v1.service";
const ADMIT: &str = "horizon-epoch154-suffix-admission-20261029-v1.service";
const GUARD: &str = "horizon-guard-154-checkpoint-continuation-20261029-v1.service";
const TIMER: &str = "horizon-guard-154-checkpoint-continuation-20261029-v1.timer";
const STOP: &str = "horizon-stop-154-checkpoint-continuation-20261029-v1.service";
const CANARY: &str = "horizon-qualify-154-checkpoint-continuation-guard-canary-20261029-v1.service";
const CANARY_ACTOR: &str = "horizon-native154-suffix-guard-qualification-20261029-v1.service";
const FAMILY: [&str; 8] = [
    ACTOR,
    CONTROL,
    ADMIT,
    GUARD,
    TIMER,
    STOP,
    CANARY,
    CANARY_ACTOR,
];
const HELPER: &str = "/usr/local/lib/jetstreamer/horizon-native154-suffix-control-tools-20261029-v1/jetstreamer-native154-suffix-control";
const POLICY: &str =
    "/usr/local/lib/jetstreamer/horizon-native154-suffix-policy-20261030-v1/policy.json";
const POLICY_SHA: &str = "170f05aa2ac0ddfcb4b0f35478fdc510970e0b171c7d80a03b0140f8bf15ecd7";
const HELPER_SHA: &str = "166f1ed64aed6eac023da39321a88e5fb7b7a5abd4ee38b64568f58ce510f2b8";
const ROOTS: [&str; 11] = [
    "/home/sol/.jetstreamer-private/checkpoint-continuation-154-20261029-v1",
    "/home/sol/.jetstreamer-private/checkpoint-continuation-154-launch-20261029-v1",
    "/var/lib/jetstreamer/horizon-native154-suffix-20261029-v1",
    "/usr/local/lib/jetstreamer/horizon-native154-suffix-execution-20261029-v1",
    "/usr/local/lib/jetstreamer/horizon-native154-suffix-release-20261029-v1",
    "/var/lib/jetstreamer/horizon-native154-suffix-guard-canary-20261029-v1",
    "/home/sol/.jetstreamer-private/checkpoint-continuation-154-guard-canary-20261029-v1",
    "/usr/local/lib/jetstreamer/horizon-native154-suffix-control-tools-20261029-v1",
    "/usr/local/lib/jetstreamer/horizon-native154-suffix-policy-20261030-v1",
    "/usr/local/lib/jetstreamer/horizon-native154-suffix-tools-20261029-v2",
    "/usr/local/lib/jetstreamer/horizon-native154-suffix-cli-capability-20261029-v2",
];
const LOCK: &str = "/home/sol/.jetstreamer-private/checkpoint-continuation-154.lock";
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;
const DIRECTORY: i32 = 0x10000;
const MAX_ENTRIES: usize = 250_000;
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Restart,Result,ExecMainStatus,ExecMainPID,ControlGroup,Job,TriggeredBy,Triggers,WantedBy,RequiredBy,Upholds,UpheldBy,OnSuccess,OnFailure,DropInPaths,ExecStart,Type,RemainAfterExit,User,Group,KillMode,Delegate,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec";

pub fn need(ok: bool, why: &str) -> R<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
pub fn string<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v[k].as_str()
        .ok_or_else(|| format!("missing string {k}").into())
}
pub fn number(v: &Value, k: &str) -> R<u64> {
    v[k].as_u64()
        .ok_or_else(|| format!("missing number {k}").into())
}
pub fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
pub fn clock() -> R<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn ident(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.len(),
        m.blocks(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
pub fn bytes(path: &Path, limit: u64) -> R<Vec<u8>> {
    need(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical metadata required",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    need(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0 && m.len() <= limit,
        "unsafe Root metadata",
    )?;
    let mut out = Vec::new();
    Read::by_ref(&mut f).take(limit + 1).read_to_end(&mut out)?;
    need(
        out.len() as u64 == m.len()
            && ident(&m) == ident(&f.metadata()?)
            && ident(&m) == ident(&fs::symlink_metadata(path)?),
        "metadata raced",
    )?;
    Ok(out)
}
pub fn bound(b: &Value) -> R<Value> {
    let raw = bytes(Path::new(string(b, "path")?), 32 << 20)?;
    need(sha(&raw) == string(b, "sha256")?, "bound hash differs")?;
    Ok(serde_json::from_slice(&raw)?)
}
fn fixed(path: &str, hash: &str) -> R<Value> {
    bound(&json!({"path":path,"sha256":hash}))
}
fn command(program: &str, args: &[&str]) -> R<Vec<u8>> {
    let out = Command::new("/usr/bin/timeout")
        .args(["--signal=TERM", "--kill-after=2s", "8s", program])
        .args(args)
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env("LC_ALL", "C")
        .output()?;
    need(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 1 << 20,
        "bounded native query failed",
    )?;
    Ok(out.stdout)
}
pub(crate) fn native(unit: &str) -> R<Value> {
    need(
        !unit.starts_with('-')
            && unit.len() <= 255
            && unit
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.@".contains(&c)),
        "unit syntax",
    )?;
    let raw = command(
        "/usr/bin/systemctl",
        &["--system", "show", unit, "--no-pager", "-p", FIELDS],
    )?;
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&raw)?.lines() {
        let (k, v) = line.split_once('=').ok_or("native delimiter")?;
        need(
            FIELDS.split(',').any(|f| f == k) && map.insert(k.into(), json!(v)).is_none(),
            "native unknown or duplicate property",
        )?;
    }
    let v = Value::Object(map);
    need(v["Id"] == unit, "native unit crossed")?;
    Ok(v)
}
fn unit_object(unit: &str) -> String {
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
fn decode_jobs(v: &Value) -> R<Vec<String>> {
    need(v["type"] == "a(usssoo)", "typed ListJobs signature")?;
    let data = v["data"].as_array().ok_or("jobs returns")?;
    need(data.len() == 1, "jobs return arity")?;
    let mut names = Vec::new();
    let mut seen = BTreeSet::new();
    for j in data[0].as_array().ok_or("jobs array")? {
        let row = j.as_array().ok_or("job tuple")?;
        need(row.len() == 6, "job arity")?;
        let id = row[0].as_u64().ok_or("job id")?;
        let unit = row[1].as_str().ok_or("job unit")?;
        need(
            id > 0
                && id <= u64::from(u32::MAX)
                && seen.insert(id)
                && !unit.is_empty()
                && unit.len() <= 255
                && !unit
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                && row[2].as_str().is_some_and(|s| !s.is_empty())
                && matches!(row[3].as_str(), Some("waiting" | "running"))
                && row[4] == format!("/org/freedesktop/systemd1/job/{id}")
                && row[5] == unit_object(unit),
            "typed job identity",
        )?;
        names.push(unit.into());
    }
    Ok(names)
}
fn queued() -> R<Value> {
    let raw = command(
        "/usr/bin/busctl",
        &[
            "--system",
            "--json=short",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "ListJobs",
        ],
    )?;
    let v: Value = serde_json::from_slice(&raw)?;
    let names = decode_jobs(&v)?;
    need(
        !names.iter().any(|s| FAMILY.contains(&s.as_str())),
        "original154 family has queued job",
    )?;
    Ok(json!({"typed_native_ListJobs":v,"raw_sha256":sha(&raw)}))
}
fn completed_metadata(v: &Value) -> R<bool> {
    let (iid, kind, argv) = if v["Id"] == ADMIT {
        (
            "b225fea6a4cf4f4680139cab3e7d69e7",
            "simple",
            "/usr/local/lib/jetstreamer/horizon-epoch136-suffix-lifecycle-tools-20261030-combined-v7/jetstreamer-r2 admit-suffix154 /usr/local/lib/jetstreamer/horizon-current0223-accounting-20261030-v1/suffix154-admission.json --spec-sha256 829a71c6d0953b685ec24de1b103813960f92462c2a829b8ce8c72f466415b44 --self-sha256 641e6d1af6731b54b54b4ee70f5b36b07ae48705ef5f857c37e08efbb79e4ab7",
        )
    } else if v["Id"] == CANARY_ACTOR {
        (
            "fb35fbed1796419ab0a2c858b55440be",
            "oneshot",
            "/usr/local/lib/jetstreamer/horizon-native154-suffix-control-qualification-20261029-v1/jetstreamer-native154-suffix-control qualify-guard --self-sha256 000f88450150f7ac98d122c5d5a041f1b75fe383dce1edd9210e9ca90a61d95b",
        )
    } else {
        return Ok(false);
    };
    need(
        v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "exited"
            && v["InvocationID"] == iid
            && v["Type"] == kind
            && v["RemainAfterExit"] == "yes"
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && string(v, "ExecStart")?.contains(&format!("argv[]={argv} ; ignore_errors=no"))
            && string(v, "ExecStart")?.matches("argv[]=").count() == 1,
        "exact completed154 metadata identity/command required",
    )?;
    for hook in ["ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost"] {
        let raw = command(
            "/usr/bin/busctl",
            &[
                "--system",
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                &unit_object(string(v, "Id")?),
                "org.freedesktop.systemd1.Service",
                hook,
            ],
        )?;
        let typed: Value = serde_json::from_slice(&raw)?;
        need(
            typed["type"] == "a(sasbttttuii)" && typed["data"] == json!([]),
            "completed metadata has execution hook",
        )?;
    }
    Ok(true)
}
fn no_trigger(v: &Value, timer: bool, completed: bool) -> R<()> {
    for k in [
        "Job",
        "TriggeredBy",
        "WantedBy",
        "RequiredBy",
        "Upholds",
        "UpheldBy",
        "OnSuccess",
        "DropInPaths",
    ] {
        if k == "TriggeredBy" && v["Id"] == GUARD {
            need(
                v[k] == "" || v[k] == TIMER,
                "foreign trigger for old154 guard",
            )?;
        } else {
            need(v[k] == "", "original family can activate or has overlay")?;
        }
    }
    if !timer {
        need(
            v.get("Triggers").is_none_or(|v| v == ""),
            "original family triggers another unit",
        )?;
    }
    need(
        completed || matches!(v["ActiveState"].as_str(), Some("inactive" | "failed")),
        "original family not terminal",
    )?;
    if !timer && v["LoadState"] != "not-found" {
        for k in ["MainPID", "ControlPID", "NRestarts"] {
            need(v[k] == "0", "original family live or restarted")?;
        }
    }
    if timer {
        need(
            v.get("ControlGroup").is_none(),
            "exact timer must omit unsupported cgroup property",
        )?;
    } else if v["LoadState"] == "not-found" {
        need(
            v.get("ControlGroup").is_none_or(|v| v == ""),
            "original family retains cgroup",
        )?;
    } else {
        need(v["ControlGroup"] == "", "original family retains cgroup")?;
    }
    if !timer && v["LoadState"] != "not-found" {
        need(v["Restart"] == "no", "original family restarts")?;
    }
    Ok(())
}
fn family() -> R<Value> {
    let mut out = serde_json::Map::new();
    for unit in FAMILY {
        let v = native(unit)?;
        let completed = completed_metadata(&v)?;
        no_trigger(&v, unit == TIMER, completed)?;
        if unit == ACTOR {
            need(
                v["LoadState"] == "loaded"
                    && v["InvocationID"] == IID
                    && v["ActiveState"] == "failed"
                    && v["Result"] == "exit-code"
                    && v["ExecMainStatus"] == "1"
                    && v["MemoryMax"] == "68719476736"
                    && v["MemorySwapMax"] == "0"
                    && v["KillMode"] == "control-group"
                    && v["Delegate"] == "no"
                    && v["OnFailure"] == STOP,
                "exact original154 failure/envelope changed",
            )?;
            let expected = format!(
                "argv[]={HELPER} wrapper {POLICY} --policy-sha256 {POLICY_SHA} --self-sha256 {HELPER_SHA} ; ignore_errors=no"
            );
            need(
                string(&v, "ExecStart")?.contains(&expected)
                    && string(&v, "ExecStart")?.matches("argv[]=").count() == 1,
                "original actor command changed",
            )?;
        }
        if unit == STOP && v["LoadState"] != "not-found" {
            let expected = format!(
                "argv[]={HELPER} emergency {POLICY} --policy-sha256 {POLICY_SHA} --self-sha256 {HELPER_SHA} ; ignore_errors=no"
            );
            need(
                string(&v, "ExecStart")?.contains(&expected)
                    && string(&v, "ExecStart")?.matches("argv[]=").count() == 1
                    && v["OnFailure"] == "",
                "stop-only failure handler changed",
            )?;
        }
        if unit == TIMER {
            need(
                v["LoadState"] == "loaded"
                    && v["Triggers"] == GUARD
                    && v["ActiveState"] == "inactive"
                    && v["SubState"] == "dead",
                "old guard timer changed",
            )?;
        }
        out.insert(unit.into(), v);
    }
    Ok(Value::Object(out))
}

#[derive(Default)]
struct Scope {
    facts: BTreeMap<String, Value>,
    inodes: BTreeSet<(u64, u64)>,
    bytes: u64,
}
fn accounted(m: &fs::Metadata) -> R<u64> {
    Ok(m.len()
        .max(m.blocks().checked_mul(512).ok_or("block overflow")?))
}
fn open_dir(path: &Path) -> R<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(DIRECTORY | NOFOLLOW | CLOEXEC)
        .open(path)?)
}
fn record(scope: &mut Scope, key: String, m: &fs::Metadata) -> R<()> {
    need(
        scope.facts.len() < MAX_ENTRIES && !scope.facts.contains_key(&key),
        "scope bound or repeated path",
    )?;
    scope.bytes = scope
        .bytes
        .checked_add(accounted(m)?)
        .ok_or("scope sum overflow")?;
    need(scope.bytes <= 16 << 30, "retained scope exceeds16GiB")?;
    record_inode(
        &mut scope.inodes,
        (m.dev(), m.ino()),
        m.is_file(),
        m.nlink(),
    )?;
    scope.facts.insert(key, ident(m));
    Ok(())
}
fn record_inode(
    inodes: &mut BTreeSet<(u64, u64)>,
    key: (u64, u64),
    regular: bool,
    links: u64,
) -> R<()> {
    need(
        (!regular || links == 1) && inodes.insert(key),
        "scope hardlink or duplicate inode",
    )
}
fn walk(fd: &File, dev: u64, key: &str, scope: &mut Scope, depth: u32, deadline: Instant) -> R<()> {
    need(
        depth <= 128 && Instant::now() < deadline,
        "scan deadline/depth",
    )?;
    let before = fd.metadata()?;
    need(
        before.is_dir() && before.dev() == dev,
        "directory device changed",
    )?;
    let anchor = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    let mut children = fs::read_dir(&anchor)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|e| e.file_name());
    for entry in children {
        need(Instant::now() < deadline, "scan deadline")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "scope filename UTF8")?;
        let path = entry.path();
        let m = fs::symlink_metadata(&path)?;
        need(
            m.dev() == dev && !m.file_type().is_symlink() && (m.is_file() || m.is_dir()),
            "scope symlink/foreign filesystem/special file",
        )?;
        let child_key = format!("{key}/{name}");
        record(scope, child_key.clone(), &m)?;
        if m.is_dir() {
            let child = open_dir(&path)?;
            need(ident(&m) == ident(&child.metadata()?), "directory replaced")?;
            walk(&child, dev, &child_key, scope, depth + 1, deadline)?;
        }
        need(
            ident(&m) == ident(&fs::symlink_metadata(&path)?),
            "scope entry changed",
        )?;
    }
    need(
        ident(&before) == ident(&fd.metadata()?),
        "directory changed during scan",
    )
}
fn scan(deadline: Instant) -> R<Scope> {
    let mut scope = Scope::default();
    for (i, root) in ROOTS.iter().enumerate() {
        let path = Path::new(root);
        let m = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Missing roots are explicit facts and must remain missing across the second pass.
                scope.facts.insert(format!("root:{i}"), json!("absent"));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        need(
            path.canonicalize()? == path && m.is_dir(),
            "canonical retained directory required",
        )?;
        let fd = open_dir(path)?;
        need(ident(&m) == ident(&fd.metadata()?), "root raced")?;
        record(&mut scope, format!("root:{i}"), &m)?;
        walk(&fd, m.dev(), &format!("root:{i}"), &mut scope, 0, deadline)?;
        need(
            ident(&m) == ident(&fs::symlink_metadata(path)?),
            "root changed",
        )?;
    }
    let p = Path::new(LOCK);
    let m = fs::symlink_metadata(p)?;
    need(
        p.canonicalize()? == p && m.is_file(),
        "exact retained original lock required",
    )?;
    record(&mut scope, "lock".into(), &m)?;
    Ok(scope)
}
fn path_reference(blob: &[u8], path: &[u8]) -> bool {
    !path.is_empty()
        && blob.windows(path.len()).enumerate().any(|(i, s)| {
            s == path
                && (i + path.len() == blob.len()
                    || b"/\0\n\r\t '\";|&()<>[]{}:=,".contains(&blob[i + path.len()]))
        })
}
fn transient(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(3)
}
fn start_ticks(raw: &[u8]) -> R<String> {
    Ok(std::str::from_utf8(raw)?
        .rsplit_once(") ")
        .ok_or("proc stat framing")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("proc ticks")?
        .into())
}
fn mapping_aliases_absent(raw: &[u8], inodes: &BTreeSet<(u64, u64)>) -> R<()> {
    for line in std::str::from_utf8(raw)?.lines() {
        let fields = line.split_whitespace().take(5).collect::<Vec<_>>();
        need(fields.len() == 5, "proc maps framing")?;
        let inode = fields[4].parse::<u64>()?;
        let (major, minor) = fields[3].split_once(':').ok_or("proc maps device")?;
        let major = u64::from(u32::from_str_radix(major, 16)?);
        let minor = u64::from(u32::from_str_radix(minor, 16)?);
        let device = (minor & 0xff)
            | ((major & 0xfff) << 8)
            | ((minor & !0xff) << 12)
            | ((major & !0xfff) << 32);
        need(
            inode == 0 || !inodes.contains(&(device, inode)),
            "live mapping inode alias into old154 scope",
        )?;
    }
    Ok(())
}
fn proc_absent(scope: &Scope, deadline: Instant) -> R<Value> {
    let mut count = 0u64;
    let me = std::process::id().to_string();
    for p in fs::read_dir("/proc")? {
        need(Instant::now() < deadline, "process scan deadline")?;
        let p = p?;
        let name = p.file_name().to_string_lossy().into_owned();
        if name == me || name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let root = p.path();
        let before = match fs::read(root.join("stat")) {
            Ok(x) => x,
            Err(e) if transient(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        let check = |blob: &[u8]| -> R<()> {
            for path in ROOTS.into_iter().chain([LOCK]) {
                need(
                    !path_reference(blob, path.as_bytes()),
                    "live process references old154 scope",
                )?;
            }
            Ok(())
        };
        for field in ["cmdline", "maps", "environ"] {
            match fs::read(root.join(field)) {
                Ok(b) => {
                    check(&b)?;
                    if field == "maps" {
                        mapping_aliases_absent(&b, &scope.inodes)?;
                    }
                }
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        for field in ["cwd", "root", "exe"] {
            match fs::read_link(root.join(field)) {
                Ok(p) => {
                    check(p.as_os_str().as_encoded_bytes())?;
                    match fs::metadata(root.join(field)) {
                        Ok(m) => need(
                            !scope.inodes.contains(&(m.dev(), m.ino())),
                            "live process root/cwd/exe inode alias",
                        )?,
                        Err(e) if transient(&e) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        match fs::read_dir(root.join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    let path = fd?.path();
                    match fs::read_link(&path) {
                        Ok(p) => check(p.as_os_str().as_encoded_bytes())?,
                        Err(e) if transient(&e) => continue,
                        Err(e) => return Err(e.into()),
                    }
                    match fs::metadata(&path) {
                        Ok(m) => need(
                            !scope.inodes.contains(&(m.dev(), m.ino())),
                            "live inode alias into old154 scope",
                        )?,
                        Err(e) if transient(&e) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Err(e) if transient(&e) => {}
            Err(e) => return Err(e.into()),
        }
        match fs::read(root.join("stat")) {
            Ok(after) => need(
                start_ticks(&before)? == start_ticks(&after)?,
                "PID reuse during census",
            )?,
            Err(e) if transient(&e) => {}
            Err(e) => return Err(e.into()),
        }
        count += 1;
    }
    Ok(
        json!({"processes_inspected":count,"scope_references":0,"permission_errors":0,"inode_alias_checks":true}),
    )
}
fn protected(fleet: &Value) -> R<Value> {
    let replays = fleet["actual_executing_replays"]
        .as_array()
        .ok_or("fleet replays")?;
    need(
        replays.len() == 7
            && fleet["complete_DATA_bytes"] == BASE_DATA
            && fleet["complete_projected_memory_bytes"] == BASE_MEMORY,
        "current seven-lane fleet required",
    )?;
    let mut out = serde_json::Map::new();
    for row in replays {
        let expected = &row["unit"];
        let name = string(expected, "Id")?;
        let v = native(name)?;
        for k in ["Id", "InvocationID", "MainPID", "ControlGroup", "NRestarts"] {
            need(v[k] == expected[k], "protected replay identity changed")?;
        }
        need(
            v["ActiveState"] == "active"
                && v["SubState"] == "running"
                && v["NRestarts"] == "0"
                && v["MemoryMax"] == "73014444032"
                && v["MemorySwapMax"] == "0"
                && v["Restart"] == "no",
            "protected replay cap/state changed",
        )?;
        out.insert(name.into(), v);
    }
    for (name, expected) in fleet["stable_non_replay_owners"]
        .as_object()
        .ok_or("protected background owners")?
    {
        let v = native(name)?;
        for k in [
            "Id",
            "InvocationID",
            "MainPID",
            "ControlGroup",
            "NRestarts",
            "ActiveState",
            "SubState",
        ] {
            need(v[k] == expected[k], "protected background owner changed")?;
        }
        out.insert(name.clone(), v);
    }
    need(out.len() >= 9, "uploader and original199 owners required")?;
    Ok(Value::Object(out))
}
fn originals() -> R<Value> {
    let base = "/var/lib/jetstreamer/horizon-native154-suffix-20261029-v1";
    let owner = fixed(
        &format!("{base}/owner.json"),
        "68e16da57d67b791b70bce1a84b381df1c264f60c33cf179adb93ea1a8437e63",
    )?;
    let prepared = fixed(
        &format!("{base}/prepared.json"),
        "31ae09051bf59fbfbf3b905b26e9275d26ba47743bd83963f331077f92708cff",
    )?;
    let admitted = fixed(
        &format!("{base}/admission.json"),
        "5b86e54636b49fda85bbe1be7b1167a75be584292c59d6033750a2b5b8968615",
    )?;
    let terminal = fixed(
        &format!("{base}/terminal.json"),
        "ec1f4455f70444f63602c7b26700c0eaee8d7528f2f00befb6fd327c9b19b16b",
    )?;
    let _policy = fixed(POLICY, POLICY_SHA)?;
    let resources = fixed(
        "/usr/local/lib/jetstreamer/horizon-native154-suffix-tools-20261029-v2/resource-policy.json",
        "2621515838b9f5118838b59537e372a082ea921757dc17e7a56065ebbbdfebf8",
    )?;
    let node_plan = fixed(
        &format!("{base}/node-plan.json"),
        "3c673bb36eb5ca8456a0a180960dd4b3c25b07471926f50763967f32cb15c5bc",
    )?;
    need(
        owner["producer_invocation_id"] == IID
            && prepared["candidate_incremental_peak_bytes"] == OLD_DATA
            && admitted["candidate_incremental_peak_bytes"] == OLD_DATA
            && terminal["producer_invocation_id"] == IID
            && terminal["control_group_drained"] == true
            && terminal["data_reservation_bytes"] == OLD_DATA
            && terminal["memory_released_bytes"] == 64u64 << 30
            && terminal["remaining_growth_released"] == false
            && terminal["archive_completion_claimed"] == false
            && resources["candidate_incremental_peak_bytes"] == OLD_DATA
            && node_plan["run_root"] == ROOTS[0]
            && node_plan["producer_unit"] == ACTOR
            && resources["native_copy_restore_indexes_bytes"] == 64u64 << 30
            && resources["suffix_archive_and_growth_bytes"] == 8u64 << 30
            && resources["assembled_archive_bytes"] == 224u64 << 30
            && resources["independent_verification_scratch_bytes"] == 32u64 << 30
            && resources["incremental_margin_bytes"] == 32u64 << 30
            && admitted["launch_expires_unix_seconds"]
                .as_u64()
                .is_some_and(|t| clock().is_ok_and(|now| now > t)),
        "original charge/terminal/expired launch differs",
    )?;
    Ok(
        json!({"owner_sha256":"68e16da57d67b791b70bce1a84b381df1c264f60c33cf179adb93ea1a8437e63","terminal_sha256":"ec1f4455f70444f63602c7b26700c0eaee8d7528f2f00befb6fd327c9b19b16b","all_bound_original_metadata_unchanged":true,"memory_already_released_bytes":64u64<<30}),
    )
}

fn validate_ancestry_result(ancestry: &Value, authority: &Value) -> R<()> {
    need(
        ancestry["current_authority"] == *authority
            && ancestry["original_invocation_id"] == IID
            && ancestry["charged_original_DATA_bytes"] == OLD_DATA
            && ancestry["prior_effective_original154_DATA_endings"] == 0
            && ancestry["complete_ancestry_authenticated"] == true,
        "genuine once-only ancestry result required",
    )
}

/// The callback must independently follow and authenticate the actual authority lineage.
/// It must return the shape below only after rejecting any prior effective154 ending.
/// Neither an unauthenticated JSON receipt nor `remaining_growth_released=false` is enough.
pub fn check(plan: &Value, verify_ancestry: AncestryVerifier) -> R<Value> {
    let started = clock()?;
    let deadline = Instant::now() + std::time::Duration::from_secs(150);
    need(
        plan["schema"] == "horizon-original154-future-DATA-check-plan-v1"
            && plan["owner"] == "/root"
            && plan["current_authority"] == json!({"path":HEAD,"sha256":HEAD_SHA}),
        "exact check plan/current authority required",
    )?;
    let head = bound(&plan["current_authority"])?;
    need(
        head["complete_DATA_bytes"] == BASE_DATA
            && head["complete_projected_memory_bytes"] == BASE_MEMORY,
        "current authority scalar changed",
    )?;
    let ancestry = verify_ancestry(&plan["ancestry_request"])?;
    validate_ancestry_result(&ancestry, &plan["current_authority"])?;
    let original = originals()?;
    let fleet = bound(&plan["current_fleet"])?;
    need(
        fleet["authenticated_inventory"] == plan["inventory"],
        "inventory not current fleet binding",
    )?;
    let inventory = bound(&plan["inventory"])?;
    need(
        inventory["entries"]
            .as_array()
            .ok_or("inventory rows")?
            .iter()
            .filter(|r| r["epoch"] == 154 && r["state"] == "ready-pair")
            .count()
            == 1,
        "154 ready-pair classification required",
    )?;
    let family_before = family()?;
    let peers_before = protected(&fleet)?;
    let jobs_before = queued()?;
    let first = scan(deadline)?;
    let no_writers_before = proc_absent(&first, deadline)?;
    let second = scan(deadline)?;
    need(
        first.facts == second.facts && first.bytes == second.bytes,
        "complete retained scope changed across passes",
    )?;
    let no_writers_after = proc_absent(&second, deadline)?;
    let family_after = family()?;
    let peers_after = protected(&fleet)?;
    let jobs_after = queued()?;
    need(
        family_before == family_after && peers_before == peers_after,
        "family or protected peers changed",
    )?;
    need(
        bound(&plan["current_authority"])? == head
            && verify_ancestry(&plan["ancestry_request"])? == ancestry,
        "authority/ancestry changed during check",
    )?;
    let finished = clock()?;
    need(
        finished >= started && finished - started <= 150,
        "finite check expired",
    )?;
    Ok(
        json!({"schema":"horizon-original154-future-DATA-check-v1","owner":"/root","original_invocation_id":IID,
        "recorded_unix_seconds":finished,"started_unix_seconds":started,"current_authority":plan["current_authority"],"current_fleet":plan["current_fleet"],"inventory":plan["inventory"],
        "ancestry":ancestry,"originals":original,"retained_roots":ROOTS,"retained_lock":LOCK,"scope_entries":first.facts.len(),"scope_accounted_bytes":first.bytes,
        "scope_facts_sha256":sha(&serde_json::to_vec(&first.facts)?),"scope_limit_bytes":16u64<<30,"retained_DATA_bytes":RETAINED_DATA,"original_DATA_bytes":OLD_DATA,
        "proposed_unused_future_DATA_bytes":ENDED_DATA,"family_before":family_before,"family_after":family_after,
        "protected_peers_before":peers_before,"protected_peers_after":peers_after,"jobs_before":jobs_before,"jobs_after":jobs_after,
        "no_writers_before":no_writers_before,"no_writers_after":no_writers_after,"new_memory_credit_bytes":0,"physical_bytes_removed":0,
        "DATA_ending_selected":false,"guard_mutations":false,"replay_admission_authorized":false,"remote_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_multiply_linked_retained_file() {
        assert!(record_inode(&mut BTreeSet::new(), (1, 2), true, 2).is_err());
    }
    #[test]
    fn rejects_duplicate_inode_even_with_distinct_scope_paths() {
        let mut set = BTreeSet::new();
        record_inode(&mut set, (1, 2), true, 1).unwrap();
        assert!(record_inode(&mut set, (1, 2), true, 1).is_err());
    }
    fn ancestry() -> Value {
        json!({"current_authority":{"path":HEAD,"sha256":HEAD_SHA},"original_invocation_id":IID,"charged_original_DATA_bytes":OLD_DATA,"prior_effective_original154_DATA_endings":0,"complete_ancestry_authenticated":true})
    }
    #[test]
    fn qualified_ancestry_shape() {
        let v = ancestry();
        validate_ancestry_result(&v, &v["current_authority"]).unwrap();
    }
    #[test]
    fn rejects_any_previously_effective_ending() {
        let mut v = ancestry();
        v["prior_effective_original154_DATA_endings"] = json!(1);
        assert!(validate_ancestry_result(&v, &v["current_authority"]).is_err());
    }
    #[test]
    fn rejects_historical_raw_row_as_complete_proof() {
        let mut v = ancestry();
        v.as_object_mut()
            .unwrap()
            .remove("complete_ancestry_authenticated");
        assert!(validate_ancestry_result(&v, &v["current_authority"]).is_err());
    }
    #[test]
    fn rejects_smaller_carried_original_charge() {
        let mut v = ancestry();
        v["charged_original_DATA_bytes"] = json!(OLD_DATA - 1);
        assert!(validate_ancestry_result(&v, &v["current_authority"]).is_err());
    }
    #[test]
    fn rejects_mapping_under_an_external_hardlink_path() {
        let set = BTreeSet::from([(0xfc00, 123)]);
        assert!(
            mapping_aliases_absent(b"1000-2000 rw-s 00000000 fc:00 123 /external/alias\n", &set)
                .is_err()
        );
    }
    #[test]
    fn anonymous_mapping_cannot_supply_alias_or_credit() {
        assert!(
            mapping_aliases_absent(
                b"1000-2000 rw-p 00000000 00:00 0\n",
                &BTreeSet::from([(0, 0)])
            )
            .is_ok()
        );
    }
    #[test]
    fn rejects_duplicate_native_job_id() {
        let row = json!([
            1,
            ACTOR,
            "start",
            "waiting",
            "/org/freedesktop/systemd1/job/1",
            unit_object(ACTOR)
        ]);
        assert!(decode_jobs(&json!({"type":"a(usssoo)","data":[[row.clone(),row]]})).is_err());
    }
    #[test]
    fn exact_data_arithmetic() {
        assert_eq!(ENDED_DATA, 352_187_318_272);
        assert_eq!(BASE_DATA - ENDED_DATA, 6_229_838_610_226);
        assert_eq!(BASE_MEMORY, 759_789_531_136);
    }
    #[test]
    fn path_boundary() {
        assert!(path_reference(b"x /tmp/foo/bar", b"/tmp/foo"));
        assert!(!path_reference(b"x /tmp/foobar", b"/tmp/foo"));
        assert!(!path_reference(b"x", b""));
    }
    #[test]
    fn typed_empty_jobs() {
        assert!(
            decode_jobs(&json!({"type":"a(usssoo)","data":[[]]}))
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn rejects_text_and_wrong_nesting_jobs() {
        assert!(decode_jobs(&json!({"type":"a(usssoo)","data":[]})).is_err());
        assert!(decode_jobs(&json!({"type":"s","data":[[]]})).is_err());
    }
    #[test]
    fn rejects_crossed_job_object() {
        assert!(decode_jobs(&json!({"type":"a(usssoo)","data":[[[1,ACTOR,"start","waiting","/org/freedesktop/systemd1/job/2",unit_object(ACTOR)]]]})).is_err());
    }
    #[test]
    fn native_path_encoding() {
        assert_eq!(
            unit_object("a-b.service"),
            "/org/freedesktop/systemd1/unit/a_2db_2eservice"
        );
    }
    #[test]
    fn proc_stat_comm_with_parenthesis() {
        let text = format!(
            "1 (a ) b) S {} 42",
            (0..18).map(|_| "0").collect::<Vec<_>>().join(" ")
        );
        assert_eq!(start_ticks(text.as_bytes()).unwrap(), "42");
    }
    #[test]
    fn scan_roots_do_not_include_prefix_archive() {
        assert!(!ROOTS.iter().any(|p| p.contains("epoch154-v158-validation")));
        assert_eq!(ROOTS.len(), 11);
    }
}

}

mod ending {
//! Separate no-clobber ending writer. Check receipts alone cannot end a promise.
use super::checker::{self as c, AncestryVerifier, R};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub const END_ROOT: &str = "/var/lib/jetstreamer/horizon-original154-unused-future-DATA-20261110-v1/edc1d1915dcb4c2785d2cf24cdaa10c2";
fn private_parent(path: &Path) -> R<()> {
    c::need(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical ending parent required",
    )?;
    let m = fs::symlink_metadata(path)?;
    c::need(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "private Root ending directory required",
    )
}
fn durable(path: &Path, v: &Value) -> R<()> {
    let parent = path.parent().ok_or("ending parent")?;
    private_parent(parent)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(0x20000 | 0x80000)
        .open(path)?;
    serde_json::to_writer_pretty(&mut f, v)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
/// Caller driver must prove exact sealed image, native finite helper identity/cap/guard and
/// current Root ownership before entering. This function creates intent BEFORE fresh check.
/// A failed check leaves intent permanently retained and grants zero selected resource credit.
/// Root may select only the actual ending after this actor drains; consumers and guard handoff
/// remain separate. No in-place change to HEAD, original receipts, files or systemd is performed.
pub fn end(plan: &Value, verify_ancestry: AncestryVerifier) -> R<Value> {
    c::need(
        plan["schema"] == "horizon-original154-future-DATA-ending-plan-v1"
            && plan["owner"] == "/root",
        "exact ending plan required",
    )?;
    let prior = c::bound(&plan["qualified_check"])?;
    c::need(
        prior["schema"] == "horizon-original154-future-DATA-check-v1"
            && prior["original_invocation_id"] == c::IID
            && prior["current_authority"] == plan["check_plan"]["current_authority"]
            && prior["proposed_unused_future_DATA_bytes"] == c::ENDED_DATA
            && prior["scope_accounted_bytes"]
                .as_u64()
                .is_some_and(|b| b <= 16 << 30)
            && prior["DATA_ending_selected"] == false,
        "genuine successful exact check required",
    )?;
    let now = c::clock()?;
    let at = c::number(&prior, "recorded_unix_seconds")?;
    c::need(now >= at && now - at <= 300, "qualified check expired")?;
    let root = Path::new(END_ROOT);
    private_parent(root)?;
    // Shared no-clobber intent prevents parallel checks from selecting this owner twice.
    c::need(
        !root.join("ended.json").try_exists()?,
        "original154 ending already exists",
    )?;
    durable(
        &root.join("intent.json"),
        &json!({"schema":"horizon-original154-future-DATA-ending-intent-v1","original_invocation_id":c::IID,"qualified_check":plan["qualified_check"],"recorded_unix_seconds":now,"memory_credit_bytes":0,"ending_selected":false}),
    )?;
    let actual = c::check(&plan["check_plan"], verify_ancestry)?;
    c::need(
        actual["current_authority"] == prior["current_authority"]
            && actual["scope_facts_sha256"] == prior["scope_facts_sha256"]
            && actual["protected_peers_after"] == prior["protected_peers_after"]
            && actual["family_after"] == prior["family_after"],
        "fresh ending check changed scope/owner/authority",
    )?;
    let ended = json!({"schema":"horizon-original154-future-DATA-ended-v1","owner":"/root","original_invocation_id":c::IID,
        "previous_complete_DATA_authority":actual["current_authority"],"previous_complete_DATA_bytes":c::BASE_DATA,"complete_DATA_bytes":c::BASE_DATA-c::ENDED_DATA,
        "complete_projected_memory_bytes":c::BASE_MEMORY,"original_DATA_reservation_bytes":c::OLD_DATA,"retained_DATA_bytes":c::RETAINED_DATA,
        "unused_future_DATA_ended_bytes":c::ENDED_DATA,"new_memory_credit_bytes":0,"physical_bytes_removed":0,
        "qualified_check":plan["qualified_check"],"genuine_fresh_check":actual,"recorded_unix_seconds":c::clock()?,
        "all_original_files_and_receipts_retained":true,"Root_selection_pending_actor_drain":true,"effective_consumers_and_continuous_guard_handoff_pending":true,
        "replay_admission_authorized":false,"guard_mutations":false,"remote_mutations":false});
    durable(&root.join("ended.json"), &ended)?;
    Ok(ended)
}

}

mod ancestry {
//! Authenticate the exact reviewed effective DATA chain, independently of its summary flags.
use super::checker::{self as c, R};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const MANIFEST: &str = "/usr/local/lib/jetstreamer/horizon-original154-future-data-source-20261110-v2/lineage-manifest.json";
const MANIFEST_SHA: &str = "4906d22bdcc5656c2f28da7a9a28d45496c65ca57fc13cf898382b09a514b505";
fn array<'a>(v: &'a Value, k: &str) -> R<&'a Vec<Value>> {
    v[k].as_array()
        .ok_or_else(|| format!("missing array {k}").into())
}
fn data(v: &Value) -> R<u64> {
    let values = ["complete_DATA_bytes", "complete_DATA_lower_bound_bytes"]
        .iter()
        .filter_map(|k| v.get(k))
        .map(|v| v.as_u64().ok_or("invalid DATA integer"))
        .collect::<Result<Vec<_>, _>>()?;
    c::need(
        !values.is_empty() && values.iter().all(|n| *n == values[0]),
        "missing or ambiguous DATA total",
    )?;
    Ok(values[0])
}
fn amount(v: &Value, p: &str) -> R<u64> {
    v.pointer(p)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing numeric pointer {p}").into())
}
fn equation(parent: u64, child: u64, operation: &str, amount: u64) -> R<i128> {
    let expected = match operation {
        "add" => parent.checked_add(amount),
        "subtract" => parent.checked_sub(amount),
        "equal" if amount == 0 => Some(parent),
        _ => None,
    };
    c::need(expected == Some(child), "independent DATA equation differs")?;
    Ok(i128::from(child) - i128::from(parent))
}
fn other_claim(index: usize, child: &Value, support: &[Value]) -> R<()> {
    let (key, iid) = match index {
        5 | 30 | 35 => (
            "original_producer_invocation_id",
            if index == 5 {
                "722adc397ae24bb4b96d452783599f57"
            } else {
                "2a1c51f557a64cd1ad691281cbb77c94"
            },
        ),
        45 => (
            "ended_original_invocation_id",
            "722adc397ae24bb4b96d452783599f57",
        ),
        56 => (
            "ended_failed74_actor_future",
            "f37b155136614e0183ba2e9adb8714ef",
        ),
        68 => ("actor_invocation_id", "5f4b7cb4621a4a2080fd9b083c14f5a0"),
        _ => return Err("unreviewed negative DATA edge".into()),
    };
    // The exact manifest pins every original. Also derive claim identity from the genuine row.
    let direct = child[key] == iid;
    let original = support.iter().any(|v| {
        [
            "original_invocation_id",
            "producer_invocation_id",
            "actor_invocation_id",
            "ended_old722_actor_future",
        ]
        .iter()
        .any(|key| v[key] == iid)
    });
    c::need(
        iid != c::IID && (direct || original),
        "negative edge is not exact other claim",
    )?;
    if index == 68 {
        let rows = array(child, "ended_failed_startpre_obligations")?;
        c::need(
            rows.len() == 1 && rows[0]["invocation_id"] == iid,
            "failed1530 claim crossed",
        )?;
    }
    Ok(())
}
fn source_increment(kind: &str, value: &Value) -> R<u64> {
    match kind {
        "166-lane" => amount(value, "/new_candidate_own_DATA_bytes")?
            .checked_add(amount(value, "/new_candidate_guard_metadata_bytes")?)
            .ok_or_else(|| "lane increment overflow".into()),
        "167-lane" => amount(value, "/candidate_own_DATA_bytes")?
            .checked_add(amount(value, "/candidate_guard_metadata_bytes")?)
            .ok_or_else(|| "lane increment overflow".into()),
        "163-control" | "policy-QA" | "nine-cache-QA" | "ended-tool-QA" | "166-metadata"
        | "167-metadata" | "168-metadata" => amount(value, "/new_retained_DATA_bytes"),
        _ => Err("unreviewed canonical increment".into()),
    }
}

pub fn verify(request: &Value) -> R<Value> {
    c::need(
        request["manifest"] == json!({"path":MANIFEST,"sha256":MANIFEST_SHA}),
        "exact lineage selector required",
    )?;
    let manifest = c::bound(&request["manifest"])?;
    c::need(
        manifest["schema"] == "horizon-original154-DATA-lineage-source-inputs-v1"
            && manifest["current_authority"] == json!({"path":c::HEAD,"sha256":c::HEAD_SHA}),
        "lineage head crossed",
    )?;
    let nodes = array(&manifest, "nodes")?;
    let edges = array(&manifest, "edges")?;
    c::need(
        nodes.len() == 70
            && edges.len() == 69
            && nodes[0]["binding"] == manifest["current_authority"]
            && nodes[69]["binding"] == manifest["canonical_booking"],
        "complete exact lineage required",
    )?;
    let mut documents = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, node) in nodes.iter().enumerate() {
        c::need(
            node["index"] == i && seen.insert(c::string(&node["binding"], "path")?.to_owned()),
            "repeated or reordered lineage node",
        )?;
        let actual = c::bound(&node["binding"])?;
        c::need(
            actual["schema"] == node["schema"]
                && data(&actual)? == c::number(node, "complete_DATA_bytes")?,
            "actual node schema or total differs",
        )?;
        documents.push(actual);
    }
    let mut positive = 0i128;
    let mut negative = 0i128;
    for (i, edge) in edges.iter().enumerate() {
        c::need(
            edge["child_index"] == i
                && edge["parent_index"] == i + 1
                && edge["parent_key"] == nodes[i]["parent_key"],
            "lineage edge crossed or omitted",
        )?;
        let child = &documents[i];
        let parent = &documents[i + 1];
        let key = c::string(edge, "parent_key")?;
        c::need(
            child[key] == nodes[i + 1]["binding"],
            "actual hash-bound alias edge differs",
        )?;
        let supports = array(edge, "supporting_bindings")?
            .iter()
            .map(c::bound)
            .collect::<R<Vec<_>>>()?;
        let arithmetic = &edge["arithmetic"];
        let mut total = 0u64;
        for field in array(arithmetic, "fields")? {
            total = total
                .checked_add(amount(
                    child,
                    field.as_str().ok_or("numeric pointer string")?,
                )?)
                .ok_or("edge amount overflow")?;
        }
        if let Some(field) = arithmetic["external_amount_field"].as_str() {
            c::need(supports.len() == 1, "external arithmetic source ambiguity")?;
            total = total
                .checked_add(amount(&supports[0], field)?)
                .ok_or("external amount overflow")?;
        }
        let delta = equation(
            data(parent)?,
            data(child)?,
            c::string(arithmetic, "operation")?,
            total,
        )?;
        c::need(
            edge["signed_delta_bytes"].as_i64().map(i128::from) == Some(delta)
                && c::number(edge, "child_DATA_bytes")? == data(child)?
                && c::number(edge, "parent_DATA_bytes")? == data(parent)?,
            "recorded edge arithmetic differs",
        )?;
        if delta < 0 {
            other_claim(i, child, &supports)?;
            negative += delta;
        } else if delta > 0 {
            c::need(
                child.get("epoch").is_none_or(|e| e != 154)
                    && !child
                        .as_object()
                        .ok_or("node object")?
                        .values()
                        .any(|v| v.as_str() == Some(c::IID)),
                "original154 rebooking in effective chain",
            )?;
            positive += delta;
        }
    }
    c::need(
        positive == 2_084_401_315_840
            && negative == -2_301_968_252_928
            && i128::from(data(&documents[69])?) + positive + negative == i128::from(c::BASE_DATA),
        "full chain sum differs",
    )?;
    let raw = c::bound(&manifest["raw_accounting"])?;
    let projected = array(&raw, "projected_obligations")?;
    let peers = array(&raw, "active_peer_allocations")?;
    let mut keys = BTreeSet::new();
    let mut raw_sum = 0u64;
    let mut target_count = 0;
    for row in projected {
        c::need(
            keys.insert(c::string(row, "claim_key")?),
            "duplicate raw claim",
        )?;
        raw_sum = raw_sum
            .checked_add(c::number(row, "outstanding_bytes")?)
            .ok_or("raw sum overflow")?;
        if row["producer_invocation_id"] == c::IID {
            c::need(
                row["claim_key"] == format!("suffix154/{}", c::IID)
                    && row["epoch"] == 154
                    && row["outstanding_bytes"] == c::OLD_DATA,
                "raw154 charge differs",
            )?;
            target_count += 1;
        }
    }
    c::need(
        projected.len() == 38
            && target_count == 1
            && raw_sum == 5_290_153_274_320
            && raw["protected_existing_DATA_bytes"] == 5_367_462_685_648u64
            && raw_sum.checked_add(72u64 << 30)
                == Some(c::number(&raw, "protected_existing_DATA_bytes")?),
        "complete raw DATA proof differs",
    )?;
    let target_peers = peers
        .iter()
        .filter(|r| r["invocation_id"] == c::IID)
        .collect::<Vec<_>>();
    c::need(
        target_peers.len() == 1
            && target_peers[0]["data_reservation_bytes"] == c::OLD_DATA
            && target_peers[0]["unit"] == c::ACTOR
            && target_peers[0]["memory_max_bytes"] == 0
            && target_peers[0]["remaining_growth_released"] == false,
        "raw same-claim peer differs",
    )?;
    let base = &documents[69];
    let increments = array(base, "positive_increments")?;
    let previous = c::bound(&base["previous"])?;
    let mut external = 0u64;
    let mut increment_keys = BTreeSet::new();
    for row in increments {
        c::need(
            increment_keys.insert(c::string(row, "kind")?)
                && !c::string(row, "kind")?.contains("154"),
            "duplicate or target154 canonical increment",
        )?;
        let source = c::bound(&row["source"])?;
        let amount = source_increment(c::string(row, "kind")?, &source)?;
        c::need(
            amount == c::number(row, "bytes")?,
            "actual canonical increment differs",
        )?;
        external = external
            .checked_add(amount)
            .ok_or("canonical sum overflow")?;
    }
    c::need(
        increments.len() == 9
            && external == 679_347_695_616
            && previous["complete_retained_external_DATA_bytes"] == 752_782_484_322u64
            && base["all_original_raw_rows_and_obligations_retained"] == true
            && base["raw_DATA_bytes"] == raw["protected_existing_DATA_bytes"]
            && base["complete_retained_external_DATA_bytes"] == external + 752_782_484_322
            && data(base)?
                == c::number(base, "raw_DATA_bytes")?
                    + c::number(base, "complete_retained_external_DATA_bytes")?,
        "canonical retained complete booking differs",
    )?;
    Ok(
        json!({"current_authority":manifest["current_authority"],"original_invocation_id":c::IID,"charged_original_DATA_bytes":c::OLD_DATA,"prior_effective_original154_DATA_endings":0,"complete_ancestry_authenticated":true,"manifest":request["manifest"],"authenticated_nodes":70,"authenticated_edges":69,"positive_delta_sum_bytes":positive,"negative_delta_sum_bytes":negative,"raw154_representations_counted_as_one":true,"historical722_duplicate_and_exact_addback_preserved":true,"selection_performed":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_arithmetic_rejects_overflow_and_false_equal() {
        assert!(equation(u64::MAX, 0, "add", 1).is_err());
        assert!(equation(0, 0, "subtract", 1).is_err());
        assert!(equation(1, 1, "equal", 1).is_err());
        assert_eq!(equation(5, 3, "subtract", 2).unwrap(), -2);
    }
    #[test]
    fn unregistered_negative_or_target_claim_rejected() {
        assert!(other_claim(8, &json!({}), &[]).is_err());
        assert!(other_claim(5, &json!({"original_producer_invocation_id":c::IID}), &[]).is_err());
        assert!(
            other_claim(
                5,
                &json!({"original_producer_invocation_id":"722adc397ae24bb4b96d452783599f57"}),
                &[]
            )
            .is_ok()
        );
    }
    #[test]
    fn scalar_never_uses_previous_or_ambiguous_totals() {
        assert!(data(&json!({"previous_complete_DATA_bytes":5})).is_err());
        assert!(
            data(&json!({"complete_DATA_bytes":5,"complete_DATA_lower_bound_bytes":4})).is_err()
        );
        assert_eq!(data(&json!({"complete_DATA_bytes":5})).unwrap(), 5);
    }
}

}
