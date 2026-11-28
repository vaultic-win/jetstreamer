//! Epoch-specific native gates. This module has no fleet/R2 writer or resource-credit path.
#[path = "native_empty_hooks.rs"]
mod native_empty_hooks;
use crate::{
    bounded_resource_runner::{self as engine, Plan, StorageHooks},
    profile::*,
};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch185-cohesive-capped-inputs-20261105-v3";
const MIB: u64 = 1 << 20;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    memory: u64,
    scratch: u64,
    output: u64,
    metadata: u64,
    vmas: u64,
    log: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    plan: Plan,
    admission: Bound,
    actor_service_path: PathBuf,
    guard_service_path: PathBuf,
    timer_service: Bound,
    guard_unit: String,
    timer_unit: String,
    control_root: PathBuf,
    token_root: PathBuf,
    guard_receipt_root: PathBuf,
    self_program: PathBuf,
    self_sha256: String,
    limits: Limits,
    setup_deadline_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: String,
    epoch: u64,
    unit: String,
    task_owner: String,
    phase: String,
    issued_at: u64,
    expires_at: u64,
    minimum_free_bytes: u64,
    memory_max_bytes: u64,
    current_full_reader: Bound,
    current_frame: Bound,
    typed_memory: Bound,
    typed_data: Bound,
    fleet_owner: Bound,
    status_readback: Bound,
    root_acceptance: Bound,
    full_reader_accepted: bool,
    raw_obligations_preserved: bool,
    prefix_only: bool,
    ordinary_full_replay_authorized: bool,
    publication_authorized: bool,
    resource_credit_bytes: u64,
}
static ENVELOPE: OnceLock<Envelope> = OnceLock::new();
struct LogState {
    started: Instant,
    progress: Instant,
    emitted: Instant,
    phase: String,
    wait: String,
}
static LOG: OnceLock<Mutex<LogState>> = OnceLock::new();
fn clock() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn redact(value: &str) -> String {
    value
        .split_whitespace()
        .map(|word| {
            if word.contains("http://") || word.contains("https://") {
                "[URL redacted]"
            } else if [
                "token=",
                "credential",
                "authorization",
                "secret",
                "password",
                "account=",
                "project=",
            ]
            .iter()
            .any(|key| word.to_ascii_lowercase().contains(key))
            {
                "[sensitive field redacted]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
fn emit(kind: &str, detail: &str, advance: bool, force: bool) {
    let log = LOG.get_or_init(|| {
        Mutex::new(LogState {
            started: Instant::now(),
            progress: Instant::now(),
            emitted: Instant::now(),
            phase: "startup".into(),
            wait: String::new(),
        })
    });
    if let Ok(mut state) = log.lock() {
        if advance {
            state.progress = Instant::now();
        }
        if force || state.emitted.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "{}",
                json!({"at_unix_seconds":clock().unwrap_or(0),"epoch":185,"operation":"capped cold root-prefix qualification","phase":state.phase,
                "event":kind,"detail":redact(detail),"awaited_condition":redact(&state.wait),"elapsed_millis":state.started.elapsed().as_millis(),
                "last_substantive_progress_millis_ago":state.progress.elapsed().as_millis(),"heartbeat_advances_work":false})
            );
            state.emitted = Instant::now();
        }
    }
}
pub(crate) fn phase(name: &str, awaited: &str) {
    let log = LOG.get_or_init(|| {
        Mutex::new(LogState {
            started: Instant::now(),
            progress: Instant::now(),
            emitted: Instant::now(),
            phase: String::new(),
            wait: String::new(),
        })
    });
    if let Ok(mut s) = log.lock() {
        s.phase = name.into();
        s.wait = awaited.into();
    }
    emit("phase start", name, true, true);
}
pub(crate) fn progress(detail: &str) {
    emit("progress", detail, true, false);
}
pub(crate) fn heartbeat() {
    emit(
        "heartbeat",
        "waiting or processing; no gate authority",
        false,
        false,
    );
}
pub(crate) fn failed(detail: &str) {
    emit("failure", detail, false, true);
}
pub(crate) fn child_line(line: &str) {
    eprintln!("{}", redact(line));
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn immutable(path: &Path, max: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical immutable path"
    );
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "immutable ancestry changed"
        );
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o7222 == 0
            && before.len() <= max,
        "unsafe immutable evidence"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut bytes)?;
    let after = f.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && identity(&before) == identity(&after)
            && identity(&after) == identity(&named),
        "evidence changed"
    );
    Ok(bytes)
}
// Authenticate PID1's exact manager link without changing the observed native value.
fn manager_fragment_shape(actual: &Path, target: &Path, selected: &Path) -> bool {
    selected.is_absolute()
        && selected.file_name().is_some_and(|name| {
            actual.as_os_str() == Path::new("/etc/systemd/system").join(name).as_os_str()
        })
        && target.as_os_str() == selected.as_os_str()
}
fn verified_fragment(actual: &str, selected: &Path) -> Result<bool> {
    let selected_before = fs::symlink_metadata(selected)?;
    immutable(selected, MIB)?;
    let path = Path::new(actual);
    if path.as_os_str() == selected.as_os_str() {
        ensure!(
            identity(&selected_before) == identity(&fs::symlink_metadata(selected)?),
            "direct unit source changed"
        );
        return Ok(true);
    }
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.file_type().is_symlink()
            && before.uid() == 0
            && before.gid() == 0
            && before.nlink() == 1,
        "untrusted manager unit link"
    );
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "manager unit link ancestry changed"
        );
    }
    let target = fs::read_link(path)?;
    ensure!(
        manager_fragment_shape(path, &target, selected),
        "manager unit link crossed exact source or unit name"
    );
    let after = fs::symlink_metadata(path)?;
    ensure!(
        identity(&before) == identity(&after)
            && after.uid() == 0
            && after.gid() == 0
            && fs::read_link(path)?.as_os_str() == target.as_os_str()
            && identity(&selected_before) == identity(&fs::symlink_metadata(selected)?),
        "manager unit link or bound source changed during authentication"
    );
    Ok(true)
}

fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u32, u64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.mode(),
        m.nlink(),
    )
}
fn bound(b: &Bound, max: u64) -> Result<Vec<u8>> {
    ensure!(hex(&b.sha256, 64), "invalid evidence digest");
    let bytes = immutable(&b.path, max)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == b.sha256,
        "evidence digest mismatch"
    );
    Ok(bytes)
}
fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o7777 == 0o700,
        "private directory changed"
    );
    Ok(())
}
fn persist(path: &Path, value: &Value) -> Result<()> {
    private(path.parent().context("receipt parent")?)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    serde_json::to_writer(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn native(unit: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        unit.starts_with(UNIT_PREFIX) && unit.ends_with(".service")
            || unit.starts_with("horizon-guard-185-capped-cold-")
                && (unit.ends_with(".service") || unit.ends_with(".timer")),
        "foreign native target"
    );
    let output=Command::new("/usr/bin/systemctl").args(["show",unit,"--no-pager","--property=Id,LoadState,InvocationID,MainPID,ControlPID,NRestarts,ActiveState,SubState,Result,ExecMainStatus,ControlGroup,MemoryMax,MemorySwapMax,Restart,Type,FragmentPath,DropInPaths,ExecStart,ExecStartPre,ExecStartPost,ExecStopPost,User,Group,NoNewPrivileges,MemoryAccounting,Unit,Triggers,TriggeredBy,TimersMonotonic,LastTriggerUSecMonotonic,ExecMainStartTimestampMonotonic"])
        .env("LC_ALL","C").env_remove("SYSTEMD_HOST").output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 65536,
        "native query failed"
    );
    let mut result = BTreeMap::new();
    let mut timers = Vec::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native framing")?;
        if k == "TimersMonotonic" && unit.ends_with(".timer") {
            timers.push(v);
        } else {
            ensure!(
                result.insert(k.into(), v.into()).is_none(),
                "duplicate native property"
            );
        }
    }
    if unit.ends_with(".timer") {
        ensure!(
            timers.len() == 2
                && timers
                    .iter()
                    .filter(|v| v.starts_with("{ OnActiveUSec=1s ; next_elapse="))
                    .count()
                    == 1
                && timers
                    .iter()
                    .filter(|v| v.starts_with("{ OnUnitInactiveUSec=30s ; next_elapse="))
                    .count()
                    == 1,
            "foreign, duplicate or missing timer cadence"
        );
        result.insert("TimersMonotonic".into(), timers.join("\n"));
    } else {
        native_empty_hooks::complete_missing(
            unit,
            &["ExecStartPost", "ExecStopPost"],
            &mut result,
        )?;
    }
    Ok(result)
}
fn property<'a>(n: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    n.get(name)
        .map(String::as_str)
        .with_context(|| format!("missing native property {name}"))
}
fn native_command(raw: &str, expected: &[String]) -> Result<()> {
    let (identity, _) = raw
        .split_once(" ; ignore_errors=")
        .context("native command framing")?;
    ensure!(
        identity == format!("{{ path={} ; argv[]={}", expected[0], expected.join(" ")),
        "native command changed"
    );
    Ok(())
}
fn actor_argv(e: &Envelope, plan: &Bound, pre: bool) -> Vec<String> {
    let mut args = vec![e.self_program.to_string_lossy().into_owned()];
    if pre {
        args.push("prestart".into());
    }
    args.extend([
        plan.path.to_string_lossy().into_owned(),
        "--plan-sha256".into(),
        plan.sha256.clone(),
        "--self-sha256".into(),
        e.self_sha256.clone(),
    ]);
    args
}
fn actor_policy(
    e: &Envelope,
    n: &BTreeMap<String, String>,
    iid: &str,
    prestart: bool,
) -> Result<u32> {
    ensure!(
        property(n, "Id")? == e.plan.unit
            && property(n, "LoadState")? == "loaded"
            && property(n, "InvocationID")? == iid
            && hex(iid, 32)
            && property(n, "NRestarts")? == "0"
            && property(n, "Restart")? == "no"
            && property(n, "Type")? == "exec"
            && property(n, "ControlGroup")? == format!("/system.slice/{}", e.plan.unit),
        "native actor identity mismatch"
    );
    ensure!(
        property(n, "User")? == "sol"
            && property(n, "Group")? == "horizon"
            && property(n, "MemoryAccounting")? == "yes"
            && property(n, "NoNewPrivileges")? == "yes"
            && property(n, "ExecStartPost")?.is_empty()
            && property(n, "ExecStopPost")?.is_empty(),
        "actor identity or extra hook changed"
    );
    ensure!(
        property(n, "MemoryMax")?.parse::<u64>()? == e.limits.memory
            && property(n, "MemorySwapMax")? == "0",
        "native memory profile mismatch"
    );
    ensure!(
        verified_fragment(property(n, "FragmentPath")?, &e.actor_service_path)?
            && property(n, "DropInPaths")?.is_empty(),
        "native source changed"
    );
    immutable(&e.actor_service_path, MIB)?;
    let pid = if prestart {
        ensure!(
            property(n, "ActiveState")? == "activating"
                && property(n, "SubState")? == "start-pre"
                && property(n, "MainPID")? == "0",
            "actor is not blocked in start-pre"
        );
        property(n, "ControlPID")?.parse()?
    } else {
        ensure!(
            property(n, "ActiveState")? == "active"
                && property(n, "SubState")? == "running"
                && property(n, "ControlPID")? == "0",
            "actor is not running"
        );
        property(n, "MainPID")?.parse()?
    };
    ensure!(pid > 1, "invalid actor PID");
    Ok(pid)
}
fn ticks(pid: u32) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(')')
        .context("process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("process start")?
        .parse()?)
}
fn proc_identity(pid: u32, e: &Envelope, prestart: bool, plan: &Bound) -> Result<()> {
    let executable = fs::metadata(format!("/proc/{pid}/exe"))?;
    let original = fs::metadata(&e.self_program)?;
    ensure!(
        (executable.dev(), executable.ino()) == (original.dev(), original.ino()),
        "mapped driver mismatch"
    );
    let mut expected = vec![e.self_program.to_string_lossy().to_string()];
    if prestart {
        expected.push("prestart".into());
    }
    expected.extend([
        plan.path.to_string_lossy().into(),
        "--plan-sha256".into(),
        plan.sha256.clone(),
        "--self-sha256".into(),
        e.self_sha256.clone(),
    ]);
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(
        raw.len() <= MIB as usize && raw.last() == Some(&0),
        "cmdline framing"
    );
    let actual = raw[..raw.len() - 1]
        .split(|b| *b == 0)
        .map(|x| std::str::from_utf8(x).map(str::to_owned))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(actual == expected, "driver argv mismatch");
    Ok(())
}
fn admission(e: &Envelope, now: u64) -> Result<Admission> {
    let a: Admission = serde_json::from_slice(&bound(&e.admission, 4 * MIB)?)?;
    admission_policy(&a, e, now)?;
    for b in [
        &a.current_full_reader,
        &a.current_frame,
        &a.typed_memory,
        &a.typed_data,
        &a.fleet_owner,
        &a.status_readback,
        &a.root_acceptance,
    ] {
        bound(b, 4 * MIB)?;
    }
    // This wrapper consumes Root's normal-sealed acceptance, never replaces a typed current reader.
    Ok(a)
}
fn admission_policy(a: &Admission, e: &Envelope, now: u64) -> Result<()> {
    ensure!(
        a.schema == "horizon-epoch185-root-accepted-native-admission-v1"
            && a.epoch == 185
            && a.unit == e.plan.unit
            && !a.task_owner.is_empty()
            && a.phase == "verification"
            && a.issued_at <= now
            && now < a.expires_at
            && a.expires_at - a.issued_at <= MAX_RUNTIME + 600,
        "admission owner or clock mismatch"
    );
    ensure!(
        a.full_reader_accepted
            && a.raw_obligations_preserved
            && a.prefix_only
            && !a.ordinary_full_replay_authorized
            && !a.publication_authorized
            && a.resource_credit_bytes == 0
            && a.minimum_free_bytes == e.plan.minimum_free_bytes
            && a.memory_max_bytes == e.limits.memory,
        "admission scope mismatch"
    );
    Ok(())
}
fn validate_envelope(e: &Envelope) -> Result<()> {
    ensure!(
        e.schema == "horizon-epoch185-guarded-cold-envelope-v4",
        "foreign envelope"
    );
    engine::validate_plan(&e.plan)?;
    ensure!(
        e.plan.node.path == Path::new(PACKAGE).join("jetstreamer-node")
            && e.plan.node.sha256 == PARENT_SHA
            && e.plan.worker == Path::new(PACKAGE).join("jetstreamer-historical-worker-v1-6-15")
            && e.plan.snapshot == Path::new(PACKAGE).join(SNAPSHOT_NAME)
            && e.plan.ledger_directory == Path::new(PACKAGE)
            && e.plan.epoch_hashes.path == Path::new(PACKAGE).join("epoch-hashes-185.txt")
            && e.plan.epoch_hashes.sha256
                == "9ef0d882bf9b530abcd77f8aae199a0c2057c06b32a1d738c7443e3e431606fa",
        "cohesive package paths changed"
    );
    ensure!(
        e.setup_deadline_seconds >= 30
            && e.setup_deadline_seconds <= 600
            && e.limits.memory > 0
            && e.limits.memory <= 195_084_404_736
            && e.limits.scratch > 0
            && e.limits.scratch <= MAX_SCRATCH
            && e.limits.output > 0
            && e.limits.output <= (128u64 << 30)
            && e.limits.metadata >= MIB
            && e.limits.metadata <= 64 * MIB
            && e.limits.log > 0
            && e.limits.log <= 64 * MIB
            && e.limits.vmas > 0
            && e.limits.vmas <= 4_194_304,
        "experimental limits widened"
    );
    ensure!(
        e.control_root.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && e.control_root
                .file_name()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.starts_with("epoch185-cold-control-"))
            && e.token_root
                == Path::new("/usr/local/lib/jetstreamer/horizon-epoch185-cold-gates-v4")
            && e.guard_receipt_root == Path::new("/var/lib/jetstreamer/epoch185-cold-guard-v4"),
        "control namespaces changed"
    );
    ensure!(
        e.guard_unit.starts_with("horizon-guard-185-capped-cold-")
            && e.guard_unit.ends_with(".service")
            && e.guard_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && e.timer_unit == e.guard_unit.replace(".service", ".timer")
            && e.self_program
                .parent()
                .is_some_and(|p| p.starts_with("/usr/local/lib/jetstreamer"))
            && hex(&e.self_sha256, 64),
        "guard or driver namespace mismatch"
    );
    Ok(())
}
fn gate_policy(g: &Value, e: &Envelope, iid: &str, ready: &Value, now: u64) -> Result<()> {
    ensure!(
        g["schema"] == "horizon-epoch185-native-gate-v4"
            && g["epoch"] == 185
            && g["actor_unit"] == e.plan.unit
            && g["actor_invocation_id"] == iid
            && g["admission_sha256"] == e.admission.sha256
            && g["driver_sha256"] == e.self_sha256
            && g["ready_pid"] == ready["pid"]
            && g["ready_start_ticks"] == ready["start_ticks"]
            && g["ready_sha256"] == ready["sha256"]
            && g["guard_unit"] == e.guard_unit
            && g["timer_unit"] == e.timer_unit
            && g["guard_result"]["schema"] == "horizon-epoch185-native-guard-result-v4"
            && g["guard_result"]["success"] == true
            && g["guard_result"]["timer_driven"] == true
            && g["guard_result"]["actor_invocation_id"] == iid
            && g["guard_result"]["admission_sha256"] == e.admission.sha256,
        "gate binding mismatch"
    );
    let issued = g["issued_at"].as_u64().context("gate issue clock")?;
    let expires = g["expires_at"].as_u64().context("gate deadline")?;
    let started = ready["started_at"].as_u64().context("ready clock")?;
    let fire = g["guard_result"]["sampled_at"]
        .as_u64()
        .context("guard clock")?;
    ensure!(
        started <= fire
            && fire <= issued
            && issued <= now
            && now < expires
            && expires <= started + e.setup_deadline_seconds
            && now - fire <= 30,
        "gate deadline or first-fire freshness failed"
    );
    Ok(())
}
fn enrollment_policy(v: &Value, e: &Envelope, iid: &str, ready: &Value, now: u64) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-epoch185-native-owner-enrollment-v4"
            && v["epoch"] == 185
            && v["actor_unit"] == e.plan.unit
            && v["actor_invocation_id"] == iid
            && v["ready_pid"] == ready["pid"]
            && v["ready_start_ticks"] == ready["start_ticks"]
            && v["admission_sha256"] == e.admission.sha256
            && v["restarts"] == 0
            && v["phase"] == "verification"
            && v["root_operator_owner"] == true
            && v["actual_start_pre_evidence_accepted"] == true
            && v["numeric_delivery_eta_millis"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && v["sampled_at"]
                .as_u64()
                .is_some_and(|n| n >= ready["started_at"].as_u64().unwrap_or(u64::MAX)
                    && n <= now
                    && now - n <= 30)
            && v["resource_credit_bytes"] == 0,
        "owner/status/fleet/native acceptance mismatch"
    );
    Ok(())
}
fn load_gate(e: &Envelope, iid: &str, ready: &Value) -> Result<Value> {
    let dir = e.token_root.join(iid);
    let token = dir.join("token.json");
    let bytes = immutable(&token, 4 * MIB)?;
    let seal: Value = serde_json::from_slice(&immutable(
        &dir.join("deployment-seal-receipt.json"),
        4 * MIB,
    )?)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == dir.to_string_lossy().as_ref()
            && seal["members"]
                .as_array()
                .context("gate seal members")?
                .iter()
                .any(|m| m["name"] == "token.json"
                    && m["sha256"] == format!("{:x}", Sha256::digest(&bytes))),
        "gate lacks exact normal seal"
    );
    let g: Value = serde_json::from_slice(&bytes)?;
    gate_policy(&g, e, iid, ready, clock()?)?;
    for key in [
        "task_acknowledgment",
        "status_readback",
        "fleet_enrollment",
        "current_reader_native_acceptance",
    ] {
        let b: Bound = serde_json::from_value(g[key].clone())
            .context("missing actual-IID enrollment evidence")?;
        let v: Value = serde_json::from_slice(&bound(&b, 4 * MIB)?)?;
        enrollment_policy(&v, e, iid, ready, clock()?)?;
        ensure!(v["kind"] == key, "enrollment receipt kind mismatch");
        let underlying: Bound = serde_json::from_value(v["underlying_accepted_proof"].clone())
            .context("missing original accepted enrollment proof")?;
        bound(&underlying, 4 * MIB)?;
    }
    let guard = validate_guard(e)?;
    ensure!(
        property(&guard, "InvocationID")?
            == g["guard_result"]["guard_invocation_id"]
                .as_str()
                .context("guard IID")?
            && property(&guard, "Result")? == "success"
            && property(&guard, "ExecMainStatus")? == "0"
            && property(&guard, "MainPID")? == "0"
            && property(&guard, "ControlPID")? == "0",
        "first guard not actually complete"
    );
    Ok(g)
}
fn validate_guard(e: &Envelope) -> Result<BTreeMap<String, String>> {
    let guard = native(&e.guard_unit)?;
    ensure!(
        property(&guard, "LoadState")? == "loaded"
            && verified_fragment(property(&guard, "FragmentPath")?, &e.guard_service_path)?
            && property(&guard, "DropInPaths")?.is_empty()
            && property(&guard, "Restart")? == "no"
            && property(&guard, "NRestarts")? == "0"
            && property(&guard, "Result")? == "success"
            && property(&guard, "ActiveState")? != "failed"
            && property(&guard, "TriggeredBy")?
                .split_whitespace()
                .any(|u| u == e.timer_unit),
        "guard native source changed"
    );
    immutable(&e.guard_service_path, MIB)?;
    Ok(guard)
}
fn validate_timer(e: &Envelope) -> Result<()> {
    let timer = native(&e.timer_unit)?;
    ensure!(
        property(&timer, "LoadState")? == "loaded"
            && property(&timer, "ActiveState")? == "active"
            && property(&timer, "Unit")? == e.guard_unit
            && verified_fragment(property(&timer, "FragmentPath")?, &e.timer_service.path)?
            && property(&timer, "DropInPaths")?.is_empty(),
        "guard timer changed"
    );
    bound(&e.timer_service, MIB)?;
    validate_guard(e)?;
    Ok(())
}
fn ready_path(e: &Envelope, iid: &str) -> PathBuf {
    e.control_root.join(format!("ready-{iid}.json"))
}
fn read_ready(e: &Envelope, iid: &str) -> Result<Value> {
    private(&e.control_root)?;
    let path = ready_path(e, iid);
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.uid() == unsafe { libc::geteuid() }
            && before.len() <= MIB,
        "ready receipt custody"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f).take(MIB + 1).read_to_end(&mut bytes)?;
    ensure!(
        identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(&path)?),
        "ready receipt drift"
    );
    let mut v: Value = serde_json::from_slice(&bytes)?;
    v["sha256"] = format!("{:x}", Sha256::digest(bytes)).into();
    Ok(v)
}
fn prestart(e: &Envelope, plan: &Bound) -> Result<()> {
    phase(
        "pre-start readiness",
        "exact actor metadata, admission and first genuine timer guard; expiry stops this attempt",
    );
    private(&e.control_root)?;
    let iid = env::var("INVOCATION_ID")?;
    let n = native(&e.plan.unit)?;
    let pid = actor_policy(e, &n, &iid, true)?;
    native_command(property(&n, "ExecStart")?, &actor_argv(e, plan, false))?;
    native_command(property(&n, "ExecStartPre")?, &actor_argv(e, plan, true))?;
    ensure!(pid == std::process::id(), "not the live ControlPID");
    proc_identity(pid, e, true, plan)?;
    admission(e, clock()?)?;
    for (path, length, digest) in [
        (&e.plan.node.path, 48_138_328u64, PARENT_SHA),
        (&e.plan.worker, 8_962_632u64, WORKER),
        (&e.plan.snapshot, SNAPSHOT_SIZE, SNAPSHOT),
    ] {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == *path
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o222 == 0
                && m.len() == length
                && !digest.is_empty(),
            "pre-start exact input metadata failed"
        );
    }
    engine::bound_file(&e.plan.epoch_hashes.path, &e.plan.epoch_hashes.sha256, MIB)?;
    engine::bound_file(
        &Path::new(PACKAGE).join("preflight-185-singleton-v4.json"),
        "01f3be9f86ccf2a39284b0faf11b7910532c2348e2a0801ef1e50a77548d3dc3",
        MIB,
    )?;
    let started = clock()?;
    let ready = json!({"schema":"horizon-epoch185-worker-ready-v4","epoch":185,"actor_unit":e.plan.unit,"actor_invocation_id":iid,"pid":pid,"start_ticks":ticks(pid)?,"started_at":started,"admission_sha256":e.admission.sha256,"driver_sha256":e.self_sha256,"metadata_and_prerequisites_validated":true});
    persist(&ready_path(e, &iid), &ready)?;
    progress("worker ready receipt durably committed after prerequisite validation");
    let deadline = started
        .checked_add(e.setup_deadline_seconds)
        .context("deadline overflow")?;
    loop {
        ensure!(
            clock()? < deadline,
            "pre-start deadline expired; preserve attempt and re-admit distinct retry"
        );
        let n = native(&e.plan.unit)?;
        ensure!(
            actor_policy(e, &n, &iid, true)? == pid
                && ticks(pid)? == ready["start_ticks"].as_u64().unwrap(),
            "pre-start actor changed"
        );
        match fs::symlink_metadata(e.token_root.join(&iid).join("token.json")) {
            Ok(_) => {
                let current = read_ready(e, &iid)?;
                load_gate(e, &iid, &current)?;
                validate_timer(e)?;
                emit(
                    "completion",
                    "exact first-fire gate accepted before useful work",
                    true,
                    true,
                );
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        heartbeat();
        std::thread::sleep(Duration::from_secs(1));
    }
}
fn allocated(root: &Path, maximum: u64) -> Result<u64> {
    let dev = fs::symlink_metadata(root)?.dev();
    let mut pending = vec![(root.to_path_buf(), 0u32)];
    let mut bytes = 0u64;
    let mut entries = 0u64;
    let start = Instant::now();
    while let Some((path, depth)) = pending.pop() {
        ensure!(
            depth <= 64 && entries < 4_000_000 && start.elapsed() < Duration::from_secs(30),
            "guard allocation census bound"
        );
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.dev() == dev && !m.file_type().is_symlink(),
            "guard allocation escaped"
        );
        bytes = bytes
            .checked_add(m.blocks().checked_mul(512).context("allocation overflow")?)
            .context("allocation sum")?;
        ensure!(bytes <= maximum, "allocation ceiling exceeded");
        entries += 1;
        if m.is_dir() {
            for q in fs::read_dir(path)? {
                pending.push((q?.path(), depth + 1));
            }
        } else {
            ensure!(m.is_file(), "foreign scratch object");
        }
        heartbeat();
    }
    Ok(bytes)
}
fn free_bytes(path: &Path) -> Result<u64> {
    let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()))?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0,
        "statvfs failure"
    );
    s.f_bavail
        .checked_mul(s.f_frsize)
        .context("free-byte overflow")
}
fn resource_policy(
    e: &Envelope,
    free: u64,
    memory: u64,
    scratch: u64,
    output: u64,
    metadata: u64,
    vmas: u64,
) -> Result<()> {
    ensure!(free >= e.plan.minimum_free_bytes, "DATA floor failed");
    ensure!(memory <= e.limits.memory, "memory stop ceiling failed");
    ensure!(scratch <= e.limits.scratch, "scratch ceiling failed");
    ensure!(output <= e.limits.output, "output ceiling failed");
    ensure!(metadata <= e.limits.metadata, "metadata ceiling failed");
    ensure!(vmas <= e.limits.vmas, "VMA stop ceiling failed");
    Ok(())
}
fn resource_check(e: &Envelope) -> Result<Value> {
    ensure!(
        free_bytes(&e.plan.run_root)? >= e.plan.minimum_free_bytes,
        "DATA floor failed"
    );
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(&e.plan.unit);
    let memory = fs::read_to_string(cg.join("memory.current"))?
        .trim()
        .parse::<u64>()?;
    ensure!(memory <= e.limits.memory, "memory stop ceiling failed");
    let scratch = allocated(&e.plan.run_root.join("scratch"), e.limits.scratch)?
        .checked_add(allocated(
            &e.plan.run_root.join("ledger"),
            e.limits.scratch,
        )?)
        .context("scratch and ledger overflow")?;
    let output = allocated(&e.plan.run_root.join("output"), e.limits.output)?;
    let metadata = allocated(&e.control_root, e.limits.metadata)?
        .checked_add(allocated(
            &e.plan.run_root.join("receipts"),
            e.limits.metadata,
        )?)
        .context("metadata sum overflow")?;
    let log_path = e.control_root.join("private-stdout-stderr.log");
    if let Ok(m) = fs::symlink_metadata(&log_path) {
        ensure!(
            m.is_file() && !m.file_type().is_symlink() && m.len() <= e.limits.log,
            "private log ceiling failed"
        );
    }
    let mut max_vmas = 0usize;
    let pids = fs::read_to_string(cg.join("cgroup.procs"))?;
    for pid in pids.lines() {
        let pid = pid.parse::<u32>()?;
        let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
        max_vmas = max_vmas.max(maps.lines().count());
    }
    ensure!(max_vmas as u64 <= e.limits.vmas, "VMA stop ceiling failed");
    resource_policy(
        e,
        free_bytes(&e.plan.run_root)?,
        memory,
        scratch,
        output,
        metadata,
        max_vmas as u64,
    )?;
    Ok(
        json!({"memory_bytes":memory,"scratch_allocated_bytes":scratch,"output_allocated_bytes":output,"metadata_allocated_bytes":metadata,"maximum_process_vmas":max_vmas,"free_bytes":free_bytes(&e.plan.run_root)?}),
    )
}
fn monotonic_micros() -> Result<u64> {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } == 0,
        "monotonic clock failed"
    );
    Ok((t.tv_sec as u64) * 1_000_000 + (t.tv_nsec as u64) / 1_000)
}
// systemctl prints timer usec values as exact native timespans, while its
// ExecMainStartTimestampMonotonic property remains a raw microsecond integer.
// No floating point, truncation, saturating arithmetic or unknown units.
fn native_timer_micros(raw: &str) -> Result<u64> {
    ensure!(
        !raw.is_empty() && raw.len() <= 128 && raw.is_ascii() && raw.trim() == raw,
        "native timer timespan framing"
    );
    let value = if raw.bytes().all(|b| b.is_ascii_digit()) {
        raw.parse::<u64>()?
    } else {
        let mut total = 0u64;
        let mut previous_rank = 8u8;
        for token in raw.split(' ') {
            let at = token
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .context("native timer timespan unit")?;
            let (number, unit) = token.split_at(at);
            let (rank, multiplier) = match unit {
                "w" => (7, 604_800_000_000u64),
                "d" => (6, 86_400_000_000),
                "h" => (5, 3_600_000_000),
                "min" => (4, 60_000_000),
                "s" => (3, 1_000_000),
                "ms" => (2, 1_000),
                "us" => (1, 1),
                _ => anyhow::bail!("unsupported native timer timespan unit"),
            };
            ensure!(
                rank < previous_rank,
                "native timer units duplicated or out of order"
            );
            previous_rank = rank;
            let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
            ensure!(
                !whole.is_empty()
                    && whole.bytes().all(|b| b.is_ascii_digit())
                    && fraction.len() <= 6
                    && fraction.bytes().all(|b| b.is_ascii_digit())
                    && (!number.contains('.') || !fraction.is_empty()),
                "native timer decimal spelling"
            );
            let integer = whole
                .parse::<u64>()?
                .checked_mul(multiplier)
                .context("native timer integer overflow")?;
            let fractional = if fraction.is_empty() {
                0
            } else {
                let numerator = fraction
                    .parse::<u64>()?
                    .checked_mul(multiplier)
                    .context("native timer fraction overflow")?;
                let scale = 10u64.pow(fraction.len() as u32);
                ensure!(
                    numerator.is_multiple_of(scale),
                    "native timer sub-microsecond value"
                );
                numerator / scale
            };
            total = total
                .checked_add(integer)
                .and_then(|v| v.checked_add(fractional))
                .context("native timer timespan sum overflow")?;
        }
        total
    };
    ensure!(
        value > 0 && value != u64::MAX,
        "native timer trigger must be finite positive"
    );
    Ok(value)
}
fn timer_activation_fresh(trigger: u64, begin: u64, at: u64) -> Result<()> {
    ensure!(
        trigger > 0
            && trigger != u64::MAX
            && begin > 0
            && begin
                .checked_sub(trigger)
                .is_some_and(|gap| gap <= 5_000_000)
            && at.checked_sub(begin).is_some_and(|age| age <= 90_000_000),
        "not a fresh timer-driven native activation"
    );
    Ok(())
}
fn guard_once(e: &Envelope, plan: &Bound) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "external native guard must run as root"
    );
    phase(
        "native timer guard",
        "complete current admission, exact actor and bounded resource safety",
    );
    let actor = native(&e.plan.unit)?;
    let iid = property(&actor, "InvocationID")?.to_owned();
    let pre = property(&actor, "ActiveState")? == "activating";
    let actor_pid = actor_policy(e, &actor, &iid, pre)?;
    native_command(property(&actor, "ExecStart")?, &actor_argv(e, plan, false))?;
    native_command(
        property(&actor, "ExecStartPre")?,
        &actor_argv(e, plan, true),
    )?;
    proc_identity(actor_pid, e, pre, plan)?;
    let own = validate_guard(e)?;
    let mut guard_args = actor_argv(e, plan, false);
    guard_args.insert(1, "guard".into());
    native_command(property(&own, "ExecStart")?, &guard_args)?;
    let own_iid = env::var("INVOCATION_ID")?;
    ensure!(
        property(&own, "InvocationID")? == own_iid
            && (property(&own, "MainPID")?.parse::<u32>()? == std::process::id()
                || property(&own, "ControlPID")?.parse::<u32>()? == std::process::id()),
        "not actual native guard owner"
    );
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    ensure!(
        membership.trim() == format!("0::/system.slice/{}", e.guard_unit),
        "foreign guard cgroup"
    );
    validate_timer(e)?;
    let timer = native(&e.timer_unit)?;
    let trigger_raw = property(&timer, "LastTriggerUSecMonotonic")?;
    let begin_raw = property(&own, "ExecMainStartTimestampMonotonic")?;
    let trigger = native_timer_micros(trigger_raw)?;
    let begin = begin_raw.parse::<u64>()?;
    timer_activation_fresh(trigger, begin, monotonic_micros()?)?;
    let outcome = (|| -> Result<Value> {
        admission(e, clock()?)?;
        let data = resource_check(e)?;
        let after = native(&e.plan.unit)?;
        ensure!(
            actor_policy(e, &after, &iid, pre)? == actor_pid,
            "guard actor changed"
        );
        Ok(data)
    })();
    private(&e.guard_receipt_root)?;
    let receipt = json!({"schema":"horizon-epoch185-native-guard-result-v4","epoch":185,"actor_unit":e.plan.unit,"actor_invocation_id":iid,"actor_pid":actor_pid,"actor_start_ticks":ticks(actor_pid)?,"guard_invocation_id":own_iid,"timer_unit":e.timer_unit,"timer_driven":true,"timer_last_trigger_monotonic_micros":trigger,"guard_start_monotonic_micros":begin,"timer_last_trigger_native_property":trigger_raw,"guard_start_native_property":begin_raw,"admission_sha256":e.admission.sha256,"sampled_at":clock()?,"success":outcome.is_ok(),"resource_sample":outcome.as_ref().ok(),"failure":outcome.as_ref().err().map(|err|redact(&format!("{err:#}"))),"capacity_credit_bytes":0});
    persist(
        &e.guard_receipt_root.join(format!("guard-{own_iid}.json")),
        &receipt,
    )?;
    if let Err(error) = outcome {
        persist(
            &e.guard_receipt_root
                .join(format!("stop-intent-{own_iid}.json")),
            &json!({"actor_unit":e.plan.unit,"actor_invocation_id":iid,"reason":"exact admitted actor guard failed","receipt":format!("guard-{own_iid}.json"),"at":clock()?}),
        )?;
        // Recheck the exact invocation immediately before issuing the only service mutation.
        ensure!(
            property(&native(&e.plan.unit)?, "InvocationID")? == iid,
            "actor changed before owned stop"
        );
        let stopped = Command::new("/usr/bin/systemctl")
            .args(["stop", "--no-block", &e.plan.unit])
            .env_remove("SYSTEMD_HOST")
            .status()?;
        ensure!(stopped.success(), "owned guard stop request failed");
        return Err(error);
    }
    println!("{}", receipt);
    emit(
        "completion",
        "native timer guard succeeded with no resource credit",
        true,
        true,
    );
    Ok(())
}
struct Guarded {
    last: Mutex<Instant>,
}
impl StorageHooks for Guarded {
    fn decode_plan(&self, bytes: &[u8]) -> Result<Plan> {
        let e: Envelope = serde_json::from_slice(bytes)?;
        validate_envelope(&e)?;
        let p = e.plan.clone();
        ensure!(ENVELOPE.set(e).is_ok(), "envelope loaded twice");
        Ok(p)
    }
    fn initial_gate(&self, _p: &Plan, iid: &str) -> Result<()> {
        let e = ENVELOPE.get().context("missing envelope")?;
        let a = admission(e, clock()?)?;
        ensure!(a.expires_at > clock()?, "expired admission");
        let n = native(&e.plan.unit)?;
        ensure!(
            actor_policy(e, &n, iid, false)? == std::process::id(),
            "not actual native owner"
        );
        let plan = cli(None)?.0;
        proc_identity(std::process::id(), e, false, &plan)?;
        let ready = read_ready(e, iid)?;
        load_gate(e, iid, &ready)?;
        validate_timer(e)?;
        resource_check(e)?;
        progress("native owner, full-reader admission and first-fire gate accepted");
        Ok(())
    }
    fn prepare(&self, _p: &Plan) -> Result<()> {
        let e = ENVELOPE.get().context("missing envelope")?;
        admission(e, clock()?)?;
        validate_timer(e)?;
        resource_check(e)?;
        Ok(())
    }
    fn configure_command(&self, _p: &Plan, cmd: &mut Command) -> Result<()> {
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1")
            .env(
                WORKER_ENV,
                Path::new(PACKAGE).join("jetstreamer-historical-worker-v1-6-15"),
            )
            .env("JETSTREAMER_ARCHIVE_BACKEND", "http")
            .env(
                "JETSTREAMER_HTTP_BASE_URL",
                "https://files.old-faithful.net/",
            )
            .env(
                "JETSTREAMER_COMPACT_INDEX_BASE_URL",
                "https://files.old-faithful.net/",
            )
            .env("JETSTREAMER_HISTORICAL_POH_THREADS", "10")
            .env("JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS", "600")
            .env("JETSTREAMER_VERIFY_SNAPSHOTS", "1")
            .env("JETSTREAMER_SKIP_SNAPSHOT_VERIFY", "0")
            .env("JETSTREAMER_LOAD_FROM_DIR", "0")
            .env("JETSTREAMER_ENFORCE_ARCHIVE_HASH", "1")
            .env("SOLANA_RAYON_THREADS", "8")
            .env("RAYON_NUM_THREADS", "8")
            .env("RUST_LOG", "info");
        Ok(())
    }
    fn before_spawn(&self, _p: &Plan, iid: &str) -> Result<Value> {
        let e = ENVELOPE.get().context("missing envelope")?;
        admission(e, clock()?)?;
        let n = native(&e.plan.unit)?;
        actor_policy(e, &n, iid, false)?;
        validate_timer(e)?;
        resource_check(e)
    }
    fn guard(
        &self,
        _p: &Plan,
        iid: &str,
        _child: u32,
        _elapsed: Duration,
        _draining: bool,
    ) -> Result<()> {
        heartbeat();
        let mut last = self
            .last
            .lock()
            .map_err(|_| anyhow::anyhow!("guard clock poisoned"))?;
        if last.elapsed() < Duration::from_secs(5) {
            return Ok(());
        }
        *last = Instant::now();
        let e = ENVELOPE.get().context("missing envelope")?;
        let check = (|| {
            admission(e, clock()?)?;
            let n = native(&e.plan.unit)?;
            actor_policy(e, &n, iid, false)?;
            validate_timer(e)?;
            resource_check(e)
        })();
        if let Err(error) = check {
            persist(
                &e.plan.run_root.join("receipts/owned-guard-stop.json"),
                &json!({"schema":"horizon-epoch185-owned-guard-stop-v4","actor_invocation_id":iid,"reason":redact(&format!("{error:#}")),"at":clock()?,"capacity_credit_bytes":0}),
            )?;
            return Err(error);
        }
        Ok(())
    }
}
fn cli(mode: Option<&str>) -> Result<(Bound, String)> {
    let a: Vec<_> = env::args().collect();
    let offset = usize::from(mode.is_some());
    ensure!(
        a.len() == 6 + offset
            && mode.is_none_or(|m| a[1] == m)
            && a[2 + offset] == "--plan-sha256"
            && a[4 + offset] == "--self-sha256",
        "usage: [prestart|guard] PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        hex(&a[3 + offset], 64) && hex(&a[5 + offset], 64),
        "CLI digest"
    );
    Ok((
        Bound {
            path: PathBuf::from(&a[1 + offset]),
            sha256: a[3 + offset].clone(),
        },
        a[5 + offset].clone(),
    ))
}
pub(crate) fn dispatch() -> Result<()> {
    let mode = env::args()
        .nth(1)
        .filter(|m| m == "prestart" || m == "guard");
    let (plan, self_hash) = cli(mode.as_deref())?;
    let e: Envelope = serde_json::from_slice(&bound(&plan, 4 * MIB)?)?;
    validate_envelope(&e)?;
    ensure!(
        e.self_sha256 == self_hash,
        "self digest differs from envelope"
    );
    engine::bound_file(&fs::read_link("/proc/self/exe")?, &self_hash, 256 * MIB)?;
    if mode.as_deref() == Some("prestart") {
        return prestart(&e, &plan);
    }
    if mode.as_deref() == Some("guard") {
        return guard_once(&e, &plan);
    }
    let hooks = Guarded {
        last: Mutex::new(Instant::now() - Duration::from_secs(5)),
    };
    engine::execute_with_storage(&hooks)?;
    emit(
        "completion",
        "bounded canonical prefix completed; 716 suffix slots remain",
        true,
        true,
    );
    Ok(())
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod fragment_link_regressions {
    use super::*;
    #[test]
    fn exact_manager_name_and_absolute_sealed_target_are_required() {
        let selected = Path::new("/usr/local/lib/jetstreamer/package/actor.service");
        assert!(manager_fragment_shape(
            Path::new("/etc/systemd/system/actor.service"),
            selected,
            selected
        ));
        assert!(!manager_fragment_shape(
            Path::new("/etc/systemd/system/other.service"),
            selected,
            selected
        ));
        assert!(!manager_fragment_shape(
            Path::new("/etc/systemd/system/actor.service"),
            Path::new("/usr/local/lib/jetstreamer/foreign/actor.service"),
            selected
        ));
    }
    #[test]
    fn relative_and_lexically_normalized_targets_do_not_gain_authority() {
        let selected = Path::new("/usr/local/lib/jetstreamer/package/actor.service");
        let actual = Path::new("/etc/systemd/system/actor.service");
        for target in [
            "../../../usr/local/lib/jetstreamer/package/actor.service",
            "/usr/local/lib/jetstreamer/package/./actor.service",
            "/usr/local/lib/jetstreamer/other/../package/actor.service",
        ] {
            assert!(!manager_fragment_shape(actual, Path::new(target), selected));
        }
    }
    #[test]
    fn foreign_manager_namespaces_and_raw_path_aliases_are_rejected() {
        let selected = Path::new("/usr/local/lib/jetstreamer/package/actor.service");
        for actual in [
            "/run/systemd/system/actor.service",
            "/etc/systemd/system/./actor.service",
            "/etc/systemd/system//actor.service",
            "/tmp/actor.service",
        ] {
            assert!(!manager_fragment_shape(
                Path::new(actual),
                selected,
                selected
            ));
        }
    }
    #[test]
    #[ignore = "Reads the actual Root-sealed dormant v9 unit sources and manager links; no activation or mutation."]
    fn actual_normal_sealed_v9_links_pass_without_unit_activation() {
        let root = Path::new(
            "/usr/local/lib/jetstreamer/horizon-epoch185-missing-token-native-units-20261105-v9",
        );
        for name in [
            "horizon-qualify-185-capped-cold-missing-token-20261105-v9.service",
            "horizon-guard-185-capped-cold-missing-token-20261105-v9.service",
            "horizon-guard-185-capped-cold-missing-token-20261105-v9.timer",
        ] {
            let actual = Path::new("/etc/systemd/system").join(name);
            assert!(verified_fragment(actual.to_str().unwrap(), &root.join(name)).unwrap());
        }
    }
}
