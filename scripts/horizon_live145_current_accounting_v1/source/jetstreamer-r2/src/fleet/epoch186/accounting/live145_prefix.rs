//! Additive accounting for the exact healthy v8g1 private exporter.
//! This authenticates the already admitted actor; it never launches, writes,
//! publishes, restarts, retires or renews its original admission/deadline.
use super::*;
#[allow(dead_code)]
#[path = "live145_prefix/custody.rs"]
mod custody;
#[allow(dead_code)]
#[path = "live145_prefix/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "live145_prefix/native.rs"]
mod native;

pub(super) const ACTOR: &str = "horizon-extract145-prefix-shared72h-20261107-v8g1.service";
pub(super) const GUARD: &str = "horizon-guard145-prefix-shared72h-20261107-v8g1.service";
pub(super) const TIMER: &str = "horizon-guard145-prefix-shared72h-20261107-v8g1.timer";
const IID: &str = "f37b155136614e0183ba2e9adb8714ef";
const TIMER_IID: &str = "f6f2308db2dc47be8f470030fb587b90";
const PLAN: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-plan-shared72h-20261107-v8g1/plan.json";
const PLAN_SHA: &str = "c1a7b5fcad8aa850be48a811fdfa7f703aa162d615070689fbba68f8f025dcf3";
const PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-tools-20261107-v8/epoch145-prefix-extract";
const PROGRAM_SHA: &str = "b416b7c932ef781c8d0f863b63b803379dd58cb1affe99dced6a61830a95ad76";
const STATE: &str =
    "/home/sol/.jetstreamer-private/epoch145-prefix-extract-shared72h-20261107-v8g1-state";
pub(super) const MEMORY: u64 = (80 << 30) + (256 << 20);
pub(super) const DATA: u64 = (160 << 30) + (128 << 20) + RETAINED_185_SOURCE_DATA;
pub(super) const DATA_FLOOR: u64 = 5_074_152_197_938;
pub(super) const MEMORY_FLOOR: u64 = 642_177_138_688;
pub(super) const CPU: u64 = 9_000_000;
// Already booked source DATA is retained independently of the exporter output.
const RETAINED_185_SOURCE_DATA: u64 = 4 << 30;
const SOURCE_BOOKING: &str = "/home/sol/.jetstreamer-private/epoch185-positive-current-reader-integration-source-20261107-v1/SOURCE_ONLY_COPY_BOOKING.json";
const SOURCE_BOOKING_SHA: &str = "69a2b96fc43a742d599f87391c683e6a91130172b4d4465657d681afe7aab370";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selector {
    plan: BoundFile,
    ready: BoundFile,
    admission: BoundFile,
    guard_before_source: BoundFile,
}
fn old(b: &BoundFile) -> model::Bound {
    model::Bound {
        path: b.path.clone(),
        sha256: b.sha256.clone(),
    }
}
fn value(b: &BoundFile, immutable: bool) -> Result<Value> {
    io::unique_json(&custody::bytes(&old(b), 8 << 20, immutable)?)
}
fn exact(s: &Selector) -> Result<()> {
    for (bound, path, sha) in [
        (&s.plan, PLAN.to_owned(), PLAN_SHA),
        (
            &s.ready,
            format!("{STATE}/ready.json"),
            "d8cd0712b4ee180fa10d3d977b6981a40846d7cd5f78698fd4a0bf9ad938457b",
        ),
        (
            &s.admission,
            format!("{STATE}/admission.json"),
            "eecfdac8d2b968979c3bf541d75b5362d6b223b8d58da17600b7c4af25664c02",
        ),
        (
            &s.guard_before_source,
            format!("{STATE}/guard-before-source-read.json"),
            "3410e0ea3c4fbbfe911185e893f9c79eb246a6cf419ecea7f567ac03ae79c53d",
        ),
    ] {
        ensure!(
            bound.path == Path::new(&path) && bound.sha256 == sha,
            "live145 selector crosses original v8g1 evidence"
        );
    }
    Ok(())
}
fn token(
    t: &model::Token,
    p: &model::Plan,
    a: &model::Admission,
    pb: &model::Bound,
    ab: &model::Bound,
    clock: u64,
    boot: u64,
) -> Result<()> {
    ensure!(
        t.schema == "horizon-epoch145-private-extractor-native-guard-token-v1"
            && t.plan == *pb
            && t.admission == *ab
            && t.actor_iid == IID
            && t.actor_iid == a.actor_iid
            && t.actor_pid == a.actor_pid
            && t.actor_start_ticks == a.actor_start_ticks
            && custody::hex(&t.guard_iid, 32)
            && t.guard_pid > 1
            && t.guard_start_ticks > 0
            && t.at_unix_seconds >= a.accepted_at
            && t.at_unix_seconds <= clock
            && t.at_boottime_millis >= a.accepted_boottime_millis
            && t.at_boottime_millis <= boot
            && boot
                .checked_sub(t.at_boottime_millis)
                .is_some_and(|n| n <= 90_000)
            && t.protected_free_bytes == DATA_FLOOR
            && t.protected_free_bytes == p.minimum_free_bytes.max(a.required_initial_data_bytes)
            && t.protected_available_memory_bytes == MEMORY_FLOOR
            && t.protected_available_memory_bytes
                == p.minimum_available_memory_bytes
                    .max(a.required_initial_memory_bytes)
            && t.actual_free_bytes >= t.protected_free_bytes
            && t.actual_available_memory_bytes >= t.protected_available_memory_bytes,
        "live145 crossed, stale, future, lowered-floor or failed token"
    );
    Ok(())
}
fn command(mode: &str) -> String {
    format!(
        "{{ path={PROGRAM} ; argv[]={PROGRAM} {mode} {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {PROGRAM_SHA} ;"
    )
}
fn guard_native(v: &Value) -> Result<()> {
    let expected_guard_memory = (256u64 << 20).to_string();
    ensure!(
        v["Id"] == GUARD
            && v["LoadState"] == "loaded"
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Type"] == "exec"
            && v["User"] == "root"
            && v["MemoryMax"].as_str() == Some(expected_guard_memory.as_str())
            && v["MemorySwapMax"] == "0"
            && v["TasksMax"] == "512"
            && v["CPUQuotaPerSecUSec"] == "1s"
            && v["InvocationID"]
                .as_str()
                .is_some_and(|s| custody::hex(s, 32))
            && v["ExecStart"].as_str().is_some_and(
                |s| s.starts_with(&command("guard")) && s.matches("argv[]=").count() == 1
            ),
        "live145 foreign periodic guard command or kernel limits"
    );
    let active = v["ActiveState"] == "active"
        && v["SubState"] == "running"
        && v["MainPID"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|n| n > 1)
        && v["ControlGroup"] == format!("/system.slice/{GUARD}");
    let completed = v["ActiveState"] == "inactive"
        && v["SubState"] == "dead"
        && v["MainPID"] == "0"
        && v["ControlGroup"] == ""
        && v["Result"] == "success"
        && v["ExecMainCode"] == "1"
        && v["ExecMainStatus"] == "0";
    ensure!(
        active || completed,
        "live145 guard failed, queued, restarting or unknown lifecycle"
    );
    Ok(())
}
fn timer_native(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == TIMER
            && v["LoadState"] == "loaded"
            && v["InvocationID"] == TIMER_IID
            && v["ActiveState"] == "active"
            && matches!(v["SubState"].as_str(), Some("waiting" | "running"))
            && v["Triggers"] == GUARD,
        "live145 timer changed identity or is unarmed"
    );
    Ok(())
}
fn actor_native(v: &Value, a: &model::Admission) -> Result<()> {
    let expected_pid = a.actor_pid.to_string();
    let expected_actor_memory = (80u64 << 30).to_string();
    ensure!(
        v["Id"] == ACTOR
            && v["InvocationID"] == IID
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"].as_str() == Some(expected_pid.as_str())
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Type"] == "exec"
            && v["MemoryMax"].as_str() == Some(expected_actor_memory.as_str())
            && v["MemorySwapMax"] == "0"
            && v["TasksMax"] == "512"
            && v["CPUQuotaPerSecUSec"] == "8s"
            && v["ExecStart"].as_str().is_some_and(
                |s| s.starts_with(&command("extract")) && s.matches("argv[]=").count() == 1
            ),
        "live145 exporter owner, command, restart or hard bounds changed"
    );
    Ok(())
}
fn plan_shape(
    p: &model::Plan,
    a: &model::Admission,
    ready: &Value,
    before: &Value,
    pb: &model::Bound,
    ab: &model::Bound,
    clock: u64,
) -> Result<()> {
    ensure!(
        p.schema == "horizon-epoch145-private-prefix-extractor-plan-v1"
            && p.actor_unit == ACTOR
            && p.guard_unit == GUARD
            && p.timer_unit == TIMER
            && p.program.path == Path::new(PROGRAM)
            && p.program.sha256 == PROGRAM_SHA
            && p.actor_memory_bytes == 80u64 << 30
            && p.guard_memory_bytes == 256u64 << 20
            && p.external_pool_bytes == 6u64 << 30
            && p.output_maximum_bytes == 160u64 << 30
            && p.minimum_free_bytes == DATA_FLOOR
            && p.minimum_available_memory_bytes == MEMORY_FLOOR
            && p.source.path == Path::new(model::SOURCE)
            && p.source.sha256 == model::SOURCE_SHA
            && p.manifest.path == Path::new(model::MANIFEST)
            && p.manifest.sha256 == model::MANIFEST_SHA
            && p.execution_deadline == 1_794_296_895
            && clock <= p.execution_deadline
            && a.schema == "horizon-epoch145-private-extraction-typed-admission-v1"
            && a.plan == *pb
            && a.actor_unit == ACTOR
            && a.actor_iid == IID
            && a.accepted_at >= p.issued_at
            && a.accepted_at <= p.entry_deadline
            && a.required_initial_memory_bytes <= MEMORY_FLOOR
            && a.required_initial_data_bytes <= DATA_FLOOR
            && ready["schema"] == "horizon-epoch145-private-extractor-ready-v1"
            && ready["plan"] == json!(pb)
            && ready["admission"] == json!(ab)
            && ready["actor_iid"] == IID
            && ready["actor_pid"] == a.actor_pid
            && ready["actor_start_ticks"] == a.actor_start_ticks
            && ready["archive_body_reads_started"] == false
            && before["schema"] == "horizon-epoch145-actual-pre-read-guard-v1"
            && before["plan"] == json!(pb)
            && before["admission"] == json!(ab),
        "live145 original plan/readiness/admission/source custody changed"
    );
    let initial: model::Token = serde_json::from_value(before["token"].clone())?;
    ensure!(
        initial.at_unix_seconds <= p.entry_deadline,
        "live145 first guard missed original entry"
    );
    token(
        &initial,
        p,
        a,
        pb,
        ab,
        initial.at_unix_seconds,
        initial.at_boottime_millis,
    )
}
fn sealed_program(p: &model::Plan) -> Result<()> {
    custody::bytes(&p.program, 128 << 20, true)?;
    let seal = custody::json(&p.program_seal, true)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"]
                == p.program
                    .path
                    .parent()
                    .context("live145 program parent")?
                    .to_string_lossy()
                    .as_ref()
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .filter(|r| r["name"] == "epoch145-prefix-extract"
                    && r["sha256"] == PROGRAM_SHA
                    && r["mode"] == "0555")
                .count()
                == 1),
        "live145 actual program seal differs"
    );
    Ok(())
}
fn peer(s: &Selector, p: &model::Plan, actor: &Value) -> Value {
    json!({"unit":ACTOR,"invocation_id":IID,"state":"active-private-canonical-prefix-export",
        "memory_max_bytes":MEMORY,"actual_actor_memory_hard_limit_bytes":80u64<<30,
        "reserved_guard_memory_bytes":256u64<<20,"data_reservation_bytes":DATA,
        "native_pool_suballocation":false,"external_pool_charged_by_this_peer_bytes":0,
        "guard_unit":GUARD,"timer_unit":TIMER,"timer_invocation_id":TIMER_IID,
        "guard_floor_bytes":DATA_FLOOR,"minimum_available_memory_bytes":MEMORY_FLOOR,
        "live145_prefix_export":binding(&s.plan),"source_bindings":[binding(&s.plan),binding(&s.ready),binding(&s.admission),binding(&s.guard_before_source),json!(p.program),json!(p.program_seal),json!({"path":SOURCE_BOOKING,"sha256":SOURCE_BOOKING_SHA})],
        "retained185_source_DATA_bytes":RETAINED_185_SOURCE_DATA,"output_DATA_bytes":160u64<<30,"metadata_DATA_bytes":128u64<<20,
        "original_source":p.source,"original_failed_partial_retained_bytes":41_966_206_710u64,
        "original_failed_output_reservation_retained_bytes":160u64<<30,
        "no_original_source_or_failed_attempt_credit":true,"credit_bytes":0,
        "resource_release_qualified":false,"native":actor})
}
pub(super) fn peer_shape(v: &Value) -> Result<()> {
    ensure!(
        v["unit"] == ACTOR
            && v["invocation_id"] == IID
            && v["memory_max_bytes"] == MEMORY
            && v["data_reservation_bytes"] == DATA
            && v["reserved_guard_memory_bytes"] == 256u64 << 20
            && v["actual_actor_memory_hard_limit_bytes"] == 80u64 << 30
            && v["native_pool_suballocation"] == false
            && v["external_pool_charged_by_this_peer_bytes"] == 0
            && v["guard_floor_bytes"] == DATA_FLOOR
            && v["minimum_available_memory_bytes"] == MEMORY_FLOOR
            && v["credit_bytes"] == 0
            && v["resource_release_qualified"] == false
            && v["live145_prefix_export"] == json!({"path":PLAN,"sha256":PLAN_SHA}),
        "live145 peer omits, aliases, releases or double-charges an independent promise"
    );
    Ok(())
}
fn required_selector(selected: bool, deployed: bool) -> Result<()> {
    ensure!(
        selected || !deployed,
        "deployed live145 attempt requires explicit accounting, including after terminality; no implicit debt release"
    );
    Ok(())
}
pub(super) fn actual(selector: Option<&Selector>, clock: u64) -> Result<Option<Value>> {
    let deployed = match fs::symlink_metadata(PLAN) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    required_selector(selector.is_some(), deployed)?;
    let Some(s) = selector else {
        return Ok(None);
    };
    exact(s)?;
    let source_booking = protected_generated(&BoundFile {
        path: SOURCE_BOOKING.into(),
        sha256: SOURCE_BOOKING_SHA.into(),
    })?;
    ensure!(
        source_booking["additional_whole_phase_DATA_allowance_bytes"] == RETAINED_185_SOURCE_DATA
            && source_booking["future_admission_must_add_this_DATA_once"] == true
            && source_booking["normal_pool_bytes_retained"] == 6u64 << 30,
        "live145 independent185 source DATA promise changed"
    );
    let raw_plan = value(&s.plan, true)?;
    let p: model::Plan = serde_json::from_value(raw_plan)?;
    let a: model::Admission = serde_json::from_value(value(&s.admission, false)?)?;
    let ready = value(&s.ready, false)?;
    let before = value(&s.guard_before_source, false)?;
    let pb = old(&s.plan);
    // The actor sees the immutable /var/lib projection; the reader uses its
    // canonical /home backing without requiring a privileged remount.
    let ab = model::Bound {
        path: p.state_root.join("admission.json"),
        sha256: s.admission.sha256.clone(),
    };
    plan_shape(&p, &a, &ready, &before, &pb, &ab, clock)?;
    sealed_program(&p)?;
    ensure!(
        custody::frozen_identity(&p.source.path)? == p.source_identity
            && custody::frozen_identity(&p.manifest.path)? == p.manifest_identity,
        "live145 retained source/manifest metadata changed"
    );
    for (path, identity) in [
        (Path::new(STATE), &p.state_directory_identity),
        (p.output_root.as_path(), &p.output_directory_identity),
    ] {
        custody::private_directory(path)?;
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.dev() == identity.device
                && m.ino() == identity.inode
                && m.dev() == fs::metadata("/home/sol")?.dev(),
            "live145 state/output inode or budget filesystem changed"
        );
    }
    for name in [
        "extraction-complete.json",
        "extraction-failure.json",
        "watchdog-failure.json",
    ] {
        match fs::symlink_metadata(Path::new(STATE).join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
            Ok(_) => anyhow::bail!(
                "live145 reached a terminal phase; retain debt until a qualified lifecycle consumer exists"
            ),
        }
    }
    native::owner(&p, &pb, false, a.actor_pid, IID, a.actor_start_ticks)?;
    native::original()?;
    let timer = native::timer(&p)?;
    timer_native(&timer)?;
    let actor = io::properties(ACTOR)?;
    actor_native(&actor, &a)?;
    let bytes = custody::token_snapshot(&Path::new(STATE).join("guard-latest.json"))?;
    let token_value = io::unique_json(&bytes)?;
    let current: model::Token = serde_json::from_value(token_value.clone())?;
    let captured_at = custody::now()?;
    ensure!(
        captured_at <= p.execution_deadline,
        "live145 immutable execution deadline expired"
    );
    let boot = custody::boottime()?;
    token(&current, &p, &a, &pb, &ab, captured_at, boot)?;
    let guard = io::properties(GUARD)?;
    guard_native(&guard)?;
    // The reviewed native reader also authenticates the actual typed empty
    // pre-start array. A completed guard may not hide a drop-in or pre-hook.
    let guard_full = native::show(GUARD)?;
    ensure!(
        guard_full["DropInPaths"] == ""
            && guard_full["ExecStartPre"] == ""
            && guard_full["ControlPID"] == "0"
            && guard_full["Job"] == ""
            && guard_full["User"] == "root"
            && guard_full["Group"] == "root"
            && guard_full["InvocationID"] == guard["InvocationID"]
            && guard_full["MainPID"] == guard["MainPID"],
        "live145 periodic guard custody changed or contains a pre-hook"
    );
    if guard["ActiveState"] == "active" {
        let pid: u32 = string(&guard, "/MainPID")?.parse()?;
        native::owner(
            &p,
            &pb,
            true,
            pid,
            string(&guard, "/InvocationID")?,
            native::ticks(pid)?,
        )?;
    } else {
        ensure!(
            guard["InvocationID"] == current.guard_iid,
            "live145 completed guard is not the actual fresh token writer"
        );
        let cg = Path::new("/sys/fs/cgroup/system.slice").join(GUARD);
        if cg.exists() {
            ensure!(
                fs::read_to_string(cg.join("cgroup.procs"))?
                    .trim()
                    .is_empty()
                    && fs::read_to_string(cg.join("cgroup.events"))?
                        .lines()
                        .any(|s| s == "populated 0"),
                "live145 completed guard cgroup remains populated"
            );
        }
    }
    ensure!(
        io::properties(ACTOR)? == actor,
        "live145 actor changed during finite capture"
    );
    let timer_after = native::timer(&p)?;
    timer_native(&timer_after)?;
    for key in [
        "Id",
        "InvocationID",
        "LoadState",
        "ActiveState",
        "Triggers",
        "DropInPaths",
        "Job",
    ] {
        ensure!(
            timer[key] == timer_after[key],
            "live145 timer identity/definition changed"
        );
    }
    let row = peer(s, &p, &actor);
    peer_shape(&row)?;
    Ok(Some(
        json!({"schema":"live145-v8g1-current-accounting-capture-v1","captured_at":captured_at,
        "captured_boottime_millis":boot,"plan":binding(&s.plan),"peer":row,"token":token_value,
        "token_sha256":custody::sha(&bytes),"actor_native":actor,"guard_native":guard,"timer_native":timer,
        "archive_body_reads":false,"memory_or_DATA_credit_bytes":0,"replay_launch_authorized":false}),
    ))
}
pub(super) fn peers(v: Option<&Value>) -> Vec<Value> {
    v.map(|v| vec![v["peer"].clone()]).unwrap_or_default()
}
pub(super) fn guard_floor(v: Option<&Value>) -> u64 {
    if v.is_some() { DATA_FLOOR } else { 0 }
}
pub(super) fn cpu(v: Option<&Value>) -> u64 {
    if v.is_some() { CPU } else { 0 }
}
pub(super) fn disjoint(
    v: Option<&Value>,
    owners: &[core::Owner],
    guards: &[GuardSpec],
) -> Result<()> {
    if v.is_none() {
        return Ok(());
    }
    ensure!(
        !owners
            .iter()
            .any(|o| [ACTOR, GUARD, TIMER].contains(&o.unit.as_str()) || o.iid == IID)
            && !guards.iter().any(|g| g.unit == GUARD || g.timer == TIMER),
        "live145 typed peer aliases an existing owner/guard charge"
    );
    Ok(())
}
/// Historical guard comparisons do not certify current live coverage. Current
/// accounting construction still requires the deployed selector in actual().
/// A declared live scope must carry both authenticated capture endpoints.
pub(super) fn comparison_scope(declared: bool, a: Option<&Value>, b: Option<&Value>) -> Result<bool> {
    ensure!((declared && a.is_some() && b.is_some())
        || (!declared && a.is_none() && b.is_none()),
        "live145 comparison source/capture scope crossed; no dropped live debt");
    Ok(declared)
}
pub(super) fn stable(a: Option<&Value>, b: Option<&Value>) -> Result<()> {
    match (a, b) {
        (None, None) => Ok(()),
        (Some(a), Some(b)) => {
            peer_shape(&a["peer"])?;
            peer_shape(&b["peer"])?;
            ensure!(
                a["peer"] == b["peer"]
                    && a["plan"] == b["plan"]
                    && number(a, "/captured_at")? <= number(b, "/captured_at")?
                    && number(a, "/token/at_boottime_millis")?
                        <= number(b, "/token/at_boottime_millis")?,
                "live145 actor/source/floors changed or token time reversed"
            );
            Ok(())
        }
        _ => anyhow::bail!("live145 appeared/disappeared during accounting; no automatic release"),
    }
}
pub(super) fn guard_discovered(
    name: &str,
    native: &Value,
    current: Option<&Value>,
) -> Result<bool> {
    if name != GUARD || current.is_none() {
        return Ok(false);
    }
    guard_native(native)?;
    Ok(true)
}
/// Comparison views only. The report retains every raw native snapshot and
/// captured token. Ordinary guard fires may change their IID/PID/exit fields.
pub(super) fn comparison(v: &Value, current: Option<&Value>) -> Result<Value> {
    let mut result = v.as_object().context("live145 comparison object")?.clone();
    let Some(current) = current else {
        return Ok(v.clone());
    };
    peer_shape(&current["peer"])?;
    if let Some(actor) = result.get(ACTOR) {
        ensure!(
            *actor == current["actor_native"],
            "live145 native actor differs from authenticated peer"
        );
    }
    if let Some(guard) = result.get(GUARD) {
        guard_native(guard)?;
        result.insert(
            GUARD.into(),
            json!({"Id":GUARD,"original_actor_iid":IID,
            "plan":current["plan"],"memory_reserved_in_actor_peer_bytes":256u64<<20,
            "exact_periodic_guard_authenticated":true}),
        );
    }
    if let Some(timer) = result.get(TIMER) {
        timer_native(timer)?;
        // Waiting/running is the sole timer variation. Definition and IID stay raw.
        let mut timer = timer.as_object().context("live145 timer object")?.clone();
        timer.insert("SubState".into(), json!("armed"));
        result.insert(TIMER.into(), json!(timer));
    }
    Ok(json!(result))
}
/// Enforced inside the positive185 full reader, before its worker can open.
/// Existing typed memory constructors consume the independent actor+guard peer;
/// this extra gate also preserves the live exporter's MemAvailable runway.
/// No source-bound irreclaimable RSS credit exists here, so retain its full
/// remaining hard promise conservatively instead of borrowing that runway.
pub(super) fn candidate_fit(
    current185: Option<&Value>,
    live: Option<&Value>,
    observer: &Value,
) -> Result<()> {
    let (Some(candidate), Some(live)) = (current185, live) else {
        return Ok(());
    };
    peer_shape(&live["peer"])?;
    let peers = candidate["peers"]
        .as_array()
        .context("live145 candidate185 peers")?;
    let candidate_memory = peers.iter().try_fold(0u64, |n, p| {
        n.checked_add(number(p, "/memory_max_bytes")?)
            .context("live145 candidate memory overflow")
    })?;
    let required = MEMORY_FLOOR
        .checked_add(MEMORY)
        .and_then(|n| n.checked_add(candidate_memory))
        .and_then(|n| n.checked_add(6u64 << 30))
        .context("live145 protected memory runway overflow")?;
    let available = number(observer, "/host_memory/conservative_available_kib")?
        .checked_mul(1024)
        .context("live145 observed available overflow")?;
    ensure!(
        candidate_memory > 0
            && available >= required
            && number(candidate, "/guard_floor_bytes")? >= DATA_FLOOR + RETAINED_185_SOURCE_DATA,
        "positive185 would breach live145 memory runway or inherited DATA floor"
    );
    Ok(())
}
pub(super) fn retained_data_floor(base: u64, live: Option<&Value>) -> Result<u64> {
    if live.is_none() {
        return Ok(base);
    }
    // The separately booked integration source phase is not present in old raw
    // accounting. Retain its entire4GiB once in the live supplement floor.
    Ok(base.max(
        DATA_FLOOR
            .checked_add(RETAINED_185_SOURCE_DATA)
            .context("live145 source floor overflow")?,
    ))
}

#[cfg(test)]
#[path = "live145_prefix/tests.rs"]
mod tests;
