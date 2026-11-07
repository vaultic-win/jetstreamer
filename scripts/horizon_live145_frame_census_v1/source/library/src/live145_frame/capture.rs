//! Additive accounting for the exact healthy v8g1 private exporter.
//! This authenticates the already admitted actor; it never launches, writes,
//! publishes, restarts, retires or renews its original admission/deadline.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value,json};
use std::{fs, path::Path, os::unix::fs::MetadataExt};
type BoundFile = model::Bound;
fn binding(b:&BoundFile)->Value {json!(b)}
fn string<'a>(v:&'a Value,p:&str)->Result<&'a str> {v.pointer(p).and_then(Value::as_str).with_context(||format!("live145 string {p}"))}
fn protected_generated(b:&BoundFile)->Result<Value> {custody::evidence(b)}

#[allow(dead_code)]
#[path = "custody.rs"]
mod custody;
#[allow(dead_code)]
#[path = "model.rs"]
mod model;
#[allow(dead_code)]
#[path = "native.rs"]
mod native;

pub(crate) const ACTOR: &str = "horizon-extract145-prefix-shared72h-20261107-v8g1.service";
pub(crate) const GUARD: &str = "horizon-guard145-prefix-shared72h-20261107-v8g1.service";
pub(crate) const TIMER: &str = "horizon-guard145-prefix-shared72h-20261107-v8g1.timer";
const IID: &str = "f37b155136614e0183ba2e9adb8714ef";
const TIMER_IID: &str = "f6f2308db2dc47be8f470030fb587b90";
const PLAN: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-plan-shared72h-20261107-v8g1/plan.json";
const PLAN_SHA: &str = "c1a7b5fcad8aa850be48a811fdfa7f703aa162d615070689fbba68f8f025dcf3";
const PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-tools-20261107-v8/epoch145-prefix-extract";
const PROGRAM_SHA: &str = "b416b7c932ef781c8d0f863b63b803379dd58cb1affe99dced6a61830a95ad76";
const STATE: &str =
    "/home/sol/.jetstreamer-private/epoch145-prefix-extract-shared72h-20261107-v8g1-state";
pub(crate) const MEMORY: u64 = (80 << 30) + (256 << 20);
pub(crate) const DATA: u64 = (160 << 30) + (128 << 20) + RETAINED_185_SOURCE_DATA;
pub(crate) const DATA_FLOOR: u64 = 5_074_152_197_938;
pub(crate) const MEMORY_FLOOR: u64 = 642_177_138_688;
// Already booked source DATA is retained independently of the exporter output.
const RETAINED_185_SOURCE_DATA: u64 = 4 << 30;
const SOURCE_BOOKING: &str = "/home/sol/.jetstreamer-private/epoch185-positive-current-reader-integration-source-20261107-v1/SOURCE_ONLY_COPY_BOOKING.json";
const SOURCE_BOOKING_SHA: &str = "69a2b96fc43a742d599f87391c683e6a91130172b4d4465657d681afe7aab370";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selector {
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
pub(crate) fn peer_shape(v: &Value) -> Result<()> {
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
pub(crate) fn actual(selector: Option<&Selector>, clock: u64) -> Result<Option<Value>> {
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
        "token_sha256":custody::sha(&bytes),"token_source_bytes":bytes,"guard_full":guard_full,"actor_native":actor,"guard_native":guard,"timer_native":timer,
        "archive_body_reads":false,"memory_or_DATA_credit_bytes":0,"replay_launch_authorized":false}),
    ))
}

#[path="io.rs"] mod io;
pub(crate) fn exact_selector()->Result<Selector> {Ok(serde_json::from_value(json!({"plan": {"path": "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-plan-shared72h-20261107-v8g1/plan.json", "sha256": "c1a7b5fcad8aa850be48a811fdfa7f703aa162d615070689fbba68f8f025dcf3"}, "ready": {"path": "/home/sol/.jetstreamer-private/epoch145-prefix-extract-shared72h-20261107-v8g1-state/ready.json", "sha256": "d8cd0712b4ee180fa10d3d977b6981a40846d7cd5f78698fd4a0bf9ad938457b"}, "admission": {"path": "/home/sol/.jetstreamer-private/epoch145-prefix-extract-shared72h-20261107-v8g1-state/admission.json", "sha256": "eecfdac8d2b968979c3bf541d75b5362d6b223b8d58da17600b7c4af25664c02"}, "guard_before_source": {"path": "/home/sol/.jetstreamer-private/epoch145-prefix-extract-shared72h-20261107-v8g1-state/guard-before-source-read.json", "sha256": "3410e0ea3c4fbbfe911185e893f9c79eb246a6cf419ecea7f567ac03ae79c53d"}}))?)}
pub(crate) fn capture_now(clock:u64)->Result<Value> {actual(Some(&exact_selector()?),clock)?.context("live145 capture missing")}
pub(crate) fn verify_recorded(v:&Value)->Result<()> {
 let s=exact_selector()?;exact(&s)?;
 let p:model::Plan=serde_json::from_value(value(&s.plan,true)?)?;
 let a:model::Admission=serde_json::from_value(value(&s.admission,false)?)?;
 let pb=old(&s.plan);let ab=model::Bound {path:p.state_root.join("admission.json"),sha256:s.admission.sha256.clone()};
 let clock=v["captured_at"].as_u64().context("live145 recorded clock")?;
 let boot=v["captured_boottime_millis"].as_u64().context("live145 recorded boottime")?;
 plan_shape(&p,&a,&value(&s.ready,false)?,&value(&s.guard_before_source,false)?,&pb,&ab,clock)?;
 sealed_program(&p)?;
 ensure!(v["schema"]=="live145-v8g1-current-accounting-capture-v1" && v["plan"]==json!(pb)
  && v["archive_body_reads"]==false && v["memory_or_DATA_credit_bytes"]==0
  && v["replay_launch_authorized"]==false,"live145 recorded capture envelope");
 let bytes:Vec<u8>=serde_json::from_value(v["token_source_bytes"].clone())?;
 ensure!(bytes.len()<=1<<20 && custody::sha(&bytes)==v["token_sha256"] && io::unique_json(&bytes)?==v["token"],"live145 raw token custody");
 let t:model::Token=serde_json::from_value(v["token"].clone())?;
 token(&t,&p,&a,&pb,&ab,clock,boot)?;
 actor_native(&v["actor_native"],&a)?;guard_native(&v["guard_native"])?;timer_native(&v["timer_native"])?;
 let g=&v["guard_full"];
 ensure!(g["DropInPaths"]=="" && g["ExecStartPre"]=="" && g["ControlPID"]=="0" && g["Job"]=="" && g["User"]=="root" && g["Group"]=="root"
  && g["InvocationID"]==v["guard_native"]["InvocationID"] && g["MainPID"]==v["guard_native"]["MainPID"],"live145 recorded full guard custody");
 if v["guard_native"]["ActiveState"]=="inactive" {ensure!(v["guard_native"]["InvocationID"]==t.guard_iid,"completed guard token writer differs");}
 peer_shape(&v["peer"])?;
 ensure!(v["peer"]==peer(&s,&p,&v["actor_native"]),"recorded peer source set differs");
 Ok(())
}
/// Fleet's qualified helper records the original narrow native property shape.
/// Full limits, timer definitions and fresh token are authenticated independently
/// by capture_now; no unknown or failed guard observation is normalized.
pub(crate) fn check_raw(census:&Value, proof:&Value)->Result<()> {
 verify_recorded(proof)?;
 for (unit,key) in [(ACTOR,"actor_native"),(GUARD,"guard_native"),(TIMER,"timer_native")] {
  let n=&census[unit];let reference=&proof[key];
  ensure!(n.is_object() && n["Id"]==unit,"live145 family omitted");
  for k in ["Id","LoadState"] {
   ensure!(n[k]==reference[k],"live145 census stable field differs: {unit}/{k}");
  }
  if unit!=TIMER {ensure!(n["NRestarts"]=="0" && n["Type"]=="exec","live145 census restart/type changed");}
  if unit==GUARD {
   ensure!(n["InvocationID"].as_str().is_some_and(|s|custody::hex(s,32)),"guard IID syntax");
   let active=n["ActiveState"]=="active" && n["SubState"]=="running"
    && n["MainPID"].as_str().and_then(|p|p.parse::<u32>().ok()).is_some_and(|p|p>1)
    && n["ControlGroup"]==format!("/system.slice/{GUARD}");
   let terminal=n["ActiveState"]=="inactive" && n["SubState"]=="dead" && n["MainPID"]=="0"
    && n["ControlGroup"]=="" && n["Result"]=="success" && n["ExecMainStatus"]=="0";
   ensure!(active||terminal,"failed or unknown live145 guard observation");
  } else {
   for k in ["InvocationID","ActiveState"] {
    ensure!(n[k]==reference[k],"live145 actor/timer owner differs: {k}");
   }
   if unit==TIMER {ensure!(matches!(n["SubState"].as_str(),Some("waiting"|"running")),"timer unarmed");}
   else {ensure!(n["SubState"]=="running" && n["MainPID"]==reference["MainPID"] && n["ControlGroup"]==reference["ControlGroup"],"actor not executing or changed process");}
  }
  if unit==TIMER {
   if n.get("Triggers").is_some(){ensure!(n["Triggers"]==GUARD,"live145 timer trigger changed");}
   if let Some(s)=n.get("TimersMonotonic").and_then(Value::as_str) {
    let rows=s.lines().collect::<Vec<_>>();ensure!(rows.len()==2
     && rows.iter().filter(|x|x.starts_with("{ OnActiveUSec=1s ; next_elapse=") && x.ends_with(" }")).count()==1
     && rows.iter().filter(|x|x.starts_with("{ OnUnitActiveUSec=30s ; next_elapse=") && x.ends_with(" }")).count()==1,"live145 raw timer cadence changed");
   }
  }
  if unit!=TIMER {
   ensure!(crate::same_exec_start(&n["ExecStart"],&reference["ExecStart"]),"live145 raw command identity differs");
   ensure!(n["ExecStart"].as_str().is_some_and(|s|s.starts_with(&command(if unit==ACTOR{"extract"}else{"guard"})) && s.matches("argv[]=").count()==1),"live145 census changed command");
  }
  for k in ["Restart","MemoryMax","MemorySwapMax","CPUQuotaPerSecUSec","TasksMax","User"] {
   if n.get(k).is_some(){ensure!(n[k]==reference[k],"live145 full census bound differs: {k}");}
  }
  if n.get("DropInPaths").is_some(){ensure!(n["DropInPaths"]=="","live145 census drop-in");}
  if n.get("ExecStartPre").is_some(){ensure!(n["ExecStartPre"]=="","live145 census pre-hook");}
  if n.get("ControlPID").is_some(){ensure!(n["ControlPID"]=="0","live145 control process");}
  if n.get("Job").is_some(){ensure!(n["Job"]=="","live145 queued job");}
 }
 Ok(())
}
pub(crate) fn pair(a:&Value,b:&Value)->Result<()> {
 verify_recorded(a)?;verify_recorded(b)?;
 ensure!(a["actor_native"]==b["actor_native"] && a["peer"]==b["peer"] && a["plan"]==b["plan"]
  && a["captured_at"].as_u64()<=b["captured_at"].as_u64()
  && a["captured_boottime_millis"].as_u64()<=b["captured_boottime_millis"].as_u64()
  && a["token"]["at_boottime_millis"].as_u64()<=b["token"]["at_boottime_millis"].as_u64(),"live145 capture reverses clock or changes promise");
 for k in ["Id","LoadState","InvocationID","ActiveState","Triggers","DropInPaths","Job","TimersMonotonic"] {
  if k=="TimersMonotonic" {continue;} // dynamic next-elapse values; each original cadence is checked below
  ensure!(a["timer_native"][k]==b["timer_native"][k],"live145 timer identity or definition changed");
 }
 for v in [a,b] {let schedules=v["timer_native"]["TimersMonotonic"].as_str().context("timer schedules")?;
  let rows=schedules.lines().collect::<Vec<_>>();ensure!(rows.len()==2
   && rows.iter().filter(|s|s.starts_with("{ OnActiveUSec=1s ; next_elapse=") && s.ends_with(" }")).count()==1
   && rows.iter().filter(|s|s.starts_with("{ OnUnitActiveUSec=30s ; next_elapse=") && s.ends_with(" }")).count()==1,"live145 changed timer cadence");}
 Ok(())
}
