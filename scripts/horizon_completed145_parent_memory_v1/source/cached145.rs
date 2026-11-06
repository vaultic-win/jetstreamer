//! Explicit completion-only memory projection. Raw history, residual guard and DATA
//! survive unchanged. This module never reads an archive body or signals a process.
use crate::{
    VerifiedParentMemory, fsutil as f,
    model::{Artifact, Bound, Current, PARENT},
    process_references,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub const UNIT: &str = "horizon-qualify-145-cached-b2a09f57de39c384.service";
pub const IID: &str = "15ddd220e2144aaa8d7418f73f60768f";
pub const GUARD: u64 = 512 << 20;
pub const DATA: u64 = 337 << 30;
const FAMILY: [&str; 4] = [
    UNIT,
    "horizon-qualify-145-cached-b2a09f57de39c384-guard.service",
    "horizon-qualify-145-cached-b2a09f57de39c384-stop.service",
    "horizon-qualify-145-cached-b2a09f57de39c384-guard.timer",
];
const WITNESS: &str = "/home/sol/.jetstreamer-private/cached145-postreplay-handoff-20261105-v1/ROOT_ACTUAL145_CLEAN_TERMINAL_AND_VERIFIED_SEGMENT.json";
const WITNESS_SHA: &str = "8fe99753332d62254da147dcf1324bf4834a78d595d55c853228ce3fb469cd9d";
const RUNNER: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-cached-runner-tools-20261101-v1/jetstreamer-epoch145-cached-runner";
const PLAN: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-cached-b2a09f57de39c384-work-plan-20261101-v1/plan.json";
const SOURCES: [(&str, &str); 6] = [
    (
        "/etc/systemd/system/horizon-qualify-145-cached-b2a09f57de39c384.service",
        "6a7a56a73015b7dbbaad7c97699329796a60debdbe2378090b86604c00e2dee7",
    ),
    (
        "/etc/systemd/system/horizon-qualify-145-cached-b2a09f57de39c384-guard.service",
        "975b8d0a887846fae40b29efabbfb4225d877a7ee0585e9e5991ab50f4bd7419",
    ),
    (
        "/etc/systemd/system/horizon-qualify-145-cached-b2a09f57de39c384-stop.service",
        "3bdaca1cf37de1e715e28c49e4a5ecdc0adc699537b099cbf2b5dbf842bc8bd3",
    ),
    (
        "/etc/systemd/system/horizon-qualify-145-cached-b2a09f57de39c384-guard.timer",
        "c9322a90c0b7213817f804880b1df1de12259d765853db11a2eaa46d4640aed3",
    ),
    (
        RUNNER,
        "6b7c54805a0fb2cd48157ae13a6b5806c1d17d79030f2bda67a74e642f00bf72",
    ),
    (
        PLAN,
        "9274bef992c06ffb55a1170b3c3332de25225bdf14eacf1ff8c6ab905ff35408",
    ),
];
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub registration: Bound,
    pub registration_seal: Bound,
    pub census: Bound,
}
/// Inputs known before capture. The output digest belongs only to `Request`,
/// which is constructed after the immutable census has been written and hashed.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub schema: String,
    pub registration: Bound,
    pub registration_seal: Bound,
    pub census_path: PathBuf,
}
impl Request {
    pub fn capture_request(&self) -> CaptureRequest {
        CaptureRequest {
            schema: "cached145-completed-parent-capture-request-v2".into(),
            registration: self.registration.clone(),
            registration_seal: self.registration_seal.clone(),
            census_path: self.census.path.clone(),
        }
    }
}
fn capture_scope(r: &CaptureRequest, current: &Current) -> Result<()> {
    let output = Path::new("/var/lib/jetstreamer/horizon-completed145-parent-memory-census-v2")
        .join(&current.observer.sha256)
        .join("census.json");
    ensure!(
        r.schema == "cached145-completed-parent-capture-request-v2" && r.census_path == output,
        "completed145 capture schema/output namespace differs"
    );
    Ok(())
}
fn matching_capture_request(c: &CaptureRequest, r: &Request, current: &Current) -> Result<()> {
    capture_scope(c, current)?;
    ensure!(
        *c == r.capture_request(),
        "completed145 census registration/seal/output crossed"
    );
    Ok(())
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub original_terminal: Bound,
    pub census_program: Artifact,
    pub source_scope_review: Bound,
    pub source_bindings: Vec<Bound>,
    pub native_units: Vec<String>,
    pub parent_retirement_bytes: u64,
    pub retained_guard_bytes: u64,
    pub retained_data_bytes: u64,
    pub parent_memory_release_authorized: bool,
    pub replay_restart_authorized: bool,
    pub archive_mutations: bool,
    pub r2_mutations: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub native: BTreeMap<String, Value>,
    pub inspected_processes: u64,
    pub process_references: Vec<String>,
    pub remaining_cgroup_members: Vec<String>,
    pub source_bindings: Vec<Bound>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Census {
    pub schema: String,
    pub current: Current,
    pub request: CaptureRequest,
    pub program: Bound,
    pub actor_invocation_id: String,
    pub actor_native_before: Value,
    pub actor_native_after: Value,
    pub recorded_unix_seconds: u64,
    pub before: Endpoint,
    pub after: Endpoint,
    pub archive_body_reads: u64,
    pub mutations: u64,
}
fn bindings() -> Vec<Bound> {
    SOURCES
        .iter()
        .map(|(path, sha256)| Bound {
            path: (*path).into(),
            sha256: (*sha256).into(),
        })
        .collect()
}
fn policy_shape(p: &Policy) -> Result<()> {
    ensure!(
        p.schema == "cached145-completed-parent-only-memory-policy-v1"
            && p.original_terminal.path == Path::new(WITNESS)
            && p.original_terminal.sha256 == WITNESS_SHA
            && p.parent_retirement_bytes == PARENT
            && p.retained_guard_bytes == GUARD
            && p.retained_data_bytes == DATA
            && p.parent_memory_release_authorized
            && !p.replay_restart_authorized
            && !p.archive_mutations
            && !p.r2_mutations,
        "completed145 exact parent-only authority/lineage differs"
    );
    ensure!(
        p.native_units == FAMILY.map(str::to_owned) && p.source_bindings == bindings(),
        "completed145 native/source universe differs"
    );
    Ok(())
}
fn policy(r: &Request) -> Result<Policy> {
    ensure!(
        r.schema == "cached145-completed-parent-only-memory-request-v1",
        "completed145 explicit request required"
    );
    registration_policy(&r.registration, &r.registration_seal)
}
fn registration_policy(registration: &Bound, registration_seal: &Bound) -> Result<Policy> {
    let dir = registration
        .path
        .parent()
        .context("completed145 registration parent")?;
    ensure!(
        dir.parent() == Some(Path::new("/usr/local/lib/jetstreamer"))
            && dir
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-completed145-parent-memory-registration-"))
            && registration
                .path
                .file_name()
                .is_some_and(|s| s == "registration.json"),
        "completed145 registration namespace"
    );
    crate::sealed_member(&f::immutable(registration_seal)?, registration, "0444")?;
    let p: Policy = serde_json::from_value(f::immutable(registration)?)?;
    policy_shape(&p)?;
    crate::qualified(&p.census_program, "completed145-parent-only-memory-census")?;
    let review = f::immutable(&p.source_scope_review)?;
    ensure!(
        review["schema"] == "cached145-completed-parent-launcher-scope-review-v1"
            && review["native_units"] == json!(p.native_units)
            && review["source_bindings"] == json!(p.source_bindings)
            && review["census_program"] == json!(p.census_program.program)
            && review["all_original_parent_launch_paths_classified"] == true
            && review["automatic_parent_launchers_absent"] == true
            && review["omitted_launcher_paths"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && review["live_exporter_and_its_guard_excluded_from_release"] == true
            && review["original_DATA_and_source_retention_unchanged"] == true,
        "completed145 independently qualified launcher scope required"
    );
    Ok(p)
}
fn original(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-cached145-authenticated-original-terminal-and-segment-v1"
            && v["epoch"] == 145
            && v["original_IID"] == IID
            && v["parent_completed_cleanly"] == true
            && v["original_process_and_cgroup_absent"] == true
            && v["resource_credit_or_retirement_authorized"] == false
            && v["independent_full_plugin_or_remote_readiness_claimed"] == false,
        "completed145 original terminal lineage differs"
    );
    let n = &v["native"];
    ensure!(
        n["Id"] == UNIT
            && n["InvocationID"] == ""
            && n["MainPID"] == "0"
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Result"] == "success"
            && n["ExecMainStatus"] == "0"
            && n["ActiveState"] == "inactive"
            && n["SubState"] == "dead"
            && n["ControlGroup"] == ""
            && n["Job"] == "",
        "completed145 original terminal was not successful and drained"
    );
    let j = &v["original_PID1_success_event"];
    ensure!(
        j["_PID"] == "1"
            && j["_UID"] == "0"
            && j["_EXE"] == "/usr/lib/systemd/systemd"
            && j["UNIT"] == UNIT
            && j["INVOCATION_ID"] == IID
            && j["MESSAGE"] == format!("{UNIT}: Deactivated successfully.")
            && j["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448",
        "completed145 original successful PID1 event differs"
    );
    Ok(())
}
fn native_shape(n: &BTreeMap<String, Value>) -> Result<()> {
    ensure!(
        n.keys().map(String::as_str).collect::<BTreeSet<_>>() == FAMILY.into_iter().collect(),
        "completed145 exact native family incomplete"
    );
    for (i, name) in FAMILY.iter().enumerate() {
        let row = &n[*name];
        ensure!(
            row["Id"] == *name
                && row["LoadState"] == "loaded"
                && row["Job"] == ""
                && row["DropInPaths"] == ""
                && row["FragmentPath"] == format!("/etc/systemd/system/{name}"),
            "completed145 changed native source, drop-in or queued job"
        );
        if i == 3 {
            ensure!(
                row["ActiveState"] == "inactive"
                    && row["SubState"] == "dead"
                    && row["TriggeredBy"] == ""
                    && row["Triggers"] == FAMILY[1],
                "completed145 guard timer is armed or replaced"
            );
        } else {
            ensure!(
                row["MainPID"] == "0"
                    && row["ControlPID"] == "0"
                    && row["ControlGroup"] == ""
                    && row["NRestarts"] == "0"
                    && row["Restart"] == "no"
                    && row["MemoryAccounting"] == "yes"
                    && row["MemorySwapMax"] == "0"
                    && row["MemoryMax"]
                        == if i == 0 {
                            PARENT.to_string()
                        } else {
                            GUARD.to_string()
                        }
                    && matches!(
                        (row["ActiveState"].as_str(), row["SubState"].as_str()),
                        (Some("inactive"), Some("dead")) | (Some("failed"), Some("failed"))
                    ),
                "completed145 parent/guard/stop revived or hard promise changed"
            );
            ensure!(
                row["TriggeredBy"] == if i == 1 { FAMILY[3] } else { "" },
                "completed145 unexpected automatic trigger"
            );
        }
    }
    let p = &n[UNIT];
    ensure!(
        p["InvocationID"] == ""
            && p["Result"] == "success"
            && p["ExecMainStatus"] == "0"
            && p["ActiveState"] == "inactive"
            && p["SubState"] == "dead",
        "completed145 parent replaced or failed"
    );
    let expected = format!(
        "{{ path={RUNNER} ; argv[]={RUNNER} hold {PLAN} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
        SOURCES[5].1, SOURCES[4].1
    );
    ensure!(
        p["ExecStart"] == expected,
        "completed145 loaded parent command differs from exact closed source"
    );
    Ok(())
}
fn endpoint_shape(e: &Endpoint) -> Result<()> {
    native_shape(&e.native)?;
    ensure!(
        e.inspected_processes > 0
            && e.process_references.is_empty()
            && e.remaining_cgroup_members.is_empty()
            && e.source_bindings == bindings(),
        "completed145 incomplete process/cgroup/source closure"
    );
    Ok(())
}
fn native(name: &str) -> Result<Value> {
    const FIELDS: &str = "Id,LoadState,InvocationID,ActiveState,SubState,MainPID,ControlPID,ControlGroup,NRestarts,Restart,Job,Result,ExecMainStatus,MemoryAccounting,MemoryMax,MemorySwapMax,FragmentPath,DropInPaths,TriggeredBy,Triggers,ExecStart";
    let out = Command::new("/usr/bin/systemctl")
        .arg("--system")
        .args(["show", name, "--no-pager", &format!("--property={FIELDS}")])
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .env("LC_ALL", "C")
        .output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 65536,
        "completed145 native census failed"
    );
    let mut row = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .context("completed145 native framing")?;
        ensure!(
            FIELDS.split(',').any(|k| k == key) && row.insert(key.into(), json!(value)).is_none(),
            "completed145 unexpected or duplicate native field"
        );
    }
    Ok(Value::Object(row))
}
fn endpoint() -> Result<Endpoint> {
    let sources = bindings();
    for binding in &sources {
        f::bytes(binding, 128 << 20, false)?;
    }
    let native = FAMILY
        .iter()
        .map(|name| Ok(((*name).to_owned(), native(name)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    native_shape(&native)?;
    let mut members = vec![];
    for name in &FAMILY[..3] {
        let path = PathBuf::from("/sys/fs/cgroup/system.slice")
            .join(name)
            .join("cgroup.procs");
        match fs::read_to_string(&path) {
            Ok(raw) => {
                ensure!(raw.len() <= 65536, "completed145 cgroup bound");
                members.extend(raw.split_whitespace().map(str::to_owned));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e).context("completed145 cgroup unreadable"),
        }
    }
    let mut refs = vec![];
    let mut inspected = 0;
    // Do not scan the archive/work root: the independent exporter legitimately
    // retains it. Only the closed parent image and exact original launch plan.
    for target in [RUNNER, PLAN] {
        let result = process_references::scan(Path::new("/proc"), Path::new(target))?;
        inspected = inspected.max(result.inspected_processes);
        refs.extend(result.references);
    }
    let e = Endpoint {
        native,
        inspected_processes: inspected,
        process_references: refs,
        remaining_cgroup_members: members,
        source_bindings: sources,
    };
    endpoint_shape(&e)?;
    Ok(e)
}
fn current_inputs(current: &Current) -> Result<()> {
    for bound in [
        &current.observer,
        &current.fleet,
        &current.fleet_plan,
        &current.frame,
    ] {
        f::json(bound)?;
    }
    Ok(())
}
/// Independent read-only census API; call only from a self/native-qualified
/// receipt writer. Actor proof is checked again at selection, never user JSON.
pub fn capture(
    r: &CaptureRequest,
    current: &Current,
    actor: &Bound,
    iid: &str,
    actor_before: &Value,
    actor_after: &Value,
    now: u64,
) -> Result<Census> {
    capture_scope(r, current)?;
    let p = registration_policy(&r.registration, &r.registration_seal)?;
    ensure!(
        *actor == p.census_program.program && f::hex(iid, 32) && actor_before == actor_after,
        "completed145 independent census actor crossed"
    );
    actor_shape(actor_before, actor, iid)?;
    current_inputs(current)?;
    original(&f::json(&p.original_terminal)?)?;
    let before = endpoint()?;
    let after = endpoint()?;
    ensure!(
        before.native == after.native,
        "completed145 native closure changed"
    );
    for b in &p.source_bindings {
        f::bytes(b, 128 << 20, false)?;
    }
    Ok(Census {
        schema: "cached145-completed-parent-current-census-v2".into(),
        current: current.clone(),
        request: r.clone(),
        program: actor.clone(),
        actor_invocation_id: iid.into(),
        actor_native_before: actor_before.clone(),
        actor_native_after: actor_after.clone(),
        recorded_unix_seconds: now,
        before,
        after,
        archive_body_reads: 0,
        mutations: 0,
    })
}
fn actor_shape(n: &Value, program: &Bound, iid: &str) -> Result<()> {
    ensure!(
        n["Id"] == "horizon-completed145-parent-memory-census-20261106-v1.service"
            && n["InvocationID"] == iid
            && f::hex(iid, 32)
            && n["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|p| p > 1)
            && n["ControlPID"] == "0"
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["Job"] == ""
            && n["MemoryAccounting"] == "yes"
            && n["MemoryMax"] == "2147483648"
            && n["MemorySwapMax"] == "0"
            && n["program"] == json!(program),
        "completed145 census is not exact native2GiB actor"
    );
    Ok(())
}
fn raw_row(a: &Value) -> Result<Value> {
    let peers = a["active_peer_allocations"]
        .as_array()
        .context("completed145 raw peers")?;
    let rows = peers
        .iter()
        .filter(|r| r["unit"] == UNIT || r["invocation_id"] == IID)
        .collect::<Vec<_>>();
    ensure!(rows.len() == 1, "completed145 raw row absent/duplicated");
    let r = rows[0];
    let p = &r["cached145_resource_promise"];
    ensure!(
        r["state"] == "terminal-retained-private-cached145"
            && r["unit"] == UNIT
            && r["invocation_id"] == IID
            && r["memory_max_bytes"] == PARENT + GUARD
            && r["parent_memory_max_bytes"] == PARENT
            && r["guard_memory_max_bytes"] == GUARD
            && r["data_reservation_bytes"] == DATA
            && r["native_pool_suballocation"] == false
            && r["credit_bytes"] == 0
            && r["resource_release_qualified"] == false
            && p["schema"] == "jetstreamer-epoch145-cached-independent-resource-promise-v1"
            && p["process_hard_limit_protected_bytes"] == PARENT
            && p["guard_hard_limit_protected_bytes"] == GUARD
            && p["total_parent_and_guard_hard_protection_bytes"] == PARENT + GUARD
            && p["DATA_retained_bytes"] == DATA
            && p["memory_or_DATA_credit_bytes"] == 0,
        "completed145 raw192GiB parent/512MiB guard/337GiB DATA lineage differs"
    );
    let growth = a["projected_obligations"]
        .as_array()
        .context("completed145 DATA obligations")?
        .iter()
        .filter(|r| r["producer_invocation_id"] == IID)
        .collect::<Vec<_>>();
    ensure!(
        growth.len() == 1
            && growth[0]["epoch"] == 145
            && growth[0]["claim_key"] == format!("cached145/{IID}")
            && growth[0]["outstanding_bytes"] == DATA,
        "completed145337GiB DATA missing or reduced"
    );
    Ok(r.clone())
}
fn compose(raw: u64, effective: u64, raw_peer: u64, effective_peer: u64) -> Result<(u64, u64)> {
    ensure!(
        effective <= raw && effective_peer <= raw_peer && effective_peer >= PARENT + GUARD,
        "completed145 baseline/guard underflow"
    );
    Ok((
        effective
            .checked_sub(PARENT)
            .context("completed145 total underflow")?,
        effective_peer
            .checked_sub(PARENT)
            .context("completed145 peer underflow")?,
    ))
}
pub(crate) fn apply(
    mut base: VerifiedParentMemory,
    r: &Request,
    current: &Current,
    raw_before: &Value,
    raw_after: &Value,
    now: u64,
) -> Result<VerifiedParentMemory> {
    ensure!(
        base.parent_selection_applied && base.selected_cached145_parent_retirement_bytes() == 0,
        "completed145 requires original199 selection and forbids repeated deduction"
    );
    let p = policy(r)?;
    let c: Census = serde_json::from_value(f::immutable(&r.census)?)?;
    f::fresh(c.recorded_unix_seconds, now, 300)?;
    matching_capture_request(&c.request, r, current)?;
    ensure!(
        c.schema == "cached145-completed-parent-current-census-v2"
            && c.current == *current
            && c.program == p.census_program.program
            && c.actor_native_before == c.actor_native_after
            && c.archive_body_reads == 0
            && c.mutations == 0,
        "completed145 census source/tuple/authority crossed"
    );
    actor_shape(&c.actor_native_before, &c.program, &c.actor_invocation_id)?;
    endpoint_shape(&c.before)?;
    endpoint_shape(&c.after)?;
    ensure!(
        c.before.native == c.after.native,
        "completed145 census native changed"
    );
    original(&f::json(&p.original_terminal)?)?;
    let row = raw_row(raw_before)?;
    ensure!(
        row == raw_row(raw_after)?,
        "completed145 raw source changed across full reader"
    );
    let live = endpoint()?;
    ensure!(
        live.native == c.after.native,
        "completed145 live closure changed since independent census"
    );
    let (total, peer) = compose(
        base.raw_total_bytes,
        base.effective_total_bytes,
        base.raw_peer_bytes,
        base.effective_peer_bytes,
    )?;
    base.effective_total_bytes = total;
    base.effective_peer_bytes = peer;
    base.evidence["completed_cached145_parent_retirement_bytes"] = json!(PARENT);
    base.evidence["effective_total_memory_promises_bytes"] = json!(total);
    base.evidence["effective_peer_memory_bytes"] = json!(peer);
    base.evidence["completed_cached145_selection"] = json!({"request":r,"current":current,
        "raw_row_preserved":row,"selected_parent_bytes":0,"retained_guard_bytes":GUARD,
        "retained_DATA_bytes":DATA,"physical_credit_bytes":0,"DATA_credit_bytes":0,
        "live_exporter_limits_changed":false,"new_replay_admission_authorized":false});
    Ok(base)
}
#[cfg(test)]
mod tests;
