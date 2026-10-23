//! Add the exact private original141 owner without replacing old144 history.
use super::*;
const UNIT: &str = "horizon-qualify-141-original-entry-root-20261023-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-original-entry-root-20261023-v1";
const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-fleet-reader-20261023-v4/jetstreamer-r2";
const READER_SHA: &str = "f35c32110e9a30bf4e27f11ec8b87fdd21d9e025efea4353df049d06ed199182";
const NODE_SHA: &str = "d0c784a403d65819de70a499fc4d981217fd16fc30b70fac7e5ec979d0423ff0";
const FIRST_GUARD: &str = "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194";
const TRACE_UNIT: &str = "horizon-qualify-141-original-entry-trace-20261023-v1.service";
const TRACE_ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-original-entry-trace-20261023-v1";
const TRACE_READER: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-trace-reader-20261023-v2/jetstreamer-r2";
const TRACE_READER_SHA: &str = "0805e5b0025a3338a1591a5291cfa9187927a4f8971b243130026556bcab2ecd";
const TRACE_GUARD_SHA: &str = "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
const FREEZE_UNIT: &str =
    "horizon-qualify-141-original-entry-freeze-components-20261023-v1.service";
const FREEZE_ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch141-original-entry-freeze-components-20261023-v1";
const FREEZE_READER: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-freeze-reader-20261023-v1/jetstreamer-r2";
const FREEZE_READER_SHA: &str = "d96fb78b85ee92e00560515ecafc48bc5f4b6f8ef148eed71221dced3af65517";
const VOTE_UNIT: &str = "horizon-qualify-141-original-entry-vote-prefix-20261023-v1.service";
const VOTE_ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch141-original-entry-vote-prefix-20261023-v1";
const VOTE_READER: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-vote-prefix-reader-20261023-v1/jetstreamer-r2";
const VOTE_READER_SHA: &str = "11e14c8d8e6799ace6891d30d55cba6a42663f5de1a83e3a27437c900984a739";
const CAPPED_UNIT: &str = "horizon-qualify-141-original-entry-capped-root-20261023-v1.service";
const CAPPED_ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch141-original-entry-capped-root-20261023-v1";
const CAPPED_READER: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-capped-root-reader-20261023-v1/jetstreamer-r2";
const CAPPED_READER_SHA: &str = "98d7e79faa62d8250d307f8fcc3b7dd2bd14f0e67424d4c8eced429663ac5d86";
fn vote_result() -> Bound {
    Bound {
        path:
            "/usr/local/lib/jetstreamer/horizon-epoch141-vote-prefix-result-20261023-v1/result.json"
                .into(),
        sha256: "2947b49f24aaeb731cb7ea102c55726bb065545ffba5e1c585bbddd7dcd06972".into(),
    }
}
fn predecessor_result() -> Bound {
    Bound { path:"/usr/local/lib/jetstreamer/horizon-epoch141-freeze-components-result-20261023-v1/result.json".into(),sha256:"f158bd27bf7c071684f4e2c1d7a49b1ed8c432c2c530f03fd59d4792b47e233d".into() }
}
fn trace_disabled(trace: &bool) -> bool {
    !trace
}
fn identity(s: &Profile) -> (&'static str, &'static str) {
    if s.capped_root {
        (CAPPED_UNIT, CAPPED_ROOT)
    } else if s.vote_prefix {
        (VOTE_UNIT, VOTE_ROOT)
    } else if s.freeze_components {
        (FREEZE_UNIT, FREEZE_ROOT)
    } else if s.trace {
        (TRACE_UNIT, TRACE_ROOT)
    } else {
        (UNIT, ROOT)
    }
}
fn reader_binding(s: &Profile) -> (&'static str, &'static str) {
    if s.capped_root {
        (CAPPED_READER, CAPPED_READER_SHA)
    } else if s.vote_prefix {
        (VOTE_READER, VOTE_READER_SHA)
    } else if s.freeze_components {
        (FREEZE_READER, FREEZE_READER_SHA)
    } else if s.trace {
        (TRACE_READER, TRACE_READER_SHA)
    } else {
        (READER, READER_SHA)
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    #[serde(default, skip_serializing_if = "trace_disabled")]
    capped_root: bool,
    #[serde(default, skip_serializing_if = "trace_disabled")]
    vote_prefix: bool,
    #[serde(default, skip_serializing_if = "trace_disabled")]
    freeze_components: bool,
    #[serde(default, skip_serializing_if = "trace_disabled")]
    coordinated_adoption: bool,
    #[serde(default, skip_serializing_if = "trace_disabled")]
    trace: bool,
    launch: Bound,
    event_fleet: Bound,
    event_plan: Bound,
    invocation_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    #[serde(default)]
    capped_root: bool,
    #[serde(default)]
    vote_prefix: bool,
    #[serde(default)]
    freeze_components: bool,
    #[serde(default)]
    coordinated_adoption: bool,
    #[serde(default)]
    trace: bool,
    schema: String,
    launch: Bound,
    event_fleet: Bound,
    event_plan: Bound,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}
pub(super) fn enabled(p: &Plan) -> bool {
    p.original141_root.is_some()
}
pub(super) fn freeze_enabled(p: &Plan) -> bool {
    p.original141_root
        .as_ref()
        .is_some_and(|s| s.freeze_components)
}
pub(super) fn vote_enabled(p: &Plan) -> bool {
    p.original141_root.as_ref().is_some_and(|s| s.vote_prefix)
}
pub(super) fn capped_enabled(p: &Plan) -> bool {
    p.original141_root.as_ref().is_some_and(|s| s.capped_root)
}
pub(super) fn invocation(p: &Plan) -> Option<&str> {
    p.original141_root
        .as_ref()
        .map(|s| s.invocation_id.as_str())
}
pub(super) fn launch_binding(p: &Plan) -> Option<&Bound> {
    p.original141_root.as_ref().map(|s| &s.launch)
}
pub(super) fn retained144_census(p: &Plan, scope: &Scope101200) -> bool {
    scope.diagnostic_ranges.len() == if enabled(p) { 2 } else { 1 }
        && scope
            .diagnostic_ranges
            .first()
            .is_some_and(|d| d.range == "144")
        && scope.diagnostic_ranges.iter().skip(1).all(|d| owner(p, d))
}
pub(super) fn reader(p: &Plan) -> bool {
    p.original141_root.as_ref().is_some_and(|s| {
        let (path, sha) = reader_binding(s);
        p.tools.r2.path == Path::new(path) && p.tools.r2.sha256 == sha
    })
}
// A guarded trace may finish while its new reader is being qualified. Adopt it
// through one fresh coordinated observation, preserving the original admission
// clock. This bounded scheduling delay cannot carry into later routine cycles.
pub(super) fn adoption_interval(p: &Plan) -> Result<Option<u64>> {
    let Some(s) = &p.original141_root else {
        return Ok(None);
    };
    if !s.trace
        || !s.coordinated_adoption
        || s.event_fleet.path != p.previous_fleet.path
        || s.event_fleet.sha256 != p.previous_fleet.sha256
    {
        return Ok(None);
    }
    read(s)?;
    let launch = bound_json(&s.launch, false)?;
    ensure!(
        launch["observer"] == serde_json::to_value(&p.previous_observer)?,
        "trace adoption cannot replace the admitted observer"
    );
    let old = bound_json(&p.previous_observer, false)?;
    let interval = utc_seconds(&p.sample_target_utc)?
        .checked_sub(utc_seconds(
            old["recorded_at_utc"]
                .as_str()
                .context("admission observer time")?,
        )?)
        .context("adoption precedes admission")?;
    ensure!(
        (1800..=3600).contains(&interval),
        "trace adoption must use one fresh >=30min, <=60min coordinated successor"
    );
    Ok(Some(interval))
}
fn iid(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn owner(p: &Plan, d: &DiagnosticClaim) -> bool {
    p.original141_root.as_ref().is_some_and(|s| {
        let (unit, _) = identity(s);
        d.range == "141"
            && d.controller_unit == unit
            && d.producer_unit == unit
            && d.expected_controller_invocation_id == s.invocation_id
            && d.expected_producer_invocation_id == s.invocation_id
            && iid(&s.invocation_id)
    })
}
fn claim(s: &Profile) -> Value {
    let (unit, root) = identity(s);
    json!({"epoch":141,"unit":unit,"invocation_id":s.invocation_id,"scratch_path":format!("{root}/scratch"),"launch_receipt":s.launch})
}
fn checked(s: &Profile, r: &Value, e: &Value, ep: &Value, g: &Value) -> Result<()> {
    let (unit, root) = identity(s);
    let peak = if s.capped_root {
        512u64 << 30
    } else {
        256u64 << 30
    };
    if s.capped_root {
        ensure!(
            s.trace
                && !s.freeze_components
                && !s.vote_prefix
                && !s.coordinated_adoption
                && r["worker_sha256"]
                    == "fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759"
                && r["capped_shrink_candidate"] == true
                && r["capped_shrink_profile_qualified"] == false
                && r["full_cold_epoch_peak_qualified"] == false
                && r["century_200_300_planning_assumption_applied"] == false
                && r["resource_budget_kind"]
                    == "bounded-qualification-stop-not-adopted-full-epoch-peak"
                && r.get("worker_entry_terminal_slot").is_none(),
            "capped141 must bind its distinct worker and experimental budget, without a diagnostic stop"
        );
    }
    if s.freeze_components {
        ensure!(
            s.trace
                && r["worker_freeze_component_diagnostic"] == true
                && r["worker_entry_terminal_slot"]
                    == if s.vote_prefix { 60912005 } else { 60912004 },
            "freeze141 requires its separately bounded worker"
        );
    }
    if s.trace {
        ensure!(
            r["historical_trace_enabled"] == true
                && r["whole_root_physical_limit_bytes"] == peak
                && r["maximum_runtime_seconds"] == if s.capped_root { 432000 } else { 1800 }
                && g["producer_stop_enabled"] == true
                && g["maximum_root_physical_bytes"] == peak
                && g.get("root_physical_observation_error")
                    .is_some_and(Value::is_null)
                && g["root_physical_observation"]["maximum_physical_bytes"] == peak
                && g["root_physical_observation"]["exceeds_budget"] == false
                && g["root_physical_observation"]["conservative_physical_bytes"]
                    .as_u64()
                    .is_some_and(|n| n <= peak),
            "trace141 handoff lacks bounded logging/physical guard scope"
        );
    }
    ensure!(
        s.launch.path == Path::new(root).join("receipts/launch.json")
            && iid(&s.invocation_id)
            && r["schema"]
                == if s.trace {
                    if s.capped_root {
                        "jetstreamer-private-epoch141-original-entry-capped-root-launch-v2"
                    } else if s.vote_prefix {
                        "jetstreamer-private-epoch141-original-entry-vote-prefix-launch-v2"
                    } else if s.freeze_components {
                        "jetstreamer-private-epoch141-original-entry-freeze-components-launch-v2"
                    } else {
                        "jetstreamer-private-epoch141-original-entry-trace-launch-v2"
                    }
                } else {
                    "jetstreamer-private-epoch141-original-entry-root-launch-v2"
                }
            && r["epoch"] == 141
            && r["unit"] == unit
            && r["invocation_id"] == s.invocation_id
            && r["launched"] == true
            && r["node_sha256"] == NODE_SHA
            && r["bootstrap_slot"] == 60911751
            && r["replay_start_slot"] == 60911752
            && r["terminal_root_slot"] == 61328765
            && r["run_root"] == root
            && r["private_original_entry_root_qualification"] == true
            && r["first_guard"]["path"] == format!("{root}/receipts/first-guard.json")
            && r["candidate_incremental_peak_bytes"] == if s.trace { peak } else { 768u64 << 30 },
        "original141 handoff has foreign launch/owner/span"
    );
    for key in [
        "replay_launch_authorized",
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "full_epoch_verified",
        "complete_epoch_span_covered",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "local_retirement_authorized",
        "runtime_promotion_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            r[key] == false,
            "original141 handoff grants authority:{key}"
        );
    }
    if s.coordinated_adoption {
        ensure!(
            s.trace
                && r["previous_fleet"] == serde_json::to_value(&s.event_fleet)?
                && e["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
                && e["first_epoch"] == 101
                && e["last_epoch"] == 200
                && e["plan"].as_str() == s.event_plan.path.to_str()
                && e["plan_sha256"] == s.event_plan.sha256
                && ep["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
                && ep["first_epoch"] == 101
                && ep["last_epoch"] == 200
                && ep["observer"] == r["observer"]
                && e["observer_receipt"] == r["observer"]["path"]
                && e["observer_sha256"] == r["observer"]["sha256"]
                && e["inventory"]["anomalies"] == 0
                && ep["gates"]["141"]["state"] == "failed-needs-repair"
                && e["epochs"].as_array().is_some_and(|a| a
                    .iter()
                    .any(|v| v["epoch"] == 141 && v["state"] == "failed-needs-repair"))
                && ep["diagnostics"]
                    .as_array()
                    .is_some_and(|a| a.iter().all(|v| v["unit"] != unit)),
            "trace141 coordinated adoption must retain its exact accepted prelaunch predecessor"
        );
    } else {
        ensure!(
            e["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
                && e["first_epoch"] == 101
                && e["last_epoch"] == 200
                && e["plan"].as_str() == s.event_plan.path.to_str()
                && e["plan_sha256"] == s.event_plan.sha256
                && e["previous_fleet"] == r["previous_fleet"]
                && ep["previous_fleet"] == r["previous_fleet"]
                && ep["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
                && ep["first_epoch"] == 101
                && ep["last_epoch"] == 200
                && ep["observer"] == r["observer"]
                && e["observer_receipt"] == r["observer"]["path"]
                && e["observer_sha256"] == r["observer"]["sha256"]
                && ep["admission_transition_guard"] == r["first_guard"]
                && e["admission_transition_guard"] == r["first_guard"]
                && e["inventory"]["anomalies"] == 0
                && e["producer_mutations"] == false
                && e["publication_authorized"] == false
                && e["remote_mutations"] == false
                && ep["gates"]["141"]["state"] == "failed-needs-repair"
                && e["epochs"].as_array().is_some_and(|a| a
                    .iter()
                    .filter(|v| v["epoch"] == 141)
                    .count()
                    == 1
                    && a.iter()
                        .any(|v| v["epoch"] == 141 && v["state"] == "failed-needs-repair")),
            "original141 event changes scope/predecessor/repair state"
        );
        let claims = ep["diagnostics"]
            .as_array()
            .context("original141 event diagnostics")?;
        ensure!(
            claims
                .iter()
                .filter(|v| v["unit"] == unit)
                .eq(std::iter::once(&claim(s))),
            "original141 event claim differs"
        );
        let events = e["diagnostics"]
            .as_array()
            .context("original141 event owner census")?;
        ensure!(
            events.iter().filter(|v| v["unit"]["Id"] == unit).count() == 1
                && events.iter().any(|v| v["unit"]["Id"] == unit
                    && v["epoch"] == 141
                    && v["live"] == true
                    && v["launch_invocation_id"] == s.invocation_id
                    && v["unit"]["InvocationID"] == s.invocation_id
                    && v["unit"]["NRestarts"] == "0"
                    && v["launch_receipt"].as_str() == s.launch.path.to_str()
                    && v["launch_receipt_sha256"] == s.launch.sha256),
            "original141 event lacks exact actual live invocation"
        );
    }
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"]
                == if s.trace {
                    TRACE_GUARD_SHA
                } else {
                    FIRST_GUARD
                }
            && g["producer_invocation_id"] == s.invocation_id
            && g["producer"]["invocation_id"] == s.invocation_id
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["cgroup"] == format!("/system.slice/{unit}")
            && g.get("trip_reason").is_some_and(Value::is_null)
            && g.get("worker_observation_error")
                .is_some_and(Value::is_null)
            && g["workers"].as_array().is_some_and(|w| w.len() == 1
                && w[0][0].as_u64().is_some_and(|n| n > 0)
                && w[0][1].as_u64().is_some_and(|n| n > 0 && n <= 3500000))
            && g["maximum_worker_vmas"] == 3500000
            && g["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && g["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 3572465819078)
            && g["available_bytes"]
                .as_u64()
                .zip(g["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "original141 handoff lacks exact no-trip guard firstfire"
    );
    Ok(())
}
fn read(s: &Profile) -> Result<(Value, Value)> {
    if s.capped_root {
        let prior = bound_json(&vote_result(), true)?;
        ensure!(
            prior["schema"] == "jetstreamer-epoch141-vote-prefix-result-v2"
                && prior["invocation_id"] == "5b09e442086149b3a9775d728f1ff047"
                && prior["worker_sha256"]
                    == "8f61690a486c5c0322857b25980ec681ec58cfd870b3425cba4bb892e2f4eb9b"
                && prior["terminal"]["main_pid"] == 0
                && prior["terminal"]["restarts"] == 0
                && prior["terminal"]["exit_status"] == 1
                && prior["execution_evidence"]["formerly_failing_vote_strict_execution_passed"]
                    == true
                && prior["execution_evidence"]["later_batch_first_entry"] == 452
                && prior["full_epoch_verified"] == false
                && prior["publication_authorized"] == false,
            "capped141 lacks exact successful bounded vote-prefix evidence"
        );
    }
    if s.vote_prefix {
        ensure!(
            s.freeze_components && s.trace && !s.coordinated_adoption,
            "vote prefix requires separately bounded same-sample handoff"
        );
        let prior = bound_json(&predecessor_result(), true)?;
        ensure!(
            prior["schema"] == "jetstreamer-epoch141-freeze-components-result-v2"
                && prior["invocation_id"] == "412f43b5db1046a2822efe3aeff95162"
                && prior["terminal"]["main_pid"] == 0
                && prior["terminal"]["restarts"] == 0
                && prior["terminal"]["exit_status"] == 1
                && prior["boundary"]["slot"] == 60912004
                && prior["boundary"]["matches_later_vote_expected_hash"] == true
                && prior["boundary"]["finalized_reward_digest_matches"] == true
                && prior["full_epoch_verified"] == false
                && prior["publication_authorized"] == false,
            "vote prefix lacks retained bounded predecessor result"
        );
    }
    let r = bound_json(&s.launch, false)?;
    let e = bound_json(&s.event_fleet, false)?;
    let p = bound_json(&s.event_plan, true)?;
    let gb: Bound = serde_json::from_value(r["first_guard"].clone())?;
    let g = bound_json(&gb, false)?;
    checked(s, &r, &e, &p, &g)?;
    Ok((claim(s), serde_json::to_value(gb)?))
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    if let Some(s) = &p.original141_root {
        ensure!(
            is_101(p)?
                && reader(p)
                && !p.expected_epochs.contains(&141)
                && p.scope_101_200
                    .as_ref()
                    .is_some_and(|s| s.private144_observer)
                && p.repair183_handoff.is_some()
                && p.repair185_handoff.is_some()
                && p.publication144.is_some()
                && native141::all_retry_enabled(p)
                && census141_poh::collected(p),
            "original141 requires complete retained host history and private ETA isolation"
        );
        read(s)?;
    }
    Ok(())
}
fn config_row(s: &Profile) -> Value {
    let (unit, root) = identity(s);
    json!({"range":"141","controller_unit":unit,"producer_unit":unit,"expected_controller_invocation_id":s.invocation_id,"expected_producer_invocation_id":s.invocation_id,"scratch_path":format!("{root}/scratch"),"worker_executable_basename":"historical-worker"})
}
fn migrate(scope: &mut Scope101200, config: &mut Value, s: &Profile) -> Result<()> {
    let (unit, _) = identity(s);
    ensure!(
        scope.private144_observer
            && scope.diagnostic_ranges.len() == 1
            && scope.diagnostic_ranges[0].range == "144",
        "original141 requires retained sole144 diagnostic"
    );
    let rows = config["diagnostic_replays"]
        .as_array_mut()
        .context("private census")?;
    ensure!(
        rows.len() == 1 && rows[0]["range"] == "144",
        "original141 cannot replace/drop/duplicate old diagnostic"
    );
    rows.push(config_row(s));
    scope.diagnostic_ranges.push(DiagnosticClaim {
        range: "141".into(),
        controller_unit: unit.into(),
        producer_unit: unit.into(),
        expected_controller_invocation_id: s.invocation_id.clone(),
        expected_producer_invocation_id: s.invocation_id.clone(),
    });
    Ok(())
}
fn replace_terminal_trace(
    p: &mut Plan,
    config: &mut Value,
    next: &Profile,
    fleet: &Value,
) -> Result<()> {
    let old = p.original141_root.as_ref().context("old trace profile")?;
    ensure!(
        old.trace
            && next.trace
            && !old.capped_root
            && ((!old.freeze_components
                && !old.vote_prefix
                && next.freeze_components
                && !next.vote_prefix
                && !next.capped_root)
                || (old.freeze_components
                    && !old.vote_prefix
                    && next.vote_prefix
                    && next.freeze_components
                    && !next.capped_root)
                || (old.freeze_components
                    && old.vote_prefix
                    && next.capped_root
                    && !next.freeze_components
                    && !next.vote_prefix)),
        "only terminal trace-to-freeze or freeze-to-vote observer replacement is supported"
    );
    let (old_unit, _) = identity(old);
    ensure!(
        !next.capped_root
            || (old.invocation_id == "5b09e442086149b3a9775d728f1ff047"
                && !next.coordinated_adoption),
        "capped141 must replace the exact result-bound vote-prefix invocation"
    );
    ensure!(
        !next.vote_prefix
            || (old.invocation_id == "412f43b5db1046a2822efe3aeff95162"
                && !next.coordinated_adoption),
        "vote prefix must replace the exact result-bound freeze invocation"
    );
    let terminal: Vec<_> = fleet["diagnostics"]
        .as_array()
        .context("terminal diagnostic census")?
        .iter()
        .filter(|d| d["unit"]["Id"] == old_unit)
        .collect();
    ensure!(
        terminal.len() == 1
            && terminal[0]["live"] == false
            && terminal[0]["unit"]["InvocationID"] == old.invocation_id
            && terminal[0]["unit"]["MainPID"] == "0"
            && terminal[0]["unit"]["NRestarts"] == "0"
            && terminal[0]["unit"]["ActiveState"] == "failed"
            && terminal[0]["unit"]["SubState"] == "failed"
            && terminal[0]["unit"]["Result"] == "exit-code"
            && terminal[0]["unit"]["ExecMainStatus"] == "1",
        "cannot replace a live, restarted, foreign or unresolved trace owner"
    );
    let scope = p.scope_101_200.as_ref().context("diagnostic scope")?;
    ensure!(
        retained144_census(p, scope) && owner(p, &scope.diagnostic_ranges[1]),
        "old diagnostic scope changed"
    );
    let rows = config["diagnostic_replays"]
        .as_array_mut()
        .context("diagnostic config")?;
    ensure!(
        rows.len() == 2 && rows[0]["range"] == "144" && rows[1] == config_row(old),
        "cannot drop or change retained diagnostic history"
    );
    rows[1] = config_row(next);
    let (unit, _) = identity(next);
    p.scope_101_200.as_mut().unwrap().diagnostic_ranges[1] = DiagnosticClaim {
        range: "141".into(),
        controller_unit: unit.into(),
        producer_unit: unit.into(),
        expected_controller_invocation_id: next.invocation_id.clone(),
        expected_producer_invocation_id: next.invocation_id.clone(),
    };
    // No fleet history is removed: fold() appends the new claim to the complete
    // previous fleet template, which retains the old terminal trace and launch.
    Ok(())
}
fn fold(f: &mut Value, c: Value, g: Value, s: &Profile) -> Result<()> {
    let (unit, _) = identity(s);
    ensure!(
        f["gates"]["141"]["state"] == "failed-needs-repair",
        "private141 cannot close repair incident"
    );
    let ds = f["diagnostics"]
        .as_array_mut()
        .context("diagnostic history")?;
    let old: Vec<_> = ds.iter().filter(|v| v["unit"] == unit).collect();
    ensure!(
        old.is_empty() || old == vec![&c],
        "original141 conflicts with retained claim"
    );
    if old.is_empty() {
        ds.push(c);
    }
    let names = f["tracked_units"]
        .as_array_mut()
        .context("tracked history")?;
    if !names.contains(&json!(unit)) {
        names.push(json!(unit));
    }
    let evidence = f["gates"]["141"]["evidence"]
        .as_array_mut()
        .context("repair evidence")?;
    let mut additions = vec![serde_json::to_value(&s.launch)?, g];
    if s.vote_prefix {
        additions.push(serde_json::to_value(predecessor_result())?);
    }
    if s.capped_root {
        additions.push(serde_json::to_value(vote_result())?);
    }
    for b in additions {
        if !evidence.contains(&b) {
            evidence.push(b);
        }
    }
    f["gates"]["141"]["next_action"] = if s.capped_root {
        json!(
            "Advance the freshly built corrected/capped v1.4.25 worker to canonical root61328765 under its512GiB whole-root and5day experimental stops. Preserve all prior diagnostic roots and the strictly passed60912005vote evidence. Reassess actual growth/RSS/pressure at each coordinated sample; this budget is not an adopted full-cold peak. Root success qualifies only the416766slot prefix;15234epoch141suffix slots and independent complete-span/full/plugin/delivery gates remain before a ready pair."
        )
    } else if s.vote_prefix {
        json!(
            "Capture worker-enforced60912005 terminal and frozen Bank evidence; determine whether the formerly failing60912005entry388transaction378 vote executes successfully with the separately built corrected-builtin worker. Retain prior60912004 canonical vote-expected Bank/reward match and both earlier failed roots. Parent progress is prefetch, not execution proof. Keep incident open through complete-span qualification and a verified ready pair."
        )
    } else if s.freeze_components {
        json!(
            "Capture the bounded worker's frozen Bank components at60911999 and60912004 and its native terminal result. Compare parent/account-delta/signature-count/blockhash/hardfork inputs and epoch-transition rewards/clock/collector. A worker stop at60912004 is diagnostic evidence, not the parent's61328765 checkpoint or full141 recovery. Preserve both earlier failed roots and keep incident open through a verified ready pair."
        )
    } else {
        json!(
            "Preserve exact private original-entry root qualification60911751..61328765 and guard/observer ownership. Capture actual terminal/checkpoint result promptly; partial-root success is not full141 or a sidecar ETA. Keep incident open through complete-span qualification and verified ready pair."
        )
    };
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    if let Some(s) = &p.original141_root {
        let (c, g) = read(s)?;
        fold(f, c, g, s)?;
        if s.capped_root {
            let previous = bound_json(&p.previous_fleet, false)?;
            if previous["epochs"].as_array().is_some_and(|rows| {
                rows.iter()
                    .any(|r| r["epoch"] == 144 && r["state"] == "remote-ready")
            }) {
                for epoch in 136..=139 {
                    if f["gates"][epoch.to_string()]["state"] == "blocked-qualification" {
                        f["gates"][epoch.to_string()]["next_action"] = json!(
                            "Epoch144 is now remote-ready and the rebuilt141worker has passed the formerly blocking vote. Review retained136–139prefix checkpoint provenance and independent full/current-plugin evidence, then dispatch qualified retained work or a freshly admitted repair with the corrected worker. Keep each incident open until its verified ready pair."
                        );
                    }
                }
            }
            if f["gates"]["140"]["state"] == "blocked-qualification" {
                f["gates"]["140"]["next_action"] = json!(
                    "The complete original-entry/PoH bundle and successful60912005vote-prefix result are sealed. Advance corrected/capped141qualification to61328765 to close its canonical-root obligation; then qualify the retained140prefix plus248post-cut slots through the independent complete-span/full/plugin/delivery gates. Preserve the original140evidence."
                );
            }
            if f["gates"]["186"]["state"] == "blocked-qualification" {
                f["gates"]["186"]["next_action"] = json!(
                    "Capped1.6.15worker, cohesive186inputs and input capability are staged. Implement its distinct bounded admission/guard/fleet path against the current five production claims plus any live141remaining-growth claim. Reassess after each accepted event/sample; require a clean expanded operating point before another experimental lane. The512GiB/384GiB draft is not a qualified full-cold budget."
                );
            }
        }
    }
    Ok(())
}
pub(super) fn transition_template(p: &Plan, f: &Value) -> Result<bool> {
    let Some(s) = &p.original141_root else {
        return Ok(false);
    };
    read(s)?;
    Ok(*f == bound_json(&s.event_plan, true)?)
}
pub(super) fn consume_transition(p: &Plan, f: &mut Value) -> Result<()> {
    if enabled(p) && !f["admission_transition_guard"].is_null() {
        ensure!(
            transition_template(p, f)?,
            "original141 cannot consume foreign admission guard"
        );
        f["admission_transition_guard"] = Value::Null;
    }
    Ok(())
}
pub(super) fn diagnostics(p: &Plan, model: &Value, v: &Value, observed: bool) -> Result<Value> {
    let s = p.original141_root.as_ref().context("original141 profile")?;
    let (unit, root) = identity(s);
    ensure!(
        !p.expected_epochs.contains(&141)
            && !model["ranges"]
                .as_array()
                .context("model ranges")?
                .iter()
                .any(|r| r["range"] == "141"
                    || r["epochs"]
                        .as_array()
                        .is_some_and(|a| a.contains(&json!(141))))
            && !v["replays"]
                .as_array()
                .context("ordinary census")?
                .iter()
                .any(|r| r["range"] == "141" || r["range"] == "141-141"),
        "original141 cannot acquire ordinary replay/ETA claim"
    );
    let rows = v["diagnostic_replays"]
        .as_array()
        .context("diagnostic census")?;
    ensure!(
        rows.len() == 2
            && rows.iter().filter(|r| r["range"] == "141").count() == 1
            && rows.iter().filter(|r| r["range"] == "144").count() == 1,
        "original141 requires exact141+retained144census"
    );
    let row = rows.iter().find(|r| r["range"] == "141").unwrap();
    if !observed {
        ensure!(
            *row == config_row(s),
            "original141 config owner/path changed"
        );
    } else {
        ensure!(
            row["producer_unit"] == unit
                && row["expected_producer_invocation_id"] == s.invocation_id
                && row["scratch_path"] == format!("{root}/scratch"),
            "original141 envelope owner changed"
        );
        for key in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "replay_launch_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            ensure!(row[key] == false, "original141 envelope grants {key}");
        }
        match row["status"].as_str() {
            Some("unavailable") => ensure!(
                row["observation"].is_null()
                    && row["error"].as_str().is_some_and(|e| !e.trim().is_empty()),
                "original141 missing explicit unresolved diagnostic evidence"
            ),
            Some("observed") => {
                let o = &row["observation"];
                ensure!(
                    row["error"].is_null()
                        && o["range"] == "141"
                        && o["scratch_path"] == format!("{root}/scratch")
                        && o["invocation_binding_stable"] == true,
                    "original141 observed identity differs"
                );
                for kind in ["controller", "producer"] {
                    for point in ["before", "after"] {
                        let owner = &o[format!("{kind}_{point}")];
                        ensure!(
                            owner["invocation_id"] == s.invocation_id
                                && owner["restarts"] == 0
                                && matches!(
                                    owner["active_state"].as_str(),
                                    Some("active" | "activating")
                                ),
                            "original141 observed owner changed"
                        );
                    }
                }
            }
            _ => anyhow::bail!("unknown original141 diagnostic outcome"),
        }
    }
    // The existing144validator still receives its exact one-row census.
    let mut old = v.clone();
    old["diagnostic_replays"] = json!(
        rows.iter()
            .filter(|r| r["range"] == "144")
            .collect::<Vec<_>>()
    );
    Ok(old)
}
pub(super) fn enable(p: &mut Plan, config: &mut Value, b: &Bound) -> Result<()> {
    ensure!(
        is_101(p)? && publication144::composite_reader(p) && p.repair185_handoff.is_some(),
        "original141 needs accepted five-lane history"
    );
    let spec: Spec = serde_json::from_value(bound_json(b, true)?)?;
    ensure!(
        spec.schema == "jetstreamer-original141-routine-handoff-v2"
            && !spec.replay_launch_authorized
            && !spec.publication_authorized
            && !spec.remote_mutations
            && !spec.r2_mutations,
        "authorizing or foreign original141 handoff"
    );
    let launch = bound_json(&spec.launch, false)?;
    let s = Profile {
        capped_root: spec.capped_root,
        vote_prefix: spec.vote_prefix,
        freeze_components: spec.freeze_components,
        coordinated_adoption: spec.coordinated_adoption,
        trace: spec.trace,
        launch: spec.launch,
        event_fleet: spec.event_fleet,
        event_plan: spec.event_plan,
        invocation_id: launch["invocation_id"]
            .as_str()
            .context("original141 invocation")?
            .into(),
    };
    ensure!(
        !enabled(p) || s.freeze_components || s.capped_root,
        "only a separately qualified freeze diagnostic can replace the terminal trace observer"
    );
    let (unit, _) = identity(&s);
    let (c, g) = read(&s)?;
    if s.coordinated_adoption {
        ensure!(
            s.trace
                && s.event_fleet.path == p.previous_fleet.path
                && s.event_fleet.sha256 == p.previous_fleet.sha256
                && s.event_plan.path == p.fleet_template.path
                && s.event_plan.sha256 == p.fleet_template.sha256,
            "coordinated trace adoption cannot replace the accepted history"
        );
    } else {
        let actual = bound_json(&s.event_plan, true)?;
        let mut expected = bound_json(&p.fleet_template, true)?;
        expected["previous_fleet"] = serde_json::to_value(&p.previous_fleet)?;
        expected["output"] = json!(s.event_fleet.path);
        expected["admission_transition_guard"] = g.clone();
        // The launch event adds evidence and ownership only; next-action updates
        // belong to the later ordinary cycle, not the same-sample admission delta.
        expected["diagnostics"]
            .as_array_mut()
            .context("old diagnostic history")?
            .push(c);
        expected["tracked_units"]
            .as_array_mut()
            .context("old tracked history")?
            .push(json!(unit));
        expected["gates"]["141"]["evidence"]
            .as_array_mut()
            .context("old repair history")?
            .extend([serde_json::to_value(&s.launch)?, g]);
        ensure!(
            expected == actual && actual["observer"] == serde_json::to_value(&p.previous_observer)?,
            "original141 event changes unrelated claims/history/scalars"
        );
    }
    if enabled(p) {
        let previous = bound_json(&p.previous_fleet, false)?;
        replace_terminal_trace(p, config, &s, &previous)?;
    } else {
        migrate(p.scope_101_200.as_mut().context("101scope")?, config, &s)?;
    }
    p.previous_fleet = s.event_fleet.clone();
    p.fleet_template = s.event_plan.clone();
    let (path, digest) = reader_binding(&s);
    p.tools.r2 = Bound {
        path: path.into(),
        sha256: digest.into(),
    };
    p.original141_root = Some(s);
    p.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    validate(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capped_replacement_requires_exact_terminal_vote_and_retains_144() {
        let (mut p, _, mut config) = fixture();
        let old = p.original141_root.as_mut().unwrap();
        old.trace = true;
        old.freeze_components = true;
        old.vote_prefix = true;
        old.invocation_id = "5b09e442086149b3a9775d728f1ff047".into();
        old.launch.path = Path::new(VOTE_ROOT).join("receipts/launch.json");
        config["diagnostic_replays"][1] = config_row(old);
        let old_id = old.invocation_id.clone();
        let scope = p.scope_101_200.as_mut().unwrap();
        scope.diagnostic_ranges[1].controller_unit = VOTE_UNIT.into();
        scope.diagnostic_ranges[1].producer_unit = VOTE_UNIT.into();
        scope.diagnostic_ranges[1].expected_controller_invocation_id = old_id.clone();
        scope.diagnostic_ranges[1].expected_producer_invocation_id = old_id.clone();
        let first = config["diagnostic_replays"][0].clone();
        let mut next = profile();
        next.trace = true;
        next.capped_root = true;
        next.invocation_id = "c".repeat(32);
        next.launch.path = Path::new(CAPPED_ROOT).join("receipts/launch.json");
        let ledger = json!({"diagnostics":[{"live":false,"unit":{"Id":VOTE_UNIT,"InvocationID":old_id,"MainPID":"0","NRestarts":"0","ActiveState":"failed","SubState":"failed","Result":"exit-code","ExecMainStatus":"1"}}]});
        for (pointer, value) in [
            ("/diagnostics/0/live", json!(true)),
            ("/diagnostics/0/unit/MainPID", json!("1")),
            ("/diagnostics/0/unit/Id", json!(FREEZE_UNIT)),
            ("/diagnostics/0/unit/InvocationID", json!("b".repeat(32))),
        ] {
            let mut bad = ledger.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                replace_terminal_trace(&mut p, &mut config, &next, &bad).is_err(),
                "{pointer}"
            );
        }
        replace_terminal_trace(&mut p, &mut config, &next, &ledger).unwrap();
        assert_eq!(config["diagnostic_replays"][0], first);
        assert_eq!(
            config["diagnostic_replays"][1]["producer_unit"],
            CAPPED_UNIT
        );
        p.original141_root = Some(next);
        assert!(retained144_census(&p, p.scope_101_200.as_ref().unwrap()));
        assert!(capped_enabled(&p));
        assert!(crate::generation_101(&p).starts_with("capped141-"));
    }
    #[test]
    fn vote_replacement_requires_terminal_freeze_and_keeps_retained_144() {
        let (mut p, _, mut config) = fixture();
        let old = p.original141_root.as_mut().unwrap();
        old.trace = true;
        old.freeze_components = true;
        old.invocation_id = "412f43b5db1046a2822efe3aeff95162".into();
        old.launch.path = Path::new(FREEZE_ROOT).join("receipts/launch.json");
        config["diagnostic_replays"][1] = config_row(old);
        let old_id = old.invocation_id.clone();
        let scope = p.scope_101_200.as_mut().unwrap();
        scope.diagnostic_ranges[1].controller_unit = FREEZE_UNIT.into();
        scope.diagnostic_ranges[1].producer_unit = FREEZE_UNIT.into();
        scope.diagnostic_ranges[1].expected_controller_invocation_id = old_id.clone();
        scope.diagnostic_ranges[1].expected_producer_invocation_id = old_id.clone();
        let first = config["diagnostic_replays"][0].clone();
        let mut next = profile();
        next.trace = true;
        next.freeze_components = true;
        next.vote_prefix = true;
        next.invocation_id = "c".repeat(32);
        next.launch.path = Path::new(VOTE_ROOT).join("receipts/launch.json");
        let ledger = json!({"diagnostics":[{"live":false,"unit":{"Id":FREEZE_UNIT,"InvocationID":old_id,"MainPID":"0","NRestarts":"0","ActiveState":"failed","SubState":"failed","Result":"exit-code","ExecMainStatus":"1"}}]});
        for (pointer, value) in [
            ("/diagnostics/0/live", json!(true)),
            ("/diagnostics/0/unit/NRestarts", json!("1")),
            ("/diagnostics/0/unit/Id", json!(TRACE_UNIT)),
            ("/diagnostics/0/unit/ExecMainStatus", json!("0")),
        ] {
            let mut bad = ledger.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                replace_terminal_trace(&mut p, &mut config, &next, &bad).is_err(),
                "{pointer}"
            );
        }
        replace_terminal_trace(&mut p, &mut config, &next, &ledger).unwrap();
        assert_eq!(config["diagnostic_replays"][0], first);
        assert_eq!(config["diagnostic_replays"][1]["producer_unit"], VOTE_UNIT);
        p.original141_root = Some(next);
        assert!(retained144_census(&p, p.scope_101_200.as_ref().unwrap()));
        assert!(vote_enabled(&p));
        assert!(crate::generation_101(&p).starts_with("vote141-"));
    }
    #[test]
    fn freeze_observer_replacement_requires_the_exact_terminal_trace_and_preserves_144() {
        let (mut p, _, mut config) = fixture();
        let old = p.original141_root.as_mut().unwrap();
        old.trace = true;
        old.launch.path = Path::new(TRACE_ROOT).join("receipts/launch.json");
        config["diagnostic_replays"][1] = config_row(old);
        let old_id = old.invocation_id.clone();
        let scope = p.scope_101_200.as_mut().unwrap();
        scope.diagnostic_ranges[1].controller_unit = TRACE_UNIT.into();
        scope.diagnostic_ranges[1].producer_unit = TRACE_UNIT.into();
        let first = config["diagnostic_replays"][0].clone();
        let mut next = profile();
        next.trace = true;
        next.freeze_components = true;
        next.coordinated_adoption = true;
        next.invocation_id = "c".repeat(32);
        next.launch.path = Path::new(FREEZE_ROOT).join("receipts/launch.json");
        let ledger = json!({"diagnostics":[{"live":false,"unit":{"Id":TRACE_UNIT,"InvocationID":old_id,"MainPID":"0","NRestarts":"0","ActiveState":"failed","SubState":"failed","Result":"exit-code","ExecMainStatus":"1"}}]});
        for (pointer, value) in [
            ("/diagnostics/0/live", json!(true)),
            ("/diagnostics/0/unit/MainPID", json!("1")),
            ("/diagnostics/0/unit/InvocationID", json!("a".repeat(32))),
        ] {
            let mut bad = ledger.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                replace_terminal_trace(&mut p, &mut config, &next, &bad).is_err(),
                "{pointer}"
            );
        }
        replace_terminal_trace(&mut p, &mut config, &next, &ledger).unwrap();
        assert_eq!(config["diagnostic_replays"][0], first);
        assert_eq!(
            config["diagnostic_replays"][1]["producer_unit"],
            FREEZE_UNIT
        );
        p.original141_root = Some(next);
        assert!(retained144_census(&p, p.scope_101_200.as_ref().unwrap()));
        assert!(freeze_enabled(&p));
    }
    #[test]
    fn trace_profile_keeps_old_history_and_uses_distinct_reader_owner_and_root() {
        let (mut p, model, _, _, _, _, mut config, _) = crate::tests::fixture101();
        let mut s = profile();
        assert!(serde_json::to_value(&s).unwrap().get("trace").is_none());
        s.trace = true;
        s.launch.path = Path::new(TRACE_ROOT).join("receipts/launch.json");
        let scope = p.scope_101_200.as_mut().unwrap();
        scope.private144_observer = true;
        config["diagnostic_replays"] = json!([{"range":"144","preserved_number":u64::MAX}]);
        let old = config["diagnostic_replays"][0].clone();
        migrate(scope, &mut config, &s).unwrap();
        assert_eq!(config["diagnostic_replays"][0], old);
        assert_eq!(config["diagnostic_replays"][1]["producer_unit"], TRACE_UNIT);
        assert_eq!(
            config["diagnostic_replays"][1]["scratch_path"],
            format!("{TRACE_ROOT}/scratch")
        );
        p.original141_root = Some(s);
        p.tools.r2 = Bound {
            path: TRACE_READER.into(),
            sha256: TRACE_READER_SHA.into(),
        };
        assert!(reader(&p));
        assert!(owner(
            &p,
            &p.scope_101_200.as_ref().unwrap().diagnostic_ranges[1]
        ));
        assert_eq!(
            diagnostics(&p, &model, &config, false).unwrap()["diagnostic_replays"],
            json!([old])
        );
        p.tools.r2.sha256 = READER_SHA.into();
        assert!(!reader(&p));
    }
    fn profile() -> Profile {
        let bound = |path: &str| Bound {
            path: path.into(),
            sha256: "a".repeat(64),
        };
        Profile {
            capped_root: false,
            vote_prefix: false,
            freeze_components: false,
            coordinated_adoption: false,
            trace: false,
            launch: bound(&format!("{ROOT}/receipts/launch.json")),
            event_fleet: bound(
                "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/original141-event.json",
            ),
            event_plan: bound("/sealed/original141-event-plan.json"),
            invocation_id: "b".repeat(32),
        }
    }
    fn fixture() -> (Plan, Value, Value) {
        let (mut p, model, _, _, _, _, mut config, _) = crate::tests::fixture101();
        let scope = p.scope_101_200.as_mut().unwrap();
        scope.private144_observer = true;
        scope.diagnostic_ranges[0].expected_controller_invocation_id =
            private144::INVOCATION.into();
        scope.diagnostic_ranges[0].expected_producer_invocation_id = private144::INVOCATION.into();
        config["diagnostic_replays"] = json!([{"range":"144","preserved_number":u64::MAX}]);
        let s = profile();
        migrate(scope, &mut config, &s).unwrap();
        p.original141_root = Some(s);
        p.tools.r2 = Bound {
            path: READER.into(),
            sha256: READER_SHA.into(),
        };
        (p, model, config)
    }
    #[test]
    fn migration_preserves_old144_and_all_ordinary_claims_losslessly() {
        let (p, model, config) = fixture();
        assert!(is_101(&p).unwrap());
        assert!(reader(&p));
        let mut composite = fixture().0;
        composite.controller_rebind = Some(Bound {
            path: "/proof.json".into(),
            sha256: "a".repeat(64),
        });
        assert!(crate::generation_101(&composite).starts_with("controller-rebind-original141-"));
        assert_ne!(crate::generation_101(&composite), crate::generation_101(&p));
        let old = diagnostics(&p, &model, &config, false).unwrap();
        assert_eq!(
            old["diagnostic_replays"],
            json!([{"range":"144","preserved_number":u64::MAX}])
        );
        assert_eq!(old["replays"], config["replays"]);
        assert_eq!(p.expected_epochs, vec![198]);
        let d = &p.scope_101_200.as_ref().unwrap().diagnostic_ranges[1];
        assert!(owner(&p, d));
        let mut bad = config.clone();
        bad["diagnostic_replays"][1]["scratch_path"] = json!("/foreign");
        assert!(diagnostics(&p, &model, &bad, false).is_err());
        let mut bad = config.clone();
        bad["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(config["diagnostic_replays"][1].clone());
        assert!(diagnostics(&p, &model, &bad, false).is_err());
        let mut bad = config;
        bad["diagnostic_replays"].as_array_mut().unwrap().remove(0);
        assert!(diagnostics(&p, &model, &bad, false).is_err());
    }
    #[test]
    fn unavailable_never_becomes_activity_eta_or_inactivity_proof() {
        let (p, mut model, mut v) = fixture();
        v["diagnostic_replays"][1] = json!({"range":"141","producer_unit":UNIT,"expected_producer_invocation_id":"b".repeat(32),"scratch_path":format!("{ROOT}/scratch"),"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,"status":"unavailable","observation":null,"error":"worker not yet available"});
        diagnostics(&p, &model, &v, true).unwrap();
        for key in [
            "error",
            "status",
            "producer_unit",
            "expected_producer_invocation_id",
            "scratch_path",
        ] {
            let mut bad = v.clone();
            bad["diagnostic_replays"][1][key] = Value::Null;
            assert!(diagnostics(&p, &model, &bad, true).is_err(), "{key}");
        }
        for key in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "replay_launch_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            let mut bad = v.clone();
            bad["diagnostic_replays"][1][key] = json!(true);
            assert!(diagnostics(&p, &model, &bad, true).is_err(), "{key}");
        }
        model["ranges"]
            .as_array_mut()
            .unwrap()
            .push(json!({"range":"141","epochs":[141]}));
        assert!(diagnostics(&p, &model, &v, true).is_err());
    }
    #[test]
    fn observed_requires_every_before_after_owner_without_restarts() {
        let (p, model, mut v) = fixture();
        let mut o = json!({"range":"141","scratch_path":format!("{ROOT}/scratch"),"invocation_binding_stable":true});
        for kind in ["controller", "producer"] {
            for point in ["before", "after"] {
                o[format!("{kind}_{point}")] =
                    json!({"invocation_id":"b".repeat(32),"restarts":0,"active_state":"active"});
            }
        }
        v["diagnostic_replays"][1] = json!({"range":"141","producer_unit":UNIT,"expected_producer_invocation_id":"b".repeat(32),"scratch_path":format!("{ROOT}/scratch"),"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,"status":"observed","observation":o,"error":null});
        diagnostics(&p, &model, &v, true).unwrap();
        for kind in ["controller", "producer"] {
            for point in ["before", "after"] {
                for field in ["invocation_id", "restarts", "active_state"] {
                    let mut bad = v.clone();
                    bad["diagnostic_replays"][1]["observation"][format!("{kind}_{point}")][field] =
                        Value::Null;
                    assert!(
                        diagnostics(&p, &model, &bad, true).is_err(),
                        "{kind}_{point}.{field}"
                    );
                }
            }
        }
    }
    #[test]
    fn fold_is_idempotent_preserves_every_prior_claim_and_keeps_repair_open() {
        let s = profile();
        let g = json!({"path":"/first-guard.json","sha256":"c".repeat(64)});
        let mut f = json!({"diagnostics":[{"epoch":144,"unit":"retained144"},{"epoch":141,"unit":"old-acquisition"}],"tracked_units":["retained144","old-acquisition"],"gates":{"141":{"state":"failed-needs-repair","next_action":"old","evidence":[{"number":u64::MAX}]},"159":{"state":"failed-needs-repair","next_action":"preserved159"}}});
        let old = f.clone();
        fold(&mut f, claim(&s), g.clone(), &s).unwrap();
        assert_eq!(f["diagnostics"][0], old["diagnostics"][0]);
        assert_eq!(f["diagnostics"][1], old["diagnostics"][1]);
        assert_eq!(f["gates"]["159"], old["gates"]["159"]);
        assert_eq!(f["gates"]["141"]["evidence"][0], json!({"number":u64::MAX}));
        assert_eq!(f["gates"]["141"]["state"], "failed-needs-repair");
        let once = f.clone();
        fold(&mut f, claim(&s), g.clone(), &s).unwrap();
        assert_eq!(f, once);
        f["gates"]["141"]["state"] = json!("blocked-qualification");
        assert!(fold(&mut f, claim(&s), g, &s).is_err());
    }
    fn handoff_fixture() -> (Profile, Value, Value, Value, Value) {
        let s = profile();
        let guard =
            json!({"path":format!("{ROOT}/receipts/first-guard.json"),"sha256":"c".repeat(64)});
        let observer = json!({"path":"/sample.json","sha256":"d".repeat(64)});
        let prior = json!({"path":"/prior-fleet.json","sha256":"e".repeat(64)});
        let mut r = json!({"schema":"jetstreamer-private-epoch141-original-entry-root-launch-v2","epoch":141,"unit":UNIT,"invocation_id":s.invocation_id,"launched":true,"node_sha256":NODE_SHA,"bootstrap_slot":60911751,"replay_start_slot":60911752,"terminal_root_slot":61328765,"run_root":ROOT,"private_original_entry_root_qualification":true,"first_guard":guard,"candidate_incremental_peak_bytes":768u64<<30,"observer":observer,"previous_fleet":prior,"required_guard_minimum_free_bytes":3572465819078u64});
        for key in [
            "replay_launch_authorized",
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "full_epoch_verified",
            "complete_epoch_span_covered",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "local_retirement_authorized",
            "runtime_promotion_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[key] = json!(false);
        }
        let p = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":101,"last_epoch":200,"previous_fleet":prior,"observer":observer,"admission_transition_guard":guard,"gates":{"141":{"state":"failed-needs-repair"}},"diagnostics":[claim(&s)]});
        let e = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,"plan":s.event_plan.path,"plan_sha256":s.event_plan.sha256,"previous_fleet":prior,"observer_receipt":observer["path"],"observer_sha256":observer["sha256"],"admission_transition_guard":guard,"inventory":{"anomalies":0},"producer_mutations":false,"publication_authorized":false,"remote_mutations":false,"epochs":[{"epoch":141,"state":"failed-needs-repair"}],"diagnostics":[{"unit":{"Id":UNIT,"InvocationID":s.invocation_id,"NRestarts":"0"},"epoch":141,"live":true,"launch_invocation_id":s.invocation_id,"launch_receipt":s.launch.path,"launch_receipt_sha256":s.launch.sha256}]});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_sha256":FIRST_GUARD,"producer_invocation_id":s.invocation_id,"producer":{"invocation_id":s.invocation_id,"restarts":0,"active":"active","sub":"running","cgroup":format!("/system.slice/{UNIT}")},"trip_reason":null,"worker_observation_error":null,"workers":[[10,100]],"maximum_worker_vmas":3500000,"minimum_free_bytes":3572465819078u64,"available_bytes":3572465819079u64,"remote_mutations":false,"r2_mutations":false});
        (s, r, e, p, g)
    }
    #[test]
    fn handoff_cannot_borrow_another_event_owner_guard_or_close_the_incident() {
        let (s, r, e, p, g) = handoff_fixture();
        checked(&s, &r, &e, &p, &g).unwrap();
        for key in [
            "invocation_id",
            "node_sha256",
            "terminal_root_slot",
            "first_guard",
            "current_sidecar_eta_valid",
        ] {
            let mut bad = r.clone();
            bad[key] = Value::Null;
            assert!(checked(&s, &bad, &e, &p, &g).is_err(), "launch {key}");
        }
        for key in [
            "previous_fleet",
            "observer_sha256",
            "admission_transition_guard",
            "epochs",
            "diagnostics",
        ] {
            let mut bad = e.clone();
            bad[key] = Value::Null;
            assert!(checked(&s, &r, &bad, &p, &g).is_err(), "event {key}");
        }
        let mut bad = p.clone();
        bad["gates"]["141"]["state"] = json!("remote-ready");
        assert!(checked(&s, &r, &e, &bad, &g).is_err());
        let mut bad = g.clone();
        bad["producer"]["invocation_id"] = json!("a".repeat(32));
        assert!(checked(&s, &r, &e, &p, &bad).is_err());
        let mut bad = g;
        bad["workers"] = json!([]);
        assert!(checked(&s, &r, &e, &p, &bad).is_err());
    }
    #[test]
    fn coordinated_trace_adoption_needs_its_exact_prelaunch_history_and_physical_guard() {
        let (mut s, mut r, e, p, mut g) = handoff_fixture();
        s.trace = true;
        s.coordinated_adoption = true;
        s.launch.path = Path::new(TRACE_ROOT).join("receipts/launch.json");
        r["schema"] = json!("jetstreamer-private-epoch141-original-entry-trace-launch-v2");
        r["unit"] = json!(TRACE_UNIT);
        r["run_root"] = json!(TRACE_ROOT);
        r["first_guard"]["path"] = json!(format!("{TRACE_ROOT}/receipts/first-guard.json"));
        r["previous_fleet"] = serde_json::to_value(&s.event_fleet).unwrap();
        r["historical_trace_enabled"] = json!(true);
        r["candidate_incremental_peak_bytes"] = json!(256u64 << 30);
        r["whole_root_physical_limit_bytes"] = json!(256u64 << 30);
        r["maximum_runtime_seconds"] = json!(1800);
        g["guard_sha256"] = json!(TRACE_GUARD_SHA);
        g["producer"]["cgroup"] = json!(format!("/system.slice/{TRACE_UNIT}"));
        g["producer_stop_enabled"] = json!(true);
        g["maximum_root_physical_bytes"] = json!(256u64 << 30);
        g["root_physical_observation_error"] = Value::Null;
        g["root_physical_observation"] = json!({"maximum_physical_bytes":256u64<<30,"exceeds_budget":false,"conservative_physical_bytes":4096});
        checked(&s, &r, &e, &p, &g).unwrap();
        for key in [
            "previous_fleet",
            "historical_trace_enabled",
            "whole_root_physical_limit_bytes",
        ] {
            let mut bad = r.clone();
            bad[key] = Value::Null;
            assert!(checked(&s, &bad, &e, &p, &g).is_err(), "{key}");
        }
        let mut bad = p.clone();
        bad["diagnostics"].as_array_mut().unwrap().push(claim(&s));
        assert!(checked(&s, &r, &e, &bad, &g).is_err());
        let mut bad = g.clone();
        bad["root_physical_observation"]["exceeds_budget"] = json!(true);
        assert!(checked(&s, &r, &e, &p, &bad).is_err());
    }
    #[test]
    #[ignore = "root exact sealed0709 controller-rebound five-lane templates only; no sampling, remote requests or writes"]
    fn actual_five_lane_and_private_census_compatibility() {
        let b=Bound{path:"/var/lib/jetstreamer/horizon-routine-plan-101-200-20261023T070958Z-controller-rebind-repair185-repair183-upload144-census141-boundaries-native141-all-retry-public160-timed-scans-upload198-v1/cycle-plan.json".into(),sha256:"b2b5c98aacf9b732449bcb24cbaf3e2d5b100b7e52e43264ada8371465c44012".into()};
        let mut p: Plan = serde_json::from_value(bound_json(&b, true).unwrap()).unwrap();
        assert!(!enabled(&p));
        validate_templates(
            &p,
            &bound_json(&p.model_template, true).unwrap(),
            &bound_json(&p.fleet_template, true).unwrap(),
            &bound_json(&p.previous_fleet, false).unwrap(),
            &bound_json(&p.previous_estimates, false).unwrap(),
            &bound_json(&p.previous_observer, false).unwrap(),
        )
        .unwrap();
        // This is only an in-memory proposed census. No launch/event receipt
        // exists for this synthetic owner, so full adoption remains impossible.
        let mut config = bound_json(&p.observer_config, true).unwrap();
        let s = profile();
        migrate(p.scope_101_200.as_mut().unwrap(), &mut config, &s).unwrap();
        p.original141_root = Some(s);
        assert!(crate::generation_101(&p).starts_with("controller-rebind-original141-"));
        p.tools.r2 = Bound {
            path: READER.into(),
            sha256: READER_SHA.into(),
        };
        for (name, accepted) in [
            ("prefix157", prefix157::writer(&p)),
            ("prefix144", prefix144::writer(&p)),
            ("native144", native144::writer(&p)),
            ("continuation144", continuation144::writer(&p)),
            ("assembly144", assembly144::writer(&p)),
            ("native141", native141::reader(&p)),
            ("all-acquisition141", native141::all_acquisition_reader(&p)),
            ("census141", census141_poh::reader(&p)),
            ("publication144", publication144::reader(&p)),
            ("public160", public160::reader(&p)),
            ("public198", public198::writer(&p)),
        ] {
            assert!(accepted, "new reader lost retained {name} support");
        }
        let model = bound_json(&p.model_template, true).unwrap();
        let effective = private144::effective_model(
            &p,
            &delivery160::effective_model(
                &p,
                &delivery198::effective_model(&p, &controller_recovery::model(&p, &model).unwrap())
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let effective =
            repair185::effective_model(&p, &repair183::effective_model(&p, &effective).unwrap())
                .unwrap();
        validate_observer_config(&p, &effective, &config).unwrap();
    }
}
