//! Exact guarded assembly-only handoff. Original continuation remains history.
use super::*;
const UNIT: &str = "horizon-qualify-144-assembly-only-recovery-20261022-v1.service";
const ORIGINAL: &str = "horizon-qualify-144-checkpoint-continuation-20261022-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch144-assembly-only-20261022-v2";
const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-assembly144-fleet-reader-20261022-v1/jetstreamer-r2";
const READER_SHA: &str = "16d95994451b4d665154d19609ff76e40ad4e40f3c82bfc96702298cf1ed676b";
const READER_V2: &str =
    "/usr/local/lib/jetstreamer/horizon-assembly144-scan-fleet-reader-20261022-v2/jetstreamer-r2";
const READER_V2_SHA: &str = "60b51166d0e953c887bda59e3f7c0d9aafd90f91de7af3aa51fc8af271f8bd88";
const TOOL_SHA: &str = "25402432882dc8fdcb7331c34be7a20056c0df13ce0eaec33f571edba9695b97";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    launch: Bound,
    event_fleet: Bound,
    event_plan: Bound,
    invocation_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    launch: Bound,
    event_fleet: Bound,
    event_plan: Bound,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
pub(super) fn owner(p: &Plan, d: &DiagnosticClaim) -> bool {
    p.assembly144_recovery.as_ref().is_some_and(|s| {
        d.range == "144"
            && d.controller_unit == UNIT
            && d.producer_unit == UNIT
            && d.expected_controller_invocation_id == s.invocation_id
            && d.expected_producer_invocation_id == s.invocation_id
    })
}
pub(super) fn writer(p: &Plan) -> bool {
    p.assembly144_recovery.is_some()
        && ((p.tools.r2.path == Path::new(READER)
            && p.tools.r2.sha256 == READER_SHA
            && is_sha(READER_SHA))
            || reader_v2(p))
}
pub(super) fn reader_v2(p: &Plan) -> bool {
    p.assembly144_recovery.is_some()
        && ((p.tools.r2.path == Path::new(READER_V2) && p.tools.r2.sha256 == READER_V2_SHA)
            || native141::reader(p))
}
pub(super) fn upgrade_reader(p: &mut Plan) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.assembly144_recovery.is_some()
            && p.continuation144.is_some()
            && p.tools.r2.path == Path::new(READER)
            && p.tools.r2.sha256 == READER_SHA,
        "assembly reader migration needs exact original private profile"
    );
    p.tools.r2 = Bound {
        path: READER_V2.into(),
        sha256: READER_V2_SHA.into(),
    };
    Ok(())
}
fn claim(p: &Profile) -> Value {
    json!({"epoch":144,"unit":UNIT,"invocation_id":p.invocation_id,"scratch_path":ROOT,"launch_receipt":p.launch})
}
fn checked(
    p: &Profile,
    r: &Value,
    e: &Value,
    plan: &Value,
    g: &Value,
    a: &Value,
) -> Result<(Value, Value)> {
    ensure!(
        r["schema"] == "jetstreamer-private144-assembly-only-launch-v1"
            && r["epoch"] == 144
            && r["unit"] == UNIT
            && r["invocation_id"] == p.invocation_id
            && p.invocation_id.len() == 32
            && p.invocation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && r["launched"] == true
            && r["assembly_only_no_replay"] == true
            && r["assembler_sha256"] == TOOL_SHA
            && r["output_root"] == ROOT
            && r["maximum_runtime_seconds"] == 86400
            && r["maximum_archive_bytes"] == 112u64 << 30
            && r["candidate_incremental_peak_bytes"] == 160u64 << 30
            && r["protected_existing_floor_bytes"] == 3_916_063_202_758u64,
        "assembly144 exact private launch differs"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "replay_launch_authorized",
        "full_epoch_verified",
        "local_retirement_authorized",
        "canonical_sidecar_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(r[flag] == false, "assembly launch grants authority:{flag}");
    }
    ensure!(
        a["schema"] == "jetstreamer-private144-assembly-only-admission-v1"
            && a["admitted"] == true
            && a["assembler_sha256"] == TOOL_SHA
            && a["assembly_only_no_replay"] == true
            && a["candidate_incremental_peak_bytes"] == 160u64 << 30
            && a["protected_existing_floor_bytes"] == 3_916_063_202_758u64
            && a["maximum_runtime_seconds"] == 86400
            && a["maximum_archive_bytes"] == 112u64 << 30
            && a["output_root"] == ROOT
            && a["output_filesystem"] == "/home/sol"
            && a["output_filesystem_device"].as_u64().is_some()
            && a["original_timeout"]["Id"] == ORIGINAL
            && a["original_timeout"]["InvocationID"] == "8fddd3ef045c4fe5b12c7d25f43a4b73"
            && a["original_timeout"]["MainPID"] == "0"
            && a["original_timeout"]["NRestarts"] == "0"
            && a["original_timeout"]["Result"] == "timeout"
            && a["original_timeout"]["ActiveState"] == "failed"
            && a["original_timeout"]["SubState"] == "failed"
            && a["original_timeout"]["Restart"] == "no"
            && a["original_timeout"]["RuntimeMaxUSec"] == "2h"
            && a["required_guard_minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && a["observer"] == r["observer"]
            && a["fleet"] == r["previous_fleet"],
        "assembly admission/original timeout differs"
    );
    for flag in [
        "replay_launch_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            a[flag] == false,
            "assembly admission grants authority:{flag}"
        );
    }
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("assembly admission clock")?;
    let launched = r["recorded_unix_seconds"]
        .as_u64()
        .context("assembly launch clock")?;
    ensure!(
        admitted <= launched && launched - admitted <= 900,
        "assembly launch from stale/future admission"
    );
    ensure!(
        e["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && e["first_epoch"] == 101
            && e["last_epoch"] == 200
            && e["producer_mutations"] == false
            && e["publication_authorized"] == false
            && e["remote_mutations"] == false
            && e["plan"].as_str() == p.event_plan.path.to_str()
            && e["plan_sha256"] == p.event_plan.sha256
            && plan["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
            && plan["first_epoch"] == 101
            && plan["last_epoch"] == 200
            && plan["admission_transition_guard"] == e["admission_transition_guard"]
            && e["observer_sha256"] == plan["observer"]["sha256"]
            && e["observer_receipt"] == plan["observer"]["path"]
            && e["previous_fleet"] == r["previous_fleet"]
            && plan["previous_fleet"] == r["previous_fleet"]
            && plan["observer"] == r["observer"]
            && e["inventory"]["anomalies"] == 0,
        "assembly event predecessor/plan/inventory differs"
    );
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["producer_invocation_id"] == p.invocation_id
            && g["producer"]["invocation_id"] == p.invocation_id
            && g["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["pid"].as_u64().is_some_and(|n| n > 0)
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["guard_sha256"]
                == "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194"
            && g.get("trip_reason").is_some_and(Value::is_null)
            && g.get("worker_observation_error")
                .is_some_and(Value::is_null)
            && g["workers"].as_array().is_some_and(Vec::is_empty)
            && g["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && g["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 3_916_063_202_758)
            && g["available_bytes"]
                .as_u64()
                .zip(g["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["maximum_worker_vmas"] == 3500000
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "assembly requires genuine zero-worker no-trip guard first fire"
    );
    let c = claim(p);
    ensure!(
        plan["diagnostics"]
            .as_array()
            .context("assembly plan history")?
            .iter()
            .filter(|d| d["unit"] == UNIT)
            .eq(std::iter::once(&c))
            && plan["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|d| d["unit"] == ORIGINAL
                    && d["invocation_id"] == "8fddd3ef045c4fe5b12c7d25f43a4b73")
                .count()
                == 1
            && e["diagnostics"]
                .as_array()
                .context("assembly event history")?
                .iter()
                .filter(|d| d["unit"]["Id"] == UNIT
                    && d["launch_invocation_id"] == p.invocation_id
                    && d["launch_receipt"].as_str() == p.launch.path.to_str()
                    && d["launch_receipt_sha256"] == p.launch.sha256)
                .count()
                == 1,
        "assembly missing/changed/duplicate owner history"
    );
    Ok((c, e["admission_transition_guard"].clone()))
}
fn read(p: &Profile) -> Result<(Value, Value)> {
    let r = bound_json(&p.launch, true)?;
    let e = bound_json(&p.event_fleet, false)?;
    let plan = bound_json(&p.event_plan, true)?;
    let g = bound_json(
        &serde_json::from_value(e["admission_transition_guard"].clone())?,
        false,
    )?;
    let a = bound_json(&serde_json::from_value(r["admission"].clone())?, true)?;
    checked(p, &r, &e, &plan, &g, &a)
}
pub(super) fn completed_transition(p: &Plan) -> Result<Option<(Value, Value)>> {
    p.assembly144_recovery.as_ref().map(read).transpose()
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    if let Some(s) = &p.assembly144_recovery {
        ensure!(
            is_101(p)?
                && writer(p)
                && p.continuation144.is_some()
                && p.native144_restore.is_some()
                && p.completed144_prefix.is_some()
                && !p.expected_epochs.contains(&144)
                && p.scope_101_200
                    .as_ref()
                    .is_some_and(|s| s.private144_observer
                        && original141::retained144_census(p, s)
                        && owner(p, &s.diagnostic_ranges[0])),
            "foreign assembly144 routine profile"
        );
        read(s)?;
    }
    Ok(())
}
pub(super) fn transition_template(p: &Plan, f: &Value) -> Result<bool> {
    Ok(completed_transition(p)?.is_some_and(|(_, g)| f["admission_transition_guard"] == g))
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    if let Some((c, g)) = completed_transition(p)? {
        ensure!(
            f["diagnostics"]
                .as_array()
                .context("assembly template history")?
                .iter()
                .filter(|d| d["unit"] == UNIT)
                .eq(std::iter::once(&c))
                && (f["admission_transition_guard"].is_null()
                    || f["admission_transition_guard"] == g),
            "assembly cannot replace history or another guard"
        );
        f["admission_transition_guard"] = Value::Null;
    }
    Ok(())
}
fn row(v: &Value, iid: &str, observed: bool) -> Result<()> {
    ensure!(
        v["range"] == "144"
            && v["producer_unit"] == UNIT
            && v["expected_producer_invocation_id"] == iid
            && v["scratch_path"] == ROOT,
        "assembly observer scope differs"
    );
    if observed {
        ensure!(
            v["status"] == "unavailable"
                && v["observation"].is_null()
                && v["error"].as_str().is_some_and(|s| !s.trim().is_empty()),
            "assembly-only cannot produce worker/resource evidence"
        );
        for flag in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "replay_launch_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            ensure!(v[flag] == false, "assembly observer grants authority");
        }
    } else {
        ensure!(
            v["controller_unit"] == UNIT
                && v["expected_controller_invocation_id"] == iid
                && v["worker_executable_basename"] == "historical-worker"
                && v.get("append_log").is_none_or(Value::is_null),
            "assembly observer config differs"
        );
    }
    Ok(())
}
pub(super) fn observer(p: &Plan, v: &Value, observed: bool) -> Result<()> {
    let s = p
        .assembly144_recovery
        .as_ref()
        .context("assembly profile")?;
    ensure!(
        !v["replays"]
            .as_array()
            .context("assembly ordinary census")?
            .iter()
            .any(|r| r["range"] == "144"),
        "assembly cannot be ordinary replay"
    );
    let rows = v["diagnostic_replays"]
        .as_array()
        .context("assembly diagnostic census")?;
    ensure!(rows.len() == 1, "assembly diagnostic census differs");
    row(&rows[0], &s.invocation_id, observed)
}
pub(super) fn enable(next: &mut Plan, config: &mut Value, b: &Bound) -> Result<()> {
    ensure!(
        is_101(next)? && next.assembly144_recovery.is_none() && next.continuation144.is_some(),
        "assembly requires intact original continuation profile"
    );
    let s: Spec = serde_json::from_slice(&bound_bytes(b, true)?)?;
    ensure!(
        s.schema == "jetstreamer-assembly144-routine-spec-v1"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.r2_mutations
            && s.event_fleet.path.parent() == Some(Path::new(FLEET_ROOT_101)),
        "foreign assembly handoff spec"
    );
    let launch = bound_json(&s.launch, true)?;
    let profile = Profile {
        launch: s.launch,
        event_fleet: s.event_fleet,
        event_plan: s.event_plan,
        invocation_id: launch["invocation_id"]
            .as_str()
            .context("assembly iid")?
            .into(),
    };
    let (c, g) = read(&profile)?;
    let ep = bound_json(&profile.event_plan, true)?;
    let mut expected = bound_json(&next.fleet_template, true)?;
    expected["previous_fleet"] = serde_json::to_value(&next.previous_fleet)?;
    expected["output"] = json!(profile.event_fleet.path);
    expected["admission_transition_guard"] = g.clone();
    expected["diagnostics"]
        .as_array_mut()
        .context("assembly old history")?
        .push(c);
    expected["tracked_units"]
        .as_array_mut()
        .context("assembly tracked history")?
        .push(json!(UNIT));
    expected["gates"]["144"]["evidence"]
        .as_array_mut()
        .context("assembly gate history")?
        .extend([serde_json::to_value(&profile.launch)?, g]);
    ensure!(
        expected == ep && ep["observer"] == serde_json::to_value(&next.previous_observer)?,
        "assembly event changes other claims/history/gates/scalars"
    );
    let scope = next.scope_101_200.as_mut().context("assembly scope")?;
    migrate(scope, config, &profile.invocation_id)?;
    next.previous_fleet = profile.event_fleet.clone();
    next.fleet_template = profile.event_plan.clone();
    next.assembly144_recovery = Some(profile);
    next.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    next.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
    validate(next)
}
fn migrate(scope: &mut Scope101200, config: &mut Value, iid: &str) -> Result<()> {
    ensure!(
        scope.diagnostic_ranges.len() == 1
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && scope.diagnostic_ranges[0].producer_unit == ORIGINAL
            && scope.diagnostic_ranges[0].expected_producer_invocation_id
                == "8fddd3ef045c4fe5b12c7d25f43a4b73"
            && scope.diagnostic_ranges[0].controller_unit == ORIGINAL
            && scope.diagnostic_ranges[0].expected_controller_invocation_id
                == scope.diagnostic_ranges[0].expected_producer_invocation_id,
        "assembly cannot replace foreign/newer diagnostic"
    );
    let rows = config["diagnostic_replays"]
        .as_array_mut()
        .context("assembly old diagnostic config")?;
    ensure!(
        rows.len() == 1
            && rows[0]["producer_unit"] == ORIGINAL
            && rows[0]["controller_unit"] == ORIGINAL
            && rows[0]["expected_producer_invocation_id"]
                == scope.diagnostic_ranges[0].expected_producer_invocation_id
            && rows[0]["expected_controller_invocation_id"]
                == scope.diagnostic_ranges[0].expected_controller_invocation_id,
        "assembly observer already changed"
    );
    rows[0] = json!({"range":"144","controller_unit":UNIT,"producer_unit":UNIT,"expected_controller_invocation_id":iid,"expected_producer_invocation_id":iid,
        "scratch_path":ROOT,"worker_executable_basename":"historical-worker"});
    scope.diagnostic_ranges[0] = DiagnosticClaim {
        range: "144".into(),
        controller_unit: UNIT.into(),
        producer_unit: UNIT.into(),
        expected_controller_invocation_id: iid.into(),
        expected_producer_invocation_id: iid.into(),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reader_upgrade_changes_only_exact_tool_and_gets_distinct_namespaces() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let profile = fixture().0;
        p.assembly144_recovery = Some(profile);
        p.continuation144=Some(serde_json::from_value(json!({"launch":{"path":"/old","sha256":"a".repeat(64)},
            "event_fleet":{"path":"/oldfleet","sha256":"b".repeat(64)},"event_plan":{"path":"/oldplan","sha256":"c".repeat(64)},
            "invocation_id":"8fddd3ef045c4fe5b12c7d25f43a4b73"})).unwrap());
        let scope = p.scope_101_200.as_mut().unwrap();
        scope.private144_observer = true;
        scope.diagnostic_ranges = vec![DiagnosticClaim {
            range: "144".into(),
            controller_unit: UNIT.into(),
            producer_unit: UNIT.into(),
            expected_controller_invocation_id: "b".repeat(32),
            expected_producer_invocation_id: "b".repeat(32),
        }];
        p.tools.r2 = Bound {
            path: READER.into(),
            sha256: READER_SHA.into(),
        };
        assert_eq!(
            generation_101(&p),
            "assembly144-upload198-refresh-completed144-v1"
        );
        let mut expected = serde_json::to_value(&p).unwrap();
        upgrade_reader(&mut p).unwrap();
        assert!(writer(&p));
        assert!(reader_v2(&p));
        expected["tools"]["r2"] = serde_json::to_value(&p.tools.r2).unwrap();
        assert_eq!(serde_json::to_value(&p).unwrap(), expected);
        assert_eq!(
            generation_101(&p),
            "assembly144-upload198-refresh-completed144-v2"
        );
        assert!(upgrade_reader(&mut p).is_err());
        p.tools.r2.sha256 = "d".repeat(64);
        assert!(!writer(&p));
        assert!(!reader_v2(&p));
    }
    fn fixture() -> (Profile, Value, Value, Value, Value, Value) {
        let b = || Bound {
            path: "/bound/evidence".into(),
            sha256: "a".repeat(64),
        };
        let p = Profile {
            launch: b(),
            event_fleet: b(),
            event_plan: b(),
            invocation_id: "b".repeat(32),
        };
        let mut r = json!({"schema":"jetstreamer-private144-assembly-only-launch-v1","epoch":144,"unit":UNIT,
            "invocation_id":p.invocation_id,"launched":true,"assembly_only_no_replay":true,"assembler_sha256":TOOL_SHA,
            "output_root":ROOT,"maximum_runtime_seconds":86400,"maximum_archive_bytes":112u64<<30,
            "candidate_incremental_peak_bytes":160u64<<30,"protected_existing_floor_bytes":3916063202758u64,
            "required_guard_minimum_free_bytes":4000000000000u64,"previous_fleet":b(),"observer":b(),"recorded_unix_seconds":1001});
        for flag in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "replay_launch_authorized",
            "full_epoch_verified",
            "local_retirement_authorized",
            "canonical_sidecar_authorized",
            "runtime_promotion_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[flag] = json!(false);
        }
        let plan = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":101,"last_epoch":200,
            "observer":b(),"previous_fleet":b(),"admission_transition_guard":b(),"diagnostics":[
                {"epoch":144,"unit":ORIGINAL,"invocation_id":"8fddd3ef045c4fe5b12c7d25f43a4b73","counter":u64::MAX},claim(&p)]});
        let e = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,"producer_mutations":false,
            "publication_authorized":false,"remote_mutations":false,"plan":p.event_plan.path,"plan_sha256":p.event_plan.sha256,
            "admission_transition_guard":b(),"observer_sha256":plan["observer"]["sha256"],"observer_receipt":plan["observer"]["path"],
            "previous_fleet":r["previous_fleet"],"inventory":{"anomalies":0},"diagnostics":[{"unit":{"Id":UNIT},
                "launch_invocation_id":p.invocation_id,"launch_receipt":p.launch.path,"launch_receipt_sha256":p.launch.sha256}]});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","producer_invocation_id":p.invocation_id,
            "producer":{"invocation_id":p.invocation_id,"cgroup":format!("/system.slice/{UNIT}"),"restarts":0,"active":"active","sub":"running",
                "load_state":"loaded","pid":123,"restart_policy":"no","kill_mode":"control-group","delegated":false},
            "guard_sha256":"eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194","trip_reason":null,
            "worker_observation_error":null,"workers":[],"minimum_free_bytes":r["required_guard_minimum_free_bytes"],
            "available_bytes":4000000000001u64,"maximum_worker_vmas":3500000,"remote_mutations":false,"r2_mutations":false});
        let mut a = json!({"schema":"jetstreamer-private144-assembly-only-admission-v1","admitted":true,"assembler_sha256":TOOL_SHA,
            "assembly_only_no_replay":true,"output_root":ROOT,"output_filesystem":"/home/sol","output_filesystem_device":123,
            "candidate_incremental_peak_bytes":160u64<<30,"protected_existing_floor_bytes":3916063202758u64,
            "maximum_runtime_seconds":86400,"maximum_archive_bytes":112u64<<30,"recorded_unix_seconds":1000,
            "required_guard_minimum_free_bytes":r["required_guard_minimum_free_bytes"],"observer":r["observer"],"fleet":r["previous_fleet"],
            "original_timeout":{"Id":ORIGINAL,"InvocationID":"8fddd3ef045c4fe5b12c7d25f43a4b73","MainPID":"0","NRestarts":"0",
                "Result":"timeout","ActiveState":"failed","SubState":"failed","Restart":"no","RuntimeMaxUSec":"2h"}});
        for flag in [
            "replay_launch_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            a[flag] = json!(false);
        }
        (p, r, e, plan, g, a)
    }
    #[test]
    fn exact_assembly_requires_distinct_scope_and_preserved_original_history() {
        let (p, r, e, plan, g, a) = fixture();
        checked(&p, &r, &e, &plan, &g, &a).unwrap();
        for (key, v) in [
            (
                "schema",
                json!("jetstreamer-private-epoch144-checkpoint-continuation-launch-v2"),
            ),
            ("unit", json!(ORIGINAL)),
            ("assembler_sha256", json!("c".repeat(64))),
            ("publication_authorized", json!(true)),
            ("maximum_runtime_seconds", json!(7200)),
            ("ordinary_replay_claim", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[key] = v;
            assert!(checked(&p, &bad, &e, &plan, &g, &a).is_err(), "{key}");
        }
        let mut bad = plan.clone();
        bad["diagnostics"][0]["invocation_id"] = json!("different");
        assert!(checked(&p, &r, &e, &bad, &g, &a).is_err());
        let mut bad = a.clone();
        bad["original_timeout"]["Result"] = json!("success");
        assert!(checked(&p, &r, &e, &plan, &g, &bad).is_err());
        let mut bad = g;
        bad["workers"] = json!([[123, 400000]]);
        assert!(checked(&p, &r, &e, &plan, &bad, &a).is_err());
    }
    #[test]
    fn observer_migration_preserves_other_claims_and_never_creates_a_rate() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let scope = p.scope_101_200.as_mut().unwrap();
        scope.private144_observer = true;
        scope.diagnostic_ranges = vec![DiagnosticClaim {
            range: "144".into(),
            controller_unit: ORIGINAL.into(),
            producer_unit: ORIGINAL.into(),
            expected_controller_invocation_id: "8fddd3ef045c4fe5b12c7d25f43a4b73".into(),
            expected_producer_invocation_id: "8fddd3ef045c4fe5b12c7d25f43a4b73".into(),
        }];
        let mut config = json!({"replays":[{"counter":u64::MAX}],"previous_sample":"keep","diagnostic_replays":[{
            "producer_unit":ORIGINAL,"controller_unit":ORIGINAL,"expected_producer_invocation_id":"8fddd3ef045c4fe5b12c7d25f43a4b73",
            "expected_controller_invocation_id":"8fddd3ef045c4fe5b12c7d25f43a4b73"}]});
        let before = config.clone();
        migrate(scope, &mut config, &"b".repeat(32)).unwrap();
        assert_eq!(config["replays"], before["replays"]);
        assert_eq!(config["previous_sample"], before["previous_sample"]);
        row(&config["diagnostic_replays"][0], &"b".repeat(32), false).unwrap();
        assert!(migrate(scope, &mut config, &"b".repeat(32)).is_err());
        let mut r = json!({"range":"144","producer_unit":UNIT,"expected_producer_invocation_id":"b".repeat(32),"scratch_path":ROOT,
            "status":"unavailable","observation":null,"error":"assembly has no historical worker"});
        for flag in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "replay_launch_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            r[flag] = json!(false);
        }
        row(&r, &"b".repeat(32), true).unwrap();
        r["status"] = json!("observed");
        assert!(row(&r, &"b".repeat(32), true).is_err());
    }
}
