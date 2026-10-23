//! Exact private144 suffix/assembly observation; preserves native/prefix history.
use super::*;
const UNIT: &str = "horizon-qualify-144-checkpoint-continuation-20261022-v1.service";
const SCRATCH: &str =
    "/home/sol/.jetstreamer-private/checkpoint-continuation-144-20261022-v1/scratch";
const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-continuation144-fleet-reader-20261022-v1/jetstreamer-r2";
const READER_SHA: &str = "47ce22c92728e9c3595d86d17a0fe07ea2ad00156ac585c48accdfba7dbe581a";

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
    p.continuation144.as_ref().is_some_and(|s| {
        d.range == "144"
            && d.controller_unit == UNIT
            && d.producer_unit == UNIT
            && d.expected_controller_invocation_id == s.invocation_id
            && d.expected_producer_invocation_id == s.invocation_id
    })
}
pub(super) fn writer(p: &Plan) -> bool {
    (p.continuation144.is_some()
        && p.tools.r2.path == Path::new(READER)
        && p.tools.r2.sha256 == READER_SHA
        && is_sha(READER_SHA))
        || assembly144::writer(p)
}
fn claim(p: &Profile) -> Value {
    json!({"epoch":144,"unit":UNIT,"invocation_id":p.invocation_id,"scratch_path":SCRATCH,"launch_receipt":p.launch})
}
fn checked(p: &Profile, r: &Value, e: &Value, plan: &Value, g: &Value) -> Result<(Value, Value)> {
    ensure!(
        r["schema"] == "jetstreamer-private-epoch144-checkpoint-continuation-launch-v2"
            && r["epoch"] == 144
            && r["unit"] == UNIT
            && r["invocation_id"] == p.invocation_id
            && r["launched"] == true
            && p.invocation_id.len() == 32
            && p.invocation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && r["node_sha256"]
                == "ac47031ac2cc42c0d7c343aebbfe049433fc76b7ee8d6da3ca2ac7de9f428dbd"
            && r["bootstrap_slot"] == 62639490
            && r["suffix_start_slot"] == 62639491
            && r["terminal_slot"] == 62639999
            && r["remaining_slots"] == 509
            && r["maximum_runtime_seconds"] == 7200
            && r["experimental_envelope_bytes"] == 192u64 << 30
            && r["protected_existing_floor_bytes"] == 3_916_063_202_758u64
            && r["private_suffix_authorized"] == true
            && r["private_assembly_authorized"] == true,
        "continuation144 launch differs from exact private full-path scope"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "full_epoch_verified",
        "local_retirement_authorized",
        "canonical_sidecar_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            r[flag] == false,
            "continuation144 launch grants forbidden authority:{flag}"
        );
    }
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
        "continuation144 event predecessor or inventory differs"
    );
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["producer_invocation_id"] == p.invocation_id
            && g["producer"]["invocation_id"] == p.invocation_id
            && g["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["guard_sha256"]
                == "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194"
            && g.get("trip_reason").is_some_and(Value::is_null)
            && g.get("worker_observation_error")
                .is_some_and(Value::is_null)
            && g["producer"]["pid"].as_u64().is_some_and(|n| n > 0)
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false
            && g["maximum_worker_vmas"] == 3500000
            && g["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && g["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 3_916_063_202_758)
            && g["available_bytes"]
                .as_u64()
                .zip(g["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["workers"].as_array().is_some_and(|w| w.len() == 1
                && w[0][0].as_u64().is_some_and(|n| n > 0)
                && w[0][1].as_u64().is_some_and(|n| n > 0 && n <= 3500000)),
        "continuation144 requires actual full-path guard first fire"
    );
    let expected = claim(p);
    ensure!(
        plan["diagnostics"]
            .as_array()
            .context("continuation144 plan diagnostics")?
            .iter()
            .filter(|d| d["unit"] == UNIT)
            .eq(std::iter::once(&expected))
            && e["diagnostics"]
                .as_array()
                .context("continuation144 event history")?
                .iter()
                .filter(|d| d["unit"]["Id"] == UNIT
                    && d["launch_invocation_id"] == p.invocation_id
                    && d["launch_receipt"].as_str() == p.launch.path.to_str()
                    && d["launch_receipt_sha256"] == p.launch.sha256)
                .count()
                == 1,
        "continuation144 event owner differs"
    );
    Ok((expected, e["admission_transition_guard"].clone()))
}
fn read(p: &Profile) -> Result<(Value, Value)> {
    let r = bound_json(&p.launch, true)?;
    let e = bound_json(&p.event_fleet, false)?;
    let plan = bound_json(&p.event_plan, true)?;
    let gb: Bound = serde_json::from_value(e["admission_transition_guard"].clone())?;
    let g = bound_json(&gb, false)?;
    checked(p, &r, &e, &plan, &g)
}
pub(super) fn completed_transition(p: &Plan) -> Result<Option<(Value, Value)>> {
    p.continuation144.as_ref().map(read).transpose()
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    let Some(profile) = &p.continuation144 else {
        return Ok(());
    };
    ensure!(
        is_101(p)?
            && p.native144_restore.is_some()
            && p.completed144_prefix.is_some()
            && p.prefix157_audit.is_some()
            && public198::refreshed(p)
            && writer(p)
            && !p.expected_epochs.contains(&144)
            && p.scope_101_200
                .as_ref()
                .is_some_and(|s| s.private144_observer
                    && original141::retained144_census(p, s)
                    && (owner(p, &s.diagnostic_ranges[0])
                        || assembly144::owner(p, &s.diagnostic_ranges[0]))),
        "foreign continuation144 routine profile"
    );
    read(profile)?;
    Ok(())
}
pub(super) fn transition_template(p: &Plan, f: &Value) -> Result<bool> {
    Ok(p.continuation144
        .as_ref()
        .map(read)
        .transpose()?
        .is_some_and(|(_, g)| f["admission_transition_guard"] == g))
}
fn fold(f: &mut Value, c: &Value, g: &Value) -> Result<()> {
    ensure!(
        f["diagnostics"]
            .as_array()
            .context("continuation144 template history")?
            .iter()
            .filter(|d| d["unit"] == UNIT)
            .eq(std::iter::once(c)),
        "continuation144 diagnostic removed,changed or duplicated"
    );
    ensure!(
        f["admission_transition_guard"].is_null() || f["admission_transition_guard"] == *g,
        "continuation144 cannot consume another guard"
    );
    f["admission_transition_guard"] = Value::Null;
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    assembly144::derive_fleet(p, f)?;
    if let Some(profile) = &p.continuation144 {
        let (c, g) = read(profile)?;
        fold(f, &c, &g)?;
    }
    Ok(())
}
fn row(row: &Value, iid: &str, observed: bool) -> Result<()> {
    ensure!(
        row["range"] == "144"
            && row["producer_unit"] == UNIT
            && row["expected_producer_invocation_id"] == iid
            && row["scratch_path"] == SCRATCH,
        "continuation144 observer owner differs"
    );
    if !observed {
        ensure!(
            row["controller_unit"] == UNIT
                && row["expected_controller_invocation_id"] == iid
                && row["worker_executable_basename"] == "historical-worker"
                && row.get("append_log").is_none_or(Value::is_null),
            "continuation144 observer config differs"
        );
        return Ok(());
    }
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            row[flag] == false,
            "continuation144 observer grants authority"
        );
    }
    match row["status"].as_str() {
        Some("unavailable") => ensure!(
            row["observation"].is_null()
                && row["error"].as_str().is_some_and(|s| !s.trim().is_empty()),
            "continuation144 absence is not terminal proof"
        ),
        Some("observed") => {
            let o = &row["observation"];
            ensure!(
                row["error"].is_null()
                    && o["range"] == "144"
                    && o["scratch_path"] == SCRATCH
                    && o["invocation_binding_stable"] == true,
                "continuation144 sample unstable"
            );
            for kind in ["controller", "producer"] {
                for point in ["before", "after"] {
                    let u = &o[format!("{kind}_{point}")];
                    ensure!(
                        u["invocation_id"] == iid
                            && u["restarts"] == 0
                            && matches!(u["active_state"].as_str(), Some("active" | "activating")),
                        "continuation144 sampled owner changed"
                    );
                }
            }
        }
        _ => anyhow::bail!("unknown continuation144 diagnostic outcome"),
    }
    Ok(())
}
pub(super) fn observer(p: &Plan, v: &Value, observed: bool) -> Result<()> {
    let profile = p
        .continuation144
        .as_ref()
        .context("continuation144 profile")?;
    ensure!(
        !v["replays"]
            .as_array()
            .context("ordinary census")?
            .iter()
            .any(|r| r["range"] == "144"),
        "continuation144 cannot become an ordinary ETA claim"
    );
    let rows = v["diagnostic_replays"]
        .as_array()
        .context("continuation144 diagnostics")?;
    ensure!(rows.len() == 1, "continuation144 diagnostic census differs");
    row(&rows[0], &profile.invocation_id, observed)
}
pub(super) fn enable(next: &mut Plan, config: &mut Value, b: &Bound) -> Result<()> {
    ensure!(
        is_101(next)?
            && next.continuation144.is_none()
            && next.native144_restore.is_some()
            && next.completed144_prefix.is_some(),
        "continuation144 requires intact native/prefix history"
    );
    let s: Spec = serde_json::from_slice(&bound_bytes(b, true)?)?;
    ensure!(
        s.schema == "jetstreamer-continuation144-routine-spec-v2"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.r2_mutations
            && s.event_fleet.path.parent() == Some(Path::new(FLEET_ROOT_101)),
        "foreign continuation144 handoff spec"
    );
    let launch = bound_json(&s.launch, true)?;
    let event = bound_json(&s.event_fleet, false)?;
    let ep = bound_json(&s.event_plan, true)?;
    ensure!(
        event["previous_fleet"] == serde_json::to_value(&next.previous_fleet)?
            && event["observer_sha256"] == next.previous_observer.sha256
            && ep["previous_fleet"] == serde_json::to_value(&next.previous_fleet)?
            && ep["observer"] == serde_json::to_value(&next.previous_observer)?,
        "continuation144 handoff changes predecessor"
    );
    let profile = Profile {
        launch: s.launch,
        event_fleet: s.event_fleet,
        event_plan: s.event_plan,
        invocation_id: launch["invocation_id"]
            .as_str()
            .context("continuation144 invocation")?
            .into(),
    };
    let (c, g) = read(&profile)?;
    // Reproduce the exact append-only renderer delta; everything else, including
    // large consensus integers and original diagnostic histories, must be equal.
    let mut expected = bound_json(&next.fleet_template, true)?;
    expected["previous_fleet"] = serde_json::to_value(&next.previous_fleet)?;
    expected["output"] = json!(profile.event_fleet.path);
    expected["admission_transition_guard"] = g.clone();
    expected["diagnostics"]
        .as_array_mut()
        .context("old diagnostic history")?
        .push(c.clone());
    let names = expected["tracked_units"]
        .as_array_mut()
        .context("old tracked units")?;
    if !names.contains(&json!(UNIT)) {
        names.push(json!(UNIT));
    }
    expected["gates"]["144"]["evidence"]
        .as_array_mut()
        .context("old144 evidence")?
        .extend([serde_json::to_value(&profile.launch)?, g]);
    ensure!(
        expected == ep,
        "continuation144 event changed other claims,history,gate or scalar"
    );
    let scope = next
        .scope_101_200
        .as_mut()
        .context("continuation144 scope")?;
    migrate(scope, config, &profile.invocation_id)?;
    next.previous_fleet = profile.event_fleet.clone();
    next.fleet_template = profile.event_plan.clone();
    next.continuation144 = Some(profile);
    next.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    next.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
    validate(next)?;
    Ok(())
}
fn migrate(scope: &mut Scope101200, config: &mut Value, iid: &str) -> Result<()> {
    ensure!(
        scope.diagnostic_ranges.len() == 1
            && scope.diagnostic_ranges[0].producer_unit == native144::UNIT
            && scope.diagnostic_ranges[0].controller_unit == native144::UNIT
            && scope.diagnostic_ranges[0].expected_controller_invocation_id
                == scope.diagnostic_ranges[0].expected_producer_invocation_id
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "continuation144 cannot replace newer diagnostic"
    );
    let rows = config["diagnostic_replays"]
        .as_array_mut()
        .context("old native144 observer")?;
    ensure!(
        rows.len() == 1
            && rows[0]["producer_unit"] == native144::UNIT
            && rows[0]["controller_unit"] == native144::UNIT
            && rows[0]["expected_controller_invocation_id"]
                == scope.diagnostic_ranges[0].expected_controller_invocation_id
            && rows[0]["expected_producer_invocation_id"]
                == scope.diagnostic_ranges[0].expected_producer_invocation_id,
        "continuation144 observer already migrated"
    );
    rows[0] = json!({"range":"144","controller_unit":UNIT,"producer_unit":UNIT,"expected_controller_invocation_id":iid,
        "expected_producer_invocation_id":iid,"scratch_path":SCRATCH,"worker_executable_basename":"historical-worker"});
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
    fn fixture() -> (Profile, Value, Value, Value, Value) {
        let b = |path: &str| Bound {
            path: path.into(),
            sha256: "a".repeat(64),
        };
        let p = Profile {
            launch: b("/launch"),
            event_fleet: b("/event"),
            event_plan: b("/event-plan"),
            invocation_id: "b".repeat(32),
        };
        let mut r = json!({"schema":"jetstreamer-private-epoch144-checkpoint-continuation-launch-v2","epoch":144,"unit":UNIT,"invocation_id":p.invocation_id,"launched":true,
            "node_sha256":"ac47031ac2cc42c0d7c343aebbfe049433fc76b7ee8d6da3ca2ac7de9f428dbd","bootstrap_slot":62639490,"suffix_start_slot":62639491,
            "terminal_slot":62639999,"remaining_slots":509,"maximum_runtime_seconds":7200,"experimental_envelope_bytes":192u64<<30,
            "protected_existing_floor_bytes":3916063202758u64,"private_suffix_authorized":true,"private_assembly_authorized":true,
            "required_guard_minimum_free_bytes":4500000000000u64,"previous_fleet":{"path":"/prior","sha256":"c".repeat(64)},
            "observer":{"path":"/observer","sha256":"d".repeat(64)}});
        for flag in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
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
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","producer_invocation_id":p.invocation_id,
            "producer":{"invocation_id":p.invocation_id,"cgroup":format!("/system.slice/{UNIT}"),"restarts":0,"active":"active","sub":"running",
                "pid":123,"load_state":"loaded","restart_policy":"no","kill_mode":"control-group","delegated":false},
            "guard_sha256":"eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194","trip_reason":null,"worker_observation_error":null,
            "remote_mutations":false,"r2_mutations":false,"maximum_worker_vmas":3500000,"minimum_free_bytes":r["required_guard_minimum_free_bytes"],
            "available_bytes":4500000000001u64,"workers":[[123,400000]]});
        let e = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,"producer_mutations":false,
            "publication_authorized":false,"remote_mutations":false,"plan":p.event_plan.path,"plan_sha256":p.event_plan.sha256,
            "observer_sha256":r["observer"]["sha256"],"observer_receipt":"/observer","previous_fleet":r["previous_fleet"],"inventory":{"anomalies":0},
            "admission_transition_guard":{"path":"/guard","sha256":"e".repeat(64)},
            "diagnostics":[{"unit":{"Id":UNIT},"launch_invocation_id":p.invocation_id,"launch_receipt":"/launch","launch_receipt_sha256":p.launch.sha256}]});
        let plan = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":101,"last_epoch":200,"admission_transition_guard":e["admission_transition_guard"],
            "observer":r["observer"],"previous_fleet":r["previous_fleet"],"diagnostics":[claim(&p)]});
        (p, r, e, plan, g)
    }
    #[test]
    fn guarded_event_cannot_borrow_native_only_budget_predecessor_or_authority() {
        let (p, r, e, plan, g) = fixture();
        checked(&p, &r, &e, &plan, &g).unwrap();
        for (key, v) in [
            ("experimental_envelope_bytes", json!(40u64 << 30)),
            ("unit", json!(native144::UNIT)),
            ("publication_authorized", json!(true)),
            ("remaining_slots", json!(510)),
        ] {
            let mut bad = r.clone();
            bad[key] = v;
            assert!(checked(&p, &bad, &e, &plan, &g).is_err(), "{key}");
        }
        for (key, v) in [
            ("previous_fleet", json!({})),
            ("plan_sha256", json!("f".repeat(64))),
            ("producer_mutations", json!(true)),
        ] {
            let mut bad = e.clone();
            bad[key] = v;
            assert!(checked(&p, &r, &bad, &plan, &g).is_err(), "{key}");
        }
        for (key, v) in [
            ("workers", json!([])),
            ("workers", json!([[1, 3500001]])),
            ("worker_observation_error", json!("unreadable")),
            ("minimum_free_bytes", json!(3916063202758u64)),
        ] {
            let mut bad = g.clone();
            bad[key] = v;
            assert!(checked(&p, &r, &e, &plan, &bad).is_err(), "{key}");
        }
        let mut bad = g;
        bad.as_object_mut().unwrap().remove("trip_reason");
        assert!(checked(&p, &r, &e, &plan, &bad).is_err());
    }
    #[test]
    fn migration_changes_only_exact_old_diagnostic_and_preserves_production_clocks_and_u64s() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let scope = p.scope_101_200.as_mut().unwrap();
        let old = "f".repeat(32);
        scope.private144_observer = true;
        scope.diagnostic_ranges[0] = DiagnosticClaim {
            range: "144".into(),
            controller_unit: native144::UNIT.into(),
            producer_unit: native144::UNIT.into(),
            expected_controller_invocation_id: old.clone(),
            expected_producer_invocation_id: old.clone(),
        };
        let mut config = json!({"replays":[{"counter":u64::MAX}],"previous_sample":"keep","diagnostic_replays":[{
            "range":"144","controller_unit":native144::UNIT,"producer_unit":native144::UNIT,"expected_controller_invocation_id":old,
            "expected_producer_invocation_id":old,"scratch_path":"/old/native/scratch","worker_executable_basename":"historical-worker"}]});
        let before = config.clone();
        let iid = "b".repeat(32);
        migrate(scope, &mut config, &iid).unwrap();
        row(&config["diagnostic_replays"][0], &iid, false).unwrap();
        assert_eq!(config["replays"], before["replays"]);
        assert_eq!(config["previous_sample"], before["previous_sample"]);
        assert!(migrate(scope, &mut config, &iid).is_err());
        p.continuation144 = Some(fixture().0);
        p.tools.r2 = Bound {
            path: READER.into(),
            sha256: READER_SHA.into(),
        };
        assert!(is_101(&p).unwrap());
        assert!(writer(&p));
        assert_eq!(
            generation_101(&p),
            "continuation144-upload198-refresh-completed144-v2"
        );
        p.tools.r2.sha256 = "0".repeat(64);
        assert!(!writer(&p));
    }
    #[test]
    fn private_observer_never_turns_unavailable_into_eta_or_cleanup() {
        let iid = "a".repeat(32);
        let r = json!({"range":"144","producer_unit":UNIT,"expected_producer_invocation_id":iid,"scratch_path":SCRATCH,
            "status":"unavailable","observation":null,"error":"prefix validation,assembly,terminal or unreadable",
            "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
        row(&r, &iid, true).unwrap();
        for (key, v) in [
            ("producer_unit", json!(native144::UNIT)),
            ("publication_authorized", json!(true)),
            ("error", json!("")),
            ("current_sidecar_eta_valid", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[key] = v;
            assert!(row(&bad, &iid, true).is_err());
        }
    }
    #[test]
    fn fold_preserves_prior_histories_and_u64s_and_rejects_foreign_guard() {
        let c = json!({"epoch":144,"unit":UNIT,"invocation_id":"a".repeat(32)});
        let g = json!({"path":"/guard","sha256":"b".repeat(64)});
        let mut f = json!({"diagnostics":[{"unit":native144::UNIT,"counter":u64::MAX},{"unit":"prefix144","counter":u64::MAX-1},c],"admission_transition_guard":g,"gates":{"144":{"counter":u64::MAX}}});
        let old = f.clone();
        fold(&mut f, &c, &g).unwrap();
        assert_eq!(f["diagnostics"], old["diagnostics"]);
        assert_eq!(f["gates"], old["gates"]);
        let once = f.clone();
        fold(&mut f, &c, &g).unwrap();
        assert_eq!(f, once);
        f["admission_transition_guard"] = json!({"foreign":true});
        assert!(fold(&mut f, &c, &g).is_err());
    }
}
