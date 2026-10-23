//! Add the exact private original141 owner without replacing old144 history.
use super::*;
const UNIT: &str = "horizon-qualify-141-original-entry-root-20261023-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-original-entry-root-20261023-v1";
const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-fleet-reader-20261023-v2/jetstreamer-r2";
const READER_SHA: &str = "97b65c2fe933d6f765dcbbd3e781626d12021f5ec21eb162b2fe20df3210fef8";
const NODE_SHA: &str = "d0c784a403d65819de70a499fc4d981217fd16fc30b70fac7e5ec979d0423ff0";
const FIRST_GUARD: &str = "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194";
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
    remote_mutations: bool,
    r2_mutations: bool,
}
pub(super) fn enabled(p: &Plan) -> bool {
    p.original141_root.is_some()
}
pub(super) fn reader(p: &Plan) -> bool {
    enabled(p) && p.tools.r2.path == Path::new(READER) && p.tools.r2.sha256 == READER_SHA
}
fn iid(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn owner(p: &Plan, d: &DiagnosticClaim) -> bool {
    p.original141_root.as_ref().is_some_and(|s| {
        d.range == "141"
            && d.controller_unit == UNIT
            && d.producer_unit == UNIT
            && d.expected_controller_invocation_id == s.invocation_id
            && d.expected_producer_invocation_id == s.invocation_id
            && iid(&s.invocation_id)
    })
}
fn claim(s: &Profile) -> Value {
    json!({"epoch":141,"unit":UNIT,"invocation_id":s.invocation_id,"scratch_path":format!("{ROOT}/scratch"),"launch_receipt":s.launch})
}
fn checked(s: &Profile, r: &Value, e: &Value, ep: &Value, g: &Value) -> Result<()> {
    ensure!(
        s.launch.path == Path::new(ROOT).join("receipts/launch.json")
            && iid(&s.invocation_id)
            && r["schema"] == "jetstreamer-private-epoch141-original-entry-root-launch-v2"
            && r["epoch"] == 141
            && r["unit"] == UNIT
            && r["invocation_id"] == s.invocation_id
            && r["launched"] == true
            && r["node_sha256"] == NODE_SHA
            && r["bootstrap_slot"] == 60911751
            && r["replay_start_slot"] == 60911752
            && r["terminal_root_slot"] == 61328765
            && r["run_root"] == ROOT
            && r["private_original_entry_root_qualification"] == true
            && r["first_guard"]["path"] == format!("{ROOT}/receipts/first-guard.json")
            && r["candidate_incremental_peak_bytes"] == 768u64 << 30,
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
            .filter(|v| v["unit"] == UNIT)
            .eq(std::iter::once(&claim(s))),
        "original141 event claim differs"
    );
    let events = e["diagnostics"]
        .as_array()
        .context("original141 event owner census")?;
    ensure!(
        events.iter().filter(|v| v["unit"]["Id"] == UNIT).count() == 1
            && events.iter().any(|v| v["unit"]["Id"] == UNIT
                && v["epoch"] == 141
                && v["live"] == true
                && v["launch_invocation_id"] == s.invocation_id
                && v["unit"]["InvocationID"] == s.invocation_id
                && v["unit"]["NRestarts"] == "0"
                && v["launch_receipt"].as_str() == s.launch.path.to_str()
                && v["launch_receipt_sha256"] == s.launch.sha256),
        "original141 event lacks exact actual live invocation"
    );
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == FIRST_GUARD
            && g["producer_invocation_id"] == s.invocation_id
            && g["producer"]["invocation_id"] == s.invocation_id
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
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
    json!({"range":"141","controller_unit":UNIT,"producer_unit":UNIT,"expected_controller_invocation_id":s.invocation_id,"expected_producer_invocation_id":s.invocation_id,"scratch_path":format!("{ROOT}/scratch"),"worker_executable_basename":"historical-worker"})
}
fn migrate(scope: &mut Scope101200, config: &mut Value, s: &Profile) -> Result<()> {
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
        controller_unit: UNIT.into(),
        producer_unit: UNIT.into(),
        expected_controller_invocation_id: s.invocation_id.clone(),
        expected_producer_invocation_id: s.invocation_id.clone(),
    });
    Ok(())
}
fn fold(f: &mut Value, c: Value, g: Value, s: &Profile) -> Result<()> {
    ensure!(
        f["gates"]["141"]["state"] == "failed-needs-repair",
        "private141 cannot close repair incident"
    );
    let ds = f["diagnostics"]
        .as_array_mut()
        .context("diagnostic history")?;
    let old: Vec<_> = ds.iter().filter(|v| v["unit"] == UNIT).collect();
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
    if !names.contains(&json!(UNIT)) {
        names.push(json!(UNIT));
    }
    let evidence = f["gates"]["141"]["evidence"]
        .as_array_mut()
        .context("repair evidence")?;
    for b in [serde_json::to_value(&s.launch)?, g] {
        if !evidence.contains(&b) {
            evidence.push(b);
        }
    }
    f["gates"]["141"]["next_action"] = json!(
        "Preserve exact private original-entry root qualification60911751..61328765 and guard/observer ownership. Capture actual terminal/checkpoint result promptly; partial-root success is not full141 or a sidecar ETA. Keep incident open through complete-span qualification and verified ready pair."
    );
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    if let Some(s) = &p.original141_root {
        let (c, g) = read(s)?;
        fold(f, c, g, s)?;
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
            row["producer_unit"] == UNIT
                && row["expected_producer_invocation_id"] == s.invocation_id
                && row["scratch_path"] == format!("{ROOT}/scratch"),
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
                        && o["scratch_path"] == format!("{ROOT}/scratch")
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
        !enabled(p)
            && is_101(p)?
            && publication144::composite_reader(p)
            && p.repair185_handoff.is_some(),
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
        launch: spec.launch,
        event_fleet: spec.event_fleet,
        event_plan: spec.event_plan,
        invocation_id: launch["invocation_id"]
            .as_str()
            .context("original141 invocation")?
            .into(),
    };
    let (c, g) = read(&s)?;
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
        .push(json!(UNIT));
    expected["gates"]["141"]["evidence"]
        .as_array_mut()
        .context("old repair history")?
        .extend([serde_json::to_value(&s.launch)?, g]);
    ensure!(
        expected == actual && actual["observer"] == serde_json::to_value(&p.previous_observer)?,
        "original141 event changes unrelated claims/history/scalars"
    );
    migrate(p.scope_101_200.as_mut().context("101scope")?, config, &s)?;
    p.previous_fleet = s.event_fleet.clone();
    p.fleet_template = s.event_plan.clone();
    p.original141_root = Some(s);
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    p.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    validate(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> Profile {
        let bound = |path: &str| Bound {
            path: path.into(),
            sha256: "a".repeat(64),
        };
        Profile {
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
    #[test]
    fn handoff_cannot_borrow_another_event_owner_guard_or_close_the_incident() {
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
