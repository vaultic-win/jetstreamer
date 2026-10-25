use super::*;
const BOOT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
fn b(path: &str) -> Value {
    json!({"path":path,"sha256":"a".repeat(64)})
}
fn terminal(epoch: u64) -> Value {
    let (path, sha) = original_launch(epoch).unwrap();
    json!({"launch":{"path":path,"sha256":sha},"producer_result":b("/var/lib/jetstreamer/terminal/result.json"),
        "terminal_properties":b("/var/lib/jetstreamer/terminal/manager.json"),
        "manager_journal":b("/var/lib/jetstreamer/terminal/journal.json"),"successors":[]})
}
fn plan(omitted: &[u64]) -> Plan {
    let mut v = json!({"schema":SCHEMA,"observer":b("/sealed/observer.json"),"fleet":b("/sealed/fleet.json"),
        "receipt_directory":"/private/status","estimate_receipt":"/private/estimate.json",
        "downstream_allowance_millis":{"204":1000,"205":1000,"225":1000,"226":1000},"estimate_basis":"fixture only","omitted_originals":{},"delegated_verification":{}});
    for epoch in omitted {
        v["omitted_originals"][epoch.to_string()] = terminal(*epoch);
        v["downstream_allowance_millis"]
            .as_object_mut()
            .unwrap()
            .remove(&epoch.to_string());
    }
    serde_json::from_value(v).unwrap()
}
fn live_unit(p: &Profile) -> Value {
    json!({"Id":p.unit,"LoadState":"loaded","InvocationID":p.iid,"MainPID":"100","NRestarts":"0",
        "ControlGroup":format!("/system.slice/{}",p.unit),"ActiveState":"active","SubState":"running","Result":"success","ExecMainStatus":"0"})
}
fn fleet(omitted: &[u64]) -> Value {
    let mut active = Vec::new();
    let mut census = serde_json::Map::new();
    for p in PROFILES.iter().filter(|p| p.first != 141) {
        let mut u = live_unit(p);
        if omitted.contains(&p.first) {
            u["MainPID"] = json!("0");
            u["ControlGroup"] = json!("");
            u["ActiveState"] = json!("inactive");
            u["SubState"] = json!("dead");
        }
        census.insert(p.unit.into(), u);
        if !omitted.contains(&p.first) {
            active.push(json!({"epoch":p.first,"phase":if p.first<225{"private-known-root-prefix"}else{"diagnostic-qualification"},"producer":live_unit(p)}));
        }
    }
    json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","active":active,"unit_census":census,"recorded_unix_seconds":100})
}
fn launch(epoch: u64) -> Value {
    serde_json::from_slice(if epoch == 204 {
        include_bytes!("fixtures/launch204.json")
    } else {
        include_bytes!("fixtures/launch205.json")
    })
    .unwrap()
}
// Future terminal data below is a synthetic schema fixture, never actual success.
fn proof(epoch: u64) -> (Value, Value, Vec<Value>) {
    let p = profile(epoch).unwrap();
    let l = launch(epoch);
    let mut r = json!({"schema":format!("jetstreamer-private-epoch{epoch}-shrink-root-prefix-resource-v1"),"epoch":epoch,
        "unit":p.unit,"invocation_id":p.iid,"success":true,"error":null,"child_return_code":0,"external_signal":0,
        "natural_parent_completion_required":true,"producer_canonical_root_prefix_present":true,
        "target_slot":p.terminal,"terminal_root_slot":p.terminal,"plan":{"sha256":l["plan_sha256"]},"authority":{}});
    for key in [
        "runner_sha256",
        "node_sha256",
        "worker_sha256",
        "snapshot_sha256",
    ] {
        r[key] = l[key].clone();
    }
    for key in [
        "canonical_prefix_independently_qualified",
        "full_cold_epoch_peak_qualified",
        "ordinary_replay_authorized",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        r["authority"][key] = json!(false);
    }
    let u = json!({"Id":p.unit,"LoadState":"loaded","InvocationID":p.iid,"MainPID":"0","NRestarts":"0","ControlGroup":"",
        "ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainStatus":"0","ExecStart":l["expected_exec_start"]});
    let rows = vec![
        json!({"_PID":"1","_UID":"0","UNIT":p.unit,"INVOCATION_ID":p.iid,"_BOOT_ID":BOOT,
        "MESSAGE":format!("{}: Deactivated successfully.",p.unit),"__REALTIME_TIMESTAMP":"90000000"}),
    ];
    (r, u, rows)
}
#[test]
fn v2_allows_only_exact_remaining_original_profiles_and_keeps_legacy_strict() {
    for omitted in [vec![], vec![204], vec![205], vec![204, 205]] {
        let p = plan(&omitted);
        plan_epochs(&p).unwrap();
        active_scope(&p, &fleet(&omitted)).unwrap();
    }
    let mut old = plan(&[]);
    old.schema = "jetstreamer-qualification-status-plan-v1".into();
    plan_epochs(&old).unwrap();
    let mut old = plan(&[205]);
    old.schema = "jetstreamer-qualification-status-plan-v1".into();
    assert!(plan_epochs(&old).is_err());
    for epoch in [225, 226] {
        let mut p = plan(&[]);
        p.downstream_allowance_millis.remove(&epoch);
        assert!(plan_epochs(&p).is_err());
    }
    let mut p = plan(&[205]);
    let t = p.omitted_originals.remove(&205).unwrap();
    p.omitted_originals.insert(225, t);
    assert!(plan_epochs(&p).is_err());
}
#[test]
fn terminal205_and_both_terminal_cases_preserve_the_genuine_launch_shapes() {
    for omitted in [vec![205], vec![204, 205]] {
        let p = plan(&omitted);
        let f = fleet(&omitted);
        active_scope(&p, &f).unwrap();
        for epoch in omitted {
            let bytes: &[u8] = if epoch == 204 {
                include_bytes!("fixtures/launch204.json")
            } else {
                include_bytes!("fixtures/launch205.json")
            };
            assert_eq!(
                hex_lower(&Sha256::digest(bytes)),
                original_launch(epoch).unwrap().1
            );
            let (result, u, rows) = proof(epoch);
            terminal_value(
                epoch,
                &p.omitted_originals[&epoch],
                (&launch(epoch), &result, &u),
                &rows,
                &f,
                BOOT,
            )
            .unwrap();
        }
    }
}
#[test]
fn wrong_epoch_iid_terminal_evidence_and_unrelated_authority_are_rejected() {
    let p = plan(&[205]);
    let f = fleet(&[205]);
    let (result, u, rows) = proof(205);
    let t = &p.omitted_originals[&205];
    let l = launch(205);
    for (ptr, value) in [
        ("/epoch", json!(204)),
        ("/invocation_id", json!("f".repeat(32))),
        ("/unit", json!(profile(204).unwrap().unit)),
        ("/terminal_root_slot", json!(88991999)),
        ("/child_return_code", json!(1)),
        ("/external_signal", json!(15)),
        ("/success", json!(false)),
        ("/authority/publication_authorized", json!(true)),
        ("/worker_sha256", json!("f".repeat(64))),
    ] {
        let mut bad = result.clone();
        *bad.pointer_mut(ptr).unwrap() = value;
        assert!(
            terminal_value(205, t, (&l, &bad, &u), &rows, &f, BOOT).is_err(),
            "{ptr}"
        );
    }
    let mut bad = serde_json::from_value::<Terminal>(terminal(205)).unwrap();
    bad.launch.sha256 = "f".repeat(64);
    assert!(terminal_value(205, &bad, (&l, &result, &u), &rows, &f, BOOT).is_err());
    let mut bad = rows.clone();
    bad[0]["INVOCATION_ID"] = json!("f".repeat(32));
    assert!(terminal_value(205, t, (&l, &result, &u), &bad, &f, BOOT).is_err());
    let mut bad = rows.clone();
    bad.push(rows[0].clone());
    assert!(terminal_value(205, t, (&l, &result, &u), &bad, &f, BOOT).is_err());
}
#[test]
fn a_live_omitted_original_or_changed_live_phase_is_never_silently_dropped() {
    let p = plan(&[205]);
    assert!(active_scope(&p, &fleet(&[])).is_err());
    let mut f = fleet(&[205]);
    f["unit_census"][profile(205).unwrap().unit] = live_unit(profile(205).unwrap());
    assert!(active_scope(&p, &f).is_err());
    let mut f = fleet(&[205]);
    f["active"][0]["phase"] = json!("private-verification");
    assert!(active_scope(&p, &f).is_err());
    let (_, mut u, _) = proof(205);
    u["ActiveState"] = json!("active");
    u["SubState"] = json!("running");
    assert!(terminal_state(profile(205).unwrap(), &u, false).is_err());
}
#[test]
fn replacement_binding_phase_and_complete_current_census_detect_races() {
    let mut p = plan(&[205]);
    let mut f = fleet(&[205]);
    let unit = "horizon-qualify-205-capped-continuation-fixture.service";
    let mut t = terminal(205);
    t["successors"] = json!([{"unit":unit,"invocation_id":"d".repeat(32),"phase":"capped204205-continuation","launch":b("/sealed/new-launch.json")}]);
    p.omitted_originals
        .insert(205, serde_json::from_value(t).unwrap());
    let u = json!({"Id":unit,"InvocationID":"d".repeat(32),"MainPID":"200","ActiveState":"active","SubState":"running"});
    f["active"].as_array_mut().unwrap().push(json!({"epoch":205,"phase":"capped204205-continuation","unit":u,"launch":b("/sealed/new-launch.json")}));
    f["unit_census"][unit] = u;
    active_scope(&p, &f).unwrap();
    let current =
        serde_json::from_value::<BTreeMap<String, Value>>(f["unit_census"].clone()).unwrap();
    same_census(&f, &current).unwrap();
    let mut changed = current.clone();
    changed.get_mut(unit).unwrap()["InvocationID"] = json!("e".repeat(32));
    assert!(same_census(&f, &changed).is_err());
    changed = current;
    changed.insert(
        "horizon-qualify-205-unaccepted.service".into(),
        json!({"MainPID":"999"}),
    );
    assert!(same_census(&f, &changed).is_err());
    f["active"].as_array_mut().unwrap().last_mut().unwrap()["phase"] =
        json!("private-verification");
    assert!(active_scope(&p, &f).is_err());
}
#[test]
fn saved_v2_countdowns_cannot_change_phase_or_reintroduce_a_terminal_original() {
    let p = plan(&[205]);
    let mut states = plan_epochs(&p)
        .unwrap()
        .into_iter()
        .map(|epoch| EpochStatus {
            epoch,
            jet_size_bytes: 0,
            elapsed_execution_millis: 100,
            estimated_remaining_millis: 1000,
            sampled_at_utc: "2026-10-24T17:29:00Z".into(),
            phase: "replay".into(),
        })
        .collect::<Vec<_>>();
    assert!(saved_statuses_match(&p, &states, "2026-10-24T17:29:00Z").unwrap());
    states[0].phase = "verification".into();
    assert!(!saved_statuses_match(&p, &states, "2026-10-24T17:29:00Z").unwrap());
    states[0].phase = "replay".into();
    states[0].epoch = 205;
    assert!(!saved_statuses_match(&p, &states, "2026-10-24T17:29:00Z").unwrap());
}
#[test]
fn command_records_keep_exact_argv_and_ignore_errors_policy() {
    let bare = "{ path=/sealed/node ; argv[]=/sealed/node plan ; ignore_errors=no }";
    let actual = "{ path=/sealed/node ; argv[]=/sealed/node plan ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
    assert_eq!(command(bare), command(actual));
    assert!(command(&actual.replace("ignore_errors=no", "ignore_errors=yes")).is_none());
    assert!(command(&(actual.to_string() + " { path=/other }")).is_none());
    assert_ne!(
        command(actual),
        command(&bare.replace("node plan", "node other-plan"))
    );
}

#[test]
fn healthy_originals_can_delegate_live205_without_terminal_evidence_or_a_worker_rate() {
    let mut p = plan(&[]);
    p.downstream_allowance_millis.remove(&205);
    p.delegated_verification.insert(
        205,
        serde_json::from_value(b("/var/lib/jetstreamer/205-plan/plan.json")).unwrap(),
    );
    assert_eq!(plan_epochs(&p).unwrap(), vec![204, 225, 226]);
    assert!(p.omitted_originals.is_empty());
    active_scope(&p, &fleet(&[])).unwrap();
    let mut wrong = plan(&[]);
    wrong.downstream_allowance_millis.remove(&204);
    wrong.delegated_verification.insert(
        204,
        serde_json::from_value(b("/sealed/wrong.json")).unwrap(),
    );
    assert!(plan_epochs(&wrong).is_err());
    p.omitted_originals
        .insert(205, serde_json::from_value(terminal(205)).unwrap());
    assert!(plan_epochs(&p).is_err());
}

fn recovery_fixture() -> (Plan, Value) {
    let mut p = plan(&[204, 205]);
    let mut f = fleet(&[204, 205]);
    let unit = "horizon-qualify-204-assembly-only-recovery-v2.service";
    let iid = "e".repeat(32);
    let launch = b("/sealed/recovery204-actor.json");
    let mut t = terminal(204);
    t["successors"] = json!([{"unit":unit,"invocation_id":iid,"phase":"assembly-recovery204","launch":launch}]);
    p.omitted_originals.insert(204, serde_json::from_value(t).unwrap());
    let u = json!({"Id":unit,"InvocationID":iid,"MainPID":"200","NRestarts":"0","ActiveState":"active","SubState":"running"});
    f["active"].as_array_mut().unwrap().push(json!({"epoch":204,"phase":"assembly-recovery204","live":true,
        "unit":u,"actor_launch":launch,"origin_launch":b("/sealed/recovery204-origin.json"),
        "recovery_plan":b("/sealed/recovery204-plan.json"),"ordinary_replay_claim":false,"source_failure_remains_failure":true,
        "status":{"phase":"verification"}}));
    f["unit_census"][unit] = u;
    // A well-shaped row is not a substitute for an authenticated accepted plan.
    f["plan"] = json!("/not-created-qualification-recovery204-plan.json");
    f["plan_sha256"] = json!("a".repeat(64));
    (p, f)
}
#[test]
fn exact_recovery204_shape_keeps_terminal_proofs_and_requires_real_authentication() {
    let (p, f) = recovery_fixture();
    let raw = f.clone();
    let original = serde_json::to_value(&p.omitted_originals[&204]).unwrap();
    active_scope(&p, &f).unwrap();
    assert_eq!(f, raw);
    assert_eq!(serde_json::to_value(&p.omitted_originals[&204]).unwrap(), original);
    let current = serde_json::from_value(f["unit_census"].clone()).unwrap();
    assert!(recovery_current(&p, &f, &current).is_err());
    assert_eq!(f, raw);
}
#[test]
fn recovery204_cannot_be_omitted_downgraded_duplicated_or_borrowed_by_205() {
    let (p, f) = recovery_fixture();
    let mut omitted = plan(&[204, 205]);
    assert!(active_scope(&omitted, &f).is_err());
    // The old terminal proof remains required independently of the new successor.
    omitted.omitted_originals.remove(&204);
    assert!(plan_epochs(&omitted).is_err());
    let index = f["active"].as_array().unwrap().len()-1;
    for (key, value) in [
        ("epoch",json!(205)), ("phase",json!("capped204205-continuation")),
        ("live",json!(false)), ("ordinary_replay_claim",json!(true)),
        ("source_failure_remains_failure",json!(false)), ("actor_launch",b("/sealed/foreign.json")),
        ("origin_launch",Value::Null), ("recovery_plan",Value::Null),
        ("status",json!({"phase":"replay"})),
    ] {
        let mut bad = f.clone(); bad["active"][index][key]=value;
        assert!(active_scope(&p,&bad).is_err(),"{key}");
    }
    let mut duplicate=f.clone(); let row=duplicate["active"][index].clone();
    duplicate["active"].as_array_mut().unwrap().push(row);
    assert!(active_scope(&p,&duplicate).is_err());
    let mut altered=p; let mut t=terminal(205);
    t["successors"]=serde_json::to_value(&altered.omitted_originals[&204].successors).unwrap();
    altered.omitted_originals.insert(205,serde_json::from_value(t).unwrap());
    assert!(active_scope(&altered,&f).is_err());
}
#[test]
fn recovery204_successor_never_hides_raw_guard_or_foreign_unit_changes() {
    let (p,mut f)=recovery_fixture();
    let guard="horizon-guard-204-assembly-only-recovery-v2.service";
    f["unit_census"][guard]=json!({"Id":guard,"InvocationID":"f".repeat(32),"MainPID":"201","ActiveState":"active","SubState":"running"});
    active_scope(&p,&f).unwrap();
    let current: BTreeMap<String,Value>=serde_json::from_value(f["unit_census"].clone()).unwrap();
    same_census(&f,&current).unwrap();
    let mut missing=current.clone();missing.remove(guard);assert!(same_census(&f,&missing).is_err());
    let mut changed=current;changed.get_mut(guard).unwrap()["InvocationID"]=json!("d".repeat(32));
    assert!(same_census(&f,&changed).is_err());
}
