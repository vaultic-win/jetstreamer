use super::*;

fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}
fn binding() -> BoundFile {
    BoundFile {
        path: "/var/lib/jetstreamer/static-parser-fixture.json".into(),
        sha256: "a".repeat(64),
    }
}
fn terminal(epoch: u64) -> Terminal {
    let (_, _, _, path, sha, _) = profile(epoch).unwrap();
    Terminal {
        launch: BoundFile {
            path: path.into(),
            sha256: sha.into(),
        },
        producer_result: binding(),
        terminal_properties: binding(),
        manager_journal: binding(),
    }
}
fn basis() -> Basis {
    Basis {
        schema: SCHEMA.into(),
        observer: binding(),
        fleet: binding(),
        inherited_capacity: binding(),
        historical_guards: HEALTHY
            .into_iter()
            .chain(ORIGINALS.iter().map(|p| p.1))
            .map(|name| (name.into(), binding()))
            .collect(),
        protected_guards: HEALTHY
            .into_iter()
            .map(|name| (name.into(), binding()))
            .collect(),
        terminal_originals: [204, 205]
            .into_iter()
            .map(|epoch| (epoch, terminal(epoch)))
            .collect(),
    }
}
fn fixture(epoch: u64) -> (Value, Value, Value, Vec<Value>) {
    match epoch {
        204 => (
            value(include_bytes!("fixtures/launch204.json")),
            value(include_bytes!("fixtures/result204.json")),
            value(include_bytes!("fixtures/manager204.json")),
            journal(include_bytes!("fixtures/journal204.jsonl")).unwrap(),
        ),
        205 => (
            value(include_bytes!("fixtures/launch205.json")),
            value(include_bytes!("fixtures/result205.json")),
            value(include_bytes!("fixtures/manager205.json")),
            journal(include_bytes!("fixtures/journal205.jsonl")).unwrap(),
        ),
        _ => unreachable!(),
    }
}
fn fleet() -> Value {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../fixtures/foundation213-current-five-guards.json"
    ))
    .unwrap();
    let mut rows = fixtures.iter().filter(|row| row["owner"]["Id"] != prefix223_native20::UNIT)
        .map(|row| {
            let name=row["owner"]["Id"].as_str().unwrap();
            let epoch=if name == HEALTHY[0] {225} else if name == HEALTHY[1] {209} else if name == ORIGINALS[0].1 {204} else {205};
            let mut owner=row["owner"].clone();
            owner["NRestarts"]=json!("0");owner["ActiveState"]=json!("active");owner["SubState"]=json!("running");
            json!({"epoch":epoch,"phase":"diagnostic-qualification","ordinary_replay_claim":false,"producer":owner})
        }).collect::<Vec<_>>();
    rows.push(prefix223_live_peer::fixture_row());
    let census = rows
        .iter()
        .map(|row| {
            let owner = singleton227_admission::active_owner(row).unwrap();
            (owner["Id"].as_str().unwrap().to_owned(), owner.clone())
        })
        .collect::<serde_json::Map<_, _>>();
    let diagnostics=ORIGINALS.iter().map(|(epoch,unit,iid,path,sha,_)|json!({"epoch":epoch,"unit":{"Id":unit},"live":false,"launch_invocation_id":iid,"launch_receipt":path,"launch_receipt_sha256":sha})).collect::<Vec<_>>();
    json!({"active":rows,"unit_census":census,"diagnostics":diagnostics,"recorded_unix_seconds":1792869000u64})
}
fn three() -> Value {
    let mut f = fleet();
    f["active"].as_array_mut().unwrap().retain(|row| {
        HEALTHY.contains(
            &singleton227_admission::active_owner(row).unwrap()["Id"]
                .as_str()
                .unwrap(),
        )
    });
    f
}
fn parse(
    epoch: u64,
    launch: &Value,
    result: &Value,
    manager: &Value,
    rows: &[Value],
    f: &Value,
) -> Result<u64> {
    terminal_value(
        epoch,
        &terminal(epoch),
        (launch, result, manager),
        rows,
        f,
        "2e60f44d8e484d7e91fcc2dc724d2ae6",
    )
}
#[test]
fn both_actual_originals_have_natural_terminal_proofs() {
    for epoch in [204, 205] {
        let (launch, result, manager, rows) = fixture(epoch);
        assert!(parse(epoch, &launch, &result, &manager, &rows, &fleet()).unwrap() > 0);
        history(epoch, &terminal(epoch), &fleet()).unwrap();
    }
    let mut s = basis();
    terminal_keys(&s).unwrap();
    s.terminal_originals.remove(&204);
    assert!(terminal_keys(&s).is_err());
    s.terminal_originals.insert(206, terminal(204));
    assert!(terminal_keys(&s).is_err());
}
#[test]
fn terminal_proof_rejects_changed_identity_root_signal_or_authority() {
    for epoch in [204, 205] {
        let (launch, result, manager, rows) = fixture(epoch);
        for (key, replacement) in [
            ("success", json!(false)),
            ("external_signal", json!(15)),
            ("child_return_code", json!(130)),
            ("terminal_root_slot", json!(1)),
            ("invocation_id", json!("a".repeat(32))),
            ("worker_sha256", json!("a".repeat(64))),
        ] {
            let mut changed = result.clone();
            changed[key] = replacement;
            assert!(
                parse(epoch, &launch, &changed, &manager, &rows, &fleet()).is_err(),
                "{epoch}:{key}"
            );
        }
        let mut changed = result.clone();
        changed["authority"]["publication_authorized"] = json!(true);
        assert!(parse(epoch, &launch, &changed, &manager, &rows, &fleet()).is_err());
        let mut changed = launch.clone();
        changed["evidence"]["units"][0]["invocation_id"] = json!("a".repeat(32));
        assert!(parse(epoch, &changed, &result, &manager, &rows, &fleet()).is_err());
        let mut early = fleet();
        early["recorded_unix_seconds"] = json!(1);
        assert!(parse(epoch, &launch, &result, &manager, &rows, &early).is_err());
    }
}
#[test]
fn complete_manager_history_rejects_forced_duplicate_truncated_or_replaced_rows() {
    for epoch in [204, 205] {
        let (launch, result, manager, rows) = fixture(epoch);
        for key in ["_BOOT_ID", "INVOCATION_ID", "UNIT", "_PID", "_UID"] {
            let mut changed = rows.clone();
            changed[0][key] = json!("wrong");
            assert!(
                parse(epoch, &launch, &result, &manager, &changed, &fleet()).is_err(),
                "{key}"
            );
        }
        for message in ["Stopping original", "Failed original", "Killing original"] {
            let mut changed = rows.clone();
            changed[0]["MESSAGE"] = json!(message);
            assert!(parse(epoch, &launch, &result, &manager, &changed, &fleet()).is_err());
        }
        let mut changed = rows.clone();
        changed.push(rows[2].clone());
        assert!(parse(epoch, &launch, &result, &manager, &changed, &fleet()).is_err());
        let mut changed = rows.clone();
        changed.remove(1);
        assert!(parse(epoch, &launch, &result, &manager, &changed, &fleet()).is_err());
        let mut changed = rows.clone();
        changed.remove(2);
        assert!(parse(epoch, &launch, &result, &manager, &changed, &fleet()).is_err());
        let mut changed = rows.clone();
        changed.swap(1, 2);
        assert!(parse(epoch, &launch, &result, &manager, &changed, &fleet()).is_err());
    }
}
#[test]
fn actual_terminal_current_state_allows_collection_and_rejects_live_original_race() {
    for epoch in [204, 205] {
        let (_, _, manager, _) = fixture(epoch);
        terminal_state(epoch, &manager, true).unwrap();
        for (key, replacement) in [
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("MainPID", "42"),
            ("NRestarts", "1"),
            ("InvocationID", "replacement"),
            ("Result", "signal"),
        ] {
            let mut changed = manager.clone();
            changed[key] = json!(replacement);
            assert!(terminal_state(epoch, &changed, false).is_err(), "{key}");
        }
        let mut collected = manager.clone();
        collected["LoadState"] = json!("not-found");
        collected["InvocationID"] = json!("");
        terminal_state(epoch, &collected, false).unwrap();
        assert!(terminal_state(epoch, &collected, true).is_err());
    }
}
#[test]
fn exactly_three_actual_healthy_owners_and_v1_remains_five() {
    let f = three();
    live_roster(&f).unwrap();
    assert!(continuation_guards::refresh(&f, &BTreeMap::new(), 0, 0)
        .err()
        .unwrap()
        .to_string()
        .contains("exact five"));
    for bad in ["missing", "duplicate", "scanner", "native", "replacement"] {
        let mut changed = f.clone();
        match bad {
            "missing" => {
                changed["active"].as_array_mut().unwrap().pop();
            }
            "duplicate" => {
                let row = changed["active"][0].clone();
                changed["active"].as_array_mut().unwrap().push(row);
            }
            "replacement" => {
                changed["active"][2]["producer"]["InvocationID"] = json!("a".repeat(32));
            }
            name => {
                changed["active"].as_array_mut().unwrap().push(json!({"epoch":205,"producer":{"Id":format!("horizon-capped205-{name}.service")}}));
            }
        }
        assert!(live_roster(&changed).is_err(), "{bad}");
    }
}
#[test]
fn transition_keeps_each_diagnostic_and_every_original_launch_binding() {
    let old = fleet();
    let current = three();
    preserve_diagnostics(&old, &current).unwrap();
    for bad in ["drop", "duplicate", "replace"] {
        let mut changed = current.clone();
        match bad {
            "drop" => {
                changed["diagnostics"].as_array_mut().unwrap().pop();
            }
            "duplicate" => {
                let row = changed["diagnostics"][0].clone();
                changed["diagnostics"].as_array_mut().unwrap().push(row);
            }
            _ => changed["diagnostics"][0]["launch_receipt_sha256"] = json!("a".repeat(64)),
        }
        assert!(preserve_diagnostics(&old, &changed).is_err(), "{bad}");
    }
    let mut relabelled = current;
    relabelled["diagnostics"][0]["live"] = json!(true);
    assert!(history(204, &terminal(204), &relabelled).is_err());
}
#[test]
fn five_historical_and_three_live_guards_are_mandatory() {
    let mut s = basis();
    guard_partition(&s).unwrap();
    s.historical_guards.remove(ORIGINALS[0].1);
    assert!(guard_partition(&s).is_err());
    let mut s = basis();
    s.protected_guards.insert(ORIGINALS[0].1.into(), binding());
    assert!(guard_partition(&s).is_err());
    let mut s = basis();
    s.protected_guards.remove(HEALTHY[0]);
    assert!(guard_partition(&s).is_err());
}
#[test]
fn genuine_guard_floors_and_all_inherited_reserves_cannot_decrease() {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../fixtures/foundation213-current-five-guards.json"
    ))
    .unwrap();
    let mut actual = 0;
    for row in fixtures {
        let name = row["owner"]["Id"].as_str().unwrap();
        let n = retained_guard_floor(name, &row["receipt"], &row["plan"]).unwrap();
        actual = actual.max(n);
        let mut changed = row["plan"].clone();
        changed["minimum_free_bytes"] = json!(1);
        assert!(retained_guard_floor(name, &row["receipt"], &changed).is_err());
    }
    assert_eq!(actual, 2_000_000_000_000);
    assert_eq!(floor(100, 50, 200, 400, 300, 350).unwrap(), 400); // Larger terminal floor stays charged.
    assert_eq!(floor(100, 50, 200, 100, 500, 350).unwrap(), 500);
    assert_eq!(floor(100, 50, 200, 100, 300, 600).unwrap(), 600);
    assert_eq!(floor(1000, 50, 200, 100, 300, 600).unwrap(), 1050);
    assert!(floor(u64::MAX, 1, 0, 0, 0, 0).is_err());
    assert!(envelope(400, 10, 409).is_err());
    assert_eq!(envelope(400, 10, 410).unwrap(), 410);
}
#[test]
fn inherited_capacity_binds_exact_five_guard_map_and_disallows_new_authority() {
    let s = basis();
    let cap = json!({"schema":"jetstreamer-foundation-holding-capacity-v1","host":"horizon-vaultic","first_epoch":201,"last_epoch":300,
        "restore_only":true,"all_live_growth_and_century_floor_protected":true,"minimum_free_bytes":2000,"century_floor_bytes":1000,
        "resource_basis":{"protected_guards":s.historical_guards,"fleet":{"path":"/var/lib/jetstreamer/old-fleet.json","sha256":"a".repeat(64)}},
        "replay_launch_authorized":false,"local_retirement_authorized":false,"publication_authorized":false,"r2_mutations":false});
    assert_eq!(inherited(&cap, &s.historical_guards).unwrap().0, 2000);
    inherited(
        &json!({"schema":"jetstreamer-foundation-holding-restore-admission-v1","capacity":cap}),
        &s.historical_guards,
    )
    .unwrap();
    let mut changed = cap.clone();
    changed["resource_basis"]["protected_guards"]
        .as_object_mut()
        .unwrap()
        .remove(ORIGINALS[0].1);
    assert!(inherited(&changed, &s.historical_guards).is_err());
    let mut changed = cap;
    changed["local_retirement_authorized"] = json!(true);
    assert!(inherited(&changed, &s.historical_guards).is_err());
}

#[test]
fn v2_schema_rejects_unmodeled_owner_exemption_fields() {
    let raw = json!({"schema":SCHEMA,"observer":{"path":"/sealed/o","sha256":"a".repeat(64)},
        "fleet":{"path":"/sealed/f","sha256":"b".repeat(64)},"inherited_capacity":{"path":"/sealed/c","sha256":"c".repeat(64)},
        "historical_guards":{},"protected_guards":{},"terminal_originals":{}});
    serde_json::from_value::<Basis>(raw.clone()).unwrap();
    let mut changed = raw;
    changed["ignored_owners"] = json!(["scanner.service"]);
    assert!(serde_json::from_value::<Basis>(changed).is_err());
}
