use super::*;
fn fixture() -> Value {
    serde_json::from_str(include_str!("../../fixtures/cached145-closure.json")).unwrap()
}
fn native_fixture() -> BTreeMap<String, Value> {
    let mut rows: BTreeMap<String, Value> =
        serde_json::from_value(fixture()["native"].clone()).unwrap();
    // Frame dependency sets are historical metadata. These exact source fields
    // are deliberately added only to a TEST fixture for source-validator tests.
    for name in FAMILY {
        let row = rows.get_mut(name).unwrap();
        row["FragmentPath"] = json!(format!("/etc/systemd/system/{name}"));
        row["DropInPaths"] = json!("");
    }
    rows
}
#[test]
fn actual_completed_original_parent_and_native_family_are_supported() {
    original(&fixture()["original"]).unwrap();
    native_shape(&native_fixture()).unwrap();
    raw_row(&fixture()["raw"]).unwrap();
}
#[test]
fn absent_or_crossed_success_pid1_cannot_retire_memory() {
    for (pointer, v) in [
        ("/original_IID", json!("a".repeat(32))),
        ("/parent_completed_cleanly", json!(false)),
        ("/original_process_and_cgroup_absent", json!(false)),
        ("/original_PID1_success_event/_PID", json!("99")),
        (
            "/original_PID1_success_event/INVOCATION_ID",
            json!("a".repeat(32)),
        ),
        ("/original_PID1_success_event/MESSAGE", json!("failed")),
        ("/native/Result", json!("exit-code")),
        ("/native/MainPID", json!("123")),
    ] {
        let mut v0 = fixture()["original"].clone();
        *v0.pointer_mut(pointer).unwrap() = v;
        assert!(original(&v0).is_err(), "{pointer}");
    }
}
#[test]
fn live_replaced_restarted_or_queued_family_rejects() {
    for name in &FAMILY[..3] {
        for (key, v) in [
            ("MainPID", json!("7")),
            ("ControlPID", json!("7")),
            ("Job", json!("9")),
            ("NRestarts", json!("1")),
            ("Restart", json!("always")),
            ("ControlGroup", json!("/live")),
            ("ActiveState", json!("active")),
            ("DropInPaths", json!("/override.conf")),
            ("MemoryMax", json!("1")),
        ] {
            let mut n = native_fixture();
            n.get_mut(*name).unwrap()[key] = v;
            assert!(native_shape(&n).is_err(), "{name}:{key}");
        }
    }
}
#[test]
fn armed_timer_or_new_automatic_trigger_cannot_release_parent() {
    for (name, key, v) in [
        (FAMILY[3], "ActiveState", json!("active")),
        (FAMILY[3], "SubState", json!("waiting")),
        (FAMILY[3], "Job", json!("7")),
        (UNIT, "TriggeredBy", json!("other.timer")),
        (FAMILY[1], "TriggeredBy", json!("other.timer")),
    ] {
        let mut n = native_fixture();
        n.get_mut(name).unwrap()[key] = v;
        assert!(native_shape(&n).is_err());
    }
}
#[test]
fn missing_family_member_and_unknown_native_alias_reject() {
    for name in FAMILY {
        let mut n = native_fixture();
        n.remove(name);
        assert!(native_shape(&n).is_err());
    }
    let mut n = native_fixture();
    n.insert("unknown.service".into(), json!({}));
    assert!(native_shape(&n).is_err());
}
#[test]
fn raw_parent_only_retirement_preserves_guard_and_all337gib_data() {
    let row = raw_row(&fixture()["raw"]).unwrap();
    assert_eq!(row["memory_max_bytes"], PARENT + GUARD);
    assert_eq!(row["data_reservation_bytes"], DATA);
    let (total, peer) = compose(961344700416, 547954098176, 600 << 30, 400 << 30).unwrap();
    assert_eq!(total, 341795667968);
    assert_eq!(peer, (400 << 30) - PARENT);
}
#[test]
fn raw_duplicates_missing_or_already_reduced_promises_reject() {
    let a = fixture()["raw"].clone();
    for (key, v) in [
        ("memory_max_bytes", json!(GUARD)),
        ("parent_memory_max_bytes", json!(0)),
        ("guard_memory_max_bytes", json!(0)),
        ("data_reservation_bytes", json!(0)),
        ("credit_bytes", json!(PARENT)),
        ("resource_release_qualified", json!(true)),
    ] {
        let mut b = a.clone();
        b["active_peer_allocations"][0][key] = v;
        assert!(raw_row(&b).is_err(), "{key}");
    }
    let mut b = a.clone();
    let row = b["active_peer_allocations"][0].clone();
    b["active_peer_allocations"]
        .as_array_mut()
        .unwrap()
        .push(row);
    assert!(raw_row(&b).is_err());
    let mut b = a.clone();
    b["active_peer_allocations"] = json!([]);
    assert!(raw_row(&b).is_err());
    let mut b = a;
    b["projected_obligations"][0]["outstanding_bytes"] = json!(DATA - 1);
    assert!(raw_row(&b).is_err());
}
#[test]
fn process_cgroup_or_incomplete_scan_blocks_closure() {
    let good = Endpoint {
        native: native_fixture(),
        inspected_processes: 17,
        process_references: vec![],
        remaining_cgroup_members: vec![],
        source_bindings: bindings(),
    };
    endpoint_shape(&good).unwrap();
    let mut b = good.clone();
    b.process_references.push("pid123runner".into());
    assert!(endpoint_shape(&b).is_err());
    let mut b = good.clone();
    b.remaining_cgroup_members.push("123".into());
    assert!(endpoint_shape(&b).is_err());
    let mut b = good.clone();
    b.inspected_processes = 0;
    assert!(endpoint_shape(&b).is_err());
    let mut b = good;
    b.source_bindings.pop();
    assert!(endpoint_shape(&b).is_err());
}
#[test]
fn source_policy_cannot_release_guard_data_or_restart_authority() {
    let p = Policy {
        schema: "cached145-completed-parent-only-memory-policy-v1".into(),
        original_terminal: Bound {
            path: WITNESS.into(),
            sha256: WITNESS_SHA.into(),
        },
        census_program: Artifact {
            program: Bound {
                path: "/test/census".into(),
                sha256: "a".repeat(64),
            },
            qualification: None,
        },
        source_scope_review: Bound {
            path: "/test/review".into(),
            sha256: "b".repeat(64),
        },
        source_bindings: bindings(),
        native_units: FAMILY.map(str::to_owned).to_vec(),
        parent_retirement_bytes: PARENT,
        retained_guard_bytes: GUARD,
        retained_data_bytes: DATA,
        parent_memory_release_authorized: true,
        replay_restart_authorized: false,
        archive_mutations: false,
        r2_mutations: false,
    };
    policy_shape(&p).unwrap();
    for key in [
        "replay_restart_authorized",
        "archive_mutations",
        "r2_mutations",
    ] {
        let mut raw = json!(p);
        raw[key] = json!(true);
        let bad: Policy = serde_json::from_value(raw).unwrap();
        assert!(policy_shape(&bad).is_err());
    }
    for key in [
        "retained_guard_bytes",
        "retained_data_bytes",
        "parent_retirement_bytes",
    ] {
        let mut raw = json!(p);
        raw[key] = json!(0);
        let bad: Policy = serde_json::from_value(raw).unwrap();
        assert!(policy_shape(&bad).is_err());
    }
}
#[test]
fn arithmetic_underflow_or_inconsistent_raw_baseline_rejects() {
    assert!(compose(1, 2, 100, 99).is_err());
    assert!(compose(PARENT, PARENT, GUARD, GUARD).is_err());
    assert!(compose(PARENT - 1, PARENT - 1, PARENT + GUARD, PARENT + GUARD).is_err());
}
#[test]
fn current_request_is_optional_and_legacy_serialization_has_no_new_key() {
    let raw: Value =
        serde_json::from_str(include_str!("../../fixtures/legacy-parent-request.json")).unwrap();
    let request: crate::model::Request = serde_json::from_value(raw.clone()).unwrap();
    assert!(request.completed_cached145.is_none());
    assert_eq!(serde_json::to_value(request).unwrap(), raw);
}
#[test]
fn loaded_parent_command_and_live_exporter_identity_cannot_be_substituted() {
    let mut n = native_fixture();
    n.get_mut(UNIT).unwrap()["ExecStart"] = json!("/other/program");
    assert!(native_shape(&n).is_err());
    let mut n = native_fixture();
    n.get_mut(UNIT).unwrap()["Id"] =
        json!("horizon-extract145-prefix-real1328-20261106-v1.service");
    assert!(native_shape(&n).is_err());
    let mut raw = fixture()["raw"].clone();
    raw["active_peer_allocations"][0]["invocation_id"] = json!("914b442c5f61432f8ba3243eb7c0f20d");
    assert!(raw_row(&raw).is_err());
}
#[test]
fn census_actor_needs_exact_native_identity_and_independent_hard_booking() {
    let program = Bound {
        path: "/test/census".into(),
        sha256: "a".repeat(64),
    };
    let iid = "b".repeat(32);
    let n = json!({"Id":"horizon-completed145-parent-memory-census-20261106-v1.service","InvocationID":iid,
        "MainPID":"123","ControlPID":"0","ActiveState":"active","SubState":"running","NRestarts":"0",
        "Restart":"no","Job":"","MemoryAccounting":"yes","MemoryMax":"2147483648","MemorySwapMax":"0","program":program});
    actor_shape(&n, &program, &iid).unwrap();
    for (key, value) in [
        ("Id", json!(UNIT)),
        ("MainPID", json!("0")),
        ("NRestarts", json!("1")),
        ("MemoryMax", json!("0")),
        ("Job", json!("7")),
        ("program", json!({"path":"/other","sha256":"a".repeat(64)})),
    ] {
        let mut bad = n.clone();
        bad[key] = value;
        assert!(actor_shape(&bad, &program, &iid).is_err(), "{key}");
    }
}
