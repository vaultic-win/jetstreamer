use super::*;
fn row() -> Value {
    json!({"Id":UNIT,"LoadState":"loaded","Type":"exec","User":"sol","MemoryAccounting":"yes","MemoryMax":"206158430208","MemorySwapMax":"0","CPUQuotaPerSecUSec":"8s","TasksMax":"1024","Restart":"no","NRestarts":"0","ControlGroup":format!("/system.slice/{UNIT}"),"ExecStart":format!("{} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",expected(&format!("{PACKAGE}/jetstreamer-node"),&parent_args()))})
}
#[test]
fn enrolled_parent_rejects_foreign_owner_caps_cpu_and_restarts() {
    let good = row();
    raw_profile(&good).unwrap();
    for (k, v) in [
        ("Id", json!("foreign.service")),
        ("MemoryMax", json!("infinity")),
        ("MemorySwapMax", json!("infinity")),
        ("CPUQuotaPerSecUSec", json!("16s")),
        ("Restart", json!("on-failure")),
        ("NRestarts", json!("1")),
        ("ControlGroup", json!("/system.slice/foreign.service")),
    ] {
        let mut bad = good.clone();
        bad[k] = v;
        assert!(raw_profile(&bad).is_err(), "{k}");
    }
}
#[test]
fn direct163_cannot_borrow_the_legacy_diagnostic_schema() {
    let claim = DiagnosticClaim {
        epoch: 163,
        unit: UNIT.into(),
        invocation_id: "a".repeat(32),
        scratch_path: Path::new(ROOT).join("private"),
        launch_receipt: BoundFile {
            path: REGISTER.into(),
            sha256: "b".repeat(64),
        },
    };
    let good = json!({"schema":"horizon-direct163-typed-enrollment-v1","parent_owner":{"unit":UNIT,"iid":"a".repeat(32)},"unattended_authorized":true,"publication_authorized":false,"r2_mutations":false});
    assert!(launch_matches(&claim, &good));
    for k in ["schema", "parent_owner", "unattended_authorized"] {
        let mut bad = good.clone();
        bad[k] = Value::Null;
        assert!(!launch_matches(&claim, &bad));
    }
}
#[test]
fn actual_guard_payload_requires_root_image_unit_iid_clock_and_parent() {
    let iid = "a".repeat(32);
    let parent = "b".repeat(32);
    let journal = json!({"_SYSTEMD_UNIT":GUARD,"_SYSTEMD_INVOCATION_ID":iid,"_UID":"0","_EXE":GUARD_IMAGE,"__REALTIME_TIMESTAMP":"100000000"});
    let payload = json!({"armed":true,"parent_invocation_id":parent,"memory_continuity_validated":true,"available_bytes":1000,"worker_vmas":null});
    fire_payload(&journal, &payload, &iid, &parent, 1000, 101).unwrap();
    for (k, v) in [
        ("_UID", json!("1001")),
        ("_EXE", json!("/foreign")),
        ("_SYSTEMD_UNIT", json!(STOP)),
        ("_SYSTEMD_INVOCATION_ID", json!("c".repeat(32))),
        ("__REALTIME_TIMESTAMP", json!("102000000")),
    ] {
        let mut bad = journal.clone();
        bad[k] = v;
        assert!(
            fire_payload(&bad, &payload, &iid, &parent, 1000, 101).is_err(),
            "{k}"
        );
    }
    assert!(fire_payload(&journal, &payload, &iid, &parent, 1000, 281).is_err());
    for (k, v) in [
        ("armed", json!(false)),
        ("parent_invocation_id", json!("c".repeat(32))),
        ("worker_vmas", json!(3000001)),
        ("available_bytes", json!(999)),
        ("memory_continuity_validated", json!(false)),
    ] {
        let mut bad = payload.clone();
        bad[k] = v;
        assert!(
            fire_payload(&journal, &bad, &iid, &parent, 1000, 101).is_err(),
            "{k}"
        );
    }
}
#[test]
fn private_comparison_only_normalizes_the_registered_direct_guard_identity() {
    let base = json!({"unit":GUARD,"invocation_id":"a".repeat(32),"direct163_registration":{"path":REGISTER,"sha256":"b".repeat(64)},"included_once_in_direct163_parent_claim":true,"actual_memory_hard_limit_bytes":2u64<<30});
    let mut renewed = base.clone();
    renewed["invocation_id"] = json!("c".repeat(32));
    assert!(normalize_peers(std::slice::from_ref(&base), std::slice::from_ref(&renewed)).unwrap());
    renewed["actual_memory_hard_limit_bytes"] = json!(1);
    assert!(!normalize_peers(std::slice::from_ref(&base), &[renewed]).unwrap());
    let mut foreign = base;
    foreign["direct163_registration"]["path"] = json!("/foreign");
    assert!(normalize_peers(&[foreign.clone()], &[foreign]).is_err());
}

#[test]
fn terminal_identity_requires_drained_original_owner_and_never_accepts_replacement() {
    let iid = "a".repeat(32);
    let good = json!({"Id":UNIT,"MainPID":"0","ControlPID":"0","NRestarts":"0",
        "Job":"","InvocationID":iid,"ActiveState":"failed"});
    terminal_identity(&good, &iid).unwrap();
    for (key, value) in [
        ("Id", json!("foreign.service")),
        ("MainPID", json!("123")),
        ("ControlPID", json!("124")),
        ("NRestarts", json!("1")),
        ("Job", json!("123")),
        ("InvocationID", json!("b".repeat(32))),
        ("ActiveState", json!("active")),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(terminal_identity(&bad, &iid).is_err(), "{key}");
    }
}
#[test]
fn parent_aggregate_charges_full_data_and_both_auxiliaries_exactly_once_even_when_terminal() {
    let e = json!({"owner":{"iid":"a".repeat(32)},"registration":{"path":REGISTER,"sha256":"b".repeat(64)},
        "guard_native":{"InvocationID":"c".repeat(32)},"fallback_native":{"InvocationID":""},
        "admission":{"minimum_free_bytes":4202184371152u64,
        "candidate_memory":{"candidate_scheduling_total_bytes":197768759296u64,"guard_memory_bytes":2u64<<30,"failure_stop_memory_bytes":512u64<<20}}});
    let rows = allocation_rows(&e).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(
        rows.iter()
            .map(|r| r["memory_max_bytes"].as_u64().unwrap())
            .sum::<u64>(),
        197768759296
    );
    assert_eq!(
        rows.iter()
            .map(|r| r["data_reservation_bytes"].as_u64().unwrap())
            .sum::<u64>(),
        768u64 << 30
    );
    assert_eq!(rows[1]["actual_memory_hard_limit_bytes"], 2u64 << 30);
    assert_eq!(rows[2]["actual_memory_hard_limit_bytes"], 512u64 << 20);
    assert!(rows.iter().all(|r| r["native_pool_suballocation"] == false));
    let mut terminal = e.clone();
    terminal["terminal"] = json!(true);
    assert_eq!(allocation_rows(&terminal).unwrap(), rows);
    terminal["admission"]["candidate_memory"]["guard_memory_bytes"] = json!(0);
    assert!(allocation_rows(&terminal).is_err());
}

#[test]
fn strict_native_string_accessor_rejects_missing_wrong_types_and_malformed_pointers() {
    let good = json!({"owner":{"iid":"original"},"a/b":{"~":"escaped"}});
    assert_eq!(string(&good, "/owner/iid").unwrap(), "original");
    assert_eq!(string(&good, "/a~1b/~0").unwrap(), "escaped");
    for pointer in ["", "owner/iid", "/", "/missing", "/owner", "/a~2b"] {
        assert!(string(&good, pointer).is_err(), "{pointer}");
    }
    for value in [Value::Null, json!(1), json!(true), json!([]), json!({})] {
        assert!(string(&json!({"iid":value}), "/iid").is_err());
    }
}
