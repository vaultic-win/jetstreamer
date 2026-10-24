use super::*;
fn fixture() -> (
    BTreeMap<String, String>,
    BTreeMap<String, String>,
    Vec<Value>,
) {
    (
        parse_properties(include_bytes!("fixtures/initial-properties.txt")).unwrap(),
        parse_properties(include_bytes!("fixtures/terminal-properties.txt")).unwrap(),
        parse_journal(include_bytes!("fixtures/journal.jsonl")).unwrap(),
    )
}
fn current(terminal: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut p = terminal.clone();
    for (k, v) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("MainPID", "0"),
        ("ControlGroup", ""),
    ] {
        p.insert(k.into(), v.into());
    }
    p
}
fn copy_bound(b: &BoundFile) -> BoundFile {
    BoundFile {
        path: b.path.clone(),
        sha256: b.sha256.clone(),
    }
}
fn scope_fixture() -> (BoundFile, Value, BoundFile, BoundFile) {
    (
        BoundFile {
            path: RECEIPT.into(),
            sha256: RECEIPT_SHA.into(),
        },
        json!({"invocation_id":IID,"bindings":{"self_sha256":c::RUNNER_SHA,"plan_path":PLAN,"plan_sha256":PLAN_SHA},
            "node_sha256":c::NODE_SHA,"worker_sha256":c::WORKER_SHA,"worker_started":false,"entry_replay":false,
            "parent_planning_report":{"worker_spawned":false,"archive_created":false}}),
        BoundFile {
            path: PLAN.into(),
            sha256: PLAN_SHA.into(),
        },
        BoundFile {
            path: format!("/etc/systemd/system/{UNIT}").into(),
            sha256: UNIT_SHA.into(),
        },
    )
}
#[test]
fn actual_sealed_fixtures_preserve_positive_historical_identity_and_collected_zeros() {
    for (bytes, sha) in [
        (
            include_bytes!("fixtures/initial-properties.txt").as_slice(),
            INITIAL_SHA,
        ),
        (
            include_bytes!("fixtures/terminal-properties.txt").as_slice(),
            TERMINAL_SHA,
        ),
        (
            include_bytes!("fixtures/journal.jsonl").as_slice(),
            JOURNAL_SHA,
        ),
    ] {
        assert_eq!(hex_lower(&Sha256::digest(bytes)), sha);
    }
    let (initial, terminal, rows) = fixture();
    historical(&initial, &terminal, &rows).unwrap();
    let actual = current(&terminal);
    current_matches(&actual, &terminal).unwrap();
    assert_eq!(actual["ExecMainPID"], "0");
    assert_eq!(actual["ExecMainExitTimestampMonotonic"], "0");
    assert_eq!(initial["ExecMainPID"], "580417");
    assert_eq!(initial["ExecMainStartTimestampMonotonic"], "1781970577079");
}
#[test]
fn collected_profile_rejects_other_receipts_plans_units_and_no_worker_bindings() {
    let (b, v, p, u) = scope_fixture();
    exact_scope(&b, &v, &p, &u).unwrap();
    let mut bad = copy_bound(&b);
    bad.path =
        "/var/lib/jetstreamer/horizon-227-selection-capability-result-v2/capability.json".into();
    assert!(!applies(&bad));
    assert!(exact_scope(&bad, &v, &p, &u).is_err());
    for n in 0..6 {
        let (mut b, mut p, mut u) = (copy_bound(&b), copy_bound(&p), copy_bound(&u));
        match n {
            0 => b.sha256 = "0".repeat(64),
            1 => p.path = "/sealed/other-plan".into(),
            2 => p.sha256 = "0".repeat(64),
            3 => u.path = "/etc/systemd/system/other.service".into(),
            4 => u.sha256 = "0".repeat(64),
            _ => b.path = "/home/ubuntu/.jetstreamer-private/other/receipts/capability.json".into(),
        }
        assert!(exact_scope(&b, &v, &p, &u).is_err());
    }
    for (ptr, value) in [
        ("/invocation_id", json!("a".repeat(32))),
        ("/bindings/self_sha256", json!("0".repeat(64))),
        ("/bindings/plan_path", json!("/other")),
        ("/bindings/plan_sha256", json!("0".repeat(64))),
        ("/node_sha256", json!("0".repeat(64))),
        ("/worker_sha256", json!("0".repeat(64))),
        ("/worker_started", json!(true)),
        ("/entry_replay", json!(true)),
        ("/parent_planning_report/worker_spawned", json!(true)),
        ("/parent_planning_report/archive_created", json!(true)),
    ] {
        let mut bad = v.clone();
        *bad.pointer_mut(ptr).unwrap() = value;
        assert!(exact_scope(&b, &bad, &p, &u).is_err(), "{ptr}");
    }
}
#[test]
fn collected_current_requires_exact_actual_clean_state_sandbox_and_command() {
    let (_, terminal, _) = fixture();
    let actual = current(&terminal);
    for key in actual.keys() {
        let mut bad = actual.clone();
        bad.insert(key.clone(), format!("{}-changed", actual[key]));
        assert!(current_matches(&bad, &terminal).is_err(), "{key}");
        let mut bad = actual.clone();
        bad.remove(key);
        assert!(current_matches(&bad, &terminal).is_err(), "missing {key}");
    }
    for (key, value) in [
        ("ExecMainPID", "580417"),
        ("MainPID", "580417"),
        ("InvocationID", IID),
        ("ControlGroup", "/system.slice/other"),
        ("ExecMainExitTimestampMonotonic", "1781978075500"),
    ] {
        let mut bad = actual.clone();
        bad.insert(key.into(), value.into());
        assert!(current_matches(&bad, &terminal).is_err(), "{key}");
    }
    let mut bad = actual.clone();
    bad.insert("Unexpected".into(), "true".into());
    assert!(current_matches(&bad, &terminal).is_err());
}
#[test]
fn historical_identity_and_pid1_journal_reject_missing_extra_conflicting_or_reordered_rows() {
    let (initial, terminal, rows) = fixture();
    for key in initial.keys() {
        let mut bad = initial.clone();
        bad.insert(key.clone(), format!("{}-changed", initial[key]));
        assert!(historical(&bad, &terminal, &rows).is_err(), "{key}");
    }
    for n in 0..rows.len() {
        let mut bad = rows.clone();
        bad.remove(n);
        assert!(historical(&initial, &terminal, &bad).is_err());
        let mut bad = rows.clone();
        bad.push(rows[n].clone());
        assert!(historical(&initial, &terminal, &bad).is_err());
        for (key, value) in [
            ("_PID", json!("99")),
            ("_UID", json!("1000")),
            ("INVOCATION_ID", json!("f".repeat(32))),
            ("_BOOT_ID", json!("f".repeat(32))),
            ("_MACHINE_ID", json!("f".repeat(32))),
            ("UNIT", json!("other.service")),
            ("MESSAGE", json!("failed")),
            ("__MONOTONIC_TIMESTAMP", json!(START.to_string())),
            ("__SEQNUM", json!("0")),
        ] {
            let mut bad = rows.clone();
            bad[n][key] = value;
            assert!(
                historical(&initial, &terminal, &bad).is_err(),
                "row {n} {key}"
            );
        }
    }
    let mut bad = rows.clone();
    bad.swap(0, 1);
    assert!(historical(&initial, &terminal, &bad).is_err());
    let mut bad = rows.clone();
    bad[2]["JOB_RESULT"] = json!("failed");
    assert!(historical(&initial, &terminal, &bad).is_err());
    let mut bad = rows.clone();
    bad[2]["JOB_ID"] = json!("other");
    assert!(historical(&initial, &terminal, &bad).is_err());
}
#[test]
fn parsers_reject_duplicate_properties_and_malformed_or_oversized_journal() {
    assert!(parse_properties(b"ExecMainPID=0\nExecMainPID=580417\n").is_err());
    assert!(parse_properties(b"not a property\n").is_err());
    assert!(parse_journal(b"").is_err());
    assert!(parse_journal(b"{\"_PID\":\"1\"}\nnot json\n").is_err());
    assert!(parse_journal(&vec![b' '; (16 << 20) + 1]).is_err());
}
