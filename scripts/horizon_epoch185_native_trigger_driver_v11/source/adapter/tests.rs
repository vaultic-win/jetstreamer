use super::*;
use std::os::unix::fs::PermissionsExt;
#[test]
fn actual1800_formatted_timer_trigger_is_exact_and_raw_guard_start_stays_raw() {
    let trigger = native_timer_micros("4w 1d 43min 54.141704s").unwrap();
    assert_eq!(trigger, 2_508_234_141_704);
    assert_eq!(native_timer_micros("2508234141704").unwrap(), trigger);
    let begin = "2508234142704".parse::<u64>().unwrap();
    timer_activation_fresh(trigger, begin, begin + 1000).unwrap();
    assert!("4w 1d 43min 54.142704s".parse::<u64>().is_err());
}
#[test]
fn native_timer_timespan_rejects_malformed_unsupported_and_nonintegral_values() {
    for raw in [
        "",
        " 1s",
        "1s ",
        "1s  1us",
        "infinity",
        "n/a",
        "1ns",
        "1year",
        "-1s",
        "+1s",
        "1e3s",
        ".5s",
        "1.s",
        "1.2.3s",
        "1s 1s",
        "1us 1s",
        "1s 1",
        "1.0000001s",
        "0.1us",
        "0.0001ms",
        "1µs",
        "1s\n",
    ] {
        assert!(native_timer_micros(raw).is_err(), "accepted {raw:?}");
    }
    assert_eq!(
        native_timer_micros("1h 2min 3.000004s").unwrap(),
        3_723_000_004
    );
    assert_eq!(native_timer_micros("1ms 1us").unwrap(), 1001);
}
#[test]
fn native_timer_timespan_overflow_zero_and_infinity_never_become_trigger() {
    for raw in [
        "0",
        "0us",
        "0.000000s",
        "18446744073709551616",
        "18446744073709551615",
        "18446744073709551615us",
        "18446744073709551615s",
        "30500569w",
        "18446744073709551ms 615us",
        "18446744073709551ms 616us",
    ] {
        assert!(native_timer_micros(raw).is_err(), "accepted {raw:?}");
    }
    assert_eq!(
        native_timer_micros("18446744073709551614us").unwrap(),
        u64::MAX - 1
    );
}
#[test]
fn native_timer_activation_retains_exact_five_and_ninety_second_bounds() {
    let trigger = 2_508_234_141_704;
    let begin = trigger + 5_000_000;
    timer_activation_fresh(trigger, begin, begin + 90_000_000).unwrap();
    for (trigger, begin, at) in [
        (trigger, begin + 1, begin + 1),
        (trigger, begin, begin + 90_000_001),
        (trigger, trigger - 1, trigger),
        (trigger, begin, begin - 1),
        (0, begin, begin),
        (trigger, 0, begin),
        (u64::MAX, u64::MAX, u64::MAX),
    ] {
        assert!(timer_activation_fresh(trigger, begin, at).is_err());
    }
}
fn fixture() -> Envelope {
    let b = json!({"path":"/sealed/bound.json","sha256":"b".repeat(64)});
    serde_json::from_value(json!({"schema":"horizon-epoch185-guarded-cold-envelope-v4",
        "plan":{"schema":PLAN_SCHEMA,"unit":"horizon-qualify-185-capped-cold-fixture.service",
            "node":{"path":format!("{PACKAGE}/jetstreamer-node"),"sha256":PARENT_SHA},
            "worker":format!("{PACKAGE}/jetstreamer-historical-worker-v1-6-15"),"snapshot":format!("{PACKAGE}/{SNAPSHOT_NAME}"),
            "ledger_directory":PACKAGE,"epoch_hashes":{"path":format!("{PACKAGE}/epoch-hashes-185.txt"),"sha256":"9ef0d882bf9b530abcd77f8aae199a0c2057c06b32a1d738c7443e3e431606fa"},
            "run_root":"/home/sol/.jetstreamer-private/capped-root-prefix-185-fixture","target_slot":TARGET,"terminal_slot":TERMINAL,
            "minimum_free_bytes":MINIMUM_FREE,"maximum_runtime_seconds":600},
        "admission":b,"actor_service_path":"/etc/systemd/system/horizon-qualify-185-capped-cold-fixture.service",
        "guard_service_path":"/etc/systemd/system/horizon-guard-185-capped-cold-fixture.service","timer_service":b,
        "guard_unit":"horizon-guard-185-capped-cold-fixture.service","timer_unit":"horizon-guard-185-capped-cold-fixture.timer",
        "control_root":"/home/sol/.jetstreamer-private/epoch185-cold-control-fixture",
        "token_root":"/usr/local/lib/jetstreamer/horizon-epoch185-cold-gates-v4","guard_receipt_root":"/var/lib/jetstreamer/epoch185-cold-guard-v4",
        "self_program":"/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v4/epoch185-guarded-cold","self_sha256":"c".repeat(64),
        "limits":{"memory":195084404736u64,"scratch":384u64<<30,"output":128u64<<30,"metadata":64*MIB,"vmas":4194304,"log":64*MIB},
        "setup_deadline_seconds":120})).unwrap()
}
fn manifest() -> Value {
    json!({"schema_version":1,"epoch":185,"output_slot_start":79920000,"output_slot_count":431284,
    "worker_executable_sha256":WORKER,"runtime":{"runtime_profile":"solana-v1.6.15"},
    "bootstrap":{"slot":79919283,"slot_complete":true,"accounts_hash":"Hozk66F2tKQuhouHceuwU9xZzWaXksnBeU1JBysRBmmf"},
    "terminal":{"slot":80351283,"slot_complete":true,"accounts_hash":"Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8"},"archive_sha256":"a".repeat(64)})
}
fn ready() -> Value {
    json!({"pid":123,"start_ticks":456,"sha256":"d".repeat(64),"started_at":1000})
}
fn gate(e: &Envelope) -> Value {
    json!({"schema":"horizon-epoch185-native-gate-v4","epoch":185,"actor_unit":e.plan.unit,
    "actor_invocation_id":"a".repeat(32),"admission_sha256":e.admission.sha256,"driver_sha256":e.self_sha256,
    "ready_pid":123,"ready_start_ticks":456,"ready_sha256":"d".repeat(64),"guard_unit":e.guard_unit,"timer_unit":e.timer_unit,
    "issued_at":1011,"expires_at":1050,"guard_result":{"schema":"horizon-epoch185-native-guard-result-v4","success":true,"timer_driven":true,
        "actor_invocation_id":"a".repeat(32),"admission_sha256":e.admission.sha256,"sampled_at":1010}})
}
fn accepted(e: &Envelope) -> Admission {
    let b = json!({"path":"/sealed/bound.json","sha256":"b".repeat(64)});
    serde_json::from_value(json!({"schema":"horizon-epoch185-root-accepted-native-admission-v1","epoch":185,"unit":e.plan.unit,
        "task_owner":"Root","phase":"verification","issued_at":1000,"expires_at":1600,"minimum_free_bytes":e.plan.minimum_free_bytes,
        "memory_max_bytes":e.limits.memory,"current_full_reader":b,"current_frame":b,"typed_memory":b,"typed_data":b,
        "fleet_owner":b,"status_readback":b,"root_acceptance":b,"full_reader_accepted":true,"raw_obligations_preserved":true,
        "prefix_only":true,"ordinary_full_replay_authorized":false,"publication_authorized":false,"resource_credit_bytes":0})).unwrap()
}
#[test]
fn exact_epoch185_plan_and_prefix_are_accepted() {
    let e = fixture();
    validate_envelope(&e).unwrap();
    engine::root_manifest_valid(&manifest()).unwrap();
}
#[test]
fn foreign_epoch_unit_is_rejected() {
    let mut e = fixture();
    e.plan.unit = "horizon-qualify-186-capped-cold-fixture.service".into();
    assert!(validate_envelope(&e).is_err());
}
#[test]
fn terminal_suffix_cannot_be_promoted_to_prefix() {
    let mut e = fixture();
    e.plan.terminal_slot = 80351999;
    assert!(validate_envelope(&e).is_err());
    let mut m = manifest();
    m["output_slot_count"] = 432000.into();
    assert!(engine::root_manifest_valid(&m).is_err());
}
#[test]
fn parent_digest_and_package_cannot_be_substituted() {
    let mut e = fixture();
    e.plan.node.sha256 = "0".repeat(64);
    assert!(validate_envelope(&e).is_err());
    let mut e = fixture();
    e.plan.worker = "/other/worker".into();
    assert!(validate_envelope(&e).is_err());
}
#[test]
fn bootstrap_and_private_root_are_exact() {
    let mut e = fixture();
    e.plan.snapshot = "/sealed/foreign".into();
    assert!(validate_envelope(&e).is_err());
    let mut e = fixture();
    e.plan.run_root = "/home/sol/.jetstreamer-private/foreign".into();
    assert!(validate_envelope(&e).is_err());
}
#[test]
fn historical_floor_cannot_be_lowered() {
    let mut e = fixture();
    e.plan.minimum_free_bytes = MINIMUM_FREE - 1;
    assert!(validate_envelope(&e).is_err());
}
#[test]
fn runtime_and_memory_stop_ceiling_cannot_be_widened() {
    let mut e = fixture();
    e.plan.maximum_runtime_seconds = MAX_RUNTIME + 1;
    assert!(validate_envelope(&e).is_err());
    let mut e = fixture();
    e.limits.memory += 1;
    assert!(validate_envelope(&e).is_err());
}
#[test]
fn focused_command_cannot_borrow_full_cohort_flags() {
    let e = fixture();
    let c = engine::command(&e.plan);
    let a = c
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(a.contains(&"--qualification-end-slot=80351283".into()));
    assert!(!a
        .iter()
        .any(|a| a.contains("root-checkpoint-cohort") || a.contains("cohort-manifest")));
}
#[test]
fn prefix_rejects_wrong_worker_runtime_or_hash() {
    for (key, value) in [
        ("/worker_executable_sha256", json!("f".repeat(64))),
        ("/runtime/runtime_profile", json!("solana-v1.6.16")),
        ("/bootstrap/accounts_hash", json!("wrong")),
        ("/terminal/slot_complete", json!(false)),
        ("/archive_sha256", json!("0".repeat(64))),
    ] {
        let mut m = manifest();
        *m.pointer_mut(key).unwrap() = value;
        assert!(engine::root_manifest_valid(&m).is_err(), "accepted {key}");
    }
}
#[test]
fn exact_gate_requires_actual_iid_and_ready_identity() {
    let e = fixture();
    let g = gate(&e);
    gate_policy(&g, &e, &"a".repeat(32), &ready(), 1020).unwrap();
    assert!(gate_policy(&g, &e, &"b".repeat(32), &ready(), 1020).is_err());
    let mut r = ready();
    r["start_ticks"] = 457.into();
    assert!(gate_policy(&g, &e, &"a".repeat(32), &r, 1020).is_err());
}
#[test]
fn false_or_nontimer_guard_cannot_open_gate() {
    let e = fixture();
    for key in ["success", "timer_driven"] {
        let mut g = gate(&e);
        g["guard_result"][key] = false.into();
        assert!(gate_policy(&g, &e, &"a".repeat(32), &ready(), 1020).is_err());
    }
}
#[test]
fn gate_expiry_and_stale_first_fire_are_rejected() {
    let e = fixture();
    let g = gate(&e);
    assert!(gate_policy(&g, &e, &"a".repeat(32), &ready(), 1050).is_err());
    assert!(gate_policy(&g, &e, &"a".repeat(32), &ready(), 1041).is_err());
}
#[test]
fn guard_must_follow_readiness_and_original_clock() {
    let e = fixture();
    let mut g = gate(&e);
    g["guard_result"]["sampled_at"] = 999.into();
    assert!(gate_policy(&g, &e, &"a".repeat(32), &ready(), 1020).is_err());
    let mut g = gate(&e);
    g["expires_at"] = 1121.into();
    assert!(gate_policy(&g, &e, &"a".repeat(32), &ready(), 1020).is_err());
}
#[test]
fn current_reader_owner_and_expiry_are_mandatory() {
    let e = fixture();
    let mut a = accepted(&e);
    admission_policy(&a, &e, 1100).unwrap();
    a.full_reader_accepted = false;
    assert!(admission_policy(&a, &e, 1100).is_err());
    let a = accepted(&e);
    assert!(admission_policy(&a, &e, 1600).is_err());
}
#[test]
fn admission_never_grants_full_replay_publication_or_credit() {
    let e = fixture();
    let mut a = accepted(&e);
    a.resource_credit_bytes = 1;
    assert!(admission_policy(&a, &e, 1100).is_err());
    let mut a = accepted(&e);
    a.publication_authorized = true;
    assert!(admission_policy(&a, &e, 1100).is_err());
    let mut a = accepted(&e);
    a.ordinary_full_replay_authorized = true;
    assert!(admission_policy(&a, &e, 1100).is_err());
}
#[test]
fn each_resource_bound_is_enforced_independently() {
    let e = fixture();
    let good = [
        e.plan.minimum_free_bytes,
        e.limits.memory,
        e.limits.scratch,
        e.limits.output,
        e.limits.metadata,
        e.limits.vmas,
    ];
    resource_policy(&e, good[0], good[1], good[2], good[3], good[4], good[5]).unwrap();
    for i in 0..6 {
        let mut v = good;
        if i == 0 {
            v[i] -= 1
        } else {
            v[i] += 1
        }
        assert!(resource_policy(&e, v[0], v[1], v[2], v[3], v[4], v[5]).is_err());
    }
}
#[test]
fn actual_allocation_walk_rejects_symlink_and_limit() {
    let t = tempfile::tempdir().unwrap();
    fs::write(t.path().join("data"), vec![0u8; 8192]).unwrap();
    assert!(allocated(t.path(), 1).is_err());
    std::os::unix::fs::symlink("/", t.path().join("escape")).unwrap();
    assert!(allocated(t.path(), 1 << 20).is_err());
}
#[test]
fn actual_receipt_collision_preserves_original() {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let p = t.path().join("receipt");
    persist(&p, &json!({"original":true})).unwrap();
    assert!(persist(&p, &json!({"replacement":true})).is_err());
    let v: Value = serde_json::from_slice(&fs::read(p).unwrap()).unwrap();
    assert_eq!(v["original"], true);
}
#[test]
fn logging_redacts_sensitive_urls_and_tokens() {
    let value = redact("phase https://host/object?X-Amz-Signature=abc token=secret ready");
    assert!(!value.contains("Signature"));
    assert!(!value.contains("secret"));
    assert!(value.contains("ready"));
}
#[test]
fn logging_heartbeat_does_not_reset_progress_clock() {
    phase("fixture", "awaiting a test condition");
    let before = LOG.get().unwrap().lock().unwrap().progress;
    heartbeat();
    assert_eq!(LOG.get().unwrap().lock().unwrap().progress, before);
}

#[test]
fn actual_iid_enrollment_requires_numeric_eta_and_root_owner() {
    let e = fixture();
    let r = ready();
    let iid = "a".repeat(32);
    let mut v = json!({"schema":"horizon-epoch185-native-owner-enrollment-v4","epoch":185,"actor_unit":e.plan.unit,
        "actor_invocation_id":iid,"ready_pid":123,"ready_start_ticks":456,"admission_sha256":e.admission.sha256,
        "restarts":0,"phase":"verification","root_operator_owner":true,"actual_start_pre_evidence_accepted":true,
        "numeric_delivery_eta_millis":1000,"sampled_at":1001,"resource_credit_bytes":0});
    enrollment_policy(&v, &e, &iid, &r, 1020).unwrap();
    v["numeric_delivery_eta_millis"] = Value::Null;
    assert!(enrollment_policy(&v, &e, &iid, &r, 1020).is_err());
    v["numeric_delivery_eta_millis"] = 1000.into();
    v["root_operator_owner"] = false.into();
    assert!(enrollment_policy(&v, &e, &iid, &r, 1020).is_err());
}

#[test]
#[ignore = "Root-booked read-only queries of genuine installed v11 metadata; no activation"]
fn actual_v11_native_hook_arrays_and_timer_cadence_are_observed() {
    for role in ["qualify", "guard"] {
        let name = format!("horizon-{role}-185-capped-cold-missing-token-20261105-v11.service");
        let observed = native(&name).unwrap();
        assert_eq!(property(&observed, "ExecStartPost").unwrap(), "");
        assert_eq!(property(&observed, "ExecStopPost").unwrap(), "");
    }
    let timer = native("horizon-guard-185-capped-cold-missing-token-20261105-v11.timer").unwrap();
    assert_eq!(
        property(&timer, "TimersMonotonic").unwrap().lines().count(),
        2
    );
}

#[test]
#[ignore = "Exact unprivileged actor metadata capability; no activation"]
fn actual_v11_actor_hook_arrays_are_readable_without_manage_unit_authority() {
    let observed =
        native("horizon-qualify-185-capped-cold-missing-token-20261105-v11.service").unwrap();
    assert_eq!(property(&observed, "ExecStartPost").unwrap(), "");
    assert_eq!(property(&observed, "ExecStopPost").unwrap(), "");
}
