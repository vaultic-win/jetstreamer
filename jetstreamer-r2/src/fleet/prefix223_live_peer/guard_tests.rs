//! Regression against the genuine completed 207 guard that admission rejected.
//! These pure fixtures grant no live admission or publication authority.
use super::*;

const SAMPLE: u64 = 1_792_913_160;
const NOW: u64 = 1_792_914_656;

fn fixture() -> (DiagnosticClaim, Value, Value, Value, String) {
    let d = serde_json::from_str(include_str!("fixtures/claim207.json")).unwrap();
    let l: Value = serde_json::from_str(include_str!("fixtures/launch207-profile.json")).unwrap();
    let p = serde_json::from_str(include_str!("fixtures/plan207.json")).unwrap();
    let g = serde_json::from_str(include_str!("fixtures/guard207.json")).unwrap();
    let sha = l["guard_plan"]["sha256"].as_str().unwrap().to_owned();
    (d, l, p, g, sha)
}

#[test]
fn genuine_standalone207_guard_binds_unit_without_a_producer_unit_field() {
    let (d, l, p, g, sha) = fixture();
    assert_eq!(
        hex_lower(&Sha256::digest(include_bytes!("fixtures/guard207.json"))),
        "52e28879667be131c8dd163a76c825bad2943dac963bef6337720c5a6dcf3629"
    );
    assert_eq!(
        hex_lower(&Sha256::digest(include_bytes!("fixtures/plan207.json"))),
        sha
    );
    assert!(g["producer"].get("unit").is_none());
    assert_eq!(p["unit"], d.unit);
    assert_eq!(g["plan"], l["guard_plan"]["path"]);
    assert!(singleton207::guard_matches(&d, &l, &p));
    guard_shape(&d, &l, &p, &g, &sha, SAMPLE, NOW).unwrap();
}

#[test]
fn real_guard_identity_plan_and_protective_obligations_remain_mandatory() {
    let (d, l, p, g, sha) = fixture();
    for (path, value) in [
        ("/plan", json!("/sealed/another-guard-plan.json")),
        ("/plan_sha256", json!("e".repeat(64))),
        ("/guard_sha256", json!("e".repeat(64))),
        ("/producer_invocation_id", json!("e".repeat(32))),
        ("/producer/invocation_id", json!("e".repeat(32))),
        ("/producer/cgroup", json!("/system.slice/another.service")),
        ("/producer/restarts", json!(1)),
        ("/producer/active", json!("inactive")),
        ("/producer/sub", json!("dead")),
        ("/producer/kill_mode", json!("process")),
        ("/producer/delegated", json!(true)),
        ("/producer_stop_enabled", json!(false)),
        ("/minimum_free_bytes", json!(0)),
        ("/available_bytes", json!(0)),
        ("/workers", json!([])),
        ("/workers", json!([[42, 1], [43, 1]])),
        ("/workers/0/1", json!(3_500_000)),
        ("/root_physical_observation/exceeds_budget", json!(true)),
        (
            "/root_physical_observation/conservative_physical_bytes",
            json!(437_438_953_473u64),
        ),
        ("/trip_reason", json!("root-physical-budget")),
        ("/worker_observation_error", json!("unavailable")),
        ("/root_physical_observation_error", json!("unavailable")),
        ("/canary_target_error", json!("unavailable")),
        ("/target_handoff_error", json!("unavailable")),
        ("/r2_mutations", json!(true)),
        ("/remote_mutations", json!(true)),
    ] {
        let mut changed = g.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            guard_shape(&d, &l, &p, &changed, &sha, SAMPLE, NOW).is_err(),
            "changed guard {path}"
        );
    }
    for (path, value) in [
        ("/unit", json!("another.service")),
        ("/invocation_id", json!("e".repeat(32))),
        ("/worker_root", json!("/another-root")),
        ("/receipt_directory", json!("/another-receipts")),
    ] {
        let mut changed = p.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            guard_shape(&d, &l, &changed, &g, &sha, SAMPLE, NOW).is_err(),
            "changed plan {path}"
        );
    }
    let mut changed = l.clone();
    changed["guard_plan"]["path"] = json!("/another-plan.json");
    assert!(guard_shape(&d, &changed, &p, &g, &sha, SAMPLE, NOW).is_err());
    let mut changed = d;
    changed.unit = "another.service".into();
    assert!(guard_shape(&changed, &l, &p, &g, &sha, SAMPLE, NOW).is_err());
}

#[test]
fn real_guard_clock_and_missing_obligations_still_fail_closed() {
    let (d, l, p, g, sha) = fixture();
    let recorded = g["recorded_unix_seconds"].as_u64().unwrap();
    assert!(guard_shape(&d, &l, &p, &g, &sha, recorded + 1, NOW).is_err());
    assert!(guard_shape(&d, &l, &p, &g, &sha, SAMPLE, recorded - 1).is_err());
    assert!(guard_shape(&d, &l, &p, &g, &sha, SAMPLE, recorded + 1801).is_err());
    for key in [
        "plan",
        "producer_invocation_id",
        "producer_stop_enabled",
        "root_physical_observation",
        "trip_reason",
        "worker_observation_error",
        "root_physical_observation_error",
        "canary_target_error",
        "target_handoff_error",
    ] {
        let mut changed = g.clone();
        changed.as_object_mut().unwrap().remove(key);
        assert!(
            guard_shape(&d, &l, &p, &changed, &sha, SAMPLE, NOW).is_err(),
            "missing guard {key}"
        );
    }
}
