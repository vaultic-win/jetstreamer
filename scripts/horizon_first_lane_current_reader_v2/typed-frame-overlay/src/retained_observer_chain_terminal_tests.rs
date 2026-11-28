//! Pure ancestry integration tests. Terminal predecessor below is an explicit TEST ONLY
//! projection from accepted 22:58 fields, never an actual accepted fleet receipt.
use super::*;
fn plan_value() -> Value {
    serde_json::from_str(include_str!(
        "cached145_terminal_observer_fixtures/current-plan0028.json"
    ))
    .unwrap()
}
fn accepted_previous() -> Value {
    serde_json::from_str(include_str!(
        "cached145_terminal_observer_fixtures/accepted-previous-fleet2258.json"
    ))
    .unwrap()
}
fn sample(name: &str) -> Value {
    serde_json::from_str(match name {
        "2328" => include_str!("cached145_terminal_observer_fixtures/observer2328.json"),
        "2358" => include_str!("cached145_terminal_observer_fixtures/observer2358.json"),
        "0028" => include_str!("cached145_terminal_observer_fixtures/observer0028.json"),
        _ => panic!("unknown test sample"),
    })
    .unwrap()
}
fn witness() -> terminal::Witness {
    terminal::Witness::load(
        |s| {
            serde_json::from_str(if s.path == terminal::CAPTURE.path {
                include_str!("cached145_terminal_observer_fixtures/capture.json")
            } else {
                include_str!("cached145_terminal_observer_fixtures/terminal.json")
            })
            .map_err(Into::into)
        },
        &utc_seconds,
    )
    .unwrap()
}
fn read(b: &BoundFile) -> Result<Value> {
    for name in ["2328", "2358", "0028"] {
        let v = sample(name);
        if b.path.to_string_lossy().contains(&format!("T{name}09Z")) {
            return Ok(v);
        }
    }
    anyhow::bail!("undeclared sample")
}
fn terminal_previous() -> Value {
    let mut previous = accepted_previous();
    let v = sample("2358");
    previous["sampled_at_utc"] = v["recorded_at_utc"].clone();
    previous["observer_receipt"] = v["cadence"]["previous_sample"].clone();
    // This is a synthetic test projection with the exact real 23:58 receipt binding.
    previous["observer_receipt"] = json!(
        "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261105T235809Z-postcompletion154-v1.json"
    );
    previous["observer_sha256"] = sample("0028")["cadence"]["previous_sample_sha256"].clone();
    let mut n = previous["unit_census"][terminal::UNIT].clone();
    for (k, v) in [
        ("InvocationID", ""),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ControlGroup", ""),
        ("Job", ""),
    ] {
        n[k] = json!(v);
    }
    previous["unit_census"][terminal::UNIT] = n.clone();
    for r in previous["diagnostics"].as_array_mut().unwrap() {
        if r["unit"]["Id"] == terminal::UNIT {
            r["unit"] = n.clone();
            r["live"] = json!(false);
            r["terminal_outcome_requires_canary_receipt"] = json!(true);
        }
    }
    previous
}
fn selected(previous: &Value) -> Scope {
    scope_terminal(&plan_value(), previous, witness()).unwrap()
}
#[test]
fn initial_real_unavailable_verification_and_completed_rows_bridge_without_changing_them() {
    let previous = accepted_previous();
    let s = selected(&previous);
    let p = prove(&s, utc_seconds("2026-11-06T00:29:00Z").unwrap(), read).unwrap();
    assert_eq!(p.intermediates().len(), 2);
    let last = sample("0028");
    assert_eq!(
        last["diagnostic_replays"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["producer_unit"] == terminal::UNIT)
            .unwrap()["status"],
        "unavailable"
    );
}
#[test]
fn later_terminal_to_terminal_cycle_uses_original_capture_identity_and_real_terminal_anchor() {
    let previous = terminal_previous();
    let s = selected(&previous);
    assert_eq!(s.pid, terminal::PID);
    assert_eq!(previous["unit_census"][terminal::UNIT]["MainPID"], "0");
    let proof = prove(&s, utc_seconds("2026-11-06T00:29:00Z").unwrap(), read).unwrap();
    assert!(proof.intermediates().is_empty());
    assert_eq!(previous["unit_census"][terminal::UNIT]["MainPID"], "0");
}
#[test]
fn terminal_scope_rejects_lost_parent_guard_or_data_promises_and_foreign_invocation() {
    for key in [
        "process_hard_limit_protected_bytes",
        "guard_hard_limit_protected_bytes",
        "DATA_retained_bytes",
    ] {
        let mut p = terminal_previous();
        let row = p["diagnostics"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["unit"]["Id"] == terminal::UNIT)
            .unwrap();
        row["cached145_resource_promise"][key] = json!(0);
        assert!(witness().predecessor(&p, &utc_seconds).is_err());
    }
    let mut p = terminal_previous();
    p["unit_census"][terminal::UNIT]["InvocationID"] = json!("1".repeat(32));
    assert!(witness().predecessor(&p, &utc_seconds).is_err());
}
#[test]
fn terminal_chain_does_not_waive_freshness_missing_receipts_or_raw_error_checks() {
    let s = selected(&accepted_previous());
    let now = utc_seconds("2026-11-06T00:29:00Z").unwrap();
    assert!(prove(&s, now + 1801, read).is_err());
    assert!(
        prove(&s, now, |b| {
            if b.path.to_string_lossy().contains("T232809Z") {
                anyhow::bail!("missing original receipt")
            } else {
                read(b)
            }
        })
        .is_err()
    );
    assert!(
        prove(&s, now, |b| {
            let mut v = read(b)?;
            if b.path.to_string_lossy().contains("T232809Z") {
                for r in v["diagnostic_replays"].as_array_mut().unwrap() {
                    if r["producer_unit"] == terminal::UNIT {
                        r["error"] = json!("unrelated failure");
                    }
                }
            }
            Ok(v)
        })
        .is_err()
    );
}

#[test]
fn original_completed_predecessor_and_current_full_census_bridge_one_failed_historical_end() {
    let previous: Value = serde_json::from_str(include_str!(
        "historical_census_gap_fixtures/previous0328.json"
    ))
    .unwrap();
    let historical: Value = serde_json::from_str(include_str!(
        "historical_census_gap_fixtures/sample0358.json"
    ))
    .unwrap();
    let current: Value = serde_json::from_str(include_str!(
        "historical_census_gap_fixtures/sample0428.json"
    ))
    .unwrap();
    let scope = selected(&previous);
    let now = utc_seconds("2026-11-07T04:29:00Z").unwrap();
    let read_fixture = |b: &BoundFile| -> Result<Value> {
        if *b == scope.current {
            return Ok(current.clone());
        }
        ensure!(
            b.path.to_string_lossy().contains("T035809Z"),
            "undeclared historical fixture"
        );
        Ok(historical.clone())
    };
    let proof = prove(&scope, now, read_fixture).unwrap();
    assert_eq!(proof.intermediates().len(), 1);
    assert_eq!(proof.samples[1].1, historical);
    let mut bad_current = current.clone();
    bad_current["host_resident_memory"]["before"] =
        historical["host_resident_memory"]["before"].clone();
    assert!(
        prove(&scope, now, |b| {
            if *b == scope.current {
                Ok(bad_current.clone())
            } else {
                Ok(historical.clone())
            }
        })
        .is_err()
    );
    let mut skipped = current.clone();
    skipped["cadence"]["previous_sample"] = previous["observer_receipt"].clone();
    // A false direct 1800s link across the actual hour remains rejected.
    skipped["cadence"]["previous_sample_sha256"] = previous["observer_sha256"].clone();
    assert!(prove(&scope, now, |_| Ok(skipped.clone())).is_err());
}

#[test]
fn expanded_chain_cannot_reverse_terminal_phase_or_revive_original_parent() {
    let scope = selected(&accepted_previous());
    let mut early_current = sample("2328");
    // TEST ONLY: ask a verified parent phase to link backwards to the later,
    // genuinely completed phase. The phase gate must reject before time checks.
    early_current["cadence"]["previous_sample"] = sample("0028")["cadence"]["previous_sample"].clone();
    early_current["cadence"]["previous_sample_sha256"] = sample("0028")["cadence"]["previous_sample_sha256"].clone();
    let error = prove(&scope, utc_seconds("2026-11-05T23:29:00Z").unwrap(), |bound| {
        if *bound == scope.current { Ok(early_current.clone()) } else { Ok(sample("2358")) }
    }).err().expect("phase reversal must fail");
    assert!(error.to_string().contains("phase regressed or revived original parent"), "{error:#}");
}
