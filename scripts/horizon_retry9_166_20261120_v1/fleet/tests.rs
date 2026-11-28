use super::*;

fn plan() -> Plan {
    serde_json::from_str(include_str!("PLAN-0215.SOURCE_TEMPLATE.json")).unwrap()
}

#[test]
fn actual_0215_zero_fleet_retains_all_bookings_and_nineteen_statuses() {
    let p = plan();
    let old = read_bound(&p.previous_fleet).unwrap();
    let fleet = reconcile(&p, 1_795_140_989).unwrap();
    assert_eq!(fleet["sampled_at_utc"], "2026-11-20T02:15:00Z");
    assert_eq!(fleet["observer"]["sha256"], OBS0215);
    assert_eq!(fleet["actual_executing_replays"], json!([]));
    assert_eq!(fleet["actual_active_bootstraps"], json!([]));
    assert_eq!(
        fleet["terminal_producers"].as_array().unwrap().len(),
        old["terminal_producers"].as_array().unwrap().len() + 2
    );
    for key in [
        "continuing_audit_obligation",
        "complete_DATA_authority",
        "complete_DATA_bytes",
        "complete_projected_memory_bytes",
        "additional_retained_build_allocation",
        "retained_retry6_166_DATA_bytes",
        "authenticated_inventory",
    ] {
        assert_eq!(fleet[key], old[key], "{key}");
    }
    let auxiliary = &fleet["retry9_auxiliary_commitments"];
    assert_eq!(auxiliary["build_fixed_image_bytes"], 4u64 << 30);
    assert_eq!(auxiliary["build_memory_bytes"], 2u64 << 30);
    assert_eq!(auxiliary["build_cpu_quota_micros"], 1_000_000);
    assert_eq!(
        auxiliary["holding_restore_overlap_bytes"],
        69_333_973_781u64
    );
    assert_eq!(auxiliary["holding_memory_bytes"], 2u64 << 30);
    assert_eq!(auxiliary["holding_cpu_quota_micros"], 2_000_000);
    assert_eq!(
        fleet["actual_active_holding_transfers"][0]["unit"],
        "horizon-closed166-retry7-park-20261120-v1.service"
    );
    let audit = load(&fleet["authenticated_status_audit"]).unwrap();
    for epoch in STATUS_EPOCHS {
        let row = one(&fleet["epochs"], "epoch", &json!(epoch)).unwrap();
        assert_eq!(
            row["current_authenticated_status_receipt"],
            audit["receipts"][epoch.to_string()]
        );
    }
    for (epoch, _, iid) in STOPPED {
        let row = one(&fleet["epochs"], "epoch", &json!(epoch)).unwrap();
        assert_eq!(row["state"], "repair");
        assert_eq!(row["terminal_transition"]["producer_invocation_id"], iid);
    }
}

#[test]
fn zero_observer_rejects_new_ordinary_owner_or_changed_diagnostic_generation() {
    let p = plan();
    let overlay = read_bound(&p.recovery_events[1]).unwrap();
    let mut sample = load(&overlay["observer"]).unwrap();
    zero_sample(&sample).unwrap();
    sample["replays"] = json!([{"range":"166"}]);
    assert!(zero_sample(&sample).is_err());
    sample["replays"] = json!([]);
    for row in sample["diagnostic_replays"].as_array_mut().unwrap() {
        if row["range"] == "167" {
            row["expected_producer_invocation_id"] = json!("stale");
        }
    }
    assert!(zero_sample(&sample).is_err());
}

#[test]
fn archived_stop_allows_unloaded_owner_and_rejects_pid_or_foreign_generation() {
    let native = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nInvocationID=\nMainPID=0\nNRestarts=0\nJob=\n";
    terminal(native, STOPPED[0].2).unwrap();
    assert!(terminal(&native.replace("MainPID=0", "MainPID=42"), STOPPED[0].2).is_err());
    assert!(
        terminal(
            &native.replace("InvocationID=", "InvocationID=other"),
            STOPPED[0].2
        )
        .is_err()
    );
    assert!(terminal(&format!("{native}Job=\n"), STOPPED[0].2).is_err());
}

#[test]
fn later_sample_requires_the_exact_previous_observation_and_later_clock() {
    let p = plan();
    let previous_event = read_bound(&p.recovery_events[0]).unwrap();
    let next_event = read_bound(&p.recovery_events[1]).unwrap();
    let previous = binding(&previous_event["observer"]).unwrap();
    let before = read_bound(&previous).unwrap();
    let current = load(&next_event["observer"]).unwrap();
    linked(&previous, &before, &current).unwrap();
    let mut later = current.clone();
    later["cadence"]["previous_sample_sha256"] = json!(PREVIOUS_SHA);
    assert!(linked(&previous, &before, &later).is_err());
    later = current;
    later["recorded_at_utc"] = before["recorded_at_utc"].clone();
    assert!(linked(&previous, &before, &later).is_err());
}
