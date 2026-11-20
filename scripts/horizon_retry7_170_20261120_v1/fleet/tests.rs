use super::*;

fn actual() -> (Plan, Evidence) {
    let plan: Plan = serde_json::from_str(include_str!("PLAN-0115.SOURCE_TEMPLATE.json")).unwrap();
    // Root-run fixture tests authenticate retained JSON files only; no native queries.
    let evidence = read_evidence(&plan).unwrap();
    (plan, evidence)
}

#[test]
fn genuine_three_to_two_transition_preserves_every_unedited_field() {
    let (plan, mut evidence) = actual();
    evidence.previous["future_additional_commitment"] =
        json!({"bytes":12345,"release_allowed":false});
    let output = reconcile(&plan, &evidence, 1795137400).unwrap();
    let changed = [
        "terminal_producers",
        "epoch170_join_identity",
        "next_lane_recovery",
        "previous_Root_operational_review",
        "observer",
        "authenticated_status_audit",
        "sole_next_observer",
        "sampled_at_utc",
        "recorded_unix_seconds",
        "actual_executing_replays",
        "actual_active_bootstraps",
        "active_producer_count",
        "live_replay_count",
        "useful_replay_count",
        "bootstrap_count",
        "guarded_bootstrap_owner_count",
        "same_sample_conservative_free_DATA_bytes",
        "complete_cycle_conservative_available_DATA_bytes",
        "epochs",
        "new_resource_observations",
        "fresh_campaign_unit_census_claimed",
        "replay_launch_authorized",
        "producer_mutations",
        "remote_mutations",
        "resource_credit_bytes",
        "review_is_not_a_native_Frame_or_admission_receipt",
        "cycle_reconciliation_scope",
    ];
    for (key, value) in evidence.previous.as_object().unwrap() {
        if !changed.contains(&key.as_str()) {
            assert_eq!(&output[key], value, "lost {key}");
        }
    }
    assert_eq!(output["complete_DATA_bytes"], 6_794_761_027_378u64);
    assert_eq!(
        output["complete_projected_memory_bytes"],
        761_131_708_416u64
    );
    assert_eq!(
        output["additional_retained_build_allocation"],
        evidence.recovery["additional_retained_build_allocation"]
    );
    assert_eq!(
        output["retained_terminal_recovery_commitments"],
        evidence.recovery
    );
    assert_eq!(
        output["terminal_producers"].as_array().unwrap().len(),
        evidence.previous["terminal_producers"]
            .as_array()
            .unwrap()
            .len()
            + 1
    );
    assert_eq!(
        output["terminal170_transition"]["historical_live_owner"],
        *one(
            &evidence.previous["actual_executing_replays"],
            "epoch",
            &json!(170)
        )
        .unwrap()
    );
    let row = one(&output["epochs"], "epoch", &json!(170)).unwrap();
    assert_eq!(row["current_replay"], Value::Null);
    assert_eq!(row["no_live_producer_claimed"], true);
    assert_eq!(row["state"], "repair");
    assert_eq!(row["current_repair_owner"], "/root");
    assert_eq!(
        row["current_status"],
        evidence.receipts[&170]["after_status"]
    );
    assert_eq!(output["live_replay_count"], 2);
    assert_eq!(output["resource_credit_bytes"], 0);
    assert_eq!(output["new_resource_observations"], false);
    assert_eq!(output["fresh_campaign_unit_census_claimed"], false);
}

#[test]
fn fabricated_two_owner_predecessor_and_missing_stop_are_rejected() {
    let (plan, mut e) = actual();
    let original = e.previous.clone();
    e.previous["live_replay_count"] = json!(2);
    assert!(reconcile(&plan, &e, 0).is_err());
    e.previous = original;
    let original = e.stop.clone();
    for pointer in [
        "/producer_invocation_id",
        "/plan_sha256",
        "/terminal/invocation_id",
        "/terminal/pid",
        "/terminal/active",
        "/terminal/result",
        "/scratch_deleted",
    ] {
        e.stop = original.clone();
        *e.stop.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(reconcile(&plan, &e, 0).is_err(), "{pointer}");
    }
    e.stop = original;
    e.intent["sample"]["producer"]["invocation_id"] = json!("a".repeat(32));
    assert!(reconcile(&plan, &e, 0).is_err());
}

#[test]
fn advancing_peer_requires_both_sides_and_real_progress() {
    let (plan, mut e) = actual();
    let original = e.sample.clone();
    for pointer in [
        "/replays/0/producer_before/invocation_id",
        "/replays/1/producer_after/main_pid",
        "/replays/0/controller_after/restarts",
        "/replays/1/useful_work/slot_delta",
        "/replays/0/useful_work/append_log_evidence/stdout_append_binding_verified",
    ] {
        e.sample = original.clone();
        *e.sample.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(reconcile(&plan, &e, 0).is_err(), "{pointer}");
    }
    e.sample = original.clone();
    e.sample["replays"][1] = e.sample["replays"][0].clone();
    assert!(reconcile(&plan, &e, 0).is_err());
    e.sample = original;
    e.sample["replays"][0]["useful_work"]["last"]["slot"] = json!(71912528);
    assert!(reconcile(&plan, &e, 0).is_err());
}

#[test]
fn broken_cadence_and_status_identity_fail_closed() {
    let (plan, mut e) = actual();
    let old = e.sample["cadence"]["previous_sample_sha256"].clone();
    e.sample["cadence"]["previous_sample_sha256"] = json!("f".repeat(64));
    assert!(reconcile(&plan, &e, 0).is_err());
    e.sample["cadence"]["previous_sample_sha256"] = old;
    let old = e.status.clone();
    e.status["authenticated_status_count"] = json!(18);
    assert!(reconcile(&plan, &e, 0).is_err());
    e.status = old;
    let old = e.receipts[&170].clone();
    e.receipts.get_mut(&170).unwrap()["terminal170_native"]["MainPID"] = json!("2295526");
    assert!(reconcile(&plan, &e, 0).is_err());
    e.receipts.insert(170, old);
    e.next["replays"][1]["expected_producer_invocation_id"] = json!(STOP_IID);
    assert!(reconcile(&plan, &e, 0).is_err());
}

#[test]
fn reduced_commitments_and_unrelated_terminal_generation_are_rejected() {
    let (plan, mut e) = actual();
    let old = e.previous.clone();
    for key in [
        "complete_DATA_bytes",
        "complete_projected_memory_bytes",
        "retained_retry6_166_DATA_bytes",
    ] {
        e.previous = old.clone();
        e.previous[key] = json!(0);
        assert!(reconcile(&plan, &e, 0).is_err());
    }
    e.previous = old;
    e.recovery["all_reservation_ending_bytes"] = json!(1);
    assert!(reconcile(&plan, &e, 0).is_err());
    e.recovery["all_reservation_ending_bytes"] = json!(0);
    e.previous["actual_executing_replays"][2]["unit"]["InvocationID"] = json!("a".repeat(32));
    assert!(reconcile(&plan, &e, 0).is_err());
}
