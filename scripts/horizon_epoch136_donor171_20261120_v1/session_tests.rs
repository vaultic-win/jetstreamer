use super::*;

fn bound(name: &str) -> Value {
    binding(&Path::new(BASE).join(name), &"a".repeat(64))
}
fn fixture() -> (Value, Value, Value, Value) {
    let iid = "1".repeat(32);
    let plan = json!({"helper":bound("tools/epoch136-actual-payload"),
        "node":bound("tools/jetstreamer-node"),"worker":bound("tools/jetstreamer-historical-worker-v1-4-25")});
    let admission = json!({"plan":bound("plan.json"),"recorded_unix_seconds":900,
        "launch_expires_unix_seconds":1800,"protected_existing_free_bytes":100});
    let ready = json!({"schema":"horizon-epoch136-actual-ready-v1","unit":UNIT,"invocation_id":iid,
        "helper":plan["helper"],"node":plan["node"],"worker":plan["worker"],
        "pid":21,"start_ticks":30,"guard_plan_sha256":"a".repeat(64),
        "recorded_unix_seconds":1000,"node_spawned":false,"worker_spawned":false,"publication_authorized":false,
        "guard_prefire":{"sample":{"schema":"jetstreamer-horizon-standalone-guard-sample-v1",
            "producer_invocation_id":iid,"producer":{"invocation_id":iid,"pid":21,"restarts":0,
                "active":"active","sub":"running","cgroup":format!("/system.slice/{UNIT}")},
            "guard_sha256":scope::GUARD_SHA,"plan_sha256":"a".repeat(64),"producer_stop_enabled":true,
            "minimum_free_bytes":100,"maximum_root_physical_bytes":scope::ROOT_STOP,
            "maximum_worker_vmas":scope::VMA,"trip_reason":null,"worker_observation_error":null,
            "root_physical_observation_error":null,"root_physical_observation":{"exceeds_budget":false,"conservative_physical_bytes":42},
            "available_bytes":200,"recorded_unix_seconds":999,"bounded_measurement":false,
            "bounded_canary":null,"native_main":null,"workers":[]}}});
    let launch = json!({"schema":"jetstreamer-epoch136-actual-20261120-launch-v1","unit":UNIT,
        "invocation_id":iid,"pid":21,"start_ticks":30,"plan":admission["plan"],"publication_authorized":false});
    (plan, admission, ready, launch)
}
#[test]
fn denial_is_required_but_never_becomes_a_positive_release() {
    let (plan, _, _, _) = fixture();
    let pass = json!({"schema":"horizon-epoch136-native-preinit-result-v1",
        "genuine_cli_snapshot_binding_and_hello_reached":true,"denial_returned_nonzero":true,
        "worker_reaped":true,"initialize_release_sent":false,"snapshot_restored":false,
        "actual_worker_guard_qualified":false,"slots_replayed":0,"publication_authorized":false,
        "node_sha256":plan["node"]["sha256"],"worker_sha256":plan["worker"]["sha256"]});
    contract::denial(&plan, &pass).unwrap();
    for key in [
        "initialize_release_sent",
        "snapshot_restored",
        "actual_worker_guard_qualified",
        "publication_authorized",
    ] {
        let mut altered = pass.clone();
        altered[key] = json!(true);
        assert!(contract::denial(&plan, &altered).is_err());
    }
    let mut wrong = plan;
    wrong["node"]["sha256"] = json!("b".repeat(64));
    assert!(contract::denial(&wrong, &pass).is_err());
}
#[test]
fn ready_requires_pre_spawn_owner_and_original_launch() {
    let (plan, admission, ready, launch) = fixture();
    contract::ready(&plan, &admission, &ready, &launch, 1000).unwrap();
    for key in ["node_spawned", "worker_spawned", "publication_authorized"] {
        let mut changed = ready.clone();
        changed[key] = json!(true);
        assert!(contract::ready(&plan, &admission, &changed, &launch, 1000).is_err());
    }
    for key in ["pid", "start_ticks"] {
        let mut changed = launch.clone();
        changed[key] = json!(99);
        assert!(contract::ready(&plan, &admission, &ready, &changed, 1000).is_err());
    }
}
#[test]
fn prefire_rejects_worker_missing_scan_trips_and_future_samples() {
    let (_, admission, ready, _) = fixture();
    let sample = &ready["guard_prefire"]["sample"];
    contract::prefire(sample, &ready, &admission, 1000).unwrap();
    for (key, value) in [
        ("workers", json!([[22, 100]])),
        ("workers", Value::Null),
        ("recorded_unix_seconds", json!(1001)),
        ("recorded_unix_seconds", json!(879)),
        ("root_physical_observation", Value::Null),
        ("root_physical_observation_error", json!("denied")),
        ("trip_reason", json!("disk")),
        ("available_bytes", json!(99)),
        ("producer_stop_enabled", json!(false)),
    ] {
        let mut changed = sample.clone();
        changed[key] = value;
        assert!(
            contract::prefire(&changed, &ready, &admission, 1000).is_err(),
            "accepted {key}"
        );
    }
}
fn registered() -> (Value, Value, Value, Value, Value) {
    let (plan, _, ready, _) = fixture();
    let owner = contract::pending_owner(
        &plan,
        &ready,
        &bound("reproduction/receipts/ready.json"),
        &bound("reproduction/receipts/parent-status-request.json"),
    );
    let reg = json!({"schema":"horizon-epoch136-current-owner-registration-v1","epoch":136,"unit":UNIT,
        "invocation_id":ready["invocation_id"],"helper":plan["helper"],"request":owner["parent_request"],
        "repair_open":true,"ordinary_replay_claim":false,"authenticated_readback":true,
        "recorded_unix_seconds":1000,"status_receipt":bound("status-receipt.json"),"fleet_receipt":bound("fleet.json")});
    let status = json!({"epoch":136,"key":"epoch-136.epoch-status.json","authenticated_readback":true,
        "producer_invocation_id":ready["invocation_id"],"current_repair_owner":"/root",
        "epoch136_pending_owner":owner,"epoch136_registration_unix_seconds":1000,
        "after_status":{"epoch":136,"phase":"verification"},"after_etag":"etag","after_sha256":"a".repeat(64)});
    let initial = json!({"complete_DATA_bytes":1,"complete_projected_memory_bytes":2,
        "all_reservation_ending_bytes":0,"actual_executing_replays":[{"epoch":166}],
        "actual_active_bootstraps":[],"actual_active_private_diagnostics":[{"epoch":168}],
        "terminal172_closure":bound("closure172.json")});
    let mut fleet = initial.clone();
    fleet["epoch136_pending_owner"] = owner.clone();
    fleet["epoch136_registration_unix_seconds"] = json!(1000);
    fleet["all_active_status_reports_authenticated_readback"] = json!(true);
    fleet["effective_status_receipts"] = json!({"136":reg["status_receipt"]});
    (reg, owner, status, fleet, initial)
}
#[test]
fn status_requires_authenticated_exact_pending_owner_and_current_fleet() {
    let (reg, owner, status, fleet, initial) = registered();
    contract::registration(&reg, &owner, &status, &fleet, &initial, 1000).unwrap();
    for (key, value) in [
        ("authenticated_readback", json!(false)),
        ("producer_invocation_id", json!("f".repeat(32))),
        ("epoch136_pending_owner", Value::Null),
        ("epoch", json!(169)),
        ("after_sha256", json!("bad")),
    ] {
        let mut changed = status.clone();
        changed[key] = value;
        assert!(contract::registration(&reg, &owner, &changed, &fleet, &initial, 1000).is_err());
    }
    let mut changed = fleet.clone();
    changed["complete_projected_memory_bytes"] = json!(1);
    assert!(contract::registration(&reg, &owner, &status, &changed, &initial, 1000).is_err());
    let mut changed = fleet;
    changed["effective_status_receipts"]["136"] = bound("another.json");
    assert!(contract::registration(&reg, &owner, &status, &changed, &initial, 1000).is_err());
}
#[test]
fn status_cannot_be_stale_crossed_or_promoted_to_replay() {
    let (reg, owner, status, fleet, initial) = registered();
    assert!(contract::registration(&reg, &owner, &status, &fleet, &initial, 1121).is_err());
    assert!(contract::registration(&reg, &owner, &status, &fleet, &initial, 999).is_err());
    for (key, value) in [
        ("ordinary_replay_claim", json!(true)),
        ("request", bound("other.json")),
        ("repair_open", json!(false)),
        ("recorded_unix_seconds", json!(999)),
    ] {
        let mut changed = reg.clone();
        changed[key] = value;
        assert!(contract::registration(&changed, &owner, &status, &fleet, &initial, 1000).is_err());
    }
}
