use super::*;
fn request() -> Value {
    let proofs=(166..=172).map(|e|json!({"epoch":e,"proof":{"path":format!("/sealed/current-{e}.json"),"sha256":"a".repeat(64)}})).collect::<Vec<_>>();
    json!({"owner_basis":"exact-current-seven-local2-20261110-v1","resource_promise_ending_authorized":false,
        "replay_launch_authorized":false,"native_Frame_or_full_Reader_authority":false,"future_host_or_shared_role_bound_claimed":false,
        "current_guard_proofs":proofs})
}
fn fixture() -> Value {
    let p = pins().unwrap();
    let rows=owners(&p).unwrap().iter().map(|o|{
        let unit=o["whole_service_profile"].clone();
        json!({"epoch":o["epoch"],"phase":"replay","useful_transaction_replay":true,"unit":unit,"native_producer_profile":unit,
            "source_start_unix_seconds":o["start"],"source_start_native":o["start_native"],"run_directory":o["run_directory"],
            "admission":o["admission"],"guard_protection":o["guard_protection"],"DATA_guard_handoff":o["handoff"],
            "declaration":{"unit":o["unit"],"invocation_id":o["iid"],"main_pid":o["pid"].as_u64().unwrap().to_string(),
                "original_start_unix_seconds":o["start"],"original_start_native":o["start_native"],"admission":o["admission"],
                "guard_protection":o["guard_protection"],"DATA_guard_handoff":o["handoff"]}})
    }).collect::<Vec<_>>();
    let epochs=(101..=200).map(|e|{
        let current=rows.iter().find(|r|r["epoch"]==e);
        json!({"epoch":e,"state":if current.is_some(){"live-replay"}else{"remote-ready"},"current_live_producer":current.map(|r|r["unit"].clone())})
    }).collect::<Vec<_>>();
    json!({"actual_executing_replays":rows,"terminal_producer_count":7,"authenticated_status_count":19,
        "terminal_producer_event":p["terminal_producer_event"],"terminal_producers":p["terminal_producers"],"actual_active_bootstraps":[],"epochs":epochs,
        "stable_non_replay_owners":p["stable_non_replay_owners"]})
}
fn native_fixture() -> Value {
    let p = pins().unwrap();
    let mut actual = p["owners"][0]["whole_service_profile"].clone();
    actual["MemoryAccounting"] = json!("yes");
    actual["Delegate"] = json!("no");
    actual
}
fn accepted() -> data_guard_reader::Accepted {
    data_guard_reader::Accepted {
        protection: json!({"guard_unit":"guard.service","timer_unit":"guard.timer","timer_invocation_id":"a".repeat(32),"plan":{"path":"/sealed/guard-plan.json","sha256":"b".repeat(64)}}),
        plan: Value::Null,
        runtime: json!({"path":"/sealed/guard","sha256":"c".repeat(64)}),
        registration: Value::Null,
        native_witness: Value::Null,
        handoff: Value::Null,
    }
}
fn guard_service(a: &data_guard_reader::Accepted) -> Value {
    let command = format!(
        "{{ path=/sealed/guard ; argv[]=/sealed/guard /sealed/guard-plan.json --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ; start_time=[now] ; stop_time=[now] ; pid=0 ; code=exited ; status=0/0 }}",
        "b".repeat(64),
        "c".repeat(64)
    );
    json!({"Id":a.protection["guard_unit"],"LoadState":"loaded","Restart":"no","NRestarts":"0","MemoryMax":"1073741824",
        "MemorySwapMax":"0","Result":"success","ExecMainStatus":"0","ActiveState":"inactive","SubState":"dead",
        "MainPID":"0","ControlPID":"0","Job":"","ExecStart":command})
}
#[test]
fn exact_current_seven_local2_fleet_is_accepted_with_all_original_births() {
    let f = fixture();
    let report = validate_fleet(&f).unwrap();
    assert_eq!(
        report["immutable_owner_profiles"].as_array().unwrap().len(),
        7
    );
    assert_eq!(report["resource_credit_bytes"], 0);
    assert_eq!(
        report["all_whole_service_and_shared_role_future_gates_still_required"],
        true
    );
}
#[test]
fn original_standard_local1_or_reused_iid_cannot_supply_current_anon() {
    for (key, value) in [
        (
            "Id",
            json!("horizon-qualify-166-standard-20261109-v1.service"),
        ),
        (
            "Id",
            json!("horizon-replacement-166-local1-20261110-v1.service"),
        ),
        ("InvocationID", json!("0".repeat(32))),
        ("MainPID", json!("1041050")),
        ("NRestarts", json!("1")),
        ("ControlPID", json!("42")),
        ("Job", json!("13")),
    ] {
        let mut f = fixture();
        f["actual_executing_replays"][0]["unit"][key] = value;
        assert!(validate_fleet(&f).is_err(), "{key}");
    }
}
#[test]
fn exact_owner_set_cannot_duplicate_or_omit_a_lane() {
    let mut f = fixture();
    let repeated = f["actual_executing_replays"][0].clone();
    f["actual_executing_replays"][1] = repeated;
    assert!(validate_fleet(&f).is_err());
    let mut f = fixture();
    f["actual_executing_replays"].as_array_mut().unwrap().pop();
    assert!(validate_fleet(&f).is_err());
}
#[test]
fn original_birth_clock_run_and_evidence_cannot_reset() {
    for key in [
        "source_start_unix_seconds",
        "source_start_native",
        "run_directory",
        "admission",
        "guard_protection",
        "DATA_guard_handoff",
    ] {
        let mut f = fixture();
        f["actual_executing_replays"][0][key] = Value::Null;
        assert!(validate_fleet(&f).is_err(), "{key}");
    }
    let mut f = fixture();
    f["actual_executing_replays"][0]["declaration"]["original_start_unix_seconds"] =
        json!(1794359999u64);
    assert!(validate_fleet(&f).is_err());
}
#[test]
fn changed_whole_service_caps_or_shared_background_owner_are_rejected() {
    for (key, value) in [
        ("MemoryMax", json!("71940702208")),
        ("MemorySwapMax", json!("1")),
        ("Restart", json!("on-failure")),
        ("User", json!("root")),
        ("ControlGroup", json!("/system.slice")),
        ("TasksMax", json!("2048")),
        ("ExecStart", json!("other")),
    ] {
        let mut f = fixture();
        f["actual_executing_replays"][0]["native_producer_profile"][key] = value;
        assert!(validate_fleet(&f).is_err(), "{key}");
    }
    let mut f = fixture();
    f["stable_non_replay_owners"] = json!({});
    assert!(validate_fleet(&f).is_err());
}
#[test]
fn current_gauge_requires_hierarchical_own_service_with_no_delegation_or_swap() {
    whole_service(&native_fixture()).unwrap();
    for (key, value) in [
        ("MemoryAccounting", json!("no")),
        ("Delegate", json!("yes")),
        ("MemorySwapMax", json!("infinity")),
        ("MainPID", json!("2")),
    ] {
        let mut n = native_fixture();
        n[key] = value;
        assert!(whole_service(&n).is_err(), "{key}");
    }
}
#[test]
fn fresh_guard_request_requires_every_owner_and_explicit_denial_of_authority() {
    let good = request();
    validate_request(&good).unwrap();
    for key in [
        "owner_basis",
        "current_guard_proofs",
        "resource_promise_ending_authorized",
        "replay_launch_authorized",
        "native_Frame_or_full_Reader_authority",
        "future_host_or_shared_role_bound_claimed",
    ] {
        let mut changed = good.clone();
        changed.as_object_mut().unwrap().remove(key);
        assert!(validate_request(&changed).is_err(), "{key}");
    }
    let mut changed = good.clone();
    changed["current_guard_proofs"][0]["proof"]["sha256"] = json!("0".repeat(64));
    assert!(validate_request(&changed).is_err());
    let mut changed = good;
    changed["current_guard_proofs"][1]["epoch"] = json!(166);
    assert!(validate_request(&changed).is_err());
}
#[test]
fn armed_successor_timer_requires_original_iid_trigger_and_no_pending_job() {
    let a = accepted();
    let good = json!({"Id":"guard.timer","InvocationID":"a".repeat(32),"LoadState":"loaded","ActiveState":"active","SubState":"waiting","Triggers":"guard.service","Job":""});
    timer(&good, &a.protection).unwrap();
    for (key, value) in [
        ("InvocationID", json!("b".repeat(32))),
        ("ActiveState", json!("inactive")),
        ("Triggers", json!("other.service")),
        ("Job", json!("7")),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(timer(&bad, &a.protection).is_err(), "{key}");
    }
}
#[test]
fn successor_service_retains_exact_image_argv_memory_and_success_state() {
    let a = accepted();
    let good = guard_service(&a);
    service(&good, &a.protection, &a).unwrap();
    for (key, value) in [
        ("MemoryMax", json!("2147483648")),
        ("MemorySwapMax", json!("1")),
        ("Restart", json!("always")),
        ("Result", json!("signal")),
        ("ActiveState", json!("failed")),
        ("ExecStart", json!("unknown")),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(service(&bad, &a.protection, &a).is_err(), "{key}");
    }
    let mut running = good;
    running["ActiveState"] = json!("activating");
    running["SubState"] = json!("start");
    running["MainPID"] = json!("42");
    service(&running, &a.protection, &a).unwrap();
}
#[test]
fn changed_native_guard_argv_cannot_reuse_a_matching_image_path() {
    let a = accepted();
    let mut bad = guard_service(&a);
    let command = s(&bad, "ExecStart")
        .unwrap()
        .replace("--plan-sha256", "--other-plan");
    bad["ExecStart"] = json!(command);
    assert!(service(&bad, &a.protection, &a).is_err());
}
#[test]
fn original_admission_never_creates_new_credit_or_reapplies_an_ending() {
    let p = pins().unwrap();
    let exact = &p["owners"][0];
    let mut a = json!({"schema":"horizon-standard-replacement-admission-v1","owner":"/root","primary_thread":PRIMARY,
        "epoch":exact["epoch"],"producer_unit":exact["unit"],"producer_invocation_id":exact["iid"],"producer_pid":exact["pid"],
        "fresh_admission_passed":true,"all_existing_growth_and_floor_protected":true,"all_prior_promises_retained":true,
        "old_partial_and_inputs_preserved":true,"candidate_hard_memory_bytes":CAP,"guard_minimum_free_bytes":data_guard_reader::FLOOR,
        "resource_credit_bytes":0,"memory_or_DATA_promise_ending_bytes":0,"remote_mutations":false,"r2_mutations":false});
    admission(&a, exact).unwrap();
    a["memory_or_DATA_promise_ending_bytes"] = json!(1);
    assert!(admission(&a, exact).is_err());
}
#[test]
fn shared_reader_errors_are_preserved_without_widening_its_error_type() {
    assert!(
        shared::<()>(Err("rejected native handoff".into()))
            .unwrap_err()
            .to_string()
            .contains("rejected native handoff")
    );
}

#[test]
fn complete_guard_protection_expiry_uses_oldest_native_proof_not_planning_allowance() {
    let rows = (0..7)
        .map(|i| json!({"sample_recorded_unix_seconds":100+i}))
        .collect::<Vec<_>>();
    assert_eq!(protection_expiry(&json!(rows)).unwrap(), 145);
    assert!(protection_expiry(&json!([])).is_err());
    let rows = (0..7)
        .map(|_| json!({"sample_recorded_unix_seconds":u64::MAX}))
        .collect::<Vec<_>>();
    assert!(protection_expiry(&json!(rows)).is_err());
}

#[test]
fn terminal_original_history_is_retained_without_releasing_its_promises() {
    let mut f = fixture();
    f["terminal_producers"][0]["resource_release_bytes"] = json!(1);
    assert!(validate_fleet(&f).is_err());
    let mut f = fixture();
    f["terminal_producers"].as_array_mut().unwrap().pop();
    assert!(validate_fleet(&f).is_err());
}
