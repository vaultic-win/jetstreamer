use super::*;
fn plan() -> Plan {
    let mut p = crate::tests::plan();
    p.epoch = 170;
    p.attempt = "local3retry3".into();
    p.producer_unit = "horizon-qualify-170-replacement-local3retry3-20261110-v1.service".into();
    p.current_allocation = Some(current_allocation::Request {
        schema: terminal169::SCHEMA.into(),
    });
    p.retry3 = Some(retry3::Request {
        stopped_event: p.review.clone(),
        concurrent_working_set: p.review.clone(),
    });
    let mut resident = terminal169::tests::request();
    resident.terminal167 = Some(terminal167::exact());
    resident
        .owners
        .retain(|o| serde_json::to_value(o).unwrap()["epoch"] == 166);
    p.resident_memory = Some(resident);
    let mut guard = prelaunch_data::tests::request();
    guard.runtime.path = completed167_native_guard::RUNTIME.into();
    guard.runtime.sha256 = completed167_native_guard::IMAGE_SHA.into();
    guard.qualification =
        serde_json::from_value(completed167_native_guard::qualification_binding()).unwrap();
    guard.runtime_seal = serde_json::from_value(completed167_native_guard::seal_binding()).unwrap();
    p.data_fulfillment = Some(guard);
    p
}
fn declaration_fixture() -> Value {
    json!({"schema":WORKING_SET_SCHEMA,"immutable_raw_guard_floor_bytes":RAW_FLOOR,
        "complete_DATA_bytes":COMPLETE_DATA,"completed167_output_review":review_binding(),
        "completed167_retained_output_cap_bytes":completed_output_report::RETAINED_CAP})
}
fn report() -> Value {
    let native:Vec<_>=["check","execute"].into_iter().map(|phase| json!({
        "Id":format!("horizon-retry3-scratch167-retire-167-{phase}-20261115-v2.service"),
        "LoadState":"not-found","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","NRestarts":"0",
        "Job":"","Triggers":"","TriggeredBy":"","OnSuccess":"","OnFailure":"","FragmentPath":"","InvocationID":""})).collect();
    json!({"schema":"horizon-completed-scratch167-output-scope-validation-v1","review":review_binding(),
        "retained_physical_bytes":127434752u64,"retained_capacity_bytes":completed_output_report::RETAINED_CAP,
        "original_allowance_bytes":completed_output_report::OLD_CAP,
        "potential_allowance_reduction_bytes":completed_output_report::OLD_CAP-completed_output_report::RETAINED_CAP,
        "full_file_hashes_checked":true,"native":native,"existing_guards_changed":false,"booking_changed":false,
        "resource_credit_bytes":0,"replay_admission_authorized":false})
}
#[test]
fn new_totals_add_only_retained_cap_and_keep_original_holding_provenance() {
    assert_eq!(COMPLETE_DATA, 6_245_005_213_490);
    assert_eq!(RAW_FLOOR, 6_279_297_842_994);
    assert_eq!(terminal169::COMPLETE_DATA, 6_244_870_995_762);
    assert_eq!(terminal169::RAW_FLOOR, 6_279_163_625_266);
    assert_eq!(COMPLETE_DATA - terminal169::COMPLETE_DATA, 128 << 20);
    assert_eq!(RAW_FLOOR - terminal169::RAW_FLOOR, 128 << 20);
    assert_eq!(terminal169::EXTRA_DATA, 4 << 30);
}
#[test]
fn completed_route_and_guard_cannot_be_crossed_with_legacy() {
    let mut p = plan();
    current_allocation::shape(&p).unwrap();
    prelaunch_data::shape(p.data_fulfillment.as_ref().unwrap()).unwrap();
    for path in [prelaunch_data::RUNTIME, prelaunch_data::TERMINAL_RUNTIME] {
        p.data_fulfillment.as_mut().unwrap().runtime.path = path.into();
        assert!(current_allocation::shape(&p).is_err());
    }
    p.data_fulfillment.as_mut().unwrap().runtime.path = completed167_native_guard::RUNTIME.into();
    p.resident_memory.as_mut().unwrap().terminal167 = None;
    assert!(current_allocation::shape(&p).is_err());
    let mut p = plan();
    for epoch in [166, 167, 169, 171] {
        p.epoch = epoch;
        assert!(current_allocation::shape(&p).is_err());
    }
    p.epoch = 170;
    p.current_allocation = None;
    assert!(current_allocation::shape(&p).is_err());
}
#[test]
fn outer_guard_review_and_fleet_use_new_totals_only_for_completed_route() {
    let p = plan();
    assert_eq!(terminal169::data(&p), COMPLETE_DATA);
    assert_eq!(terminal169::floor(&p), RAW_FLOOR);
    assert_eq!(
        terminal169::memory_scope(p.resident_memory.as_ref().unwrap(), 170).unwrap(),
        COMPLETE_DATA
    );
    assert_eq!(
        guard_template(&p, profile(170).unwrap())["minimum_free_bytes"],
        RAW_FLOOR
    );
    let mut r = crate::tests::review(&p);
    r.epoch = p.epoch;
    r.current_budget = Some(current_budget::exact());
    r.data_fulfillment = p.data_fulfillment.clone();
    r.minimum_initial_available_data_bytes = RAW_FLOOR
        + r.fresh_subtree_overlap_booked_bytes
        + r.additional_growth_not_covered_by_existing_promise_bytes;
    review_shape(&p, &r, r.recorded_unix_seconds).unwrap();
    r.minimum_initial_available_data_bytes -= completed_output_report::RETAINED_CAP;
    assert!(review_shape(&p, &r, r.recorded_unix_seconds).is_err());
    let rows: Vec<_> = (101..=200)
        .map(|epoch| json!({"epoch":epoch,"state":"missing"}))
        .collect();
    let mut fleet = json!({"owner":"/root","primary_thread":THREAD,"epochs":rows,
        "complete_DATA_bytes":COMPLETE_DATA,"complete_projected_memory_bytes":current_budget::CURRENT_MEMORY,
        "actual_executing_replays":[],"actual_active_bootstraps":[]});
    let inventory = json!({"entries":rows,"anomalies":0,"archive_only":0});
    fleet_shape(&fleet, &inventory, &p).unwrap();
    fleet["complete_DATA_bytes"] = json!(terminal169::COMPLETE_DATA);
    assert!(fleet_shape(&fleet, &inventory, &p).is_err());
    let mut legacy = plan();
    legacy.resident_memory.as_mut().unwrap().terminal167 = None;
    assert_eq!(terminal169::data(&legacy), terminal169::COMPLETE_DATA);
    assert_eq!(terminal169::floor(&legacy), terminal169::RAW_FLOOR);
}
#[test]
fn retained_declaration_rejects_old_floor_or_missing_review_cap() {
    let p = plan();
    let v = declaration_fixture();
    declaration(&v, &p).unwrap();
    for (k, value) in [
        ("schema", json!("horizon-retry3-terminal169-working-set-v3")),
        (
            "immutable_raw_guard_floor_bytes",
            json!(terminal169::RAW_FLOOR),
        ),
        ("complete_DATA_bytes", json!(terminal169::COMPLETE_DATA)),
        ("completed167_output_review", Value::Null),
        (
            "completed167_retained_output_cap_bytes",
            json!(completed_output_report::OLD_CAP),
        ),
    ] {
        let mut bad = v.clone();
        bad[k] = value;
        assert!(declaration(&bad, &p).is_err(), "{k}");
    }
    let mut bad = v;
    bad["completed167_output_review"]["sha256"] = json!("f".repeat(64));
    assert!(declaration(&bad, &p).is_err());
}
#[test]
fn both_full_hash_reports_are_mandatory_and_cannot_claim_credit() {
    let p = plan();
    let good = Some(report());
    equal_reports(&p, &good, &good).unwrap();
    assert!(equal_reports(&p, &None, &good).is_err());
    assert!(equal_reports(&p, &good, &None).is_err());
    for (key, value) in [
        ("full_file_hashes_checked", json!(false)),
        ("resource_credit_bytes", json!(1)),
        (
            "retained_capacity_bytes",
            json!(completed_output_report::OLD_CAP),
        ),
        ("booking_changed", json!(true)),
    ] {
        let mut bad = report();
        bad[key] = value;
        assert!(equal_reports(&p, &Some(bad.clone()), &good).is_err());
        assert!(equal_reports(&p, &good, &Some(bad.clone())).is_err());
        assert!(equal_reports(&p, &Some(bad.clone()), &Some(bad)).is_err());
    }
    let mut bad = report();
    bad["native"][0]["Job"] = json!("start");
    assert!(equal_reports(&p, &good, &Some(bad)).is_err());
}
#[test]
fn legacy_route_cannot_carry_completed_scope_reports_or_declaration() {
    let p = crate::tests::plan();
    equal_reports(&p, &None, &None).unwrap();
    assert!(equal_reports(&p, &Some(report()), &Some(report())).is_err());
    assert!(declaration(&declaration_fixture(), &p).is_err());
    declaration(
        &json!({"schema":"horizon-retry3-terminal169-working-set-v3"}),
        &p,
    )
    .unwrap();
}

#[test]
fn zero166_shape_is_an_explicit_successor_of_the_one_owner_route() {
    let mut p = plan();
    current_allocation::shape(&p).unwrap();
    p.resident_memory.as_mut().unwrap().owners.clear();
    assert!(current_allocation::shape(&p).is_err());
    p.resident_memory.as_mut().unwrap().terminal166 = Some(terminal166::exact());
    current_allocation::shape(&p).unwrap();
    assert_eq!(working_set_schema(&p), ZERO166_WORKING_SET_SCHEMA);
    assert_eq!(terminal169::data(&p), COMPLETE_DATA);
    assert_eq!(terminal169::floor(&p), RAW_FLOOR);
    let mut v = declaration_fixture();
    assert!(declaration(&v, &p).is_err());
    v["schema"] = json!(ZERO166_WORKING_SET_SCHEMA);
    declaration(&v, &p).unwrap();
    p.resident_memory.as_mut().unwrap().terminal167 = None;
    assert!(current_allocation::shape(&p).is_err());
    p.resident_memory.as_mut().unwrap().terminal167 = Some(terminal167::exact());
    p.resident_memory.as_mut().unwrap().terminal169 = None;
    assert!(current_allocation::shape(&p).is_err());
}
#[test]
fn zero166_schema_is_not_accepted_by_one_owner_or_legacy_routes() {
    let p = plan();
    let mut v = declaration_fixture();
    v["schema"] = json!(ZERO166_WORKING_SET_SCHEMA);
    assert!(declaration(&v, &p).is_err());
    let p = crate::tests::plan();
    assert!(declaration(&json!({"schema":ZERO166_WORKING_SET_SCHEMA}), &p).is_err());
}
