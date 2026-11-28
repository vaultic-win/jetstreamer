use super::*;
pub(crate) fn request() -> resident_memory::Request {
    let owners:Vec<_>=[(166,"local3retry4","58778e77980e4a15828c3be837e447aa"),(167,"local3retry3","7ce90d0ec8114cf3a6be73eb9cf75ae8")].into_iter().map(|(e,a,i)|json!({"epoch":e,"unit":format!("horizon-qualify-{e}-replacement-{a}-20261110-v1.service"),"invocation_id":i,"main_pid":1,"main_start_ticks":1,"admission":{"path":"/fixture/admission","sha256":"a".repeat(64)},"guard_protection":{"path":"/fixture/protection","sha256":"b".repeat(64)}})).collect();
    serde_json::from_value(json!({"terminal169":exact(),"observer":{"path":"/fixture/observer","sha256":"c".repeat(64)},"owners":owners,"admission_only_capture":true,"host_kernel_same_resident_basis":true})).unwrap()
}
#[test]
fn genuine_terminal_pid1_requires_original_start_exit_and_failure() {
    let v: Value = serde_json::from_str(include_str!("dep_af8718a95a94_terminal169-169-PID1.json")).unwrap();
    journal(&v, 2_000_000_000).unwrap();
    for key in [
        "_PID",
        "_UID",
        "_EXE",
        "UNIT",
        "INVOCATION_ID",
        "_BOOT_ID",
        "_MACHINE_ID",
    ] {
        let mut bad = v.clone();
        bad[2][key] = json!("foreign");
        assert!(journal(&bad, 2_000_000_000).is_err(), "{key}");
    }
    for index in [1, 2, 3] {
        let mut bad = v.clone();
        bad.as_array_mut().unwrap().remove(index);
        assert!(journal(&bad, 2_000_000_000).is_err());
    }
    let mut bad = v.clone();
    bad[2]["EXIT_STATUS"] = json!("0");
    assert!(journal(&bad, 2_000_000_000).is_err());
    let mut bad = v.clone();
    bad[3]["UNIT_RESULT"] = json!("success");
    assert!(journal(&bad, 2_000_000_000).is_err());
    assert!(journal(&v, 1).is_err());
    let mut bad = v.clone();
    bad[2]["__MONOTONIC_TIMESTAMP"] = json!("1");
    assert!(journal(&bad, 2_000_000_000).is_err());
}
#[test]
fn collected_unit_cannot_supply_original_iid_or_hide_new_activity() {
    let mut v: Value = serde_json::from_str(include_str!("dep_c5c8237b4f6a_terminal169-169-NATIVE.json")).unwrap();
    v["LoadState"] = json!("not-found");
    native_closed(&v).unwrap();
    for (k, x) in [
        ("InvocationID", json!(IID)),
        ("MainPID", json!("1")),
        ("ControlPID", json!("1")),
        ("Job", json!("42 start")),
        ("ActiveState", json!("active")),
        ("LoadState", json!("loaded")),
    ] {
        let mut bad = v.clone();
        bad[k] = x;
        assert!(native_closed(&bad).is_err(), "{k}");
    }
    let mut loaded = v.clone();
    loaded["LoadState"] = json!("loaded");
    loaded["InvocationID"] = json!(IID);
    loaded["NRestarts"] = json!("0");
    loaded["ActiveState"] = json!("failed");
    loaded["SubState"] = json!("failed");
    loaded["Result"] = json!("exit-code");
    loaded["ExecMainStatus"] = json!("1");
    native_closed(&loaded).unwrap();
    loaded["InvocationID"] = json!("a".repeat(32));
    assert!(native_closed(&loaded).is_err());
}
#[test]
fn holding_booking_is_exact_additive_never_a_release() {
    let v: Value = serde_json::from_str(include_str!("dep_c21caee18c93_holding-DATA-booking.json")).unwrap();
    booking(&v).unwrap();
    assert_eq!(COMPLETE_DATA, current_budget::CURRENT_DATA + (4 << 30));
    assert_eq!(RAW_FLOOR, current_budget::CURRENT_FLOOR + (4 << 30));
    for k in [
        "additional_DATA_bytes",
        "complete_DATA_bytes",
        "minimum_free_bytes",
        "new_memory_promise_bytes",
        "resource_credit_bytes",
    ] {
        let mut bad = v.clone();
        bad[k] = json!(1);
        assert!(booking(&bad).is_err(), "{k}");
    }
}
#[test]
fn terminal_route_only_allows_exact_two_live_memory_owners() {
    let r = request();
    assert_eq!(memory_scope(&r, 170).unwrap(), COMPLETE_DATA);
    for candidate in [166, 167, 169, 171] {
        assert!(memory_scope(&r, candidate).is_err());
    }
    let original = serde_json::to_value(r).unwrap();
    for k in ["unit", "invocation_id", "epoch"] {
        let mut bad = original.clone();
        bad["owners"][0][k] = json!("foreign");
        if let Ok(r) = serde_json::from_value::<resident_memory::Request>(bad) {
            assert!(memory_scope(&r, 170).is_err());
        }
    }
    let mut bad = original.clone();
    bad["owners"].as_array_mut().unwrap().pop();
    assert!(memory_scope(&serde_json::from_value(bad).unwrap(), 170).is_err());
    let mut bad = original;
    bad["terminal169"]["additive_data_booking"]["sha256"] = json!("f".repeat(64));
    assert!(memory_scope(&serde_json::from_value(bad).unwrap(), 170).is_err());
}
#[test]
fn explicit_plan_opt_in_cannot_widen_legacy_routes() {
    let mut p = crate::tests::plan();
    p.resident_memory = Some(request());
    assert!(shape(&p).is_err());
    p.epoch = 170;
    p.attempt = "local3retry3".into();
    p.current_allocation = Some(current_allocation::Request {
        schema: SCHEMA.into(),
    });
    p.retry3 = Some(retry3::Request {
        stopped_event: p.review.clone(),
        concurrent_working_set: p.review.clone(),
    });
    p.data_fulfillment = Some(prelaunch_data::tests::request());
    p.data_fulfillment.as_mut().unwrap().runtime.path = prelaunch_data::TERMINAL_RUNTIME.into();
    shape(&p).unwrap();
    current_allocation::shape(&p).unwrap();
    assert_eq!(
        guard_template(&p, profile(170).unwrap())["minimum_free_bytes"],
        RAW_FLOOR
    );
    p.current_allocation.as_mut().unwrap().schema = "horizon-current-allocation-request-v1".into();
    assert!(shape(&p).is_err());
    p.resident_memory.as_mut().unwrap().terminal169 = None;
    shape(&p).unwrap();
}

#[test]
fn terminal_process_membership_detects_descendants_without_prefix_aliases() {
    assert!(process_in_unit(&format!("0::/system.slice/{UNIT}\n")).unwrap());
    assert!(process_in_unit(&format!("0::/system.slice/{UNIT}/child\n")).unwrap());
    assert!(!process_in_unit(&format!("0::/system.slice/{UNIT}-foreign\n")).unwrap());
    assert!(!process_in_unit("0::/init.scope\n").unwrap());
    for bad in [
        "",
        "1:cpu:/system.slice",
        "0::relative",
        "0::/\n0::/other\n",
    ] {
        assert!(process_in_unit(bad).is_err());
    }
}
