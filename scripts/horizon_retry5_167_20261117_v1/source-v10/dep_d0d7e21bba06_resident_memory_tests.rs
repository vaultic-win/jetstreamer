use super::*;
pub(super) fn fixture() -> (Request, Value, Value, Value, BTreeMap<String, u64>, u64) {
    let b = Bound {
        path: "/var/lib/jetstreamer/genuine-sample.json".into(),
        sha256: "a".repeat(64),
    };
    let mut owners = Vec::new();
    let mut rows = Vec::new();
    let mut fleet_rows = Vec::new();
    let mut live = BTreeMap::new();
    let mut host_processes = vec![json!({"pid":1,"start_ticks":1,"rss_bytes":2u64<<30})];
    for epoch in [166, 167, 168] {
        let pid = epoch * 10;
        let worker = pid + 1;
        let start = 1000 + epoch;
        let unit = format!("horizon-qualify-{epoch}-replacement-local2-20261110-v1.service");
        let iid = format!("{epoch:032x}");
        let o = Owner {
            epoch,
            unit: unit.clone(),
            invocation_id: iid.clone(),
            main_pid: pid,
            main_start_ticks: start,
            admission: b.clone(),
            guard_protection: b.clone(),
        };
        let processes = vec![
            json!({"pid":pid,"start_ticks":start,"rss_bytes":1u64<<30}),
            json!({"pid":worker,"start_ticks":start+1,"rss_bytes":19u64<<30}),
        ];
        host_processes.extend(processes.clone());
        let role = json!({"unit":unit,"invocation_id":iid,"active_state":"active","sub_state":"running","restarts":0,"main_pid":pid,"control_group":format!("/system.slice/{unit}"),"memory_current_bytes":24u64<<30,"memory_events":{"max":0,"oom":0,"oom_kill":0},"cgroup":{"counters":{"memory_events.max":0,"memory_events.oom":0,"memory_events.oom_kill":0}},"rss":{"census_stable":true,"error":null,"processes":processes,"aggregate_rss_bytes":20u64<<30}});
        let spec = profile(epoch).unwrap();
        let worker_path = format!("{}/replacement-local2-20261110-v1/worker", spec.lane);
        let row = json!({"range":epoch.to_string(),"invocation_binding_stable":true,"producer_cgroup_counter_delta":{"memory_events.max":0,"memory_events.oom":0,"memory_events.oom_kill":0},"controller_before":role,"controller_after":role,"producer_before":role,"producer_after":role,"worker_before":{"pid":worker,"executable":worker_path},"worker_after":{"pid":worker,"executable":worker_path}});
        rows.push(row);
        let native = json!({"Id":unit,"InvocationID":iid,"LoadState":"loaded","ActiveState":"active","SubState":"running","MainPID":pid.to_string(),"ControlPID":"0","NRestarts":"0","Job":"","ControlGroup":format!("/system.slice/{unit}"),"MemoryMax":"73014444032","MemorySwapMax":"0"});
        let mut images = BTreeMap::new();
        images.insert(pid.to_string(),json!({"pid":pid,"start_ticks":start,"executable":format!("{}/jetstreamer-node",spec.package),"sha256":NODE_SHA}));
        images.insert(worker.to_string(),json!({"pid":worker,"start_ticks":start+1,"executable":worker_path,"sha256":WORKER_SHA}));
        live.insert(epoch.to_string(),json!({"native_before":native,"native_after":native,"controller_before":role,"controller_after":role,"producer_before":role,"producer_after":role,"process_images_before":images,"process_images_after":images}));
        fleet_rows.push(json!({"epoch":epoch,"unit":native,"in_current_observer":true,"admission":o.admission,"guard_protection":o.guard_protection}));
        owners.push(o);
    }
    let host = json!({"status":"observed","rss":{"census_stable":true,"error":null,"processes":host_processes,"aggregate_rss_bytes":62u64<<30},"kernel_components_bytes":{"Slab":1u64<<30,"KernelStack":0,"PageTables":0,"Percpu":0}});
    let at = 1_794_340_860;
    let total = 810_902_843_392u64;
    let observer = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-11-10T20:00:00Z","completed_at_utc":"2026-11-10T20:00:00Z","host_memory":{"total_kib":total/1024},"host_resident_memory":{"before":host,"after":host},"replays":rows});
    let fleet = json!({"schema":"horizon-Root-complete-fleet-operational-review-v1","owner":"/root","primary_thread":THREAD,"recorded_unix_seconds":at-10,"observer":b,"complete_projected_memory_bytes":MEMORY,"actual_executing_replays":fleet_rows,"actual_active_bootstraps":[],"active_producer_count":3});
    let current = json!({"host_before":host,"host_after":host,"lanes":live});
    let mem = BTreeMap::from([
        ("MemTotal".into(), total),
        ("MemAvailable".into(), 700u64 << 30),
    ]);
    (
        Request {
            terminal169: None,
            terminal167: None,
            terminal166: None,
            terminal170: None,
            host_kernel_same_resident_basis: false,
            admission_only_capture: false,
            observer: b,
            owners,
        },
        fleet,
        observer,
        current,
        mem,
        at,
    )
}
fn evaluate(f: &(Request, Value, Value, Value, BTreeMap<String, u64>, u64)) -> Result<Value> {
    checked(&f.0, 169, &f.1, &f.2, &f.3, &f.4, f.5)
}
#[test]
fn three_exact_resident_lanes_fix_double_charge_without_reducing_promises() {
    let f = fixture();
    let r = evaluate(&f).unwrap();
    assert_eq!(r["complete_projected_memory_bytes"], MEMORY);
    assert_eq!(
        r["realized_resident_bytes_subtracted_from_future_growth"],
        60u64 << 30
    );
    assert_eq!(r["resource_credit_bytes"], 0);
    assert!(f.4["MemAvailable"] < MEMORY + RESERVE);
}
#[test]
fn same_controller_producer_processes_are_counted_once() {
    let f = fixture();
    assert_eq!(evaluate(&f).unwrap()["lanes"].as_array().unwrap().len(), 3);
    assert_eq!(
        evaluate(&f).unwrap()["realized_resident_bytes_subtracted_from_future_growth"],
        60u64 << 30
    );
}
#[test]
fn exact_host_matches_not_supplied_rss_determine_subtraction() {
    let mut f = fixture();
    for suffix in ["before", "after"] {
        f.2["replays"][0][format!("producer_{suffix}")]["rss"]["processes"][1]["rss_bytes"] =
            json!(30u64 << 30);
        f.2["replays"][0][format!("producer_{suffix}")]["rss"]["aggregate_rss_bytes"] =
            json!(31u64 << 30);
    }
    assert_eq!(
        evaluate(&f).unwrap()["realized_resident_bytes_subtracted_from_future_growth"],
        60u64 << 30
    );
}
#[test]
fn non_lane_rss_and_kernel_receive_no_promise_subtraction() {
    let f = fixture();
    let r = evaluate(&f).unwrap();
    assert_eq!(r["non_lane_resident_credit_bytes"], 0);
    assert_eq!(r["host_resident_planning_upper_bytes"], 63u64 << 30);
}
#[test]
fn missing_host_census_fails_closed() {
    let mut f = fixture();
    f.2["host_resident_memory"]["after"] = Value::Null;
    assert!(evaluate(&f).is_err());
}
#[test]
fn unavailable_diagnostic_is_not_silently_used_as_standard_lane() {
    let mut f = fixture();
    f.2["replays"].as_array_mut().unwrap().pop();
    assert!(evaluate(&f).is_err());
}
#[test]
fn live_owner_not_in_accepted_observer_cannot_earn_subtraction() {
    let mut f = fixture();
    f.1["actual_executing_replays"][0]["in_current_observer"] = json!(false);
    assert!(evaluate(&f).is_err());
}
#[test]
fn stale_coordinated_sample_rejected() {
    let mut f = fixture();
    f.5 += 1801;
    assert!(evaluate(&f).is_err());
}
#[test]
fn old_or_foreign_observer_binding_rejected() {
    let mut f = fixture();
    f.0.observer.sha256 = "b".repeat(64);
    assert!(evaluate(&f).is_err());
}
#[test]
fn current_pid_reuse_rejected() {
    let mut f = fixture();
    f.3["lanes"]["166"]["producer_after"]["rss"]["processes"][0]["start_ticks"] = json!(999);
    assert!(evaluate(&f).is_err());
}
#[test]
fn same_pid_different_host_identity_rejected() {
    let mut f = fixture();
    f.3["host_before"]["rss"]["processes"][1]["start_ticks"] = json!(999);
    assert!(evaluate(&f).is_err());
}
#[test]
fn changed_invocation_rejected() {
    let mut f = fixture();
    f.3["lanes"]["166"]["native_after"]["InvocationID"] = json!("b".repeat(32));
    assert!(evaluate(&f).is_err());
}
#[test]
fn duplicate_owner_cannot_double_spend_realized_resident_bytes() {
    let mut f = fixture();
    f.0.owners[1].epoch = 166;
    assert!(evaluate(&f).is_err());
}
#[test]
fn source_topology_change_rejected() {
    let mut f = fixture();
    f.3["lanes"]["166"]["controller_after"]["unit"] = json!("other.service");
    assert!(evaluate(&f).is_err());
}
#[test]
fn stale_worker_executable_rejected() {
    let mut f = fixture();
    f.3["lanes"]["166"]["process_images_after"]["1661"]["sha256"] = json!("b".repeat(64));
    assert!(evaluate(&f).is_err());
}
#[test]
fn current_node_source_path_change_rejected() {
    let mut f = fixture();
    for suffix in ["before", "after"] {
        f.3["lanes"]["166"][format!("process_images_{suffix}")]["1660"]["executable"] =
            json!("/different/node");
    }
    assert!(evaluate(&f).is_err());
}
#[test]
fn current_hard_cap_change_rejected() {
    let mut f = fixture();
    f.3["lanes"]["166"]["native_after"]["MemoryMax"] = json!("146028888064");
    assert!(evaluate(&f).is_err());
}
#[test]
fn kernel_children_cannot_be_added_on_top_of_slab() {
    let mut f = fixture();
    f.3["host_before"]["kernel_components_bytes"]["SReclaimable"] = json!(1);
    assert!(evaluate(&f).is_err());
}
#[test]
fn current_cgroup_charge_clamps_rss_subtraction() {
    let mut f = fixture();
    for suffix in ["before", "after"] {
        f.3["lanes"]["166"][format!("producer_{suffix}")]["memory_current_bytes"] =
            json!(10u64 << 30);
    }
    assert_eq!(
        evaluate(&f).unwrap()["realized_resident_bytes_subtracted_from_future_growth"],
        50u64 << 30
    );
}
#[test]
fn large_memavailable_does_not_hide_resident_projection_overcommit() {
    let mut f = fixture();
    f.4.insert("MemAvailable".into(), f.4["MemTotal"]);
    for suffix in ["before", "after"] {
        f.3[format!("host_{suffix}")]["rss"]["processes"][0]["rss_bytes"] = json!(100u64 << 30);
        f.3[format!("host_{suffix}")]["rss"]["aggregate_rss_bytes"] = json!(160u64 << 30);
    }
    assert!(evaluate(&f).is_err());
}
#[test]
fn available_memory_remains_independent_gate() {
    let mut f = fixture();
    f.4.insert("MemAvailable".into(), 500u64 << 30);
    assert!(evaluate(&f).is_err());
}
#[test]
fn aggregate_census_cannot_hide_missing_process() {
    let mut f = fixture();
    f.3["host_before"]["rss"]["processes"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(evaluate(&f).is_err());
}
#[test]
fn total_host_memory_cannot_change_between_accepted_sample_and_admission() {
    let mut f = fixture();
    f.4.insert("MemTotal".into(), 900u64 << 30);
    assert!(evaluate(&f).is_err());
}
#[test]
fn wrong_epoch_candidate_cannot_credit_its_own_slot() {
    let f = fixture();
    assert!(checked(&f.0, 166, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
}

#[test]
fn new_current_hard_memory_event_rejected() {
    let mut f = fixture();
    f.3["lanes"]["166"]["producer_after"]["memory_events"]["max"] = json!(1);
    assert!(evaluate(&f).is_err());
}
#[test]
fn observed_oom_event_never_qualifies_memory_subtraction() {
    let mut f = fixture();
    f.2["replays"][0]["producer_cgroup_counter_delta"]["memory_events.oom_kill"] = json!(1);
    assert!(evaluate(&f).is_err());
}

fn host_only_fixture() -> (Request, Value, Value, Value, BTreeMap<String, u64>, u64) {
    let mut f = fixture();
    f.0.owners.clear();
    f.0.host_kernel_same_resident_basis = true;
    f.1["actual_executing_replays"] = json!([]);
    f.1["actual_active_bootstraps"] = json!([]);
    f.1["active_producer_count"] = json!(0);
    f.1["complete_projected_memory_bytes"] = json!(current_budget::CURRENT_MEMORY);
    f.1["complete_DATA_bytes"] = json!(current_budget::CURRENT_DATA);
    f.2["replays"] = json!([]);
    f.3["lanes"] = json!({});
    let h = json!({"status":"observed","rss":{"census_stable":true,"error":null,"processes":[{"pid":1,"start_ticks":1,"rss_bytes":2u64<<30}],"aggregate_rss_bytes":2u64<<30},"kernel_components_bytes":{"Slab":40u64<<30,"KernelStack":0,"PageTables":0,"Percpu":16u64<<30}});
    f.2["host_resident_memory"] = json!({"before":h,"after":h});
    f.3["host_before"] = h.clone();
    f.3["host_after"] = h;
    f.4.insert(
        "MemAvailable".into(),
        current_budget::CURRENT_MEMORY + RESERVE - (2 << 30),
    );
    f
}
#[test]
fn zero_owner_host_only_uses_real_ancestry_and_retains_every_current_promise() {
    let f = host_only_fixture();
    let r = evaluate(&f).unwrap();
    assert_eq!(r["zero_owner_host_only_realization"], true);
    assert_eq!(r["lanes"], json!([]));
    assert_eq!(
        r["realized_resident_bytes_subtracted_from_future_growth"],
        0
    );
    assert_eq!(
        r["host_component_realization"]["realized_host_component_bytes"],
        39u64 << 30
    );
    assert_eq!(r["host_resident_planning_upper_bytes"], 58u64 << 30);
    assert_eq!(r["host_component_realization"]["Percpu_credited_bytes"], 0);
    assert!(
        r["host_component_realization"]["provenance"]["historical_native_proof"]["sha256"]
            .is_string()
    );
    let current = current_budget::memory_recheck(&r, f.4["MemTotal"], f.4["MemAvailable"]).unwrap();
    assert_eq!(
        current["complete_projected_memory_bytes"],
        current_budget::CURRENT_MEMORY
    );
    assert_eq!(current["resource_credit_bytes"], 0);
    assert_eq!(current["promise_ending_bytes"], 0);
}
#[test]
fn zero_owner_host_only_rejects_missing_opt_in_old_totals_and_foreign_epoch() {
    let mut f = host_only_fixture();
    f.0.host_kernel_same_resident_basis = false;
    assert!(evaluate(&f).is_err());
    f.0.host_kernel_same_resident_basis = true;
    f.1["complete_projected_memory_bytes"] = json!(MEMORY);
    assert!(evaluate(&f).is_err());
    f.1["complete_projected_memory_bytes"] = json!(current_budget::CURRENT_MEMORY);
    f.1["complete_DATA_bytes"] = json!(DATA);
    assert!(evaluate(&f).is_err());
    f.1["complete_DATA_bytes"] = json!(current_budget::CURRENT_DATA);
    assert!(checked(&f.0, 168, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
}
#[test]
fn zero_owner_host_only_rejects_hidden_fleet_observer_and_native_owners() {
    let mut f = host_only_fixture();
    f.1["active_producer_count"] = json!(1);
    assert!(evaluate(&f).is_err());
    f.1["active_producer_count"] = json!(0);
    f.1["actual_active_bootstraps"] = json!([{"epoch":166}]);
    assert!(evaluate(&f).is_err());
    f.1["actual_active_bootstraps"] = json!([]);
    f.2["replays"] = json!([{"range":"166"}]);
    assert!(evaluate(&f).is_err());
    f.2["replays"] = json!([]);
    f.3["lanes"] = json!({"166":{}});
    assert!(evaluate(&f).is_err());
}
#[test]
fn zero_owner_host_only_rejects_missing_unstable_and_stale_census() {
    let mut f = host_only_fixture();
    f.3["host_after"]["rss"]["census_stable"] = json!(false);
    assert!(evaluate(&f).is_err());
    f.3["host_after"]["rss"]["census_stable"] = json!(true);
    f.3["host_before"]["kernel_components_bytes"]["Slab"] = Value::Null;
    assert!(evaluate(&f).is_err());
    let mut f = host_only_fixture();
    f.5 += 1801;
    assert!(evaluate(&f).is_err());
}
#[test]
fn zero_owner_host_only_still_rejects_current_available_and_resident_overcommit() {
    let mut f = host_only_fixture();
    let needed = evaluate(&f).unwrap()["required_available_bytes"]
        .as_u64()
        .unwrap();
    f.4.insert("MemAvailable".into(), needed - 1);
    assert!(evaluate(&f).is_err());
    let mut f = host_only_fixture();
    f.4.insert("MemAvailable".into(), f.4["MemTotal"]);
    f.3["host_after"]["rss"]["processes"][0]["rss_bytes"] = json!(100u64 << 30);
    f.3["host_after"]["rss"]["aggregate_rss_bytes"] = json!(100u64 << 30);
    assert!(evaluate(&f).is_err());
}
#[test]
fn zero_owner_host_only_charges_current_delta_after_legacy_pass() {
    let mut f = host_only_fixture();
    let r = evaluate(&f).unwrap();
    let required = r["required_available_bytes"].as_u64().unwrap();
    f.4.insert(
        "MemAvailable".into(),
        required + current_budget::MEMORY_DELTA - 1,
    );
    let r = evaluate(&f).unwrap();
    assert!(current_budget::memory_recheck(&r, f.4["MemTotal"], f.4["MemAvailable"]).is_err());
}

fn peer_admission_fixture() -> (Request, Value, Value, Value, BTreeMap<String, u64>, u64) {
    let mut f = fixture();
    f.0.owners.truncate(1);
    f.0.host_kernel_same_resident_basis = true;
    f.0.admission_only_capture = true;
    f.0.owners[0].unit = "horizon-qualify-166-replacement-local3retry2-20261110-v1.service".into();
    f.1["actual_executing_replays"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    f.1["active_producer_count"] = json!(1);
    f.1["complete_projected_memory_bytes"] = json!(current_budget::CURRENT_MEMORY);
    f.1["complete_DATA_bytes"] = json!(current_budget::CURRENT_DATA);
    f.1["actual_executing_replays"][0]["in_current_observer"] = json!(false);
    f.2["replays"].as_array_mut().unwrap().truncate(1);
    f.3["lanes"]
        .as_object_mut()
        .unwrap()
        .retain(|k, _| k == "166");
    for v in [&mut f.1, &mut f.2, &mut f.3] {
        let encoded = serde_json::to_string(v).unwrap().replace(
            "horizon-qualify-166-replacement-local2-20261110-v1.service",
            "horizon-qualify-166-replacement-local3retry2-20261110-v1.service",
        );
        *v = serde_json::from_str(&encoded).unwrap();
    }
    let mut host = f.3["host_before"].clone();
    host["rss"]["processes"].as_array_mut().unwrap().truncate(3);
    host["rss"]["aggregate_rss_bytes"] = json!(22u64 << 30);
    host["kernel_components_bytes"]["Slab"] = json!(20u64 << 30);
    f.3["host_before"] = host.clone();
    f.3["host_after"] = host.clone();
    f.2["host_resident_memory"] = json!({"before":host,"after":host});
    f.2["schema"] = json!("horizon-retry2-admission-only-resident-snapshot-v1");
    f.2.as_object_mut().unwrap().remove("completed_at_utc");
    f.2["routine_observation"] = json!(false);
    f.2["previous_routine_observer"] = json!(f.0.observer);
    f.2["started_unix_seconds"] = json!(f.5 - 2);
    f.2["completed_unix_seconds"] = json!(f.5 - 1);
    f.4.insert(
        "MemAvailable".into(),
        current_budget::CURRENT_MEMORY + RESERVE - (10 << 30),
    );
    f
}
#[test]
fn newborn_peer_can_be_measured_without_claiming_old_observer_membership() {
    let f = peer_admission_fixture();
    let r = evaluate(&f).unwrap();
    assert_eq!(
        r["realized_resident_bytes_subtracted_from_future_growth"],
        20u64 << 30
    );
    assert_eq!(
        r["host_component_realization"]["realized_host_component_bytes"],
        19u64 << 30
    );
    current_budget::memory_recheck(&r, f.4["MemTotal"], f.4["MemAvailable"]).unwrap();
    assert_eq!(
        f.1["actual_executing_replays"][0]["in_current_observer"],
        false
    );
}
#[test]
fn retry4_166_peer_passes_complete_resident_accounting_for170() {
    let mut f = peer_admission_fixture();
    f.0.owners[0].unit = "horizon-qualify-166-replacement-local3retry4-20261110-v1.service".into();
    for v in [&mut f.1, &mut f.2, &mut f.3] {
        *v = serde_json::from_str(
            &serde_json::to_string(v)
                .unwrap()
                .replace("local3retry2", "local3retry4"),
        )
        .unwrap();
    }
    let result = checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).unwrap();
    assert_eq!(
        result["realized_resident_bytes_subtracted_from_future_growth"],
        20u64 << 30
    );
    assert_eq!(result["resource_credit_bytes"], 0);
    f.3["lanes"]["166"]["native_after"]["InvocationID"] = json!("f".repeat(32));
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
}
#[test]
fn exact_peer_attempts_reject_unknown_and_cross_epoch_retry4_units() {
    for epoch in [166, 167, 169, 170] {
        for attempt in ["local3retry2", "local3retry3"] {
            let unit = format!("horizon-qualify-{epoch}-replacement-{attempt}-20261110-v1.service");
            assert_eq!(qualified_peer_attempt(epoch, &unit).unwrap(), attempt);
        }
        let unit = format!("horizon-qualify-{epoch}-replacement-local3retry4-20261110-v1.service");
        assert_eq!(qualified_peer_attempt(epoch, &unit).is_ok(), epoch == 166);
    }
    for unit in [
        "horizon-qualify-167-replacement-local3retry4-20261110-v1.service",
        "horizon-qualify-166-replacement-local3retry5-20261110-v1.service",
        "foreign-local3retry4-20261110-v1.service",
        "horizon-qualify-166-replacement-local3retry4-20261110-v1.service.extra",
    ] {
        assert!(qualified_peer_attempt(166, unit).is_err());
    }
    assert!(
        qualified_peer_attempt(
            168,
            "horizon-qualify-168-replacement-local3retry3-20261110-v1.service"
        )
        .is_err()
    );
}
#[test]
fn actual_three_owner_bindings_select_their_exact_attempts() {
    let actual: Value =
        serde_json::from_str(include_str!("dep_05d3c4e05078_actual-three-owner-native.json")).unwrap();
    let event = &actual["event"];
    let mut epochs = BTreeSet::new();
    for row in event["active_replay_invocations"]
        .as_array()
        .unwrap()
        .iter()
        .chain(event["active_bootstrap_invocations"].as_array().unwrap())
    {
        let epoch = row["epoch"].as_u64().unwrap();
        epochs.insert(epoch);
        let attempt = qualified_peer_attempt(epoch, row["unit"]["unit"].as_str().unwrap()).unwrap();
        assert_eq!(
            attempt,
            if epoch == 166 {
                "local3retry4"
            } else {
                "local3retry3"
            }
        );
    }
    assert_eq!(epochs, BTreeSet::from([166, 167, 169]));
}
#[test]
fn newborn_peer_route_cannot_relabel_routine_snapshot_or_skip_opt_in() {
    let mut f = peer_admission_fixture();
    f.0.admission_only_capture = false;
    assert!(evaluate(&f).is_err());
    f.0.admission_only_capture = true;
    f.2["schema"] = json!("jetstreamer-horizon-live-resource-sample-v2");
    assert!(evaluate(&f).is_err());
    f.2["schema"] = json!("horizon-retry2-admission-only-resident-snapshot-v1");
    f.2["routine_observation"] = json!(true);
    assert!(evaluate(&f).is_err());
}
#[test]
fn newborn_peer_route_rejects_foreign_scope_and_expired_current_fleet() {
    let mut f = peer_admission_fixture();
    f.1["recorded_unix_seconds"] = json!(f.5 - 121);
    assert!(evaluate(&f).is_err());
    f.1["recorded_unix_seconds"] = json!(f.5 - 10);
    f.0.owners[0].unit = "horizon-qualify-166-replacement-local2-20261110-v1.service".into();
    assert!(evaluate(&f).is_err());
}
#[test]
fn newborn_peer_route_retains_pid_event_and_independent_memory_rejections() {
    let mut f = peer_admission_fixture();
    f.3["lanes"]["166"]["producer_after"]["memory_events"]["oom_kill"] = json!(1);
    assert!(evaluate(&f).is_err());
    let mut f = peer_admission_fixture();
    f.3["lanes"]["166"]["producer_after"]["rss"]["processes"][1]["start_ticks"] = json!(999);
    assert!(evaluate(&f).is_err());
    let mut f = peer_admission_fixture();
    f.4.insert("MemAvailable".into(), 1);
    assert!(evaluate(&f).is_err());
}

fn retry4_peer_fixture() -> (Request, Value, Value, Value, BTreeMap<String, u64>, u64) {
    let b = Bound {
        path: "/var/lib/jetstreamer/genuine-sample.json".into(),
        sha256: "a".repeat(64),
    };
    let mut owners = Vec::new();
    let mut rows = Vec::new();
    let mut fleet_rows = Vec::new();
    let mut live = BTreeMap::new();
    let mut host_processes = vec![json!({"pid":1,"start_ticks":1,"rss_bytes":2u64<<30})];
    for o in serde_json::from_str::<Vec<Owner>>(include_str!("dep_97e29106102e_retry4-exact-peers.json")).unwrap() {
        let epoch = o.epoch;
        let pid = o.main_pid;
        let worker = pid + 1; // Synthetic RSS endpoint; owner identities remain actual pins.
        let start = o.main_start_ticks;
        let unit = o.unit.clone();
        let iid = o.invocation_id.clone();
        let processes = vec![
            json!({"pid":pid,"start_ticks":start,"rss_bytes":1u64<<30}),
            json!({"pid":worker,"start_ticks":start+1,"rss_bytes":19u64<<30}),
        ];
        host_processes.extend(processes.clone());
        let role = json!({"unit":unit,"invocation_id":iid,"active_state":"active","sub_state":"running","restarts":0,"main_pid":pid,"control_group":format!("/system.slice/{unit}"),"memory_current_bytes":24u64<<30,"memory_events":{"max":0,"oom":0,"oom_kill":0},"cgroup":{"counters":{"memory_events.max":0,"memory_events.oom":0,"memory_events.oom_kill":0}},"rss":{"census_stable":true,"error":null,"processes":processes,"aggregate_rss_bytes":20u64<<30}});
        let spec = profile(epoch).unwrap();
        let worker_path = format!("{}/replacement-local3retry3-20261110-v1/worker", spec.lane);
        let row = json!({"range":epoch.to_string(),"invocation_binding_stable":true,"producer_cgroup_counter_delta":{"memory_events.max":0,"memory_events.oom":0,"memory_events.oom_kill":0},"controller_before":role,"controller_after":role,"producer_before":role,"producer_after":role,"worker_before":{"pid":worker,"executable":worker_path},"worker_after":{"pid":worker,"executable":worker_path}});
        rows.push(row);
        let native = json!({"Id":unit,"InvocationID":iid,"LoadState":"loaded","ActiveState":"active","SubState":"running","MainPID":pid.to_string(),"ControlPID":"0","NRestarts":"0","Job":"","ControlGroup":format!("/system.slice/{unit}"),"MemoryMax":"73014444032","MemorySwapMax":"0"});
        let mut images = BTreeMap::new();
        images.insert(pid.to_string(),json!({"pid":pid,"start_ticks":start,"executable":format!("{}/jetstreamer-node",spec.package),"sha256":NODE_SHA}));
        images.insert(worker.to_string(),json!({"pid":worker,"start_ticks":start+1,"executable":worker_path,"sha256":WORKER_SHA}));
        live.insert(epoch.to_string(),json!({"native_before":native,"native_after":native,"controller_before":role,"controller_after":role,"producer_before":role,"producer_after":role,"process_images_before":images,"process_images_after":images}));
        fleet_rows.push(json!({"epoch":epoch,"unit":native,"in_current_observer":true,"admission":o.admission,"guard_protection":o.guard_protection}));
        owners.push(o);
    }
    let host = json!({"status":"observed","rss":{"census_stable":true,"error":null,"processes":host_processes,"aggregate_rss_bytes":42u64<<30},"kernel_components_bytes":{"Slab":20u64<<30,"KernelStack":0,"PageTables":0,"Percpu":0}});
    let at = 1_794_340_860;
    let total = 810_902_843_392u64;
    let observer = json!({"schema":"horizon-retry2-admission-only-resident-snapshot-v1","routine_observation":false,"previous_routine_observer":b,"started_unix_seconds":at-2,"completed_unix_seconds":at-1,"host_memory":{"total_kib":total/1024},"host_resident_memory":{"before":host,"after":host},"replays":rows});
    let fleet = json!({"schema":"horizon-Root-complete-fleet-operational-review-v1","owner":"/root","primary_thread":THREAD,"recorded_unix_seconds":at-10,"observer":b,"complete_projected_memory_bytes":current_budget::CURRENT_MEMORY,"complete_DATA_bytes":current_budget::CURRENT_DATA,"actual_executing_replays":fleet_rows,"actual_active_bootstraps":[],"active_producer_count":2});
    let current = json!({"host_before":host,"host_after":host,"lanes":live});
    let mem = BTreeMap::from([
        ("MemTotal".into(), total),
        ("MemAvailable".into(), 700u64 << 30),
    ]);
    (
        Request {
            terminal169: None,
            terminal167: None,
            terminal166: None,
            terminal170: None,
            host_kernel_same_resident_basis: true,
            admission_only_capture: true,
            observer: b,
            owners,
        },
        fleet,
        observer,
        current,
        mem,
        at,
    )
}
fn evaluate_retry4(
    f: &(Request, Value, Value, Value, BTreeMap<String, u64>, u64),
) -> Result<Value> {
    checked(&f.0, 166, &f.1, &f.2, &f.3, &f.4, f.5)
}
#[test]
fn exact166_retry4_actual_two_peers_pass_complete_resident_accounting() {
    let f = retry4_peer_fixture();
    let r = evaluate_retry4(&f).unwrap();
    assert_eq!(
        r["realized_resident_bytes_subtracted_from_future_growth"],
        40u64 << 30
    );
    assert_eq!(r["resource_credit_bytes"], 0);
    assert_eq!(r["promise_ending_bytes"], 0);
    current_budget::memory_recheck(&r, f.4["MemTotal"], f.4["MemAvailable"]).unwrap();
}
#[test]
fn retry4_exact_peer_set_rejects_omission_extra_duplicate_and_changed_identity() {
    let f = retry4_peer_fixture();
    let pins = serde_json::to_value(&f.0.owners).unwrap();
    let mut variants = Vec::new();
    let mut v = pins.clone();
    v.as_array_mut().unwrap().pop();
    variants.push(v);
    let mut v = pins.clone();
    let extra = v[0].clone();
    v.as_array_mut().unwrap().push(extra);
    variants.push(v);
    let mut v = pins.clone();
    v[1] = v[0].clone();
    variants.push(v);
    for (path, value) in [
        ("/0/epoch", json!(170)),
        (
            "/0/unit",
            json!("horizon-qualify-167-replacement-local3retry2-20261110-v1.service"),
        ),
        ("/0/invocation_id", json!("a".repeat(32))),
        ("/0/main_pid", json!(1)),
        ("/0/main_start_ticks", json!(1)),
        ("/0/admission/sha256", json!("a".repeat(64))),
        ("/0/guard_protection/sha256", json!("b".repeat(64))),
    ] {
        let mut v = pins.clone();
        *v.pointer_mut(path).unwrap() = value;
        variants.push(v);
    }
    for v in variants {
        let mut f = retry4_peer_fixture();
        f.0.owners = serde_json::from_value(v).unwrap();
        assert!(evaluate_retry4(&f).is_err());
    }
}
#[test]
fn retry4_scope_does_not_open_legacy166_attempts() {
    let f = retry4_peer_fixture();
    let mut p: Plan =
        serde_json::from_str(include_str!("dep_58bd338ae33e_epoch166.RETRY4_PLAN.SOURCE_TEMPLATE.json")).unwrap();
    p.data_fulfillment = Some(crate::prelaunch_data::tests::request());
    admission_scope(&f.0, &p).unwrap();
    for attempt in ["local3retry2", "local3retry3", "local3"] {
        p.attempt = attempt.into();
        assert!(admission_scope(&f.0, &p).is_err());
    }
}
#[test]
fn retry4_full_accounting_keeps_original_clock_and_memory_rejections() {
    let mut f = retry4_peer_fixture();
    f.1["recorded_unix_seconds"] = json!(f.5 - 121);
    assert!(evaluate_retry4(&f).is_err());
    let mut f = retry4_peer_fixture();
    f.2["completed_unix_seconds"] = json!(f.5 + 1);
    assert!(evaluate_retry4(&f).is_err());
    let mut f = retry4_peer_fixture();
    f.3["lanes"]["167"]["producer_after"]["rss"]["processes"][1]["start_ticks"] = json!(1);
    assert!(evaluate_retry4(&f).is_err());
    let mut f = retry4_peer_fixture();
    f.3["lanes"]["169"]["producer_after"]["memory_events"]["oom_kill"] = json!(1);
    assert!(evaluate_retry4(&f).is_err());
    let mut f = retry4_peer_fixture();
    f.4.insert("MemAvailable".into(), 1);
    assert!(evaluate_retry4(&f).is_err());
    let mut f = retry4_peer_fixture();
    f.1["complete_DATA_bytes"] = json!(current_budget::CURRENT_DATA - 1);
    assert!(evaluate_retry4(&f).is_err());
    let mut f = retry4_peer_fixture();
    f.0.host_kernel_same_resident_basis = false;
    assert!(evaluate_retry4(&f).is_err());
}

// Keep the removed lane's host RSS present as overhead: only live166/167 earn
// realization, while every historical promise remains in the projection.
fn terminal169_fixture() -> (Request, Value, Value, Value, BTreeMap<String, u64>, u64) {
    let mut f = fixture();
    f.0.owners.retain(|o| o.epoch != 168);
    f.1["actual_executing_replays"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["epoch"] != 168);
    f.1["active_producer_count"] = json!(2);
    f.2["replays"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["range"] != "168");
    f.3["lanes"].as_object_mut().unwrap().remove("168");
    fn replace(v: &mut Value, from: &str, to: &str) {
        match v {
            Value::String(s) => {
                if s.as_str() == from {
                    *s = to.into();
                } else if s.as_str() == format!("/system.slice/{from}") {
                    *s = format!("/system.slice/{to}");
                }
            }
            Value::Array(a) => {
                for x in a {
                    replace(x, from, to)
                }
            }
            Value::Object(o) => {
                for x in o.values_mut() {
                    replace(x, from, to)
                }
            }
            _ => {}
        }
    }
    for o in &mut f.0.owners {
        let (attempt, iid) = if o.epoch == 166 {
            ("local3retry4", "58778e77980e4a15828c3be837e447aa")
        } else {
            ("local3retry3", "7ce90d0ec8114cf3a6be73eb9cf75ae8")
        };
        let unit = format!(
            "horizon-qualify-{}-replacement-{attempt}-20261110-v1.service",
            o.epoch
        );
        for v in [&mut f.1, &mut f.2, &mut f.3] {
            replace(v, &o.unit, &unit);
            replace(v, &o.invocation_id, iid);
        }
        o.unit = unit;
        o.invocation_id = iid.into();
    }
    f.0.terminal169 = Some(terminal169::exact());
    f.0.admission_only_capture = true;
    f.0.host_kernel_same_resident_basis = true;
    f.1["complete_DATA_bytes"] = json!(terminal169::COMPLETE_DATA);
    f.1["complete_projected_memory_bytes"] = json!(current_budget::CURRENT_MEMORY);
    f.2["schema"] = json!("horizon-retry2-admission-only-resident-snapshot-v1");
    f.2["routine_observation"] = json!(false);
    f.2["previous_routine_observer"] = json!(f.0.observer);
    f.2["started_unix_seconds"] = json!(f.5 - 5);
    f.2["completed_unix_seconds"] = json!(f.5 - 1);
    f
}
#[test]
fn terminal169_full_memory_projection_credits_only_two_live_rss_sets() {
    let f = terminal169_fixture();
    let r = checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).unwrap();
    assert_eq!(r["complete_projected_memory_bytes"], MEMORY);
    assert_eq!(r["lanes"].as_array().unwrap().len(), 2);
    assert_eq!(
        r["realized_resident_bytes_subtracted_from_future_growth"],
        40u64 << 30
    );
    assert_eq!(r["promise_ending_bytes"], 0);
    let total = f.4["MemTotal"];
    let available = f.4["MemAvailable"];
    let final_point = current_budget::memory_recheck(&r, total, available).unwrap();
    assert_eq!(
        final_point["complete_projected_memory_bytes"],
        current_budget::CURRENT_MEMORY
    );
    assert_eq!(
        final_point["required_available_bytes"].as_u64().unwrap(),
        r["required_available_bytes"].as_u64().unwrap() + current_budget::MEMORY_DELTA
    );
}
#[test]
fn terminal169_memory_outer_gate_rejects_missing_booking_and_forged_third_owner() {
    let mut f = terminal169_fixture();
    f.1["complete_DATA_bytes"] = json!(current_budget::CURRENT_DATA);
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
    let mut f = terminal169_fixture();
    f.0.terminal169 = None;
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
    let mut f = terminal169_fixture();
    let third = f.1["actual_executing_replays"][0].clone();
    f.1["actual_executing_replays"]
        .as_array_mut()
        .unwrap()
        .push(third);
    f.1["active_producer_count"] = json!(3);
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
    let mut f = terminal169_fixture();
    f.3["lanes"]["169"] = json!({"rss_bytes":73_014_444_032u64});
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
}

fn terminal167_fixture() -> (Request, Value, Value, Value, BTreeMap<String, u64>, u64) {
    let mut f = terminal169_fixture();
    f.0.terminal167 = Some(terminal167::exact());
    f.1["complete_DATA_bytes"] = json!(completed167::COMPLETE_DATA);
    f.0.owners.retain(|o| o.epoch == 166);
    f.1["actual_executing_replays"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["epoch"] == 166);
    f.1["active_producer_count"] = json!(1);
    f.2["replays"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["range"] == "166");
    f.3["lanes"].as_object_mut().unwrap().remove("167");
    // Synthetic host with sufficient capacity; stopped RSS remains fully charged.
    *f.4.get_mut("MemTotal").unwrap() += 32u64 << 30;
    *f.4.get_mut("MemAvailable").unwrap() += 32u64 << 30;
    f.2["host_memory"]["total_kib"] = json!(f.4["MemTotal"] / 1024);
    f
}
#[test]
fn terminal167_complete_memory_gate_keeps_stopped_rss_as_overhead_and_all_promises() {
    let f = terminal167_fixture();
    let r = checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).unwrap();
    assert_eq!(r["lanes"].as_array().unwrap().len(), 1);
    assert_eq!(
        r["realized_resident_bytes_subtracted_from_future_growth"],
        20u64 << 30
    );
    assert_eq!(r["complete_projected_memory_bytes"], MEMORY);
    assert_eq!(r["promise_ending_bytes"], 0);
    assert_eq!(r["resource_credit_bytes"], 0);
    current_budget::memory_recheck(&r, f.4["MemTotal"], f.4["MemAvailable"]).unwrap();
}
#[test]
fn terminal167_complete_memory_gate_rejects_hidden_peer_and_missing_optin() {
    let mut f = terminal167_fixture();
    f.0.terminal167 = None;
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
    let mut f = terminal167_fixture();
    f.3["lanes"]["167"] = json!({});
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
    let mut f = terminal167_fixture();
    f.1["complete_DATA_bytes"] = json!(current_budget::CURRENT_DATA);
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
}
#[test]
fn terminal167_complete_memory_gate_still_rejects_insufficient_memory() {
    let mut f = terminal167_fixture();
    f.4.insert("MemAvailable".into(), 1);
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
}

#[test]
fn terminal167_original_tight_host_fixture_still_rejects() {
    let mut f = terminal167_fixture();
    *f.4.get_mut("MemTotal").unwrap() -= 32u64 << 30;
    *f.4.get_mut("MemAvailable").unwrap() -= 32u64 << 30;
    f.2["host_memory"]["total_kib"] = json!(f.4["MemTotal"] / 1024);
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
}

fn terminal166_fixture() -> (Request, Value, Value, Value, BTreeMap<String, u64>, u64) {
    let mut f = terminal167_fixture();
    f.0.terminal166 = Some(terminal166::exact());
    f.0.owners.clear();
    f.1["actual_executing_replays"] = json!([]);
    f.1["actual_active_bootstraps"] = json!([]);
    f.1["active_producer_count"] = json!(0);
    f.2["replays"] = json!([]);
    f.3["lanes"] = json!({});
    // Additional synthetic capacity proves arithmetic; it is never production evidence.
    *f.4.get_mut("MemTotal").unwrap() += 32u64 << 30;
    *f.4.get_mut("MemAvailable").unwrap() += 32u64 << 30;
    f.2["host_memory"]["total_kib"] = json!(f.4["MemTotal"] / 1024);
    f
}
#[test]
fn zero166_memory_retains_all_promises_and_zero_lane_realization() {
    let f = terminal166_fixture();
    let result = checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).unwrap();
    assert_eq!(result["lanes"], json!([]));
    assert_eq!(
        result["realized_resident_bytes_subtracted_from_future_growth"],
        0
    );
    assert_eq!(result["complete_projected_memory_bytes"], MEMORY);
    assert_eq!(result["zero_owner_host_only_realization"], true);
    assert_eq!(result["promise_ending_bytes"], 0);
    assert_eq!(result["resource_credit_bytes"], 0);
    current_budget::memory_recheck(&result, f.4["MemTotal"], f.4["MemAvailable"]).unwrap();
}
#[test]
fn zero166_memory_rejects_implicit_optin_hidden_owners_and_cap_downgrade() {
    let mut f = terminal166_fixture();
    f.0.terminal166 = None;
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
    for key in ["actual_executing_replays", "actual_active_bootstraps"] {
        let mut f = terminal166_fixture();
        f.1[key] = json!([{"epoch":166}]);
        assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
    }
    let mut f = terminal166_fixture();
    f.3["lanes"]["166"] = json!({});
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
    let mut f = terminal166_fixture();
    f.1["complete_DATA_bytes"] = json!(terminal169::COMPLETE_DATA);
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
    let mut f = terminal166_fixture();
    f.4.insert("MemAvailable".into(), 1);
    assert!(checked(&f.0, 170, &f.1, &f.2, &f.3, &f.4, f.5).is_err());
}
