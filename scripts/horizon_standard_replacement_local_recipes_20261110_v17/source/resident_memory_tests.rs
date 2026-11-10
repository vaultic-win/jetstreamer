use super::*;
fn fixture() -> (Request, Value, Value, Value, BTreeMap<String, u64>, u64) {
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
            data_guard_handoff: None,
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
            host_kernel_same_resident_basis: false,
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

#[test]
fn complete_seven_owner_accounting_is_supported_but_candidate_must_still_be_disjoint() {
    let (mut request, mut fleet, _, _, _, _) = fixture();
    for epoch in 169..=172 {
        let unit = format!("horizon-qualify-{epoch}-replacement-local2-20261110-v1.service");
        let iid = format!("{epoch:032x}");
        let pid = epoch * 10;
        let b = request.owners[0].admission.clone();
        request.owners.push(Owner {
            epoch,
            unit: unit.clone(),
            invocation_id: iid.clone(),
            main_pid: pid,
            main_start_ticks: 1000 + epoch,
            admission: b.clone(),
            guard_protection: b.clone(),
            data_guard_handoff: None,
        });
        fleet["actual_executing_replays"].as_array_mut().unwrap().push(json!({"epoch":epoch,"unit":{"Id":unit,"InvocationID":iid,"MainPID":pid.to_string(),"ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running"},"in_current_observer":true,"admission":b,"guard_protection":b}));
    }
    fleet["active_producer_count"] = json!(7);
    assert_eq!(owner_rows(&fleet, &request, None).unwrap().len(), 7);
    assert!(owner_rows(&fleet, &request, Some(172)).is_err());
    request.owners.push(Owner {
        epoch: 173,
        unit: "foreign.service".into(),
        invocation_id: "a".repeat(32),
        main_pid: 9999,
        main_start_ticks: 1,
        admission: request.observer.clone(),
        guard_protection: request.observer.clone(),
        data_guard_handoff: None,
    });
    assert!(owner_rows(&fleet, &request, None).is_err());
}
