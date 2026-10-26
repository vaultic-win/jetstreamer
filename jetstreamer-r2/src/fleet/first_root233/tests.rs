//! Positive examples and changed-evidence rejection; no production paths or I/O.
use super::*;
// An inherited legacy guard in these fixtures, never a new profile minimum.
const FLOOR: u64 = 2_000_000_000_000;
fn admission_fixture() -> Value {
    let minimum = FLOOR;
    let total = 1_200_000_000_000u64;
    let growth = 10_000_000_000u64;
    let floor = (480u64 << 30).max(total.div_ceil(10));
    let needed = floor + growth + MEMORY + (2u64 << 30);
    let row = json!({"host_total_memory_bytes":total,"protected_existing_memory_growth_bytes":growth,
        "candidate_memory_max_bytes":MEMORY,"minimum_available_memory_bytes":needed,
        "sampled_available_memory_bytes":needed+100,"actual_available_memory_bytes":needed+1,
        "first_root233_memory_policy":{"schema":"jetstreamer-first-root233-native223-memory-policy-v1",
            "native223_unit":prefix223_native20::UNIT,
            "native223_floor_state":"live","native223_release_proof":null,
            "native223_invocation_id":"e70aaf097e7c4583b216aba454145910","effective_available_memory_floor_bytes":floor,
            "candidate_producer_hard_memory_bytes":MEMORY,"candidate_guard_and_metadata_hard_memory_bytes":2u64<<30,
            "protected_existing_hard_memory_growth_bytes":growth,"required_available_memory_bytes":needed,"floor_counted_once":true}});
    let observer = json!({"path":"/sealed/observer.json","sha256":"a".repeat(64)});
    let fleet = json!({"path":"/sealed/fleet.json","sha256":"b".repeat(64)});
    let mut a = scope();
    a["schema"] = json!("jetstreamer-private-first-root233-admission-v1");
    a["admitted"] = json!(true);
    a["producer_started"] = json!(false);
    a["resource_samples_taken"] = json!(0);
    a["observer"] = observer.clone();
    a["fleet"] = fleet.clone();
    a["recorded_unix_seconds"] = json!(1000);
    a["guard_minimum_free_bytes"] = json!(minimum + DRAINAGE);
    a["capacity"] = json!({"schema":"jetstreamer-horizon-maintenance-capacity-v1",
        "minimum_free_bytes":minimum,"century_floor_bytes":250_000_000_000u64,
        "protected_remaining_growth_bytes":1_000_000_000_000u64,"maximum_existing_guard_floor_bytes":FLOOR,
        "additional_bytes":DISK_RESERVATION,"required_initial_free_bytes":minimum+DISK_RESERVATION,
        "sampled_available_bytes":minimum+DISK_RESERVATION+100,"actual_available_bytes":minimum+DISK_RESERVATION+1,
        "all_live_growth_and_century_floor_protected":true,"capped_peer_accounting":{
            "producer_and_independent_guard_hard_memory_charged":true,"allocation_credit_bytes":0},
        "observer":observer,"fleet":fleet,"memory_before":row,"memory_after":row,
        "unit_census_before":{"original":{"InvocationID":"actual"}},
        "unit_census_after":{"original":{"InvocationID":"actual"}},
        "unit_census_after_memory_and_guard_checks":{"original":{"InvocationID":"actual"}},"recorded_unix_seconds":999});
    a["capacity"]["bracketed_obligations"] = json!({"disk_growth_before_bytes":999_000_000_000u64,
        "disk_growth_after_bytes":1_000_000_000_000u64,"protected_disk_growth_bytes":1_000_000_000_000u64,
        "hard_memory_growth_before_bytes":growth,"hard_memory_growth_after_bytes":growth,
        "protected_hard_memory_growth_bytes":growth,"complete_policy":{"complete_required_memory_bytes":needed}});
    deny_fields(&mut a);
    a
}
fn guard_fixture(a: &Value) -> (Value, Value) {
    let invocation = "c".repeat(32);
    let p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":invocation,
        "filesystem":"/","worker_root":ROOT,"receipt_directory":GUARD_RECEIPTS,
        "minimum_free_bytes":a["guard_minimum_free_bytes"],"maximum_root_physical_bytes":TREE_STOP,"maximum_worker_vmas":3500000});
    let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","recorded_unix_seconds":1010,
        "producer_invocation_id":invocation,"guard_sha256":GUARD_SHA,"plan_sha256":"d".repeat(64),
        "producer":{"invocation_id":invocation,"restarts":0,"cgroup":format!("/system.slice/{UNIT}"),
            "active":"active","sub":"running","pid":40},"producer_stop_enabled":true,
        "maximum_worker_vmas":3500000,"maximum_root_physical_bytes":TREE_STOP,
        "root_physical_observation":{"maximum_physical_bytes":TREE_STOP,"exceeds_budget":false,"conservative_physical_bytes":100},
        "minimum_free_bytes":a["guard_minimum_free_bytes"],"available_bytes":a["guard_minimum_free_bytes"].as_u64().unwrap()+1,
        "workers":[[42,125]],"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,
        "canary_target_error":null,"target_handoff_error":null,"remote_mutations":false,"r2_mutations":false});
    (p, g)
}
#[test]
fn saved_admission_retains_every_hard_growth_floor_and_original_census() {
    let a = admission_fixture();
    admission::validate_saved(&a).unwrap();
    for (path, value) in [
        (
            "/capacity/maximum_existing_guard_floor_bytes",
            json!(FLOOR + 1),
        ),
        (
            "/capacity/protected_remaining_growth_bytes",
            json!(2_000_000_000_000u64),
        ),
        (
            "/capacity/actual_available_bytes",
            json!(FLOOR + DISK_RESERVATION - 1),
        ),
        (
            "/capacity/memory_before/first_root233_memory_policy/effective_available_memory_floor_bytes",
            json!(120_000_000_000u64),
        ),
        (
            "/capacity/memory_after/protected_existing_memory_growth_bytes",
            json!(20_000_000_000u64),
        ),
        (
            "/capacity/memory_after/actual_available_memory_bytes",
            json!(MEMORY),
        ),
        (
            "/capacity/unit_census_after/original/InvocationID",
            json!("replacement"),
        ),
        ("/recorded_unix_seconds", json!(1100)),
        ("/publication_authorized", json!(true)),
    ] {
        let mut bad = a.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(admission::validate_saved(&bad).is_err(), "{path}");
    }
}
#[test]
fn a_first_guard_proves_actual_identity_and_never_accepts_a_target_stop() {
    let a = admission_fixture();
    let (p, g) = guard_fixture(&a);
    assert_eq!(
        capture::guard_valid(&a, &g, &p, &"d".repeat(64), 1020).unwrap(),
        "c".repeat(32)
    );
    for (path, value) in [
        ("/producer/invocation_id", json!("e".repeat(32))),
        ("/producer/restarts", json!(1)),
        ("/workers", json!([])),
        ("/workers", json!([[42, 1], [43, 1]])),
        ("/workers/0/1", json!(3500000)),
        ("/root_physical_observation/exceeds_budget", json!(true)),
        (
            "/root_physical_observation/conservative_physical_bytes",
            json!(TREE_STOP + 1),
        ),
        ("/recorded_unix_seconds", json!(999)),
        ("/trip_reason", json!("root-physical-budget")),
        (
            "/root_physical_observation_error",
            json!("scan unavailable"),
        ),
    ] {
        let mut bad = g.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(
            capture::guard_valid(&a, &bad, &p, &"d".repeat(64), 1020).is_err(),
            "{path}"
        );
    }
    let mut target = p.clone();
    target["bounded_canary"] = json!({"target_stop_intent":"fake"});
    assert!(capture::guard_valid(&a, &g, &target, &"d".repeat(64), 1020).is_err());
    let mut lower = p;
    lower["minimum_free_bytes"] = json!(FLOOR);
    assert!(capture::guard_valid(&a, &g, &lower, &"d".repeat(64), 1020).is_err());
}
#[test]
fn copied_worker_requires_the_actual_pid_lifetime_cpu_mask_and_digest() {
    let (_, g) = guard_fixture(&admission_fixture());
    let w = json!({"pid":42,"executable":format!("{ROOT}/scratch/unique/bound-worker/historical-worker"),
        "sha256":WORKER_SHA,"uid":1000,"nlink":1,"bytes":6511712,"mode":0o555,
        "cgroup":format!("0::/system.slice/{UNIT}"),"cpus_allowed_list":"8-15","effective_cgroup_cpus":"8-15",
        "process_stat_before":"12345","process_stat_after":"12345"});
    capture::worker_saved(&w, &g).unwrap();
    for (key, value) in [
        ("pid", json!(43)),
        ("sha256", json!("a".repeat(64))),
        ("executable", json!("/other/bound-worker/historical-worker")),
        ("cpus_allowed_list", json!("0-7")),
        ("effective_cgroup_cpus", json!("0-127")),
        ("process_stat_after", json!("12346")),
        ("mode", json!(0o755)),
    ] {
        let mut bad = w.clone();
        bad[key] = value;
        assert!(capture::worker_saved(&bad, &g).is_err(), "{key}");
    }
}
#[test]
fn roster_rejects_an_untyped_peer_and_raw_owner_replacement() {
    let row = prefix223_live_peer::fixture_row();
    let owner = row["producer"].clone();
    let f = json!({"active":[row],"unit_census":{(prefix223_native20::UNIT):owner}});
    admission::roster(&f).unwrap();
    let mut bad = f.clone();
    bad["active"].as_array_mut().unwrap().push(json!({"epoch":204,
        "producer":{"Id":"horizon-qualify-204-capped-continuation-v3.service","InvocationID":"d".repeat(32)}}));
    assert!(admission::roster(&bad).is_err());
    let mut bad = f;
    bad["unit_census"][prefix223_native20::UNIT]["InvocationID"] = json!("replacement");
    assert!(admission::roster(&bad).is_err());
}

#[test]
fn resource_roster_accepts_an_expanded_typed_scope_without_a_fixed_lane_count() {
    let native = prefix223_live_peer::fixture_row();
    let rows = vec![
        native,
        json!({"epoch":225,"producer":{"Id":"horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
            "InvocationID":"4cd76ae1353a4411885b997f04306402","NRestarts":"0"}}),
        json!({"epoch":209,"phase":"diagnostic-qualification","ordinary_replay_claim":false,
            "producer":{"Id":singleton209::UNIT,"InvocationID":"1bf0db73ccd44c2c90461889498d4f82","NRestarts":"0"}}),
        json!({"epoch":210,"phase":"diagnostic-qualification","ordinary_replay_claim":false,
            "producer":{"Id":singleton210::UNIT,"InvocationID":"d".repeat(32),"NRestarts":"0"}}),
    ];
    let census = rows
        .iter()
        .map(|r| {
            let owner = &r["producer"];
            (owner["Id"].as_str().unwrap().to_string(), owner.clone())
        })
        .collect::<serde_json::Map<_, _>>();
    let f = json!({"active":rows,"unit_census":census});
    admission::roster(&f).unwrap();
    // This checks roster eligibility only. Actual admission still authenticates
    // every full launch/frame/guard and reserves every owner's complete envelope.
}

#[test]
fn a_new_lane_waits_for_a_complete_clean_expanded_observation_window() {
    let invocation = "a".repeat(32);
    let owner = json!({"Id":"peer.service","InvocationID":invocation});
    let f = json!({"active":[{"producer":owner}]});
    let worker =
        json!({"pid":42,"matching_workers":1,"executable_beneath_bound_scratch":true,"vmas":100});
    let row = json!({"producer_before":{"invocation_id":invocation,"restarts":0},
        "producer_after":{"unit":"peer.service","invocation_id":invocation,"restarts":0},
        "invocation_binding_stable":true,"worker_before":worker,"worker_after":worker,
        "cross_sample":{"elapsed_seconds":1800,"producer_cgroup_counter_delta":{
            "memory_events.max":0,"memory_events.oom":0,"memory_events.oom_kill":0,"memory_events.oom_group_kill":0}}});
    let o = json!({"cadence":{"observed_interval_seconds":1800},"replays":[],
        "diagnostic_replays":[{"status":"observed","observation":row}],
        "host_global_pressure":{"cross_sample":{"status":"observed","elapsed_millis":1800000,
            "counter_delta_usec":{"memory.full_total_usec":0,"cpu.some_total_usec":0,"io.full_total_usec":0}}}});
    admission::clean_expanded_window(&f, &o).unwrap();
    for (path, value) in [
        ("/cadence/observed_interval_seconds", json!(1799)),
        (
            "/diagnostic_replays/0/observation/cross_sample/elapsed_seconds",
            json!(100),
        ),
        (
            "/diagnostic_replays/0/observation/producer_before/invocation_id",
            json!("b".repeat(32)),
        ),
        (
            "/diagnostic_replays/0/observation/cross_sample/producer_cgroup_counter_delta/memory_events.oom",
            json!(1),
        ),
        (
            "/diagnostic_replays/0/observation/worker_before/vmas",
            json!(3500000),
        ),
        (
            "/diagnostic_replays/0/observation/worker_after/matching_workers",
            json!(0),
        ),
        ("/diagnostic_replays/0/status", json!("unavailable")),
        (
            "/host_global_pressure/cross_sample/counter_delta_usec/memory.full_total_usec",
            json!(180000001),
        ),
    ] {
        let mut bad = o.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(
            admission::clean_expanded_window(&f, &bad).is_err(),
            "{path}"
        );
    }
}
#[test]
fn the_same_prefix_cannot_be_relabelled_as_another_epoch_or_complete_archive() {
    let (claim, v) = launch_fixture();
    assert!(launch_matches(&claim, &v));
    for (key, value) in [
        ("terminal_root_slot", json!(101087999)),
        ("output_slot_count", json!(432000)),
        ("uncovered_suffix_slots", json!(0)),
        ("full_epoch_qualified", json!(true)),
        ("remote_mutations", json!(true)),
    ] {
        let mut bad = v.clone();
        bad[key] = value;
        assert!(!launch_matches(&claim, &bad), "{key}");
    }
    let foreign = DiagnosticClaim {
        epoch: 234,
        ..claim
    };
    assert!(!launch_matches(&foreign, &v));
}

#[test]
fn kernel_caps_require_actual_page_rounding_and_the_exact_cpu_budget() {
    let v = json!({"page_size_bytes":4096,"memory_max_bytes":224999997440u64,
        "memory_high_bytes":149999996928u64,"memory_swap_max_bytes":0,"tasks_max":512,
        "cpu_quota_microseconds":800000,"cpu_period_microseconds":100000,"effective_cpus":"8-15"});
    capture::kernel_saved(&v).unwrap();
    for (key, value) in [
        ("memory_max_bytes", json!(MEMORY)),
        ("memory_high_bytes", json!(150000000000u64)),
        ("memory_swap_max_bytes", json!(1)),
        ("tasks_max", json!(1024)),
        ("cpu_quota_microseconds", json!(800001)),
        ("effective_cpus", json!("0-7")),
        ("page_size_bytes", json!(0)),
    ] {
        let mut bad = v.clone();
        bad[key] = value;
        assert!(capture::kernel_saved(&bad).is_err(), "{key}");
    }
}

#[test]
fn safe_bracket_maximum_accepts_increased_obligations_only_when_all_samples_fit() {
    let mut a = admission_fixture();
    let before = 10_000_000_000u64;
    let after = 11_000_000_000u64;
    let needed = (480u64 << 30) + after + MEMORY + (2u64 << 30);
    a["capacity"]["bracketed_obligations"]["hard_memory_growth_after_bytes"] = json!(after);
    a["capacity"]["bracketed_obligations"]["protected_hard_memory_growth_bytes"] = json!(after);
    a["capacity"]["bracketed_obligations"]["complete_policy"]["complete_required_memory_bytes"] =
        json!(needed);
    let row = &mut a["capacity"]["memory_after"];
    row["protected_existing_memory_growth_bytes"] = json!(after);
    row["minimum_available_memory_bytes"] = json!(needed);
    row["first_root233_memory_policy"]["protected_existing_hard_memory_growth_bytes"] =
        json!(after);
    row["first_root233_memory_policy"]["required_available_memory_bytes"] = json!(needed);
    for key in ["memory_before", "memory_after"] {
        a["capacity"][key]["sampled_available_memory_bytes"] = json!(needed + 1);
        a["capacity"][key]["actual_available_memory_bytes"] = json!(needed + 1);
    }
    admission::validate_saved(&a).unwrap();
    a["capacity"]["memory_before"]["actual_available_memory_bytes"] =
        json!(needed - (after - before));
    assert!(admission::validate_saved(&a).is_err());
}

#[test]
fn sandbox_refuses_thread_expansion_cpu_reuse_or_an_extra_write_root() {
    let mut p = [
        ("Type", "exec"),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "150000000000"),
        ("MemoryMax", "225000000000"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("TasksMax", "512"),
        ("RuntimeMaxUSec", "3d"),
        ("LimitFSIZE", "137438953472"),
        ("LimitFSIZESoft", "137438953472"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("ProtectControlGroups", "yes"),
        ("NoNewPrivileges", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateNetwork", "no"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
        ("ReadWritePaths", ROOT),
        ("OOMPolicy", "kill"),
        ("OOMScoreAdjust", "1000"),
        ("UMask", "0077"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("AllowedCPUs", "8-15"),
        ("CPUAffinity", "8-15"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect::<BTreeMap<_, _>>();
    p.insert(
        "Environment".into(),
        environment().into_iter().collect::<Vec<_>>().join(" "),
    );
    p.insert(
        "ExecStart".into(),
        format!("{} ; ignore_errors=no", command()),
    );
    sandbox(&p).unwrap();
    for (key, value) in [
        ("AllowedCPUs", "0-7"),
        ("CPUAffinity", "0-7"),
        ("CPUQuotaPerSecUSec", "16s"),
        ("MemoryMax", "256000000000"),
        ("ReadWritePaths", "/home/ubuntu/.jetstreamer-private"),
        ("CapabilityBoundingSet", "cap_dac_override"),
    ] {
        let mut bad = p.clone();
        bad.insert(key.into(), value.into());
        assert!(sandbox(&bad).is_err(), "{key}");
    }
    let mut bad = p;
    bad.get_mut("Environment")
        .unwrap()
        .push_str(" SOLANA_RAYON_THREADS=64");
    assert!(sandbox(&bad).is_err());
}

#[test]
fn new_profile_uses_century_mean_and_growth_without_a_fixed_floor_and_retains_legacy_guards() {
    for (century, growth, legacy, expected) in [
        (250_000_000_000u64, 0u64, 0u64, 250_000_000_000u64),
        (250_000_000_000, 1_000_000_000_000, 0, 1_250_000_000_000),
        (
            250_000_000_000,
            1_000_000_000_000,
            2_000_000_000_000,
            2_000_000_000_000,
        ),
    ] {
        let mut a = admission_fixture();
        let required = expected + DISK_RESERVATION;
        a["guard_minimum_free_bytes"] = json!(expected + DRAINAGE);
        let c = &mut a["capacity"];
        c["century_floor_bytes"] = json!(century);
        c["protected_remaining_growth_bytes"] = json!(growth);
        c["maximum_existing_guard_floor_bytes"] = json!(legacy);
        c["minimum_free_bytes"] = json!(expected);
        c["required_initial_free_bytes"] = json!(required);
        c["sampled_available_bytes"] = json!(required + 1);
        c["actual_available_bytes"] = json!(required + 1);
        c["bracketed_obligations"]["disk_growth_before_bytes"] = json!(growth);
        c["bracketed_obligations"]["disk_growth_after_bytes"] = json!(growth);
        c["bracketed_obligations"]["protected_disk_growth_bytes"] = json!(growth);
        admission::validate_saved(&a).unwrap();
        let (p, g) = guard_fixture(&a);
        capture::guard_valid(&a, &g, &p, &"d".repeat(64), 1020).unwrap();
        let mut bad = a.clone();
        bad["capacity"]["century_floor_bytes"] = json!(0);
        assert!(admission::validate_saved(&bad).is_err());
        let mut bad = a.clone();
        bad["capacity"]["minimum_free_bytes"] = json!(expected - 1);
        assert!(admission::validate_saved(&bad).is_err());
        let mut bad = a.clone();
        bad["guard_minimum_free_bytes"] = json!(expected + DRAINAGE - 1);
        assert!(admission::validate_saved(&bad).is_err());
        let mut bad = a;
        bad["capacity"]["maximum_existing_guard_floor_bytes"] = json!(expected + 1);
        assert!(admission::validate_saved(&bad).is_err());
    }
}
