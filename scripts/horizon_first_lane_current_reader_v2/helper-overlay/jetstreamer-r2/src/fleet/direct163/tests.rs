use super::*;
fn physical(free: u64, memory: u64) -> Value {
    json!({"free_bytes":free,"available_memory_bytes":memory,"free_inodes":131072,"vm_max_map_count":4194304,"sampled_unix_micros":1000000,"pressure_total_usec":{"cpu":0,"memory":0,"io":0}})
}
#[test]
fn full_fit_charges_candidate_data_and_auxiliary_memory_once() {
    let b = json!({"candidate_scheduling_total_bytes":197768759296u64});
    let p = physical(5u64 << 40, 500u64 << 30);
    let mut after = p.clone();
    after["sampled_unix_micros"] = json!(2000000);
    let required = fits(&b, 4u64 << 40, 810902843392, &p, &after).unwrap();
    assert_eq!(required, (4u64 << 40) + (768u64 << 30));
    let mut low = after.clone();
    low["free_bytes"] = json!(required - 1);
    assert!(fits(&b, 4u64 << 40, 810902843392, &p, &low).is_err());
}
#[test]
fn full_fit_rejects_physical_pressure_inodes_and_vma_regression() {
    let b = json!({"candidate_scheduling_total_bytes":197768759296u64});
    let p = physical(5u64 << 40, 500u64 << 30);
    for (k, v) in [
        ("available_memory_bytes", json!(1)),
        ("free_inodes", json!(131071)),
        ("vm_max_map_count", json!(4194303)),
    ] {
        let mut bad = p.clone();
        bad["sampled_unix_micros"] = json!(2000000);
        bad[k] = v;
        assert!(fits(&b, 4u64 << 40, 810902843392, &p, &bad).is_err(), "{k}");
    }
}
fn claims() -> Value {
    json!({"current_unique_owner_census":[{"unit":"original.service","iid":"a"}],"current_owner_hard_limits":{"original.service":{"MemoryMax":"1"}},"active_peer_allocations":[],"projected_obligations":[],"current_replay_cpu_quota_micros":16000000,"protected_existing_DATA_bytes":4202184371152u64,"standing_frontier_bytes":1,"confirmed_DATA_floor_bytes":1,"active_trial_memory_promises_bytes":0})
}
#[test]
fn full_admission_never_carries_a_changed_or_unknown_claim_into_old_typed_views() {
    let a = claims();
    unchanged_claims(&a, &a).unwrap();
    for k in [
        "current_unique_owner_census",
        "current_owner_hard_limits",
        "active_peer_allocations",
        "projected_obligations",
        "current_replay_cpu_quota_micros",
        "protected_existing_DATA_bytes",
        "standing_frontier_bytes",
        "confirmed_DATA_floor_bytes",
        "active_trial_memory_promises_bytes",
    ] {
        let mut b = a.clone();
        b[k] = json!(["foreign workload"]);
        assert!(unchanged_claims(&a, &b).is_err(), "{k}");
        b = a.clone();
        b.as_object_mut().unwrap().remove(k);
        assert!(unchanged_claims(&a, &b).is_err(), "missing {k}");
    }
}
#[test]
fn full_admission_preserves_observed_pressure_thresholds() {
    let good = json!({"host_global_pressure":{"cross_sample":{"status":"observed","elapsed_millis":1000,"counter_delta_usec":{"memory.full_total_usec":100000,"cpu.some_total_usec":500000,"io.full_total_usec":100000}}}});
    pressures(&good).unwrap();
    for k in [
        "memory.full_total_usec",
        "cpu.some_total_usec",
        "io.full_total_usec",
    ] {
        let mut b = good.clone();
        b["host_global_pressure"]["cross_sample"]["counter_delta_usec"][k] = json!(1000001);
        assert!(pressures(&b).is_err(), "{k}");
    }
}
#[test]
fn original_selector_completion_cannot_borrow_a_failed_or_unreaped_invocation() {
    let binding = Bound {
        path: "/bound.json".into(),
        sha256: "a".repeat(64),
    };
    let outer = json!({"schema":"terminal199-parent-memory-selector-original-execution-v1","capability_only":false,"invocation_id":"b".repeat(32)});
    let done = json!({"schema":"epoch163-parent-memory-selector-original-completion-v1","receipt":binding,"invocation_id":"b".repeat(32),"result":"success","exec_main_status":0,"original_outer_reaped":true,"original_cgroup_empty":true,"original_descriptors_drained":true});
    original_selection(&outer, &done, &binding, "memory").unwrap();
    for k in [
        "original_outer_reaped",
        "original_cgroup_empty",
        "original_descriptors_drained",
    ] {
        let mut bad = done.clone();
        bad[k] = json!(false);
        assert!(
            original_selection(&outer, &bad, &binding, "memory").is_err(),
            "{k}"
        );
    }
    let mut bad = done;
    bad["invocation_id"] = json!("c".repeat(32));
    assert!(original_selection(&outer, &bad, &binding, "memory").is_err());
}

#[test]
fn current_pressure_rejects_regression_and_busy_new_resource_windows() {
    let budget = json!({"candidate_scheduling_total_bytes":197768759296u64});
    let a = physical(5u64 << 40, 500u64 << 30);
    let mut b = a.clone();
    b["sampled_unix_micros"] = json!(2000000);
    fits(&budget, 4u64 << 40, 810902843392, &a, &b).unwrap();
    for resource in ["cpu", "memory", "io"] {
        let mut bad = b.clone();
        bad["pressure_total_usec"][resource] = json!(1000000);
        assert!(
            fits(&budget, 4u64 << 40, 810902843392, &a, &bad).is_err(),
            "{resource}"
        );
    }
    b["sampled_unix_micros"] = json!(999999);
    assert!(fits(&budget, 4u64 << 40, 810902843392, &a, &b).is_err());
}

#[test]
fn capacity_preserves_physical_host_ceiling_cpu_promises_affinity_and_proven_point() {
    let budget = json!({"total_scheduling_reserved_bytes":745722857472u64,
        "scheduling_headroom_bytes":65179985920u64,
        "total_conservative_hard_exposure_bytes":756796882944u64});
    let accounting = json!({"current_replay_cpu_quota_micros":8_000_000,
        "current_unique_owner_census":[{"role":"diagnostic-replay"}]});
    let a = json!({"available_logical_cpus":32});
    capacity(&budget, &accounting, 810902843392, &a, &a).unwrap();
    assert!(
        capacity(
            &json!({"total_scheduling_reserved_bytes":810902843393u64}),
            &accounting,
            810902843392,
            &a,
            &a
        )
        .is_err()
    );
    let narrow = json!({"available_logical_cpus":18});
    assert!(capacity(&budget, &accounting, 810902843392, &narrow, &narrow).is_err());
    assert!(capacity(&budget, &accounting, 810902843392, &a, &narrow).is_err());
    let busy = json!({"current_replay_cpu_quota_micros":8_000_000,
        "current_unique_owner_census":[{"role":"diagnostic-replay"},{"role":"replay-producer"}]});
    assert!(capacity(&budget, &busy, 810902843392, &a, &a).is_err());
    let overflow =
        json!({"current_replay_cpu_quota_micros":u64::MAX,"current_unique_owner_census":[]});
    assert!(capacity(&budget, &overflow, 810902843392, &a, &a).is_err());
}
