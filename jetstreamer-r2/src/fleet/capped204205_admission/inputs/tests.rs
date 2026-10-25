use super::*;
fn binding(path: &str) -> Value {
    json!({"path":path,"sha256":"a".repeat(64)})
}
fn spec() -> Spec {
    serde_json::from_value(json!({"schema":"jetstreamer-capped204205-continuation-admission-spec-v1",
    "producer_plan":binding("/sealed/plan.json"),"resource_proposal":binding("/sealed/proposal.json"),
    "resource_capability":binding("/sealed/capability.json"),"source_closure":binding("/sealed/source.json"),
    "producer":binding("/sealed/node"),"control":binding("/sealed/control"),
    "observer":binding("/sealed/observer.json"),"fleet":binding("/sealed/fleet.json"),"fleet_observation_readable_mirror":"/sealed/fleet-observation.json","protected_guards":{},"output":"/sealed/admission.json"})).unwrap()
}
fn fixture() -> (Spec, Value, Value) {
    let s = spec();
    let mut p = json!({"schema":"jetstreamer-capped204205-continuation-plan-v1","epoch":204,
        "node_sha256":s.producer.sha256,"guard_sha256":s.control.sha256,
        "producer_unit":"horizon-qualify-204-capped-continuation-fixture.service",
        "guard_unit":"horizon-guard-204-capped-continuation-fixture.service",
        "run_root":"/home/ubuntu/.jetstreamer-private/checkpoint-continuation-204-fixture",
        "protected_existing_floor_bytes":2_000_000_000_000u64,"candidate_incremental_peak_bytes":256u64<<30,
        "maximum_root_physical_bytes":240u64<<30,"maximum_process_rss_bytes":150u64<<30,
        "maximum_worker_vmas":3500000,"maximum_stage_millis":86400000,
        "prefix_bytes":100000000000u64,"prefix_archive":binding("/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1/output/epoch-204-prefix.jet"),
        "source_capture":binding("/sealed/capture.json"),"restart_snapshot":binding("/sealed/snapshot.tar.zst"),
        "worker":binding("/sealed/worker"),"metadata":{}});
    for key in [
        "original_launch",
        "producer_result",
        "terminal_properties",
        "manager_journal",
        "prefix_manifest",
        "prefix_validation",
    ] {
        p["metadata"][key] = binding(&format!("/sealed/{key}.json"));
    }
    let mut r = json!({"schema":"jetstreamer-capped204205-resource-proposal-v1","producer_plan":private157::binding(&s.producer_plan),
        "source_closure":private157::binding(&s.source_closure),"resource_capability":private157::binding(&s.resource_capability),
        "external_control_metadata_bytes":16<<20,"guard_memory_max_bytes":1<<30,
        "kernel_limits":{"requested_memory_max_bytes":225000000000u64,"requested_memory_high_bytes":150000000000u64,
            "memory_swap_max_bytes":0,"tasks_max":512,"cpu_quota_usec_per_second":8000000,"runtime_max_usec":86400000000u64}});
    for key in [
        "epoch",
        "node_sha256",
        "guard_sha256",
        "producer_unit",
        "guard_unit",
        "run_root",
        "protected_existing_floor_bytes",
        "candidate_incremental_peak_bytes",
        "maximum_root_physical_bytes",
        "maximum_process_rss_bytes",
        "maximum_worker_vmas",
    ] {
        r[key] = p[key].clone();
    }
    for key in [
        "ordinary_replay_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        r[key] = json!(false);
    }
    (s, p, r)
}
#[test]
fn frozen_proposal_rejects_native_only_or_underreserved_paths_and_invalid_kernel_caps() {
    let (s, p, r) = fixture();
    proposal(&s, &p, &r).unwrap();
    for (pointer, value) in [
        ("/candidate_incremental_peak_bytes", json!(192u64 << 30)),
        ("/external_control_metadata_bytes", json!(0)),
        ("/maximum_root_physical_bytes", json!(1)),
        ("/kernel_limits/requested_memory_max_bytes", json!(1)),
        (
            "/kernel_limits/requested_memory_high_bytes",
            json!(u64::MAX),
        ),
        ("/kernel_limits/memory_swap_max_bytes", json!(1)),
        ("/kernel_limits/tasks_max", json!(513)),
        ("/kernel_limits/cpu_quota_usec_per_second", json!(8000001)),
        ("/kernel_limits/runtime_max_usec", json!(u64::MAX)),
        ("/publication_authorized", json!(true)),
        ("/producer_plan/sha256", json!("b".repeat(64))),
    ] {
        let mut bad = r.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(proposal(&s, &p, &bad).is_err(), "{pointer}");
    }
}
#[test]
fn missing_or_static_only_capability_never_becomes_enforcement_proof() {
    let (s, p, r) = fixture();
    assert!(capability_value(&s, &p, &r, &Value::Null).is_err());
    let mut good = json!({"schema":"jetstreamer-capped204205-resource-capability-v1","capability_kind":"disposable-equivalent-sandbox-guard",
        "epoch":204,"producer":private157::binding(&s.producer),"control":private157::binding(&s.control),
        "source_closure":private157::binding(&s.source_closure),"kernel_limits":r["kernel_limits"],
        "guard_memory_max_bytes":r["guard_memory_max_bytes"],"maximum_root_physical_bytes":p["maximum_root_physical_bytes"],
        "maximum_process_rss_bytes":p["maximum_process_rss_bytes"],"maximum_worker_vmas":3500000,
        "bounded_enforcement_proven":true,"observed_production_peak_claimed":false,"native_initialized":false,"archive_body_read":false,
        "stages":["prefix_validation","native_restore","suffix_validation","assembly"],
        "probe_unit":"horizon-capped204205-resource-probe-fixture.service","probe_invocation_id":"b".repeat(32),"host_machine_id":"c".repeat(32),"enforcement":{}});
    for key in [
        "ordinary_replay_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        good[key] = json!(false);
    }
    for key in [
        "whole_process_tree_bounded",
        "whole_root_bounded",
        "guard_trip_stops_exact_invocation",
        "unproven_guard_blocks_stage_entry",
        "monotonic_stage_deadlines",
        "restore_suffix_assembly_overlap_included",
        "native_barrier_precedes_entries",
        "no_canonical_sidecar_or_publication",
    ] {
        good["enforcement"][key] = json!(true);
    }
    capability_value(&s, &p, &r, &good).unwrap();
    for (pointer, value) in [
        ("/bounded_enforcement_proven", json!(false)),
        ("/capability_kind", json!("static-plan-check")),
        ("/enforcement/whole_process_tree_bounded", json!(false)),
        (
            "/enforcement/guard_trip_stops_exact_invocation",
            json!(false),
        ),
        ("/kernel_limits/requested_memory_max_bytes", json!(1)),
        ("/probe_invocation_id", json!("0".repeat(32))),
        ("/source_closure/sha256", json!("b".repeat(64))),
        ("/publication_authorized", json!(true)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(capability_value(&s, &p, &r, &bad).is_err(), "{pointer}");
    }
}
fn policy_fixture(s: &Spec, p: &Value) -> Value {
    let (old, iid) = original(204).unwrap();
    let mut input = json!({"schema":"jetstreamer-capped204205-native-input-policy-v1","epoch":204,"original_unit":old,
        "original_invocation_id":iid,"restart_snapshot":{"path":p["restart_snapshot"]["path"],"sha256":p["restart_snapshot"]["sha256"],"bytes":8225957010u64},
        "native_worker_must_rehash_full_snapshot":true,"actual_suffix_must_repeat_native_barrier":true});
    for (key, member) in [
        ("original_launch_sha256", "original_launch"),
        ("producer_result_sha256", "producer_result"),
        ("terminal_properties_sha256", "terminal_properties"),
        ("manager_journal_sha256", "manager_journal"),
        ("prefix_manifest_sha256", "prefix_manifest"),
        ("prefix_validation_sha256", "prefix_validation"),
    ] {
        input[key] = p["metadata"][member]["sha256"].clone();
    }
    for key in [
        "current_source_idleness_proven",
        "resource_admission_passed",
        "native_initialized",
        "suffix_execution_authorized",
        "assembly_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        input[key] = json!(false);
    }
    let mut v = json!({"schema":"jetstreamer-capped204205-admission-inputs-v1","validated":true,"epoch":204,
        "plan_sha256":s.producer_plan.sha256,"self_sha256":s.control.sha256,"proposal":p,
        "source_capture_sha256":p["source_capture"]["sha256"],"input_policy":input,"manifest_content_sha256":"c".repeat(64),
        "resource_samples_taken":0,"source_idle_censuses_taken":1,
        "source_idle":{"schema":"jetstreamer-capped204205-source-idle-v1","epoch":204,"unit":old,"historical_invocation_id":iid,
            "source_root":"/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1",
            "current_source_idle":true,"process_reference_census":{"references":[]},"resource_sample_performed":false,
            "publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false},
        "archive_identity":{"device":1,"inode":2,"bytes":p["prefix_bytes"],"uid":0,"links":1,"mode":0o100444},
        "retained_snapshot_identity":{"device":1,"inode":3,"bytes":8225957010u64,"uid":0,"links":1,"mode":0o100444}});
    for key in [
        "archive_body_read",
        "snapshot_body_read",
        "native_initialized",
        "fresh_admission_passed",
        "guard_proven",
        "suffix_execution_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        v[key] = json!(false);
    }
    v
}
#[test]
fn genuine_source_policy_keeps_reader_native_barrier_and_actual_idleness() {
    let (s, p, _) = fixture();
    let good = policy_fixture(&s, &p);
    policy(&s, &p, &good).unwrap();
    for (pointer, value) in [
        ("/source_idle/current_source_idle", json!(false)),
        (
            "/source_idle/process_reference_census/references",
            json!(["writer"]),
        ),
        (
            "/input_policy/prefix_validation_sha256",
            json!("b".repeat(64)),
        ),
        (
            "/input_policy/actual_suffix_must_repeat_native_barrier",
            json!(false),
        ),
        ("/archive_identity/links", json!(2)),
        ("/archive_identity/uid", json!(1000)),
        ("/proposal/epoch", json!(205)),
        ("/fresh_admission_passed", json!(true)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(policy(&s, &p, &bad).is_err(), "{pointer}");
    }
    stable_policies(&good, &good).unwrap();
    let mut changed = good.clone();
    changed["archive_identity"]["inode"] = json!(4);
    assert!(stable_policies(&good, &changed).is_err());
}
#[test]
fn generated_probe_result_binds_real_kernel_controls_and_exact_artifact() {
    let (_s, _p, r) = fixture();
    let probe = BoundFile {
        path: "/sealed/probe".into(),
        sha256: "d".repeat(64),
    };
    let plan = BoundFile {
        path: "/sealed/probe-plan.json".into(),
        sha256: "e".repeat(64),
    };
    let cap = json!({"epoch":204,"probe_unit":"horizon-capped204205-resource-probe-fixture.service",
        "probe_invocation_id":"c".repeat(32),"enforcement":{"generated":true},"kernel_limits":r["kernel_limits"],
        "guard_memory_max_bytes":1<<30});
    let mut result = json!({"schema":"jetstreamer-capped204205-resource-probe-result-v1","self_sha256":probe.sha256,
        "plan_sha256":plan.sha256,"probe_unit":cap["probe_unit"],"probe_invocation_id":cap["probe_invocation_id"],
        "epoch":204,"enforcement":cap["enforcement"],"kernel_limits":cap["kernel_limits"],"bounded_enforcement_proven":true,
        "native_initialized":false,"archive_body_read":false,
        "actual_kernel":{"host_page_size_bytes":4096,"requested_memory_max_bytes":225000000000u64,
            "requested_memory_high_bytes":150000000000u64,"kernel_memory_max_bytes":224999997440u64,
            "kernel_memory_high_bytes":149999996928u64,"memory_swap_max_bytes":0,"tasks_max":512,
            "runtime_max_usec":86400000000u64,"guard_requested_memory_max_bytes":1<<30,"guard_kernel_memory_max_bytes":1<<30,
            "cpu_period_usec":100000,"cpu_quota_usec":800000}});
    for key in [
        "ordinary_replay_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        result[key] = json!(false);
    }
    probe_result(&cap, &probe, &plan, &result).unwrap();
    for (pointer, value) in [
        ("/self_sha256", json!("f".repeat(64))),
        (
            "/actual_kernel/kernel_memory_max_bytes",
            json!(225000000000u64),
        ),
        ("/actual_kernel/host_page_size_bytes", json!(0)),
        ("/actual_kernel/memory_swap_max_bytes", json!(1)),
        ("/actual_kernel/cpu_quota_usec", json!(799999)),
        ("/actual_kernel/guard_kernel_memory_max_bytes", json!(1)),
        ("/bounded_enforcement_proven", json!(false)),
    ] {
        let mut bad = result.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            probe_result(&cap, &probe, &plan, &bad).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn probe_command_accepts_one_actual_manager_record_without_relaxing_identity() {
    let expected = "{ path=/sealed/probe ; argv[]=/sealed/probe /sealed/plan --plan-sha256 abc --self-sha256 def ; ignore_errors=no }";
    let actual = expected.trim_end_matches(" }").to_owned()
        + " ; start_time=[Fri 2026-10-24 00:00:00 UTC] ; stop_time=[Fri 2026-10-24 00:00:01 UTC] ; pid=300 ; code=exited ; status=0 }";
    assert!(probe_exec_start_matches(expected, expected));
    assert!(probe_exec_start_matches(expected, &actual));
    for bad in [
        actual.replace("path=/sealed/probe", "path=/wrong/probe"),
        actual.replace("argv[]=/sealed/probe", "argv[]=/wrong/probe"),
        actual.replace("/sealed/plan --", "/sealed/other --"),
        actual.replace("sha256 abc", "sha256 xyz"),
        actual.replace("ignore_errors=no", "ignore_errors=yes"),
        actual.replace("pid=300", "pid=+300"),
        actual.replace("pid=300", "pid=4294967296"),
        actual.replace("code=exited", "code="),
        actual.replace("status=0", "status="),
        actual.replace("status=0", "status=0 trailing"),
        actual.replace("stop_time=[Fri 2026-10-24 00:00:01 UTC]", "stop_time=[]"),
        actual.replace(" ; pid=300", " ; extra=1 ; pid=300"),
        actual.clone() + " trailing",
        actual.clone() + " ; " + expected,
        actual.replace("status=0 }", "status=0 } { path=/evil }"),
        actual.replace(" ; stop_time=", " stop_time="),
    ] {
        assert!(!probe_exec_start_matches(expected, &bad), "accepted {bad}");
    }
}

#[test]
fn thread_profile_proposal_binds_exactly_eight_sorted_cpu_ids_and_keeps_old_history() {
    let (s, p, mut r) = fixture();
    proposal(&s, &p, &r).unwrap();
    let profile = json!({"schema":"jetstreamer-capped204205-eight-thread-profile-v1","cpu_ids":[0,1,2,3,4,5,6,7]});
    r["kernel_limits"]["thread_profile"] = profile.clone();
    proposal(&s, &p, &r).unwrap();
    for ids in [
        json!([]),
        json!([0, 1, 2, 3, 4, 5, 6]),
        json!([0, 1, 2, 3, 4, 5, 6, 7, 8]),
        json!([0, 1, 2, 3, 4, 5, 6, 6]),
        json!([7, 6, 5, 4, 3, 2, 1, 0]),
    ] {
        let mut bad = r.clone();
        bad["kernel_limits"]["thread_profile"]["cpu_ids"] = ids;
        assert!(proposal(&s, &p, &bad).is_err());
    }
    r["kernel_limits"]["thread_profile"]["unexpected"] = json!(true);
    assert!(proposal(&s, &p, &r).is_err());
}
