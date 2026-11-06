//! Pure parser/policy fixtures only. No kernel, filesystem, service or clock IO.
use super::*;

fn sample(at: u64) -> Snapshot {
    let manager = [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "active"),
        ("InvocationID", "1234567890abcdef1234567890abcdef"),
        ("ControlGroup", GROUP),
        ("Delegate", "no"),
        ("MemoryMax", "70866960384"),
        ("MemorySwapMax", "0"),
        ("DropInPaths", ""),
        ("Job", ""),
        ("FragmentPath", "/synthetic/parent.slice"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let raw = [("memory.max","70866960384\n"),("memory.swap.max","0\n"),("memory.current","20\n"),("memory.swap.current","0\n"),
        ("memory.stat","anon 1\nfile 16\nshmem 12\nkernel 7\nslab 5\nslab_reclaimable 2\nslab_unreclaimable 3\n"),
        ("memory.events","low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"),("cgroup.type","domain\n"),
        ("cgroup.controllers","cpuset cpu io memory pids\n"),("cgroup.subtree_control","cpu io memory pids\n"),
        ("cgroup.events","populated 0\nfrozen 0\n"),("cgroup.stat","nr_descendants 0\nnr_dying_descendants 8\n"),("cgroup.procs","")]
        .into_iter().map(|(k,v)| (k.into(),v.into())).collect();
    Snapshot {
        started_unix_millis: at,
        completed_unix_millis: at + 1,
        parent: Identity {
            device: 29,
            inode: 6_781_920,
            uid: 0,
            gid: 0,
            mode: 0o40755,
        },
        outer_tmpfs: Identity {
            device: 63,
            inode: 1,
            uid: 0,
            gid: 0,
            mode: 0o40711,
        },
        inner_tmpfs: Identity {
            device: 58,
            inode: 1,
            uid: 0,
            gid: 0,
            mode: 0o40711,
        },
        manager,
        raw,
        boot_id: "12345678-1234-1234-1234-123456789abc".into(),
        kernel_release: KERNEL.into(),
        kernel_config_sha256: KERNEL_CONFIG_SHA.into(),
        contracts: CONTRACTS
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect(),
    }
}
fn no_authority(v: &Value) {
    assert_eq!(v["capacity_credit_bytes"], 0);
    assert_eq!(v["future_growth_released_bytes"], 0);
    assert!(v["resident_physical_lower_bound_bytes"].is_null());
    for key in [
        "complete_writer_or_charge_ownership_proven",
        "coherent_physical_snapshot_proven",
        "counter_batching_error_bound_proven",
        "ordinary_replay_claim",
        "admission_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        assert_eq!(v[key], false, "{key}");
    }
}

#[test]
fn telemetry_is_opt_in_and_only_the_ordinary_cadence_can_enable_it() {
    settings(false, ObservationReason::UserRequestedStatus, 1).unwrap();
    settings(true, ObservationReason::Routine, 1800).unwrap();
    assert!(settings(true, ObservationReason::Routine, 1799).is_err());
    assert!(settings(true, ObservationReason::UserRequestedStatus, 1800).is_err());
}
#[test]
fn optional_config_defaults_off_and_rejects_non_boolean_enablement() {
    let v = serde_json::json!({"schema":CONFIG_SCHEMA,"previous_sample":"/synthetic/previous.json",
        "minimum_interval_seconds":1800,"not_before_utc":"2026-11-06T16:41:26Z",
        "filesystem_path":"/","output":"/synthetic/output.json","replays":[]});
    let c: Config = serde_json::from_value(v.clone()).unwrap();
    assert!(!c.retained_prefix205_ram);
    let mut enabled = v.clone();
    enabled["retained_prefix205_ram"] = serde_json::json!(true);
    let c: Config = serde_json::from_value(enabled).unwrap();
    validate_config(&c).unwrap();
    let mut invalid = v;
    invalid["retained_prefix205_ram"] = serde_json::json!("true");
    assert!(serde_json::from_value::<Config>(invalid).is_err());
}
#[test]
fn valid_raw_endpoints_preserve_overlapping_categories_without_summing_usage() {
    let v = report(Ok(sample(10)), Ok(sample(20)));
    assert_eq!(v["status"], "observed");
    no_authority(&v);
    assert_eq!(v["before"]["raw"]["memory.current"], "20\n");
    assert_eq!(
        v["before"]["raw"]["memory.stat"],
        sample(10).raw["memory.stat"]
    );
    assert_eq!(v["accounting"]["shmem_is_subset_of_file_not_added"], true);
    assert_eq!(v["accounting"]["kernel_and_slab_children_not_added"], true);
    assert!(v.get("total_resident_bytes").is_none());
}
#[test]
fn nested_tmpfs_has_distinct_identity_and_quota_context_without_another_charge() {
    let v = report(Ok(sample(10)), Ok(sample(20)));
    assert_eq!(v["before"]["outer_tmpfs"]["device"], 63);
    assert_eq!(v["before"]["inner_tmpfs"]["device"], 58);
    assert_eq!(
        v["accounting"]["nested_mount_quotas_are_not_usage_or_parent_charge_summands"],
        true
    );
    assert_eq!(v["accounting"]["per_mount_shmem_attribution_proven"], false);
    no_authority(&v);
}
#[test]
fn owner_iid_boot_cgroup_or_nested_mount_replacement_makes_report_unavailable() {
    for edit in 0..5 {
        let mut after = sample(20);
        match edit {
            0 => {
                after.manager.insert(
                    "InvocationID".into(),
                    "abcdef1234567890abcdef1234567890".into(),
                );
            }
            1 => after.boot_id = "abcdef12-1234-1234-1234-123456789abc".into(),
            2 => after.parent.inode += 1,
            3 => after.inner_tmpfs.inode += 1,
            _ => after.outer_tmpfs.inode += 1,
        }
        let v = report(Ok(sample(10)), Ok(after));
        assert_eq!(v["status"], "unavailable");
        assert!(v["before"].is_object() && v["after"].is_object());
        no_authority(&v);
    }
}
#[test]
fn foreign_contract_kernel_and_parent_policy_are_rejected_even_if_stable() {
    for edit in 0..8 {
        let mut s = sample(10);
        match edit {
            0 => {
                s.contracts.insert(CONTRACTS[0].0.into(), "0".repeat(64));
            }
            1 => s.kernel_release = "other-kernel".into(),
            2 => {
                s.manager.insert("MemoryMax".into(), "max".into());
            }
            3 => {
                s.manager.insert("Delegate".into(), "yes".into());
            }
            4 => {
                s.raw.insert("memory.swap.max".into(), "1\n".into());
            }
            5 => {
                s.raw
                    .insert("cgroup.subtree_control".into(), "cpu io\n".into());
            }
            6 => {
                s.raw.insert("cgroup.type".into(), "threaded\n".into());
            }
            _ => s.parent.mode = 0o40777,
        }
        assert!(validate(&s).is_err(), "{edit}");
    }
}
#[test]
fn occupancy_and_dying_descendants_are_preserved_without_claiming_writer_closure() {
    let mut s = sample(10);
    s.raw
        .insert("cgroup.events".into(), "populated 1\nfrozen 0\n".into());
    s.raw.insert(
        "cgroup.stat".into(),
        "nr_descendants 2\nnr_dying_descendants 9\n".into(),
    );
    s.raw.insert("cgroup.procs".into(), "123\n".into());
    let v = report(Ok(s), Ok(sample(20)));
    assert_eq!(v["status"], "observed");
    assert_eq!(v["before"]["raw"]["cgroup.procs"], "123\n");
    assert_eq!(v["accounting"]["descendant_counters_not_added"], true);
    no_authority(&v);
}
#[test]
fn counter_changes_are_raw_telemetry_and_never_a_minimum_or_credit() {
    let mut after = sample(20);
    after.raw.insert("memory.current".into(), "1\n".into());
    after.raw.insert(
        "memory.stat".into(),
        "anon 0\nfile 0\nshmem 0\nkernel 1\n".into(),
    );
    let v = report(Ok(sample(10)), Ok(after));
    assert_eq!(v["status"], "observed");
    no_authority(&v);
    assert!(v.get("minimum_consumed_bytes").is_none());
    assert!(v.get("counter_delta").is_none());
}
#[test]
fn partial_capture_failure_preserves_successful_endpoint_and_zero_authority() {
    let v = report(Ok(sample(10)), Err(anyhow!("synthetic read deadline")));
    assert_eq!(v["status"], "unavailable");
    assert!(v["before"].is_object());
    assert!(v["after"].is_null());
    no_authority(&v);
    let v = report(Err(anyhow!("before failed")), Err(anyhow!("after failed")));
    no_authority(&v);
}
#[test]
fn malformed_duplicate_missing_or_overflowing_counter_input_is_unavailable() {
    for bad in [
        "anon 1\nanon 2\n",
        "anon -1\n",
        "anon 18446744073709551616\n",
        "anon 1 extra\n",
        "",
    ] {
        assert!(pairs(bad).is_err());
    }
    for bad in ["max", "-1", "1 2", "18446744073709551616", ""] {
        assert!(number(bad).is_err());
    }
    for name in FILES {
        let mut s = sample(10);
        s.raw.remove(name);
        assert!(validate(&s).is_err(), "{name}");
    }
}
#[test]
fn controller_duplicates_and_cross_window_time_reversal_fail_closed() {
    let mut s = sample(10);
    s.raw.insert(
        "cgroup.controllers".into(),
        "cpuset cpu io memory pids cpu\n".into(),
    );
    assert!(validate(&s).is_err());
    let v = report(Ok(sample(20)), Ok(sample(10)));
    assert_eq!(v["status"], "unavailable");
    no_authority(&v);
}
#[test]
fn oversized_raw_endpoint_is_unavailable_with_zero_credit() {
    let mut s = sample(10);
    s.raw.insert("cgroup.procs".into(), "123\n".repeat(40000));
    let v = report(Ok(s), Ok(sample(20)));
    assert_eq!(v["status"], "unavailable");
    no_authority(&v);
}

#[path = "retained_memory_parent_native_tests.rs"]
mod native;
