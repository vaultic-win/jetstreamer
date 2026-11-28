use super::*;
fn plan() -> Plan {
    let b = Bound {
        path: "/var/lib/example.json".into(),
        sha256: "a".repeat(64),
    };
    Plan{schema:"horizon-standard-replacement-recipe-plan-v1".into(),owner:"/root".into(),primary_thread:THREAD.into(),epoch:166,attempt:"a1".into(),review:b.clone(),fleet:b.clone(),inventory:b.clone(),input_proof:b.clone(),cleanup_completion:b,closed_units:vec!["horizon-qualify-166-standard-20261109-v1.service".into(),"horizon-replacement-166-a1-20261110-v1.service".into(),"horizon-guard-replacement-166-a1-20261110-v1.timer".into(),"horizon-guard-replacement-166-a1-20261110-v1.service".into(),"horizon-guard-166-standard-duplicate722-correction-20261110-v1.timer".into(),"horizon-guard-166-standard-duplicate722-correction-20261110-v1.service".into(),"jetstreamer-epochs159-173-target1-controller-v1-r2.service".into()],producer_unit:"horizon-replacement-166-a1-20261110-v1.service".into(),guard_base:"horizon-guard-replacement-166-a1-20261110-v1".into(),fresh_subtree:"/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-a1-20261110-v1".into(),prepare_authorized:true,replay_launch_authorized:false,resource_promise_ending_authorized:false,remote_mutations:false}
}
fn review(p: &Plan) -> Review {
    Review {
        schema: "horizon-standard-replacement-prelaunch-review-v1".into(),
        owner: "/root".into(),
        primary_thread: THREAD.into(),
        epoch: 166,
        attempt: p.attempt.clone(),
        recorded_unix_seconds: 1000,
        source_fleet: p.fleet.clone(),
        source_inventory: p.inventory.clone(),
        input_proof: p.input_proof.clone(),
        cleanup_completion: p.cleanup_completion.clone(),
        complete_authority: Bound {
            path: AUTHORITY.into(),
            sha256: AUTHORITY_SHA.into(),
        },
        full_current_proc_and_unit_census: p.review.clone(),
        all_original_and_replacement_launchers_in_closed_units: true,
        no_target_active_or_queued_claim: true,
        old_partial_and_inputs_preserved: true,
        all_prior_promises_retained: true,
        exclusive_original_slot_replacement: true,
        complete_projected_memory_bytes: MEMORY,
        complete_data_bytes: DATA,
        minimum_initial_available_data_bytes: FLOOR + (64 << 20),
        candidate_remaining_growth_bytes: 200 << 30,
        fresh_subtree_overlap_booked_bytes: 64 << 20,
        retained_lane_physical_bytes: 50 << 30,
        existing_original_slot_future_growth_bytes: 238 << 30,
        proposed_fresh_working_maximum_bytes: 200 << 30,
        additional_growth_not_covered_by_existing_promise_bytes: 0,
        exact_slot_mapping_and_physical_ledger: p.review.clone(),
        normal_pool_bytes: 10 << 30,
        verifier_pool_bytes: 96 << 30,
        native_pool_bytes: 16 << 30,
        shared_pool_bytes: 64 << 30,
        complete_booked_cpu_quota_micros: 9_000_000,
        resource_credit_bytes: 0,
        memory_or_data_promise_ending_bytes: 0,
        ordinary_full_plugin_boundary_gates_retained: true,
    }
}
fn original(p: &Plan) -> Vec<String> {
    let s = profile(p.epoch).unwrap();
    let mut v = vec![
        "/usr/bin/systemd-run".into(),
        format!("--unit={}", s.old_unit),
        format!("--property=StandardOutput=append:{}/producer.log", s.lane),
        format!("--property=StandardError=append:{}/producer.log", s.lane),
        format!("--setenv=JETSTREAMER_PRIVATE_RUN_ROOT={}/private", s.lane),
        format!("{}/output", s.lane),
    ];
    v.extend(
        [
            "--property=MemoryHigh=68719476736",
            "--property=MemoryMax=73014444032",
            "--property=MemorySwapMax=0",
            "--property=CPUQuota=900%",
            "--property=TasksMax=1024",
            "--property=Restart=no",
            "--setenv=JETSTREAMER_VERIFY_SNAPSHOTS=1",
            "--setenv=JETSTREAMER_SKIP_SNAPSHOT_VERIFY=0",
            "--setenv=JETSTREAMER_ENFORCE_ARCHIVE_HASH=1",
            "--verify",
            "--root-checkpoint-cohort",
        ]
        .map(String::from),
    );
    v
}
#[test]
fn exact166_scope_passes() {
    assert!(shapes(&plan()).is_ok());
}
#[test]
fn wrong_epoch_rejected() {
    let mut p = plan();
    p.epoch = 169;
    assert!(shapes(&p).is_err());
}
#[test]
fn launch_authority_rejected() {
    let mut p = plan();
    p.replay_launch_authorized = true;
    assert!(shapes(&p).is_err());
}
#[test]
fn resource_ending_rejected() {
    let mut p = plan();
    p.resource_promise_ending_authorized = true;
    assert!(shapes(&p).is_err());
}
#[test]
fn old_producer_reuse_rejected() {
    let mut p = plan();
    p.producer_unit = profile(166).unwrap().old_unit.into();
    assert!(shapes(&p).is_err());
}
#[test]
fn duplicate_census_rejected() {
    let mut p = plan();
    p.closed_units.push(p.closed_units[0].clone());
    assert!(shapes(&p).is_err());
}
#[test]
fn missing_current_old_guard_rejected() {
    let mut p = plan();
    p.closed_units.retain(|u| !u.contains("duplicate722"));
    assert!(shapes(&p).is_err());
}
#[test]
fn foreign_output_rejected() {
    let mut p = plan();
    p.fresh_subtree = "/home/sol/output".into();
    assert!(shapes(&p).is_err());
}
#[test]
fn review_passes_without_resource_ending() {
    let p = plan();
    assert!(review_shape(&p, &review(&p), 1001).is_ok());
}
#[test]
fn stale_review_rejected() {
    let p = plan();
    assert!(review_shape(&p, &review(&p), 1121).is_err());
}
#[test]
fn future_review_rejected() {
    let p = plan();
    assert!(review_shape(&p, &review(&p), 999).is_err());
}
#[test]
fn fresh68g_added_to_original_memory_rejected() {
    let p = plan();
    let mut r = review(&p);
    r.complete_projected_memory_bytes += 68 << 30;
    assert!(review_shape(&p, &r, 1000).is_err());
}
#[test]
fn lower_floor_rejected() {
    let p = plan();
    let mut r = review(&p);
    r.minimum_initial_available_data_bytes = FLOOR - 1;
    assert!(review_shape(&p, &r, 1000).is_err());
}
#[test]
fn claimed_cleanup_credit_rejected() {
    let p = plan();
    let mut r = review(&p);
    r.resource_credit_bytes = 1;
    assert!(review_shape(&p, &r, 1000).is_err());
}
#[test]
fn double_spent_original_slot_rejected() {
    let p = plan();
    let mut r = review(&p);
    r.exclusive_original_slot_replacement = false;
    assert!(review_shape(&p, &r, 1000).is_err());
}
#[test]
fn existing_partial_must_be_charged() {
    let p = plan();
    let mut r = review(&p);
    r.old_partial_and_inputs_preserved = false;
    assert!(review_shape(&p, &r, 1000).is_err());
}
#[test]
fn recipe_changes_only_five_exact_tokens() {
    let p = plan();
    let old = original(&p);
    let new = producer_recipe(&old, &p, profile(166).unwrap()).unwrap();
    assert_eq!(old.len(), new.len());
    assert_eq!(old.iter().zip(&new).filter(|(a, b)| a != b).count(), 5);
}
#[test]
fn duplicate_unit_arg_rejected() {
    let p = plan();
    let mut old = original(&p);
    old.push(old[1].clone());
    assert!(producer_recipe(&old, &p, profile(166).unwrap()).is_err());
}
#[test]
fn resume_override_rejected() {
    let p = plan();
    let mut old = original(&p);
    old.push("--setenv=JETSTREAMER_ROOT_COHORT_RESUME_RUN=/old/run".into());
    assert!(producer_recipe(&old, &p, profile(166).unwrap()).is_err());
}
#[test]
fn missing_archive_integrity_rejected() {
    let p = plan();
    let mut old = original(&p);
    old.retain(|x| !x.contains("ENFORCE_ARCHIVE_HASH"));
    assert!(producer_recipe(&old, &p, profile(166).unwrap()).is_err());
}
#[test]
fn guard_uses_retained_strong_floor_and_combined_lane_cap() {
    let p = plan();
    let g = guard_template(&p, profile(166).unwrap());
    assert_eq!(g["minimum_free_bytes"], FLOOR);
    assert_eq!(g["maximum_root_physical_bytes"], ROOT_CAP);
    assert_eq!(g["worker_root"], profile(166).unwrap().lane);
    assert!(
        g["invocation_id"]
            .as_str()
            .unwrap()
            .starts_with("REPLACE_ONLY")
    );
}
#[test]
fn inactive_unit_with_queued_job_rejected() {
    let mut n = BTreeMap::from([
        ("Id".into(), "test.service".into()),
        ("ActiveState".into(), "inactive".into()),
        ("MainPID".into(), "0".into()),
        ("ControlPID".into(), "0".into()),
        ("Job".into(), "24".into()),
    ]);
    assert!(closed(&n, "test.service").is_err());
    n.insert("Job".into(), "".into());
    assert!(closed(&n, "test.service").is_ok());
}

#[test]
fn retained_partial_plus_full_fresh288g_rejected() {
    let p = plan();
    let mut r = review(&p);
    r.proposed_fresh_working_maximum_bytes = ROOT_CAP;
    r.candidate_remaining_growth_bytes = ROOT_CAP;
    assert!(slot_budget(&r).is_err());
}
#[test]
fn prior_future_promise_cannot_disappear() {
    let p = plan();
    let mut r = review(&p);
    r.existing_original_slot_future_growth_bytes = 100 << 30;
    assert!(slot_budget(&r).is_err());
}
#[test]
fn uncovered_fresh_growth_charged_in_addition_to_strong_floor() {
    let p = plan();
    let mut r = review(&p);
    r.existing_original_slot_future_growth_bytes = 100 << 30;
    r.additional_growth_not_covered_by_existing_promise_bytes = 100 << 30;
    assert!(slot_budget(&r).is_err());
    r.minimum_initial_available_data_bytes += (100_u64) << 30;
    assert!(slot_budget(&r).is_ok());
}

#[test]
fn timer_absence_allows_unsupported_pid_properties() {
    let n = BTreeMap::from([
        ("Id".into(), "test.timer".into()),
        ("ActiveState".into(), "inactive".into()),
        ("Job".into(), "".into()),
    ]);
    assert!(closed(&n, "test.timer").is_ok());
    assert!(closed(&n, "test.service").is_err());
}
#[test]
fn descriptor_relative_evidence_rejects_parent_symlink() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let t = tempfile::tempdir().unwrap();
    let real = t.path().join("real");
    fs::create_dir(&real).unwrap();
    let f = real.join("e.json");
    fs::write(&f, b"{}").unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&real, t.path().join("alias")).unwrap();
    assert!(raw(&t.path().join("alias/e.json"), 32, false).is_err());
}
#[test]
fn descriptor_relative_evidence_rejects_file_symlink() {
    use std::os::unix::fs::symlink;
    let t = tempfile::tempdir().unwrap();
    let f = t.path().join("real.json");
    fs::write(&f, b"{}").unwrap();
    symlink(&f, t.path().join("alias.json")).unwrap();
    assert!(raw(&t.path().join("alias.json"), 32, false).is_err());
}
#[test]
fn evidence_hardlink_is_not_accepted_as_new_binding() {
    let t = tempfile::tempdir().unwrap();
    let f = t.path().join("real.json");
    fs::write(&f, b"{}").unwrap();
    fs::hard_link(&f, t.path().join("alias.json")).unwrap();
    assert!(raw(&f, 32, false).is_err());
}
#[test]
fn no_clobber_receipt_preserves_existing_result() {
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "Root fixture identity required"
    );
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let first = atomic_json(t.path(), "receipt.json", &json!({"v":1})).unwrap();
    assert!(atomic_json(t.path(), "receipt.json", &json!({"v":2})).is_err());
    assert_eq!(bound(&first).unwrap(), json!({"v":1}));
}
#[test]
fn guard_recipe_retains_original_timing_and_no_restart() {
    let p = plan();
    let a = guard_recipe_template(&p);
    for x in [
        "--on-active=1s",
        "--on-unit-inactive=5s",
        "--property=Restart=no",
        "--property=MemorySwapMax=0",
        GUARD,
        GUARD_SHA,
    ] {
        assert!(a.iter().any(|s| s == x));
    }
    assert!(
        a.iter()
            .any(|s| s == "REPLACE_WITH_SEALED_ACTUAL_PLAN_SHA256")
    );
}

#[test]
fn nested_singleton_and_multi_epoch_live_claims_are_rejected() {
    assert!(claims_epoch(&json!({"range":"165-168"}), 166));
    assert!(claims_epoch(&json!({"range":"166"}), 166));
    assert!(claims_epoch(&json!({"bootstrap":{"epoch":166}}), 166));
    assert!(!claims_epoch(&json!({"range":"167-168"}), 166));
}
