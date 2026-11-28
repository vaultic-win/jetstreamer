use super::*;

pub(super) fn plan() -> Plan {
    serde_json::from_value(json!({
        "schema":"horizon-retry6-166-scratch-retirement-plan-v1","owner":"/root","epoch":166,
        "run":RUN,"scratch":SCRATCH,"device":DEVICE,"run_inode":RUN_INODE,"scratch_inode":SCRATCH_INODE,
        "stop_intent":Bound::fixed(INTENT,INTENT_SHA),"stop_completion":Bound::fixed(STOP,STOP_SHA),
        "admission":Bound::fixed(ADMISSION,ADMISSION_SHA),"guard_protection":Bound::fixed(PROTECTION,PROTECTION_SHA),
        "no_resume_review":{"path":"/sealed/no-resume.json","sha256":"a".repeat(64)},
        "dependency_review":{"path":"/sealed/dependencies.json","sha256":"b".repeat(64)},
        "shared_locks":[
            {"path":MUTATION_LOCK,"device":DEVICE,"inode":101135013,"uid":UID,"gid":GID,"mode":384},
            {"path":custody::EPOCH_LOCK,"device":DEVICE,"inode":103678014,"uid":UID,"gid":GID,"mode":384}
        ],
        "retire_scratch_contents":true,"preserve_archive_and_inputs":true,
        "preserve_cohort_state":true,"preserve_scratch_root":true,
        "resource_credit_bytes":0,"resource_promise_ending_authorized":false,
        "replay_launch_authorized":false,"archive_deletion_authorized":false,"remote_mutations":false
    })).unwrap()
}
fn no_resume_review() -> NoResumeReview {
    serde_json::from_value(json!({
        "schema":"horizon-retry6-166-no-resume-review-v1","owner":"/root","epoch":166,
        "run":RUN,"scratch":SCRATCH,"producer_unit":UNIT,"producer_invocation_id":IID,
        "original_native":Bound::fixed(NATIVE,NATIVE_SHA),"stop_completion":Bound::fixed(STOP,STOP_SHA),
        "original_argv":Bound::fixed(ORIGINAL_ARGV,ORIGINAL_ARGV_SHA),
        "manifest":Bound::fixed(MANIFEST,MANIFEST_SHA),"package_seal":Bound::fixed(PACKAGE_SEAL,PACKAGE_SEAL_SHA),
        "source_lineage":Bound::fixed(LINEAGE,LINEAGE_SHA),
        "node":Bound::fixed(NODE,NODE_SHA),"worker":Bound::fixed(WORKER,WORKER_SHA),
        "source_commit":SOURCE_COMMIT,"cohort_state_sha256":STATE_SHA,
        "exact_source_image_evidence":[{"path":"/sealed/original-production-build.json","sha256":"c".repeat(64)}],
        "reviewed_source_evidence":REVIEWED_SOURCE_SHAS.iter().enumerate().map(|(index,digest)|
            json!({"path":format!("/sealed/source-{index}.rs"),"sha256":digest})).collect::<Vec<_>>(),
        "analysis":{"path":"/sealed/no-resume-review.txt","sha256":"e".repeat(64)},
        "exact_source_image_binding_established":true,"no_admitted_scratch_continuation":true,
        "no_native_bank_or_writer_cursor":true,"original_invocation_restarts_from_bootstrap":true,
        "snapshot_exports_and_indirect_readers_reviewed":true,"preserve_partial_archive_and_inputs":true
    })).unwrap()
}
#[test]
fn exact_profile_rejects_neighbor_retry_wrong_receipts_and_resource_release() {
    let p = plan();
    validate_plan(&p).unwrap();
    for (key, value) in [
        ("epoch", json!(170)),
        ("scratch_inode", json!(SCRATCH_INODE + 1)),
        ("run_inode", json!(RUN_INODE + 1)),
        ("device", json!(DEVICE + 1)),
        ("run", json!(RUN.replace("retry6", "retry8"))),
        ("scratch", json!(SCRATCH.replace("retry6", "retry8"))),
        ("resource_credit_bytes", json!(1)),
        ("resource_promise_ending_authorized", json!(true)),
        ("replay_launch_authorized", json!(true)),
        ("archive_deletion_authorized", json!(true)),
        ("remote_mutations", json!(true)),
        ("preserve_cohort_state", json!(false)),
        ("preserve_scratch_root", json!(false)),
    ] {
        let mut value_plan = serde_json::to_value(&p).unwrap();
        value_plan[key] = value;
        let changed: Plan = serde_json::from_value(value_plan).unwrap();
        assert!(validate_plan(&changed).is_err(), "accepted {key}");
    }
    let mut bad = plan();
    bad.stop_completion.sha256 = "f".repeat(64);
    assert!(validate_plan(&bad).is_err());
    let mut bad = plan();
    bad.shared_locks[1].inode += 1;
    assert!(validate_plan(&bad).is_err());
}
#[test]
fn no_resume_requires_exact_images_state_and_actual_build_proof() {
    validate_no_resume(&no_resume_review()).unwrap();
    for (key, value) in [
        ("exact_source_image_binding_established", json!(false)),
        ("exact_source_image_evidence", json!([])),
        (
            "exact_source_image_evidence",
            json!([Bound::fixed(LINEAGE, LINEAGE_SHA)]),
        ),
        ("reviewed_source_evidence", json!([])),
        ("cohort_state_sha256", json!("0".repeat(64))),
        ("producer_invocation_id", json!("another-invocation")),
        ("node", json!(Bound::fixed(NODE, &"0".repeat(64)))),
        ("worker", json!(Bound::fixed(WORKER, &"0".repeat(64)))),
        ("source_commit", json!("0".repeat(40))),
        (
            "snapshot_exports_and_indirect_readers_reviewed",
            json!(false),
        ),
        ("no_admitted_scratch_continuation", json!(false)),
    ] {
        let mut r = serde_json::to_value(no_resume_review()).unwrap();
        r[key] = value;
        let r: NoResumeReview = serde_json::from_value(r).unwrap();
        assert!(validate_no_resume(&r).is_err(), "accepted {key}");
    }
}
#[test]
fn resume_scope_allows_refreshed_dependency_proof_but_not_changed_retirement_authority() {
    let p = plan();
    let original = scope_sha(&p).unwrap();
    let mut fresh = plan();
    fresh.dependency_review = Bound::fixed("/sealed/fresh-dependencies.json", &"f".repeat(64));
    assert_eq!(scope_sha(&fresh).unwrap(), original);
    fresh.no_resume_review.sha256 = "f".repeat(64);
    assert_ne!(scope_sha(&fresh).unwrap(), original);
    let mut changed = plan();
    changed.scratch_inode += 1;
    assert_ne!(scope_sha(&changed).unwrap(), original);
}
#[test]
fn stopped_owner_gate_refuses_jobs_live_children_or_restarts() {
    let before = BTreeMap::from([
        ("Id", UNIT),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("Job", ""),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
    ]);
    validate_closed(&before, UNIT).unwrap();
    for (key, value) in [
        ("MainPID", "42"),
        ("ControlPID", "42"),
        ("Job", "1/start"),
        ("NRestarts", "1"),
        ("ActiveState", "active"),
        ("SubState", "running"),
    ] {
        let mut fields = before.clone();
        fields.insert(key, value);
        assert!(validate_closed(&fields, UNIT).is_err());
    }
}
