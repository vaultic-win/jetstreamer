use super::*;
use std::os::unix::fs::symlink;

fn bound() -> Bound {
    Bound {
        path: PathBuf::from("/sealed/evidence.json"),
        sha256: "a".repeat(64),
    }
}
fn plan() -> Plan {
    Plan {
        schema: "jetstreamer-standard166-scratch-retirement-plan-v1".into(),
        owner: "/root".into(),
        epoch: 166,
        run_directory: RUN.into(),
        scratch: scratch(),
        run_identity: Directory {
            device: 64512,
            inode: 1,
            uid: 1001,
            gid: 1003,
            mode: 0o700,
        },
        scratch_identity: Directory {
            device: 64512,
            inode: 2,
            uid: 1001,
            gid: 1003,
            mode: 0o700,
        },
        source_review: Bound {
            path: "/sealed/HANDOFF.md".into(),
            sha256: SOURCE_REVIEW_SHA.into(),
        },
        stop_event: Bound {
            path: EVENT.into(),
            sha256: "b".repeat(64),
        },
        fleet: bound(),
        dependency_review: bound(),
        closed_units: vec![
            UNIT.into(),
            format!("{GUARD}.service"),
            format!("{GUARD}.timer"),
        ],
        preserve_partial_archive_and_inputs: true,
        preserve_scratch_inode: true,
        local_contents_retirement_authorized: true,
        resource_promise_ending_authorized: false,
        replay_launch_authorized: false,
        archive_deletion_authorized: false,
        remote_mutations: false,
        r2_mutations: false,
    }
}
fn native_value() -> Value {
    json!({"Id":UNIT,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0","InvocationID":IID})
}
fn stop() -> (Value, Value) {
    (
        json!({"schema":"jetstreamer-horizon-standalone-stop-intent-v1","producer_invocation_id":IID,"plan_sha256":GUARD_PLAN_SHA,"reason":"filesystem-floor",
        "sample":{"schema":"jetstreamer-horizon-standalone-guard-sample-v1","producer_invocation_id":IID,"plan_sha256":GUARD_PLAN_SHA,
        "guard_sha256":"35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc","producer":{"pid":4188448,"invocation_id":IID,"restarts":0},"producer_stop_enabled":true,"available_bytes":10,"minimum_free_bytes":11}}),
        json!({"schema":"jetstreamer-horizon-standalone-stop-completion-v1","producer_invocation_id":IID,"plan_sha256":GUARD_PLAN_SHA,
        "intent":Path::new(GUARD_RECEIPTS).join("stop-intent.json"),"terminal":{"invocation_id":IID,"pid":0,"active":"inactive","sub":"dead","restarts":0},"scratch_deleted":false,"remote_mutations":false,"r2_mutations":false}),
    )
}
fn fixture() -> (tempfile::TempDir, File, u64, u32, u32) {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let m = fs::metadata(temp.path()).unwrap();
    let root = stopped_tree::open_root(temp.path(), m.dev(), m.ino()).unwrap();
    (temp, root, m.dev(), m.uid(), m.gid())
}
fn write(p: &Path) {
    fs::write(p, b"disposable stopped state").unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn scope_refuses_foreign_epoch_path_inode_owner_and_authority() {
    scope(&plan()).unwrap();
    for field in [
        "epoch",
        "scratch",
        "run_directory",
        "source_review",
        "resource_promise_ending_authorized",
        "replay_launch_authorized",
        "archive_deletion_authorized",
        "remote_mutations",
        "r2_mutations",
        "preserve_scratch_inode",
    ] {
        let mut v = serde_json::to_value(plan()).unwrap();
        v[field] = match field {
            "epoch" => json!(167),
            "scratch" | "run_directory" => json!("/other"),
            "source_review" => serde_json::to_value(bound()).unwrap(),
            "preserve_scratch_inode" => json!(false),
            _ => json!(true),
        };
        let p: Plan = serde_json::from_value(v).unwrap();
        assert!(scope(&p).is_err(), "{field}");
    }
    let mut p = plan();
    p.scratch_identity.inode = 0;
    assert!(scope(&p).is_err());
    let mut p = plan();
    p.scratch_identity.uid = 0;
    assert!(scope(&p).is_err());
    let mut p = plan();
    p.closed_units.pop();
    assert!(scope(&p).is_err());
}
#[test]
fn fresh_evidence_can_advance_but_destructive_scope_cannot() {
    let mut p = plan();
    let original = scope_sha(&p).unwrap();
    p.fleet.sha256 = "c".repeat(64);
    p.dependency_review.sha256 = "d".repeat(64);
    assert_eq!(scope_sha(&p).unwrap(), original);
    p.scratch_identity.inode += 1;
    assert_ne!(scope_sha(&p).unwrap(), original);
}
#[test]
fn terminal_checks_accept_collected_original_and_reject_replacement_running_and_jobs() {
    let v = native_value();
    closed(&v, true).unwrap();
    let mut missing = v.clone();
    missing["LoadState"] = json!("not-found");
    missing["InvocationID"] = json!("");
    closed(&missing, true).unwrap();
    for (k, x) in [
        ("InvocationID", json!("a".repeat(32))),
        ("MainPID", json!("123")),
        ("ActiveState", json!("active")),
        ("Job", json!("17")),
        ("NRestarts", json!("1")),
    ] {
        let mut changed = v.clone();
        changed[k] = x;
        assert!(closed(&changed, true).is_err(), "{k}");
    }
    let timer = json!({"Id":format!("{GUARD}.timer"),"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","Job":""});
    closed(&timer, false).unwrap();
    let mut timer = timer;
    timer["ActiveState"] = json!("active");
    timer["SubState"] = json!("waiting");
    assert!(closed(&timer, false).is_err());
}
#[test]
fn stop_evidence_requires_original_solo_guard_chain_and_below_floor() {
    let (i, c) = stop();
    validate_stop(&i, &c).unwrap();
    for (k, x) in [
        ("producer_invocation_id", json!("other")),
        ("reason", json!("vma")),
        ("plan_sha256", json!("a".repeat(64))),
    ] {
        let mut bad = i.clone();
        bad[k] = x;
        assert!(validate_stop(&bad, &c).is_err());
    }
    let mut bad = i.clone();
    bad["sample"]["available_bytes"] = json!(11);
    assert!(validate_stop(&bad, &c).is_err());
    for (k, x) in [
        ("scratch_deleted", json!(true)),
        ("remote_mutations", json!(true)),
        ("intent", json!("/other")),
    ] {
        let mut bad = c.clone();
        bad[k] = x;
        assert!(validate_stop(&i, &bad).is_err());
    }
    let mut bad = c;
    bad["terminal"]["pid"] = json!(42);
    assert!(validate_stop(&i, &bad).is_err());
}
#[test]
fn extra_cohort_cursor_or_changed_fingerprint_blocks_retirement() {
    let mut state = json!({"schema":"jetstreamer-root-cohort-run-v1","start_epoch":166,"end_epoch":166,"status":"running-private","manifest_fingerprint":FINGERPRINT});
    validate_cohort_state(&state).unwrap();
    state["resume_slot"] = json!(71712010);
    assert!(validate_cohort_state(&state).is_err());
    state.as_object_mut().unwrap().remove("resume_slot");
    state["manifest_fingerprint"] = json!("other");
    assert!(validate_cohort_state(&state).is_err());
}
#[test]
fn nested_and_exact_mounts_fail_while_siblings_are_disjoint() {
    no_scratch_mounts(
        "1 0 0:1 / /private rw - ext4 /dev/x rw",
        Path::new("/private/scratch"),
    )
    .unwrap();
    no_scratch_mounts(
        "1 0 0:1 / /private/scratch-other rw - ext4 /dev/x rw",
        Path::new("/private/scratch"),
    )
    .unwrap();
    for path in ["/private/scratch", "/private/scratch/nested"] {
        assert!(
            no_scratch_mounts(
                &format!("1 0 0:1 / {path} rw - ext4 /dev/x rw"),
                Path::new("/private/scratch")
            )
            .is_err()
        );
    }
    assert!(no_scratch_mounts("malformed", Path::new("/private/scratch")).is_err());
}
#[test]
fn atomic_receipt_ignores_interrupted_staging_and_never_clobbers_final() {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let partial = t.path().join(".interrupted-temp");
    write(&partial);
    let final_path = t.path().join("completion.json");
    assert!(!exists(&final_path).unwrap());
    let b = atomic_record(&final_path, &json!({"complete":true})).unwrap();
    assert_eq!(b.sha256, sha(&fs::read(&final_path).unwrap()));
    let original = fs::read(&final_path).unwrap();
    assert!(atomic_record(&final_path, &json!({"complete":false})).is_err());
    assert_eq!(fs::read(&final_path).unwrap(), original);
    assert!(partial.exists());
}
#[test]
fn interrupted_and_repeated_execution_preserves_root_and_retained_sibling() {
    let (t, root, dev, uid, gid) = fixture();
    let inode = root.metadata().unwrap().ino();
    let retained = tempfile::tempdir().unwrap();
    write(&retained.path().join("partial.jet"));
    write(&t.path().join("first"));
    write(&t.path().join("second"));
    let ledger = stopped_tree::capture(&root, dev, uid, gid).unwrap();
    fs::remove_file(t.path().join("first")).unwrap();
    assert!(execute_tree(&root, &ledger, dev, uid, gid, false).is_err());
    assert_eq!(
        execute_tree(&root, &ledger, dev, uid, gid, true).unwrap(),
        1
    );
    assert_eq!(
        execute_tree(&root, &ledger, dev, uid, gid, true).unwrap(),
        0
    );
    assert_eq!(root.metadata().unwrap().ino(), inode);
    assert_eq!(
        fs::read(retained.path().join("partial.jet")).unwrap(),
        b"disposable stopped state"
    );
    write(&t.path().join("replacement"));
    assert!(execute_tree(&root, &ledger, dev, uid, gid, true).is_err());
    assert!(t.path().join("replacement").exists());
}
#[test]
fn scratch_replacement_and_symlinked_ancestor_are_rejected() {
    let (t, root, dev, uid, gid) = fixture();
    let ledger = stopped_tree::capture(&root, dev, uid, gid).unwrap();
    let other = tempfile::tempdir().unwrap();
    assert!(stopped_tree::open_root(other.path(), dev, root.metadata().unwrap().ino()).is_err());
    symlink(other.path(), t.path().join("alias")).unwrap();
    assert!(open_directory(&t.path().join("alias")).is_err());
    assert!(execute_tree(&root, &ledger, dev, uid, gid, true).is_err());
}
#[test]
fn staged_symlink_directory_is_scanned_and_unknown_reference_is_fatal() {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let definitions = tempfile::tempdir().unwrap();
    let unit = definitions.path().join("consumer.service");
    fs::write(
        &unit,
        format!("ExecStart=/bin/reader {LANE}/private/file\n"),
    )
    .unwrap();
    fs::set_permissions(&unit, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(definitions.path(), t.path().join("linked")).unwrap();
    let (mut count, mut total) = (0, 0);
    assert!(
        staged_walk(
            t.path(),
            0,
            &mut BTreeSet::new(),
            &mut count,
            &mut total,
            &[]
        )
        .is_err()
    );
    let allowed = vec![AllowedDefinition {
        unit: UNIT.into(),
        binding: Bound {
            path: unit.canonicalize().unwrap(),
            sha256: sha(&fs::read(&unit).unwrap()),
        },
    }];
    let (mut count, mut total) = (0, 0);
    staged_walk(
        t.path(),
        0,
        &mut BTreeSet::new(),
        &mut count,
        &mut total,
        &allowed,
    )
    .unwrap();
    assert_eq!(count, 1);
    fs::write(&unit, format!("Changed {LANE}/private/file\n")).unwrap();
    let (mut count, mut total) = (0, 0);
    assert!(
        staged_walk(
            t.path(),
            0,
            &mut BTreeSet::new(),
            &mut count,
            &mut total,
            &allowed
        )
        .is_err()
    );
}
#[test]
fn lifecycle_binding_rejects_an_intent_for_another_generation() {
    let basis = json!({"inode":17,"tool":"sealed"});
    let v = json!({"schema":"intent-v1","basis":basis});
    validate_binding(&v, "intent-v1", &basis).unwrap();
    assert!(validate_binding(&v, "complete-v1", &basis).is_err());
    assert!(validate_binding(&v, "intent-v1", &json!({"inode":18,"tool":"sealed"})).is_err());
}
#[test]
fn fleet_claim_detection_finds_nested_scope_and_singleton_range() {
    assert!(covers166(&json!({"claim":{"epoch":166}})));
    assert!(covers166(&json!({"range":"166"})));
    assert!(covers166(&json!({"first_epoch":159,"last_epoch":173})));
    assert!(!covers166(&json!({"epoch":167})));
    assert!(!covers166(&json!([])));
}

#[test]
fn real_stop_event_uses_exact_keyed_rows_and_rejects_array_or_omission() {
    let mut rows = serde_json::Map::new();
    for e in 166..=172 {
        rows.insert(e.to_string(), json!({"epoch":e}));
    }
    let mut event = json!({"rows":rows});
    assert_eq!(event_epoch166(&event).unwrap()["epoch"], 166);
    event["rows"].as_object_mut().unwrap().remove("172");
    assert!(event_epoch166(&event).is_err());
    assert!(event_epoch166(&json!({"rows":[{"epoch":166}]})).is_err());
}
#[test]
fn accepted_actual_root_terminal_fleet_is_required_not_legacy_shape() {
    let event = bound();
    let mut rows = Vec::new();
    for e in 101..=200 {
        rows.push(json!({"epoch":e,"state":if e==166{"failed-needs-repair"}else{"remote-ready"}}));
    }
    let mut f = json!({"schema":"horizon-Root-complete-fleet-operational-review-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","recorded_unix_seconds":100,"terminal_producer_event":event,"epochs":rows,"live_replay_count":0,"active_producer_count":0,"terminal_producer_count":7,"authenticated_status_count":19,"resource_credit_bytes":0,"replay_launch_authorized":false,"actual_executing_replays":[]});
    fleet_view(&f, &event, 101).unwrap();
    assert!(fleet_view(&f, &event, 1901).is_err());
    f["schema"] = json!("jetstreamer-horizon-campaign-fleet-v1");
    assert!(fleet_view(&f, &event, 101).is_err());
    f["schema"] = json!("horizon-Root-complete-fleet-operational-review-v1");
    f["actual_executing_replays"] = json!([{"epoch":166}]);
    assert!(fleet_view(&f, &event, 101).is_err());
}

#[test]
fn exact_dev_null_unit_masks_are_nonexecuting_but_other_special_shapes_fail() {
    let t = tempfile::tempdir().unwrap();
    let masked = t.path().join("old-fixture.service");
    symlink("/dev/null", &masked).unwrap();
    assert!(masked_unit_definition(&masked).unwrap());
    let (mut count, mut total) = (0, 0);
    staged_walk(
        &masked,
        0,
        &mut BTreeSet::new(),
        &mut count,
        &mut total,
        &[],
    )
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(total, 0);
    let other = t.path().join("not-a-unit");
    symlink("/dev/null", &other).unwrap();
    assert!(!masked_unit_definition(&other).unwrap());
    assert!(staged_walk(&other, 0, &mut BTreeSet::new(), &mut count, &mut total, &[]).is_err());
    assert!(!masked_unit_definition(Path::new("/dev/null")).unwrap());
}
