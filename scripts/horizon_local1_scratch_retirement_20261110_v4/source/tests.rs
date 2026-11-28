//! Isolated source test definitions. Campaign operations are never invoked.
use super::*;
use std::os::unix::fs::symlink;
fn bound() -> Bound {
    Bound {
        path: "/sealed/evidence.json".into(),
        sha256: "a".repeat(64),
    }
}
fn plan(epoch: u64) -> Plan {
    let pr = profile(epoch).unwrap();
    Plan {
        schema: "jetstreamer-local1-scratch-retirement-plan-v1".into(),
        owner: "/root".into(),
        epoch,
        run_directory: pr.run.into(),
        scratch: scratch(pr),
        run_identity: Directory {
            device: 64512,
            inode: pr.run_inode,
            uid: 1001,
            gid: 1003,
            mode: 0o700,
        },
        scratch_identity: Directory {
            device: 64512,
            inode: pr.scratch_inode,
            uid: 1001,
            gid: 1003,
            mode: 0o700,
        },
        source_review: Bound {
            path: SOURCE_REVIEW.into(),
            sha256: SOURCE_REVIEW_SHA.into(),
        },
        stop_event: Bound {
            path: EVENT.into(),
            sha256: EVENT_SHA.into(),
        },
        terminal_journal: Bound {
            path: pr.out().join("original-invocation-terminal.json"),
            sha256: "b".repeat(64),
        },
        fleet: bound(),
        dependency_review: bound(),
        closed_units: vec![
            pr.unit.into(),
            format!("{}.service", pr.guard),
            format!("{}.timer", pr.guard),
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
fn native_value(pr: &Profile) -> Value {
    json!({"Id":pr.unit,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0","InvocationID":pr.iid})
}
fn failure(pr: &Profile) -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "ACTUAL_PRODUCER_NATIVE.json",
            json!({"Id":pr.unit,"InvocationID":pr.iid,"MainPID":pr.pid.to_string(),"LoadState":"loaded","ActiveState":"active","SubState":"running","ControlPID":"0","NRestarts":"0","Job":"","Restart":"no","ControlGroup":format!("/system.slice/{}",pr.unit),"ExecMainStartTimestampMonotonic":pr.start_monotonic_usecs.to_string()}),
        ),
        (
            "ORIGINAL_PRODUCER_START.json",
            json!({"code":0,"stdout":"","stderr":format!("Running as unit: {}; invocation ID: {}\n",pr.unit,pr.iid)}),
        ),
        (
            "FAILED_SETUP.json",
            json!({"error":format!("('genuine first guard did not succeed by original25second deadline', {})",pr.epoch),"originals_preserved":true,"old_or_other_producers_not_signalled":true}),
        ),
        (
            "FAILED_NEW_SCOPE_STOP_REQUEST.json",
            json!({"code":0,"stdout":"","stderr":""}),
        ),
        ("FAILED_SETUP_TERMINAL_NATIVE.json", native_value(pr)),
    ])
}
fn journal(pr: &Profile) -> Value {
    json!([{"_PID":"1","_UID":"0","_COMM":"systemd","_EXE":"/usr/lib/systemd/systemd","SYSLOG_IDENTIFIER":"systemd","UNIT":pr.unit,"INVOCATION_ID":pr.iid,"_BOOT_ID":BOOT,"_MACHINE_ID":MACHINE,"__CURSOR":"s=test;i=1","__REALTIME_TIMESTAMP":((pr.start_unix+26)*1_000_000).to_string(),"__MONOTONIC_TIMESTAMP":(pr.start_monotonic_usecs+26_000_000).to_string(),"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{}: Deactivated successfully.",pr.unit)}])
}
fn accepted_fleet() -> Value {
    let rows = (101..=200)
        .map(|e| json!({"epoch":e,"state":"remote-ready"}))
        .collect::<Vec<_>>();
    let terminals = (166..=172).map(|e| json!({"epoch":e})).collect::<Vec<_>>();
    let mut f = json!({"schema":"horizon-Root-complete-fleet-operational-review-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","recorded_unix_seconds":100,"terminal_producer_event":plan(166).stop_event,"epochs":rows,"terminal_producers":terminals,"terminal_producer_count":7,"authenticated_status_count":19,"resource_credit_bytes":0,"replay_launch_authorized":false,"live_replay_count":7,"active_producer_count":7,"actual_executing_replays":[],"actual_active_bootstraps":[],"replacement_owner_declarations":[]});
    for e in 166..=172 {
        let unit = json!({"Id":format!("horizon-qualify-{e}-replacement-local2-20261110-v1.service"),"InvocationID":format!("{e:032x}"),"MainPID":(e+1000).to_string(),"LoadState":"loaded","ActiveState":"active","SubState":"running","ControlPID":"0","NRestarts":"0","Job":""});
        let declaration = json!({"epoch":e,"phase":"replay","unit":unit["Id"],"invocation_id":unit["InvocationID"]});
        f["actual_executing_replays"].as_array_mut().unwrap().push(json!({"epoch":e,"phase":"replay","unit":unit,"declaration":declaration,"run_directory":format!("/home/sol/.jetstreamer-private/epoch{e}-standard-lane-20261109-v1/replacement-local2-20261110-v1/private/run"),"resource_credit_bytes":0}));
        f["replacement_owner_declarations"]
            .as_array_mut()
            .unwrap()
            .push(declaration);
        f["epochs"][(e - 101) as usize] =
            json!({"epoch":e,"state":"live-replay","current_live_producer":unit});
    }
    f
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
fn exact_three_profiles_accept_only_pinned_local1_scope() {
    let mut units = BTreeSet::new();
    let mut inodes = BTreeSet::new();
    for e in 166..=168 {
        let pr = profile(e).unwrap();
        scope(&plan(e)).unwrap();
        assert!(pr.run.starts_with(pr.local1_root));
        assert!(units.insert(pr.unit));
        assert!(inodes.insert(pr.scratch_inode));
        assert!(!pr.local1_root.contains("local2"));
    }
    assert!(profile(165).is_err());
    assert!(profile(169).is_err());
}
#[test]
fn scope_rejects_foreign_identities_subtrees_and_expanded_authority() {
    for field in [
        "epoch",
        "scratch",
        "run_directory",
        "source_review",
        "terminal_journal",
        "resource_promise_ending_authorized",
        "replay_launch_authorized",
        "archive_deletion_authorized",
        "remote_mutations",
        "r2_mutations",
        "preserve_scratch_inode",
        "preserve_partial_archive_and_inputs",
        "local_contents_retirement_authorized",
    ] {
        let mut v = serde_json::to_value(plan(166)).unwrap();
        v[field] = match field {
            "epoch" => json!(169),
            "scratch" | "run_directory" => {
                json!(profile(166).unwrap().run.replace("local1", "local2"))
            }
            "source_review" | "terminal_journal" => serde_json::to_value(bound()).unwrap(),
            "preserve_scratch_inode"
            | "preserve_partial_archive_and_inputs"
            | "local_contents_retirement_authorized" => json!(false),
            _ => json!(true),
        };
        assert!(
            scope(&serde_json::from_value::<Plan>(v).unwrap()).is_err(),
            "{field}"
        );
    }
    for field in ["inode", "device", "uid", "gid", "mode"] {
        let mut v = serde_json::to_value(plan(166)).unwrap();
        v["scratch_identity"][field] = json!(0);
        assert!(
            scope(&serde_json::from_value::<Plan>(v).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut p = plan(166);
    p.closed_units.push("healthy-local2.service".into());
    assert!(scope(&p).is_err());
    let mut p = plan(166);
    p.closed_units.pop();
    assert!(scope(&p).is_err());
}
#[test]
fn retry_allows_new_fresh_evidence_but_never_new_terminal_basis() {
    let mut p = plan(166);
    let original = scope_sha(&p).unwrap();
    p.fleet.sha256 = "c".repeat(64);
    p.dependency_review.sha256 = "d".repeat(64);
    assert_eq!(scope_sha(&p).unwrap(), original);
    p.terminal_journal.sha256 = "e".repeat(64);
    assert_ne!(scope_sha(&p).unwrap(), original);
}
#[test]
fn terminal_checks_distinguish_collected_local1_and_active_replacement() {
    for e in 166..=168 {
        let pr = profile(e).unwrap();
        let v = native_value(pr);
        closed(&v, true, pr).unwrap();
        let mut absent = v.clone();
        absent["LoadState"] = json!("not-found");
        absent["InvocationID"] = json!("");
        closed(&absent, true, pr).unwrap();
        for (k, x) in [
            ("InvocationID", json!("a".repeat(32))),
            ("MainPID", json!("123")),
            ("ControlPID", json!("7")),
            ("ActiveState", json!("active")),
            ("SubState", json!("running")),
            ("Job", json!("17")),
            ("NRestarts", json!("1")),
        ] {
            let mut changed = v.clone();
            changed[k] = x;
            assert!(closed(&changed, true, pr).is_err(), "{k}");
        }
        let mut timer = json!({"Id":format!("{}.timer",pr.guard),"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","Job":""});
        closed(&timer, false, pr).unwrap();
        timer["ActiveState"] = json!("active");
        timer["SubState"] = json!("waiting");
        assert!(closed(&timer, false, pr).is_err());
    }
}
#[test]
fn retained_launch_failure_stop_chain_never_borrows_other_invocation() {
    for e in 166..=168 {
        let pr = profile(e).unwrap();
        let values = failure(pr);
        validate_failed_launch(&values, pr).unwrap();
        for name in [
            "ACTUAL_PRODUCER_NATIVE.json",
            "ORIGINAL_PRODUCER_START.json",
            "FAILED_SETUP.json",
            "FAILED_NEW_SCOPE_STOP_REQUEST.json",
            "FAILED_SETUP_TERMINAL_NATIVE.json",
        ] {
            let mut changed = values.clone();
            changed.insert(name, json!({}));
            assert!(validate_failed_launch(&changed, pr).is_err(), "{name}");
        }
        assert!(
            validate_failed_launch(&values, profile(if e == 166 { 167 } else { 166 }).unwrap())
                .is_err()
        );
    }
}
#[test]
fn native_original_iid_terminal_entry_is_sufficient_without_guard_stop_fabrication() {
    for e in 166..=168 {
        let pr = profile(e).unwrap();
        validate_terminal_journal_bytes(&serde_json::to_vec(&journal(pr)).unwrap(), pr).unwrap();
        assert!(validate_terminal_journal(&native_value(pr), pr).is_err());
    }
}
#[test]
fn authentic_native_jsonl_is_accepted_without_rewriting_journal_entries() {
    let pr = profile(166).unwrap();
    let mut raw = serde_json::to_vec(&journal(pr)[0]).unwrap();
    raw.push(b'\n');
    validate_terminal_journal_bytes(&raw, pr).unwrap();
}
#[test]
fn exact_failed_batch_history_cannot_claim_protected_or_useful_replays() {
    let failed=(166..=168).map(|e|json!({"epoch":e,"error":format!("('genuine first guard did not succeed by original25second deadline', {e})")})).collect::<Vec<_>>();
    let mut batch = json!({"recorded_unix_seconds":1794337157u64,"protected":[],"failed":failed,"bootstrap_count":0,"useful_transaction_replay_count":0,"full_native_replacement_fleet_status_and_observer_integration_next":true});
    validate_failed_batch(&batch).unwrap();
    batch["useful_transaction_replay_count"] = json!(1);
    assert!(validate_failed_batch(&batch).is_err());
}
#[test]
fn native_terminal_rejects_spliced_identity_worker_messages_and_wrong_lifetime() {
    let pr = profile(166).unwrap();
    let good = journal(pr);
    for (k, x) in [
        ("UNIT", json!("other.service")),
        ("INVOCATION_ID", json!("0".repeat(32))),
        ("_PID", json!("123")),
        ("_UID", json!("1001")),
        ("_BOOT_ID", json!("0".repeat(32))),
        ("_MACHINE_ID", json!("0".repeat(32))),
        ("MESSAGE_ID", json!("de5b426a63be47a7b6ac3eaac82e2f6f")),
        ("MESSAGE", json!("Stopping worker...")),
        (
            "__REALTIME_TIMESTAMP",
            json!((pr.start_unix * 1_000_000 - 1).to_string()),
        ),
        ("__REALTIME_TIMESTAMP", json!("1794337158000000")),
        (
            "__MONOTONIC_TIMESTAMP",
            json!((pr.start_monotonic_usecs - 1).to_string()),
        ),
        ("__MONOTONIC_TIMESTAMP", json!("+123")),
        ("UNIT", json!([pr.unit])),
        ("__CURSOR", json!("")),
    ] {
        let mut bad = good.clone();
        bad[0][k] = x;
        assert!(
            validate_terminal_journal_bytes(&serde_json::to_vec(&bad).unwrap(), pr).is_err(),
            "{k}"
        );
    }
    let mut bad = good.clone();
    bad[0].as_object_mut().unwrap().remove("INVOCATION_ID");
    bad[0]["_SYSTEMD_INVOCATION_ID"] = json!(pr.iid);
    assert!(validate_terminal_journal_bytes(&serde_json::to_vec(&bad).unwrap(), pr).is_err());
    let mut bad = good.clone();
    bad.as_array_mut().unwrap().push(good[0].clone());
    assert!(validate_terminal_journal(&bad, pr).is_err());
}
#[test]
fn journal_parser_rejects_duplicate_native_fields_and_malformed_json() {
    let pr = profile(166).unwrap();
    let bytes = serde_json::to_string(&journal(pr)).unwrap();
    let duplicate = bytes.replacen(r#""_PID":"1""#, r#""_PID":"123","_PID":"1""#, 1);
    assert_ne!(duplicate, bytes);
    assert!(validate_terminal_journal_bytes(duplicate.as_bytes(), pr).is_err());
    assert!(validate_terminal_journal_bytes(b"{broken", pr).is_err());
    assert!(validate_terminal_journal_bytes(b"[]", pr).is_err());
}
#[test]
fn cohort_state_is_exact_for_each_epoch_with_no_continuation_cursor() {
    for e in 166..=168 {
        let pr = profile(e).unwrap();
        let mut state = json!({"schema":"jetstreamer-root-cohort-run-v1","start_epoch":e,"end_epoch":e,"status":"running-private","manifest_fingerprint":pr.fingerprint});
        validate_cohort_state(&state, pr).unwrap();
        state["resume_slot"] = json!(71712010);
        assert!(validate_cohort_state(&state, pr).is_err());
        state.as_object_mut().unwrap().remove("resume_slot");
        state["manifest_fingerprint"] = json!("other");
        assert!(validate_cohort_state(&state, pr).is_err());
    }
}
#[test]
fn archive_or_input_arrival_blocks_without_changing_either() {
    let t = tempfile::tempdir().unwrap();
    fs::create_dir(t.path().join("archives")).unwrap();
    fs::create_dir(t.path().join("inputs")).unwrap();
    empty_retained(t.path()).unwrap();
    write(&t.path().join("archives/epoch-166.jet"));
    assert!(empty_retained(t.path()).is_err());
    assert!(t.path().join("archives/epoch-166.jet").exists());
    let t = tempfile::tempdir().unwrap();
    fs::create_dir(t.path().join("archives")).unwrap();
    fs::create_dir(t.path().join("inputs")).unwrap();
    write(&t.path().join("inputs/new-input"));
    assert!(empty_retained(t.path()).is_err());
    assert!(t.path().join("inputs/new-input").exists());
}
#[test]
fn healthy_local2_and_original_lane_are_disjoint_from_failed_local1() {
    let pr = profile(166).unwrap();
    assert!(references_local1(&json!({"unit":pr.unit}), pr));
    assert!(references_local1(&json!({"scratch":scratch(pr)}), pr));
    assert!(!references_local1(
        &json!({"run":pr.run.replace("local1","local2")}),
        pr
    ));
    assert!(!references_local1(
        &json!({"run":format!("{}-sibling",pr.local1_root)}),
        pr
    ));
    assert!(!references_local1(
        &json!({"lane":"/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/private"}),
        pr
    ));
}
#[test]
fn staged_scan_permits_local2_but_requires_exact_closed_local1_definition() {
    let pr = profile(166).unwrap();
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let unit = t.path().join("consumer.service");
    fs::write(
        &unit,
        format!(
            "ExecStart=/bin/reader {}/private/file\n",
            pr.local1_root.replace("local1", "local2")
        ),
    )
    .unwrap();
    fs::set_permissions(&unit, fs::Permissions::from_mode(0o600)).unwrap();
    let scan = |allowed: &[AllowedDefinition]| {
        let (mut count, mut total) = (0, 0);
        staged_walk(
            pr,
            t.path(),
            0,
            &mut BTreeSet::new(),
            &mut count,
            &mut total,
            allowed,
        )
    };
    scan(&[]).unwrap();
    fs::write(
        &unit,
        format!("ExecStart=/bin/reader {}/file\n", pr.local1_root),
    )
    .unwrap();
    assert!(scan(&[]).is_err());
    let allowed = vec![AllowedDefinition {
        unit: pr.unit.into(),
        binding: Bound {
            path: unit.canonicalize().unwrap(),
            sha256: sha(&fs::read(&unit).unwrap()),
        },
    }];
    scan(&allowed).unwrap();
    fs::write(&unit, format!("Changed {}/file\n", pr.local1_root)).unwrap();
    assert!(scan(&allowed).is_err());
}
#[test]
fn current_complete_fleet_preserves_seven_live_local2_owners() {
    let f = accepted_fleet();
    for e in 166..=168 {
        fleet_view(&f, &plan(e).stop_event, 101, profile(e).unwrap()).unwrap();
    }
    let pr = profile(166).unwrap();
    assert!(fleet_view(&f, &plan(166).stop_event, 1901, pr).is_err());
    for field in [
        "epochs",
        "terminal_producers",
        "actual_active_bootstraps",
        "actual_executing_replays",
    ] {
        let mut changed = f.clone();
        changed[field] = Value::Null;
        assert!(
            fleet_view(&changed, &plan(166).stop_event, 101, pr).is_err(),
            "{field}"
        );
    }
}
#[test]
fn genuine_disjoint_local2_bootstrap_remains_allowed() {
    let mut f = accepted_fleet();
    let mut owner = f["actual_executing_replays"]
        .as_array_mut()
        .unwrap()
        .pop()
        .unwrap();
    owner["phase"] = json!("bootstrap");
    owner["declaration"]["phase"] = json!("bootstrap");
    let native = owner["unit"].clone();
    f["actual_active_bootstraps"] = json!([owner]);
    f["live_replay_count"] = json!(6);
    f["epochs"][71] =
        json!({"epoch":172,"state":"staged-admissible","current_live_producer":native});
    f["replacement_owner_declarations"][6]["phase"] = json!("bootstrap");
    fleet_view(&f, &plan(166).stop_event, 101, profile(166).unwrap()).unwrap();
}
#[test]
fn active_or_queued_local1_fleet_claim_blocks_retirement() {
    let pr = profile(166).unwrap();
    let f = accepted_fleet();
    for key in [
        "replacement_owner_declarations",
        "queued_producers",
        "queued_replays",
        "admitted_continuations",
    ] {
        let mut changed = f.clone();
        changed[key] = json!([{"unit":pr.unit,"invocation_id":pr.iid}]);
        assert!(
            fleet_view(&changed, &plan(166).stop_event, 101, pr).is_err(),
            "{key}"
        );
    }
    let mut row_claim = f.clone();
    row_claim["epochs"][0]["queued_producer"] = json!({"unit":pr.unit});
    assert!(fleet_view(&row_claim, &plan(166).stop_event, 101, pr).is_err());
    let mut changed = f;
    changed["actual_executing_replays"][0]["run_directory"] = json!(pr.run);
    assert!(fleet_view(&changed, &plan(166).stop_event, 101, pr).is_err());
}
#[test]
fn fleet_history_gate_requires_all_seven_original_chains_unchanged() {
    let mut originals = serde_json::Map::new();
    let mut terminals = Vec::new();
    for e in 166..=172 {
        let original = json!({"unit":format!("old-{e}.service"),"original_invocation_id":format!("{e:032x}"),"native":{"MainPID":"0","Id":format!("old-{e}.service")},"stop_intent":bound(),"stop_completion":bound(),"journal":bound(),"original_archive":format!("/old/{e}/archive.jet"),"scratch":format!("/old/{e}/scratch")});
        terminals.push(json!({"epoch":e,"original_invocation_id":original["original_invocation_id"],"stop_intent":original["stop_intent"],"stop_completion":original["stop_completion"],"original_PID1_journal":original["journal"],"partial_archive_preserved":original["original_archive"],"scratch_preserved":original["scratch"],"repair_open":true,"resource_release_bytes":0,"terminal_native":original["native"]}));
        originals.insert(e.to_string(), original);
    }
    let event = json!({"schema":"horizon-seven-standard-reserve-stop-repair-event-v1","owner":"/root","resource_promises_released":false,"repair_open":true,"rows":originals});
    let mut f = json!({"terminal_producers":terminals});
    fleet_histories(&f, &event).unwrap();
    f["terminal_producers"][6]["original_invocation_id"] = json!("other");
    assert!(fleet_histories(&f, &event).is_err());
    let mut event = event;
    event["rows"].as_object_mut().unwrap().remove("172");
    assert!(event_rows(&event).is_err());
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
fn lifecycle_binding_rejects_an_intent_for_another_generation() {
    let basis = json!({"inode":17,"tool":"sealed"});
    let v = json!({"schema":"intent-v1","basis":basis});
    validate_binding(&v, "intent-v1", &basis).unwrap();
    assert!(validate_binding(&v, "complete-v1", &basis).is_err());
    assert!(validate_binding(&v, "intent-v1", &json!({"inode":18,"tool":"sealed"})).is_err());
}
