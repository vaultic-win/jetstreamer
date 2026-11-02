use super::*;
const CID: &str = "bafyreifb7sgso2papddd2qi7odimlathgwzukzebr5riizjhvnwkwgsbwa";
fn index() -> Index {
    let path = Path::new(PRIVATE)
        .join("qualification-202/diagnostic-output-selected-store8-v1/compact-indexes/202")
        .join(format!(
            "epoch-202-{CID}-mainnet-cid-to-offset-and-size.index"
        ));
    Index {
        path,
        identity: Identity {
            device: 66305,
            inode: 7,
            size: 9000000000,
            blocks: 17578125,
            uid: 1000,
            gid: 1000,
            mode: libc::S_IFREG | 0o600,
            nlink: 1,
            mtime: 1,
            mtime_nsec: 2,
        },
        original_ctime: 3,
        original_ctime_nsec: 4,
        owner: 0,
        epoch: 202,
        header_hex: include_bytes!("fixtures/actual202-cid-header.bin")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        reproduction_url: format!(
            "https://files.old-faithful.net/202/epoch-202-{CID}-mainnet-cid-to-offset-and-size.index"
        ),
        canonical_r2_receipt: Evidence {
            path: "/var/lib/test/actual-r2.json".into(),
            sha256: "a".repeat(64),
            uid: 0,
        },
    }
}
fn plan() -> Plan {
    Plan {
        schema: "jetstreamer-terminal-compact-index-retirement-plan-v1".into(),
        state: "/var/lib/jetstreamer/test-index-state".into(),
        owners: vec![Owner {
            root: Path::new(PRIVATE).join("qualification-202"),
            actors: vec![Actor {
                unit: "horizon-qualify-original202.service".into(),
                invocation_id: "a".repeat(32),
                historical_provenance: None,
            }],
            preserved: vec![Preserved {
                path: Path::new(PRIVATE).join("qualification-202/output/epoch-202.jet"),
                identity: index().identity,
                ctime: 1,
                ctime_nsec: 2,
            }],
        }],
        indexes: vec![index()],
        source_review: Evidence {
            path: "/var/lib/test/source-review.md".into(),
            sha256: "b".repeat(64),
            uid: 0,
        },
        inert_recipes: vec![],
        local_index_retirement_authorized: true,
        archive_deletion_authorized: false,
        remote_mutations: false,
        r2_mutations: false,
    }
}
fn collected_actor() -> (Actor, Value) {
    let mut a = plan().owners.remove(0).actors.remove(0);
    a.historical_provenance = Some(ActorProvenance {
        evidence: Evidence {
            path: "/var/lib/test/original-observation.json".into(),
            sha256: "c".repeat(64),
            uid: 0,
        },
        unit_json_pointer: "/original/unit".into(),
        invocation_id_json_pointer: "/original/invocation_id".into(),
    });
    let history = json!({"original":{"unit":a.unit,"invocation_id":a.invocation_id}});
    (a, history)
}
#[test]
fn collected_loaded_actor_requires_exact_historical_provenance_and_explicit_terminal_state() {
    let (a, history) = collected_actor();
    let show = include_str!("fixtures/collected-loaded.show");
    let v = actor_state(&a, show, Some(0), Some(&history)).unwrap();
    assert_eq!(v["collected_current_invocation"], true);
    assert!(actor_state(&a, show, Some(1), Some(&history)).is_err());
    assert!(actor_state(&a, show, Some(0), None).is_err());
    let mut wrong = history.clone();
    wrong["original"]["invocation_id"] = json!("b".repeat(32));
    assert!(actor_state(&a, show, Some(0), Some(&wrong)).is_err());
    wrong = history.clone();
    wrong["original"]["unit"] = json!("another.service");
    assert!(actor_state(&a, show, Some(0), Some(&wrong)).is_err());
    let mut absent_binding = a;
    absent_binding.historical_provenance = None;
    assert!(actor_state(&absent_binding, show, Some(0), Some(&history)).is_err());
}
#[test]
fn true_not_found_show_nonzero_is_accepted_only_with_complete_collected_closure() {
    let (a, history) = collected_actor();
    let show = include_str!("fixtures/collected-not-found.show");
    for exit in [0, 1, 4] {
        actor_state(&a, show, Some(exit), Some(&history)).unwrap();
    }
    for exit in [None, Some(2), Some(5), Some(255)] {
        assert!(actor_state(&a, show, exit, Some(&history)).is_err());
    }
    assert!(actor_state(&a, "", Some(1), Some(&history)).is_err());
    assert!(
        actor_state(
            &a,
            "Failed to connect to bus: Permission denied\n",
            Some(1),
            Some(&history)
        )
        .is_err()
    );
    for old in [
        "MainPID=0\n",
        "ControlPID=0\n",
        "NRestarts=0\n",
        "Restart=\n",
        "Job=\n",
        "InvocationID=\n",
    ] {
        assert!(
            actor_state(&a, &show.replace(old, ""), Some(1), Some(&history)).is_err(),
            "missing {old}"
        );
    }
}
#[test]
fn replacement_invocations_restart_jobs_live_pids_and_ambiguous_properties_never_qualify() {
    let (a, history) = collected_actor();
    let show = include_str!("fixtures/collected-loaded.show");
    for (old, new) in [
        (
            "InvocationID=\n",
            format!("InvocationID={}\n", "b".repeat(32)),
        ),
        ("MainPID=0", "MainPID=42".into()),
        ("ControlPID=0", "ControlPID=42".into()),
        ("NRestarts=0", "NRestarts=1".into()),
        ("Restart=no", "Restart=on-failure".into()),
        ("Job=\n", "Job=42\n".into()),
        ("ActiveState=inactive", "ActiveState=active".into()),
        ("SubState=dead", "SubState=running".into()),
        ("LoadState=loaded", "LoadState=error".into()),
    ] {
        assert!(
            actor_state(&a, &show.replace(old, &new), Some(0), Some(&history)).is_err(),
            "{new}"
        );
    }
    assert!(actor_state(&a, &format!("{show}MainPID=0\n"), Some(0), Some(&history)).is_err());
    let original = show.replace(
        "InvocationID=\n",
        &format!("InvocationID={}\n", a.invocation_id),
    );
    actor_state(&a, &original, Some(0), None).unwrap();
    assert!(actor_state(&a, &original, Some(1), None).is_err());
}
#[test]
fn real_headers_use_actual_epoch_cid_network_kind_and_value_width() {
    header(
        include_bytes!("fixtures/actual202-slot-header.bin"),
        202,
        CID,
        "slot-to-cid",
    )
    .unwrap();
    header(
        include_bytes!("fixtures/actual202-cid-header.bin"),
        202,
        CID,
        "cid-to-offset-and-size",
    )
    .unwrap();
    validate_plan(&plan()).unwrap();
}
#[test]
fn altered_header_metadata_wrong_epoch_cid_or_kind_never_qualifies() {
    let original = include_bytes!("fixtures/actual202-cid-header.bin");
    for offset in [0, 8, 12, 24, 25, 30, 50, 100] {
        let mut b = original.to_vec();
        b[offset] ^= 1;
        assert!(
            header(&b, 202, CID, "cid-to-offset-and-size").is_err(),
            "offset {offset}"
        );
    }
    assert!(header(original, 203, CID, "cid-to-offset-and-size").is_err());
    assert!(
        header(
            original,
            202,
            &CID.replace('a', "b"),
            "cid-to-offset-and-size"
        )
        .is_err()
    );
    assert!(header(original, 202, CID, "slot-to-cid").is_err());
    assert!(header(&original[..20], 202, CID, "cid-to-offset-and-size").is_err());
}
#[test]
fn filename_url_epoch_and_mainnet_are_bound_without_reading_payload() {
    let i = index();
    assert_eq!(
        name_parts(&i).unwrap(),
        (CID.into(), "cid-to-offset-and-size".into())
    );
    for name in [
        "epoch-202.jet",
        "epoch-202.jet.sha256",
        "epoch-202-not-a-cid-mainnet-slot-to-cid.index",
    ] {
        let mut p = plan();
        p.indexes[0].path.set_file_name(name);
        assert!(validate_plan(&p).is_err());
    }
    let mut p = plan();
    p.indexes[0].reproduction_url = "https://example.invalid/cache".into();
    assert!(validate_plan(&p).is_err());
}
#[test]
fn live237_unready223_foreign_owner_and_shared_inodes_reject() {
    let mut p = plan();
    p.owners[0].root = Path::new(PRIVATE).join("qualification-237-general-target1-budget620-v2");
    assert!(validate_plan(&p).is_err());
    let mut p = plan();
    p.indexes[0].epoch = 223;
    assert!(validate_plan(&p).is_err());
    let mut p = plan();
    p.indexes[0].identity.nlink = 2;
    assert!(validate_plan(&p).is_err());
    let mut p = plan();
    p.indexes.push(index());
    assert!(validate_plan(&p).is_err());
}
#[test]
fn source_archives_actors_and_root_bound_evidence_are_mandatory() {
    let mut p = plan();
    p.owners[0].actors.clear();
    assert!(validate_plan(&p).is_err());
    let mut p = plan();
    p.owners[0].preserved.clear();
    assert!(validate_plan(&p).is_err());
    let mut p = plan();
    p.source_review.uid = 1000;
    assert!(validate_plan(&p).is_err());
    let mut p = plan();
    p.indexes[0].canonical_r2_receipt.uid = 1000;
    assert!(validate_plan(&p).is_err());
    let mut p = plan();
    p.archive_deletion_authorized = true;
    assert!(validate_plan(&p).is_err());
    let mut p = plan();
    p.r2_mutations = true;
    assert!(validate_plan(&p).is_err());
    let (actor, _) = collected_actor();
    let mut p = plan();
    p.owners[0].actors[0] = actor;
    validate_plan(&p).unwrap();
    p.owners[0].actors[0]
        .historical_provenance
        .as_mut()
        .unwrap()
        .evidence
        .uid = 1000;
    assert!(validate_plan(&p).is_err());
}
#[test]
fn canonical_receipt_never_promotes_holding_partial_or_unreadback_evidence() {
    let good = json!({"schema":"jetstreamer-horizon-r2-receipt-v1","epoch":202,
        "bucket":"solana-archive-with-accounts-data","archive_key":"epoch-202.jet",
        "checksum_key":"epoch-202.jet.sha256","remote_sha256_readback":true,
        "archive_length":987654321,"archive_sha256":"a".repeat(64)});
    canonical_receipt(&good, 202).unwrap();
    for (field, value) in [
        ("epoch", json!(203)),
        ("schema", json!("jetstreamer-horizon-holding-receipt-v1")),
        ("archive_key", json!("foundation_node_01/epoch-202.jet")),
        ("archive_key", json!("epoch-202-through-87500000.jet")),
        ("checksum_key", json!("epoch-202.sha256")),
        ("remote_sha256_readback", json!(false)),
        ("archive_length", json!(0)),
        ("archive_length", json!("987654321")),
        ("archive_sha256", json!("A".repeat(64))),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        assert!(canonical_receipt(&bad, 202).is_err(), "field {field}");
    }
}
#[test]
fn interrupted_file_record_binds_original_exact_index_before_mutation() {
    let i = index();
    let v = json!({"operation":"original","index":i});
    bind_file_record(&v, "original", &i).unwrap();
    assert!(bind_file_record(&v, "another-operation", &i).is_err());
    let mut replacement = index();
    replacement.identity.inode += 1;
    assert!(bind_file_record(&v, "original", &replacement).is_err());
    let mut missing = v.clone();
    missing.as_object_mut().unwrap().remove("index");
    assert!(bind_file_record(&missing, "original", &i).is_err());
}
#[test]
fn reviewed_map_parser_finds_alias_after_fd_closed_and_rejects_malformed_rows() {
    let dev = libc::makedev(259, 1);
    let b = b"7f00-7fff r--p 0 103:01 42 /renamed/index (deleted)\n";
    assert!(reviewed::maps_reference(b, dev, 42).unwrap());
    assert!(!reviewed::maps_reference(b, dev, 43).unwrap());
    assert!(!reviewed::maps_reference(b, libc::makedev(259, 2), 42).unwrap());
    assert!(reviewed::maps_reference(b"unparsed row\n", dev, 42).is_err());
}
#[test]
fn references_respect_path_boundaries_and_staged_launch_recipes() {
    let p = plan();
    let root = p.owners[0].root.as_os_str().as_bytes();
    assert!(path_reference(
        format!("{}\0", p.owners[0].root.display()).as_bytes(),
        root
    ));
    assert!(path_reference(
        format!("{}/output", p.owners[0].root.display()).as_bytes(),
        root
    ));
    assert!(!path_reference(
        format!("{}-sibling", p.owners[0].root.display()).as_bytes(),
        root
    ));
    assert!(recipe_reference(
        b"[Timer]\nUnit=horizon-qualify-original202.service\n",
        &p
    ));
    assert!(!recipe_reference(b"[Timer]\nUnit=unrelated.service\n", &p));
}
#[test]
fn reviewed_external_staged_symlink_is_read_and_cycles_oversize_fail_closed() {
    let d = tempfile::tempdir().unwrap();
    let outside = d.path().join("outside.service");
    fs::write(&outside, b"[Service]\nExecStart=original\n").unwrap();
    let link = d.path().join("unit.service");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert_eq!(
        reviewed::staged_body(&link).unwrap(),
        fs::read(&outside).unwrap()
    );
    let cycle = d.path().join("cycle.service");
    std::os::unix::fs::symlink(&cycle, &cycle).unwrap();
    assert!(reviewed::staged_body(&cycle).is_err());
    let huge = d.path().join("huge.service");
    File::create(&huge).unwrap().set_len(LIMIT + 1).unwrap();
    assert!(reviewed::staged_body(&huge).is_err());
}
#[test]
fn custody_lifecycle_is_idempotent_but_replacement_or_unproven_absence_rejects() {
    for args in [
        (true, false, false, false, false),
        (true, false, true, false, false),
        (false, true, true, false, false),
        (false, true, true, true, false),
        (false, false, true, true, false),
        (false, false, true, true, true),
    ] {
        lifecycle(args.0, args.1, args.2, args.3, args.4).unwrap();
    }
    for args in [
        (false, false, false, false, false),
        (true, true, true, false, false),
        (false, false, true, false, false),
        (true, false, true, true, true),
        (false, true, false, true, false),
    ] {
        assert!(lifecycle(args.0, args.1, args.2, args.3, args.4).is_err());
    }
}
#[test]
fn no_clobber_receipts_and_fd_relative_rename_preserve_archive_sibling() {
    let d = tempfile::tempdir().unwrap();
    let dir = File::open(d.path()).unwrap();
    fs::write(
        d.path().join("epoch-202.jet"),
        b"preserved archive sentinel",
    )
    .unwrap();
    write_once(&dir, "intent.json", &json!({"operation":"first"})).unwrap();
    assert!(write_once(&dir, "intent.json", &json!({"operation":"replacement"})).is_err());
    let v: Value =
        serde_json::from_slice(&fs::read(d.path().join("intent.json")).unwrap()).unwrap();
    assert_eq!(v["operation"], "first");
    fs::write(d.path().join("member.index"), b"cache sentinel").unwrap();
    rename_child(&dir, "member.index", &dir, "quarantine").unwrap();
    assert!(rename_child(&dir, "epoch-202.jet", &dir, "quarantine").is_err());
    assert_eq!(
        fs::read(d.path().join("epoch-202.jet")).unwrap(),
        b"preserved archive sentinel"
    );
    assert!(child("../epoch-202.jet").is_err());
    assert!(child("a/b").is_err());
}
