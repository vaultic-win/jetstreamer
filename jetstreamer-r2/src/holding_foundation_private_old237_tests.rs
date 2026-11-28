//! Pure/synthetic source regressions. No campaign paths, payloads or network.
use super::*;

fn fixture(name: &str) -> Value {
    let bytes: &[u8] = match name {
        "acceptance" => include_bytes!("test-data/old-v2-237-acceptance795.json"),
        "completion" => include_bytes!("test-data/old-v2-237-scratch-completion.json"),
        "review" => include_bytes!("test-data/old-v2-237-original-review.json"),
        "stop" => include_bytes!("test-data/old-v2-237-original-stop.json"),
        _ => panic!("fixed source fixture only"),
    };
    serde_json::from_slice(bytes).unwrap()
}
fn raw_metadata() -> Value {
    let raw = include_bytes!("test-data/old-v2-237-cohort-state.json");
    json!([{"name":"cohort-state.json","device":66305,"inode":13547609,"length":raw.len(),"sha256":STATE_SHA,
        "uid":1000,"gid":1000,"mode":0o600,"raw_base64":BASE64_STANDARD.encode(raw)}])
}
fn bound(name: &str) -> Bound {
    Bound {
        path: format!("/var/lib/jetstreamer/source-fixture/{name}.json").into(),
        sha256: "a".repeat(64),
    }
}
fn inspection() -> Value {
    json!({"schema":"jetstreamer-old-v2-237-native-inspection-v1","artifact":"old-v2-237",
        "source":Artifact::OldV2237.source(),"source_identity":Artifact::OldV2237.expected(),
        "length":157334577077u64,"sha256":"b".repeat(64),"multipart_etag":"fixture-etag",
        "multipart_part_size":DEFAULT_PART_SIZE,"lineage":lineage_bindings(),"raw_metadata":raw_metadata(),
        "inspection_spec":bound("inspect"),"native_inspection_invocation_id":"c".repeat(32),
        "native_inspection_pid":123,"tool_sha256":"d".repeat(64),"recorded_unix_seconds":1000,
        "complete_stable_sha256_verified":true,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false,
        "closure_before":{"source_identity_checked":true,"maps_and_fds_device_inode_checked":true,"local_retirement_authorized":false},
        "closure_after":{"source_identity_checked":true,"maps_and_fds_device_inode_checked":true,"local_retirement_authorized":false},
        "canonical_archive":false,"canonical_publication_authorized":false,"full_plugin_qualified":false,
        "boundary_qualified":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false})
}
#[test]
fn exact_new_variant_cannot_select_old_v1_new_v4_or_canonical_generation() {
    let a: Artifact = serde_json::from_value(json!("old-v2-237")).unwrap();
    assert_eq!(a, Artifact::OldV2237);
    assert_eq!(a.expected().length, 157334577077);
    assert_eq!(a.expected().inode, 13547667);
    assert!(a.source().starts_with(ROOT));
    assert!(
        a.source()
            .to_string_lossy()
            .contains("run-2030542-1793568723686999262")
    );
    assert_eq!(a.producer(), Some(PRODUCER));
    assert!(!digest(a.sha())); // Unknown until a real complete native inspection.
    for label in ["old-v1-237", "new-v4-237", "canonical237", "237"] {
        assert!(serde_json::from_value::<Artifact>(json!(label)).is_err());
    }
}
#[test]
fn real_retirement_preservation_fixture_crosses_the_entire_fixed_lineage_predicate() {
    lineage_shape(
        &fixture("acceptance"),
        &fixture("completion"),
        &fixture("review"),
        &fixture("stop"),
    )
    .unwrap();
    for (which, pointer, value) in [
        ("acceptance", "/native_terminal_exit_status", json!(1)),
        (
            "acceptance",
            "/retained_inputs_and_partial_identity_match_actual_check_exactly",
            json!(false),
        ),
        (
            "completion",
            "/common/preserved/partial_archive/path",
            json!("/old-v1/epoch-237.jet"),
        ),
        (
            "completion",
            "/common/preserved/partial_archive/identity/inode",
            json!(11311387),
        ),
        (
            "completion",
            "/common/preserved/partial_archive/identity/bytes",
            json!(149096347639u64),
        ),
        ("completion", "/common/tool_sha256", json!("0".repeat(64))),
        ("completion", "/scratch_deleted", json!(false)),
        (
            "review",
            "/producer_invocation_id",
            json!("f77854054df74e468e717668051429c9"),
        ),
        ("review", "/scratch_contains_replay_cursor", json!(true)),
        (
            "stop",
            "/sample/producer/cgroup",
            json!("/system.slice/new-v4.service"),
        ),
    ] {
        let (mut a, mut c, mut r, mut s) = (
            fixture("acceptance"),
            fixture("completion"),
            fixture("review"),
            fixture("stop"),
        );
        let target = match which {
            "acceptance" => &mut a,
            "completion" => &mut c,
            "review" => &mut r,
            _ => &mut s,
        };
        *target.pointer_mut(pointer).unwrap() = value;
        assert!(lineage_shape(&a, &c, &r, &s).is_err(), "{which} {pointer}");
    }
}
#[test]
fn closed_owner_spec_requires_exact_original_iids_and_each_accepted_metadata_binding() {
    let mut units = BTreeMap::from([
        (PRODUCER.into(), PRODUCER_IID.into()),
        (GUARD.into(), GUARD_IID.into()),
        (TIMER.into(), String::new()),
    ]);
    let original = bindings().to_vec();
    closure_requirements(&units, &original).unwrap();
    units.insert(PRODUCER.into(), "f77854054df74e468e717668051429c9".into());
    assert!(closure_requirements(&units, &original).is_err());
    units.insert(PRODUCER.into(), PRODUCER_IID.into());
    for index in 0..original.len() {
        let mut changed = original.clone();
        changed.remove(index);
        assert!(closure_requirements(&units, &changed).is_err());
    }
    let mut duplicate = original.clone();
    duplicate.push(original[0].clone());
    assert!(closure_requirements(&units, &duplicate).is_err());
}
#[test]
fn original_cohort_bytes_are_preserved_without_inventing_a_sidecar_or_checkpoint() {
    let original = raw_metadata();
    validate_metadata(&original).unwrap();
    for (key, value) in [
        ("name", json!("epoch-237.jet.sha256")),
        ("length", json!(223)),
        ("mode", json!(0o644)),
        (
            "raw_base64",
            json!(BASE64_STANDARD.encode(b"normalized metadata")),
        ),
    ] {
        let mut changed = original.clone();
        changed[0][key] = value;
        assert!(validate_metadata(&changed).is_err(), "{key}");
    }
    let mut duplicate = original.clone();
    duplicate.as_array_mut().unwrap().push(original[0].clone());
    assert!(validate_metadata(&duplicate).is_err());
}
#[test]
fn inspect_plan_is_selector_free_and_cannot_supply_a_guessed_digest() {
    let p = json!({"schema":"jetstreamer-old-v2-237-native-inspect-plan-v1","mapping":bound("mapping"),"closure":bound("closure")});
    serde_json::from_value::<Inspect>(p.clone()).unwrap();
    for key in [
        "sha256",
        "source",
        "epoch",
        "length",
        "local_retirement_authorized",
    ] {
        let mut changed = p.clone();
        changed[key] = json!("guessed");
        assert!(serde_json::from_value::<Inspect>(changed).is_err(), "{key}");
    }
    let p: ParkSpec = serde_json::from_value(json!({"schema":"jetstreamer-foundation-closed-private-park-plan-v1",
        "mapping":bound("mapping"),"closure":bound("closure"),"artifact":"old-v2-237","sha256":"b".repeat(64)})).unwrap();
    assert!(park_digest(&p).is_err()); // No Root/native receipt is consulted.
}
#[test]
fn complete_inspection_binds_native_identity_digest_metadata_and_denies_promotion() {
    let v = inspection();
    inspection_shape(&v, &"b".repeat(64)).unwrap();
    for (pointer, value) in [
        ("/source_identity/inode", json!(11311387)),
        ("/complete_stable_sha256_verified", json!(false)),
        ("/native_inspection_invocation_id", json!("")),
        ("/native_inspection_pid", json!(0)),
        ("/tool_sha256", json!("unqualified")),
        ("/closure_before/source_identity_checked", json!(false)),
        (
            "/closure_after/maps_and_fds_device_inode_checked",
            json!(false),
        ),
        ("/canonical_archive", json!(true)),
        ("/local_retirement_authorized", json!(true)),
        ("/r2_mutations", json!(true)),
    ] {
        let mut changed = v.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            inspection_shape(&changed, &"b".repeat(64)).is_err(),
            "{pointer}"
        );
    }
    assert!(inspection_shape(&v, &"a".repeat(64)).is_err());
    assert!(inspection_shape(&v, &"0".repeat(64)).is_err());
}
fn checked() -> (Bound, Value, Value) {
    let spec = bound("check");
    let b = Bound {
        path: Path::new(STATE)
            .join("receipts")
            .join(format!("old-v2-237-check-{}.json", spec.sha256)),
        sha256: "f".repeat(64),
    };
    let operation = json!({"artifact":"old-v2-237","source":Artifact::OldV2237.source(),"sha256":"b".repeat(64),"custody":bound("custody")});
    let v = json!({"schema":"jetstreamer-old-v2-237-private-retirement-check-v1","check_spec":spec,"operation":operation,
        "check_only":true,"local_retirement_authorized":false,"original_source_hash_verified":true,
        "closure_after_hash":{"source_identity_checked":true,"maps_and_fds_device_inode_checked":true},
        "source_stamp":Artifact::OldV2237.expected(),"recorded_unix_seconds":1000});
    (b, v, operation)
}
#[test]
fn separate_retirement_check_is_fresh_exact_and_cannot_authorize_other_custody() {
    let (b, v, op) = checked();
    prior_check_shape(&b, &v, &op, 1900).unwrap();
    assert!(prior_check_shape(&b, &v, &op, 1901).is_err());
    assert!(prior_check_shape(&b, &v, &op, 999).is_err());
    for (key, value) in [
        ("check_only", json!(false)),
        ("local_retirement_authorized", json!(true)),
        ("original_source_hash_verified", json!(false)),
        ("source_stamp", json!(null)),
    ] {
        let mut changed = v.clone();
        changed[key] = value;
        assert!(prior_check_shape(&b, &changed, &op, 1001).is_err());
    }
    let mut changed = op.clone();
    changed["custody"] = json!(bound("other-custody"));
    assert!(prior_check_shape(&b, &v, &changed, 1001).is_err());
    let mut foreign = b.clone();
    foreign.path = "/tmp/unrelated-check.json".into();
    assert!(prior_check_shape(&foreign, &v, &op, 1001).is_err());
}
#[test]
fn durable_intent_can_bind_the_prior_check_without_changing_its_target_scope() {
    let (b, v, op) = checked();
    let mut intent_op = op.clone();
    intent_op["old_v2_237_prior_check"] = json!(b);
    prior_check_shape(&b, &v, &intent_op, 1001).unwrap();
    // A retry checks at the persisted original intent time, not a renewed time.
    assert!(prior_check_shape(&b, &v, &intent_op, 5000).is_err());
    intent_op["source"] = json!("/new-v4/epoch-237.jet");
    assert!(prior_check_shape(&b, &v, &intent_op, 1001).is_err());
}
