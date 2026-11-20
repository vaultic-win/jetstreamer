//! Pure source fixtures; no campaign path, payload, manager or network access.
use super::*;

fn fixtures() -> (Value, Value, Value) {
    (
        serde_json::from_slice(include_bytes!("test-data/checkpoint203-launch.json")).unwrap(),
        serde_json::from_slice(include_bytes!("test-data/checkpoint203-outcome.json")).unwrap(),
        serde_json::from_slice(include_bytes!("test-data/checkpoint203-verification.json"))
            .unwrap(),
    )
}
fn bound(name: &str) -> Bound {
    Bound {
        path: format!("/fixture/{name}.json").into(),
        sha256: "a".repeat(64),
    }
}
#[test]
fn selector_is_exact_closed_checkpoint_duplicate_not_prefix_or_canonical203() {
    let a: Artifact = serde_json::from_value(json!("checkpoint203")).unwrap();
    assert_eq!(a, Artifact::Checkpoint203);
    assert_eq!(a.source(), Path::new(ROOT).join(RELATIVE_SOURCE));
    assert_eq!(a.expected().inode, 1004455);
    assert_eq!(a.expected().length, 103802397352);
    assert_eq!(a.sha(), SHA);
    assert_eq!(a.producer(), Some(PRODUCER));
    assert!(a.requires_prior_check());
    for label in ["203", "prefix203", "canonical203", "scratch203"] {
        assert!(serde_json::from_value::<Artifact>(json!(label)).is_err());
    }
}
#[test]
fn retained_actual_lineage_fixture_binds_exact_producer_and_verified_body() {
    let (launch, outcome, verification) = fixtures();
    lineage_shape(&launch, &outcome, &verification).unwrap();
    for (which, pointer, value) in [
        (0, "/invocation_id", json!("f".repeat(32))),
        (1, "/private_output", json!("/other/epoch-203.jet")),
        (1, "/retirement_authorized", json!(true)),
        (2, "/source_identity/ino", json!(25840726)),
        (2, "/archive_sha256", json!("b".repeat(64))),
        (2, "/current_plugin_verification_passed", json!(false)),
        (
            2,
            "/producer_terminal/journal/invocation_id",
            json!("f".repeat(32)),
        ),
    ] {
        let (mut l, mut o, mut v) = fixtures();
        let target = match which {
            0 => &mut l,
            1 => &mut o,
            _ => &mut v,
        };
        *target.pointer_mut(pointer).unwrap() = value;
        assert!(lineage_shape(&l, &o, &v).is_err(), "{pointer}");
    }
}
#[test]
fn closure_requires_exact_iid_and_all_three_sealed_lineage_bindings() {
    let mut units = BTreeMap::from([(PRODUCER.into(), IID.into())]);
    let original = bindings().to_vec();
    closure_requirements(&units, &original).unwrap();
    for index in 0..original.len() {
        let mut missing = original.clone();
        missing.remove(index);
        assert!(closure_requirements(&units, &missing).is_err());
    }
    let mut duplicate = original.clone();
    duplicate.push(original[0].clone());
    assert!(closure_requirements(&units, &duplicate).is_err());
    units.insert(PRODUCER.into(), "748ffa40e0a2408da0a10fc9e160cf0a".into());
    assert!(closure_requirements(&units, &original).is_err());
}
#[test]
fn raw_verification_bytes_are_preserved_without_invented_source_sidecars() {
    let v = metadata_value(include_bytes!("test-data/checkpoint203-verification.json"));
    validate_metadata(&v).unwrap();
    for (key, value) in [
        ("name", json!("epoch-203.jet.sha256")),
        ("source", json!(bound("other"))),
        ("mode", json!(0o600)),
        ("raw_base64", json!(BASE64_STANDARD.encode(b"normalized"))),
    ] {
        let mut changed = v.clone();
        changed[0][key] = value;
        assert!(validate_metadata(&changed).is_err(), "{key}");
    }
    let mut duplicate = v.clone();
    duplicate.as_array_mut().unwrap().push(v[0].clone());
    assert!(validate_metadata(&duplicate).is_err());
}
#[test]
fn known_digest_cannot_borrow_unknown237_inspection_or_another_body() {
    let mut p = ParkSpec {
        schema: "jetstreamer-foundation-closed-private-park-plan-v1".into(),
        mapping: bound("mapping"),
        artifact: Artifact::Checkpoint203,
        sha256: SHA.into(),
        closure: bound("closure"),
        inspection: None,
    };
    old237::park_digest(&p).unwrap();
    p.sha256 = "b".repeat(64);
    assert!(old237::park_digest(&p).is_err());
    p.sha256 = SHA.into();
    p.inspection = Some(bound("foreign-inspection"));
    assert!(old237::park_digest(&p).is_err());
}
#[test]
fn new_exact_check_role_keeps_900second_expiry_and_rejects_other_artifacts() {
    let a = Artifact::Checkpoint203;
    let spec = bound("check");
    let b = Bound {
        path: Path::new(STATE)
            .join("receipts")
            .join(format!("checkpoint203-check-{}.json", spec.sha256)),
        sha256: "f".repeat(64),
    };
    let op = json!({"artifact":a,"source":a.source(),"sha256":SHA,"custody":bound("custody")});
    let v = json!({"schema":"jetstreamer-checkpoint203-private-retirement-check-v1","check_spec":spec,"operation":op,
        "check_only":true,"local_retirement_authorized":false,"original_source_hash_verified":true,
        "closure_after_hash":{"source_identity_checked":true,"maps_and_fds_device_inode_checked":true},
        "source_stamp":a.expected(),"recorded_unix_seconds":1000});
    old237::prior_check_shape(&b, &v, &op, 1900).unwrap();
    assert!(old237::prior_check_shape(&b, &v, &op, 1901).is_err());
    assert!(old237::prior_check_shape(&b, &v, &op, 999).is_err());
    let mut intent = op.clone();
    intent[a.prior_check_field()] = json!(b);
    old237::prior_check_shape(&b, &v, &intent, 1001).unwrap();
    assert!(old237::prior_check_shape(&b, &v, &intent, 5000).is_err());
    intent["artifact"] = json!(Artifact::OldV2237);
    assert!(old237::prior_check_shape(&b, &v, &intent, 1001).is_err());
    intent["artifact"] = json!(Artifact::Singleton207);
    assert!(old237::prior_check_shape(&b, &v, &intent, 1001).is_err());
}
