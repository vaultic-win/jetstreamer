//! Pure retained metadata fixtures; no real campaign payload, manager or network.
use super::*;

fn fixtures() -> (Value,Value,Value) {
    (serde_json::from_slice(include_bytes!("test-data/failed234-native-terminal.json")).unwrap(),
     serde_json::from_slice(include_bytes!("test-data/failed234-growth-release.json")).unwrap(),
     serde_json::from_slice(include_bytes!("test-data/failed234-full-hash.json")).unwrap())
}
fn bound(name: &str) -> Bound {
    Bound { path:format!("/fixture/{name}.json").into(), sha256:"a".repeat(64) }
}
fn units() -> BTreeMap<String,String> {
    let mut result=BTreeMap::from([(PRODUCER.into(),IID.into())]);
    for peer in CLOSED_PEERS { result.insert(peer.into(),String::new()); }
    result
}

#[test]
fn failed234_selector_cannot_select_other_runs_or_canonical234() {
    let a: Artifact=serde_json::from_value(json!("failed-v5-234")).unwrap();
    assert_eq!(a,Artifact::FailedV5234);
    assert_eq!(a.source(),Path::new(ROOT).join(RELATIVE_SOURCE));
    assert_eq!(a.expected().device,66305);
    assert_eq!(a.expected().inode,15061993);
    assert_eq!(a.expected().length,53619759409);
    assert_eq!(a.expected().uid,1000);
    assert_eq!(a.expected().mode,0o600);
    assert_eq!(a.expected().links,1);
    assert_eq!(a.sha(),SHA);
    assert_eq!(a.producer(),Some(PRODUCER));
    assert!(a.requires_prior_check());
    for alias in ["234","canonical234","failed234","failed-v4-234","old-v5-234","partial234"] {
        assert!(serde_json::from_value::<Artifact>(json!(alias)).is_err());
    }
}
#[test]
fn genuine_failed_producer_and_whole_hash_fixtures_bind_the_original_partial() {
    let (terminal,release,hash)=fixtures();
    lineage_shape(&terminal,&release,&hash).unwrap();
    assert_eq!(hex_lower(&Sha256::digest(include_bytes!("test-data/failed234-native-terminal.json"))),TERMINAL_SHA);
    assert_eq!(hex_lower(&Sha256::digest(include_bytes!("test-data/failed234-growth-release.json"))),RELEASE_SHA);
    assert_eq!(hex_lower(&Sha256::digest(include_bytes!("test-data/failed234-full-hash.json"))),HASH_SHA);
}
#[test]
fn changed_failure_or_future_growth_receipt_is_rejected() {
    for (which,pointer,value) in [
        (0,"/InvocationID",json!("f".repeat(32))),
        (0,"/ActiveState",json!("active")),
        (0,"/MainPID",json!("3988871")),
        (0,"/Restart",json!("on-failure")),
        (0,"/Job",json!("123")),
        (1,"/Main_accepted_future_obligation_reclassification_only",json!(false)),
        (1,"/failed_partial_archive_and_inputs_retained",json!(false)),
        (1,"/physical_storage_credit_bytes",json!(1)),
        (1,"/terminal/InvocationID",json!("f".repeat(32))),
    ] {
        let (mut t,mut r,h)=fixtures();
        *(if which==0 {t.pointer_mut(pointer)}else{r.pointer_mut(pointer)}).unwrap()=value;
        assert!(lineage_shape(&t,&r,&h).is_err(),"{pointer}");
    }
}
#[test]
fn hash_cannot_be_borrowed_from_another_body_or_unclosed_hash_owner() {
    for (pointer,value) in [
        ("/sha256",json!("b".repeat(64))),
        ("/file/path",json!("/home/ubuntu/horizon/epoch-234.jet")),
        ("/file/inode",json!(15061994)),
        ("/file/logical_bytes",json!(53619759408u64)),
        ("/file/ctime_ns",json!(1793951476200348481i64)),
        ("/file/nlink",json!(2)),
        ("/mode",json!(0o444)),
        ("/actual_invocation_id",json!("f".repeat(32))),
        ("/hash_owner_stopped_and_cgroup_drained",json!(false)),
        ("/no_R2_mutation_or_local_retirement",json!(false)),
        ("/original_cohort_state/sha256",json!("b".repeat(64))),
    ] {
        let (t,r,mut h)=fixtures();*h.pointer_mut(pointer).unwrap()=value;
        assert!(lineage_shape(&t,&r,&h).is_err(),"{pointer}");
    }
}
#[test]
fn closure_requires_all_named_actors_and_each_original_evidence_exactly_once() {
    let actors=units();let original=bindings().to_vec();
    closure_requirements(&actors,&original).unwrap();
    for peer in CLOSED_PEERS {
        let mut missing=actors.clone();missing.remove(peer);
        assert!(closure_requirements(&missing,&original).is_err(),"{peer}");
    }
    for index in 0..original.len() {
        let mut missing=original.clone();missing.remove(index);
        assert!(closure_requirements(&actors,&missing).is_err());
    }
    let mut duplicate=original.clone();duplicate.push(original[0].clone());
    assert!(closure_requirements(&actors,&duplicate).is_err());
    let mut replaced=actors;replaced.insert(PRODUCER.into(),"f".repeat(32));
    assert!(closure_requirements(&replaced,&original).is_err());
}
#[test]
fn raw_stale_cohort_metadata_stays_byte_exact_without_fabricated_sidecars() {
    let raw=include_bytes!("test-data/failed234-cohort-state.json");
    let v=metadata_value(raw);validate_metadata(&v).unwrap();
    assert_eq!(BASE64_STANDARD.decode(v[0]["raw_base64"].as_str().unwrap()).unwrap(),raw);
    for (key,value) in [
        ("name",json!("epoch-234.jet.sha256")),
        ("source_path",json!("/other/cohort-state.json")),
        ("mode",json!(0o444)),
        ("raw_base64",json!(BASE64_STANDARD.encode(b"complete"))),
        ("source_identity",json!(Artifact::Checkpoint203.expected())),
    ] {
        let mut changed=v.clone();changed[0][key]=value;
        assert!(validate_metadata(&changed).is_err(),"{key}");
    }
    let mut duplicate=v.clone();duplicate.as_array_mut().unwrap().push(v[0].clone());
    assert!(validate_metadata(&duplicate).is_err());
}
#[test]
fn known234_digest_rejects_other_inspection_and_unknown_content() {
    let mut p=ParkSpec {schema:"jetstreamer-foundation-closed-private-park-plan-v1".into(),
        mapping:bound("mapping"),artifact:Artifact::FailedV5234,sha256:SHA.into(),
        closure:bound("closure"),inspection:None};
    old237::park_digest(&p).unwrap();
    p.inspection=Some(bound("other-inspection"));assert!(old237::park_digest(&p).is_err());
    p.inspection=None;p.sha256="b".repeat(64);assert!(old237::park_digest(&p).is_err());
}
#[test]
fn prior_check_is_exact_separate_and_expires_after_900_seconds() {
    let a=Artifact::FailedV5234;let spec=bound("check");
    let b=Bound {path:Path::new(STATE).join("receipts").join(format!("failed-v5-234-check-{}.json",spec.sha256)),sha256:"f".repeat(64)};
    let operation=json!({"artifact":a,"source":a.source(),"sha256":SHA,"custody":bound("custody")});
    let v=json!({"schema":"jetstreamer-failed-v5-234-private-retirement-check-v1","check_spec":spec,
        "operation":operation,"check_only":true,"local_retirement_authorized":false,
        "original_source_hash_verified":true,"closure_after_hash":{"source_identity_checked":true,
        "maps_and_fds_device_inode_checked":true},"source_stamp":a.expected(),"recorded_unix_seconds":1000});
    old237::prior_check_shape(&b,&v,&operation,1900).unwrap();
    assert!(old237::prior_check_shape(&b,&v,&operation,1901).is_err());
    assert!(old237::prior_check_shape(&b,&v,&operation,999).is_err());
    let mut intent=operation.clone();intent[a.prior_check_field()]=json!(b);
    old237::prior_check_shape(&b,&v,&intent,1001).unwrap();
    for other in [Artifact::OldV2237,Artifact::Checkpoint203,Artifact::Singleton207] {
        let mut changed=intent.clone();changed["artifact"]=json!(other);
        assert!(old237::prior_check_shape(&b,&v,&changed,1001).is_err());
    }
}
#[test]
fn missing_separate_check_or_wrong_original_stamp_is_rejected() {
    let a=Artifact::FailedV5234;let spec=bound("check");
    let b=Bound {path:Path::new(STATE).join("receipts").join(format!("failed-v5-234-check-{}.json",spec.sha256)),sha256:"f".repeat(64)};
    let operation=json!({"artifact":a,"source":a.source(),"sha256":SHA,"custody":bound("custody")});
    let mut v=json!({"schema":"jetstreamer-failed-v5-234-private-retirement-check-v1","check_spec":spec,
        "operation":operation,"check_only":true,"local_retirement_authorized":false,
        "original_source_hash_verified":true,"closure_after_hash":{"source_identity_checked":true,
        "maps_and_fds_device_inode_checked":true},"source_stamp":a.expected(),"recorded_unix_seconds":1000});
    v["source_stamp"]["inode"]=json!(15061994);
    assert!(old237::prior_check_shape(&b,&v,&operation,1001).is_err());
    v["source_stamp"]=json!(a.expected());v["check_only"]=json!(false);
    assert!(old237::prior_check_shape(&b,&v,&operation,1001).is_err());
}
#[test]
fn partial_manifest_and_every_promotion_claim_stay_distinct() {
    let a=Artifact::FailedV5234;
    let mut v=json!({"schema":"jetstreamer-foundation-closed-private-manifest-v1",
        "host":host::HOST,"prefix":SUBPREFIX,"artifact":a,"source":a.source(),"source_identity":a.expected(),
        "sha256":SHA,"length":a.expected().length,"object_key":key(SHA).unwrap(),
        "restore_before_consumer_reuse":true,"failed_v5_234_lineage":lineage_bindings(),
        "raw_metadata":metadata_value(include_bytes!("test-data/failed234-cohort-state.json"))});
    for key in ["canonical_archive","canonical_publication_authorized","full_plugin_qualified","boundary_qualified",
        "runtime_checkpoint_qualified","job_resume_authorized","replay_launch_authorized"] {v[key]=json!(false);}
    no_promotion(&v).unwrap();validate_metadata(&v["raw_metadata"]).unwrap();
    for key in ["canonical_archive","canonical_publication_authorized","full_plugin_qualified","boundary_qualified",
        "runtime_checkpoint_qualified","job_resume_authorized","replay_launch_authorized"] {
        let mut changed=v.clone();changed[key]=json!(true);assert!(no_promotion(&changed).is_err(),"{key}");
    }
    for (pointer,value) in [("/artifact",json!("old-v2-237")),("/sha256",json!("b".repeat(64))),
        ("/source_identity/inode",json!(15061994)),("/source",json!("/home/ubuntu/horizon/epoch-234.jet"))] {
        let mut changed=v.clone();*changed.pointer_mut(pointer).unwrap()=value;
        assert!(validate_manifest(&changed).is_err(),"{pointer}");
    }
}
