use super::*;

fn raw(a: Artifact) -> &'static [u8] {
    match a {
        Artifact::Adaptive223 => include_bytes!("partial223-fixtures/adaptive-223-metadata.json"),
        Artifact::FullRoot223 => include_bytes!("partial223-fixtures/full-root-223-metadata.json"),
        Artifact::PartialSingleton223 => {
            include_bytes!("partial223-fixtures/singleton-223-metadata.json")
        }
        _ => unreachable!(),
    }
}
fn lineage(a: Artifact) -> Value {
    serde_json::from_slice(match a {
        Artifact::Adaptive223 => {
            include_bytes!("partial223-fixtures/adaptive-223-lineage.json").as_slice()
        }
        Artifact::FullRoot223 => {
            include_bytes!("partial223-fixtures/full-root-223-lineage.json").as_slice()
        }
        Artifact::PartialSingleton223 => {
            include_bytes!("partial223-fixtures/singleton-223-lineage.json").as_slice()
        }
        _ => unreachable!(),
    })
    .unwrap()
}
fn inspection(a: Artifact) -> Value {
    json!({"schema":"jetstreamer-partial223-native-inspection-v1","artifact":a,
        "source":a.source(),"source_identity":a.expected(),"length":a.expected().length,
        "sha256":"a".repeat(64),"multipart_etag":"fixture-etag","multipart_part_size":DEFAULT_PART_SIZE,
        "native_inspection_invocation_id":"b".repeat(32),"native_inspection_pid":42,"tool_sha256":"c".repeat(64),
        "lineage":lineage_bindings(a),"raw_metadata":metadata_value(a,raw(a)),
        "complete_stable_sha256_verified":true,"recorded_unix_seconds":1,
        "closure_before":{"source_identity_checked":true,"maps_and_fds_device_inode_checked":true,"local_retirement_authorized":false},
        "closure_after":{"source_identity_checked":true,"maps_and_fds_device_inode_checked":true,"local_retirement_authorized":false},
        "local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false,
        "canonical_archive":false,"canonical_publication_authorized":false,"full_plugin_qualified":false,
        "boundary_qualified":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false})
}
#[test]
fn fixed_generations_preserve_raw_failure_and_run_metadata() {
    for p in PROFILES.iter() {
        let a = p.artifact;
        assert_eq!(a.source(), p.root.join(&p.relative_source));
        assert_eq!(a.expected(), p.source_identity);
        assert_eq!(a.epoch(), 223);
        assert_eq!(a.producer(), Some(p.producer.as_str()));
        assert!(a.requires_prior_check());
        assert_eq!(a.sha(), "");
        assert!(p.allocated_bytes >= p.source_identity.length);
        lineage_shape(a, &lineage(a)).unwrap();
        validate_metadata(a, &metadata_value(a, raw(a))).unwrap();
        inspection_shape(a, &inspection(a), &"a".repeat(64)).unwrap();
    }
    assert_eq!(
        PROFILES.iter().map(|p| p.allocated_bytes).sum::<u64>(),
        187_854_090_240
    );
}
#[test]
fn other_generation_and_promotion_never_pass_inspection() {
    for p in PROFILES.iter() {
        let a = p.artifact;
        let good = inspection(a);
        for field in [
            "canonical_archive",
            "canonical_publication_authorized",
            "full_plugin_qualified",
            "boundary_qualified",
            "runtime_checkpoint_qualified",
            "job_resume_authorized",
            "replay_launch_authorized",
            "local_retirement_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = good.clone();
            bad[field] = json!(true);
            assert!(
                inspection_shape(a, &bad, &"a".repeat(64)).is_err(),
                "{field}"
            );
        }
        for other in PROFILES.iter().filter(|q| q.artifact != a) {
            assert!(inspection_shape(other.artifact, &good, &"a".repeat(64)).is_err());
            assert!(validate_metadata(other.artifact, &good["raw_metadata"]).is_err());
            assert!(lineage_shape(other.artifact, &lineage(a)).is_err());
        }
        let mut bad = good.clone();
        bad["source_identity"]["inode"] = json!(1);
        assert!(inspection_shape(a, &bad, &"a".repeat(64)).is_err());
        let mut bad = good.clone();
        bad["closure_after"]["maps_and_fds_device_inode_checked"] = json!(false);
        assert!(inspection_shape(a, &bad, &"a".repeat(64)).is_err());
    }
}
#[test]
fn normalization_or_sidecar_relabeling_loses_original_metadata_proof() {
    for p in PROFILES.iter() {
        let a = p.artifact;
        let mut v = metadata_value(a, raw(a));
        v[0]["name"] = json!("epoch-223.jet.sha256");
        assert!(validate_metadata(a, &v).is_err());
        let parsed: Value = serde_json::from_slice(raw(a)).unwrap();
        let normalized = serde_json::to_vec(&parsed).unwrap();
        assert_ne!(normalized, raw(a));
        assert!(validate_metadata(a, &metadata_value(a, &normalized)).is_err());
    }
}
#[test]
fn exact_original_owner_and_lineage_are_mandatory() {
    for p in PROFILES.iter() {
        let mut units = BTreeMap::from([(p.producer.clone(), p.invocation_id.clone())]);
        if p.artifact == Artifact::Adaptive223 {
            units.insert(
                "horizon-controller-220-223-current-v1.service".into(),
                "0b69b5009dc74bbda94b94d059a3daa7".into(),
            );
            units.insert(
                "jetstreamer-adaptive-reserve-220-223-current-v1.service".into(),
                String::new(),
            );
            units.insert(
                "jetstreamer-adaptive-reserve-220-223-current-v1.timer".into(),
                String::new(),
            );
        }
        let evidence = vec![Bound {
            path: p.lineage.path.clone(),
            sha256: p.lineage.sha256.clone(),
        }];
        closure_requirements(p.artifact, &units, &evidence).unwrap();
        assert!(closure_requirements(p.artifact, &units, &[]).is_err());
        units.insert(p.producer.clone(), "a".repeat(32));
        assert!(closure_requirements(p.artifact, &units, &evidence).is_err());
    }
}

#[test]
fn prior_check_binds_generation_operation_and_nine_hundred_second_window() {
    for p in PROFILES.iter() {
        let a = p.artifact;
        let spec = Bound {
            path: "/fixture/check.json".into(),
            sha256: "c".repeat(64),
        };
        let bound = Bound {
            path: Path::new(STATE).join("receipts").join(format!(
                "{}-check-{}.json",
                a.check_label(),
                spec.sha256
            )),
            sha256: "d".repeat(64),
        };
        let operation = json!({"artifact":a,"custody":"fixed fixture custody","closure":"fixed fixture closure"});
        let value = json!({"schema":format!("jetstreamer-{}-private-retirement-check-v1",a.check_label()),
            "check_only":true,"local_retirement_authorized":false,"original_source_hash_verified":true,
            "closure_after_hash":{"source_identity_checked":true,"maps_and_fds_device_inode_checked":true},
            "check_spec":spec,"operation":operation,"source_stamp":a.expected(),"recorded_unix_seconds":1000});
        let mut final_operation = operation.clone();
        final_operation[a.prior_check_field()] = serde_json::to_value(&bound).unwrap();
        old237::prior_check_shape(&bound, &value, &final_operation, 1900).unwrap();
        assert!(old237::prior_check_shape(&bound, &value, &final_operation, 1901).is_err());
        final_operation["custody"] = json!("substituted custody");
        assert!(old237::prior_check_shape(&bound, &value, &final_operation, 1001).is_err());
    }
}
