use super::*;
fn actual() -> Value {
    serde_json::from_str(include_str!("actual_aac_capture.json")).unwrap()
}
fn check(v: &Value) -> Result<()> {
    candidate_shape(&v["candidate"])?;
    qa_shape(&v["qa"], &v["annex"])?;
    root_shape(
        &v["qa"],
        &v["root_result"],
        &v["root_executable"],
        &v["sandbox"],
    )?;
    configuration_shape(&v["preflight"], &v["configuration"])?;
    production_shape(&v["build"], &v["capture"])
}
#[test]
fn actual_aac_capture_preserves_33_tests_root_proof_and_transitive_limits() {
    let v = actual();
    check(&v).unwrap();
    let limits = v["candidate"]["scope"]["limits"].as_str().unwrap();
    assert!(limits.contains("not independently audited"));
    assert!(limits.contains("not an actual linker map"));
    assert!(v["annex"]["actual_exec_sessions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["final_exit_code"] == 86));
    // The genuine earlier failed QA attempts remain historical failures.
    assert_eq!(v["qa"]["test_counts"]["total_distinct_passed"], 33);
    assert_eq!(v["candidate"]["scope"]["deployment_sealed"], false);
    assert_eq!(v["qa"]["production_or_runtime_qualification_passed"], false);
}
#[test]
fn changed_helper_source_qa_root_sandbox_or_capture_authority_is_rejected() {
    let valid = actual();
    for (path, value) in [
        (
            "/candidate/source_commit",
            json!("94705c5d546341f4fdfc6cc50c819c4031f9ab1d"),
        ),
        ("/candidate/source_tree", json!("a".repeat(40))),
        ("/candidate/artifacts/0/sha256", json!("a".repeat(64))),
        ("/candidate/artifacts/0/bytes", json!(0)),
        ("/candidate/scope/operational_actions", json!(true)),
        ("/candidate/scope/limits", json!("")),
        ("/qa/test_counts/total_distinct_passed", json!(31)),
        ("/qa/test_counts/genuine_root_writer_reader", json!(0)),
        ("/qa/strict_clippy/horizon_library", json!("failed")),
        (
            "/qa/production_or_runtime_qualification_passed",
            json!(true),
        ),
        ("/annex/qa_report/sha256", json!("a".repeat(64))),
        ("/annex/actual_exec_sessions/0/completed", json!(false)),
        ("/annex/detached_cargo_jobs_started", json!(true)),
        ("/root_result/test_executable_sha256", json!("a".repeat(64))),
        ("/root_result/selected_test_passed", json!(false)),
        ("/root_result/archive_inputs", json!(true)),
        ("/root_executable/immutable_memfd_seals", json!(0)),
        ("/root_executable/argv/3", json!("another_test")),
        ("/sandbox/actual_capabilities/CapEff", json!(3)),
        (
            "/sandbox/manager_properties/InvocationID",
            json!("a".repeat(32)),
        ),
        ("/preflight/inherited_overrides", json!({"DOCS_RS":"1"})),
        ("/preflight/scope", json!("post-build audit")),
        ("/configuration/0/input/sha256", json!("a".repeat(64))),
        ("/build/exit_code", json!(1)),
        ("/capture/artifact/sha256", json!("a".repeat(64))),
        ("/capture/all_members_independently_rehashed", json!(false)),
        ("/capture/admission_attempted", json!(true)),
        ("/capture/r2_mutations", json!(true)),
    ] {
        let mut bad = valid.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(check(&bad).is_err(), "accepted mutation {path}");
    }
    for key in [
        "root_result",
        "root_executable",
        "sandbox",
        "annex",
        "preflight",
        "configuration",
    ] {
        let mut bad = valid.clone();
        bad.as_object_mut().unwrap().remove(key);
        assert!(check(&bad).is_err(), "accepted missing {key}");
    }
}
fn seal() -> Seal {
    serde_json::from_value(json!({"schema":"jetstreamer-sealed-deployment-receipt-v1",
        "plan_sha256":"97503ed4e13c27c95ce56e442d63e4975c0505524bf387ea4415225156b03773","sealer_sha256":"b".repeat(64),"destination":PACKAGE,
        "members":[{"source":"/captured/jetstreamer-epoch204-assembly-only","name":"jetstreamer-epoch204-assembly-only",
            "sha256":ARTIFACT,"bytes":4993664,"mode":"0555"}],"created_unix_seconds":1,
        "publication_authorized":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false})).unwrap()
}
#[test]
fn member_identity_requires_one_bounded_immutable_exact_artifact() {
    let good = seal();
    selected_member(
        &good,
        "jetstreamer-epoch204-assembly-only",
        ARTIFACT,
        128 << 20,
    )
    .unwrap();
    for field in ["missing", "duplicate", "sha", "bytes", "mode", "relative"] {
        let mut bad = seal();
        match field {
            "missing" => bad.members.clear(),
            "duplicate" => bad.members.push(Member {
                source: "/another".into(),
                name: "jetstreamer-epoch204-assembly-only".into(),
                sha256: ARTIFACT.into(),
                bytes: 4993664,
                mode: "0555".into(),
            }),
            "sha" => bad.members[0].sha256 = "a".repeat(64),
            "bytes" => bad.members[0].bytes = (128 << 20) + 1,
            "mode" => bad.members[0].mode = "0755".into(),
            _ => bad.members[0].source = "relative".into(),
        }
        assert!(
            selected_member(
                &bad,
                "jetstreamer-epoch204-assembly-only",
                ARTIFACT,
                128 << 20
            )
            .is_err(),
            "accepted {field}"
        );
    }
}
#[test]
fn old947_capture_cannot_qualify_generation2_and_v1_history_stays_named() {
    let old = BoundFile { path:"/var/lib/jetstreamer/horizon-204-assembly-recovery-94705c5d-v1/deployment-seal-receipt.json".into(),
        sha256:"650dd82061693363e5fd94cc6e76a28b808a3e301da864ffda90483f4d7f9a04".into()};
    let assembler = BoundFile {
        path: Path::new(PACKAGE).join("jetstreamer-epoch204-assembly-only"),
        sha256: ARTIFACT.into(),
    };
    assert!(super::super::validate(&old, &assembler).is_err());
    assert_eq!(
        UNIT,
        "horizon-qualify-204-assembly-only-recovery-v2.service"
    );
    assert_eq!(FAILED_V1_IID, "2acdd92edcf5410293e8bfda15f92a63");
    assert!(context::closed_names().contains(FAILED_V1_UNIT));
    assert!(context::closed_names().contains(FAILED_V1_GUARD));
    assert!(GENERATION.starts_with("jetstreamer-epoch204-assembly-only-recovery-v2/"));
}
#[test]
fn generation2_seal_never_borrows_an_old_destination_or_grants_authority() {
    seal_shape(&seal()).unwrap();
    for field in [
        "destination",
        "plan",
        "publication",
        "launch",
        "remote",
        "r2",
    ] {
        let mut bad = seal();
        match field {
            "destination" => {
                bad.destination =
                    "/var/lib/jetstreamer/horizon-204-assembly-recovery-94705c5d-v1".into()
            }
            "plan" => bad.plan_sha256 = "a".repeat(64),
            "publication" => bad.publication_authorized = true,
            "launch" => bad.replay_launch_authorized = true,
            "remote" => bad.remote_mutations = true,
            _ => bad.r2_mutations = true,
        }
        assert!(seal_shape(&bad).is_err(), "accepted seal {field}");
    }
}
