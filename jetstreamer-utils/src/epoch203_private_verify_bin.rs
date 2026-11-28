//! Independent 203 source/producer/RPC bindings; never publication admission.
mod profile {
    pub const UNIT: &str = "horizon-qualify-203-checkpoint-continuation-ed66145-v1.service";
    pub const INVOCATION: &str = "ddf3ed2de8b040758ee7a0d696159afd";
    pub const SOURCE: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-203-ed66145-v1/output/epoch-203-checkpoint-restart-v4.jet";
    pub const NODE: &str = "1a299ad19472906b0721555ae3bd01840cbd249724ece9c0f61e086b8ace8716";
    pub const PRODUCER_PLAN: &str =
        "c1215dac8f5a35bf34ad315d3b99666be5c3a690b4050aff63df352fa3e251bf";
    pub const PREFIX: &str = "ba191cf1918cac8b67cb7512bd07cc1eeccb16e525e4c15c27fd7c325f6993ce";
    pub const SUFFIX: &str = "c3b34173473268950e08e7f1022dd4bc194ab7502fcd6251059c2fbf07fa9615";
    pub const SNAPSHOT: &str = "d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6";
    pub const PROVENANCE: &str = "84ec677139274d012a8d5d180e51cbe81d4f0843ca416956b8c1cfd45a9e4f03";
    pub const EXPECTATION: &str =
        "f23cde383b60323e9c307a067b9ef998bcee3b9ab4f8ffa4358a411219068302";
    pub const FULL: &str = "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9";
    pub const PLUGIN: &str = "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547";
    pub const MIN_PROTECTED: u64 =
        248_289_182_611 + (640u64 << 30) + 300_000_000_000 + (160u64 << 30);

    pub const EPOCH: u64 = 203;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch203-verification-plan-v1";
    pub const OUTCOME_SCHEMA: &str = "jetstreamer-private-epoch203-checkpoint-continuation-v1";
    pub const EXPECTATION_SCHEMA: &str = "jetstreamer-private-epoch203-provenance-expectation-v1";
    pub const INTENT_SCHEMA: &str = "jetstreamer-private-epoch203-verification-intent-v1";
    pub const FULL_SCHEMA: &str = "jetstreamer-private-epoch203-full-scan-v1";
    pub const VERIFICATION_SCHEMA: &str = "jetstreamer-private-epoch203-verification-v1";
    pub const PRIVATE_PREFIX: &str = "horizon-203-private-scan-";
    pub const ARCHIVE_NAME: &str = "epoch-203.jet";
    pub const ROOT_SLOT: u64 = 88127580;
    pub const ANCHOR_SLOT: u64 = 87695999;
    pub const ANCHOR_HASH: &str = "4c9Zfnjqk9Ur8gLU6woi1wJEZePZN37MfjVFGVuKt5su";
    pub const TERMINAL_SLOT: u64 = 88127999;
    pub const TERMINAL_HASH: &str = "8eVbfSWY2UX4KW1ms9y7TJNmJEfc5DfFoXa5iF5W7XgR";
    pub const COMPLETION_MARKER: &str =
        "private203 continuation assembled; final/plugin/import/publication gates remain closed";
    pub const PRODUCER_EXE: &str =
        "/var/lib/jetstreamer/horizon-continuation203-parent-ed66145-v1/jetstreamer-node";
    pub const PRODUCER_PID: &str = "3634151";
    pub const BOUNDARY_METADATA: Option<&str> =
        Some("67c39d1471cca1e831c3cf3b840e7de19aac2ede2bfc83146cc6f0b0ef603ff4");
    pub const BOUNDARY_SCHEMA: &str = "jetstreamer-private-epoch203-boundary-metadata-v1";
    pub const PRIOR_NATIVE: Option<&str> =
        Some("5260d7af71ab802ca711fce706020312212d0c8cdfc01c473398b0a9a0108420");
    pub const REMAINING_SUFFIX: Option<u64> = Some(419);
}
use profile::*;
include!("private_v4_verify_runner.rs");

#[cfg(test)]
mod tests203 {
    use super::*;
    #[test]
    #[ignore = "requires root and exact immutable 203 RPC/provenance metadata; read-only, no archive access"]
    fn actual203_independent_metadata_matches_shared_verifier_without_target_access() {
        let p:Plan=serde_json::from_value(json!({"schema":PLAN_SCHEMA,
            "producer_outcome":{"path":"/not-opened/continuation.json","sha256":"a".repeat(64)},
            "provenance_expectation":{"path":"/var/lib/jetstreamer/horizon-203-provenance-expectation-cbd682a4-v1/expectation.json","sha256":EXPECTATION},
            "boundary_metadata":{"path":"/var/lib/jetstreamer/horizon-203-boundary-metadata-collected-f597924c-v1/candidate.json","sha256":BOUNDARY_METADATA},
            "full_verifier":{"path":"/not-opened/full","sha256":FULL},"plugin":{"path":"/not-opened/plugin","sha256":PLUGIN},
            "private_directory":"/var/lib/jetstreamer/horizon-203-private-scan-not-created","protected_free_bytes":MIN_PROTECTED,
            "maximum_archive_bytes":128u64<<30,"threads":8})).unwrap();
        validate_plan(&p).unwrap();
        validate_boundary_metadata(&p).unwrap();
        let v = read_json(&p.provenance_expectation).unwrap();
        assert_eq!(v["expected_provenance_sha256"], PROVENANCE);
        assert_eq!(v["expected_provenance_encoded_bytes"], 1073);
        assert_eq!(v["source_manifest_scope_validated"], true);
        assert_eq!(v["assembled_target_opened"], false);
    }
    fn outcome() -> Value {
        json!({"schema":OUTCOME_SCHEMA,"producer_unit":UNIT,"producer_invocation_id":INVOCATION,
            "private_output":SOURCE,"node_sha256":NODE,"plan":{"sha256":PRODUCER_PLAN},
            "prefix_archive_sha256":PREFIX,"suffix_archive_sha256":SUFFIX,"restart_snapshot_sha256":SNAPSHOT,
            "prior_native_result_sha256":PRIOR_NATIVE,"remaining_slots":419,
            "assembly":{"source_archives":2,"slots_merged":432000,"provenance_version":4},
            "fresh_prefix_full_validation_passed":true,"fresh_native_checkpoint_matches":true,"canonical_root_slot":88127580,
            "canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false})
    }
    #[test]
    fn original203_sources_native_comparison_and_full_v4_coverage_are_mandatory() {
        validate_outcome(&outcome()).unwrap();
        for (pointer, value) in [
            (
                "/producer_invocation_id",
                json!("1dfd29e7ced140b3ba407359cbdc0ee1"),
            ),
            (
                "/node_sha256",
                json!("83398ece0317a6ab3b321f9e1eb8d0c7f76f21f1cb5997cd07899ba19f2992f3"),
            ),
            ("/prior_native_result_sha256", Value::Null),
            ("/remaining_slots", json!(457)),
            ("/canonical_root_slot", json!(92447542)),
            ("/assembly/provenance_version", json!(2)),
            ("/publication_authorized", json!(true)),
            ("/assembly/slots_merged", json!(431581)),
        ] {
            let mut bad = outcome();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_outcome(&bad).is_err(), "{pointer}");
        }
    }
    #[test]
    fn scans_use_independent203_rpc_anchors_and_1073_byte_v4_expectation() {
        let args = full_args(Path::new("/private/epoch-203.jet"));
        assert_eq!(args[3], "87695999");
        assert_eq!(args[4], "4c9Zfnjqk9Ur8gLU6woi1wJEZePZN37MfjVFGVuKt5su");
        assert_eq!(args[6], "88127999");
        assert_eq!(args[7], "8eVbfSWY2UX4KW1ms9y7TJNmJEfc5DfFoXa5iF5W7XgR");
        assert_eq!(
            args[11],
            "84ec677139274d012a8d5d180e51cbe81d4f0843ca416956b8c1cfd45a9e4f03"
        );
        assert_eq!(
            plugin_args(Path::new("/private")),
            ["203:203", "/private", "--threads", "8", "--verify-only"]
        );
    }
    #[test]
    fn actual203_completion_requires_original_pid_executable_and_manager_order() {
        let complete = json!({"_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":INVOCATION,"_EXE":PRODUCER_EXE,
            "_PID":"3634151","__REALTIME_TIMESTAMP":"100","MESSAGE":"private203 continuation assembled; final/plugin/import/publication gates remain closed"});
        let manager = json!({"UNIT":UNIT,"_PID":"1","_EXE":"/usr/lib/systemd/systemd","__REALTIME_TIMESTAMP":"101",
            "MESSAGE":format!("{UNIT}: Deactivated successfully.")});
        let bytes = format!("{complete}\n{manager}\n");
        validate_terminal_journal(bytes.as_bytes()).unwrap();
        let mut wrong = complete.clone();
        wrong["_PID"] = json!("847475");
        assert!(validate_terminal_journal(format!("{wrong}\n{manager}\n").as_bytes()).is_err());
        assert!(validate_terminal_journal(format!("{complete}\n").as_bytes()).is_err());
    }
    #[test]
    fn epoch203_requires_its_independent_boundary_evidence_and_private_output_scope() {
        let mut p:Plan=serde_json::from_value(json!({"schema":PLAN_SCHEMA,
            "producer_outcome":{"path":"/sealed/continuation.json","sha256":"a".repeat(64)},
            "provenance_expectation":{"path":"/sealed/expectation.json","sha256":EXPECTATION},
            "boundary_metadata":{"path":"/sealed/candidate.json","sha256":BOUNDARY_METADATA},
            "full_verifier":{"path":"/sealed/full","sha256":FULL},"plugin":{"path":"/sealed/plugin","sha256":PLUGIN},
            "private_directory":"/var/lib/jetstreamer/horizon-203-private-scan-test-v1","protected_free_bytes":MIN_PROTECTED,
            "maximum_archive_bytes":128u64<<30,"threads":8})).unwrap();
        validate_plan(&p).unwrap();
        p.boundary_metadata = None;
        assert!(validate_plan(&p).is_err());
        p.boundary_metadata = Some(Evidence {
            path: "/sealed/candidate.json".into(),
            sha256: BOUNDARY_METADATA.unwrap().into(),
        });
        p.private_directory = "/var/lib/jetstreamer/horizon-213-private-scan-test-v1".into();
        assert!(validate_plan(&p).is_err());
    }
}
