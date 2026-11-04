//! Exact capped 186 inputs. Replay remains gated on separate fresh admission.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = true;
    pub const ARCHIVE_NAME: &str = "epoch-186-prefix.jet";
    pub const PARENT_SHA: &str = "e987401354f0cddbd838b71439768d6ed84baddfe8c0c2b484addec553db1887";
    pub const RAYON_THREADS: u32 = 8;
    pub const EPOCH: u64 = 186;
    pub const TARGET: u64 = 80_783_539;
    pub const TERMINAL: u64 = TARGET;
    pub const INITIAL_REPLAY: u64 = 80_351_284;
    // Private experimental stops, not an adopted cold-epoch planning budget.
    // Fresh admission must separately add output/copy overlap to live growth.
    pub const MAX_SCRATCH: u64 = 384 << 30;
    pub const MINIMUM_FREE: u64 = 3_572_465_819_078;
    pub const MAX_RUNTIME: u64 = 259_200;
    pub const SNAPSHOT_SIZE: u64 = 7_316_986_109;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch186-capped-root-prefix-plan-v2";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch186-capped-root-prefix-resource-v2";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch186-capped-root-prefix-stop-v2";
    pub const UNIT_PREFIX: &str = "horizon-qualify-186-capped-root-prefix-";
    pub const ROOT_PREFIX: &str = "capped-root-prefix-186-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-80351283-Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-80783539-EWu2G86akFM3CKJ8D4YZzi8ASZeaPKm2WXLG239Zjnj9.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = "6eef40863851927d0611fd90dd7c68528c8e1491a0fc18a28de492afa67316bd";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_15";
    pub const SNAPSHOT: &str = "2b128e27dce19d7df54cbcdba52e9fc6e6897fcdce288d05369c41e9382b5112";
}
mod bounded_resource_runner {
    include!("bounded_resource_runner.rs");
    struct InputCapability;
    impl StorageHooks for InputCapability {
        fn capability_only(&self) -> bool {
            true
        }
        fn capability_result(
            &self,
            p: &Plan,
            invocation: &str,
            bindings: &Value,
            cmd: &Command,
        ) -> Result<()> {
            persist(
                &p.run_root.join("receipts/capability.json"),
                &json!({
                    "schema":"jetstreamer-private-epoch186-capped-input-capability-v2",
                    "epoch":EPOCH,"unit":p.unit,"invocation_id":invocation,"plan":bindings,
                    "node_sha256":p.node.sha256,"worker_sha256":WORKER,
                    "worker_feature":"capped-shrink-candidate","snapshot_sha256":SNAPSHOT,
                    "snapshot_bytes":SNAPSHOT_SIZE,"epoch_hashes_sha256":p.epoch_hashes.sha256,
                    "bootstrap_slot":80351283,"terminal_root_slot":TERMINAL,
                    "output_slot_start":80352000,"output_slot_count":431540,
                    "excluded_epoch_suffix_slots":460,
                    "node_arguments":cmd.get_args().map(|a|a.to_string_lossy().into_owned()).collect::<Vec<_>>(),
                    "all_immutable_inputs_rehashed":true,"worker_spawned":false,
                    "snapshot_restored":false,"archive_created":false,
                    "fresh_admission_required":true,"guard_first_fire_required":true,
                    "replay_launch_authorized":false,"canonical_prefix_qualified":false,
                    "full_cold_epoch_peak_qualified":false,"complete_epoch_span_covered":false,
                    "runtime_promotion_authorized":false,"publication_authorized":false,
                    "remote_mutations":false,"r2_mutations":false
                }),
            )
        }
    }
    pub(super) fn input_capability() {
        main_with_storage(&InputCapability);
    }

    #[cfg(test)]
    mod tests186 {
        use super::*;
        fn plan() -> Plan {
            Plan {
                schema: PLAN_SCHEMA.into(),
                unit: format!("{UNIT_PREFIX}test.service"),
                node: BoundFile {
                    path: "/sealed/node".into(),
                    sha256: PARENT_SHA.into(),
                },
                worker: "/sealed/capped-worker".into(),
                snapshot: format!("/sealed/{SNAPSHOT_NAME}").into(),
                ledger_directory: "/sealed".into(),
                epoch_hashes: BoundFile {
                    path: "/sealed/checkpoints".into(),
                    sha256: "b".repeat(64),
                },
                run_root: format!("/home/sol/.jetstreamer-private/{ROOT_PREFIX}test").into(),
                target_slot: TARGET,
                terminal_slot: TERMINAL,
                minimum_free_bytes: MINIMUM_FREE,
                maximum_runtime_seconds: MAX_RUNTIME,
            }
        }
        #[test]
        fn scope_and_command_cannot_borrow_another_host_epoch_or_worker() {
            let p = plan();
            validate_plan(&p).unwrap();
            for i in 0..6 {
                let mut p = plan();
                match i {
                    0 => p.terminal_slot += 1,
                    1 => p.minimum_free_bytes -= 1,
                    2 => {
                        p.run_root =
                            format!("/home/ubuntu/.jetstreamer-private/{ROOT_PREFIX}test").into()
                    }
                    3 => p.node.sha256 = "c".repeat(64),
                    4 => p.unit = "horizon-qualify-204-other.service".into(),
                    _ => p.maximum_runtime_seconds += 1,
                }
                assert!(validate_plan(&p).is_err());
            }
            let c = command(&p);
            let args = c
                .get_args()
                .map(|s| s.to_str().unwrap())
                .collect::<Vec<_>>();
            assert!(args.contains(&"--qualification-end-slot=80783539"));
            assert!(
                !args
                    .iter()
                    .any(|a| a.contains("root-checkpoint-cohort") || a.contains("publish"))
            );
            assert!(
                c.get_envs()
                    .any(|(key, value)| key == WORKER_ENV && value == Some(p.worker.as_os_str()))
            );
        }
        fn manifest() -> Value {
            json!({"schema_version":1,"epoch":186,"output_slot_start":80352000,
            "output_slot_count":431540,"worker_executable_sha256":WORKER,
            "runtime":{"runtime_profile":"solana-v1.6.15"},
            "bootstrap":{"slot":80351283,"slot_complete":true,"accounts_hash":"Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8"},
            "terminal":{"slot":80783539,"slot_complete":true,"accounts_hash":"EWu2G86akFM3CKJ8D4YZzi8ASZeaPKm2WXLG239Zjnj9"},
            "archive_sha256":"a".repeat(64)})
        }
        #[test]
        fn canonical_root_prefix_rejects_full_epoch_or_foreign_runtime() {
            root_manifest_valid(&manifest()).unwrap();
            for (pointer, value) in [
                ("/epoch", json!(185)),
                ("/output_slot_count", json!(432000)),
                ("/runtime/runtime_profile", json!("solana-v1.6.16")),
                ("/worker_executable_sha256", json!("c".repeat(64))),
                ("/terminal/slot", json!(80783999)),
                ("/terminal/slot_complete", json!(false)),
            ] {
                let mut m = manifest();
                *m.pointer_mut(pointer).unwrap() = value;
                assert!(root_manifest_valid(&m).is_err(), "accepted {pointer}");
            }
        }
        #[test]
        fn capability_returns_before_resource_sampling_or_child_spawn() {
            let t = tempfile::tempdir().unwrap();
            fs::create_dir(t.path().join("receipts")).unwrap();
            fs::set_permissions(t.path().join("receipts"), fs::Permissions::from_mode(0o700))
                .unwrap();
            let mut p = plan();
            p.run_root = t.path().into();
            let mut command = Command::new("/this-child-must-not-run");
            execute_prepared(
                &InputCapability,
                &p,
                &"a".repeat(32),
                Path::new("/missing-cgroup"),
                &mut command,
                &json!({}),
            )
            .unwrap();
            let receipt: Value = serde_json::from_slice(
                &fs::read(t.path().join("receipts/capability.json")).unwrap(),
            )
            .unwrap();
            for key in [
                "worker_spawned",
                "snapshot_restored",
                "archive_created",
                "replay_launch_authorized",
                "canonical_prefix_qualified",
                "complete_epoch_span_covered",
                "publication_authorized",
                "r2_mutations",
            ] {
                assert_eq!(receipt[key], false, "{key}");
            }
        }
    }
}
fn main() {
    if std::env::args().next_back().as_deref() == Some("--storage-capability") {
        bounded_resource_runner::input_capability();
    } else {
        eprintln!(
            "epoch186 replay requires separate qualified admission and guard handoff; only --storage-capability is enabled"
        );
        std::process::exit(2);
    }
}
