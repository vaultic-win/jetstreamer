//! Private capped-shrink204 prefix; no suffix, publication or runtime promotion.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = true;
    pub const ARCHIVE_NAME: &str = "epoch-204-prefix.jet";
    pub const PARENT_SHA: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
    pub const RAYON_THREADS: u32 = 16;
    pub const EPOCH: u64 = 204;
    pub const TARGET: u64 = 88_559_361;
    pub const TERMINAL: u64 = TARGET;
    pub const INITIAL_REPLAY: u64 = 88_127_581;
    // User-selected century scratch allowance plus separate output/margin.
    // Rejection baseline only; admission must add every live growth claim.
    pub const MAX_SCRATCH: u64 = 300_000_000_000;
    pub const MINIMUM_FREE: u64 = 248_289_182_611 + MAX_SCRATCH + (160 << 30);
    pub const MAX_RUNTIME: u64 = 259_200;
    pub const SNAPSHOT_SIZE: u64 = 8_215_471_895;
    pub const PLAN_SCHEMA: &str =
        "jetstreamer-private-epoch204-shrink-root-prefix-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch204-shrink-root-prefix-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch204-shrink-root-prefix-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-204-shrink-root-prefix-resource-";
    pub const ROOT_PREFIX: &str = "shrink-root-prefix-resource-204-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-88559361-83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_16";
    pub const SNAPSHOT: &str = "d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6";
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
            // run() has independently hashed every immutable input and copied
            // only genesis. execute_prepared() returns here before measure_root,
            // resource sampling, child spawn or any replay entry.
            let arguments: Vec<_> = cmd
                .get_args()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();
            persist(
                &p.run_root.join("receipts/capability.json"),
                &json!({
                    "schema":"jetstreamer-private-epoch204-capped-prefix-input-capability-v1",
                    "epoch":EPOCH,"unit":p.unit,"invocation_id":invocation,
                    "runner_sha256":bindings["self_sha256"],"plan":bindings,
                    "node_sha256":p.node.sha256,"worker_sha256":WORKER,
                    "snapshot_sha256":SNAPSHOT,"snapshot_bytes":SNAPSHOT_SIZE,
                    "epoch_hashes_sha256":p.epoch_hashes.sha256,
                    "bootstrap_slot":88127580,"terminal_root_slot":TERMINAL,
                    "output_slot_start":88128000,"output_slot_count":431362,
                    "node_arguments":arguments,"all_immutable_inputs_rehashed":true,
                    "worker_spawned":false,"snapshot_restored":false,"archive_created":false,
                    "replay_launch_authorized":false,"canonical_prefix_qualified":false,
                    "full_cold_epoch_peak_qualified":false,"publication_authorized":false,
                    "remote_mutations":false,"r2_mutations":false
                }),
            )
        }
    }
    pub(super) fn input_capability() {
        main_with_storage(&InputCapability);
    }
    #[cfg(test)]
    mod tests204 {
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
                snapshot: PathBuf::from(format!("/sealed/{SNAPSHOT_NAME}")),
                ledger_directory: "/sealed".into(),
                epoch_hashes: BoundFile {
                    path: "/sealed/epoch-hashes-204.txt".into(),
                    sha256: "b".repeat(64),
                },
                run_root: PathBuf::from(format!(
                    "/home/ubuntu/.jetstreamer-private/{ROOT_PREFIX}test"
                )),
                target_slot: TARGET,
                terminal_slot: TERMINAL,
                minimum_free_bytes: MINIMUM_FREE,
                maximum_runtime_seconds: MAX_RUNTIME,
            }
        }
        #[test]
        fn input_capability_dispatch_cannot_spawn_even_an_absent_parent() {
            let temp = tempfile::tempdir().unwrap();
            fs::create_dir(temp.path().join("receipts")).unwrap();
            fs::set_permissions(
                temp.path().join("receipts"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            let mut p = plan();
            p.run_root = temp.path().into();
            let mut cmd = Command::new("/nonexistent-epoch204-parent-must-not-run");
            execute_prepared(
                &InputCapability,
                &p,
                &"a".repeat(32),
                Path::new("/no-cgroup-access"),
                &mut cmd,
                &json!({"self_sha256":"b".repeat(64)}),
            )
            .unwrap();
            let r: Value = serde_json::from_slice(
                &fs::read(temp.path().join("receipts/capability.json")).unwrap(),
            )
            .unwrap();
            for key in [
                "worker_spawned",
                "snapshot_restored",
                "archive_created",
                "replay_launch_authorized",
                "canonical_prefix_qualified",
                "publication_authorized",
                "r2_mutations",
            ] {
                assert_eq!(r[key], false, "{key}");
            }
            assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
            assert!(
                execute_prepared(
                    &InputCapability,
                    &p,
                    &"a".repeat(32),
                    Path::new("/no-cgroup-access"),
                    &mut cmd,
                    &json!({"self_sha256":"b".repeat(64)})
                )
                .is_err()
            );
        }
        #[test]
        fn launch_scope_cannot_borrow_bounded_probe_or_relax_resources() {
            validate_plan(&plan()).unwrap();
            for which in 0..7 {
                let mut p = plan();
                match which {
                    0 => p.target_slot = 88_584_000,
                    1 => p.terminal_slot = 88_991_999,
                    2 => p.minimum_free_bytes -= 1,
                    3 => p.maximum_runtime_seconds += 1,
                    4 => p.unit = "horizon-qualify-204-bounded-resource-test.service".into(),
                    5 => {
                        p.run_root =
                            "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-203-test"
                                .into()
                    }
                    _ => p.node.sha256 = "c".repeat(64),
                }
                assert!(validate_plan(&p).is_err());
            }
            let p = plan();
            let c = command(&p);
            let args: Vec<_> = c.get_args().map(|a| a.to_str().unwrap()).collect();
            assert!(args.contains(&"--verify"));
            assert!(args.contains(&"--qualification-end-slot=88559361"));
            assert!(
                args.iter()
                    .any(|a| a.ends_with("/output/epoch-204-prefix.jet"))
            );
            assert!(
                !args
                    .iter()
                    .any(|a| a.contains("publish") || a.contains("root-checkpoint-cohort"))
            );
        }
        fn manifest() -> Value {
            json!({"schema_version":1,"epoch":204,"output_slot_start":88128000,
                "output_slot_count":431362,"worker_executable_sha256":WORKER,
                "runtime":{"runtime_profile":"solana-v1.6.16"},
                "bootstrap":{"slot":88127580,"slot_complete":true,
                    "accounts_hash":"4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"},
                "terminal":{"slot":88559361,"slot_complete":true,
                    "accounts_hash":"83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA"},
                "archive_sha256":"a".repeat(64)})
        }
        #[test]
        fn complete204_prefix_rejects_short_probe_foreign_worker_or_full_epoch() {
            root_manifest_valid(&manifest()).unwrap();
            for (pointer, changed) in [
                ("/epoch", json!(203)),
                ("/output_slot_start", json!(88127581)),
                ("/output_slot_count", json!(24000)),
                ("/output_slot_count", json!(432000)),
                ("/terminal/slot", json!(88584000)),
                ("/terminal/slot", json!(88991999)),
                (
                    "/terminal/accounts_hash",
                    json!("4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"),
                ),
                ("/bootstrap/accounts_hash", Value::Null),
                (
                    "/worker_executable_sha256",
                    json!("3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"),
                ),
                ("/runtime/runtime_profile", json!("solana-v1.6.25")),
                ("/terminal/slot_complete", json!(false)),
            ] {
                let mut m = manifest();
                *m.pointer_mut(pointer).unwrap() = changed;
                assert!(root_manifest_valid(&m).is_err(), "accepted {pointer}");
            }
        }
        #[test]
        fn root_marker_requires_exact_parent_logger_and_checkpoint() {
            let good = "[2026 INFO  jetstreamer_node::historical_replay] historical checkpoint slot=88559361 bank_hash=x complete=true";
            assert!(root_checkpoint_marker(good));
            for bad in [
                good.replace("88559361", "88584000"),
                good.replace("INFO", "ERROR"),
                good.replace("complete=true", "complete=false"),
                good.replace("jetstreamer_node::historical_replay", "program_log"),
            ] {
                assert!(!root_checkpoint_marker(&bad));
            }
        }
    }
}
fn main() {
    if std::env::args().next_back().as_deref() == Some("--storage-capability") {
        bounded_resource_runner::input_capability();
    } else {
        bounded_resource_runner::main();
    }
}
