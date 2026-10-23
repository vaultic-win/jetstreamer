//! Private capped-shrink205 prefix; no suffix, publication or runtime promotion.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = true;
    pub const ARCHIVE_NAME: &str = "epoch-205-prefix.jet";
    pub const PARENT_SHA: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
    pub const RAYON_THREADS: u32 = 16;
    pub const EPOCH: u64 = 205;
    pub const TARGET: u64 = 88_991_050;
    pub const TERMINAL: u64 = TARGET;
    pub const INITIAL_REPLAY: u64 = 88_559_362;
    // User-selected century scratch allowance plus separate output/margin.
    // Rejection baseline only; admission must add every live growth claim.
    pub const MAX_SCRATCH: u64 = 300_000_000_000;
    pub const MINIMUM_FREE: u64 = 248_289_182_611 + MAX_SCRATCH + (160 << 30);
    pub const MAX_RUNTIME: u64 = 259_200;
    pub const SNAPSHOT_SIZE: u64 = 8_225_957_010;
    pub const PLAN_SCHEMA: &str =
        "jetstreamer-private-epoch205-shrink-root-prefix-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch205-shrink-root-prefix-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch205-shrink-root-prefix-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-205-shrink-root-prefix-resource-";
    pub const ROOT_PREFIX: &str = "shrink-root-prefix-resource-205-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-88559361-83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-88991050-BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_16";
    pub const SNAPSHOT: &str = "24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e";
}
mod bounded_resource_runner {
    include!("bounded_resource_runner.rs");
    #[cfg(test)]
    mod tests205 {
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
                    path: "/sealed/epoch-hashes-205.txt".into(),
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
        fn launch_scope_cannot_borrow_bounded_probe_or_relax_resources() {
            validate_plan(&plan()).unwrap();
            for which in 0..7 {
                let mut p = plan();
                match which {
                    0 => p.target_slot = 88_584_000,
                    1 => p.terminal_slot = 88_991_999,
                    2 => p.minimum_free_bytes -= 1,
                    3 => p.maximum_runtime_seconds += 1,
                    4 => p.unit = "horizon-qualify-205-bounded-resource-test.service".into(),
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
            assert!(args.contains(&"--qualification-end-slot=88991050"));
            assert!(
                args.iter()
                    .any(|a| a.ends_with("/output/epoch-205-prefix.jet"))
            );
            assert!(
                !args
                    .iter()
                    .any(|a| a.contains("publish") || a.contains("root-checkpoint-cohort"))
            );
        }
        fn manifest() -> Value {
            json!({"schema_version":1,"epoch":205,"output_slot_start":88560000,
                "output_slot_count":431051,"worker_executable_sha256":WORKER,
                "runtime":{"runtime_profile":"solana-v1.6.16"},
                "bootstrap":{"slot":88559361,"slot_complete":true,
                    "accounts_hash":"83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA"},
                "terminal":{"slot":88991050,"slot_complete":true,
                    "accounts_hash":"BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp"},
                "archive_sha256":"a".repeat(64)})
        }
        #[test]
        fn complete205_prefix_rejects_short_probe_foreign_worker_or_full_epoch() {
            root_manifest_valid(&manifest()).unwrap();
            for (pointer, changed) in [
                ("/epoch", json!(203)),
                ("/output_slot_start", json!(88559362)),
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
            let good = "[2026 INFO  jetstreamer_node::historical_replay] historical checkpoint slot=88991050 bank_hash=x complete=true";
            assert!(root_checkpoint_marker(good));
            for bad in [
                good.replace("88991050", "88584000"),
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
    bounded_resource_runner::main();
}
