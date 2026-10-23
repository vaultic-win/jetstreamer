//! Dormant native v1.6.20 known-root prefix; no epoch/publication authority.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = true;
    pub const ARCHIVE_NAME: &str = "epoch-223.jet";
    pub const PARENT_SHA: &str = "99f643ff0dbbcd37d1fbc524a1c1088d7273c7fc91330df059d30d51b8b0fcd4";
    pub const RAYON_THREADS: u32 = 2;
    pub const EPOCH: u64 = 223;
    pub const TARGET: u64 = 96_767_522;
    pub const TERMINAL: u64 = TARGET;
    pub const INITIAL_REPLAY: u64 = 96_335_539;
    // Century scratch planning only; output/margin and other owners are extra.
    // Fresh whole-fleet admission and an invocation-bound guard are mandatory.
    pub const MINIMUM_FREE: u64 = 548_289_182_611;
    pub const MAX_SCRATCH: u64 = 300_000_000_000;
    pub const MAX_RUNTIME: u64 = 259200;
    pub const SNAPSHOT_SIZE: u64 = 9_815_262_303;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch223-v1620-root-prefix-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch223-v1620-root-prefix-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch223-v1620-root-prefix-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-223-v1620-root-prefix-resource-";
    pub const ROOT_PREFIX: &str = "qualification-223-v1620-prefix-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = "a651b7a6ee3c0d4f8359e1ea6cfcb96becf259d440ee744beb173b264de6af20";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_20";
    pub const SNAPSHOT: &str = "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
}
mod bounded_resource_runner {
    include!("bounded_resource_runner.rs");
    struct Prefix20;
    impl StorageHooks for Prefix20 {
        fn capability_only(&self) -> bool {
            env::args()
                .next_back()
                .is_some_and(|s| s == "--storage-capability")
        }
        fn capability_result(
            &self,
            p: &Plan,
            iid: &str,
            bindings: &Value,
            _: &Command,
        ) -> Result<()> {
            let output = command(p).arg("--epoch223-prefix-preflight").output()?;
            ensure!(
                output.status.success(),
                "parent planning rejected native20 prefix: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report = planning_report(std::str::from_utf8(&output.stdout)?, &p.worker)?;
            persist(
                &p.run_root.join("receipts/capability.json"),
                &json!({
                "schema":"jetstreamer-private-epoch223-v1620-root-prefix-capability-v1",
                "invocation_id":iid,"bindings":bindings,"parent_planning_report":report,
                "node_sha256":PARENT_SHA,"worker_sha256":WORKER,"snapshot_sha256":SNAPSHOT,
                "entry_replay":false,"worker_started":false,"resource_observation_performed":false,
                "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
            )
        }
    }
    fn planning_report(text: &str, worker: &Path) -> Result<Value> {
        ensure!(text.len() <= 1 << 20, "planning output bound");
        let rows = text
            .lines()
            .filter_map(|s| serde_json::from_str::<Value>(s).ok())
            .filter(|v| v["schema"] == "jetstreamer-private-epoch223-prefix-planning-preflight-v1")
            .collect::<Vec<_>>();
        ensure!(rows.len() == 1, "missing/duplicate planning report");
        let r = rows.into_iter().next().unwrap();
        ensure!(
            r["epoch"] == EPOCH
                && r["bootstrap_slot"] == 96_335_538u64
                && r["terminal_slot"] == TERMINAL
                && r["runtime_profile"] == "solana-v1.6.20"
                && r["runtime_revision"] == "77bdb45d4af61fc687161ec06cc0178ff79726d5"
                && r["worker_identity"] == "jetstreamer-historical-worker-v1-6-20"
                && r["worker_environment_override"] == WORKER_ENV
                && r["worker_executable"].as_str() == worker.to_str()
                && r["pre_worker_barrier_reached"] == true
                && r["runtime_checkpoint_policy_validated"] == true
                && r["worker_profile_validated"] == true
                && r["worker_spawned"] == false
                && r["archive_created"] == false
                && r["publication_authorized"] == false,
            "wrong native20 planning envelope"
        );
        Ok(r)
    }
    pub(super) fn entry() {
        main_with_storage(&Prefix20);
    }
    #[cfg(test)]
    mod native20_tests {
        use super::*;
        #[test]
        fn native20_plan_and_preflight_cannot_borrow_warmup_tail_or_runtime25() {
            let mut p = Plan {
                schema: PLAN_SCHEMA.into(),
                unit: format!("{UNIT_PREFIX}test.service"),
                node: BoundFile {
                    path: "/sealed/node".into(),
                    sha256: PARENT_SHA.into(),
                },
                worker: "/sealed/worker".into(),
                snapshot: format!("/sealed/{SNAPSHOT_NAME}").into(),
                ledger_directory: "/sealed".into(),
                epoch_hashes: BoundFile {
                    path: "/sealed/hashes".into(),
                    sha256: "b".repeat(64),
                },
                run_root: format!("/home/ubuntu/.jetstreamer-private/{ROOT_PREFIX}test").into(),
                target_slot: TARGET,
                terminal_slot: TERMINAL,
                minimum_free_bytes: MINIMUM_FREE,
                maximum_runtime_seconds: MAX_RUNTIME,
            };
            validate_plan(&p).unwrap();
            assert!(
                command(&p)
                    .get_args()
                    .any(|s| s == "--qualification-end-slot=96767522")
            );
            p.target_slot = 96_335_554;
            assert!(validate_plan(&p).is_err());
            p.target_slot = TARGET;
            p.run_root =
                "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-prefix-test".into();
            assert!(validate_plan(&p).is_err());
            let report = json!({"schema":"jetstreamer-private-epoch223-prefix-planning-preflight-v1",
                "epoch":EPOCH,"bootstrap_slot":96335538,"terminal_slot":TERMINAL,
                "runtime_profile":"solana-v1.6.20","runtime_revision":"77bdb45d4af61fc687161ec06cc0178ff79726d5",
                "worker_identity":"jetstreamer-historical-worker-v1-6-20","worker_environment_override":WORKER_ENV,
                "worker_executable":"/sealed/worker","pre_worker_barrier_reached":true,
                "runtime_checkpoint_policy_validated":true,"worker_profile_validated":true,
                "worker_spawned":false,"archive_created":false,"publication_authorized":false});
            planning_report(&report.to_string(), Path::new("/sealed/worker")).unwrap();
            for key in [
                "epoch",
                "terminal_slot",
                "runtime_profile",
                "runtime_revision",
                "worker_identity",
                "worker_environment_override",
                "worker_executable",
                "pre_worker_barrier_reached",
                "runtime_checkpoint_policy_validated",
                "worker_profile_validated",
                "worker_spawned",
                "archive_created",
                "publication_authorized",
            ] {
                let mut bad = report.clone();
                bad[key] = Value::Null;
                assert!(
                    planning_report(&bad.to_string(), Path::new("/sealed/worker")).is_err(),
                    "{key}"
                );
            }
        }
        fn manifest() -> Value {
            json!({"schema_version":1,"epoch":223,"output_slot_start":96336000,"output_slot_count":431523,
                "worker_executable_sha256":WORKER,"archive_sha256":"a".repeat(64),
                "runtime":{"runtime_profile":"solana-v1.6.20"},
                "bootstrap":{"slot":96335538,"slot_complete":true,"accounts_hash":"Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE","bank_hash":"8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"},
                "terminal":{"slot":96767522,"slot_complete":true,"accounts_hash":"3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7","bank_hash":"EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB"}})
        }
        #[test]
        fn native20_requires_full_worker_and_both_real_canonical_roots() {
            root_manifest_valid(&manifest()).unwrap();
            for key in [
                "schema_version",
                "epoch",
                "output_slot_start",
                "output_slot_count",
                "worker_executable_sha256",
                "archive_sha256",
            ] {
                let mut bad = manifest();
                bad[key] = Value::Null;
                assert!(root_manifest_valid(&bad).is_err());
            }
            for point in ["bootstrap", "terminal"] {
                for key in ["slot", "slot_complete", "accounts_hash", "bank_hash"] {
                    let mut bad = manifest();
                    bad[point][key] = Value::Null;
                    assert!(root_manifest_valid(&bad).is_err());
                }
            }
            for worker in [
                "fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c",
                "52d6c86a8103b8965ca68ead96af471a7899a0a0e6e69c48989b39fd5d922f0c",
            ] {
                let mut bad = manifest();
                bad["worker_executable_sha256"] = json!(worker);
                assert!(root_manifest_valid(&bad).is_err());
            }
            let mut bad = manifest();
            bad["runtime"]["runtime_profile"] = json!("solana-v1.6.25");
            assert!(root_manifest_valid(&bad).is_err());
            assert_eq!(MAX_SCRATCH, 300_000_000_000);
        }
    }
}
fn main() {
    bounded_resource_runner::entry();
}
