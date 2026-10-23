//! Private failure-context reproduction using an entry-bounded worker.
//! The old parent requires an epoch/root output range, so it retains that request.
//! The exact worker rejects every entry after96335554 before decoding or mutation.
//! Neither a target stop nor any produced artifact qualifies an epoch or root.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = false;
    pub const ARCHIVE_NAME: &str = "epoch-223.jet";
    pub const PARENT_SHA: &str = "90474659be2a4a7d1cc9d4dfe3d5ab1587adb1b388b83163b2bf16c771624f66";
    pub const WORKER: &str = "b99691fd5995fe5f06e508cfd8f156b8e5cb7342ddab503fb2383e42e712d025";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_25";
    pub const RAYON_THREADS: u32 = 2;
    pub const EPOCH: u64 = 223;
    pub const TARGET: u64 = 96_335_554;
    pub const TERMINAL: u64 = 96_767_522;
    pub const INITIAL_REPLAY: u64 = 96_335_539;
    pub const MINIMUM_FREE: u64 = 548_289_182_611;
    pub const MAX_SCRATCH: u64 = 300_000_000_000;
    pub const MAX_RUNTIME: u64 = 3600;
    pub const SNAPSHOT_SIZE: u64 = 9_815_262_303;
    pub const SNAPSHOT: &str = "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME];
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch223-warmup-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch223-warmup-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch223-warmup-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-223-warmup-resource-";
    pub const ROOT_PREFIX: &str = "qualification-223-v1625-warmup-";
}
mod bounded_resource_runner {
    include!("bounded_resource_runner.rs");
    struct WarmupStorage {
        next_guard: std::sync::Mutex<Instant>,
    }
    fn available_memory() -> Result<u64> {
        let text = fs::read_to_string("/proc/meminfo")?;
        ensure!(text.len() <= 65536, "meminfo bounds");
        let rows = text
            .lines()
            .filter_map(|line| line.strip_prefix("MemAvailable:"))
            .collect::<Vec<_>>();
        ensure!(rows.len() == 1, "available memory missing/duplicate");
        let fields = rows[0].split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() == 2 && fields[1] == "kB",
            "available memory format"
        );
        fields[0]
            .parse::<u64>()?
            .checked_mul(1024)
            .context("available memory overflow")
    }
    impl StorageHooks for WarmupStorage {
        fn before_spawn(&self, _p: &Plan, _iid: &str) -> Result<Value> {
            ensure!(
                available_memory()? >= (448 + 128) * (1u64 << 30),
                "warmup memory admission"
            );
            Ok(
                json!({"worker_entry_start":INITIAL_REPLAY,"worker_entry_end_exclusive":TARGET+1,
                "parent_requested_root":TERMINAL,"parent_request_is_not_worker_scope":true,
                "maximum_scratch_bytes":MAX_SCRATCH,"canonical_prefix_qualified":false}),
            )
        }
        fn guard(
            &self,
            p: &Plan,
            iid: &str,
            child: u32,
            _elapsed: Duration,
            _draining: bool,
        ) -> Result<()> {
            let mut next = self
                .next_guard
                .lock()
                .map_err(|_| anyhow::anyhow!("guard lock poisoned"))?;
            if Instant::now() < *next {
                return Ok(());
            }
            *next = Instant::now() + Duration::from_secs(15);
            let check = (|| -> Result<()> {
                ensure!(
                    available_memory()? >= 448 * (1u64 << 30),
                    "host-memory reserve"
                );
                ensure!(
                    free_bytes(&p.run_root)? >= 248_289_182_611,
                    "century disk floor"
                );
                scratch(&p.run_root.join("scratch"))?;
                Ok(())
            })();
            if let Err(error) = check {
                persist(
                    &p.run_root.join("receipts/guard-stop.json"),
                    &json!({"schema":"jetstreamer-private-epoch223-warmup-guard-stop-v1",
                    "invocation_id":iid,"child_pid":child,"reason":format!("{error:#}"),"publication_authorized":false,"r2_mutations":false}),
                )?;
                return Err(error);
            }
            Ok(())
        }
    }
    pub(super) fn entry() {
        main_with_storage(&WarmupStorage {
            next_guard: std::sync::Mutex::new(Instant::now()),
        });
    }
    #[cfg(test)]
    mod warmup_tests {
        use super::*;
        fn plan() -> Plan {
            Plan {
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
                    sha256: "a".repeat(64),
                },
                run_root: format!("/home/ubuntu/.jetstreamer-private/{ROOT_PREFIX}test").into(),
                target_slot: TARGET,
                terminal_slot: TERMINAL,
                minimum_free_bytes: MINIMUM_FREE,
                maximum_runtime_seconds: MAX_RUNTIME,
            }
        }
        #[test]
        fn worker_envelope_is_separate_from_parent_root_request_and_denies_root_success() {
            let p = plan();
            validate_plan(&p).unwrap();
            let cmd = command(&p);
            let args = cmd
                .get_args()
                .map(|s| s.to_str().unwrap())
                .collect::<Vec<_>>();
            assert!(args.contains(&"--qualification-end-slot=96767522"));
            assert_eq!(TARGET - INITIAL_REPLAY + 1, 16);
            assert!(root_manifest_valid(&json!({})).is_err());
            assert!(
                cmd.get_envs()
                    .any(|(key, value)| key == WORKER_ENV && value == Some(p.worker.as_os_str()))
            );
            for choice in 0..4 {
                let mut bad = p.clone();
                match choice {
                    0 => bad.target_slot += 1,
                    1 => bad.maximum_runtime_seconds += 1,
                    2 => bad.minimum_free_bytes -= 1,
                    _ => bad.node.sha256 = "b".repeat(64),
                };
                assert!(validate_plan(&bad).is_err());
            }
        }
    }
}
fn main() {
    bounded_resource_runner::entry();
}
