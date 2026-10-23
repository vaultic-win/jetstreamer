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
            _command: &Command,
        ) -> Result<()> {
            let mut planning = command(p);
            let result = planning.arg("--epoch223-prefix-preflight").output()?;
            ensure!(
                result.status.success(),
                "actual parent planning rejected warmup scope: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let report = planning_report(std::str::from_utf8(&result.stdout)?, &p.worker)?;
            persist(
                &p.run_root.join("receipts/capability.json"),
                &json!({
                "schema":CAPABILITY_SCHEMA,"invocation_id":iid,
                "bindings":bindings,"node_sha256":PARENT_SHA,"worker_sha256":WORKER,"parent_planning_report":report,
                "snapshot_sha256":SNAPSHOT,"worker_entry_start":INITIAL_REPLAY,"worker_entry_end_exclusive":TARGET+1,
                "parent_requested_root":TERMINAL,"input_hashes_and_private_paths_verified":true,
                "worker_started":false,"entry_replay":false,"resource_observation_performed":false,
                "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
            )
        }
        fn before_spawn(&self, _p: &Plan, _iid: &str) -> Result<Value> {
            ensure!(
                available_memory()? >= (448 + 128) * (1u64 << 30),
                "warmup memory admission"
            );
            ensure!(
                free_bytes(&_p.run_root)? >= ENFORCED_FREE,
                "warmup protected free-space admission"
            );
            Ok(
                json!({"worker_entry_start":INITIAL_REPLAY,"worker_entry_end_exclusive":TARGET+1,
                "parent_requested_root":TERMINAL,"parent_request_is_not_worker_scope":true,
                "scratch_planning_bytes":MAX_SCRATCH,"enforced_filesystem_floor_bytes":ENFORCED_FREE,
                "canonical_prefix_qualified":false}),
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
                    free_bytes(&p.run_root)? >= ENFORCED_FREE,
                    "protected filesystem floor"
                );
                // Live AccountsDb trees can take minutes to census. Enforce the
                // reserved host free-space floor here; the external guard owns
                // VMA protection. The scratch estimate is not a measured cap.
                Ok(())
            })();
            if let Err(error) = check {
                persist(
                    &p.run_root.join("receipts/guard-stop.json"),
                    &json!({"schema":GUARD_SCHEMA,
                    "invocation_id":iid,"child_pid":child,"reason":format!("{error:#}"),"publication_authorized":false,"r2_mutations":false}),
                )?;
                return Err(error);
            }
            Ok(())
        }
    }
    fn planning_report(text: &str, worker: &Path) -> Result<Value> {
        ensure!(text.len() <= 1 << 20, "parent planning output too large");
        let reports = text
            .lines()
            .filter_map(|s| serde_json::from_str::<Value>(s).ok())
            .filter(|v| v["schema"] == "jetstreamer-private-epoch223-prefix-planning-preflight-v1")
            .collect::<Vec<_>>();
        ensure!(
            reports.len() == 1,
            "missing/duplicate parent planning report"
        );
        let report = reports.into_iter().next().unwrap();
        ensure!(
            report["epoch"] == 223
                && report["bootstrap_slot"] == 96_335_538u64
                && report["terminal_slot"] == TERMINAL
                && report["runtime_profile"] == RUNTIME
                && report["runtime_revision"] == REVISION
                && report["worker_identity"] == WORKER_ID
                && report["worker_environment_override"] == WORKER_ENV
                && report["pre_worker_barrier_reached"] == true
                && report["runtime_checkpoint_policy_validated"] == true
                && report["worker_profile_validated"] == true
                && report["worker_executable"].as_str() == worker.to_str()
                && report["worker_spawned"] == false
                && report["archive_created"] == false
                && report["publication_authorized"] == false,
            "parent planning envelope differs"
        );
        Ok(report)
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
            assert!(ENFORCED_FREE > MINIMUM_FREE);
            assert!(root_manifest_valid(&json!({})).is_err());
            assert!(validate_checkpoint_names(&CHECKPOINT_NAMES.join("\n")).is_ok());
            assert!(validate_checkpoint_names(SNAPSHOT_NAME).is_err());
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
        #[test]
        fn capability_requires_the_actual_parent_barrier_and_no_worker() {
            let report = json!({"schema":"jetstreamer-private-epoch223-prefix-planning-preflight-v1","epoch":223,"bootstrap_slot":96335538,
                "terminal_slot":TERMINAL,"runtime_profile":RUNTIME,"runtime_revision":REVISION,
                "worker_identity":WORKER_ID,"worker_environment_override":WORKER_ENV,
                "pre_worker_barrier_reached":true,"runtime_checkpoint_policy_validated":true,
                "worker_profile_validated":true,"worker_executable":"/sealed/worker","worker_spawned":false,"archive_created":false,"publication_authorized":false});
            planning_report(&report.to_string(), Path::new("/sealed/worker")).unwrap();
            assert!(planning_report("", Path::new("/sealed/worker")).is_err());
            let mut bad = report.clone();
            bad["worker_spawned"] = json!(true);
            assert!(planning_report(&bad.to_string(), Path::new("/sealed/worker")).is_err());
            assert!(planning_report(&report.to_string(), Path::new("/different/worker")).is_err());
            for key in [
                "runtime_profile",
                "runtime_revision",
                "worker_identity",
                "worker_environment_override",
            ] {
                let mut bad = report.clone();
                bad[key] = json!("foreign-runtime");
                assert!(planning_report(&bad.to_string(), Path::new("/sealed/worker")).is_err());
            }
        }
    }
}
fn main() {
    bounded_resource_runner::entry();
}
