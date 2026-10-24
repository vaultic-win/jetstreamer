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
        fn target_stop_protocol(&self) -> TargetStopProtocol {
            warmup_target_protocol(
                RUNTIME,
                PARENT_SHA,
                WORKER,
                INITIAL_REPLAY,
                TARGET,
                TERMINAL,
            )
        }
        fn progress_slot(&self, line: &str) -> Option<u64> {
            warmup_complete_slot(line)
        }
        fn progress_counters(&self, line: &str) -> Option<Value> {
            let slot = warmup_slot(line)?;
            let counter = |prefix: &str| {
                line.split_whitespace()
                    .find_map(|s| s.strip_prefix(prefix))
                    .and_then(|s| s.parse::<u64>().ok())
            };
            Some(
                json!({"slot":slot,"transactions":counter("txs=")?,"account_updates":counter("accounts=")?}),
            )
        }
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
            let mut capability = json!({
                "schema":CAPABILITY_SCHEMA,"invocation_id":iid,
                "bindings":bindings,"node_sha256":PARENT_SHA,"worker_sha256":WORKER,"parent_planning_report":report,
                "snapshot_sha256":SNAPSHOT,"worker_entry_start":INITIAL_REPLAY,"worker_entry_end_exclusive":TARGET+1,
                "parent_requested_root":TERMINAL,"input_hashes_and_private_paths_verified":true,
                "worker_started":false,"entry_replay":false,"resource_observation_performed":false,
                "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
            if self.target_stop_protocol() == TargetStopProtocol::CooperativeResumeOnly {
                capability["target_stop_protocol"] = json!(self.target_stop_protocol().label());
            }
            persist(&p.run_root.join("receipts/capability.json"), &capability)
        }
        fn before_spawn(&self, _p: &Plan, _iid: &str) -> Result<Value> {
            ensure!(
                available_memory()? >= INITIAL_AVAILABLE,
                "warmup memory admission"
            );
            ensure!(
                free_bytes(&_p.run_root)? >= ENFORCED_FREE.max(MINIMUM_FREE),
                "warmup protected free-space admission"
            );
            Ok(
                json!({"worker_entry_start":INITIAL_REPLAY,"worker_entry_end_exclusive":TARGET+1,
                "parent_requested_root":TERMINAL,"parent_request_is_not_worker_scope":true,
                "scratch_planning_bytes":MAX_SCRATCH,"enforced_filesystem_floor_bytes":ENFORCED_FREE,
                "minimum_available_memory_bytes":MEMORY_RESERVE,"initial_available_memory_bytes":INITIAL_AVAILABLE,
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
                ensure!(available_memory()? >= MEMORY_RESERVE, "host-memory reserve");
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
    fn warmup_target_protocol(
        runtime: &str,
        parent: &str,
        worker: &str,
        initial: u64,
        target: u64,
        terminal: u64,
    ) -> TargetStopProtocol {
        if runtime == "solana-v1.6.20"
            && parent == "99f643ff0dbbcd37d1fbc524a1c1088d7273c7fc91330df059d30d51b8b0fcd4"
            && worker == "52d6c86a8103b8965ca68ead96af471a7899a0a0e6e69c48989b39fd5d922f0c"
            && initial == 96_335_539
            && target == 96_335_554
            && terminal == 96_767_522
        {
            TargetStopProtocol::CooperativeResumeOnly
        } else {
            TargetStopProtocol::ResumeAndInterrupt
        }
    }
    fn warmup_complete_slot(line: &str) -> Option<u64> {
        let (prefix, tail) =
            line.split_once(" jetstreamer_node] private epoch223 warmup complete slot=")?;
        (prefix.starts_with('[')
            && prefix.trim_end().ends_with(" INFO")
            && tail.trim() == format!("{TARGET} complete=true"))
        .then_some(TARGET)
    }
    fn warmup_slot(line: &str) -> Option<u64> {
        if let Some(slot) = warmup_complete_slot(line) {
            return Some(slot);
        }
        let (prefix, tail) = line.split_once(" jetstreamer_node] warmup slot ")?;
        if !prefix.starts_with('[') || !prefix.trim_end().ends_with(" INFO") {
            return None;
        }
        let (slot, rest) = tail.split_once('/')?;
        if rest.split_whitespace().next()?.parse::<u64>().ok()? != 96_335_999
            || !tail.trim_end().ends_with("(recording starts at 96336000)")
        {
            return None;
        }
        let slot = slot.parse::<u64>().ok()?;
        (INITIAL_REPLAY..=TARGET).contains(&slot).then_some(slot)
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
        extern "C" fn fixture_force_exit(_: i32) {
            unsafe {
                libc::_exit(130);
            }
        }
        #[test]
        fn cooperative_child_fixture() {
            let Ok(root) = env::var("JETSTREAMER_TEST_EPOCH223_WARMUP_ROOT") else {
                return;
            };
            let root = PathBuf::from(root);
            assert!(
                root.starts_with(env::temp_dir())
                    && root
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("epoch223-warmup-fixture-")
            );
            let accounts = root.join("scratch/runtime/accounts-state");
            fs::create_dir_all(&accounts).unwrap();
            fs::write(accounts.join("1.0"), b"fixture accounts").unwrap();
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = fixture_force_exit as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
                assert_eq!(
                    libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()),
                    0
                );
            }
            eprintln!(
                "[2026-10-23T20:44:33Z INFO  jetstreamer_node] private epoch223 warmup complete slot={TARGET} complete=true"
            );
            assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
            // Simulate ordinary shutdown drainage; a second interrupt is fatal,
            // exactly as in the sealed parent's already-set shutdown handler.
            thread::sleep(Duration::from_millis(100));
            fs::remove_dir_all(accounts).unwrap();
            std::process::exit(0);
        }
        fn fixture_command(root: &Path) -> Command {
            let mut command = Command::new(env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "bounded_resource_runner::warmup_tests::cooperative_child_fixture",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("JETSTREAMER_TEST_EPOCH223_WARMUP_ROOT", root)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0);
            command
        }
        #[test]
        fn cooperative_complete_slot_freezes_captures_then_resumes_and_drains_without_interrupt() {
            struct Fixture;
            impl StorageHooks for Fixture {
                fn progress_slot(&self, line: &str) -> Option<u64> {
                    warmup_complete_slot(line)
                }
                fn target_stop_protocol(&self) -> TargetStopProtocol {
                    TargetStopProtocol::CooperativeResumeOnly
                }
            }
            let t = tempfile::Builder::new()
                .prefix("epoch223-warmup-fixture-")
                .tempdir()
                .unwrap();
            for name in ["scratch", "output", "receipts", "cgroup"] {
                let d = t.path().join(name);
                fs::create_dir(&d).unwrap();
                fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
            }
            for name in [
                "memory.current",
                "memory.peak",
                "memory.events",
                "memory.stat",
                "cpu.stat",
                "io.stat",
                "memory.pressure",
                "io.pressure",
            ] {
                fs::write(t.path().join("cgroup").join(name), b"0\n").unwrap();
            }
            let mut p = plan();
            p.run_root = t.path().into();
            p.minimum_free_bytes = 0;
            p.maximum_runtime_seconds = 10;
            measure(&p,&"a".repeat(32),&t.path().join("cgroup"),&mut fixture_command(t.path()),&json!({"self_sha256":"a".repeat(64),"plan_path":"/fixture","plan_sha256":"b".repeat(64)}),&Fixture).unwrap();
            let result: Value =
                serde_json::from_slice(&fs::read(t.path().join("receipts/resource.json")).unwrap())
                    .unwrap();
            let intent: Value = serde_json::from_slice(
                &fs::read(t.path().join("receipts/target-stop.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(result["success"], true);
            assert_eq!(result["child_return_code"], 0);
            assert_eq!(result["target_reached"], true);
            assert_eq!(result["external_signal"], 0);
            assert_eq!(result["target_stop_protocol"], "cooperative-resume-only");
            assert_eq!(intent["target_stop_protocol"], "cooperative-resume-only");
            assert_eq!(result["capture"]["accounts_state"]["regular_files"], 1);
            assert!(
                result["authority"]
                    .as_object()
                    .unwrap()
                    .values()
                    .all(|v| v == false)
            );
            assert!(!t.path().join("scratch/runtime/accounts-state").exists());
            assert!(!t.path().join("receipts/failure.json").exists());
        }
        #[test]
        fn legacy_resume_still_interrupts_and_exit130_cannot_qualify() {
            let t = tempfile::Builder::new()
                .prefix("epoch223-warmup-fixture-")
                .tempdir()
                .unwrap();
            let mut child = ChildGroup(fixture_command(t.path()).spawn().unwrap(), false);
            // Establish the same already-self-stopped state as failed 13a5.
            prepare_target_capture(child.0.id(), TargetStopProtocol::CooperativeResumeOnly)
                .unwrap();
            resume_target(child.0.id(), TargetStopProtocol::ResumeAndInterrupt).unwrap();
            let status = child.0.wait().unwrap();
            child.1 = true;
            assert_eq!(status.code(), Some(130));
            assert!(!controlled_success(true, 0, status.code()));
            assert!(!controlled_success(false, 0, Some(0)));
            assert!(!controlled_success(true, libc::SIGTERM, Some(0)));
        }
        #[test]
        fn cooperative_protocol_requires_exact_native20_parent_worker_and_first16_scope() {
            let p = "99f643ff0dbbcd37d1fbc524a1c1088d7273c7fc91330df059d30d51b8b0fcd4";
            let w = "52d6c86a8103b8965ca68ead96af471a7899a0a0e6e69c48989b39fd5d922f0c";
            assert_eq!(
                warmup_target_protocol("solana-v1.6.20", p, w, 96335539, 96335554, 96767522),
                TargetStopProtocol::CooperativeResumeOnly
            );
            for (runtime, parent, worker, initial, target, terminal) in [
                ("solana-v1.6.25", p, w, 96335539, 96335554, 96767522),
                (
                    "solana-v1.6.20",
                    "old-parent",
                    w,
                    96335539,
                    96335554,
                    96767522,
                ),
                (
                    "solana-v1.6.20",
                    p,
                    "a651b7a6ee3c0d4f8359e1ea6cfcb96becf259d440ee744beb173b264de6af20",
                    96335539,
                    96335554,
                    96767522,
                ),
                ("solana-v1.6.20", p, w, 96335540, 96335554, 96767522),
                ("solana-v1.6.20", p, w, 96335539, 96335555, 96767522),
                ("solana-v1.6.20", p, w, 96335539, 96335554, 96767999),
            ] {
                assert_eq!(
                    warmup_target_protocol(runtime, parent, worker, initial, target, terminal),
                    TargetStopProtocol::ResumeAndInterrupt
                );
            }
            let configured = WarmupStorage {
                next_guard: std::sync::Mutex::new(Instant::now()),
            }
            .target_stop_protocol();
            assert_eq!(
                configured,
                if RUNTIME == "solana-v1.6.20" {
                    TargetStopProtocol::CooperativeResumeOnly
                } else {
                    TargetStopProtocol::ResumeAndInterrupt
                }
            );
            assert_eq!(
                DiskStorage.target_stop_protocol(),
                TargetStopProtocol::ResumeAndInterrupt
            );
        }
        #[test]
        fn only_verified_complete_slot_marker_triggers_capture() {
            let marker = format!(
                "[2026-10-23T19:00:00Z INFO jetstreamer_node] private epoch223 warmup complete slot={TARGET} complete=true"
            );
            assert_eq!(warmup_complete_slot(&marker), Some(TARGET));
            assert_eq!(
                warmup_complete_slot(&marker.replace(" INFO ", " INFO  ")),
                Some(TARGET)
            );
            for bad in [
                marker.replace("jetstreamer_node]", "other_module]"),
                marker.replace("complete=true", "complete=false"),
                marker.replace(&TARGET.to_string(), &(TARGET + 1).to_string()),
                format!("program log: {marker}"),
                format!("{marker} trailing"),
            ] {
                assert_eq!(warmup_complete_slot(&bad), None);
            }
            let log = format!(
                "[2026-10-23T19:00:00Z INFO jetstreamer_node] warmup slot {TARGET}/96335999 txs=123 accounts=456 (recording starts at 96336000)"
            );
            assert_eq!(warmup_slot(&log), Some(TARGET));
            assert_eq!(warmup_slot(&log.replace(" INFO ", " INFO  ")), Some(TARGET));
            assert_eq!(warmup_complete_slot(&log), None);
            let storage = WarmupStorage {
                next_guard: std::sync::Mutex::new(Instant::now()),
            };
            assert_eq!(storage.progress_slot(&log), None);
            assert_eq!(
                storage.progress_counters(&log).unwrap(),
                json!({"slot":TARGET,"transactions":123,"account_updates":456})
            );
            for bad in [
                log.replace("jetstreamer_node]", "other_module]"),
                log.replace("/96335999", "/96767522"),
                log.replace("starts at 96336000", "starts at 96336001"),
                log.replace("warmup slot", "progress slot"),
                log.replace(&format!("{TARGET}/"), &format!("{}/", TARGET + 1)),
            ] {
                assert_eq!(warmup_slot(&bad), None);
            }
        }
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
            assert!(ENFORCED_FREE > 0);
            assert_eq!(INITIAL_AVAILABLE, MEMORY_RESERVE + (128u64 << 30));
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
