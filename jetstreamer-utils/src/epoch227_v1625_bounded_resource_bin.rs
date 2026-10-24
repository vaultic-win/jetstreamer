//! Private epoch 227 v1.6.25 comparison through the original failing complete slot.
//! The transport target is never a canonical checkpoint or publication boundary.
#![recursion_limit = "256"]
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = false;
    pub const ARCHIVE_NAME: &str = "epoch-227-canary.jet";
    pub const PARENT_SHA: &str = "79963ff4872ad7470acced6b04b944a8744ec2de2acccd6d6e843584fcddcb92";
    pub const PARENT_PATH: &str =
        "/var/lib/jetstreamer/horizon-227-v1625-selection-parent-v2/jetstreamer-node";
    pub const WORKER: &str = "d01adb1980ee52a59a7aff7a3a0496746ca325e5fc655817d9a7743a1913ef62";
    pub const WORKER_PATH: &str = "/var/lib/jetstreamer/horizon-227-v1625-diagnostic-d01adb19-v1/jetstreamer-historical-worker-v1-6-25";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_25";
    pub const RUNTIME: &str = "solana-v1.6.25";
    pub const REVISION: &str = "7de8a55b54d3e11058b82f9483bb405d143b455c";
    pub const WORKER_ID: &str = "jetstreamer-historical-worker-v1-6-25";
    pub const EPOCH: u64 = 227;
    pub const TARGET: u64 = 98_091_122;
    pub const TERMINAL: u64 = 98_495_291;
    pub const INITIAL_REPLAY: u64 = 98_063_465;
    pub const RAYON_THREADS: u32 = 8;
    pub const MINIMUM_FREE: u64 = 245_383_154_903;
    pub const MAX_SCRATCH: u64 = 300_000_000_000;
    pub const MAX_RUNTIME: u64 = 21_600;
    pub const MEMORY_MAX: u64 = 225_000_000_000;
    pub const MEMORY_HIGH: u64 = 150_000_000_000;
    pub const INPUT: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-98495291-GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const SNAPSHOT: &str = "77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07";
    pub const SNAPSHOT_SIZE: u64 = 10_261_480_487;
    pub const ACCOUNTS: &str = "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR";
    pub const NATIVE_PROOF: &str =
        "/var/lib/jetstreamer/horizon-native227-v1625-terminal-proof-small-v2/proof.json";
    pub const NATIVE_READONLY: &str = "/var/lib/jetstreamer/horizon-227-v1625-native-qualified-input-readonly-v1/native-proof.json";
    pub const NATIVE_SHA: &str = "da6e00906c266f5993e0332b2abb864558db4ab4c0786d765d1828e658675d7b";
    pub const NATIVE_ORIGIN: &str =
        "/var/lib/jetstreamer/horizon-227-v1625-native-capture-small-v2/intent.json";
    pub const NATIVE_ORIGIN_SHA: &str =
        "0b363d7f7f63854f69d6d6681daad0205ed9f68bc395a08aa30bf1759cca1d8f";
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch227-v1625-comparison-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch227-v1625-comparison-result-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch227-v1625-comparison-stop-v1";
    pub const CAPABILITY_SCHEMA: &str =
        "jetstreamer-private-epoch227-v1625-comparison-capability-v1";
    pub const GUARD_SCHEMA: &str = "jetstreamer-private-epoch227-v1625-comparison-guard-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-227-v1625-bounded-resource-";
    pub const ROOT_PREFIX: &str = "bounded-resource-227-v1625-";
}
mod bounded_resource_runner {
    include!("bounded_resource_runner.rs");
    struct ComparisonStorage {
        next_guard: std::sync::Mutex<Instant>,
    }
    fn scope(p: &Plan) -> Result<()> {
        validate_plan(p)?;
        ensure!(
            p.node.path == Path::new(PARENT_PATH)
                && p.worker == Path::new(WORKER_PATH)
                && p.snapshot == Path::new(INPUT).join(SNAPSHOT_NAME)
                && p.ledger_directory == Path::new(INPUT)
                && p.run_root
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| {
                        s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                    }),
            "227 comparison worker, immutable input or private scope differs"
        );
        Ok(())
    }
    fn native_proof_shape(v: &Value) -> Result<()> {
        ensure!(
            v["schema"] == "jetstreamer-private-epoch227-v1625-native-terminal-proof-v1"
                && v["epoch"] == EPOCH
                && v["unit"] == "horizon-native-input-227-v1625-small-v2.service"
                && v["invocation_id"] == "36b96647e20e41a4a82c92b77b1bb290"
                && v["main_pid"] == 456026
                && v["native_input_qualified"] == true
                && v["running_origin"] == json!({"path":NATIVE_ORIGIN,"sha256":NATIVE_ORIGIN_SHA})
                && v["native_marker"]["slot"] == "98063464"
                && v["native_marker"]["accounts_hash"] == ACCOUNTS
                && v["native_marker"]["replay_entries"] == "0"
                && v["native_marker"]["bootstrap_writes"] == "0",
            "227 comparison lacks its exact independently qualified native input"
        );
        for key in [
            "entry_replay",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(
                v[key] == false,
                "227 native proof grants unrelated authority:{key}"
            );
        }
        Ok(())
    }
    fn qualified_input() -> Result<Value> {
        bound_file(Path::new(NATIVE_READONLY), NATIVE_SHA, 4 << 20)?;
        let proof: Value = serde_json::from_slice(&fs::read(NATIVE_READONLY)?)?;
        native_proof_shape(&proof)?;
        Ok(
            json!({"path":NATIVE_PROOF,"sha256":NATIVE_SHA,"deployed_readonly_input":{"path":NATIVE_READONLY,"sha256":NATIVE_SHA},
            "native_marker":proof["native_marker"],"input_only":true,
            "entry_replay_qualified":false,"ordinary_replay_authorized":false,"full_epoch_qualified":false,"full_cold_epoch_peak_qualified":false,"runtime_promotion_authorized":false,
            "canonical_sidecar_authorized":false,"publication_authorized":false}),
        )
    }
    fn complete_slot(line: &str) -> Option<u64> {
        let (prefix, tail) =
            line.split_once(" jetstreamer_node] private epoch227 v1625 comparison complete slot=")?;
        (prefix.starts_with('[')
            && prefix.trim_end().ends_with(" INFO")
            && tail.trim() == format!("{TARGET} complete=true"))
        .then_some(TARGET)
    }
    fn planning_report(text: &str, worker: &Path) -> Result<Value> {
        ensure!(text.len() <= 1 << 20, "227 planning report bounds");
        let mut reports = text
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|v| {
                v["schema"] == "jetstreamer-private-epoch227-comparison-planning-preflight-v1"
            })
            .collect::<Vec<_>>();
        ensure!(reports.len() == 1, "227 planning report absent/duplicate");
        let v = reports.pop().unwrap();
        ensure!(
            v["epoch"] == EPOCH
                && v["bootstrap_slot"] == INITIAL_REPLAY - 1
                && v["terminal_slot"] == TERMINAL
                && v["controlled_target_slot"] == TARGET
                && v["worker_entry_start"] == INITIAL_REPLAY
                && v["worker_entry_end_exclusive"] == TARGET + 1
                && v["canonical_checkpoint_slots"] == json!([INITIAL_REPLAY - 1, TERMINAL])
                && v["controlled_target_is_checkpoint"] == false
                && v["runtime_profile"] == RUNTIME
                && v["runtime_revision"] == REVISION
                && v["worker_identity"] == WORKER_ID
                && v["worker_environment_override"] == WORKER_ENV
                && v["worker_profile_validated"] == true
                && v["worker_executable"].as_str() == worker.to_str()
                && v["runtime_checkpoint_policy_validated"] == true
                && v["pre_worker_barrier_reached"] == true
                && v["worker_spawned"] == false
                && v["archive_created"] == false,
            "227 actual parent pre-worker planning scope differs"
        );
        for key in [
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(v[key] == false, "227 preflight grants authority:{key}");
        }
        Ok(v)
    }
    fn host_memory(text: &str) -> Result<(u64, u64)> {
        ensure!(text.len() <= 65536, "227 meminfo bounds");
        let field = |name: &str| -> Result<u64> {
            let lines = text
                .lines()
                .filter_map(|line| line.strip_prefix(name))
                .collect::<Vec<_>>();
            ensure!(
                lines.len() == 1,
                "227 missing/duplicate memory field:{name}"
            );
            let fields = lines[0].split_whitespace().collect::<Vec<_>>();
            ensure!(
                fields.len() == 2 && fields[1] == "kB",
                "227 memory field format"
            );
            fields[0]
                .parse::<u64>()?
                .checked_mul(1024)
                .context("227 memory conversion overflow")
        };
        let total = field("MemTotal:")?;
        let available = field("MemAvailable:")?;
        ensure!(
            total > 0 && available <= total,
            "227 host memory census differs"
        );
        Ok((available, total.div_ceil(10)))
    }
    fn caps(max: u64, high: u64, swap: u64, cpu: &str, tasks: u64, page: u64) -> Result<()> {
        ensure!(
            page > 0 && page.is_power_of_two(),
            "227 invalid host page size"
        );
        ensure!(
            max == MEMORY_MAX / page * page
                && high == MEMORY_HIGH / page * page
                && swap == 0
                && tasks == 512,
            "227 hard memory/task envelope differs"
        );
        let fields = cpu.split_whitespace().collect::<Vec<_>>();
        ensure!(fields.len() == 2, "227 CPU quota format");
        let quota = fields[0].parse::<u64>()?;
        let period = fields[1].parse::<u64>()?;
        ensure!(
            (1000..=1_000_000).contains(&period) && period.checked_mul(8) == Some(quota),
            "227 CPU quota differs from 8 cores"
        );
        Ok(())
    }
    fn actual_caps(p: &Plan) -> Result<()> {
        let cgroup = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
        let read = |name: &str| -> Result<u64> {
            Ok(fs::read_to_string(cgroup.join(name))?.trim().parse()?)
        };
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
        caps(
            read("memory.max")?,
            read("memory.high")?,
            read("memory.swap.max")?,
            &fs::read_to_string(cgroup.join("cpu.max"))?,
            read("pids.max")?,
            page,
        )
    }
    impl StorageHooks for ComparisonStorage {
        fn decode_plan(&self, bytes: &[u8]) -> Result<Plan> {
            let p: Plan = serde_json::from_slice(bytes)?;
            scope(&p)?;
            Ok(p)
        }
        fn prepare(&self, _p: &Plan) -> Result<()> {
            qualified_input()?;
            Ok(())
        }
        fn target_stop_protocol(&self) -> TargetStopProtocol {
            TargetStopProtocol::CooperativeResumeOnly
        }
        fn progress_slot(&self, line: &str) -> Option<u64> {
            complete_slot(line)
        }
        fn progress_counters(&self, _line: &str) -> Option<Value> {
            None
        }
        fn configure_command(&self, _p: &Plan, cmd: &mut Command) -> Result<()> {
            cmd.env("JETSTREAMER_HISTORICAL_POH_THREADS", "2")
                .env("RUST_MIN_STACK", "67108864")
                .env("TOKIO_WORKER_THREADS", "8");
            Ok(())
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
            self.configure_command(p, &mut planning)?;
            let output = planning.arg("--epoch227-comparison-preflight").output()?;
            ensure!(
                output.status.success(),
                "227 actual parent preflight failed:{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report = planning_report(std::str::from_utf8(&output.stdout)?, &p.worker)?;
            let native = qualified_input()?;
            persist(
                &p.run_root.join("receipts/capability.json"),
                &json!({"schema":CAPABILITY_SCHEMA,
                "invocation_id":iid,"bindings":bindings,"node_sha256":PARENT_SHA,"worker_sha256":WORKER,
                "snapshot_sha256":SNAPSHOT,"native_input":native,"parent_planning_report":report,
                "canonical_checkpoint_slots":[INITIAL_REPLAY-1,TERMINAL],"target_slot":TARGET,"target_is_checkpoint":false,
                "target_stop_protocol":"cooperative-resume-only","worker_started":false,"entry_replay":false,
                "resource_observation_performed":false,"ordinary_replay_authorized":false,"full_epoch_qualified":false,"full_cold_epoch_peak_qualified":false,
                "canonical_prefix_qualified":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,
                "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
            )
        }
        fn before_spawn(&self, p: &Plan, _iid: &str) -> Result<Value> {
            scope(p)?;
            actual_caps(p)?;
            let native = qualified_input()?;
            let (available, reserve) = host_memory(&fs::read_to_string("/proc/meminfo")?)?;
            ensure!(
                available
                    >= reserve
                        .checked_add(MEMORY_MAX)
                        .context("227 initial memory overflow")?,
                "227 initial host memory reserve"
            );
            let required = p
                .minimum_free_bytes
                .checked_add(MAX_SCRATCH)
                .context("227 initial free overflow")?;
            ensure!(
                free_bytes(&p.run_root)? >= required,
                "227 initial protected free-space reserve"
            );
            Ok(
                json!({"native_input":native,"worker_entry_start":INITIAL_REPLAY,"worker_entry_end_exclusive":TARGET+1,
                "canonical_checkpoint_slots":[INITIAL_REPLAY-1,TERMINAL],"target_slot":TARGET,"target_is_checkpoint":false,
                "target_stop_protocol":"cooperative-resume-only","scratch_planning_bytes":MAX_SCRATCH,
                "protected_free_floor_bytes":p.minimum_free_bytes,"required_initial_free_bytes":required,
                "minimum_host_available_memory_bytes":reserve,"maximum_memory_bytes":MEMORY_MAX,
                "canonical_prefix_qualified":false,"publication_authorized":false}),
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
                .map_err(|_| anyhow::anyhow!("227 guard lock poisoned"))?;
            if Instant::now() < *next {
                return Ok(());
            }
            *next = Instant::now() + Duration::from_secs(15);
            let check = (|| -> Result<()> {
                let (available, reserve) = host_memory(&fs::read_to_string("/proc/meminfo")?)?;
                ensure!(available >= reserve, "227 host memory reserve");
                ensure!(
                    free_bytes(&p.run_root)? >= p.minimum_free_bytes,
                    "227 protected filesystem floor"
                );
                Ok(())
            })();
            if let Err(error) = check {
                persist(
                    &p.run_root.join("receipts/guard-stop.json"),
                    &json!({"schema":GUARD_SCHEMA,
                    "invocation_id":iid,"child_pid":child,"reason":format!("{error:#}"),
                    "scratch_deleted":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
                )?;
                return Err(error);
            }
            Ok(())
        }
    }
    pub(super) fn entry() {
        main_with_storage(&ComparisonStorage {
            next_guard: std::sync::Mutex::new(Instant::now()),
        });
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn plan() -> Plan {
            let root = PathBuf::from(
                "/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-fixture",
            );
            Plan {
                schema: PLAN_SCHEMA.into(),
                unit: format!("{UNIT_PREFIX}fixture.service"),
                node: BoundFile {
                    path: PARENT_PATH.into(),
                    sha256: PARENT_SHA.into(),
                },
                worker: WORKER_PATH.into(),
                snapshot: Path::new(INPUT).join(SNAPSHOT_NAME),
                ledger_directory: INPUT.into(),
                epoch_hashes: BoundFile {
                    path: "/sealed/checkpoints".into(),
                    sha256: "a".repeat(64),
                },
                run_root: root,
                target_slot: TARGET,
                terminal_slot: TERMINAL,
                minimum_free_bytes: MINIMUM_FREE,
                maximum_runtime_seconds: MAX_RUNTIME,
            }
        }
        fn native() -> Value {
            let mut v = json!({"schema":"jetstreamer-private-epoch227-v1625-native-terminal-proof-v1","epoch":EPOCH,
                "unit":"horizon-native-input-227-v1625-small-v2.service","invocation_id":"36b96647e20e41a4a82c92b77b1bb290",
                "main_pid":456026,"native_input_qualified":true,"running_origin":{"path":NATIVE_ORIGIN,"sha256":NATIVE_ORIGIN_SHA},
                "native_marker":{"slot":"98063464","accounts_hash":ACCOUNTS,"replay_entries":"0","bootstrap_writes":"0"}});
            for key in [
                "entry_replay",
                "replay_launch_authorized",
                "runtime_promotion_authorized",
                "full_epoch_qualified",
                "canonical_sidecar_authorized",
                "publication_authorized",
                "remote_mutations",
                "r2_mutations",
            ] {
                v[key] = json!(false);
            }
            v
        }
        fn report() -> Value {
            json!({"schema":"jetstreamer-private-epoch227-comparison-planning-preflight-v1","epoch":EPOCH,
                "bootstrap_slot":INITIAL_REPLAY-1,"terminal_slot":TERMINAL,"controlled_target_slot":TARGET,
                "worker_entry_start":INITIAL_REPLAY,"worker_entry_end_exclusive":TARGET+1,
                "canonical_checkpoint_slots":[INITIAL_REPLAY-1,TERMINAL],"controlled_target_is_checkpoint":false,
                "runtime_profile":RUNTIME,"runtime_revision":REVISION,"worker_identity":WORKER_ID,
                "worker_environment_override":WORKER_ENV,"worker_profile_validated":true,"worker_executable":WORKER_PATH,
                "runtime_checkpoint_policy_validated":true,"pre_worker_barrier_reached":true,"worker_spawned":false,
                "archive_created":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,
                "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})
        }
        #[test]
        fn exact_entry_bound_target_is_separate_from_real_checkpoint_scope() {
            let p = plan();
            scope(&p).unwrap();
            validate_checkpoint_names(&CHECKPOINT_NAMES.join("\n")).unwrap();
            assert!(validate_checkpoint_names(SNAPSHOT_NAME).is_err());
            for change in 0..6 {
                let mut bad = plan();
                match change {
                    0 => bad.target_slot += 1,
                    1 => bad.terminal_slot = TARGET,
                    2 => bad.worker = "/sealed/full-worker".into(),
                    3 => bad.snapshot = Path::new(INPUT).join(TERMINAL_NAME),
                    4 => bad.maximum_runtime_seconds += 1,
                    _ => {
                        bad.run_root =
                            "/home/ubuntu/.jetstreamer-private/native-input227-v1625-fixture".into()
                    }
                }
                assert!(scope(&bad).is_err(), "{change}");
            }
            assert_eq!(MAX_SCRATCH, 300_000_000_000);
            assert_ne!(MAX_SCRATCH, 96_000_000_000);
        }
        #[test]
        fn qualified_native_input_cannot_promote_runtime_or_accept_another_attempt() {
            native_proof_shape(&native()).unwrap();
            for pointer in [
                "/epoch",
                "/invocation_id",
                "/native_input_qualified",
                "/running_origin/sha256",
                "/native_marker/accounts_hash",
                "/native_marker/replay_entries",
            ] {
                let mut bad = native();
                *bad.pointer_mut(pointer).unwrap() = Value::Null;
                assert!(native_proof_shape(&bad).is_err(), "{pointer}");
            }
            let mut bad = native();
            bad["publication_authorized"] = json!(true);
            assert!(native_proof_shape(&bad).is_err());
        }
        #[test]
        fn actual_parent_preflight_must_stop_before_worker_and_retain_both_real_roots() {
            planning_report(&report().to_string(), Path::new(WORKER_PATH)).unwrap();
            assert!(planning_report("", Path::new(WORKER_PATH)).is_err());
            assert!(
                planning_report(
                    &format!("{}\n{}", report(), report()),
                    Path::new(WORKER_PATH)
                )
                .is_err()
            );
            for pointer in [
                "/worker_spawned",
                "/pre_worker_barrier_reached",
                "/runtime_checkpoint_policy_validated",
                "/worker_entry_end_exclusive",
                "/canonical_checkpoint_slots",
                "/controlled_target_is_checkpoint",
                "/runtime_profile",
                "/worker_executable",
            ] {
                let mut bad = report();
                *bad.pointer_mut(pointer).unwrap() = Value::Null;
                assert!(
                    planning_report(&bad.to_string(), Path::new(WORKER_PATH)).is_err(),
                    "{pointer}"
                );
            }
        }
        #[test]
        fn complete_slot_marker_alone_controls_cooperative_resume_only_protocol() {
            let storage = ComparisonStorage {
                next_guard: std::sync::Mutex::new(Instant::now()),
            };
            let marker = format!(
                "[2026-10-24T00:00:00Z INFO  jetstreamer_node] private epoch227 v1625 comparison complete slot={TARGET} complete=true"
            );
            assert_eq!(storage.progress_slot(&marker), Some(TARGET));
            assert_eq!(
                storage.target_stop_protocol(),
                TargetStopProtocol::CooperativeResumeOnly
            );
            for line in [
                marker.replace("complete=true", "complete=false"),
                marker.replace(&TARGET.to_string(), &(TARGET + 1).to_string()),
                marker.replace(" INFO ", " WARN "),
                format!("program log: {marker}"),
                format!(
                    "[2026-10-24T00:00:00Z INFO  jetstreamer_node] progress slot {TARGET}/{TERMINAL} (6%)"
                ),
            ] {
                assert_eq!(storage.progress_slot(&line), None, "{line}");
            }
        }
        #[test]
        fn caps_and_memory_reserve_preserve_exact_kernel_rounding_and_ten_percent_floor() {
            caps(
                224_999_997_440,
                149_999_996_928,
                0,
                "800000 100000",
                512,
                4096,
            )
            .unwrap();
            assert!(
                caps(
                    225_000_000_000,
                    149_999_996_928,
                    0,
                    "800000 100000",
                    512,
                    4096
                )
                .is_err()
            );
            assert!(
                caps(
                    224_999_997_440,
                    149_999_996_928,
                    1,
                    "800000 100000",
                    512,
                    4096
                )
                .is_err()
            );
            assert!(
                caps(
                    224_999_997_440,
                    149_999_996_928,
                    0,
                    "900000 100000",
                    512,
                    4096
                )
                .is_err()
            );
            assert!(
                caps(
                    224_999_997_440,
                    149_999_996_928,
                    0,
                    "800000 100000",
                    1024,
                    4096
                )
                .is_err()
            );
            assert_eq!(
                host_memory("MemTotal: 11 kB\nMemAvailable: 5 kB\n").unwrap(),
                (5120, 1127)
            );
            assert!(host_memory("MemTotal: 11 kB\nMemTotal: 11 kB\nMemAvailable: 5 kB\n").is_err());
        }
        extern "C" fn unexpected_interrupt(_: i32) {
            unsafe {
                libc::_exit(130);
            }
        }
        #[test]
        fn cooperative_fixture_child() {
            let Ok(root) = env::var("JETSTREAMER_TEST_EPOCH227_COMPARISON_ROOT") else {
                return;
            };
            let root = PathBuf::from(root);
            assert!(
                root.starts_with(env::temp_dir())
                    && root
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("epoch227-comparison-fixture-")
            );
            let accounts = root.join("scratch/runtime/accounts-state");
            fs::create_dir_all(&accounts).unwrap();
            fs::write(accounts.join("1.0"), b"fixture accounts only").unwrap();
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = unexpected_interrupt as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
                assert_eq!(
                    libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()),
                    0
                );
            }
            eprintln!(
                "[2026-10-24T00:00:00Z INFO  jetstreamer_node] private epoch227 v1625 comparison complete slot={TARGET} complete=true"
            );
            assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
            thread::sleep(Duration::from_millis(50));
            fs::remove_dir_all(accounts).unwrap();
            std::process::exit(0);
        }
        #[test]
        fn completed_slot_capture_resumes_and_drains_without_second_sigint() {
            let root = tempfile::Builder::new()
                .prefix("epoch227-comparison-fixture-")
                .tempdir()
                .unwrap();
            let mut command = Command::new(env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "bounded_resource_runner::tests::cooperative_fixture_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("JETSTREAMER_TEST_EPOCH227_COMPARISON_ROOT", root.path())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .process_group(0);
            let mut child = ChildGroup(command.spawn().unwrap(), false);
            let pid = child.0.id();
            let mut reader = BufReader::new(child.0.stderr.take().unwrap());
            let mut marker = String::new();
            reader.read_line(&mut marker).unwrap();
            assert_eq!(complete_slot(&marker), Some(TARGET));
            prepare_target_capture(pid, TargetStopProtocol::CooperativeResumeOnly).unwrap();
            assert_eq!(
                fs::read(root.path().join("scratch/runtime/accounts-state/1.0")).unwrap(),
                b"fixture accounts only"
            );
            resume_target(pid, TargetStopProtocol::CooperativeResumeOnly).unwrap();
            assert_eq!(child.0.wait().unwrap().code(), Some(0));
            child.1 = true;
            assert!(!root.path().join("scratch/runtime/accounts-state").exists());
        }
    }
}
fn main() {
    bounded_resource_runner::entry();
}
