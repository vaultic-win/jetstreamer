//! Exact private 223 semantic-candidate bracket; no root/publication authority.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = true;
    pub const ARCHIVE_NAME: &str = "epoch-223.jet";
    pub const PARENT_SHA: &str = match option_env!("JETSTREAMER_EPOCH223_DEMOTION_PARENT_SHA256") {
        Some(s) => s,
        None => "",
    };
    pub const WORKER: &str = "0f8cc22ad76365f4feb1ef328ce77babbb5242a9b5edb38e9bd076528bc530c0";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_EPOCH223_DEMOTION";
    pub const RAYON_THREADS: u32 = 2;
    pub const EPOCH: u64 = 223;
    pub const TARGET: u64 = 96_544_588;
    pub const TERMINAL: u64 = TARGET;
    pub const INITIAL_REPLAY: u64 = 96_335_539;
    pub const MINIMUM_FREE: u64 = 2_471_798_691_840;
    pub const MAX_SCRATCH: u64 = 300_000_000_000;
    pub const MAX_RUNTIME: u64 = 129600;
    pub const SNAPSHOT_SIZE: u64 = 9_815_262_303;
    pub const SNAPSHOT: &str = "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME];
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch223-demotion-bracket-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch223-demotion-bracket-result-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch223-demotion-bracket-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-223-demotion-bracket-";
    pub const ROOT_PREFIX: &str = "qualification-223-demotion-bracket-";
}
mod bounded {
    include!("bounded_resource_runner.rs");
    const NATIVE_PATH: &str = match option_env!("JETSTREAMER_EPOCH223_DEMOTION_NATIVE_PROOF_PATH") {
        Some(s) => s,
        None => "",
    };
    const NATIVE_SHA: &str = match option_env!("JETSTREAMER_EPOCH223_DEMOTION_NATIVE_PROOF_SHA256")
    {
        Some(s) => s,
        None => "",
    };
    const ADMISSION_PATH: &str = match option_env!("JETSTREAMER_EPOCH223_DEMOTION_ADMISSION_PATH") {
        Some(s) => s,
        None => "",
    };
    const ADMISSION_SHA: &str = match option_env!("JETSTREAMER_EPOCH223_DEMOTION_ADMISSION_SHA256")
    {
        Some(s) => s,
        None => "",
    };
    struct Bracket {
        next_guard: std::sync::Mutex<Instant>,
    }
    fn proof(path: &str, sha: &str) -> Result<Value> {
        bound_file(Path::new(path), sha, 1 << 20)?;
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }
    fn prerequisites(p: &Plan) -> Result<(Value, Value)> {
        let native = proof(NATIVE_PATH, NATIVE_SHA)?;
        ensure!(
            native["schema"] == "jetstreamer-epoch223-demotion-native-input-proof-v1"
                && native["source_commit"] == "551728fda72afd36ce6f8652ddb0020ec249e860"
                && native["worker_sha256"] == WORKER
                && native["harness_sha256"]
                    == "a280b1f48f0bb430c482e01a03b4b800ee8f95f326590059e4cdf4873b14a22b"
                && native["test_name"]
                    == "runtime::tests::native_epoch223_cold_input_matches_canonical_accounts_commitment"
                && native["source_qa_sha256"]
                    == "3d5ea04ae0658070be51a8b410e2d6af8e0305bade8b7df455957e9db77a2f0f"
                && native["manager_success"] == true
                && native["restart_count"] == 0
                && native["snapshot_sha256"] == SNAPSHOT
                && native["genesis_sha256"] == GENESIS
                && native["success"] == true
                && native["bootstrap_slot"] == 96_335_538u64
                && native["bank_hash"] == "8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"
                && native["accounts_hash"] == "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE"
                && native["last_blockhash"] == "9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa"
                && native["capitalization"] == 503_889_539_326_183_230u64
                && native["transaction_count"] == 27_822_879_094u64
                && native["tick_height"] == 6_165_474_496u64
                && native["next_write_version"] == 105_933_183_112u64
                && native["replay_entries"] == 0
                && native["bootstrap_writes"] == 0,
            "new exact-worker native input proof is missing or differs"
        );
        let a = proof(ADMISSION_PATH, ADMISSION_SHA)?;
        ensure!(
            a["schema"] == "jetstreamer-epoch223-demotion-bracket-admission-v1"
                && a["unit"] == p.unit
                && a["worker_sha256"] == WORKER
                && a["parent_sha256"] == PARENT_SHA
                && a["snapshot_sha256"] == SNAPSHOT
                && a["native_input_sha256"] == NATIVE_SHA
                && a["target_slot"] == TERMINAL
                && a["bootstrap_slot"] == 96_335_538u64
                && a["full_fleet_census_complete"] == true
                && a["overlap_replacement_detected"] == false
                && a["requested_memory_high_bytes"] == 150_000_000_000u64
                && a["requested_memory_max_bytes"] == 225_000_000_000u64
                && a["protected_floor_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= 2_000_000_000_000u64),
            "bracket admission differs from closed profile"
        );
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let sampled = a["recorded_unix_seconds"]
            .as_u64()
            .context("admission time")?;
        ensure!(sampled <= now && now - sampled <= 120, "admission expired");
        for k in ["accepted_observer_sha256", "accepted_fleet_sha256"] {
            ensure!(
                a[k].as_str().is_some_and(digest),
                "unbound complete-fleet admission"
            );
        }
        Ok((native, a))
    }
    fn guard(a: &Value) -> Result<()> {
        let g = &a["guard"];
        let pid = g["pid"].as_u64().context("guard PID")?;
        let unit = g["unit"].as_str().context("guard unit")?;
        ensure!(
            pid > 1
                && unit.starts_with("horizon-guard-223-demotion-")
                && unit.ends_with(".service")
                && !unit.contains('/')
                && g["invocation_id"].as_str().is_some_and(identity)
                && g["restart_count"] == 0,
            "foreign guard identity"
        );
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let fields = stat
            .rsplit_once(')')
            .context("guard stat")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        ensure!(
            fields
                .get(19)
                .context("guard start ticks")?
                .parse::<u64>()?
                == g["start_ticks"].as_u64().context("bound guard ticks")?,
            "guard PID reused"
        );
        ensure!(
            fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::/system.slice/{unit}"),
            "guard cgroup changed"
        );
        let exe = fs::read_link(format!("/proc/{pid}/exe"))?;
        // The independent guard's sealed immutable ELF is rehashed here.
        bound_file(
            &exe,
            g["executable_sha256"].as_str().context("guard ELF")?,
            256 << 20,
        )?;
        Ok(())
    }
    impl StorageHooks for Bracket {
        fn configure_command(&self, _p: &Plan, c: &mut Command) -> Result<()> {
            c.arg("--epoch223-tail-comparison");
            Ok(())
        }
        fn capability_only(&self) -> bool {
            env::args()
                .next_back()
                .is_some_and(|s| s == "--storage-capability")
        }
        fn prepare(&self, p: &Plan) -> Result<()> {
            ensure!(
                digest(PARENT_SHA) && PARENT_SHA != "0".repeat(64),
                "runner lacks separately pinned parent build; unconfigured builds cannot launch"
            );
            if !self.capability_only() {
                prerequisites(p)?;
            }
            Ok(())
        }
        fn before_spawn(&self, p: &Plan, iid: &str) -> Result<Value> {
            let (native, a) = prerequisites(p)?;
            guard(&a)?;
            let cg = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
            for (file, key) in [
                ("memory.max", "effective_memory_max_bytes"),
                ("memory.high", "effective_memory_high_bytes"),
            ] {
                ensure!(
                    fs::read_to_string(cg.join(file))?.trim().parse::<u64>()?
                        == a[key].as_u64().context("bound actual kernel limit")?,
                    "kernel envelope changed"
                );
            }
            ensure!(
                fs::read_to_string(cg.join("memory.swap.max"))?.trim() == "0",
                "swap enabled"
            );
            Ok(json!({"native_input":native,"admission":a,"unit":p.unit,
                "actual_runner_invocation_id":iid,"actual_runner_pid":std::process::id(),
                "publication_authorized":false,"r2_mutations":false}))
        }
        fn guard(
            &self,
            _p: &Plan,
            _iid: &str,
            _child: u32,
            _elapsed: Duration,
            _draining: bool,
        ) -> Result<()> {
            // Process identity/liveness guard, not a second fleet/resource poll.
            let mut next = self
                .next_guard
                .lock()
                .map_err(|_| anyhow::anyhow!("guard cadence poisoned"))?;
            if Instant::now() < *next {
                return Ok(());
            }
            *next = Instant::now() + Duration::from_secs(15);
            guard(&proof(ADMISSION_PATH, ADMISSION_SHA)?)
        }
        fn capability_result(
            &self,
            p: &Plan,
            iid: &str,
            bindings: &Value,
            _: &Command,
        ) -> Result<()> {
            let mut c = command(p);
            self.configure_command(p, &mut c)?;
            let output = c.arg("--epoch223-tail-preflight").output()?;
            ensure!(
                output.status.success(),
                "private parent preflight rejected bracket"
            );
            let text = String::from_utf8(output.stdout)?;
            let line = text
                .lines()
                .find(|s| s.starts_with('{'))
                .context("preflight JSON")?;
            let report: Value = serde_json::from_str(line)?;
            ensure!(
                report["schema"] == "jetstreamer-private-epoch223-demotion-bracket-preflight-v1"
                    && report["worker_sha256"] == WORKER
                    && report["terminal_slot"] == TERMINAL
                    && report["worker_spawned"] == false
                    && report["publication_authorized"] == false,
                "foreign preflight"
            );
            persist(
                &p.run_root.join("receipts/capability.json"),
                &json!({
                "schema":"jetstreamer-epoch223-demotion-bracket-capability-v1","invocation_id":iid,
                "bindings":bindings,"parent_preflight":report,"native_input_qualified":false,
                "fresh_resource_admission_passed":false,"worker_spawned":false,
                "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
            )
        }
        fn validate_manifest(&self, m: &Value) -> Result<()> {
            ensure!(
                m["schema_version"] == 1
                    && m["epoch"] == 223
                    && m["worker_executable_sha256"] == WORKER
                    && m["runtime"]["runtime_profile"]
                        == "solana-v1.6.20-epoch223-called-program-demotion-candidate"
                    && m["bootstrap"]["slot"] == 96_335_538u64
                    && m["bootstrap"]["bank_hash"]
                        == "8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"
                    && m["output_slot_start"] == 96_336_000u64
                    && m["output_slot_count"] == 208_589u64
                    && m["terminal"]["slot"] == TERMINAL
                    && m["terminal"]["slot_complete"] == true
                    && m["archive_sha256"]
                        .as_str()
                        .is_some_and(|s| digest(s) && s != "0".repeat(64)),
                "private bracket producer manifest differs"
            );
            Ok(())
        }
    }
    pub(super) fn entry() {
        main_with_storage(&Bracket {
            next_guard: std::sync::Mutex::new(Instant::now()),
        });
    }
    #[cfg(test)]
    mod bracket_tests {
        use super::*;
        #[test]
        fn manifest_cannot_borrow_original_runtime_or_full_root_authority() {
            let runner = Bracket {
                next_guard: std::sync::Mutex::new(Instant::now()),
            };
            let good = json!({"schema_version":1,"epoch":223,"worker_executable_sha256":WORKER,
                "runtime":{"runtime_profile":"solana-v1.6.20-epoch223-called-program-demotion-candidate"},
                "bootstrap":{"slot":96335538,"bank_hash":"8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"},
                "output_slot_start":96336000,"output_slot_count":208589,
                "terminal":{"slot":96544588,"slot_complete":true},"archive_sha256":"a".repeat(64)});
            assert!(runner.validate_manifest(&good).is_ok());
            let mut old = good.clone();
            old["runtime"]["runtime_profile"] = json!("solana-v1.6.20");
            assert!(runner.validate_manifest(&old).is_err());
            let mut root = good.clone();
            root["terminal"]["slot"] = json!(96767522);
            assert!(runner.validate_manifest(&root).is_err());
            let mut worker = good;
            worker["worker_executable_sha256"] = json!("1".repeat(64));
            assert!(runner.validate_manifest(&worker).is_err());
        }
    }
}
fn main() {
    bounded::entry();
}
