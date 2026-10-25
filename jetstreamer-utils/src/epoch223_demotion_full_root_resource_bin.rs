//! Exact private 223 semantic full-root source; no ordinary/publication authority.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = true;
    pub const ARCHIVE_NAME: &str = "epoch-223.jet";
    pub const PARENT_SHA: &str =
        match option_env!("JETSTREAMER_EPOCH223_DEMOTION_FULL_ROOT_PARENT_SHA256") {
            Some(s) => s,
            None => "",
        };
    pub const WORKER: &str =
        match option_env!("JETSTREAMER_EPOCH223_DEMOTION_FULL_ROOT_WORKER_SHA256") {
            Some(s) => s,
            None => "",
        };
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_EPOCH223_DEMOTION_FULL_ROOT";
    pub const RAYON_THREADS: u32 = 2;
    pub const EPOCH: u64 = 223;
    pub const TARGET: u64 = 96_767_522;
    pub const TERMINAL: u64 = TARGET;
    pub const INITIAL_REPLAY: u64 = 96_335_539;
    // Admission binds the evidenced local century/own-drain floor. Other
    // owners' temporary floors stay in complete fleet accounting.
    pub const MINIMUM_FREE: u64 = 1;
    pub const MAX_SCRATCH: u64 = 300_000_000_000;
    pub const MAX_RUNTIME: u64 = 259200;
    pub const SNAPSHOT_SIZE: u64 = 9_815_262_303;
    pub const SNAPSHOT: &str = "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch223-full-root-demotion-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch223-full-root-demotion-result-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch223-full-root-demotion-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-223-full-root-demotion-";
    pub const ROOT_PREFIX: &str = "qualification-223-full-root-demotion-";
}
mod bounded {
    include!("bounded_resource_runner.rs");
    mod readiness {
        include!("epoch223_demotion_full_root_runtime.rs");
    }
    struct FullRoot {
        next_guard: std::sync::Mutex<Instant>,
        runtime: readiness::Runtime,
    }
    impl FullRoot {
        fn new() -> Self {
            Self {
                next_guard: std::sync::Mutex::new(Instant::now()),
                runtime: readiness::Runtime::new(),
            }
        }
    }
    impl StorageHooks for FullRoot {
        fn configure_command(&self, _p: &Plan, c: &mut Command) -> Result<()> {
            c.arg("--epoch223-tail-comparison");
            self.runtime.configure_parent(c)?;
            Ok(())
        }
        fn capability_only(&self) -> bool {
            env::args()
                .next_back()
                .is_some_and(|s| s == "--storage-capability")
        }
        fn decode_plan(&self, bytes: &[u8]) -> Result<Plan> {
            self.runtime.decode(bytes)
        }
        fn before_inputs(
            &self,
            p: &Plan,
            iid: &str,
            plan: &BoundFile,
            self_sha: &str,
        ) -> Result<()> {
            self.runtime
                .before_inputs(p, iid, plan, self_sha, self.capability_only())
        }
        fn prepare(&self, _p: &Plan) -> Result<()> {
            ensure!(
                digest(PARENT_SHA) && PARENT_SHA != "0".repeat(64),
                "runner lacks separately pinned parent build; unconfigured builds cannot launch"
            );
            Ok(())
        }
        fn before_spawn(&self, p: &Plan, iid: &str) -> Result<Value> {
            self.runtime.before_spawn(p, iid)
        }
        fn guard(
            &self,
            _p: &Plan,
            _iid: &str,
            _child: u32,
            _elapsed: Duration,
            _draining: bool,
        ) -> Result<()> {
            let mut next = self
                .next_guard
                .lock()
                .map_err(|_| anyhow::anyhow!("guard cadence poisoned"))?;
            if Instant::now() < *next {
                return Ok(());
            }
            *next = Instant::now() + Duration::from_secs(15);
            self.runtime.guard()
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
                "private parent preflight rejected full-root scope"
            );
            let text = String::from_utf8(output.stdout)?;
            let line = text
                .lines()
                .find(|s| s.starts_with('{'))
                .context("preflight JSON")?;
            let report: Value = serde_json::from_str(line)?;
            ensure!(
                report["schema"] == "jetstreamer-private-epoch223-full-root-demotion-preflight-v1"
                    && report["worker_sha256"] == WORKER
                    && report["terminal_slot"] == TERMINAL
                    && report["worker_spawned"] == false
                    && report["publication_authorized"] == false,
                "foreign preflight"
            );
            persist(
                &p.run_root.join("receipts/capability.json"),
                &json!({
                "schema":"jetstreamer-epoch223-full-root-demotion-capability-v1","invocation_id":iid,
                "bindings":bindings,"parent_preflight":report,"native_input_qualified":false,
                "fresh_resource_admission_passed":false,"worker_spawned":false,
                "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
            )
        }
        fn validate_manifest(&self, m: &Value) -> Result<()> {
            validate_full_root_manifest(m, WORKER)
        }
    }
    pub(super) fn entry() {
        if let Some(result) = readiness::role_entry() {
            if let Err(error) = result {
                eprintln!("epoch223 role failed: {error:#}");
                std::process::exit(1);
            }
            return;
        }
        main_with_storage(&FullRoot::new());
    }
    fn validate_full_root_manifest(m: &Value, worker: &str) -> Result<()> {
        ensure!(
            digest(worker)
                && worker != "0".repeat(64)
                && worker != "0f8cc22ad76365f4feb1ef328ce77babbb5242a9b5edb38e9bd076528bc530c0"
                && worker != "a651b7a6ee3c0d4f8359e1ea6cfcb96becf259d440ee744beb173b264de6af20"
                && m["schema_version"] == 1
                && m["epoch"] == 223
                && m["worker_executable_sha256"] == worker
                && m["runtime"]["runtime_profile"]
                    == "solana-v1.6.20-epoch223-called-program-demotion-candidate"
                && m["bootstrap"]["slot"] == 96_335_538u64
                && m["bootstrap"]["accounts_hash"]
                    == "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE"
                && m["bootstrap"]["bank_hash"] == "8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"
                && m["output_slot_start"] == 96_336_000u64
                && m["output_slot_count"] == 431_523u64
                && m["terminal"]["slot"] == 96_767_522u64
                && m["terminal"]["slot_complete"] == true
                && m["terminal"]["accounts_hash"] == "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7"
                && m["terminal"]["bank_hash"] == "EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB"
                && m["archive_sha256"]
                    .as_str()
                    .is_some_and(|s| digest(s) && s != "0".repeat(64)),
            "full-root private producer manifest lacks exact scope/worker/actual terminal commitments"
        );
        Ok(())
    }
    #[cfg(test)]
    mod root_tests {
        use super::*;
        #[test]
        fn replay_mode_requires_distinct_proof_qualification_and_capability_fields() {
            let plan = json!({"schema":PLAN_SCHEMA,"unit":format!("{UNIT_PREFIX}source-fixture.service"),
                "node":{"path":"/sealed/future-parent","sha256":if PARENT_SHA.is_empty(){"c".repeat(64)}else{PARENT_SHA.into()}},"worker":"/sealed/future-worker",
                "snapshot":format!("/sealed/{SNAPSHOT_NAME}"),"ledger_directory":"/sealed/genesis",
                "epoch_hashes":{"path":"/sealed/checkpoints","sha256":"a".repeat(64)},
                "run_root":format!("/home/ubuntu/.jetstreamer-private/{ROOT_PREFIX}source-fixture"),
                "target_slot":TARGET,"terminal_slot":TERMINAL,"minimum_free_bytes":1,"maximum_runtime_seconds":MAX_RUNTIME});
            let p: Plan = serde_json::from_value(plan.clone()).unwrap();
            validate_plan(&p).unwrap();
            let capability = json!({"schema":"jetstreamer-epoch223-full-root-demotion-runtime-plan-v3","mode":"capability","plan":plan});
            FullRoot::new()
                .decode_plan(&serde_json::to_vec(&capability).unwrap())
                .unwrap();
            let mut missing = capability.clone();
            missing["mode"] = json!("full-root");
            assert!(
                FullRoot::new()
                    .decode_plan(&serde_json::to_vec(&missing).unwrap())
                    .is_err()
            );
            let mut borrowed = capability.clone();
            borrowed["schema"] = json!("jetstreamer-epoch223-demotion-runtime-plan-v3");
            assert!(
                FullRoot::new()
                    .decode_plan(&serde_json::to_vec(&borrowed).unwrap())
                    .is_err()
            );
            let mut mixed = capability;
            mixed["capability"] = json!({"path":"/sealed/declared-proof","sha256":"b".repeat(64)});
            assert!(
                FullRoot::new()
                    .decode_plan(&serde_json::to_vec(&mixed).unwrap())
                    .is_err()
            );
            let mut expanded = p.clone();
            expanded.terminal_slot += 477;
            assert!(validate_plan(&expanded).is_err());
            let mut bracket = p;
            bracket.unit = "horizon-qualify-223-demotion-bracket-source-fixture.service".into();
            assert!(validate_plan(&bracket).is_err());
        }
        #[test]
        fn root_manifest_rejects_wrong_commitments_span_worker_or_runtime() {
            let worker = "a".repeat(64);
            let good = json!({"schema_version":1,"epoch":223,"worker_executable_sha256":worker,
                "runtime":{"runtime_profile":"solana-v1.6.20-epoch223-called-program-demotion-candidate"},
                "bootstrap":{"slot":96335538,"accounts_hash":"Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE","bank_hash":"8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"},
                "output_slot_start":96336000,"output_slot_count":431523,
                "terminal":{"slot":96767522,"slot_complete":true,"accounts_hash":"3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7","bank_hash":"EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB"},"archive_sha256":"b".repeat(64)});
            validate_full_root_manifest(&good, &worker).unwrap();
            for (path, v) in [
                (
                    "/terminal/accounts_hash",
                    json!("Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE"),
                ),
                (
                    "/terminal/bank_hash",
                    json!("3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7"),
                ),
                ("/terminal/slot", json!(96544588)),
                ("/terminal/slot_complete", json!(false)),
                ("/output_slot_count", json!(432000)),
                ("/runtime/runtime_profile", json!("solana-v1.6.20")),
                (
                    "/worker_executable_sha256",
                    json!("0f8cc22ad76365f4feb1ef328ce77babbb5242a9b5edb38e9bd076528bc530c0"),
                ),
            ] {
                let mut bad = good.clone();
                *bad.pointer_mut(path).unwrap() = v;
                assert!(
                    validate_full_root_manifest(&bad, &worker).is_err(),
                    "{path}"
                );
            }
            assert!(validate_full_root_manifest(&good, "").is_err());
            assert!(validate_full_root_manifest(&good, &"0".repeat(64)).is_err());
        }
    }
}
fn main() {
    bounded::entry();
}
