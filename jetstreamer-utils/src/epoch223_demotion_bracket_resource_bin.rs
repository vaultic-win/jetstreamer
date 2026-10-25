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
    mod readiness {
        include!("epoch223_demotion_runtime.rs");
    }
    struct Bracket {
        next_guard: std::sync::Mutex<Instant>,
        runtime: readiness::Runtime,
    }
    impl Bracket {
        fn new() -> Self {
            Self {
                next_guard: std::sync::Mutex::new(Instant::now()),
                runtime: readiness::Runtime::new(),
            }
        }
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
        if let Some(result) = readiness::role_entry() {
            if let Err(error) = result {
                eprintln!("epoch223 role failed: {error:#}");
                std::process::exit(1);
            }
            return;
        }
        main_with_storage(&Bracket::new());
    }
    #[cfg(test)]
    mod bracket_tests {
        use super::*;
        #[test]
        fn manifest_cannot_borrow_original_runtime_or_full_root_authority() {
            let runner = Bracket::new();
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
