//! End-to-end digest-bound receipt graph; no privileged filesystem or native run.
use super::native211::{self as c, EvidenceReader};
use super::*;
const WALL: u64 = 1_792_778_400;
const BOOT: &str = "00000000-0000-0000-0000-000000000001";
#[derive(Default)]
struct Memory {
    files: BTreeMap<PathBuf, Vec<u8>>,
    fault: Option<(&'static str, &'static str, Value)>,
}
impl Memory {
    fn bytes_at(&mut self, path: impl Into<PathBuf>, bytes: Vec<u8>) -> BoundFile {
        let path = path.into();
        let sha256 = hex_lower(&Sha256::digest(&bytes));
        self.files.insert(path.clone(), bytes);
        BoundFile { path, sha256 }
    }
    fn change(&self, label: &str, v: &mut Value) {
        if let Some((target, pointer, value)) = &self.fault
            && *target == label
        {
            *v.pointer_mut(pointer).expect("fixture fault pointer") = value.clone();
        }
    }
    fn put(&mut self, label: &str, path: impl Into<PathBuf>, mut v: Value) -> BoundFile {
        self.change(label, &mut v);
        self.bytes_at(path, serde_json::to_vec(&v).unwrap())
    }
    fn document(&self, b: &BoundFile) -> Value {
        self.json(b, true).unwrap()
    }
}
impl EvidenceReader for Memory {
    fn bytes(&self, b: &BoundFile, maximum: u64) -> Result<Vec<u8>> {
        ensure!(b.path.starts_with("/var/lib/jetstreamer"), "test namespace");
        let bytes = self.files.get(&b.path).context("fixture missing")?;
        ensure!(
            bytes.len() as u64 <= maximum && hex_lower(&Sha256::digest(bytes)) == b.sha256,
            "fixture binding"
        );
        Ok(bytes.clone())
    }
    fn json(&self, b: &BoundFile, _immutable: bool) -> Result<Value> {
        Ok(serde_json::from_slice(&self.bytes(b, 16 << 20)?)?)
    }
    fn canonical(&self, p: &Path) -> Result<PathBuf> {
        ensure!(self.files.contains_key(p), "fixture canonical");
        Ok(p.to_owned())
    }
}
fn bound(b: &BoundFile) -> Value {
    private157::binding(b)
}
fn deny(mut v: Value) -> Value {
    c::deny(&mut v);
    v
}
fn retention() -> Value {
    json!({"LoadState":"loaded","ActiveState":"active","SubState":"active","After":c::UNIT,"IgnoreOnIsolate":"yes","DefaultDependencies":"no","DropInPaths":"","Job":"","Wants":"","Requires":"","BindsTo":"","Upholds":""})
}
fn owner(unit: &str, iid: &str, pid: &str, active: bool) -> Value {
    json!({"Id":unit,"LoadState":"loaded","ActiveState":if active{"active"}else{"inactive"},"SubState":if active{"running"}else{"dead"},"InvocationID":iid,"MainPID":pid,"NRestarts":"0","Result":"success","ControlGroup":format!("/system.slice/{unit}"),"ExecStart":"{ path=/sealed/peer ; argv[]=/sealed/peer ; ignore_errors=no }"})
}
struct Chain {
    memory: Memory,
    handoff: BoundFile,
    origin: BoundFile,
    proof: Value,
    previous: Value,
    running_plan: Value,
    running_fleet: Value,
    terminal_plan: Value,
    peers: BTreeMap<String, Value>,
    terminal: Value,
}
fn fixture(fault: Option<(&'static str, &'static str, Value)>) -> Chain {
    let mut m = Memory {
        fault,
        ..Memory::default()
    };
    let iid = "a".repeat(32);
    let gid = "b".repeat(32);
    let harness = json!({"path":c::TEST,"sha256":c::TEST_SHA});
    let guard = json!({"path":c::GUARD,"sha256":c::GUARD_SHA});
    let observer = m.put(
        "observer",
        "/var/lib/jetstreamer/observer/sample.json",
        json!({"recorded_at_utc":"2026-10-23T18:00:00Z"}),
    );
    let old_evidence = m.put(
        "evidence",
        "/var/lib/jetstreamer/older/proof.json",
        json!({"history":true}),
    );
    let old_plan = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,"observer":bound(&observer),"output":"/var/lib/jetstreamer/fleet/old.json","status_receipt_directory":"/var/lib/jetstreamer/status","gates":{"211":{"state":"staged-admissible","next_action":"native qualification","evidence":[bound(&old_evidence)]},"247":{"state":"live-replay","next_action":"retain","evidence":[bound(&old_evidence)],"operator_status":{"basis":bound(&old_evidence),"completion":bound(&old_evidence),"raw_status":bound(&old_evidence)}}},"tracked_units":["replay.service","audit.service","old.service"],"pipeline_claims":[{"epoch":210,"phase":"private-cold-snapshot-verification","unit":"historical210.service","invocation_id":"d".repeat(32),"expected_exec_start":"historical unchanged","evidence":[bound(&old_evidence)]}],"diagnostics":[{"epoch":250,"unit":"audit.service","invocation_id":"e".repeat(32),"scratch_path":"/private/audit","launch_receipt":bound(&old_evidence)}]});
    let old_plan_b = m.put(
        "old_plan",
        "/var/lib/jetstreamer/fleet/old-plan.json",
        old_plan.clone(),
    );
    let peers = BTreeMap::from([
        (
            "replay.service".into(),
            owner("replay.service", &"c".repeat(32), "43", true),
        ),
        (
            "audit.service".into(),
            owner("audit.service", &"d".repeat(32), "44", true),
        ),
        (
            "old.service".into(),
            owner("old.service", &"e".repeat(32), "0", false),
        ),
    ]);
    let previous = json!({"schema":SCHEMA,"observer_receipt":observer.path,"observer_sha256":observer.sha256,"sampled_at_utc":"2026-10-23T18:00:00Z","recorded_unix_seconds":WALL,"plan":old_plan_b.path,"plan_sha256":old_plan_b.sha256,"unit_census":peers,"active":[{"epoch":247,"producer":peers["replay.service"]}]});
    let prior = m.put(
        "previous",
        "/var/lib/jetstreamer/fleet/old.json",
        previous.clone(),
    );
    let source=m.put("source","/var/lib/jetstreamer/source/proof.json",json!({"schema":"horizon-native211-source-publication-v1","remote_ref":"refs/heads/account-updates","remote_head":"f".repeat(40),"all_required_dependencies_in_remote":true,"exact_deployed_source_provenance_reviewed":true,"no_untracked_required_source":true,"artifacts":[{"role":"launcher","artifact":{"path":"/var/lib/jetstreamer/launcher/bin","sha256":"1".repeat(64)}}]}));
    let qe = m.put(
        "qualification_evidence",
        "/var/lib/jetstreamer/prestart/evidence.json",
        json!({"qualified_consumers":true}),
    );
    let q=m.put("prestart","/var/lib/jetstreamer/prestart/proof.json",deny(json!({"schema":"horizon-native211-prestart-qualification-v1","harness":harness,"guard":guard,"source_publication":bound(&source),"observer_complete_tuple_accepted":true,"fleet_running_and_terminal_accepted":true,"inactive_status_exact_owner_accepted":true,"terminal_retention_accepted":true,"pre_restore_gate_tests_accepted":true,"actual_first_guard_required_before_snapshot":true,"actual_native_startup_qualified":false,"launcher_artifact_sha256":"1".repeat(64),"qualification_evidence":bound(&qe)})));
    let review=m.put("review","/var/lib/jetstreamer/review/proof.json",deny(json!({"schema":"horizon-native211-current-fleet-review-v1","epoch":211,"Main_accepted":true,"guard":guard,"source_publication":bound(&source),"prestart_qualification":bound(&q),"cpu_affinity":[0,1,2,3,4,5,6,7]})));
    let a=m.put("admission","/var/lib/jetstreamer/admission/proof.json",deny(json!({"schema":"horizon-native211-current-fleet-admission-v1","epoch":211,"mode":"native-cold","unit":c::UNIT,"private_run_root":c::ROOT,"maximum_memory_bytes":c::MEMORY,"candidate_incremental_peak_bytes":c::SCRATCH,"protected_existing_floor_bytes":10,"harness":harness,"guard":guard,"boot_id":BOOT,"admitted":true,"review":bound(&review),"source_publication":bound(&source),"observer":bound(&observer),"fleet":bound(&prior),"reservation_ledger":bound(&old_evidence),"recorded_unix_seconds":WALL+50,"expires_unix_seconds":WALL+110})));
    let p=m.put("startup","/var/lib/jetstreamer/horizon-native211-startup-plan-test/plan.json",json!({"schema":"horizon-native211-startup-plan-v1","epoch":211,"unit":c::UNIT,"guard_unit":c::GUARD_UNIT,"worker_root":c::ROOT,"bootstrap_slot":91_151_575u64,"snapshot_sha256":c::SNAPSHOT_SHA,"maximum_root_physical_bytes":c::SCRATCH,"maximum_memory_bytes":c::MEMORY,"token_root":"/var/lib/jetstreamer/horizon-native211-startup-tokens","boot_id":BOOT,"harness":harness,"guard":guard,"minimum_free_bytes":10,"issued_monotonic_us":100,"expires_monotonic_us":60_000_100,"admission":bound(&a)}));
    let gp=m.put("guard_plan","/var/lib/jetstreamer/guard/plan.json",json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":c::UNIT,"invocation_id":iid,"filesystem":"/","worker_root":c::ROOT,"minimum_free_bytes":10,"maximum_root_physical_bytes":c::SCRATCH,"maximum_worker_vmas":3500000,"native_main":{"main_pid":42,"executable":c::TEST,"sha256":c::TEST_SHA}}));
    let g=m.put("guard_sample","/var/lib/jetstreamer/guard/sample.json",json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","plan":gp.path,"plan_sha256":gp.sha256,"guard_sha256":c::GUARD_SHA,"guard_invocation_id":gid,"producer_invocation_id":iid,"producer":{"invocation_id":iid,"pid":42,"active":"active","sub":"running","restarts":0,"load_state":"loaded","result":"success","restart_policy":"no","kill_mode":"control-group","delegated":false,"cgroup":format!("/system.slice/{}",c::UNIT)},"producer_stop_enabled":true,"native_main":{"main_pid":42,"executable":c::TEST,"sha256":c::TEST_SHA},"minimum_free_bytes":10,"available_bytes":20,"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":c::SCRATCH,"root_physical_observation":{"maximum_physical_bytes":c::SCRATCH,"exceeds_budget":false,"conservative_physical_bytes":0},"workers":[[42,100]],"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"canary_target_error":null,"target_handoff_error":null,"bounded_measurement":false,"bounded_canary":null,"target_handoff":null,"remote_mutations":false,"r2_mutations":false,"recorded_unix_seconds":WALL+58}));
    let j=m.put("first_journal","/var/lib/jetstreamer/guard/journal.json",json!([
        {"_PID":"1","_UID":"0","_BOOT_ID":BOOT.replace('-',""),"UNIT":c::GUARD_UNIT,"INVOCATION_ID":gid,"MESSAGE":format!("Starting {} - native",c::GUARD_UNIT),"__MONOTONIC_TIMESTAMP":"120"},
        {"_PID":"1","_UID":"0","_BOOT_ID":BOOT.replace('-',""),"UNIT":c::GUARD_UNIT,"INVOCATION_ID":gid,"MESSAGE":format!("{}: Deactivated successfully.",c::GUARD_UNIT),"__MONOTONIC_TIMESTAMP":"150"}]));
    let t=m.put("token",format!("/var/lib/jetstreamer/horizon-native211-startup-tokens/{iid}/guard-admission.json"),deny(json!({"schema":"horizon-native211-first-guard-token-v1","startup_plan_sha256":p.sha256,"unit":c::UNIT,"invocation_id":iid,"main_pid":42,"harness":harness,"guard":guard,"boot_id":BOOT,"admission":bound(&a),"recorded_monotonic_us":170,"guard_invocation_id":gid,"guard_plan":bound(&gp),"guard_sample":bound(&g),"guard_pid1_journal":bound(&j)})));
    m.bytes_at(
        t.path.with_file_name("guard-admission.sha256"),
        format!("{}\n", t.sha256).into_bytes(),
    );
    let unit = m.bytes_at(
        "/var/lib/jetstreamer/producer/native.service",
        b"sealed unit template".to_vec(),
    );
    let mut producer = owner(c::UNIT, &iid, "42", true);
    for (key, value) in [
        ("Type", "exec"),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "120259084288"),
        ("MemoryMax", "137438953472"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("RuntimeMaxUSec", "45min"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("ReadWritePaths", c::ROOT),
        ("Transient", "no"),
        ("RemainAfterExit", "no"),
        ("DropInPaths", ""),
        ("CPUAffinity", "0-7"),
        ("ExecMainStartTimestampMonotonic", "110"),
    ] {
        producer[key] = json!(value);
    }
    producer["ExecStart"] = json!(format!("{} ; ignore_errors=no }}", c::command()));
    producer["Environment"] = json!(format!(
        "RUST_MIN_STACK=134217728 SOLANA_RAYON_THREADS=8 JETSTREAMER_HISTORICAL_POH_THREADS=2 JETSTREAMER_EPOCH211_V1616_TEST_SCRATCH={}/scratch JETSTREAMER_EPOCH211_STARTUP_PLAN={} JETSTREAMER_EPOCH211_STARTUP_PLAN_SHA256={}",
        c::ROOT,
        p.path.display(),
        p.sha256
    ));
    producer["FragmentPath"] = json!(unit.path);
    let h=m.put("handoff","/var/lib/jetstreamer/horizon-native211-execution-test/guarded-startup-handoff.json",deny(json!({"schema":"horizon-native211-guarded-startup-v1","unit":c::UNIT,"invocation_id":iid,"main_pid":42,"producer":producer,"unit_file":bound(&unit),"retention":retention(),"startup_plan":bound(&p),"admission":bound(&a),"guard_plan":bound(&gp),"first_guard_sample":bound(&g),"first_guard_pid1_journal":bound(&j),"first_guard_token":bound(&t),"recorded_monotonic_us":180,"recorded_unix_seconds":WALL+59,"native_input_qualified":false})));
    let origin_path = "/var/lib/jetstreamer/horizon-native211-running-test/intent.json";
    let capture=m.put("running_spec","/var/lib/jetstreamer/running-spec/spec.json",json!({"schema":"jetstreamer-native211-running-capture-spec-v1","startup_handoff":bound(&h),"output":origin_path}));
    let origin=m.put("origin",origin_path,deny(json!({"schema":c::SCHEMA,"epoch":211,"unit":c::UNIT,"private_run_root":c::ROOT,"invocation_id":iid,"main_pid":42,"test_sha256":c::TEST_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,"bootstrap_slot":91_151_575u64,"accounts_hash":c::ACCOUNTS_HASH,"maximum_memory_bytes":c::MEMORY,"maximum_scratch_bytes":c::SCRATCH,"expected_exec_start":producer["ExecStart"],"startup_handoff":bound(&h),"admission":bound(&a),"observer":bound(&observer),"fleet":bound(&prior),"boot_id":BOOT,"resource_samples_taken":0,"ordinary_replay_claim":false,"replay_entries":0,"native_input_qualified":false,"public_sidecar_countdown_authorized":true,"recorded_unix_seconds":WALL+60,"sampled_at_utc":"2026-10-23T18:01:00Z","capture_spec":bound(&capture),"capture_helper_sha256":"2".repeat(64),"producer_start_monotonic_microseconds":110,"producer":producer})));
    let claim = json!({"epoch":211,"phase":"private-cold-snapshot-verification","unit":c::UNIT,"invocation_id":iid,"expected_exec_start":producer["ExecStart"],"evidence":[bound(&origin)]});
    let mut running_plan = old_plan;
    running_plan["pipeline_claims"]
        .as_array_mut()
        .unwrap()
        .push(claim);
    running_plan["tracked_units"]
        .as_array_mut()
        .unwrap()
        .push(json!(c::UNIT));
    running_plan["previous_fleet"] = bound(&prior);
    running_plan["metadata_event"] = bound(&origin);
    running_plan["gates"]["211"]["state"] = json!("blocked-qualification");
    running_plan["gates"]["211"]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(bound(&origin));
    running_plan["output"] = json!("/var/lib/jetstreamer/fleet/running.json");
    let rp = m.put(
        "running_plan",
        "/var/lib/jetstreamer/fleet/running-plan.json",
        running_plan.clone(),
    );
    let mut running_fleet = previous.clone();
    running_fleet["unit_census"][c::UNIT] = producer;
    running_fleet["plan"] = json!(rp.path);
    running_fleet["plan_sha256"] = json!(rp.sha256);
    running_fleet["recorded_unix_seconds"] = json!(WALL + 61);
    let rf = m.put(
        "running_fleet",
        "/var/lib/jetstreamer/fleet/running.json",
        running_fleet.clone(),
    );
    let marker = json!({"slot":"91151575","bank_hash":"1".repeat(32),"accounts_hash":c::ACCOUNTS_HASH,"last_blockhash":"2".repeat(32),"capitalization":"18446744073709551615","transaction_count":"3","tick_height":"4","next_write_version":"5","replay_entries":"0","bootstrap_writes":"0"});
    let marker_text = marker
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| format!("{k}={}", v.as_str().unwrap()))
        .collect::<Vec<_>>()
        .join(" ");
    let row = |message: String, mono: u64| json!({"_PID":"42","_BOOT_ID":BOOT.replace('-',""),"_SYSTEMD_UNIT":c::UNIT,"_SYSTEMD_INVOCATION_ID":iid,"MESSAGE":message,"__MONOTONIC_TIMESTAMP":mono.to_string(),"__REALTIME_TIMESTAMP":((WALL+119)*1_000_000).to_string()});
    let mut rows = json!([row(format!("epoch211-v1616-native-input {marker_text}"),100_000_000),row("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; finished".into(),100_000_001),{"_PID":"1","_UID":"0","_BOOT_ID":BOOT.replace('-',""),"UNIT":c::UNIT,"INVOCATION_ID":iid,"MESSAGE":format!("{}: Deactivated successfully.",c::UNIT),"__MONOTONIC_TIMESTAMP":"100000002","__REALTIME_TIMESTAMP":((WALL+119)*1_000_000).to_string()}]);
    m.change("terminal_journal", &mut rows);
    let raw = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let journal = m.bytes_at(
        "/var/lib/jetstreamer/horizon-native211-terminal-raw-test/journal.json",
        raw.into_bytes(),
    );
    let proof_path = "/var/lib/jetstreamer/horizon-native211-terminal-proof-test/proof.json";
    let spec=m.put("terminal_spec","/var/lib/jetstreamer/terminal-spec/spec.json",json!({"schema":"jetstreamer-native211-terminal-capture-spec-v1","running_origin":bound(&origin),"journal":bound(&journal),"observer":bound(&observer),"fleet":bound(&rf),"output":proof_path}));
    let mut terminal = owner(c::UNIT, &iid, "0", false);
    for (key, value) in [
        ("ExecMainPID", "42"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", "0"),
        ("ControlPID", "0"),
        ("Job", ""),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("TriggeredBy", ""),
    ] {
        terminal[key] = json!(value);
    }
    let proof_b=m.put("proof",proof_path,deny(json!({"schema":native211_terminal::SCHEMA,"epoch":211,"unit":c::UNIT,"native_input_qualified":true,"resource_samples_taken":0,"running_origin":bound(&origin),"capture_spec":bound(&spec),"journal":bound(&journal),"observer":bound(&observer),"fleet":bound(&rf),"invocation_id":iid,"main_pid":42,"boot_id":BOOT,"terminal_unix_microseconds":(WALL+119)*1_000_000,"terminal_monotonic_microseconds":100_000_002,"native_marker":marker,"recorded_unix_seconds":WALL+120,"sampled_at_utc":"2026-10-23T18:00:00Z","terminal_retention":retention(),"terminal_manager":terminal})));
    let proof = m.document(&proof_b);
    let mut terminal_plan = running_plan.clone();
    terminal_plan["previous_fleet"] = bound(&rf);
    terminal_plan["metadata_event"] = bound(&proof_b);
    terminal_plan["output"] = json!("/var/lib/jetstreamer/fleet/terminal.json");
    terminal_plan["gates"]["211"]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(bound(&proof_b));
    Chain {
        memory: m,
        handoff: h,
        origin,
        proof,
        previous,
        running_plan,
        running_fleet,
        terminal_plan,
        peers,
        terminal,
    }
}
impl Chain {
    fn claim(&self) -> PipelineClaim {
        serde_json::from_value(
            self.running_plan["pipeline_claims"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()
                .clone(),
        )
        .unwrap()
    }
    fn check(&self) -> Result<()> {
        c::startup_read(&self.handoff, &self.memory)?;
        c::claim_read(&self.claim(), &self.memory)?;
        let rp: Plan = serde_json::from_value(self.running_plan.clone())?;
        native211_event::event_predecessor_read(
            &self.previous,
            &rp,
            &self.memory.document(&self.origin),
            "2026-10-23T18:00:00Z",
            WALL + 62,
            &self.memory,
        )?;
        native211_capture::peers(&self.previous, &self.peers, c::UNIT)?;
        let iid = native211_terminal::validate_read(&self.proof, &self.memory)?;
        let tp: Plan = serde_json::from_value(self.terminal_plan.clone())?;
        native211_terminal::predecessor_read(
            &self.running_fleet,
            &tp,
            &self.proof,
            "2026-10-23T18:00:00Z",
            WALL + 121,
            &self.memory,
        )?;
        let owners = vec![(c::UNIT.to_owned(), iid)];
        let mut terminal_fleet = self.running_fleet.clone();
        terminal_fleet["metadata_event"] = self.terminal_plan["metadata_event"].clone();
        terminal_fleet["unit_census"][c::UNIT] = self.terminal.clone();
        let current = BTreeMap::from([(c::UNIT.to_owned(), self.terminal.clone())]);
        crate::inactive_status::native211_status_values_test(
            &current,
            &terminal_fleet,
            &owners,
            &owners[0],
        )
    }
}
#[test]
fn native211_complete_chain_preserves_history_and_allows_exact_terminal_status_cleanup() {
    fixture(None).check().unwrap();
}
#[test]
fn native211_complete_chain_rejects_changed_prestart_gate_terminal_and_authority() {
    for (document, pointer, value) in [
        (
            "prestart",
            "/schema",
            json!("horizon-native211-lifecycle-qualification-v1"),
        ),
        (
            "prestart",
            "/actual_first_guard_required_before_snapshot",
            json!(false),
        ),
        ("prestart", "/actual_native_startup_qualified", json!(true)),
        (
            "prestart",
            "/fleet_running_and_terminal_accepted",
            Value::Null,
        ),
        (
            "prestart",
            "/launcher_artifact_sha256",
            json!("9".repeat(64)),
        ),
        ("prestart", "/publication_authorized", json!(true)),
        ("review", "/publication_authorized", json!(true)),
        ("source", "/remote_ref", json!("refs/heads/unpublished")),
        ("token", "/main_pid", json!(43)),
        ("token", "/harness/sha256", json!("0".repeat(64))),
        ("token", "/boot_id", json!("old-boot")),
        ("token", "/startup_plan_sha256", json!("0".repeat(64))),
        ("first_journal", "/1/_PID", json!("42")),
        ("guard_sample", "/trip_reason", json!("reserve")),
        ("guard_sample", "/producer_stop_enabled", json!(false)),
        ("handoff", "/recorded_unix_seconds", json!(WALL + 111)),
        (
            "handoff",
            "/first_guard_token/path",
            json!("/var/lib/jetstreamer/wrong/token.json"),
        ),
        ("origin", "/publication_authorized", json!(true)),
        (
            "running_spec",
            "/output",
            json!("/var/lib/jetstreamer/wrong/intent.json"),
        ),
        ("terminal_journal", "/0/_BOOT_ID", json!("previous-boot")),
        ("terminal_journal", "/0/_PID", json!("43")),
        ("terminal_journal", "/2/__MONOTONIC_TIMESTAMP", json!("1")),
        (
            "terminal_journal",
            "/1/MESSAGE",
            json!("test result: FAILED. 0 passed"),
        ),
        ("proof", "/terminal_manager/ExecMainPID", json!("43")),
        ("proof", "/terminal_manager/ExecMainStatus", json!("1")),
        ("proof", "/publication_authorized", json!(true)),
    ] {
        assert!(
            fixture(Some((document, pointer, value))).check().is_err(),
            "{document}{pointer}"
        );
    }
}
#[test]
fn native211_complete_chain_preserves_peer_claim_gate_and_cleanup_owner() {
    let mut c = fixture(None);
    c.running_plan["pipeline_claims"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    assert!(c.check().is_err());
    let mut c = fixture(None);
    c.running_plan["diagnostics"] = json!([]);
    assert!(c.check().is_err());
    let mut c = fixture(None);
    c.running_plan["gates"]["247"]["operator_status"] = Value::Null;
    assert!(c.check().is_err());
    let mut c = fixture(None);
    c.terminal_plan["gates"]["211"]["state"] = json!("complete");
    assert!(c.check().is_err());
    let mut c = fixture(None);
    c.terminal_plan["tracked_units"] = json!([c::UNIT]);
    assert!(c.check().is_err());
    let mut c = fixture(None);
    c.peers.remove("audit.service");
    assert!(c.check().is_err());
    let mut c = fixture(None);
    c.peers.get_mut("old.service").unwrap()["InvocationID"] = json!("f".repeat(32));
    assert!(c.check().is_err());
    let mut c = fixture(None);
    c.terminal["InvocationID"] = json!("f".repeat(32));
    assert!(c.check().is_err());
    let mut c = fixture(None);
    c.terminal["MainPID"] = json!("42");
    assert!(c.check().is_err());
    let mut c = fixture(None);
    let token = c.memory.document(&c.handoff)["first_guard_token"]["path"]
        .as_str()
        .unwrap()
        .to_owned();
    c.memory.files.insert(
        Path::new(&token).with_file_name("guard-admission.sha256"),
        vec![b'0'; 65],
    );
    assert!(c.check().is_err());
}
