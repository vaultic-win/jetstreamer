//! Closed epoch 228 first-root experiment. This is not an ordinary replay route.
use super::*;
mod admission;
mod capability;
mod capture;
mod status;

pub(super) const SCHEMA: &str = "jetstreamer-private-bounded228-launch-v1";
pub(super) const UNIT: &str = "horizon-qualify-228-root-tail-1bfa8d51-v1.service";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-228-v1620-root-tail-v1";
const NODE: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/jetstreamer-node";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-contiguous-228-230-current-46b4b4a-v1";
const NODE_SHA: &str = "f2c11e5b596e5a0107ddded523c310a1deb71b9206e95f3113f5ac713b920e11";
const WORKER_SHA: &str = "1bfa8d51d44729c75db7ffe5d466cec9d902216d9362a6efb129bf927ca85673";
const SNAPSHOT_SHA: &str = "da26bd1b4b3b93be74c9dae28d1d982f821474333aa06e87f32dfa83342915f3";
const SNAPSHOT: &str = "snapshot-98495291-GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq.tar.zst";
const CHECKPOINTS: &str = "/var/lib/jetstreamer/horizon-bounded228-inputs-v1/epoch-hashes.json";
const CHECKPOINTS_SHA: &str = "41c99cdb6da5990cff72ee893d292b3db40eb9786b0ae0018409b380d4cfbd47";
const CAPABILITY: &str =
    "/var/lib/jetstreamer/horizon-cached-singleton-228-preparation-v1/capability.json";
const CAPABILITY_SHA: &str = "215a0ca0b4acf966935edb83fdb06eaea114c93c2b2c1e9cc36c19755cb1e8ce";
const NATIVE: &str =
    "/var/lib/jetstreamer/horizon-native228-terminal-proof-1b207be8-from338-v3/proof.json";
const NATIVE_SHA: &str = "81a30f0039b2344b81e7678004c87d96c9ac6a8ac7b5ff0c6b98631989363f43";
pub(super) const GUARD: &str = "/var/lib/jetstreamer/horizon-native223-prefix-guard-044ccba7-v1/jetstreamer-horizon-standalone-guard";
pub(super) const GUARD_SHA: &str =
    "044ccba70304c6d5690d2628c1ca08586462efdcc2d9f278903ee8bab0da6b3f";
pub(super) const PROTECTIVE: &str = "horizon-bounded228-protective-v1.service";
pub(super) const GUARD_RECEIPTS: &str =
    "/var/lib/jetstreamer/horizon-228-first-root-guard-receipts-v1";
const ARCHIVE: &str = "epoch-228-through-98928278.jet";
const BOOTSTRAP: u64 = 98_495_291;
const FIRST: u64 = 98_496_000;
const TERMINAL: u64 = 98_928_278;
pub(super) const MEMORY: u64 = 225_000_000_000;
const DRAINAGE: u64 = 32 << 30;
const TREE_STOP: u64 = 300_000_000_000 + (128 << 30);
pub(super) const DISK_RESERVATION: u64 = TREE_STOP + DRAINAGE + (32 << 20);

pub(super) fn admit() -> Result<()> {
    admission::run()
}
pub(super) fn probe_parent() -> Result<()> {
    capability::run()
}
pub(super) fn capture_launch() -> Result<()> {
    capture::run()
}
pub(super) async fn publish_status() -> Result<()> {
    status::run().await
}
pub(super) fn status_matches(
    r: &StatusPublicationReceipt,
    epoch: u64,
    o: &Value,
    u: &BTreeMap<String, Value>,
) -> bool {
    status::matches(r, epoch, o, u)
}
pub(super) fn inactive_owner(r: &StatusPublicationReceipt) -> Result<Option<(String, String)>> {
    status::inactive_owner(r)
}

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.unit.starts_with("horizon-qualify-228-root-tail-")
}
fn binding(path: &str, sha: &str) -> BoundFile {
    BoundFile {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn scope() -> Value {
    json!({"epoch":228,"unit":UNIT,"private_run_root":ROOT,"node_sha256":NODE_SHA,
        "worker_sha256":WORKER_SHA,"snapshot_sha256":SNAPSHOT_SHA,"runtime":"solana-v1.6.20",
        "runtime_revision":"77bdb45d4af61fc687161ec06cc0178ff79726d5",
        "bootstrap_slot":BOOTSTRAP,"output_slot_start":FIRST,"terminal_root_slot":TERMINAL,
        "terminal_accounts_hash":"6Ec1ZPL4kEMFLU2qAsRfrbmYnEhm8pL77Xt1PoBhyGra",
        "output_slot_count":432279,"retained_verification_tail_slots":279,"tail_extraction_required":true,"natural_parent_completion_required":true,
        "canonical_epoch_end_slot":98927999u64,"canonical_epoch_slot_count":432000,
        "bootstrap_prelude_slot_count":708,"checkpoint_bearing_source_retained":true,
        "extraction_executor_qualified":false,"full_verification_required":true,
        "plugin_verification_required":true,"independent_publication_gates_required":true,
        "maximum_scratch_bytes":300_000_000_000u64,"scratch_is_trial_allowance_not_quota":true,
        "own_tree_guard_threshold_bytes":TREE_STOP,"candidate_incremental_disk_reservation_bytes":DISK_RESERVATION,
        "maximum_memory_bytes":MEMORY,"maximum_runtime_seconds":259200,"remote_mutations":false,"r2_mutations":false,
        "capability":private157::binding(&binding(CAPABILITY,CAPABILITY_SHA)),
        "native_input":private157::binding(&binding(NATIVE,NATIVE_SHA)),
        "checkpoints":private157::binding(&binding(CHECKPOINTS,CHECKPOINTS_SHA))})
}
const DENIED: [&str; 13] = [
    "ordinary_replay_authorized",
    "full_cold_epoch_peak_qualified",
    "canonical_prefix_independently_qualified",
    "native_restart_qualified",
    "suffix_qualified",
    "assembly_qualified",
    "full_epoch_qualified",
    "full_plugin_qualified",
    "runtime_promotion_authorized",
    "canonical_sidecar_authorized",
    "publication_authorized",
    "repair_closed",
    "archive_mutations_authorized",
];
fn deny_authority(v: &Value) -> Result<()> {
    ensure!(
        DENIED.iter().all(|k| v[*k] == false),
        "bounded epoch 228 grants forbidden qualification or publication authority"
    );
    Ok(())
}
fn deny_fields(v: &mut Value) {
    for k in DENIED {
        v[k] = json!(false);
    }
}
fn scope_matches(v: &Value) -> bool {
    scope()
        .as_object()
        .is_some_and(|fields| fields.iter().all(|(k, x)| v[k] == *x))
}
fn command() -> String {
    format!(
        "{{ path={NODE} ; argv[]={NODE} 228 {ROOT}/ledger --verify --qualification-end-slot={TERMINAL} --snapshot-archive={PACKAGE}/{SNAPSHOT} --epoch-hashes={CHECKPOINTS} --horizon-output={ROOT}/output/{ARCHIVE} --replay-scratch={ROOT}/scratch"
    )
}
fn environment() -> BTreeSet<String> {
    [
        "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1".into(),
        "JETSTREAMER_HISTORICAL_WORKER_V1_6_20=/var/lib/jetstreamer/horizon-228-capped-candidate-1bfa8d51-v1/jetstreamer-historical-worker-v1-6-20".into(),
        "SOLANA_RAYON_THREADS=8".into(),
        "RAYON_NUM_THREADS=8".into(),
        "JETSTREAMER_HISTORICAL_POH_THREADS=8".into(),
        "TOKIO_WORKER_THREADS=8".into(),
        "RUST_MIN_STACK=134217728".into(),
        "RUST_LOG=info".into(),
    ]
    .into_iter()
    .collect()
}
fn prerequisites() -> Result<()> {
    let cap = native209::immutable_json(&binding(CAPABILITY, CAPABILITY_SHA))?;
    ensure!(
        cap["schema"] == "jetstreamer-private-cached-singleton-input-capability-v1"
            && cap["profile"] == "epoch228-v1620-root-tail"
            && cap["all_immutable_inputs_rehashed"] == true
            && cap["worker_spawned"] == false
            && cap["preparation"]["canonical_bootstrap_slot"] == BOOTSTRAP
            && cap["preparation"]["canonical_checkpoint_slot"] == TERMINAL
            && cap["preparation"]["focused_tail_output_slot_count"] == 432279
            && cap["replay_launch_authorized"] == false
            && cap["publication_authorized"] == false,
        "bounded228 cached preparation is not its exact retained root-tail input"
    );
    let native = native209::immutable_json(&binding(NATIVE, NATIVE_SHA))?;
    let iid = native228_terminal::validate(&native)?;
    ensure!(
        iid == "1b207be826cc45979d5a92a44de4bd14"
            && native["native_input_qualified"] == true
            && native["entry_replay"] == false
            && native["full_epoch_qualified"] == false
            && native["native_marker"]["slot"] == "98495291"
            && native["native_marker"]["accounts_hash"]
                == "GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq",
        "bounded228 needs its genuine original bootstrap-only qualification"
    );
    let bytes = read_stable_bounded(
        Path::new(CHECKPOINTS),
        1024,
        "bounded228 exact checkpoint map",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == CHECKPOINTS_SHA,
        "bounded228 trusted checkpoint bytes changed"
    );
    Ok(())
}

pub(super) fn sandbox(p: &BTreeMap<String, String>) -> Result<()> {
    singleton227_capture::require(
        p,
        &[
            ("Type", "exec"),
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryHigh", "150000000000"),
            ("MemoryMax", "225000000000"),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("TasksMax", "512"),
            ("RuntimeMaxUSec", "3d"),
            ("LimitFSIZE", "137438953472"),
            ("LimitFSIZESoft", "137438953472"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("ProtectControlGroups", "yes"),
            ("NoNewPrivileges", "yes"),
            ("PrivateTmp", "yes"),
            ("PrivateNetwork", "no"),
            ("CapabilityBoundingSet", ""),
            ("AmbientCapabilities", ""),
            ("ReadWritePaths", ROOT),
            ("OOMPolicy", "kill"),
            ("OOMScoreAdjust", "1000"),
            ("UMask", "0077"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("NRestarts", "0"),
            ("Result", "success"),
        ],
    )?;
    for field in ["AllowedCPUs", "CPUAffinity"] {
        ensure!(
            p.get(field)
                .is_some_and(|s| matches!(s.as_str(), "16-23" | "16 17 18 19 20 21 22 23")),
            "bounded epoch 228 requires its separately assigned eight CPU mask: {field}"
        );
    }
    let values = p
        .get("Environment")
        .context("bounded epoch 228 environment absent")?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(
        values.len() == environment().len()
            && values.into_iter().collect::<BTreeSet<_>>() == environment()
            && p.get("ExecStart")
                .is_some_and(|s| private_prefix::same_command(&json!(s), &command())),
        "bounded epoch 228 command or explicit thread environment differs"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    ensure!(
        c.epoch == 228
            && c.unit == UNIT
            && c.scratch_path == Path::new(ROOT)
            && private_prefix::owner(current, UNIT, &c.invocation_id, &command()),
        "bounded epoch 228 live identity differs"
    );
    sandbox(&capture::properties()?)?;
    capture::kernel_limits()?;
    Ok(())
}
pub(super) fn launch_matches(c: &DiagnosticClaim, v: &Value) -> bool {
    c.epoch == 228
        && c.unit == UNIT
        && c.scratch_path == Path::new(ROOT)
        && v["schema"] == SCHEMA
        && scope_matches(v)
        && v["launched"] == true
        && v["ordinary_replay_claim"] == false
        && v["entry_replay"] == true
        && v["public_sidecar_countdown_authorized"] == true
        && deny_authority(v).is_ok()
        && v["evidence"]["units"]
            .as_array()
            .is_some_and(|u| u.len() == 1)
        && v["evidence"]["units"][0]["unit"] == UNIT
        && v["evidence"]["units"][0]["invocation_id"] == c.invocation_id
        && v["evidence"]["units"][0]["restarts"] == 0
        && private_prefix::same_command(&v["expected_exec_start"], &command())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, v: &Value, p: &Value) -> bool {
    let floor = v["guard_minimum_free_bytes"].as_u64();
    launch_matches(c, v)
        && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
        && p["unit"] == UNIT
        && p["invocation_id"] == c.invocation_id
        && p["filesystem"] == "/"
        && p["worker_root"] == ROOT
        && p["receipt_directory"] == GUARD_RECEIPTS
        && floor.is_some_and(|n| n > DRAINAGE)
        && p["minimum_free_bytes"] == v["guard_minimum_free_bytes"]
        && p["maximum_root_physical_bytes"] == TREE_STOP
        && p["maximum_worker_vmas"] == 3500000
        && ["bounded_canary", "bounded_measurement", "native_main"]
            .iter()
            .all(|k| p.get(*k).is_none_or(Value::is_null))
}
pub(super) fn bindings(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    ensure!(
        launch_matches(c, v),
        "bounded epoch 228 launch profile or claim differs"
    );
    prerequisites()?;
    let a = native209::immutable_json(&serde_json::from_value(v["admission"].clone())?)?;
    admission::validate_saved(&a)?;
    let g = bound_json(&serde_json::from_value(v["guard"].clone())?)?;
    let pb: BoundFile = serde_json::from_value(v["guard_plan"].clone())?;
    let p = native209::immutable_json(&pb)?;
    let captured = v["recorded_unix_seconds"]
        .as_u64()
        .context("bounded epoch 228 capture clock absent")?;
    ensure!(
        capture::guard_valid(&a, &g, &p, &pb.sha256, captured)? == c.invocation_id
            && v["capture_helper_sha256"] == a["admission_helper_sha256"]
            && canonical_digest(&v["capture_helper_sha256"])
            && v["observer"] == a["observer"]
            && v["fleet"] == a["fleet"]
            && v["guard_minimum_free_bytes"] == a["guard_minimum_free_bytes"]
            && g["producer"]["pid"] == v["evidence"]["units"][0]["main_pid"]
            && v["sandbox"]["ExecMainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == g["producer"]["pid"].as_u64(),
        "bounded epoch 228 capture substituted its admission, guard, PID, or clock"
    );
    sandbox(&serde_json::from_value(v["sandbox"].clone())?)?;
    capture::kernel_saved(&v["kernel_limits"])?;
    ensure!(
        v["clock_anchor"]["wall_millis"]
            .as_u64()
            .is_some_and(|n| n / 1000 == captured)
            && v["clock_anchor"]["producer_start_monotonic_us"].as_u64()
                == v["sandbox"]["ExecMainStartTimestampMonotonic"]
                    .as_str()
                    .and_then(|n| n.parse::<u64>().ok()),
        "bounded epoch 228 capture clock is not anchored to its original PID1 start"
    );
    private_prefix::elapsed(
        captured,
        v["clock_anchor"]["wall_millis"]
            .as_u64()
            .context("bounded epoch 228 capture wall clock absent")?,
        v["clock_anchor"]["monotonic_millis"]
            .as_u64()
            .context("bounded epoch 228 capture monotonic clock absent")?,
        v["clock_anchor"]["producer_start_monotonic_us"]
            .as_u64()
            .context("bounded epoch 228 start clock absent")?,
    )?;
    capture::worker_saved(&v["worker_binding"], &g)?;
    let selected = &v["guard_manager"]["completed_selection"];
    ensure!(
        selected["binding"] == v["guard"] && selected["history"]["unit"] == PROTECTIVE,
        "bounded epoch 228 selected guard history differs"
    );
    warmup223::validate_completed_guard_history(&selected["history"], &g)?;
    Ok(())
}

#[cfg(test)]
pub(super) fn launch_fixture() -> (DiagnosticClaim, Value) {
    let mut v = scope();
    deny_fields(&mut v);
    v["schema"] = json!(SCHEMA);
    v["launched"] = json!(true);
    v["ordinary_replay_claim"] = json!(false);
    v["entry_replay"] = json!(true);
    v["public_sidecar_countdown_authorized"] = json!(true);
    v["evidence"] = json!({"units":[{"unit":UNIT,"invocation_id":"c".repeat(32),"restarts":0}]});
    v["expected_exec_start"] = json!(format!("{} ; ignore_errors=no ; pid=0 }}", command()));
    let claim = DiagnosticClaim {
        epoch: 228,
        unit: UNIT.into(),
        invocation_id: "c".repeat(32),
        scratch_path: ROOT.into(),
        launch_receipt: binding("/sealed/launch.json", &"0".repeat(64)),
    };
    (claim, v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact228_root_tail_is_never_an_ordinary_or_complete_epoch_claim() {
        let (d, v) = launch_fixture();
        assert!(launch_matches(&d, &v));
        assert_eq!(TERMINAL - FIRST + 1, 432_279);
        assert_eq!(FIRST - BOOTSTRAP - 1, 708);
        for (key, bad) in [
            ("terminal_root_slot", json!(98_927_999)),
            ("output_slot_count", json!(432_000)),
            ("retained_verification_tail_slots", json!(0)),
            ("tail_extraction_required", json!(false)),
            ("worker_sha256", json!("0".repeat(64))),
            ("snapshot_sha256", json!("0".repeat(64))),
            ("ordinary_replay_claim", json!(true)),
            ("extraction_executor_qualified", json!(true)),
        ] {
            let mut changed = v.clone();
            changed[key] = bad;
            assert!(!launch_matches(&d, &changed), "{key}");
        }
        for k in DENIED {
            let mut changed = v.clone();
            changed[k] = json!(true);
            assert!(!launch_matches(&d, &changed), "{k}");
        }
        let mut wrong_owner = d;
        wrong_owner.invocation_id = "d".repeat(32);
        assert!(!launch_matches(&wrong_owner, &v));
        wrong_owner.unit = "horizon-qualify-228-230-root-cohort-v1.service".into();
        assert!(!launch_matches(&wrong_owner, &v));
        assert!(!namespace(&wrong_owner));
        assert!(command().contains("--qualification-end-slot=98928278"));
        assert!(!command().contains("--root-checkpoint-cohort"));
        assert!(environment().contains(&format!("JETSTREAMER_HISTORICAL_WORKER_V1_6_20=/var/lib/jetstreamer/horizon-228-capped-candidate-1bfa8d51-v1/jetstreamer-historical-worker-v1-6-20")));
    }
    #[test]
    fn guard_cannot_borrow_233_or_a_different_tail_budget() {
        let (d, mut v) = launch_fixture();
        v["guard_minimum_free_bytes"] = json!(DRAINAGE + 100);
        let p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,
            "invocation_id":d.invocation_id,"filesystem":"/","worker_root":ROOT,
            "receipt_directory":GUARD_RECEIPTS,"minimum_free_bytes":DRAINAGE+100,
            "maximum_root_physical_bytes":TREE_STOP,"maximum_worker_vmas":3500000});
        assert!(guard_matches(&d, &v, &p));
        for (key, bad) in [
            ("unit", json!(first_root233::UNIT)),
            ("worker_root", json!(first_root233::ROOT)),
            ("maximum_root_physical_bytes", json!(300_000_000_000u64)),
            ("native_main", json!({})),
        ] {
            let mut changed = p.clone();
            changed[key] = bad;
            assert!(!guard_matches(&d, &v, &changed), "{key}");
        }
    }
}
