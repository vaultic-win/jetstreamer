//! Closed epoch 233 first-root experiment. This is not an ordinary replay route.
use super::*;
mod admission;
mod capture;
mod status;
#[cfg(test)]
mod tests;

pub(super) const SCHEMA: &str = "jetstreamer-private-first-root233-launch-v1";
pub(super) const UNIT: &str = "horizon-qualify-233-first-root-602556d-v1.service";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-233-first-root-602556d-v1";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-contiguous-233-236-cached-602556d-v5";
const NODE_SHA: &str = "d01828127997c4f14bdbca8c92a7bf66fb211bc39776429ccf36a4e69684c7e3";
const WORKER_SHA: &str = "88581898fb68efa52bbb2415eeb0c229c68d32cd36ee40d124c87761ba2b7486";
const SNAPSHOT_SHA: &str = "5709b09f085f165203cd1a610e916a6cb38791ee58520fbd78187f383b8a3cbc";
const SNAPSHOT: &str = "snapshot-100655540-A11g8aGUD2GCEGp7qcciMSW2Lf1StGPaUUZTLP1BHrRL.tar.zst";
const CHECKPOINTS: &str =
    "/var/lib/jetstreamer/horizon-233-cli-capability-policy-v1/epoch233-first-root-checkpoints.txt";
const CHECKPOINTS_SHA: &str = "a76a676116ba834fe0b5a58e34f8ed6758db7c9d4793d4a054b3c19c0cd5096e";
const CAPABILITY: &str =
    "/var/lib/jetstreamer/horizon-233-cli-capability-actual-v1/capability.json";
const CAPABILITY_SHA: &str = "1b74afd8eedb0b4c3bc91daf4b438aa245cff8e61ccac884e0773592e1657721";
const NATIVE: &str =
    "/home/ubuntu/.jetstreamer-private/v1-7-15-store8-build-16f18d8-20261008T191103Z.json";
const NATIVE_SHA: &str = "7c07e9b6a63ef56e202b0139fd0fa13802322d71c8b4c7a0a748a736a6202721";
pub(super) const GUARD: &str = "/var/lib/jetstreamer/horizon-native223-prefix-guard-044ccba7-v1/jetstreamer-horizon-standalone-guard";
pub(super) const GUARD_SHA: &str =
    "044ccba70304c6d5690d2628c1ca08586462efdcc2d9f278903ee8bab0da6b3f";
const PROTECTIVE: &str = "horizon-first-root233-protective-v1.service";
const GUARD_RECEIPTS: &str = "/var/lib/jetstreamer/horizon-233-first-root-guard-receipts-v1";
const ARCHIVE: &str = "epoch-233-through-101087369.jet";
const BOOTSTRAP: u64 = 100_655_540;
const FIRST: u64 = 100_656_000;
const TERMINAL: u64 = 101_087_369;
pub(super) const FLOOR: u64 = 2_000_000_000_000;
pub(super) const MEMORY: u64 = 225_000_000_000;
const DRAINAGE: u64 = 32 << 30;
const TREE_STOP: u64 = 300_000_000_000 + (128 << 30);
pub(super) const DISK_RESERVATION: u64 = TREE_STOP + DRAINAGE + (32 << 20);

pub(super) fn admit() -> Result<()> {
    admission::run()
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
    c.unit.starts_with("horizon-qualify-233-first-root-")
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
    json!({"epoch":233,"unit":UNIT,"private_run_root":ROOT,"node_sha256":NODE_SHA,
        "worker_sha256":WORKER_SHA,"snapshot_sha256":SNAPSHOT_SHA,"runtime":"solana-v1.7.15",
        "runtime_revision":"4892eb4e1ad278d5249b6cda8983f88effb3e98b",
        "bootstrap_slot":BOOTSTRAP,"output_slot_start":FIRST,"terminal_root_slot":TERMINAL,
        "terminal_accounts_hash":"CDRFzxzySaCm9MNtqEKSiFhB8b2QgS5dNeTonv6aZ9Ny",
        "output_slot_count":431370,"uncovered_suffix_slots":630,"natural_parent_completion_required":true,
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
        "first root 233 grants forbidden qualification or publication authority"
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
        "{{ path={PACKAGE}/jetstreamer-node ; argv[]={PACKAGE}/jetstreamer-node 233 {ROOT}/ledger --verify --qualification-end-slot={TERMINAL} --snapshot-archive={PACKAGE}/{SNAPSHOT} --epoch-hashes={CHECKPOINTS} --horizon-output={ROOT}/output/{ARCHIVE} --replay-scratch={ROOT}/scratch"
    )
}
fn environment() -> BTreeSet<String> {
    [
        "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1".into(),
        format!(
            "JETSTREAMER_HISTORICAL_WORKER_V1_7_15={PACKAGE}/jetstreamer-historical-worker-v1-7-15"
        ),
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
        cap["schema"] == "jetstreamer-epoch233-preworker-cli-capability-v1"
            && cap["node_sha256"] == NODE_SHA
            && cap["epoch_qualified"] == false
            && cap["native_snapshot_tests_repeated"] == false
            && cap["replay_launch_authorized"] == false
            && cap["probes"].as_array().is_some_and(|p| p.len() == 2)
            && cap["probes"][0]["barrier"] == "before-output"
            && cap["probes"][0]["exit_code"] == 2
            && cap["probes"][1]["barrier"] == "missing-post-bootstrap"
            && cap["probes"][1]["exit_code"] == 1,
        "first root 233 exact CLI capability differs"
    );
    let native = bound_json(&binding(NATIVE, NATIVE_SHA))?;
    ensure!(
        native["artifact"]["sha256"] == WORKER_SHA
            && native["runtime"] == "solana-v1.7.15"
            && native["qualification_gates"]["real_snapshot_tests"]["passed"] == 2
            && native["qualification_gates"]["real_snapshot_tests"]["failed"] == 0
            && native["qualification_gates"]["generation_pinned_boundary_snapshot_slot"]
                == BOOTSTRAP,
        "first root 233 cached native qualification differs"
    );
    let bytes = read_stable_bounded(Path::new(CHECKPOINTS), 1024, "first root 233 checkpoints")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == CHECKPOINTS_SHA,
        "first root 233 sealed checkpoint policy changed"
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
                .is_some_and(|s| matches!(s.as_str(), "8-15" | "8 9 10 11 12 13 14 15")),
            "first root 233 requires its separately assigned eight CPU mask: {field}"
        );
    }
    let values = p
        .get("Environment")
        .context("first root 233 environment absent")?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(
        values.len() == environment().len()
            && values.into_iter().collect::<BTreeSet<_>>() == environment()
            && p.get("ExecStart")
                .is_some_and(|s| private_prefix::same_command(&json!(s), &command())),
        "first root 233 command or explicit thread environment differs"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    ensure!(
        c.epoch == 233
            && c.unit == UNIT
            && c.scratch_path == Path::new(ROOT)
            && private_prefix::owner(current, UNIT, &c.invocation_id, &command()),
        "first root 233 live identity differs"
    );
    sandbox(&capture::properties()?)?;
    capture::kernel_limits()?;
    Ok(())
}
pub(super) fn launch_matches(c: &DiagnosticClaim, v: &Value) -> bool {
    c.epoch == 233
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
        && floor.is_some_and(|n| n >= FLOOR + DRAINAGE)
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
        "first root 233 launch profile or claim differs"
    );
    prerequisites()?;
    let a = native209::immutable_json(&serde_json::from_value(v["admission"].clone())?)?;
    admission::validate_saved(&a)?;
    let g = bound_json(&serde_json::from_value(v["guard"].clone())?)?;
    let pb: BoundFile = serde_json::from_value(v["guard_plan"].clone())?;
    let p = native209::immutable_json(&pb)?;
    let captured = v["recorded_unix_seconds"]
        .as_u64()
        .context("first root 233 capture clock absent")?;
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
        "first root 233 capture substituted its admission, guard, PID, or clock"
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
        "first root 233 capture clock is not anchored to its original PID1 start"
    );
    private_prefix::elapsed(
        captured,
        v["clock_anchor"]["wall_millis"]
            .as_u64()
            .context("first root 233 capture wall clock absent")?,
        v["clock_anchor"]["monotonic_millis"]
            .as_u64()
            .context("first root 233 capture monotonic clock absent")?,
        v["clock_anchor"]["producer_start_monotonic_us"]
            .as_u64()
            .context("first root 233 start clock absent")?,
    )?;
    capture::worker_saved(&v["worker_binding"], &g)?;
    let selected = &v["guard_manager"]["completed_selection"];
    ensure!(
        selected["binding"] == v["guard"] && selected["history"]["unit"] == PROTECTIVE,
        "first root 233 selected guard history differs"
    );
    warmup223::validate_completed_guard_history(&selected["history"], &g)?;
    Ok(())
}
