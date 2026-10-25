//! Closed full epoch 207 candidate; launch never qualifies an archive or authorizes R2.
use super::*;
mod admission;
mod capture;
mod status;
mod terminal;
pub(super) fn capture_terminal() -> Result<()> {
    terminal::run()
}
#[cfg(test)]
mod tests;

pub(super) const SCHEMA: &str = "jetstreamer-private-singleton207-launch-v1";
pub(super) const UNIT: &str = "horizon-qualify-207-singleton-admitted-v1.service";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-207-singleton-admitted-v1";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-focused-207-complete-span-store8-ca2e38b-v2";
const NODE: &str = "/var/lib/jetstreamer/horizon-207-singleton-node-08e1-v1/jetstreamer-node";
const NODE_SHA: &str = "08e14bb09a1cbf762ed1b8910a1d8a9e949f0a5890984060304bc6c7d45206f7";
const WORKER: &str = "/var/lib/jetstreamer/horizon-focused-207-complete-span-store8-ca2e38b-v2/jetstreamer-historical-worker-v1-6-16-store8";
const WORKER_SHA: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
const SNAPSHOT_SHA: &str = "8af3cd20c8f9820dacd25932fc6b7938193e0d1a5dc83d8ddd59dfeea69b2ddc";
const SNAPSHOT: &str = "snapshot-89423444-3NVZVHDVwXgMxuTP77gaZF4UBP1oNBQzGScBGyoLx2Px.tar.zst";
const MANIFEST: &str = "/var/lib/jetstreamer/horizon-207-root-metadata-candidate-reviewed-20261025-sdk59001-v1/preflight207-singleton-candidate.json";
const MANIFEST_SHA: &str = "801707df48654c272b0fffc1005eea97b90dbd1ffe59190aede1c1616e134379";
const FINGERPRINT: &str = "sha256:9df04afe0f7ced39c179f2e5dafc34dac2aa6724fe1a8285b38cbfb528834db7";
const METADATA: &str = "/var/lib/jetstreamer/horizon-207-root-metadata-authenticated-reviewed-20261025-sdk59001-v1/metadata-evidence.json";
const METADATA_SHA: &str = "41262e1c49c26c72009ef5ec3d6fbdee081873cbb64c4983398f9d7555478176";
const CAPABILITY: &str =
    "/var/lib/jetstreamer/horizon-207-singleton-preflight-admitted-md5-v1/preflight-capture.json";
const CAPABILITY_SHA: &str = "835ca977c73d3db0717fd5257b6e7f8307fa012379826ba20bf750c5322a3d9a";
const NATIVE: &str = "/var/lib/jetstreamer/horizon-native207-terminal-proof-v1/proof.json";
const NATIVE_SHA: &str = "ed39b654d78d4530f82877866d4474435beb353503ad1d3ebfcae04823489819";
pub(super) const GUARD: &str = "/var/lib/jetstreamer/horizon-native223-prefix-guard-044ccba7-v1/jetstreamer-horizon-standalone-guard";
pub(super) const GUARD_SHA: &str =
    "044ccba70304c6d5690d2628c1ca08586462efdcc2d9f278903ee8bab0da6b3f";
pub(super) const PROTECTIVE: &str = "horizon-singleton207-protective-v1.service";
pub(super) const GUARD_RECEIPTS: &str =
    "/var/lib/jetstreamer/horizon-207-singleton-guard-receipts-v1";

const BOOTSTRAP: u64 = 89_423_444;
const FIRST: u64 = 89_424_000;
const TERMINAL: u64 = 89_855_999;
pub(super) const MEMORY: u64 = 225_000_000_000;
const DRAINAGE: u64 = 32 << 30;
const TREE_STOP: u64 = 300_000_000_000 + (128 << 30);
pub(super) const DISK_RESERVATION: u64 = TREE_STOP + DRAINAGE + (32 << 20);

pub(super) fn prepare_inputs() -> Result<()> {
    prerequisites::prepare_inputs()
}

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
    c.unit.starts_with("horizon-qualify-207-singleton-")
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
    json!({"epoch":207,"unit":UNIT,"private_run_root":ROOT,"node_sha256":NODE_SHA,
        "worker_sha256":WORKER_SHA,"snapshot_sha256":SNAPSHOT_SHA,"runtime":"solana-v1.6.16",
        
        "bootstrap_slot":BOOTSTRAP,"output_slot_start":FIRST,"terminal_slot":TERMINAL,"canonical_root_slots":[89523820u64,89855469u64],
        "canonical_accounts_hashes":["7NUvFRrgkc2pc9DPmD7vrrooZkEwc6r8KqUMq5MrG3ik","9i59TwLmzXvbomizFZNuXgPygtx8zJ3P4nWDQuNxrTxK"],
        "output_slot_count":432000,"post_last_known_root_slots":530,"epoch208_tail_authorized":false,"natural_parent_completion_required":true,
        "maximum_scratch_bytes":300_000_000_000u64,"scratch_is_trial_allowance_not_quota":true,"upstream_shrink_budget_cap":false,
        "own_tree_guard_threshold_bytes":TREE_STOP,"candidate_incremental_disk_reservation_bytes":DISK_RESERVATION,
        "maximum_memory_bytes":MEMORY,"maximum_runtime_seconds":259200,"remote_mutations":false,"r2_mutations":false,
        "capability":private157::binding(&binding(CAPABILITY,CAPABILITY_SHA)),
        "native_input":private157::binding(&binding(NATIVE,NATIVE_SHA)),
        "manifest":private157::binding(&binding(MANIFEST,MANIFEST_SHA)),"manifest_fingerprint":FINGERPRINT,
        "authenticated_metadata":private157::binding(&binding(METADATA,METADATA_SHA))})
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
        "singleton 207 grants forbidden qualification or publication authority"
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
        "{{ path={NODE} ; argv[]={NODE} 207 {ROOT}/output --verify --root-checkpoint-cohort --cohort-manifest={MANIFEST} --cohort-manifest-fingerprint={FINGERPRINT} --snapshot-archive={PACKAGE}/{SNAPSHOT}"
    )
}
fn environment() -> BTreeSet<String> {
    [
        "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1".into(),
        format!("JETSTREAMER_HISTORICAL_WORKER_V1_6_16={WORKER}"),
        "SOLANA_RAYON_THREADS=8".into(),
        "RAYON_NUM_THREADS=8".into(),
        "JETSTREAMER_HISTORICAL_POH_THREADS=8".into(),
        "TOKIO_WORKER_THREADS=8".into(),
        "RUST_MIN_STACK=134217728".into(),
        "RUST_LOG=info".into(),
        format!("JETSTREAMER_PRIVATE_RUN_ROOT={ROOT}/private"),
    ]
    .into_iter()
    .collect()
}
mod prerequisites;
fn prerequisites() -> Result<()> {
    prerequisites::validate()
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
            ("TasksMax", "1024"),
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
            "singleton 207 requires its separately assigned eight CPU mask: {field}"
        );
    }
    let values = p
        .get("Environment")
        .context("singleton 207 environment absent")?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(
        values.len() == environment().len()
            && values.into_iter().collect::<BTreeSet<_>>() == environment()
            && p.get("ExecStart")
                .is_some_and(|s| private_prefix::same_command(&json!(s), &command())),
        "singleton 207 command or explicit thread environment differs"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    ensure!(
        c.epoch == 207
            && c.unit == UNIT
            && c.scratch_path == Path::new(ROOT)
            && private_prefix::owner(current, UNIT, &c.invocation_id, &command()),
        "singleton 207 live identity differs"
    );
    sandbox(&capture::properties()?)?;
    capture::kernel_limits()?;
    Ok(())
}
pub(super) fn launch_matches(c: &DiagnosticClaim, v: &Value) -> bool {
    c.epoch == 207
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
        "singleton 207 launch profile or claim differs"
    );
    prerequisites()?;
    let a = native209::immutable_json(&serde_json::from_value(v["admission"].clone())?)?;
    admission::validate_saved(&a)?;
    let g = bound_json(&serde_json::from_value(v["guard"].clone())?)?;
    let pb: BoundFile = serde_json::from_value(v["guard_plan"].clone())?;
    let p = native209::immutable_json(&pb)?;
    let captured = v["recorded_unix_seconds"]
        .as_u64()
        .context("singleton 207 capture clock absent")?;
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
        "singleton 207 capture substituted its admission, guard, PID, or clock"
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
        "singleton 207 capture clock is not anchored to its original PID1 start"
    );
    private_prefix::elapsed(
        captured,
        v["clock_anchor"]["wall_millis"]
            .as_u64()
            .context("singleton 207 capture wall clock absent")?,
        v["clock_anchor"]["monotonic_millis"]
            .as_u64()
            .context("singleton 207 capture monotonic clock absent")?,
        v["clock_anchor"]["producer_start_monotonic_us"]
            .as_u64()
            .context("singleton 207 start clock absent")?,
    )?;
    capture::worker_saved(&v["worker_binding"], &g)?;
    let selected = &v["guard_manager"]["completed_selection"];
    ensure!(
        selected["binding"] == v["guard"] && selected["history"]["unit"] == PROTECTIVE,
        "singleton 207 selected guard history differs"
    );
    warmup223::validate_completed_guard_history(&selected["history"], &g)?;
    Ok(())
}

pub(super) fn assigned_cpus_available(value: &str) -> Result<()> {
    let mut available = BTreeSet::new();
    for token in value.trim().split(',') {
        let (start, end) = if let Some((a, b)) = token.split_once('-') {
            (a.parse::<u32>()?, b.parse::<u32>()?)
        } else {
            let n = token.parse::<u32>()?;
            (n, n)
        };
        ensure!(
            start <= end && end < 4096,
            "singleton 207 parent CPU mask is malformed or oversized"
        );
        for cpu in start..=end {
            ensure!(
                available.insert(cpu),
                "singleton 207 parent CPU mask duplicates a CPU"
            );
        }
    }
    ensure!(
        (16..24).all(|cpu| available.contains(&cpu)),
        "singleton 207 separately assigned CPUs are unavailable"
    );
    Ok(())
}
