//! Closed payload contract. The parent-owned admission controller supplies current
//! resource evidence; this reader cannot retire, borrow, or manufacture a booking.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
#[path = "scope.rs"]
pub(crate) mod scope;
use scope::*;
pub(crate) const TOOLS: &str = scope::TOOLS;
pub(crate) const ADMISSION_PATH: &str = scope::ADMISSION_PATH;
pub(crate) const FILESYSTEM: &str = "/home/sol";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub schema: String,
    pub node: Bound,
    pub helper: Bound,
    pub worker: Bound,
    pub tools_seal: Bound,
    pub qualification: Bound,
    pub source_proof: Bound,
    pub source_commit: String,
    pub history: Bound,
    pub controller: Bound,
    pub barrier_version: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Admission {
    pub schema: String,
    pub plan: Bound,
    pub helper: Bound,
    pub node: Bound,
    pub worker: Bound,
    pub tools_seal: Bound,
    pub writer: Bound,
    pub writer_invocation_id: String,
    pub recorded_unix_seconds: u64,
    pub launch_expires_unix_seconds: u64,
    pub protected_existing_free_bytes: u64,
    pub required_initial_free_bytes: u64,
    pub data_reservation_bytes: u64,
    pub memory_max_bytes: u64,
    pub cpu_quota_micros: u64,
    pub resource_accounting: Bound,
    pub bounded_reproduction_authorized: bool,
    pub publication_authorized: bool,
    pub remote_mutations: bool,
    pub r2_mutations: bool,
    pub full_epoch_span_proven: bool,
}
pub(crate) fn digest(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}
fn package(name: &str) -> PathBuf {
    Path::new(TOOLS).join(name)
}
pub(crate) fn plan_shape(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "horizon-epoch136-actual-plan-v1"
            && p.barrier_version == BARRIER_VERSION
            && p.node.path == package("jetstreamer-node")
            && p.helper.path == package("epoch136-actual-payload")
            && p.worker.path == Path::new(WORKER_PATH)
            && p.worker.sha256 == WORKER_SHA
            && p.tools_seal.path == package("deployment-seal-receipt.json")
            && p.source_proof.path == package("artifact-proof.json")
            && p.qualification.path == package("qualification.json")
            && p.qualification.sha256 == QUALIFICATION_SHA
            && p.history.path == package("historical-accounting-review.json")
            && p.history.sha256
                == "dccb6e51d0b7522d8a7fedcbbbb8bb3fe194967b9452c7e97a9865f08493ed4c"
            && p.controller.path == Path::new(BASE).join("controller/admit136")
            && digest(&p.source_commit, 40)
            && [
                &p.node,
                &p.helper,
                &p.worker,
                &p.tools_seal,
                &p.qualification,
                &p.source_proof,
                &p.history,
                &p.controller
            ]
            .iter()
            .all(|b| b.path.is_absolute() && digest(&b.sha256, 64)),
        "wrong new-generation package, images, source or authority"
    );
    Ok(())
}
pub(crate) fn qualification(p: &Plan, worker: &Value, source: &Value) -> Result<()> {
    ensure!(
        worker["schema"] == "horizon-epoch136-new-charge-trace-qualification-v1"
            && worker["verified_remote_commit"] == QUALIFIED_WORKER_COMMIT
            && worker["production"]["optin"]["worker"]["sha256"] == WORKER_SHA
            && worker["actual_epoch_replay_admitted"] == false
            && worker["archive_verified"] == false,
        "production worker qualification differs"
    );
    ensure!(
        source["schema"] == "horizon-epoch136-actual-artifact-proof-v1"
            && source["source_commit"] == p.source_commit
            && source["source_contained_in_origin_account_updates"] == true
            && source["qualified_worker_commit"] == QUALIFIED_WORKER_COMMIT
            && source["worker"] == json!(p.worker)
            && source["node"] == json!(p.node)
            && source["payload"] == json!(p.helper)
            && source["exact_node_cli_and_snapshot_route_qualified"] == true
            && source["actual_worker_pre_initialize_gate_qualified"] == true
            && source["tests_passed"].as_u64().is_some_and(|n| n > 0)
            && source["tests_failed"] == 0
            && source["publication_authorized"] == false,
        "node/payload source and actual route remain unqualified"
    );
    Ok(())
}
pub(crate) fn admission_shape(p: &Plan, plan: &Bound, a: &Admission, now: u64) -> Result<()> {
    plan_shape(p)?;
    ensure!(
        a.schema == "horizon-epoch136-actual-admission-v1"
            && a.plan == *plan
            && a.helper == p.helper
            && a.node == p.node
            && a.worker == p.worker
            && a.tools_seal == p.tools_seal
            && a.writer == p.controller
            && digest(&a.writer_invocation_id, 32)
            && a.recorded_unix_seconds <= now
            && now < a.launch_expires_unix_seconds
            && a.launch_expires_unix_seconds
                .checked_sub(a.recorded_unix_seconds)
                .is_some_and(|n| n > 0 && n <= 900)
            && a.protected_existing_free_bytes > 0
            && a.required_initial_free_bytes
                == a.protected_existing_free_bytes
                    .checked_add(DATA)
                    .context("DATA overflow")?
            && a.data_reservation_bytes == DATA
            && a.memory_max_bytes == MEMORY
            && a.cpu_quota_micros == CPU_MICROS
            && a.bounded_reproduction_authorized
            && !a.publication_authorized
            && !a.remote_mutations
            && !a.r2_mutations
            && !a.full_epoch_span_proven
            && a.resource_accounting.path == Path::new(BASE).join("capacity.json")
            && digest(&a.resource_accounting.sha256, 64),
        "missing, foreign, expired or unbounded parent admission"
    );
    Ok(())
}
/// The writer is independently qualified and pinned by Plan. This is a reader
/// adapter, not a capacity calculator or a substitute for its fresh native census.
pub(crate) fn capacity(a: &Admission, v: &Value) -> Result<()> {
    capacity_shape(a, v, super::now()?)?;
    for field in [
        "predecessor_capacity",
        "exclusive_handoff_receipt",
        "complete_fleet",
    ] {
        let binding: Bound = serde_json::from_value(v[field].clone())?;
        ensure!(
            binding.path.is_absolute() && digest(&binding.sha256, 64),
            "capacity evidence binding"
        );
        super::value(&binding)?;
    }
    Ok(())
}
pub(crate) fn capacity_shape(a: &Admission, v: &Value, clock: u64) -> Result<()> {
    let existing = v["existing_memory_promises_after_exclusive_handoff_bytes"]
        .as_u64()
        .context("existing memory")?;
    let total = existing.checked_add(MEMORY).context("memory sum")?;
    let now = v["recorded_unix_seconds"]
        .as_u64()
        .context("capacity clock")?;
    ensure!(
        v["schema"] == "horizon-epoch136-exclusive-capacity-v1"
            && v["writer"] == json!(a.writer)
            && v["writer_invocation_id"] == a.writer_invocation_id
            && v["candidate_unit"] == UNIT
            && v["candidate_run_root"] == ROOT
            && v["candidate_memory_max_bytes"] == MEMORY
            && v["candidate_data_bytes"] == DATA
            && v["candidate_cpu_quota_micros"] == CPU_MICROS
            && v["complete_host_ledger_checked"] == true
            && v["current_native_ownership_checked"] == true
            && v["no_overlapping_epoch136_controller"] == true
            && v["guard_512MiB_hard_limit_charged_in_complete_ledger"] == true
            && v["os_and_peer_floors_preserved"] == true
            && v["all_historical_attempts_and_retained_data_preserved"] == true
            && v["old_failed4_memory_retirement_reused_as_new_credit"] == false
            && v["old_failed4_new_memory_credit_bytes"] == 0
            && v["exclusive_handoff_accepted"] == true
            && v["exclusive_handoff_memory_bytes"]
                .as_u64()
                .is_some_and(|n| n >= MEMORY)
            && v["handoff_source_no_longer_launchable"] == true
            && v["handoff_source_physically_drained"] == true
            && v["total_memory_promises_including_floor_and_candidate_bytes"] == total
            && v["host_memory_bytes"].as_u64().is_some_and(|n| total <= n)
            && v["protected_existing_home_free_bytes"] == a.protected_existing_free_bytes
            && v["available_home_bytes"]
                .as_u64()
                .is_some_and(|n| n >= a.required_initial_free_bytes)
            && v["actual_home_backing_device_verified"] == true
            && v["candidate_reserved_once"] == true
            && now <= clock
            && clock - now <= 120
            && now < a.launch_expires_unix_seconds
            && now.saturating_add(120) >= a.recorded_unix_seconds,
        "current exclusive resource handoff is missing, stale or overcommitted"
    );
    Ok(())
}
pub(crate) fn validate_guard_scope(v: &Value, iid: &str, floor: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && v["unit"] == UNIT
            && v["invocation_id"] == iid
            && v["filesystem"] == FILESYSTEM
            && v["worker_root"] == ROOT
            && v["receipt_directory"] == format!("{ROOT}/receipts/guard")
            && v["minimum_free_bytes"] == floor
            && v["maximum_root_physical_bytes"] == ROOT_STOP
            && v["maximum_worker_vmas"] == VMA
            && v["bounded_canary"].is_null()
            && v["bounded_measurement"].is_null()
            && v["native_main"].is_null(),
        "guard scope differs"
    );
    Ok(())
}
pub(crate) fn native_duration_micros(raw: &str) -> Result<u64> {
    ensure!(
        !raw.trim().is_empty() && raw.len() <= 128,
        "native duration length"
    );
    let mut total = 0u64;
    for component in raw.split_whitespace() {
        let mut part = None;
        for (suffix, scale) in [
            ("us", 1u64),
            ("ms", 1000),
            ("s", 1_000_000),
            ("min", 60_000_000),
            ("h", 3_600_000_000),
            ("d", 86_400_000_000),
        ] {
            if let Some(n) = component.strip_suffix(suffix) {
                ensure!(
                    !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()),
                    "native duration syntax"
                );
                part = Some(
                    n.parse::<u64>()?
                        .checked_mul(scale)
                        .context("duration overflow")?,
                );
                break;
            }
        }
        total = total
            .checked_add(part.context("nonfinite/unknown duration")?)
            .context("duration sum")?;
    }
    Ok(total)
}
pub(crate) fn description() -> Value {
    json!({"schema":"horizon-epoch136-actual-payload-description-v1","unit":UNIT,"run_root":ROOT,
        "worker_sha256":WORKER_SHA,"snapshot_sha256":SNAPSHOT_SHA,"genesis_sha256":GENESIS_SHA,
        "bootstrap":BOOTSTRAP,"first":FIRST,"end":END,"slot_count":COUNT,"excluded_epoch_slots":55,
        "target":{"slot":FAILURE_SLOT,"entry":197,"transaction":113,"instruction":2,"signature":TARGET_SIGNATURE},
        "memory_max_bytes":MEMORY,"data_reservation_bytes":DATA,"root_stop_bytes":ROOT_STOP,
        "requires_new_exclusive_capacity_handoff":true,"requires_first_real_worker_guard_before_initialize":true,
        "launch_authorized":false,"publication_authorized":false,"resource_observation_performed":false})
}
