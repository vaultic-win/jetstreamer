use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf};
pub const GIB: u64 = 1 << 30;
pub const PARENT: u64 = 192 * GIB;
pub const RESIDUAL: u64 = GIB;
pub const RAW_MEMORY: u64 = PARENT + RESIDUAL;
pub const DATA: u64 = 768 * GIB;
pub const PRODUCER: &str =
    "jetstreamer-root-sweep-e199-backfill-20261102-v1-e199-200-lane-a-1.service";
pub const CONTROLLER: &str = "jetstreamer-epoch199-backfill-20261102-controller-v1-r2.service";
pub const CONTROLLER_IID: &str = "dbf49bb1b72c42c584f2d3ac94259cb8";
pub const PRODUCER_IID: &str = "2a1c51f557a64cd1ad691281cbb77c94";
pub const CONTROLLER_PID: u64 = 2_467_123;
pub const SCRIPT: &str = "/usr/local/lib/jetstreamer/horizon-epoch199-backfill-controller-guard-20261102-v1/adaptive-root-cohort-sweep.py";
pub const SCRIPT_SHA: &str = "62592209a3fc2b659ea4bfb924bbcf34435b4228c87e56232eb6b962b907023e";
pub const STATE: &str = "/var/lib/jetstreamer-root-sweep-epoch199-backfill-20261102-v1/state.json";
pub const STATE_SHA: &str = "051642bf5ff3f1fffb5e7d8b2133ff399a0a0f1947fef50c74976b12858da152";
pub const REGISTRY: &str =
    "/usr/local/lib/jetstreamer/horizon-original199-terminal-context-20261104-v2/registry.json";
pub const REGISTRY_SHA: &str = "733487fcb07438d603999234b0a0598d62261ba0c1cb0ba6003693260ebc1389";
pub const GUARD: &str = "jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.service";
pub const TIMER: &str = "jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.timer";
pub const GUARD_SCRIPT: &str = "/usr/local/lib/jetstreamer/horizon-epoch199-backfill-controller-guard-20261102-v1/guard_adaptive_replay_reserve.py";
pub const GUARD_SHA: &str = "b62e58f5be764935a679408e1fcc446a9768170109a6639c87fd01571b9f2b62";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Current {
    pub observer: Bound,
    pub fleet: Bound,
    pub fleet_plan: Bound,
    pub frame: Bound,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub program: Bound,
    pub qualification: Option<Bound>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub enabled: bool,
    pub terminal_context: Bound,
    pub controller_source: Bound,
    pub controller_executable: Bound,
    pub controller_argv: Vec<String>,
    pub controller_start_ticks: u64,
    pub quarantined_state: Bound,
    pub guard_source: Bound,
    pub census: Artifact,
    /// Exact closed relevant scope, including every native alias/future launcher.
    pub native_units: Vec<String>,
    /// Qualified review binds the scope to exhaustive source and process discovery.
    pub census_scope_review: Bound,
    pub raw_memory_bytes: u64,
    pub selected_parent_bytes: u64,
    pub residual_controller_guard_bytes: u64,
    #[serde(rename = "DATA_bytes")]
    pub data_bytes: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub current: Current,
    pub registration: Bound,
    pub registration_seal: Bound,
    pub current_reader: Bound,
    pub reader_program: Artifact,
    pub current_reader_acceptance: Bound,
    pub census: Bound,
    pub baseline: Baseline,
    /// Absence preserves the existing exact selection bytes and every145 promise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_cached145: Option<crate::cached145::Request>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Baseline {
    Captured141Only {
        captured141: Bound,
    },
    Captured141AndFailed4 {
        captured141: Bound,
        combined: Bound,
        combined_command_proof: Bound,
        combined_command_acceptance: Bound,
        combined_program: Box<Artifact>,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    pub pid: u64,
    pub start_ticks: u64,
    pub unit: String,
    pub invocation_id: String,
    pub executable: Bound,
    pub argv: Vec<String>,
    pub command_source: Bound,
    pub cwd: PathBuf,
    pub cgroup: String,
    pub descriptor_refs: Vec<String>,
    pub mmap_refs: Vec<String>,
    pub role: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub native: BTreeMap<String, Value>,
    pub matching_processes: Vec<Process>,
    pub scanned_process_count: u64,
    pub scanned_dimensions: Vec<String>,
    pub unresolved_processes: Vec<Value>,
    pub unreadable_processes: Vec<Value>,
    pub original_worker_cgroup: String,
    pub original_worker_cgroup_members: Vec<u64>,
    pub original_worker_descriptor_holders: Vec<Value>,
    pub original_worker_mmap_holders: Vec<Value>,
    pub controller_state: Bound,
    /// Complete relevant source/launcher findings, not just live unit names.
    pub launcher_findings: Vec<LauncherFinding>,
    pub unresolved_launchers: Vec<Value>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherFinding {
    pub unit: String,
    pub disposition: String,
    pub source: Bound,
    pub qualification: Bound,
    pub current_invocation_id: Option<String>,
    pub may_start_original_parent: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Census {
    pub schema: String,
    pub current: Current,
    pub program: Bound,
    pub scope_review: Bound,
    pub recorded_unix_seconds: u64,
    pub before: Endpoint,
    pub after: Endpoint,
    pub complete_native_unit_universe: Vec<String>,
    pub complete_source_roots: Vec<PathBuf>,
    pub source_listing_before: Bound,
    pub source_listing_after: Bound,
    pub controller_source: Bound,
    pub guard_source: Bound,
    pub source_custody_unchanged: bool,
    pub mutation_count: u64,
}

pub const CONTROLLER_ARGV_SHA: &str =
    "0794dc630a72ab66e860703280cbe1e5d9d95c17dc8f61614d88708d7349c8de";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSpec {
    pub schema: String,
    pub policy: Policy,
    pub current: Current,
    pub current_reader: Bound,
    pub reader_program: Artifact,
    pub current_reader_acceptance: Bound,
    pub output_directory: PathBuf,
}

pub const CONTROLLER_RENDERED_COMMAND_SHA: &str =
    "646c41b81b1a70e19de864248b0cb60576f9b2434ceee12d584339c4d9491501";
