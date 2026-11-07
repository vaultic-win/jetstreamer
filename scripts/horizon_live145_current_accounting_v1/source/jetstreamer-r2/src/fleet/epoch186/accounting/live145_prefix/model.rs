//! Exact operational plan, without caller-supplied admission booleans.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

pub const GIB: u64 = 1 << 30;
pub const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch145-cached-b2a09f57de39c384/work/diagnostic/epoch-145-through-63072070.jet";
pub const MANIFEST: &str = "/home/sol/.jetstreamer-private/epoch145-cached-b2a09f57de39c384/work/diagnostic/epoch-145-through-63072070.jet.segment.json";
pub const SOURCE_SHA: &str = "cb8ac0bc47919c22dc7898e068fb43ffac80aceadcacac3ff8f24ef32d3b3353";
pub const MANIFEST_SHA: &str = "a101b885c5d60a13b8567d3968acd0e5177ec4f04669b91333cb9b3c5ca4b96a";
pub const WITNESS: &str = "/home/sol/.jetstreamer-private/cached145-postreplay-handoff-20261105-v1/ROOT_ACTUAL145_CLEAN_TERMINAL_AND_VERIFIED_SEGMENT.json";
pub const WITNESS_SHA: &str = "8fe99753332d62254da147dcf1324bf4834a78d595d55c853228ce3fb469cd9d";
pub const ORIGINAL_UNIT: &str = "horizon-qualify-145-cached-b2a09f57de39c384.service";
pub const ORIGINAL_IID: &str = "15ddd220e2144aaa8d7418f73f60768f";
pub const SOURCE_BYTES: u64 = 105_633_748_687;
pub const GUARD_MAX_AGE_MILLIS: u64 = 90_000;
pub const MAX_METADATA_BYTES: u64 = 128 << 20;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: String,
    pub generation: String,
    pub program: Bound,
    /// Normal sealer receipt for the executable. Never an execution permit.
    pub program_seal: Bound,
    /// Separately sealed Rust process owns the reviewed typed-selector graph.
    pub admission_bridge: Bound,
    pub admission_bridge_seal: Bound,
    pub terminal: Bound,
    pub source: Bound,
    pub source_identity: Identity,
    pub manifest: Bound,
    pub manifest_identity: Identity,
    /// Genuine reviewed Request for the existing opaque parent-memory constructor.
    pub memory_request: Bound,
    /// Genuine current explicit DATA policy and its normal seal, consumed by the
    /// existing opaque DATA constructor, not hand-written selected totals.
    pub data_policy: Bound,
    pub data_policy_seal: Bound,
    pub actor_unit: String,
    pub guard_unit: String,
    pub timer_unit: String,
    pub output_root: PathBuf,
    pub output_directory_identity: DirectoryIdentity,
    pub state_root: PathBuf,
    pub state_directory_identity: DirectoryIdentity,
    pub output_maximum_bytes: u64,
    pub actor_memory_bytes: u64,
    pub guard_memory_bytes: u64,
    pub external_pool_bytes: u64,
    pub actor_cpu_quota_micros: u64,
    pub guard_cpu_quota_micros: u64,
    pub tasks_max: u64,
    /// Existing ceiling, never a policy lowering another owner's guard.
    pub minimum_available_memory_bytes: u64,
    pub minimum_free_bytes: u64,
    pub issued_at: u64,
    pub entry_deadline: u64,
    pub execution_deadline: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub schema: String,
    pub plan: Bound,
    pub actor_unit: String,
    pub actor_iid: String,
    pub actor_pid: u32,
    pub actor_start_ticks: u64,
    pub accepted_at: u64,
    pub accepted_boottime_millis: u64,
    pub memory_evidence: Value,
    pub data_evidence: Value,
    pub existing_memory_bytes: u64,
    pub protected_existing_data_bytes: u64,
    pub required_initial_memory_bytes: u64,
    pub required_initial_data_bytes: u64,
    pub original_native: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub schema: String,
    pub plan: Bound,
    pub admission: Bound,
    pub actor_iid: String,
    pub actor_pid: u32,
    pub actor_start_ticks: u64,
    pub guard_iid: String,
    pub guard_pid: u32,
    pub guard_start_ticks: u64,
    pub at_unix_seconds: u64,
    pub at_boottime_millis: u64,
    pub protected_free_bytes: u64,
    pub protected_available_memory_bytes: u64,
    pub actual_free_bytes: u64,
    pub actual_available_memory_bytes: u64,
}
