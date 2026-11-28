//! Exact private epoch145 scans. No checksum, import, publication or R2 authority.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

pub const GIB: u64 = 1 << 30;
pub const SOURCE: &str =
    "/home/sol/.jetstreamer-private/epoch145-prefix-extract-real1328-20261106-v1/epoch-145.jet";
pub const ORIGINAL_SOURCE: &str = "/home/sol/.jetstreamer-private/epoch145-cached-b2a09f57de39c384/work/diagnostic/epoch-145-through-63072070.jet";
pub const SOURCE_SHA: &str = "cb8ac0bc47919c22dc7898e068fb43ffac80aceadcacac3ff8f24ef32d3b3353";
pub const MANIFEST_SHA: &str = "a101b885c5d60a13b8567d3968acd0e5177ec4f04669b91333cb9b3c5ca4b96a";
pub const WITNESS: &str = "/home/sol/.jetstreamer-private/cached145-postreplay-handoff-20261105-v1/ROOT_ACTUAL145_CLEAN_TERMINAL_AND_VERIFIED_SEGMENT.json";
pub const WITNESS_SHA: &str = "8fe99753332d62254da147dcf1324bf4834a78d595d55c853228ce3fb469cd9d";
pub const ORIGINAL_UNIT: &str = "horizon-qualify-145-cached-b2a09f57de39c384.service";
pub const ORIGINAL_IID: &str = "15ddd220e2144aaa8d7418f73f60768f";
pub const EXPORT_UNIT: &str = "horizon-extract145-prefix-real1328-20261106-v1.service";
pub const EXPORT_IID: &str = "914b442c5f61432f8ba3243eb7c0f20d";
pub const EXPORT_PROGRAM_SHA: &str =
    "a6461b6ce945d51874c4ad0adf189dc93b2a188a07f50c5d067784702d257c50";
pub const EXPORT_PLAN_SHA: &str =
    "0c47a737ef3a3086ffe2e8042ba9a989175c1547eb1ab0680f121628b431d6e9";
pub const FULL_SHA: &str = "41c03e493daa309ab7cffd9760b4e6cfe2195b3af0bb13a17f19508eb929d6e7";
pub const PLUGIN_SHA: &str = "73e7535b9cedc7e565a92735ca6e07c7efb8e66755a6d5272ed16649b4d8cee9";
pub const INCOMING: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-independent-boundary-metadata-20261106-v1/incoming-62639999-source.json";
pub const INCOMING_SHA: &str = "5fd04d4f501d77f9866b469f33e3ac729d44187979e6937e9856e880de401ede";
pub const TERMINAL: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-independent-boundary-metadata-20261106-v1/terminal-63071999-response.json";
pub const TERMINAL_SHA: &str = "0c0adba08c80831f2cfcbf98ba6a0ad5e4d0cc537f7570c2c0414dce755860c7";
pub const GUARD_MAX_AGE_MILLIS: u64 = 90_000;
pub const MAX_METADATA_BYTES: u64 = 128 << 20;
pub const MIN_DATA_FLOOR: u64 = 4_856_730_676_176;
pub const MIN_UNCOVERED_MEMORY_BYTES: u64 = 1_612_808_192;

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
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Full,
    Plugin,
}
impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Plugin => "plugin",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: String,
    pub generation: String,
    pub stage: Stage,
    pub program: Bound,
    pub program_seal: Bound,
    pub admission_bridge: Bound,
    pub admission_bridge_seal: Bound,
    pub terminal: Bound,
    /// The immutable canonical-width output, never the 432071-slot source.
    pub source: Bound,
    pub source_identity: Identity,
    /// Frozen genuine exporter completion after original completion and drain.
    pub manifest: Bound,
    pub manifest_identity: Identity,
    pub export_plan: Bound,
    pub export_admission: Bound,
    pub export_first_guard: Bound,
    pub export_original_completion: Bound,
    pub incoming: Bound,
    pub terminal_boundary: Bound,
    pub verifier: Bound,
    pub verifier_seal: Bound,
    pub memory_request: Bound,
    pub data_policy: Bound,
    pub data_policy_seal: Bound,
    pub actor_unit: String,
    pub guard_unit: String,
    pub timer_unit: String,
    /// Read-only canonical archive parent; no output writes are allowed here.
    pub output_root: PathBuf,
    pub output_directory_identity: DirectoryIdentity,
    pub state_root: PathBuf,
    pub state_directory_identity: DirectoryIdentity,
    pub actor_memory_bytes: u64,
    pub guard_memory_bytes: u64,
    pub external_pool_bytes: u64,
    pub actor_cpu_quota_micros: u64,
    pub guard_cpu_quota_micros: u64,
    pub tasks_max: u64,
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
