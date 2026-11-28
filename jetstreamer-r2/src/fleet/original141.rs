//! Original immutable profile, retained for existing receipts.
const PACKAGE: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-original-parent-20261023-v1";
const WORKER_SHA: &str = "abe395d482174e490833928c7343a33d135d8572096faf873ce3103c35fe520d";
const WORKER_ENTRY_TERMINAL: Option<u64> = None;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch141-original-entry-root-launch-v2";
pub(super) const UNIT: &str = "horizon-qualify-141-original-entry-root-20261023-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-original-entry-root-20261023-v1";
const PLAN: &str = "/usr/local/lib/jetstreamer/horizon-original141-root-plan-20261023-v2/plan.json";
const ADMISSION: &str =
    "/var/lib/jetstreamer/horizon-original141-admission-20261023-v1/admission.json";
pub(super) const GUARD_SHA: &str =
    "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194";
const GUARD_UNIT: &str = "horizon-original141-root-guard-20261023-v1.service";
const GUARD_ROOT: &str = "/var/lib/jetstreamer/horizon-original141-root-guard-20261023-v1";
const GUARD_BIN: &str = "/usr/local/lib/jetstreamer/horizon-standalone-guard-target-handoff-20261019-v2/jetstreamer-horizon-standalone-guard";
const PEAK: u64 = 768 << 30;
const MAX_RUNTIME: u64 = 604800;
const RUNTIME_DISPLAY: &str = "1w";
const TRACE: bool = false;
const CAPPED_SHRINK: bool = false;
const CPU_CORES: u64 = 2;
const MIN_MEMORY: u64 = 192 << 30;
const SAMPLE_MEMORY_KIB: u64 = 256 * 1024 * 1024;
include!("original141_core.rs");
