//! Distinct bounded trace repair; preserves the failed original root.
const PACKAGE: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-original-parent-20261023-v1";
const WORKER_SHA: &str = "abe395d482174e490833928c7343a33d135d8572096faf873ce3103c35fe520d";
const WORKER_ENTRY_TERMINAL: Option<u64> = None;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch141-original-entry-trace-launch-v2";
pub(super) const UNIT: &str = "horizon-qualify-141-original-entry-trace-20261023-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-original-entry-trace-20261023-v1";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-trace-plan-20261023-v1/plan.json";
const ADMISSION: &str =
    "/var/lib/jetstreamer/horizon-original141-trace-admission-20261023-v1/admission.json";
pub(super) const GUARD_SHA: &str =
    "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
const GUARD_UNIT: &str = "horizon-original141-trace-guard-20261023-v1.service";
const GUARD_ROOT: &str = "/var/lib/jetstreamer/horizon-original141-trace-guard-20261023-v1";
const GUARD_BIN: &str = "/usr/local/lib/jetstreamer/horizon-original141-trace-guard-20261023-v1/jetstreamer-horizon-standalone-guard";
// Whole private root, including scratch and output; experimental stop only.
const PEAK: u64 = 256 << 30;
const MAX_RUNTIME: u64 = 1800;
const RUNTIME_DISPLAY: &str = "30min";
const TRACE: bool = true;
const CAPPED_SHRINK: bool = false;
const CPU_CORES: u64 = 2;
const MIN_MEMORY: u64 = 128 << 30;
const SAMPLE_MEMORY_KIB: u64 = 192 * 1024 * 1024;
include!("original141_core.rs");
