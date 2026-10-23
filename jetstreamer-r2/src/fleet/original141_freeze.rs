//! Closed freeze-component diagnostic; stops in the worker at60912004.
const PACKAGE: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-freeze-parent-20261023-v1";
const WORKER_SHA: &str = "e5600e93710cda7bb2b8cf691c2e6707d307e7957b7023f0551d744b6e240605";
const WORKER_ENTRY_TERMINAL: Option<u64> = Some(60912004);
pub(super) const SCHEMA: &str =
    "jetstreamer-private-epoch141-original-entry-freeze-components-launch-v2";
pub(super) const UNIT: &str =
    "horizon-qualify-141-original-entry-freeze-components-20261023-v1.service";
const ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch141-original-entry-freeze-components-20261023-v1";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-freeze-components-plan-20261023-v1/plan.json";
const ADMISSION: &str = "/var/lib/jetstreamer/horizon-original141-freeze-components-admission-20261023-v1/admission.json";
pub(super) const GUARD_SHA: &str =
    "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
const GUARD_UNIT: &str = "horizon-original141-freeze-components-guard-20261023-v1.service";
const GUARD_ROOT: &str =
    "/var/lib/jetstreamer/horizon-original141-freeze-components-guard-20261023-v1";
const GUARD_BIN: &str = "/usr/local/lib/jetstreamer/horizon-original141-trace-guard-20261023-v1/jetstreamer-horizon-standalone-guard";
const PEAK: u64 = 256 << 30;
const MAX_RUNTIME: u64 = 1800;
const RUNTIME_DISPLAY: &str = "30min";
const TRACE: bool = true;
const CAPPED_SHRINK: bool = false;
const CPU_CORES: u64 = 2;
const MIN_MEMORY: u64 = 128 << 30;
const SAMPLE_MEMORY_KIB: u64 = 192 * 1024 * 1024;
include!("original141_core.rs");
