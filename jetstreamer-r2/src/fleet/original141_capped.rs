//! Corrected v1.4.25 capped worker, private canonical-root qualification only.
const PACKAGE: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-capped-parent-20261023-v1";
const WORKER_SHA: &str = "fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759";
const WORKER_ENTRY_TERMINAL: Option<u64> = None;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch141-original-entry-capped-root-launch-v2";
pub(super) const UNIT: &str = "horizon-qualify-141-original-entry-capped-root-20261023-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-original-entry-capped-root-20261023-v1";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-capped-root-plan-20261023-v1/plan.json";
const ADMISSION: &str =
    "/var/lib/jetstreamer/horizon-original141-capped-root-admission-20261023-v1/admission.json";
pub(super) const GUARD_SHA: &str =
    "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
const GUARD_UNIT: &str = "horizon-original141-capped-root-guard-20261023-v1.service";
const GUARD_ROOT: &str = "/var/lib/jetstreamer/horizon-original141-capped-root-guard-20261023-v1";
const GUARD_BIN: &str = "/usr/local/lib/jetstreamer/horizon-original141-trace-guard-20261023-v1/jetstreamer-horizon-standalone-guard";
// Whole-root experimental stop, including scratch, indices and private output.
// Neither a qualified full-cold peak nor the200–300 century planning seed.
const PEAK: u64 = 512 << 30;
const MAX_RUNTIME: u64 = 432000;
const RUNTIME_DISPLAY: &str = "5d";
const TRACE: bool = true;
const CAPPED_SHRINK: bool = true;
const CPU_CORES: u64 = 8;
const MIN_MEMORY: u64 = 128 << 30;
const SAMPLE_MEMORY_KIB: u64 = 192 * 1024 * 1024;
include!("original141_core.rs");

#[cfg(test)]
mod capped_scope_tests {
    use super::*;
    #[test]
    fn cannot_borrow_the_vote_stop_or_claim_a_qualified_full_cold_budget() {
        let mut value = json!({});
        trace_fields(&mut value);
        for key in DENIED {
            value[*key] = json!(false);
        }
        denied(&value).unwrap();
        for (key, v) in [
            ("worker_entry_terminal_slot", json!(60912005)),
            ("worker_freeze_component_diagnostic", json!(true)),
            ("full_cold_epoch_peak_qualified", json!(true)),
            ("century_200_300_planning_assumption_applied", json!(true)),
        ] {
            let mut bad = value.clone();
            bad[key] = v;
            assert!(denied(&bad).is_err(), "{key}");
        }
    }
}
