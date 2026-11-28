use native257::{process_ticks, publication};
mod first_guard {
    include!("../../native265-launch/src/first_guard.rs");
}
mod handoff {
    include!("native257/handoff.rs");
}
mod mount_proof {
    include!("native261/mount_proof.rs");
}
mod retire {
    include!("native257/retire.rs");
}
mod startup {
    include!("native257/startup.rs");
}
mod stop {
    include!("../../native265-launch/src/qualification.rs");
}
mod units {
    include!("native257/units.rs");
}
#[cfg(test)]
use mount_proof::sample_fixture;
use mount_proof::{check_devices, check_mount_sample};
const TOKEN_SCHEMA: &str = "horizon-native266-first-guard-token-v1";
const PLAN_SCHEMA: &str = "horizon-native266-startup-plan-v1";
const HANDOFF_SCHEMA: &str = "horizon-native266-guarded-startup-v1";
const ADMISSION_SCHEMA: &str = "horizon-native266-current-fleet-admission-v1";
const STOP_INTENT: &str = "horizon266-native-guard-stop-intent-v1";
const PREPARED_SCHEMA: &str = "horizon-native266-prepared-units-v1";
const PLAN_PREFIX: &str = "horizon-native266-startup-plan-";
const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH266_STARTUP_PLAN_SHA256";
const GUARD_SHA_ENV: &str = "HORIZON266_GUARD_PLAN_SHA256";
const PLAN_ENV: &str = "JETSTREAMER_EPOCH266_STARTUP_PLAN";

const EPOCH: u64 = 266;
const RETENTION_DESCRIPTION_EPOCH: u64 = EPOCH;
const SLOT: u64 = 114_910_768;
const SNAPSHOT_SHA: &str = "c3bfdbf63b7941a9c111a668bc03f71b197203eb52a45c9ea39e94797272babb";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const HARNESS: &str = INPUT;
const HARNESS_SHA: &str = INPUT_SHA;
const RESERVATION: u64 = DISK_RECEIPTS;
const SCRATCH: u64 = ROOT_CAP;
const EXPECTED_FILESYSTEM: &str = FILESYSTEM;
const STOP_CAPTURE: &str = "horizon-native266-protective-stop-capture-v1";

const STOP_ACCEPTED: &str = "horizon-native266-protective-stop-qualification-v1";

const STOP_RETIRED: &str = "horizon-native266-qualification-unit-retirement-v1";

const STOP_REQUEST: &str = "horizon266-native-guard-stop-request-v1";

include!("native261/controller.rs");

fn permits_predecessor(_: &Bound, _: &Bound, _: &Value) -> bool {
    false
}

#[cfg(test)]
mod predecessor_tests {
    use super::*;
    #[test]
    fn rejects_a_foreign_preparation_launcher() {
        let old = Bound::new("/unused", "a".repeat(64));
        assert!(!permits_predecessor(&old, &old, &json!("b".repeat(40))));
    }
}
