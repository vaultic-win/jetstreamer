//! Device-aware fleet admission for the bounded epoch 212 bootstrap.
use super::*;
pub(crate) mod retired265;
mod funding {
    include!("native261/funding.rs");
}
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
mod profile {
    pub(super) const ROOT: &str = "/run/horizon212-native-cold-v1";
    pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
}
#[path = "../../horizon212-native-input/src/tmpfs.rs"]
mod tmpfs;
use profile::{FILESYSTEM, ROOT};

pub(super) const UNIT: &str = "horizon-212-native-input-20261120-v1.service";
const GUARD_UNIT: &str = "horizon-native212-protective-v1.service";
const TIMER: &str = "horizon-native212-protective-v1.timer";
const MEMORY: u64 = 111_669_149_696;
const ROOT_CAP: u64 = 44 << 30;
const DISK_RECEIPTS: u64 = 256 << 20;
const GUARD_MEMORY: u64 = 256 << 20;
const CONTROLLER_MEMORY: u64 = 256 << 20;
const INPUT: &str =
    "/var/lib/jetstreamer/horizon212-native-input-tmpfs-20261120-v1/horizon212-native-input";
const INPUT_SHA: &str = "73f93411831428c4f6cce9c625b817fb12a9746ca4901312ea0d8d820fc6ae9b";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon212-native-guard-tmpfs-20261120-v1/horizon212-native-guard";
const GUARD_SHA: &str = "cd1ef010b27734e7b7ccb0d594289b7d8ca88a2d7ca49ae84f6a6a2841093eee";
const PACKET: &str =
    "/var/lib/jetstreamer/horizon212-bootstrap-measure-efef7615-v142-v1/inputs.json";
const PACKET_SHA: &str = "6c69e2da820cc696ad67c0866e504f8666075aefcacad3148980776f57967945";
const WORKER: &str = "/var/lib/jetstreamer/horizon-singleton211-production-worker-1c89b6a214f9487b-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget";
const WORKER_SHA: &str = "1c89b6a214f9487babfd9dc121ade06037b371fbfcc3243f0e6ec67b6b961c41";
const LAUNCHER: &str =
    "/var/lib/jetstreamer/horizon212-native-launch-tmpfs-20261120-v5/horizon-native212-launch";

const TOKEN_SCHEMA: &str = "horizon-native212-first-guard-token-v1";
const PLAN_SCHEMA: &str = "horizon-native212-startup-plan-v1";
const HANDOFF_SCHEMA: &str = "horizon-native212-guarded-startup-v1";
const ADMISSION_SCHEMA: &str = "horizon-native212-current-fleet-admission-v1";
const STOP_INTENT: &str = "horizon212-native-guard-stop-intent-v1";
const PREPARED_SCHEMA: &str = "horizon-native212-prepared-units-v1";
const PLAN_PREFIX: &str = "horizon-native212-startup-plan-";
const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH212_STARTUP_PLAN_SHA256";
const GUARD_SHA_ENV: &str = "HORIZON212_GUARD_PLAN_SHA256";
const PLAN_ENV: &str = "JETSTREAMER_EPOCH212_STARTUP_PLAN";

const EPOCH: u64 = 212;
const RETENTION_DESCRIPTION_EPOCH: u64 = EPOCH;
const RETENTION: &str = "horizon-native212-terminal-retention.target";
const TOKENS: &str = "/var/lib/jetstreamer/horizon-native212-startup-tokens";
const SLOT: u64 = 91_583_512;
const SNAPSHOT_SHA: &str = "94d7ed8cf39d2b2d665d2c720a3381afb7555d3b3201b7c4d68d6cb0bcbb8a96";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const HARNESS: &str = INPUT;
const HARNESS_SHA: &str = INPUT_SHA;
const RESERVATION: u64 = DISK_RECEIPTS;
const SCRATCH: u64 = ROOT_CAP;
const EXPECTED_FILESYSTEM: &str = FILESYSTEM;
const PRODUCER_SANDBOX: &str = "WorkingDirectory=/run/horizon212-native-cold-v1\nInaccessiblePaths=/tmp /var/tmp /dev/shm\nPrivateDevices=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX\nOOMPolicy=kill\nOOMScoreAdjust=1000\nAmbientCapabilities=\nStandardOutput=journal\nStandardError=journal\nLogRateLimitIntervalSec=30s\nLogRateLimitBurst=100\n";
const STOP_CAPTURE: &str = "horizon-native212-protective-stop-capture-v1";

const STOP_ACCEPTED: &str = "horizon-native212-protective-stop-qualification-v1";

const STOP_RETIRED: &str = "horizon-native212-qualification-unit-retirement-v1";

const STOP_REQUEST: &str = "horizon212-native-guard-stop-request-v1";

const PRIOR_PREPARATION: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-native212-prepared-host-stop-febf1909-v1/prepared.json",
    "b4a3e24ffabf317e3518a49738f6efd7e501ecc2385161a42a6fd969a42e5b1a",
);
const PRIOR_LAUNCHER: (&str, &str) = (
    "/var/lib/jetstreamer/horizon212-native-launch-tmpfs-20261120-v1/horizon-native212-launch",
    "0db9ebf07a920f7f1bae2f6a33e037e0f80976f3caebc21ace6c8fbfa877adb7",
);
const PRIOR_LAUNCHER_COMMIT: &str = "febf1909551c7dc9a14961404dfafa186a592fd8";

fn permits_predecessor(reference: &Bound, gate: &Bound, source: &Value) -> bool {
    reference == &Bound::new(PRIOR_PREPARATION.0, PRIOR_PREPARATION.1)
        && gate == &Bound::new(PRIOR_LAUNCHER.0, PRIOR_LAUNCHER.1)
        && *source == PRIOR_LAUNCHER_COMMIT
}

include!("native261/controller.rs");

include!("native261/preparation_tests.rs");
