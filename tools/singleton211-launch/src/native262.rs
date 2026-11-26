//! Invocation-bound cold restore for the sealed epoch 262 bootstrap.
use super::*;
pub mod foundation_roster;
mod funding;
mod peer_window;
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
    pub(super) const ROOT: &str = "/run/horizon262-native-cold-v1";
    pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
}
#[path = "../../horizon262-native-input/src/tmpfs.rs"]
mod tmpfs;
use profile::{FILESYSTEM, ROOT};

pub(super) const UNIT: &str = "horizon-262-native-input-20261126-v1.service";
const GUARD_UNIT: &str = "horizon-native262-protective-v1.service";
const TIMER: &str = "horizon-native262-protective-v1.timer";
const RETENTION: &str = "horizon-native262-terminal-retention.target";
const MEMORY: u64 = 192_000_000_000;
const ROOT_CAP: u64 = 124 << 30;
const DISK_RECEIPTS: u64 = 256 << 20;
const GUARD_MEMORY: u64 = 256 << 20;
const CONTROLLER_MEMORY: u64 = 256 << 20;
const INPUT: &str =
    "/var/lib/jetstreamer/horizon262-native-input-tmpfs-20261126-v1/horizon262-native-input";
const INPUT_SHA: &str = "6b14b1ec1a5a5db6b3fb4d216cb75d882366a77ef7bd913ce1926eda97939a72";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon262-native-guard-20261126-v1/horizon262-native-guard";
const GUARD_SHA: &str = "7a07bd136f3b4efae96d8642aa4ac21fe923ffe1db94aa291c11c524a770fc31";
const PACKET: &str = "/var/lib/jetstreamer/horizon262-native-input-tmpfs-20261126-v1/inputs.json";
const PACKET_SHA: &str = "08bb1abfc6da49a6917784d23a1f9f983f91c22bcc8ed686ee048ef8a7e56b7d";
const WORKER: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15";
const WORKER_SHA: &str = "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4";
const LAUNCHER: &str = "/var/lib/jetstreamer/horizon262-native-launch-v2/horizon-native262-launch";

const EPOCH: u64 = 262;
const RETENTION_DESCRIPTION_EPOCH: u64 = EPOCH;
const TOKENS: &str = "/var/lib/jetstreamer/horizon-native262-startup-tokens";
const TOKEN_SCHEMA: &str = "horizon-native262-first-guard-token-v1";
const PLAN_SCHEMA: &str = "horizon-native262-startup-plan-v1";
const HANDOFF_SCHEMA: &str = "horizon-native262-guarded-startup-v1";
const ADMISSION_SCHEMA: &str = "horizon-native262-current-fleet-admission-v1";
const PREPARED_SCHEMA: &str = "horizon-native262-prepared-units-v1";
const PLAN_PREFIX: &str = "horizon-native262-startup-plan-";
const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH262_STARTUP_PLAN_SHA256";
const PLAN_ENV: &str = "JETSTREAMER_EPOCH262_STARTUP_PLAN";
const GUARD_SHA_ENV: &str = "HORIZON262_GUARD_PLAN_SHA256";
const STOP_CAPTURE: &str = "horizon-native262-protective-stop-capture-v1";
const STOP_ACCEPTED: &str = "horizon-native262-protective-stop-qualification-v1";
const STOP_RETIRED: &str = "horizon-native262-qualification-unit-retirement-v1";
const STOP_INTENT: &str = "horizon262-native-guard-stop-intent-v1";
const STOP_REQUEST: &str = "horizon262-native-guard-stop-request-v1";

const SLOT: u64 = 113_182_967;
const SNAPSHOT_SHA: &str = "2f54e3ca459503fd903e037e1d3f073e672f870a6525633c1629147f7bb584b2";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const HARNESS: &str = INPUT;
const HARNESS_SHA: &str = INPUT_SHA;
const RESERVATION: u64 = DISK_RECEIPTS;
const SCRATCH: u64 = ROOT_CAP;
const EXPECTED_FILESYSTEM: &str = FILESYSTEM;
const PRODUCER_SANDBOX: &str = "WorkingDirectory=/run/horizon262-native-cold-v1\nInaccessiblePaths=/tmp /var/tmp /dev/shm\nPrivateDevices=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX\nOOMPolicy=kill\nOOMScoreAdjust=1000\nAmbientCapabilities=\nStandardOutput=journal\nStandardError=journal\nLogRateLimitIntervalSec=30s\nLogRateLimitBurst=100\n";

fn permits_predecessor(reference: &Bound, launcher: &Bound, source: &Value) -> bool {
    *reference == Bound::new(
        "/var/lib/jetstreamer/horizon-native262-prepared-cold-v1/prepared.json",
        "c6bcf30316ffa9f83acf8b4c383579fc4b2dd052ad3c0d0678b072c39df20094",
    ) && *launcher == Bound::new(
        "/var/lib/jetstreamer/horizon262-native-launch-v1/horizon-native262-launch",
        "91dba2d3940a854a5058347d703b318cf8b00bc8a742790416f42af1e67fceb2",
    ) && source == "04f98e96a96e3dbdbc27c82659090324042ae8ae"
}

include!("native261/controller.rs");
