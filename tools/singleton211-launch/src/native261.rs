//! Device-aware fleet admission for the bounded epoch 261 bootstrap.
use super::*;
mod funding;
use native257::{process_ticks, publication};
mod first_guard {
    include!("../../native265-launch/src/first_guard.rs");
}
mod handoff {
    include!("native257/handoff.rs");
}
mod mount_proof;
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
    pub(super) const ROOT: &str = "/run/horizon261-native-cold-v1";
    pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
}
#[path = "../../horizon261-native-input/src/tmpfs.rs"]
mod tmpfs;
use profile::{FILESYSTEM, ROOT};

pub(super) const UNIT: &str = "horizon-261-native-input-20261120-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native261-protective-v1.service";
const TIMER: &str = "horizon-native261-protective-v1.timer";
pub(super) const MEMORY: u64 = 192_000_000_000;
const ROOT_CAP: u64 = 124 << 30;
pub(super) const DISK_RECEIPTS: u64 = 256 << 20;
const GUARD_MEMORY: u64 = 256 << 20;
pub(super) const CONTROLLER_MEMORY: u64 = 256 << 20;
const INPUT: &str =
    "/var/lib/jetstreamer/horizon261-native-input-tmpfs-20261120-v1/horizon261-native-input";
const INPUT_SHA: &str = "b657cbaa98f543bb40fd9d01786ae0747ef30f4d2ed4727d81469461ea02d899";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon261-native-guard-tmpfs-20261120-v1/horizon261-native-guard";
const GUARD_SHA: &str = "b11fc491490a797ae874d4406e68dd01bdcd5486b486a8b44e3635e66fce8f51";
const PACKET: &str =
    "/var/lib/jetstreamer/horizon261-bootstrap-measure-3cbb2796-v137-v1/inputs.json";
const PACKET_SHA: &str = "9d36d766ab81ac0f831dc1af81198bef3f67ec7ad47f05d1541629d0916bf385";
const WORKER: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15";
const WORKER_SHA: &str = "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4";
const LAUNCHER: &str =
    "/var/lib/jetstreamer/horizon261-native-launch-tmpfs-20261120-v4/horizon-native261-launch";

const TOKEN_SCHEMA: &str = "horizon-native261-first-guard-token-v1";
const PLAN_SCHEMA: &str = "horizon-native261-startup-plan-v1";
const HANDOFF_SCHEMA: &str = "horizon-native261-guarded-startup-v1";
const ADMISSION_SCHEMA: &str = "horizon-native261-current-fleet-admission-v1";
const STOP_INTENT: &str = "horizon261-native-guard-stop-intent-v1";
const PREPARED_SCHEMA: &str = "horizon-native261-prepared-units-v1";
const PLAN_PREFIX: &str = "horizon-native261-startup-plan-";
const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH261_STARTUP_PLAN_SHA256";
const GUARD_SHA_ENV: &str = "HORIZON261_GUARD_PLAN_SHA256";
const PLAN_ENV: &str = "JETSTREAMER_EPOCH261_STARTUP_PLAN";

const EPOCH: u64 = 261;
const RETENTION_DESCRIPTION_EPOCH: u64 = EPOCH;
const RETENTION: &str = "horizon-native261-terminal-retention.target";
const TOKENS: &str = "/var/lib/jetstreamer/horizon-native261-startup-tokens";
const SLOT: u64 = 112_751_208;
const SNAPSHOT_SHA: &str = "5e84f74696d1f3100650e134fb91487d3e083c374a3262b05f67378b9b1c8256";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const HARNESS: &str = INPUT;
const HARNESS_SHA: &str = INPUT_SHA;
const RESERVATION: u64 = DISK_RECEIPTS;
const SCRATCH: u64 = ROOT_CAP;
const EXPECTED_FILESYSTEM: &str = FILESYSTEM;
const PRODUCER_SANDBOX: &str = "WorkingDirectory=/run/horizon261-native-cold-v1\nInaccessiblePaths=/tmp /var/tmp /dev/shm\nPrivateDevices=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX\nOOMPolicy=kill\nOOMScoreAdjust=1000\nAmbientCapabilities=\n";
const STOP_CAPTURE: &str = "horizon-native261-protective-stop-capture-v1";

const STOP_ACCEPTED: &str = "horizon-native261-protective-stop-qualification-v1";

const STOP_RETIRED: &str = "horizon-native261-qualification-unit-retirement-v1";

const STOP_REQUEST: &str = "horizon261-native-guard-stop-request-v1";

include!("native261/controller.rs");
