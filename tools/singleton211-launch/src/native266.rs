//! Device-aware fleet admission for the bounded epoch 266 bootstrap.
use super::*;
#[path = "native266_observer_gap.rs"]
mod observer_gap;
pub use observer_gap::validate_v164_observer_predecessor;
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
    pub(super) const ROOT: &str = "/run/horizon266-native-cold-v1";
    pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
}
#[path = "../../horizon266-native-input/src/tmpfs.rs"]
mod tmpfs;
use profile::{FILESYSTEM, ROOT};

pub(super) const UNIT: &str = "horizon-266-native-input-20261121-v1.service";
const GUARD_UNIT: &str = "horizon-native266-protective-v1.service";
const TIMER: &str = "horizon-native266-protective-v1.timer";
const MEMORY: u64 = 192_000_000_000;
const ROOT_CAP: u64 = 124 << 30;
const DISK_RECEIPTS: u64 = 256 << 20;
const GUARD_MEMORY: u64 = 256 << 20;
const CONTROLLER_MEMORY: u64 = 256 << 20;
const INPUT: &str =
    "/var/lib/jetstreamer/horizon266-native-input-tmpfs-20261121-v1/horizon266-native-input";
const INPUT_SHA: &str = "0c8aa52ede6067b16991e7d79d3c97f0aacf4de6158d5023c3114e39a40c1397";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon266-native-guard-tmpfs-20261121-v1/horizon266-native-guard";
const GUARD_SHA: &str = "63defdffad878d470ff6f100471408efcd2a207a5c1bb60ac4b75e7204c49c10";
const PACKET: &str =
    "/var/lib/jetstreamer/horizon266-bootstrap-measure-067e29e0-v155-v1/inputs.json";
const PACKET_SHA: &str = "383502fd0018bfc694e6a3fd2328ddb4e26afa4315551eb42037a513a522c169";
const WORKER: &str = "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-historical-worker-v1-8-11";
const WORKER_SHA: &str = "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae";
const LAUNCHER: &str =
    "/var/lib/jetstreamer/horizon266-native-launch-tmpfs-20261121-v1/horizon-native266-launch";

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
const RETENTION: &str = "horizon-native266-terminal-retention.target";
const TOKENS: &str = "/var/lib/jetstreamer/horizon-native266-startup-tokens";
const SLOT: u64 = 114_910_768;
const SNAPSHOT_SHA: &str = "c3bfdbf63b7941a9c111a668bc03f71b197203eb52a45c9ea39e94797272babb";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const HARNESS: &str = INPUT;
const HARNESS_SHA: &str = INPUT_SHA;
const RESERVATION: u64 = DISK_RECEIPTS;
const SCRATCH: u64 = ROOT_CAP;
const EXPECTED_FILESYSTEM: &str = FILESYSTEM;
const PRODUCER_SANDBOX: &str = "WorkingDirectory=/run/horizon266-native-cold-v1\nInaccessiblePaths=/tmp /var/tmp /dev/shm\nPrivateDevices=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX\nOOMPolicy=kill\nOOMScoreAdjust=1000\nAmbientCapabilities=\nStandardOutput=journal\nStandardError=journal\nLogRateLimitIntervalSec=30s\nLogRateLimitBurst=100\n";
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
