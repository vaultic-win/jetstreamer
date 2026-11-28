//! Device-aware fleet admission for the bounded epoch 266 bootstrap.
use super::*;
#[path = "native266_observer_gap.rs"]
mod observer_gap;
pub use observer_gap::validate_observer_predecessor;
pub use observer_gap::validate_observer_predecessor as validate_v164_observer_predecessor;
mod funding {
    include!("native261/funding.rs");
}
mod profile {
    pub(super) const ROOT: &str = "/run/horizon266-native-cold-v1";
    pub(super) const FILESYSTEM: &str = "/var/lib/jetstreamer";
}
#[path = "../../horizon266-native-input/src/original_tmpfs.rs"]
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

const RETENTION: &str = "horizon-native266-terminal-retention.target";
const TOKENS: &str = "/var/lib/jetstreamer/horizon-native266-startup-tokens";
const PRODUCER_SANDBOX: &str = "WorkingDirectory=/run/horizon266-native-cold-v1\nInaccessiblePaths=/tmp /var/tmp /dev/shm\nPrivateDevices=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX\nOOMPolicy=kill\nOOMScoreAdjust=1000\nAmbientCapabilities=\nStandardOutput=journal\nStandardError=journal\nLogRateLimitIntervalSec=30s\nLogRateLimitBurst=100\n";
include!("native266_common.rs");
