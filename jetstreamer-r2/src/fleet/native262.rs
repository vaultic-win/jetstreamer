//! Fleet ownership for the invocation-bound epoch 262 cold bootstrap.
use super::native265::{
    EvidenceReader, FsEvidence, binding, deny, hex, namespace, num, sealed, text,
};
use super::*;
use horizon_singleton211_launch::native262::validate_saved_handoff;

pub(super) const UNIT: &str = "horizon-262-native-input-20261126-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native262-protective-v1.service";
pub(super) const TIMER: &str = "horizon-native262-protective-v1.timer";
pub(super) const RETAIN: &str = "horizon-native262-terminal-retention.target";
pub(super) const ROOT: &str = "/run/horizon262-native-cold-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon262-native-input-tmpfs-20261126-v1/horizon262-native-input";
pub(super) const TEST_SHA: &str =
    "6b14b1ec1a5a5db6b3fb4d216cb75d882366a77ef7bd913ce1926eda97939a72";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon262-native-guard-20261126-v1/horizon262-native-guard";
pub(super) const GUARD_SHA: &str =
    "7a07bd136f3b4efae96d8642aa4ac21fe923ffe1db94aa291c11c524a770fc31";
pub(super) const PROFILE: native265_guard::SampleProfile = native265_guard::SampleProfile {
    unit: UNIT,
    guard_sha: GUARD_SHA,
    harness: TEST,
    harness_sha: TEST_SHA,
    worker: &native265::WORKER_PROFILE,
    memory: 192_000_000_000,
    scratch: 124 << 30,
};
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch262-native-input-running-v1";
pub(super) const PHASE: &str = "private-cold-snapshot-verification";
const RUN_SPEC: &str = "jetstreamer-native262-running-capture-spec-v1";
const EPOCH: u64 = 262;
const SLOT: u64 = 113_182_967;
const RANGE: &str = "262-262";
const DISK_RESERVATION: u64 = 256 << 20;
const ACCOUNTS_HASH: &str = "39EumnbfaaQdkf2ZMjL1uvVR9T9HcmE1RUP1xeCfpXVU";
const SNAPSHOT_SHA: &str = "2f54e3ca459503fd903e037e1d3f073e672f870a6525633c1629147f7bb584b2";
const SNAPSHOT: &str = "/home/ubuntu/.jetstreamer-private/epoch262-stock-bootstrap/snapshot-113182967-39EumnbfaaQdkf2ZMjL1uvVR9T9HcmE1RUP1xeCfpXVU.tar.zst";

use super::native262 as current;
macro_rules! epoch_name {
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "262", $suffix)
    };
}
pub(super) mod event {
    include!("native_cold/event.rs");
}
mod guard {
    include!("native_cold/guard.rs");
}
mod history {
    include!("native_cold/history.rs");
}
pub(super) mod terminal {
    include!("native_cold/terminal.rs");
}
include!("native_cold/owner.rs");

const TMPFS_BYTES: u64 = 128 << 30;
include!("native_cold/tmpfs.rs");
