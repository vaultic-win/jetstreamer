//! Running resource ownership for the guarded epoch 261 cold bootstrap.
use super::native265::{
    EvidenceReader, FsEvidence, binding, deny, hex, namespace, num, sealed, text,
};
use super::*;
pub(super) const UNIT: &str = "horizon-261-native-input-20261120-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native261-protective-v1.service";
pub(super) const TIMER: &str = "horizon-native261-protective-v1.timer";
pub(super) const RETAIN: &str = "horizon-native261-terminal-retention.target";
pub(super) const ROOT: &str = "/run/horizon261-native-cold-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon261-native-input-tmpfs-20261120-v1/horizon261-native-input";
pub(super) const TEST_SHA: &str =
    "b657cbaa98f543bb40fd9d01786ae0747ef30f4d2ed4727d81469461ea02d899";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon261-native-guard-tmpfs-20261120-v1/horizon261-native-guard";
pub(super) const GUARD_SHA: &str =
    "b11fc491490a797ae874d4406e68dd01bdcd5486b486a8b44e3635e66fce8f51";
pub(super) const PROFILE: native265_guard::SampleProfile = native265_guard::SampleProfile {
    unit: UNIT,
    guard_sha: GUARD_SHA,
    harness: TEST,
    harness_sha: TEST_SHA,
    worker: &native265::WORKER_PROFILE,
    memory: 192_000_000_000,
    scratch: 124 << 30,
};
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch261-native-input-running-v1";
pub(super) const PHASE: &str = "private-cold-snapshot-verification";
const RUN_SPEC: &str = "jetstreamer-native261-running-capture-spec-v1";

const EPOCH: u64 = 261;
const SLOT: u64 = 112_751_208;
const RANGE: &str = "261-261";
const DISK_RESERVATION: u64 = 256 << 20;
const ACCOUNTS_HASH: &str = "Hgio4phsEt74AkKo6KdVmFzDoK35yS3fUkF6u3RkhSut";
const SNAPSHOT_SHA: &str = "5e84f74696d1f3100650e134fb91487d3e083c374a3262b05f67378b9b1c8256";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-261-264-current-46b4b4a-v1/snapshot-112751208-Hgio4phsEt74AkKo6KdVmFzDoK35yS3fUkF6u3RkhSut.tar.zst";
use super::native261 as current;
use horizon_singleton211_launch::native261::validate_saved_handoff;
macro_rules! epoch_name {
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "261", $suffix)
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

mod retained {
    include!("native261_retained.rs");
}
pub(super) use retained::verify_history;
