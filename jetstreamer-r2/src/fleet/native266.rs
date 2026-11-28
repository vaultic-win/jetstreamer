//! Running resource ownership for the guarded epoch 266 cold bootstrap.
use super::native265::{
    EvidenceReader, FsEvidence, binding, deny, hex, namespace, num, sealed, text,
};
use super::*;
pub(super) const UNIT: &str = "horizon-266-native-input-20261121-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native266-protective-v1.service";
pub(super) const TIMER: &str = "horizon-native266-protective-v1.timer";
pub(super) const RETAIN: &str = "horizon-native266-terminal-retention.target";
pub(super) const ROOT: &str = "/run/horizon266-native-cold-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon266-native-input-tmpfs-20261121-v1/horizon266-native-input";
pub(super) const TEST_SHA: &str = "0c8aa52ede6067b16991e7d79d3c97f0aacf4de6158d5023c3114e39a40c1397";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon266-native-guard-tmpfs-20261121-v1/horizon266-native-guard";
pub(super) const GUARD_SHA: &str = "63defdffad878d470ff6f100471408efcd2a207a5c1bb60ac4b75e7204c49c10";
pub(super) const PROFILE: native265_guard::SampleProfile = native265_guard::SampleProfile {
    unit: UNIT,
    guard_sha: GUARD_SHA,
    harness: TEST,
    harness_sha: TEST_SHA,
    worker: &native265::WorkerProfile {
        path: "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-historical-worker-v1-8-11",
        sha256: "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae",
        backend: "solana-v1.8.11",
        solana_commit: "423a4d65461e36fefb371a2f164c20c4e7ed5afa",
    },
    memory: 192_000_000_000,
    scratch: 124 << 30,
};
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch266-native-input-running-v1";
pub(super) const PHASE: &str = "private-cold-snapshot-verification";
const RUN_SPEC: &str = "jetstreamer-native266-running-capture-spec-v1";

use super::native266 as current;
use horizon_singleton211_launch::native266::validate_saved_handoff;
macro_rules! epoch_name {
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "266", $suffix)
    };
}
include!("native_cold/epoch266.rs");
