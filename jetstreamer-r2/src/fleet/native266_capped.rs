//! Running resource ownership for the guarded epoch 266 cold bootstrap.
use super::native265::{
    EvidenceReader, FsEvidence, binding, deny, hex, namespace, num, sealed, text,
};
use super::*;
pub(super) const UNIT: &str = "horizon-266-capped-native-input-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native266-capped-protective-v1.service";
pub(super) const TIMER: &str = "horizon-native266-capped-protective-v1.timer";
pub(super) const RETAIN: &str = "horizon-native266-capped-retention.target";
pub(super) const ROOT: &str = "/run/horizon266-capped-native-cold-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon266-capped-native-input-v200-a1/horizon266-native-input";
pub(super) const TEST_SHA: &str = "72f04be574d9f81a0d0e610392ae9b53aed171029c2ea0e81bfd34a4919f9bac";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon266-capped-native-input-v200-a1/horizon266-native-guard";
pub(super) const GUARD_SHA: &str = "e21d62171ad35efdba9c83e86da25092ff7d2ad9a88507b86eb9bf51d9b8072a";
pub(super) const PROFILE: native265_guard::SampleProfile = native265_guard::SampleProfile {
    unit: UNIT,
    guard_sha: GUARD_SHA,
    harness: TEST,
    harness_sha: TEST_SHA,
    worker: &native265::WorkerProfile {
        path: "/var/lib/jetstreamer/horizon266-capped-worker-package-v199-a1/jetstreamer-historical-worker-v1-8-11",
        sha256: "763f1aff1f752f0d9886f0f2324a73c9c66a154269d28931575744316bb2f220",
        backend: "solana-v1.8.11",
        solana_commit: "423a4d65461e36fefb371a2f164c20c4e7ed5afa",
    },
    memory: 192_000_000_000,
    scratch: 124 << 30,
};
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch266-capped-native-input-running-v1";
pub(super) const PHASE: &str = "private-cold-snapshot-verification";
const RUN_SPEC: &str = "jetstreamer-native266-capped-running-capture-spec-v1";

use super::native266_capped as current;
use horizon_singleton211_launch::native266_capped::validate_saved_handoff;
macro_rules! epoch_name {
    ("jetstreamer-private-epoch", "-native-terminal-proof-v1") => { "jetstreamer-private-epoch266-capped-native-terminal-proof-v1" };
    ("jetstreamer-native", "-terminal-capture-spec-v1") => { "jetstreamer-native266-capped-terminal-capture-spec-v1" };
    ("capture-native", $suffix:literal) => { concat!("capture-native266-capped", $suffix) };
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "266", $suffix)
    };
}
include!("native_cold/epoch266.rs");
