//! Closed first 16-entry native 20 owner. No synthetic checkpoint or zero-entry claim.
use super::super::*;
pub(super) const UNIT: &str = "horizon-qualify-223-v1620-warmup-resource-d15ee08b-v1.service";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-warmup-d15ee08b-v1";
const RUNNER: &str = "/var/lib/jetstreamer/horizon-223-v1620-warmup-envelope480-v1/jetstreamer-epoch223-v1620-warmup-resource";
const RUNNER_SHA: &str = "d15ee08ba4017419e131fba00d74dc366cb5a0b12156e782dc7c3b00fe5ae911";
const PLAN: &str = "/var/lib/jetstreamer/horizon-223-v1620-warmup-envelope480-v1/actual-plan.json";
const PLAN_SHA: &str = "f9d5dccfc3c5587ddefb8fba758133d53ce7b66cf46a83f2839e52f814d56a7b";
const STATE: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-admission-v1";
const GUARD: &str = "horizon-warmup223-native20-protective-v1.service";
const GUARD_TIMER: &str = "horizon-warmup223-native20-protective-v1.timer";
const GUARD_PLAN: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-guard-v1/guard-plan.json";
const GUARD_RECEIPTS: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-guard-receipts-v1";
const GUARD_SHA: &str = "134904cf2e28ce3ede1dd85a6878e40a407443580d4e83a50cb30efc29fd28be";
const DISK_FLOOR: u64 = 2_000_000_000_000;
const INITIAL_DISK: u64 = 2_300_000_000_000;
const MEMORY_RESERVE: u64 = 480u64 << 30;
const INITIAL_MEMORY: u64 = 608u64 << 30;

const SPEC_SCHEMA: &str = "jetstreamer-private-warmup223-native20-admission-spec-v1";
const ADMISSION_SCHEMA: &str = "jetstreamer-private-warmup223-native20-admission-v1";
const CAPABILITY_PATH: &str =
    "/var/lib/jetstreamer/horizon-warmup223-native20-capability-v4/capability.json";
const CAPABILITY_SHA: &str = "41a800a190c6db29081477a4c4cd8df0808a588fe05bdaf3adf8acb2b1967474";
const EXPECT_FULL227: bool = false;

include!("native20_shared.rs");
