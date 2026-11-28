//! Closed first 16-entry native 20 owner. No synthetic checkpoint or zero-entry claim.
use super::super::*;
pub(super) const UNIT: &str = "horizon-qualify-223-v1620-warmup-resource-8457f800-v2.service";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-warmup-8457f800-v2";
const RUNNER: &str = "/var/lib/jetstreamer/horizon-223-v1620-warmup-cooperative-8457f800-v2/jetstreamer-epoch223-v1620-warmup-resource";
const RUNNER_SHA: &str = "8457f800789027054f118e783d2b3aba7a6a3294801b77734d30fda056f28f25";
const PLAN: &str =
    "/var/lib/jetstreamer/horizon-223-v1620-warmup-cooperative-8457f800-v2/actual-plan.json";
const PLAN_SHA: &str = "928482470656dac32cfc4e0ca686b0b025c9f5cbbd4c8fc0bb302ed21cebbe68";
const STATE: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-admission-v2";
const GUARD: &str = "horizon-warmup223-native20-protective-v2.service";
const GUARD_TIMER: &str = "horizon-warmup223-native20-protective-v2.timer";
const GUARD_PLAN: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-guard-v2/guard-plan.json";
const GUARD_RECEIPTS: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-guard-receipts-v2";
const GUARD_SHA: &str = "134904cf2e28ce3ede1dd85a6878e40a407443580d4e83a50cb30efc29fd28be";
const DISK_FLOOR: u64 = 2_000_000_000_000;
const INITIAL_DISK: u64 = 2_300_000_000_000;
const MEMORY_RESERVE: u64 = 480u64 << 30;
const INITIAL_MEMORY: u64 = 608u64 << 30;

const SPEC_SCHEMA: &str = "jetstreamer-private-warmup223-native20-admission-spec-v2";
const ADMISSION_SCHEMA: &str = "jetstreamer-private-warmup223-native20-admission-v2";
const CAPABILITY_PATH: &str =
    "/var/lib/jetstreamer/horizon-warmup223-native20-capability-v5/capability.json";
const CAPABILITY_SHA: &str = "955bb371ec8543fab27811f5cb0ed3c72f26134706daaeab041105666999f164";
const EXPECT_FULL227: bool = true;

include!("native20_shared.rs");
