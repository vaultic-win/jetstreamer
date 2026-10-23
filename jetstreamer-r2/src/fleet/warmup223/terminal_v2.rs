//! Terminal handoff for this bounded native20 warmup, never prefix qualification.
use super::super::*;
use super::native20_v2 as c;
pub(super) const SCHEMA: &str = "jetstreamer-private-warmup223-native20-terminal-v2";
const ORIGIN: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-admission-v2/launch.json";
const STARTUP: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-startup-attempt1-v1";
const RUNNER_SHA: &str = "8457f800789027054f118e783d2b3aba7a6a3294801b77734d30fda056f28f25";
const PLAN: &str =
    "/var/lib/jetstreamer/horizon-223-v1620-warmup-cooperative-8457f800-v2/actual-plan.json";
const PLAN_SHA: &str = "928482470656dac32cfc4e0ca686b0b025c9f5cbbd4c8fc0bb302ed21cebbe68";

const SPEC_SCHEMA: &str = "jetstreamer-warmup223-native20-terminal-spec-v2";
const STARTUP_UNIT: &str = "horizon-qualify-223-v1620-warmup-resource-d15ee08b-v1.service";
const REQUIRE_COOPERATIVE: bool = true;

include!("terminal_shared.rs");
