//! Terminal handoff for this bounded native20 warmup, never prefix qualification.
use super::super::*;
use super::native20 as c;
pub(super) const SCHEMA: &str = "jetstreamer-private-warmup223-native20-terminal-v1";
const ORIGIN: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-admission-v1/launch.json";
const STARTUP: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-startup-attempt1-v1";
const RUNNER_SHA: &str = "d15ee08ba4017419e131fba00d74dc366cb5a0b12156e782dc7c3b00fe5ae911";
const PLAN: &str = "/var/lib/jetstreamer/horizon-223-v1620-warmup-envelope480-v1/actual-plan.json";
const PLAN_SHA: &str = "f9d5dccfc3c5587ddefb8fba758133d53ce7b66cf46a83f2839e52f814d56a7b";

const SPEC_SCHEMA: &str = "jetstreamer-warmup223-native20-terminal-spec-v1";
const STARTUP_UNIT: &str = "horizon-qualify-223-v1620-warmup-resource-d15ee08b-v1.service";
const REQUIRE_COOPERATIVE: bool = false;

include!("terminal_shared.rs");
