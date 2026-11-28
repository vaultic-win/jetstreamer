pub(crate) const MEMORY: u64 = 120_000_000_000;
pub(crate) const ROOT_CAP: u64 = 160_000_000_000;
// Closed epoch-specific production bindings.
pub(crate) const GUARD_UNIT: &str = "horizon-native257-protective-v1.service";
pub(crate) const UNIT: &str = "horizon-257-native-input-20261120-v1.service";
pub(crate) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1";
pub(crate) const TOKEN_SCHEMA: &str = "horizon-native257-first-guard-token-v1";
pub(crate) const TOKEN_ROOT: &str = "/var/lib/jetstreamer/horizon-native257-startup-tokens";
pub(crate) const HARNESS: &str =
    "/var/lib/jetstreamer/horizon257-native-input-limited-20261120-v1/horizon257-native-input";
pub(crate) const HARNESS_SHA: &str = env!("HORIZON257_NATIVE_HARNESS_SHA256");
pub(crate) const PROCESS_PIN: &str = "horizon257-native-guard-process-pin-v1";
pub(crate) const ROOT_PIN: &str = "horizon257-native-guard-root-pin-v1";
pub(crate) const STATIC: &str = "horizon257-native-guard-static-validation-v1";
pub(crate) const TERMINAL: &str = "horizon257-native-guard-terminal-v1";
pub(crate) const TRANSITION: &str = "horizon257-native-guard-transition-v1";
pub(crate) const STOP_INTENT: &str = "horizon257-native-guard-stop-intent-v1";
pub(crate) const STOP_REQUEST: &str = "horizon257-native-guard-stop-request-v1";
pub(crate) const RECEIPT_PREFIX: &str = "/var/lib/jetstreamer/horizon-native257-guard-receipts-";
pub(crate) const FILESYSTEM: &str = ROOT;
