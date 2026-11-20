pub(crate) const MEMORY: u64 = 104 << 30;
pub(crate) const ROOT_CAP: u64 = 44 << 30;
// Closed epoch-specific production bindings.
pub(crate) const GUARD_UNIT: &str = "horizon-native212-protective-v1.service";
pub(crate) const UNIT: &str = "horizon-212-native-input-20261120-v1.service";
pub(crate) const ROOT: &str = "/run/horizon212-native-cold-v1";
pub(crate) const TOKEN_SCHEMA: &str = "horizon-native212-first-guard-token-v1";
pub(crate) const TOKEN_ROOT: &str = "/var/lib/jetstreamer/horizon-native212-startup-tokens";
pub(crate) const HARNESS: &str =
    "/var/lib/jetstreamer/horizon212-native-input-tmpfs-20261120-v1/horizon212-native-input";
pub(crate) const HARNESS_SHA: &str = env!("HORIZON212_NATIVE_HARNESS_SHA256");
pub(crate) const PROCESS_PIN: &str = "horizon212-native-guard-process-pin-v1";
pub(crate) const ROOT_PIN: &str = "horizon212-native-guard-root-pin-v1";
pub(crate) const STATIC: &str = "horizon212-native-guard-static-validation-v1";
pub(crate) const TERMINAL: &str = "horizon212-native-guard-terminal-v1";
pub(crate) const TRANSITION: &str = "horizon212-native-guard-transition-v1";
pub(crate) const STOP_INTENT: &str = "horizon212-native-guard-stop-intent-v1";
pub(crate) const STOP_REQUEST: &str = "horizon212-native-guard-stop-request-v1";
pub(crate) const RECEIPT_PREFIX: &str = "/var/lib/jetstreamer/horizon-native212-guard-receipts-";
pub(crate) const FILESYSTEM: &str = "/var/lib/jetstreamer";
