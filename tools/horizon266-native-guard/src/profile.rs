pub(crate) const MEMORY: u64 = 192_000_000_000;
pub(crate) const ROOT_CAP: u64 = 124 << 30;
// Closed epoch-specific production bindings.
pub(crate) const GUARD_UNIT: &str = "horizon-native266-protective-v1.service";
pub(crate) const UNIT: &str = "horizon-266-native-input-20261121-v1.service";
pub(crate) const ROOT: &str = "/run/horizon266-native-cold-v1";
pub(crate) const TOKEN_SCHEMA: &str = "horizon-native266-first-guard-token-v1";
pub(crate) const TOKEN_ROOT: &str = "/var/lib/jetstreamer/horizon-native266-startup-tokens";
pub(crate) const HARNESS: &str =
    "/var/lib/jetstreamer/horizon266-native-input-tmpfs-20261121-v1/horizon266-native-input";
pub(crate) const HARNESS_SHA: &str = env!("HORIZON266_NATIVE_HARNESS_SHA256");
pub(crate) const PROCESS_PIN: &str = "horizon266-native-guard-process-pin-v1";
pub(crate) const ROOT_PIN: &str = "horizon266-native-guard-root-pin-v1";
pub(crate) const STATIC: &str = "horizon266-native-guard-static-validation-v1";
pub(crate) const TERMINAL: &str = "horizon266-native-guard-terminal-v1";
pub(crate) const TRANSITION: &str = "horizon266-native-guard-transition-v1";
pub(crate) const STOP_INTENT: &str = "horizon266-native-guard-stop-intent-v1";
pub(crate) const STOP_REQUEST: &str = "horizon266-native-guard-stop-request-v1";
pub(crate) const RECEIPT_PREFIX: &str = "/var/lib/jetstreamer/horizon-native266-guard-receipts-";
pub(crate) const FILESYSTEM: &str = "/var/lib/jetstreamer";
