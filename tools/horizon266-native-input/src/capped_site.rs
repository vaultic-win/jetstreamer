//! Separate worker and startup ownership for the shrink-debt-capped build.
pub(crate) const WORKER: &str = "/var/lib/jetstreamer/horizon266-capped-worker-package-v199-a1/jetstreamer-historical-worker-v1-8-11";
pub(crate) const WORKER_SHA: &str =
    "763f1aff1f752f0d9886f0f2324a73c9c66a154269d28931575744316bb2f220";
pub(crate) const HARNESS: &str =
    "/var/lib/jetstreamer/horizon266-capped-native-input-v200-a1/horizon266-native-input";
pub(crate) const GUARD_UNIT: &str = "horizon-native266-capped-protective-v1.service";
pub(crate) const UNIT: &str = "horizon-266-capped-native-input-v1.service";
pub(crate) const ROOT: &str = "/run/horizon266-capped-native-cold-v1";
pub(crate) const TOKENS: &str = "/var/lib/jetstreamer/horizon-native266-capped-startup-tokens";
