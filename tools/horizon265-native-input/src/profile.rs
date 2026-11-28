pub(crate) const MEMORY: u64 = 128_000_000_000;
pub(crate) const ROOT_CAP: u64 = 506_191_984_640;
pub(crate) const RESERVATION: u64 = 506_191_984_640;
// Closed epoch-specific production bindings.
pub(crate) const GUARD_UNIT: &str = "horizon-native265-protective-v1.service";
pub(crate) const UNIT: &str = "horizon-265-native-input-20261119-v1.service";
pub(crate) const TOKENS: &str = "/var/lib/jetstreamer/horizon-native265-startup-tokens";
pub(crate) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1";
pub(crate) const TOKEN_SCHEMA: &str = "horizon-native265-first-guard-token-v1";
pub(crate) const PLAN_SCHEMA: &str = "horizon-native265-startup-plan-v1";
pub(crate) const ADMISSION_SCHEMA: &str = "horizon-native265-current-fleet-admission-v1";
pub(crate) const PLAN_ENV: &str = "JETSTREAMER_EPOCH265_STARTUP_PLAN";
pub(crate) const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH265_STARTUP_PLAN_SHA256";
pub(crate) const PLAN_PREFIX: &str = "horizon-native265-startup-plan-";
pub(crate) const RESULT: &str = "horizon265-exact-worker-cold-input-result-v1";
pub(crate) const EPOCH: u64 = 265;
pub(crate) const SLOT: u64 = 114_479_281;
pub(crate) const SNAPSHOT_SIZE: u64 = 16_483_458_670;
pub(crate) const ACCOUNTS_HASH: &str = "Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW";
pub(crate) const SNAPSHOT_SHA: &str =
    "04eb59e2dbbc2b0d4f1535741fa9d56794c32ad18e14c98df4fa76a5ae397641";
pub(crate) const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-265-265-current-46b4b4a-v1/snapshot-114479281-Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW.tar.zst";
pub(crate) const PACKET: &str =
    "/var/lib/jetstreamer/horizon265-native-input-evidence-20261119-v1/input-packet.json";
pub(crate) const PACKET_SHA: &str =
    "f7dbb6eedd4f47c940c959639d399ea3af68343f18fc894c736170f6dc089153";
pub(crate) const INPUT_SCHEMA: &str = "horizon265-input-packet-v1";
pub(crate) fn measurement_verified(value: &serde_json::Value) -> bool {
    value["sealed_file_bytes_and_index_structure_accepted"] == true
}
pub(crate) fn validate_extra(_: &serde_json::Value) -> anyhow::Result<()> {
    Ok(())
}
pub(crate) const FILESYSTEM: &str = "/";

#[cfg(test)]
pub(crate) const HARNESS: &str = "/var/lib/jetstreamer/horizon-native265-test/native-input-test";
pub(crate) fn harness_allowed(_: &std::path::Path) -> bool {
    true
}
