pub(crate) const MEMORY: u64 = 192_000_000_000;
pub(crate) const ROOT_CAP: u64 = 124 << 30;
pub(crate) const RESERVATION: u64 = 268_435_456;
// Closed epoch-specific production bindings.
pub(crate) const GUARD_UNIT: &str = "horizon-native261-protective-v1.service";
pub(crate) const UNIT: &str = "horizon-261-native-input-20261120-v1.service";
pub(crate) const TOKENS: &str = "/var/lib/jetstreamer/horizon-native261-startup-tokens";
pub(crate) const ROOT: &str = "/run/horizon261-native-cold-v1";
pub(crate) const TOKEN_SCHEMA: &str = "horizon-native261-first-guard-token-v1";
pub(crate) const PLAN_SCHEMA: &str = "horizon-native261-startup-plan-v1";
pub(crate) const ADMISSION_SCHEMA: &str = "horizon-native261-current-fleet-admission-v1";
pub(crate) const PLAN_ENV: &str = "JETSTREAMER_EPOCH261_STARTUP_PLAN";
pub(crate) const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH261_STARTUP_PLAN_SHA256";
pub(crate) const PLAN_PREFIX: &str = "horizon-native261-startup-plan-";
pub(crate) const RESULT: &str = "horizon261-exact-worker-cold-input-result-v1";
pub(crate) const EPOCH: u64 = 261;
pub(crate) const SLOT: u64 = 112_751_208;
pub(crate) const SNAPSHOT_SIZE: u64 = 15_435_685_203;
pub(crate) const ACCOUNTS_HASH: &str = "Hgio4phsEt74AkKo6KdVmFzDoK35yS3fUkF6u3RkhSut";
pub(crate) const SNAPSHOT_SHA: &str =
    "5e84f74696d1f3100650e134fb91487d3e083c374a3262b05f67378b9b1c8256";
pub(crate) const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-261-264-current-46b4b4a-v1/snapshot-112751208-Hgio4phsEt74AkKo6KdVmFzDoK35yS3fUkF6u3RkhSut.tar.zst";
pub(crate) const PACKET: &str =
    "/var/lib/jetstreamer/horizon261-bootstrap-measure-3cbb2796-v137-v1/inputs.json";
pub(crate) const PACKET_SHA: &str =
    "9d36d766ab81ac0f831dc1af81198bef3f67ec7ad47f05d1541629d0916bf385";
pub(crate) const INPUT_SCHEMA: &str = "horizon261-bootstrap-inputs-v1";
pub(crate) fn measurement_verified(value: &serde_json::Value) -> bool {
    value["all_native_input_bytes_verified"] == true
}
const NODE: &str = "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node";
const NODE_SHA: &str = "2789f8211dafc4230a084910867db99699e6470b4a08a6fd8cc6dc00bf080f32";
pub(crate) const HARNESS: &str =
    "/var/lib/jetstreamer/horizon261-native-input-tmpfs-20261120-v1/horizon261-native-input";
pub(crate) fn harness_allowed(path: &std::path::Path) -> bool {
    path == std::path::Path::new(HARNESS)
}
pub(crate) fn validate_extra(v: &serde_json::Value) -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::path::Path;
    ensure!(
        v["native_runtime_qualified"] == false
            && v["entry_replay"] == false
            && v["admission_authorized"] == false
            && v["remote_mutations"] == false
            && v["snapshot_extracted"] == false
            && v["bootstrap_generation"] == 1_640_541_082_024_797u64
            && v["terminal_generation"] == 1_640_768_983_113_907u64
            && v["bootstrap_slot"] == SLOT
            && v["terminal_root_slot"] == 113_182_967
            && v["corrected_ranges_sha256"]
                == "adf684d1a7354b85ae477234877c23c7eaa046de7e8b6c73cc2015d3dca02f68"
            && v["native_window_comparison_sha256"]
                == "00bfb3d6fddda86216c35160fafac81fdda5af53bce4485e6052ce8596819510",
        "wrong epoch 261 bootstrap, source or authority"
    );
    let files = v["files"].as_array().context("native inputs")?;
    ensure!(
        files.len() == 4
            && files.iter().any(|row| row["path"] == NODE
                && row["sha256"] == NODE_SHA
                && row["identity"]["bytes"] == 49_064_824
                && super::identity(Path::new(NODE)).is_ok_and(|id| row["identity"] == id)),
        "selected node changed"
    );
    let bound = v["bound_source_evidence"]
        .as_array()
        .context("source evidence")?;
    ensure!(bound.len() == 8, "sealed source evidence count changed");
    for row in bound {
        let path = Path::new(row["path"].as_str().context("source evidence path")?);
        ensure!(
            super::identity(path)? == row["identity"],
            "source evidence changed: {}",
            path.display()
        );
    }
    Ok(())
}
pub(crate) const FILESYSTEM: &str = "/var/lib/jetstreamer";
