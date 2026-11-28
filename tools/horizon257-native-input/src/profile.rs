pub(crate) const MEMORY: u64 = 120_000_000_000;
pub(crate) const ROOT_CAP: u64 = 160_000_000_000;
pub(crate) const RESERVATION: u64 = 256_000_000_000;
// Closed epoch-specific production bindings.
pub(crate) const GUARD_UNIT: &str = "horizon-native257-protective-v1.service";
pub(crate) const UNIT: &str = "horizon-257-native-input-20261120-v1.service";
pub(crate) const TOKENS: &str = "/var/lib/jetstreamer/horizon-native257-startup-tokens";
pub(crate) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1";
pub(crate) const TOKEN_SCHEMA: &str = "horizon-native257-first-guard-token-v1";
pub(crate) const PLAN_SCHEMA: &str = "horizon-native257-startup-plan-v1";
pub(crate) const ADMISSION_SCHEMA: &str = "horizon-native257-current-fleet-admission-v1";
pub(crate) const PLAN_ENV: &str = "JETSTREAMER_EPOCH257_STARTUP_PLAN";
pub(crate) const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH257_STARTUP_PLAN_SHA256";
pub(crate) const PLAN_PREFIX: &str = "horizon-native257-startup-plan-";
pub(crate) const RESULT: &str = "horizon257-exact-worker-cold-input-result-v1";
pub(crate) const EPOCH: u64 = 257;
pub(crate) const SLOT: u64 = 111_022_755;
pub(crate) const SNAPSHOT_SIZE: u64 = 15_020_667_485;
pub(crate) const ACCOUNTS_HASH: &str = "8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3";
pub(crate) const SNAPSHOT_SHA: &str =
    "3e2b236f2cba29fbfe40f39f133fe9c845df9280e3fc6dd1cb70e4e018a4744d";
pub(crate) const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-257-260-current-46b4b4a-v1/snapshot-111022755-8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3.tar.zst";
pub(crate) const PACKET: &str =
    "/var/lib/jetstreamer/horizon257-native-bootstrap-inputs-20261120-v1/inputs.json";
pub(crate) const PACKET_SHA: &str =
    "d325e670fecbd4073ca86bd52afefd99ac992c7d0392de1a3e82c9dcb3e1d40f";
pub(crate) const INPUT_SCHEMA: &str = "horizon257-bootstrap-inputs-v1";
pub(crate) fn measurement_verified(value: &serde_json::Value) -> bool {
    value["all_native_input_bytes_verified"] == true
}
const NODE: &str = "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node";
const NODE_SHA: &str = "2789f8211dafc4230a084910867db99699e6470b4a08a6fd8cc6dc00bf080f32";
pub(crate) const HARNESS: &str =
    "/var/lib/jetstreamer/horizon257-native-input-limited-20261120-v1/horizon257-native-input";
pub(crate) fn harness_allowed(path: &std::path::Path) -> bool {
    path == std::path::Path::new(HARNESS)
}
pub(crate) fn validate_extra(v: &serde_json::Value) -> anyhow::Result<()> {
    validate_selected(v, &super::identity(std::path::Path::new(NODE))?)
}
fn validate_selected(v: &serde_json::Value, node: &serde_json::Value) -> anyhow::Result<()> {
    anyhow::ensure!(
        v["native_runtime_qualified"] == false
            && v["replay_launch_authorized"] == false
            && v["corrected_ranges_sha256"]
                == "5810e796b7565404320544ebb5cd98055eb5cfaf60af64884c96481e5f75d126"
            && v["singleton_manifest"]["bootstrap"]["generation"] == 1639569360423179u64
            && v["singleton_manifest"]["final_checkpoint"]["generation"] == 1640034318698892u64,
        "foreign snapshot generation or corrected source"
    );
    let rows = v["files"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing input rows"))?;
    anyhow::ensure!(
        rows.len() == 4
            && rows.iter().any(|r| r["path"] == NODE
                && r["sha256"] == NODE_SHA
                && r["identity"]["bytes"] == 49064824
                && node == &r["identity"]),
        "selected node identity differs"
    );
    Ok(())
}
pub(crate) const FILESYSTEM: &str = ROOT;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn changed_generation_ranges_or_selected_node_rejects_input() {
        let identity = json!({"bytes":49064824, "inode":123});
        let input = json!({"native_runtime_qualified":false,"replay_launch_authorized":false,
            "corrected_ranges_sha256":"5810e796b7565404320544ebb5cd98055eb5cfaf60af64884c96481e5f75d126",
            "singleton_manifest":{"bootstrap":{"generation":1639569360423179u64},"final_checkpoint":{"generation":1640034318698892u64}},
            "files":[{"path":NODE,"sha256":NODE_SHA,"identity":identity}, {}, {}, {}]});
        validate_selected(&input, &identity).unwrap();
        for pointer in [
            "/corrected_ranges_sha256",
            "/singleton_manifest/bootstrap/generation",
            "/singleton_manifest/final_checkpoint/generation",
            "/files/0/path",
            "/files/0/sha256",
            "/files/0/identity/inode",
            "/native_runtime_qualified",
            "/replay_launch_authorized",
        ] {
            let mut altered = input.clone();
            *altered.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(validate_selected(&altered, &identity).is_err(), "{pointer}");
        }
        assert!(!harness_allowed(std::path::Path::new(
            "/var/lib/jetstreamer/horizon-native265-test/native-input-test"
        )));
    }
}
