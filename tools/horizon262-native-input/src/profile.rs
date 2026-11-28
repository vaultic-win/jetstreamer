use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::Path;

pub(crate) const MEMORY: u64 = 192_000_000_000;
pub(crate) const ROOT_CAP: u64 = 124 << 30;
pub(crate) const RESERVATION: u64 = 268_435_456;
pub(crate) const GUARD_UNIT: &str = "horizon-native262-protective-v1.service";
pub(crate) const UNIT: &str = "horizon-262-native-input-20261126-v1.service";
pub(crate) const TOKENS: &str = "/var/lib/jetstreamer/horizon-native262-startup-tokens";
pub(crate) const ROOT: &str = "/run/horizon262-native-cold-v1";
pub(crate) const TOKEN_SCHEMA: &str = "horizon-native262-first-guard-token-v1";
pub(crate) const PLAN_SCHEMA: &str = "horizon-native262-startup-plan-v1";
pub(crate) const ADMISSION_SCHEMA: &str = "horizon-native262-current-fleet-admission-v1";
pub(crate) const PLAN_ENV: &str = "JETSTREAMER_EPOCH262_STARTUP_PLAN";
pub(crate) const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH262_STARTUP_PLAN_SHA256";
pub(crate) const PLAN_PREFIX: &str = "horizon-native262-startup-plan-";
pub(crate) const RESULT: &str = "horizon262-exact-worker-cold-input-result-v1";
pub(crate) const EPOCH: u64 = 262;
pub(crate) const SLOT: u64 = 113_182_967;
pub(crate) const SNAPSHOT_SIZE: u64 = 15_858_223_025;
pub(crate) const ACCOUNTS_HASH: &str = "39EumnbfaaQdkf2ZMjL1uvVR9T9HcmE1RUP1xeCfpXVU";
pub(crate) const SNAPSHOT_SHA: &str =
    "2f54e3ca459503fd903e037e1d3f073e672f870a6525633c1629147f7bb584b2";
pub(crate) const SNAPSHOT: &str = "/home/ubuntu/.jetstreamer-private/epoch262-stock-bootstrap/snapshot-113182967-39EumnbfaaQdkf2ZMjL1uvVR9T9HcmE1RUP1xeCfpXVU.tar.zst";
pub(crate) const PACKET: &str =
    "/var/lib/jetstreamer/horizon262-native-input-tmpfs-20261126-v1/inputs.json";
pub(crate) const PACKET_SHA: &str =
    "08bb1abfc6da49a6917784d23a1f9f983f91c22bcc8ed686ee048ef8a7e56b7d";
pub(crate) const INPUT_SCHEMA: &str = "horizon262-native-input-packet-v1";
pub(crate) const HARNESS: &str =
    "/var/lib/jetstreamer/horizon262-native-input-tmpfs-20261126-v1/horizon262-native-input";
pub(crate) const FILESYSTEM: &str = "/var/lib/jetstreamer";
const GENERATION: u64 = 1_640_768_983_113_907;
const FINGERPRINT: &str = "sha256:8163fe7dc28e19a4c624242273e1188fd7767731bab26374af4561f067e27cfd";

pub(crate) fn measurement_verified(packet: &Value) -> bool {
    packet["custody_identity_verified"] == true
}

pub(crate) fn harness_allowed(path: &Path) -> bool {
    path == Path::new(HARNESS)
}

fn receipt(packet: &Value, name: &str) -> Result<Value> {
    let sha = packet["proofs"][name]["sha256"]
        .as_str()
        .context("missing receipt SHA-256")?;
    let directory = Path::new(PACKET).parent().context("packet directory")?;
    Ok(serde_json::from_slice(&super::read_small(
        &directory.join(name),
        sha,
        1 << 20,
    )?)?)
}

fn manifest_matches(manifest: &Value) -> bool {
    let manifest = &manifest["manifest"];
    let Some(epochs) = manifest["epochs"].as_array() else {
        return false;
    };
    let Some(cohorts) = manifest["verification_cohorts"].as_array() else {
        return false;
    };
    if epochs.len() != 1 || cohorts.len() != 1 {
        return false;
    }
    let bootstrap = &epochs[0]["bootstrap"];
    let cohort = &cohorts[0];
    manifest["first_epoch"] == EPOCH
        && manifest["last_epoch"] == EPOCH
        && epochs[0]["epoch"] == EPOCH
        && epochs[0]["runtime"] == super::BACKEND
        && bootstrap["slot"] == SLOT
        && bootstrap["accounts_hash"] == ACCOUNTS_HASH
        && bootstrap["generation"] == GENERATION
        && bootstrap["size"] == SNAPSHOT_SIZE
        && bootstrap["md5_hash"] == "Ioeesei/m2n5lkHa+tzBbQ=="
        && bootstrap["crc32c"] == "DWP/pQ=="
        && cohort["first_epoch"] == EPOCH
        && cohort["last_epoch"] == EPOCH
        && cohort["runtime"] == super::BACKEND
        && cohort["bootstrap"] == *bootstrap
        && cohort["root_checkpoints"][0]["slot"] == 113_615_476u64
        && cohort["root_checkpoints"][0]["generation"] == 1_641_012_878_403_786u64
        && cohort["root_checkpoints"][0]["accounts_hash"]
            == "9VhNZirsXzcu2X1P3PE9TbB9XNHJ383LVFuaMtDFguAo"
}

pub(crate) fn validate_extra(packet: &Value) -> Result<()> {
    ensure!(
        packet["bootstrap_slot"] == SLOT
            && packet["bootstrap_generation"] == GENERATION
            && packet["manifest_fingerprint"] == FINGERPRINT
            && packet["snapshot_extracted"] == false
            && packet["native_runtime_qualified"] == false
            && packet["replay_admitted"] == false
            && packet["publication_authorized"] == false,
        "wrong epoch 262 input scope"
    );
    let custody = receipt(packet, "custody.json")?;
    let worker = receipt(packet, "worker.json")?;
    let parser = receipt(packet, "node-parser.json")?;
    let boundaries = receipt(packet, "boundaries.json")?;
    let manifest = receipt(packet, "manifest.json")?;
    let refs = &packet["proofs"];
    let snapshot = &custody["snapshot"];
    ensure!(
        custody["epoch"] == EPOCH
            && custody["snapshot_slot"] == SLOT
            && custody["generation"] == GENERATION
            && custody["replay_admitted"] == false
            && snapshot["path"] == SNAPSHOT
            && snapshot["sha256"] == SNAPSHOT_SHA
            && snapshot["size"] == SNAPSHOT_SIZE
            && snapshot["root_owned_read_only"] == true
            && worker["epoch"] == EPOCH
            && worker["native_bootstrap_opened"] == false
            && worker["protocol_version"] == super::PROTOCOL_VERSION
            && worker["worker"]["path"] == super::WORKER
            && worker["worker"]["sha256"] == super::WORKER_SHA
            && worker["custody"] == refs["custody.json"]
            && worker["parser_receipt"] == refs["node-parser.json"]
            && worker["plan"] == refs["manifest.json"]
            && worker["boundary_receipt"] == refs["boundaries.json"]
            && parser["epoch"] == EPOCH
            && parser["manifest"] == refs["manifest.json"]
            && parser["bootstrap"] == refs["custody.json"]
            && parser["worker_launched"] == false
            && boundaries["epoch"] == EPOCH
            && boundaries["manifest"] == refs["manifest.json"]
            && boundaries["boundaries"]["first"]["slot"] == 113_184_000u64
            && boundaries["boundaries"]["last"]["slot"] == 113_615_999u64
            && manifest["manifest_fingerprint"] == FINGERPRINT
            && manifest_matches(&manifest),
        "epoch 262 source receipts do not agree"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_manifest_rejects_wrong_native_route_and_both_generations() {
        let good: Value =
            serde_json::from_str(include_str!("../fixtures/singleton-manifest.json")).unwrap();
        assert!(manifest_matches(&good));
        for (pointer, wrong) in [
            ("/manifest/epochs/0/runtime", Value::from("solana-v1.8.11")),
            (
                "/manifest/epochs/0/bootstrap/generation",
                Value::from(GENERATION + 1),
            ),
            (
                "/manifest/verification_cohorts/0/root_checkpoints/0/generation",
                Value::from(0),
            ),
        ] {
            let mut candidate = good.clone();
            *candidate.pointer_mut(pointer).unwrap() = wrong;
            assert!(!manifest_matches(&candidate));
        }
    }
}
