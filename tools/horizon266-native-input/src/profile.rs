#[cfg(feature = "capped-worker")]
pub(crate) use super::capped::{
    INPUT_SCHEMA, PACKET, PACKET_SHA, measurement_verified, validate_extra,
};
#[cfg(feature = "capped-worker")]
pub(crate) use super::capped_site::TOKENS;
#[cfg(feature = "capped-worker")]
pub(crate) use super::capped_site::{GUARD_UNIT, HARNESS, ROOT, UNIT};
pub(crate) const MEMORY: u64 = 192_000_000_000;
pub(crate) const ROOT_CAP: u64 = 124 << 30;
pub(crate) const RESERVATION: u64 = 268_435_456;
// Closed epoch-specific production bindings.
#[cfg(not(feature = "capped-worker"))]
pub(crate) const GUARD_UNIT: &str = "horizon-native266-protective-v1.service";
#[cfg(not(feature = "capped-worker"))]
pub(crate) const UNIT: &str = "horizon-266-native-input-20261121-v1.service";
#[cfg(not(feature = "capped-worker"))]
pub(crate) const TOKENS: &str = "/var/lib/jetstreamer/horizon-native266-startup-tokens";
#[cfg(not(feature = "capped-worker"))]
pub(crate) const ROOT: &str = "/run/horizon266-native-cold-v1";
pub(crate) const TOKEN_SCHEMA: &str = "horizon-native266-first-guard-token-v1";
pub(crate) const PLAN_SCHEMA: &str = "horizon-native266-startup-plan-v1";
pub(crate) const ADMISSION_SCHEMA: &str = "horizon-native266-current-fleet-admission-v1";
pub(crate) const PLAN_ENV: &str = "JETSTREAMER_EPOCH266_STARTUP_PLAN";
pub(crate) const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH266_STARTUP_PLAN_SHA256";
pub(crate) const PLAN_PREFIX: &str = "horizon-native266-startup-plan-";
pub(crate) const RESULT: &str = "horizon266-exact-worker-cold-input-result-v1";
pub(crate) const EPOCH: u64 = 266;
pub(crate) const SLOT: u64 = 114_910_768;
pub(crate) const SNAPSHOT_SIZE: u64 = 16_826_334_350;
pub(crate) const ACCOUNTS_HASH: &str = "HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK";
pub(crate) const SNAPSHOT_SHA: &str =
    "c3bfdbf63b7941a9c111a668bc03f71b197203eb52a45c9ea39e94797272babb";
pub(crate) const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/snapshot-114910768-HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK.tar.zst";
#[cfg(not(feature = "capped-worker"))]
pub(crate) const PACKET: &str =
    "/var/lib/jetstreamer/horizon266-bootstrap-measure-067e29e0-v155-v1/inputs.json";
#[cfg(not(feature = "capped-worker"))]
pub(crate) const PACKET_SHA: &str =
    "383502fd0018bfc694e6a3fd2328ddb4e26afa4315551eb42037a513a522c169";
#[cfg(not(feature = "capped-worker"))]
pub(crate) const INPUT_SCHEMA: &str = "horizon266-bootstrap-measure-v1";

#[cfg(not(feature = "capped-worker"))]
const NODE: &str =
    "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-node";
#[cfg(not(feature = "capped-worker"))]
const NODE_SHA: &str = "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1";
#[cfg(not(feature = "capped-worker"))]
pub(crate) const HARNESS: &str =
    "/var/lib/jetstreamer/horizon266-native-input-tmpfs-20261121-v1/horizon266-native-input";
pub(crate) fn harness_allowed(path: &std::path::Path) -> bool {
    path == std::path::Path::new(HARNESS)
}
pub(crate) const FILESYSTEM: &str = "/var/lib/jetstreamer";

#[cfg(not(feature = "capped-worker"))]
use anyhow::{Context, Result, ensure};
#[cfg(not(feature = "capped-worker"))]
use serde_json::Value;
#[cfg(not(feature = "capped-worker"))]
use std::path::Path;

#[cfg(not(feature = "capped-worker"))]
pub(crate) fn measurement_verified(v: &Value) -> bool {
    let layout = &v["snapshot_layout"];
    v["bootstrap_slot"] == SLOT
        && v["bootstrap_generation"] == 1_641_767_242_524_970u64
        && v["bootstrap_gcs_md5"] == "frRtvWbKEzOW/onIQa3MeQ=="
        && v["terminal_root_slot"] == 115_343_448
        && v["terminal_generation"] == 1_642_024_788_266_141u64
        && v["native_runtime_qualified"] == false
        && v["snapshot_extracted"] == false
        && v["entry_replay"] == false
        && v["admission_authorized"] == false
        && v["remote_mutations"] == false
        && layout["accounts"]["files"] == 397_061
        && layout["accounts"]["logical_bytes"] == 62_687_854_592u64
        && layout["accounts"]["tar_payload_bytes"] == 62_687_854_592u64
        && layout["files"]["files"] == 397_064
        && layout["files"]["sum_logical_rounded_4096"] == 63_094_784_000u64
        && layout["decoded_tar_bytes"] == 63_298_076_672u64
        && layout["sparse_files"] == 0
}

#[cfg(not(feature = "capped-worker"))]
pub(crate) fn validate_extra(v: &Value) -> Result<()> {
    let files = v["files"].as_array().context("input rows")?;
    let node = super::identity(Path::new(NODE))?;
    ensure!(
        files.len() == 4
            && node["bytes"] == 48_454_432
            && files
                .iter()
                .any(|r| r["path"] == NODE && r["sha256"] == NODE_SHA && r["identity"] == node),
        "measured node changed"
    );
    let proofs = v["bound_source_evidence"]
        .as_array()
        .context("source proofs")?;
    ensure!(proofs.len() == 4, "source evidence count");
    for row in proofs {
        let path = Path::new(row["path"].as_str().context("proof path")?);
        ensure!(
            super::identity(path)? == row["identity"],
            "bound evidence changed: {}",
            path.display()
        );
    }
    let dir = Path::new(PACKET)
        .parent()
        .context("measurement directory")?;
    let q: Value = serde_json::from_slice(&super::read_small(
        &dir.join("qualification.json"),
        "99fe131a55a5004cc06fa4375fcd2a7f0a95f26d7aabd5e08c3abdb721bbb59a",
        4096,
    )?)?;
    ensure!(
        q["input_measurement_only"] == true && q["result"]["sha256"] == PACKET_SHA,
        "measurement qualification mismatch"
    );
    super::read_small(
        &dir.join("deployment-seal-receipt.json"),
        "de356675ab7fc3457921e29c05fbe652ea10cdfa8f8cb86c4bac987e6b5b2266",
        16384,
    )?;
    Ok(())
}
