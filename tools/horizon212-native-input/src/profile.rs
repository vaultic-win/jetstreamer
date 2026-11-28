pub(crate) const MEMORY: u64 = 104 << 30;
pub(crate) const ROOT_CAP: u64 = 44 << 30;
pub(crate) const RESERVATION: u64 = 268_435_456;
// Closed epoch-specific production bindings.
pub(crate) const GUARD_UNIT: &str = "horizon-native212-protective-v1.service";
pub(crate) const UNIT: &str = "horizon-212-native-input-20261120-v1.service";
pub(crate) const TOKENS: &str = "/var/lib/jetstreamer/horizon-native212-startup-tokens";
pub(crate) const ROOT: &str = "/run/horizon212-native-cold-v1";
pub(crate) const TOKEN_SCHEMA: &str = "horizon-native212-first-guard-token-v1";
pub(crate) const PLAN_SCHEMA: &str = "horizon-native212-startup-plan-v1";
pub(crate) const ADMISSION_SCHEMA: &str = "horizon-native212-current-fleet-admission-v1";
pub(crate) const PLAN_ENV: &str = "JETSTREAMER_EPOCH212_STARTUP_PLAN";
pub(crate) const PLAN_SHA_ENV: &str = "JETSTREAMER_EPOCH212_STARTUP_PLAN_SHA256";
pub(crate) const PLAN_PREFIX: &str = "horizon-native212-startup-plan-";
pub(crate) const RESULT: &str = "horizon212-exact-worker-cold-input-result-v1";
pub(crate) const EPOCH: u64 = 212;
pub(crate) const SLOT: u64 = 91_583_512;
pub(crate) const SNAPSHOT_SIZE: u64 = 8_715_614_412;
pub(crate) const ACCOUNTS_HASH: &str = "548ThATYndZ7kSzuEgkRx9eVd4MD4hbLgU9ydtjZbbKV";
pub(crate) const SNAPSHOT_SHA: &str =
    "94d7ed8cf39d2b2d665d2c720a3381afb7555d3b3201b7c4d68d6cb0bcbb8a96";
pub(crate) const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-focused-212-complete-span-store8-ca2e38b-v1/snapshot-91583512-548ThATYndZ7kSzuEgkRx9eVd4MD4hbLgU9ydtjZbbKV.tar.zst";
pub(crate) const PACKET: &str =
    "/var/lib/jetstreamer/horizon212-bootstrap-measure-efef7615-v142-v1/inputs.json";
pub(crate) const PACKET_SHA: &str =
    "6c69e2da820cc696ad67c0866e504f8666075aefcacad3148980776f57967945";
pub(crate) const INPUT_SCHEMA: &str = "horizon212-bootstrap-inputs-v1";
pub(crate) fn measurement_verified(value: &serde_json::Value) -> bool {
    value["all_native_input_bytes_verified"] == true
}
const NODE: &str = "/var/lib/jetstreamer/horizon-singleton211-production-node-c17619b16d5d20f0-v1/jetstreamer-node";
const NODE_SHA: &str = "c17619b16d5d20f0d7aefc6e62ce99e68cc8b2bc88153f82183ebb0d4c5ede1d";
pub(crate) const HARNESS: &str =
    "/var/lib/jetstreamer/horizon212-native-input-tmpfs-20261120-v1/horizon212-native-input";
pub(crate) fn harness_allowed(path: &std::path::Path) -> bool {
    path == std::path::Path::new(HARNESS)
}
pub(crate) const FILESYSTEM: &str = "/var/lib/jetstreamer";

pub(crate) fn validate_extra(v: &serde_json::Value) -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::path::Path;
    ensure!(
        v["native_runtime_qualified"] == false
            && v["entry_replay"] == false
            && v["admission_authorized"] == false
            && v["remote_mutations"] == false
            && v["snapshot_extracted"] == false
            && v["bootstrap_generation"] == 1_629_232_341_551_900u64
            && v["bootstrap_slot"] == SLOT
            && v["terminal_root_slot"] == 92_015_419
            && v["terminal_generation"] == 1_629_495_308_790_561u64
            && v["final_output_slot"] == 92_015_999
            && v["manifest_fingerprint"]
                == "sha256:2786d8eec808864b2e54b91d28709e81fc799f9637d18349cb6a3f12ef308e8c"
            && v["snapshot_layout"]["files"]["sum_logical_rounded_4096"] == 29_000_957_952u64
            && v["snapshot_layout"]["files"]["files"] == 380_066,
        "epoch 212 snapshot, layout or authority changed"
    );
    let files = v["files"].as_array().context("input rows")?;
    let node = super::identity(Path::new(NODE))?;
    ensure!(
        files.len() == 4
            && files.iter().any(|row| row["path"] == NODE
                && row["sha256"] == NODE_SHA
                && node["bytes"] == 49_006_264
                && row["identity"] == node),
        "selected node changed"
    );
    let proofs = v["bound_source_evidence"]
        .as_array()
        .context("sealed input provenance")?;
    ensure!(proofs.len() == 8, "source evidence count");
    for row in proofs {
        let path = Path::new(row["path"].as_str().context("proof path")?);
        ensure!(
            super::identity(path)? == row["identity"],
            "bound source identity changed {}",
            path.display()
        );
    }
    // The exact deployed node accepted these 212 inputs in its isolated metadata phase.
    super::read_small(
        Path::new(
            "/var/lib/jetstreamer/horizon212-bootstrap-measure-efef7615-v142-v1/node-preflight.json",
        ),
        "cf41ffb95dd1aed0628a7f5e1d715d356279dbaa42e06e74054507a64307d5bd",
        4096,
    )?;
    Ok(())
}
