//! Cross-check the native build, tested guard image and actual independent peer.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

pub(crate) const SOURCE_COMMIT: &str = "772d5936e39bf6a2640b4f8667cedf3d48862198";
const BUILD: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch167-retry8-recovery-20261120-v1/guard-peer-fixtures-v1/artifact-proof.json";
const BUILD_SHA: &str = "9aac63276a7f1aa051b501cb980c54186edfce3aa92367bc0c36722779dbc8fe";
const TEST_LOG: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0345-zero-recovery-20261120-v1/live166-start/horizon-167-retry8-guard-peer-native-0407-20261120-v1.log";
const LOG_SHA: &str = "f77c325c2ca63c70a9cb0812ecaa1f04db5660cbf0096d2feb2515af07ec0601";
fn successful(v: &Value, invocation: &str) -> bool {
    v["Result"] == "success"
        && v["ExecMainStatus"] == "0"
        && v["SubState"] == "exited"
        && v["InvocationID"] == invocation
}

pub(crate) fn check(
    proof: &Value,
    image_sha: &str,
    owner: &Value,
    read: fn(&Path, u64, bool) -> Result<Vec<u8>>,
) -> Result<()> {
    ensure!(
        proof["commit"] == SOURCE_COMMIT
            && proof["remote"] == "origin/account-updates"
            && proof["peer"] == *owner
            && proof["unit"] == "horizon-167-retry8-guard-peer-native-0407-20261120-v1"
            && successful(&proof["native"], "40b2dbb34a2942228d892ce8ba8f7bdb")
            && proof["build_proof"]["path"] == BUILD
            && proof["build_proof"]["sha256"] == BUILD_SHA
            && proof["tests"]["path"] == TEST_LOG
            && proof["tests"]["sha256"] == LOG_SHA,
        "native guard qualification references, source, unit, or live peer differ"
    );
    let build = read(Path::new(BUILD), 1 << 20, true)?;
    ensure!(
        format!("{:x}", Sha256::digest(&build)) == BUILD_SHA,
        "guard build proof digest changed"
    );
    let build: Value = serde_json::from_slice(&build)?;
    let artifacts = build["artifacts"].as_array().context("build artifacts")?;
    let guard: Vec<_> = artifacts.iter().filter(|a| a["name"] == "guard").collect();
    ensure!(
        successful(&build["native"], "5574c6b301e54b4aa054cf75181e3e58")
            && guard.len() == 1
            && guard[0]["mode"] == 0o555
            && guard[0]["sha256"] == image_sha,
        "tested build or guard artifact differs"
    );
    let log = read(Path::new(TEST_LOG), 1 << 20, false)?;
    ensure!(
        format!("{:x}", Sha256::digest(&log)) == LOG_SHA,
        "qualified test log changed"
    );
    let text = std::str::from_utf8(&log)?;
    ensure!(text.lines().any(|s| s.starts_with("test result: ok. 100 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"))
        && text.lines().any(|s| s == "test data_fulfillment::tests::retry8_requires_full_historical_floor_and_whole_lane_cap ... ok")
        && text.lines().any(|s| s == "test data_fulfillment::tests::revised_cleanup_witness_retains_only_qualified_survivors ... ok")
        && text.lines().filter_map(|line| serde_json::from_str::<Value>(line).ok()).any(|row| row == *owner),
        "guard native tests, original witnesses, candidate scope or authenticated live owner missing");
    Ok(())
}
