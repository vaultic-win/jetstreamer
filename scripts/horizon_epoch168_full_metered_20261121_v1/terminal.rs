//! Independently collected boundary of the guarded, metered epoch 168.
use super::*;
pub(super) const PRODUCER_UNIT: &str = "horizon-qualify-168-full-metered-20261121-v1.service";
pub(super) const PRODUCER_IID: &str = "9cebb1d022124fb08588e93e055d5446";
pub(super) const LIVE_SHA: &str =
    "11c7cbb269258849d637259fad7a005f3e1255fbeaac99e3239f089495164ac7";
pub(super) const TERMINAL_ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-current-delivery-20261121-v1";

pub(super) fn boundary(live: &Value) -> Result<receipt::TerminalBoundary> {
    let path = Path::new(TERMINAL_ROOT).join("epoch-expectations/epoch-168.json");
    let witness = &live["independent_boundary"];
    let digest = "8e488ce3e19af44b99d14dc2e4b7560f05515ba1478a2608da4ca6766eea747e";
    ensure!(
        witness["path"] == json!(path) && witness["sha256"] == digest,
        "different boundary witness"
    );
    let bytes = small(&path, 65536)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == digest,
        "finalized RPC evidence changed"
    );
    let record: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        record["schema"] == "horizon-current-reader-epoch-expectation-v1"
            && record["epoch"] == EPOCH
            && record["parent_slot"] == 72_575_999
            && live["epoch_bounds"] == json!([72_576_000, 73_007_999])
            && record["terminal_slot"] == 73_007_999,
        "unexpected finalized epoch coverage"
    );
    let hash = bs58::decode(s(&record["terminal_blockhash"])?).into_vec()?;
    Ok(receipt::TerminalBoundary {
        epoch: EPOCH,
        last_block: record["terminal_slot"].as_u64().context("terminal slot")?,
        last_block_hash: hash
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid terminal blockhash length"))?,
    })
}
