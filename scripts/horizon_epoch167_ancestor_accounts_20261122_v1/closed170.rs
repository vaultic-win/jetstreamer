//! Identities of the two stopped epoch 170 producers and the cold inputs retained for their successor.
use super::*;
pub const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-closed-accounts-20261122-v1";
pub const PROFILE: &[u8] = include_bytes!("profiles170.json");
pub const CHECK_SCHEMA: &str = "horizon170-closed-accounts-check-v1";
pub const COMPLETE_SCHEMA: &str = "horizon170-closed-accounts-complete-v1";
pub(super) const EPOCH: u64 = 170;
pub(super) const SLOT: &str = "73439777";
pub(super) const ACCOUNTS_HASH: &str = "AAfuW4HhAkKNYunC4zf6ipDSCUYsnVfoLMFrmBeb5Sbs";
pub(super) const SNAPSHOT_BYTES: u64 = 2151049662;
pub(super) const LANE: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1";
pub(super) const SNAPSHOT: &str =
    "snapshot-73439777-AAfuW4HhAkKNYunC4zf6ipDSCUYsnVfoLMFrmBeb5Sbs.tar.zst";
pub(super) const SNAPSHOT_SHA: &str =
    "1fff1c4d4c76f56f7b5ba6ba17f379d7811cddb3e314043829ceb864205cab0a";
pub(super) const FINGERPRINT: &str =
    "sha256:a18e763167b4cd47833f89627209ea7b5e08e55de16152df612e2c0d9be05890";
pub(super) const RETRY9_ATTEMPT: &str =
    "replacement-local3retry7-20261110-v1/replacement-local3retry9-20261110-v1";
pub(super) const RETRY10_ATTEMPT: &str =
    "replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1";
pub(super) const RETRY9: &str = "8d120ed88adc4afb9485fb3f61dfa29c";
pub(super) const RETRY10: &str = "a456b826ce1c4634a2df66d66c5cc07f";
pub(super) const RETRY9_INODE: u64 = 113186657;
pub(super) const RETRY10_INODE: u64 = 114886083;
pub(super) const RETRY9_CAP: u64 = 288 << 30;
pub(super) const CAP: u64 = 384 << 30;
pub(super) fn validated_indexes<'a>(
    profile: &'a Value,
    enrollment: &Value,
) -> Result<(&'a [Value], &'static str)> {
    let stock = bound(&enrollment["stock_manifest"])?;
    let epochs = stock["manifest"]["epochs"]
        .as_array()
        .context("no stock epochs")?;
    let [epoch] = epochs.as_slice() else {
        anyhow::bail!("wrong source epoch count")
    };
    let bank = &epoch["bootstrap"];
    let recovery = bound(&enrollment["earlier_census"])?;
    ensure!(
        profile["epoch"] == EPOCH
            && profile["worker"]["sha256"] == WORKER_SHA
            && profile["node"]["sha256"] == NODE_SHA
            && profile["bootstrap"]["sha256"] == SNAPSHOT_SHA
            && profile["bootstrap"]["identity"][2] == SNAPSHOT_BYTES
            && profile["manifest"]["sha256"] == enrollment["stock_manifest"]["sha256"]
            && epoch["epoch"] == EPOCH
            && epoch["runtime"] == "solana-v1.5.6"
            && bank["generation"] == 1634787467305970u64
            && bank["slot"] == 73439777u64
            && bank["accounts_hash"] == ACCOUNTS_HASH
            && bank["size"] == SNAPSHOT_BYTES
            && recovery["replacement_origin"] == bank["slot"]
            && recovery["replay_resume_available"] == false
            && recovery["checkpoint_bundles"] == json!([]),
        "wrong epoch 170 recovery origin"
    );
    closed("horizon-qualify-170-replacement-local3retry11-20261122.service")?;
    let source = profile["projections"]
        .as_array()
        .context("missing genesis and indexes")?;
    ensure!(
        source.len() == 4
            && Path::new(string(&source[0], "source")?)
                .file_name()
                .is_some_and(|n| n == "genesis.tar.bz2"),
        "wrong genesis or compact indexes"
    );
    Ok((&source[1..], "source"))
}
