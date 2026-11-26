//! Bound each epoch 230 candidate to its own snapshot and terminal checkpoint.
#[cfg(not(feature = "epoch230-vote-boundary-demotion"))]
pub(crate) const BOOTSTRAP_SLOT: u64 = 99_359_376;
#[cfg(not(feature = "epoch230-vote-boundary-demotion"))]
pub(crate) const END_EXCLUSIVE: u64 = 99_375_856;
#[cfg(all(
    feature = "epoch230-called-program-demotion",
    not(feature = "epoch230-vote-boundary-demotion")
))]
pub(crate) const BACKEND_ID: &str = "solana-v1.6.20-epoch230-called-program-demotion-candidate";

#[cfg(feature = "epoch230-vote-boundary-demotion")]
pub(crate) const BOOTSTRAP_SLOT: u64 = 99_430_284;
#[cfg(feature = "epoch230-vote-boundary-demotion")]
pub(crate) const END_EXCLUSIVE: u64 = 99_437_434;
#[cfg(feature = "epoch230-vote-boundary-demotion")]
pub(crate) const BACKEND_ID: &str = "solana-v1.6.20-epoch230-vote-boundary-demotion-candidate";

pub(crate) fn validate_snapshot(slot: u64) -> Result<(), String> {
    if slot != BOOTSTRAP_SLOT {
        return Err(format!(
            "epoch 230 demotion requires the exact cold snapshot {}",
            BOOTSTRAP_SLOT
        ));
    }
    Ok(())
}
