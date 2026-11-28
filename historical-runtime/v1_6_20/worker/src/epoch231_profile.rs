//! Keep the cold qualification and the checkpoint continuation separately bounded.
#[cfg(not(feature = "epoch231-checkpoint-continuation"))]
pub(crate) const BOOTSTRAP_SLOT: u64 = 99_791_404;
#[cfg(not(feature = "epoch231-checkpoint-continuation"))]
pub(crate) const END_EXCLUSIVE: u64 = 99_803_090;
#[cfg(not(feature = "epoch231-checkpoint-continuation"))]
pub(crate) const BACKEND_ID: &str = "solana-v1.6.20-epoch231-called-program-demotion-candidate";

#[cfg(feature = "epoch231-checkpoint-continuation")]
pub(crate) const BOOTSTRAP_SLOT: u64 = 99_803_089;
// The 231–232 cohort must run through epoch 232 after checking root 100,655,540.
#[cfg(feature = "epoch231-checkpoint-continuation")]
pub(crate) const END_EXCLUSIVE: u64 = 100_656_000;
#[cfg(feature = "epoch231-checkpoint-continuation")]
pub(crate) const BACKEND_ID: &str = "solana-v1.6.20-epoch231-checkpoint-continuation-candidate";

pub(crate) fn validate_snapshot(slot: u64) -> Result<(), String> {
    if slot != BOOTSTRAP_SLOT {
        return Err(format!(
            "epoch 231 candidate requires snapshot {}",
            BOOTSTRAP_SLOT
        ));
    }
    Ok(())
}
