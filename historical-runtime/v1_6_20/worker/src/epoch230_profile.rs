//! Exact epoch 230 candidate replay span through the first checked hourly root.
pub(crate) const BOOTSTRAP_SLOT: u64 = 99_359_376;
pub(crate) const END_EXCLUSIVE: u64 = 99_375_856;

pub(crate) fn validate_snapshot(slot: u64) -> Result<(), String> {
    if slot != BOOTSTRAP_SLOT {
        return Err("epoch 230 demotion requires the exact cold snapshot 99359376".into());
    }
    Ok(())
}
