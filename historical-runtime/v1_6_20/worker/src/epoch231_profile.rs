//! Bound the epoch 231 comparison to its cold snapshot and first checked root.
pub(crate) const BOOTSTRAP_SLOT: u64 = 99_791_404;
pub(crate) const END_EXCLUSIVE: u64 = 99_803_090;

pub(crate) fn validate_snapshot(slot: u64) -> Result<(), String> {
    if slot != BOOTSTRAP_SLOT {
        return Err("epoch 231 demotion requires the exact cold snapshot 99791404".into());
    }
    Ok(())
}
