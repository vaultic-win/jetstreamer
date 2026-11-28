//! Private epoch 229 replay span from the authenticated bootstrap to the next checked root.
pub(crate) const BOOTSTRAP_SLOT: u64 = 98_927_417;
pub(crate) const END_EXCLUSIVE: u64 = 98_939_267;

pub(crate) fn validate_snapshot(slot: u64) -> Result<(), String> {
    if slot != BOOTSTRAP_SLOT {
        return Err("epoch 229 demotion requires the exact cold snapshot 98927417".into());
    }
    Ok(())
}
