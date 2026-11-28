//! Replacement for the 170 launch that drained before admission on November 22.
use super::*;

pub(super) const ROOT_INODE: u64 = 113836033;
pub(super) const LOG_INODE: u64 = 113836034;
pub(super) const ROOT_RECEIPT: &str =
    "466f48f20716b258189e242eef4d4e2e54fbf6202e6ecd4ff008eb3dd0d10b19";
pub const BASE: &str = "epoch170-retry12-rebook-20261122-v1";
pub const ATTEMPT: &str = "replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/cold-retry12-20261122";
pub const UNIT: &str = "horizon-qualify-170-replacement-local3retry12-20261122.service";
pub const TIMER: &str = "horizon-guard-170-replacement-local3retry12-20261122.timer";
pub const GUARD_SHA: &str = "cf359b7b189d3f562e0048fd02cfe72f9ccc0cc6366d456272674c94947a3112";
pub const GSEAL: &str = "856fe3669446046e06e8dc1a0a56a0137f129722075d81da6908031cff92a3aa";
pub const CONTRACT: &str = "e132e52d67eb1afa249d81fc90d257d1f882d266843d7d4a7b2d498ca33b1f13";
pub const CSEAL: &str = "b3bb8fc596f171bffc5870ffcd43a7cfeed2106c99c1f4a65f6cecc79ca41528";
pub const WITNESS: &str = "d54f9e01ea7f055440169420e7bb14194e5575a6626e06b1543631a02e9cf7f1";
const PRIOR: &str = "epoch170-retry11-rebook-20261122-v1";
const FAILED_UNIT: &str = "horizon-qualify-170-replacement-local3retry11-20261122.service";
const FAILED_TIMER: &str = "horizon-guard-170-replacement-local3retry11-20261122.timer";
const FAILED_IID: &str = "7a9f41a86d9240be89e3484fc01c3a31";

pub(super) fn previous_attempt(root: &Value) -> Result<Value> {
    previous_cold_attempt(
        root,
        PRIOR,
        FAILED_UNIT,
        FAILED_TIMER,
        FAILED_IID,
        "PROVIDER_POSTSTOP_FLOOR_RECONSTRUCTION.json",
    )
}

/// Protect the observed return of peer allowance without spending the candidate's booking.
fn floor_with_headroom(price: &Value, peer_swing: u64) -> Result<u64> {
    let available = n(price, "available_HOME_bytes")?;
    let required = n(price, "complete_required_HOME_bytes")?;
    let protected = n(price, "protected_raw_floor_bytes")?;
    let remaining = n(&price["bookings"]["170"], "remaining_bytes")?;
    ensure!(
        protected.checked_add(remaining) == Some(required),
        "epoch 170 remaining bytes and protected HOME do not reconcile"
    );
    let headroom = available
        .checked_sub(required)
        .context("candidate and peers do not fit")?;
    protected
        .checked_add(peer_swing.min(headroom))
        .context("armed HOME floor overflow")
}

pub fn funded_guard_floor(price: &Value) -> Result<u64> {
    let (survey, _) = doc(
        &rt(PRIOR).join("OBSERVED_PEER_FLOOR_SWING.json"),
        Some("070a69a7eb0c22dce2c1c471ce3a92865c52129ad64afe228bfe676d12fc1f77"),
    )?;
    floor_with_headroom(price, n(&survey, "rounded_up_GiB_bytes")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_generation_and_native_peer_variation() {
        let prior = rt(PRIOR);
        let (intent, _) = doc(&prior.join("START_INTENT.json"), None).unwrap();
        let price = &intent["prestart"];
        let (proof, _) = doc(
            &prior.join("PROVIDER_POSTSTOP_FLOOR_RECONSTRUCTION.json"),
            None,
        )
        .unwrap();
        let floor = funded_guard_floor(price).unwrap();
        assert!(
            floor
                >= proof["armed_floor"].as_u64().unwrap()
                    + proof["maximum_above_armed"].as_u64().unwrap()
        );
        assert_eq!(
            floor,
            price["protected_raw_floor_bytes"].as_u64().unwrap() + (10 << 30)
        );
        assert!(
            floor
                + price["bookings"]["170"]["remaining_bytes"]
                    .as_u64()
                    .unwrap()
                <= price["available_HOME_bytes"].as_u64().unwrap()
        );
    }

    #[test]
    fn floor_uses_only_uncommitted_headroom() {
        let mut p = json!({"protected_raw_floor_bytes":100,"complete_required_HOME_bytes":180,
            "available_HOME_bytes":183,"bookings":{"170":{"remaining_bytes":80}}});
        assert_eq!(floor_with_headroom(&p, 12).unwrap(), 103);
        p["available_HOME_bytes"] = json!(180);
        assert_eq!(floor_with_headroom(&p, 12).unwrap(), 100);
        p["available_HOME_bytes"] = json!(179);
        assert!(floor_with_headroom(&p, 12).is_err());
        p["available_HOME_bytes"] = json!(500);
        p["bookings"]["170"]["remaining_bytes"] = json!(79);
        assert!(floor_with_headroom(&p, 12).is_err());
    }
}
