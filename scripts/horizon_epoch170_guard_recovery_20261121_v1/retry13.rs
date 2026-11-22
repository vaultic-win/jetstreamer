//! Replacement for the 170 launch that drained before admission on November 22.
use super::*;

pub(super) const ROOT_INODE: u64 = 113981945;
pub(super) const LOG_INODE: u64 = 113981946;
pub(super) const ROOT_RECEIPT: &str =
    "654e6612f8ce9ee2f9f5c9f172f79f9ce5da4b0f6f02443c856f3a5228a5ca69";
pub const BASE: &str = "epoch170-retry13-rebook-20261122-v1";
pub const ATTEMPT: &str = "replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/cold-retry13-20261122";
pub const UNIT: &str = "horizon-qualify-170-replacement-local3retry13-20261122.service";
pub const TIMER: &str = "horizon-guard-170-replacement-local3retry13-20261122.timer";
pub const GUARD_SHA: &str = "7839c6f0e50ada05e1dbb7a6a371c8438e85c95afdc0f2349a37db123076912e";
pub const GSEAL: &str = "cf184147b708f38ef2816012c584da30b31f3c07551f5f0282fef4a7fa53cc73";
pub const CONTRACT: &str = "332cbec8b7da2c397c075c4332d47d1a609a40b14510c7cd3bb76424c33a7163";
pub const CSEAL: &str = "61804f07280b303bb48e433a962d3f52f0070219035d57d30f42f3b7b6d989ff";
pub const WITNESS: &str = "bad306defdffc45ca0d899fe5f84f42344115e5f69df20934050fbe4e3f5d3cb";
const PRIOR: &str = "epoch170-retry12-rebook-20261122-v1";

pub(super) fn previous_attempt(root: &Value) -> Result<Value> {
    let failed = previous_cold_attempt(
        root,
        PRIOR,
        "horizon-qualify-170-replacement-local3retry12-20261122.service",
        "horizon-guard-170-replacement-local3retry12-20261122.timer",
        "f26354f4e63748059e441cbbee250fdb",
        "NONEXACT_PEER_PROTECTED_FLOOR.json",
    )?;
    let (prior_root, _) = doc(
        &rt(PRIOR).join("SUCCESSOR_ROOT.json"),
        Some("466f48f20716b258189e242eef4d4e2e54fbf6202e6ecd4ff008eb3dd0d10b19"),
    )?;
    previous_cold_attempt(
        &prior_root,
        "epoch170-retry11-rebook-20261122-v1",
        "horizon-qualify-170-replacement-local3retry11-20261122.service",
        "horizon-guard-170-replacement-local3retry11-20261122.timer",
        "7a9f41a86d9240be89e3484fc01c3a31",
        "PROVIDER_POSTSTOP_FLOOR_RECONSTRUCTION.json",
    )?;
    Ok(failed)
}

pub fn funded_guard_floor(price: &Value) -> Result<u64> {
    let conservative = &price["startup_nonexact_peer_floor"];
    let floor = n(conservative, "protected_raw_floor_bytes")?;
    let required = n(conservative, "complete_required_HOME_bytes")?;
    let allowance = n(&price["bookings"]["170"], "remaining_bytes")?;
    let exposure = n(conservative, "allowance_needed")?;
    ensure!(
        conservative["schema"] == "horizon-170-nonexact-peer-prestart-v1"
            && conservative["occupied172_credit_bytes"] == 0
            && n(conservative, "full172_cap_bytes")? == 288 << 30
            && n(conservative, "candidate_remaining_bytes")? == allowance
            && n(conservative, "ordinary_protected_raw_floor_bytes")?.checked_add(exposure)
                == Some(floor)
            && n(conservative, "ordinary_required_HOME_bytes")?.checked_add(exposure)
                == Some(required)
            && price["fits"] == true
            && price["candidate"].is_null()
            && conservative["funded"] == true
            && floor == n(price, "protected_raw_floor_bytes")?
            && required == n(price, "complete_required_HOME_bytes")?
            && required
                == floor
                    .checked_add(allowance)
                    .context("cold booking overflow")?,
        "unfunded peer reservations or changed candidate allowance"
    );
    let surplus = n(price, "available_HOME_bytes")?
        .checked_sub(required)
        .context("insufficient HOME for the full peer and candidate reservations")?;
    // Apply the existing startup cushion only to surplus beyond all conservative bookings.
    floor
        .checked_add(surplus.min(10 << 30))
        .context("guard floor overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_failure_fits_at_full_peer_reservations() {
        let domain = rt(PRIOR);
        let (evidence, _) = doc(
            &domain.join("NONEXACT_PEER_PROTECTED_FLOOR.json"),
            Some("807e323070335a5aed8740fa1d6ab3045ae6efc7c001402450f9e6761000111d"),
        )
        .unwrap();
        let intent = bound(&evidence["prestart"], &domain.join("START_INTENT.json")).unwrap();
        let post = bound(&evidence["failed"], &domain.join("START_FAILURE.json")).unwrap();
        let mut price = intent["prestart"].clone();
        assert!(funded_guard_floor(&price).is_err());
        price["protected_raw_floor_bytes"] = evidence["nonexact_protected"].clone();
        price["complete_required_HOME_bytes"] = evidence["nonexact_required"].clone();
        price["startup_nonexact_peer_floor"] = json!({"schema":"horizon-170-nonexact-peer-prestart-v1",
            "funded":true, "occupied172_credit_bytes":0, "full172_cap_bytes":288u64<<30,
            "candidate_remaining_bytes":evidence["remaining_170_prestart"],"allowance_needed":evidence["allowance_needed"],
            "ordinary_protected_raw_floor_bytes":intent["prestart"]["protected_raw_floor_bytes"],
            "ordinary_required_HOME_bytes":intent["prestart"]["complete_required_HOME_bytes"],
            "protected_raw_floor_bytes":evidence["nonexact_protected"],
            "complete_required_HOME_bytes":evidence["nonexact_required"]});
        let result = funded_guard_floor(&price).unwrap();
        assert!(result >= n(&post["post_guard_capacity"], "protected_raw_floor_bytes").unwrap());
        let required = n(&price, "complete_required_HOME_bytes").unwrap();
        price["available_HOME_bytes"] = json!(required);
        assert_eq!(
            funded_guard_floor(&price).unwrap(),
            evidence["nonexact_protected"]
        );
        price["available_HOME_bytes"] = json!(required - 1);
        assert!(funded_guard_floor(&price).is_err());
        price["available_HOME_bytes"] = json!(required + (20u64 << 30));
        price["startup_nonexact_peer_floor"]["funded"] = json!(false);
        assert!(funded_guard_floor(&price).is_err());
        price["startup_nonexact_peer_floor"]["funded"] = json!(true);
        price["complete_required_HOME_bytes"] = json!(required - 1);
        assert!(funded_guard_floor(&price).is_err());
    }
}
