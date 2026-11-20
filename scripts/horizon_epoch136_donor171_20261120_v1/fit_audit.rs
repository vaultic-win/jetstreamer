//! Select the full-download or public-stream accounting recorded by the fleet.
use super::{audit_budget, n, sum};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::process::Command;

pub(crate) fn observe(obligation: &Value) -> Result<Value> {
    if obligation.get("method").is_none() {
        audit_budget::validate_fleet_obligation(obligation)?;
        return audit_budget::observe();
    }
    ensure!(
        obligation["method"] == "public HTTP range playback",
        "unknown audit method"
    );
    let result = Command::new("/usr/bin/python3")
        .args(["-I", "-B", "-c", include_str!("public_audit.py")])
        .arg(serde_json::to_string(obligation)?)
        .output()
        .context("capture public audit owner")?;
    ensure!(
        result.status.success() && result.stdout.len() < 1 << 20,
        "public audit observation: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(serde_json::from_slice(&result.stdout)?)
}

pub(super) fn data(fit: &Value, free: u64, obligation: &Value) -> Result<Value> {
    if obligation.get("method").is_none() {
        return audit_budget::data_requirements(fit, free);
    }
    // Validated by observe() before and after the measurement. Streaming stages
    // zero archive bytes. Keep the entire working and Cargo allowance on HOME.
    let storage = &obligation["current_storage"];
    let work = n(obligation, "working_allocation_cap_bytes")?;
    let cargo = n(obligation, "cargo_growth_allowance_bytes")?;
    let growth = sum(work, cargo)?;
    ensure!(
        storage["remaining_archive_growth_bytes"] == 0
            && storage["remaining_DATA_growth_bytes"] == growth,
        "public audit growth differs"
    );
    let floor = n(obligation, "configured_free_floor_bytes")?;
    let continuous = [
        "complete_concurrent_remaining_growth_bytes",
        "fresh_subtree_overlap_bytes",
        "unrelated_growth_margin_bytes",
        "additional_growth_not_covered_by_existing_promise_bytes",
    ]
    .iter()
    .try_fold(floor, |v, key| sum(v, n(fit, key)?))?;
    let historical = n(fit, "required_raw_available_bytes")?;
    let required = sum(continuous.max(historical), growth)?;
    ensure!(free >= required, "HOME free={free}, required={required}");
    Ok(json!({
        "historical_required_DATA_bytes":historical,
        "audit_continuity_before_audit_growth_bytes":continuous,
        "required_DATA_bytes":required,"audit_remaining_archive_bytes":0,
        "audit_remaining_working_bytes":work,"audit_cargo_growth_allowance_bytes":cargo,
        "audit_remaining_growth_bytes":growth,"audit_free_floor_bytes":floor,
        "archive_acceptance_ceiling_bytes":obligation["archive_acceptance_ceiling_bytes"],
        "ceiling_is_not_a_capacity_reservation":true,"audit":storage,
        "complete_concurrent_remaining_growth_bytes":fit["complete_concurrent_remaining_growth_bytes"],
        "old166scratch_DATA_obligation_retained":obligation["old166scratch_DATA_obligation_retained"],
        "resource_credit_bytes":0,"promise_ending_bytes":0
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_playback_preserves_both_floors_and_the_full_work_allowance() {
        let obligation = json!({
            "method":"public HTTP range playback","configured_free_floor_bytes":1000,
            "working_allocation_cap_bytes":16u64 << 30,"cargo_growth_allowance_bytes":2u64 << 30,
            "current_storage":{"remaining_archive_growth_bytes":0,"remaining_DATA_growth_bytes":18u64 << 30}
        });
        let mut fit = json!({"required_raw_available_bytes":20,
            "complete_concurrent_remaining_growth_bytes":100, "fresh_subtree_overlap_bytes":10,
            "unrelated_growth_margin_bytes":5, "additional_growth_not_covered_by_existing_promise_bytes":1});
        for (raw, floor) in [(20, 1116), (1200, 1200)] {
            fit["required_raw_available_bytes"] = json!(raw);
            let required = floor + (18u64 << 30);
            let pass = data(&fit, required, &obligation).unwrap();
            assert_eq!(pass["required_DATA_bytes"], required);
            assert_eq!(pass["audit_remaining_archive_bytes"], 0);
            assert!(data(&fit, required - 1, &obligation).is_err());
        }
        fit["complete_concurrent_remaining_growth_bytes"] = json!(u64::MAX);
        assert!(data(&fit, u64::MAX, &obligation).is_err());
    }
}
