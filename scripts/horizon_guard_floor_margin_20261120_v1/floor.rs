//! Fund a stable first-guard threshold only from measured uncommitted HOME slack.
//! Candidate growth, peer promises and inherited floors are never credited away.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
pub const MARGIN: u64 = 16 << 30;
fn n(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().with_context(|| format!("missing {key}"))
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("floor budget overflow")
}
fn available(v: &Value) -> Result<u64> {
    Ok(n(v, "available_HOME_bytes")?.min(n(
        &v["exact_audit_DATA"]["audit"],
        "conservative_available_DATA_bytes",
    )?))
}
fn shape(v: &Value) -> Result<(u64, u64, u64)> {
    let floor = n(v, "protected_raw_floor_bytes")?;
    let growth = n(v, "remaining_standard_root_bytes")?;
    let required = add(floor, growth)?;
    ensure!(
        floor > 0
            && growth > 0
            && required == n(v, "complete_required_DATA_bytes")?
            && add(n(v, "standard_root_allocated_bytes")?, growth)? == n(v, "root_cap_bytes")?
            && v["resource_credit_bytes"] == 0
            && v["resource_promise_ending_bytes"] == 0,
        "incomplete candidate/peer floor accounting"
    );
    Ok((floor, growth, available(v)?))
}
pub fn select(v: &Value) -> Result<Value> {
    let (floor, growth, free) = shape(v)?;
    let required = add(floor, growth)?;
    let slack = free
        .checked_sub(required)
        .context("no uncommitted HOME slack")?;
    ensure!(
        slack >= MARGIN,
        "uncommitted HOME slack cannot fund 16 GiB first-guard margin"
    );
    let armed = add(floor, MARGIN)?;
    let peak = add(armed, growth)?;
    ensure!(free >= peak, "guard margin exceeds full-fit availability");
    Ok(
        json!({"schema":"horizon-first-guard-funded-floor-v1","base_protected_floor_bytes":floor,
        "candidate_remaining_growth_bytes":growth,"candidate_root_cap_bytes":v["root_cap_bytes"],
        "complete_required_DATA_bytes":required,"conservative_available_HOME_bytes":free,
        "verified_uncommitted_slack_bytes":slack,"funded_margin_bytes":MARGIN,
        "armed_floor_bytes":armed,"complete_required_DATA_with_guard_margin_bytes":peak,
        "uncommitted_slack_after_margin_bytes":slack-MARGIN,
        "resource_credit_bytes":0,"resource_promise_ending_bytes":0}),
    )
}
pub fn post(v: &Value, selection: &Value) -> Result<Value> {
    let (needed, growth, free) = shape(v)?;
    let base = n(selection, "base_protected_floor_bytes")?;
    let armed = n(selection, "armed_floor_bytes")?;
    let initial_required = add(base, n(selection, "candidate_remaining_growth_bytes")?)?;
    let initial_free = n(selection, "conservative_available_HOME_bytes")?;
    let initial_slack = initial_free
        .checked_sub(initial_required)
        .context("selection overcommitted initial HOME")?;
    ensure!(
        selection["schema"] == "horizon-first-guard-funded-floor-v1"
            && n(selection, "funded_margin_bytes")? == MARGIN
            && armed == add(base, MARGIN)?
            && initial_slack >= MARGIN
            && selection["complete_required_DATA_bytes"] == initial_required
            && selection["verified_uncommitted_slack_bytes"] == initial_slack
            && selection["uncommitted_slack_after_margin_bytes"] == initial_slack - MARGIN
            && selection["complete_required_DATA_with_guard_margin_bytes"]
                == add(initial_required, MARGIN)?
            && selection["candidate_root_cap_bytes"] == v["root_cap_bytes"]
            && selection["resource_credit_bytes"] == 0
            && selection["resource_promise_ending_bytes"] == 0,
        "changed first-guard floor selection"
    );
    ensure!(
        needed <= armed,
        "post-guard protected floor exceeds funded threshold: required {needed}, armed {armed}"
    );
    let peak = add(armed, growth)?;
    ensure!(
        free >= peak,
        "post-guard HOME cannot fund armed threshold plus complete candidate growth: available {free}, required {peak}"
    );
    Ok(
        json!({"schema":"horizon-post-guard-funded-floor-v1","armed_floor_bytes":armed,
        "post_guard_protected_floor_bytes":needed,"upward_floor_drift_bytes":needed.saturating_sub(base),
        "margin_remaining_above_post_guard_floor_bytes":armed-needed,
        "candidate_remaining_growth_bytes":growth,"complete_required_DATA_with_guard_margin_bytes":peak,
        "conservative_available_HOME_bytes":free,"resource_credit_bytes":0,"resource_promise_ending_bytes":0}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn actual_pre() -> Value {
        json!({"protected_raw_floor_bytes":8513508777282u64,"remaining_standard_root_bytes":100970090496u64,
            "standard_root_allocated_bytes":2109124608u64,"root_cap_bytes":103079215104u64,
            "complete_required_DATA_bytes":8614478867778u64,"available_HOME_bytes":8723981164544u64,
            "exact_audit_DATA":{"audit":{"conservative_available_DATA_bytes":8723980529664u64}},
            "resource_credit_bytes":0,"resource_promise_ending_bytes":0})
    }
    #[test]
    fn retained_prelaunch_slack_funds_margin_without_credit() {
        let v = actual_pre();
        let s = select(&v).unwrap();
        assert_eq!(s["verified_uncommitted_slack_bytes"], 109501661886u64);
        assert_eq!(s["armed_floor_bytes"], 8530688646466u64);
        assert_eq!(
            s["complete_required_DATA_with_guard_margin_bytes"],
            8631658736962u64
        );
        post(&v, &s).unwrap();
    }
    #[test]
    fn accepts_drift_within_funded_margin_without_lowering_guard() {
        let mut v = actual_pre();
        let s = select(&v).unwrap();
        v["protected_raw_floor_bytes"] =
            json!(n(&v, "protected_raw_floor_bytes").unwrap() + MARGIN);
        v["complete_required_DATA_bytes"] =
            json!(n(&v, "complete_required_DATA_bytes").unwrap() + MARGIN);
        assert_eq!(
            post(&v, &s).unwrap()["margin_remaining_above_post_guard_floor_bytes"],
            0
        );
        v["protected_raw_floor_bytes"] = json!(n(&v, "protected_raw_floor_bytes").unwrap() + 1);
        v["complete_required_DATA_bytes"] =
            json!(n(&v, "complete_required_DATA_bytes").unwrap() + 1);
        assert!(post(&v, &s).is_err());
    }
    #[test]
    fn post_fit_must_cover_candidate_growth_above_the_armed_floor() {
        let mut v = actual_pre();
        let s = select(&v).unwrap();
        v["available_HOME_bytes"] =
            json!(n(&s, "complete_required_DATA_with_guard_margin_bytes").unwrap() - 1);
        // The raw post fit still passes; the higher actual guard may not be ignored.
        assert!(
            n(&v, "available_HOME_bytes").unwrap() > n(&v, "complete_required_DATA_bytes").unwrap()
        );
        assert!(post(&v, &s).is_err());
    }
    #[test]
    fn no_slack_credit_partial_fit_or_overflow_is_accepted() {
        let original = actual_pre();
        let mut v = original.clone();
        v["exact_audit_DATA"]["audit"]["conservative_available_DATA_bytes"] =
            json!(n(&v, "complete_required_DATA_bytes").unwrap() + MARGIN - 1);
        assert!(select(&v).is_err());
        let mut v = original.clone();
        v["resource_credit_bytes"] = json!(1);
        assert!(select(&v).is_err());
        let mut v = original.clone();
        v["complete_required_DATA_bytes"] = json!(1);
        assert!(select(&v).is_err());
        let mut v = original;
        v["protected_raw_floor_bytes"] = json!(u64::MAX);
        assert!(select(&v).is_err());
    }
    #[test]
    fn altered_initial_funding_is_not_a_valid_floor_selection() {
        let v = actual_pre();
        let mut selection = select(&v).unwrap();
        selection["verified_uncommitted_slack_bytes"] = json!(u64::MAX);
        assert!(post(&v, &selection).is_err());
    }
}
