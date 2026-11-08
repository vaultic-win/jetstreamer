//! Match the caller's authenticated live145 comparison domain on BOTH sides.
//! These are historical views only: raw fleet/history and every promise remain unchanged.
use super::*;
use horizon_recovered_resource_frame_typed_bridge_v1::live145_frame as contract;

pub(super) fn previous(plan: &Value, fleet: &Value) -> Result<Value> {
    if !contract::selected(plan)? {
        ensure!(
            fleet.get(contract::FIELD).is_none_or(Value::is_null),
            "cold185 undeclared prior live145 history"
        );
        // Also rejects an undeclared raw actor/guard/timer; never strip by name alone.
        return contract::comparison_fleet(plan, fleet, None);
    }
    let captures = fleet[contract::FIELD]
        .as_array()
        .context("cold185 selected prior live145 history is missing")?;
    ensure!(
        captures.len() == 2,
        "cold185 prior live145 needs both original captures"
    );
    let before = Some(captures[0].clone());
    let after = Some(captures[1].clone());
    let authenticated = contract::history(&before, &after)?;
    ensure!(
        authenticated.as_ref() == Some(&fleet[contract::FIELD]),
        "cold185 prior live145 history changed during authentication"
    );
    // Authenticate the raw historical census against each recorded endpoint.
    // The exact contract checks original source/owner/limits/clock/cadence and
    // permits only its already-qualified periodic-guard rollover.
    let first = contract::comparison_fleet(plan, fleet, before.as_ref())?;
    let last = contract::comparison_fleet(plan, fleet, after.as_ref())?;
    ensure!(
        first == last,
        "cold185 prior live145 projection changed unrelated history"
    );
    Ok(last)
}
