//! Retained Frame bridge for complete existing observers, never intermediate fleets.
use super::*;
use crate::cached145_terminal_observer as terminal;
use crate::retained_observer_chain as chain;
pub(super) fn retained(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<bool> {
    let previous = e
        .prior_recovery
        .context("observer recovery accepted predecessor Frame")?;
    let t = e
        .cohort183_transition
        .context("observer recovery transition")?;
    let anchor = &previous["bindings"]["observer"];
    let at = utc_seconds(
        e.observer["recorded_at_utc"]
            .as_str()
            .context("observer recovery current UTC")?,
    )?;
    let old = utc_seconds(
        previous["sampled_at_utc"]
            .as_str()
            .context("observer recovery anchor UTC")?,
    )?;
    let direct = at
        == old
            .checked_add(1800)
            .context("observer recovery direct overflow")?
        && e.observer["cadence"]["previous_sample"] == anchor["path"]
        && e.observer["cadence"]["previous_sample_sha256"] == anchor["sha256"];
    let unavailable = e.observer["diagnostic_replays"]
        .as_array()
        .is_some_and(|rows| {
            rows.iter()
                .any(|r| r["producer_unit"] == terminal::UNIT && r["status"] == "unavailable")
        });
    ensure!(
        !unavailable || !t[terminal::FIELD].is_null(),
        "cached145 unavailable ancestry requires exact terminal descriptor"
    );
    let terminal_witness = if t[terminal::FIELD].is_null() {
        None
    } else {
        terminal::Witness::descriptor_matches(&t[terminal::FIELD])?;
        Some(terminal::Witness::load(
            |source| {
                let name = if source.path == terminal::CAPTURE.path {
                    "terminal145.capture"
                } else {
                    "terminal145.terminal"
                };
                e.cohort183_sources
                    .get(name)
                    .cloned()
                    .context("cached145 terminal ancestry source missing")
            },
            &utc_seconds,
        )?)
    };
    if terminal_witness.is_none() && direct && t["observation_bridge"].is_null() {
        return Ok(false);
    }
    ensure!(
        t["cached145"]["mode"] == "retained" && t["repair_incident_remains_open"] == true,
        "observer recovery is restricted to unchanged retained cached145 lineage"
    );
    let plan = e.fleet_plan;
    let current: crate::Bound = serde_json::from_value(plan["observer"].clone())?;
    ensure!(
        serde_json::to_value(&current)? == bindings["observer"],
        "observer recovery current binding differs"
    );
    let fleet = e
        .cohort183_sources
        .get("cached145.current_previous_fleet")
        .context("observer recovery accepted prior fleet")?;
    ensure!(
        fleet["observer_receipt"] == anchor["path"]
            && fleet["observer_sha256"] == anchor["sha256"]
            && fleet["sampled_at_utc"] == previous["sampled_at_utc"],
        "observer recovery prior fleet crosses accepted Frame anchor"
    );
    let rows = if t["observation_bridge"].is_null() {
        Vec::new()
    } else {
        let rows = t["observation_bridge"]
            .as_array()
            .context("observer recovery bridge array")?;
        ensure!(
            !rows.is_empty() && rows.len() <= crate::MAXIMUM_OBSERVATION_BRIDGE_INTERMEDIATES,
            "observer-only bridge count differs"
        );
        rows.clone()
    };
    let mut declared = Vec::new();
    for row in &rows {
        ensure!(
            row.as_object()
                .is_some_and(|r| r.len() == 1 && r.contains_key("observer")),
            "observer recovery cannot introduce a fleet, policy or metadata hop"
        );
        declared.push(serde_json::from_value::<crate::Bound>(
            row["observer"].clone(),
        )?);
    }
    let scope = if let Some(witness) = terminal_witness {
        chain::scope_terminal(plan, fleet, witness)?
    } else {
        chain::scope(plan, fleet)?
    };
    let proof = chain::prove(&scope, now, |bound| {
        if *bound == current {
            return Ok(e.observer.clone());
        }
        let selected = declared
            .iter()
            .enumerate()
            .filter(|(_, b)| *b == bound)
            .collect::<Vec<_>>();
        ensure!(
            selected.len() == 1,
            "observer recovery source missing, duplicated or not declared"
        );
        e.cohort183_sources
            .get(&format!("bridge.{}.observer", selected[0].0))
            .cloned()
            .context("observer recovery complete intermediate source absent")
    })?;
    ensure!(
        proof.intermediates() == declared,
        "observer recovery declared chain skips or reorders actual predecessor receipts"
    );
    Ok(true)
}

#[cfg(test)]
#[path = "cached145_terminal_observer_recovery_tests.rs"]
mod terminal_ancestry_tests;
