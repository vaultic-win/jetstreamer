//! Same-cadence full265 finalization telemetry; ordinary running replay stays ordinary.
use super::*;
use jetstreamer_horizon_observe::full265 as exact;
pub(super) fn validate(c: &Config) -> Result<()> {
    ensure!(
        c.diagnostic_replays
            .iter()
            .all(|r| r.producer_unit != exact::UNIT && r.controller_unit != exact::UNIT),
        "265 full replay must use ordinary replay telemetry"
    );
    for r in &c.replays {
        if r.producer_unit == exact::UNIT || r.controller_unit == exact::UNIT {
            exact::telemetry_tuple(
                &r.range,
                &r.producer_unit,
                &r.controller_unit,
                &r.expected_producer_invocation_id,
                &r.expected_controller_invocation_id,
                &r.scratch_path,
            )?;
        }
    }
    Ok(())
}
fn observe(sample: u64) -> Result<Value> {
    let initial = exact::manager()?;
    let o = exact::check_manager(&initial)?;
    let phase = exact::capture_phase(&initial, sample)?.context("265 EOF absent at cutoff")?;
    let before = observe_unit(exact::UNIT, &o.iid)?;
    let after = observe_unit(exact::UNIT, &o.iid)?;
    let last = exact::manager()?;
    exact::same_snapshot(&initial, &last)?;
    ensure!(
        exact::owner(&o, &last)?
            && stable_unit(&before, &after)
            && before.main_pid == after.main_pid
            && initial["MainPID"].as_str() == Some(before.main_pid.to_string().as_str()),
        "265 finalization owner changed"
    );
    for u in [&before, &after] {
        let rss = serde_json::to_value(&u.rss)?;
        ensure!(
            rss["census_stable"] == true
                && rss["error"].is_null()
                && rss["processes"]
                    .as_array()
                    .is_some_and(|rows| rows.iter().any(|r| r["pid"] == u.main_pid)),
            "265 finalization RSS unavailable"
        );
    }
    Ok(
        serde_json::json!({"range":"265-265","resource_only":true,"post_replay_finalization":true,
        "controller_before":before,"producer_before":before,"controller_after":after,"producer_after":after,
        "phase_evidence":phase,"invocation_binding_stable":true,"useful_work":{"sufficient_for_rates":false,"entry_progress_observed":false},
        "entry_replay":false,"ordinary_replay_claim":false,"terminal_completion_proven":false,"resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}
pub(super) fn sample(clock: u64) -> Result<Value> {
    let o = exact::load()?;
    let (status, observation, error) = match observe(clock) {
        Ok(v) => ("observed", Some(v), None),
        Err(e) => ("unavailable", None, Some(format!("{e:#}"))),
    };
    Ok(
        serde_json::json!({"range":"265-265","producer_unit":exact::UNIT,"expected_producer_invocation_id":o.iid,
        "post_replay_resource_only":true,"status":status,"observation":observation,"error":error,
        "ordinary_replay_claim":false,"entry_replay":false,"terminal_completion_proven":false,"resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}
