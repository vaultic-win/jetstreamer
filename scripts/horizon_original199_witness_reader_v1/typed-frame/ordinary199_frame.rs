//! Composes one authenticated199 delta ahead of the retained validators. Full
//! evidence and output keep the actual owner census; only legacy inputs project.
use super::*;
use crate::ordinary199::{self, Proof};

pub struct Views {
    observer: Value,
    fleet: Value,
    plan: Value,
    prior_plan: Value,
    prior_frame: Option<Value>,
    sources: std::collections::BTreeMap<String, Value>,
}
fn project_value(v: &Value) -> Result<Value> {
    match v["schema"].as_str() {
        Some("jetstreamer-horizon-campaign-fleet-v1") => ordinary199::project_fleet(v),
        Some("jetstreamer-horizon-campaign-fleet-plan-v1") => ordinary199::project_plan(v),
        Some(SCHEMA) => ordinary199::project_frame(v),
        _ => Ok(v.clone()),
    }
}
impl Views {
    pub fn prepare(e: &Evidence<'_>, proof: &Proof) -> Result<Self> {
        proof.revalidate_inputs()?;
        ensure!(
            e.fleet[ordinary199::FIELD] == serde_json::to_value(&proof.binding)?
                && e.fleet["epoch199_promises"] == proof.accounting(),
            "199 full fleet omitted/changed its real owner accounting"
        );
        proof.validate_observer(e.observer)?;
        proof.validate_native(&e.fleet["unit_census"])?;
        if !e.prior_fleet_plan[ordinary199::FIELD].is_null() {
            ensure!(
                e.prior_fleet_plan[ordinary199::FIELD] == serde_json::to_value(&proof.binding)?,
                "199 retained enrollment changed"
            );
        } else {
            ensure!(
                e.fleet["previous_fleet"] == serde_json::to_value(&proof.budget.prelaunch.fleet)?,
                "199 first coexistence lacks exact prelaunch predecessor"
            );
        }
        let sources = e
            .cohort183_sources
            .iter()
            .map(|(k, v)| Ok((k.clone(), project_value(v)?)))
            .collect::<Result<_>>()?;
        Ok(Self {
            observer: ordinary199::project_observer(e.observer)?,
            fleet: ordinary199::project_fleet(e.fleet)?,
            plan: ordinary199::project_plan(e.fleet_plan)?,
            prior_plan: ordinary199::project_plan(e.prior_fleet_plan)?,
            prior_frame: e
                .prior_recovery
                .map(ordinary199::project_frame)
                .transpose()?,
            sources,
        })
    }
    pub fn prepare_retained(
        e: &Evidence<'_>,
        proof: &Proof,
        context: &crate::terminal199_context::Retained,
    ) -> Result<Self> {
        proof.revalidate_inputs()?;
        ensure!(
            e.fleet[ordinary199::FIELD] == serde_json::to_value(&proof.binding)?
                && e.fleet["epoch199_promises"] == proof.accounting(),
            "199 full fleet omitted/changed its real owner accounting"
        );
        proof.validate_observer_retained(e.observer, context)?;
        proof.validate_native_retained(&e.fleet["unit_census"], context)?;
        if !e.prior_fleet_plan[ordinary199::FIELD].is_null() {
            ensure!(
                e.prior_fleet_plan[ordinary199::FIELD] == serde_json::to_value(&proof.binding)?,
                "199 retained enrollment changed"
            );
        } else {
            ensure!(
                e.fleet["previous_fleet"] == serde_json::to_value(&proof.budget.prelaunch.fleet)?,
                "199 first coexistence lacks exact prelaunch predecessor"
            );
        }
        let sources = e
            .cohort183_sources
            .iter()
            .map(|(k, v)| Ok((k.clone(), project_value_retained(v, context)?)))
            .collect::<Result<_>>()?;
        Ok(Self {
            observer: ordinary199::project_observer_retained(e.observer, proof, context)?,
            fleet: ordinary199::project_fleet_retained(e.fleet, context)?,
            plan: ordinary199::project_plan_for_context(e.fleet_plan, context)?,
            prior_plan: ordinary199::project_plan_for_context(e.prior_fleet_plan, context)?,
            prior_frame: e
                .prior_recovery
                .map(|frame| ordinary199::project_frame_retained(frame, context))
                .transpose()?,
            sources,
        })
    }
    pub fn evidence<'a>(&'a self, e: &'a Evidence<'_>) -> Evidence<'a> {
        Evidence {
            observer: &self.observer,
            fleet: &self.fleet,
            fleet_plan: &self.plan,
            prior_parent: e.prior_parent,
            prior_completion: e.prior_completion,
            prior_fleet_plan: &self.prior_plan,
            transition: e.transition,
            prior_recovery: self.prior_frame.as_ref(),
            fleet_transition: e.fleet_transition,
            capture_tool_sha: e.capture_tool_sha,
            cohort183_transition: e.cohort183_transition,
            cohort183_sources: &self.sources,
            native154_transition: e.native154_transition,
            native154_sources: e.native154_sources,
        }
    }
}
pub fn proof(e: &Evidence<'_>) -> Result<Option<Proof>> {
    ordinary199::load_for_plan(&e.fleet_plan[ordinary199::FIELD], e.fleet_plan)
}
pub fn proof_for_context(
    e: &Evidence<'_>,
    context: &crate::terminal199_context::Retained,
) -> Result<Option<Proof>> {
    ordinary199::load_for_context(&e.fleet_plan[ordinary199::FIELD], context)
}
pub fn validate_full_frame(frame: &Value, e: &Evidence<'_>, proof: &Proof) -> Result<()> {
    ensure!(
        frame[ordinary199::FIELD] == serde_json::to_value(&proof.binding)?
            && frame["epoch199_promises"] == proof.accounting(),
        "199 full Frame omitted actual promises"
    );
    proof.validate_native(&frame["native_census_before"])?;
    proof.validate_native(&frame["native_census_after"])?;
    let projected = proof.normalize_guard(
        &frame["native_census_before"],
        &frame["native_census_after"],
    )?;
    let a = ordinary199::project_census(&frame["native_census_before"])?;
    let b = ordinary199::project_census(&projected)?;
    ensure!(
        a == b
            || cached145_frame::guard::census_stable(e, &a, &b, &frame["cached145_guard_history"])?,
        "199 full Frame changes another native owner"
    );
    proof.revalidate_inputs()?;
    Ok(())
}

fn project_value_retained(
    v: &Value,
    context: &crate::terminal199_context::Retained,
) -> Result<Value> {
    match v["schema"].as_str() {
        Some("jetstreamer-horizon-campaign-fleet-v1") => {
            ordinary199::project_fleet_retained(v, context)
        }
        Some("jetstreamer-horizon-campaign-fleet-plan-v1") => {
            ordinary199::project_plan_for_context(v, context)
        }
        Some(SCHEMA) => ordinary199::project_frame_retained(v, context),
        _ => Ok(v.clone()),
    }
}

pub fn validate_full_frame_retained(
    frame: &Value,
    e: &Evidence<'_>,
    proof: &Proof,
    context: &crate::terminal199_context::Retained,
) -> Result<()> {
    ensure!(
        frame[ordinary199::FIELD] == serde_json::to_value(&proof.binding)?
            && frame["epoch199_promises"] == proof.accounting(),
        "199 full Frame omitted actual promises"
    );
    proof.validate_native_retained(&frame["native_census_before"], context)?;
    proof.validate_native_retained(&frame["native_census_after"], context)?;
    let projected = proof.normalize_guard_retained(
        &frame["native_census_before"],
        &frame["native_census_after"],
        context,
    )?;
    let a = ordinary199::project_census(&frame["native_census_before"])?;
    let b = ordinary199::project_census(&projected)?;
    ensure!(
        a == b
            || cached145_frame::guard::census_stable(e, &a, &b, &frame["cached145_guard_history"])?,
        "199 full Frame changes another native owner"
    );
    proof.revalidate_inputs()?;
    Ok(())
}
