//! Compose an already proven retained normal fleet hop with observer-only legacy routes.
//!
//! The genuine transition, fleet bindings and output Frame remain untouched. Only the
//! in-memory legacy input view projects the exact hop after validating its full raw
//! policy, metadata, native census, source census and complete observer ancestry.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct Views {
    fleet: Value,
    plan: Value,
    transition: Value,
    sources: BTreeMap<String, Value>,
}
impl Views {
    pub(crate) fn prepare(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<Option<Self>> {
        let Some(t) = e.cohort183_transition else {
            return Ok(None);
        };
        let Some(rows) = t["observation_bridge"].as_array() else {
            return Ok(None);
        };
        if !rows
            .iter()
            .any(|row| row["schema"] == private154_downstream_history::FLEET_BRIDGE_SCHEMA)
        {
            return Ok(None);
        }
        // The complete observer-chain contract bounds current plus intermediate
        // observations to128, and retains its original freshness clock.
        ensure!(
            !rows.is_empty() && rows.len() <= crate::MAXIMUM_OBSERVATION_BRIDGE_INTERMEDIATES,
            "retained fleet composition exceeds the original observer-chain depth"
        );
        fleet_binding(
            e.fleet,
            e.fleet_plan,
            &bindings["fleet_plan"],
            &bindings["observer"],
        )?;
        ensure!(
            t["previous_recovery"] == bindings["prior_recovery"]
                && t["fleet_plan"] == bindings["fleet_plan"]
                && t["prior_fleet_plan"] == bindings["prior_fleet_plan"],
            "retained fleet composition changed its genuine bound ancestry"
        );
        let previous = e
            .prior_recovery
            .context("retained fleet composition prior Frame")?;
        let anchor = previous["bindings"]["fleet"].clone();
        let original_previous = e
            .cohort183_sources
            .get("cached145.current_previous_fleet")
            .context("retained fleet composition original accepted fleet")?;
        fleet_binding(
            original_previous,
            e.prior_fleet_plan,
            &bindings["prior_fleet_plan"],
            &previous["bindings"]["observer"],
        )?;
        // This independently checks every real fleet/plan hop, retained event,
        // policy field and native owner before any legacy projection is made.
        let (head, extra) = private154_downstream_history::retained_observation_head(e)?;
        let typed_count = rows
            .iter()
            .filter(|row| row["schema"] == private154_downstream_history::FLEET_BRIDGE_SCHEMA)
            .count();
        ensure!(
            extra
                == typed_count
                    .checked_mul(2)
                    .context("retained fleet source count overflow")?
                && extra > 0
                && e.fleet["previous_fleet"] == head
                && e.fleet_plan["previous_fleet"] == head,
            "retained fleet composition lacks exact genuine terminal fleet head"
        );
        let mut expected = BTreeSet::new();
        for (index, row) in rows.iter().enumerate() {
            expected.insert(format!("bridge.{index}.observer"));
            if row["schema"] == private154_downstream_history::FLEET_BRIDGE_SCHEMA {
                expected.insert(format!("bridge.{index}.fleet"));
                expected.insert(format!("bridge.{index}.fleet_plan"));
            }
        }
        let actual = e
            .cohort183_sources
            .keys()
            .filter(|key| key.starts_with("bridge."))
            .cloned()
            .collect::<BTreeSet<_>>();
        ensure!(
            actual == expected,
            "retained fleet composition has missing, extra or aliased bridge source roles"
        );
        let mut view = Self {
            fleet: e.fleet.clone(),
            plan: e.fleet_plan.clone(),
            transition: t.clone(),
            sources: e.cohort183_sources.clone(),
        };
        view.fleet["previous_fleet"] = anchor.clone();
        view.plan["previous_fleet"] = anchor;
        view.transition["observation_bridge"] = Value::Array(
            rows.iter()
                .map(|row| json!({"observer":row["observer"].clone()}))
                .collect(),
        );
        for (index, row) in rows.iter().enumerate() {
            if row["schema"] == private154_downstream_history::FLEET_BRIDGE_SCHEMA {
                for member in ["fleet", "fleet_plan"] {
                    view.sources
                        .remove(&format!("bridge.{index}.{member}"))
                        .context("retained fleet composition lost a proven source")?;
                }
            }
        }
        // All observer sources stay complete, genuinely captured and digest-bound.
        // The unchanged chain proves exact order, accepted anchor, owner identity,
        // non-synthetic cadence and the original 1800-second current clock.
        ensure!(
            cached145_observer_recovery::retained(&view.evidence(e), bindings, now)?,
            "retained fleet composition failed complete genuine observer recovery"
        );
        Ok(Some(view))
    }
    pub(crate) fn evidence<'a>(&'a self, e: &'a Evidence<'_>) -> Evidence<'a> {
        Evidence {
            observer: e.observer,
            fleet: &self.fleet,
            fleet_plan: &self.plan,
            prior_parent: e.prior_parent,
            prior_completion: e.prior_completion,
            prior_fleet_plan: e.prior_fleet_plan,
            transition: e.transition,
            prior_recovery: e.prior_recovery,
            fleet_transition: e.fleet_transition,
            capture_tool_sha: e.capture_tool_sha,
            native154_transition: e.native154_transition,
            cohort183_transition: Some(&self.transition),
            cohort183_sources: &self.sources,
            native154_sources: e.native154_sources,
        }
    }
}
