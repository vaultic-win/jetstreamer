//! Typed cached145 policy layer over the unchanged recovered-resource contract.
//! Sources and native observations remain genuine; only qualified policy views project.
use super::*;
use crate::cached145_terminal_observer as terminal;

#[path = "cached145_frame_guard.rs"]
pub mod guard;
#[path = "cached145_history.rs"]
pub(super) mod history;
#[path = "cached145_input137_entry.rs"]
pub(super) mod input137_entry;
const PRIOR19: &str = "18db4e154af9b7733a6200441dd5983a30a7a441a890644486dbabab299a1919";
const PRIOR23: &str = "9526cb9110d1a08608f44b7b2e1f0334baba153ac2cae8c59ad237871d2583f5";
const PRIOR25: &str = "473b13ca865f879802d93d577aea052f0d6becc19469123392a1be763ab9a3b4";
const PRIOR26: &str = "3fa515037d632bfd7410d6b561ccb2302193ceafe73e4f64e75e3625f262931e";
const PRIOR_BUFFERED_FRAME_V4: &str =
    "6465811554ccbc97664f796d9bcce0baa361bb82febd9111ee287fdb84d32744";
const PRIOR_TYPED_BRIDGE_20261105: &str =
    "b8c5c8319ebd65d0b99ada0c2ba77efbd22b91e269f570effbc806044a1763a5";
fn prior_capture_matches(value: &Value, current: &str) -> bool {
    value == PRIOR19
        || value == PRIOR23
        || value == PRIOR25
        || value == PRIOR26
        || value == "9dd1c2b42e0ee9e99f8d575838d33347d69b3659d24340e23b14605942d16e1e"
        || value == "c97d413ab065c1a3455de336dd4009644e3eeaa0b8fb6e6559ed9a542225c377"
        || value == PRIOR_BUFFERED_FRAME_V4
        || value == "7d320b8a4f4d7e87f4fa53d5c614cf13d032760533c84db5e4802928eff8e6de"
        || value == QUALIFIED_ORDINARY199_FRAME_V5_CAPTURE_SHA
        || value == QUALIFIED_HELPER_V4_FRAME_CAPTURE_SHA
        || value == QUALIFIED_RETAINED199_V3_CAPTURE_SHA
        || value == PRIOR_TYPED_BRIDGE_20261105
        || value == QUALIFIED_CLOSED145_FAMILY_CAPTURE_SHA
        || value == QUALIFIED_SEALED_ALIAS_FRAME_CAPTURE_SHA
        // Genuine b692 image has original0728 native acceptance and normal seal.
        || value == "b692189704ed9001c016b1931ec6e54210104d36a5fbf787dfdd9d2505ae75eb"
        || value == current
}

pub fn selected(e: &Evidence<'_>) -> bool {
    e.cohort183_transition
        .is_some_and(|t| !t["cached145"].is_null())
}
pub fn entry(e: &Evidence<'_>) -> bool {
    e.cohort183_transition
        .is_some_and(|t| t["cached145"]["mode"] == "entry")
}
fn source<'a>(e: &'a Evidence<'_>, name: &str) -> Result<&'a Value> {
    e.cohort183_sources
        .get(&format!("cached145.{name}"))
        .with_context(|| format!("cached145 Frame source missing: {name}"))
}
fn as_bound(v: &Value) -> Result<history::Bound> {
    Ok(serde_json::from_value(v.clone())?)
}
fn values(e: &Evidence<'_>) -> Result<std::collections::BTreeMap<String, Value>> {
    let mut values = std::collections::BTreeMap::new();
    for name in history::SOURCES {
        values.insert(name.to_owned(), source(e, name)?.clone());
    }
    ensure!(
        e.cohort183_sources
            .keys()
            .filter(|k| k.starts_with("cached145."))
            .count()
            == history::SOURCE_COUNT + 1,
        "cached145 Frame derived source count differs"
    );
    Ok(values)
}
fn graph(e: &Evidence<'_>, bindings: &Value) -> Result<(history::Descriptor, history::Projection)> {
    let t = e
        .cohort183_transition
        .context("cached145 Frame transition absent")?;
    let d: history::Descriptor = serde_json::from_value(t["cached145"].clone())?;
    let values = values(e)?;
    let previous_transition = e
        .cohort183_sources
        .get("delivery.previous_transition")
        .context("cached145 authentic previous transition missing")?;
    let prior_descriptor = if previous_transition["cached145"].is_null() {
        None
    } else {
        Some(serde_json::from_value::<history::Descriptor>(
            previous_transition["cached145"].clone(),
        )?)
    };
    let current_plan_bound = as_bound(&bindings["fleet_plan"])?;
    let current_fleet_bound = as_bound(&bindings["fleet"])?;
    let previous_fleet = source(e, "current_previous_fleet")?;
    let projection = history::validate_and_project(&history::Graph {
        descriptor: &d,
        previous_descriptor: prior_descriptor.as_ref(),
        values: &values,
        current_plan_bound: &current_plan_bound,
        current_fleet_bound: &current_fleet_bound,
        current_plan: e.fleet_plan,
        current_fleet: e.fleet,
        previous_plan: e.prior_fleet_plan,
        previous_fleet,
    })?;
    ensure!(
        projection.parent_hard_protection_bytes == 192u64 << 30
            && projection.guard_hard_protection_bytes == 512u64 << 20
            && projection.data_retained_bytes == 337u64 << 30
            && projection.resource_credit_bytes == 0,
        "cached145 Frame history releases a promise"
    );
    Ok((d, projection))
}
fn native_same(a: &Value, b: &Value) -> bool {
    if a == b {
        return true;
    }
    let (Some(mut a), Some(mut b)) = (a.as_object().cloned(), b.as_object().cloned()) else {
        return false;
    };
    for k in [
        "DropInPaths",
        "PrivateTmp",
        "Unit",
        "TimersMonotonic",
        "TimeoutStopUSec",
    ] {
        if !a.contains_key(k) || !b.contains_key(k) {
            a.remove(k);
            b.remove(k);
        }
    }
    let (Some(ae), Some(be)) = (a.remove("ExecStart"), b.remove("ExecStart")) else {
        return false;
    };
    a == b
        && ae
            .as_str()
            .zip(be.as_str())
            .is_some_and(|(a, b)| same_exec_start_text(a, b))
}
fn status_free_epoch(v: &Value) -> Result<Value> {
    let mut v = v.as_object().context("cached145 entry epoch row")?.clone();
    v.remove("status");
    Ok(Value::Object(v))
}
pub(super) fn existing_fleet_unchanged(projected: &Value, base: &Value) -> Result<()> {
    let a = projected.as_object().context("cached145 projected fleet")?;
    let b = base.as_object().context("cached145 original fleet")?;
    ensure!(
        a.keys().eq(b.keys()),
        "cached145 entry changes fleet schema fields"
    );
    for (key, old) in b {
        let new = &a[key];
        match key.as_str() {
            "plan"
            | "plan_sha256"
            | "previous_fleet"
            | "recorded_unix_seconds"
            | "transitions"
            | "historical_debt_revalidated_unix_seconds"
            | "periodic_guard_census_before" => {}
            "unit_census" => {
                let x = new
                    .as_object()
                    .context("cached145 projected native census")?;
                let y = old
                    .as_object()
                    .context("cached145 original native census")?;
                ensure!(
                    x.keys().eq(y.keys())
                        && y.iter()
                            .all(|(k, v)| x.get(k).is_some_and(|n| native_same(n, v))),
                    "cached145 entry changes original native roles"
                );
            }
            "epochs" => {
                let x = new.as_array().context("cached145 projected epochs")?;
                let y = old.as_array().context("cached145 old epochs")?;
                ensure!(
                    x.len() == 100 && y.len() == 100,
                    "cached145 entry drops assigned epochs"
                );
                for prior in y {
                    let epoch = prior["epoch"].as_u64().context("cached145 epoch number")?;
                    let rows = x.iter().filter(|r| r["epoch"] == epoch).collect::<Vec<_>>();
                    ensure!(
                        rows.len() == 1 && status_free_epoch(rows[0])? == status_free_epoch(prior)?,
                        "cached145 entry changes gate, failure or readiness of an epoch"
                    );
                }
            }
            "pipelines" => {
                let x = new.as_array().context("cached145 current pipelines")?;
                let y = old.as_array().context("cached145 old pipelines")?;
                ensure!(
                    x.len() == y.len(),
                    "cached145 entry changes pipeline census"
                );
                for (old, new) in y.iter().zip(x) {
                    let mut old = old.clone();
                    let mut new = new.clone();
                    ensure!(
                        native_same(&old["unit"], &new["unit"]),
                        "cached145 entry changes pipeline owner"
                    );
                    old.as_object_mut()
                        .context("cached145 old pipeline")?
                        .remove("unit");
                    new.as_object_mut()
                        .context("cached145 new pipeline")?
                        .remove("unit");
                    ensure!(
                        old == new,
                        "cached145 entry changes pipeline history or phase"
                    );
                }
            }
            _ => ensure!(
                new == old,
                "cached145 entry changes undeclared fleet field: {key}"
            ),
        }
    }
    Ok(())
}
fn envelope(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<()> {
    let sample = utc_seconds(
        e.observer["recorded_at_utc"]
            .as_str()
            .context("cached145 sample time")?,
    )?;
    ensure!(
        sample <= now
            && now - sample <= 1800
            && e.observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && e.observer["cadence"]["routine_minimum_interval_enforced"] == true
            && e.observer["cadence"]["minimum_interval_seconds"] == 1800
            && e.observer["cadence"]["observed_interval_seconds"]
                .as_u64()
                .is_some_and(|n| n >= 1800),
        "cached145 Frame lacks fresh genuine routine observer"
    );
    ensure!(
        e.fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && e.fleet["first_epoch"] == 101
            && e.fleet["last_epoch"] == 200
            && e.fleet["observer_receipt"] == bindings["observer"]["path"]
            && e.fleet["observer_sha256"] == bindings["observer"]["sha256"]
            && e.fleet["sampled_at_utc"] == e.observer["recorded_at_utc"]
            && e.fleet["plan"] == bindings["fleet_plan"]["path"]
            && e.fleet["plan_sha256"] == bindings["fleet_plan"]["sha256"]
            && e.fleet_plan["observer"] == bindings["observer"]
            && e.fleet["inventory"]["anomalies"] == 0,
        "cached145 Frame fleet/sample/plan differs"
    );
    let previous = e
        .prior_recovery
        .context("cached145 prior accepted Frame absent")?;
    ensure!(
        previous["schema"] == SCHEMA
            && previous["accepted_resource_lineage"] == true
            && previous["full_routine_completion_claimed"] == false
            && previous["new_resource_observations"] == 0
            && guard::census_stable(
                e,
                &previous["native_census_before"],
                &previous["native_census_after"],
                &previous["cached145_guard_history"]
            )?
            && prior_capture_matches(&previous["self_sha256"], e.capture_tool_sha),
        "cached145 prior recovery is not an exact qualified accepted artifact"
    );
    authority_denied(previous)?;
    ensure!(
        e.prior_parent["schema"] == "jetstreamer-normal-routine-frame-parent-acceptance-v1"
            && e.prior_parent["accepted"] == true
            && e.prior_parent["completion"] == bindings["prior_completion"]
            && e.prior_parent["mandatory_cohort191_zero_credit_correction"]
                == bindings["correction191"]
            && e.prior_completion["schema"] == "jetstreamer-horizon-routine-cycle-completion-v1"
            && e.prior_completion["observer"] == e.prior_parent["observer"]
            && e.prior_completion["fleet"] == e.prior_parent["fleet"],
        "cached145 Frame loses original accepted parent/completion"
    );
    for key in [
        "prior_parent",
        "prior_completion",
        "correction191",
        "transition",
    ] {
        ensure!(
            previous["bindings"][key] == bindings[key],
            "cached145 Frame changes original authority: {key}"
        );
    }
    ensure!(
        previous["bindings"]["fleet_plan"] == bindings["prior_fleet_plan"]
            && e.fleet_transition.is_none()
            && bindings["fleet_transition"].is_null()
            && e.native154_transition.is_none()
            && bindings["native154_transition"].is_null()
            && e.native154_sources.is_empty(),
        "cached145 Frame mixes an unrelated transition"
    );
    Ok(())
}
pub fn validate(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<()> {
    envelope(e, bindings, now)?;
    let (d, p) = graph(e, bindings)?;
    let t = e.cohort183_transition.context("cached145 transition")?;
    authority_denied(t)?;
    ensure!(
        t["schema"] == REFRESH_SCHEMA
            && t["previous_recovery"] == bindings["prior_recovery"]
            && t["prior_fleet_plan"] == bindings["prior_fleet_plan"]
            && t["fleet_plan"] == bindings["fleet_plan"]
            && t["repair_incident_remains_open"] == true,
        "cached145 current transition ancestry differs"
    );
    let previous = e.prior_recovery.context("cached145 previous Frame")?;
    let old = e
        .cohort183_sources
        .get("delivery.previous_transition")
        .context("cached145 original transition source")?;
    let mut normalized_t = t.clone();
    normalized_t
        .as_object_mut()
        .context("cached145 transition object")?
        .remove("cached145");
    let mut sources = e
        .cohort183_sources
        .iter()
        .filter(|(k, _)| !k.starts_with("cached145."))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    if d.mode == "entry" {
        ensure!(
            t[terminal::FIELD].is_null(),
            "terminal ancestry cannot create a new cached145 entry"
        );
        ensure!(entry(e), "cached145 entry classifier differs");
        ensure!(
            source(e, "entry_previous_frame")? == previous
                && source(e, "entry_previous_fleet")? == source(e, "current_previous_fleet")?
                && source(e, "entry_previous_plan")? == e.prior_fleet_plan
                && source(e, "entry_observer")? == e.observer
                && previous["bindings"]["observer"] == bindings["observer"]
                && previous["sampled_at_utc"] == e.observer["recorded_at_utc"]
                && t["previous_cohort183_transition"]
                    == previous["bindings"]["cohort183_transition"],
            "cached145 entry is not the same-observer immediate accepted head"
        );
        let mut expected = old.clone();
        for key in [
            "previous_recovery",
            "prior_fleet_plan",
            "fleet_plan",
            "previous_cohort183_transition",
        ] {
            expected[key] = t[key].clone();
        }
        ensure!(
            normalized_t == expected,
            "cached145 entry changes original141/G6/G7 or another prior history"
        );
        existing_fleet_unchanged(&p.current_fleet, &p.previous_fleet)?;
        // The accepted previous Frame remains the historical base. Every original native
        // role is also independently revalidated by validate_frame on the genuine view.
        validate_refresh_owners(
            &Evidence {
                observer: e.observer,
                fleet: &p.current_fleet,
                fleet_plan: &p.current_plan,
                prior_parent: e.prior_parent,
                prior_completion: e.prior_completion,
                prior_fleet_plan: &p.previous_plan,
                transition: e.transition,
                prior_recovery: e.prior_recovery,
                fleet_transition: e.fleet_transition,
                capture_tool_sha: e.capture_tool_sha,
                cohort183_transition: Some(&normalized_t),
                cohort183_sources: &sources,
                native154_transition: e.native154_transition,
                native154_sources: e.native154_sources,
            },
            utc_seconds(
                e.observer["recorded_at_utc"]
                    .as_str()
                    .context("cached145 entry time")?,
            )?,
        )?;
    } else {
        let recovered = super::cached145_observer_recovery::retained(e, bindings, now)?;
        ensure!(
            d.mode == "retained"
                && previous["bindings"]["fleet"] == e.fleet["previous_fleet"]
                && e.fleet_plan["previous_fleet"] == previous["bindings"]["fleet"]
                && (recovered
                    || (e.observer["cadence"]["previous_sample"]
                        == previous["bindings"]["observer"]["path"]
                        && e.observer["cadence"]["previous_sample_sha256"]
                            == previous["bindings"]["observer"]["sha256"]
                        && utc_seconds(
                            e.observer["recorded_at_utc"]
                                .as_str()
                                .context("cached145 current UTC")?
                        )? == utc_seconds(
                            previous["sampled_at_utc"]
                                .as_str()
                                .context("cached145 previous UTC")?
                        )?
                        .checked_add(1800)
                        .context("cached145 cadence overflow")?
                        && t["observation_bridge"].is_null())),
            "cached145 retained refresh is not a genuine direct 1800-second successor"
        );
        if !t[terminal::FIELD].is_null() {
            ensure!(
                recovered,
                "terminal ancestry descriptor lacks its complete observer proof"
            );
            normalized_t
                .as_object_mut()
                .context("terminal transition object")?
                .remove(terminal::FIELD);
            sources.retain(|key, _| key != "terminal145.capture" && key != "terminal145.terminal");
        }
        if !t[crate::cached145_inactive_timer_reload::FIELD].is_null() {
            crate::cached145_inactive_timer_reload::validate(&t[crate::cached145_inactive_timer_reload::FIELD], e.cohort183_sources)?;
            ensure!(!t[terminal::FIELD].is_null(), "inactive timer reload requires exact terminal ancestry");
            normalized_t.as_object_mut().context("timer reload transition object")?.remove(crate::cached145_inactive_timer_reload::FIELD);
            sources.retain(|key, _| !key.starts_with("reload145."));
        }
        let old = sources
            .get_mut("delivery.previous_transition")
            .context("cached145 previous transition")?;
        old.as_object_mut()
            .context("cached145 old transition object")?
            .remove("cached145");
        if !old[terminal::FIELD].is_null() {
            terminal::Witness::descriptor_matches(&old[terminal::FIELD])?;
            old.as_object_mut()
                .context("terminal previous transition object")?
                .remove(terminal::FIELD);
        }
        if !old[crate::cached145_inactive_timer_reload::FIELD].is_null() {
            ensure!(old[crate::cached145_inactive_timer_reload::FIELD] == t[crate::cached145_inactive_timer_reload::FIELD], "inactive timer reload source changed across retained transition");
            crate::cached145_inactive_timer_reload::descriptor_matches(&old[crate::cached145_inactive_timer_reload::FIELD])?;
            old.as_object_mut().context("old reload descriptor object")?.remove(crate::cached145_inactive_timer_reload::FIELD);
        }
        // The typed guard witness was validated against the genuine predecessor.
        // Give the legacy validator only its explicitly qualified stable view.
        let mut stable_previous = previous.clone();
        stable_previous["native_census_after"] = stable_previous["native_census_before"].clone();
        validate_evidence_without_cached145(
            &Evidence {
                observer: e.observer,
                fleet: &p.current_fleet,
                fleet_plan: &p.current_plan,
                prior_parent: e.prior_parent,
                prior_completion: e.prior_completion,
                prior_fleet_plan: &p.previous_plan,
                transition: e.transition,
                prior_recovery: Some(&stable_previous),
                fleet_transition: e.fleet_transition,
                capture_tool_sha: e.capture_tool_sha,
                cohort183_transition: Some(&normalized_t),
                cohort183_sources: &sources,
                native154_transition: e.native154_transition,
                native154_sources: e.native154_sources,
            },
            bindings,
            now,
        )?;
    }
    Ok(())
}
pub fn validate_native(e: &Evidence<'_>, actual: &serde_json::Map<String, Value>) -> Result<()> {
    if !selected(e) {
        return Ok(());
    }
    let t = e
        .cohort183_transition
        .context("cached145 native transition")?;
    let cap = source(e, "capture")?;
    let scope: history::scope::Scope = serde_json::from_value(source(e, "scope")?.clone())?;
    let u = scope.unit()?;
    let current = &e.fleet["unit_census"][&u];
    let n = &actual[&u];
    ensure!(
        native_same(current, n),
        "cached145 actual producer owner changed since fleet capture"
    );
    let rows = e.fleet["diagnostics"]
        .as_array()
        .context("cached145 native diagnostic rows")?
        .iter()
        .filter(|r| r["unit"]["Id"] == u)
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1
            && rows[0][history::FIELD]["invocation_id"] == cap["owner"]["invocation_id"]
            && rows[0][history::FIELD]["guard_hard_limit_protected_bytes"] == 512u64 << 20
            && rows[0][history::FIELD]["DATA_retained_bytes"] == 337u64 << 30,
        "cached145 native row lost independent resource promise"
    );
    for name in [
        u.clone(),
        format!(
            "horizon-qualify-145-cached-{}-guard.service",
            scope.attempt_id
        ),
        format!(
            "horizon-qualify-145-cached-{}-guard.timer",
            scope.attempt_id
        ),
        format!(
            "horizon-qualify-145-cached-{}-stop.service",
            scope.attempt_id
        ),
    ] {
        ensure!(
            actual.get(&name).is_some(),
            "cached145 Frame native census omits a protected role"
        );
    }
    ensure!(
        !t["cached145"].is_null(),
        "cached145 native history unexpectedly absent"
    );
    Ok(())
}

#[cfg(test)]
#[path = "cached145_frame_tests.rs"]
mod tests;

#[cfg(test)]
mod cached145_prior23_transition_tests {
    use super::*;
    #[test]
    fn qualified_buffered_v4_remains_accepted_as_prior_after_current_image_changes() {
        let successor = "a".repeat(64);
        let prior = "6465811554ccbc97664f796d9bcce0baa361bb82febd9111ee287fdb84d32744";
        assert_ne!(prior, successor);
        assert!(prior_capture_matches(&json!(prior), &successor));
        assert!(prior_capture_matches(&json!(successor), &successor));
        assert!(prior_capture_matches(&json!(PRIOR19), &successor));
        assert!(prior_capture_matches(&json!(PRIOR23), &successor));
        assert!(prior_capture_matches(&json!(PRIOR25), &successor));
        assert!(prior_capture_matches(&json!(PRIOR26), &successor));
        assert!(!prior_capture_matches(&json!("b".repeat(64)), &successor));
        assert!(!prior_capture_matches(&Value::Null, &successor));
    }
    #[test]
    fn exact_qualified_prior23_is_retained_without_accepting_foreign_artifacts() {
        let current = "a".repeat(64);
        assert!(prior_capture_matches(&json!(PRIOR23), &current));
        assert!(prior_capture_matches(&json!(PRIOR25), &current));
        assert!(prior_capture_matches(&json!(PRIOR19), &current));
        assert!(prior_capture_matches(
            &json!("9dd1c2b42e0ee9e99f8d575838d33347d69b3659d24340e23b14605942d16e1e"),
            &current
        ));
        assert!(prior_capture_matches(&json!(current), &current));
        assert!(!prior_capture_matches(&json!("b".repeat(64)), &current));
        assert!(!prior_capture_matches(&Value::Null, &current));
    }
}

#[cfg(test)]
#[path = "qualified_previous_ordinary199_v5_tests.rs"]
mod qualified_previous_ordinary199_v5_tests;

#[cfg(test)]
mod terminal_ancestry_prior_artifact_tests {
    use super::*;
    #[test]
    fn genuine_previous_typed_capture_remains_accepted_after_new_current_image() {
        let current = "a".repeat(64);
        assert!(prior_capture_matches(
            &json!(PRIOR_TYPED_BRIDGE_20261105),
            &current
        ));
        assert!(!prior_capture_matches(&json!("b".repeat(64)), &current));
    }
}
