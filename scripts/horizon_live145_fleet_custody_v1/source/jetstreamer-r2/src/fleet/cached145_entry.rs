//! Exact cached145 same-observer entry over an authenticated inherited plan.
//! Policy projection is local; genuine plan/native receipts remain unchanged.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Entry,
    Retained,
}
struct Selection {
    mode: Mode,
    claim: DiagnosticClaim,
    family: Vec<String>,
}
pub(super) struct Validated {
    inherited: Plan,
    inherited_bound: BoundFile,
    previous: Value,
    selection: Selection,
    live145_plan: Value,
    observer_recovery: Option<super::retained_observer_chain::Proof>,
    ordinary199: Option<ordinary199::Proof>,
    recovery199: Option<recovery199_contract::Proof>,
    terminal199_context: Option<terminal199_context::Retained>,
}
fn family(unit: &str) -> Result<Vec<String>> {
    let stem = unit
        .strip_suffix(".service")
        .context("cached145 entry producer suffix")?;
    Ok(vec![
        unit.to_owned(),
        format!("{stem}-guard.service"),
        format!("{stem}-guard.timer"),
        format!("{stem}-stop.service"),
    ])
}
fn cached_claims(plan: &Value) -> Result<Vec<DiagnosticClaim>> {
    plan["diagnostics"]
        .as_array()
        .context("cached145 entry complete diagnostic claims")?
        .iter()
        .map(|r| serde_json::from_value::<DiagnosticClaim>(r.clone()).map_err(Into::into))
        .collect::<Result<Vec<_>>>()
        .map(|v| v.into_iter().filter(cached145::namespace).collect())
}
/// The production route selector, also exercised against the complete authentic
/// baseline in tests. It is evaluated before generic metadata/admission routing.
fn same_claim(a: &DiagnosticClaim, b: &DiagnosticClaim) -> bool {
    a.epoch == b.epoch
        && a.unit == b.unit
        && a.invocation_id == b.invocation_id
        && a.scratch_path == b.scratch_path
        && a.launch_receipt == b.launch_receipt
}
fn projected_policy(
    plan: &Value,
    baseline: &Value,
    claim: &DiagnosticClaim,
    family: &[String],
) -> Result<Value> {
    let old_names = baseline["tracked_units"]
        .as_array()
        .context("cached145 inherited tracked units")?;
    let names = plan["tracked_units"]
        .as_array()
        .context("cached145 current tracked units")?;
    ensure!(
        names.len() == old_names.len() + 4
            && family
                .iter()
                .all(|name| !old_names.iter().any(|v| v == name)
                    && names.iter().filter(|v| *v == name).count() == 1),
        "cached145 policy does not retain exactly one independent four-role family"
    );
    let mut p = plan.clone();
    p["tracked_units"]
        .as_array_mut()
        .context("cached145 tracked projection")?
        .retain(|v| !family.iter().any(|n| v == n));
    let diagnostics = p["diagnostics"]
        .as_array_mut()
        .context("cached145 diagnostic projection")?;
    ensure!(
        diagnostics
            .iter()
            .filter(|v| v["unit"] == claim.unit)
            .count()
            == 1,
        "cached145 duplicate or absent retained claim"
    );
    diagnostics.retain(|v| v["unit"] != claim.unit);
    p["admission_transition_guard"] = Value::Null;
    for clock in ["observer", "output", "previous_fleet"] {
        p[clock] = baseline[clock].clone();
    }
    ensure!(
        p == *baseline,
        "cached145 policy changes another inherited gate, claim, field or metadata head"
    );
    Ok(p)
}
#[cfg(test)]
fn select(
    previous: &Value,
    prior_plan: &Value,
    baseline: &Value,
    next: &Value,
    sample: &str,
) -> Result<Option<Selection>> {
    select_with_chain(previous, prior_plan, baseline, next, sample, false)
}
fn select_with_chain(
    previous: &Value,
    prior_plan: &Value,
    baseline: &Value,
    next: &Value,
    sample: &str,
    complete_recovery_chain: bool,
) -> Result<Option<Selection>> {
    let mut candidates = cached_claims(next)?;
    if candidates.is_empty() {
        return Ok(None);
    }
    ensure!(
        candidates.len() == 1,
        "cached145 route requires one exact independent candidate"
    );
    let claim = candidates.pop().context("cached145 candidate")?;
    let prior = cached_claims(prior_plan)?;
    let mode = if next["admission_transition_guard"].is_null() {
        if prior.is_empty() {
            return Ok(None);
        }
        ensure!(
            prior.len() == 1 && same_claim(&prior[0], &claim),
            "cached145 retained route crosses original owner/capture"
        );
        Mode::Retained
    } else {
        ensure!(
            prior.is_empty(),
            "cached145 entry repeats a prior admission"
        );
        Mode::Entry
    };
    ensure!(
        previous["schema"] == SCHEMA
            && previous["first_epoch"] == 101
            && previous["last_epoch"] == 200
            && previous["inventory"]["anomalies"] == 0
            && baseline["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
            && next["schema"] == baseline["schema"]
            && next["first_epoch"] == 101
            && next["last_epoch"] == 200
            && next["metadata_event"] == baseline["metadata_event"]
            && prior_plan["metadata_event"] == baseline["metadata_event"],
        "cached145 route crosses scope or inherited metadata head"
    );
    let attempt = claim
        .unit
        .strip_prefix("horizon-qualify-145-cached-")
        .and_then(|v| v.strip_suffix(".service"))
        .context("cached145 exact producer family")?;
    ensure!(
        claim.invocation_id.len() == 32
            && claim
                .invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && claim.scratch_path
                == Path::new(&format!(
                    "/home/sol/.jetstreamer-private/epoch145-cached-{attempt}/work"
                ))
            && claim.launch_receipt.path
                == Path::new(&format!(
                    "/var/lib/jetstreamer/epoch145-cached-{attempt}/receipts/capture.json"
                )),
        "cached145 claim crosses original IID or capture namespace"
    );
    let family = family(&claim.unit)?;
    projected_policy(next, baseline, &claim, &family)?;
    match mode {
        Mode::Entry => {
            ensure!(
                *prior_plan == *baseline
                    && previous["admission_transition_guard"].is_null()
                    && previous["sampled_at_utc"] == sample
                    && next["observer"] == baseline["observer"]
                    && next["observer"]["path"] == previous["observer_receipt"]
                    && next["observer"]["sha256"] == previous["observer_sha256"]
                    && family
                        .iter()
                        .all(|n| previous["unit_census"].get(n).is_none()),
                "cached145 entry crosses its exact same-observer original baseline"
            );
        }
        Mode::Retained => {
            projected_policy(prior_plan, baseline, &claim, &family)?;
            let predecessor = utc_seconds(
                previous["sampled_at_utc"]
                    .as_str()
                    .context("cached145 prior clock")?,
            )?;
            let recovered = complete_recovery_chain
                && utc_seconds(sample)?
                    >= predecessor
                        .checked_add(1800)
                        .context("cached145 recovery clock overflow")?;
            ensure!(
                (recovered
                    || utc_seconds(sample)?
                        == utc_seconds(
                            previous["sampled_at_utc"]
                                .as_str()
                                .context("cached145 retained predecessor UTC")?
                        )?
                        .checked_add(1800)
                        .context("cached145 cadence overflow")?)
                    && prior_plan["observer"]["path"] == previous["observer_receipt"]
                    && prior_plan["observer"]["sha256"] == previous["observer_sha256"],
                "cached145 retained route is not a genuine direct 1800-second successor"
            );
        }
    }
    Ok(Some(Selection {
        mode,
        claim,
        family,
    }))
}

pub(super) fn prepare(p: &Plan, pb: &BoundFile, sample: &str) -> Result<Option<Validated>> {
    prepare_inner(p, pb, sample, None)
}
pub(super) fn prepare_cold185(
    p: &Plan,
    pb: &BoundFile,
    sample: &str,
    route: &cold185::enrollment::FleetRoute,
) -> Result<Option<Validated>> {
    prepare_inner(p, pb, sample, Some(route))
}
fn prepare_inner(
    p: &Plan,
    pb: &BoundFile,
    sample: &str,
    route: Option<&cold185::enrollment::FleetRoute>,
) -> Result<Option<Validated>> {
    let current_has_cached = p.diagnostics.iter().any(cached145::namespace);
    let Some(previous_bound) = p.previous_fleet.as_ref() else {
        ensure!(
            !current_has_cached,
            "cached145 scope lacks original predecessor"
        );
        return Ok(None);
    };
    let previous = bound_json(previous_bound)?;
    let previous = if let Some(route) = route {
        route.legacy_previous(&previous)?
    } else {
        previous
    };
    let previous_has_cached = previous["diagnostics"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|r| {
            r["cached145_resource_promise"]["schema"]
                == "jetstreamer-epoch145-cached-independent-resource-promise-v1"
        });
    if !current_has_cached {
        ensure!(
            !previous_has_cached,
            "cached145 retained diagnostic cannot disappear from monitoring"
        );
        return Ok(None);
    }
    let prior_bound: BoundFile =
        serde_json::from_value(json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}))?;
    let prior_raw = bound_json(&prior_bound)?;
    let prior_raw = if let Some(route) = route {
        route.projected_plan(&prior_raw)?
    } else {
        prior_raw
    };
    let next_raw = bound_json(pb)?;
    let next_raw = if let Some(route) = route {
        route.projected_plan(&next_raw)?
    } else {
        next_raw
    };
    super::live145_fleet::continuity(&prior_raw,&next_raw)?;
    let live145_plan=next_raw.clone();
    let prior_raw=super::live145_fleet::plan(&prior_raw)?;
    let next_raw=super::live145_fleet::plan(&next_raw)?;
    let prior_plan = ordinary199::project_plan(&recovery199_contract::project_plan(&prior_raw)?)?;
    let next = ordinary199::project_plan(&recovery199_contract::project_plan(&next_raw)?)?;
    let mut candidates = cached_claims(&next)?;
    ensure!(
        candidates.len() == 1,
        "cached145 route has multiple independent claims"
    );
    let claim = candidates.pop().context("cached145 original candidate")?;
    let capture = bound_json(&claim.launch_receipt)?;
    cached145::launch(&capture, &claim)?;
    let work_plan = bound_json(&serde_json::from_value(capture["plan"].clone())?)?;
    let admission = bound_json(&serde_json::from_value(
        work_plan["parent_admission"].clone(),
    )?)?;
    let admitted_bound: BoundFile = serde_json::from_value(admission["fleet"].clone())?;
    let admitted = bound_json(&admitted_bound)?;
    let inherited_bound: BoundFile =
        serde_json::from_value(json!({"path":admitted["plan"],"sha256":admitted["plan_sha256"]}))?;
    let baseline = bound_json(&inherited_bound)?;
    ensure!(
        next["previous_fleet"] == serde_json::to_value(previous_bound)?,
        "cached145 predecessor tuple differs"
    );
    let observer_recovery = if next["admission_transition_guard"].is_null()
        && !cached_claims(&prior_plan)?.is_empty()
    {
        super::retained_observer_chain::recovery(p, &previous, sample)?
    } else {
        None
    };
    let selection = select_with_chain(
        &previous,
        &prior_plan,
        &baseline,
        &next,
        sample,
        observer_recovery.is_some(),
    )?
    .context("cached145 route lost its original candidate")?;
    if selection.mode == Mode::Entry {
        ensure!(
            *previous_bound == admitted_bound,
            "cached145 entry borrowed another admitted baseline"
        );
    } else {
        super::cached145_retained::authenticate(
            &selection.claim,
            &capture,
            &previous,
            &baseline,
            &admitted_bound,
        )?;
        let observer = bound_json(&p.observer)?;
        ensure!(
            observer_recovery.is_some()
                || (observer["cadence"]["previous_sample"] == previous["observer_receipt"]
                    && observer["cadence"]["previous_sample_sha256"]
                        == previous["observer_sha256"]
                    && observer["cadence"]["routine_minimum_interval_enforced"] == true),
            "cached145 retained observer is not the genuine predecessor-bound routine sample"
        );
    }
    Ok(Some(Validated {
        inherited: serde_json::from_value(baseline)?,
        inherited_bound,
        previous,
        selection,
        live145_plan,
        observer_recovery,
        ordinary199: ordinary199::load(&serde_json::to_value(&p.epoch199_enrollment)?)?,
        recovery199: recovery199_contract::load_plan(&bound_json(pb)?)?,
        terminal199_context: p
            .epoch199_terminal_context
            .as_ref()
            .map(|b| {
                terminal199_context::Retained::load(&serde_json::from_value(serde_json::to_value(
                    b,
                )?)?)
            })
            .transpose()?,
    }))
}

impl Validated {
    pub(super) fn revalidate_observer_chain(&self) -> Result<()> {
        if let Some(proof) = &self.observer_recovery {
            proof.revalidate()?;
        }
        Ok(())
    }

    pub(super) fn inherited(&self) -> (&Plan, &BoundFile) {
        (&self.inherited, &self.inherited_bound)
    }
    pub(super) fn predecessor(
        &self,
        previous: &Value,
        p: &Plan,
        sample: &str,
        now: u64,
    ) -> Result<()> {
        ensure!(
            *previous == self.previous,
            "cached145 authenticated predecessor changed"
        );
        if self.selection.mode == Mode::Retained {
            self.revalidate_observer_chain()?;
            return validate_previous_fleet(previous, p.first_epoch, p.last_epoch, sample);
        }
        let gb = p
            .admission_transition_guard
            .as_ref()
            .context("cached145 first protective guard binding")?;
        let guard = bound_json(gb)?;
        let guard_plan = bound_json(&serde_json::from_value(
            json!({"path":guard["plan"],"sha256":guard["plan_sha256"]}),
        )?)?;
        // The existing generic validator retains all guard/source/freshness gates.
        validate_same_sample_admission(previous, p, sample, &guard, &guard_plan, now)
    }
    pub(super) fn inherited_previous(&self) -> Result<Value> {
        let mut previous = if let Some(context) = &self.terminal199_context {
            ordinary199::project_fleet_retained(
                &recovery199_contract::project_fleet(&self.previous)?,
                context,
            )?
        } else {
            ordinary199::project_fleet(&recovery199_contract::project_fleet(&self.previous)?)?
        };
        if self.selection.mode == Mode::Retained {
            let census = previous["unit_census"]
                .as_object_mut()
                .context("cached145 retained predecessor census")?;
            for n in &self.selection.family {
                ensure!(
                    census.remove(n).is_some(),
                    "cached145 retained predecessor drops protected role"
                );
            }
            previous["diagnostics"]
                .as_array_mut()
                .context("cached145 retained predecessor diagnostics")?
                .retain(|r| r["unit"]["Id"] != self.selection.claim.unit);
            previous["active"]
                .as_array_mut()
                .context("cached145 retained predecessor active list")?
                .retain(|r| {
                    !(r["epoch"] == 145 && r["producer"]["Id"] == self.selection.claim.unit)
                });
            previous["admission_transition_guard"] = Value::Null;
        }
        super::live145_fleet::previous(&self.live145_plan,&previous)
    }
    pub(super) fn inherited_native(
        &self,
        actual: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>> {
        let native = actual
            .get(&self.selection.claim.unit)
            .context("cached145 actual held owner omitted")?;
        if native["ActiveState"] == "active" && native["SubState"] == "running" {
            let inspection = cached145::validate_live(&self.selection.claim, native)?;
            ensure!(
                self.selection.mode == Mode::Retained
                    || inspection["phase"] == "held-before-parent-exec",
                "cached145 same-observer entry already executed its parent"
            );
        } else {
            ensure!(
                self.selection.mode == Mode::Retained,
                "cached145 entry is not held and running"
            );
            super::cached145_retained::terminal_native(&self.selection.claim, native)?;
        }
        let recovery_view: BTreeMap<String, Value> = if let Some(p) = &self.recovery199 {
            p.validate_native(&serde_json::to_value(actual)?)?;
            serde_json::from_value(recovery199_contract::project_census(
                &serde_json::to_value(actual)?,
            )?)?
        } else {
            actual.clone()
        };
        let actual = &recovery_view;
        let actual = if let Some(proof) = &self.ordinary199 {
            if let Some(context) = &self.terminal199_context {
                proof.validate_native_retained(&serde_json::to_value(actual)?, context)?;
            } else {
                proof.validate_native(&serde_json::to_value(actual)?)?;
            }
            serde_json::from_value(ordinary199::project_census(&serde_json::to_value(actual)?)?)?
        } else {
            ensure!(
                !ordinary199::FAMILY
                    .iter()
                    .any(|name| actual.contains_key(*name)),
                "199 actual owner lacks authenticated enrollment"
            );
            actual.clone()
        };
        let previous=super::live145_fleet::previous(&self.live145_plan,&self.previous)?;
        project_inherited_native_retained(
            &actual,
            &previous,
            &self.selection.family,
            self.terminal199_context.as_ref(),
        )
    }
}
// Call only after authenticating the cached capture and its actual live/terminal
// owner. The projection may remove that exact family and no inherited actor.
#[cfg(test)]
fn project_inherited_native(
    actual: &BTreeMap<String, Value>,
    previous: &Value,
    family: &[String],
) -> Result<BTreeMap<String, Value>> {
    project_inherited_native_retained(actual, previous, family, None)
}
fn project_inherited_native_retained(
    actual: &BTreeMap<String, Value>,
    previous: &Value,
    family: &[String],
    terminal: Option<&terminal199_context::Retained>,
) -> Result<BTreeMap<String, Value>> {
    let projected_previous = if let Some(context) = terminal {
        ordinary199::project_fleet_retained(
            &recovery199_contract::project_fleet(previous)?,
            context,
        )?
    } else {
        ordinary199::project_fleet(&recovery199_contract::project_fleet(previous)?)?
    };
    let mut projected = actual.clone();
    for name in family {
        ensure!(
            projected.remove(name).is_some(),
            "cached145 protected role omitted from actual census"
        );
    }
    let expected = projected_previous["unit_census"]
        .as_object()
        .context("cached145 inherited complete native census")?;
    let expected = expected
        .keys()
        .filter(|n| !family.contains(n))
        .collect::<Vec<_>>();
    ensure!(
        projected.keys().eq(expected.into_iter()),
        "cached145 projection removes or adds another actual actor"
    );
    Ok(projected)
}

#[cfg(test)]
#[path = "cached145_entry_tests.rs"]
mod tests;
