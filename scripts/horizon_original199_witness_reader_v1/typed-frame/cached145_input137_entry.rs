//! Same-observer input137 entry comparison over independently validated guard fires.
//! Preserve raw fleets. Only exact completed cached145/199 guard metadata projects.
use super::*;

fn append_rollover(
    e: &Evidence<'_>,
    fleet: &Value,
    history_rows: &mut serde_json::Map<String, Value>,
) -> Result<()> {
    let scope: history::scope::Scope = serde_json::from_value(source(e, "scope")?.clone())?;
    scope.validate()?;
    let descriptor = &e
        .cohort183_transition
        .context("input137 cached145 descriptor absent")?["cached145"];
    history::rollover::validate(
        fleet,
        &scope,
        &descriptor["sources"]["capture"]["origin"],
        source(e, "capture")?,
        &descriptor["sources"]["first_guard_plan"]["origin"],
        source(e, "first_guard_plan")?,
    )?;
    let Some(proof) = fleet.get("cached145_guard_census_rollover") else {
        return Ok(());
    };
    for row in proof["proofs"]
        .as_array()
        .context("input137 rollover rows")?
    {
        for side in ["before", "after"] {
            let iid = row[format!("{side}_native")]["InvocationID"]
                .as_str()
                .context("input137 completed guard IID")?;
            let raw = json!({
                "binding":row[format!("{side}_raw_guard_sample")],
                "value":row[format!("{side}_raw_guard_sample_value")]
            });
            if let Some(old) = history_rows.insert(iid.into(), raw.clone()) {
                ensure!(old == raw, "input137 changes an existing raw guard witness");
            }
        }
    }
    if let Some(timers) = proof.get("timer_proofs") {
        let rows = timers.as_array().context("input137 timer proof list")?;
        let name = format!(
            "horizon-qualify-145-cached-{}-guard.timer",
            scope.attempt_id
        );
        ensure!(
            rows.len() == 1,
            "input137 rollover adds another guard timer"
        );
        let row = &rows[0];
        ensure!(
            row["unit"] == name
                && row["only_next_elapse_normalized"] == true
                && row["after_native"] == fleet["unit_census"][&name],
            "input137 timer proof differs from its genuine fleet census"
        );
        crate::cached145_timer::pair(&name, &row["before_native"], &row["after_native"])?;
    }
    Ok(())
}

pub(crate) fn existing_fleet_unchanged(
    e: &Evidence<'_>,
    projected: &Value,
    base: &Value,
) -> Result<()> {
    existing_fleet_unchanged_inner(e, projected, base, None)
}
pub(crate) fn existing_fleet_unchanged_retained(
    e: &Evidence<'_>,
    projected: &Value,
    base: &Value,
    context: &crate::terminal199_context::Retained,
) -> Result<()> {
    existing_fleet_unchanged_inner(e, projected, base, Some(context))
}
fn existing_fleet_unchanged_inner(
    e: &Evidence<'_>,
    projected: &Value,
    base: &Value,
    historical: Option<&crate::terminal199_context::Retained>,
) -> Result<()> {
    // The caller first revalidates the actual immutable accepted baseline Frame.
    let mut raw = serde_json::Map::new();
    append_rollover(e, base, &mut raw)?;
    append_rollover(e, projected, &mut raw)?;
    let old_census = base["unit_census"]
        .as_object()
        .context("input137 base native census")?;
    let new_census = projected["unit_census"]
        .as_object()
        .context("input137 entry native census")?;
    ensure!(
        old_census.keys().eq(new_census.keys()),
        "input137 changes an original native role set"
    );
    let mut current = projected.clone();
    let mut old = base.clone();
    ensure!(
        projected[ordinary199::FIELD] == base[ordinary199::FIELD]
            && projected["epoch199_promises"] == base["epoch199_promises"],
        "input137 changes the independently enrolled199 owner or promises"
    );
    let proof = match historical {
        Some(context) => ordinary199::load_for_context(&base[ordinary199::FIELD], context)?,
        None => ordinary199::load(&base[ordinary199::FIELD])?,
    };
    if let Some(proof) = proof {
        proof.revalidate_inputs()?;
        current["unit_census"] = if let Some(context) = historical {
            proof.normalize_guard_recorded_producer(
                &base["unit_census"],
                &projected["unit_census"],
                context,
            )?
        } else {
            proof.normalize_guard(&base["unit_census"], &projected["unit_census"])?
        };
        if projected["epoch199_guard_census_before"] != base["epoch199_guard_census_before"] {
            let mut before = base["unit_census"].clone();
            let mut after = projected["unit_census"].clone();
            before[ordinary199::GUARD] = base["epoch199_guard_census_before"].clone();
            after[ordinary199::GUARD] = projected["epoch199_guard_census_before"].clone();
            if let Some(context) = historical {
                proof.normalize_guard_recorded_producer(&before, &after, context)?;
            } else {
                proof.normalize_guard(&before, &after)?;
            }
            current["epoch199_guard_census_before"] = base["epoch199_guard_census_before"].clone();
        }
    }
    let normalized = guard::project(
        e,
        old_census,
        current["unit_census"]
            .as_object()
            .context("input137 normalized native census")?,
        &Value::Object(raw),
    )?;
    ensure!(
        normalized == *old_census,
        "input137 changes an original producer or unrelated native field"
    );
    current["unit_census"] = Value::Object(normalized);
    // Both optional envelopes were validated above against their authentic raw
    // samples, exact capture/plan and current census before this narrow view.
    current
        .as_object_mut()
        .context("input137 entry fleet object")?
        .remove("cached145_guard_census_rollover");
    old.as_object_mut()
        .context("input137 base fleet object")?
        .remove("cached145_guard_census_rollover");
    super::existing_fleet_unchanged(&current, &old)
}
