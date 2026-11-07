//! Existing metadata history pattern for three fixed observational artifact roles.
//! Runtime image authorization remains exclusively in C; this contract grants none.
use super::*;
use private154_downstream_roles_pure::{self as roles, Role};
pub const KEY: &str = "private154_downstream_roles";
pub const MEMBERS: [&str; 6] = [
    "event",
    "role_plan",
    "previous_plan",
    "previous_fleet",
    "entry_plan",
    "entry_fleet",
];
pub const SCHEMA: &str = "jetstreamer-recovered-private154-downstream-role-history-v1";
pub struct Validated {
    pub metadata_event: Value,
    pub previous_metadata_event: Value,
    pub previous_fleet: Value,
    pub events: Vec<Value>,
}
pub fn descriptor<'a>(e: &'a Evidence<'_>) -> Option<&'a Value> {
    e.cohort183_transition
        .and_then(|t| t.get(KEY))
        .filter(|h| !h.is_null())
}
fn source<'a>(e: &'a Evidence<'_>, role: &str, member: &str) -> Result<&'a Value> {
    e.cohort183_sources
        .get(&format!("private154_downstream.{role}.{member}"))
        .with_context(|| format!("downstream history source {role}.{member}"))
}
fn origin<'a>(h: &'a Value, role: &str, member: &str) -> Result<&'a Value> {
    let pair = &h["sources"][format!("{role}.{member}")];
    ensure!(
        pair.as_object().is_some_and(|o| o.len() == 2
            && o.contains_key("origin")
            && o.contains_key("preserved")),
        "downstream history source pair differs"
    );
    let _: Bound = serde_json::from_value(pair["origin"].clone())?;
    let _: Bound = serde_json::from_value(pair["preserved"].clone())?;
    ensure!(
        pair["origin"]["sha256"] == pair["preserved"]["sha256"],
        "downstream preserved source bytes differ"
    );
    Ok(&pair["origin"])
}
pub fn latest<'a>(e: &'a Evidence<'_>) -> Result<Option<(&'a Value, &'a Value)>> {
    let Some(h) = descriptor(e) else {
        return Ok(None);
    };
    let role = h["roles"]
        .as_array()
        .and_then(|r| r.last())
        .and_then(Value::as_str)
        .context("downstream last role")?;
    Ok(Some((origin(h, role, "event")?, source(e, role, "event")?)))
}
pub fn previous_metadata_event(e: &Evidence<'_>) -> Result<Option<Value>> {
    let Some((binding, event)) = latest(e)? else {
        return Ok(None);
    };
    Ok(Some(if descriptor(e).unwrap()["mode"] == "entry" {
        event["previous_metadata_event"].clone()
    } else {
        binding.clone()
    }))
}
pub fn source_count(e: &Evidence<'_>) -> Result<usize> {
    Ok(descriptor(e).map_or(0, |h| {
        h["sources"].as_object().map_or(0, serde_json::Map::len)
    }))
}
pub fn validate(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<Option<Validated>> {
    let Some(h) = descriptor(e) else {
        ensure!(
            !e.cohort183_sources
                .keys()
                .any(|k| k.starts_with("private154_downstream.")),
            "downstream sources lack descriptor"
        );
        return Ok(None);
    };
    let sequence = h["roles"].as_array().context("downstream history roles")?;
    let expected = ["collect", "import", "deliver"];
    ensure!(
        h["schema"] == SCHEMA
            && h.as_object().is_some_and(|o| o.len() == 4)
            && (1..=3).contains(&sequence.len())
            && sequence.iter().zip(expected).all(|(a, b)| a == b)
            && h["sources"]
                .as_object()
                .is_some_and(|o| (MEMBERS.len() * sequence.len()
                    ..=(MEMBERS.len() + 1) * sequence.len())
                    .contains(&o.len())),
        "downstream history broadens, duplicates or reorders closed roles"
    );
    let mut prior_event: Option<Value> = None;
    let mut captured = Vec::new();
    let mut origins = 0usize;
    for (index, name) in sequence.iter().enumerate() {
        let name = name.as_str().unwrap();
        let role = Role::parse(name)?;
        for member in MEMBERS {
            origin(h, name, member)?;
            source(e, name, member)?;
        }
        let event = source(e, name, "event")?;
        let plan = source(e, name, "role_plan")?;
        ensure!(
            event["role"] == name
                && event["role_plan"] == *origin(h, name, "role_plan")?
                && event["claim"]["evidence"][0] == *origin(h, name, "role_plan")?,
            "downstream claim changed role plan"
        );
        let origin_receipt = if event["live_origin"].is_null() {
            ensure!(
                h["sources"][format!("{name}.live_origin")].is_null(),
                "live downstream role has an undeclared collected origin"
            );
            Value::Null
        } else {
            ensure!(
                event["live_origin"] == *origin(h, name, "live_origin")?,
                "collected downstream origin binding differs"
            );
            origins += 1;
            source(e, name, "live_origin")?.clone()
        };
        roles::validate_event_with_origin(
            event,
            origin(h, name, "role_plan")?,
            &event["artifact_image"],
            &origin_receipt,
        )?;
        ensure!(
            plan["schema"].as_str().is_some_and(|s| matches!(
                s,
                "jetstreamer-private154-publication-evidence-plan-v1"
                    | "jetstreamer-exact154-v4-publication-plan-v1"
                    | "jetstreamer-exact154-single-delivery-plan-v1"
            )),
            "downstream role plan has foreign source shape"
        );
        let old = source(e, name, "previous_plan")?;
        let old_fleet = source(e, name, "previous_fleet")?;
        let next = source(e, name, "entry_plan")?;
        let entry = source(e, name, "entry_fleet")?;
        ensure!(
            event["previous_plan"] == *origin(h, name, "previous_plan")?
                && event["previous_fleet"] == *origin(h, name, "previous_fleet")?,
            "downstream event crossed actual predecessor"
        );
        if let Some(previous) = &prior_event {
            ensure!(
                event["previous_metadata_event"] == *previous,
                "downstream role event skipped an accepted head"
            );
        } else {
            ensure!(
                event["previous_metadata_event"]
                    == json!({"path":private154_plugin_terminal_pure::OUTPUT,
            "sha256":e.cohort183_transition.unwrap()[private154_plugin_history::KEY]["sources"]["event"]["origin"]["sha256"]}),
                "downstream first role does not follow genuine plugin terminal"
            );
        }
        roles::validate_delta(old, next, event, origin(h, name, "event")?)?;
        fleet_binding(
            old_fleet,
            old,
            origin(h, name, "previous_plan")?,
            &old["observer"],
        )?;
        fleet_binding(
            entry,
            next,
            origin(h, name, "entry_plan")?,
            &old["observer"],
        )?;
        ensure!(
            entry["metadata_event"] == *origin(h, name, "event")?
                && entry["metadata_only"] == true
                && entry["resource_admission_authorized"] == false
                && entry["sampled_at_utc"] == old_fleet["sampled_at_utc"],
            "downstream entry creates resource or publication authority"
        );
        let current = &e.fleet["unit_census"][role.unit()];
        roles::validate_observed_native(current, event)?;
        if index + 1 < sequence.len() {
            ensure!(
                current["MainPID"] == "0",
                "sequential downstream roles overlap"
            );
        }
        prior_event = Some(origin(h, name, "event")?.clone());
        captured.push(event.clone());
    }
    ensure!(
        h["sources"].as_object().unwrap().len() == MEMBERS.len() * sequence.len() + origins,
        "downstream role history source census differs"
    );
    let (head, event) = latest(e)?.unwrap();
    let name = sequence.last().unwrap().as_str().unwrap();
    let old_t = e
        .cohort183_sources
        .get("delivery.previous_transition")
        .context("downstream previous transition")?;
    let previous_fleet = if h["mode"] == "entry" {
        let at = event["recorded_unix_seconds"]
            .as_u64()
            .context("downstream event clock")?;
        ensure!(
            at <= now
                && now - at <= 1800
                && bindings["prior_fleet_plan"] == *origin(h, name, "previous_plan")?
                && *e.prior_fleet_plan == *source(e, name, "previous_plan")?
                && e.prior_recovery
                    .context("downstream prior resource frame")?["bindings"]["fleet"]
                    == *origin(h, name, "previous_fleet")?,
            "downstream initial adoption is stale or crossed actual prior frame"
        );
        let prior_count = old_t[KEY]["roles"].as_array().map_or(0, Vec::len);
        ensure!(
            prior_count + 1 == sequence.len(),
            "downstream initial history skips an actor adoption"
        );
        for old_role in sequence
            .iter()
            .take(prior_count)
            .map(|r| r.as_str().unwrap())
        {
            for member in MEMBERS {
                ensure!(
                    old_t[KEY]["sources"][format!("{old_role}.{member}")]
                        == h["sources"][format!("{old_role}.{member}")],
                    "downstream history rewrites prior accepted role"
                );
            }
        }
        if bindings["fleet"] == *origin(h, name, "entry_fleet")? {
            ensure!(
                *e.fleet == *source(e, name, "entry_fleet")?
                    && *e.fleet_plan == *source(e, name, "entry_plan")?,
                "downstream actual entry differs"
            );
            origin(h, name, "previous_fleet")?.clone()
        } else {
            origin(h, name, "entry_fleet")?.clone()
        }
    } else {
        ensure!(h["mode"] == "retained", "foreign downstream history mode");
        let mut prior = old_t[KEY].clone();
        prior["mode"] = json!("retained");
        ensure!(prior == *h, "downstream immutable history changed");
        retained_observation_head(e)?.0
    };
    Ok(Some(Validated {
        metadata_event: head.clone(),
        previous_metadata_event: previous_metadata_event(e)?.unwrap(),
        previous_fleet,
        events: captured,
    }))
}
pub fn row_clock(e: &Evidence<'_>, claim: &Value, row: &Value) -> Result<Option<bool>> {
    if !roles::scope(
        claim["phase"].as_str().unwrap_or(""),
        claim["unit"].as_str().unwrap_or(""),
    ) {
        return Ok(None);
    };
    let Some((_, event)) = latest(e)? else {
        return Ok(Some(false));
    };
    let clock = if e.fleet["metadata_only"] == true {
        &event["recorded_at_utc"]
    } else {
        &e.observer["recorded_at_utc"]
    };
    Ok(Some(
        row["sampled_at_utc"] == *clock
            && row["resource_sampled_at_utc"] == e.observer["recorded_at_utc"],
    ))
}

/// An intermediate normal observation may preserve the same genuine downstream
/// metadata event. Retain its actual fleet ancestry and compare every policy
/// field except the three ordinary observation/output/predecessor bindings.
pub const FLEET_BRIDGE_SCHEMA: &str = "jetstreamer-private154-retained-fleet-observation-bridge-v1";
pub fn retained_observation_head(e: &Evidence<'_>) -> Result<(Value, usize)> {
    let previous = e.prior_recovery.context("downstream bridge prior frame")?;
    let mut fleet_head = previous["bindings"]["fleet"].clone();
    let rows = e
        .cohort183_transition
        .and_then(|t| t["observation_bridge"].as_array());
    let Some(rows) = rows.filter(|rows| rows.iter().any(|r| r["schema"] == FLEET_BRIDGE_SCHEMA))
    else {
        return Ok((fleet_head, 0));
    };
    let h = descriptor(e).context("typed fleet bridge lacks downstream history")?;
    ensure!(
        h["mode"] == "retained" && !rows.is_empty() && rows.len() <= crate::MAXIMUM_OBSERVATION_BRIDGE_INTERMEDIATES,
        "typed fleet bridge changed retained role history or length"
    );
    let (metadata, _) = latest(e)?.context("typed fleet bridge lacks genuine metadata head")?;
    let mut prior_plan = e.prior_fleet_plan.clone();
    let mut observer_head = previous["bindings"]["observer"].clone();
    let mut clock = utc_seconds(
        previous["sampled_at_utc"]
            .as_str()
            .context("typed fleet bridge predecessor clock")?,
    )?;
    let mut extra_sources = 0usize;
    for (index, row) in rows.iter().enumerate() {
        let bridge_source = |member: &str| {
            e.cohort183_sources
                .get(&format!("bridge.{index}.{member}"))
                .with_context(|| format!("typed fleet bridge source missing: {index}.{member}"))
        };
        let observer = bridge_source("observer")?;
        let next = utc_seconds(
            observer["recorded_at_utc"]
                .as_str()
                .context("typed fleet bridge sample clock")?,
        )?;
        ensure!(
            observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                && observer["cadence"]["routine_minimum_interval_enforced"] == true
                && observer["cadence"]["minimum_interval_seconds"] == 1800
                && observer["cadence"]["previous_sample"] == observer_head["path"]
                && observer["cadence"]["previous_sample_sha256"] == observer_head["sha256"]
                && next >= clock + 1800
                && observer["cadence"]["observed_interval_seconds"] == next - clock,
            "typed fleet bridge lost genuine observer cadence or ancestry"
        );
        if row["schema"].is_null() {
            ensure!(
                row.as_object()
                    .is_some_and(|o| o.len() == 1 && o.contains_key("observer")),
                "typed fleet bridge has an undeclared observer-only row"
            );
        } else {
            ensure!(
                row["schema"] == FLEET_BRIDGE_SCHEMA
                    && row.as_object().is_some_and(|o| o.len() == 4
                        && ["schema", "observer", "fleet", "fleet_plan"]
                            .iter()
                            .all(|k| o.contains_key(*k))),
                "typed fleet bridge row changes scope or source census"
            );
            for member in ["observer", "fleet", "fleet_plan"] {
                ensure!(
                    row[member].as_object().is_some_and(|o| o.len() == 2
                        && o.contains_key("path")
                        && o.contains_key("sha256")),
                    "typed fleet bridge binding shape differs"
                );
                let binding: Bound = serde_json::from_value(row[member].clone())?;
                ensure!(
                    binding.path.is_absolute()
                        && binding.sha256.len() == 64
                        && binding
                            .sha256
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "typed fleet bridge binding is not absolute and digest-bound"
                );
            }
            let fleet = bridge_source("fleet")?;
            let plan = bridge_source("fleet_plan")?;
            fleet_binding(fleet, plan, &row["fleet_plan"], &row["observer"])?;
            ensure!(
                plan["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
                    && plan["previous_fleet"] == fleet_head
                    && fleet["previous_fleet"] == fleet_head
                    && plan["output"] == row["fleet"]["path"]
                    && plan["metadata_event"] == *metadata
                    && fleet["metadata_event"] == *metadata
                    && fleet["metadata_only"] == false
                    && fleet["resource_admission_authorized"] == false
                    && fleet["sampled_at_utc"] == observer["recorded_at_utc"],
                "typed fleet bridge changed normal observation, metadata or authoritative fleet ancestry"
            );
            let mut expected = prior_plan.clone();
            for key in ["observer", "output", "previous_fleet"] {
                expected[key] = plan[key].clone();
            }
            ensure!(
                expected == *plan,
                "typed fleet bridge changed retained policy, gates, claims or history"
            );
            let tracked = plan["tracked_units"]
                .as_array()
                .context("typed fleet bridge tracked units")?;
            let census = fleet["unit_census"]
                .as_object()
                .context("typed fleet bridge native census")?;
            ensure!(
                tracked.len() >= 531
                    && tracked
                        .iter()
                        .all(|u| u.as_str().is_some_and(|u| census.contains_key(u))),
                "typed fleet bridge dropped historical native census"
            );
            for name in h["roles"]
                .as_array()
                .context("typed fleet bridge retained roles")?
            {
                let name = name.as_str().context("typed fleet bridge role name")?;
                let role = Role::parse(name)?;
                roles::validate_observed_native(
                    &fleet["unit_census"][role.unit()],
                    source(e, name, "event")?,
                )?;
            }
            fleet_head = row["fleet"].clone();
            prior_plan = plan.clone();
            extra_sources = extra_sources
                .checked_add(2)
                .context("typed fleet bridge source overflow")?;
        }
        observer_head = row["observer"].clone();
        clock = next;
    }
    ensure!(
        e.fleet["previous_fleet"] == fleet_head
            && e.fleet_plan["previous_fleet"] == fleet_head
            && e.observer["cadence"]["previous_sample"] == observer_head["path"]
            && e.observer["cadence"]["previous_sample_sha256"] == observer_head["sha256"],
        "typed fleet bridge is not the actual current observation/fleet predecessor"
    );
    Ok((fleet_head, extra_sources))
}
