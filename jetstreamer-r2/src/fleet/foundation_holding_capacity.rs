//! Foundation maintenance bytes, never a replay/native launch admission.
//! Reuses exact current peer/guard growth accounting and preserves old floors.
use super::*;
#[path = "foundation_holding_capacity_guards.rs"]
mod continuation_guards;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    observer: BoundFile,
    fleet: BoundFile,
    protected_guards: BTreeMap<String, BoundFile>,
}
fn envelope(minimum: u64, additional: u64, available: u64) -> Result<u64> {
    let required = minimum
        .checked_add(additional)
        .context("Foundation restore space overflow")?;
    ensure!(
        available >= required,
        "Foundation restore would consume protected live growth/floors"
    );
    Ok(required)
}
fn sampled(o: &Value, f: &Value, now: u64) -> Result<u64> {
    let sampled = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("Foundation observer clock")?,
    )?;
    ensure!(
        sampled <= now
            && now - sampled <= 1800
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0,
        "Foundation restoration needs the accepted fresh 201-300 observation"
    );
    let mut rows = o["replays"]
        .as_array()
        .context("Foundation replay census")?
        .iter()
        .collect::<Vec<_>>();
    for d in o["diagnostic_replays"]
        .as_array()
        .context("Foundation diagnostic census")?
    {
        if d["status"] != "observed" {
            native209_admission::unavailable_is_inactive(d, f)?;
            continue;
        }
        ensure!(d["error"].is_null(), "Foundation diagnostic observer error");
        rows.push(&d["observation"]);
    }
    let mut seen = BTreeSet::new();
    for active in f["active"]
        .as_array()
        .context("Foundation full owner census")?
    {
        let owner = singleton227_admission::active_owner(active)?;
        let unit = owner["Id"].as_str().context("Foundation owner name")?;
        if !seen.insert(unit) {
            continue;
        }
        let matches = rows
            .iter()
            .filter(|r| r["producer_after"]["unit"] == unit)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "Foundation owner omitted/duplicated in accepted observation"
        );
        let row = matches[0];
        ensure!(
            row["invocation_binding_stable"] == true
                && row["producer_before"]["invocation_id"] == owner["InvocationID"]
                && row["producer_after"]["invocation_id"] == owner["InvocationID"]
                && row["producer_after"]["restarts"] == 0
                && row["producer_after"]["rss"]["census_stable"] == true,
            "Foundation owner identity changed in the coordinated sample"
        );
    }
    ensure!(
        rows.len() == seen.len(),
        "Foundation sample contains an unaccounted owner"
    );
    Ok(sampled)
}
pub(super) fn check(value: &Value, additional: u64) -> Result<Value> {
    check_inner(value, additional, None)
}
pub(super) fn check_with_restore(
    value: &Value,
    additional: u64,
    context: &crate::holding::Foundation213RestoreContext<'_>,
) -> Result<Value> {
    check_inner(value, additional, Some(context))
}
fn check_inner(
    value: &Value,
    additional: u64,
    context: Option<&crate::holding::Foundation213RestoreContext<'_>>,
) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Foundation restore capacity requires root"
    );
    if let Some(context) = context {
        ensure!(
            additional == 0,
            "self-restoration cannot issue a new capacity reservation"
        );
        context.revalidate()?;
        context.require_basis(value)?;
    }
    let s: Spec = serde_json::from_value(value.clone())?;
    ensure!(
        s.fleet
            .path
            .starts_with("/var/lib/jetstreamer/horizon-campaign-fleet"),
        "foreign Foundation fleet"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    ensure!(
        f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256,
        "Foundation fleet is not bound to the exact observer"
    );
    let accounting_o = native227_terminal_observer_view(&f, &o)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    // The accepted bytes remain unchanged. A typed running restoration keeps
    // its one fresh entry gate; it is not a new admission after a slow hash.
    let validation_clock = context.map_or(now, |c| c.entry_clock());
    let continuing = context.is_some_and(|c| c.entered());
    let t = sampled(&accounting_o, &f, validation_clock)?;
    // Reject unknown/native peers rather than invent a zero-growth reservation.
    prefix223_live_peer::roster(&f)?;
    native210_peer_history::validate(&f)?;
    let floor = singleton227_admission::century_floor_for_maintenance(&f)?;
    // Original guard bindings were fresh at the real entry time. Keep that
    // immutable proof, then use genuinely current completed protective fires.
    if context.is_some() {
        prefix223_live_peer::disk(&f, &accounting_o, &s.protected_guards, t, validation_clock)?;
    }
    let (current_guards, guard_history) = if context.is_some() {
        continuation_guards::refresh(&f, &s.protected_guards, t, now)?
    } else {
        (
            serde_json::from_value(serde_json::to_value(&s.protected_guards)?)?,
            Value::Null,
        )
    };
    let (growth, measurements) =
        prefix223_live_peer::disk(&f, &accounting_o, &current_guards, t, now)?;
    let (computed_minimum, largest_guard_floor) =
        native228_admission::protected_floor(floor, growth, &current_guards)?;
    let mut minimum = context.map_or(computed_minimum, |c| {
        computed_minimum.max(c.protected_floor())
    });
    let sampled_free = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("Foundation sampled disk")?;
    let required = if continuing {
        minimum
            .checked_add(additional)
            .context("continuation reserve overflow")?
    } else {
        envelope(minimum, additional, sampled_free)?
    };
    let names = f["unit_census"]
        .as_object()
        .context("Foundation fleet units")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let before = census(&names, 201, 300)?;
    native210_peer_history::current(&f, &before)?;
    prefix223_live_peer::current(&f, &before)?;
    if let Some(context) = context {
        singleton227_admission::owners_with_foundation_restore(&f, &before, context)?;
    } else {
        singleton227_admission::owners(&f, &before)?;
    }
    let caps = prefix223_live_peer::limits(&f)?;
    let actual_free = singleton227_admission::disk_free()?;
    envelope(minimum, additional, actual_free)?;
    let after = census(&names, 201, 300)?;
    native210_peer_history::current(&f, &after)?;
    prefix223_live_peer::current(&f, &after)?;
    if let Some(context) = context {
        singleton227_admission::owners_with_foundation_restore(&f, &after, context)?;
    } else {
        singleton227_admission::owners(&f, &after)?;
    }
    ensure!(
        before == after && caps == prefix223_live_peer::limits(&f)?,
        "Foundation owners/caps changed during capacity admission"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let after_accounting_o = native227_terminal_observer_view(&f, &o)?;
    sampled(
        &after_accounting_o,
        &f,
        context.map_or(now, |c| c.entry_clock()),
    )?;
    ensure!(
        accounting_o["terminal_observation_accounting"]
            == after_accounting_o["terminal_observation_accounting"],
        "Foundation terminal observation accounting changed during admission"
    );
    let (after_guards, after_guard_history) = if context.is_some() {
        continuation_guards::refresh(&f, &s.protected_guards, t, now)?
    } else {
        (
            serde_json::from_value(serde_json::to_value(&s.protected_guards)?)?,
            Value::Null,
        )
    };
    let (after_growth, after_measurements) =
        prefix223_live_peer::disk(&f, &after_accounting_o, &after_guards, t, now)?;
    if continuing {
        let (after_floor, _) =
            native228_admission::protected_floor(floor, after_growth, &after_guards)?;
        minimum = minimum.max(after_floor);
    } else {
        ensure!(
            after_growth <= growth,
            "Foundation protected growth increased during admission"
        );
    }
    let final_available = singleton227_admission::disk_free()?;
    envelope(minimum, additional, final_available)?;
    if let Some(context) = context {
        context.revalidate()?;
    }
    let mut capacity = json!({"schema":"jetstreamer-foundation-holding-capacity-v1","host":"horizon-vaultic","first_epoch":201,"last_epoch":300,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"sampled_at_utc":f["sampled_at_utc"],
        "resource_basis":value,"century_floor_bytes":floor,"protected_remaining_growth_bytes":growth,
        "maximum_existing_guard_floor_bytes":largest_guard_floor,"minimum_free_bytes":minimum,"additional_restore_bytes":additional,
        "required_initial_free_bytes":required,"sampled_available_bytes":sampled_free,"actual_available_bytes":actual_free,
        "protected_growth_before":measurements,"protected_growth_after":after_measurements,"protected_caps":caps,
        "unit_census_before":before,"unit_census_after":after,"recorded_unix_seconds":now,"maximum_age_seconds":900,
        "restore_only":true,"all_live_growth_and_century_floor_protected":true,"new_resource_samples":0,
        "replay_launch_authorized":false,"local_retirement_authorized":false,"publication_authorized":false,"r2_mutations":false});
    if let Some(evidence) = accounting_o.get("terminal_observation_accounting") {
        capacity["terminal_observation_accounting"] = evidence.clone();
    }
    if let Some(context) = context {
        capacity["self_maintenance_restore_accounting"] = context.evidence();
        capacity["protected_remaining_growth_bytes"] = json!(growth.max(after_growth));
        capacity["required_initial_free_bytes"] = json!(minimum
            .checked_add(additional)
            .context("continuation required reserve overflow")?);
        capacity["actual_available_bytes"] = json!(final_available);
        capacity["actual_available_bytes_before"] = json!(actual_free);
        capacity["current_protected_guard_history_before"] = guard_history;
        capacity["current_protected_guard_history_after"] = after_guard_history;
        capacity["entry_freshness_validation_unix_seconds"] = json!(validation_clock);
        capacity["already_admitted_continuation_only"] = json!(continuing);
    }
    Ok(capacity)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepted_observer_freshness_is_strict_at_saved_entry_only() {
        let timestamp = "2026-10-24T10:00:00Z";
        let sample = utc_seconds(timestamp).unwrap();
        let observer = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":timestamp,"replays":[],"diagnostic_replays":[]});
        let fleet = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"sampled_at_utc":timestamp,"inventory":{"anomalies":0},"active":[]});
        let saved_entry = sample + 1800;
        assert_eq!(sampled(&observer, &fleet, saved_entry).unwrap(), sample);
        assert!(sampled(&observer, &fleet, saved_entry + 1).is_err());
        assert!(sampled(&observer, &fleet, sample - 1).is_err());
        // A continuation uses the unchanged entry clock, never a renewed sample.
        assert_eq!(sampled(&observer, &fleet, saved_entry).unwrap(), sample);
        assert_eq!(observer["recorded_at_utc"], timestamp);
        assert_eq!(fleet["sampled_at_utc"], timestamp);
    }
    #[test]
    fn restoration_adds_bytes_without_spending_existing_floor_or_overflowing() {
        assert_eq!(envelope(2000, 125, 2125).unwrap(), 2125);
        assert!(envelope(2000, 125, 2124).is_err());
        assert_eq!(envelope(2000, 0, 2000).unwrap(), 2000);
        assert!(envelope(u64::MAX, 1, u64::MAX).is_err());
    }
    #[test]
    fn restoration_capacity_spec_has_no_replay_launch_or_floor_override() {
        let b = json!({"path":"/bound/evidence.json","sha256":"a".repeat(64)});
        let mut s = json!({"observer":b,"fleet":b,"protected_guards":{}});
        assert!(serde_json::from_value::<Spec>(s.clone()).is_ok());
        for key in [
            "ignore_peer",
            "minimum_free_bytes",
            "launch",
            "delete_local",
        ] {
            s[key] = json!(true);
            assert!(serde_json::from_value::<Spec>(s.clone()).is_err());
            s.as_object_mut().unwrap().remove(key);
        }
    }
}
