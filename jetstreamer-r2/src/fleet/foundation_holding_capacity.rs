//! Foundation maintenance bytes, never a replay/native launch admission.
//! Reuses exact current peer/guard growth accounting and preserves old floors.
use super::*;

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
        "Foundation restoration needs the accepted fresh201-300 observation"
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
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Foundation restore capacity requires root"
    );
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
    let t = sampled(&accounting_o, &f, now)?;
    // Reject unknown/native peers rather than invent a zero-growth reservation.
    prefix223_live_peer::roster(&f)?;
    native210_peer_history::validate(&f)?;
    let floor = singleton227_admission::century_floor_for_maintenance(&f)?;
    let (growth, measurements) =
        prefix223_live_peer::disk(&f, &accounting_o, &s.protected_guards, t, now)?;
    let (minimum, largest_guard_floor) =
        native228_admission::protected_floor(floor, growth, &s.protected_guards)?;
    let sampled_free = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("Foundation sampled disk")?;
    let required = envelope(minimum, additional, sampled_free)?;
    let names = f["unit_census"]
        .as_object()
        .context("Foundation fleet units")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let before = census(&names, 201, 300)?;
    native210_peer_history::current(&f, &before)?;
    prefix223_live_peer::current(&f, &before)?;
    singleton227_admission::owners(&f, &before)?;
    let caps = prefix223_live_peer::limits(&f)?;
    let actual_free = singleton227_admission::disk_free()?;
    envelope(minimum, additional, actual_free)?;
    let after = census(&names, 201, 300)?;
    native210_peer_history::current(&f, &after)?;
    prefix223_live_peer::current(&f, &after)?;
    singleton227_admission::owners(&f, &after)?;
    ensure!(
        before == after && caps == prefix223_live_peer::limits(&f)?,
        "Foundation owners/caps changed during capacity admission"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let after_accounting_o = native227_terminal_observer_view(&f, &o)?;
    sampled(&after_accounting_o, &f, now)?;
    ensure!(
        accounting_o["terminal_observation_accounting"]
            == after_accounting_o["terminal_observation_accounting"],
        "Foundation terminal observation accounting changed during admission"
    );
    let (after_growth, after_measurements) =
        prefix223_live_peer::disk(&f, &after_accounting_o, &s.protected_guards, t, now)?;
    ensure!(
        after_growth <= growth,
        "Foundation protected growth increased during admission"
    );
    envelope(minimum, additional, singleton227_admission::disk_free()?)?;
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
    Ok(capacity)
}
#[cfg(test)]
mod tests {
    use super::*;
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
