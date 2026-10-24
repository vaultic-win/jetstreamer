//! Shared bounded maintenance capacity, never a replay/native launch admission.
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
        .context("Maintenance space overflow")?;
    ensure!(
        available >= required,
        "Maintenance would consume protected live growth/floors"
    );
    Ok(required)
}
fn sampled(o: &Value, f: &Value, now: u64) -> Result<u64> {
    let sampled = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("Maintenance observer clock")?,
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
        "Maintenance needs the accepted fresh201-300 observation"
    );
    let mut rows = o["replays"]
        .as_array()
        .context("Maintenance replay census")?
        .iter()
        .collect::<Vec<_>>();
    for d in o["diagnostic_replays"]
        .as_array()
        .context("Maintenance diagnostic census")?
    {
        if d["status"] != "observed" {
            native209_admission::unavailable_is_inactive(d, f)?;
            continue;
        }
        ensure!(
            d["error"].is_null(),
            "Maintenance diagnostic observer error"
        );
        rows.push(&d["observation"]);
    }
    let mut seen = BTreeSet::new();
    for active in f["active"]
        .as_array()
        .context("Maintenance full owner census")?
    {
        let owner = singleton227_admission::active_owner(active)?;
        let unit = owner["Id"].as_str().context("Maintenance owner name")?;
        if !seen.insert(unit) {
            continue;
        }
        let matches = rows
            .iter()
            .filter(|r| r["producer_after"]["unit"] == unit)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "Maintenance owner omitted/duplicated in accepted observation"
        );
        let row = matches[0];
        ensure!(
            row["invocation_binding_stable"] == true
                && row["producer_before"]["invocation_id"] == owner["InvocationID"]
                && row["producer_after"]["invocation_id"] == owner["InvocationID"]
                && row["producer_after"]["restarts"] == 0
                && row["producer_after"]["rss"]["census_stable"] == true,
            "Maintenance owner identity changed in the coordinated sample"
        );
    }
    ensure!(
        rows.len() == seen.len(),
        "Maintenance sample contains an unaccounted owner"
    );
    Ok(sampled)
}
#[derive(Clone, Copy)]
pub(super) struct Candidate {
    pub additional_bytes: u64,
    pub memory_max_bytes: u64,
    pub minimum_protected_disk_bytes: u64,
}
pub(super) fn check(value: &Value, additional: u64) -> Result<Value> {
    check_inner(value, additional, None)
}
pub(super) fn check_candidate(value: &Value, candidate: Candidate) -> Result<Value> {
    ensure!(
        candidate.additional_bytes > 0
            && candidate.memory_max_bytes > 0
            && candidate.minimum_protected_disk_bytes > 0,
        "invalid bounded maintenance candidate"
    );
    check_inner(value, candidate.additional_bytes, Some(candidate))
}
pub(super) fn assembly223(value: &Value) -> Result<Value> {
    check_candidate(
        value,
        Candidate {
            additional_bytes: (160 << 30) + (32 << 20),
            memory_max_bytes: 64 << 30,
            minimum_protected_disk_bytes: 2_000_000_000_000,
        },
    )
}
fn completed_guards(
    f: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<Value> {
    prefix223_native20_admission::completed_guards_for(
        &prefix223_live_peer::roster(f)?,
        guards,
        sample,
        now,
    )
}
fn memory_required(reserve: u64, total: u64, candidate: u64) -> Result<u64> {
    ensure!(
        total > 0 && candidate > 0 && candidate <= total,
        "invalid maintenance memory envelope"
    );
    total
        .div_ceil(10)
        .checked_add(reserve)
        .and_then(|n| n.checked_add(candidate))
        .context("maintenance memory reservation overflow")
}
fn memory_sample(o: &Value, f: &Value, candidate: u64) -> Result<Value> {
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .and_then(|n| n.checked_mul(1024))
        .context("maintenance host total memory")?;
    let sampled = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .and_then(|n| n.checked_mul(1024))
        .context("maintenance sampled available memory")?;
    let (reserve, owners) = prefix223_live_peer::memory(f)?;
    let required = memory_required(reserve, total, candidate)?;
    let actual = native209_admission::actual_memory()?;
    ensure!(
        sampled >= required && actual >= required,
        "maintenance candidate consumes protected memory/90 percent target"
    );
    Ok(
        json!({"candidate_memory_max_bytes":candidate,"memory_target_percent":90,
        "host_total_memory_bytes":total,"protected_existing_memory_growth_bytes":reserve,
        "protected_memory_evidence":owners,"minimum_available_memory_bytes":required,
        "sampled_available_memory_bytes":sampled,"actual_available_memory_bytes":actual}),
    )
}
fn check_inner(value: &Value, additional: u64, candidate: Option<Candidate>) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Maintenance capacity requires root"
    );
    let s: Spec = serde_json::from_value(value.clone())?;
    ensure!(
        s.fleet
            .path
            .starts_with("/var/lib/jetstreamer/horizon-campaign-fleet"),
        "foreign Maintenance fleet"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    ensure!(
        f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256,
        "Maintenance fleet is not bound to the exact observer"
    );
    let accounting_o = native227_terminal_observer_view(&f, &o)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let t = sampled(&accounting_o, &f, now)?;
    let guard_history = candidate
        .map(|_| completed_guards(&f, &s.protected_guards, t, now))
        .transpose()?;
    // Reject unknown/native peers rather than invent a zero-growth reservation.
    prefix223_live_peer::roster(&f)?;
    native210_peer_history::validate(&f)?;
    let floor = singleton227_admission::century_floor_for_maintenance(&f)?;
    let (growth, measurements) =
        prefix223_live_peer::disk(&f, &accounting_o, &s.protected_guards, t, now)?;
    let (minimum, largest_guard_floor) =
        native228_admission::protected_floor(floor, growth, &s.protected_guards)?;
    // A separately authenticated candidate may require a larger sealed floor.
    // Ordinary Foundation maintenance retains its existing dynamic floor.
    let minimum = candidate.map_or(minimum, |c| minimum.max(c.minimum_protected_disk_bytes));
    let sampled_free = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("Maintenance sampled disk")?;
    let required = envelope(minimum, additional, sampled_free)?;
    let names = f["unit_census"]
        .as_object()
        .context("Maintenance fleet units")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let before = census(&names, 201, 300)?;
    native210_peer_history::current(&f, &before)?;
    prefix223_live_peer::current(&f, &before)?;
    singleton227_admission::owners(&f, &before)?;
    let caps = prefix223_live_peer::limits(&f)?;
    let memory_before = candidate
        .map(|c| memory_sample(&accounting_o, &f, c.memory_max_bytes))
        .transpose()?;
    let actual_free = singleton227_admission::disk_free()?;
    envelope(minimum, additional, actual_free)?;
    let after = census(&names, 201, 300)?;
    native210_peer_history::current(&f, &after)?;
    prefix223_live_peer::current(&f, &after)?;
    singleton227_admission::owners(&f, &after)?;
    ensure!(
        before == after && caps == prefix223_live_peer::limits(&f)?,
        "Maintenance owners/caps changed during capacity admission"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let after_accounting_o = native227_terminal_observer_view(&f, &o)?;
    sampled(&after_accounting_o, &f, now)?;
    ensure!(
        accounting_o["terminal_observation_accounting"]
            == after_accounting_o["terminal_observation_accounting"],
        "Maintenance terminal observation accounting changed during admission"
    );
    let (after_growth, after_measurements) =
        prefix223_live_peer::disk(&f, &after_accounting_o, &s.protected_guards, t, now)?;
    ensure!(
        after_growth <= growth,
        "Maintenance protected growth increased during admission"
    );
    envelope(minimum, additional, singleton227_admission::disk_free()?)?;
    let guard_history_after = candidate
        .map(|_| completed_guards(&f, &s.protected_guards, t, now))
        .transpose()?;
    let memory_after = candidate
        .map(|c| memory_sample(&after_accounting_o, &f, c.memory_max_bytes))
        .transpose()?;
    if let (Some(before), Some(after)) = (&memory_before, &memory_after) {
        ensure!(
            after["protected_existing_memory_growth_bytes"].as_u64()
                <= before["protected_existing_memory_growth_bytes"].as_u64(),
            "maintenance protected memory growth increased"
        );
    }
    // Assembly's added memory/timer checks must be inside a complete manager
    // bracket too; leave Foundation's established two-census shape unchanged.
    let final_census = if candidate.is_some() {
        let current = census(&names, 201, 300)?;
        native210_peer_history::current(&f, &current)?;
        prefix223_live_peer::current(&f, &current)?;
        singleton227_admission::owners(&f, &current)?;
        ensure!(
            before == current && caps == prefix223_live_peer::limits(&f)?,
            "maintenance owners/caps changed across final memory/guard checks"
        );
        envelope(minimum, additional, singleton227_admission::disk_free()?)?;
        Some(current)
    } else {
        None
    };
    let mut capacity = json!({"schema":"jetstreamer-horizon-maintenance-capacity-v1","host":"horizon-vaultic","first_epoch":201,"last_epoch":300,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"sampled_at_utc":f["sampled_at_utc"],
        "resource_basis":value,"century_floor_bytes":floor,"protected_remaining_growth_bytes":growth,
        "maximum_existing_guard_floor_bytes":largest_guard_floor,"minimum_free_bytes":minimum,"additional_bytes":additional,
        "required_initial_free_bytes":required,"sampled_available_bytes":sampled_free,"actual_available_bytes":actual_free,
        "protected_growth_before":measurements,"protected_growth_after":after_measurements,"protected_caps":caps,
        "unit_census_before":before,"unit_census_after":after,"recorded_unix_seconds":now,"maximum_age_seconds":900,
        "maintenance_only":true,"all_live_growth_and_century_floor_protected":true,"new_resource_samples":0,
        "replay_launch_authorized":false,"local_retirement_authorized":false,"publication_authorized":false,"r2_mutations":false});
    if let Some(evidence) = accounting_o.get("terminal_observation_accounting") {
        capacity["terminal_observation_accounting"] = evidence.clone();
    }
    if let Some(before) = memory_before {
        capacity["protected_guard_history_before"] =
            guard_history.context("missing maintenance guard history")?;
        capacity["protected_guard_history_after"] =
            guard_history_after.context("missing maintenance final guard history")?;
        capacity["unit_census_after_memory_and_guard_checks"] =
            json!(final_census.context("missing final maintenance census")?);
        capacity["memory_before"] = before;
        capacity["memory_after"] = memory_after.context("missing maintenance final memory")?;
    }
    Ok(capacity)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_memory_preserves_remaining_owner_charge_and_ninety_percent_target() {
        assert_eq!(memory_required(80, 1000, 64).unwrap(), 244);
        assert_eq!(memory_required(0, 1000, 64).unwrap(), 164);
        assert_eq!(memory_required(0, 1001, 64).unwrap(), 165);
        assert!(memory_required(1, 0, 64).is_err());
        assert!(memory_required(1, 1000, 1001).is_err());
        assert!(memory_required(u64::MAX, 1000, 64).is_err());
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
