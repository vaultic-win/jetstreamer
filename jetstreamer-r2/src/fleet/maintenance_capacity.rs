//! Fresh bounded private epoch 223 maintenance with every accepted owner protected.
//! Capped peers retain their raw fleet/observer history and full hard limits.
use super::*;
mod singleton210_memory;
#[derive(Clone, Copy)]
enum MemoryMode {
    Existing,
    Full210,
    Full209Delivery,
    FirstRoot233,
}

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
        "Maintenance needs the accepted fresh 201-300 observation"
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
pub(super) fn check_candidate(value: &Value, candidate: Candidate) -> Result<Value> {
    ensure!(
        candidate.additional_bytes > 0
            && candidate.memory_max_bytes > 0
            && candidate.minimum_protected_disk_bytes > 0,
        "invalid bounded maintenance candidate"
    );
    check_inner(value, candidate, MemoryMode::Existing)
}
pub(super) fn check_singleton210(value: &Value, minimum_disk: u64) -> Result<Value> {
    ensure!(minimum_disk > 0, "210 protected disk floor missing");
    check_inner(
        value,
        Candidate {
            additional_bytes: singleton210::PEAK
                .checked_add(singleton210::METADATA_RESERVE)
                .context("210 added metadata overflow")?,
            memory_max_bytes: singleton210::MEMORY,
            minimum_protected_disk_bytes: minimum_disk,
        },
        MemoryMode::Full210,
    )
}
pub(super) fn singleton210_memory_proven(capacity: &Value) -> Result<()> {
    singleton210_memory::validate_capacity(capacity)
}
pub(super) fn check_first_root233(value: &Value) -> Result<Value> {
    check_inner(
        value,
        Candidate {
            additional_bytes: first_root233::DISK_RESERVATION,
            memory_max_bytes: first_root233::MEMORY,
            minimum_protected_disk_bytes: first_root233::FLOOR,
        },
        MemoryMode::FirstRoot233,
    )
}
pub(super) fn check_singleton209_delivery(value: &Value, candidate: Candidate) -> Result<Value> {
    ensure!(
        candidate.additional_bytes == 1 << 30
            && matches!(candidate.memory_max_bytes,
        n if n==16<<30 || n==32<<30 || n==64<<30)
            && candidate.minimum_protected_disk_bytes > 0,
        "209 delivery memory or metadata envelope differs"
    );
    check_inner(value, candidate, MemoryMode::Full209Delivery)
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
fn legacy_observer(o: &Value, names: &BTreeSet<String>) -> Result<Value> {
    let mut view = o.clone();
    view["diagnostic_replays"]
        .as_array_mut()
        .context("maintenance diagnostic census")?
        .retain(|row| {
            !row["producer_unit"]
                .as_str()
                .is_some_and(|name| names.contains(name))
        });
    Ok(view)
}
fn accounting_views(f: &Value, o: &Value) -> Result<(Value, Value)> {
    // These authenticate the complete launch/frame/registration before a peer
    // can leave the legacy-only resource view. Raw evidence is never modified.
    capped204205_work::peer_observation(f, o)?;
    let names = capped204205_work::peer_names(f)?;
    Ok((
        capped204205_work::peer_legacy_view(f)?,
        legacy_observer(o, &names)?,
    ))
}
pub(super) fn current_owners(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    native210_peer_history::current(f, current)?;
    prefix223_live_peer::current(&capped204205_work::peer_legacy_view(f)?, current)?;
    // Only proven auxiliary guards leave this comparison. Every producer stays
    // in the raw active roster, so an omitted or changed actor still fails.
    singleton227_admission::owners(f, &capped204205_work::peer_current(f, current)?)
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
// The c7 canary adapter can include an explicit available-floor component.
// Full stage policies add that same floor separately, so retain every hard
// growth byte while accounting for this one authenticated component once.
fn hard_growth(f: &Value, total: u64, reserve: u64, owners: &[Value]) -> Result<(u64, u64)> {
    let expected = canary227_peer::memory_floor(f, total)?;
    let mut accounted = None;
    for row in owners {
        if let Some(value) = row.get("memory_floor_top_up_bytes") {
            ensure!(
                row["unit"] == canary227::UNIT
                    && accounted.is_none()
                    && row["memory_floor_policy"] == expected,
                "duplicate or inconsistent maintenance floor component"
            );
            let bytes = value
                .as_u64()
                .context("maintenance floor component is not an integer")?;
            ensure!(
                expected["memory_floor_top_up_bytes"] == bytes,
                "maintenance floor component differs from exact policy"
            );
            accounted = Some(bytes);
        }
    }
    let accounted = accounted.unwrap_or(0);
    Ok((
        reserve
            .checked_sub(accounted)
            .context("maintenance floor component exceeds protected total")?,
        accounted,
    ))
}
fn memory_sample(
    o: &Value,
    f: &Value,
    reserve: u64,
    owners: Vec<Value>,
    candidate: u64,
    mode: MemoryMode,
) -> Result<Value> {
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .and_then(|n| n.checked_mul(1024))
        .context("maintenance host total memory")?;
    let sampled = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .and_then(|n| n.checked_mul(1024))
        .context("maintenance sampled available memory")?;
    let (reserve, accounted_floor) = if matches!(mode, MemoryMode::Existing) {
        (reserve, 0)
    } else {
        hard_growth(f, total, reserve, &owners)?
    };
    let (required, policy) = match mode {
        MemoryMode::Existing => (memory_required(reserve, total, candidate)?, None),
        MemoryMode::Full210 => {
            let (n, p) = singleton210_memory::required(f, total, reserve, candidate)?;
            (n, Some(("full210_memory_policy", p)))
        }
        MemoryMode::Full209Delivery => {
            let (n, p) = singleton210_memory::delivery_required(f, total, reserve, candidate)?;
            (n, Some(("full209_delivery_memory_policy", p)))
        }
        MemoryMode::FirstRoot233 => {
            let (n, p) = singleton210_memory::first_root233_required(f, total, reserve, candidate)?;
            (n, Some(("first_root233_memory_policy", p)))
        }
    };
    let actual = native209_admission::actual_memory()?;
    ensure!(
        sampled >= required && actual >= required,
        "maintenance candidate consumes protected memory/90 percent target"
    );
    let mut result = json!({"candidate_memory_max_bytes":candidate,"memory_target_percent":90,
        "host_total_memory_bytes":total,"protected_existing_memory_growth_bytes":reserve,
        "protected_memory_evidence":owners,"minimum_available_memory_bytes":required,
        "sampled_available_memory_bytes":sampled,"actual_available_memory_bytes":actual,
        "available_floor_component_accounted_once_bytes":accounted_floor});
    if let Some((key, policy)) = policy {
        result[key] = policy;
    }
    Ok(result)
}
fn check_inner(value: &Value, candidate: Candidate, mode: MemoryMode) -> Result<Value> {
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
    let (legacy, legacy_o) = accounting_views(&f, &accounting_o)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let t = sampled(&legacy_o, &legacy, now)?;
    prefix223_live_peer::roster(&legacy)?;
    native210_peer_history::validate(&f)?;
    let floor = singleton227_admission::century_floor_for_maintenance(&f)?;
    let names = f["unit_census"]
        .as_object()
        .context("Maintenance fleet units")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let before = census(&names, 201, 300)?;
    current_owners(&f, &before)?;
    // Share the already qualified sibling accounting policy, including the
    // complete guard-key union, genuine latest fires and independent guard caps.
    let guard_history = capped204205_admission::guards(&f, &s.protected_guards, &before, t, now)?;
    let caps = capped204205_admission::combined_limits(&f, &s.protected_guards, &before, now)?;
    let (growth, measurements, memory_growth, memory_evidence) =
        capped204205_admission::combined_resources(
            &f,
            &accounting_o,
            &s.protected_guards,
            &before,
            t,
            now,
        )?;
    let (minimum, largest_guard_floor) =
        native228_admission::protected_floor(floor, growth, &s.protected_guards)?;
    let minimum = minimum.max(candidate.minimum_protected_disk_bytes);
    let sampled_free = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("Maintenance sampled disk")?;
    let required = envelope(minimum, candidate.additional_bytes, sampled_free)?;
    let memory_before = memory_sample(
        &accounting_o,
        &f,
        memory_growth,
        memory_evidence,
        candidate.memory_max_bytes,
        mode,
    )?;
    let actual_free = singleton227_admission::disk_free()?;
    envelope(minimum, candidate.additional_bytes, actual_free)?;
    let after = census(&names, 201, 300)?;
    current_owners(&f, &after)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        before == after
            && caps
                == capped204205_admission::combined_limits(&f, &s.protected_guards, &after, now)?,
        "Maintenance owners/caps changed during capacity admission"
    );
    let after_accounting_o = native227_terminal_observer_view(&f, &o)?;
    let (after_legacy, after_legacy_o) = accounting_views(&f, &after_accounting_o)?;
    sampled(&after_legacy_o, &after_legacy, now)?;
    ensure!(
        accounting_o["terminal_observation_accounting"]
            == after_accounting_o["terminal_observation_accounting"],
        "Maintenance terminal observation accounting changed during admission"
    );
    let guard_history_after =
        capped204205_admission::guards(&f, &s.protected_guards, &after, t, now)?;
    let (after_growth, after_measurements, after_memory_growth, after_memory_evidence) =
        capped204205_admission::combined_resources(
            &f,
            &after_accounting_o,
            &s.protected_guards,
            &after,
            t,
            now,
        )?;
    let bracketed = matches!(mode, MemoryMode::FirstRoot233);
    ensure!(
        bracketed || (after_growth <= growth && after_memory_growth <= memory_growth),
        "Maintenance protected resource growth increased during admission"
    );
    let memory_after = memory_sample(
        &after_accounting_o,
        &f,
        after_memory_growth,
        after_memory_evidence,
        candidate.memory_max_bytes,
        mode,
    )?;
    let current = census(&names, 201, 300)?;
    current_owners(&f, &current)?;
    let final_caps =
        capped204205_admission::combined_limits(&f, &s.protected_guards, &current, now)?;
    ensure!(
        before == current && caps == final_caps,
        "maintenance owners/caps changed across final memory/guard checks"
    );
    let final_free = singleton227_admission::disk_free()?;
    let growth_before = growth;
    let (minimum, required, growth, bracket_policy) = if bracketed {
        let growth = growth.max(after_growth);
        let (floor, _) = native228_admission::protected_floor(floor, growth, &s.protected_guards)?;
        let minimum = floor.max(candidate.minimum_protected_disk_bytes);
        let recomputed_disk = envelope(minimum, candidate.additional_bytes, sampled_free)?;
        envelope(
            minimum,
            candidate.additional_bytes,
            actual_free.min(final_free),
        )?;
        let n = |row: &Value, key: &str| {
            row[key]
                .as_u64()
                .with_context(|| format!("first root 233 bracket field absent: {key}"))
        };
        let hard = n(&memory_before, "protected_existing_memory_growth_bytes")?
            .max(n(&memory_after, "protected_existing_memory_growth_bytes")?);
        let (recomputed_memory, policy) = singleton210_memory::first_root233_required(
            &f,
            n(&memory_after, "host_total_memory_bytes")?,
            hard,
            candidate.memory_max_bytes,
        )?;
        let (required, required_memory) = capped204205_admission::bracketed_requirements(
            required,
            recomputed_disk,
            n(&memory_before, "minimum_available_memory_bytes")?,
            n(&memory_after, "minimum_available_memory_bytes")?,
            recomputed_memory,
        );
        ensure!(
            capped204205_admission::bracketed_fit(
                before == current,
                caps == final_caps,
                required,
                required_memory,
                [sampled_free, actual_free, final_free],
                [
                    n(&memory_before, "sampled_available_memory_bytes")?
                        .min(n(&memory_after, "sampled_available_memory_bytes")?),
                    n(&memory_before, "actual_available_memory_bytes")?,
                    n(&memory_after, "actual_available_memory_bytes")?
                ]
            ),
            "first root 233 complete bracketed disk/memory obligations do not fit every availability and identity gate"
        );
        (
            minimum,
            required,
            growth,
            Some(json!({"recomputed_complete_memory_policy":policy,
            "complete_required_memory_bytes":required_memory,"recomputed_complete_disk_requirement_bytes":recomputed_disk})),
        )
    } else {
        envelope(minimum, candidate.additional_bytes, final_free)?;
        (minimum, required, growth, None)
    };
    let mut capacity = json!({"schema":"jetstreamer-horizon-maintenance-capacity-v1","host":"horizon-vaultic","first_epoch":201,"last_epoch":300,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"sampled_at_utc":f["sampled_at_utc"],
        "resource_basis":value,"century_floor_bytes":floor,"protected_remaining_growth_bytes":growth,
        "maximum_existing_guard_floor_bytes":largest_guard_floor,"minimum_free_bytes":minimum,"additional_bytes":candidate.additional_bytes,
        "required_initial_free_bytes":required,"sampled_available_bytes":sampled_free,"actual_available_bytes":actual_free.min(final_free),
        "protected_growth_before":measurements,"protected_growth_after":after_measurements,"protected_caps":caps,
        "unit_census_before":before,"unit_census_after":after,"recorded_unix_seconds":now,"maximum_age_seconds":900,
        "maintenance_only":true,"all_live_growth_and_century_floor_protected":true,"new_resource_samples":0,
        "replay_launch_authorized":false,"local_retirement_authorized":false,"publication_authorized":false,"r2_mutations":false,
        "protected_guard_history_before":guard_history,"protected_guard_history_after":guard_history_after,
        "unit_census_after_memory_and_guard_checks":current,"memory_before":memory_before,"memory_after":memory_after,
        "capped_peer_accounting":{"raw_fleet_and_observer_preserved":true,"producer_and_independent_guard_hard_memory_charged":true,
            "full_admitted_disk_envelopes_charged":true,"allocation_credit_bytes":0}});
    if let Some(evidence) = accounting_o.get("terminal_observation_accounting") {
        capacity["terminal_observation_accounting"] = evidence.clone();
    }
    if bracketed {
        let accounted = memory_after["available_floor_component_accounted_once_bytes"]
            .as_u64()
            .context("first root 233 accounted floor component absent")?;
        ensure!(
            memory_before["available_floor_component_accounted_once_bytes"] == accounted,
            "first root 233 accounted floor component changed across brackets"
        );
        let before_hard = memory_growth
            .checked_sub(accounted)
            .context("first root 233 first hard growth underflow")?;
        let after_hard = after_memory_growth
            .checked_sub(accounted)
            .context("first root 233 final hard growth underflow")?;
        capacity["bracketed_obligations"] = json!({"disk_growth_before_bytes":growth_before,
            "disk_growth_after_bytes":after_growth,"protected_disk_growth_bytes":growth,
            "raw_memory_growth_before_bytes":memory_growth,"raw_memory_growth_after_bytes":after_memory_growth,
            "available_floor_component_accounted_once_bytes":accounted,
            "hard_memory_growth_before_bytes":before_hard,"hard_memory_growth_after_bytes":after_hard,
            "protected_hard_memory_growth_bytes":before_hard.max(after_hard),
            "policy":"safe maximum of both brackets; each disk/memory sample must fit; identities and caps remain exact"});
        capacity["bracketed_obligations"]["complete_policy"] =
            bracket_policy.context("first root 233 bracket policy absent")?;
    }
    Ok(capacity)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capped_legacy_observation_is_derived_without_dropping_other_rows_or_history() {
        let original = json!({"recorded_at_utc":"2026-10-24T10:00:00Z",
            "diagnostic_replays":[{"producer_unit":"capped.service","status":"unavailable","error":"registered failure"},
                {"producer_unit":"legacy.service","status":"observed","observation":{"exact":123}}],
            "host_memory":{"total_kib":1000},"history":[{"iid":"actual"}]});
        let snapshot = original.clone();
        let view = legacy_observer(&original, &BTreeSet::from(["capped.service".into()])).unwrap();
        assert_eq!(original, snapshot);
        assert_eq!(
            view["diagnostic_replays"],
            json!([original["diagnostic_replays"][1]])
        );
        assert_eq!(view["host_memory"], original["host_memory"]);
        assert_eq!(view["history"], original["history"]);
        assert_eq!(
            legacy_observer(&original, &BTreeSet::new()).unwrap(),
            original
        );
    }
    #[test]
    fn unknown_capped_claim_never_acquires_a_legacy_accounting_view() {
        let f = json!({"active":[{"epoch":204,"phase":"capped204205-continuation",
            "unit":{"Id":"horizon-qualify-204-capped-continuation-foreign.service"}}]});
        let o = json!({"diagnostic_replays":[]});
        assert!(accounting_views(&f, &o).is_err());
        assert_eq!(f["active"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn full_stage_floor_component_never_removes_hard_growth_or_counts_floor_twice() {
        let row = prefix223_live_peer::fixture_row();
        let f = json!({"active":[row],"unit_census":{(prefix223_native20::UNIT):row["producer"]}});
        let total = 1_024_000_000_000;
        let policy = canary227_peer::memory_floor(&f, total).unwrap();
        let top_up = policy["memory_floor_top_up_bytes"].as_u64().unwrap();
        let evidence = json!({"unit":canary227::UNIT,"memory_floor_policy":policy,
            "memory_floor_top_up_bytes":top_up,"remaining_hard_memory_growth_bytes":123});
        assert_eq!(
            hard_growth(&f, total, top_up + 123, std::slice::from_ref(&evidence)).unwrap(),
            (123, top_up)
        );
        assert_eq!(hard_growth(&f, total, 123, &[]).unwrap(), (123, 0));
        assert!(
            hard_growth(
                &f,
                total,
                top_up + 123,
                &[evidence.clone(), evidence.clone()]
            )
            .is_err()
        );
        assert!(hard_growth(&f, total, top_up - 1, std::slice::from_ref(&evidence)).is_err());
        let mut foreign = evidence.clone();
        foreign["unit"] = json!("unqualified.service");
        assert!(hard_growth(&f, total, top_up + 123, &[foreign]).is_err());
        let mut wrong = evidence.clone();
        wrong["memory_floor_top_up_bytes"] = json!(top_up - 1);
        assert!(hard_growth(&f, total, top_up + 123, &[wrong]).is_err());
        let mut wrong = evidence;
        wrong["memory_floor_policy"] = Value::Null;
        assert!(hard_growth(&f, total, top_up + 123, &[wrong]).is_err());
    }
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
