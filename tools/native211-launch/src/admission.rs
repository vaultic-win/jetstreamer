//! One fresh, complete current-fleet decision. No fixed historical peer count.
use super::*;
fn prestart(lifecycle: &Value, review: &Value, self_sha: &str) -> Result<()> {
    ensure!(
        lifecycle["schema"] == "horizon-native211-prestart-qualification-v1"
            && lifecycle["harness"] == json!(Bound::new(HARNESS, HARNESS_SHA))
            && lifecycle["guard"] == review["guard"]
            && lifecycle["source_publication"] == review["source_publication"]
            && lifecycle["observer_complete_tuple_accepted"] == true
            && lifecycle["fleet_running_and_terminal_accepted"] == true
            && lifecycle["inactive_status_exact_owner_accepted"] == true
            && lifecycle["terminal_retention_accepted"] == true
            && lifecycle["pre_restore_gate_tests_accepted"] == true
            && lifecycle["actual_first_guard_required_before_snapshot"] == true
            && lifecycle["actual_native_startup_qualified"] == false
            && lifecycle["launcher_artifact_sha256"] == self_sha,
        "epoch211 pre-start consumers or gate enforcement not qualified"
    );
    Ok(())
}
pub(super) fn reservations(review: &Value) -> Result<Vec<capacity::Reservation>> {
    let ledger = binding(&review["reservation_ledger"])?.sealed()?;
    ensure!(
        ledger["schema"] == "horizon-native211-retained-reservations-v1"
            && ledger["Main_accepted"] == true
            && ledger["all_active_and_dormant_obligations_preserved"] == true
            && ledger["fleet"] == review["fleet"]
            && ledger["observer"] == review["observer"],
        "reservation ledger binding"
    );
    no_authority(&ledger)?;
    let rows: Vec<capacity::Reservation> = serde_json::from_value(ledger["reservations"].clone())?;
    ensure!(
        !rows.is_empty() && rows.len() <= 128,
        "reservation census bounds"
    );
    let mut names = BTreeSet::new();
    for r in &rows {
        ensure!(
            names.insert(&r.unit) && hex(&r.invocation_id, 32),
            "duplicate/invalid reservation owner"
        );
        // Per-owner booking is a separately accepted immutable extraction, retaining
        // its original admission/handoff; it cannot be replaced by an unbound number.
        let s = r.source.sealed()?;
        ensure!(
            s["schema"] == "horizon-native211-existing-booking-v1"
                && s["Main_accepted"] == true
                && s["unit"] == r.unit
                && s["invocation_id"] == r.invocation_id
                && s["maximum_memory_bytes"] == r.maximum_memory_bytes
                && s["remaining_disk_growth_bytes"] == r.remaining_disk_growth_bytes
                && s["minimum_free_bytes"] == r.minimum_free_bytes,
            "existing booking differs"
        );
        let original = binding(&s["original_admission_or_handoff"])?.json()?;
        for key in [
            "maximum_memory_bytes",
            "remaining_disk_growth_bytes",
            "minimum_free_bytes",
        ] {
            let pointer = text(&s["original_field_pointers"], key)?;
            ensure!(
                original.pointer(pointer) == Some(&s[key]),
                "booking not derived from original evidence {key}"
            );
        }
        for key in ["unit", "invocation_id"] {
            let pointer = text(&s["original_field_pointers"], key)?;
            ensure!(
                original.pointer(pointer) == Some(&s[key]),
                "booking owner provenance differs"
            );
        }
    }
    // Supplied predecessor is the accepted host booking, not a caller-selected subset.
    let previous = binding(&ledger["previous_accepted_booking"])?.sealed()?;
    ensure!(
        previous["schema"] == "horizon-native211-prior-host-booking-v1"
            && previous["Main_accepted"] == true
            && previous["complete_host_booking"] == true,
        "missing prior complete host booking"
    );
    let prior = previous["reservations"]
        .as_array()
        .context("prior bookings")?;
    ensure!(!prior.is_empty(), "empty prior host booking");
    for p in prior {
        let unit = text(p, "unit")?;
        let r = rows
            .iter()
            .find(|r| r.unit == unit)
            .context("silently dropped historical reservation")?;
        ensure!(
            p["invocation_id"] == r.invocation_id
                && p["maximum_memory_bytes"] == r.maximum_memory_bytes
                && num(p, "remaining_disk_growth_bytes")? <= r.remaining_disk_growth_bytes
                && num(p, "minimum_free_bytes")? <= r.minimum_free_bytes,
            "historical booking lowered without separate qualified transition"
        );
    }
    Ok(rows)
}
pub(super) fn validate(
    n: &mut Native,
    review: &Value,
    review_ref: &Bound,
    self_sha: &str,
    candidate: bool,
) -> Result<Value> {
    ensure!(
        review["schema"] == "horizon-native211-current-fleet-review-v1"
            && review["epoch"] == 211
            && review["Main_accepted"] == true
            && review["single_campaign_controller_confirmed"] == true,
        "unaccepted current-fleet review"
    );
    no_authority(review)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    ensure!(review["boot_id"] == boot, "review belongs to another boot");
    fresh(num(review, "recorded_unix_seconds")?, now()?, 300)?;
    let owner_pid = num(review, "main_controller_pid")?;
    let stat = fs::read_to_string(format!("/proc/{owner_pid}/stat"))?;
    let ticks = stat
        .rsplit_once(')')
        .context("controller stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("controller start ticks")?
        .parse::<u64>()?;
    ensure!(
        review["main_controller_start_ticks"] == ticks,
        "campaign controller replaced"
    );
    let guard = binding(&review["guard"])?;
    guard.artifact()?;
    ensure!(
        guard == Bound::new(GUARD, GUARD_SHA),
        "guard deployment differs from qualified gated image"
    );
    let source = binding(&review["source_publication"])?.sealed()?;
    if !candidate {
        publication::validate(n, &source, &guard, self_sha)?;
    }
    // Admission may start the exact harness only into its internal waiting gate.
    // The current invocation's first native guard proof cannot exist yet: launch
    // must capture and validate it before publishing the restore token.
    let lifecycle = binding(&review["prestart_qualification"])?.sealed()?;
    prestart(&lifecycle, review, self_sha)?;
    binding(&lifecycle["qualification_evidence"])?.json()?;
    let fleet = binding(&review["fleet"])?.json()?;
    let observer = binding(&review["observer"])?.json()?;
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["observer_receipt"] == review["observer"]["path"]
            && fleet["observer_sha256"] == review["observer"]["sha256"]
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && fleet["memory_target"]["valid"] == true,
        "fleet/observer binding"
    );
    fresh(num(&fleet, "recorded_unix_seconds")?, now()?, 300)?;
    ensure!(
        fleet["pipelines"] == json!([])
            && fleet["diagnostics"] == json!([])
            && fleet["auxiliary_diagnostics"] == json!([]),
        "unimplemented non-replay lifecycle owner; fail closed"
    );
    ensure!(
        observer["cadence"]["routine_minimum_interval_enforced"] == true
            && num(&observer["cadence"], "observed_interval_seconds")? >= 1800,
        "complete cadence observation required"
    );
    let rows = reservations(review)?;
    let currents = live::census(n, review, &fleet, &rows, candidate)?;
    let (total, available, disk) = live::resources()?;
    let obs_total = num(&observer["host_memory"], "total_kib")?
        .checked_mul(1024)
        .context("memory overflow")?;
    ensure!(total == obs_total, "host memory changed");
    let century = capacity::century(&binding(&review["century"])?.sealed()?, &fleet)?;
    let cap = capacity::arithmetic(total, available, disk, century, &rows, &currents)?;
    let mut admission = json!({"schema":"horizon-native211-current-fleet-admission-v1","epoch":211,"mode":"native-cold","unit":UNIT,
        "private_run_root":ROOT,"maximum_memory_bytes":MEMORY,"candidate_incremental_peak_bytes":SCRATCH,
        "protected_existing_floor_bytes":cap["protected_existing_floor_bytes"],"harness":Bound::new(HARNESS,HARNESS_SHA),
        "guard":guard,"boot_id":boot,"admitted":true,"review":review_ref,"source_publication":review["source_publication"],
        "observer":review["observer"],"fleet":review["fleet"],"reservation_ledger":review["reservation_ledger"],
        "capacity":cap,"actual_current_memory":currents,"recorded_unix_seconds":now()?,"expires_unix_seconds":now()?.checked_add(60).context("clock overflow")?});
    deny_authority(&mut admission);
    Ok(admission)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prestart_acceptance_requires_live_first_guard_without_claiming_it_already_happened() {
        let review = json!({"guard":Bound::new(GUARD,GUARD_SHA),"source_publication":{"path":"/var/lib/jetstreamer/source/proof.json","sha256":"a".repeat(64)}});
        let accepted = json!({"schema":"horizon-native211-prestart-qualification-v1",
            "harness":Bound::new(HARNESS,HARNESS_SHA),"guard":review["guard"],"source_publication":review["source_publication"],
            "observer_complete_tuple_accepted":true,"fleet_running_and_terminal_accepted":true,
            "inactive_status_exact_owner_accepted":true,"terminal_retention_accepted":true,
            "pre_restore_gate_tests_accepted":true,"actual_first_guard_required_before_snapshot":true,
            "actual_native_startup_qualified":false,"launcher_artifact_sha256":"b".repeat(64)});
        prestart(&accepted, &review, &"b".repeat(64)).unwrap();
        for (key, value) in [
            (
                "schema",
                json!("horizon-native211-lifecycle-qualification-v1"),
            ),
            ("actual_first_guard_required_before_snapshot", json!(false)),
            ("actual_native_startup_qualified", json!(true)),
            ("pre_restore_gate_tests_accepted", json!(false)),
            ("fleet_running_and_terminal_accepted", json!(false)),
        ] {
            let mut bad = accepted.clone();
            bad[key] = value;
            assert!(prestart(&bad, &review, &"b".repeat(64)).is_err(), "{key}");
        }
    }
}
