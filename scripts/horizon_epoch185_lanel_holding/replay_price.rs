//! Add the incremental cost of the serial holding reservation to both projections of the
//! candidate replay tree, preserving the original distance between the native and donor floors.
use super::*;

const CADENCE: &str = "/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1/tools-cold168-retry4-failed166-v7-entry146/deployment-seal-receipt.json";
const CADENCE_SHA: &str = "c1b777be3164beca0db8afc9777a02bbbd8f7babc09acf063acb00297cd51504";

fn check_event(fleet: &Value, fleet_ref: &Value, state: &Value) -> Result<()> {
    let transfers = fleet["actual_active_holding_transfers"]
        .as_array()
        .context("missing holding census")?;
    let reservation = &state["holding_reservation"];
    let Some(event_ref) = fleet.get("epoch185_lanel_holding") else {
        // A start can precede the next 30-minute fleet sample.
        ensure!(
            reservation.is_null() || transfers.is_empty(),
            "overlapping serial holding commitment"
        );
        return Ok(());
    };
    ensure!(
        !reservation.is_null(),
        "recorded holding commitment disappeared"
    );
    let path = Path::new(text(event_ref, "path")?);
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("holding event name")?;
    ensure!(
        path.parent() == Path::new(text(fleet_ref, "path")?).parent()
            && name
                .strip_prefix("HOLDING185-")
                .and_then(|s| s.strip_suffix(".json"))
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())),
        "different cadence event directory or name"
    );
    let event = read_bound(event_ref)?;
    ensure!(
        event["schema"] == "horizon-epoch185-lanel-cadence-event-v1"
            && event["fleet"] == fleet["previous_Root_operational_review"]
            && event["observer"] == fleet["observer"],
        "wrong cadence predecessor or sample"
    );
    let old = &event["result"];
    let ticket = &old["holding_reservation"];
    let recorded_live = !old["active_transfer"].is_null();
    ensure!(
        (recorded_live && transfers.as_slice() == std::slice::from_ref(event_ref))
            || (!recorded_live && transfers.is_empty()),
        "different serial holding actors"
    );
    ensure!(
        ticket["admission"] == reservation["admission"]
            && ticket["unit"] == UNIT
            && (ticket["start"].is_null() || ticket["start"] == reservation["start"])
            && (old["observation"]["stage"] != "custody-recorded"
                || (state["observation"]["stage"] == "custody-recorded"
                    && old["observation"]["custody"] == state["observation"]["custody"])),
        "different holding generation"
    );
    Ok(())
}

fn add_required(q: &mut Value, key: &str, extra: u64) -> Result<()> {
    let v = amount(q, key)?
        .checked_add(extra)
        .context("reservation overflow")?;
    q[key] = json!(v);
    Ok(())
}

fn charge(native: &mut Value, lane: &str, extra: u64, available: u64) -> Result<()> {
    let zero = format!("full{lane}_zero_remaining_native_HOME_bytes");
    let donor = &mut native["epoch159_donor_cover"];
    let remaining = amount(donor, "remaining_home_bytes")?
        .checked_sub(extra)
        .context("unfunded holding restore enlargement in donor budget")?;
    add_required(donor, "native_home_required", extra)?;
    let required = amount(donor, "native_home_required")?;
    ensure!(
        required <= available,
        "epoch 185 holding reserve requires {required} HOME bytes, available {available}"
    );
    donor["remaining_home_bytes"] = json!(remaining);
    for k in [
        "complete_required_HOME_bytes",
        "protected_raw_floor_bytes",
        zero.as_str(),
    ] {
        add_required(native, k, extra)?;
    }
    Ok(())
}

fn apply_booking(q: &mut Value, f: &Value, book: &Value, review: &Value, lane: &str) -> Result<()> {
    ensure!(
        q["status_registration"]["consumer_seal"] == ref_for(Path::new(CADENCE), CADENCE_SHA),
        "occupied epoch 185 requires qualified cadence"
    );
    let cost = rotation_cost(q, f, review)?;
    ensure!(
        book["serial_restore_enlargement_bytes"] == cost["serial_restore_enlargement_bytes"]
            && book["metadata_allowance_bytes"] == cost["metadata_allowance_bytes"],
        "serial reservation differs from current fleet"
    );
    let additional = amount(book, "serial_restore_enlargement_bytes")?
        .checked_add(amount(book, "metadata_allowance_bytes")?)
        .context("reservation overflow")?;
    let available = amount(q, "available_HOME_bytes")?.min(amount(
        f,
        "complete_cycle_conservative_available_DATA_bytes",
    )?);
    charge(q, lane, additional, available)
}

pub(super) fn apply(lane: &str) -> Result<Value> {
    ensure!(matches!(lane, "166" | "170"), "unsupported replay");
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take((2 << 20) + 1)
        .read_to_end(&mut input)?;
    ensure!(input.len() <= 2 << 20, "oversized price input");
    let mut args: Value = serde_json::from_slice(&input)?;
    let mut q = args["native"].take();
    let state = super::stable_reconciliation()?;
    ensure!(
        state == args["before"],
        "holding changed during native price"
    );
    ensure!(
        q["schema"] == "horizon-incident-replay-fit-v1"
            && q["epoch"] == 145
            && q["resource_credit_bytes"] == 0
            && q["replay_launch_authorized"] == false
            && q.get("epoch185_lanel_holding").is_none()
            && q["epoch159_donor_cover"]["fleet"] == q["fleet"]
            && q["epoch159_donor_cover"]["native_recorded_unix_seconds"]
                == q["recorded_unix_seconds"],
        "foreign or already adjusted replay price"
    );
    let f = read_bound(&q["fleet"])?;
    check_event(&f, &q["fleet"], &state)?;
    let book = &state["holding_reservation"];
    if !book.is_null() {
        let review = read_bound(&state["observation"]["transfer_review"])?;
        apply_booking(&mut q, &f, book, &review, lane)?;
    }
    q["epoch185_lanel_holding"] = state;
    Ok(q)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn charges_current_and_fully_grown_trees_and_donor_once() {
        let raw = json!({"complete_required_HOME_bytes":100,"protected_raw_floor_bytes":85,"full166_zero_remaining_native_HOME_bytes":97,
            "epoch159_donor_cover":{"native_home_required":125,"remaining_home_bytes":12}});
        let mut adjusted = raw.clone();
        charge(&mut adjusted, "166", 10, 135).unwrap();
        assert_eq!(adjusted["full166_zero_remaining_native_HOME_bytes"], 107);
        assert_eq!(adjusted["complete_required_HOME_bytes"], 110);
        assert_eq!(adjusted["protected_raw_floor_bytes"], 95);
        assert_eq!(
            adjusted["epoch159_donor_cover"]["native_home_required"],
            135
        );
        assert_eq!(adjusted["epoch159_donor_cover"]["remaining_home_bytes"], 2);
        assert!(charge(&mut raw.clone(), "166", 10, 134).is_err());
        assert!(charge(&mut raw.clone(), "166", 13, 999).is_err());
    }
    #[test]
    fn reserved_and_terminal_cost_uses_exact_cadence_and_conservative_free_bytes() {
        let book = json!({"serial_restore_enlargement_bytes":40,"metadata_allowance_bytes":2});
        let review = json!({"historical_serial":{"sha256":"serial"},"metadata_allowance_bytes":2});
        let mut fleet = json!({"active_serial_holding_authority":review["historical_serial"],"complete_cycle_conservative_available_DATA_bytes":1042,
            "retry9_auxiliary_commitments":{"holding_serial":true,"holding_cpu_quota_micros":2000000,
            "holding_memory_bytes":2u64<<30,"holding_staging_bytes":0,"holding_restore_overlap_bytes":LENGTH-40}});
        let raw = json!({"status_registration":{"consumer_seal":ref_for(Path::new(CADENCE),CADENCE_SHA)},"fits":true,
            "schema":"horizon-incident-replay-fit-v1","resource_credit_bytes":0,"replay_launch_authorized":false,
            "bounded_qualification":null,"candidate":null,"registered_retry11_holding":{"stage":"completed-copy"},"registered_cold168_holding":{"stage":"completed-copy"},
            "complete_required_HOME_bytes":920,"protected_raw_floor_bytes":900,"full170_zero_remaining_native_HOME_bytes":912,
            "available_HOME_bytes":1050,"epoch159_donor_cover":{"native_home_required":1000,"remaining_home_bytes":43}});
        let mut q = raw.clone();
        apply_booking(&mut q, &fleet, &book, &review, "170").unwrap();
        assert_eq!(q["full170_zero_remaining_native_HOME_bytes"], 954);
        assert_eq!(q["epoch159_donor_cover"]["remaining_home_bytes"], 1);
        assert_eq!(q["resource_credit_bytes"], 0);
        let mut foreign = raw.clone();
        foreign["status_registration"]["consumer_seal"]["sha256"] = json!("foreign");
        assert!(apply_booking(&mut foreign, &fleet, &book, &review, "170").is_err());
        let mut different = book.clone();
        different["serial_restore_enlargement_bytes"] = json!(39);
        assert!(apply_booking(&mut raw.clone(), &fleet, &different, &review, "170").is_err());
        fleet["complete_cycle_conservative_available_DATA_bytes"] = json!(1041);
        assert!(apply_booking(&mut raw.clone(), &fleet, &book, &review, "170").is_err());
    }
}
