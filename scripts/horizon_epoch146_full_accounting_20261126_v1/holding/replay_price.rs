//! Add the incremental cost of the serial holding reservation to both projections of the
//! candidate replay tree, preserving the original distance between the native and donor floors.
use super::*;

const CADENCE: &str = "/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1/tools-cold168-retry4-failed166-v7-entry146/deployment-seal-receipt.json";
const CADENCE_SHA: &str = "c1b777be3164beca0db8afc9777a02bbbd8f7babc09acf063acb00297cd51504";
const CADENCE20: &str = "/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v20-entry146/deployment-seal-receipt.json";
const CADENCE21: &str = "/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v21-entry146/deployment-seal-receipt.json";
const CADENCE22: &str = "/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v22-entry146/deployment-seal-receipt.json";
const CADENCE23: &str = "/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v23-entry146/deployment-seal-receipt.json";
const CADENCE24: &str = "/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v24-entry146/deployment-seal-receipt.json";
const CADENCE25: &str = "/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v25-entry146/deployment-seal-receipt.json";
const FULL170_UNIT: &str = "horizon-qualify-170-full-metered-20261124-v1.service";
const FOCUSED168_UNIT: &str = "horizon-qualify-168-full-metered-cold-v6-20261126.service";

const FOCUSED168_TERMINAL: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch168-retry6-rebook-20261126-v1/FOCUSED_TERMINAL.json";
const FOCUSED168_TERMINAL_SHA: &str =
    "5e67a984da9df5350bfce86060557a18603dbac5a18a06747c272922d14b7b71";

fn exact_terminal(q: &Value) -> bool {
    let focused = &q["focused168_retry6"];
    matches!(
        q["status_registration"]["consumer_seal"]["path"].as_str(),
        Some(CADENCE24 | CADENCE25)
    ) && focused["terminal"] == ref_for(Path::new(FOCUSED168_TERMINAL), FOCUSED168_TERMINAL_SHA)
        && focused["resource_credit_bytes"] == 0
        && focused["processes"].as_array().is_some_and(Vec::is_empty)
        && q["population"].get(FOCUSED168_UNIT).is_none()
}

pub(super) fn active_cadence_basis(q: &Value) -> Result<bool> {
    if q["epoch"] != 170
        || !matches!(
            q["status_registration"]["consumer_seal"]["path"].as_str(),
            Some(CADENCE20 | CADENCE21 | CADENCE22 | CADENCE23 | CADENCE24 | CADENCE25)
        )
    {
        return Ok(false);
    }
    let full = &q["epoch170_metered_full"];
    let actor = &q["candidate"];
    let focus = &q["focused168_retry6"];
    let raw = amount(q, "protected_raw_floor_bytes")?;
    let complete = raw
        .checked_add(amount(&q["bookings"]["170"], "remaining_bytes")?)
        .context("overflow in epoch 170 booking")?;
    let floor = amount(focus, "minimum_free_bytes")?;
    Ok(full["stage"] == "active"
        && full["producer_unit"] == FULL170_UNIT
        && actor["producer_unit"] == FULL170_UNIT
        && iid_valid(text(full, "producer_invocation_id")?)
        && actor["producer_invocation_id"] == full["producer_invocation_id"]
        && actor["armed_floor"] == raw
        && amount(full, "candidate_repriced_floor_bytes")? <= raw
        && complete == amount(q, "full170_required_HOME_bytes")?
        && complete.max(floor) == amount(q, "complete_required_HOME_bytes")?
        && (exact_terminal(q)
            || (focus.get("terminal").is_none()
                && q["population"][FOCUSED168_UNIT]
                    .as_array()
                    .is_some_and(|members| members.len() == 2)))
        && q["bookings"]["168"]["remaining_bytes"] == focus["paid"]["remaining_bytes"]
        && q["bookings"]["168"]["remaining_bytes"]
            == q["retry5_complete_booking"]["candidate_remaining_bytes"]
        && q["epoch159_donor_cover"]["fleet"] == q["fleet"]
        && q["epoch159_donor_cover"]["native_recorded_unix_seconds"] == q["recorded_unix_seconds"])
}

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

fn price_input() -> Result<Value> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take((2 << 20) + 1)
        .read_to_end(&mut input)?;
    ensure!(input.len() <= 2 << 20, "oversized price input");
    Ok(serde_json::from_slice(&input)?)
}

pub(super) fn apply(lane: &str) -> Result<Value> {
    ensure!(matches!(lane, "166" | "170"), "unsupported replay");
    let mut args = price_input()?;
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

fn active_booking(q: &mut Value, fleet: &Value, book: &Value, review: &Value) -> Result<()> {
    let cost = rotation_cost(q, fleet, review)?;
    ensure!(
        cost["serial_restore_enlargement_bytes"] == book["serial_restore_enlargement_bytes"]
            && cost["metadata_allowance_bytes"] == book["metadata_allowance_bytes"],
        "serial reservation differs from the active fleet"
    );
    // Keep the incumbent guard equations available independently of this
    // serial enlargement. Future restore admission uses this outer floor.
    q["complete_required_HOME_bytes"] = cost["required_home_bytes"].clone();
    q["available_HOME_bytes"] = cost["available_home_bytes"].clone();
    q["fits"] = cost["fits_after_serial_handback"].clone();
    q["epoch185_serial_cost"] = cost;
    Ok(())
}

pub(super) fn apply_active() -> Result<Value> {
    let mut input = price_input()?;
    let mut quote = input["native"].take();
    let state = super::stable_reconciliation()?;
    ensure!(
        state == input["before"]
            && quote["schema"] == "horizon-incident-replay-fit-v1"
            && quote["epoch"] == 170
            && quote["resource_credit_bytes"] == 0
            && quote["replay_launch_authorized"] == false
            && quote.get("epoch185_lanel_holding").is_none()
            && quote.get("epoch185_serial_cost").is_none(),
        "foreign, changed or already adjusted active replay price"
    );
    let fleet = read_bound(&quote["fleet"])?;
    if fleet.get("epoch185_lanel_holding").is_none() {
        ensure!(
            fleet["actual_active_holding_transfers"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "unregistered active holding transfer"
        );
    }
    check_event(&fleet, &quote["fleet"], &state)?;
    if quote["focused168_retry6"].get("terminal").is_some() {
        ensure!(
            exact_terminal(&quote)
                && quote["focused168_retry6"]["terminal"]
                    == fleet["current_cold168_retry6_terminal"]
                && fleet.get("current_cold168_retry6_focused").is_none(),
            "focused epoch 168 terminal is not bound by the accepted fleet"
        );
    }
    let book = &state["holding_reservation"];
    if !book.is_null() {
        let cadence = &input["cadence_seal"];
        let cadence_path = text(cadence, "path")?;
        ensure!(
            quote["status_registration"]["consumer_seal"] == *cadence
                && matches!(
                    cadence_path,
                    CADENCE20 | CADENCE21 | CADENCE22 | CADENCE23 | CADENCE24 | CADENCE25
                )
                && active_cadence_basis(&quote)?,
            "occupied epoch 185 requires the sealed active fleet price"
        );
        let seal = read_bound(cadence)?;
        ensure!(
            seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
                && seal["destination"]
                    == Path::new(cadence_path)
                        .parent()
                        .context("V20 seal directory")?
                        .to_string_lossy()
                        .as_ref()
                && seal["remote_mutations"] == false,
            "foreign holding cadence seal"
        );
        let review = read_bound(&state["observation"]["transfer_review"])?;
        active_booking(&mut quote, &fleet, book, &review)?;
    }
    quote["epoch185_lanel_holding"] = state;
    Ok(quote)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn active_fixture() -> (Value, Value, Value, Value) {
        let book = json!({"serial_restore_enlargement_bytes":40,"metadata_allowance_bytes":2});
        let review = json!({"historical_serial":{"sha256":"serial"},"metadata_allowance_bytes":2});
        let fleet = json!({"active_serial_holding_authority":review["historical_serial"],
            "complete_cycle_conservative_available_DATA_bytes":1142,
            "retry9_auxiliary_commitments":{"holding_serial":true,"holding_cpu_quota_micros":2000000,
            "holding_memory_bytes":2u64<<30,"holding_staging_bytes":0,"holding_restore_overlap_bytes":LENGTH-40}});
        let iid = "a12dd506a77b4b18810129a4de84a831";
        let quote = json!({"schema":"horizon-incident-replay-fit-v1","epoch":170,
            "status_registration":{"consumer_seal":{"path":CADENCE20}},
            "fits":true,"resource_credit_bytes":0,"replay_launch_authorized":false,
            "recorded_unix_seconds":100,"bounded_qualification":null,"fleet":{"sha256":"a"},
            "candidate":{"producer_unit":FULL170_UNIT,"producer_invocation_id":iid,"armed_floor":900},
            "epoch170_metered_full":{"stage":"active","producer_unit":FULL170_UNIT,
                "producer_invocation_id":iid,"candidate_repriced_floor_bytes":899},
            "population":{FOCUSED168_UNIT:[[1,2],[3,4]]},
            "focused168_retry6":{"minimum_free_bytes":1100,"paid":{"remaining_bytes":40}},
            "bookings":{"168":{"remaining_bytes":40},"170":{"remaining_bytes":100}},
            "retry5_complete_booking":{"candidate_remaining_bytes":40},
            "registered_retry11_holding":{"stage":"completed-copy"},
            "registered_cold168_holding":{"stage":"completed-copy"},
            "complete_required_HOME_bytes":1100,"protected_raw_floor_bytes":900,
            "full170_required_HOME_bytes":1000,"available_HOME_bytes":1200,
            "epoch159_donor_cover":{"native_home_required":1000,"remaining_home_bytes":45,
                "fleet":{"sha256":"a"},"native_recorded_unix_seconds":100}});
        (quote, fleet, book, review)
    }

    #[test]
    fn active_serial_enlargement_uses_the_joint_floor_once() {
        let (mut quote, mut fleet, book, review) = active_fixture();
        assert_eq!(
            rotation_cost(&quote, &fleet, &review).unwrap()["required_home_bytes"],
            1142
        );
        active_booking(&mut quote, &fleet, &book, &review).unwrap();
        assert_eq!(quote["complete_required_HOME_bytes"], 1142);
        assert_eq!(quote["available_HOME_bytes"], 1142);
        assert_eq!(quote["protected_raw_floor_bytes"], 900);
        assert_eq!(quote["full170_required_HOME_bytes"], 1000);
        assert_eq!(quote["epoch159_donor_cover"]["remaining_home_bytes"], 45);
        assert_eq!(
            quote["retry5_complete_booking"]["candidate_remaining_bytes"],
            40
        );
        assert_eq!(quote["fits"], true);
        assert!(active_booking(&mut quote, &fleet, &book, &review).is_err());
        let (mut quote, _, _, _) = active_fixture();
        fleet["complete_cycle_conservative_available_DATA_bytes"] = json!(1141);
        active_booking(&mut quote, &fleet, &book, &review).unwrap();
        assert_eq!(quote["fits"], false);
    }

    #[test]
    fn active_serial_quote_accepts_the_raised_guard_cadence() {
        for path in [CADENCE21, CADENCE22, CADENCE23] {
            let (mut quote, fleet, book, review) = active_fixture();
            quote["status_registration"]["consumer_seal"]["path"] = json!(path);
            active_booking(&mut quote, &fleet, &book, &review).unwrap();
            assert_eq!(quote["complete_required_HOME_bytes"], 1142);
        }
    }

    #[test]
    fn terminal_focused168_preserves_the_prior_floor_and_serial_reservation() {
        let (mut quote, fleet, book, review) = active_fixture();
        quote["status_registration"]["consumer_seal"]["path"] = json!(CADENCE24);
        quote["population"]
            .as_object_mut()
            .unwrap()
            .remove(FOCUSED168_UNIT);
        quote["focused168_retry6"]["terminal"] =
            ref_for(Path::new(FOCUSED168_TERMINAL), FOCUSED168_TERMINAL_SHA);
        quote["focused168_retry6"]["resource_credit_bytes"] = json!(0);
        quote["focused168_retry6"]["processes"] = json!([]);
        assert!(active_cadence_basis(&quote).unwrap());
        let mut credited = quote.clone();
        credited["focused168_retry6"]["resource_credit_bytes"] = json!(1);
        assert!(!active_cadence_basis(&credited).unwrap());
        let mut active = quote.clone();
        active["population"][FOCUSED168_UNIT] = json!([[1, 2], [3, 4]]);
        assert!(!active_cadence_basis(&active).unwrap());
        let mut foreign = quote.clone();
        foreign["focused168_retry6"]["terminal"]["sha256"] = json!("foreign");
        assert!(!active_cadence_basis(&foreign).unwrap());
        active_booking(&mut quote, &fleet, &book, &review).unwrap();
        assert_eq!(quote["complete_required_HOME_bytes"], 1142);
        assert_eq!(
            quote["epoch185_serial_cost"]["serial_restore_enlargement_bytes"],
            40
        );
    }

    #[test]
    fn active_serial_quote_rejects_crossed_guard_worker_or_writer() {
        let (quote, fleet, book, review) = active_fixture();
        for (path, value) in [
            ("/candidate", Value::Null),
            (
                "/epoch170_metered_full/candidate_repriced_floor_bytes",
                json!(901),
            ),
            ("/focused168_retry6/minimum_free_bytes", json!(1101)),
            ("/focused168_retry6/paid/remaining_bytes", json!(41)),
            ("/status_registration/consumer_seal/path", json!(CADENCE)),
        ] {
            let mut crossed = quote.clone();
            *crossed.pointer_mut(path).unwrap() = value;
            assert!(active_booking(&mut crossed, &fleet, &book, &review).is_err());
        }
    }

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
