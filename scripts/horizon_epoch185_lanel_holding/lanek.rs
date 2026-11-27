//! Reuse the paid serial transfer slot only after the lane-l custody handback.
use super::*;

pub(super) const LANE: HoldingLane = HoldingLane {
    root: "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1",
    unit: "horizon-closed185-lanek-park-20261127-v1.service",
    group: "/system.slice/horizon-closed185-lanek-park-20261127-v1.service",
    review: "b2ab6a023abb0bc0791561280a8cc8967e13ea5b40fd69616ba2174f59998eb7",
    manifest: "c62a2eec03efacb86947eac6c8c123b0d51476dad3cc019cb277b5643924c5e7",
    length: 66_545_963_870,
    schema: "horizon-epoch185-lanek-holding-observation-v1",
};

fn check_cost(fit: &Value, review: &Value, prior: &Value) -> Result<()> {
    let reservation = &prior["result"]["holding_reservation"];
    ensure!(
        prior["schema"] == "horizon-epoch185-lanel-cadence-event-v1"
            && prior["result"]["observation"]["stage"] == "custody-recorded"
            && prior["result"].get("active_transfer") == Some(&Value::Null)
            && reservation["unit"] == LANE_L.unit
            && reservation["start"] == review["prior_serial_start"]
            && reservation["restore_overlap_bytes"] == LANE_L.length
            && fit["schema"] == "horizon-epoch185-lanek-holding-fit-v1"
            && fit["fits"] == true
            && fit["cpu_quota_micros"] == 2_000_000
            && fit["memory_bytes"] == (2u64 << 30)
            && fit["archive_staging_bytes"] == 0
            && fit["restore_overlap_bytes"] == LANE.length
            && fit["serial_restore_slot_bytes"] == LANE_L.length
            && fit["serial_restore_enlargement_bytes"] == 0
            && fit["metadata_allowance_bytes"] == review["metadata_allowance_bytes"]
            && fit["resource_credit_bytes"] == 0,
        "foreign booking or occupied serial slot"
    );
    let home = amount(fit, "required_home_bytes")?;
    let ram = amount(fit, "required_ram_bytes")?;
    ensure!(
        home >= LANE_L.length
            && home <= amount(fit, "available_home_bytes")?
            && ram >= amount(fit, "memory_bytes")?
            && ram <= amount(fit, "available_ram_bytes")?,
        "unfunded serial holding fit"
    );
    Ok(())
}

pub(super) fn booking_cost(
    booking: &Value,
    fit: &Value,
    fleet: &Value,
    review: &Value,
    observed: &Value,
) -> Result<Value> {
    ensure!(
        booking["transfer_review"] == observed["transfer_review"]
            && booking["serial_restore_slot_bytes"] == LANE_L.length
            && fleet["active_serial_holding_authority"] == review["historical_serial"]
            && fleet["epoch185_lanel_holding"] == fit["retained_lane_l"]
            && fleet["actual_active_holding_transfers"] == json!([]),
        "holding ticket differs from accepted roster"
    );
    let prior = read_bound(&fit["retained_lane_l"])?;
    ensure!(
        prior["observer"] == fleet["observer"]
            && prior["fleet"] == fleet["previous_Root_operational_review"],
        "different handback sample"
    );
    check_cost(fit, review, &prior)?;
    read_bound(&review["historical_serial"])?;
    read_bound(&prior["result"]["observation"]["custody"])?;
    let screen = read_bound(&fit["price"])?;
    ensure!(
        screen["schema"] == "horizon-epoch140-bounded-recording-resource-screen-v1"
            && screen["fleet"] == fit["fleet"]
            && screen["resource_credit_bytes"] == 0
            && amount(fit, "recorded_unix_seconds")?
                .checked_sub(amount(&screen, "recorded_unix_seconds")?)
                .is_some_and(|age| age <= 120)
            && amount(fit, "required_home_bytes")?
                >= amount(&screen, "retained_required_home_bytes")?
            && amount(fit, "required_ram_bytes")?
                >= amount(&screen, "retained_required_ram_bytes")?,
        "native capacity screen differs from admission"
    );
    match fit
        .get("epoch140")
        .context("missing epoch 140 disposition")?
    {
        Value::Null => (),
        actor => {
            let booked = read_bound(&actor["booking"])?;
            read_bound(&actor["held_owner"])?;
            read_bound(&actor["cpu_loan"])?;
            ensure!(
                booked["unit"] == "horizon-epoch140-suffix-recording.service"
                    && amount(actor, "reserved_home_bytes")? == amount(&booked, "HOME_bytes")?
                    && amount(actor, "reserved_ram_bytes")? == amount(&booked, "RAM_bytes")?,
                "epoch 140 reservation changed"
            );
        }
    }
    Ok(json!({
        "fits_after_serial_handback":true, "serial_restore_enlargement_bytes":0,
        "metadata_allowance_bytes":fit["metadata_allowance_bytes"]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_larger_restore_window_funds_only_one_serial_transfer() {
        let review =
            json!({"prior_serial_start":{"sha256":"a"}, "metadata_allowance_bytes": 2097152});
        let mut prior = json!({"schema":"horizon-epoch185-lanel-cadence-event-v1","result":{
            "observation":{"stage":"custody-recorded"},"active_transfer":null,
            "holding_reservation":{"unit":LANE_L.unit,"start":review["prior_serial_start"],
            "restore_overlap_bytes": LANE_L.length}}});
        let fit = json!({"schema":"horizon-epoch185-lanek-holding-fit-v1","fits":true,
            "cpu_quota_micros":2000000,"memory_bytes":2u64<<30,"archive_staging_bytes":0,
            "restore_overlap_bytes": LANE.length,"serial_restore_slot_bytes": LANE_L.length,
            "serial_restore_enlargement_bytes":0,"metadata_allowance_bytes":2097152,"resource_credit_bytes":0,
            "available_home_bytes":LANE_L.length, "required_home_bytes":LANE_L.length,
            "available_ram_bytes":2u64<<30,"required_ram_bytes":2u64<<30});
        check_cost(&fit, &review, &prior).unwrap();
        for key in [
            "available_home_bytes",
            "available_ram_bytes",
            "serial_restore_slot_bytes",
            "restore_overlap_bytes",
            "cpu_quota_micros",
        ] {
            let mut changed = fit.clone();
            changed[key] = json!(amount(&fit, key).unwrap() - 1);
            assert!(check_cost(&changed, &review, &prior).is_err(), "{key}");
        }
        prior["result"]["active_transfer"] = prior["result"]["holding_reservation"].clone();
        assert!(check_cost(&fit, &review, &prior).is_err());
    }
}
