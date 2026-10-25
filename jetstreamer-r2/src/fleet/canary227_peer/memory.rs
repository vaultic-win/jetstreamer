//! Producer headroom, independent guard ceiling and native 223 floor are
//! separate reservations. Saved proofs must reproduce all three exactly.
use super::*;
pub(super) const GUARD: u64 = 1 << 30;
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("canary saved memory integer missing: {key}"))
}
pub(super) fn row(
    owner: &str,
    caps: Value,
    floor: Value,
    binding: BoundFile,
    sample: Value,
    proof: Value,
) -> Result<Value> {
    let producer = number(&caps, "remaining_hard_memory_growth_bytes")?;
    let top_up = number(&floor, "memory_floor_top_up_bytes")?;
    let row = json!({"epoch":227,"unit":c::UNIT,"invocation_id":owner,
        "hard_memory_envelope":caps,"memory_floor_policy":floor,
        "guard_unit":PROTECTIVE,"guard":private157::binding(&binding),
        "guard_observation":sample,"actual_guard_timer_proof":proof,
        "guard_hard_memory_reserved_bytes":GUARD,
        "producer_remaining_hard_memory_growth_bytes":producer,
        "memory_floor_top_up_bytes":top_up,
        "remaining_hard_memory_growth_bytes":add_memory(producer, top_up, GUARD)?});
    validate_saved_memory_row(&row)?;
    Ok(row)
}
pub(in crate::fleet) fn validate_saved_memory_row(row: &Value) -> Result<()> {
    let owner = &row["invocation_id"];
    let caps = &row["hard_memory_envelope"];
    let page = number(caps, "host_page_size_bytes")?;
    ensure!(
        (4096..=65536).contains(&page),
        "canary saved memory page size"
    );
    let charge = number(caps, "current_cgroup_charge_bytes")?;
    let producer = memory_values(
        number(caps, "kernel_memory_max_bytes")?,
        number(caps, "kernel_memory_high_bytes")?,
        charge,
        number(caps, "memory_swap_max_bytes")?,
        page,
    )?;
    let properties = &caps["systemd_properties"];
    let expected_max = c::MEMORY.to_string();
    let expected_high = c::HIGH.to_string();
    ensure!(
        row["unit"] == c::UNIT
            && row["epoch"] == 227
            && iid(owner)
            && properties["Id"] == c::UNIT
            && properties["InvocationID"] == *owner
            && properties["MemoryMax"].as_str() == Some(expected_max.as_str())
            && properties["MemoryHigh"].as_str() == Some(expected_high.as_str())
            && properties["MemorySwapMax"] == "0"
            && number(caps, "requested_memory_max_bytes")? == c::MEMORY
            && number(caps, "requested_memory_high_bytes")? == c::HIGH
            && number(caps, "tasks_max")? == 512
            && number(caps, "cpu_period_usec")? > 0
            && number(caps, "cpu_period_usec")?.checked_mul(8)
                == Some(number(caps, "cpu_quota_usec")?)
            && charge
                == number(caps, "cgroup_charge_before_bytes")?
                    .min(number(caps, "cgroup_charge_after_bytes")?)
            && number(caps, "cgroup_charge_before_bytes")?
                <= number(caps, "kernel_memory_max_bytes")?
            && number(caps, "cgroup_charge_after_bytes")?
                <= number(caps, "kernel_memory_max_bytes")?
            && number(caps, "remaining_hard_memory_growth_bytes")? == producer,
        "canary saved producer cap, charge or invocation differs"
    );
    let sample = &row["guard_observation"];
    let proof = &row["actual_guard_timer_proof"];
    if proof["manager"].get("schema").is_some() {
        manager::validate_saved(&proof["manager"], sample)?;
        ensure!(
            proof["completed"] == proof["manager"]["completed_guard"],
            "canary saved peer manager selected another completed fire"
        );
    } else {
        ensure!(
            [
                "successor",
                "properties_after",
                "process_before",
                "process_after",
                "manager_events"
            ]
            .iter()
            .all(|key| proof["manager"].get(*key).is_none()),
            "canary peer lifecycle evidence cannot masquerade as legacy launch proof"
        );
    }
    let binding: BoundFile = serde_json::from_value(row["guard"].clone())?;
    let expected_guard_max = GUARD.to_string();
    ensure!(
        row["guard_unit"] == PROTECTIVE
            && sample["producer_invocation_id"] == *owner
            && sample["producer"]["invocation_id"] == *owner
            && iid(&sample["guard_invocation_id"])
            && proof["manager"]["properties"]["MemoryMax"].as_str()
                == Some(expected_guard_max.as_str())
            && proof["manager"]["manager_completion"]["UNIT"] == PROTECTIVE
            && proof["manager"]["manager_completion"]["INVOCATION_ID"]
                == sample["guard_invocation_id"]
            && proof["completed"]["binding"] == private157::binding(&binding)
            && proof["manager"]["completed_guard"]["binding"] == private157::binding(&binding)
            && number(row, "guard_hard_memory_reserved_bytes")? == GUARD,
        "canary saved independent guard memory or invocation differs"
    );
    let floor = &row["memory_floor_policy"];
    let total = number(floor, "host_total_memory_bytes")?;
    let baseline = total / 10;
    let live = floor["native223_live"]
        .as_bool()
        .context("canary saved native 223 floor state")?;
    let native_floor = if live { PREFIX223_MEMORY_FLOOR } else { 0 };
    let top_up = baseline.max(native_floor) - baseline;
    ensure!(
        total > 0
            && number(floor, "host_baseline_bytes")? == baseline
            && number(floor, "native223_available_memory_floor_bytes")? == native_floor
            && number(floor, "effective_available_memory_floor_bytes")?
                == baseline.max(native_floor)
            && number(floor, "memory_floor_top_up_bytes")? == top_up
            && number(row, "memory_floor_top_up_bytes")? == top_up
            && number(row, "producer_remaining_hard_memory_growth_bytes")? == producer
            && number(row, "remaining_hard_memory_growth_bytes")?
                == add_memory(producer, top_up, GUARD)?,
        "canary saved producer/guard/floor reservation understated or double counted"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        // Synthetic numeric evidence only, never an admission or repaired
        // historical capacity receipt. No manager or filesystem reads.
        let owner = "a".repeat(32);
        let guard_iid = "b".repeat(32);
        let page = 4096;
        let cap = c::MEMORY / page * page;
        let high = c::HIGH / page * page;
        let charge = 100_000_000_000u64;
        let caps = json!({"host_page_size_bytes":page,"kernel_memory_max_bytes":cap,
            "kernel_memory_high_bytes":high,"memory_swap_max_bytes":0,
            "requested_memory_max_bytes":c::MEMORY,"requested_memory_high_bytes":c::HIGH,
            "current_cgroup_charge_bytes":charge,"cgroup_charge_before_bytes":charge+1,
            "cgroup_charge_after_bytes":charge,"remaining_hard_memory_growth_bytes":cap-charge,
            "tasks_max":512,"cpu_period_usec":100000,"cpu_quota_usec":800000,
            "systemd_properties":{"Id":c::UNIT,"InvocationID":owner,
                "MemoryMax":c::MEMORY.to_string(),"MemoryHigh":c::HIGH.to_string(),"MemorySwapMax":"0"}});
        let sample = json!({"producer_invocation_id":owner,"producer":{"invocation_id":owner},
            "guard_invocation_id":guard_iid});
        let binding = BoundFile {
            path: "/synthetic/guard.json".into(),
            sha256: "c".repeat(64),
        };
        let proof = json!({"completed":{"binding":private157::binding(&binding)},
            "manager":{"properties":{"MemoryMax":GUARD.to_string()},
                "manager_completion":{"UNIT":PROTECTIVE,"INVOCATION_ID":guard_iid},
                "completed_guard":{"binding":private157::binding(&binding)}}});
        let mut fleet = json!({"active":[],"unit_census":{}});
        fleet["unit_census"][prefix223_native20::UNIT] = json!({"ActiveState":"active",
            "SubState":"running","InvocationID":PREFIX223_IID});
        let floor = memory_floor(&fleet, 1_000_000_000_000).unwrap();
        row(&owner, caps, floor, binding, sample, proof).unwrap()
    }
    #[test]
    fn producer_guard_and_native_floor_are_each_reserved_once() {
        let row = fixture();
        let producer = number(&row, "producer_remaining_hard_memory_growth_bytes").unwrap();
        let top_up = number(&row, "memory_floor_top_up_bytes").unwrap();
        assert!(top_up > 0);
        assert_eq!(
            number(&row, "remaining_hard_memory_growth_bytes").unwrap(),
            producer + top_up + GUARD
        );
        validate_saved_memory_row(&row).unwrap();
        // Validation is read-only and repeating it does not add another ceiling.
        validate_saved_memory_row(&row).unwrap();
        for guard in [0, GUARD * 2] {
            let mut bad = row.clone();
            bad["guard_hard_memory_reserved_bytes"] = json!(guard);
            bad["remaining_hard_memory_growth_bytes"] = json!(producer + top_up + guard);
            assert!(validate_saved_memory_row(&bad).is_err());
        }
    }
    #[test]
    fn completed_and_ongoing_peer_proofs_keep_exactly_one_independent_gibibyte() {
        for ongoing in [false, true] {
            let mut saved = fixture();
            let (manager, sample) = manager::fixture(ongoing);
            saved["guard"] = manager["completed_guard"]["binding"].clone();
            saved["guard_observation"] = sample;
            saved["actual_guard_timer_proof"] = json!({
                "completed":manager["completed_guard"],"manager":manager});
            validate_saved_memory_row(&saved).unwrap();
            let producer = number(&saved, "producer_remaining_hard_memory_growth_bytes").unwrap();
            let floor = number(&saved, "memory_floor_top_up_bytes").unwrap();
            assert_eq!(
                number(&saved, "remaining_hard_memory_growth_bytes").unwrap(),
                producer + floor + (1 << 30)
            );
            for guard in [0, 2 << 30] {
                let mut bad = saved.clone();
                bad["guard_hard_memory_reserved_bytes"] = json!(guard);
                bad["remaining_hard_memory_growth_bytes"] = json!(producer + floor + guard);
                assert!(validate_saved_memory_row(&bad).is_err());
            }
            let mut changed = saved.clone();
            changed["actual_guard_timer_proof"]["manager"]["properties_after"]["InvocationID"] =
                json!("f".repeat(32));
            assert!(validate_saved_memory_row(&changed).is_err());
            let mut downgraded = saved.clone();
            downgraded["actual_guard_timer_proof"]["manager"]
                .as_object_mut()
                .unwrap()
                .remove("schema");
            assert!(validate_saved_memory_row(&downgraded).is_err());
        }
    }
    #[test]
    fn both_saved_brackets_reject_changed_cap_charge_owner_guard_and_total() {
        let row = fixture();
        let saved = json!({"memory_before":{"protected_memory_evidence":[row]},
            "memory_after":{"protected_memory_evidence":[row]}});
        for phase in ["memory_before", "memory_after"] {
            let valid = &saved[phase]["protected_memory_evidence"][0];
            prefix223_live_peer::validate_saved_row(valid).unwrap();
            for (pointer, value) in [
                (
                    "/hard_memory_envelope/kernel_memory_max_bytes",
                    json!(c::MEMORY),
                ),
                ("/hard_memory_envelope/kernel_memory_high_bytes", json!(1)),
                ("/hard_memory_envelope/memory_swap_max_bytes", json!(1)),
                (
                    "/hard_memory_envelope/current_cgroup_charge_bytes",
                    json!(1),
                ),
                (
                    "/hard_memory_envelope/cgroup_charge_before_bytes",
                    json!(u64::MAX),
                ),
                (
                    "/hard_memory_envelope/systemd_properties/InvocationID",
                    json!("d".repeat(32)),
                ),
                ("/invocation_id", json!("d".repeat(32))),
                (
                    "/guard_observation/producer_invocation_id",
                    json!("d".repeat(32)),
                ),
                (
                    "/guard_observation/producer/invocation_id",
                    json!("d".repeat(32)),
                ),
                (
                    "/guard_observation/guard_invocation_id",
                    json!("d".repeat(32)),
                ),
                (
                    "/actual_guard_timer_proof/manager/properties/MemoryMax",
                    json!("2147483648"),
                ),
                (
                    "/actual_guard_timer_proof/manager/manager_completion/UNIT",
                    json!(c::UNIT),
                ),
                (
                    "/actual_guard_timer_proof/completed/binding/sha256",
                    json!("d".repeat(64)),
                ),
                ("/guard_unit", json!(c::UNIT)),
                ("/guard_hard_memory_reserved_bytes", json!(0)),
                ("/remaining_hard_memory_growth_bytes", json!(0)),
                ("/producer_remaining_hard_memory_growth_bytes", json!(0)),
                ("/memory_floor_top_up_bytes", json!(0)),
            ] {
                let mut bad = valid.clone();
                *bad.pointer_mut(pointer).unwrap() = value;
                assert!(
                    prefix223_live_peer::validate_saved_row(&bad).is_err(),
                    "accepted {phase}{pointer}"
                );
            }
            for key in [
                "guard",
                "guard_observation",
                "guard_hard_memory_reserved_bytes",
                "actual_guard_timer_proof",
            ] {
                let mut bad = valid.clone();
                bad.as_object_mut().unwrap().remove(key);
                assert!(
                    prefix223_live_peer::validate_saved_row(&bad).is_err(),
                    "accepted missing {phase}/{key}"
                );
            }
        }
    }
    #[test]
    fn systemd_memory_properties_require_exact_strings() {
        let valid = fixture();
        validate_saved_memory_row(&valid).unwrap();
        for (pointer, cap) in [
            (
                "/hard_memory_envelope/systemd_properties/MemoryMax",
                c::MEMORY,
            ),
            (
                "/hard_memory_envelope/systemd_properties/MemoryHigh",
                c::HIGH,
            ),
            (
                "/actual_guard_timer_proof/manager/properties/MemoryMax",
                GUARD,
            ),
        ] {
            for value in [
                json!(cap),
                json!(cap as f64),
                json!(false),
                Value::Null,
                json!([cap.to_string()]),
                json!({"value":cap.to_string()}),
                json!(format!("0{cap}")),
                json!(format!("{cap} ")),
            ] {
                let mut bad = valid.clone();
                *bad.pointer_mut(pointer).unwrap() = value;
                assert!(
                    validate_saved_memory_row(&bad).is_err(),
                    "accepted non-exact systemd string {pointer}"
                );
            }
        }
    }
}
