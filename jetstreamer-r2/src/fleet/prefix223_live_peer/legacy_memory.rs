//! Complete the two closed legacy peer profiles that older auxiliary-only
//! accounting did not fully reserve. This never drops or discounts a row.
use super::*;
const LEGACY225: &str =
    "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service";
const GUARD: u64 = 1 << 30;
#[derive(Clone)]
struct Observation {
    unit: String,
    iid: String,
    cap: u64,
    high: u64,
    charge: u64,
    swap: u64,
    guard: u64,
}
fn integer(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("legacy peer memory integer missing:{key}"))
}
fn expected_caps(unit: &str) -> Result<(u64, u64)> {
    if unit == LEGACY225 {
        Ok((192 << 30, 160 << 30))
    } else {
        ensure!(
            unit == singleton209::UNIT,
            "unrecognized legacy memory owner"
        );
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
        ensure!(
            page.is_power_of_two() && (4096..=65536).contains(&page),
            "legacy peer page size"
        );
        Ok((225_000_000_000 / page * page, 150_000_000_000 / page * page))
    }
}
/// Saved provenance must replay the independent guard arithmetic, even when
/// the producer roster is complete. Live completion never repairs old receipts.
pub(in crate::fleet) fn validate_saved_row(row: &Value) -> Result<()> {
    let unit = row["unit"].as_str().context("saved legacy memory owner")?;
    if unit == canary227::UNIT {
        return canary227_peer::validate_saved_memory_row(row);
    }
    if unit != LEGACY225 && unit != singleton209::UNIT {
        return Ok(());
    }
    let (cap, high) = expected_caps(unit)?;
    let charge = integer(row, "current_cgroup_charge_bytes")?;
    let high_key = if unit == LEGACY225 {
        "memory_high_bytes"
    } else {
        "kernel_memory_high_bytes"
    };
    ensure!(
        integer(row, "hard_memory_cap_bytes")? == cap
            && integer(row, high_key)? == high
            && integer(row, "memory_swap_max_bytes")? == 0
            && charge <= cap
            && integer(row, "guard_hard_memory_reserved_bytes")? == GUARD
            && integer(row, "remaining_hard_memory_growth_bytes")?
                == (cap - charge)
                    .checked_add(GUARD)
                    .context("saved legacy memory overflow")?,
        "saved legacy producer or independent guard memory reservation differs"
    );
    Ok(())
}
fn append_or_complete(total: &mut u64, rows: &mut Vec<Value>, o: &Observation) -> Result<()> {
    let (cap, high) = expected_caps(&o.unit)?;
    ensure!(
        o.cap == cap && o.high == high && o.swap == 0 && o.charge <= cap && o.guard == GUARD,
        "closed legacy peer hard memory/high/swap/guard cap changed"
    );
    let matches = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r["unit"] == o.unit)
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    ensure!(matches.len() <= 1, "duplicate closed legacy memory owner");
    let producer = cap - o.charge;
    if let Some(&index) = matches.first() {
        let row = &mut rows[index];
        ensure!(
            row["invocation_id"] == o.iid
                && row["hard_memory_cap_bytes"] == cap
                && row["current_cgroup_charge_bytes"] == o.charge,
            "closed legacy memory owner identity changed"
        );
        let already = row
            .get("guard_hard_memory_reserved_bytes")
            .map(|v| v.as_u64().context("legacy guard reserve type"))
            .transpose()?
            .unwrap_or(0);
        ensure!(
            (already == 0 || already == GUARD)
                && integer(row, "remaining_hard_memory_growth_bytes")?
                    == producer
                        .checked_add(already)
                        .context("legacy memory overflow")?,
            "legacy memory row understated or double-counted"
        );
        if already == 0 {
            *total = total
                .checked_add(GUARD)
                .context("legacy complete memory overflow")?;
            row["guard_hard_memory_reserved_bytes"] = json!(GUARD);
            row["remaining_hard_memory_growth_bytes"] = json!(producer
                .checked_add(GUARD)
                .context("legacy memory overflow")?);
        }
        row["memory_swap_max_bytes"] = json!(o.swap);
        validate_saved_row(row)?;
    } else {
        ensure!(
            o.unit == LEGACY225,
            "closed full209 producer memory row missing"
        );
        let remaining = producer
            .checked_add(GUARD)
            .context("legacy memory overflow")?;
        *total = total
            .checked_add(remaining)
            .context("legacy complete memory overflow")?;
        rows.push(json!({"unit":o.unit,"invocation_id":o.iid,"hard_memory_cap_bytes":cap,
            "memory_high_bytes":high,"current_cgroup_charge_bytes":o.charge,"memory_swap_max_bytes":0,
            "guard_hard_memory_reserved_bytes":GUARD,"remaining_hard_memory_growth_bytes":remaining,
            "accounting":"exact closed natural225 producer remaining hard cap plus full independent protective guard ceiling"}));
        validate_saved_row(rows.last().context("new legacy memory row missing")?)?;
    }
    Ok(())
}
pub(super) fn complete(
    f: &Value,
    mut total: u64,
    mut rows: Vec<Value>,
) -> Result<(u64, Vec<Value>)> {
    for active in f["active"]
        .as_array()
        .context("legacy memory accepted roster")?
    {
        let owner = singleton227_admission::active_owner(active)?;
        let name = owner["Id"].as_str().context("legacy memory owner name")?;
        if name != LEGACY225 && name != singleton209::UNIT {
            continue;
        }
        let (guard, _) = prefix223_native20_admission::guard_selector(name)?;
        let properties = singleton227_capture::properties(guard, "MemoryMax")?;
        singleton227_capture::require(&properties, &[("MemoryMax", "1073741824")])?;
        let (cap, high, charge, swap) = if name == LEGACY225 {
            ensure!(
                owner["ControlGroup"] == format!("/system.slice/{name}"),
                "legacy225 cgroup differs"
            );
            let root = Path::new("/sys/fs/cgroup/system.slice").join(name);
            ensure!(root.canonicalize()? == root, "legacy225 cgroup redirected");
            let read = |file: &str| -> Result<u64> {
                Ok(fs::read_to_string(root.join(file))?.trim().parse()?)
            };
            (
                read("memory.max")?,
                read("memory.high")?,
                read("memory.current")?,
                read("memory.swap.max")?,
            )
        } else {
            // Full209's typed reader already authenticated these live kernel
            // values and the exact launch. Do not sample its charge a second time.
            let matches = rows
                .iter()
                .filter(|r| r["unit"] == name)
                .collect::<Vec<_>>();
            ensure!(
                matches.len() == 1,
                "closed full209 memory evidence missing/duplicate"
            );
            (
                integer(matches[0], "hard_memory_cap_bytes")?,
                integer(matches[0], "kernel_memory_high_bytes")?,
                integer(matches[0], "current_cgroup_charge_bytes")?,
                0,
            )
        };
        append_or_complete(
            &mut total,
            &mut rows,
            &Observation {
                unit: name.into(),
                iid: owner["InvocationID"]
                    .as_str()
                    .context("legacy memory IID")?
                    .into(),
                cap,
                high,
                charge,
                swap,
                guard: GUARD,
            },
        )?;
    }
    Ok((total, rows))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn actual() -> Value {
        serde_json::from_str(include_str!(
            "../assembly204_recovery/fixtures/actual399_incomplete_memory.json"
        ))
        .unwrap()
    }
    #[test]
    fn real_saved_capacity_missing225_requires_additive_producer_and_guard_reservations() {
        let saved = actual();
        let phase = &saved["memory_before"];
        let mut total = integer(phase, "protected_existing_memory_growth_bytes").unwrap();
        let mut rows = phase["protected_memory_evidence"]
            .as_array()
            .unwrap()
            .clone();
        assert!(!rows.iter().any(|r| r["unit"] == LEGACY225));
        let old_total = total;
        let (cap, high) = expected_caps(singleton209::UNIT).unwrap();
        let full209 = rows
            .iter()
            .find(|r| r["unit"] == singleton209::UNIT)
            .unwrap();
        let o209 = Observation {
            unit: singleton209::UNIT.into(),
            iid: full209["invocation_id"].as_str().unwrap().into(),
            cap,
            high,
            charge: integer(full209, "current_cgroup_charge_bytes").unwrap(),
            swap: 0,
            guard: GUARD,
        };
        append_or_complete(&mut total, &mut rows, &o209).unwrap();
        // Explicit synthetic kernel observation, never a rewrite of historical
        // capacity: exercise the actual missing225 writer branch deterministically.
        let o225 = Observation {
            unit: LEGACY225.into(),
            iid: "4cd76ae1353a4411885b997f04306402".into(),
            cap: 192 << 30,
            high: 160 << 30,
            charge: 160 << 30,
            swap: 0,
            guard: GUARD,
        };
        append_or_complete(&mut total, &mut rows, &o225).unwrap();
        assert_eq!(total, old_total + (32 << 30) + 2 * GUARD);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            total,
            rows.iter()
                .map(|r| integer(r, "remaining_hard_memory_growth_bytes").unwrap())
                .sum::<u64>()
        );
        let once = total;
        append_or_complete(&mut total, &mut rows, &o209).unwrap();
        append_or_complete(&mut total, &mut rows, &o225).unwrap();
        assert_eq!(total, once);
    }
    #[test]
    fn actual399_full209_guard_omission_is_rejected_independently_of225_roster() {
        let saved = actual();
        for phase in ["memory_before", "memory_after"] {
            let row = saved[phase]["protected_memory_evidence"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["unit"] == singleton209::UNIT)
                .unwrap();
            assert!(validate_saved_row(row).is_err());
            let mut corrected = row.clone();
            let charge = integer(row, "current_cgroup_charge_bytes").unwrap();
            let (cap, _) = expected_caps(singleton209::UNIT).unwrap();
            corrected["memory_swap_max_bytes"] = json!(0);
            corrected["guard_hard_memory_reserved_bytes"] = json!(GUARD);
            corrected["remaining_hard_memory_growth_bytes"] = json!(cap - charge + GUARD);
            validate_saved_row(&corrected).unwrap();
            for key in [
                "guard_hard_memory_reserved_bytes",
                "remaining_hard_memory_growth_bytes",
                "memory_swap_max_bytes",
            ] {
                let mut changed = corrected.clone();
                changed[key] = json!(if key == "memory_swap_max_bytes" { 1 } else { 0 });
                assert!(
                    validate_saved_row(&changed).is_err(),
                    "accepted changed {phase}/{key}"
                );
            }
        }
    }
    #[test]
    fn closed_legacy_memory_rejects_changed_caps_iid_duplicate_and_understatement() {
        let base = Observation {
            unit: LEGACY225.into(),
            iid: "a".repeat(32),
            cap: 192 << 30,
            high: 160 << 30,
            charge: 160 << 30,
            swap: 0,
            guard: GUARD,
        };
        for field in ["cap", "high", "swap", "guard", "charge"] {
            let mut changed = base.clone();
            match field {
                "cap" => changed.cap -= 1,
                "high" => changed.high -= 1,
                "swap" => changed.swap = 1,
                "guard" => changed.guard = 0,
                _ => changed.charge = changed.cap + 1,
            };
            assert!(append_or_complete(&mut 0, &mut vec![], &changed).is_err());
        }
        let mut total = 0;
        let mut rows = vec![];
        append_or_complete(&mut total, &mut rows, &base).unwrap();
        let mut changed = base.clone();
        changed.iid = "b".repeat(32);
        assert!(append_or_complete(&mut total, &mut rows, &changed).is_err());
        let mut duplicate = rows.clone();
        duplicate.push(rows[0].clone());
        assert!(append_or_complete(&mut total, &mut duplicate, &base).is_err());
        rows[0]["remaining_hard_memory_growth_bytes"] = json!(0);
        assert!(append_or_complete(&mut total, &mut rows, &base).is_err());
    }
}
