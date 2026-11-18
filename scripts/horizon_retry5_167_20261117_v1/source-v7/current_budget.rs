//! Current promises remain additive to the immutable original-slot ancestry.
use super::*;
pub(super) const MEMORY_DELTA: u64 = 1_342_177_280;
pub(super) const DATA_DELTA: u64 = 10_737_418_240;
pub(super) const CURRENT_MEMORY: u64 = 761_131_708_416;
pub(super) const CURRENT_DATA: u64 = 6_240_576_028_466;
pub(super) const CURRENT_FLOOR: u64 = data_fulfillment::CURRENT_FLOOR;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Budget {
    pub historical_memory_bytes: u64,
    pub historical_data_bytes: u64,
    pub additional_memory_bytes: u64,
    pub additional_data_bytes: u64,
    pub complete_memory_bytes: u64,
    pub complete_data_bytes: u64,
    pub raw_floor_bytes: u64,
    pub promise_ending_bytes: u64,
    pub resource_credit_bytes: u64,
}
pub(super) fn selected(p: &Plan) -> bool {
    ["local3retry2", "local3retry3"].contains(&p.attempt.as_str()) || crate::retry4::selected(p) || crate::retry167::selected(p)
}
pub(super) fn exact() -> Budget {
    Budget {
        historical_memory_bytes: MEMORY,
        historical_data_bytes: DATA,
        additional_memory_bytes: MEMORY_DELTA,
        additional_data_bytes: DATA_DELTA,
        complete_memory_bytes: CURRENT_MEMORY,
        complete_data_bytes: CURRENT_DATA,
        raw_floor_bytes: CURRENT_FLOOR,
        promise_ending_bytes: 0,
        resource_credit_bytes: 0,
    }
}
pub(super) fn validate(v: &Budget) -> Result<()> {
    ensure!(
        *v == exact(),
        "all current promises and exact historical ancestry required"
    );
    ensure!(
        MEMORY.checked_add(MEMORY_DELTA) == Some(CURRENT_MEMORY)
            && DATA.checked_add(DATA_DELTA) == Some(CURRENT_DATA)
            && FLOOR.checked_add(DATA_DELTA) == Some(CURRENT_FLOOR),
        "current authority arithmetic differs"
    );
    Ok(())
}
pub(super) fn memory_recheck(legacy: &Value, total: u64, available: u64) -> Result<Value> {
    let point = legacy.get("qualified_accounting").unwrap_or(legacy);
    let n = |key: &str| {
        point[key]
            .as_u64()
            .with_context(|| format!("missing historical memory field {key}"))
    };
    ensure!(
        n("complete_projected_memory_bytes")? == MEMORY,
        "foreign historical memory basis"
    );
    let required = n("required_available_bytes")?
        .checked_add(MEMORY_DELTA)
        .context("current memory required overflow")?;
    let resident = if point["mode"] == "conservative-full-promise-fallback" {
        ensure!(
            n("required_available_bytes")? == MEMORY + RESERVE,
            "fallback must retain every promise"
        );
        0
    } else {
        ensure!(
            point["mode"] == "invocation-matched-realized-resident-portions-v1",
            "unknown historical accounting mode"
        );
        n("host_resident_planning_upper_bytes")?
    };
    let available = if point["mode"] == "invocation-matched-realized-resident-portions-v1" {
        ensure!(
            n("fresh_MemTotal_bytes")? == total,
            "resident total memory changed"
        );
        available.min(n("fresh_MemAvailable_bytes")?)
    } else {
        available
    };
    let projected = resident
        .checked_add(required)
        .context("current memory projection overflow")?;
    ensure!(
        total
            >= CURRENT_MEMORY
                .checked_add(RESERVE)
                .context("full current memory overflow")?
            && available >= required
            && projected <= total,
        "current retained memory delta does not fit independent host projection"
    );
    Ok(
        json!({"historical_accounting":legacy,"complete_projected_memory_bytes":CURRENT_MEMORY,"historical_complete_projected_memory_bytes":MEMORY,"additional_retained_memory_bytes":MEMORY_DELTA,"required_available_bytes":required,"host_resident_planning_upper_bytes":resident,"resident_plus_future_and_reserve_bytes":projected,"actual_available_bytes":available,"actual_total_bytes":total,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}
pub(super) fn disk_point(
    raw: u64,
    fulfilled: u64,
    requested: u64,
    extra: u64,
    staging: u64,
) -> Result<Value> {
    ensure!(
        staging >= 64 << 20 && fulfilled > 0 && fulfilled <= 241_482_399_744,
        "unqualified allocation/staging amount"
    );
    let floor = CURRENT_FLOOR
        .checked_add(extra)
        .and_then(|n| n.checked_add(staging))
        .context("current initial demand overflow")?;
    ensure!(
        requested >= floor,
        "current DATA delta or uncovered growth omitted"
    );
    let sum = raw
        .checked_add(fulfilled)
        .context("raw plus fulfillment overflow")?;
    let effective = requested
        .checked_sub(fulfilled)
        .context("fulfillment exceeds demand")?;
    ensure!(
        sum >= requested && raw >= effective,
        "current DATA admission does not fit"
    );
    Ok(
        json!({"complete_DATA_bytes":CURRENT_DATA,"historical_complete_DATA_bytes":DATA,"additional_retained_DATA_bytes":DATA_DELTA,"raw_initial_demand_bytes":requested,"effective_required_free_bytes":effective,"conservative_raw_available_bytes":raw,"fulfilled_existing_DATA_bytes":fulfilled,"available_plus_fulfilled_bytes":sum,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_delta_is_mandatory_and_old_authority_unchanged() {
        let b = exact();
        validate(&b).unwrap();
        for k in [
            "historical_memory_bytes",
            "historical_data_bytes",
            "additional_memory_bytes",
            "additional_data_bytes",
            "complete_memory_bytes",
            "complete_data_bytes",
            "raw_floor_bytes",
            "promise_ending_bytes",
            "resource_credit_bytes",
        ] {
            let mut v = serde_json::to_value(&b).unwrap();
            v[k] = json!(1);
            assert!(
                validate(&serde_json::from_value(v).unwrap()).is_err(),
                "{k}"
            );
        }
    }
    #[test]
    fn exact_initial_boundary_includes_current_delta_and_staging() {
        let raw = 6_033_453_367_090;
        let need = CURRENT_FLOOR + (64 << 20);
        disk_point(raw, 241_482_399_744, need, 0, 64 << 20).unwrap();
        assert!(disk_point(raw - 1, 241_482_399_744, need, 0, 64 << 20).is_err());
        assert!(disk_point(raw, 241_482_399_744, FLOOR + (64 << 20), 0, 64 << 20).is_err());
    }
    #[test]
    fn double_fulfillment_growth_and_overflow_fail() {
        assert!(disk_point(u64::MAX, 1, u64::MAX, 0, 64 << 20).is_err());
        assert!(
            disk_point(
                CURRENT_FLOOR,
                482_964_799_488,
                CURRENT_FLOOR + (64 << 20),
                0,
                64 << 20
            )
            .is_err()
        );
        assert!(disk_point(CURRENT_FLOOR, 1, CURRENT_FLOOR + (64 << 20), 1, 64 << 20).is_err());
        assert!(disk_point(CURRENT_FLOOR, 1, u64::MAX, u64::MAX, 64 << 20).is_err());
    }
    #[test]
    fn full_current_memory_is_rechecked_after_legacy_fit() {
        let old = MEMORY + RESERVE;
        let legacy = json!({"mode":"conservative-full-promise-fallback","complete_projected_memory_bytes":MEMORY,"required_available_bytes":old});
        assert!(memory_recheck(&legacy, old, old).is_err());
        memory_recheck(&legacy, old + MEMORY_DELTA, old + MEMORY_DELTA).unwrap();
        let resident = json!({"mode":"invocation-matched-realized-resident-portions-v1","complete_projected_memory_bytes":MEMORY,"required_available_bytes":old-100,"host_resident_planning_upper_bytes":101});
        assert!(memory_recheck(&resident, old + MEMORY_DELTA, old + MEMORY_DELTA).is_err());
    }
    #[test]
    fn malformed_resident_projection_never_defaults_to_zero() {
        let v = json!({"mode":"invocation-matched-realized-resident-portions-v1","complete_projected_memory_bytes":MEMORY,"required_available_bytes":MEMORY+RESERVE});
        assert!(memory_recheck(&v, CURRENT_MEMORY + RESERVE, CURRENT_MEMORY + RESERVE).is_err());
        let mut v = v;
        v["mode"] = json!("unknown");
        assert!(memory_recheck(&v, CURRENT_MEMORY + RESERVE, CURRENT_MEMORY + RESERVE).is_err());
    }
    #[test]
    fn current_delta_rechecks_conservative_final_memory_endpoint() {
        let total = CURRENT_MEMORY + RESERVE;
        let need = MEMORY + RESERVE - 100;
        let mut v = json!({"mode":"invocation-matched-realized-resident-portions-v1","complete_projected_memory_bytes":MEMORY,"required_available_bytes":need,"host_resident_planning_upper_bytes":0,"fresh_MemTotal_bytes":total,"fresh_MemAvailable_bytes":need+MEMORY_DELTA});
        memory_recheck(&v, total, total).unwrap();
        v["fresh_MemAvailable_bytes"] = json!(need + MEMORY_DELTA - 1);
        assert!(memory_recheck(&v, total, total).is_err());
    }
}
