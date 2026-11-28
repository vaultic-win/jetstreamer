//! Bounded first128 composition over the unchanged opaque typed baseline.
//! Native128 stays an independent128GiB/40GiB charge after original drains.
use super::*;
const NATIVE_MEMORY: u64 = 128 << 30;
const NATIVE_DATA: u64 = 40 << 30;
pub(super) enum Stage<'a> {
    Admission,
    Enrolled(&'a Bound),
}
/// No caller JSON or scalar threshold can construct this point-of-use budget.
pub(super) struct Budget {
    evidence: Value,
    existing_data: u64,
    required_free: u64,
    total_memory: u64,
}
impl Budget {
    pub(super) fn evidence(&self) -> &Value { &self.evidence }
    pub(super) fn existing_data_bytes(&self) -> u64 { self.existing_data }
    pub(super) fn required_free_bytes(&self) -> u64 { self.required_free }
    pub(super) fn host_fit(&self, host_total: u64) -> Result<()> {
        ensure!(self.total_memory <= host_total,
            "first128 full typed + retained native128 + replay hard exposure exceeds host");
        Ok(())
    }
}
fn contains_identity(value: &Value, iid: &str) -> bool {
    match value {
        Value::String(s) => s == super::super::native_restore::ACTOR || s == iid,
        Value::Array(rows) => rows.iter().any(|v| contains_identity(v, iid)),
        Value::Object(row) => row.iter().any(|(k,v)| k == super::super::native_restore::ACTOR || contains_identity(v, iid)),
        _ => false,
    }
}
/// Fail closed if a later full builder starts charging this exact actor. Such a
/// new raw integration needs its own qualified composition, never a second add.
fn native_not_in_raw(raw: &Value, iid: &str) -> Result<()> {
    for key in ["current_unique_owner_census", "active_peer_allocations", "native_pool_suballocations", "projected_obligations"] {
        let rows = raw[key].as_array().with_context(|| format!("native128 complete raw table {key}"))?;
        ensure!(rows.iter().all(|row| !contains_identity(row, iid)
            && row.get("native128_retention").is_none()),
            "native128 already represented or aliased in raw charge table {key}");
    }
    let hard = raw["current_owner_hard_limits"].as_object().context("native128 complete raw hard limits")?;
    ensure!(!contains_identity(&json!(hard), iid)
        && raw.get("native128_retention").is_none()
        && raw.get("retained_native128_memory_bytes").is_none()
        && raw.get("retained_native128_DATA_bytes").is_none(),
        "native128 raw charge exists; bounded additive mode would duplicate it");
    Ok(())
}
fn replay_delta(raw: &Value, stage: &Stage<'_>) -> Result<(u64,u64)> {
    let peers = raw["active_peer_allocations"].as_array().context("first128 current peer charges")?;
    let rows = peers.iter().filter(|row| row["unit"] == PARENT128).collect::<Vec<_>>();
    match stage {
        Stage::Admission => {
            ensure!(rows.is_empty(), "new first128 candidate already charged");
            Ok((HARD128+AUX128, 768u64<<30))
        }
        Stage::Enrolled(enrollment) => {
            ensure!(rows.len() == 1 && rows[0]["first163128_registration"] == json!(enrollment)
                && rows[0]["memory_max_bytes"] == HARD128+AUX128
                && rows[0]["data_reservation_bytes"] == 768u64<<30
                && rows[0]["memory_credit_bytes"] == 0 && rows[0]["DATA_credit_bytes"] == 0,
                "release requires exact one existing enrolled first128 memory/DATA charge");
            Ok((0,0))
        }
    }
}
fn phase_native(phase: &Value, retained: &Value) -> Result<()> {
    ensure!(phase["native128_retention"] == *retained
        && phase["native128_does_not_release_promises"] == true
        && phase["native128_memory_bytes_retained"] == NATIVE_MEMORY
        && phase["native128_DATA_bytes_retained"] == NATIVE_DATA
        && retained["memory_bytes"] == NATIVE_MEMORY && retained["DATA_bytes"] == NATIVE_DATA
        && retained["memory_credit_bytes"] == 0 && retained["DATA_credit_bytes"] == 0
        && retained["physical_credit_bytes"] == 0 && retained["release_authorized"] == false,
        "first128 current phase omitted, crossed or released actual retained native128");
    Ok(())
}
pub(super) fn compose(
    view: &memory::VerifiedParentMemory,
    data: &data::VerifiedData,
    phase: &Value,
    native: &native_capability::Retained,
    before: &Value,
    after: &Value,
    stage: Stage<'_>,
) -> Result<Budget> {
    ensure!(view.selected_parent_retirement_bytes() == 192u64<<30
        && view.selected_cached145_parent_retirement_bytes() == 192u64<<30,
        "first128 needs both distinct qualified parent selections");
    ensure!(data.evidence()["current"] == view.evidence()["request"]["current"],
        "native128 composition cannot cross genuine typed memory/DATA tuples");
    phase_native(phase, native.evidence())?;
    let iid = native.evidence()["actor_invocation_id"].as_str().context("retained native IID")?;
    native_not_in_raw(before, iid)?;
    native_not_in_raw(after, iid)?;
    let delta = replay_delta(before, &stage)?;
    ensure!(delta == replay_delta(after, &stage)?, "first128 charge changed across complete raw passes");
    // The original reader's exact baseline must also lack this native charge.
    let reader_bound = to_bound(&view.evidence()["request"]["current_reader"])?;
    let reader = immutable(&reader_bound)?;
    for key in ["accounting_before", "accounting"] {
        let original = immutable(&to_bound(&reader[key])?)?;
        native_not_in_raw(&original, iid)?;
        if key == "accounting" { unchanged_claims(&original, after)?; }
    }
    // Preserve the actual145 memory and DATA dimensions independently. This is
    // not proof of native inclusion; native's own exact charge is added below.
    ensure!(view.effective_total_bytes() >= (80u64<<30)+(256u64<<20),
        "first128 baseline loses retained actual145 memory");
    let existing_memory = view.effective_total_bytes().checked_add(NATIVE_MEMORY).context("retained native memory overflow")?;
    ensure!(existing_memory >= n(phase,"minimum_existing_memory_bytes")?, "first128 composed existing memory below current phase");
    let total_memory = existing_memory.checked_add(delta.0).context("first128 total hard exposure overflow")?;
    let baseline_data = data.effective_protected_bytes()
        .max(n(before,"protected_existing_DATA_bytes")?).max(n(after,"protected_existing_DATA_bytes")?)
        .max(n(before,"inherited_live_guard_maximum_bytes")?).max(n(after,"inherited_live_guard_maximum_bytes")?)
        .max(current_phase::DATA_MINIMUM);
    // Add native DATA once before taking already-booked whole-phase floors.
    // The phase floor may already include that same40GiB; it is never added twice.
    let existing_data = baseline_data.checked_add(NATIVE_DATA).context("retained native DATA overflow")?
        .max(n(phase,"protected_existing_DATA_bytes")?);
    let required_free = existing_data.checked_add(delta.1).context("first128 complete DATA overflow")?;
    let evidence = json!({"schema":"epoch163-first-output128-composed-native-retention-budget-v1",
        "current":view.evidence()["request"]["current"],"native128_retention":native.evidence(),
        "unchanged_typed_existing_memory_bytes":view.effective_total_bytes(),"existing_memory_bytes":existing_memory,
        "native128_memory_additive_bytes":NATIVE_MEMORY,"native128_DATA_additive_bytes":NATIVE_DATA,
        "native128_proven_absent_from_original_and_both_fresh_raw_charged_tables":true,
        "candidate_scheduling_total_bytes":delta.0,"candidate_incremental_DATA_bytes":delta.1,
        "total_conservative_hard_exposure_bytes":total_memory,"baseline_protected_DATA_bytes":baseline_data,
        "protected_existing_DATA_bytes":existing_data,"required_initial_free_bytes":required_free,
        "new_extra_parent_retirement_bytes":0,"memory_credit_bytes":0,"DATA_credit_bytes":0,"physical_credit_bytes":0});
    Ok(Budget { evidence, existing_data, required_free, total_memory })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn point_of_use_host_check_cannot_omit_native_memory_after_drain() {
        // This is only a negative capacity test, never a synthetic native proof.
        let old_total = 600u64<<30;
        let budget = Budget { evidence: Value::Null, existing_data: 0, required_free: 0,
            total_memory: old_total + NATIVE_MEMORY };
        assert!(budget.host_fit(old_total + NATIVE_MEMORY - 1).is_err());
        assert!(budget.host_fit(old_total).is_err());
    }
    #[test]
    fn missing_or_aliased_native_charge_cannot_be_hidden_by_a_large_scalar_total() {
        let iid="a".repeat(32);
        let omitted=json!({"raw_total_memory_promises_bytes":u64::MAX});
        assert!(native_not_in_raw(&omitted,&iid).is_err());
        for key in ["current_unique_owner_census","active_peer_allocations","native_pool_suballocations","projected_obligations"] {
            let mut raw=json!({"current_unique_owner_census":[],"active_peer_allocations":[],"native_pool_suballocations":[],"projected_obligations":[],"current_owner_hard_limits":{}});
            raw[key]=json!([{"unit":super::super::super::native_restore::ACTOR,"invocation_id":iid,"memory_max_bytes":128u64<<30}]);
            assert!(native_not_in_raw(&raw,&iid).is_err(),"{key}");
            raw[key]=json!([{"unit":"alias.service","producer_invocation_id":iid}]);
            assert!(native_not_in_raw(&raw,&iid).is_err(),"aliased {key}");
        }
    }
    #[test]
    fn omitted_crossed_or_released_phase_is_not_actual_native_retention() {
        let retained=json!({"memory_bytes":128u64<<30,"DATA_bytes":40u64<<30,"memory_credit_bytes":0,"DATA_credit_bytes":0,"physical_credit_bytes":0,"release_authorized":false});
        for phase in [Value::Null,json!({"native128_retention":{"foreign":true}}),json!({"native128_retention":retained,"native128_does_not_release_promises":false})] {
            assert!(phase_native(&phase,&retained).is_err());
        }
        let mut phase=json!({"native128_retention":retained,"native128_does_not_release_promises":true,"native128_memory_bytes_retained":128u64<<30,"native128_DATA_bytes_retained":40u64<<30});
        phase["native128_retention"]["DATA_credit_bytes"]=json!(1);
        assert!(phase_native(&phase,&phase["native128_retention"]).is_err());
    }
    #[test]
    fn release_cannot_omit_duplicate_cross_or_credit_the_existing_replay_charge() {
        let enrollment=Bound {path:REGISTER128.into(),sha256:"a".repeat(64)};
        for rows in [json!([]),json!([{"unit":PARENT128},{"unit":PARENT128}]),
            json!([{"unit":PARENT128,"first163128_registration":{"foreign":true}}]),
            json!([{"unit":PARENT128,"first163128_registration":enrollment,"memory_max_bytes":HARD128+AUX128,"data_reservation_bytes":768u64<<30,"memory_credit_bytes":1,"DATA_credit_bytes":0}])] {
            assert!(replay_delta(&json!({"active_peer_allocations":rows}),&Stage::Enrolled(&enrollment)).is_err());
        }
    }
}
