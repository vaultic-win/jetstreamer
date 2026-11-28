//! Additive current controller booking. Historical ledgers retain their owners.
use super::*;
pub(super) const DATA_MINIMUM: u64 = 5_114_649_588_372;
const PRIMARY: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
fn scope(p: &Value) -> Result<()> {
    ensure!(p["schema"] == "epoch163-first-output128-current-phase-v1"
        && p["exclusive_operational_owner"] == PRIMARY
        && n(p,"protected_existing_DATA_bytes")? >= DATA_MINIMUM
        && n(p,"complete_conservative_raw_DATA_booking_bytes")? >= DATA_MINIMUM
        && n(p,"protected_existing_DATA_bytes")? >= n(p,"complete_conservative_raw_DATA_booking_bytes")?
        && p["all_original_memory_DATA_and_raw_producer_promises_retained"] == true
        && p["no_release_or_idle_credit"] == true
        && p["failed145_does_not_release_promises"] == true
        && p["native128_does_not_release_promises"] == true
        && p["native128_memory_bytes_retained"] == 128u64<<30
        && p["native128_DATA_bytes_retained"] == 40u64<<30
        && p["native128_retention"]["schema"] == "epoch163-native128-retained-first128-charge-v1"
        && p["native128_retention"]["charging_scope"] == "first128-point-of-use-additive-to-unchanged-typed-baseline"
        && p["native128_retention"]["memory_bytes"] == 128u64<<30
        && p["native128_retention"]["DATA_bytes"] == 40u64<<30
        && p["native128_retention"]["memory_credit_bytes"] == 0
        && p["native128_retention"]["DATA_credit_bytes"] == 0
        && p["native128_retention"]["physical_credit_bytes"] == 0
        && p["native128_retention"]["release_authorized"] == false
        && p["retained145_memory_bytes"] == (80u64<<30)+(256u64<<20)
        && n(p,"retained145_DATA_bytes")? >= (164u64<<30)+(128u64<<20)
        && p["retained145_cpu_quota_micros"] == 9_000_000
        && p["normal_external_pool_bytes"] == 6u64<<30
        && p["candidate_memory_bytes"] == HARD128+AUX128
        && p["candidate_DATA_bytes"] == 768u64<<30
        && p["replay_launch_authorized"] == false && p["publication_authorized"] == false,
        "first128 complete current controller/phase liabilities") ;
    Ok(())
}
pub(super) fn validate(b: &Bound) -> Result<Value> {
    let p=immutable(b)?;
    scope(&p)?;
    let mut next=Some(to_bound(&p["previous_phase_ledger"])?);
    let native_phase=to_bound(&p["native128_retention"]["native_phase_ledger"])?;
    let mut saw_native_phase=false;
    let mut visited=std::collections::BTreeSet::new();
    while let Some(bound)=next.take() {
        ensure!(visited.len()<128 && visited.insert(bound.path.clone()),"first128 phase cycle/depth");
        ensure!(!bound.path.extension().is_some_and(|s| ["jet","zst","bz2","tar"].iter().any(|x| s==*x)),"phase reference cannot open an input body");
        if json!(bound)==json!(native_phase) { saw_native_phase=true; }
        let prior=protected(&bound)?;
        for field in ["protected_existing_DATA_bytes","complete_conservative_raw_DATA_booking_bytes","raw_DATA_bytes"] {
            if let Some(bytes)=prior[field].as_u64() {
                let retained_native = if prior["schema"] == "horizon-native163-current-fixed128-phase-v1" && field == "protected_existing_DATA_bytes" { 40u64<<30 } else { 0 };
                ensure!(n(&p,"protected_existing_DATA_bytes")? >= bytes.checked_add(retained_native).context("retained native DATA overflow")?,"first128 current booking drops a later DATA/native charge");
            }
        }
        next=prior.get("previous_phase_ledger").filter(|v|!v.is_null()).map(to_bound).transpose()?;
    }
    ensure!(saw_native_phase,"first128 phase ancestry must include exact retained native128 original phase binding");
    let takeover=Bound{path:"/home/sol/.jetstreamer-private/epoch163-first-output128-admission-source-20261106-v1/ROOT_USER_ORDERED_VISIBLE_THREAD_TAKEOVER_20261107.json".into(),sha256:"9b895fd8e137c30ba7a6d94432639c2e7e114140bb2cde5700f32e08987ab61f".into()};
    ensure!(p["visible_thread_takeover"]==json!(takeover),"first128 takeover binding");
    let authority=protected(&takeover)?;
    ensure!(authority["current_sole_primary_thread"]==PRIMARY && authority["supersedes_prior_owner_ACK_for_future_control"]==true,"first128 current sole authority");
    Ok(p)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_native_phase_or_archived_owner_cannot_book_current_replay() {
        assert!(scope(&json!({"schema":"horizon-native163-current-fixed128-phase-v1","exclusive_operational_owner":PRIMARY})).is_err());
        assert!(scope(&json!({"schema":"epoch163-first-output128-current-phase-v1","exclusive_operational_owner":"01a1af2b-bc56-7311-a916-55aa5e102974"})).is_err());
    }
}
