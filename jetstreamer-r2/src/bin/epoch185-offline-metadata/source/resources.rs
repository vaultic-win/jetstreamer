use crate::storage::{Bound, n};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("resource integer overflow")
}
pub fn project(
    ledger: &Value,
    tuple: &Value,
    raw: &Value,
    memory: &Value,
    data: &Value,
) -> Result<Value> {
    ensure!(
        ledger["schema"]
            == "horizon-resource-phases-native163-issuer-offline185-materializer-source-QA-v25",
        "unsupported phase schema: review/rebase a newer ledger explicitly"
    );
    ensure!(
        ledger["exclusive_operational_owner"] == "01a1af2b-bc56-7311-a916-55aa5e102974"
            && ledger["all_old_memory_DATA_and_raw_producer_promises_retained"] == true,
        "phase ownership/history"
    );
    let additional = n(ledger, "complete_retained_additional_DATA_bytes")?;
    let raw_base = n(ledger, "raw_DATA_bytes")?;
    let conservative = n(ledger, "complete_conservative_raw_DATA_booking_bytes")?;
    ensure!(
        add(raw_base, additional)? == conservative,
        "R25 additive DATA already counted or omitted"
    );
    ensure!(
        n(raw, "protected_existing_DATA_bytes")? == raw_base,
        "phase ledger/raw reader crossing; rebase required"
    );
    ensure!(
        n(
            &data["data_selection"]["projection"],
            "raw_protected_existing_DATA_bytes"
        )? == raw_base,
        "typed DATA/raw ledger crossing"
    );
    let effective_memory = n(
        &memory["selection"],
        "effective_total_memory_promises_bytes",
    )?;
    let effective_data = n(
        &data["data_selection"]["projection"],
        "proposed_protected_existing_DATA_bytes",
    )?;
    ensure!(
        n(tuple, "effective_existing_memory_bytes")? == effective_memory
            && n(tuple, "effective_existing_DATA_bytes")? == effective_data,
        "complete tuple/typed selection mismatch"
    );
    let qa = n(ledger, "temporary_QA_memory_additional_bytes")?;
    ensure!(
        qa == n(
            ledger,
            "additional_QA_memory_bytes_retained_until_authoritative_closure"
        )?,
        "unreconciled separate QA phases"
    );
    let pool = n(ledger, "normal_external_pool_bytes")?;
    ensure!(
        pool == 6u64 << 30 && qa == 0,
        "R25 current external pool/closed phases changed: require reviewed successor ledger"
    );
    // R25's normal EXTERNAL6GiB is added exactly once. The reader native_pool16GiB
    // is a different retained historical raw promise and is never subtracted.
    let actor = 2u64 << 30;
    let future_guard = 256u64 << 20;
    let candidate_memory = add(actor, future_guard)?;
    let candidate_data = add(
        add(384u64 << 30, 128u64 << 30)?,
        add(64u64 << 20, 64u64 << 20)?,
    )?;
    let selected_existing = add(effective_data, additional)?;
    let complete_raw = add(conservative, candidate_data)?;
    let selected_total = add(selected_existing, candidate_data)?;
    let projected_memory = add(add(add(effective_memory, pool)?, qa)?, candidate_memory)?;
    let floor = n(raw, "inherited_live_guard_maximum_bytes")?
        .max(selected_existing)
        .max(n(
            ledger,
            "input163_protected_transfer_floor_after_new_helper_DATA_bytes",
        )?);
    let cpu = add(n(raw, "current_replay_cpu_quota_micros")?, 4_000_000)?;
    Ok(
        json!({"schema":"epoch185-R25-retained-metadata-resource-projection-v1",
  "basis_sampled_at_utc":tuple["sampled_at_utc"],"raw_existing_DATA_bytes":raw_base,"retained_additional_DATA_bytes":additional,
  "complete_conservative_raw_existing_DATA_bytes":conservative,"selected_existing_DATA_bytes":effective_data,
  "selected_existing_plus_external_DATA_bytes":selected_existing,"candidate_DATA_bytes":candidate_data,
  "selected_total_DATA_bytes":selected_total,"raw_conservative_total_DATA_bytes":complete_raw,
  "effective_existing_memory_bytes":effective_memory,"normal_external_pool_bytes_counted_once":pool,
  "additional_QA_memory_bytes":qa,"candidate_actor_memory_bytes":actor,"future_guard_memory_bytes":future_guard,
  "projected_total_memory_bytes":projected_memory,"projected_replay_plus_candidate_CPU_micros":cpu,
  "minimum_free_bytes_for_future_template":floor,"R25_fixed_R8_overlap_not_used":true,
  "historical_raw_native_pool_bytes_preserved":raw["native_pool_bytes"],
  "no_resource_credit_bytes":0,"fresh_capacity_validated":false,"admission_authorized":false}),
    )
}
pub fn projection_sources(tuple: &Bound, ledger: &Bound, raw: &Bound) -> Value {
    json!({"complete_tuple":tuple,"current_phase_ledger":ledger,"raw_accounting":raw})
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Value, Value, Value) {
        (
            json!({"schema":"horizon-resource-phases-native163-issuer-offline185-materializer-source-QA-v25","exclusive_operational_owner":"01a1af2b-bc56-7311-a916-55aa5e102974","all_old_memory_DATA_and_raw_producer_promises_retained":true,"complete_retained_additional_DATA_bytes":63306015586u64,"raw_DATA_bytes":4641344777168u64,"complete_conservative_raw_DATA_booking_bytes":4704650792754u64,"temporary_QA_memory_additional_bytes":0,"additional_QA_memory_bytes_retained_until_authoritative_closure":0,"normal_external_pool_bytes":6u64<<30,"input163_protected_transfer_floor_after_new_helper_DATA_bytes":4720000000000u64}),
            json!({"effective_existing_memory_bytes":341795667968u64,"effective_existing_DATA_bytes":4202184371152u64,"sampled_at_utc":"historical"}),
            json!({"protected_existing_DATA_bytes":4641344777168u64,"current_replay_cpu_quota_micros":3000000,"inherited_live_guard_maximum_bytes":4202184371152u64,"native_pool_bytes":16u64<<30}),
            json!({"selection":{"effective_total_memory_promises_bytes":341795667968u64}}),
            json!({"data_selection":{"projection":{"raw_protected_existing_DATA_bytes":4641344777168u64,"proposed_protected_existing_DATA_bytes":4202184371152u64}}}),
        )
    }
    #[test]
    fn raw_and_selected_data_use_same_additional_phase_once() {
        let (l, t, r, m, d) = fixture();
        let p = project(&l, &t, &r, &m, &d).unwrap();
        assert_eq!(p["projected_total_memory_bytes"], 350654038016u64);
        assert_eq!(p["selected_total_DATA_bytes"], 4815380418354u64);
        assert_eq!(p["raw_conservative_total_DATA_bytes"], 5254540824370u64);
        assert_eq!(
            p["minimum_free_bytes_for_future_template"],
            4720000000000u64
        );
        assert_eq!(p["admission_authorized"], false);
    }
    #[test]
    fn stale_phase_math_and_unknown_credits_are_rejected() {
        let (l, t, r, m, d) = fixture();
        for (k, v) in [
            ("raw_DATA_bytes", json!(1)),
            (
                "complete_conservative_raw_DATA_booking_bytes",
                json!(4704650792755u64),
            ),
            ("temporary_QA_memory_additional_bytes", json!(8589934592u64)),
            ("normal_external_pool_bytes", json!(16u64 << 30)),
        ] {
            let mut x = l.clone();
            x[k] = v;
            assert!(project(&x, &t, &r, &m, &d).is_err(), "{k}");
        }
    }
}
