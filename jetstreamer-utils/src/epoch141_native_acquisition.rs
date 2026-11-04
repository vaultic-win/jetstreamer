//! Candidate first-target raw acquisition. Never a recovery route.
use super::*;
use jetstreamer_utils::horizon_legacy_acquisition::{
    plan_v1_4_25_acquisition_queries, validate_v1_4_25_acquisition_records,
};
pub(super) const SCHEMA: &str =
    "jetstreamer-epoch141-ledger-native-first-target-acquisition-plan-v1";
fn borrowed(r: &NativeCandidate) -> ResolvedLegacyRecord<'_> {
    ResolvedLegacyRecord {
        family: &r.family,
        key: &r.key,
        value: r.value.as_deref(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    plan: &Plan,
    bound: &BoundBzipCollection,
    scopes: &[LegacySlotScope],
    invocation: &str,
    values: &BTreeMap<String, String>,
    start: Instant,
    free: u64,
) -> Result<()> {
    ensure!(
        plan.schema == SCHEMA
            && scopes.len() == 18_283
            && scopes[0].slot == 60911776
            && scopes[0].parent_slot == 60911771,
        "acquisition cannot substitute scope or claim the full census"
    );
    ensure!(
        free >= plan
            .minimum_free_bytes
            .checked_add(OUTPUT_RESERVATION)
            .context("acquisition reserve overflow")?,
        "acquisition output reserve unavailable"
    );
    let scope = scopes[0];
    let intent_bytes = bounded_write(
        &plan.metadata_receipt,
        &json!({
        "schema":"jetstreamer-epoch141-native-first-target-acquisition-intent-v1",
        "invocation_id":invocation,"plan_sha256":values["--plan-sha256"],"slot":scope.slot,"parent_slot":scope.parent_slot,
        "complete_finalized_target_census_count":scopes.len(),"native_session_complete":false,
        "full_target_census_complete":false,"acquisition_only":true,"publication_authorized":false,
        "replay_launch_authorized":false,"runtime_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    let logs = plan.log_directory.join("first-target-acquisition");
    fs::DirBuilder::new().mode(0o700).create(&logs)?;
    File::open(&plan.log_directory)?.sync_all()?;
    let mut last = Instant::now();
    let mut callback = || {
        if last.elapsed().as_secs() >= 1 {
            guard(plan, start)?;
            last = Instant::now();
        }
        Ok(())
    };
    let ((first, complete, summary), session) = with_native_read_session(
        &plan.database_directory,
        &bound.collection,
        &logs,
        &plan.expected_families,
        NativeReadBudget {
            batches: 2,
            queries: 65_537,
            value_bytes: 64 * 1024 * 1024,
        },
        &mut callback,
        |reader, guard_callback| {
            let first = reader.read_candidates(
                &[NativeQuery {
                    family: "meta".into(),
                    key: scope.slot.to_be_bytes().to_vec(),
                }],
                guard_callback,
            )?;
            let first_records: Vec<_> = first.iter().map(borrowed).collect();
            let query_plan = plan_v1_4_25_acquisition_queries(&first_records, scope)
                .map_err(anyhow::Error::msg)?;
            let queries: Vec<_> = query_plan
                .queries
                .iter()
                .map(|q| NativeQuery {
                    family: q.family.into(),
                    key: q.key.clone(),
                })
                .collect();
            let complete = reader.read_candidates(&queries, guard_callback)?;
            let records: Vec<_> = complete.iter().map(borrowed).collect();
            let summary = validate_v1_4_25_acquisition_records(&first_records, scope, &records)
                .map_err(anyhow::Error::msg)?;
            Ok((first, complete, summary))
        },
    )?;
    ensure!(
        session.batches == 2
            && session.queries == complete.len() + 1
            && session.complete_census_revalidated
            && !session.source_completeness_proven
            && !session.live_state_proven
            && !session.publication_authorized,
        "acquisition session accounting differs"
    );
    for evidence in [
        &plan.source_verification,
        &plan.collection_receipt,
        &plan.complete_census,
        &plan.gap_audit,
        plan.finalized_collection_plan
            .as_ref()
            .context("collector plan")?,
        plan.finalized_collection_receipt
            .as_ref()
            .context("collector completion")?,
    ] {
        bound_file(&evidence.path, &evidence.sha256, 32 * 1024 * 1024, false)?;
    }
    bound_file(
        Path::new(&values["--plan"]),
        &values["--plan-sha256"],
        65536,
        true,
    )?;
    let after = guard(plan, start)?;
    let encode = |records: &[NativeCandidate]| {
        records.iter().map(|r|json!({"family":r.family,
        "key_base64":STANDARD.encode(&r.key),"value_base64":r.value.as_ref().map(|v|STANDARD.encode(v))})).collect::<Vec<_>>()
    };
    let output = json!({
        "schema":"jetstreamer-epoch141-native-first-target-acquisition-v1","epoch":141,
        "slot":scope.slot,"parent_slot":scope.parent_slot,"recorded_unix_seconds":now()?,"invocation_id":invocation,
        "self_sha256":values["--self-sha256"],"plan_sha256":values["--plan-sha256"],"admission_sha256":values["--admission-sha256"],
        "source_verification_sha256":plan.source_verification.sha256,"collection_sha256":plan.collection_receipt.sha256,
        "complete_census_sha256":plan.complete_census.sha256,"gap_census_sha256":FULL_CENSUS_SHA,
        "finalized_collection_plan_sha256":plan.finalized_collection_plan.as_ref().unwrap().sha256,
        "finalized_collection_receipt_sha256":plan.finalized_collection_receipt.as_ref().unwrap().sha256,
        "first_metadata":encode(&first),"records":encode(&complete),"acquisition_summary":summary,"native_session":session,
        "native_session_complete":true,"complete_retained_census_revalidated_after_close":true,
        "complete_finalized_target_census_count":scopes.len(),"queried_target_count":1,"recovered_target_count":0,"full_target_census_complete":false,
        "available_bytes_before":free,"available_bytes_before_result":after,"minimum_free_bytes":plan.minimum_free_bytes,
        "elapsed_seconds":start.elapsed().as_secs(),"acquisition_only":true,
        "source_completeness_proven":false,"live_state_proven":false,"canonical_ancestry_proven":false,
        "runtime_clock_authenticated":false,"hidden_poh_hashes_recovered":false,"runtime_promotion_authorized":false,
        "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let bytes = serde_json::to_vec_pretty(&output)?.len() as u64 + 1;
    ensure!(
        (intent_bytes as u64)
            .checked_add(bytes)
            .is_some_and(|n| n <= OUTPUT_RESERVATION - 64 * 1024 * 1024)
            && after
                >= plan
                    .minimum_free_bytes
                    .checked_add(bytes)
                    .context("acquisition final reserve overflow")?,
        "acquisition output exceeds reserve"
    );
    bounded_write(&plan.output_receipt, &output)?;
    println!(
        "first-target acquisition durable after native close/source rehash; no recovery/ancestry/PoH/publication authority"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root exact retained epoch141 rejection bytes; read-only no native open or sampling"]
    fn actual_rejected_metadata_plans778_raw_shreds_without_recovery_authority() {
        let bytes=bound_file(Path::new("/home/sol/.jetstreamer-private/epoch141-native-rejection-20261022-v1/results/metadata-rejection.json"),"635a30409eb977732b141c76b915f8416db2f5e32280ccbb209af69743cb836e",16*1024*1024,false).unwrap();
        let receipt: Value = serde_json::from_slice(&bytes).unwrap();
        let records: Vec<_> = receipt["rejection"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| NativeCandidate {
                family: r["family"].as_str().unwrap().into(),
                key: STANDARD.decode(r["key_base64"].as_str().unwrap()).unwrap(),
                value: r["value_base64"]
                    .as_str()
                    .map(|v| STANDARD.decode(v).unwrap()),
            })
            .collect();
        let scope = LegacySlotScope {
            slot: 60911776,
            parent_slot: 60911771,
        };
        let first: Vec<_> = records.iter().map(borrowed).collect();
        let planned = plan_v1_4_25_acquisition_queries(&first, scope).unwrap();
        assert!(!planned.metadata.is_connected);
        assert_eq!(planned.metadata.last_index, 777);
        assert_eq!(planned.metadata.completed_data_indexes.len(), 625);
        assert_eq!(planned.queries.len(), 786);
        assert!(plan_v1_4_25_scope_queries(&first, &[scope]).is_err());
        assert_eq!(records[0].value.as_ref().unwrap().len(), 2573);
    }
}
