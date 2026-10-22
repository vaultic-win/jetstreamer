//! All-target raw diagnostic acquisition in one bounded native session. False
//! connectivity, absent values and planner rejections are retained, not repaired.
use super::*;
use jetstreamer_utils::horizon_legacy_acquisition::{
    plan_v1_4_25_acquisition_queries, validate_v1_4_25_acquisition_records,
};
pub(super) const SCHEMA: &str = "jetstreamer-epoch141-ledger-native-all-target-acquisition-plan-v2";
pub(super) const ADMISSION: &str = "epoch141-read-only-all-target-acquisition-v5";
fn borrowed(r: &NativeCandidate) -> ResolvedLegacyRecord<'_> {
    ResolvedLegacyRecord {
        family: &r.family,
        key: &r.key,
        value: r.value.as_deref(),
    }
}
fn encode(rows: &[NativeCandidate]) -> Vec<Value> {
    rows.iter().map(|r|json!({"family":r.family,"key_base64":STANDARD.encode(&r.key),"value_base64":r.value.as_ref().map(|v|STANDARD.encode(v))})).collect()
}
struct TargetOutcome {
    value: Value,
    acquired: bool,
    missing: u64,
    odd: u64,
}
fn acquire_target(
    target: LegacySlotScope,
    read: &mut impl FnMut(&[NativeQuery]) -> Result<Vec<NativeCandidate>>,
) -> Result<TargetOutcome> {
    let first = read(&[NativeQuery {
        family: "meta".into(),
        key: target.slot.to_be_bytes().to_vec(),
    }])?;
    let borrowed_first: Vec<_> = first.iter().map(borrowed).collect();
    let q = match plan_v1_4_25_acquisition_queries(&borrowed_first, target) {
        Ok(q) => q,
        Err(reason) => {
            return Ok(TargetOutcome {
                value: json!({"status":"metadata-rejected","planner_error":reason,"first_metadata":encode(&first),"records":[]}),
                acquired: false,
                missing: 0,
                odd: 0,
            });
        }
    };
    let queries: Vec<_> = q
        .queries
        .iter()
        .map(|q| NativeQuery {
            family: q.family.into(),
            key: q.key.clone(),
        })
        .collect();
    let complete = read(&queries)?;
    let rows: Vec<_> = complete.iter().map(borrowed).collect();
    // Unlike a diagnostic planning rejection, native read errors and changed
    //metadata/order propagate as fatal and cannot yield a target outcome.
    let summary = validate_v1_4_25_acquisition_records(&borrowed_first, target, &rows)
        .map_err(anyhow::Error::msg)?;
    let missing = summary.missing_data_shred_indexes.len() as u64;
    let odd = summary.unexpected_data_shred_length_indexes.len() as u64;
    Ok(TargetOutcome {
        value: json!({"status":"raw-acquired","first_metadata":encode(&first),"records":encode(&complete),"summary":summary}),
        acquired: true,
        missing,
        odd,
    })
}
pub(super) fn scope(scopes: &[LegacySlotScope]) -> Result<()> {
    ensure!(
        scopes.len() == 18283
            && scopes
                .first()
                .is_some_and(|s| s.slot == 60911776 && s.parent_slot == 60911771)
            // The interval ends61328765, but the independently finalized gap
            //census's last post-gap target is61328744. They are not aliases.
            && scopes.last().is_some_and(|s| s.slot == 61328744)
            && scopes.windows(2).all(|w| w[0].slot < w[1].slot)
            && scopes
                .iter()
                .all(|s| s.slot > s.parent_slot && (60911751..=61328765).contains(&s.slot)),
        "all-target acquisition needs complete ordered fixed141 census"
    );
    Ok(())
}
fn accounting(
    total: usize,
    acquired: usize,
    rejected: usize,
    batches: usize,
    receipts: usize,
) -> Result<()> {
    ensure!(
        total == 18283
            && acquired.checked_add(rejected) == Some(total)
            && receipts == total
            && acquired
                .checked_mul(2)
                .and_then(|n| n.checked_add(rejected))
                == Some(batches),
        "all-target acquisition accounting incomplete"
    );
    Ok(())
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
        plan.schema == SCHEMA,
        "foreign all-target acquisition profile"
    );
    scope(scopes)?;
    ensure!(
        free >= plan
            .minimum_free_bytes
            .checked_add(FULL_OUTPUT_RESERVATION)
            .context("all-target reserve overflow")?,
        "all-target output reservation unavailable"
    );
    let root = plan
        .output_receipt
        .parent()
        .context("all-target result parent")?;
    let batches = root.join("target-acquisitions");
    fs::DirBuilder::new().mode(0o700).create(&batches)?;
    File::open(root)?.sync_all()?;
    bounded_write(
        &plan.metadata_receipt,
        &json!({"schema":"jetstreamer-epoch141-native-all-target-acquisition-intent-v2",
        "invocation_id":invocation,"plan_sha256":values["--plan-sha256"],"census_sha256":FULL_CENSUS_SHA,"target_count":scopes.len(),
        "output_reservation_bytes":FULL_OUTPUT_RESERVATION,"output_limit_bytes":FULL_OUTPUT_LIMIT,"native_value_budget_bytes":32u64<<30,
        "native_session_complete":false,"acquisition_only":true,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    let logs = plan.log_directory.join("all-target-acquisition");
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
    // Reserve bounded final-manifest overhead before accounting target files.
    let mut written = 8u64 << 20;
    let ((receipts, acquired, rejected, missing_shreds, odd_lengths), session) =
        with_native_read_session(
            &plan.database_directory,
            &bound.collection,
            &logs,
            &plan.expected_families,
            NativeReadBudget {
                batches: 36566,
                queries: 16777216,
                value_bytes: 32u64 << 30,
            },
            &mut callback,
            |reader, guard_callback| {
                let mut receipts = Vec::with_capacity(scopes.len());
                let mut acquired = 0usize;
                let mut rejected = 0usize;
                let mut missing_shreds = 0u64;
                let mut odd_lengths = 0u64;
                for (index, target) in scopes.iter().enumerate() {
                    let outcome = acquire_target(*target, &mut |queries| {
                        reader.read_candidates(queries, guard_callback)
                    })?;
                    if outcome.acquired {
                        acquired += 1;
                    } else {
                        rejected += 1;
                    }
                    missing_shreds = missing_shreds
                        .checked_add(outcome.missing)
                        .context("missing shred count overflow")?;
                    odd_lengths = odd_lengths
                        .checked_add(outcome.odd)
                        .context("odd shred count overflow")?;
                    let outcome = outcome.value;
                    let value = json!({"schema":"jetstreamer-epoch141-native-provisional-acquisition-target-v2","slot":target.slot,"parent_slot":target.parent_slot,
                    "invocation_id":invocation,"plan_sha256":values["--plan-sha256"],"census_sha256":FULL_CENSUS_SHA,"outcome":outcome,
                    "native_session_complete":false,"source_completeness_proven":false,"live_state_proven":false,"canonical_ancestry_proven":false,
                    "runtime_clock_authenticated":false,"hidden_poh_hashes_recovered":false,"runtime_promotion_authorized":false,
                    "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
                    let bytes = serde_json::to_vec_pretty(&value)?.len() as u64 + 1;
                    written = written
                        .checked_add(bytes)
                        .context("all-target output overflow")?;
                    ensure!(
                        written <= FULL_OUTPUT_LIMIT
                            && guard(plan, start)?
                                >= plan
                                    .minimum_free_bytes
                                    .checked_add(bytes)
                                    .context("all-target reserve overflow")?,
                        "all-target output budget/reserve unavailable"
                    );
                    let path = batches.join(format!("slot-{}.json", target.slot));
                    bounded_write(&path, &value)?;
                    let content = fs::read(&path)?;
                    let sha = format!("{:x}", Sha256::digest(&content));
                    bound_file(&path, &sha, MAX_OUTPUT as u64, false)?;
                    receipts.push(json!({"path":path,"sha256":sha,"slot":target.slot,"status":value["outcome"]["status"]}));
                    if index == 0 || (index + 1).is_multiple_of(100) {
                        eprintln!(
                            "native-all-acquisition attempted_targets={} total={} acquired={} rejected={}",
                            index + 1,
                            scopes.len(),
                            acquired,
                            rejected
                        );
                    }
                }
                Ok((receipts, acquired, rejected, missing_shreds, odd_lengths))
            },
        )?;
    accounting(
        scopes.len(),
        acquired,
        rejected,
        session.batches,
        receipts.len(),
    )?;
    ensure!(
        session.complete_census_revalidated
            && !session.source_completeness_proven
            && !session.live_state_proven
            && !session.publication_authorized,
        "all-target session lacks post-close retained-source revalidation"
    );
    for r in &receipts {
        guard(plan, start)?;
        bound_file(
            Path::new(r["path"].as_str().context("target receipt path")?),
            r["sha256"].as_str().context("target digest")?,
            MAX_OUTPUT as u64,
            false,
        )?;
    }
    for b in [
        &plan.source_verification,
        &plan.collection_receipt,
        &plan.complete_census,
        &plan.gap_audit,
        plan.finalized_collection_plan
            .as_ref()
            .context("all-target finalized plan")?,
        plan.finalized_collection_receipt
            .as_ref()
            .context("all-target finalized receipt")?,
    ] {
        bound_file(&b.path, &b.sha256, 32 << 20, false)?;
    }
    bound_file(
        Path::new(&values["--plan"]),
        &values["--plan-sha256"],
        65536,
        true,
    )?;
    let mut output = json!({"schema":"jetstreamer-epoch141-native-all-target-acquisition-v2","epoch":141,"recorded_unix_seconds":now()?,
        "invocation_id":invocation,"self_sha256":values["--self-sha256"],"plan_sha256":values["--plan-sha256"],"admission_sha256":values["--admission-sha256"],
        "source_verification_sha256":plan.source_verification.sha256,"collection_sha256":plan.collection_receipt.sha256,
        "complete_census_sha256":plan.complete_census.sha256,"gap_census_sha256":FULL_CENSUS_SHA,
        "finalized_collection_plan_sha256":plan.finalized_collection_plan.as_ref().unwrap().sha256,"finalized_collection_receipt_sha256":plan.finalized_collection_receipt.as_ref().unwrap().sha256,
        "target_receipts":receipts});
    output.as_object_mut().unwrap().extend(json!({"complete_finalized_target_census_count":scopes.len(),"attempted_target_count":scopes.len(),
        "raw_acquired_target_count":acquired,"metadata_rejected_target_count":rejected,"missing_data_shred_count":missing_shreds,"unexpected_shred_length_count":odd_lengths,
        "recovered_target_count":0,"full_target_attempt_census_complete":true,"full_target_raw_acquisition_complete":rejected==0 && missing_shreds==0 && odd_lengths==0,
        "native_session":session,"native_session_complete":true,"complete_retained_census_revalidated_after_close":true,
        "output_bytes_accounted":written,"output_limit_bytes":FULL_OUTPUT_LIMIT,"output_reservation_bytes":FULL_OUTPUT_RESERVATION,
        "available_bytes_before":free,"available_bytes_before_result":guard(plan,start)?,"minimum_free_bytes":plan.minimum_free_bytes,"elapsed_seconds":start.elapsed().as_secs()}).as_object().unwrap().clone());
    output.as_object_mut().unwrap().extend(json!({
        "acquisition_only":true,"source_completeness_proven":false,"live_state_proven":false,"canonical_ancestry_proven":false,
        "runtime_clock_authenticated":false,"hidden_poh_hashes_recovered":false,"runtime_promotion_authorized":false,
        "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}).as_object().unwrap().clone());
    let bytes = serde_json::to_vec_pretty(&output)?.len() as u64 + 1;
    ensure!(
        bytes <= 8 << 20
            && guard(plan, start)?
                >= plan
                    .minimum_free_bytes
                    .checked_add(bytes)
                    .context("all-target final reserve overflow")?,
        "all-target final manifest exceeds reserved overhead"
    );
    bounded_write(&plan.output_receipt, &output)?;
    println!(
        "all18283 native acquisition attempts retained after source revalidation; acquired={acquired} rejected={rejected}; no recovery/PoH/publication authority"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn target() -> LegacySlotScope {
        LegacySlotScope {
            slot: 60911776,
            parent_slot: 60911771,
        }
    }
    fn meta() -> Vec<u8> {
        bincode::serialize(&(
            60911776u64,
            2u64,
            2u64,
            123u64,
            1u64,
            60911771u64,
            Vec::<u64>::new(),
            false,
            vec![1u32],
        ))
        .unwrap()
    }
    #[test]
    fn disconnected_raw_acquisition_keeps_nulls_odd_values_and_does_not_mask_native_errors() {
        let m = meta();
        let mut calls = 0;
        let out = acquire_target(target(), &mut |queries| {
            calls += 1;
            Ok(queries
                .iter()
                .enumerate()
                .map(|(i, q)| NativeCandidate {
                    family: q.family.clone(),
                    key: q.key.clone(),
                    value: if i == 0 {
                        Some(m.clone())
                    } else if i == 9 {
                        Some(vec![0; 7])
                    } else {
                        None
                    },
                })
                .collect())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert!(out.acquired);
        assert_eq!(out.missing, 1);
        assert_eq!(out.odd, 1);
        assert_eq!(out.value["summary"]["recorded_is_connected"], false);
        assert!(out.value["records"][1]["value_base64"].is_null());
        for fail_at in [1, 2] {
            let mut calls = 0;
            assert!(
                acquire_target(target(), &mut |queries| {
                    calls += 1;
                    if calls == fail_at {
                        anyhow::bail!("native I/O failure");
                    }
                    Ok(queries
                        .iter()
                        .map(|q| NativeCandidate {
                            family: q.family.clone(),
                            key: q.key.clone(),
                            value: Some(m.clone()),
                        })
                        .collect())
                })
                .is_err()
            );
        }
    }
    #[test]
    fn metadata_absence_is_explicit_but_changed_metadata_and_reordered_records_are_fatal() {
        let out = acquire_target(target(), &mut |queries| {
            Ok(queries
                .iter()
                .map(|q| NativeCandidate {
                    family: q.family.clone(),
                    key: q.key.clone(),
                    value: None,
                })
                .collect())
        })
        .unwrap();
        assert!(!out.acquired);
        assert_eq!(out.value["status"], "metadata-rejected");
        for reorder in [false, true] {
            let m = meta();
            let mut calls = 0;
            assert!(
                acquire_target(target(), &mut |queries| {
                    calls += 1;
                    let mut rows: Vec<_> = queries
                        .iter()
                        .map(|q| NativeCandidate {
                            family: q.family.clone(),
                            key: q.key.clone(),
                            value: Some(m.clone()),
                        })
                        .collect();
                    if calls == 2 {
                        if reorder {
                            rows.swap(0, 1);
                        } else {
                            rows[0].value = Some(vec![0]);
                        }
                    }
                    Ok(rows)
                })
                .is_err()
            );
        }
    }
    #[test]
    fn full_scope_cannot_be_replaced_by_first_target_or_reordered_subset() {
        let mut s: Vec<_> = (0..18283)
            .map(|i| LegacySlotScope {
                slot: 60911776 + i * 20,
                parent_slot: 60911771 + i * 20,
            })
            .collect();
        s.last_mut().unwrap().slot = 61328744;
        scope(&s).unwrap();
        s.last_mut().unwrap().slot = 61328765;
        assert!(
            scope(&s).is_err(),
            "interval end must not replace final post-gap target"
        );
        s.last_mut().unwrap().slot = 61328744;
        assert!(scope(&s[..1]).is_err());
        s.swap(1, 2);
        assert!(scope(&s).is_err());
    }
    #[test]
    #[ignore = "root exact finalized18283target census metadata only; no native open, resource sample, archive read or remote access"]
    fn actual_finalized_census_ends_at_last_gap_not_interval_end() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let targets = finalized::validate_complete_collection(
            Path::new("/usr/local/lib/jetstreamer/horizon-epoch140-gap-metadata-fetch-20261021-v1/plan.json"),
            "fc320b12c2a53c95f6781ed9130a57e179078ce09b654f96b79c675a96fdf5cc",
            Path::new("/var/lib/jetstreamer-epoch140-gap-metadata-20261021-v1/complete.json"),
            "21427d5debbc22ab44c337fb32679620ec663f44c52c5ceeb7100fcb450f8fe4",
        ).unwrap();
        let scopes: Vec<_> = targets
            .iter()
            .map(|m| LegacySlotScope {
                slot: m.slot,
                parent_slot: m.parent_slot,
            })
            .collect();
        scope(&scopes).unwrap();
        assert_eq!(scopes.len(), 18283);
        assert_eq!(scopes.last().unwrap().slot, 61328744);
    }
    #[test]
    fn every_rejection_is_still_an_explicit_attempt_not_recovery() {
        accounting(18283, 18282, 1, 36565, 18283).unwrap();
        accounting(18283, 0, 18283, 18283, 18283).unwrap();
        assert!(accounting(18283, 1, 0, 2, 1).is_err());
        assert!(accounting(18283, 18283, 0, 36565, 18283).is_err());
        assert!(accounting(18283, usize::MAX, 0, 0, 18283).is_err());
    }
}
