//! Raw acquisition only: never ancestry, PoH, recovery or publication authority.
//!
//! Solana893cc764 blockstore_db.rs SHA256
//! 7391732d9c41d09cdf4f1c9997c9ee37ccace9040aa5845249918084bcc0b046:
//! SlotColumn keys are big endian u64; data_shred keys are two big endian u64s.
//! The strict recovery planner and assembler deliberately remain unchanged.
use crate::{
    horizon_legacy_recovery::{LegacyLookup, LegacySlotScope, ResolvedLegacyRecord},
    horizon_legacy_shred::{DiagnosticSlotMeta, decode_v1_4_25_complete_slot_meta},
};

/// Explicit acquisition plan; disconnected metadata is retained, never repaired.
#[derive(Debug)]
pub struct AcquisitionPlan {
    /// Complete decoded target metadata, including its original connectivity bit.
    pub metadata: DiagnosticSlotMeta,
    /// Ordered target/parent metadata, root/dead/orphan markers, then all shreds.
    pub queries: Vec<LegacyLookup>,
}

/// Plan one bounded diagnostic target, without calling or weakening recovery.
/// Parent metadata and marker absence must be preserved as raw native outcomes.
/// The caller owes a complete generation-bound native session and post-close
/// source revalidation; these queries alone establish none of that evidence.
pub fn plan_v1_4_25_acquisition_queries(
    first: &[ResolvedLegacyRecord<'_>],
    scope: LegacySlotScope,
) -> Result<AcquisitionPlan, String> {
    let [record] = first else {
        return Err("acquisition needs one exact metadata lookup".into());
    };
    if record.family != "meta"
        || record.key != scope.slot.to_be_bytes()
        || scope
            .slot
            .checked_sub(scope.parent_slot)
            .is_none_or(|n| !(2..=64).contains(&n))
    {
        return Err("acquisition target metadata scope differs".into());
    }
    let metadata = decode_v1_4_25_complete_slot_meta(
        record.value.ok_or("acquisition target metadata absent")?,
        scope.slot,
        scope.parent_slot,
    )?;
    let count = usize::try_from(metadata.last_index).map_err(|_| "shred count overflow")? + 1;
    // Reserve a MiB each for target metadata twice and opaque parent metadata.
    // Raw values still owe the independent native/session and output byte caps.
    if count.checked_add(8).is_none_or(|n| n > 65_536)
        || count
            .checked_mul(1228)
            .and_then(|n| n.checked_add(3 * 1024 * 1024 + 6))
            .is_none_or(|n| n > 64 * 1024 * 1024)
    {
        return Err("acquisition query budget exceeded".into());
    }
    let mut queries = Vec::with_capacity(count + 8);
    for slot in [scope.slot, scope.parent_slot] {
        for family in ["meta", "root", "dead_slots", "orphans"] {
            queries.push(LegacyLookup {
                family,
                key: slot.to_be_bytes().to_vec(),
            });
        }
    }
    for index in 0..=metadata.last_index {
        let mut key = scope.slot.to_be_bytes().to_vec();
        key.extend_from_slice(&u64::from(index).to_be_bytes());
        queries.push(LegacyLookup {
            family: "data_shred",
            key,
        });
    }
    Ok(AcquisitionPlan { metadata, queries })
}

/// Descriptive counts only; present values are not authenticated original shreds.
#[derive(Debug, Eq, PartialEq, serde::Serialize)]
pub struct AcquisitionSummary {
    /// Original target connectivity bit; never changed to make a planner pass.
    pub recorded_is_connected: bool,
    /// Number of data-shred keys required by the complete target metadata.
    pub expected_data_shreds: usize,
    /// Absent native logical values, preserved rather than silently omitted.
    pub missing_data_shred_indexes: Vec<u32>,
    /// Present values whose length differs from the pinned 1228-byte layout.
    pub unexpected_data_shred_length_indexes: Vec<u32>,
    /// Includes all metadata and marker values; null outcomes contribute zero.
    pub total_value_bytes: usize,
}

/// Bind every raw outcome to the acquisition plan. Missing ancestry markers or
/// shreds are diagnostic evidence, not proof of completeness or canonicality.
/// Reject changed metadata, reordered/extra/missing queries and oversized output.
pub fn validate_v1_4_25_acquisition_records(
    first: &[ResolvedLegacyRecord<'_>],
    scope: LegacySlotScope,
    records: &[ResolvedLegacyRecord<'_>],
) -> Result<AcquisitionSummary, String> {
    let plan = plan_v1_4_25_acquisition_queries(first, scope)?;
    if records.len() != plan.queries.len() {
        return Err("acquisition record census differs".into());
    }
    let mut total = 0usize;
    for (record, query) in records.iter().zip(&plan.queries) {
        if record.family != query.family || record.key != query.key {
            return Err("acquisition record key/family/order differs".into());
        }
        total = total
            .checked_add(record.value.map_or(0, <[u8]>::len))
            .ok_or("acquisition byte overflow")?;
        if total > 64 * 1024 * 1024 {
            return Err("acquisition value budget exceeded".into());
        }
    }
    if records[0].value != first[0].value {
        return Err("acquisition target metadata changed".into());
    }
    let mut summary = AcquisitionSummary {
        recorded_is_connected: plan.metadata.is_connected,
        expected_data_shreds: plan.metadata.last_index as usize + 1,
        missing_data_shred_indexes: vec![],
        unexpected_data_shred_length_indexes: vec![],
        total_value_bytes: total,
    };
    for (index, record) in records[8..].iter().enumerate() {
        match record.value {
            None => summary.missing_data_shred_indexes.push(index as u32),
            Some(value) if value.len() != 1228 => summary
                .unexpected_data_shred_length_indexes
                .push(index as u32),
            Some(_) => {}
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::horizon_legacy_recovery::plan_v1_4_25_scope_queries;
    fn scope() -> LegacySlotScope {
        LegacySlotScope {
            slot: 60911776,
            parent_slot: 60911771,
        }
    }
    fn meta(last: u64, connected: bool) -> Vec<u8> {
        bincode::serialize(&(
            60911776u64,
            last + 1,
            last + 1,
            123u64,
            last,
            60911771u64,
            Vec::<u64>::new(),
            connected,
            vec![last as u32],
        ))
        .unwrap()
    }
    #[test]
    fn disconnected_observed_shred_count_gets_raw_queries_but_never_recovery() {
        let bytes = meta(777, false);
        let key = 60911776u64.to_be_bytes();
        let first = [ResolvedLegacyRecord {
            family: "meta",
            key: &key,
            value: Some(&bytes),
        }];
        assert!(plan_v1_4_25_scope_queries(&first, &[scope()]).is_err());
        let plan = plan_v1_4_25_acquisition_queries(&first, scope()).unwrap();
        assert!(!plan.metadata.is_connected);
        assert_eq!(plan.queries.len(), 786);
        assert_eq!(plan.queries[0].family, "meta");
        assert_eq!(plan.queries[4].key, 60911771u64.to_be_bytes());
        assert_eq!(
            plan.queries[785].key,
            [60911776u64.to_be_bytes(), 777u64.to_be_bytes()].concat()
        );
        let payload = vec![0; 1228];
        let records: Vec<_> = plan
            .queries
            .iter()
            .enumerate()
            .map(|(i, q)| ResolvedLegacyRecord {
                family: q.family,
                key: &q.key,
                value: if i == 0 {
                    Some(&bytes)
                } else if i >= 8 {
                    Some(&payload)
                } else {
                    None
                },
            })
            .collect();
        let result = validate_v1_4_25_acquisition_records(&first, scope(), &records).unwrap();
        assert!(!result.recorded_is_connected);
        assert_eq!(result.expected_data_shreds, 778);
        assert!(result.missing_data_shred_indexes.is_empty());
        assert_eq!(result.total_value_bytes, bytes.len() + 955384);
        assert!(plan_v1_4_25_scope_queries(&first, &[scope()]).is_err());
    }
    #[test]
    fn absent_or_malformed_raw_values_remain_explicit_diagnostics() {
        let bytes = meta(1, true);
        let key = 60911776u64.to_be_bytes();
        let first = [ResolvedLegacyRecord {
            family: "meta",
            key: &key,
            value: Some(&bytes),
        }];
        let plan = plan_v1_4_25_acquisition_queries(&first, scope()).unwrap();
        let mut records: Vec<_> = plan
            .queries
            .iter()
            .enumerate()
            .map(|(i, q)| ResolvedLegacyRecord {
                family: q.family,
                key: &q.key,
                value: if i == 0 { Some(&bytes) } else { None },
            })
            .collect();
        records[9].value = Some(&[1, 2]);
        let result = validate_v1_4_25_acquisition_records(&first, scope(), &records).unwrap();
        assert_eq!(result.missing_data_shred_indexes, [0]);
        assert_eq!(result.unexpected_data_shred_length_indexes, [1]);
        records.swap(1, 2);
        assert!(validate_v1_4_25_acquisition_records(&first, scope(), &records).is_err());
        records.swap(1, 2);
        records[0].value = None;
        assert!(validate_v1_4_25_acquisition_records(&first, scope(), &records).is_err());
        assert!(validate_v1_4_25_acquisition_records(&first, scope(), &records[..9]).is_err());
    }
    #[test]
    fn wrong_scope_duplicates_and_native_batch_overflow_fail_closed() {
        let bytes = meta(0, false);
        let key = 60911776u64.to_be_bytes();
        let first = ResolvedLegacyRecord {
            family: "meta",
            key: &key,
            value: Some(&bytes),
        };
        assert!(plan_v1_4_25_acquisition_queries(&[], scope()).is_err());
        assert!(plan_v1_4_25_acquisition_queries(&[first, first], scope()).is_err());
        assert!(
            plan_v1_4_25_acquisition_queries(
                &[ResolvedLegacyRecord {
                    family: "root",
                    ..first
                }],
                scope()
            )
            .is_err()
        );
        assert!(
            plan_v1_4_25_acquisition_queries(
                &[first],
                LegacySlotScope {
                    slot: 60911776,
                    parent_slot: 60911775
                }
            )
            .is_err()
        );
        let big = meta(65535, false);
        assert!(
            plan_v1_4_25_acquisition_queries(
                &[ResolvedLegacyRecord {
                    value: Some(&big),
                    ..first
                }],
                scope()
            )
            .is_err()
        );
    }
    #[test]
    fn connected_recovery_queries_stay_unchanged_and_acquisition_prebounds_values() {
        let bytes = meta(1, true);
        let key = 60911776u64.to_be_bytes();
        let first = [ResolvedLegacyRecord {
            family: "meta",
            key: &key,
            value: Some(&bytes),
        }];
        let strict = plan_v1_4_25_scope_queries(&first, &[scope()]).unwrap();
        let acquisition = plan_v1_4_25_acquisition_queries(&first, scope()).unwrap();
        assert!(acquisition.metadata.is_connected);
        assert_eq!(strict[0], acquisition.queries[0]);
        assert_eq!(strict[1..], acquisition.queries[8..]);
        for (count, accept) in [(52087, true), (52088, false)] {
            let bytes = meta(count - 1, false);
            let records = [ResolvedLegacyRecord {
                family: "meta",
                key: &key,
                value: Some(&bytes),
            }];
            assert_eq!(
                plan_v1_4_25_acquisition_queries(&records, scope()).is_ok(),
                accept
            );
        }
    }
}
