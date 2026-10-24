//! Diagnostic binding of every exact SlotMeta/data-shred lookup to every target.
//! Key layout: Solana 893cc764 `ledger/src/blockstore_db.rs`, SHA-256
//! 7391732d9c41d09cdf4f1c9997c9ee37ccace9040aa5845249918084bcc0b046.
//! These functions do not authenticate a native result, backup, clock or anchor.
//! They never grant source completeness, runtime or publication authority.

use crate::{
    horizon_legacy_entry::decode_v1_4_25_padded_entries,
    horizon_legacy_poh::{DiagnosticPohChain, PohExpectation, verify_v1_4_25_poh_chain},
    horizon_legacy_shred::{
        DiagnosticSlotMeta, assemble_v1_4_25_slot_from_meta, decode_v1_4_25_complete_slot_meta,
    },
};

/// An exact logical lookup; a caller maps this to the reviewed native resolver.
#[derive(Debug, Eq, PartialEq)]
pub struct LegacyLookup {
    /// Pinned complete-slot metadata or original data-shred column family.
    pub family: &'static str,
    /// Entire big-endian key, never a prefix or an internal-version first match.
    pub key: Vec<u8>,
}

/// Borrowed native-resolved candidate; provenance remains a separate caller gate.
#[derive(Clone, Copy, Debug)]
pub struct ResolvedLegacyRecord<'a> {
    /// Exact native column family.
    pub family: &'a str,
    /// Exact queried key.
    pub key: &'a [u8],
    /// Native logical value; absent metadata or data always fails recovery.
    pub value: Option<&'a [u8]>,
}

/// Independently allowed post-gap scope, without any clock or PoH claim.
#[derive(Clone, Copy, Debug)]
pub struct LegacySlotScope {
    /// Finalized visible block after the skipped interval.
    pub slot: u64,
    /// Finalized parent before that interval.
    pub parent_slot: u64,
}

fn scopes(expected: &[PohExpectation]) -> Vec<LegacySlotScope> {
    expected
        .iter()
        .map(|e| LegacySlotScope {
            slot: e.slot,
            parent_slot: e.parent_slot,
        })
        .collect()
}

fn metadata(
    records: &[ResolvedLegacyRecord<'_>],
    expected: &[LegacySlotScope],
) -> Result<Vec<DiagnosticSlotMeta>, String> {
    if expected.is_empty() || expected.len() > 64 || records.len() != expected.len() {
        return Err("incomplete or oversized exact target census".into());
    }
    let mut metas = Vec::with_capacity(expected.len());
    let mut previous = None;
    for (record, scope) in records.iter().zip(expected) {
        if scope
            .slot
            .checked_sub(scope.parent_slot)
            .is_none_or(|n| !(2..=64).contains(&n))
            || previous.is_some_and(|slot| scope.parent_slot < slot)
            || record.family != "meta"
            || record.key != scope.slot.to_be_bytes()
        {
            return Err("wrong, overlapping or reordered target metadata lookup".into());
        }
        let meta = decode_v1_4_25_complete_slot_meta(
            record.value.ok_or("missing complete target SlotMeta")?,
            scope.slot,
            scope.parent_slot,
        )?;
        if !meta.is_connected {
            return Err("target SlotMeta is not connected".into());
        }
        previous = Some(scope.slot);
        metas.push(meta);
    }
    Ok(metas)
}

/// Plan metadata rechecks and **all** contiguous data shreds for every target.
///
/// First query exactly one `meta` key per independently allowed target. Supply
/// that complete ordered result here. The second native read must execute this
/// entire returned list, including metadata rechecks, against the same admitted
/// complete census. Both native calls still owe full independent input revalidation.
/// Aggregate query/value limits match the native resolver's 65,536/64-MiB bounds.
pub fn plan_v1_4_25_shred_queries(
    first_metadata: &[ResolvedLegacyRecord<'_>],
    expected: &[PohExpectation],
) -> Result<Vec<LegacyLookup>, String> {
    plan_v1_4_25_scope_queries(first_metadata, &scopes(expected))
}

/// Plan every exact native query from topology alone, without guessing a clock.
/// This performs no PoH work and grants no trust to the returned candidate values.
pub fn plan_v1_4_25_scope_queries(
    first_metadata: &[ResolvedLegacyRecord<'_>],
    expected: &[LegacySlotScope],
) -> Result<Vec<LegacyLookup>, String> {
    let metas = metadata(first_metadata, expected)?;
    let mut count = metas.len();
    let mut bytes: usize = first_metadata.iter().map(|r| r.value.unwrap().len()).sum();
    for meta in &metas {
        let shreds = meta.last_index as usize + 1;
        count = count.checked_add(shreds).ok_or("query count overflow")?;
        bytes = bytes
            .checked_add(shreds.checked_mul(1228).ok_or("shred size overflow")?)
            .ok_or("candidate size overflow")?;
    }
    if count > 65_536 || bytes > 64 * 1024 * 1024 {
        return Err("complete target native query/value budget exceeded".into());
    }
    let mut queries = Vec::with_capacity(count);
    for meta in metas {
        queries.push(LegacyLookup {
            family: "meta",
            key: meta.slot.to_be_bytes().to_vec(),
        });
        for index in 0..=meta.last_index {
            let mut key = meta.slot.to_be_bytes().to_vec();
            key.extend_from_slice(&u64::from(index).to_be_bytes());
            queries.push(LegacyLookup {
                family: "data_shred",
                key,
            });
        }
    }
    Ok(queries)
}

/// Bind both native reads, decode complete shreds/entries and verify all chains.
///
/// Reject a dropped target, changed metadata, missing/extra/reordered/wrong-key
/// value, corrupt chain, overlapping scope or reused boundary. Prebound the
/// aggregate hash work, not merely each slot. A failure returns no partial chain
/// set. Actual native source/clock/anchor authentication, process memory/runtime
/// limits, durable receipts and every canonical publication gate remain owed.
pub fn recover_v1_4_25_records(
    first_metadata: &[ResolvedLegacyRecord<'_>],
    records: &[ResolvedLegacyRecord<'_>],
    expected: &[PohExpectation],
    maximum_hashes: u64,
    mut guard: impl FnMut() -> Result<(), String>,
) -> Result<Vec<DiagnosticPohChain>, String> {
    let queries = plan_v1_4_25_shred_queries(first_metadata, expected)?;
    if maximum_hashes == 0 || maximum_hashes > 512_000_000 || records.len() != queries.len() {
        return Err("incomplete record census or invalid aggregate hash bound".into());
    }
    let mut total_work = 0u64;
    for scope in expected {
        let work = (scope.slot - scope.parent_slot)
            .checked_mul(scope.ticks_per_slot)
            .and_then(|n| n.checked_mul(scope.hashes_per_tick))
            .ok_or("aggregate PoH overflow")?;
        total_work = total_work
            .checked_add(work)
            .ok_or("aggregate PoH overflow")?;
    }
    if total_work > maximum_hashes {
        return Err("aggregate target PoH budget exceeded".into());
    }
    for (record, query) in records.iter().zip(&queries) {
        guard()?;
        if record.family != query.family || record.key != query.key || record.value.is_none() {
            return Err("wrong, missing or reordered complete logical record".into());
        }
    }
    let metas = metadata(first_metadata, &scopes(expected))?;
    let mut offset = 0usize;
    let mut results = Vec::with_capacity(expected.len());
    let mut boundaries = std::collections::BTreeSet::new();
    for ((meta, prior), scope) in metas.iter().zip(first_metadata).zip(expected) {
        if records[offset].value != prior.value {
            return Err("SlotMeta changed between native reads".into());
        }
        offset += 1;
        let end = offset + meta.last_index as usize + 1;
        let shreds: Vec<_> = records[offset..end]
            .iter()
            .map(|r| r.value.unwrap())
            .collect();
        let assembled = assemble_v1_4_25_slot_from_meta(meta, &shreds)?;
        let decoded = assembled
            .iter()
            .map(|batch| {
                guard()?;
                decode_v1_4_25_padded_entries(&batch.bytes)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let result = verify_v1_4_25_poh_chain(&decoded, scope, maximum_hashes, &mut guard)?;
        for boundary in &result.boundaries {
            if !boundaries.insert(boundary.hash) {
                return Err("reused boundary across independent targets".into());
            }
        }
        results.push(result);
        offset = end;
    }
    guard()?;
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    struct Fixture {
        scopes: Vec<PohExpectation>,
        keys: Vec<Vec<u8>>,
        metas: Vec<Vec<u8>>,
        shreds: Vec<Vec<u8>>,
    }
    impl Fixture {
        fn new(count: usize) -> Self {
            let mut f = Self {
                scopes: vec![],
                keys: vec![],
                metas: vec![],
                shreds: vec![],
            };
            let mut hash = [9; 32];
            for index in 0..count {
                let parent = 100 + index as u64 * 3;
                let slot = parent + 3;
                let parent_hash = hash;
                let mut entries = 6u64.to_le_bytes().to_vec();
                for _ in 0..6 {
                    for _ in 0..3 {
                        hash = Sha256::digest(hash).into();
                    }
                    entries.extend_from_slice(&3u64.to_le_bytes());
                    entries.extend_from_slice(&hash);
                    entries.extend_from_slice(&0u64.to_le_bytes());
                }
                let mut shred = vec![0; 1228];
                shred[64] = 0xa5;
                shred[65..73].copy_from_slice(&slot.to_le_bytes());
                shred[77..79].copy_from_slice(&1234u16.to_le_bytes());
                shred[83..85].copy_from_slice(&3u16.to_le_bytes());
                shred[85] = 0xc0;
                shred[86..88].copy_from_slice(&((88 + entries.len()) as u16).to_le_bytes());
                shred[88..88 + entries.len()].copy_from_slice(&entries);
                f.scopes.push(PohExpectation {
                    parent_slot: parent,
                    slot,
                    parent_hash,
                    final_hash: hash,
                    ticks_per_slot: 2,
                    hashes_per_tick: 3,
                });
                f.keys.push(slot.to_be_bytes().to_vec());
                f.metas.push(
                    bincode::serialize(&(
                        slot,
                        1u64,
                        1u64,
                        123u64,
                        0u64,
                        parent,
                        Vec::<u64>::new(),
                        true,
                        vec![0u32],
                    ))
                    .unwrap(),
                );
                f.shreds.push(shred);
            }
            f
        }
        fn metadata(&self) -> Vec<ResolvedLegacyRecord<'_>> {
            self.keys
                .iter()
                .zip(&self.metas)
                .map(|(key, bytes)| ResolvedLegacyRecord {
                    family: "meta",
                    key,
                    value: Some(bytes),
                })
                .collect()
        }
        fn records<'a>(&'a self, queries: &'a [LegacyLookup]) -> Vec<ResolvedLegacyRecord<'a>> {
            queries
                .iter()
                .enumerate()
                .map(|(index, q)| ResolvedLegacyRecord {
                    family: q.family,
                    key: &q.key,
                    value: Some(if index.is_multiple_of(2) {
                        &self.metas[index / 2]
                    } else {
                        &self.shreds[index / 2]
                    }),
                })
                .collect()
        }
    }

    #[test]
    fn all_eleven_synthetic_targets_are_exactly_bound_through_complete_chains() {
        let f = Fixture::new(11);
        let metadata = f.metadata();
        let queries = plan_v1_4_25_shred_queries(&metadata, &f.scopes).unwrap();
        assert_eq!(queries.len(), 22);
        assert_eq!(queries[0].key, 103u64.to_be_bytes());
        assert_eq!(
            queries[1].key,
            [103u64.to_be_bytes(), 0u64.to_be_bytes()].concat()
        );
        let results =
            recover_v1_4_25_records(&metadata, &f.records(&queries), &f.scopes, 198, || Ok(()))
                .unwrap();
        assert_eq!(results.len(), 11);
        assert_eq!(
            results.iter().map(|r| r.boundaries.len()).sum::<usize>(),
            33
        );
        assert!(
            results
                .iter()
                .all(|r| !r.source_completeness_proven && !r.publication_authorized)
        );
    }

    #[test]
    fn missing_extra_reordered_changed_wrong_key_or_corrupt_records_fail_closed() {
        let f = Fixture::new(2);
        let metadata = f.metadata();
        let queries = plan_v1_4_25_shred_queries(&metadata, &f.scopes).unwrap();
        let good = f.records(&queries);
        let recover = |records: &[ResolvedLegacyRecord<'_>]| {
            recover_v1_4_25_records(&metadata, records, &f.scopes, 36, || Ok(()))
        };
        assert!(recover(&good).is_ok());
        assert!(recover(&good[..3]).is_err());
        let mut changed = good.clone();
        changed.push(good[0]);
        assert!(recover(&changed).is_err());
        let mut changed = good.clone();
        changed.swap(0, 2);
        assert!(recover(&changed).is_err());
        let mut changed = good.clone();
        changed[1].family = "code_shred";
        assert!(recover(&changed).is_err());
        let mut changed = good.clone();
        changed[1].key = &queries[3].key;
        assert!(recover(&changed).is_err());
        let mut changed = good.clone();
        changed[1].value = None;
        assert!(recover(&changed).is_err());
        let mut meta = f.metas[0].clone();
        meta[24] ^= 1;
        let mut changed = good.clone();
        changed[0].value = Some(&meta);
        assert!(recover(&changed).is_err());
        let mut shred = f.shreds[0].clone();
        shred[104] ^= 1;
        let mut changed = good.clone();
        changed[1].value = Some(&shred);
        assert!(recover(&changed).is_err());
        assert!(recover_v1_4_25_records(&metadata, &good, &f.scopes, 35, || Ok(())).is_err());
        assert!(
            recover_v1_4_25_records(&metadata, &good, &f.scopes, 36, || Err("guard stop".into()))
                .unwrap_err()
                .contains("guard stop")
        );
    }

    #[test]
    fn metadata_target_census_and_clock_scope_cannot_be_substituted() {
        let f = Fixture::new(2);
        let good = f.metadata();
        assert!(plan_v1_4_25_shred_queries(&good[..1], &f.scopes).is_err());
        let mut changed = good.clone();
        changed[0].key = &f.keys[1];
        assert!(plan_v1_4_25_shred_queries(&changed, &f.scopes).is_err());
        let mut scopes = f.scopes.clone();
        scopes.swap(0, 1);
        assert!(plan_v1_4_25_shred_queries(&good, &scopes).is_err());
        let queries = plan_v1_4_25_shred_queries(&good, &f.scopes).unwrap();
        let mut scopes = f.scopes.clone();
        scopes[1].hashes_per_tick = 4;
        assert!(
            recover_v1_4_25_records(&good, &f.records(&queries), &scopes, 64, || Ok(())).is_err()
        );
    }

    #[test]
    fn native_query_and_value_budgets_fail_before_building_large_query_sets() {
        let mut f = Fixture::new(1);
        for last in [60_000u64, 65_535] {
            f.metas[0] = bincode::serialize(&(
                103u64,
                last + 1,
                last + 1,
                123u64,
                last,
                100u64,
                Vec::<u64>::new(),
                true,
                vec![last as u32],
            ))
            .unwrap();
            assert!(
                plan_v1_4_25_shred_queries(&f.metadata(), &f.scopes)
                    .unwrap_err()
                    .contains("query/value budget")
            );
        }
        f.metas[0] = bincode::serialize(&(
            103u64,
            2u64,
            2u64,
            123u64,
            1u64,
            100u64,
            Vec::<u64>::new(),
            true,
            vec![1u32],
        ))
        .unwrap();
        let queries = plan_v1_4_25_shred_queries(&f.metadata(), &f.scopes).unwrap();
        assert_eq!(
            queries[2].key,
            [103u64.to_be_bytes(), 1u64.to_be_bytes()].concat()
        );
    }

    #[test]
    fn independent_targets_cannot_reuse_the_same_boundary_hashes() {
        let mut f = Fixture::new(2);
        f.scopes[1].parent_hash = f.scopes[0].parent_hash;
        f.scopes[1].final_hash = f.scopes[0].final_hash;
        let repeated = f.shreds[0][88..1139].to_vec();
        f.shreds[1][88..1139].copy_from_slice(&repeated);
        let metadata = f.metadata();
        let queries = plan_v1_4_25_shred_queries(&metadata, &f.scopes).unwrap();
        assert!(
            recover_v1_4_25_records(&metadata, &f.records(&queries), &f.scopes, 36, || Ok(()))
                .unwrap_err()
                .contains("reused boundary")
        );
    }
}
