//! Byte-only interpretation of a complete raw acquisition. This deliberately
//! does not call recovery, change SlotMeta, infer a trusted clock, execute PoH,
//! authenticate ancestry or emit runtime boundaries.
use crate::{
    horizon_legacy_acquisition::{
        plan_v1_4_25_acquisition_queries, validate_v1_4_25_acquisition_records,
    },
    horizon_legacy_entry::decode_v1_4_25_padded_entries,
    horizon_legacy_recovery::{LegacySlotScope, ResolvedLegacyRecord},
    horizon_legacy_shred::assemble_v1_4_25_padded_batches,
};

/// Observed serialized shapes, not independently authenticated chain state.
#[derive(Debug, serde::Serialize)]
pub struct ByteDiagnostic {
    /// Original recorded metadata bit, unchanged by interpretation.
    pub recorded_is_connected: bool,
    /// All exact contiguous raw values owed by the metadata.
    pub data_shreds: usize,
    /// Data-complete batches whose endpoints match the original metadata.
    pub completed_batches: usize,
    /// Structurally decoded entries across all batches.
    pub entries: usize,
    /// Empty-transaction entries; not authenticated clock ticks.
    pub ticks: usize,
    /// Structurally decoded transaction count.
    pub transactions: usize,
    /// Entries claiming no hash work, retained as a diagnostic count.
    pub zero_work_entries: usize,
    /// Sum of serialized hash-work claims; no hashing is executed here.
    pub claimed_hash_work: u64,
    /// Last serialized entry hash, still requiring complete PoH verification.
    pub last_entry_hash: [u8; 32],
    /// A final-hash comparison only, never hidden/intermediate chain proof.
    pub final_entry_matches_finalized_hash: bool,
    /// Always false: this helper never authenticates ancestry.
    pub canonical_ancestry_proven: bool,
    /// Always false: no independent clock proof is supplied or inferred.
    pub runtime_clock_authenticated: bool,
    /// Always false: no chained entry hashing is executed.
    pub poh_chain_verified: bool,
    /// Always false: byte interpretation is never a publication gate.
    pub publication_authorized: bool,
}

/// Decode acquired bytes without mutating metadata or weakening connected recovery.
///
/// The caller separately authenticates the acquisition receipt, native-close/
/// source-rehash lineage and independently finalized final hash. All records,
/// metadata rechecks, indexes, legacy headers, padding and batch endpoints are
/// mandatory. Even a matching final entry hash does not authenticate the PoH
/// chain, clock, missing boundaries, live state, ancestry or publication.
pub fn diagnose_v1_4_25_acquired_bytes(
    first: &[ResolvedLegacyRecord<'_>],
    scope: LegacySlotScope,
    records: &[ResolvedLegacyRecord<'_>],
    finalized_final_hash: [u8; 32],
) -> Result<ByteDiagnostic, String> {
    let plan = plan_v1_4_25_acquisition_queries(first, scope)?;
    let summary = validate_v1_4_25_acquisition_records(first, scope, records)?;
    if !summary.missing_data_shred_indexes.is_empty()
        || !summary.unexpected_data_shred_length_indexes.is_empty()
    {
        return Err("byte diagnostic requires every exact raw data shred".into());
    }
    let shreds: Vec<_> = records[8..].iter().map(|r| r.value.unwrap()).collect();
    let batches = assemble_v1_4_25_padded_batches(
        scope.slot,
        scope.parent_slot,
        plan.metadata.last_index,
        &shreds,
    )?;
    if batches.iter().map(|b| b.last_index).collect::<Vec<_>>()
        != plan.metadata.completed_data_indexes
    {
        return Err("byte diagnostic endpoints differ from unchanged SlotMeta".into());
    }
    let mut result = ByteDiagnostic {
        recorded_is_connected: plan.metadata.is_connected,
        data_shreds: shreds.len(),
        completed_batches: batches.len(),
        entries: 0,
        ticks: 0,
        transactions: 0,
        zero_work_entries: 0,
        claimed_hash_work: 0,
        last_entry_hash: [0; 32],
        final_entry_matches_finalized_hash: false,
        canonical_ancestry_proven: false,
        runtime_clock_authenticated: false,
        poh_chain_verified: false,
        publication_authorized: false,
    };
    for batch in batches {
        let decoded = decode_v1_4_25_padded_entries(&batch.bytes)?;
        for entry in decoded.entries {
            result.entries = result
                .entries
                .checked_add(1)
                .ok_or("entry count overflow")?;
            if result.entries > 262144 {
                return Err("aggregate byte diagnostic entry bound exceeded".into());
            }
            result.ticks += usize::from(entry.transaction_count == 0);
            result.transactions = result
                .transactions
                .checked_add(entry.transaction_count)
                .ok_or("transaction count overflow")?;
            result.zero_work_entries += usize::from(entry.num_hashes == 0);
            result.claimed_hash_work = result
                .claimed_hash_work
                .checked_add(entry.num_hashes)
                .ok_or("hash work overflow")?;
            if result.claimed_hash_work > 512000000 {
                return Err("aggregate claimed hash work exceeded".into());
            }
            result.last_entry_hash = entry.hash;
        }
    }
    if result.entries == 0 {
        return Err("empty byte diagnostic entry stream".into());
    }
    result.final_entry_matches_finalized_hash = result.last_entry_hash == finalized_final_hash;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        horizon_legacy_recovery::plan_v1_4_25_scope_queries,
        horizon_legacy_shred::{
            assemble_v1_4_25_slot_from_meta, decode_v1_4_25_complete_slot_meta,
        },
    };
    fn fixture() -> (LegacySlotScope, Vec<u8>, Vec<u8>) {
        let scope = LegacySlotScope {
            slot: 60911776,
            parent_slot: 60911771,
        };
        let meta = bincode::serialize(&(
            scope.slot,
            1u64,
            1u64,
            0u64,
            0u64,
            scope.parent_slot,
            Vec::<u64>::new(),
            false,
            vec![0u32],
        ))
        .unwrap();
        let bytes = bincode::serialize(&vec![(3u64, [7u8; 32], Vec::<u8>::new())]).unwrap();
        let mut shred = vec![0; 1228];
        shred[64] = 0xa5;
        shred[65..73].copy_from_slice(&scope.slot.to_le_bytes());
        shred[83..85].copy_from_slice(&5u16.to_le_bytes());
        shred[85] = 0xc0;
        shred[86..88].copy_from_slice(&((88 + bytes.len()) as u16).to_le_bytes());
        shred[88..88 + bytes.len()].copy_from_slice(&bytes);
        (scope, meta, shred)
    }
    fn run(
        meta: &[u8],
        shred: Option<&[u8]>,
        final_hash: [u8; 32],
    ) -> Result<ByteDiagnostic, String> {
        let scope = fixture().0;
        let key = scope.slot.to_be_bytes();
        let first = [ResolvedLegacyRecord {
            family: "meta",
            key: &key,
            value: Some(meta),
        }];
        let plan = plan_v1_4_25_acquisition_queries(&first, scope)?;
        let records: Vec<_> = plan
            .queries
            .iter()
            .enumerate()
            .map(|(i, q)| ResolvedLegacyRecord {
                family: q.family,
                key: &q.key,
                value: if i == 0 {
                    Some(meta)
                } else if i == 8 {
                    shred
                } else {
                    None
                },
            })
            .collect();
        assert!(plan_v1_4_25_scope_queries(&first, &[scope]).is_err());
        let result = diagnose_v1_4_25_acquired_bytes(&first, scope, &records, final_hash);
        assert!(plan_v1_4_25_scope_queries(&first, &[scope]).is_err());
        result
    }
    #[test]
    fn disconnected_byte_decode_never_changes_the_connected_gate_or_grants_poh() {
        let (scope, meta, shred) = fixture();
        let diagnostic = run(&meta, Some(&shred), [7; 32]).unwrap();
        assert!(!diagnostic.recorded_is_connected);
        assert_eq!(
            (
                diagnostic.entries,
                diagnostic.ticks,
                diagnostic.claimed_hash_work
            ),
            (1, 1, 3)
        );
        assert!(diagnostic.final_entry_matches_finalized_hash);
        assert!(
            !diagnostic.canonical_ancestry_proven
                && !diagnostic.runtime_clock_authenticated
                && !diagnostic.poh_chain_verified
                && !diagnostic.publication_authorized
        );
        let m = decode_v1_4_25_complete_slot_meta(&meta, scope.slot, scope.parent_slot).unwrap();
        assert!(!m.is_connected);
        assert!(assemble_v1_4_25_slot_from_meta(&m, &[&shred]).is_err());
    }
    #[test]
    fn wrong_final_hash_is_diagnostic_mismatch_not_a_fake_recovery() {
        let (_, meta, shred) = fixture();
        let d = run(&meta, Some(&shred), [8; 32]).unwrap();
        assert!(!d.final_entry_matches_finalized_hash && !d.poh_chain_verified);
    }
    #[test]
    fn missing_corrupt_headers_padding_and_metadata_are_rejected() {
        let (_, meta, shred) = fixture();
        assert!(run(&meta, None, [7; 32]).is_err());
        for (index, mask) in [(64, 1), (65, 1), (73, 1), (83, 1), (85, 0x80), (1000, 1)] {
            let mut changed = shred.clone();
            changed[index] ^= mask;
            assert!(run(&meta, Some(&changed), [7; 32]).is_err(), "{index}");
        }
        let mut trailing = meta;
        trailing.push(0);
        assert!(run(&trailing, Some(&shred), [7; 32]).is_err());
    }
}
