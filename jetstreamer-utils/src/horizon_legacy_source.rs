//! Qualification-only original-entry/source-transaction binding for v1.4.25.
//! Callers independently authenticate the complete shred census, source block,
//! transaction order, finalized anchors and clock. Matching bytes and PoH do not
//! establish native live-state completeness, signatures, a Bank root or publication.

use crate::{
    horizon_legacy_entry::{
        DiagnosticEntry, DiagnosticEntryBatch, decode_v1_4_25_padded_wire_entries,
    },
    horizon_legacy_poh::{DiagnosticPohChain, PohExpectation, verify_v1_4_25_poh_chain},
};

const MAX_SLOT_BYTES: usize = 64 << 20;
const MAX_SLOT_ENTRIES: usize = 262_144;
const MAX_SLOT_TRANSACTIONS: usize = 65_536;

/// One original entry with an exact mapping into independent source metadata.
#[derive(Debug)]
pub struct DiagnosticSourceEntry<'a> {
    /// Global original-entry index across all assembled batches, including ticks.
    pub entry_index: usize,
    /// First index in the source block's transaction sequence; ticks consume none.
    pub transaction_start_index: usize,
    /// Original entry hash/work and independently decoded signature mixin.
    pub metadata: DiagnosticEntry,
    /// Original bincode bytes, never synthesized, normalized or reordered.
    pub transactions: Vec<&'a [u8]>,
}

/// Complete candidate mapping; not permission to execute or publish it.
#[derive(Debug)]
pub struct DiagnosticSourceSlot<'a> {
    /// Entries in original batch/entry order.
    pub entries: Vec<DiagnosticSourceEntry<'a>>,
    /// Exact number of transactions compared byte-for-byte with the source block.
    pub matched_transactions: usize,
    /// Full original PoH verification, including every hidden boundary.
    pub poh: DiagnosticPohChain,
}

/// Bind every original transaction to its source index, then verify full PoH.
///
/// `padded_batches` must be complete and ordered by the independently checked
/// SlotMeta/shred endpoints. `source_transactions` must be a separately obtained
/// complete transaction sequence for `expected.slot`, not a copy derived from
/// these same batches. The caller must also bind the source's finalized parent
/// and final hash to `expected`. Every mismatch fails before returning any entry;
/// this function never mutates a Bank, recorder, source metadata or remote object.
pub fn bind_v1_4_25_source_entries<'a>(
    padded_batches: &[&'a [u8]],
    source_transactions: &[&[u8]],
    expected: &PohExpectation,
    maximum_hashes: u64,
    mut guard: impl FnMut() -> Result<(), String>,
) -> Result<DiagnosticSourceSlot<'a>, String> {
    if padded_batches.is_empty()
        || padded_batches.len() > 65_536
        || source_transactions.len() > MAX_SLOT_TRANSACTIONS
    {
        return Err("original source binding count bound exceeded".into());
    }
    let total_bytes = padded_batches.iter().try_fold(0usize, |total, batch| {
        total
            .checked_add(batch.len())
            .filter(|n| *n <= MAX_SLOT_BYTES)
    });
    if total_bytes.is_none() {
        return Err("original source binding byte bound exceeded".into());
    }
    let mut entries = Vec::new();
    let mut metadata_batches = Vec::new();
    let mut source_index = 0usize;
    for bytes in padded_batches {
        guard()?;
        let decoded = decode_v1_4_25_padded_wire_entries(bytes)?;
        if entries.len().saturating_add(decoded.entries.len()) > MAX_SLOT_ENTRIES {
            return Err("original source binding entry bound exceeded".into());
        }
        let mut metadata = Vec::with_capacity(decoded.entries.len());
        for entry in decoded.entries {
            guard()?;
            let start = source_index;
            for original in &entry.transactions {
                let source = source_transactions
                    .get(source_index)
                    .ok_or("original entries contain an extra source transaction")?;
                if original != source {
                    return Err(format!(
                        "original/source transaction differs at index {source_index}"
                    ));
                }
                source_index += 1;
            }
            metadata.push(entry.metadata.clone());
            entries.push(DiagnosticSourceEntry {
                entry_index: entries.len(),
                transaction_start_index: start,
                metadata: entry.metadata,
                transactions: entry.transactions,
            });
        }
        metadata_batches.push(DiagnosticEntryBatch {
            entries: metadata,
            serialized_bytes: decoded.serialized_bytes,
        });
    }
    if source_index != source_transactions.len() {
        return Err("original entries omit source transactions".into());
    }
    let poh = verify_v1_4_25_poh_chain(&metadata_batches, expected, maximum_hashes, &mut guard)?;
    Ok(DiagnosticSourceSlot {
        entries,
        matched_transactions: source_index,
        poh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn transaction(signature: u8) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&[signature; 64]);
        bytes.extend_from_slice(&[1, 0, 0, 1]);
        bytes.extend_from_slice(&[42; 32]);
        bytes.extend_from_slice(&[43; 32]);
        bytes.push(0);
        bytes
    }

    fn batch(hash: [u8; 32], transactions: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = 1u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(&(transactions.len() as u64).to_le_bytes());
        for tx in transactions {
            bytes.extend_from_slice(tx);
        }
        bytes.resize(bytes.len() + 5, 0);
        bytes
    }

    fn fixture() -> (Vec<Vec<u8>>, Vec<Vec<u8>>, PohExpectation) {
        let transactions = vec![transaction(1), transaction(2)];
        let mut current = [9; 32];
        let mut batches = Vec::new();
        for (index, tx) in transactions.iter().enumerate() {
            let leaf = Sha256::digest([vec![0], vec![index as u8 + 1; 64]].concat());
            current = Sha256::digest([current.as_slice(), leaf.as_slice()].concat()).into();
            batches.push(batch(current, std::slice::from_ref(tx)));
            current = Sha256::digest(current).into();
            batches.push(batch(current, &[]));
        }
        let expected = PohExpectation {
            parent_slot: 100,
            slot: 102,
            parent_hash: [9; 32],
            final_hash: current,
            ticks_per_slot: 1,
            hashes_per_tick: 2,
        };
        (batches, transactions, expected)
    }

    #[test]
    fn exact_source_sequence_keeps_all_ticks_hashes_and_metadata_indexes() {
        let (batches, source, expected) = fixture();
        let batches: Vec<_> = batches.iter().map(Vec::as_slice).collect();
        let source: Vec<_> = source.iter().map(Vec::as_slice).collect();
        let result =
            bind_v1_4_25_source_entries(&batches, &source, &expected, 4, || Ok(())).unwrap();
        assert_eq!(result.matched_transactions, 2);
        assert_eq!(result.poh.boundaries.len(), 2);
        assert!(!result.poh.source_completeness_proven);
        assert!(!result.poh.publication_authorized);
        let indexes: Vec<_> = result
            .entries
            .iter()
            .map(|e| {
                (
                    e.entry_index,
                    e.transaction_start_index,
                    e.transactions.len(),
                )
            })
            .collect();
        assert_eq!(indexes, [(0, 0, 1), (1, 1, 0), (2, 1, 1), (3, 2, 0)]);
        assert_eq!(result.entries[0].transactions, vec![source[0]]);
        assert_eq!(result.entries[2].transactions, vec![source[1]]);
    }

    #[test]
    fn missing_extra_reordered_or_changed_source_transactions_fail_closed() {
        let (batches, source, expected) = fixture();
        let batches: Vec<_> = batches.iter().map(Vec::as_slice).collect();
        let mut changed = source[0].clone();
        changed[5] ^= 1;
        for source in [
            vec![source[0].as_slice()],
            vec![
                source[0].as_slice(),
                source[1].as_slice(),
                source[0].as_slice(),
            ],
            vec![source[1].as_slice(), source[0].as_slice()],
            vec![changed.as_slice(), source[1].as_slice()],
        ] {
            assert!(
                bind_v1_4_25_source_entries(&batches, &source, &expected, 4, || Ok(())).is_err()
            );
        }
    }

    #[test]
    fn anchors_order_work_and_guard_remain_independent_required_gates() {
        let (batches, source, expected) = fixture();
        let mut batches: Vec<_> = batches.iter().map(Vec::as_slice).collect();
        let source: Vec<_> = source.iter().map(Vec::as_slice).collect();
        for wrong in [
            PohExpectation {
                parent_hash: [0; 32],
                ..expected.clone()
            },
            PohExpectation {
                final_hash: [0; 32],
                ..expected.clone()
            },
            PohExpectation {
                parent_slot: 99,
                ..expected.clone()
            },
        ] {
            assert!(bind_v1_4_25_source_entries(&batches, &source, &wrong, 8, || Ok(())).is_err());
        }
        assert!(bind_v1_4_25_source_entries(&batches, &source, &expected, 3, || Ok(())).is_err());
        assert!(
            bind_v1_4_25_source_entries(&batches, &source, &expected, 4, || Err("stopped".into()))
                .is_err()
        );
        batches.swap(1, 3); // Transaction order still matches; tick hashes do not.
        assert!(bind_v1_4_25_source_entries(&batches, &source, &expected, 4, || Ok(())).is_err());
    }

    #[test]
    fn aggregate_bounds_and_nonzero_padding_are_not_bypassed() {
        let (mut batches, source, expected) = fixture();
        let source: Vec<_> = source.iter().map(Vec::as_slice).collect();
        *batches[0].last_mut().unwrap() = 1;
        let batches: Vec<_> = batches.iter().map(Vec::as_slice).collect();
        assert!(bind_v1_4_25_source_entries(&batches, &source, &expected, 4, || Ok(())).is_err());
        assert!(bind_v1_4_25_source_entries(&[], &source, &expected, 4, || Ok(())).is_err());
        let too_many = vec![&[][..]; MAX_SLOT_TRANSACTIONS + 1];
        assert!(bind_v1_4_25_source_entries(&batches, &too_many, &expected, 4, || Ok(())).is_err());
        let chunk = [0u8; 2048];
        let too_large = vec![chunk.as_slice(); MAX_SLOT_BYTES / chunk.len() + 1];
        assert_eq!(
            bind_v1_4_25_source_entries(&too_large, &source, &expected, 4, || Ok(())).unwrap_err(),
            "original source binding byte bound exceeded"
        );
    }
}
