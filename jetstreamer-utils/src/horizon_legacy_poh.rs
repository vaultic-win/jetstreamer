//! Chained diagnostic PoH verification for the exact v1.4.25 entry semantics.
//! Trusted parent/final hashes and clock configuration are separate caller gates.
//! This does not prove source completeness, signatures or runtime qualification.

use {
    crate::horizon_legacy_entry::DiagnosticEntryBatch,
    sha2::{Digest, Sha256},
};

/// Independently authenticated scope, anchors and clock of one post-gap block.
#[derive(Clone, Debug)]
pub struct PohExpectation {
    /// Finalized parent slot before the gap.
    pub parent_slot: u64,
    /// Visible finalized block after the gap.
    pub slot: u64,
    /// Independently recorded parent's final PoH/block hash.
    pub parent_hash: [u8; 32],
    /// Independently recorded visible block's final PoH/block hash.
    pub final_hash: [u8; 32],
    /// Trusted runtime clock's ticks per slot, not inferred from input entries.
    pub ticks_per_slot: u64,
    /// Trusted nonzero runtime hashes per tick; disabled hashing is rejected.
    pub hashes_per_tick: u64,
}

/// One fully chained slot-ending tick, not a Bank hash.
#[derive(Debug, Eq, PartialEq)]
pub struct DiagnosticBoundary {
    /// Slot whose ending tick is represented.
    pub slot: u64,
    /// Tick ordinal relative to the independently anchored parent.
    pub tick_ordinal: u64,
    /// Verified PoH hash after this boundary's complete work.
    pub hash: [u8; 32],
}

/// Complete diagnostic chain result; it grants no source/runtime authority.
#[derive(Debug)]
pub struct DiagnosticPohChain {
    /// Every hidden boundary plus the visible block's final boundary, in order.
    pub boundaries: Vec<DiagnosticBoundary>,
    /// Exact executed SHA-256 calls, bounded before work starts.
    pub executed_hashes: u64,
    /// Always false: the caller still owes original source and native-state gates.
    pub source_completeness_proven: bool,
    /// Always false: no runtime checkpoint/plugin/publication gate is performed.
    pub publication_authorized: bool,
}

/// Verify every entry and tick from parent through all hidden/final boundaries.
///
/// Implements pinned `ledger::entry::next_hash` ordinary steps and signature-root
/// mixin, with exact per-tick work and complete final tick/anchor checks. A stricter
/// recovery profile rejects zero-work entries and disabled hashing. Work is bounded
/// before hashing; the guard runs before each entry and every 4096ordinary steps.
/// Caller must first authenticate complete ordered SlotMeta/shreds/batches and the
/// independent finalized anchors/clock. No partial chain is returned on failure.
pub fn verify_v1_4_25_poh_chain(
    batches: &[DiagnosticEntryBatch],
    expected: &PohExpectation,
    maximum_hashes: u64,
    mut guard: impl FnMut() -> Result<(), String>,
) -> Result<DiagnosticPohChain, String> {
    let span = expected
        .slot
        .checked_sub(expected.parent_slot)
        .filter(|n| (1..=64).contains(n))
        .ok_or("invalid PoH slot span")?;
    if !(1..=1024).contains(&expected.ticks_per_slot)
        || !(1..=1_000_000).contains(&expected.hashes_per_tick)
        || maximum_hashes == 0
        || maximum_hashes > 512_000_000
        || batches.is_empty()
        || batches.len() > 65_536
    {
        return Err("invalid PoH clock or work bounds".into());
    }
    let expected_ticks = span
        .checked_mul(expected.ticks_per_slot)
        .ok_or("tick count overflow")?;
    let expected_work = expected_ticks
        .checked_mul(expected.hashes_per_tick)
        .ok_or("PoH work overflow")?;
    if expected_work > maximum_hashes {
        return Err("PoH work bound exceeded".into());
    }
    let mut total_entries = 0usize;
    let mut total_work = 0u64;
    for batch in batches {
        if batch.entries.is_empty() {
            return Err("empty entry batch".into());
        }
        total_entries = total_entries
            .checked_add(batch.entries.len())
            .ok_or("entry count overflow")?;
        if total_entries > 262_144 {
            return Err("PoH entry bound exceeded".into());
        }
        for entry in &batch.entries {
            if entry.num_hashes == 0
                || (entry.transaction_count == 0) != entry.signature_mixin.is_none()
            {
                return Err("zero-work or inconsistent entry shape".into());
            }
            total_work = total_work
                .checked_add(entry.num_hashes)
                .ok_or("PoH work overflow")?;
            if total_work > maximum_hashes {
                return Err("PoH work bound exceeded".into());
            }
        }
    }
    if total_work != expected_work {
        return Err("complete-chain PoH work differs from clock scope".into());
    }
    guard()?;
    let mut current = expected.parent_hash;
    let mut tick_work = 0u64;
    let mut ticks = 0u64;
    let mut boundaries = Vec::with_capacity(span as usize);
    let mut seen = std::collections::BTreeSet::from([current]);
    for entry in batches.iter().flat_map(|b| &b.entries) {
        guard()?;
        if ticks == expected_ticks {
            return Err("entry follows final completion tick".into());
        }
        tick_work = tick_work
            .checked_add(entry.num_hashes)
            .ok_or("tick work overflow")?;
        let tick = entry.transaction_count == 0;
        if (tick && tick_work != expected.hashes_per_tick)
            || (!tick && tick_work >= expected.hashes_per_tick)
        {
            return Err("entry violates per-tick PoH work".into());
        }
        let ordinary = entry.num_hashes - u64::from(entry.signature_mixin.is_some());
        for round in 0..ordinary {
            if round % 4096 == 0 {
                guard()?;
            }
            current = Sha256::digest(current).into();
        }
        if let Some(mixin) = entry.signature_mixin {
            let mut hash = Sha256::new();
            hash.update(current);
            hash.update(mixin);
            current = hash.finalize().into();
        }
        if current != entry.hash {
            return Err("chained entry PoH hash mismatch".into());
        }
        if tick {
            tick_work = 0;
            ticks += 1;
            if ticks.is_multiple_of(expected.ticks_per_slot) {
                if !seen.insert(current) {
                    return Err("repeated PoH boundary hash".into());
                }
                boundaries.push(DiagnosticBoundary {
                    slot: expected
                        .parent_slot
                        .checked_add(ticks / expected.ticks_per_slot)
                        .ok_or("boundary slot overflow")?,
                    tick_ordinal: ticks,
                    hash: current,
                });
            }
        }
    }
    guard()?;
    if ticks != expected_ticks
        || tick_work != 0
        || current != expected.final_hash
        || boundaries.len() != span as usize
    {
        return Err("incomplete chain or canonical final anchor mismatch".into());
    }
    Ok(DiagnosticPohChain {
        boundaries,
        executed_hashes: total_work,
        source_completeness_proven: false,
        publication_authorized: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::horizon_legacy_entry::DiagnosticEntry;
    fn fixture() -> (Vec<DiagnosticEntryBatch>, PohExpectation) {
        let mut current = [9u8; 32];
        let mut entries = Vec::new();
        let mut hash = Sha256::new();
        hash.update(current);
        hash.update([4u8; 32]);
        current = hash.finalize().into();
        entries.push(DiagnosticEntry {
            num_hashes: 1,
            hash: current,
            transaction_count: 1,
            signature_mixin: Some([4; 32]),
        });
        for count in [2, 3, 3, 3, 3, 3] {
            for _ in 0..count {
                current = Sha256::digest(current).into();
            }
            entries.push(DiagnosticEntry {
                num_hashes: count,
                hash: current,
                transaction_count: 0,
                signature_mixin: None,
            });
        }
        let expectation = PohExpectation {
            parent_slot: 100,
            slot: 103,
            parent_hash: [9; 32],
            final_hash: current,
            ticks_per_slot: 2,
            hashes_per_tick: 3,
        };
        // The split is inside a tick: accumulated work must cross batch boundaries.
        let tail = entries.split_off(1);
        (
            vec![
                DiagnosticEntryBatch {
                    entries,
                    serialized_bytes: 0,
                },
                DiagnosticEntryBatch {
                    entries: tail,
                    serialized_bytes: 0,
                },
            ],
            expectation,
        )
    }
    #[test]
    fn chained_work_and_all_hidden_boundaries_cross_batch_boundaries() {
        let (batches, scope) = fixture();
        let result = verify_v1_4_25_poh_chain(&batches, &scope, 18, || Ok(())).unwrap();
        assert_eq!(result.executed_hashes, 18);
        // Independently generated by pinned v1.4.25 SDK hash/hashv, Rust 1.46.
        assert_eq!(
            result.boundaries.iter().map(|b| b.hash).collect::<Vec<_>>(),
            [
                [
                    186, 62, 46, 213, 28, 224, 26, 58, 205, 70, 6, 183, 66, 224, 75, 126, 78, 171,
                    32, 167, 85, 43, 182, 179, 110, 61, 7, 224, 41, 225, 193, 90
                ],
                [
                    24, 208, 161, 107, 134, 214, 1, 223, 4, 35, 36, 58, 30, 116, 224, 168, 59, 71,
                    231, 153, 112, 23, 245, 86, 216, 121, 31, 36, 176, 58, 65, 22
                ],
                [
                    58, 40, 67, 136, 158, 227, 136, 110, 69, 22, 232, 71, 238, 213, 223, 56, 55,
                    20, 78, 47, 7, 118, 245, 63, 122, 188, 207, 169, 9, 140, 123, 212
                ],
            ]
        );
        assert_eq!(
            result
                .boundaries
                .iter()
                .map(|b| (b.slot, b.tick_ordinal))
                .collect::<Vec<_>>(),
            [(101, 2), (102, 4), (103, 6)]
        );
        assert_eq!(result.boundaries.last().unwrap().hash, scope.final_hash);
        assert!(!result.source_completeness_proven && !result.publication_authorized);
    }
    #[test]
    fn rejects_mismatch_missing_reordered_extra_and_zero_work() {
        for variant in 0..6 {
            let (mut batches, mut scope) = fixture();
            match variant {
                0 => batches[1].entries[0].hash[0] ^= 1,
                1 => {
                    batches[1].entries.pop();
                }
                2 => batches[1].entries.swap(0, 1),
                3 => scope.final_hash[0] ^= 1,
                4 => batches[0].entries[0].num_hashes = 0,
                _ => batches[0].entries[0].signature_mixin = None,
            }
            assert!(verify_v1_4_25_poh_chain(&batches, &scope, 100, || Ok(())).is_err());
        }
    }
    #[test]
    fn bounds_and_runtime_guard_fail_without_a_partial_result() {
        let (batches, scope) = fixture();
        assert!(
            verify_v1_4_25_poh_chain(&batches, &scope, 17, || panic!(
                "work bound must precede hashing"
            ))
            .is_err()
        );
        assert!(
            verify_v1_4_25_poh_chain(&batches, &scope, 18, || Err("guard stopped".into())).is_err()
        );
        for (ticks, hashes) in [(0, 3), (2, 0), (2, 1_000_001), (1025, 3), (3, 3)] {
            let mut changed = scope.clone();
            changed.ticks_per_slot = ticks;
            changed.hashes_per_tick = hashes;
            assert!(verify_v1_4_25_poh_chain(&batches, &changed, 100, || Ok(())).is_err());
        }
        let mut bad = scope;
        bad.slot = u64::MAX;
        assert!(verify_v1_4_25_poh_chain(&batches, &bad, 100, || Ok(())).is_err());
    }

    #[test]
    fn rejects_extra_completion_entries_and_wrong_tick_phase() {
        let (mut batches, scope) = fixture();
        batches[1].entries.push(DiagnosticEntry {
            num_hashes: 1,
            hash: Sha256::digest(scope.final_hash).into(),
            transaction_count: 0,
            signature_mixin: None,
        });
        assert!(verify_v1_4_25_poh_chain(&batches, &scope, 100, || Ok(())).is_err());
        let (mut batches, scope) = fixture();
        batches[1].entries[0].num_hashes = 3;
        batches[1].entries.last_mut().unwrap().num_hashes = 2;
        assert!(
            verify_v1_4_25_poh_chain(&batches, &scope, 18, || Ok(()))
                .unwrap_err()
                .contains("per-tick")
        );
    }

    #[test]
    fn long_hash_work_checks_guard_inside_entry() {
        let parent = [5; 32];
        let mut hash = parent;
        for _ in 0..5000 {
            hash = Sha256::digest(hash).into();
        }
        let scope = PohExpectation {
            parent_slot: 1,
            slot: 2,
            parent_hash: parent,
            final_hash: hash,
            ticks_per_slot: 1,
            hashes_per_tick: 5000,
        };
        let batches = [DiagnosticEntryBatch {
            serialized_bytes: 0,
            entries: vec![DiagnosticEntry {
                num_hashes: 5000,
                hash,
                transaction_count: 0,
                signature_mixin: None,
            }],
        }];
        let mut calls = 0;
        assert!(
            verify_v1_4_25_poh_chain(&batches, &scope, 5000, || {
                calls += 1;
                if calls == 4 {
                    Err("in-entry guard stopped".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err()
            .contains("in-entry guard stopped")
        );
        assert_eq!(calls, 4);
    }

    #[test]
    fn complete_metadata_shreds_entry_decode_and_poh_chain_are_bound_together() {
        use crate::{
            horizon_legacy_entry::decode_v1_4_25_padded_entries,
            horizon_legacy_shred::{
                assemble_v1_4_25_slot_from_meta, decode_v1_4_25_complete_slot_meta,
            },
        };
        let metadata = bincode::serialize(&(
            103_u64,
            1_u64,
            1_u64,
            123_u64,
            0_u64,
            100_u64,
            Vec::<u64>::new(),
            true,
            vec![0_u32],
        ))
        .unwrap();
        let meta = decode_v1_4_25_complete_slot_meta(&metadata, 103, 100).unwrap();
        let mut entries = 6_u64.to_le_bytes().to_vec();
        let mut current = [9; 32];
        for _ in 0..6 {
            for _ in 0..3 {
                current = Sha256::digest(current).into();
            }
            entries.extend_from_slice(&3_u64.to_le_bytes());
            entries.extend_from_slice(&current);
            entries.extend_from_slice(&0_u64.to_le_bytes());
        }
        let scope = PohExpectation {
            parent_slot: 100,
            slot: 103,
            parent_hash: [9; 32],
            final_hash: current,
            ticks_per_slot: 2,
            hashes_per_tick: 3,
        };
        let mut shred = vec![0u8; 1228];
        shred[64] = 0xa5;
        shred[65..73].copy_from_slice(&103_u64.to_le_bytes());
        shred[77..79].copy_from_slice(&1234_u16.to_le_bytes());
        shred[83..85].copy_from_slice(&3_u16.to_le_bytes());
        shred[85] = 0xc0;
        shred[86..88].copy_from_slice(&((88 + entries.len()) as u16).to_le_bytes());
        shred[88..88 + entries.len()].copy_from_slice(&entries);
        for corrupt in [false, true] {
            let mut input = shred.clone();
            if corrupt {
                input[104] ^= 1;
            }
            let assembled = assemble_v1_4_25_slot_from_meta(&meta, &[input.as_slice()]).unwrap();
            let decoded: Vec<_> = assembled
                .iter()
                .map(|b| decode_v1_4_25_padded_entries(&b.bytes).unwrap())
                .collect();
            let result = verify_v1_4_25_poh_chain(&decoded, &scope, 18, || Ok(()));
            if corrupt {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().boundaries.len(), 3);
            }
        }
    }
}
