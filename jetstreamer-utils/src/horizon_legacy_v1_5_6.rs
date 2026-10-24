//! Diagnostic profile for Solana v1.5.6 revision
//! `01e4d0a1e9917701d1a148e1043b0ccf545c27f1`, not a runtime-route promotion.
//!
//! The pinned `entry.rs`, `blockstore_meta.rs` and Merkle implementation are
//! byte-identical to v1.4.25. The reviewed shred diff changes measurements,
//! derives and tests, not header layout, flags, data padding or deshredding.
//! Blockstore changes do not alter meta/data-shred keys. Reuse the bounded wire
//! implementation explicitly, rather than silently presenting v1.4.25 tooling
//! as v1.5.6 source qualification. This module does not authenticate a backup,
//! native logical values, signatures, finalized anchors, runtime clock or Bank.
//! It supplies no download, replay, canonical-root or publication authority.

use crate::{
    horizon_legacy_poh::{DiagnosticPohChain, PohExpectation},
    horizon_legacy_recovery::{
        LegacyLookup, LegacySlotScope, ResolvedLegacyRecord, plan_v1_4_25_scope_queries,
        recover_v1_4_25_records,
    },
};

/// Exact upstream revision audited for this diagnostic profile.
pub const UPSTREAM_REVISION: &str = "01e4d0a1e9917701d1a148e1043b0ccf545c27f1";

/// Plan exact meta rechecks and every contiguous data shred for v1.5.6.
///
/// Inputs must be independently native-resolved complete SlotMeta records.
/// All existing topology, key, count and byte bounds are preserved; no clock,
/// source completeness, PoH or runtime authority is implied by a query plan.
pub fn plan_scope_queries(
    first_metadata: &[ResolvedLegacyRecord<'_>],
    expected: &[LegacySlotScope],
) -> Result<Vec<LegacyLookup>, String> {
    plan_v1_4_25_scope_queries(first_metadata, expected)
}

/// Decode and verify complete v1.5.6 legacy target records under explicit bounds.
///
/// Reuses the reviewed identical wire/PoH semantics, including all metadata
/// rechecks, original padded shred data, entry order, aggregate hash-work limits,
/// independent parent/final anchors and unique hidden boundaries. A caller must
/// separately prove this runtime, the entire required execution-span census,
/// complete generation/native liveness and trusted clock. Results remain
/// diagnostic even when every supplied synthetic or real target passes.
pub fn recover_records(
    first_metadata: &[ResolvedLegacyRecord<'_>],
    records: &[ResolvedLegacyRecord<'_>],
    expected: &[PohExpectation],
    maximum_hashes: u64,
    guard: impl FnMut() -> Result<(), String>,
) -> Result<Vec<DiagnosticPohChain>, String> {
    recover_v1_4_25_records(first_metadata, records, expected, maximum_hashes, guard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    struct Fixture {
        scopes: Vec<PohExpectation>,
        meta_keys: Vec<Vec<u8>>,
        shred_keys: Vec<Vec<u8>>,
        metas: Vec<Vec<u8>>,
        shreds: Vec<Vec<u8>>,
    }
    impl Fixture {
        // Real five-gap topology, but deliberately SYNTHETIC hashes and clock.
        // This is not recovery of epoch 159's actual historical boundaries.
        fn new() -> Self {
            let mut f = Self {
                scopes: vec![],
                meta_keys: vec![],
                shred_keys: vec![],
                metas: vec![],
                shreds: vec![],
            };
            for (index, (parent, slot)) in [
                (68_687_895u64, 68_687_900u64),
                (68_687_903, 68_687_908),
                (68_687_927, 68_687_929),
                (68_687_975, 68_687_977),
                (68_687_979, 68_687_981),
            ]
            .into_iter()
            .enumerate()
            {
                let parent_hash = [index as u8 + 1; 32];
                let mut hash = parent_hash;
                let ticks = (slot - parent) * 2;
                let mut entries = ticks.to_le_bytes().to_vec();
                for _ in 0..ticks {
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
                shred[83..85].copy_from_slice(&((slot - parent) as u16).to_le_bytes());
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
                f.meta_keys.push(slot.to_be_bytes().to_vec());
                let mut key = slot.to_be_bytes().to_vec();
                key.extend_from_slice(&0u64.to_be_bytes());
                f.shred_keys.push(key);
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
            self.meta_keys
                .iter()
                .zip(&self.metas)
                .map(|(key, value)| ResolvedLegacyRecord {
                    family: "meta",
                    key,
                    value: Some(value),
                })
                .collect()
        }
        fn records(&self) -> Vec<ResolvedLegacyRecord<'_>> {
            (0..self.scopes.len())
                .flat_map(|i| {
                    [
                        ResolvedLegacyRecord {
                            family: "meta",
                            key: &self.meta_keys[i],
                            value: Some(&self.metas[i]),
                        },
                        ResolvedLegacyRecord {
                            family: "data_shred",
                            key: &self.shred_keys[i],
                            value: Some(&self.shreds[i]),
                        },
                    ]
                })
                .collect()
        }
    }
    #[test]
    fn five_gap_topology_preserves_all_sixteen_diagnostic_boundaries() {
        let f = Fixture::new();
        let scopes: Vec<_> = f
            .scopes
            .iter()
            .map(|s| LegacySlotScope {
                slot: s.slot,
                parent_slot: s.parent_slot,
            })
            .collect();
        assert_eq!(
            plan_scope_queries(&f.metadata(), &scopes).unwrap().len(),
            10
        );
        let result =
            recover_records(&f.metadata(), &f.records(), &f.scopes, 96, || Ok(())).unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result.iter().map(|r| r.boundaries.len()).sum::<usize>(), 16);
        assert_eq!(result.iter().map(|r| r.executed_hashes).sum::<u64>(), 96);
        assert!(
            result
                .iter()
                .all(|r| !r.source_completeness_proven && !r.publication_authorized)
        );
        assert!(recover_records(&f.metadata(), &f.records(), &f.scopes, 95, || Ok(())).is_err());
    }
    #[test]
    fn source_scope_missing_records_rechecks_and_guards_remain_fail_closed() {
        let f = Fixture::new();
        let metas = f.metadata();
        let records = f.records();
        assert!(recover_records(&metas[..4], &records, &f.scopes, 96, || Ok(())).is_err());
        for index in 0..records.len() {
            let mut changed = records.clone();
            changed[index].value = None;
            assert!(recover_records(&metas, &changed, &f.scopes, 96, || Ok(())).is_err());
        }
        let mut changed = records.clone();
        changed.swap(0, 1);
        assert!(recover_records(&metas, &changed, &f.scopes, 96, || Ok(())).is_err());
        let mut changed = records.clone();
        changed[1].family = "code_shred";
        assert!(recover_records(&metas, &changed, &f.scopes, 96, || Ok(())).is_err());
        assert!(recover_records(&metas, &records, &f.scopes, 96, || Err("guard".into())).is_err());
        let mut scopes = f.scopes.clone();
        scopes[0].final_hash = [0; 32];
        assert!(recover_records(&metas, &records, &scopes, 96, || Ok(())).is_err());
        let mut other_meta = f.metas[0].clone();
        other_meta[24] ^= 1; // timestamp, still parseable
        let mut changed = records.clone();
        changed[0].value = Some(&other_meta);
        assert!(recover_records(&metas, &changed, &f.scopes, 96, || Ok(())).is_err());
    }
    #[test]
    #[ignore = "requires exact locally retained v1.5.6 upstream checkout; no archive or native database access"]
    fn pinned_upstream_sources_match_reviewed_wire_semantics() {
        let root = std::path::PathBuf::from(
            std::env::var("HORIZON_V156_UPSTREAM").expect("exact upstream checkout required"),
        );
        let output = std::process::Command::new("git")
            .args(["-C", root.to_str().unwrap(), "rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            UPSTREAM_REVISION
        );
        for (path, expected) in [
            (
                "ledger/src/shred.rs",
                "c2380f2dc80c3153dbaea44a1f63f0dd1c80857d93647612f173ab518d16c379",
            ),
            (
                "ledger/src/blockstore_meta.rs",
                "25e29134699e586f626a56b79e507c4e0b1e92b21d47684841cdd727abc80ba7",
            ),
            (
                "ledger/src/entry.rs",
                "8ba2b21314b85f709dc9b398705ce340250e1419ab13f4e5a7dd5f44322d711f",
            ),
            (
                "merkle-tree/src/merkle_tree.rs",
                "055a9d96aa098f58dcfd83de6f0ddc8c8aeb08a93dab1c9b1e28a44a2225a6b0",
            ),
            (
                "ledger/src/blockstore_db.rs",
                "e80730c8b609460e9360badcd409e9c4bf636d91146bae3bdc4e144508411e4f",
            ),
            (
                "sdk/src/transaction.rs",
                "712b6c179fc4b61572403bc55b38c52018cedc87a4601588e706e8ce1e73d096",
            ),
            (
                "sdk/program/src/message.rs",
                "6d64aea55a0d9a52950a82e0506772c53c364a8b33e89d36c016173a59572ef6",
            ),
        ] {
            assert_eq!(
                format!(
                    "{:x}",
                    Sha256::digest(std::fs::read(root.join(path)).unwrap())
                ),
                expected,
                "{path}"
            );
        }
    }
}
