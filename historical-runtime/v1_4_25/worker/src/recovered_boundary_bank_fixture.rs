//! Version-specific Bank semantics only: no runtime input or replay authority.
//! The first epoch 141 recovered group is 60911776 <- 60911771 (five boundaries).
use crate::snapshot;
use solana_runtime::{bank::Bank, genesis_utils::create_genesis_config_with_leader};
use solana_sdk::{
    account::from_account,
    hash::{hashv, Hash},
    pubkey::Pubkey,
    sysvar::{slot_hashes, slot_hashes::SlotHashes},
};
use std::{collections::HashSet, str::FromStr, sync::Arc};

#[test]
fn pinned_bank_gap_boundaries_preserve_queue_root_and_slot_hashes() {
    let hashes: Vec<Hash> = [
        "4D13FksJYTUtKqkpuEmza1r5ouUeKqmLxnfbcNSu5pVx",
        "3PdYtB7QRbZASiDqoqNCr1GCJxjEMsKDHwUBn9CJffoh",
        "3yxwA6WMTRFXbN5amSZcn7cTPNrTvAnYabdzP57phHZr",
        "4sWkCEENvfcZRCMVW8TgHW2br3ecifbe2NGZsiucnpjt",
        "AEzkqdJNmLFiB4bA52NvYYY4TRfYsB81Y13JT7aW4tgS",
    ]
    .iter()
    .map(|h| Hash::from_str(h).unwrap())
    .collect();
    assert_eq!(hashes.iter().collect::<HashSet<_>>().len(), 5);
    let leader = Pubkey::new_from_array([7; 32]);
    let genesis = create_genesis_config_with_leader(1_000_000, &leader, 500_000);
    let mut roots = Vec::new();
    let mut child_slot_hashes = Vec::new();
    for mode in 0..3 {
        let state_dir = snapshot::private_state_dir(None).unwrap();
        let paths = snapshot::private_account_paths(&state_dir).unwrap();
        let parent = Arc::new(Bank::new_with_paths(
            &genesis.genesis_config,
            paths,
            &[],
            None,
            None,
            HashSet::new(),
        ));
        assert_eq!(parent.ticks_per_slot(), 64);
        let initial = parent.last_blockhash();
        for _ in 0..64 {
            parent.register_tick(&initial);
        }
        parent.freeze();
        // Normalize the real five-slot jump to small slots. This tests Bank's
        // tick/queue semantics, not the epoch 141 snapshot or feature schedule.
        let gap = Arc::new(Bank::new_from_parent(&parent, &leader, 5));
        assert_eq!(gap.tick_height(), 64);
        assert_eq!(gap.max_tick_height(), 384);
        for (boundary_index, boundary) in hashes.iter().enumerate() {
            for tick in 0u64..64 {
                let value = if mode == 2 {
                    *hashes.last().unwrap()
                } else if mode == 1 && tick != 63 {
                    hashv(&[boundary.as_ref(), &tick.to_le_bytes()])
                } else {
                    *boundary
                };
                gap.register_tick(&value);
            }
            assert_eq!(gap.tick_height(), 64 * (boundary_index as u64 + 2));
        }
        assert!(gap.is_complete());
        assert_eq!(gap.last_blockhash(), *hashes.last().unwrap());
        for hidden in &hashes[..4] {
            assert_eq!(gap.get_fee_calculator(hidden).is_some(), mode != 2);
        }
        gap.freeze();
        roots.push(gap.hash());
        let child = Bank::new_from_parent(&gap, &leader, 6);
        let slot_hashes: SlotHashes =
            from_account(&child.get_account(&slot_hashes::id()).unwrap()).unwrap();
        assert!(slot_hashes
            .iter()
            .any(|(slot, hash)| *slot == 5 && *hash == gap.hash()));
        child_slot_hashes.push(slot_hashes);
        // Drop account-owning banks before their private paths are removed.
        drop(child);
        drop(gap);
        drop(parent);
        drop(state_dir);
    }
    assert_eq!(
        roots[0], roots[1],
        "non-boundary tick hashes must not change Bank state"
    );
    assert_eq!(child_slot_hashes[0], child_slot_hashes[1]);
    assert_ne!(
        roots[0], roots[2],
        "repeating the final hash loses hidden queue entries"
    );
    assert_ne!(child_slot_hashes[0], child_slot_hashes[2]);
}
