// Source-only candidate checks. No snapshot restore or historical execution.
use super::*;
use solana_runtime::{accounts::Accounts, accounts_index::AccountSecondaryIndexes};
use solana_sdk::{genesis_config::ClusterType, message::Message};

fn exact_parent() -> Transaction {
    bincode::deserialize(include_bytes!(
        "../../../fixtures/epoch223-parent96544587-tx432.bin"
    ))
    .unwrap()
}

#[test]
fn exact_wire_lock_attribution_and_instruction_metadata_agree() {
    let tx = exact_parent();
    tx.verify().unwrap();
    assert_eq!(
        bincode::serialize(&tx).unwrap().as_slice(),
        &include_bytes!("../../../fixtures/epoch223-parent96544587-tx432.bin")[..]
    );
    let token = tx.message.account_keys[3];
    let expected = !cfg!(feature = "epoch223-called-program-demotion");
    for demote_sysvars in &[false, true] {
        assert_eq!(tx.message.is_writable(3, *demote_sysvars), expected);
        let (writable, readonly) = tx.message.get_account_keys_by_lock_type(*demote_sysvars);
        assert_eq!(writable.contains(&&token), expected);
        assert_eq!(readonly.contains(&&token), !expected);
        let attribution = writable_key_attribution(&[tx.clone()], *demote_sysvars).unwrap();
        assert_eq!(attribution.contains_key(token.as_ref()), expected);
        let bytes = tx.message.serialize_instructions(*demote_sysvars);
        let raydium = Message::deserialize_instruction(4, &bytes).unwrap();
        let token_meta = raydium
            .accounts
            .iter()
            .find(|meta| meta.pubkey == token)
            .unwrap();
        assert_eq!(token_meta.is_writable, expected);
    }
}

#[test]
fn native_lock_manager_uses_the_same_direct_program_policy() {
    let first = exact_parent();
    let mut second = first.clone();
    // Synthetic lock-only case: share only Token, keeping the exact original
    // header/instruction indexes. These changed signatures are not executed.
    for (index, key) in second.message.account_keys.iter_mut().enumerate() {
        if index != 3 {
            *key = Pubkey::new_unique();
        }
    }
    let accounts = Accounts::new_with_config(
        Vec::new(),
        &ClusterType::Development,
        AccountSecondaryIndexes::default(),
        false,
    );
    let txs = vec![first, second];
    let outcomes = accounts.lock_accounts(txs.iter(), true);
    assert!(outcomes[0].is_ok());
    if cfg!(feature = "epoch223-called-program-demotion") {
        assert!(outcomes[1].is_ok());
    } else {
        assert_eq!(outcomes[1], Err(TransactionError::AccountInUse));
    }
    accounts.unlock_accounts(txs.iter(), &outcomes, true);
    let retry = accounts.lock_accounts(txs[..1].iter(), true);
    assert!(retry[0].is_ok());
    accounts.unlock_accounts(txs[..1].iter(), &retry, true);
}

#[test]
fn passed_only_program_and_sysvar_flag_keep_original_semantics() {
    let mut tx = exact_parent();
    let expected = !cfg!(feature = "epoch223-called-program-demotion");
    assert_eq!(tx.message.is_writable(3, false), expected);
    tx.message
        .instructions
        .retain(|instruction| instruction.program_id_index != 3);
    assert!(tx.message.is_key_passed_to_program(3));
    assert!(tx.message.is_writable(3, false));
    assert!(tx.message.is_writable(3, true));
    tx.message.account_keys[3] = solana_sdk::sysvar::clock::id();
    assert!(tx.message.is_writable(3, false));
    assert!(!tx.message.is_writable(3, true));
    // Header-readonly keys stay readonly regardless of the private policy.
    assert!(!tx.message.is_writable(16, false));
    assert!(!tx.message.is_writable(16, true));
}

#[test]
fn canonical_hash_gate_compares_instead_of_substituting() {
    assert!(validate_epoch223_repair_bank_hash(
        96_544_586,
        "3PMZX37CYLF9Ay87r1aKREnf1cZoWDLRKXRAMx5TZYso"
    )
    .is_ok());
    assert!(validate_epoch223_repair_bank_hash(
        96_544_587,
        "5UsE976GhKUXyUyKG1tUDiN7cT2BPYvKJN7Wx1ptJHm7"
    )
    .is_ok());
    assert!(validate_epoch223_repair_bank_hash(
        96_544_587,
        "GRD2nwB5ADKJNu3oiKJibJysRLpMNw3aSkA4NhpKoHxX"
    )
    .is_err());
    assert!(validate_epoch223_repair_bank_hash(
        96_544_587,
        "BrifEBcMmiHTBhqcgwhNcFSErZn6cd12BmXjVxboeUV5"
    )
    .is_err());
}
