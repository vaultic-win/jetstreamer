// Exact wire fixtures with synthetic account values. This tests store/hash
// semantics without executing the Raydium transaction, restoring a snapshot,
// reproducing mainnet Bank state, or granting runtime/publication authority.
use solana_runtime::{bank::Bank, genesis_utils::create_genesis_config};
use solana_sdk::{account::WritableAccount, system_program};
use std::sync::Arc;

const PARENT432_WIRE: &[u8] = include_bytes!("epoch223-parent96544587-tx432.bin");
const FAILING_VOTE_WIRE: &[u8] = include_bytes!("epoch223-failing96544588-vote.bin");

#[test]
fn exact_epoch223_parent432_fixture_has_called_and_passed_token_program() {
    let tx: Transaction = bincode::deserialize(PARENT432_WIRE).unwrap();
    assert_eq!(tx.signatures.len(), 3);
    assert_eq!(
        tx.signatures[0].to_string(),
        "358YDY6TSXgU4X8Q1UzjPRrYTzBCz8CKE9tbS5neXZYWNPuo2bvWrcmji1RiWS8mbvokPxS5vF1TMP3Htymyruj8"
    );
    assert_eq!(tx.message.account_keys.len(), 17);
    assert_eq!(tx.message.header.num_required_signatures, 3);
    assert_eq!(tx.message.header.num_readonly_signed_accounts, 0);
    assert_eq!(tx.message.header.num_readonly_unsigned_accounts, 4);
    let program = tx.message.account_keys[3];
    assert_eq!(
        program.to_string(),
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    );
    let direct: Vec<_> = tx
        .message
        .instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction)| instruction.program_id_index == 3)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(direct, vec![1, 3, 5]);
    assert!(tx.message.instructions[4].accounts.contains(&3));
    assert!(tx.message.is_key_passed_to_program(3));
    assert!(tx.message.is_non_loader_key(&program, 3));
}

#[test]
fn exact_epoch223_failed_signature_is_vote_for_canonical_parent_hash() {
    use solana_vote_program::vote_instruction::VoteInstruction;
    let tx: Transaction = bincode::deserialize(FAILING_VOTE_WIRE).unwrap();
    assert_eq!(
        tx.signatures[0].to_string(),
        "4P2u3JnCkqkaDMG4TC4o2mLVckYmt3MCYzdUvNpTu7RAz3kTfVyPrRzVnchncRpTdBv8nsrCJX9kxVXiAmUxrNtD"
    );
    assert_eq!(tx.message.instructions.len(), 1);
    let instruction = &tx.message.instructions[0];
    assert_eq!(
        tx.message.account_keys[instruction.program_id_index as usize],
        solana_vote_program::id(),
    );
    match bincode::deserialize::<VoteInstruction>(&instruction.data).unwrap() {
        VoteInstruction::Vote(vote) => {
            assert_eq!(vote.slots, vec![96_544_586, 96_544_587]);
            assert_eq!(
                vote.hash.to_string(),
                "5UsE976GhKUXyUyKG1tUDiN7cT2BPYvKJN7Wx1ptJHm7"
            );
        }
        other => panic!("unexpected actual wire instruction: {:?}", other),
    }
}

#[test]
fn exact_parent432_store_selection_changes_slot_delta_and_frozen_bank_hash() {
    let tx: Transaction = bincode::deserialize(PARENT432_WIRE).unwrap();
    let program = tx.message.account_keys[3];
    let synthetic_values: Vec<_> = tx
        .message
        .account_keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let mut account =
                AccountSharedData::new(1_000_000 + index as u64, 16, &system_program::id());
            // Avoid the created-account rent branch: this test isolates the
            // dirty-key contribution, not an unobserved historical rent value.
            account.set_rent_epoch(1);
            if index == 3 {
                account.set_lamports(1_089_991_680);
                account.set_owner(solana_sdk::bpf_loader::id());
                account.set_executable(true);
            }
            (*key, account)
        })
        .collect();
    let mut loaded = vec![(
        Ok(LoadedTransaction {
            accounts: synthetic_values
                .iter()
                .map(|(_, account)| account.clone())
                .collect(),
            account_deps: vec![],
            loaders: vec![],
            rent: 0,
            rent_debits: RentDebits::default(),
        }),
        None,
    )];
    let accounts = Accounts::new_with_config(
        Vec::new(),
        &ClusterType::Development,
        AccountSecondaryIndexes::default(),
        false,
    );
    // Success is the supplied finalized execution result. We are exercising
    // account collection, not claiming execution of this transaction here.
    let collected = store_parent432_for_this_runtime(&accounts, &[tx], &mut loaded);
    assert_eq!(
        collected.iter().any(|(key, _)| *key == program),
        EXPECT_PROGRAM_STORED
    );
    let mut actual_keys: Vec<_> = collected.iter().map(|(key, _)| *key).collect();
    actual_keys.sort();
    let mut expected_keys: Vec<_> = synthetic_values[..13]
        .iter()
        .filter(|(key, _)| EXPECT_PROGRAM_STORED || *key != program)
        .map(|(key, _)| *key)
        .collect();
    expected_keys.sort();
    assert_eq!(actual_keys, expected_keys);

    let mut genesis = create_genesis_config(10_000_000).genesis_config;
    for (key, account) in &synthetic_values {
        genesis.accounts.insert(*key, account.clone().into());
    }
    let collector = synthetic_values[0].0;
    let parent_a = Arc::new(Bank::new(&genesis));
    let parent_b = Arc::new(Bank::new(&genesis));
    parent_a.freeze();
    parent_b.freeze();
    assert_eq!(parent_a.hash(), parent_b.hash());
    let without_program = Bank::new_from_parent(&parent_a, &collector, 1);
    let with_program = Bank::new_from_parent(&parent_b, &collector, 1);
    for (key, account) in &collected {
        if *key != program {
            without_program.store_account(key, account);
            with_program.store_account(key, account);
        }
    }
    let unchanged_program = synthetic_values[3].1.clone();
    assert_eq!(
        with_program.get_account(&program).unwrap(),
        unchanged_program
    );
    with_program.store_account(&program, &unchanged_program);
    // This is an unchanged program value; only its membership in slot 1's
    // dirty account set differs between the two otherwise identical branches.
    assert_eq!(
        without_program.get_account(&program),
        with_program.get_account(&program)
    );
    for (key, _) in &synthetic_values {
        assert_eq!(
            without_program.get_account(key),
            with_program.get_account(key)
        );
    }
    assert_ne!(
        without_program.rc.accounts.bank_hash_at(1),
        with_program.rc.accounts.bank_hash_at(1),
    );
    without_program.freeze();
    with_program.freeze();
    assert_eq!(
        without_program.last_blockhash(),
        with_program.last_blockhash()
    );
    assert_eq!(
        without_program.signature_count(),
        with_program.signature_count()
    );
    assert_ne!(without_program.hash(), with_program.hash());
}
