use super::writable_key_attribution;
use sha2::{Digest, Sha256};
use solana_runtime::{bank::Bank, genesis_utils::create_genesis_config_with_leader};
use solana_sdk::{
    bpf_loader_upgradeable,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

const WIRE: &[u8] = include_bytes!("../../../fixtures/epoch230-99368201-tx680.bin");
const RESPONSE: &str = include_str!("../../../fixtures/epoch230-99368201-tx680.finalized.json");
const PROGRAM_INDEX: usize = 8;
const WRITABLE_ACCOUNT_INDEX: usize = 6;

#[test]
fn epoch229_signed_transaction_demotes_only_the_invoked_program_when_active() {
    const WIRE: &[u8] = include_bytes!("../../../fixtures/epoch229-98931633-tx1764.bin");
    const PROGRAM_INDEX: usize = 3;
    let mut digest = Sha256::new();
    digest.input(WIRE);
    assert_eq!(
        format!("{:x}", digest.result()),
        "010b618395a83fe9dfaf6dd5b420e783485e55f43b8622efe3cc6d49741f6329"
    );
    let tx: Transaction = bincode::deserialize(WIRE).unwrap();
    tx.verify().unwrap();
    assert_eq!(bincode::serialize(&tx).unwrap().as_slice(), WIRE);
    assert_eq!(
        tx.signatures[0].to_string(),
        "uS2Dba6JbiNK78LJm6BdqAfuzKbKCug6fRq7K3uGJNWzfzi2uWpXQMYZyUTNeGFmpCFnBznaYwWCrMKkDk5njeF"
    );
    let message = &tx.message;
    let program = message.account_keys[PROGRAM_INDEX];
    assert_eq!(
        program.to_string(),
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    );
    assert!(message.instructions.iter().any(|instruction| {
        usize::from(instruction.program_id_index) == PROGRAM_INDEX
    }));
    assert!(message.instructions.iter().any(|instruction| {
        instruction.accounts.contains(&(PROGRAM_INDEX as u8))
    }));
    assert!(!message.account_keys.contains(&bpf_loader_upgradeable::id()));

    for &active in &[false, true] {
        let program_writable = !(cfg!(feature = "epoch228-called-program-demotion")
            || (crate::ACTIVATION_GATED_PROGRAM_DEMOTION && active));
        assert_eq!(message.is_writable(PROGRAM_INDEX, active), program_writable);
        let writes = writable_key_attribution(std::slice::from_ref(&tx), active).unwrap();
        assert_eq!(writes.contains_key(program.as_ref()), program_writable);
        assert!(writes.contains_key(message.account_keys[0].as_ref()));
    }
}

#[test]
fn preceding_bank_transaction_preserves_only_the_writable_non_program_keys() {
    const WIRE: &[u8] = include_bytes!("../../../fixtures/epoch230-99435889-tx1618.bin");
    let mut digest = Sha256::new();
    digest.input(WIRE);
    assert_eq!(
        format!("{:x}", digest.result()),
        "9572c35a33dfa7eadfdf69f2611f1574aa24075e22290740896590cbf3ffe4ff"
    );
    let transaction: Transaction = bincode::deserialize(WIRE).unwrap();
    transaction.verify().unwrap();
    assert_eq!(bincode::serialize(&transaction).unwrap().as_slice(), WIRE);
    assert_eq!(
        transaction.signatures[0].to_string(),
        "Z3HdXzUAZ57yeWrMib3rNiorVvMyJpKvWfTeTy2VjSt1jjECLPnn2bXjoPVxfjP7k25Wek2GUnFPpSsNBYXxqsS"
    );
    let message = &transaction.message;
    let token_program = message.account_keys[8];
    assert_eq!(
        token_program.to_string(),
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    );
    assert!(message.instructions[0].accounts.contains(&8));
    assert_eq!(message.instructions[1].program_id_index, 8);
    assert!(message.is_non_loader_key(&token_program, 8));
    assert!(!message.account_keys.contains(&bpf_loader_upgradeable::id()));

    for &active in &[false, true] {
        let program_writable = !(cfg!(feature = "epoch228-called-program-demotion")
            || (crate::ACTIVATION_GATED_PROGRAM_DEMOTION && active));
        assert_eq!(message.is_writable(8, active), program_writable);
        let writes = writable_key_attribution(std::slice::from_ref(&transaction), active).unwrap();
        assert_eq!(writes.contains_key(token_program.as_ref()), program_writable);
        assert!(writes.contains_key(message.account_keys[0].as_ref()));
    }
}

#[test]
fn signed_wire_selects_the_same_program_lock_and_write_attribution() {
    let mut hash = Sha256::new();
    hash.input(WIRE);
    assert_eq!(
        format!("{:x}", hash.result()),
        "64bb183163714a622db870c7afd0e88fc0d544821a6b107c9df503cc0fcfcc2f"
    );
    let tx: Transaction = bincode::deserialize(WIRE).unwrap();
    tx.verify().unwrap();
    assert_eq!(bincode::serialize(&tx).unwrap().as_slice(), WIRE);

    let receipt: serde_json::Value = serde_json::from_str(RESPONSE).unwrap();
    assert_eq!(receipt["slot"], 99_368_201);
    assert_eq!(receipt["transaction_position"], 680);
    assert_eq!(receipt["index_base"], 0);
    let meta = &receipt["response_legacy_transaction"]["meta"];
    assert!(meta["err"].is_null());
    assert_eq!(meta["fee"], 5000);
    assert_eq!(meta["preBalances"][PROGRAM_INDEX], 1_089_991_680);
    assert_eq!(meta["postBalances"][PROGRAM_INDEX], 1_089_991_680);

    let message = &tx.message;
    let program = message.account_keys[PROGRAM_INDEX];
    let writable = message.account_keys[WRITABLE_ACCOUNT_INDEX];
    assert_eq!(
        program.to_string(),
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    );
    assert!(
        PROGRAM_INDEX
            < message.account_keys.len()
                - usize::from(message.header.num_readonly_unsigned_accounts)
    );
    assert!(message.instructions[0]
        .accounts
        .contains(&(PROGRAM_INDEX as u8)));
    assert_eq!(
        message.instructions[1].program_id_index as usize,
        PROGRAM_INDEX
    );
    assert!(message.is_non_loader_key(&program, PROGRAM_INDEX));
    assert!(!message.account_keys.contains(&bpf_loader_upgradeable::id()));

    for &demote in &[false, true] {
        let program_writable = !(cfg!(feature = "epoch228-called-program-demotion")
            || (crate::ACTIVATION_GATED_PROGRAM_DEMOTION && demote));
        assert_eq!(message.is_writable(PROGRAM_INDEX, demote), program_writable);
        assert!(message.is_writable(WRITABLE_ACCOUNT_INDEX, demote));
        let writes = writable_key_attribution(std::slice::from_ref(&tx), demote).unwrap();
        assert_eq!(writes.contains_key(program.as_ref()), program_writable);
        assert!(writes.contains_key(writable.as_ref()));
        let sysvar_instructions = message.serialize_instructions(demote);
        let instruction = Message::deserialize_instruction(0, &sysvar_instructions).unwrap();
        assert_eq!(
            instruction
                .accounts
                .iter()
                .find(|key| key.pubkey == program)
                .unwrap()
                .is_writable,
            program_writable
        );
    }

    let genesis = create_genesis_config_with_leader(1_000_000, &Pubkey::new_unique(), 500_000);
    let bank = Bank::new(&genesis.genesis_config);
    assert!(bank.demote_sysvar_write_locks());
    let locked = bank.prepare_batch(std::iter::once(&tx));
    assert_eq!(locked.lock_results(), &[Ok(())]);
    let signer = Keypair::new();
    let read = |key| {
        Transaction::new_signed_with_payer(
            &[Instruction::new_with_bytes(
                Pubkey::new_unique(),
                &[],
                vec![AccountMeta::new_readonly(key, false)],
            )],
            Some(&signer.pubkey()),
            &[&signer],
            bank.last_blockhash(),
        )
    };
    let read_program = read(program);
    let expected = if cfg!(feature = "epoch228-called-program-demotion")
        || crate::ACTIVATION_GATED_PROGRAM_DEMOTION
    {
        Ok(())
    } else {
        Err(TransactionError::AccountInUse)
    };
    assert_eq!(
        bank.prepare_batch(std::iter::once(&read_program))
            .lock_results(),
        &[expected]
    );
    let read_writable = read(writable);
    assert_eq!(
        bank.prepare_batch(std::iter::once(&read_writable))
            .lock_results(),
        &[Err(TransactionError::AccountInUse)]
    );
}

#[test]
fn upgradeable_loader_preserves_the_epoch230_program_write_lock() {
    // Variant for the write-lock predicate only. The signed fixture is tested above.
    let mut tx: Transaction = bincode::deserialize(WIRE).unwrap();
    tx.message.account_keys[12] = bpf_loader_upgradeable::id();
    let program = tx.message.account_keys[PROGRAM_INDEX];
    let writable = !cfg!(feature = "epoch228-called-program-demotion");
    assert_eq!(tx.message.is_writable(PROGRAM_INDEX, true), writable);
    assert_eq!(
        writable_key_attribution(&[tx], true)
            .unwrap()
            .contains_key(program.as_ref()),
        writable
    );
}
