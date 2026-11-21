//! Test the acquired message's account locks and an independent read-only native CPI.
use super::writable_key_attribution;
use solana_runtime::{
    bank::Bank, genesis_utils::create_genesis_config_with_leader,
    message_processor::MessageProcessor,
};
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    keyed_account::KeyedAccount,
    process_instruction::InvokeContext,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::sync::atomic::{AtomicUsize, Ordering};

const WIRE: &[u8] = include_bytes!("../../../fixtures/epoch228-98505585-tx175.bin");
const RESPONSE: &str = include_str!("../../../fixtures/epoch228-98505585-tx175.finalized.json");
const CHILD_ID: [u8; 32] = [37; 32];
const PARENT_ID: [u8; 32] = [59; 32];
static CHILD_CALLS: AtomicUsize = AtomicUsize::new(0);

#[test]
fn signed_wire_metadata_and_native_bank_lock_agree() {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.input(WIRE);
    assert_eq!(
        format!("{:x}", hash.result()),
        "76df7db7d809c4bd42980e4b69ee43d210ac5f5af122dd272c6d0bf24bf6b5d4"
    );
    let tx: Transaction = bincode::deserialize(WIRE).unwrap();
    tx.verify().unwrap();
    assert_eq!(bincode::serialize(&tx).unwrap().as_slice(), WIRE);
    let record: serde_json::Value = serde_json::from_str(RESPONSE).unwrap();
    let row = &record["result"];
    assert_eq!(row["slot"], 98_505_585);
    assert_eq!(row["transactionIndex"], 175);
    assert_eq!(
        row["meta"]["err"]["InstructionError"][1],
        "PrivilegeEscalation"
    );
    assert!(row["meta"]["innerInstructions"]
        .as_array()
        .unwrap()
        .is_empty());
    let keys = &tx.message.account_keys;
    let program = keys[4];
    assert_eq!(
        program.to_string(),
        "GqTPL6qRf5aUuqscLh8Rg2HTxPUXfhhAXDptTLhp1t2J"
    );
    assert_eq!(tx.message.instructions[0].program_id_index, 4);
    assert!(tx.message.is_key_passed_to_program(4));
    for sysvars in &[false, true] {
        let mask: Vec<bool> = (0..keys.len())
            .map(|i| tx.message.is_writable(i, *sysvars))
            .collect();
        assert_eq!(
            mask,
            [true, true, true, true, false, true, false, false, false, false].to_vec()
        );
        let written = writable_key_attribution(&[tx.clone()], *sysvars).unwrap();
        assert!(!written.contains_key(program.as_ref()));
        let serialized = tx.message.serialize_instructions(*sysvars);
        let ix = solana_sdk::message::Message::deserialize_instruction(0, &serialized).unwrap();
        assert!(
            !ix.accounts
                .iter()
                .find(|k| k.pubkey == program)
                .unwrap()
                .is_writable
        );
    }
    let genesis = create_genesis_config_with_leader(1_000_000, &Pubkey::new_unique(), 500_000);
    let bank = Bank::new(&genesis.genesis_config);
    let held = bank.prepare_batch(std::iter::once(&tx));
    assert_eq!(held.lock_results(), &[Ok(())]);
    let independent = Keypair::new();
    let instruction = Instruction::new_with_bytes(
        Pubkey::new_unique(),
        &[],
        vec![AccountMeta::new_readonly(program, false)],
    );
    let companion = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&independent.pubkey()),
        &[&independent],
        bank.last_blockhash(),
    );
    let shared = bank.prepare_batch(std::iter::once(&companion));
    assert_eq!(shared.lock_results(), &[Ok(())]);
}

fn read_only_child(
    program: &Pubkey,
    accounts: &[KeyedAccount],
    data: &[u8],
    _: &mut dyn InvokeContext,
) -> Result<(), InstructionError> {
    assert_eq!(*program, Pubkey::new_from_array(CHILD_ID));
    assert_eq!(data, b"inner");
    let key = Pubkey::new_from_array(PARENT_ID);
    let account = accounts.iter().find(|a| a.unsigned_key() == &key).unwrap();
    assert!(!account.is_writable());
    CHILD_CALLS.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

fn read_only_parent(
    program: &Pubkey,
    accounts: &[KeyedAccount],
    data: &[u8],
    context: &mut dyn InvokeContext,
) -> Result<(), InstructionError> {
    let child = Pubkey::new_from_array(CHILD_ID);
    assert_eq!(data, b"outer");
    let caller = accounts
        .iter()
        .find(|a| a.unsigned_key() == program)
        .unwrap();
    assert!(!caller.is_writable());
    let callee = accounts
        .iter()
        .find(|a| a.unsigned_key() == &child)
        .unwrap();
    let ix = Instruction::new_with_bytes(
        child,
        b"inner",
        vec![AccountMeta::new_readonly(*program, false)],
    );
    MessageProcessor::native_invoke(context, ix, &[caller, callee], &[])
}

#[test]
fn bank_propagates_readonly_program_through_successful_native_cpi() {
    let genesis = create_genesis_config_with_leader(1_000_000, &Pubkey::new_unique(), 500_000);
    let mut bank = Bank::new(&genesis.genesis_config);
    let (parent, child) = (
        Pubkey::new_from_array(PARENT_ID),
        Pubkey::new_from_array(CHILD_ID),
    );
    bank.add_builtin("epoch228_readonly_parent", parent, read_only_parent);
    bank.add_builtin("epoch228_readonly_child", child, read_only_child);
    let accounts = vec![
        AccountMeta::new(parent, false),
        AccountMeta::new_readonly(child, false),
    ];
    let ix = Instruction::new_with_bytes(parent, b"outer", accounts);
    let payer = &genesis.mint_keypair;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        bank.last_blockhash(),
    );
    let original = bank.get_account(&parent).unwrap();
    CHILD_CALLS.store(0, Ordering::SeqCst);
    bank.process_transaction(&tx).unwrap();
    assert_eq!(CHILD_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(bank.get_account(&parent).unwrap(), original);
}
