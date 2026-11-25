use sha2::{Digest, Sha256};
use solana_program::message::{EPOCH228_CALLED_PROGRAM_DEMOTION, EPOCH230_CALLED_PROGRAM_DEMOTION};
use solana_sdk::{bpf_loader_upgradeable, transaction::Transaction};
use solana_vote_program::{
    id as vote_program_id,
    vote_instruction::{VoteError, VoteInstruction},
};

fn signed_transaction(wire: &[u8], sha256: &str, signature: &str) -> Transaction {
    let mut digest = Sha256::new();
    digest.input(wire);
    assert_eq!(format!("{:x}", digest.result()), sha256);
    let transaction: Transaction = bincode::deserialize(wire).unwrap();
    assert_eq!(transaction.signatures[0].to_string(), signature);
    transaction.verify().unwrap();
    assert_eq!(bincode::serialize(&transaction).unwrap().as_slice(), wire);
    transaction
}

#[test]
fn finalized_warmup_vote_commits_to_the_preceding_bank() {
    let transaction = signed_transaction(
        include_bytes!("fixtures/epoch231-warmup-99791499-tx184.bin"),
        "f3ee0dd4c94d6ae8435ef01220d63809377e3d06cd76fdd6315652412f835488",
        "2a4aeih7D4ToBtuupe4cASpinaZixkUurKvLyJSmHSUdemC3pvu8RVgWQRGhwWz5vC9AGs5uGpi2otxnC3DibWez",
    );
    let message = &transaction.message;
    assert_eq!(message.instructions.len(), 1);
    let instruction = &message.instructions[0];
    assert_eq!(
        message.account_keys[usize::from(instruction.program_id_index)],
        vote_program_id()
    );
    assert_eq!(VoteError::SlotHashMismatch as u32, 2);
    match bincode::deserialize::<VoteInstruction>(&instruction.data).unwrap() {
        VoteInstruction::Vote(vote) => {
            assert_eq!(vote.slots, vec![99_791_498]);
            assert_eq!(
                vote.hash.to_string(),
                "AVQgPbNJkaCS79o1SFgM1V89GAc2BNDReYCaJG48N7TK"
            );
        }
        other => panic!("unexpected signed vote instruction: {:?}", other),
    }
}

#[test]
fn finalized_parent_transaction_distinguishes_called_program_write_locks() {
    const PROGRAM_INDEX: usize = 8;
    let transaction = signed_transaction(
        include_bytes!("fixtures/epoch231-warmup-99791498-tx698.bin"),
        "de24d409bc5619241bbf666d4ec95cd2fd3dbcf6b1d3f95880c8e4ba007f0c44",
        "4SM1E4ZY1r1eKm1ZCo5QVmvcAejMVbTqXJzPBrEmEW3krQXrRDWsD1MuAXxCcvVHPsfmvgYd4AtE6KC9EcnukgUK",
    );
    let message = &transaction.message;
    assert_eq!(
        message.account_keys[PROGRAM_INDEX].to_string(),
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
        usize::from(message.instructions[1].program_id_index),
        PROGRAM_INDEX
    );
    assert!(!message.account_keys.contains(&bpf_loader_upgradeable::id()));

    for &demote_sysvars in &[false, true] {
        let program_writable = !(EPOCH228_CALLED_PROGRAM_DEMOTION
            || (EPOCH230_CALLED_PROGRAM_DEMOTION && demote_sysvars));
        assert_eq!(
            message.is_writable(PROGRAM_INDEX, demote_sysvars),
            program_writable
        );
        assert!(message.is_writable(0, demote_sysvars));
    }
}
