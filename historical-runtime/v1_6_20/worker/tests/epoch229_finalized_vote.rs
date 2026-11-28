#![cfg(feature = "epoch229-bank-trace")]

use sha2::{Digest, Sha256};
use solana_sdk::transaction::Transaction;
use solana_vote_program::{id as vote_program_id, vote_instruction::VoteInstruction};

const WIRE: &[u8] = include_bytes!("fixtures/epoch229-98931634-tx408.bin");

#[test]
fn trace_worker_decodes_and_verifies_the_finalized_parent_vote() {
    let mut digest = Sha256::new();
    digest.input(WIRE);
    assert_eq!(
        format!("{:x}", digest.result()),
        "e2a66249be6c162c25a5315bf7f4f60d59e90fdc4ec740d53bf12ce2a18e2407"
    );
    let transaction: Transaction = bincode::deserialize(WIRE).unwrap();
    transaction.verify().unwrap();
    assert_eq!(bincode::serialize(&transaction).unwrap().as_slice(), WIRE);
    assert_eq!(
        transaction.signatures[0].to_string(),
        "2NCRSy4TNqnRHv4jRuxe8n4mT9x1z7cfxHfKq4KVNEuKP64NQGYVMs5MGTFF9HgyQD2fJ7zE6HRteU6XDzPpieRB"
    );
    let instruction = &transaction.message.instructions[0];
    assert_eq!(
        transaction.message.account_keys[usize::from(instruction.program_id_index)],
        vote_program_id()
    );
    match bincode::deserialize::<VoteInstruction>(&instruction.data).unwrap() {
        VoteInstruction::Vote(vote) => {
            assert_eq!(vote.slots, vec![98_931_633]);
            assert_eq!(
                vote.hash.to_string(),
                "7eZpcd8gDPTZ7cGasN6K6YpFiQGbGPJvGeovtAbBrorU"
            );
            assert_eq!(vote.timestamp, Some(1_632_922_117));
        }
        other => panic!("unexpected signed instruction: {:?}", other),
    }
}
