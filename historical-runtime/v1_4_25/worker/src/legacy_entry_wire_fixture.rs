//! Test-only golden wire evidence for the independent diagnostic decoder.
//! No runtime behavior or qualification/publication authority is changed.

use sha2_fast::{Digest, Sha256};
use solana_merkle_tree::MerkleTree;
use solana_sdk::{
    hash::Hash,
    instruction::CompiledInstruction,
    message::{Message, MessageHeader},
    pubkey::Pubkey,
    signature::Signature,
    transaction::Transaction,
};

fn transaction(value: u8) -> Transaction {
    Transaction {
        signatures: vec![Signature::new(&[value; 64])],
        message: Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            account_keys: vec![Pubkey::new(&[42; 32])],
            recent_blockhash: Hash::new(&[43; 32]),
            instructions: vec![CompiledInstruction {
                program_id_index: 0,
                accounts: vec![0],
                data: vec![44, 45],
            }],
        },
    }
}

#[test]
fn pinned_sdk_legacy_entry_wire_and_signature_merkle_fixture() {
    let transactions: Vec<_> = (1..=3).map(transaction).collect();
    // Upstream Entry's fixed-order fields: num_hashes, Hash, Vec<Transaction>.
    let bytes = bincode::serialize(&vec![(7_u64, Hash::new(&[9; 32]), &transactions)]).unwrap();
    let mut expected = 1_u64.to_le_bytes().to_vec();
    expected.extend_from_slice(&7_u64.to_le_bytes());
    expected.extend_from_slice(&[9; 32]);
    expected.extend_from_slice(&3_u64.to_le_bytes());
    for value in 1..=3 {
        expected.push(1);
        expected.extend_from_slice(&[value; 64]);
        expected.extend_from_slice(&[1, 0, 0, 1]);
        expected.extend_from_slice(&[42; 32]);
        expected.extend_from_slice(&[43; 32]);
        expected.extend_from_slice(&[1, 0, 1, 0, 2, 44, 45]);
    }
    assert_eq!(bytes, expected);
    let signatures: Vec<_> = transactions
        .iter()
        .flat_map(|tx| tx.signatures.iter())
        .collect();
    let tree = MerkleTree::new(&signatures);
    let root = tree.get_root().unwrap();
    assert_eq!(bytes.len(), 476);
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "b3d19c5653173ed4150e6806bce35848b044a734058acaeff645064a8e06f773"
    );
    assert_eq!(
        root.as_ref(),
        &[
            16, 250, 232, 52, 23, 235, 40, 179, 214, 126, 89, 164, 243, 253, 102, 204, 104, 211,
            74, 173, 103, 114, 77, 91, 158, 125, 109, 78, 15, 36, 25, 101
        ][..]
    );
    println!(
        "legacy_entry_fixture_bytes={} sha256={:x}",
        bytes.len(),
        Sha256::digest(&bytes)
    );
    println!("legacy_entry_fixture_signature_merkle={:?}", root.as_ref());
}

#[test]
fn pinned_sdk_gap_poh_chain_fixture() {
    use solana_sdk::hash::{hash, hashv};
    // Mirror pinned Entry::next_hash with the SDK's own SHA implementation,
    // independently of the modern diagnostic verifier. The signature mixin is
    // synthetic; real signature Merkle serialization is tested separately above.
    let mut current = Hash::new(&[9; 32]);
    current = hashv(&[current.as_ref(), &[4; 32]]);
    let mut ticks = 0;
    for count in &[2, 3, 3, 3, 3, 3] {
        for _ in 0..*count {
            current = hash(current.as_ref());
        }
        ticks += 1;
        if ticks % 2 == 0 {
            println!(
                "gap_poh_fixture_boundary_{}={:?}",
                ticks / 2,
                current.as_ref()
            );
        }
    }
    let metadata = bincode::serialize(&(
        60912004_u64,
        4_u64,
        4_u64,
        123_u64,
        3_u64,
        60911999_u64,
        vec![60912007_u64, 60912005_u64],
        true,
        vec![1_u32, 3_u32],
    ))
    .unwrap();
    println!(
        "gap_slotmeta_fixture_sha256={:x}",
        Sha256::digest(&metadata)
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&metadata)),
        "6b2bcca69ee61a560e719e0e58456ac5907e8e24c90434b90e9f8e12b25f6ec7"
    );
    assert_eq!(
        current.as_ref(),
        &[
            58, 40, 67, 136, 158, 227, 136, 110, 69, 22, 232, 71, 238, 213, 223, 56, 55, 20, 78,
            47, 7, 118, 245, 63, 122, 188, 207, 169, 9, 140, 123, 212,
        ][..]
    );
}
