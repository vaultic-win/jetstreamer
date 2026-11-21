use jetstreamer_horizon::{convert::populate_message, transactions::VersionedMessage};
use lencode::{Decode, Encode, io::Cursor};
use solana_transaction::versioned::VersionedTransaction;

#[test]
fn signed_epoch266_transaction_preserves_two_hundred_instructions() {
    // Finalized block 114912038, transaction index 1274. The old producer
    // reported the first rejected append at instruction 65.
    let wire = include_bytes!("fixtures/epoch266-slot114912038-tx1274.bin");
    let tx: VersionedTransaction = bincode::deserialize(wire).unwrap();
    assert_eq!(bincode::serialize(&tx).unwrap(), wire.as_slice());
    assert_eq!(tx.signatures.len(), 1);
    assert_eq!(
        tx.signatures[0].to_string(),
        "2n3h3jHKNqAqUUE9jh5Pdcx3yMtxCWsd5JUKqToKG1xMnDRhcqXsYqrebTprnT8v5cbeE7h3ZHg8Gc1kPkHAtZAy"
    );
    tx.verify_and_hash_message().unwrap();
    let instructions = tx.message.instructions();
    assert_eq!(instructions.len(), 200);

    let mut message = VersionedMessage::default();
    populate_message(&mut message, &tx.message).unwrap();
    let mut archive = [0; 4096];
    let written = message
        .encode_ext(&mut Cursor::new(&mut archive[..]), None)
        .unwrap();
    let decoded =
        VersionedMessage::decode_ext(&mut Cursor::new(&archive[..written]), None).unwrap();
    let VersionedMessage::Legacy(legacy) = decoded else {
        panic!("expected legacy transaction")
    };
    assert_eq!(legacy.instructions.len(), instructions.len());
    for (actual, signed) in legacy.instructions.iter().zip(instructions) {
        assert_eq!(actual.program_id_index, signed.program_id_index);
        assert_eq!(actual.accounts, signed.accounts.as_slice());
        assert_eq!(actual.data, signed.data.as_slice());
    }
}
