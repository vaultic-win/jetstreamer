//! Signed transaction -> real archive codec -> production Dispatch -> actual
//! VerificationPlugin callbacks. The one-slot projection is diagnostic only;
//! its authentic transaction does not authenticate synthetic block/PoH metadata.
//! The unchanged epoch/span gate MUST reject it as an incomplete epoch.
use super::*;
use crate::plugins::verification::VerificationPlugin;
use base64::Engine as _;
use bincode::Options as _;
use jetstreamer_horizon::{
    archive::{ArchiveReader, ArchiveVersion, ArchiveWriter, ArchiveWriterConfig, Compression},
    block_metas::BlockMeta,
    convert::{populate_transaction, result_from_status},
    transactions::VersionedMessage,
};
use sha2::{Digest, Sha256};
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status::{TransactionStatusMeta, TransactionTokenBalance};
use std::{io::Cursor, sync::Mutex};

const EPOCH: u64 = 234;
const SLOT: u64 = 101_249_927;
const RAW: &[u8] =
    include_bytes!("../../jetstreamer-horizon/tests/fixtures/epoch234-slot101249927-tx298.bin");
const RPC: &[u8] =
    include_bytes!("../../jetstreamer-horizon/tests/fixtures/epoch234-getTransaction.json");
const BLOCK: &[u8] =
    include_bytes!("../../jetstreamer-horizon/tests/fixtures/epoch234-getBlock-signatures.json");
const SIGNATURE: &str =
    "5vsu4HtoCUafoiHmeJSPPEBnXCtCs3Saff9hSsbTGQCQ6DS3teP4i3PWQpcs5MyytginSBAttfmVLtSG1fJKvpNb";

fn authenticated() -> (VersionedTransaction, TransactionStatusMeta) {
    for (bytes, expected) in [
        (
            RAW,
            "056658fd4f6f8172bae030599afa0335f0a05ab49ea5236b1d98d5fac0809d05",
        ),
        (
            RPC,
            "7f5cbd7a11dbe22ad0a7f3ca799f35f0d23fef29aa76ed732f288c0379243c28",
        ),
        (
            BLOCK,
            "f7c29a0ee8811128afe103b9f0e67f1b668b76d9103ae51ef868767e89ef6a54",
        ),
    ] {
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected);
    }
    let rpc: serde_json::Value = serde_json::from_slice(RPC).unwrap();
    let block: serde_json::Value = serde_json::from_slice(BLOCK).unwrap();
    assert!(rpc.get("error").is_none() && block.get("error").is_none());
    assert_eq!(rpc["result"]["slot"], SLOT);
    assert_eq!(rpc["result"]["transaction"][1], "base64");
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(RAW),
        rpc["result"]["transaction"][0].as_str().unwrap()
    );
    let signatures = block["result"]["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), 547);
    assert_eq!(signatures[298], SIGNATURE);
    assert_eq!(signatures.iter().filter(|s| **s == SIGNATURE).count(), 1);
    let upstream: VersionedTransaction = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(RAW)
        .unwrap();
    let independent =
        jetstreamer_firehose::transaction::parse_versioned_transaction_from_slice(RAW).unwrap();
    assert_eq!(upstream, independent);
    assert_eq!(bincode::serialize(&upstream).unwrap(), RAW);
    upstream.sanitize().unwrap();
    upstream.verify_and_hash_message().unwrap();
    assert_eq!(upstream.signatures.len(), 1);
    assert_eq!(upstream.signatures[0].to_string(), SIGNATURE);
    assert_eq!(RAW.len(), 1203);
    assert_eq!(upstream.message.instructions().len(), 67);
    assert_eq!(
        upstream
            .message
            .instructions()
            .iter()
            .map(|i| i.accounts.len() + i.data.len())
            .sum::<usize>(),
        804
    );
    let m = &rpc["result"]["meta"];
    assert!(m["err"].is_null());
    assert_eq!(m["status"], serde_json::json!({"Ok":null}));
    assert_eq!(m["innerInstructions"], serde_json::json!([]));
    assert_eq!(m["rewards"], serde_json::json!([]));
    assert_eq!(
        m["loadedAddresses"],
        serde_json::json!({"readonly":[],"writable":[]})
    );
    for absent in ["returnData", "computeUnitsConsumed", "costUnits"] {
        assert!(m.get(absent).is_none());
    }
    let balances = |key: &str| -> Vec<TransactionTokenBalance> {
        m[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                assert!(v.get("owner").is_none() && v.get("programId").is_none());
                TransactionTokenBalance {
                    account_index: v["accountIndex"].as_u64().unwrap().try_into().unwrap(),
                    mint: v["mint"].as_str().unwrap().into(),
                    ui_token_amount: serde_json::from_value(v["uiTokenAmount"].clone()).unwrap(),
                    owner: String::new(),
                    program_id: String::new(),
                }
            })
            .collect()
    };
    let meta = TransactionStatusMeta {
        status: Ok(()),
        fee: m["fee"].as_u64().unwrap(),
        pre_balances: serde_json::from_value(m["preBalances"].clone()).unwrap(),
        post_balances: serde_json::from_value(m["postBalances"].clone()).unwrap(),
        inner_instructions: Some(vec![]),
        log_messages: Some(serde_json::from_value(m["logMessages"].clone()).unwrap()),
        pre_token_balances: Some(balances("preTokenBalances")),
        post_token_balances: Some(balances("postTokenBalances")),
        rewards: Some(vec![]),
        ..TransactionStatusMeta::default()
    };
    assert_eq!(meta.fee, 5000);
    assert_eq!(meta.log_messages.as_ref().unwrap().len(), 165);
    (upstream, meta)
}

// Independent observer of the decoded callback, alongside the production
// verification worker. It explicitly checks instruction67 and all preceding
// bytes; the production verifier's stream digest currently hashes fee/signatures
// and account updates, so that digest alone cannot establish arena preservation.
struct Audit {
    expected: Box<Transaction>,
    signed: VersionedTransaction,
    seen: Arc<Mutex<Vec<&'static str>>>,
}
impl PluginWorker for Audit {
    fn on_epoch(&mut self, _: &EpochMeta) {
        panic!("partial projection fabricated an epoch notification");
    }
    fn on_transaction(&mut self, slot: u64, index: u32, tx: &Transaction) {
        assert_eq!(slot, SLOT);
        // This is the sole transaction in a diagnostic codec projection. Its
        // actual source index298 was authenticated separately above.
        assert_eq!(index, 0);
        assert_eq!(tx.message, self.expected.message);
        assert_eq!(tx.signatures, self.expected.signatures);
        assert_eq!(result_from_status(&tx.status).unwrap(), Ok(()));
        assert_eq!(tx.fee, self.expected.fee);
        assert_eq!(tx.pre_balances, self.expected.pre_balances);
        assert_eq!(tx.post_balances, self.expected.post_balances);
        assert_eq!(
            tx.loaded_writable_addresses,
            self.expected.loaded_writable_addresses
        );
        assert_eq!(
            tx.loaded_readonly_addresses,
            self.expected.loaded_readonly_addresses
        );
        assert_eq!(tx.inner_instructions, self.expected.inner_instructions);
        assert_eq!(tx.log_messages, self.expected.log_messages);
        assert_eq!(tx.pre_token_balances, self.expected.pre_token_balances);
        assert_eq!(tx.post_token_balances, self.expected.post_token_balances);
        assert_eq!(tx.rewards, self.expected.rewards);
        assert_eq!(tx.return_data, self.expected.return_data);
        assert_eq!(
            tx.compute_units_consumed,
            self.expected.compute_units_consumed
        );
        assert_eq!(tx.cost_units, self.expected.cost_units);
        assert_eq!(tx.iter_account_updates().count(), 0);
        let VersionedMessage::Legacy(message) = &tx.message else {
            panic!("legacy message variant changed");
        };
        assert_eq!(message.instructions.len(), 67);
        assert_eq!(message.instructions.data_len(), 804);
        assert_eq!(message.instructions.get(66).unwrap().data.len(), 9);
        let solana_message::VersionedMessage::Legacy(original) = &self.signed.message else {
            panic!("signed source variant changed");
        };
        assert_eq!(
            message.header.num_required_signatures,
            original.header.num_required_signatures
        );
        assert_eq!(
            message.header.num_readonly_signed_accounts,
            original.header.num_readonly_signed_accounts
        );
        assert_eq!(
            message.header.num_readonly_unsigned_accounts,
            original.header.num_readonly_unsigned_accounts
        );
        assert_eq!(
            message.recent_blockhash.as_ref(),
            original.recent_blockhash.as_ref()
        );
        assert_eq!(message.account_keys.len(), original.account_keys.len());
        for (actual, expected) in message.account_keys.iter().zip(&original.account_keys) {
            assert_eq!(actual.as_ref(), expected.as_ref());
        }
        for (actual, expected) in message.instructions.iter().zip(&original.instructions) {
            assert_eq!(actual.program_id_index, expected.program_id_index);
            assert_eq!(actual.accounts, expected.accounts.as_slice());
            assert_eq!(actual.data, expected.data.as_slice());
        }
        self.seen.lock().unwrap().push("transaction67");
    }
    fn on_block(&mut self, note: &BlockNotification, entries: &[EntryRecord]) {
        assert_eq!(note.slot(), SLOT);
        assert!(!note.is_skipped());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tx_count, 1);
        self.seen.lock().unwrap().push("block");
    }
    fn flush(&mut self, _: &Output) {
        self.seen.lock().unwrap().push("flush");
    }
}

fn archive(format: ArchiveVersion) -> (Vec<u8>, Box<Transaction>) {
    let (upstream, meta) = authenticated();
    let mut tx = Transaction::new_boxed();
    populate_transaction(&mut tx, &upstream, &meta).unwrap();
    let mut writer = ArchiveWriter::new(
        Vec::new(),
        EPOCH,
        SLOT,
        1,
        ArchiveWriterConfig {
            format,
            compression: Compression::None,
            // V1 uses the original Adaptive policy; OuterCompressed is V2-only.
            diff_policy: if format == ArchiveVersion::V1 {
                Default::default()
            } else {
                ArchiveWriterConfig::default().diff_policy
            },
            ..Default::default()
        },
    )
    .unwrap();
    writer.begin_slot(SLOT).unwrap();
    writer.write_transaction(&tx).unwrap();
    let mut block = BlockMeta::new_boxed();
    block.slot = SLOT;
    block.parent_slot = SLOT - 1;
    block.entry_count = 1;
    block.executed_transaction_count = 1;
    // Hashes/default block fields are explicitly synthetic, never canonical
    // historical PoH evidence. This fixture is not fed to a full-verifier gate.
    writer
        .end_slot(
            &block,
            &[EntryRecord {
                num_hashes: 1,
                tx_count: 1,
            }],
        )
        .unwrap();
    let (bytes, stats) = writer.finish().unwrap();
    assert_eq!(stats.slots, 1);
    assert_eq!(stats.transactions, 1);
    assert!(
        bytes.len() < 128 * 1024,
        "diagnostic fixture unexpectedly grew"
    );
    (bytes, tx)
}

fn dispatch_fixture(format: ArchiveVersion) {
    let (bytes, expected) = archive(format);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let db = Arc::new(Client::default());
    let plugin = VerificationPlugin::new();
    runtime
        .block_on(plugin.on_start(db.clone(), EPOCH))
        .unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(WRITE_QUEUE_CAP);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut dispatch = Dispatch {
        workers: vec![
            plugin.spawn_worker(0),
            Box::new(Audit {
                expected,
                signed: authenticated().0,
                seen: seen.clone(),
            }),
        ],
        output: Output {
            tx,
            db: db.clone(),
            backlog: Arc::new(AtomicU64::new(0)),
        },
        since_flush: 0,
        consumption: Consumption::all(),
    };
    let mut reader = ArchiveReader::open(Cursor::new(bytes)).unwrap();
    reader.read_slots(0, u64::MAX, &mut dispatch).unwrap();
    dispatch.finish();
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["transaction67", "block", "flush"]
    );
    // This actual production lifecycle must reject the one-slot projection.
    // Do not shrink RunState's range or fabricate missing callbacks to pass it.
    let error = runtime
        .block_on(plugin.on_finish(db, EPOCH))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("slot coverage mismatch: delivered=1 blocks=1 skipped=0"),
        "{error}"
    );
    assert!(
        error.contains("expected one epoch notification, received 0"),
        "{error}"
    );
    assert!(
        !error.contains("worker 0:"),
        "unexpected callback invariant failure: {error}"
    );
    assert!(
        plugin.last_report().is_none(),
        "partial fixture must never yield a completion report"
    );
}
fn large_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn signed67_instruction_transaction_reaches_real_dispatch_and_verifier_in_both_wire_versions() {
    large_stack(|| {
        for format in [ArchiveVersion::V1, ArchiveVersion::V2] {
            dispatch_fixture(format);
        }
    });
}

#[test]
fn historical_packet_signature_rejects_modified_instruction_before_dispatch() {
    let (mut tx, _) = authenticated();
    let solana_message::VersionedMessage::Legacy(message) = &mut tx.message else {
        panic!("fixture variant changed");
    };
    message.instructions[66].data[0] ^= 1;
    assert!(tx.verify_and_hash_message().is_err());
    let mut trailing = RAW.to_vec();
    trailing.push(0);
    assert!(
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize::<VersionedTransaction>(&trailing)
            .is_err()
    );
}
