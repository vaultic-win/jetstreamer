//! Opt-in synthetic native test of the production replay adapter. No mainnet
//! bootstrap override, canonical publication or pressure-admission authority.
use super::*;
use jetstreamer_historical_protocol::{Checkpoint, EntryProcessed, EntryRequest, SnapshotExport};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::atomic::AtomicBool};

type Transcript = (
    String,
    Vec<u8>,
    Checkpoint,
    EntryRequest,
    EntryProcessed,
    Checkpoint,
    SnapshotExport,
    Vec<EntryRequest>,
    Vec<EntryProcessed>,
    Checkpoint,
    Checkpoint,
    Vec<EntryProcessed>,
    Checkpoint,
    u32,
    u32,
);

#[test]
#[ignore = "requires hash-bound native v1.7.15 fixture and its sealed test launcher"]
fn pressure_resume_native_adapter_executes_suffix_and_consumes_terminal() {
    let input = PathBuf::from(std::env::var_os("JETSTREAMER_RESUME_NATIVE_FIXTURE").unwrap());
    let launcher = PathBuf::from(std::env::var_os("JETSTREAMER_NATIVE_LIVE_WORKER").unwrap());
    let bytes = fs::read(input.join("native-transcript.bin")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        std::env::var("JETSTREAMER_RESUME_NATIVE_TRANSCRIPT_SHA256").unwrap()
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&launcher).unwrap())),
        std::env::var("JETSTREAMER_RESUME_NATIVE_LAUNCHER_SHA256").unwrap()
    );
    let (
        schema,
        genesis,
        _,
        _,
        _,
        boundary,
        export,
        entries,
        baseline_results,
        terminal,
        restored,
        restored_results,
        restored_terminal,
        parent,
        child,
    ): Transcript = bincode::deserialize(&bytes).unwrap();
    assert_eq!(schema, "horizon-native-checkpoint-recorder-transcript-v1");
    assert_ne!(parent, child);
    assert_eq!(baseline_results, restored_results);
    assert_eq!(terminal, restored_terminal);
    let genesis_hash = Hash::new_from_array(genesis.try_into().unwrap()).to_string();
    assert_ne!(
        genesis_hash,
        jetstreamer_historical_protocol::MAINNET_GENESIS_HASH
    );
    assert_eq!((boundary.slot, terminal.slot), (1, 2));
    let mut saved = boundary.clone();
    saved.writes.clear();
    assert_eq!(saved, restored);
    let directory = tempfile::tempdir().unwrap();
    let accounts_hash: [u8; 32] = boundary.accounts_hash.clone().try_into().unwrap();
    let snapshot = directory.path().join(format!(
        "snapshot-{}-{}.tar.bz2",
        boundary.slot,
        Hash::new_from_array(accounts_hash)
    ));
    fs::copy(input.join("native-snapshot.tar.bz2"), &snapshot).unwrap();
    assert_eq!(
        Sha256::digest(fs::read(&snapshot).unwrap()).as_slice(),
        export.archive_sha256
    );
    let profile = crate::historical::WorkerProfile {
        backend_id: "synthetic-v1.7.15-checkpoint-ipc-fixture",
        required_genesis_hash: Box::leak(genesis_hash.into_boxed_str()),
        ..crate::historical::SOLANA_V1_7_15_CANDIDATE
    };
    let mut client = HistoricalRuntimeClient::spawn(
        profile,
        crate::historical::WorkerSpawn {
            executable: launcher,
            initialization: crate::historical::HistoricalInitialization::SnapshotArchive(
                crate::historical::SnapshotInitialization {
                    ledger_path: input,
                    archive_path: snapshot,
                    expected_slot: boundary.slot,
                    expected_accounts_hash: accounts_hash,
                    expected_archive_sha256: Some(export.archive_sha256.try_into().unwrap()),
                    expected_archive_size: Some(export.archive_size),
                    scratch_parent: Some(directory.path().into()),
                },
            ),
        },
    )
    .unwrap();
    let actual = client.freeze_checkpoint(boundary.slot).unwrap();
    assert_eq!(actual.bank_hash.as_slice(), saved.bank_hash);
    assert_eq!(actual.accounts_hash.as_slice(), saved.accounts_hash);
    assert_eq!(actual.last_blockhash.as_slice(), saved.last_blockhash);
    assert_eq!(actual.capitalization, saved.capitalization);
    assert_eq!(actual.transaction_count, saved.transaction_count);
    assert_eq!(actual.tick_height, saved.tick_height);
    assert!(actual.slot_complete && actual.writes.is_empty());
    assert_eq!(
        actual.next_write_version,
        client.initialized().next_write_version
    );
    let verifier = Arc::new(SnapshotVerifier::new(
        BTreeMap::from([(
            terminal.slot,
            super::super::BankHashExpectation::LegacyAccountsHash(Hash::new_from_array(
                terminal.accounts_hash.clone().try_into().unwrap(),
            )),
        )]),
        None,
    ));
    let shutdown = Arc::new(AtomicBool::new(false));
    let failure = Arc::new(ReplayFailure::new(shutdown));
    let replay = HistoricalReplay::from_restored_checkpoint(
        client,
        HistoricalCheckpointSummary::try_from(&actual).unwrap(),
        verifier.clone(),
        failure.clone(),
        Arc::new(ReplayCursor::new()),
        Arc::new(ReplayProgress::new(boundary.slot + 1)),
        boundary.slot + 1,
        RestoredCheckpointTrust::LocalBootstrapWithCanonicalTerminal(terminal.slot),
    )
    .unwrap();
    assert!(verifier.finish().is_err());
    let mut transaction_index = 0;
    for entry in entries {
        let txs = entry
            .transactions
            .iter()
            .map(|bytes| {
                let legacy: solana_transaction::Transaction = bincode::deserialize(bytes).unwrap();
                let tx = solana_transaction::versioned::VersionedTransaction::from(legacy);
                assert_eq!(encode_legacy_transaction(&tx).unwrap(), *bytes);
                super::super::ScheduledTransaction {
                    tx,
                    expected_status: None,
                    reconstruct_fee: true,
                    status_meta: solana_transaction_status::TransactionStatusMeta::default(),
                }
            })
            .collect::<Vec<_>>();
        let count = txs.len();
        replay.process_ready_entries(vec![ReadyEntry {
            slot: entry.slot,
            entry_index: entry.entry_index.try_into().unwrap(),
            start_index: transaction_index,
            txs,
            hash: Hash::new_from_array(entry.hash.try_into().unwrap()),
            num_hashes: entry.num_hashes,
            tx_count: count,
        }]);
        transaction_index += count;
        assert!(
            failure.error_message().is_none(),
            "{:?}",
            failure.error_message()
        );
    }
    replay.verify_latest_bank().unwrap();
    verifier.finish().unwrap();
    let evidence = replay.evidence().unwrap();
    assert_eq!(evidence.terminal.slot, terminal.slot);
    assert_eq!(evidence.terminal.bank_hash.as_slice(), terminal.bank_hash);
    assert_eq!(
        evidence.terminal.accounts_hash.as_slice(),
        terminal.accounts_hash
    );
    assert_eq!(
        evidence.terminal.last_blockhash.as_slice(),
        terminal.last_blockhash
    );
    assert_eq!(evidence.terminal.capitalization, terminal.capitalization);
    assert_eq!(
        evidence.terminal.transaction_count,
        terminal.transaction_count
    );
    assert_eq!(evidence.terminal.tick_height, terminal.tick_height);
    assert!(evidence.terminal.slot_complete);
    let outcome = replay.shutdown_for_checkpoint().unwrap();
    assert!(outcome.worker_reap_verified());
    eprintln!(
        "native pressure resume adapter: suffix executed, exact future terminal consumed, worker reaped; full firehose/controller/mainnet qualification=false"
    );
}
