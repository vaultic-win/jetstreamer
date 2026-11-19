//! Opt-in synthetic native test of the production replay adapter. No mainnet
//! bootstrap override, canonical publication or pressure-admission authority.
use super::*;
use jetstreamer_historical_protocol::{Checkpoint, EntryProcessed, EntryRequest, SnapshotExport};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::atomic::AtomicBool};

#[path = "qualification_checkpoint_car_native.rs"]
mod source_car;
#[path = "qualification_checkpoint_suffix_native.rs"]
mod source_suffix;

type Transcript<P = EntryRequest, R = EntryProcessed> = (
    String,
    Vec<u8>,
    Checkpoint,
    P,
    R,
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
fn pressure_notifiers_drain_native_prefix_export_and_resume_to_terminal() {
    let input = PathBuf::from(std::env::var_os("JETSTREAMER_RESUME_NATIVE_FIXTURE").unwrap());
    let launcher = PathBuf::from(std::env::var_os("JETSTREAMER_NATIVE_LIVE_WORKER").unwrap());
    let transaction_prefix = std::env::var("JETSTREAMER_PRESSURE_NATIVE_TRANSACTIONS").ok();
    assert!(
        transaction_prefix
            .as_deref()
            .is_none_or(|value| value == "1")
    );
    let transaction_prefix = transaction_prefix.is_some();
    let epoch_aligned = std::env::var("JETSTREAMER_PRESSURE_NATIVE_EPOCH").ok();
    assert!(epoch_aligned.as_deref().is_none_or(|value| value == "1"));
    let epoch_aligned = epoch_aligned.is_some();
    assert!(!epoch_aligned || transaction_prefix);
    let bytes = fs::read(input.join(if transaction_prefix {
        "native-pressure-transcript.bin"
    } else {
        "native-transcript.bin"
    }))
    .unwrap();
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
        bootstrap,
        prefix_entries,
        prefix_results,
        boundary,
        baseline_export,
        entries,
        baseline_results,
        terminal,
        restored,
        restored_results,
        restored_terminal,
        parent,
        child,
    ): Transcript<Vec<EntryRequest>, Vec<EntryProcessed>> = if transaction_prefix {
        bincode::deserialize(&bytes).unwrap()
    } else {
        let (
            schema,
            genesis,
            bootstrap,
            entry,
            result,
            boundary,
            export,
            entries,
            results,
            terminal,
            restored,
            restored_results,
            restored_terminal,
            parent,
            child,
        ): Transcript = bincode::deserialize(&bytes).unwrap();
        (
            schema,
            genesis,
            bootstrap,
            vec![entry],
            vec![result],
            boundary,
            export,
            entries,
            results,
            terminal,
            restored,
            restored_results,
            restored_terminal,
            parent,
            child,
        )
    };
    assert_eq!(
        schema,
        if epoch_aligned {
            "horizon-native-pressure-recorder-transcript-v3"
        } else if transaction_prefix {
            "horizon-native-pressure-recorder-transcript-v2"
        } else {
            "horizon-native-checkpoint-recorder-transcript-v1"
        }
    );
    assert_eq!(prefix_entries.len(), prefix_results.len());
    assert_eq!(
        prefix_entries.len(),
        if epoch_aligned {
            65
        } else if transaction_prefix {
            2
        } else {
            1
        }
    );
    let source_transactions = prefix_entries
        .iter()
        .map(|entry| entry.transactions.len() as u64)
        .sum::<u64>();
    assert_eq!(source_transactions, u64::from(transaction_prefix));
    assert_eq!(
        boundary.transaction_count - bootstrap.transaction_count,
        source_transactions
    );
    assert!(
        prefix_results
            .iter()
            .flat_map(|entry| &entry.outcomes)
            .all(|outcome| outcome.error.is_none())
    );
    assert_ne!(parent, child);
    assert_eq!(baseline_results, restored_results);
    assert_eq!(terminal, restored_terminal);
    let genesis_hash = Hash::new_from_array(genesis.try_into().unwrap()).to_string();
    assert_ne!(
        genesis_hash,
        jetstreamer_historical_protocol::MAINNET_GENESIS_HASH
    );
    let prefix_slot = if epoch_aligned { 432_000 } else { 1 };
    assert_eq!(
        (bootstrap.slot, boundary.slot, terminal.slot),
        (prefix_slot - 1, prefix_slot, prefix_slot + 1)
    );
    let mut saved = boundary.clone();
    saved.writes.clear();
    assert_eq!(saved, restored);
    let phase = std::env::var("JETSTREAMER_PRESSURE_NATIVE_PHASE").ok();
    if let Ok(stage) = std::env::var("JETSTREAMER_PRESSURE_NATIVE_EXPORT_CRASH") {
        assert_eq!(phase.as_deref(), Some("export"));
        assert!(matches!(
            stage.as_str(),
            "after-publication-intent" | "after-snapshot-manifest" | "after-paused-report"
        ));
    }
    assert!(
        phase
            .as_deref()
            .is_none_or(|p| matches!(p, "export" | "resume"))
    );
    let temporary = phase.is_none().then(|| tempfile::tempdir().unwrap());
    let directory = match &temporary {
        Some(directory) => directory.path().to_owned(),
        None => PathBuf::from(std::env::var_os("JETSTREAMER_PRESSURE_NATIVE_DIRECTORY").unwrap()),
    };
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        if phase.as_deref() == Some("export") {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
        } else if temporary.is_some() {
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_eq!(directory.canonicalize().unwrap(), directory);
        let metadata = fs::symlink_metadata(&directory).unwrap();
        assert!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
        );
    }
    let accounts_hash: [u8; 32] = boundary.accounts_hash.clone().try_into().unwrap();
    assert_eq!(baseline_export.slot, boundary.slot);
    let profile = crate::historical::WorkerProfile {
        backend_id: "synthetic-v1.7.15-checkpoint-ipc-fixture",
        required_genesis_hash: Box::leak(genesis_hash.into_boxed_str()),
        ..crate::historical::SOLANA_V1_7_15_CANDIDATE
    };
    let (export, resume_guard) = if phase.as_deref() == Some("resume") {
        read_exited_native_bundle(&directory, &boundary, &terminal, epoch_aligned)
    } else {
        (
            export_from_pressure_notifiers(
                &input,
                &launcher,
                profile,
                &bootstrap,
                &prefix_entries,
                &boundary,
                &terminal,
                &directory,
            ),
            None,
        )
    };
    if phase.as_deref() == Some("export") {
        eprintln!(
            "native producer published authentic paused-v3 bundle; source worker reaped; exiting before resume"
        );
        return;
    }
    let snapshot = export.archive_path.clone();
    let worker_sha: [u8; 32] = Sha256::digest(fs::read(&launcher).unwrap()).into();
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
                    expected_archive_sha256: Some(export.archive_sha256),
                    expected_archive_size: Some(export.archive_size),
                    scratch_parent: Some(directory.clone()),
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
    let trust = if let Some(proof) = &resume_guard {
        use crate::checkpoint_continuation::RestartProof;
        assert!(proof.restored_verification().is_err());
        proof
            .verify_native_checkpoint(
                &actual,
                worker_sha,
                client.initialized().next_write_version,
                client.initialized().ticks_per_slot,
            )
            .unwrap();
        proof.restored_verification().unwrap()
    } else {
        RestoredCheckpointTrust::LocalBootstrapWithCanonicalTerminal(terminal.slot)
    };
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
    if let Some(proof) = &resume_guard {
        proof.require_terminal(Some(&verifier)).unwrap();
    }
    let failure = Arc::new(ReplayFailure::new(shutdown.clone()));
    let replay = Arc::new(
        HistoricalReplay::from_restored_checkpoint(
            client,
            HistoricalCheckpointSummary::try_from(&actual).unwrap(),
            verifier.clone(),
            failure.clone(),
            Arc::new(ReplayCursor::new()),
            Arc::new(ReplayProgress::new(boundary.slot + 1)),
            boundary.slot + 1,
            trust,
        )
        .unwrap(),
    );
    assert!(verifier.finish().is_err());
    if resume_guard.is_some() {
        source_suffix::record(
            &directory,
            &boundary,
            &terminal,
            &entries,
            &replay,
            shutdown,
            failure.clone(),
        );
    } else {
        let mut transaction_index = 0;
        for entry in entries {
            let txs = entry
                .transactions
                .iter()
                .map(|bytes| {
                    let legacy: solana_transaction::Transaction =
                        bincode::deserialize(bytes).unwrap();
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
    if let Some(proof) = &resume_guard {
        source_suffix::assemble(&directory, &export, &evidence, proof);
    }
    let outcome = replay.shutdown_for_checkpoint().unwrap();
    assert!(outcome.worker_reap_verified());
    eprintln!(
        "native pressure integration: production notifiers selected a queued complete block; scheduler drained through native execution; prefix recorded/converted; snapshot exported and source worker reaped; fresh worker executed suffix and consumed exact future terminal; HTTP CAR source=true; full controller/mainnet qualification=false"
    );
}

/// Drive the real HTTP CAR decoder and node callbacks from the sealed synthetic transcript.
/// The consumer starts only after selection, proving queued native work survives
/// pressure. The mirror supplies a synthetic chain, never mainnet source authority.
#[allow(clippy::too_many_arguments)]
fn export_from_pressure_notifiers(
    input: &std::path::Path,
    launcher: &std::path::Path,
    profile: crate::historical::WorkerProfile,
    bootstrap: &Checkpoint,
    prefix_entries: &[EntryRequest],
    boundary: &Checkpoint,
    terminal: &Checkpoint,
    directory: &std::path::Path,
) -> crate::historical::HistoricalSnapshotExport {
    use crate::*;
    let _serial = source_checkpoint::SIGNAL_TEST_LOCK.lock().unwrap();
    let _signal = source_checkpoint::SignalGuard::install().unwrap();
    let prefix = prefix_entries.first().unwrap();
    for (index, entry) in prefix_entries.iter().enumerate() {
        assert_eq!(entry.slot, prefix.slot);
        assert_eq!(entry.entry_index, index as u64);
    }
    assert_eq!(bootstrap.slot + 1, prefix.slot);
    assert_eq!(
        (boundary.slot, terminal.slot),
        (prefix.slot, prefix.slot + 1)
    );
    let epoch = prefix.slot / 432_000;
    let initial = directory.join(format!(
        "snapshot-{}-{}.tar.bz2",
        bootstrap.slot,
        Hash::new_from_array(bootstrap.accounts_hash.clone().try_into().unwrap())
    ));
    fs::copy(input.join("native-bootstrap.tar.bz2"), &initial).unwrap();
    let client = HistoricalRuntimeClient::spawn(
        profile,
        historical::WorkerSpawn {
            executable: launcher.into(),
            initialization: historical::HistoricalInitialization::SnapshotArchive(
                historical::SnapshotInitialization {
                    ledger_path: input.into(),
                    archive_path: initial.clone(),
                    expected_slot: bootstrap.slot,
                    expected_accounts_hash: bootstrap.accounts_hash.clone().try_into().unwrap(),
                    expected_archive_sha256: Some(
                        Sha256::digest(fs::read(&initial).unwrap()).into(),
                    ),
                    expected_archive_size: Some(fs::metadata(&initial).unwrap().len()),
                    scratch_parent: Some(directory.into()),
                },
            ),
        },
    )
    .unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let failure = Arc::new(ReplayFailure::new(shutdown.clone()));
    let progress = Arc::new(ReplayProgress::new(prefix.slot));
    let verifier = Arc::new(SnapshotVerifier::new(
        BTreeMap::from([
            (
                bootstrap.slot,
                BankHashExpectation::LegacyAccountsHash(Hash::new_from_array(
                    bootstrap.accounts_hash.clone().try_into().unwrap(),
                )),
            ),
            (
                terminal.slot,
                BankHashExpectation::LegacyAccountsHash(Hash::new_from_array(
                    terminal.accounts_hash.clone().try_into().unwrap(),
                )),
            ),
        ]),
        None,
    ));
    let replay = Arc::new(
        HistoricalReplay::new(
            client,
            Some(verifier.clone()),
            failure.clone(),
            Arc::new(ReplayCursor::new()),
            progress.clone(),
            prefix.slot,
        )
        .unwrap(),
    );
    let presence = Arc::new(SlotPresenceMap {
        start: prefix.slot,
        end_inclusive: terminal.slot,
        states: vec![SlotPresenceState::Present; 2],
        next_present_after: vec![None; 2],
    });
    let source = directory.join("closed-source.jet");
    let provenance = jetstreamer_horizon::archive::ArchiveProvenanceV2 {
        base: jetstreamer_horizon::archive::ArchiveProvenanceV1 {
            generation_profile: "synthetic/pressure-notifier-native-v1".into(),
            runtime_profile: "solana-v1.7.15".into(),
            runtime_admission: jetstreamer_horizon::archive::RuntimeAdmission::Candidate,
            runtime_revision: profile.solana_commit.into(),
            runtime_toolchain: "sealed-native-test-image".into(),
            genesis_hash: profile.required_genesis_hash.parse().unwrap(),
            bootstrap_state_kind: jetstreamer_horizon::archive::BootstrapStateKind::SnapshotArchive,
            bootstrap_slot: bootstrap.slot,
            bootstrap_state_hash: Hash::new_from_array(
                bootstrap.accounts_hash.clone().try_into().unwrap(),
            ),
            requested_slot_start: prefix.slot,
            requested_slot_count: 2,
            transaction_metadata: archive_transaction_metadata_policy(prefix.slot, 2),
        },
        worker_executable_sha256: Sha256::digest(fs::read(launcher).unwrap()).into(),
    };
    let runtime = jetstreamer_node::segment_manifest::SegmentRuntimeIdentity {
        generation_profile: provenance.base.generation_profile.clone(),
        runtime_profile: provenance.base.runtime_profile.clone(),
        runtime_admission: jetstreamer_node::segment_manifest::SegmentRuntimeAdmission::Candidate,
        runtime_revision: provenance.base.runtime_revision.clone(),
        runtime_toolchain: provenance.base.runtime_toolchain.clone(),
        runtime_target: profile.target.into(),
        genesis_hash: provenance.base.genesis_hash.to_string(),
    };
    let worker_sha = provenance.worker_executable_sha256;
    horizon::init(
        &source,
        epoch,
        prefix.slot,
        2,
        presence.clone(),
        &provenance.into(),
        Some((
            bootstrap.slot,
            Hash::new_from_array(bootstrap.last_blockhash.clone().try_into().unwrap()),
        )),
    )
    .unwrap();
    let scheduler = Arc::new(TransactionScheduler::new(
        prefix.slot,
        presence,
        Arc::new(RestartTracker::new()),
        0,
    ));
    let checkpoint_boundary =
        Arc::new(source_checkpoint::Boundary::new(prefix.slot, terminal.slot).unwrap());
    let (sender, receiver) = crossbeam_channel::bounded(prefix_entries.len() + 1);
    let gate = Arc::new(Mutex::new(()));
    let active = Arc::new(Mutex::new(None));
    let backpressure = Arc::new(AtomicBool::new(false));
    let producers = ReplayReadyEntryProducers {
        transaction: Arc::new(BankTransactionNotifier {
            progress: progress.clone(),
            scheduler: scheduler.clone(),
            failure: failure.clone(),
            ready_sender: sender.clone(),
            shutdown: shutdown.clone(),
            active_firehose_stop: active.clone(),
            backpressure_stop_requested: backpressure.clone(),
            firehose_backpressure_slot_gap_limit: 100,
            firehose_gate: gate.clone(),
        }),
        entry: Arc::new(BankEntryNotifier {
            progress: progress.clone(),
            scheduler: scheduler.clone(),
            failure: failure.clone(),
            ready_sender: sender.clone(),
            shutdown: shutdown.clone(),
            active_firehose_stop: active.clone(),
            backpressure_stop_requested: backpressure.clone(),
            firehose_backpressure_slot_gap_limit: 100,
            firehose_gate: gate.clone(),
        }),
        block_parent: Arc::new(BankBlockParentNotifier {
            scheduler: scheduler.clone(),
            failure: failure.clone(),
            ready_sender: sender.clone(),
            firehose_gate: gate.clone(),
            checkpoint_boundary: Some(checkpoint_boundary.clone()),
        }),
        block_metadata: Arc::new(BankBlockMetadataNotifier {
            scheduler: scheduler.clone(),
            progress,
            failure: failure.clone(),
            ready_sender: sender.clone(),
            live_start_slot: prefix.slot,
            shutdown: shutdown.clone(),
            active_firehose_stop: active,
            backpressure_stop_requested: backpressure,
            firehose_backpressure_slot_gap_limit: 100,
            firehose_gate: gate,
        }),
    };
    let notifiers = producers.geyser_notifiers();
    let completed = source_car::deliver(bootstrap, prefix_entries, &producers, shutdown.clone());
    assert_eq!(
        completed,
        jetstreamer_firehose::source_quiescence::CompletedSourceBlock {
            slot: prefix.slot,
            parent_slot: bootstrap.slot,
            blockhash: boundary.last_blockhash.clone().try_into().unwrap(),
            entries: prefix_entries.len() as u64,
            transactions: prefix_entries
                .iter()
                .map(|entry| entry.transactions.len() as u64)
                .sum(),
        }
    );
    checkpoint_boundary.verify(completed).unwrap();
    assert!(
        !receiver.is_empty(),
        "native work must still be queued at selection"
    );
    assert!(!shutdown.load(Ordering::SeqCst));
    assert!(
        failure.error_message().is_none(),
        "{:?}",
        failure.error_message()
    );
    send_ready_entries(&sender, &failure, scheduler.drain_ready_entries().unwrap());
    let consumer = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn({
            let replay = replay.clone();
            let failure = failure.clone();
            let shutdown = shutdown.clone();
            move || {
                ready_entry_drain::consume(
                    receiver,
                    &shutdown,
                    |entries| {
                        replay.process_ready_entries(entries);
                        failure.error_message().map_or(Ok(()), Err)
                    },
                    |_, _| {},
                )
            }
        })
        .unwrap();
    let drained = ready_entry_drain::close(notifiers, producers, sender, consumer).unwrap();
    assert_eq!(drained.entries, prefix_entries.len() as u64);
    scheduler.verify_complete(boundary.slot).unwrap();
    assert!(scheduler.verify_complete(terminal.slot).is_err());
    replay.freeze_latest_bank().unwrap();
    let before = replay.evidence().unwrap();
    assert_eq!(before.terminal.slot, boundary.slot);
    assert_eq!(before.terminal.bank_hash.as_slice(), boundary.bank_hash);
    assert_eq!(
        before.terminal.accounts_hash.as_slice(),
        boundary.accounts_hash
    );
    assert_eq!(before.terminal.last_blockhash, completed.blockhash);
    assert_eq!(
        before.terminal.transaction_count,
        boundary.transaction_count
    );
    assert!(before.terminal.slot_complete);
    assert!(
        verifier.finish().is_err(),
        "pause cannot discharge future terminal"
    );
    let checkpoint =
        runtime_checkpoint_from_manifest(&segment_checkpoint_summary(&before.terminal)).unwrap();
    horizon::close_checkpoint_prefix_source(&checkpoint).unwrap();
    let export_directory = directory.join("export");
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&export_directory)
            .unwrap();
    }
    let exported = replay
        .export_snapshot(
            boundary.slot,
            &export_directory,
            boundary.accounts_hash.clone().try_into().unwrap(),
            ".tar.bz2",
        )
        .unwrap();
    replay.freeze_latest_bank().unwrap();
    checkpoint_export::validate_checkpoint_export_evidence(&before, &replay.evidence().unwrap())
        .unwrap();
    let worker_shutdown = replay.shutdown_for_checkpoint().unwrap();
    assert!(worker_shutdown.worker_reap_verified());
    let request = || qualification_checkpoint_pause::PausedCheckpoint {
        epoch,
        output_slot_start: prefix.slot,
        end_inclusive: terminal.slot,
        boundary: completed,
        horizon_output: &source,
        directory: &export_directory,
        evidence: &before,
        snapshot: &exported,
        worker_shutdown,
        runtime: runtime.clone(),
        worker_sha,
        bootstrap_archive_sha256: Some(Sha256::digest(fs::read(&initial).unwrap()).into()),
    };
    // Bad tuple and previously closed clients fail before creating any bundle.
    let mut invalid = request();
    invalid.boundary.blockhash[0] ^= 1;
    assert!(
        qualification_checkpoint_pause::publish(invalid)
            .unwrap_err()
            .contains("differ from source")
    );
    let mut invalid = request();
    invalid.worker_shutdown = historical::HistoricalShutdownOutcome::AlreadyClosed;
    assert!(
        qualification_checkpoint_pause::publish(invalid)
            .unwrap_err()
            .contains("before ordered")
    );
    assert!(!export_directory.join("validated-prefix").exists());
    let report = qualification_checkpoint_pause::publish(request()).unwrap();
    assert_eq!(report["verified_prefix"]["segment"]["output_slot_count"], 1);
    assert_eq!(report["producer_pid"], std::process::id());
    assert_eq!(report["worker_reap_verified"], true);
    let report_path = export_directory.join("paused.json");
    let bytes = fs::read(&report_path).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        report
    );
    assert!(qualification_checkpoint_pause::publish(request()).is_err());
    assert_eq!(
        fs::read(&report_path).unwrap(),
        bytes,
        "duplicate finalization must not overwrite evidence"
    );
    assert!(failure.error_message().is_none());
    exported
}

/// Fresh-parent fixture consumes actual process/cgroup proof and deeply rereads
/// the authentic production bundle. It intentionally does not waive the private
/// resume CLI's epoch-wide scope for this synthetic slots-1/2 fixture.
fn read_exited_native_bundle(
    directory: &std::path::Path,
    boundary: &Checkpoint,
    terminal: &Checkpoint,
    epoch_aligned: bool,
) -> (
    crate::historical::HistoricalSnapshotExport,
    Option<crate::qualification_checkpoint_resume::ValidatedResume>,
) {
    use crate::checkpoint_continuation::{Evidence, sealed_bytes};
    let report_binding = Evidence {
        path: std::env::var_os("JETSTREAMER_PRESSURE_NATIVE_REPORT")
            .unwrap()
            .into(),
        sha256: std::env::var("JETSTREAMER_PRESSURE_NATIVE_REPORT_SHA256").unwrap(),
    };
    let bytes = sealed_bytes(&report_binding, 4 << 20).unwrap();
    assert_eq!(
        bytes,
        fs::read(directory.join("export/paused.json")).unwrap()
    );
    let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let proof = Evidence {
        path: std::env::var_os("JETSTREAMER_PRESSURE_NATIVE_EXIT_PROOF")
            .unwrap()
            .into(),
        sha256: std::env::var("JETSTREAMER_PRESSURE_NATIVE_EXIT_PROOF_SHA256").unwrap(),
    };
    let epoch = boundary.slot / 432_000;
    crate::qualification_checkpoint_exit::load(&proof, &report, &report_binding.sha256, epoch)
        .unwrap();
    let pid = report["producer_pid"].as_u64().unwrap();
    assert_ne!(pid, u64::from(std::process::id()));
    assert!(
        unsafe { libc::kill(i32::try_from(pid).unwrap(), 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    );
    let prefix = PathBuf::from(report["verified_prefix"]["path"].as_str().unwrap());
    let snapshot = PathBuf::from(report["snapshot"]["path"].as_str().unwrap());
    assert_eq!(prefix, directory.join("export/validated-prefix/prefix.jet"));
    assert_eq!(snapshot.parent().unwrap(), directory.join("export"));
    let (segment, manifest) =
        jetstreamer_node::checkpoint_bundle::read_and_validate_checkpoint_bundle(
            &prefix, &snapshot,
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(&segment).unwrap(),
        report["verified_prefix"]["segment"]
    );
    assert_eq!(
        serde_json::to_value(manifest.archive_sha256).unwrap(),
        report["snapshot"]["sha256"]
    );
    assert_eq!(
        manifest.archive_size,
        report["snapshot"]["length"].as_u64().unwrap()
    );
    assert_eq!(segment.terminal.slot, boundary.slot);
    assert_eq!(report["intended_terminal_slot"], terminal.slot);
    for field in [
        "full_range_completed",
        "resource_release_authorized",
        "resume_authorized",
        "publication_authorized",
    ] {
        assert_eq!(report[field], false);
    }
    eprintln!(
        "fresh native parent consumed authentic paused bundle and qualified producer/cgroup exit proof; producer_pid={pid} current_parent_pid={}",
        std::process::id()
    );
    let guard = if epoch_aligned {
        let q = crate::QualificationPlan {
            epoch,
            bootstrap_slot: boundary.slot,
            replay_start: boundary.slot + 1,
            output_slot_start: boundary.slot + 1,
            end_inclusive: terminal.slot,
        };
        let suffix = directory.join("suffix.jet");
        assert!(
            crate::qualification_checkpoint_resume::ValidatedResume::load(
                &report_binding.path,
                &report_binding.sha256,
                proof.clone(),
                crate::QualificationPlan {
                    output_slot_start: q.output_slot_start + 1,
                    ..q
                },
                &snapshot,
                &suffix
            )
            .is_err()
        );
        let guard = crate::qualification_checkpoint_resume::ValidatedResume::load(
            &report_binding.path,
            &report_binding.sha256,
            proof,
            q,
            &snapshot,
            &suffix,
        )
        .unwrap();
        guard
            .validate_bootstrap_expectation(
                q,
                &snapshot,
                crate::BankHashExpectation::LegacyAccountsHash(Hash::new_from_array(
                    boundary.accounts_hash.clone().try_into().unwrap(),
                )),
            )
            .unwrap();
        eprintln!(
            "actual ValidatedResume::load passed with native epoch-boundary prefix; wrong suffix scope rejected; synthetic roots only"
        );
        Some(guard)
    } else {
        None
    };
    (
        crate::historical::HistoricalSnapshotExport {
            slot: manifest.snapshot_slot,
            archive_path: snapshot,
            accounts_hash: manifest.accounts_hash.parse::<Hash>().unwrap().to_bytes(),
            archive_size: manifest.archive_size,
            archive_sha256: manifest.archive_sha256,
        },
        guard,
    )
}
