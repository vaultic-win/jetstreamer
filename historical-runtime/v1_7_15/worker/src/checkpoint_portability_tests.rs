// Included only in runtime::tests. Synthetic evidence is not mainnet qualification.
#[test]
#[ignore]
fn isolated_native_checkpoint_archive_restore_probe() {
    checkpoint_archive_restore_probe(false);
}

#[test]
#[ignore]
fn checkpoint_export_archive_restore_probe() {
    checkpoint_archive_restore_probe(true);
}

#[test]
#[ignore]
fn checkpoint_export_recorder_transcript_probe() {
    assert!(std::env::var_os("JETSTREAMER_CHECKPOINT_TRANSCRIPT_ROOT").is_some());
    checkpoint_archive_restore_probe(true);
}

fn checkpoint_archive_restore_probe(use_export: bool) {
    checkpoint_archive_restore_probe_with_prefix(use_export, false, false);
}

#[test]
#[ignore]
fn checkpoint_export_pressure_transcript_probe() {
    assert!(std::env::var_os("JETSTREAMER_CHECKPOINT_TRANSCRIPT_ROOT").is_some());
    assert!(std::env::var_os("JETSTREAMER_CHECKPOINT_LIVE_FIXTURE").is_some());
    checkpoint_archive_restore_probe_with_prefix(true, true, false);
}

#[test]
#[ignore]
fn checkpoint_export_epoch_pressure_transcript_probe() {
    assert!(std::env::var_os("JETSTREAMER_CHECKPOINT_TRANSCRIPT_ROOT").is_some());
    assert!(std::env::var_os("JETSTREAMER_CHECKPOINT_LIVE_FIXTURE").is_some());
    checkpoint_archive_restore_probe_with_prefix(true, true, true);
}

fn checkpoint_archive_restore_probe_with_prefix(
    use_export: bool,
    transaction_prefix: bool,
    epoch_aligned: bool,
) {
    use solana_runtime::{bank_forks::ArchiveFormat, snapshot_utils};
    const CHILD: &str = "JETSTREAMER_V1715_CHECKPOINT_PROBE_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let path = std::path::PathBuf::from(path);
        let (genesis, archive, entries): (GenesisConfig, std::path::PathBuf, Vec<EntryRequest>) =
            bincode::deserialize(&std::fs::read(path.join("input.bin")).unwrap()).unwrap();
        let directory = snapshot::private_state_dir(None).unwrap();
        let loaded = snapshot::load_archive(
            &archive,
            &directory,
            &genesis,
            &Builtins {
                genesis_builtins: Vec::new(),
                feature_builtins: Vec::new(),
            },
        )
        .unwrap();
        let mut state = RuntimeState::from_test_bank(loaded.bank, false, directory);
        let restored_bootstrap = state.freeze_checkpoint(state.bank.slot()).unwrap();
        let terminal_slot = entries.last().unwrap().slot;
        let processed = entries
            .into_iter()
            .map(|entry| state.process_entry(entry).unwrap())
            .collect::<Vec<_>>();
        let checkpoint = state.freeze_checkpoint(terminal_slot).unwrap();
        std::fs::write(
            path.join("output.bin"),
            bincode::serialize(&(
                std::process::id(),
                restored_bootstrap,
                processed,
                checkpoint,
            ))
            .unwrap(),
        )
        .unwrap();
        return;
    }

    let leader = Pubkey::new_from_array([7; 32]);
    let mut genesis = create_genesis_config_with_leader(1_000_000, &leader, 500_000);
    let bootstrap_slot = if epoch_aligned { 431_999 } else { 0 };
    let prefix_slot = bootstrap_slot + 1;
    let terminal_slot = prefix_slot + 1;
    let ticks = if epoch_aligned { 64 } else { 1 };
    genesis.genesis_config.ticks_per_slot = ticks;
    genesis.genesis_config.poh_config.hashes_per_tick = None;
    if epoch_aligned {
        // The HTTP fixture uses fixed 432000-slot epochs. A warmup schedule
        // would jump across uninitialized native epoch vote-account caches.
        genesis.genesis_config.epoch_schedule =
            solana_sdk::epoch_schedule::EpochSchedule::custom(432_000, 432_000, false);
    }
    let source_dir = snapshot::private_state_dir(None).unwrap();
    let original_source_path = source_dir.path().to_path_buf();
    let bank0 = Bank::new_with_paths(
        &genesis.genesis_config,
        snapshot::private_account_paths(&source_dir).unwrap(),
        &[],
        None,
        None,
        AccountSecondaryIndexes::default(),
        false,
        AccountShrinkThreshold::default(),
        false,
    );
    for _ in 0..ticks {
        bank0.register_tick(&Hash::new_unique());
    }
    bank0.freeze();
    let initial = if epoch_aligned {
        let bank = Bank::new_from_parent(&Arc::new(bank0), &leader, bootstrap_slot);
        // Advance through the native clock; never edit serialized bank state or
        // claim this synthetic bootstrap is a mainnet root.
        while !bank.is_complete() {
            bank.register_tick(&Hash::new_unique());
        }
        bank.freeze();
        bank
    } else {
        bank0
    };
    let mut uninterrupted = RuntimeState::from_test_bank(initial, false, source_dir);
    let bootstrap = uninterrupted.freeze_checkpoint(bootstrap_slot).unwrap();
    // Optional test-only initial snapshot for the live parent IPC fixture.
    // Keep it distinct from the exported slot-1 checkpoint being qualified.
    let bootstrap_archives = tempfile::tempdir().unwrap();
    let bootstrap_export = if std::env::var_os("JETSTREAMER_CHECKPOINT_LIVE_FIXTURE").is_some() {
        Some(
            uninterrupted
                .export_snapshot(
                    bootstrap_slot,
                    bootstrap_archives.path().to_str().unwrap(),
                    &bootstrap.accounts_hash,
                )
                .unwrap(),
        )
    } else {
        None
    };
    let mut prefix_entries = Vec::new();
    let mut prefix_results = Vec::new();
    if transaction_prefix {
        let recipient = Keypair::new();
        let transaction = system_transaction::transfer(
            &genesis.mint_keypair,
            &recipient.pubkey(),
            17,
            uninterrupted.bank.last_blockhash(),
        );
        let entry = request_for(&uninterrupted, prefix_slot, 0, 1, &[transaction]);
        let result = uninterrupted.process_entry(entry.clone()).unwrap();
        assert_eq!(result.outcomes.len(), 1);
        assert_eq!(result.outcomes[0].error, None);
        assert_eq!(uninterrupted.bank.get_balance(&recipient.pubkey()), 17);
        prefix_entries.push(entry);
        prefix_results.push(result);
    }
    for _ in 0..ticks {
        let tick = request_for(
            &uninterrupted,
            prefix_slot,
            prefix_entries.len() as u64,
            1,
            &[],
        );
        let processed = uninterrupted.process_entry(tick.clone()).unwrap();
        prefix_entries.push(tick);
        prefix_results.push(processed);
    }
    let prefix_tick = prefix_entries.last().unwrap().clone();
    let prefix_processed = prefix_results.last().unwrap().clone();

    // Bind the real worker checkpoint before serializer housekeeping. Preparing
    // hashes after housekeeping could conceal an export-induced consensus change.
    let before = uninterrupted.freeze_checkpoint(prefix_slot).unwrap();
    assert_eq!(
        before.transaction_count - bootstrap.transaction_count,
        u64::from(transaction_prefix)
    );
    let cursor = uninterrupted
        .bank
        .accounts()
        .accounts_db
        .next_write_version();
    assert_eq!(cursor, before.next_write_version);
    let staging = tempfile::tempdir().unwrap();
    let archives = tempfile::tempdir().unwrap();
    let mut export_evidence = None;
    let archive = if use_export {
        use jetstreamer_historical_protocol::{Request, RequestBody, ResponseBody};
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;
        let sentinel = archives.path().join("snapshot-unrelated.tar.bz2");
        std::fs::write(&sentinel, b"retain existing archives").unwrap();
        let mut worker = crate::Worker {
            hello_complete: true,
            state: Some(uninterrupted),
        };
        let (response, shutdown) = worker.handle(Request {
            id: 20,
            body: RequestBody::ExportSnapshot {
                slot: before.slot,
                output_directory: archives.path().to_str().unwrap().into(),
                expected_accounts_hash: before.accounts_hash.clone(),
            },
        });
        assert!(!shutdown, "export failed: {:?}", response);
        assert_eq!(response.request_id, 20);
        let exported = match response.body {
            ResponseBody::SnapshotExported(exported) => exported,
            other => panic!("unexpected export response: {:?}", other),
        };
        uninterrupted = worker.state.take().unwrap();
        let path = std::path::PathBuf::from(&exported.archive_path);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(exported.archive_size, bytes.len() as u64);
        assert_eq!(exported.archive_sha256, Sha256::digest(&bytes).as_slice());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert_eq!(exported.accounts_hash, before.accounts_hash);
        assert_eq!(exported.slot, before.slot);
        export_evidence = Some(exported);
        assert!(uninterrupted
            .export_snapshot(
                before.slot,
                archives.path().to_str().unwrap(),
                &before.accounts_hash,
            )
            .unwrap_err()
            .contains("immediately preceding"));
        uninterrupted.freeze_checkpoint(before.slot).unwrap();
        assert!(uninterrupted
            .export_snapshot(
                before.slot,
                archives.path().to_str().unwrap(),
                &before.accounts_hash,
            )
            .unwrap_err()
            .contains("refusing to replace"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            std::fs::read(sentinel).unwrap(),
            b"retain existing archives"
        );
        path
    } else {
        snapshot_utils::bank_to_snapshot_archive(
            staging.path(),
            &uninterrupted.bank,
            None,
            archives.path(),
            ArchiveFormat::TarBzip2,
            None,
            1,
        )
        .unwrap()
    };
    assert_eq!(
        uninterrupted.bank.hash().as_ref(),
        before.bank_hash.as_slice()
    );
    assert_eq!(
        uninterrupted.bank.get_accounts_hash().as_ref(),
        before.accounts_hash.as_slice()
    );
    assert_eq!(
        uninterrupted
            .bank
            .accounts()
            .accounts_db
            .next_write_version(),
        cursor
    );
    let after = uninterrupted.freeze_checkpoint(prefix_slot).unwrap();
    assert!(
        after.writes.is_empty(),
        "export introduced undelivered writes"
    );
    let mut expected_after = before.clone();
    expected_after.writes.clear();
    assert_eq!(after, expected_after);

    let restored_dir = snapshot::private_state_dir(None).unwrap();
    let loaded = snapshot::load_archive(
        &archive,
        &restored_dir,
        &genesis.genesis_config,
        &Builtins {
            genesis_builtins: Vec::new(),
            feature_builtins: Vec::new(),
        },
    )
    .unwrap();
    assert_eq!(loaded.bank.slot(), before.slot);
    assert_eq!(loaded.bank.hash().as_ref(), before.bank_hash.as_slice());
    assert_eq!(
        loaded.bank.get_accounts_hash().as_ref(),
        before.accounts_hash.as_slice()
    );
    assert_eq!(loaded.bank.capitalization(), before.capitalization);
    assert_eq!(loaded.bank.transaction_count(), before.transaction_count);
    assert_eq!(
        loaded.bank.last_blockhash().as_ref(),
        before.last_blockhash.as_slice()
    );
    assert_eq!(loaded.bank.tick_height(), before.tick_height);
    assert_eq!(
        loaded.bank.accounts().accounts_db.next_write_version(),
        cursor
    );
    assert!(loaded.bank.verify_snapshot_bank(true, false));

    let mut restored = RuntimeState::from_test_bank(loaded.bank, false, restored_dir);
    let recipient = Keypair::new();
    let transaction = system_transaction::transfer(
        &genesis.mint_keypair,
        &recipient.pubkey(),
        123,
        uninterrupted.bank.last_blockhash(),
    );
    let entry = request_for(&uninterrupted, terminal_slot, 0, 1, &[transaction]);
    let expected = uninterrupted.process_entry(entry.clone()).unwrap();
    assert_eq!(restored.process_entry(entry.clone()).unwrap(), expected);
    assert_eq!(expected.outcomes[0].error, None);
    let mut suffix_entries = vec![entry];
    let mut suffix_results = vec![expected];
    for _ in 0..ticks {
        let tick = request_for(
            &uninterrupted,
            terminal_slot,
            suffix_entries.len() as u64,
            1,
            &[],
        );
        let expected_tick = uninterrupted.process_entry(tick.clone()).unwrap();
        assert_eq!(restored.process_entry(tick.clone()).unwrap(), expected_tick);
        suffix_entries.push(tick);
        suffix_results.push(expected_tick);
    }
    let expected_checkpoint = uninterrupted.freeze_checkpoint(terminal_slot).unwrap();
    assert_eq!(
        restored.freeze_checkpoint(terminal_slot).unwrap(),
        expected_checkpoint
    );
    assert_eq!(restored.bank.get_balance(&recipient.pubkey()), 123);
    drop(uninterrupted);
    drop(restored);
    assert!(
        !original_source_path.exists(),
        "original fixture storage still exists"
    );

    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(
        fixture.path().join("input.bin"),
        bincode::serialize(&(
            genesis.genesis_config.clone(),
            archive.clone(),
            suffix_entries.clone(),
        ))
        .unwrap(),
    )
    .unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(&[
            "--ignored",
            "--exact",
            if use_export {
                "runtime::tests::checkpoint_export_archive_restore_probe"
            } else {
                "runtime::tests::isolated_native_checkpoint_archive_restore_probe"
            },
            "--nocapture",
        ])
        .env(CHILD, fixture.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "fresh-process restore failed: {} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let (pid, restored_bootstrap, processed, checkpoint): (
        u32,
        Checkpoint,
        Vec<EntryProcessed>,
        Checkpoint,
    ) = bincode::deserialize(&std::fs::read(fixture.path().join("output.bin")).unwrap()).unwrap();
    assert_ne!(pid, std::process::id());
    assert_eq!(restored_bootstrap, expected_after);
    assert_eq!(processed, suffix_results);
    assert_eq!(checkpoint, expected_checkpoint);
    if let Some(root) = std::env::var_os("JETSTREAMER_CHECKPOINT_TRANSCRIPT_ROOT") {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let root = std::path::PathBuf::from(root);
        assert!(root.is_absolute());
        assert_eq!(std::fs::canonicalize(&root).unwrap(), root);
        let metadata = std::fs::symlink_metadata(&root).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o077, 0);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        let transcript = if transaction_prefix {
            bincode::serialize(&(
                if epoch_aligned {
                    "horizon-native-pressure-recorder-transcript-v3"
                } else {
                    "horizon-native-pressure-recorder-transcript-v2"
                }
                .to_string(),
                genesis.genesis_config.hash().as_ref().to_vec(),
                bootstrap,
                prefix_entries,
                prefix_results,
                before,
                export_evidence.expect("transcript requires actual export"),
                suffix_entries,
                suffix_results,
                expected_checkpoint,
                restored_bootstrap,
                processed,
                checkpoint,
                std::process::id(),
                pid,
            ))
            .unwrap()
        } else {
            bincode::serialize(&(
                "horizon-native-checkpoint-recorder-transcript-v1".to_string(),
                genesis.genesis_config.hash().as_ref().to_vec(),
                bootstrap,
                prefix_tick,
                prefix_processed,
                before,
                export_evidence.expect("transcript requires actual export"),
                suffix_entries,
                suffix_results,
                expected_checkpoint,
                restored_bootstrap,
                processed,
                checkpoint,
                std::process::id(),
                pid,
            ))
            .unwrap()
        };
        for (name, bytes) in &[
            (
                if transaction_prefix {
                    "native-pressure-transcript.bin"
                } else {
                    "native-transcript.bin"
                },
                transcript,
            ),
            ("native-snapshot.tar.bz2", std::fs::read(&archive).unwrap()),
        ] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(root.join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        if let Some(initial) = bootstrap_export {
            for (name, bytes) in &[
                (
                    "native-genesis.bin",
                    bincode::serialize(&genesis.genesis_config).unwrap(),
                ),
                (
                    "native-bootstrap.tar.bz2",
                    std::fs::read(&initial.archive_path).unwrap(),
                ),
            ] {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o400)
                    .open(root.join(name))
                    .unwrap();
                file.write_all(bytes).unwrap();
                file.sync_all().unwrap();
            }
        }
        std::fs::File::open(root).unwrap().sync_all().unwrap();
    }
}

#[test]
fn checkpoint_export_seal_rejects_wrong_requests_and_is_consumed() {
    let (mut state, _) = test_state(1, None);
    let output = tempfile::tempdir().unwrap();
    let directory = output.path().to_str().unwrap();
    assert!(state
        .export_snapshot(0, directory, &[0; 32])
        .unwrap_err()
        .contains("immediately preceding"));
    state.bank.register_tick(&Hash::new_unique());
    for (slot, hash) in &[(1, vec![0; 32]), (0, vec![0; 31]), (0, vec![0; 32])] {
        state.freeze_checkpoint(0).unwrap();
        assert!(state
            .export_snapshot(*slot, directory, hash)
            .unwrap_err()
            .contains("differs from checkpoint"));
        assert!(state.snapshot_export_seal.is_none());
    }
    let checkpoint = state.freeze_checkpoint(0).unwrap();
    state.next_entry_index += 1;
    assert!(state
        .export_snapshot(0, directory, &checkpoint.accounts_hash)
        .is_err());
    state.freeze_checkpoint(0).unwrap();
    assert!(state.freeze_checkpoint(1).is_err());
    assert!(state.snapshot_export_seal.is_none());
    state.freeze_checkpoint(0).unwrap();
    assert!(state.process_entries(Vec::new()).is_err());
    assert!(state.snapshot_export_seal.is_none());
    assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 0);
}

#[test]
fn checkpoint_export_rejects_changed_bank_and_unsafe_output_without_publication() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (mut state, _) = test_state(1, None);
    state.bank.register_tick(&Hash::new_unique());
    let checkpoint = state.freeze_checkpoint(0).unwrap();
    let mut bad = checkpoint.clone();
    bad.next_write_version += 1;
    assert!(snapshot_export::check_bank(&state.bank, &bad).is_err());
    bad = checkpoint.clone();
    bad.bank_hash[0] ^= 1;
    assert!(snapshot_export::check_bank(&state.bank, &bad).is_err());
    let output = tempfile::tempdir().unwrap();
    let alias = output.path().join("alias");
    symlink(output.path(), &alias).unwrap();
    assert!(state
        .export_snapshot(0, alias.to_str().unwrap(), &checkpoint.accounts_hash)
        .unwrap_err()
        .contains("canonical, owned private"));
    std::fs::remove_file(alias).unwrap();
    state.freeze_checkpoint(0).unwrap();
    std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(state
        .export_snapshot(
            0,
            output.path().to_str().unwrap(),
            &checkpoint.accounts_hash
        )
        .unwrap_err()
        .contains("canonical, owned private"));
    std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let final_path = output.path().join(format!(
        "snapshot-0-{}.tar.bz2",
        Hash::new(&checkpoint.accounts_hash)
    ));
    symlink(output.path().join("missing"), &final_path).unwrap();
    state.freeze_checkpoint(0).unwrap();
    assert!(state
        .export_snapshot(
            0,
            output.path().to_str().unwrap(),
            &checkpoint.accounts_hash
        )
        .unwrap_err()
        .contains("refusing to replace"));
    assert!(std::fs::symlink_metadata(final_path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 1);
}

#[test]
fn checkpoint_export_protocol_intervening_requests_invalidate_and_fail_closed() {
    use jetstreamer_historical_protocol::{Request, RequestBody, ResponseBody, PROTOCOL_VERSION};
    let (state, _) = test_state(1, None);
    state.bank.register_tick(&Hash::new_unique());
    let mut worker = crate::Worker {
        hello_complete: true,
        state: Some(state),
    };
    for body in &[
        RequestBody::Ping,
        RequestBody::Hello {
            protocol_version: PROTOCOL_VERSION,
        },
    ] {
        let (response, stopped) = worker.handle(Request {
            id: 1,
            body: RequestBody::FreezeCheckpoint { slot: 0 },
        });
        assert!(!stopped);
        assert!(matches!(response.body, ResponseBody::Checkpoint(_)));
        assert!(worker
            .state
            .as_ref()
            .unwrap()
            .snapshot_export_seal
            .is_some());
        worker.handle(Request {
            id: 2,
            body: body.clone(),
        });
        assert!(worker
            .state
            .as_ref()
            .unwrap()
            .snapshot_export_seal
            .is_none());
    }
    let (response, stopped) = worker.handle(Request {
        id: 3,
        body: RequestBody::ExportSnapshot {
            slot: 0,
            output_directory: "/tmp".into(),
            expected_accounts_hash: vec![0; 32],
        },
    });
    assert!(stopped);
    assert!(matches!(response.body, ResponseBody::Error(_)));
    // The batch IPC path bypasses handle_body; it must still consume the seal.
    worker.handle(Request {
        id: 4,
        body: RequestBody::FreezeCheckpoint { slot: 0 },
    });
    assert!(worker
        .process_entry_batch(5, Vec::new(), &mut Vec::new())
        .unwrap());
    assert!(worker
        .state
        .as_ref()
        .unwrap()
        .snapshot_export_seal
        .is_none());
}
