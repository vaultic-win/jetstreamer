// Included only in runtime::tests. This probe does not enable protocol export.
#[test]
#[ignore]
fn isolated_native_checkpoint_archive_restore_probe() {
    use solana_runtime::{bank_forks::ArchiveFormat, snapshot_utils};
    const CHILD: &str = "JETSTREAMER_V1715_CHECKPOINT_PROBE_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let path = std::path::PathBuf::from(path);
        let (genesis, archive, entry, tick): (
            GenesisConfig,
            std::path::PathBuf,
            EntryRequest,
            EntryRequest,
        ) = bincode::deserialize(&std::fs::read(path.join("input.bin")).unwrap()).unwrap();
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
        let processed = state.process_entry(entry).unwrap();
        let ticked = state.process_entry(tick).unwrap();
        let checkpoint = state.freeze_checkpoint(2).unwrap();
        std::fs::write(
            path.join("output.bin"),
            bincode::serialize(&(std::process::id(), processed, ticked, checkpoint)).unwrap(),
        )
        .unwrap();
        return;
    }

    let leader = Pubkey::new_from_array([7; 32]);
    let mut genesis = create_genesis_config_with_leader(1_000_000, &leader, 500_000);
    genesis.genesis_config.ticks_per_slot = 1;
    genesis.genesis_config.poh_config.hashes_per_tick = None;
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
    bank0.register_tick(&Hash::new_unique());
    bank0.freeze();
    let bank = Bank::new_from_parent(&Arc::new(bank0), &leader, 1);
    bank.register_tick(&Hash::new_unique());
    let mut uninterrupted = RuntimeState::from_test_bank(bank, false, source_dir);

    // Bind the real worker checkpoint before serializer housekeeping. Preparing
    // hashes after housekeeping could conceal an export-induced consensus change.
    let before = uninterrupted.freeze_checkpoint(1).unwrap();
    let cursor = uninterrupted
        .bank
        .accounts()
        .accounts_db
        .next_write_version();
    assert_eq!(cursor, before.next_write_version);
    let staging = tempfile::tempdir().unwrap();
    let archives = tempfile::tempdir().unwrap();
    let archive = snapshot_utils::bank_to_snapshot_archive(
        staging.path(),
        &uninterrupted.bank,
        None,
        archives.path(),
        ArchiveFormat::TarBzip2,
        None,
        1,
    )
    .unwrap();
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
    let after = uninterrupted.freeze_checkpoint(1).unwrap();
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
    assert!(loaded.bank.verify_snapshot_bank());

    let mut restored = RuntimeState::from_test_bank(loaded.bank, false, restored_dir);
    let recipient = Keypair::new();
    let transaction = system_transaction::transfer(
        &genesis.mint_keypair,
        &recipient.pubkey(),
        123,
        uninterrupted.bank.last_blockhash(),
    );
    let entry = request_for(&uninterrupted, 2, 0, 1, &[transaction]);
    let expected = uninterrupted.process_entry(entry.clone()).unwrap();
    assert_eq!(restored.process_entry(entry.clone()).unwrap(), expected);
    assert_eq!(expected.outcomes[0].error, None);
    let tick = request_for(&uninterrupted, 2, 1, 1, &[]);
    let expected_tick = uninterrupted.process_entry(tick.clone()).unwrap();
    assert_eq!(restored.process_entry(tick.clone()).unwrap(), expected_tick);
    let expected_checkpoint = uninterrupted.freeze_checkpoint(2).unwrap();
    assert_eq!(restored.freeze_checkpoint(2).unwrap(), expected_checkpoint);
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
        bincode::serialize(&(genesis.genesis_config, archive, entry, tick)).unwrap(),
    )
    .unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(&[
            "--ignored",
            "--exact",
            "runtime::tests::isolated_native_checkpoint_archive_restore_probe",
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
    let (pid, processed, ticked, checkpoint): (u32, EntryProcessed, EntryProcessed, Checkpoint) =
        bincode::deserialize(&std::fs::read(fixture.path().join("output.bin")).unwrap()).unwrap();
    assert_ne!(pid, std::process::id());
    assert_eq!(processed, expected);
    assert_eq!(ticked, expected_tick);
    assert_eq!(checkpoint, expected_checkpoint);
}
