// Included only inside runtime::tests. Synthetic setup never enters production Initialize.
fn native_export_ready() -> (RuntimeState, std::path::PathBuf, Checkpoint) {
    use std::os::unix::fs::PermissionsExt;
    let (mut state, _) = test_state(1, Some(1));
    let tick = request_for(&state, 0, 0, 1, &[]);
    state.process_entry(tick).unwrap();
    let checkpoint = state.freeze_checkpoint(0).unwrap();
    // Keep all exported/failed artifacts for the separately admitted test caller.
    let output = tempfile::Builder::new()
        .prefix("native-export-unit-")
        .tempdir()
        .unwrap()
        .into_path();
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
    (state, output, checkpoint)
}

#[test]
fn native_export_requires_one_use_full_checkpoint_and_preserves_cursor() {
    let (mut state, output, checkpoint) = native_export_ready();
    let before = state.export_tuple();
    let exported = state
        .export_snapshot(0, output.to_str().unwrap(), &checkpoint.accounts_hash)
        .unwrap();
    assert_eq!(state.export_tuple(), before);
    assert_eq!(
        state.bank.accounts().accounts_db.next_write_version(),
        checkpoint.next_write_version
    );
    assert_eq!(exported.slot, 0);
    assert_eq!(exported.accounts_hash, checkpoint.accounts_hash);
    assert_eq!(
        std::fs::metadata(&exported.archive_path).unwrap().len(),
        exported.archive_size
    );
    let original = std::fs::read(&exported.archive_path).unwrap();
    assert!(state
        .export_snapshot(0, output.to_str().unwrap(), &checkpoint.accounts_hash)
        .unwrap_err()
        .contains("immediately preceding"));
    let again = state.freeze_checkpoint(0).unwrap();
    assert!(again.writes.is_empty());
    assert!(state
        .export_snapshot(0, output.to_str().unwrap(), &checkpoint.accounts_hash)
        .unwrap_err()
        .contains("replace"));
    assert!(state.snapshot_export_seal.is_none());
    assert_eq!(std::fs::read(&exported.archive_path).unwrap(), original);
}

#[test]
fn native_export_argument_and_io_failures_consume_seal() {
    for case in 0..4 {
        let (mut state, output, checkpoint) = native_export_ready();
        let (slot, hash, path) = match case {
            0 => (1, checkpoint.accounts_hash.clone(), output.clone()),
            1 => (0, vec![0; 31], output.clone()),
            2 => (0, vec![0; 32], output.clone()),
            _ => (0, checkpoint.accounts_hash.clone(), output.join("missing")),
        };
        assert!(state
            .export_snapshot(slot, path.to_str().unwrap(), &hash)
            .is_err());
        assert!(state.snapshot_export_seal.is_none());
        assert!(state
            .export_snapshot(0, output.to_str().unwrap(), &checkpoint.accounts_hash)
            .unwrap_err()
            .contains("immediately preceding"));
    }
}

#[test]
fn native_export_changed_raw_cursor_tuple_cache_and_pending_hashes_fail_closed() {
    for case in 0..4 {
        let (mut state, output, checkpoint) = native_export_ready();
        match case {
            0 => state.write_cursor += 1,
            1 => {
                state
                    .snapshot_export_seal
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .tuple
                    .transaction_count += 1
            }
            2 => state.tick_hash_count = 1,
            _ => state.bank.src.status_cache.write().unwrap().add_root(99),
        }
        assert!(state
            .export_snapshot(0, output.to_str().unwrap(), &checkpoint.accounts_hash)
            .is_err());
        assert!(state.snapshot_export_seal.is_none());
        assert!(std::fs::read_dir(&output).unwrap().next().is_none());
    }
}

#[test]
fn native_export_failed_freeze_and_batch_emission_clear_old_seal() {
    let (mut state, output, checkpoint) = native_export_ready();
    assert!(state.freeze_checkpoint(1).is_err());
    assert!(state.snapshot_export_seal.is_none());
    state.freeze_checkpoint(0).unwrap();
    assert!(state.process_entries(Vec::new()).is_err());
    assert!(state.snapshot_export_seal.is_none());
    state.freeze_checkpoint(0).unwrap();
    let request = request_for(&state, 1, 0, 1, &[]);
    assert!(matches!(
        state.process_entries_with(vec![request], |_| Err::<(), ()>(())),
        Err(ProcessEntriesError::Emit(()))
    ));
    assert!(state.snapshot_export_seal.is_none());
    assert!(state
        .export_snapshot(0, output.to_str().unwrap(), &checkpoint.accounts_hash)
        .is_err());
}

#[test]
#[cfg(not(any(
    feature = "epoch140-snapshot-clock-diagnostic",
    feature = "epoch144-snapshot-clock-diagnostic",
    feature = "epoch140-original-bootstrap-clock-diagnostic"
)))]
fn native_export_real_dispatch_invalidates_on_ping_and_streaming_error() {
    use jetstreamer_historical_protocol::{Request, RequestBody, ResponseBody};
    let (state, output, checkpoint) = native_export_ready();
    let mut worker = crate::Worker {
        hello_complete: true,
        state: Some(state),
    };
    let (ping, stop) = worker.handle(Request {
        id: 1,
        body: RequestBody::Ping,
    });
    assert!(!stop);
    assert!(matches!(ping.body, ResponseBody::Pong));
    let (response, stop) = worker.handle(Request {
        id: 2,
        body: RequestBody::ExportSnapshot {
            slot: 0,
            output_directory: output.to_str().unwrap().into(),
            expected_accounts_hash: checkpoint.accounts_hash.clone(),
        },
    });
    assert!(!stop);
    assert!(matches!(response.body, ResponseBody::Error(_)));
    let (frozen, stop) = worker.handle(Request {
        id: 3,
        body: RequestBody::FreezeCheckpoint { slot: 0 },
    });
    assert!(!stop);
    assert!(matches!(frozen.body, ResponseBody::Checkpoint(_)));
    let mut bytes = Vec::new();
    assert!(worker
        .process_entry_batch(4, Vec::new(), &mut bytes)
        .unwrap());
    assert!(worker
        .state
        .as_ref()
        .unwrap()
        .snapshot_export_seal
        .is_none());
    assert!(!bytes.is_empty());
}

#[test]
fn native_export_private_output_and_existing_alias_fail_without_clobber() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (mut state, output, checkpoint) = native_export_ready();
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(state
        .export_snapshot(0, output.to_str().unwrap(), &checkpoint.accounts_hash)
        .is_err());
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
    state.freeze_checkpoint(0).unwrap();
    let target = output.join("keep");
    std::fs::write(&target, b"existing").unwrap();
    let archive = output.join(format!(
        "snapshot-0-{}.tar.bz2",
        Hash::new(&checkpoint.accounts_hash)
    ));
    symlink(&target, &archive).unwrap();
    assert!(state
        .export_snapshot(0, output.to_str().unwrap(), &checkpoint.accounts_hash)
        .is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"existing");
    assert!(std::fs::symlink_metadata(&archive)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn native_export_prepublication_failure_and_collision_retain_staging() {
    for late_collision in &[false, true] {
        let (state, output, checkpoint) = native_export_ready();
        let final_path = output.join(format!(
            "snapshot-0-{}.tar.bz2",
            Hash::new(&checkpoint.accounts_hash)
        ));
        let mut calls = 0;
        let error = snapshot::export_archive(
            &state.bank,
            &output,
            Hash::new(&checkpoint.accounts_hash),
            || {
                calls += 1;
                if calls > 1 {
                    if *late_collision {
                        std::fs::write(&final_path, b"late-existing-file").unwrap();
                    } else {
                        return Err("injected seal mismatch before publication".into());
                    }
                }
                Ok(())
            },
        )
        .err()
        .expect("late failure must not publish a successful export");
        assert!(error.contains("retained native export evidence"));
        let stages: Vec<_> = std::fs::read_dir(&output)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("jetstreamer-native-export-")
            })
            .collect();
        assert_eq!(stages.len(), 1);
        assert!(stages[0].join("archive.part").is_file());
        assert!(stages[0].join("export-manifest.bin").is_file());
        if *late_collision {
            assert_eq!(std::fs::read(&final_path).unwrap(), b"late-existing-file");
        } else {
            assert!(!final_path.exists());
        }
    }
}

#[test]
fn native_export_ineligible_cache_does_not_discard_checkpoint_response() {
    let (mut state, output, _) = native_export_ready();
    state.bank.src.status_cache.write().unwrap().add_root(99);
    let checkpoint = state
        .freeze_checkpoint(0)
        .expect("export eligibility must not lose drained checkpoint writes");
    assert_eq!(checkpoint.next_write_version, state.write_cursor);
    assert_eq!(
        checkpoint.next_write_version,
        state.bank.accounts().accounts_db.next_write_version()
    );
    assert!(state.snapshot_export_seal.as_ref().unwrap().is_err());
    assert!(state
        .export_snapshot(0, output.to_str().unwrap(), &checkpoint.accounts_hash)
        .unwrap_err()
        .contains("rooted status cache"));
    assert!(state.snapshot_export_seal.is_none());
    assert!(std::fs::read_dir(&output).unwrap().next().is_none());
}
