//! Live native IPC portion of the synthetic recorder qualification. It uses
//! the production client and export-evidence validator without a mainnet bypass.
#[path = "../jetstreamer-node/src/checkpoint_export.rs"]
mod checkpoint_export;
#[path = "../jetstreamer-node/src/historical.rs"]
mod historical;
use super::*;
use historical::{
    HistoricalInitialization, HistoricalRuntimeClient as Client, SnapshotInitialization,
    WorkerSpawn,
};

fn write(w: historical::HistoricalAccountWrite) -> AccountWrite {
    AccountWrite {
        slot: w.slot,
        write_version: w.write_version,
        transaction_signature: w.transaction_signature.map(|v| v.to_vec()),
        pubkey: w.pubkey.to_vec(),
        lamports: w.lamports,
        owner: w.owner.to_vec(),
        executable: w.executable,
        rent_epoch: w.rent_epoch,
        data: w.data,
        stored_hash: w.stored_hash.to_vec(),
    }
}
fn frozen(c: historical::HistoricalCheckpoint) -> Checkpoint {
    Checkpoint {
        slot: c.slot,
        bank_hash: c.bank_hash.to_vec(),
        accounts_hash: c.accounts_hash.to_vec(),
        last_blockhash: c.last_blockhash.to_vec(),
        capitalization: c.capitalization,
        transaction_count: c.transaction_count,
        tick_height: c.tick_height,
        slot_complete: c.slot_complete,
        writes: c.writes.into_iter().map(write).collect(),
        next_write_version: c.next_write_version,
    }
}
fn process(client: &mut Client, entry: &EntryRequest) -> Result<EntryProcessed> {
    let r = client.process_entry(
        entry.slot,
        entry.entry_index,
        entry.num_hashes,
        entry.hash.as_slice().try_into()?,
        entry.transactions.clone(),
    )?;
    Ok(EntryProcessed {
        slot: r.slot,
        entry_index: r.entry_index,
        tick_height: r.tick_height,
        slot_complete: r.slot_complete,
        next_write_version: r.next_write_version,
        outcomes: r
            .outcomes
            .into_iter()
            .map(|o| jetstreamer_historical_protocol::TransactionOutcome {
                signature: o.signature.map(|v| v.to_vec()),
                error: o.error,
                fee: o.fee,
            })
            .collect(),
        writes: r.writes.into_iter().map(write).collect(),
    })
}
fn summary(c: &Checkpoint) -> Result<checkpoint_export::HistoricalCheckpointSummary> {
    Ok(checkpoint_export::HistoricalCheckpointSummary {
        slot: c.slot,
        bank_hash: c.bank_hash.as_slice().try_into()?,
        accounts_hash: c.accounts_hash.as_slice().try_into()?,
        last_blockhash: c.last_blockhash.as_slice().try_into()?,
        capitalization: c.capitalization,
        transaction_count: c.transaction_count,
        tick_height: c.tick_height,
        slot_complete: c.slot_complete,
        write_count: c.writes.len().try_into()?,
        next_write_version: c.next_write_version,
    })
}

pub(super) fn run(
    input: &Path,
    output: &Path,
    image: &Path,
    launcher: &Path,
    genesis: &[u8],
    bootstrap: &Checkpoint,
    prefix: &EntryRequest,
    prefix_expected: &EntryProcessed,
    boundary: &Checkpoint,
    suffix: &[EntryRequest],
    suffix_expected: &[EntryProcessed],
    terminal: &Checkpoint,
) -> Result<SnapshotExport> {
    require(
        image
            == Path::new(
                &std::env::var_os("JETSTREAMER_CHECKPOINT_FIXTURE_IMAGE")
                    .ok_or("missing fixture image")?,
            ),
        "fixture image must equal recorded native image",
    )?;
    require(
        hex(&digest(image)?) == std::env::var("JETSTREAMER_CHECKPOINT_FIXTURE_IMAGE_SHA256")?,
        "fixture digest mismatch",
    )?;
    let genesis_path = input.join("native-genesis.bin");
    require(
        Path::new(
            &std::env::var_os("JETSTREAMER_CHECKPOINT_FIXTURE_GENESIS")
                .ok_or("missing fixture genesis")?,
        ) == genesis_path,
        "fixture genesis path mismatch",
    )?;
    let genesis_hash = hash(genesis)?;
    require(
        genesis_hash.to_string() != jetstreamer_historical_protocol::MAINNET_GENESIS_HASH,
        "synthetic fixture cannot claim mainnet",
    )?;
    let profile = historical::WorkerProfile {
        backend_id: "synthetic-v1.7.15-checkpoint-ipc-fixture",
        required_genesis_hash: Box::leak(genesis_hash.to_string().into_boxed_str()),
        ..historical::SOLANA_V1_7_15_CANDIDATE
    };
    let scratch = output.join("live-scratch");
    let parent_phase = std::env::var(checkpoint_parent_handoff::PHASE).ok();
    if parent_phase.as_deref() != Some("resume") {
        fs::create_dir(&scratch)?;
    }
    let spawn = |archive: &Path, start: &Checkpoint| -> Result<Client> {
        Ok(Client::spawn(
            profile,
            WorkerSpawn {
                executable: launcher.to_path_buf(),
                initialization: HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
                    ledger_path: input.to_path_buf(),
                    archive_path: archive.to_path_buf(),
                    expected_slot: start.slot,
                    expected_accounts_hash: start.accounts_hash.as_slice().try_into()?,
                    expected_archive_sha256: Some(digest(archive)?),
                    expected_archive_size: Some(fs::metadata(archive)?.len()),
                    scratch_parent: Some(scratch.clone()),
                }),
            },
        )?)
    };
    let (export, after) = if parent_phase.as_deref() == Some("resume") {
        let state =
            checkpoint_parent_handoff::read(input, output, launcher, image, genesis, boundary)?;
        require(
            fs::read_dir(&scratch)?.next().is_none(),
            "parent restart scratch still retained",
        )?;
        state
    } else {
        let initial_archive = output.join(format!(
            "snapshot-{}-{}.tar.bz2",
            bootstrap.slot,
            hash(&bootstrap.accounts_hash)?
        ));
        let mut initial_copy = create(&initial_archive)?;
        std::io::copy(
            &mut File::open(input.join("native-bootstrap.tar.bz2"))?,
            &mut initial_copy,
        )?;
        initial_copy.sync_all()?;
        let mut client = spawn(&initial_archive, bootstrap)?;
        require(
            client.executable_sha256() == digest(launcher)?,
            "parent launcher identity differs",
        )?;
        let initial = frozen(client.freeze_checkpoint(bootstrap.slot)?);
        let mut expected_initial = bootstrap.clone();
        expected_initial.writes.clear();
        require(
            initial == expected_initial,
            "live bootstrap differs from native baseline",
        )?;
        let prefix_result = process(&mut client, prefix)?;
        require(
            &prefix_result == prefix_expected,
            "live prefix output differs from native baseline",
        )?;
        let frozen_prefix = frozen(client.freeze_checkpoint(boundary.slot)?);
        require(&frozen_prefix == boundary, "live prefix checkpoint differs")?;
        // Close the real recorder while the source worker is still alive and before
        // exporting the checkpoint. These are actual IPC outputs, not replayed rows.
        segment(
            &output.join("prefix.jet"),
            genesis_hash,
            digest(image)?,
            &initial,
            &frozen_prefix,
            std::slice::from_ref(prefix),
            std::slice::from_ref(&prefix_result),
        )?;
        let export_dir = output.join("live-export");
        fs::create_dir(&export_dir)?;
        checkpoint_export::validate_checkpoint_export_directory(&export_dir)?;
        let export = client.export_snapshot(
            boundary.slot,
            &export_dir,
            boundary.accounts_hash.as_slice().try_into()?,
            ".tar.bz2",
        )?;
        let after = frozen(client.freeze_checkpoint(boundary.slot)?);
        let before_evidence = checkpoint_export::HistoricalReplayEvidence {
            bootstrap: summary(&initial)?,
            terminal: summary(&frozen_prefix)?,
            emitted_write_versions: initial.next_write_version..frozen_prefix.next_write_version,
        };
        let after_evidence = checkpoint_export::HistoricalReplayEvidence {
            terminal: summary(&after)?,
            ..before_evidence.clone()
        };
        checkpoint_export::validate_checkpoint_export_evidence(&before_evidence, &after_evidence)?;
        let shutdown = client.shutdown_with_outcome()?;
        require(
            shutdown.worker_reap_verified(),
            "source worker reap remains pending",
        )?;
        let mut shutdown_report = create(&output.join("source-shutdown.json"))?;
        serde_json::to_writer_pretty(&mut shutdown_report, &shutdown)?;
        shutdown_report.sync_all()?;
        File::open(output)?.sync_all()?;
        drop(client);
        require(
            fs::read_dir(&scratch)?.next().is_none(),
            "source worker scratch not reaped",
        )?;
        let export = SnapshotExport {
            slot: export.slot,
            archive_path: export
                .archive_path
                .to_str()
                .ok_or("non-UTF8 export path")?
                .into(),
            archive_size: export.archive_size,
            archive_sha256: export.archive_sha256.to_vec(),
            accounts_hash: export.accounts_hash.to_vec(),
        };
        if parent_phase.as_deref() == Some("export") {
            checkpoint_parent_handoff::publish(
                input, output, launcher, image, genesis, &initial, boundary, &after, &export,
            )?;
            return Ok(export);
        }
        (export, after)
    };
    let mut resumed = spawn(Path::new(&export.archive_path), &after)?;
    let restored = frozen(resumed.freeze_checkpoint(boundary.slot)?);
    require(restored == after, "fresh live restore changed checkpoint")?;
    let results = suffix
        .iter()
        .map(|e| process(&mut resumed, e))
        .collect::<Result<Vec<_>>>()?;
    require(
        results == suffix_expected,
        "fresh live suffix differs from uninterrupted baseline",
    )?;
    let end = frozen(resumed.freeze_checkpoint(terminal.slot)?);
    require(&end == terminal, "fresh live terminal differs")?;
    segment(
        &output.join("suffix.jet"),
        genesis_hash,
        digest(image)?,
        &restored,
        &end,
        suffix,
        &results,
    )?;
    let restored_shutdown = resumed.shutdown_with_outcome()?;
    require(
        restored_shutdown.worker_reap_verified(),
        "restored worker reap remains pending",
    )?;
    drop(resumed);
    require(
        fs::read_dir(&scratch)?.next().is_none(),
        "restored worker scratch not reaped",
    )?;
    require(
        digest(Path::new(&export.archive_path))?.as_slice() == export.archive_sha256,
        "export changed during restore",
    )?;
    let mut report = create(&output.join("live-client-results.json"))?;
    serde_json::to_writer_pretty(
        &mut report,
        &json!({"schema":"horizon-synthetic-live-parent-checkpoint-v2","launcher_sha256":hex(&digest(launcher)?),"native_test_image_sha256":hex(&digest(image)?),"snapshot_sha256":hex(&export.archive_sha256),"source_scratch_reaped":true,"restored_scratch_reaped":true,"restored_shutdown":restored_shutdown,"fresh_parent_resume":parent_phase.as_deref()==Some("resume"),"all_outputs_match_uninterrupted":true,"full_parent_firehose_qualified":false,"mainnet_qualified":false,"pressure_admission_authorized":false}),
    )?;
    report.sync_all()?;
    File::open(output)?.sync_all()?;
    Ok(export)
}
