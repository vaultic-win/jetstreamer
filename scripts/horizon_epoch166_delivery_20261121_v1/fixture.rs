//! Qualification only. This command is absent from the production executable.
use super::*;
use jetstreamer_horizon::archive::{ArchiveReader, ArchiveWriter, ArchiveWriterConfig};
use jetstreamer_node::{
    archive_checksum::measure_open_archive,
    archive_publish::{ArchiveBatchItem, publish_verified_archive_batch_with_context},
};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
pub(super) fn publish(
    dir: &Path,
    epoch: u64,
    fingerprint: [u8; 32],
    bootstrap: [u8; 32],
    checkpoint: [u8; 32],
    last: [u8; 32],
) -> Result<()> {
    let (bootstrap_slot, checkpoint_slot, slot) = match epoch {
        168 => (72_575_704, 73_007_829, 73_007_999),
        166 => (71_711_708, 72_143_703, 72_143_999),
        167 => (72_143_703, 72_575_704, 72_575_999),
        172 => (74_303_701, 74_735_808, 74_735_999),
        170 => (73_439_777, 73_871_796, 73_871_999),
        _ => anyhow::bail!("unsupported native fixture"),
    };
    let private = |path: &Path| {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    };
    let output = dir.join("output");
    private(&output)?;
    let m = output.metadata()?;
    let batch = dir
        .join("private/destination-fixture/evidence/archive-batches")
        .join(format!("destination-{:016x}-{:016x}", m.dev(), m.ino()));
    private(&batch)?;
    let locks = dir.join("private/destination-fixture/locks");
    private(&locks)?;
    let lock = locks.join(format!("epoch-{epoch}.lock"));
    fs::File::create(&lock)?;
    fs::set_permissions(lock, fs::Permissions::from_mode(0o600))?;
    let staging = dir.join("staged");
    private(&staging)?;
    let staged = staging.join(format!("epoch-{epoch}.jet"));
    let mut writer = ArchiveWriter::new(
        fs::File::create(&staged)?,
        epoch,
        slot,
        1,
        ArchiveWriterConfig::default(),
    )?;
    writer.write_skipped_slot(slot)?;
    let (f, _) = writer.finish()?;
    f.sync_all()?;
    drop(f);
    let reader = ArchiveReader::open(fs::File::open(&staged)?)?;
    ensure!(reader.header().epoch == epoch);
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o440))?;
    let evidence = measure_open_archive(&fs::File::open(&staged)?)?;
    let item = ArchiveBatchItem {
        epoch,
        staged_archive: staged,
        destination_archive: output.join(format!("epoch-{epoch}.jet")),
        evidence,
    };
    let summary = |slot, accounts_hash, last_blockhash| cohort::RootCheckpointSummary {
        slot,
        bank_hash: [1; 32],
        accounts_hash,
        last_blockhash,
        capitalization: 1,
        transaction_count: 2,
        tick_height: 3,
        slot_complete: true,
        write_count: 4,
        next_write_version: 5,
    };
    let gate = cohort::RootCheckpointGateEvidence {
        kind: cohort::ROOT_CHECKPOINT_GATE_KIND.into(),
        version: 1,
        verified_manifest_checkpoints: vec![cohort::VerifiedManifestCheckpoint {
            slot: checkpoint_slot,
            accounts_hash: checkpoint,
        }],
        members: vec![cohort::RootCheckpointGateMember {
            epoch,
            bootstrap: summary(bootstrap_slot, bootstrap, [2; 32]),
            terminal: summary(slot, [3; 32], last),
        }],
    };
    let context = cohort::encode_root_checkpoint_gate_context(fingerprint, &[epoch], &gate)
        .map_err(anyhow::Error::msg)?;
    let batch_pub = publish_verified_archive_batch_with_context(
        fingerprint,
        &[epoch],
        std::slice::from_ref(&item),
        &context,
    )?;
    let committed = cohort::finish_root_checkpoint_publication(
        cohort::DestinationBinding {
            path: &output,
            device: m.dev(),
            inode: m.ino(),
        },
        &batch,
        fingerprint,
        &[cohort::ExpectedCohortArchive {
            epoch,
            destination_archive: &item.destination_archive,
            sha256: item.evidence.sha256,
        }],
        &batch_pub,
        &gate,
    )
    .map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        json!({"transaction_id":hex(&committed.transaction_id),"path":committed.receipt_path,"sha256":hex(&item.evidence.sha256)})
    );
    Ok(())
}
