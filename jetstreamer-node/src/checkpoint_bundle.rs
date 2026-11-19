//! Bind a closed, independently verified segment to its exported checkpoint.
//! This proves artifact coherence, not runtime admission, process reaping,
//! canonical epoch completion, publication or pressure-recovery authority.
use crate::{
    archive_checksum::{
        archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
    },
    handoff_snapshot::{
        HistoricalHandoffSnapshotManifest, handoff_snapshot_manifest_path,
        read_and_validate_handoff_snapshot_manifest, write_bound_handoff_snapshot_manifest,
    },
    segment_manifest::{
        HistoricalSegmentManifest, read_and_validate_segment_manifest, segment_manifest_path,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

/// Durable publication input, not proof that a worker has exited or that a
/// checkpoint is admitted for replay. Recovery callers authenticate its digest
/// independently and keep exclusive custody of all selected files.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationIntent {
    schema_version: u32,
    prefix: PathBuf,
    segment: HistoricalSegmentManifest,
    snapshot: HistoricalHandoffSnapshotManifest,
}

pub fn checkpoint_publication_intent_path(prefix: &Path) -> Result<PathBuf, String> {
    let mut name = prefix
        .file_name()
        .ok_or("prefix has no filename")?
        .to_os_string();
    name.push(".checkpoint-publication.json");
    Ok(prefix.with_file_name(name))
}

/// Called after the prefix's complete validation and ordered worker shutdown,
/// before snapshot-manifest publication. Leaves an atomic, no-clobber recovery
/// intent even when the parent exits before finishing publication. No snapshot
/// or prefix data is replaced, and ordinary duplicate publication still fails.
pub fn prepare_checkpoint_publication(
    prefix: &Path,
    archive: &Path,
    mut snapshot: HistoricalHandoffSnapshotManifest,
    verified_segment: &HistoricalSegmentManifest,
) -> Result<(PathBuf, [u8; 32]), String> {
    if !prefix.is_absolute()
        || prefix.canonicalize().map_err(|e| e.to_string())? != prefix
        || !archive.is_absolute()
        || archive.canonicalize().map_err(|e| e.to_string())? != archive
    {
        return Err("checkpoint publication requires canonical absolute paths".into());
    }
    snapshot.archive_path = archive.to_str().ok_or("non-UTF8 snapshot path")?.into();
    snapshot.validate().map_err(|e| e.to_string())?;
    validate_checkpoint_relation(verified_segment, &snapshot)?;
    let path = checkpoint_publication_intent_path(prefix)?;
    let parent = path.parent().ok_or("intent has no parent")?;
    let intent = PublicationIntent {
        schema_version: 1,
        prefix: prefix.to_path_buf(),
        segment: verified_segment.clone(),
        snapshot,
    };
    let bytes = serde_json::to_vec_pretty(&intent).map_err(|e| e.to_string())?;
    if bytes.len() > 1 << 20 {
        return Err("checkpoint publication intent exceeds bound".into());
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".checkpoint-publication-")
        .tempfile_in(parent)
        .map_err(|e| e.to_string())?;
    temporary.write_all(&bytes).map_err(|e| e.to_string())?;
    temporary.as_file().sync_all().map_err(|e| e.to_string())?;
    temporary
        .persist_noclobber(&path)
        .map_err(|e| e.to_string())?;
    File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(|e| e.to_string())?;
    Ok((path, Sha256::digest(&bytes).into()))
}

/// Explicit recovery of only the snapshot evidence publication. A missing
/// manifest may be created from this authenticated intent; an existing one must
/// match exactly and is never replaced. The complete prefix and snapshot are
/// independently reread. This does not start/stop workers or release resources.
pub fn recover_checkpoint_publication(
    intent_path: &Path,
    expected_sha256: [u8; 32],
) -> Result<(HistoricalSegmentManifest, HistoricalHandoffSnapshotManifest), String> {
    let mut intent_file = open_regular_nofollow(intent_path).map_err(|e| e.to_string())?;
    let identity = archive_file_identity(&intent_file).map_err(|e| e.to_string())?;
    let metadata = intent_file.metadata().map_err(|e| e.to_string())?;
    if metadata.len() > 1 << 20
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("checkpoint publication intent custody or size invalid".into());
    }
    let mut bytes = Vec::new();
    (&mut intent_file)
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1 << 20 || <[u8; 32]>::from(Sha256::digest(&bytes)) != expected_sha256 {
        return Err("checkpoint publication intent digest mismatch".into());
    }
    let intent: PublicationIntent = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let snapshot_path = Path::new(&intent.snapshot.archive_path);
    if intent.schema_version != 1
        || !intent.prefix.is_absolute()
        || intent.prefix.canonicalize().map_err(|e| e.to_string())? != intent.prefix
        || !snapshot_path.is_absolute()
        || snapshot_path.canonicalize().map_err(|e| e.to_string())? != snapshot_path
        || checkpoint_publication_intent_path(&intent.prefix)? != intent_path
    {
        return Err("checkpoint publication intent path or schema mismatch".into());
    }
    intent.snapshot.validate().map_err(|e| e.to_string())?;
    validate_checkpoint_relation(&intent.segment, &intent.snapshot)?;
    // The existing writer lock serializes cooperative publication/recovery.
    // The controller still owns custody and must exclude a live producer.
    let _lock = crate::archive_checksum::acquire_archive_destination_writer_lock(
        intent.prefix.parent().ok_or("prefix has no parent")?,
    )
    .map_err(|e| e.to_string())?;
    let pinned_paths = [
        intent.prefix.clone(),
        segment_manifest_path(&intent.prefix).map_err(|e| e.to_string())?,
        snapshot_path.to_path_buf(),
    ];
    let pinned_files = pinned_paths
        .iter()
        .map(|path| {
            let file = open_regular_nofollow(path).map_err(|e| e.to_string())?;
            let identity = archive_file_identity(&file).map_err(|e| e.to_string())?;
            Ok((file, identity))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let segment = read_and_validate_segment_manifest(&intent.prefix).map_err(|e| e.to_string())?;
    if segment != intent.segment {
        return Err("checkpoint publication prefix differs from intent".into());
    }
    if archive_file_identity(&intent_file).map_err(|e| e.to_string())? != identity
        || !path_matches_archive_identity(intent_path, identity).map_err(|e| e.to_string())?
    {
        return Err("checkpoint publication intent changed before recovery".into());
    }
    let sidecar = handoff_snapshot_manifest_path(snapshot_path).map_err(|e| e.to_string())?;
    match fs::symlink_metadata(&sidecar) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            publish_bound_checkpoint_snapshot(snapshot_path, intent.snapshot.clone(), &segment)?;
        }
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let sidecar_file = open_regular_nofollow(&sidecar).map_err(|e| e.to_string())?;
    let sidecar_identity = archive_file_identity(&sidecar_file).map_err(|e| e.to_string())?;
    let result = read_and_validate_checkpoint_bundle(&intent.prefix, snapshot_path)?;
    if result.0 != intent.segment || result.1 != intent.snapshot {
        return Err("checkpoint publication existing evidence differs from intent".into());
    }
    // Complete durability even if the previous parent died after rename but
    // before directory fsync. Never rewrite a surviving evidence file.
    sidecar_file.sync_all().map_err(|e| e.to_string())?;
    File::open(sidecar.parent().ok_or("sidecar has no parent")?)
        .and_then(|d| d.sync_all())
        .map_err(|e| e.to_string())?;
    if archive_file_identity(&intent_file).map_err(|e| e.to_string())? != identity
        || !path_matches_archive_identity(intent_path, identity).map_err(|e| e.to_string())?
        || !path_matches_archive_identity(&sidecar, sidecar_identity).map_err(|e| e.to_string())?
    {
        return Err("checkpoint publication evidence changed during recovery".into());
    }
    for (path, (file, identity)) in pinned_paths.iter().zip(&pinned_files) {
        if archive_file_identity(file).map_err(|e| e.to_string())? != *identity
            || !path_matches_archive_identity(path, *identity).map_err(|e| e.to_string())?
        {
            return Err("checkpoint publication source changed during recovery".into());
        }
    }
    Ok(result)
}

/// The caller must supply a segment returned by a complete source validation.
/// Structural checks here cannot turn an unverified manifest into evidence.
pub fn validate_checkpoint_relation(
    segment: &HistoricalSegmentManifest,
    snapshot: &HistoricalHandoffSnapshotManifest,
) -> Result<(), String> {
    segment.validate().map_err(|e| e.to_string())?;
    let end = segment
        .output_slot_start
        .checked_add(segment.output_slot_count)
        .ok_or("checkpoint segment range overflow")?;
    if segment.archive_sha256 == [0; 32]
        || segment.worker_executable_sha256 == [0; 32]
        || segment.terminal.slot.checked_add(1) != Some(end)
        || snapshot.boundary_slot != end
        || snapshot.snapshot_slot != segment.terminal.slot
        || snapshot.accounts_hash != segment.terminal.accounts_hash
        || snapshot.source_runtime != segment.runtime
        || snapshot.source_worker_executable_sha256 != segment.worker_executable_sha256
        || snapshot.terminal != segment.terminal
    {
        return Err(
            "checkpoint snapshot does not bind the exact verified segment terminal and runtime"
                .into(),
        );
    }
    Ok(())
}

/// Publish only after a complete segment reread and ordered worker shutdown.
/// Reuses the no-clobber snapshot writer and checks its durable readback.
/// Does not reread the large segment a third time during ordinary completion.
pub fn publish_bound_checkpoint_snapshot(
    archive: &Path,
    snapshot: HistoricalHandoffSnapshotManifest,
    verified_segment: &HistoricalSegmentManifest,
) -> Result<(PathBuf, HistoricalHandoffSnapshotManifest), String> {
    validate_checkpoint_relation(verified_segment, &snapshot)?;
    let (path, published) =
        write_bound_handoff_snapshot_manifest(archive, snapshot).map_err(|e| e.to_string())?;
    let readback =
        read_and_validate_handoff_snapshot_manifest(archive).map_err(|e| e.to_string())?;
    if readback != published {
        return Err("checkpoint snapshot changed during evidence publication".into());
    }
    validate_checkpoint_relation(verified_segment, &readback)?;
    Ok((path, published))
}

/// Recovery must deeply reread the entire retained prefix before starting a
/// suffix worker. Bind all four files across the combined read to reject
/// replacement or mutation between the individual validators. The caller must
/// also authenticate its plan and keep custody through subsequent worker use.
pub fn read_and_validate_checkpoint_bundle(
    prefix: &Path,
    snapshot: &Path,
) -> Result<(HistoricalSegmentManifest, HistoricalHandoffSnapshotManifest), String> {
    let paths = [
        prefix.to_path_buf(),
        segment_manifest_path(prefix).map_err(|e| e.to_string())?,
        snapshot.to_path_buf(),
        handoff_snapshot_manifest_path(snapshot).map_err(|e| e.to_string())?,
    ];
    let files = paths
        .iter()
        .map(|path| {
            let file = open_regular_nofollow(path).map_err(|e| e.to_string())?;
            let identity = archive_file_identity(&file).map_err(|e| e.to_string())?;
            Ok((file, identity))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let segment = read_and_validate_segment_manifest(prefix).map_err(|e| e.to_string())?;
    let checkpoint =
        read_and_validate_handoff_snapshot_manifest(snapshot).map_err(|e| e.to_string())?;
    validate_checkpoint_relation(&segment, &checkpoint)?;
    for (path, (file, identity)) in paths.iter().zip(&files) {
        if archive_file_identity(file).map_err(|e| e.to_string())? != *identity
            || !path_matches_archive_identity(path, *identity).map_err(|e| e.to_string())?
        {
            return Err(format!(
                "checkpoint bundle changed during validation: {}",
                path.display()
            ));
        }
    }
    Ok((segment, checkpoint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment_manifest::{
        SegmentCheckpointSummary, SegmentRuntimeAdmission, SegmentRuntimeIdentity,
    };
    use solana_hash::Hash;
    fn pair() -> (HistoricalSegmentManifest, HistoricalHandoffSnapshotManifest) {
        let hash = Hash::new_from_array([1; 32]).to_string();
        let checkpoint = SegmentCheckpointSummary {
            slot: 7,
            bank_hash: hash.clone(),
            accounts_hash: hash.clone(),
            last_blockhash: hash.clone(),
            capitalization: 10,
            transaction_count: 3,
            tick_height: 64,
            slot_complete: true,
            write_count: 2,
            next_write_version: 9,
        };
        let runtime = SegmentRuntimeIdentity {
            generation_profile: "test".into(),
            runtime_profile: "solana-v1.7.15".into(),
            runtime_admission: SegmentRuntimeAdmission::Candidate,
            runtime_revision: "revision".into(),
            runtime_toolchain: "toolchain".into(),
            runtime_target: "target".into(),
            genesis_hash: hash.clone(),
        };
        let segment = HistoricalSegmentManifest {
            schema_version: 1,
            epoch: 0,
            output_slot_start: 7,
            output_slot_count: 1,
            runtime: runtime.clone(),
            worker_executable_sha256: [2; 32],
            archive_sha256: [3; 32],
            bootstrap_archive_sha256: None,
            bootstrap: SegmentCheckpointSummary {
                slot: 6,
                next_write_version: 7,
                ..checkpoint.clone()
            },
            terminal: checkpoint.clone(),
            emitted_raw_write_versions: 7..9,
        };
        let snapshot = HistoricalHandoffSnapshotManifest {
            schema_version: 1,
            boundary_slot: 8,
            snapshot_slot: 7,
            accounts_hash: hash,
            archive_path: String::new(),
            archive_size: 10,
            archive_sha256: [4; 32],
            source_runtime: runtime,
            source_worker_executable_sha256: [2; 32],
            terminal: checkpoint,
        };
        (segment, snapshot)
    }
    #[test]
    fn checkpoint_bundle_binds_every_terminal_field_and_runtime_identity() {
        let (segment, snapshot) = pair();
        validate_checkpoint_relation(&segment, &snapshot).unwrap();
        let changes: &[fn(&mut HistoricalHandoffSnapshotManifest)] = &[
            |s| s.boundary_slot += 1,
            |s| s.snapshot_slot += 1,
            |s| s.accounts_hash = Hash::new_from_array([8; 32]).to_string(),
            |s| s.source_worker_executable_sha256[0] ^= 1,
            |s| s.source_runtime.generation_profile.push('x'),
            |s| s.source_runtime.runtime_profile.push('x'),
            |s| s.source_runtime.runtime_admission = SegmentRuntimeAdmission::Verified,
            |s| s.source_runtime.runtime_revision.push('x'),
            |s| s.source_runtime.runtime_toolchain.push('x'),
            |s| s.source_runtime.runtime_target.push('x'),
            |s| s.source_runtime.genesis_hash = Hash::new_from_array([8; 32]).to_string(),
            |s| s.terminal.slot += 1,
            |s| s.terminal.bank_hash = Hash::new_from_array([8; 32]).to_string(),
            |s| s.terminal.accounts_hash = Hash::new_from_array([8; 32]).to_string(),
            |s| s.terminal.last_blockhash = Hash::new_from_array([8; 32]).to_string(),
            |s| s.terminal.capitalization += 1,
            |s| s.terminal.transaction_count += 1,
            |s| s.terminal.tick_height += 1,
            |s| s.terminal.slot_complete = false,
            |s| s.terminal.write_count += 1,
            |s| s.terminal.next_write_version += 1,
        ];
        for change in changes {
            let mut wrong = snapshot.clone();
            change(&mut wrong);
            assert!(validate_checkpoint_relation(&segment, &wrong).is_err());
        }
    }
    #[test]
    fn checkpoint_bundle_rejects_unbound_or_longer_segment() {
        let (segment, snapshot) = pair();
        for field in 0..3 {
            let mut wrong = segment.clone();
            match field {
                0 => wrong.archive_sha256 = [0; 32],
                1 => wrong.worker_executable_sha256 = [0; 32],
                _ => wrong.output_slot_count += 1,
            }
            assert!(validate_checkpoint_relation(&wrong, &snapshot).is_err());
        }
    }

    #[test]
    fn publication_intent_is_atomic_bound_and_cannot_authorize_an_invalid_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("prefix.jet");
        fs::write(&prefix, b"invalid archive").unwrap();
        let (segment, mut snapshot) = pair();
        let archive = dir
            .path()
            .join(format!("snapshot-7-{}.tar.bz2", snapshot.accounts_hash));
        fs::write(&archive, b"snapshot bytes").unwrap();
        snapshot.archive_size = 14;
        snapshot.archive_sha256 = Sha256::digest(b"snapshot bytes").into();
        let (intent, digest) =
            prepare_checkpoint_publication(&prefix, &archive, snapshot.clone(), &segment).unwrap();
        let original = fs::read(&intent).unwrap();
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&original)), digest);
        assert!(prepare_checkpoint_publication(&prefix, &archive, snapshot, &segment).is_err());
        assert_eq!(fs::read(&intent).unwrap(), original);
        assert!(
            recover_checkpoint_publication(&intent, [0; 32])
                .unwrap_err()
                .contains("digest mismatch")
        );
        assert!(recover_checkpoint_publication(&intent, digest).is_err());
        assert!(!handoff_snapshot_manifest_path(&archive).unwrap().exists());
        assert_eq!(fs::read(&intent).unwrap(), original);
    }
}
