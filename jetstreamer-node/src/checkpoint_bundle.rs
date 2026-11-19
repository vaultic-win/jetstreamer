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
use std::path::{Path, PathBuf};

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
}
