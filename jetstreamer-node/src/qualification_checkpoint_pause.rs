//! Shared production finalization of a fully drained pressure checkpoint.
//! It commits a private bundle/report, never resource release or publication.
use super::*;

pub(crate) struct PausedCheckpoint<'a> {
    pub(crate) epoch: u64,
    pub(crate) output_slot_start: u64,
    pub(crate) end_inclusive: u64,
    pub(crate) boundary: jetstreamer_firehose::source_quiescence::CompletedSourceBlock,
    pub(crate) horizon_output: &'a Path,
    pub(crate) directory: &'a Path,
    pub(crate) evidence: &'a historical_replay::HistoricalReplayEvidence,
    pub(crate) snapshot: &'a historical::HistoricalSnapshotExport,
    pub(crate) worker_shutdown: historical::HistoricalShutdownOutcome,
    pub(crate) runtime: SegmentRuntimeIdentity,
    pub(crate) worker_sha: [u8; 32],
    pub(crate) bootstrap_archive_sha256: Option<[u8; 32]>,
}

pub(crate) fn publish(input: PausedCheckpoint<'_>) -> Result<serde_json::Value, String> {
    let PausedCheckpoint {
        epoch,
        output_slot_start,
        end_inclusive,
        boundary,
        horizon_output,
        directory,
        evidence,
        snapshot,
        worker_shutdown,
        runtime,
        worker_sha,
        bootstrap_archive_sha256,
    } = input;
    if matches!(
        worker_shutdown,
        historical::HistoricalShutdownOutcome::AlreadyClosed
    ) {
        return Err("paused worker was closed before ordered checkpoint shutdown".into());
    }
    if evidence.terminal.slot != boundary.slot
        || !evidence.terminal.slot_complete
        || evidence.terminal.last_blockhash != boundary.blockhash
        || snapshot.slot != boundary.slot
        || snapshot.accounts_hash != evidence.terminal.accounts_hash
    {
        return Err("paused snapshot and native checkpoint differ from source boundary".into());
    }
    fs::File::open(horizon_output)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("sync paused source: {error}"))?;
    let prefix_directory = directory.join("validated-prefix");
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&prefix_directory)
            .map_err(|e| format!("create fresh checkpoint prefix directory: {e}"))?;
    }
    let prefix_path = prefix_directory.join("prefix.jet");
    let converted = jetstreamer_node::checkpoint_prefix::convert_closed_prefix(
        horizon_output,
        &prefix_path,
        &jetstreamer_node::checkpoint_prefix::ClosedPrefixRange {
            epoch,
            first_slot: output_slot_start,
            intended_terminal: end_inclusive,
            selected_terminal: boundary.slot,
            terminal_blockhash: Hash::new_from_array(boundary.blockhash),
        },
    )?;
    let manifest = HistoricalSegmentManifest {
        schema_version: jetstreamer_node::segment_manifest::SEGMENT_MANIFEST_SCHEMA_VERSION,
        epoch,
        output_slot_start,
        output_slot_count: converted.slot_count,
        runtime: runtime.clone(),
        worker_executable_sha256: worker_sha,
        archive_sha256: converted.prefix_sha256,
        bootstrap_archive_sha256,
        bootstrap: segment_checkpoint_summary(&evidence.bootstrap),
        terminal: segment_checkpoint_summary(&evidence.terminal),
        emitted_raw_write_versions: evidence.emitted_write_versions.clone(),
    };
    let (_, written) = write_segment_manifest(&prefix_path, manifest)
        .map_err(|e| format!("validate checkpoint prefix: {e}"))?;
    let verified = read_and_validate_segment_manifest(&prefix_path)
        .map_err(|e| format!("reread checkpoint prefix: {e}"))?;
    if verified != written || verified.archive_sha256 != converted.prefix_sha256 {
        return Err("checkpoint prefix changed after conversion".into());
    }
    let snapshot_manifest = HistoricalHandoffSnapshotManifest {
        schema_version: HANDOFF_SNAPSHOT_MANIFEST_SCHEMA_VERSION,
        boundary_slot: boundary
            .slot
            .checked_add(1)
            .ok_or("checkpoint successor overflow")?,
        snapshot_slot: boundary.slot,
        accounts_hash: Hash::new_from_array(evidence.terminal.accounts_hash).to_string(),
        archive_path: String::new(),
        archive_size: snapshot.archive_size,
        archive_sha256: snapshot.archive_sha256,
        source_runtime: runtime,
        source_worker_executable_sha256: worker_sha,
        terminal: segment_checkpoint_summary(&evidence.terminal),
    };
    let (intent, intent_sha) = jetstreamer_node::checkpoint_bundle::prepare_checkpoint_publication(
        &prefix_path,
        &snapshot.archive_path,
        snapshot_manifest.clone(),
        &verified,
    )?;
    #[cfg(test)]
    publication_fault("after-publication-intent");
    let (snapshot_sidecar, _) =
        jetstreamer_node::checkpoint_bundle::publish_bound_checkpoint_snapshot(
            &snapshot.archive_path,
            snapshot_manifest,
            &verified,
        )?;
    #[cfg(test)]
    publication_fault("after-snapshot-manifest");
    let report = serde_json::json!({
        "schema": "horizon-pressure-checkpoint-paused-v3",
        "epoch": epoch,
        "intended_terminal_slot": end_inclusive,
        "selected_source_slot": boundary.slot,
        "selected_source_parent_slot": boundary.parent_slot,
        "selected_source_blockhash": boundary.blockhash,
        "source_entries": boundary.entries,
        "source_transactions": boundary.transactions,
        "closed_source": horizon_output,
        "closed_source_sha256": converted.source_sha256,
        "verified_prefix": {
            "path": prefix_path,
            "sha256": converted.prefix_sha256,
            "semantic_sha256": converted.semantic_sha256,
            "segment": verified,
            "snapshot_manifest": snapshot_sidecar,
            "publication_intent": intent,
            "publication_intent_sha256": intent_sha,
        },
        "bootstrap": segment_checkpoint_summary(&evidence.bootstrap),
        "terminal": segment_checkpoint_summary(&evidence.terminal),
        "snapshot": {
            "path": snapshot.archive_path,
            "sha256": snapshot.archive_sha256,
            "length": snapshot.archive_size,
        },
        "worker_shutdown_acknowledged": true,
        "worker_reap_verified": worker_shutdown.worker_reap_verified(),
        "worker_shutdown": worker_shutdown,
        "producer_pid": std::process::id(),
        "producer_invocation_id": env::var("INVOCATION_ID").ok(),
        "worker_executable_sha256": worker_sha,
        "prefix_full_validation_required": false,
        "full_range_completed": false,
        "resume_authorized": false,
        "resource_release_authorized": false,
        "publication_authorized": false,
    });
    checkpoint_export::write_paused_evidence(directory, &report)?;
    #[cfg(test)]
    publication_fault("after-paused-report");
    Ok(report)
}

/// Native fault qualification only. A failed producer must never acquire a
/// clean exit proof, even when its artifact publication happened to finish.
/// This hook and its environment access are absent from production builds.
#[cfg(test)]
fn publication_fault(stage: &str) {
    if env::var("JETSTREAMER_PRESSURE_NATIVE_EXPORT_CRASH").as_deref() != Ok(stage) {
        return;
    }
    assert_eq!(
        env::var("JETSTREAMER_PRESSURE_NATIVE_PHASE").as_deref(),
        Ok("export")
    );
    assert_eq!(
        env::var("JETSTREAMER_NETWORK").as_deref(),
        Ok("synthetic-pressure")
    );
    eprintln!("native checkpoint export crash at {stage}; no clean producer exit");
    // Do not run destructors or let the test harness turn this into success.
    unsafe { libc::_exit(87) }
}
