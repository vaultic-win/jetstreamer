//! Synthetic parent-restart qualification; no production recovery authority.
use super::*;
use crate::handoff_snapshot::{
    HistoricalHandoffSnapshotManifest, handoff_snapshot_manifest_path,
    read_and_validate_handoff_snapshot_manifest,
};
use crate::segment_manifest::{
    HistoricalSegmentManifest, SegmentCheckpointSummary, SegmentRuntimeAdmission,
    SegmentRuntimeIdentity, read_and_validate_segment_manifest, segment_manifest_path,
    write_segment_manifest,
};

pub const PHASE: &str = "JETSTREAMER_NATIVE_PARENT_PHASE";
const RECEIPT: &str = "parent-checkpoint.json";
const RECEIPT_SHA: &str = "JETSTREAMER_NATIVE_PARENT_RECEIPT_SHA256";
const INTERRUPT: &str = "JETSTREAMER_NATIVE_PUBLICATION_INTERRUPT";
const INTENT_SHA: &str = "JETSTREAMER_NATIVE_PUBLICATION_INTENT_SHA256";

fn interrupt_after(stage: &str) {
    if std::env::var(INTERRUPT).ok().as_deref() == Some(stage) {
        eprintln!("synthetic publication interruption after {stage}");
        // Deliberately skip destructors after the named durable boundary.
        unsafe { libc::_exit(86) }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    parent_pid: u32,
    parent_sha256: String,
    launcher_sha256: String,
    native_image_sha256: String,
    transcript_sha256: String,
    prefix_sha256: String,
    prefix_manifest_sha256: String,
    snapshot_manifest_sha256: String,
    export: SnapshotExport,
    checkpoint: Checkpoint,
}

fn summary(c: &Checkpoint) -> Result<SegmentCheckpointSummary> {
    Ok(SegmentCheckpointSummary {
        slot: c.slot,
        bank_hash: hash(&c.bank_hash)?.to_string(),
        accounts_hash: hash(&c.accounts_hash)?.to_string(),
        last_blockhash: hash(&c.last_blockhash)?.to_string(),
        capitalization: c.capitalization,
        transaction_count: c.transaction_count,
        tick_height: c.tick_height,
        slot_complete: c.slot_complete,
        write_count: c.writes.len().try_into()?,
        next_write_version: c.next_write_version,
    })
}

pub fn publish(
    input: &Path,
    output: &Path,
    launcher: &Path,
    image: &Path,
    genesis: &[u8],
    bootstrap: &Checkpoint,
    boundary: &Checkpoint,
    after: &Checkpoint,
    export: &SnapshotExport,
) -> Result<()> {
    let manifest = HistoricalHandoffSnapshotManifest {
        schema_version: 1,
        boundary_slot: boundary.slot.checked_add(1).ok_or("slot overflow")?,
        snapshot_slot: boundary.slot,
        accounts_hash: hash(&boundary.accounts_hash)?.to_string(),
        archive_path: String::new(),
        archive_size: export.archive_size,
        archive_sha256: export.archive_sha256.as_slice().try_into()?,
        source_runtime: SegmentRuntimeIdentity {
            generation_profile: "synthetic/native-checkpoint-recorder-v1".into(),
            runtime_profile: "solana-v1.7.15".into(),
            runtime_admission: SegmentRuntimeAdmission::Candidate,
            runtime_revision: "4892eb4e1ad278d5249b6cda8983f88effb3e98b".into(),
            runtime_toolchain: "rustc1.52.1-test-image".into(),
            runtime_target: "x86_64-unknown-linux-gnu".into(),
            genesis_hash: hash(genesis)?.to_string(),
        },
        source_worker_executable_sha256: digest(image)?,
        terminal: summary(boundary)?,
    };
    let prefix = output.join("prefix.jet");
    let (prefix_sidecar, written_segment) = write_segment_manifest(
        &prefix,
        HistoricalSegmentManifest {
            schema_version: 1,
            epoch: 0,
            output_slot_start: bootstrap.slot.checked_add(1).ok_or("slot overflow")?,
            output_slot_count: boundary
                .slot
                .checked_sub(bootstrap.slot)
                .ok_or("inverted prefix")?,
            runtime: manifest.source_runtime.clone(),
            worker_executable_sha256: digest(image)?,
            archive_sha256: [0; 32],
            bootstrap_archive_sha256: None,
            bootstrap: summary(bootstrap)?,
            terminal: summary(boundary)?,
            emitted_raw_write_versions: bootstrap.next_write_version..boundary.next_write_version,
        },
    )?;
    let verified_segment = read_and_validate_segment_manifest(&prefix)?;
    require(
        verified_segment == written_segment,
        "prefix manifest readback differs",
    )?;
    checkpoint_bundle::prepare_checkpoint_publication(
        &prefix,
        Path::new(&export.archive_path),
        manifest.clone(),
        &verified_segment,
    )?;
    interrupt_after("intent");
    let (sidecar, published) = checkpoint_bundle::publish_bound_checkpoint_snapshot(
        Path::new(&export.archive_path),
        manifest,
        &verified_segment,
    )?;
    require(
        read_and_validate_handoff_snapshot_manifest(&export.archive_path)? == published,
        "snapshot manifest readback differs",
    )?;
    interrupt_after("snapshot");
    publish_receipt(
        input,
        output,
        launcher,
        image,
        after,
        export,
        &prefix_sidecar,
        &sidecar,
    )
}

fn publish_receipt(
    input: &Path,
    output: &Path,
    launcher: &Path,
    image: &Path,
    after: &Checkpoint,
    export: &SnapshotExport,
    prefix_sidecar: &Path,
    sidecar: &Path,
) -> Result<()> {
    let receipt = Receipt {
        schema: "horizon-synthetic-parent-checkpoint-v2".into(),
        parent_pid: std::process::id(),
        parent_sha256: hex(&digest(&std::env::current_exe()?)?),
        launcher_sha256: hex(&digest(launcher)?),
        native_image_sha256: hex(&digest(image)?),
        transcript_sha256: hex(&digest(&input.join("native-transcript.bin"))?),
        prefix_sha256: hex(&digest(&output.join("prefix.jet"))?),
        prefix_manifest_sha256: hex(&digest(prefix_sidecar)?),
        snapshot_manifest_sha256: hex(&digest(sidecar)?),
        export: export.clone(),
        checkpoint: after.clone(),
    };
    let mut file = tempfile::Builder::new()
        .prefix(".parent-checkpoint-")
        .tempfile_in(output)?;
    serde_json::to_writer_pretty(&mut file, &receipt)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(output.join(RECEIPT))?;
    File::open(output)?.sync_all()?;
    Ok(())
}

pub fn recover(
    input: &Path,
    output: &Path,
    launcher: &Path,
    image: &Path,
    genesis: &[u8],
    boundary: &Checkpoint,
) -> Result<()> {
    let expected = std::env::var(INTENT_SHA)?;
    require(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid publication intent digest",
    )?;
    let expected: [u8; 32] = (0..32)
        .map(|i| u8::from_str_radix(&expected[i * 2..i * 2 + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "invalid digest length")?;
    let prefix = output.join("prefix.jet");
    let intent = checkpoint_bundle::checkpoint_publication_intent_path(&prefix)?;
    let (segment, snapshot) = checkpoint_bundle::recover_checkpoint_publication(&intent, expected)?;
    require(
        snapshot.terminal == summary(boundary)?
            && snapshot.source_runtime.genesis_hash == hash(genesis)?.to_string()
            && snapshot.source_worker_executable_sha256 == digest(image)?
            && Path::new(&snapshot.archive_path).parent()
                == Some(output.join("live-export").as_path()),
        "recovered publication differs from native fixture",
    )?;
    let sidecar = handoff_snapshot_manifest_path(&snapshot.archive_path)?;
    let before = (digest(&intent)?, digest(&sidecar)?);
    require(
        checkpoint_bundle::recover_checkpoint_publication(&intent, expected)?
            == (segment, snapshot.clone()),
        "repeated publication recovery differs",
    )?;
    require(
        before == (digest(&intent)?, digest(&sidecar)?),
        "repeated recovery rewrote evidence",
    )?;
    let export = SnapshotExport {
        slot: snapshot.snapshot_slot,
        archive_path: snapshot.archive_path,
        archive_size: snapshot.archive_size,
        archive_sha256: snapshot.archive_sha256.to_vec(),
        accounts_hash: boundary.accounts_hash.clone(),
    };
    let mut after = boundary.clone();
    after.writes.clear();
    publish_receipt(
        input,
        output,
        launcher,
        image,
        &after,
        &export,
        &segment_manifest_path(&prefix)?,
        &sidecar,
    )
}

pub fn read(
    input: &Path,
    output: &Path,
    launcher: &Path,
    image: &Path,
    genesis: &[u8],
    boundary: &Checkpoint,
) -> Result<(SnapshotExport, Checkpoint)> {
    let path = output.join(RECEIPT);
    let expected = std::env::var(RECEIPT_SHA)?;
    require(
        hex(&digest(&path)?) == expected,
        "parent checkpoint receipt digest mismatch",
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let meta = file.metadata()?;
    require(
        meta.len() <= 1 << 20
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0
            && meta.nlink() == 1,
        "invalid parent checkpoint receipt custody",
    )?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    require(
        hex(&Sha256::digest(&bytes)) == expected,
        "parent checkpoint receipt changed",
    )?;
    let r: Receipt = serde_json::from_slice(&bytes)?;
    require(
        r.schema == "horizon-synthetic-parent-checkpoint-v2"
            && r.parent_pid != std::process::id()
            && r.parent_sha256 == hex(&digest(&std::env::current_exe()?)?)
            && r.launcher_sha256 == hex(&digest(launcher)?)
            && r.native_image_sha256 == hex(&digest(image)?)
            && r.transcript_sha256 == hex(&digest(&input.join("native-transcript.bin"))?)
            && r.prefix_sha256 == hex(&digest(&output.join("prefix.jet"))?),
        "parent restart input identity mismatch",
    )?;
    let mut expected_checkpoint = boundary.clone();
    expected_checkpoint.writes.clear();
    require(
        r.checkpoint == expected_checkpoint,
        "parent restart checkpoint mismatch",
    )?;
    let archive = Path::new(&r.export.archive_path);
    require(
        archive.parent() == Some(output.join("live-export").as_path())
            && archive.canonicalize()? == archive,
        "parent restart snapshot escaped export directory",
    )?;
    let sidecar = handoff_snapshot_manifest_path(archive)?;
    require(
        hex(&digest(&sidecar)?) == r.snapshot_manifest_sha256,
        "parent restart snapshot manifest changed",
    )?;
    let prefix = output.join("prefix.jet");
    require(
        hex(&digest(&segment_manifest_path(&prefix)?)?) == r.prefix_manifest_sha256,
        "parent restart prefix manifest changed",
    )?;
    let (_, m) = checkpoint_bundle::read_and_validate_checkpoint_bundle(&prefix, archive)?;
    require(
        m.terminal == summary(boundary)?
            && m.source_runtime.genesis_hash == hash(genesis)?.to_string()
            && m.source_worker_executable_sha256 == digest(image)?
            && m.archive_sha256.as_slice() == r.export.archive_sha256
            && m.archive_size == r.export.archive_size
            && r.export.slot == boundary.slot
            && r.export.accounts_hash == boundary.accounts_hash,
        "parent restart snapshot evidence mismatch",
    )?;
    require(
        !output.join("suffix.jet").try_exists()?
            && !output.join("live-client-results.json").try_exists()?,
        "parent restart already consumed",
    )?;
    Ok((r.export, r.checkpoint))
}

pub fn controller(args: &[PathBuf]) -> Result<()> {
    let output = &args[1];
    require(
        fs::read_dir(output)?.next().is_none(),
        "controller output must be empty",
    )?;
    let executable = std::env::current_exe()?;
    let interruption = std::env::var(INTERRUPT).ok();
    require(
        matches!(interruption.as_deref(), None | Some("intent" | "snapshot")),
        "unknown publication interruption",
    )?;
    let child = |phase: &str, receipt_sha: Option<&str>| -> Result<std::process::Output> {
        let mut command = Command::new(&executable);
        command.args(args).env(PHASE, phase).stdin(Stdio::null());
        if let Some(sha) = receipt_sha {
            command.env(RECEIPT_SHA, sha);
            command.env(INTENT_SHA, sha);
        }
        Ok(command.output()?)
    };
    let exported = child("export", None)?;
    let mut stages = Vec::new();
    if interruption.is_some() {
        require(
            exported.status.code() == Some(86) && !output.join(RECEIPT).try_exists()?,
            "publication interruption did not stop before checkpoint receipt",
        )?;
        let intent =
            checkpoint_bundle::checkpoint_publication_intent_path(&output.join("prefix.jet"))?;
        let intent_sha = hex(&digest(&intent)?);
        let rejected = child("recover-publication", Some(&"0".repeat(64)))?;
        require(
            !rejected.status.success()
                && String::from_utf8_lossy(&rejected.stderr)
                    .contains("checkpoint publication intent digest mismatch"),
            "wrong publication intent digest accepted",
        )?;
        let recovered = child("recover-publication", Some(&intent_sha))?;
        require(
            recovered.status.success(),
            &format!(
                "publication recovery failed: {}",
                String::from_utf8_lossy(&recovered.stderr)
            ),
        )?;
        stages.push(("wrong-intent", rejected));
        stages.push(("recover-publication", recovered));
    } else {
        require(
            exported.status.success(),
            &format!(
                "export parent failed: {}",
                String::from_utf8_lossy(&exported.stderr)
            ),
        )?;
    }
    // The exporting parent has exited and been reaped. Only durable files cross
    // into the independent resume parent; no live Client or recorder is retained.
    let receipt_sha = hex(&digest(&output.join(RECEIPT))?);
    let rejected = child("resume", Some(&"0".repeat(64)))?;
    require(
        !rejected.status.success()
            && String::from_utf8_lossy(&rejected.stderr)
                .contains("parent checkpoint receipt digest mismatch"),
        "changed receipt binding accepted",
    )?;
    let resumed = child("resume", Some(&receipt_sha))?;
    require(
        resumed.status.success(),
        &format!(
            "resume parent failed: {}",
            String::from_utf8_lossy(&resumed.stderr)
        ),
    )?;
    let results_before = digest(&output.join("native-results.json"))?;
    let replayed = child("resume", Some(&receipt_sha))?;
    require(
        !replayed.status.success()
            && String::from_utf8_lossy(&replayed.stderr)
                .contains("parent restart already consumed"),
        "duplicate resume accepted",
    )?;
    require(
        digest(&output.join("native-results.json"))? == results_before
            && hex(&digest(&output.join(RECEIPT))?) == receipt_sha,
        "rejected retry changed successful evidence",
    )?;
    stages.extend([
        ("export", exported),
        ("wrong-digest", rejected),
        ("resume", resumed),
        ("duplicate", replayed),
    ]);
    for (name, result) in stages {
        let mut file = create(&output.join(format!("parent-{name}.stderr")))?;
        file.write_all(&result.stderr)?;
        file.sync_all()?;
    }
    let mut file = create(&output.join("parent-controller-results.json"))?;
    serde_json::to_writer_pretty(
        &mut file,
        &json!({
            "schema":"horizon-synthetic-parent-restart-result-v1",
            "receipt_sha256":receipt_sha,"native_results_sha256":hex(&results_before),
            "export_parent_reaped":true,"fresh_parent_resume":true,
            "changed_receipt_binding_rejected":true,"duplicate_resume_rejected":true,
            "publication_interruption":interruption,
            "publication_recovered":interruption.is_some(),
            "full_parent_firehose_qualified":false,"mainnet_qualified":false,
            "pressure_admission_authorized":false
        }),
    )?;
    file.sync_all()?;
    File::open(output)?.sync_all()?;
    Ok(())
}
