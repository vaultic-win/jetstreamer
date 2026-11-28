//! Check the epoch 230 repaired prefix against its first stock continuation.
//! The merge writes into SHA-256, so its output requires no local archive space.
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::{
    AccountsHashKind, ArchiveProvenance, ArchiveProvenanceV3, ArchiveReader, ArchiveWriterConfig,
    BootstrapStateKind, RuntimeAdmission, RuntimeHandoffProvenance, RuntimeSegmentProvenance,
    RuntimeSegmentSource, RuntimeStateCheckpoint, StateCommitment, StateCommitmentKind,
    WriteVersionNormalization, merge_runtime_segments,
};
use jetstreamer_node::{
    archive_checksum::{
        archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
    },
    segment_manifest::{
        HistoricalSegmentManifest, SegmentCheckpointSummary, SegmentRuntimeAdmission,
        segment_manifest_path, sha256_hex_string,
    },
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

const PREFIX: &str = "/home/ubuntu/.jetstreamer-private/epoch230-demotion-tmpfs-v328/run/output/epoch-230-program-demotion-diagnostic.jet";
const PREFIX_MANIFEST: &str = "/var/lib/jetstreamer/horizon230-program-demotion-ram-v328/private-segment-recovery-v1/epoch-230-private-diagnostic.segment.json";
const PREFIX_MANIFEST_SHA: &str =
    "17d669fe3cb3c1114955809b4cb6d8ba32dd5d403ac575f39a33134723f416a6";
const SUFFIX: &str = "/home/ubuntu/.jetstreamer-private/epoch230-continuation-tmpfs-v1/run-v3/output/epoch-230-slots-99375856-99383572.jet";
const SNAPSHOT_SHA: &str = "ee9e0f0a7b24f9e2171e944fb67c45c2d53b288e858fccfeff1506d513365568";
const BOUNDARY_ROOT: &str = "HouDs53rM8iQ8fuUwyZRFEukWj9ZW6HoHx4fXCSFQRBJ";
const END_ROOT: &str = "HAsyNGf1oLCESAqbCQ8K445g2aw9paY5QScx9maA4wbz";

fn load_manifest(path: &Path, expected: &str) -> Result<HistoricalSegmentManifest> {
    let mut bytes = Vec::new();
    open_regular_nofollow(path)?
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1 << 20 && format!("{:x}", Sha256::digest(&bytes)) == expected,
        "manifest digest mismatch at {}",
        path.display()
    );
    let manifest: HistoricalSegmentManifest = serde_json::from_slice(&bytes)?;
    manifest.validate()?;
    ensure!(
        manifest.epoch == 230
            && manifest.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
    );
    Ok(manifest)
}

fn checkpoint(c: &SegmentCheckpointSummary) -> Result<RuntimeStateCheckpoint> {
    Ok(RuntimeStateCheckpoint {
        slot: c.slot,
        bank_hash: c.bank_hash_value()?,
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: c.accounts_hash_value()?,
        last_blockhash: c.last_blockhash_value()?,
        capitalization: c.capitalization,
        transaction_count: c.transaction_count,
        tick_height: c.tick_height,
        slot_complete: c.slot_complete,
        next_write_version: c.next_write_version,
    })
}

fn segment(m: &HistoricalSegmentManifest, start: u64) -> RuntimeSegmentProvenance {
    RuntimeSegmentProvenance {
        slot_start: m.output_slot_start,
        slot_count: m.output_slot_count,
        generation_profile: m.runtime.generation_profile.clone(),
        runtime_profile: m.runtime.runtime_profile.clone(),
        runtime_admission: RuntimeAdmission::Candidate,
        runtime_revision: m.runtime.runtime_revision.clone(),
        runtime_toolchain: m.runtime.runtime_toolchain.clone(),
        worker_executable_sha256: Some(m.worker_executable_sha256),
        write_versions: WriteVersionNormalization {
            worker_start: m.emitted_raw_write_versions.start,
            worker_end_exclusive: m.emitted_raw_write_versions.end,
            archive_start: start,
        },
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 2 && matches!(args[0].as_str(), "--check" | "--merge"),
        "usage: check_epoch230_segment_join --check|--merge SUFFIX_MANIFEST_SHA256"
    );
    let prefix = load_manifest(Path::new(PREFIX_MANIFEST), PREFIX_MANIFEST_SHA)?;
    let suffix = load_manifest(&segment_manifest_path(SUFFIX)?, &args[1])?;
    ensure!(
        (
            prefix.output_slot_start,
            prefix.terminal.slot,
            suffix.output_slot_start,
            suffix.terminal.slot
        ) == (99_360_000, 99_375_855, 99_375_856, 99_383_572)
    );
    ensure!(
        prefix.output_slot_end()? == suffix.output_slot_start
            && suffix.output_slot_end()? == suffix.terminal.slot + 1
    );
    ensure!(
        prefix.terminal.accounts_hash == BOUNDARY_ROOT
            && suffix.bootstrap.accounts_hash == BOUNDARY_ROOT
            && suffix.terminal.accounts_hash == END_ROOT
    );
    ensure!(
        prefix.runtime.runtime_profile
            == "solana-v1.6.20-epoch230-called-program-demotion-candidate"
            && sha256_hex_string(&prefix.worker_executable_sha256)
                == "19c460438c37a39b585183d315da0db095e2f9f5c2b3614582172724f313f7b0"
    );
    ensure!(
        suffix.runtime.runtime_profile == "solana-v1.6.20"
            && sha256_hex_string(&suffix.worker_executable_sha256)
                == "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c"
    );
    let mut snapshot = [0; 32];
    for (i, b) in snapshot.iter_mut().enumerate() {
        *b = u8::from_str_radix(&SNAPSHOT_SHA[2 * i..2 * i + 2], 16)?;
    }
    ensure!(
        suffix
            .bootstrap_archive_sha256
            .is_none_or(|sha| sha == snapshot)
    );
    let first = segment(&prefix, 0);
    let second = segment(
        &suffix,
        first
            .write_versions
            .archive_end_exclusive()
            .context("prefix write range")?,
    );
    let writes = second
        .write_versions
        .archive_end_exclusive()
        .context("suffix write range")?;
    let mut handles = Vec::new();
    let mut sources = Vec::new();
    for (path, m) in [(Path::new(PREFIX), &prefix), (Path::new(SUFFIX), &suffix)] {
        let file = open_regular_nofollow(path)?;
        let id = archive_file_identity(&file)?;
        handles.push((path, file.try_clone()?, id));
        sources.push(RuntimeSegmentSource::new(
            BufReader::new(file),
            m.archive_sha256,
            m.terminal.last_blockhash_value()?,
        ));
    }
    let header = |file: &File| -> Result<_> {
        let r = ArchiveReader::open(BufReader::new(file.try_clone()?))?;
        let Some(ArchiveProvenance::V2(p)) = r.provenance()? else {
            anyhow::bail!("expected V2 input")
        };
        Ok(p)
    };
    let p = header(&handles[0].1)?;
    let s = header(&handles[1].1)?;
    ensure!(
        p.base.genesis_hash == s.base.genesis_hash
            && p.base.transaction_metadata == s.base.transaction_metadata
    );
    ensure!(
        p.worker_executable_sha256 == prefix.worker_executable_sha256
            && s.worker_executable_sha256 == suffix.worker_executable_sha256
    );
    ensure!(
        p.base.runtime_profile == prefix.runtime.runtime_profile
            && s.base.runtime_profile == suffix.runtime.runtime_profile
    );
    ensure!(
        p.base.bootstrap_state_kind == BootstrapStateKind::SnapshotArchive
            && s.base.bootstrap_state_kind == BootstrapStateKind::SnapshotArchive
    );
    let slots = suffix.output_slot_end()? - prefix.output_slot_start;
    let provenance = ArchiveProvenanceV3 {
        assembly_profile: "jetstreamer-node/epoch230-private-join-v1".into(),
        genesis_hash: p.base.genesis_hash,
        bootstrap_state_kind: p.base.bootstrap_state_kind,
        bootstrap_state: StateCommitment {
            slot: prefix.bootstrap.slot,
            kind: StateCommitmentKind::LegacyAccountsHash,
            hash: prefix.bootstrap.accounts_hash_value()?,
        },
        requested_slot_start: prefix.output_slot_start,
        requested_slot_count: slots,
        transaction_metadata: p.base.transaction_metadata,
        runtime_segments: vec![first, second],
        handoffs: vec![RuntimeHandoffProvenance {
            boundary_slot: suffix.output_slot_start,
            predecessor: checkpoint(&prefix.terminal)?,
            successor: checkpoint(&suffix.bootstrap)?,
            successor_bootstrap_kind: s.base.bootstrap_state_kind,
            successor_bootstrap_archive_sha256: snapshot,
            successor_bootstrap_write_count: suffix.bootstrap.write_count,
        }],
    };
    provenance.validate()?;
    let mut report = json!({"epoch":230,"first_slot":prefix.output_slot_start,"last_slot":suffix.terminal.slot,
        "prefix_archive_sha256":sha256_hex_string(&prefix.archive_sha256),
        "continuation_archive_sha256":sha256_hex_string(&suffix.archive_sha256),
        "consensus_handoff_passed":true,"publication_authorized":false,"archive_written":false});
    if args[0] == "--merge" {
        let (digest, stats) = merge_runtime_segments(
            sources,
            Sha256::new(),
            ArchiveWriterConfig::default(),
            &provenance,
        )?;
        ensure!(
            stats.source_archives == 2
                && stats.slots_merged == slots
                && stats.output.slots == slots
                && stats.account_updates_rebased == writes
        );
        report["merge"] = json!({"bytes":stats.output.bytes_written,"sha256":format!("{:x}",digest.finalize()),
            "slots":stats.slots_merged,"rebased_updates":writes,"transactions":stats.output.transactions,"blocks":stats.output.blocks});
    }
    for (path, file, id) in handles {
        ensure!(archive_file_identity(&file)? == id && path_matches_archive_identity(path, id)?);
    }
    println!("{report}");
    Ok(())
}
