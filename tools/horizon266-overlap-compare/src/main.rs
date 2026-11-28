//! Private terminal evidence and bounded overlap comparison for epoch 266.

#[allow(dead_code)]
#[path = "../../../jetstreamer-node/src/archive_checksum.rs"]
mod archive_checksum;
mod normalized {
    include!(concat!(env!("OUT_DIR"), "/normalized.rs"));
}
#[allow(dead_code)]
#[path = "../../horizon266-dense-prefix/src/original_view.rs"]
mod original_view;
#[allow(dead_code)]
#[path = "../../../jetstreamer-node/src/segment_manifest.rs"]
mod segment_manifest;
#[allow(dead_code)]
#[path = "../../../jetstreamer-node/src/segment_progress.rs"]
mod segment_progress;
#[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
mod terminal;

use anyhow::{Context, Result, ensure};
use archive_checksum::open_regular_nofollow;
use jetstreamer_horizon::archive::{
    ArchiveProvenance, ArchiveReader, BootstrapStateKind, RuntimeAdmission,
};
use normalized::Overlap;
use segment_manifest::{
    HistoricalSegmentManifest, SegmentCheckpointSummary, SegmentRuntimeAdmission, sha256_hex_string,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const EPOCH: u64 = 266;
const START: u64 = 114_923_431;
const OVERLAP_END: u64 = 114_923_520;
const SEGMENT_END: u64 = 114_929_698;
const OLD_CURSOR: u64 = 187_121_877_105;
const RESTART_CURSOR: u64 = 187_129_398_665;
const SEAM_BLOCK: &str = "2AVLhEfu6PZDrYe2UC3y1G6S1QSjySS97HpdvDMB1cC6";
const WORKER_SHA: &str = "763f1aff1f752f0d9886f0f2324a73c9c66a154269d28931575744316bb2f220";
const SNAPSHOT_SHA: &str = "2eb5ef470f76a742907165d6c72d4e543c513294dc3ca6200fa3d560705fd023";
const RUNTIME_REVISION: &str = "423a4d65461e36fefb371a2f164c20c4e7ed5afa";
const GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
const RAW: &str = "/home/ubuntu/.jetstreamer-private/qualification-266-capped-bounded-v210/state/destination-3b3d36405c6940de810510759e829af5e5ec72ffc8e54a1d5eb7ba63860cfc4f/work/root-cohort-266-266/run-3483521-1795402817505873578/archives/epoch-266.jet";
const TRAILER: &str =
    "/home/ubuntu/.jetstreamer-private/epoch266-indexed-prefix.VzRlYb/index-footer.bin";
const TRAILER_SHA: &str = "7209682c763e597309eeea097c0d5f226bfe201c04e600f790c6708eb6d13bb1";
const DENSE: &str = "/home/ubuntu/.jetstreamer-private/epoch266-dense-prefix.UyIG1i/output/epoch-266-prefix-through-114923430.jet";
const DENSE_PARENT: &str = "5FMSUYMxSSJDvnSZtg6fjR5CWPyCyPSUMBLDED5QQKw1";
const SEGMENT: &str = "/home/ubuntu/.jetstreamer-private/qualification-266-hourly-overlap-114929697-v1/work/output/epoch-266-slots-114923431-114929697.jet";
const LAUNCH: &str =
    "/var/lib/jetstreamer/horizon266-hourly-overlap-114929697-runtime-v1/cadence-registration.json";
const UNIT: &str = "horizon-qualify-266-hourly-overlap-114929697-v1.service";
const RESTORE: &str =
    "/var/lib/jetstreamer/horizon266-hourly-checkpoint-runtime-v1/completion-v2.json";
const RESTORE_SHA: &str = "acc63b4e817648d1a04b83bf371088c038d27b7b98d916290110b80976812e30";
const JOURNAL: &str =
    "/var/lib/jetstreamer/horizon266-hourly-checkpoint-runtime-v1/native-result.json";
const JOURNAL_SHA: &str = "780e4fca701f28b0cee5157f975b73240a5a0be1b27584764079e6699076f8e4";
const TERMINAL_ACCOUNTS: &str = "BevfHbX1MRE8ySXdbzp8WZB5i4W1spPhbsZ8UEUhU7di";
const TERMINAL_BLOCK: &str = "2kMwZAMPiphaQsWPNKgtRrpwraXwyatcXfnEY2tHQaMm";
const ARCHIVE_READ_LIMIT: u64 = 128 << 20;
const JSON_LIMIT: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
    mtime_ns: i64,
    ctime_ns: i64,
}

impl FileIdentity {
    fn read(file: &File) -> Result<Self> {
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.nlink() == 1,
            "file is not single-link and regular"
        );
        let nanos =
            |seconds: i64, fraction: i64| seconds.checked_mul(1_000_000_000)?.checked_add(fraction);
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
            bytes: meta.len(),
            mtime_ns: nanos(meta.mtime(), meta.mtime_nsec()).context("mtime overflow")?,
            ctime_ns: nanos(meta.ctime(), meta.ctime_nsec()).context("ctime overflow")?,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ComparePlan {
    schema: String,
    producer_invocation: String,
    launch_sha256: String,
    segment_manifest_sha256: String,
    segment_sha256: String,
    segment_identity: FileIdentity,
    producer_exit_status: u64,
    producer_drained: bool,
    native_manifest_complete_verified: bool,
    publication_authorized: bool,
}

#[derive(Deserialize)]
struct NativeRestore {
    slot: u64,
    bank_hash: String,
    accounts_hash: String,
    last_blockhash: String,
    capitalization: u64,
    transactions_at_root: u64,
    tick_height: u64,
    slot_complete: bool,
    initialization_writes: u64,
    initialized_cursor: u64,
    next_write_version: u64,
    ticks_per_slot: u64,
    snapshot_generation: u64,
    snapshot_sha256: String,
    worker_sha256: String,
    replay_entries_sent: u64,
}

struct LimitedArchive<R> {
    source: R,
    read: u64,
}

impl<R: Read> Read for LimitedArchive<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let available = usize::try_from(ARCHIVE_READ_LIMIT - self.read).unwrap();
        if available == 0 {
            return Err(io::Error::other("archive overlap read budget exhausted"));
        }
        let limit = output.len().min(available);
        let fetched = self.source.read(&mut output[..limit])?;
        self.read += fetched as u64;
        Ok(fetched)
    }
}

impl<R: Seek> Seek for LimitedArchive<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.source.seek(position)
    }
}

fn open(path: &Path) -> Result<(File, FileIdentity)> {
    ensure!(
        path.canonicalize()? == path,
        "path is indirect: {}",
        path.display()
    );
    let file = open_regular_nofollow(path)?;
    let identity = FileIdentity::read(&file)?;
    Ok((file, identity))
}

fn unchanged(path: &Path, file: &File, expected: FileIdentity) -> Result<()> {
    ensure!(
        FileIdentity::read(file)? == expected && open(path)?.1 == expected,
        "file identity changed: {}",
        path.display()
    );
    Ok(())
}

fn hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bound_bytes(path: &Path, expected: &str, bytes_limit: u64, root_owned: bool) -> Result<Vec<u8>> {
    ensure!(hex(expected, 64), "expected a lowercase SHA-256");
    let (file, identity) = open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        !root_owned || (metadata.uid() == 0 && metadata.mode() & 0o222 == 0),
        "unsealed root evidence: {}",
        path.display()
    );
    ensure!(identity.bytes <= bytes_limit, "evidence exceeds size bound");
    let mut bytes = Vec::with_capacity(identity.bytes as usize);
    (&file).take(bytes_limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == identity.bytes
            && sha256_hex_string(&Sha256::digest(&bytes).into()) == expected,
        "evidence hash or length differs: {}",
        path.display()
    );
    unchanged(path, &file, identity)?;
    Ok(bytes)
}

fn bound_json(path: &str, expected: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&bound_bytes(
        Path::new(path),
        expected,
        JSON_LIMIT,
        true,
    )?)?)
}

fn capture<R: Read + Seek>(
    archive: &mut ArchiveReader<LimitedArchive<R>>,
    first: u64,
    end: u64,
    anchor: &str,
    focused_envelope: bool,
) -> Result<Overlap> {
    archive.verify_chain = true;
    let envelope = focused_envelope.then_some(START..SEGMENT_END);
    let mut result = Overlap::new(EPOCH, first..end, anchor, envelope);
    let count = archive.read_slots(first, end - first, &mut result)?;
    result.validate(count, false)?;
    Ok(result)
}

fn retained() -> Result<Overlap> {
    let raw_path = Path::new(RAW);
    let (raw, raw_id) = open(raw_path)?;
    original_view::pinned_source(&raw, raw_path).map_err(|err| anyhow::anyhow!("{err}"))?;
    let trailer = bound_bytes(Path::new(TRAILER), TRAILER_SHA, 1_410, false)?;
    // Derivation reads just 90 short headers and checks the original,
    // already authenticated body identity. The indexed view never writes it.
    original_view::verify_trailer(&raw, &trailer).map_err(|err| anyhow::anyhow!("{err}"))?;
    let view = original_view::open(&raw, &trailer).map_err(|err| anyhow::anyhow!("{err}"))?;
    let mut archive = ArchiveReader::open(LimitedArchive {
        source: view,
        read: 0,
    })?;
    let raw_seam = capture(&mut archive, START - 1, START, DENSE_PARENT, false)?;
    // A second read of the final original bucket is avoided by read_slots'
    // forward continuation. It skips nonselected frame callbacks.
    let overlap = capture(&mut archive, START, OVERLAP_END, SEAM_BLOCK, false)?;
    drop(archive);
    let mut dense = open(Path::new(DENSE))?;
    ensure!(
        dense.1
            == (FileIdentity {
                device: 66305,
                inode: 21898787,
                bytes: 5060736774,
                mtime_ns: 1795775292569156586,
                ctime_ns: 1795775773813666566,
            }),
        "dense prefix no longer names the sealed conversion output"
    );
    let mut dense_reader = ArchiveReader::open(LimitedArchive {
        source: &mut dense.0,
        read: 0,
    })?;
    ensure!(
        dense_reader.header().epoch == EPOCH && dense_reader.header().slot_count == 11_431,
        "foreign dense prefix range"
    );
    let dense_seam = capture(&mut dense_reader, START - 1, START, DENSE_PARENT, false)?;
    normalized::compare("retained dense endpoint", &raw_seam, &dense_seam)?;
    ensure!(
        raw_seam.parent_hash == SEAM_BLOCK
            && raw_seam.versions.next_raw == Some(OLD_CURSOR)
            && raw_seam.versions.first_raw == dense_seam.versions.first_raw
            && raw_seam.versions.next_raw == dense_seam.versions.next_raw,
        "the dense endpoint no longer binds the retained raw cursor"
    );
    ensure!(
        overlap.versions.first_raw == Some(OLD_CURSOR),
        "original overlap does not follow its dense endpoint"
    );
    unchanged(raw_path, &raw, raw_id)?;
    unchanged(Path::new(DENSE), &dense.0, dense.1)?;
    Ok(overlap)
}

fn validate_checkpoint(
    bootstrap: &SegmentCheckpointSummary,
    restore: &NativeRestore,
) -> Result<()> {
    ensure!(
        restore.slot == START - 1
            && restore.snapshot_generation == 1641767192954871
            && restore.snapshot_sha256 == SNAPSHOT_SHA
            && restore.worker_sha256 == WORKER_SHA
            && restore.last_blockhash == SEAM_BLOCK
            && restore.capitalization == 512823375441850375
            && restore.ticks_per_slot == 64
            && restore.slot_complete
            && restore.replay_entries_sent == 0
            && restore.initialization_writes == 0
            && restore.initialized_cursor == RESTART_CURSOR
            && restore.next_write_version == RESTART_CURSOR,
        "lossless same-snapshot restore changed"
    );
    ensure!(
        bootstrap.slot == restore.slot
            && bootstrap.bank_hash == restore.bank_hash
            && bootstrap.accounts_hash == restore.accounts_hash
            && bootstrap.last_blockhash == restore.last_blockhash
            && bootstrap.capitalization == restore.capitalization
            && bootstrap.transaction_count == restore.transactions_at_root
            && bootstrap.tick_height == restore.tick_height
            && bootstrap.slot_complete
            && bootstrap.write_count == 0
            && bootstrap.next_write_version == restore.next_write_version,
        "replay bootstrap differs from the separately executed hourly restore"
    );
    Ok(())
}

fn validate_manifest(manifest: &HistoricalSegmentManifest) -> Result<()> {
    manifest.validate()?;
    ensure!(
        manifest.epoch == EPOCH
            && manifest.output_slot_start == START
            && manifest.output_slot_end()? == SEGMENT_END
            && manifest.runtime.runtime_profile == "solana-v1.8.11"
            && manifest.runtime.runtime_revision == RUNTIME_REVISION
            && manifest.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && manifest.runtime.genesis_hash == GENESIS
            && sha256_hex_string(&manifest.worker_executable_sha256) == WORKER_SHA
            && manifest
                .bootstrap_archive_sha256
                .is_none_or(|sha| sha256_hex_string(&sha) == SNAPSHOT_SHA)
            && manifest.terminal.slot == SEGMENT_END - 1
            && manifest.terminal.accounts_hash == TERMINAL_ACCOUNTS
            && manifest.terminal.last_blockhash == TERMINAL_BLOCK,
        "native segment manifest differs from the selected runtime or canonical terminal reference"
    );
    let restore = bound_json(RESTORE, RESTORE_SHA)?;
    let native = bound_json(JOURNAL, JOURNAL_SHA)?;
    ensure!(
        restore["native_result"] == native
            && restore["native_result_journal_bytes"]
                == json!({"path": JOURNAL, "sha256": JOURNAL_SHA}),
        "lossless restore receipt and journal differ"
    );
    validate_checkpoint(&manifest.bootstrap, &serde_json::from_value(native)?)
}

fn validate_provenance<R: Read + Seek>(
    reader: &mut ArchiveReader<R>,
    manifest: &HistoricalSegmentManifest,
) -> Result<()> {
    let Some(ArchiveProvenance::V2(provenance)) = reader.provenance()? else {
        anyhow::bail!("expected single-runtime V2 segment provenance");
    };
    let header = reader.header();
    ensure!(
        header.epoch == manifest.epoch
            && header.format_version == 2
            && header.slot_start == manifest.output_slot_start
            && header.slot_count == manifest.output_slot_count
            && provenance.base.requested_slot_start == manifest.output_slot_start
            && provenance.base.requested_slot_count == manifest.output_slot_count
            && provenance.base.runtime_profile == manifest.runtime.runtime_profile
            && provenance.base.runtime_revision == manifest.runtime.runtime_revision
            && provenance.base.runtime_admission == RuntimeAdmission::Candidate
            && provenance.base.runtime_toolchain == manifest.runtime.runtime_toolchain
            && provenance.base.genesis_hash.to_string() == manifest.runtime.genesis_hash
            && provenance.base.generation_profile == manifest.runtime.generation_profile
            && provenance.base.bootstrap_slot == manifest.bootstrap.slot
            && provenance.base.bootstrap_state_kind == BootstrapStateKind::SnapshotArchive
            && provenance.base.bootstrap_state_hash.to_string() == manifest.bootstrap.accounts_hash
            && provenance.worker_executable_sha256 == manifest.worker_executable_sha256,
        "selected archive does not carry the bound segment range and bootstrap provenance"
    );
    Ok(())
}

fn compare(plan_path: &Path, plan_sha: &str) -> Result<Value> {
    let plan: ComparePlan =
        serde_json::from_slice(&bound_bytes(plan_path, plan_sha, JSON_LIMIT, true)?)?;
    ensure!(
        plan.schema == "foundation-epoch266-private-overlap-comparison-plan-v1"
            && hex(&plan.producer_invocation, 32)
            && plan.producer_exit_status == 0
            && plan.producer_drained
            && plan.native_manifest_complete_verified
            && !plan.publication_authorized,
        "a closed, privately accepted native segment is required"
    );
    let launch = bound_json(LAUNCH, &plan.launch_sha256)?;
    ensure!(
        launch["epoch"] == EPOCH
            && launch["kind"] == "epoch266-private-hourly-overlap"
            && launch["unit"] == UNIT
            && launch["invocation_id"] == plan.producer_invocation
            && launch["worker"]["sha256"] == WORKER_SHA
            && launch["lossless_restore"]["sha256"] == RESTORE_SHA
            && launch["launched"] == true
            && launch["diagnostic_only"] == true
            && launch["canonical_epoch_publication_authorized"] == false,
        "launch does not bind this private producer and lossless restore"
    );
    let manifest_path = PathBuf::from(format!("{SEGMENT}.segment.json"));
    let manifest_bytes = bound_bytes(
        &manifest_path,
        &plan.segment_manifest_sha256,
        JSON_LIMIT,
        false,
    )?;
    let manifest: HistoricalSegmentManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    ensure!(
        sha256_hex_string(&manifest.archive_sha256) == plan.segment_sha256,
        "manifest does not carry the accepted archive digest"
    );
    let (segment, identity) = open(Path::new(SEGMENT))?;
    ensure!(
        identity == plan.segment_identity,
        "segment no longer matches its accepted immutable identity"
    );
    let mut reader = ArchiveReader::open(LimitedArchive {
        source: &segment,
        read: 0,
    })?;
    validate_provenance(&mut reader, &manifest)?;
    let new = capture(&mut reader, START, OVERLAP_END, SEAM_BLOCK, true)?;
    drop(reader);
    ensure!(
        new.versions.first_raw == Some(manifest.emitted_raw_write_versions.start)
            && new.versions.first_raw == Some(RESTART_CURSOR)
            && new
                .versions
                .next_raw
                .is_some_and(|cursor| cursor <= manifest.emitted_raw_write_versions.end),
        "restarted writes do not match the native segment's independent raw range"
    );
    let old = retained()?;
    let normalized = normalized::compare("epoch 266 overlap", &old, &new)?;
    unchanged(Path::new(SEGMENT), &segment, identity)?;
    Ok(json!({
        "schema": "foundation-epoch266-private-overlap-comparison-v1",
        "epoch": EPOCH, "first_slot": START, "last_slot": OVERLAP_END - 1,
        "slots": OVERLAP_END - START, "terminal_block_slot": new.parent_slot,
        "terminal_blockhash": new.parent_hash,
        "normalized_sha256": sha256_hex_string(&normalized),
        "recorded_predecessor_raw_start": old.versions.first_raw,
        "recorded_predecessor_raw_end_exclusive": old.versions.next_raw,
        "restarted_segment_raw_start": new.versions.first_raw,
        "restarted_segment_raw_end_exclusive": new.versions.next_raw,
        "predecessor_first_event_cursor": old.versions.first_event,
        "restarted_first_event_cursor": new.versions.first_event,
        "bootstrap_checkpoint": manifest.bootstrap, "accounts_hash_kind": "legacy_accounts_hash",
        "bootstrap_tuple_matches_separate_same_snapshot_restore": true,
        "predecessor_native_tuple_qualified": false, "full_prefix_poh_verified": false,
        "complete_segment_archive_sha256_independently_reread": false,
        "segment_manifest_sha256": plan.segment_manifest_sha256,
        "accepted_segment_archive_sha256": plan.segment_sha256,
        "comparison_plan_sha256": plan_sha, "invocation": plan.producer_invocation,
        "canonical_continuation_qualified": false, "publication_authorized": false,
    }))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let output = match args.as_slice() {
        [command] if command == "retained" => {
            let old = retained()?;
            json!({
                "schema": "foundation-epoch266-private-retained-overlap-v1",
                "epoch": EPOCH, "first_slot": START, "last_slot": OVERLAP_END - 1,
                "slots": OVERLAP_END - START, "terminal_block_slot": old.parent_slot,
                "terminal_blockhash": old.parent_hash, "dense_endpoint_matches_original": true,
                "recorded_raw_start": old.versions.first_raw, "recorded_raw_end_exclusive": old.versions.next_raw,
                "normalized_sha256": sha256_hex_string(&normalized::compare("retained scope", &old, &old)?),
                "predecessor_native_tuple_qualified": false, "publication_authorized": false,
            })
        }
        #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
        [command, digest, destination] if command == "collect-terminal" => {
            terminal::collect(digest, Path::new(destination), None)?
        }
        #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
        [command, digest, destination, exit, exit_digest] if command == "collect-terminal" => {
            terminal::collect(
                digest,
                Path::new(destination),
                Some((Path::new(exit), exit_digest)),
            )?
        }
        #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
        [command, digest, destination] if command == "capture-exit" => {
            terminal::capture_exit(digest, Path::new(destination))?
        }
        #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
        [command, digest, destination] if command == "capture-adjacent230-exit" => {
            terminal::capture_adjacent230_exit(digest, Path::new(destination))?
        }
        #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
        [command, digest, destination] if command == "capture-v1627-exit" => {
            terminal::capture_v1627_exit(digest, Path::new(destination))?
        }
        #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
        [command, digest, destination] if command == "capture-predecessor-exit" => {
            terminal::capture_predecessor_exit(digest, Path::new(destination))?
        }
        #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
        [command, launch, exit, destination] if command == "collect-predecessor-terminal" => {
            terminal::collect_predecessor(launch, exit, Path::new(destination))?
        }
        #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
        [command, launch] if command == "drain-failed-predecessor-terminal" => {
            terminal::drain_failed_predecessor(launch)?
        }
        #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
        [command, launch] if command == "finish-predecessor-terminal" => {
            terminal::finish_predecessor(launch)?
        }
        #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
        [command, exit, digest, destination] if command == "collect-v1627-terminal" => {
            terminal::collect_v1627_terminal(Path::new(exit), digest, Path::new(destination))?
        }
        [command, plan, digest] if command == "compare" => compare(Path::new(plan), digest)?,
        _ => anyhow::bail!(
            "usage: horizon266-overlap-compare retained | capture-exit LAUNCH_SHA256 NEW_EXIT_DIRECTORY | capture-v1627-exit LAUNCH_SHA256 NEW_EXIT_DIRECTORY | capture-adjacent230-exit LAUNCH_SHA256 NEW_EXIT_DIRECTORY | capture-predecessor-exit LAUNCH_SHA256 NEW_EXIT_DIRECTORY | collect-predecessor-terminal LAUNCH_SHA256 EXIT_SHA256 NEW_OUTPUT_DIRECTORY | finish-predecessor-terminal LAUNCH_SHA256 | drain-failed-predecessor-terminal LAUNCH_SHA256 | collect-v1627-terminal EXIT_RECEIPT EXIT_SHA256 NEW_OUTPUT_DIRECTORY | collect-terminal LAUNCH_SHA256 NEW_OUTPUT_DIRECTORY [EXIT_RECEIPT EXIT_SHA256] | compare PLAN PLAN_SHA256"
        ),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn restore() -> NativeRestore {
        NativeRestore {
            slot: START - 1,
            bank_hash: "bank".to_owned(),
            accounts_hash: "accounts".to_owned(),
            last_blockhash: SEAM_BLOCK.to_owned(),
            capitalization: 512823375441850375,
            transactions_at_root: 49787614573,
            tick_height: 7355099584,
            slot_complete: true,
            initialization_writes: 0,
            initialized_cursor: RESTART_CURSOR,
            next_write_version: RESTART_CURSOR,
            ticks_per_slot: 64,
            snapshot_generation: 1641767192954871,
            snapshot_sha256: SNAPSHOT_SHA.to_owned(),
            worker_sha256: WORKER_SHA.to_owned(),
            replay_entries_sent: 0,
        }
    }

    fn bootstrap(restore: &NativeRestore) -> SegmentCheckpointSummary {
        SegmentCheckpointSummary {
            slot: restore.slot,
            bank_hash: restore.bank_hash.clone(),
            accounts_hash: restore.accounts_hash.clone(),
            last_blockhash: restore.last_blockhash.clone(),
            capitalization: restore.capitalization,
            transaction_count: restore.transactions_at_root,
            tick_height: restore.tick_height,
            slot_complete: true,
            write_count: 0,
            next_write_version: restore.next_write_version,
        }
    }

    #[test]
    fn checkpoint_refuses_rounded_capitalization_and_foreign_cursor() {
        let restore = restore();
        let mut checkpoint = bootstrap(&restore);
        assert!(validate_checkpoint(&checkpoint, &restore).is_ok());
        checkpoint.capitalization += 25;
        assert!(validate_checkpoint(&checkpoint, &restore).is_err());
        checkpoint.capitalization -= 25;
        checkpoint.next_write_version = OLD_CURSOR;
        assert!(validate_checkpoint(&checkpoint, &restore).is_err());
    }

    #[test]
    fn seeking_does_not_restore_the_read_budget() {
        let mut archive = LimitedArchive {
            source: std::io::Cursor::new([1, 2, 3]),
            read: ARCHIVE_READ_LIMIT - 1,
        };
        let mut buf = [0; 3];
        assert_eq!(archive.read(&mut buf).unwrap(), 1);
        archive.seek(SeekFrom::Start(0)).unwrap();
        assert!(archive.read(&mut buf).is_err());
    }
}
