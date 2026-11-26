//! Assemble the private epoch 186 candidate after both guarded replays have closed.
//!
//! The host controller seals the plan and the two completion attestations
//! after checking native unit exit, archive identity and input projection.
//! The assembler checks the sealed bindings and independently decodes both
//! archives. Publish only after the separate full and current-reader checks.
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{
        AccountsHashKind, ArchiveProvenance, ArchiveProvenanceV3, ArchiveProvenanceV4,
        ArchiveReader, ArchiveWriterConfig, BootstrapStateKind, ChainMismatchPolicy, Consumption,
        RuntimeAdmission, RuntimeHandoffProvenance, RuntimeSegmentProvenance, RuntimeSegmentSource,
        RuntimeStateCheckpoint, SemanticDigest, SlotKind, SlotVisitor, StateCommitment,
        StateCommitmentKind, TransactionMetadataPolicy, WriteVersionNormalization,
        encode_archive_provenance, merge_checkpoint_restart_segments, reencode_archive_prefix,
    },
    block_metas::BlockNotification,
    entries::EntryRecord,
    epochs::EpochMeta,
    transactions::Transaction,
};
use jetstreamer_node::{
    archive_checksum::{
        ArchiveFileIdentity, archive_checksum_path, archive_file_identity, measure_open_archive,
        open_regular_nofollow, path_matches_archive_identity,
    },
    segment_manifest::{
        HistoricalSegmentManifest, SegmentCheckpointSummary, SegmentRuntimeAdmission,
        read_and_validate_segment_manifest_from, sha256_hex_string,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use std::{
    env,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, BufReader, Read, Write},
    ops::Range,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tempfile::NamedTempFile;

const EPOCH: u64 = 186;
const FIRST: u64 = 80_352_000;
const FIRST_PARENT: u64 = 80_351_995;
const PREFIX_UNIT: &str = "horizon-qualify-186-bounded-source-20261125-v1.service";
const PREFIX_SNAPSHOT: &str = "2b128e27dce19d7df54cbcdba52e9fc6e6897fcdce288d05369c41e9382b5112";
const RESTART: u64 = 80_783_539;
const LAST: u64 = 80_783_999;
const TERMINAL: u64 = 80_791_699;
const SELECTED_SLOTS: u64 = LAST - RESTART;
const CHECKPOINT_HASH: &str = "EWu2G86akFM3CKJ8D4YZzi8ASZeaPKm2WXLG239Zjnj9";
const TERMINAL_HASH: &str = "GWUc3stuKEJrz77BfMxZ1Ma9wYwwqH2AF8e9Amo98vwC";
const RESTART_SNAPSHOT: &str = "ae0762718ea638c1a9a94c6bec4bef0d341fe7272346a80cb3c72e8016589cf3";
const WORKER: &str = "9339aa0ee5c39e91ec446bfa561c0e81280a0ddc474a03cf5bb0ce07a3674893";
const REVISION: &str = "5c2dab8055e8162386fcac313b6547f223fd386c";

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptRef {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayInput {
    archive: PathBuf,
    manifest: ReceiptRef,
    terminal_receipt: ReceiptRef,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    prefix: ReplayInput,
    tail: ReplayInput,
    restart_snapshot_custody: ReceiptRef,
    output_directory: PathBuf,
    minimum_home_free_bytes: u64,
    maximum_selection_bytes: u64,
    maximum_archive_bytes: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayCompletion {
    schema: String,
    unit: String,
    invocation_id: String,
    result: String,
    exit_status: u32,
    restarts: u32,
    archive: ReceiptRef,
    manifest: ReceiptRef,
    bootstrap_payload_sha256: String,
}

impl ReplayCompletion {
    fn validate(
        &self,
        input: &ReplayInput,
        bound: &HistoricalSegmentManifest,
        bootstrap_sha256: &str,
    ) -> Result<()> {
        ensure!(
            self.schema == "horizon-epoch186-guarded-replay-completion-v1"
                && self.unit.starts_with("horizon-")
                && self.unit.ends_with(".service")
                && self.invocation_id.len() == 32
                && self.invocation_id.bytes().all(|c| c.is_ascii_hexdigit())
                && self.invocation_id.bytes().any(|c| c != b'0')
                && self.result == "success"
                && self.exit_status == 0
                && self.restarts == 0
                && self.archive.path == input.archive
                && digest(&self.archive.sha256)? == bound.archive_sha256
                && self.manifest == input.manifest
                && self.bootstrap_payload_sha256 == bootstrap_sha256,
            "completion differs from the admitted replay or its artifacts"
        );
        Ok(())
    }
}

fn verify_restart_custody(custody: &ReceiptRef) -> Result<()> {
    let source: serde_json::Value = serde_json::from_slice(&authenticate(custody, true)?)?;
    let bootstrap = &source["bootstrap"];
    ensure!(
        source["schema"] == "horizon-epoch186-verification-tail-source-entry-v1"
            && bootstrap["slot"] == RESTART
            && bootstrap["generation"] == 1_634_788_585_189_220u64
            && bootstrap["bytes"] == 6_838_562_806u64
            && bootstrap["sha256"] == RESTART_SNAPSHOT,
        "restart snapshot custody differs from the trusted generation"
    );
    Ok(())
}

fn digest(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid SHA-256"
    );
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}

fn frozen(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "aliased input"
    );
    let file = open_regular_nofollow(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.nlink() == 1 && meta.mode() & 0o222 == 0,
        "input must be frozen"
    );
    Ok(file)
}

fn authenticate(binding: &ReceiptRef, require_root: bool) -> Result<Vec<u8>> {
    let file = frozen(&binding.path)?;
    ensure!(
        !require_root || file.metadata()?.uid() == 0,
        "authority receipt must be root-owned"
    );
    let identity = archive_file_identity(&file)?;
    let mut bytes = Vec::new();
    (&file).take((1 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1 << 20
            && <[u8; 32]>::from(Sha256::digest(&bytes)) == digest(&binding.sha256)?
            && path_matches_archive_identity(&binding.path, identity)?,
        "receipt differs from its bound digest: {}",
        binding.path.display()
    );
    Ok(bytes)
}

struct Source {
    file: File,
    identity: ArchiveFileIdentity,
    manifest: HistoricalSegmentManifest,
    completion: ReplayCompletion,
}

impl Source {
    fn open(input: &ReplayInput, bootstrap_sha256: &str) -> Result<Self> {
        let file = frozen(&input.archive)?;
        let identity = archive_file_identity(&file)?;
        let bound: HistoricalSegmentManifest =
            serde_json::from_slice(&authenticate(&input.manifest, false)?)?;
        let completion: ReplayCompletion =
            serde_json::from_slice(&authenticate(&input.terminal_receipt, true)?)?;
        completion.validate(input, &bound, bootstrap_sha256)?;
        let manifest =
            read_and_validate_segment_manifest_from(&input.archive, &input.manifest.path)?;
        ensure!(manifest == bound, "segment manifest changed");
        let source = Self {
            file,
            identity,
            manifest,
            completion,
        };
        source.recheck(&input.archive)?;
        Ok(source)
    }

    fn recheck(&self, path: &Path) -> Result<()> {
        ensure!(
            archive_file_identity(&self.file)? == self.identity
                && path_matches_archive_identity(path, self.identity)?,
            "source archive changed"
        );
        Ok(())
    }
}

fn checkpoint(c: &SegmentCheckpointSummary) -> Result<RuntimeStateCheckpoint> {
    Ok(RuntimeStateCheckpoint {
        slot: c.slot,
        bank_hash: c.bank_hash.parse()?,
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: c.accounts_hash.parse()?,
        last_blockhash: c.last_blockhash.parse()?,
        capitalization: c.capitalization,
        transaction_count: c.transaction_count,
        tick_height: c.tick_height,
        slot_complete: c.slot_complete,
        next_write_version: c.next_write_version,
    })
}

fn validate_sources(
    prefix: &HistoricalSegmentManifest,
    tail: &HistoricalSegmentManifest,
) -> Result<()> {
    for source in [prefix, tail] {
        ensure!(
            source.epoch == EPOCH
                && source.runtime.runtime_profile == "solana-v1.6.15"
                && source.runtime.runtime_revision == REVISION
                && source.runtime.genesis_hash
                    == jetstreamer_historical_protocol::MAINNET_GENESIS_HASH
                && source.worker_executable_sha256 == digest(WORKER)?,
            "unexpected replay runtime or source epoch"
        );
    }
    ensure!(
        prefix.runtime == tail.runtime
            && prefix.output_slot_start == FIRST
            && prefix.output_slot_end()? == RESTART + 1
            && prefix.bootstrap.slot == 80_351_283
            && prefix.bootstrap.accounts_hash == "Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8"
            && prefix.terminal.slot == RESTART
            && prefix.terminal.accounts_hash == CHECKPOINT_HASH
            && tail.output_slot_start == RESTART + 1
            && tail.output_slot_end()? == TERMINAL + 1
            && tail.terminal.slot == TERMINAL
            && tail.terminal.accounts_hash == TERMINAL_HASH
            && tail.bootstrap.write_count == 0
            && tail
                .bootstrap_archive_sha256
                .is_none_or(|hash| hash == digest(RESTART_SNAPSHOT).expect("literal digest")),
        "unexpected focused replay extent, snapshot or checkpoint"
    );
    let predecessor = checkpoint(&prefix.terminal)?;
    let mut successor = checkpoint(&tail.bootstrap)?;
    // Raw write cursors belong to their own processes.
    successor.next_write_version = predecessor.next_write_version;
    ensure!(predecessor == successor, "restart Bank state differs");
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct BlockLink {
    slot: u64,
    hash: Hash,
    parent_slot: u64,
    parent_hash: Hash,
}

struct SelectionReader {
    semantic: SemanticDigest,
    versions: Vec<u64>,
    first: Option<BlockLink>,
    last: Option<BlockLink>,
    successor: Option<BlockLink>,
    raw_cursor: Option<u64>,
}

impl SelectionReader {
    fn new(raw_start: u64) -> Self {
        Self {
            semantic: SemanticDigest::new(),
            versions: Vec::new(),
            first: None,
            last: None,
            successor: None,
            raw_cursor: Some(raw_start),
        }
    }

    fn finish_slot(&mut self) {
        self.versions.sort_unstable();
        for version in self.versions.drain(..) {
            self.raw_cursor = self
                .raw_cursor
                .filter(|cursor| *cursor == version)
                .and_then(|cursor| cursor.checked_add(1));
        }
    }
}

impl SlotVisitor for SelectionReader {
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        self.finish_slot();
        if slot <= LAST {
            self.semantic.on_slot_start(slot, kind);
        }
    }

    fn on_epoch(&mut self, meta: &EpochMeta) {
        if meta.first_block_slot <= LAST {
            self.versions
                .extend(meta.updates.iter().map(|(update, _)| update.write_version));
            self.semantic.on_epoch(meta);
        }
    }

    fn on_pre_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        if slot <= LAST {
            self.versions.push(update.write_version);
            self.semantic.on_pre_account_update(slot, update);
        }
    }

    fn on_transaction(&mut self, slot: u64, index: u32, transaction: &Transaction) {
        if slot <= LAST {
            self.versions.extend(
                transaction
                    .iter_account_updates()
                    .map(|(update, _)| update.write_version),
            );
            self.semantic.on_transaction(slot, index, transaction);
        }
    }

    fn on_post_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        if slot <= LAST {
            self.versions.push(update.write_version);
            self.semantic.on_post_account_update(slot, update);
        }
    }

    fn on_block(&mut self, notification: &BlockNotification, entries: &[EntryRecord]) {
        if notification.slot() <= LAST {
            self.semantic.on_block(notification, entries);
        }
        if let BlockNotification::Block(block) = notification {
            let link = BlockLink {
                slot: block.slot,
                hash: block.blockhash,
                parent_slot: block.parent_slot,
                parent_hash: block.parent_blockhash,
            };
            if link.slot <= LAST {
                self.first.get_or_insert(link);
                self.last = Some(link);
            } else {
                self.successor = Some(link);
            }
        }
    }

    fn consumption(&self) -> Consumption {
        self.semantic.consumption()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct Selection {
    first: BlockLink,
    last: BlockLink,
    raw_writes: Range<u64>,
    first_successor: Option<BlockLink>,
    semantic_sha256: String,
}

fn read_selection(
    file: &File,
    manifest: &HistoricalSegmentManifest,
    include_successor: bool,
) -> Result<Selection> {
    let mut reader = ArchiveReader::open(BufReader::new(file.try_clone()?))?;
    let count = SELECTED_SLOTS + u64::from(include_successor);
    let expected_container_count = if include_successor {
        TERMINAL - RESTART
    } else {
        SELECTED_SLOTS
    };
    let header = reader.header();
    ensure!(
        header.epoch == EPOCH
            && header.slot_start == RESTART + 1
            && header.slot_count == expected_container_count
            && reader.has_complete_slot_coverage()?,
        "wrong tail container extent"
    );
    let Some(ArchiveProvenance::V2(provenance)) = reader.provenance()? else {
        anyhow::bail!("tail must have single-runtime V2 provenance");
    };
    ensure!(
        provenance.base.requested_slot_count == expected_container_count
            && provenance.base.transaction_metadata == TransactionMetadataPolicy::observed(),
        "unexpected tail provenance or transaction policy"
    );
    reader.verify_chain = true;
    reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    let mut visitor = SelectionReader::new(manifest.emitted_raw_write_versions.start);
    ensure!(
        reader.read_slots(RESTART + 1, count, &mut visitor)? == count,
        "tail coverage is incomplete"
    );
    visitor.finish_slot();
    let first = visitor.first.context("selected tail has no first block")?;
    let last = visitor.last.context("selected tail has no last block")?;
    let raw_start = manifest.emitted_raw_write_versions.start;
    let raw_end = visitor
        .raw_cursor
        .context("selected tail has a raw write gap or duplicate")?;
    ensure!(
        first.slot == RESTART + 1
            && first.parent_slot == RESTART
            && first.parent_hash == manifest.bootstrap.last_blockhash.parse::<Hash>()?
            && last.slot == LAST
            && raw_end <= manifest.emitted_raw_write_versions.end,
        "selected frame, parent or write extent differs from the replay"
    );
    let first_successor = if include_successor {
        let next = visitor
            .successor
            .context("tail lacks the first successor block")?;
        ensure!(
            next.slot == LAST + 1 && next.parent_slot == LAST && next.parent_hash == last.hash,
            "selected tail does not link to its first successor"
        );
        Some(next)
    } else {
        None
    };
    let start = if raw_end == raw_start {
        manifest.bootstrap.next_write_version
    } else {
        raw_start
    };
    Ok(Selection {
        first,
        last,
        raw_writes: start..start + (raw_end - raw_start),
        first_successor,
        semantic_sha256: sha256_hex_string(&visitor.semantic.finish()?),
    })
}

fn incoming_link(file: &File) -> Result<BlockLink> {
    let mut reader = ArchiveReader::open(BufReader::new(file.try_clone()?))?;
    reader.verify_chain = true;
    reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    let mut visitor = SelectionReader::new(0);
    ensure!(
        reader.read_slots(FIRST, 1, &mut visitor)? == 1,
        "prefix start is missing"
    );
    let block = visitor.first.context("prefix lacks its first block")?;
    ensure!(
        block.slot == FIRST && block.parent_slot == FIRST_PARENT,
        "unexpected incoming parent"
    );
    Ok(block)
}

fn assembly_provenance(
    prefix: &HistoricalSegmentManifest,
    tail: &HistoricalSegmentManifest,
    selection: &Selection,
) -> Result<ArchiveProvenanceV4> {
    let mut normalized_start = 0;
    let mut runtime_segments = Vec::with_capacity(2);
    for (source, count, raw) in [
        (
            prefix,
            RESTART - FIRST + 1,
            &prefix.emitted_raw_write_versions,
        ),
        (tail, SELECTED_SLOTS, &selection.raw_writes),
    ] {
        let write_versions = WriteVersionNormalization {
            worker_start: raw.start,
            worker_end_exclusive: raw.end,
            archive_start: normalized_start,
        };
        normalized_start = write_versions
            .archive_end_exclusive()
            .context("normalized write overflow")?;
        runtime_segments.push(RuntimeSegmentProvenance {
            slot_start: source.output_slot_start,
            slot_count: count,
            generation_profile: source.runtime.generation_profile.clone(),
            runtime_profile: source.runtime.runtime_profile.clone(),
            runtime_admission: match source.runtime.runtime_admission {
                SegmentRuntimeAdmission::Verified => RuntimeAdmission::Verified,
                SegmentRuntimeAdmission::Candidate => RuntimeAdmission::Candidate,
            },
            runtime_revision: source.runtime.runtime_revision.clone(),
            runtime_toolchain: source.runtime.runtime_toolchain.clone(),
            worker_executable_sha256: Some(source.worker_executable_sha256),
            write_versions,
        });
    }
    let provenance = ArchiveProvenanceV4 {
        base: ArchiveProvenanceV3 {
            assembly_profile: format!(
                "{}/epoch186-checkpoint-restart-v1",
                prefix.runtime.generation_profile
            ),
            genesis_hash: prefix.runtime.genesis_hash.parse()?,
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_state: StateCommitment {
                slot: prefix.bootstrap.slot,
                kind: StateCommitmentKind::LegacyAccountsHash,
                hash: prefix.bootstrap.accounts_hash.parse()?,
            },
            requested_slot_start: FIRST,
            requested_slot_count: LAST - FIRST + 1,
            transaction_metadata: TransactionMetadataPolicy::observed(),
            runtime_segments,
            handoffs: vec![RuntimeHandoffProvenance {
                boundary_slot: RESTART + 1,
                predecessor: checkpoint(&prefix.terminal)?,
                successor: checkpoint(&tail.bootstrap)?,
                successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                successor_bootstrap_archive_sha256: digest(RESTART_SNAPSHOT)?,
                successor_bootstrap_write_count: tail.bootstrap.write_count,
            }],
        },
    };
    provenance.validate()?;
    Ok(provenance)
}

struct BoundedSink<'a> {
    file: &'a mut File,
    directory: &'a File,
    maximum: u64,
    floor: u64,
    written: u64,
    phase: &'static str,
    last_progress: Instant,
}

impl Write for BoundedSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = bytes.len() as u64;
        if next > self.maximum.saturating_sub(self.written) {
            return Err(io::Error::other("archive exceeds admitted allocation"));
        }
        check_floor(self.directory, self.floor, next)?;
        let written = self.file.write(bytes)?;
        self.written += written as u64;
        if self.last_progress.elapsed() >= Duration::from_secs(60) {
            eprintln!("epoch {EPOCH} {} wrote {} bytes", self.phase, self.written);
            self.last_progress = Instant::now();
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn check_floor(directory: &File, floor: u64, next: u64) -> io::Result<()> {
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stats = unsafe { stats.assume_init() };
    if stats
        .f_bavail
        .saturating_mul(stats.f_frsize)
        .saturating_sub(next)
        < floor
    {
        return Err(io::Error::other(
            "write would cross the admitted HOME floor",
        ));
    }
    Ok(())
}

fn absent(path: &Path) -> Result<()> {
    ensure!(
        path.symlink_metadata()
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
        "output already exists: {}",
        path.display()
    );
    Ok(())
}

fn run(plan_ref: ReceiptRef) -> Result<()> {
    let plan: Plan = serde_json::from_slice(&authenticate(&plan_ref, true)?)?;
    ensure!(
        plan.schema == "jetstreamer-private-epoch186-assembly-plan-v1"
            && plan.minimum_home_free_bytes > 0
            && plan.maximum_selection_bytes > 0
            && plan.maximum_archive_bytes > 0,
        "unexpected plan schema or empty allocation"
    );
    verify_restart_custody(&plan.restart_snapshot_custody)?;
    let root = &plan.output_directory;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(root)?;
    let meta = directory.metadata()?;
    ensure!(
        root.is_absolute()
            && root.canonicalize()? == *root
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0
            && meta.dev() == fs::metadata("/home/sol")?.dev(),
        "output directory must be private and HOME-backed"
    );
    ensure!(
        unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "assembly directory already in use"
    );
    check_floor(
        &directory,
        plan.minimum_home_free_bytes,
        plan.maximum_selection_bytes
            .checked_add(plan.maximum_archive_bytes)
            .context("allocation overflow")?,
    )?;
    let result_path = root.join("epoch-186.jet");
    let receipt_path = root.join("assembly.json");
    for path in [
        &result_path,
        &receipt_path,
        &archive_checksum_path(&result_path)?,
    ] {
        absent(path)?;
    }

    eprintln!("epoch {EPOCH} verifying the complete prefix and tail inputs");
    let prefix = Source::open(&plan.prefix, PREFIX_SNAPSHOT)?;
    let tail = Source::open(&plan.tail, RESTART_SNAPSHOT)?;
    ensure!(
        prefix.completion.unit == PREFIX_UNIT
            && prefix.completion.unit != tail.completion.unit
            && prefix.completion.invocation_id != tail.completion.invocation_id,
        "replays must match the prefix service and distinct tail invocation"
    );
    validate_sources(&prefix.manifest, &tail.manifest)?;
    let incoming = incoming_link(&prefix.file)?;
    eprintln!("epoch {EPOCH} selecting and independently rereading {SELECTED_SLOTS} tail slots");
    let original = read_selection(&tail.file, &tail.manifest, true)?;
    let mut selected = NamedTempFile::new_in(root)?;
    let sink = BoundedSink {
        file: selected.as_file_mut(),
        directory: &directory,
        maximum: plan.maximum_selection_bytes,
        floor: plan.minimum_home_free_bytes,
        written: 0,
        phase: "tail extraction",
        last_progress: Instant::now(),
    };
    let (mut sink, extraction) = reencode_archive_prefix(
        BufReader::new(tail.file.try_clone()?),
        sink,
        ArchiveWriterConfig::default(),
        SELECTED_SLOTS,
    )?;
    sink.flush()?;
    sink.file.sync_all()?;
    let selection = read_selection(selected.as_file(), &tail.manifest, false)?;
    ensure!(
        extraction.slots_reencoded == SELECTED_SLOTS
            && original.semantic_sha256 == sha256_hex_string(&extraction.source_semantic_sha256)
            && selection.semantic_sha256 == sha256_hex_string(&extraction.output_semantic_sha256)
            && selection.first == original.first
            && selection.last == original.last
            && selection.raw_writes == original.raw_writes,
        "independent selection check differs from the original tail"
    );

    let provenance = assembly_provenance(&prefix.manifest, &tail.manifest, &selection)?;
    let encoded_provenance = encode_archive_provenance(&ArchiveProvenance::V4(provenance.clone()))?;
    let selected_identity = measure_open_archive(selected.as_file())?;
    let sources = vec![
        RuntimeSegmentSource::new(
            BufReader::new(prefix.file.try_clone()?),
            prefix.manifest.archive_sha256,
            prefix.manifest.terminal.last_blockhash.parse()?,
        ),
        RuntimeSegmentSource::new(
            BufReader::new(selected.as_file().try_clone()?),
            selected_identity.sha256,
            selection.last.hash,
        ),
    ];
    let mut output = NamedTempFile::new_in(root)?;
    let sink = BoundedSink {
        file: output.as_file_mut(),
        directory: &directory,
        maximum: plan.maximum_archive_bytes,
        floor: plan.minimum_home_free_bytes,
        written: 0,
        phase: "V4 assembly",
        last_progress: Instant::now(),
    };
    eprintln!("epoch {EPOCH} assembling the exact V4 range");
    let (mut sink, assembled) = merge_checkpoint_restart_segments(
        sources,
        sink,
        ArchiveWriterConfig::default(),
        &provenance,
    )?;
    sink.flush()?;
    sink.file.set_permissions(Permissions::from_mode(0o400))?;
    sink.file.sync_all()?;
    let bytes = sink.written;
    let expected_writes = provenance.base.runtime_segments[1]
        .write_versions
        .archive_end_exclusive()
        .context("missing final write cursor")?;
    ensure!(
        assembled.slots_merged == LAST - FIRST + 1
            && assembled.account_updates_rebased == expected_writes,
        "assembled frame or write count differs"
    );
    prefix.recheck(&plan.prefix.archive)?;
    tail.recheck(&plan.tail.archive)?;
    ensure!(
        archive_file_identity(selected.as_file())? == selected_identity.identity,
        "selected source changed"
    );
    eprintln!("epoch {EPOCH} hashing the assembled archive");
    let output_hash = measure_open_archive(output.as_file())?.sha256;
    let mut receipt = NamedTempFile::new_in(root)?;
    serde_json::to_writer_pretty(
        &mut receipt,
        &json!({
            "schema": "jetstreamer-private-epoch186-assembly-v1",
            "plan": plan_ref,
            "prefix": plan.prefix,
            "tail": plan.tail,
        "prefix_completion": prefix.completion,
        "tail_completion": tail.completion,
        "incoming_block": incoming,
            "restart_snapshot_custody": plan.restart_snapshot_custody,
            "complete_tail_terminal": tail.manifest.terminal,
            "tail_source_semantic_sha256": original.semantic_sha256,
        "first_successor_after_cut": original.first_successor,
            "selected_tail": selection,
            "selected_tail_sha256": sha256_hex_string(&selected_identity.sha256),
            "output_path": result_path,
            "output_bytes": bytes,
            "archive_sha256": sha256_hex_string(&output_hash),
            "provenance_sha256": sha256_hex_string(&Sha256::digest(encoded_provenance).into()),
            "slots": assembled.slots_merged,
            "normalized_writes": assembled.account_updates_rebased,
            "publication_authorized": false,
        }),
    )?;
    receipt.write_all(b"\n")?;
    receipt
        .as_file()
        .set_permissions(Permissions::from_mode(0o400))?;
    receipt.as_file().sync_all()?;
    absent(&archive_checksum_path(&result_path)?)?;
    let current = root.symlink_metadata()?;
    ensure!(
        meta.dev() == current.dev() && meta.ino() == current.ino(),
        "output directory changed"
    );
    output.persist_noclobber(&result_path)?;
    directory.sync_all()?;
    receipt.persist_noclobber(&receipt_path)?;
    directory.sync_all()?;
    println!("{}", receipt_path.display());
    Ok(())
}

fn main() -> Result<()> {
    let [path, sha256] = env::args_os()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| {
            anyhow::anyhow!("usage: jetstreamer-epoch186-assemble PLAN.json PLAN_SHA256")
        })?;
    run(ReceiptRef {
        path: path.into(),
        sha256: sha256
            .into_string()
            .map_err(|_| anyhow::anyhow!("expected a UTF-8 plan digest"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetstreamer_horizon::{
        archive::{ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveWriter, Compression},
        block_metas::BlockMeta,
    };

    fn hash(value: u8) -> Hash {
        Hash::new_from_array([value; 32])
    }

    fn checkpoint_at(
        slot: u64,
        accounts_hash: &str,
        blockhash: Hash,
        cursor: u64,
    ) -> serde_json::Value {
        json!({
            "slot": slot,
            "bank_hash": hash(30).to_string(),
            "accounts_hash": accounts_hash,
            "last_blockhash": blockhash.to_string(),
            "capitalization": 42,
            "transaction_count": 77,
            "tick_height": 123,
            "slot_complete": true,
            "write_count": 0,
            "next_write_version": cursor,
        })
    }

    fn write_fixture(
        start: u64,
        last: u64,
        bootstrap_slot: u64,
        bootstrap_accounts: &str,
        anchor: Hash,
        blocks: &[(u64, u64, Hash, &[u64])],
    ) -> Result<File> {
        let count = last - start + 1;
        let provenance = ArchiveProvenance::V2(ArchiveProvenanceV2 {
            base: ArchiveProvenanceV1 {
                generation_profile: "jetstreamer-node/historical-replay-v1".into(),
                runtime_profile: "solana-v1.6.15".into(),
                runtime_admission: RuntimeAdmission::Candidate,
                runtime_revision: REVISION.into(),
                runtime_toolchain: "rustc 1.51.0".into(),
                genesis_hash: jetstreamer_historical_protocol::MAINNET_GENESIS_HASH.parse()?,
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_slot,
                bootstrap_state_hash: bootstrap_accounts.parse()?,
                requested_slot_start: start,
                requested_slot_count: count,
                transaction_metadata: TransactionMetadataPolicy::observed(),
            },
            worker_executable_sha256: digest(WORKER)?,
        });
        let config = ArchiveWriterConfig {
            compression: Compression::None,
            ..Default::default()
        };
        let mut writer = ArchiveWriter::new_with_provenance(
            tempfile::tempfile()?,
            EPOCH,
            start,
            count,
            config,
            &provenance,
        )?;
        writer.preserve_initial_poh_anchor(start, anchor)?;
        let mut running_hash = anchor;
        let mut blocks = blocks.iter().peekable();
        let mut first = true;
        for slot in start..=last {
            let Some(&(block_slot, parent, blockhash, versions)) = blocks.peek().copied() else {
                writer.write_skipped_slot(slot)?;
                continue;
            };
            if block_slot != slot {
                writer.write_skipped_slot(slot)?;
                continue;
            }
            blocks.next();
            writer.begin_slot(slot)?;
            if first {
                first = false;
                let mut meta = EpochMeta::new_boxed();
                meta.epoch = EPOCH;
                meta.start_slot = start;
                meta.slot_count = count;
                meta.first_block_slot = slot;
                writer.write_epoch_meta(&meta)?;
            }
            for &version in versions {
                writer.write_orphan_update(&AccountUpdateView {
                    pubkey: Default::default(),
                    owner: Default::default(),
                    lamports: 1,
                    executable: false,
                    rent_epoch: 0,
                    write_version: version,
                    data: &[1, 2, 3],
                })?;
            }
            let mut meta = BlockMeta::new_boxed();
            meta.slot = slot;
            meta.parent_slot = parent;
            meta.parent_blockhash = running_hash;
            meta.blockhash = blockhash;
            writer.end_slot(&meta, &[])?;
            running_hash = blockhash;
        }
        Ok(writer.finish()?.0)
    }

    fn manifest(
        source: &File,
        range: Range<u64>,
        bootstrap: serde_json::Value,
        terminal: serde_json::Value,
        writes: Range<u64>,
    ) -> Result<HistoricalSegmentManifest> {
        Ok(serde_json::from_value(json!({
            "schema_version": 1,
            "epoch": EPOCH,
            "output_slot_start": range.start,
            "output_slot_count": range.end - range.start,
            "runtime": {
                "generation_profile":"jetstreamer-node/historical-replay-v1",
                "runtime_profile":"solana-v1.6.15",
                "runtime_admission":"candidate",
                "runtime_revision": REVISION,
                "runtime_toolchain":"rustc 1.51.0",
                "runtime_target":"x86_64-unknown-linux-gnu",
                "genesis_hash": jetstreamer_historical_protocol::MAINNET_GENESIS_HASH,
            },
            "worker_executable_sha256": WORKER,
            "archive_sha256": sha256_hex_string(&measure_open_archive(source)?.sha256),
            "bootstrap": bootstrap,
            "terminal": terminal,
            "emitted_raw_write_versions": writes,
        }))?)
    }

    #[test]
    fn joins_exact_epoch_and_excludes_post_epoch_frames_and_writes() -> Result<()> {
        let initial = "Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8";
        let prefix = write_fixture(
            FIRST,
            RESTART,
            80_351_283,
            initial,
            hash(1),
            &[
                (FIRST, FIRST - 5, hash(2), &[100]),
                (RESTART, FIRST, hash(3), &[101]),
            ],
        )?;
        let tail = write_fixture(
            RESTART + 1,
            TERMINAL,
            RESTART,
            CHECKPOINT_HASH,
            hash(3),
            &[
                (RESTART + 1, RESTART, hash(4), &[201, 200]),
                (LAST, RESTART + 1, hash(5), &[202]),
                (LAST + 1, LAST, hash(6), &[203]),
                (TERMINAL, LAST + 1, hash(7), &[204]),
            ],
        )?;
        let pm = manifest(
            &prefix,
            FIRST..RESTART + 1,
            checkpoint_at(80_351_283, initial, hash(1), 100),
            checkpoint_at(RESTART, CHECKPOINT_HASH, hash(3), 102),
            100..102,
        )?;
        let mut tm = manifest(
            &tail,
            RESTART + 1..TERMINAL + 1,
            checkpoint_at(RESTART, CHECKPOINT_HASH, hash(3), 200),
            checkpoint_at(TERMINAL, TERMINAL_HASH, hash(7), 205),
            200..205,
        )?;
        pm.validate()?;
        tm.validate()?;
        validate_sources(&pm, &tm)?;

        assert_eq!(incoming_link(&prefix)?.parent_slot, FIRST_PARENT);
        let input = ReplayInput {
            archive: "/tmp/fixture-tail.jet".into(),
            manifest: ReceiptRef {
                path: "/tmp/fixture-tail.segment.json".into(),
                sha256: "01".repeat(32),
            },
            terminal_receipt: ReceiptRef {
                path: "/tmp/terminal.json".into(),
                sha256: "02".repeat(32),
            },
        };
        let mut completion = ReplayCompletion {
            schema: "horizon-epoch186-guarded-replay-completion-v1".into(),
            unit: "horizon-epoch186-tail-fixture.service".into(),
            invocation_id: "13".repeat(16),
            result: "success".into(),
            exit_status: 0,
            restarts: 0,
            archive: ReceiptRef {
                path: input.archive.clone(),
                sha256: sha256_hex_string(&tm.archive_sha256),
            },
            manifest: ReceiptRef {
                path: input.manifest.path.clone(),
                sha256: input.manifest.sha256.clone(),
            },
            bootstrap_payload_sha256: RESTART_SNAPSHOT.into(),
        };
        completion.validate(&input, &tm, RESTART_SNAPSHOT)?;
        completion.restarts = 1;
        assert!(completion.validate(&input, &tm, RESTART_SNAPSHOT).is_err());
        completion.restarts = 0;
        assert!(completion.validate(&input, &tm, PREFIX_SNAPSHOT).is_err());
        completion.archive.sha256 = "03".repeat(32);
        assert!(completion.validate(&input, &tm, RESTART_SNAPSHOT).is_err());
        let original = read_selection(&tail, &tm, true)?;
        assert_eq!(original.raw_writes, 200..203);
        assert_eq!(original.first_successor.unwrap().hash, hash(6));
        tm.emitted_raw_write_versions.start = 201;
        assert!(read_selection(&tail, &tm, true).is_err());
        tm.emitted_raw_write_versions.start = 200;
        tm.bootstrap.bank_hash = hash(99).to_string();
        assert!(validate_sources(&pm, &tm).is_err());
        tm.bootstrap.bank_hash = pm.terminal.bank_hash.clone();
        let (selected, extraction) = reencode_archive_prefix(
            BufReader::new(tail.try_clone()?),
            tempfile::tempfile()?,
            ArchiveWriterConfig::default(),
            SELECTED_SLOTS,
        )?;
        assert_eq!(
            sha256_hex_string(&extraction.source_semantic_sha256),
            original.semantic_sha256
        );
        let measured = read_selection(&selected, &tm, false)?;
        assert_eq!(
            sha256_hex_string(&extraction.output_semantic_sha256),
            measured.semantic_sha256
        );
        assert_eq!(measured.raw_writes, original.raw_writes);
        let v4 = assembly_provenance(&pm, &tm, &measured)?;
        let selected_digest = measure_open_archive(&selected)?.sha256;
        let (output, stats) = merge_checkpoint_restart_segments(
            vec![
                RuntimeSegmentSource::new(BufReader::new(prefix), pm.archive_sha256, hash(3)),
                RuntimeSegmentSource::new(BufReader::new(selected), selected_digest, hash(5)),
            ],
            tempfile::tempfile()?,
            ArchiveWriterConfig::default(),
            &v4,
        )?;
        assert_eq!(stats.slots_merged, 432_000);
        assert_eq!(stats.account_updates_rebased, 5);
        let mut result = ArchiveReader::open(output)?;
        assert!(result.has_complete_slot_coverage()?);
        assert_eq!(result.header().slot_count, 432_000);
        assert_eq!(result.provenance()?, Some(ArchiveProvenance::V4(v4)));
        Ok(())
    }
}
