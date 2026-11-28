//! Test-only real CAR suffix recording and guarded production V4 assembly.
use super::*;
use crate::*;
use jetstreamer_horizon::archive::{
    ArchiveProvenance, ArchiveReader, ChainMismatchPolicy, SlotVisitor,
};

fn prefix(directory: &std::path::Path) -> HistoricalSegmentManifest {
    read_and_validate_segment_manifest(&directory.join("export/validated-prefix/prefix.jet"))
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record(
    directory: &std::path::Path,
    bootstrap: &Checkpoint,
    terminal: &Checkpoint,
    entries: &[EntryRequest],
    replay: &Arc<HistoricalReplay>,
    shutdown: Arc<AtomicBool>,
    failure: Arc<ReplayFailure>,
) {
    let prefix = prefix(directory);
    let start = bootstrap.slot + 1;
    assert_eq!(terminal.slot, start);
    assert_eq!(prefix.terminal.slot, bootstrap.slot);
    let presence = Arc::new(SlotPresenceMap {
        start,
        end_inclusive: terminal.slot,
        states: vec![SlotPresenceState::Present],
        next_present_after: vec![None],
    });
    let runtime = &prefix.runtime;
    let provenance = ArchiveProvenanceV2 {
        base: ArchiveProvenanceV1 {
            generation_profile: runtime.generation_profile.clone(),
            runtime_profile: runtime.runtime_profile.clone(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: runtime.runtime_revision.clone(),
            runtime_toolchain: runtime.runtime_toolchain.clone(),
            genesis_hash: runtime.genesis_hash.parse().unwrap(),
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_slot: bootstrap.slot,
            bootstrap_state_hash: Hash::new_from_array(
                bootstrap.accounts_hash.clone().try_into().unwrap(),
            ),
            requested_slot_start: start,
            requested_slot_count: 1,
            transaction_metadata: archive_transaction_metadata_policy(start, 1),
        },
        worker_executable_sha256: prefix.worker_executable_sha256,
    };
    horizon::init(
        &directory.join("suffix.jet"),
        prefix.epoch,
        start,
        1,
        presence.clone(),
        &provenance.into(),
        Some((
            bootstrap.slot,
            Hash::new_from_array(bootstrap.last_blockhash.clone().try_into().unwrap()),
        )),
    )
    .unwrap();
    let scheduler = Arc::new(TransactionScheduler::new(
        start,
        presence,
        Arc::new(RestartTracker::new()),
        0,
    ));
    let progress = Arc::new(ReplayProgress::new(start));
    let (sender, receiver) = crossbeam_channel::bounded(entries.len() + 1);
    let gate = Arc::new(Mutex::new(()));
    let active = Arc::new(Mutex::new(None));
    let backpressure = Arc::new(AtomicBool::new(false));
    let producers = ReplayReadyEntryProducers {
        transaction: Arc::new(BankTransactionNotifier {
            progress: progress.clone(),
            scheduler: scheduler.clone(),
            failure: failure.clone(),
            ready_sender: sender.clone(),
            shutdown: shutdown.clone(),
            active_firehose_stop: active.clone(),
            backpressure_stop_requested: backpressure.clone(),
            firehose_backpressure_slot_gap_limit: 100,
            firehose_gate: gate.clone(),
        }),
        entry: Arc::new(BankEntryNotifier {
            progress: progress.clone(),
            scheduler: scheduler.clone(),
            failure: failure.clone(),
            ready_sender: sender.clone(),
            shutdown: shutdown.clone(),
            active_firehose_stop: active.clone(),
            backpressure_stop_requested: backpressure.clone(),
            firehose_backpressure_slot_gap_limit: 100,
            firehose_gate: gate.clone(),
        }),
        block_parent: Arc::new(BankBlockParentNotifier {
            scheduler: scheduler.clone(),
            failure: failure.clone(),
            ready_sender: sender.clone(),
            firehose_gate: gate.clone(),
            checkpoint_boundary: None,
        }),
        block_metadata: Arc::new(BankBlockMetadataNotifier {
            scheduler: scheduler.clone(),
            progress,
            failure: failure.clone(),
            ready_sender: sender.clone(),
            live_start_slot: start,
            shutdown: shutdown.clone(),
            active_firehose_stop: active,
            backpressure_stop_requested: backpressure,
            firehose_backpressure_slot_gap_limit: 100,
            firehose_gate: gate,
        }),
    };
    let notifiers = producers.geyser_notifiers();
    let completed = source_car::deliver_complete(bootstrap, entries, &producers, shutdown.clone());
    assert_eq!(completed.slot, terminal.slot);
    assert_eq!(completed.parent_slot, bootstrap.slot);
    assert_eq!(completed.blockhash.as_slice(), terminal.last_blockhash);
    assert_eq!(completed.entries, entries.len() as u64);
    assert_eq!(completed.transactions, 1);
    assert!(!shutdown.load(Ordering::SeqCst));
    assert!(
        failure.error_message().is_none(),
        "{:?}",
        failure.error_message()
    );
    send_ready_entries(&sender, &failure, scheduler.drain_ready_entries().unwrap());
    let consumer = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn({
            let replay = replay.clone();
            let failure = failure.clone();
            move || {
                ready_entry_drain::consume(
                    receiver,
                    &shutdown,
                    |entries| {
                        replay.process_ready_entries(entries);
                        failure.error_message().map_or(Ok(()), Err)
                    },
                    |_, _| {},
                )
            }
        })
        .unwrap();
    let drained = ready_entry_drain::close(notifiers, producers, sender, consumer).unwrap();
    assert_eq!(drained.entries, entries.len() as u64);
    scheduler.verify_complete(terminal.slot).unwrap();
    assert!(
        failure.error_message().is_none(),
        "{:?}",
        failure.error_message()
    );
}

#[derive(Default)]
struct Observed {
    slots: Vec<u64>,
    epochs: Vec<(u64, u64, u64)>,
    transactions: usize,
    versions: Vec<u64>,
}
impl SlotVisitor for Observed {
    fn on_slot_start(&mut self, slot: u64, _: jetstreamer_horizon::archive::SlotKind) {
        self.slots.push(slot);
    }
    fn on_epoch(&mut self, meta: &jetstreamer_horizon::archive::EpochMeta) {
        self.epochs
            .push((meta.epoch, meta.start_slot, meta.slot_count));
        self.versions
            .extend(meta.updates.iter().map(|(update, _)| update.write_version));
    }
    fn on_pre_account_update(
        &mut self,
        _: u64,
        update: &jetstreamer_horizon::account_updates::AccountUpdateView<'_>,
    ) {
        self.versions.push(update.write_version);
    }
    fn on_transaction(
        &mut self,
        _: u64,
        _: u32,
        tx: &jetstreamer_horizon::transactions::Transaction,
    ) {
        self.transactions += 1;
        self.versions.extend(
            tx.iter_account_updates()
                .map(|(update, _)| update.write_version),
        );
    }
    fn on_post_account_update(
        &mut self,
        _: u64,
        update: &jetstreamer_horizon::account_updates::AccountUpdateView<'_>,
    ) {
        self.versions.push(update.write_version);
    }
}

pub(super) fn assemble(
    directory: &std::path::Path,
    snapshot: &crate::historical::HistoricalSnapshotExport,
    evidence: &HistoricalReplayEvidence,
    proof: &crate::qualification_checkpoint_resume::ValidatedResume,
) {
    let prefix = prefix(directory);
    let suffix_path = directory.join("suffix.jet");
    let checkpoint =
        runtime_checkpoint_from_manifest(&segment_checkpoint_summary(&evidence.terminal)).unwrap();
    horizon::finish_checkpoint_segment(&checkpoint)
        .unwrap()
        .unwrap();
    fs::File::open(&suffix_path).unwrap().sync_all().unwrap();
    let manifest = HistoricalSegmentManifest {
        schema_version: jetstreamer_node::segment_manifest::SEGMENT_MANIFEST_SCHEMA_VERSION,
        epoch: prefix.epoch,
        output_slot_start: prefix.terminal.slot + 1,
        output_slot_count: 1,
        runtime: prefix.runtime.clone(),
        worker_executable_sha256: prefix.worker_executable_sha256,
        archive_sha256: Sha256::digest(fs::read(&suffix_path).unwrap()).into(),
        bootstrap_archive_sha256: Some(snapshot.archive_sha256),
        bootstrap: segment_checkpoint_summary(&evidence.bootstrap),
        terminal: segment_checkpoint_summary(&evidence.terminal),
        emitted_raw_write_versions: evidence.emitted_write_versions.clone(),
    };
    let (_, written) = write_segment_manifest(&suffix_path, manifest).unwrap();
    let verified = read_and_validate_segment_manifest(&suffix_path).unwrap();
    assert_eq!(written, verified);
    proof.assemble(&suffix_path, &verified).unwrap();
    let archive = suffix_path.with_extension("restart-v4.jet");
    let mut reader = ArchiveReader::open(fs::File::open(&archive).unwrap()).unwrap();
    let provenance = match reader.provenance().unwrap().unwrap() {
        ArchiveProvenance::V4(value) => value,
        other => panic!("expected production V4 assembly, got {other:?}"),
    };
    assert_eq!(
        provenance.base.requested_slot_start,
        prefix.output_slot_start
    );
    assert_eq!(provenance.base.requested_slot_count, 2);
    assert_eq!(provenance.base.runtime_segments.len(), 2);
    assert_eq!(provenance.base.handoffs.len(), 1);
    reader.verify_chain = true;
    reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    let mut observed = Observed::default();
    for bucket in 0..reader.bucket_count() {
        reader.read_bucket(bucket, &mut observed).unwrap();
    }
    assert_eq!(
        observed.slots,
        vec![prefix.output_slot_start, verified.output_slot_start]
    );
    assert_eq!(
        observed.epochs,
        vec![(prefix.epoch, prefix.output_slot_start, 2)]
    );
    assert_eq!(observed.transactions, 2);
    let versions = (prefix.emitted_raw_write_versions.end
        - prefix.emitted_raw_write_versions.start)
        + (verified.emitted_raw_write_versions.end - verified.emitted_raw_write_versions.start);
    observed.versions.sort_unstable();
    assert_eq!(observed.versions, (0..versions).collect::<Vec<_>>());
    eprintln!(
        "production native suffix recorded and V4 assembly fully decoded with PoH rejection: path={} sha256={:x} slots=2 transactions=2 normalized_updates={versions}; full epoch/mainnet qualification=false",
        archive.display(),
        Sha256::digest(fs::read(&archive).unwrap())
    );
}
