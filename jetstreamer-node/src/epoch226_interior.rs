//! Private interior-range extraction. Container normalization adds no account writes.
//! Callers own whole-source authentication, no-clobber output, allocation admission,
//! source identity revalidation and an independent complete output reread.
use jetstreamer_horizon::archive::{
    ArchiveFormatError, ArchiveProvenance, ArchiveReader, ArchiveStats, ArchiveVersion,
    ArchiveWriter, ArchiveWriterConfig, BlockNotification, ChainMismatchPolicy, Consumption,
    EntryRecord, EpochMeta, FORMAT_VERSION_V2, SemanticDigest, SlotKind, SlotVisitor,
};
use jetstreamer_horizon::{account_updates::AccountUpdateView, transactions::Transaction};
use solana_hash::Hash;
use std::{
    io::{Read, Seek, Write},
    ops::Range,
};

/// Explicit selected extent. The source header is never rewritten or relabeled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InteriorSelection {
    pub epoch: u64,
    pub start: u64,
    pub count: u64,
    /// Independently accepted canonical predecessor of the first selected block.
    pub first_parent_slot: u64,
    pub first_parent_blockhash: Hash,
    pub terminal_last_blockhash: Hash,
}

/// Both digests are necessary: output contains one new, empty structural EpochMeta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InteriorExtractionStats {
    pub source_epoch: u64,
    pub source_start: u64,
    pub source_count: u64,
    pub selected: InteriorSelection,
    pub selected_source_semantic_sha256: [u8; 32],
    pub output_semantic_sha256: [u8; 32],
    /// Min/max of actual emitted events, never inferred from a native cursor.
    pub emitted_raw_write_versions: Option<Range<u64>>,
    pub output: ArchiveStats,
}

fn invalid(message: &'static str) -> ArchiveFormatError {
    ArchiveFormatError::InvalidContainerLayout(message)
}

#[derive(Default)]
struct FirstBlock {
    found: Option<(u64, u64, Hash, Option<u64>)>,
}
impl SlotVisitor for FirstBlock {
    fn on_block(&mut self, n: &BlockNotification, _: &[EntryRecord]) {
        if self.found.is_none()
            && let BlockNotification::Block(m) = n
        {
            self.found = Some((m.slot, m.parent_slot, m.parent_blockhash, m.num_partitions));
        }
    }
    fn consumption(&self) -> Consumption {
        Consumption::all()
            .without_account_update_data()
            .without_block_account_update_arenas()
    }
}

/// Selects an interior range of an uninterrupted, dense V2 source.
///
/// The selected range must contain no EpochMeta event: this route is specifically
/// for a subrange of one recorder session, whose sole original metadata precedes
/// the cut. Unexpected metadata fails instead of dropping its nested updates.
/// A new empty structural EpochMeta is emitted before the first selected block's
/// original pre-updates, matching HorizonRecorder's clear()/first-block rule.
/// Its partition field comes from that actual block, not the old source header.
/// Every original selected event and raw write version otherwise stays unchanged.
pub fn reencode_archive_interior<R: Read + Seek, W: Write>(
    source: R,
    sink: W,
    config: ArchiveWriterConfig,
    selected: InteriorSelection,
) -> Result<(W, InteriorExtractionStats), ArchiveFormatError> {
    let mut reader = ArchiveReader::open(source)?;
    let h = reader.header().clone();
    let end = selected
        .start
        .checked_add(selected.count)
        .ok_or(invalid("interior range overflow"))?;
    let source_end = h
        .slot_start
        .checked_add(h.slot_count)
        .ok_or(invalid("source range overflow"))?;
    if h.format_version != FORMAT_VERSION_V2
        || config.format != ArchiveVersion::V2
        || selected.count == 0
        || selected.start <= h.slot_start
        || end > source_end
        || selected.first_parent_slot >= selected.start
        || selected.first_parent_blockhash == Hash::default()
        || selected.terminal_last_blockhash == Hash::default()
        || !reader.has_complete_slot_coverage()?
    {
        return Err(invalid(
            "interior selection requires dense V2, a proper cut and real boundary anchors",
        ));
    }
    let Some(ArchiveProvenance::V2(mut provenance)) = reader.provenance()? else {
        return Err(invalid(
            "interior selection requires single-runtime V2 provenance",
        ));
    };
    if provenance.base.requested_slot_start != h.slot_start
        || provenance.base.requested_slot_count != h.slot_count
        || provenance.base.bootstrap_slot >= selected.start
    {
        return Err(invalid("interior source provenance range differs"));
    }
    reader.verify_chain = true;
    reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    // Bounded chunks avoid scanning the remainder once the first block is found.
    let mut probe = FirstBlock::default();
    let mut at = selected.start;
    while at < end && probe.found.is_none() {
        let count = (end - at).min(128);
        let read = reader.read_slots(at, count, &mut probe)?;
        if read != count {
            return Err(invalid("interior first-block probe ended early"));
        }
        at += read;
    }
    let (first_block, parent_slot, parent_hash, partitions) = probe
        .found
        .ok_or(invalid("interior route requires a selected block"))?;
    if parent_slot != selected.first_parent_slot || parent_hash != selected.first_parent_blockhash {
        return Err(invalid(
            "interior first block differs from accepted boundary",
        ));
    }
    provenance.base.requested_slot_start = selected.start;
    provenance.base.requested_slot_count = selected.count;
    let mut writer = ArchiveWriter::new_with_provenance(
        sink,
        selected.epoch,
        selected.start,
        selected.count,
        config,
        &ArchiveProvenance::V2(provenance),
    )?;
    writer.preserve_initial_poh_anchor(selected.start, parent_hash)?;
    let mut visitor = InteriorVisitor::new(&mut writer, selected, first_block, partitions);
    let mut at = selected.start;
    while at < end {
        let count = (end - at).min(u64::from(h.bucket_slots));
        let read = reader.read_slots(at, count, &mut visitor)?;
        if let Some(error) = visitor.error.take() {
            return Err(error);
        }
        if read != count {
            return Err(invalid("interior source ended before selected range"));
        }
        at += read;
    }
    if visitor.next != end
        || !visitor.metadata_written
        || visitor.previous_hash != selected.terminal_last_blockhash
    {
        return Err(invalid("interior selected coverage/terminal differs"));
    }
    let source_digest = visitor.source.finish()?;
    let output_digest = visitor.output.finish()?;
    let raw = visitor.raw;
    let (sink, output) = writer.finish()?;
    Ok((
        sink,
        InteriorExtractionStats {
            source_epoch: h.epoch,
            source_start: h.slot_start,
            source_count: h.slot_count,
            selected,
            selected_source_semantic_sha256: source_digest,
            output_semantic_sha256: output_digest,
            emitted_raw_write_versions: raw,
            output,
        },
    ))
}

struct InteriorVisitor<'a, W: Write> {
    writer: &'a mut ArchiveWriter<W>,
    selected: InteriorSelection,
    first_block: u64,
    partitions: Option<u64>,
    next: u64,
    previous_block_slot: u64,
    previous_hash: Hash,
    source: SemanticDigest,
    output: SemanticDigest,
    raw: Option<Range<u64>>,
    metadata_written: bool,
    saw_transaction: bool,
    error: Option<ArchiveFormatError>,
}
impl<'a, W: Write> InteriorVisitor<'a, W> {
    fn new(
        writer: &'a mut ArchiveWriter<W>,
        selected: InteriorSelection,
        first_block: u64,
        partitions: Option<u64>,
    ) -> Self {
        Self {
            writer,
            selected,
            first_block,
            partitions,
            next: selected.start,
            previous_block_slot: selected.first_parent_slot,
            previous_hash: selected.first_parent_blockhash,
            source: SemanticDigest::new(),
            output: SemanticDigest::new(),
            raw: None,
            metadata_written: false,
            saw_transaction: false,
            error: None,
        }
    }
    fn record(&mut self, result: Result<(), ArchiveFormatError>) {
        if self.error.is_none()
            && let Err(error) = result
        {
            self.error = Some(error);
        }
    }
    fn raw(&mut self, n: u64) {
        let Some(end) = n.checked_add(1) else {
            self.error = Some(invalid("interior raw write version overflow"));
            return;
        };
        match self.raw.as_mut() {
            None => self.raw = Some(n..end),
            Some(r) => {
                r.start = r.start.min(n);
                r.end = r.end.max(end);
            }
        }
    }
}
impl<W: Write> SlotVisitor for InteriorVisitor<'_, W> {
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        if self.error.is_some() {
            return;
        }
        if slot != self.next {
            self.error = Some(invalid("interior slot coverage is not contiguous"));
            return;
        }
        let Some(next) = slot.checked_add(1) else {
            self.error = Some(invalid("interior slot overflow"));
            return;
        };
        self.next = next;
        self.saw_transaction = false;
        self.source.on_slot_start(slot, kind);
        self.output.on_slot_start(slot, kind);
        let result = match kind {
            SlotKind::Skipped => self.writer.write_skipped_slot(slot),
            SlotKind::Block => self.writer.begin_slot(slot),
        };
        self.record(result);
        if slot == self.first_block && kind == SlotKind::Block && self.error.is_none() {
            let mut meta = EpochMeta::new_boxed();
            meta.epoch = self.selected.epoch;
            meta.start_slot = self.selected.start;
            meta.slot_count = self.selected.count;
            meta.first_block_slot = slot;
            meta.num_reward_partitions = self.partitions;
            // new_boxed() is empty: no original epoch or account update is invented.
            self.output.on_epoch(&meta);
            let result = self.writer.write_epoch_meta(&meta);
            self.record(result);
            self.metadata_written = self.error.is_none();
        }
    }
    fn on_epoch(&mut self, _: &EpochMeta) {
        self.error = Some(invalid(
            "interior source contains epoch metadata; use a separately reviewed route",
        ));
    }
    fn on_pre_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        if self.error.is_some() {
            return;
        }
        self.raw(update.write_version);
        if self.error.is_some() {
            return;
        }
        self.source.on_pre_account_update(slot, update);
        self.output.on_pre_account_update(slot, update);
        let result = self.writer.write_orphan_update(update);
        self.record(result);
    }
    fn on_transaction(&mut self, slot: u64, index: u32, tx: &Transaction) {
        if self.error.is_some() {
            return;
        }
        for (update, _) in tx.iter_account_updates() {
            self.raw(update.write_version);
        }
        if self.error.is_some() {
            return;
        }
        self.saw_transaction = true;
        self.source.on_transaction(slot, index, tx);
        self.output.on_transaction(slot, index, tx);
        let result = self.writer.write_transaction(tx);
        self.record(result);
    }
    fn on_post_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        if self.error.is_some() {
            return;
        }
        // The pinned recorder classifies orphan writes by whether it has
        // emitted a transaction in this slot. A zero-transaction post section
        // cannot come from that recorder. Reject it before the public writer
        // could silently classify its events as pre-transaction.
        if !self.saw_transaction {
            self.error = Some(invalid("post-update without a recorded transaction"));
            return;
        }
        self.raw(update.write_version);
        if self.error.is_some() {
            return;
        }
        self.source.on_post_account_update(slot, update);
        self.output.on_post_account_update(slot, update);
        let result = self.writer.write_orphan_update(update);
        self.record(result);
    }
    fn on_block(&mut self, notification: &BlockNotification, entries: &[EntryRecord]) {
        if self.error.is_some() {
            return;
        }
        if let BlockNotification::Block(meta) = notification {
            if meta.parent_slot != self.previous_block_slot
                || meta.parent_blockhash != self.previous_hash
            {
                self.error = Some(invalid("interior parent slot/hash changed"));
                return;
            }
            self.previous_block_slot = meta.slot;
            self.previous_hash = meta.blockhash;
            self.source.on_block(notification, entries);
            self.output.on_block(notification, entries);
            let result = self.writer.end_slot(meta, entries);
            self.record(result);
        } else {
            self.source.on_block(notification, entries);
            self.output.on_block(notification, entries);
        }
    }
    fn consumption(&self) -> Consumption {
        Consumption::all().without_block_account_update_arenas()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetstreamer_horizon::archive::{
        ArchiveProvenanceV1, ArchiveProvenanceV2, BootstrapStateKind, RuntimeAdmission,
        TransactionMetadataPolicy,
    };
    use jetstreamer_horizon::block_metas::BlockMeta;
    use solana_address::Address;
    use std::io::Cursor;

    fn fixture(metadata_inside: bool) -> (Vec<u8>, InteriorSelection) {
        let hash = |n| Hash::new_from_array([n; 32]);
        let provenance = ArchiveProvenance::V2(ArchiveProvenanceV2 {
            base: ArchiveProvenanceV1 {
                generation_profile: "fixture".into(),
                runtime_profile: "fixture".into(),
                runtime_admission: RuntimeAdmission::Candidate,
                runtime_revision: "fixture".into(),
                runtime_toolchain: "fixture".into(),
                genesis_hash: hash(9),
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_slot: 8,
                bootstrap_state_hash: hash(8),
                requested_slot_start: 10,
                requested_slot_count: 5,
                transaction_metadata: TransactionMetadataPolicy::observed(),
            },
            worker_executable_sha256: [7; 32],
        });
        let mut w = ArchiveWriter::new_with_provenance(
            Vec::new(),
            225,
            10,
            5,
            ArchiveWriterConfig {
                bucket_slots: 2,
                ..Default::default()
            },
            &provenance,
        )
        .unwrap();
        w.preserve_initial_poh_anchor(10, hash(1)).unwrap();
        let mut previous_slot = 9;
        let mut previous_hash = hash(1);
        for slot in 10..15 {
            if slot == 12 {
                w.write_skipped_slot(slot).unwrap();
                continue;
            }
            w.begin_slot(slot).unwrap();
            if slot == 10 || (metadata_inside && slot == 13) {
                let mut e = EpochMeta::new_boxed();
                e.epoch = 225;
                e.start_slot = 10;
                e.slot_count = 5;
                e.first_block_slot = slot;
                w.write_epoch_meta(&e).unwrap();
            }
            let update = |offset| AccountUpdateView {
                pubkey: Address::new_from_array([offset; 32]),
                lamports: u64::from(offset),
                owner: Address::new_from_array([99; 32]),
                executable: false,
                rent_epoch: 7,
                write_version: slot * 3 + u64::from(offset),
                data: b"actual fixture bytes",
            };
            w.write_orphan_update(&update(0)).unwrap();
            let tx_count = u32::from(slot != 14);
            if tx_count > 0 {
                let mut tx = Transaction::new_boxed();
                tx.push_account_update(&update(1)).unwrap();
                w.write_transaction(&tx).unwrap();
            }
            w.write_orphan_update(&update(2)).unwrap();
            let mut m = BlockMeta::new_boxed();
            m.slot = slot;
            m.parent_slot = previous_slot;
            m.parent_blockhash = previous_hash;
            m.blockhash = hash(slot as u8);
            m.num_partitions = Some(17);
            m.executed_transaction_count = u64::from(tx_count);
            m.entry_count = 1;
            w.end_slot(
                &m,
                &[EntryRecord {
                    num_hashes: 1,
                    tx_count,
                }],
            )
            .unwrap();
            previous_slot = slot;
            previous_hash = m.blockhash;
        }
        (
            w.finish().unwrap().0,
            InteriorSelection {
                epoch: 226,
                start: 12,
                count: 3,
                first_parent_slot: 11,
                first_parent_blockhash: hash(11),
                terminal_last_blockhash: hash(14),
            },
        )
    }
    #[test]
    fn interior_preserves_leading_skip_chain_and_independent_output_digest() {
        let (source, selection) = fixture(false);
        let (output, stats) = reencode_archive_interior(
            Cursor::new(source.clone()),
            Vec::new(),
            ArchiveWriterConfig::default(),
            selection,
        )
        .unwrap();
        assert_eq!(stats.source_epoch, 225);
        assert_eq!(stats.source_count, 5);
        assert_eq!(stats.emitted_raw_write_versions, Some(39..45));
        let mut reader = ArchiveReader::open(Cursor::new(output)).unwrap();
        assert_eq!(reader.header().epoch, 226);
        assert_eq!(reader.header().slot_start, 12);
        assert_eq!(reader.header().slot_count, 3);
        let mut digest = SemanticDigest::new();
        assert_eq!(reader.read_slots(12, 3, &mut digest).unwrap(), 3);
        assert_eq!(digest.finish().unwrap(), stats.output_semantic_sha256);
        let mut original = ArchiveReader::open(Cursor::new(source)).unwrap();
        let mut digest = SemanticDigest::new();
        original.read_slots(12, 3, &mut digest).unwrap();
        assert_eq!(
            digest.finish().unwrap(),
            stats.selected_source_semantic_sha256
        );
        assert_ne!(
            stats.output_semantic_sha256,
            stats.selected_source_semantic_sha256
        );
    }

    #[test]
    fn pinned_channel_reencodes_the_same_private_prefix() {
        let (source, selection) = fixture(false);
        let expected = reencode_archive_interior(
            Cursor::new(source.clone()),
            Vec::new(),
            ArchiveWriterConfig::default(),
            selection,
        )
        .unwrap();
        let transported = crate::checkpoint_continuation226::held_r2::fixture_reader(source);
        let actual = reencode_archive_interior(
            transported,
            Vec::new(),
            ArchiveWriterConfig::default(),
            selection,
        )
        .unwrap();
        assert_eq!(actual.1.selected, expected.1.selected);
        assert_eq!(
            actual.1.emitted_raw_write_versions,
            expected.1.emitted_raw_write_versions
        );
        assert_eq!(
            actual.1.selected_source_semantic_sha256,
            expected.1.selected_source_semantic_sha256
        );
        assert_eq!(
            actual.1.output_semantic_sha256,
            expected.1.output_semantic_sha256
        );
        let mut reread = ArchiveReader::open(Cursor::new(actual.0)).unwrap();
        let mut digest = SemanticDigest::new();
        assert_eq!(
            reread
                .read_slots(selection.start, selection.count, &mut digest)
                .unwrap(),
            selection.count
        );
        assert_eq!(digest.finish().unwrap(), expected.1.output_semantic_sha256);
    }
    #[test]
    fn rejects_a_post_update_without_any_transaction_in_its_own_slot() {
        let (_, selected) = fixture(false);
        let mut writer =
            ArchiveWriter::new(Vec::new(), 226, 12, 3, ArchiveWriterConfig::default()).unwrap();
        let mut v = InteriorVisitor::new(&mut writer, selected, 13, Some(17));
        v.on_slot_start(12, SlotKind::Skipped);
        v.on_slot_start(13, SlotKind::Block);
        v.on_transaction(13, 0, &Transaction::new_boxed());
        assert!(v.saw_transaction);
        let mut block = BlockMeta::new_boxed();
        block.slot = 13;
        block.parent_slot = 11;
        block.parent_blockhash = selected.first_parent_blockhash;
        block.blockhash = Hash::new_from_array([13; 32]);
        block.executed_transaction_count = 1;
        block.entry_count = 1;
        v.writer
            .end_slot(
                &block,
                &[EntryRecord {
                    num_hashes: 1,
                    tx_count: 1,
                }],
            )
            .unwrap();
        v.on_slot_start(14, SlotKind::Block);
        assert!(v.error.is_none());
        v.on_post_account_update(
            14,
            &AccountUpdateView {
                pubkey: Address::new_from_array([1; 32]),
                owner: Address::new_from_array([2; 32]),
                lamports: 1,
                executable: false,
                rent_epoch: 0,
                write_version: 5,
                data: b"post",
            },
        );
        assert!(matches!(
            v.error,
            Some(ArchiveFormatError::InvalidContainerLayout(
                "post-update without a recorded transaction"
            ))
        ));
    }
    struct WithoutMetadata(SemanticDigest);
    impl SlotVisitor for WithoutMetadata {
        fn on_slot_start(&mut self, s: u64, k: SlotKind) {
            self.0.on_slot_start(s, k);
        }
        fn on_epoch(&mut self, m: &EpochMeta) {
            assert_eq!(m.epoch, 226);
            assert_eq!(m.start_slot, 12);
            assert_eq!(m.slot_count, 3);
            assert_eq!(m.first_block_slot, 13);
            assert_eq!(m.num_reward_partitions, Some(17));
            assert_eq!(m.updates.iter().count(), 0);
        }
        fn on_pre_account_update(&mut self, s: u64, u: &AccountUpdateView<'_>) {
            self.0.on_pre_account_update(s, u);
        }
        fn on_transaction(&mut self, s: u64, i: u32, t: &Transaction) {
            self.0.on_transaction(s, i, t);
        }
        fn on_post_account_update(&mut self, s: u64, u: &AccountUpdateView<'_>) {
            self.0.on_post_account_update(s, u);
        }
        fn on_block(&mut self, n: &BlockNotification, e: &[EntryRecord]) {
            self.0.on_block(n, e);
        }
        fn consumption(&self) -> Consumption {
            Consumption::all().without_block_account_update_arenas()
        }
    }
    #[test]
    fn all_original_pre_transaction_post_events_and_data_are_preserved() {
        let (source, selection) = fixture(false);
        let (output, stats) = reencode_archive_interior(
            Cursor::new(source),
            Vec::new(),
            ArchiveWriterConfig::default(),
            selection,
        )
        .unwrap();
        let mut reader = ArchiveReader::open(Cursor::new(output)).unwrap();
        let mut digest = WithoutMetadata(SemanticDigest::new());
        reader.read_slots(12, 3, &mut digest).unwrap();
        // Removing only the new EMPTY structural metadata reproduces every
        // original selected callback, including account data and raw versions.
        assert_eq!(
            digest.0.finish().unwrap(),
            stats.selected_source_semantic_sha256
        );
    }
    #[test]
    fn interior_rejects_wrong_boundary_and_existing_metadata_without_dropping_updates() {
        let (source, mut selection) = fixture(false);
        selection.first_parent_slot -= 1;
        assert!(
            reencode_archive_interior(
                Cursor::new(source),
                Vec::new(),
                ArchiveWriterConfig::default(),
                selection
            )
            .is_err()
        );
        let (source, selection) = fixture(true);
        assert!(
            reencode_archive_interior(
                Cursor::new(source),
                Vec::new(),
                ArchiveWriterConfig::default(),
                selection
            )
            .is_err()
        );
    }
}
