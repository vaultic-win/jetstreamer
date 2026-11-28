//! Copy complete independently encoded buckets from a pinned dense V2 source.
//! Only the first bucket's epoch notification and container framing change.
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{
        ArchiveFormatError, ArchiveProvenance, ArchiveReader, BlockNotification, BucketDecoder,
        BucketHeader, BucketIndexEntry, ChainMismatchPolicy, Compression, EntryRecord, EpochMeta,
        FileHeader, Footer, MAGIC, MAX_BUCKET_STORED_BYTES, MAX_BUCKET_UNCOMPRESSED_BYTES,
        SemanticDigest, SlotKind, SlotVisitor, encode_archive_provenance,
    },
    transactions::Transaction,
};
use lencode::{Decode, Encode};
use solana_hash::Hash;
use std::io::{Read, Seek, SeekFrom, Write};
use xxhash_rust::xxh64::xxh64;

/// Every slot is still decoded in strict chain mode before its bucket is written.
/// The independent candidate reread compares against the resulting event digest.
pub(super) fn copy_aligned_prefix<R: Read + Seek, W: Write>(
    source: R,
    output: W,
    count: u64,
    expected_provenance: &ArchiveProvenance,
) -> Result<[u8; 32]> {
    let mut visitor = Visitor::default();
    let mut decoder = None;
    write_frames(
        source,
        output,
        count,
        expected_provenance,
        |header, first, bucket, frame, entry| {
            if decoder.is_none() {
                let mut d = BucketDecoder::for_file_header(header)?;
                d.verify_chain = true;
                decoder = Some(d);
            }
            if first {
                visitor.previous = bucket.poh_start_hash;
            }
            ensure!(
                bucket.poh_start_hash == visitor.previous,
                "discontinuous bucket anchor"
            );
            let d = decoder.as_mut().context("missing decoder")?;
            d.load_indexed_bucket_bytes(frame, entry)?;
            for _ in 0..bucket.slot_count {
                ensure!(
                    d.decode_slot_frame(entry.first_slot, &mut visitor)?,
                    "missing slot frame"
                );
                ensure!(visitor.epoch_count <= 1, "duplicate epoch notification");
                ensure!(
                    !visitor.discontinuous_parent,
                    "discontinuous stored parent hash"
                );
            }
            Ok(())
        },
    )?;
    ensure!(visitor.epoch_count == 1, "missing epoch notification");
    Ok(visitor.digest.finish()?)
}

/// Independently validate the candidate whose encoded bytes matched the
/// authenticated source prefix. Preserve the aligned export's cross-bucket
/// parent and epoch-notification checks while deriving the candidate digest.
pub(super) fn read_prefix_digest<R: Read + Seek>(
    reader: &mut ArchiveReader<R>,
) -> Result<[u8; 32]> {
    reader.verify_chain = true;
    reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    let mut visitor = Visitor::default();
    let mut slots = 0u64;
    for index in 0..reader.bucket_count() {
        let decoded = reader.read_bucket_with_header(index, &mut visitor, |header, visitor| {
            if index == 0 {
                if header.poh_start_hash == Hash::default() {
                    return Err(ArchiveFormatError::InvalidContainerLayout(
                        "aligned prefix initial anchor is zero",
                    ));
                }
                visitor.previous = header.poh_start_hash;
            }
            if header.poh_start_hash != visitor.previous {
                return Err(ArchiveFormatError::PohMismatch {
                    slot: header.first_slot,
                });
            }
            Ok(())
        })?;
        slots = slots
            .checked_add(decoded)
            .context("prefix slot count overflow")?;
        ensure!(
            !visitor.discontinuous_parent,
            "discontinuous stored parent hash"
        );
        ensure!(visitor.epoch_count <= 1, "duplicate epoch notification");
    }
    ensure!(
        slots == reader.header().slot_count,
        "incomplete aligned prefix"
    );
    ensure!(visitor.epoch_count == 1, "missing epoch notification");
    Ok(visitor.digest.finish()?)
}

/// Assemble encoded bytes from the authenticated source. The caller can supply
/// strict semantic verification, or run the independent existing-candidate verifier later.
pub(super) fn write_frames<R: Read + Seek, W: Write>(
    mut source: R,
    mut output: W,
    count: u64,
    expected_provenance: &ArchiveProvenance,
    mut inspect: impl FnMut(&FileHeader, bool, &BucketHeader, &[u8], BucketIndexEntry) -> Result<()>,
) -> Result<()> {
    let (mut header, entries) = {
        let mut reader = ArchiveReader::open(&mut source)?;
        let header = reader.header().clone();
        ensure!(
            header.format_version == 2
                && count > 0
                && count < header.slot_count
                && count.is_multiple_of(u64::from(header.bucket_slots))
                && reader.has_complete_slot_coverage()?,
            "aligned prefix requires a dense V2 source and an exact proper bucket cut"
        );
        let Some(ArchiveProvenance::V2(mut p)) = reader.provenance()? else {
            anyhow::bail!("aligned prefix requires single-worker V2 provenance");
        };
        p.base.requested_slot_count = count;
        ensure!(
            &ArchiveProvenance::V2(p) == expected_provenance,
            "prefix provenance mismatch"
        );
        let n = usize::try_from(count / u64::from(header.bucket_slots))?;
        (header, reader.bucket_index()[..n].to_vec())
    };
    let original_count = header.slot_count;
    header.slot_count = count;
    header.meta.reserved = encode_archive_provenance(expected_provenance)?;
    let mut frame = Vec::new();
    header.encode_ext(&mut frame, None)?;
    let mut prefix = MAGIC.to_vec();
    (frame.len() as u64).encode_ext(&mut prefix, None)?;
    output.write_all(&prefix)?;
    output.write_all(&frame)?;
    let mut offset = (prefix.len() + frame.len()) as u64;
    let mut index = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        source.seek(SeekFrom::Start(entry.offset))?;
        frame.resize(usize::try_from(entry.len)?, 0);
        source.read_exact(&mut frame)?;
        let mut bytes = lencode::io::Cursor::new(frame.as_slice());
        let bucket = BucketHeader::decode_ext(&mut bytes, None)?;
        ensure!(
            bucket.first_slot == entry.first_slot
                && bucket.slot_count == u32::from(header.bucket_slots),
            "source bucket geometry changed"
        );
        if i == 0 {
            ensure!(
                bucket.poh_start_hash != Hash::default(),
                "initial anchor is zero"
            );
            frame = narrow_epoch(&header, original_count, &bucket, &frame[bytes.position()..])?;
        }
        let relocated = BucketIndexEntry {
            first_slot: entry.first_slot,
            offset,
            len: frame.len() as u64,
        };
        inspect(&header, i == 0, &bucket, &frame, relocated)?;
        output.write_all(&frame)?;
        offset = offset
            .checked_add(relocated.len)
            .context("output offset overflow")?;
        index.push(relocated);
    }
    frame.clear();
    (index.len() as u64).encode_ext(&mut frame, None)?;
    for entry in &index {
        entry.encode_ext(&mut frame, None)?;
    }
    let footer = Footer {
        index_offset: offset,
        index_len: frame.len() as u64,
        bucket_count: index.len() as u64,
        index_xxh64: xxh64(&frame, 0),
    };
    output.write_all(&frame)?;
    output.write_all(&footer.to_bytes())?;
    output.flush()?;
    Ok(())
}

fn narrow_epoch(
    file: &FileHeader,
    original_count: u64,
    source: &BucketHeader,
    stored: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        source.compression == Compression::Zstd
            && source.stored_len == stored.len() as u64
            && source.uncompressed_len <= MAX_BUCKET_UNCOMPRESSED_BYTES
            && source.xxh64 == xxh64(stored, 0)
            && zstd::zstd_safe::find_frame_compressed_size(stored).ok() == Some(stored.len()),
        "invalid first Zstandard bucket"
    );
    let mut payload = zstd::bulk::decompress(stored, usize::try_from(source.uncompressed_len)?)?;
    ensure!(
        payload.len() as u64 == source.uncompressed_len,
        "first payload length mismatch"
    );
    let mut c = lencode::io::Cursor::new(payload.as_slice());
    let mut first = file.slot_start;
    for _ in 0..source.slot_count {
        ensure!(
            u64::decode_ext(&mut c, None)? == first,
            "unexpected initial slot"
        );
        let kind = SlotKind::try_from(u8::decode_ext(&mut c, None)?)?;
        if kind == SlotKind::Block {
            break;
        }
        first += 1;
    }
    ensure!(
        first < file.slot_start + u64::from(source.slot_count)
            && u8::decode_ext(&mut c, None)? == 1
            && u64::decode_ext(&mut c, None)? == file.epoch
            && u64::decode_ext(&mut c, None)? == file.slot_start,
        "first source block lacks its matching epoch notification"
    );
    let start = c.position();
    ensure!(
        u64::decode_ext(&mut c, None)? == original_count,
        "unexpected source epoch width"
    );
    let end = c.position();
    ensure!(
        u64::decode_ext(&mut c, None)? == first,
        "unexpected epoch first block slot"
    );
    let mut count = Vec::new();
    file.slot_count.encode_ext(&mut count, None)?;
    ensure!(
        count.len() == end - start,
        "prefix epoch field changes encoded width"
    );
    payload[start..end].copy_from_slice(&count);
    let compressed = zstd::bulk::compress(&payload, 9)?;
    let mut bucket = source.clone();
    bucket.stored_len = compressed.len() as u64;
    bucket.xxh64 = xxh64(&compressed, 0);
    let mut out = Vec::new();
    bucket.encode_ext(&mut out, None)?;
    ensure!(
        (out.len() + compressed.len()) as u64 <= MAX_BUCKET_STORED_BYTES,
        "rewritten bucket exceeds reader limit"
    );
    out.extend_from_slice(&compressed);
    Ok(out)
}

/// The native decoder checks all frames and parent links inside a bucket.
/// Retain the final non-skipped hash across buckets, including all-skip buckets.
#[derive(Default)]
struct Visitor {
    digest: SemanticDigest,
    previous: Hash,
    epoch_count: u64,
    discontinuous_parent: bool,
}
impl SlotVisitor for Visitor {
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        self.digest.on_slot_start(slot, kind);
    }
    fn on_epoch(&mut self, epoch: &EpochMeta) {
        self.epoch_count += 1;
        self.digest.on_epoch(epoch);
    }
    fn on_pre_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        self.digest.on_pre_account_update(slot, update);
    }
    fn on_transaction(&mut self, slot: u64, index: u32, tx: &Transaction) {
        self.digest.on_transaction(slot, index, tx);
    }
    fn on_post_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        self.digest.on_post_account_update(slot, update);
    }
    fn on_block(&mut self, notification: &BlockNotification, entries: &[EntryRecord]) {
        if let BlockNotification::Block(block) = notification {
            self.discontinuous_parent |= block.parent_blockhash != self.previous;
            self.previous = block.blockhash;
        }
        self.digest.on_block(notification, entries);
    }
}

#[cfg(test)]
#[path = "aligned/tests.rs"]
mod tests;
