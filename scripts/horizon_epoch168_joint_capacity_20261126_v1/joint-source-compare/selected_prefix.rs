//! Select and verify a contiguous retained V2 prefix with no archive-sized writes.
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    ops::Range,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{
        ArchiveFormatError, ArchiveProvenance, ArchiveReader, BucketDecoder, BucketHeader,
        BucketIndexEntry, ChainMismatchPolicy, Compression, FileHeader, Footer, MAGIC,
        MAX_BUCKET_STORED_BYTES, MAX_BUCKET_UNCOMPRESSED_BYTES, SemanticDigest, SlotKind,
        SlotVisitor, encode_archive_provenance,
    },
    block_metas::BlockNotification,
    entries::EntryRecord,
    epochs::EpochMeta,
    transactions::Transaction,
};
use lencode::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use xxhash_rust::xxh64::xxh64;

use super::{BYTES, END, FIRST, INPUT, PrefixView, invalid, original_identity};

const SEAM: u64 = 72_994_766;
const SOURCE_SHA: &str = "cdde7f4da26d0d608f9546883aba787c903e093fc800bd570288e803c0aefc3d";
const SEAM_HASH: &str = "5mMqY7Po42u2cB3L2X6VVvLFkbvPXiZXH2sYMnZiLpnU";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn check(ok: bool, message: &'static str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(message)) }
}

pub(super) struct Layout {
    front: Vec<u8>,
    middle: Range<u64>,
    back: Vec<u8>,
}

impl Layout {
    fn middle_len(&self) -> u64 {
        self.middle.end - self.middle.start
    }

    pub(super) fn len(&self) -> u64 {
        self.front.len() as u64 + self.middle_len() + self.back.len() as u64
    }
}

pub(super) struct Selected<'a, R> {
    source: R,
    bytes: &'a Layout,
    at: u64,
}

impl<'a, R> Selected<'a, R> {
    pub(super) fn new(source: R, bytes: &'a Layout) -> Self {
        Self {
            source,
            bytes,
            at: 0,
        }
    }
}

impl<R: Read + Seek> Read for Selected<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let front = self.bytes.front.len() as u64;
        let back = front + self.bytes.middle_len();
        let n = if self.at < front {
            (&self.bytes.front[self.at as usize..]).read(out)?
        } else if self.at < back {
            let length = out
                .len()
                .min(usize::try_from(back - self.at).unwrap_or(usize::MAX));
            self.source
                .seek(SeekFrom::Start(self.bytes.middle.start + self.at - front))?;
            let n = self.source.read(&mut out[..length])?;
            if n == 0 && length != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short retained bucket span",
                ));
            }
            n
        } else if self.at < self.bytes.len() {
            (&self.bytes.back[(self.at - back) as usize..]).read(out)?
        } else {
            0
        };
        self.at += n as u64;
        Ok(n)
    }
}

impl<R> Seek for Selected<'_, R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.at = match to {
            SeekFrom::Start(value) => Some(value),
            SeekFrom::Current(delta) => self.at.checked_add_signed(delta),
            SeekFrom::End(delta) => self.bytes.len().checked_add_signed(delta),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid selected seek"))?;
        Ok(self.at)
    }
}

fn frame(source: &mut (impl Read + Seek), entry: BucketIndexEntry) -> io::Result<Vec<u8>> {
    check(
        entry.len > 0 && entry.len <= MAX_BUCKET_STORED_BYTES,
        "invalid boundary frame length",
    )?;
    source.seek(SeekFrom::Start(entry.offset))?;
    let mut frame = vec![0; entry.len as usize];
    source.read_exact(&mut frame)?;
    Ok(frame)
}

fn unpack(frame: &[u8], entry: BucketIndexEntry) -> Result<(BucketHeader, Vec<u8>)> {
    let mut cursor = lencode::io::Cursor::new(frame);
    let header = BucketHeader::decode_ext(&mut cursor, None)?;
    let stored = &frame[cursor.position()..];
    check(
        header.first_slot == entry.first_slot
            && header.compression == Compression::Zstd
            && header.stored_len == stored.len() as u64
            && header.uncompressed_len <= MAX_BUCKET_UNCOMPRESSED_BYTES
            && header.xxh64 == xxh64(stored, 0)
            && zstd::zstd_safe::find_frame_compressed_size(stored).ok() == Some(stored.len()),
        "invalid contiguous Zstandard frame",
    )?;
    let payload = zstd::bulk::decompress(stored, header.uncompressed_len as usize)?;
    check(
        payload.len() as u64 == header.uncompressed_len,
        "boundary payload length mismatch",
    )?;
    Ok((header, payload))
}

fn pack(mut header: BucketHeader, payload: &[u8]) -> Result<Vec<u8>> {
    let stored = zstd::bulk::compress(payload, 9)?;
    header.uncompressed_len = payload.len() as u64;
    header.stored_len = stored.len() as u64;
    header.xxh64 = xxh64(&stored, 0);
    let mut outcome = Vec::new();
    header.encode_ext(&mut outcome, None)?;
    outcome.extend_from_slice(&stored);
    check(
        outcome.len() as u64 <= MAX_BUCKET_STORED_BYTES,
        "rewritten frame exceeds limit",
    )?;
    Ok(outcome)
}

// The epoch notification is the only semantic change to the first bucket.
// Preserve every other encoded byte, including the epoch account updates.
fn narrow_epoch(payload: &mut Vec<u8>, source: &FileHeader, count: u64, slots: u32) -> Result<()> {
    let mut cursor = lencode::io::Cursor::new(payload.as_slice());
    let mut first = None;
    for offset in 0..u64::from(slots) {
        let slot = u64::decode_ext(&mut cursor, None)?;
        check(
            slot == source.slot_start + offset,
            "unexpected initial slot",
        )?;
        if SlotKind::try_from(u8::decode_ext(&mut cursor, None)?)? == SlotKind::Block {
            first = Some(slot);
            break;
        }
    }
    let first = first.ok_or_else(|| invalid("first bucket has no epoch block"))?;
    check(
        u8::decode_ext(&mut cursor, None)? == 1
            && u64::decode_ext(&mut cursor, None)? == source.epoch
            && u64::decode_ext(&mut cursor, None)? == source.slot_start,
        "missing original epoch notification",
    )?;
    let start = cursor.position();
    check(
        u64::decode_ext(&mut cursor, None)? == source.slot_count,
        "wrong epoch span in original",
    )?;
    let end = cursor.position();
    check(
        u64::decode_ext(&mut cursor, None)? == first,
        "wrong epoch first block",
    )?;
    let mut encoded = Vec::new();
    count.encode_ext(&mut encoded, None)?;
    payload.splice(start..end, encoded);
    Ok(())
}

fn header_bytes(header: &FileHeader) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    header.encode_ext(&mut payload, None)?;
    let mut encoded = MAGIC.to_vec();
    (payload.len() as u64).encode_ext(&mut encoded, None)?;
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

fn append_index(
    bytes: &mut Vec<u8>,
    index_offset: u64,
    entries: &[BucketIndexEntry],
) -> Result<()> {
    let mut index = Vec::new();
    (entries.len() as u64).encode_ext(&mut index, None)?;
    for entry in entries {
        entry.encode_ext(&mut index, None)?;
    }
    let footer = Footer {
        index_offset,
        index_len: index.len() as u64,
        bucket_count: entries.len() as u64,
        index_xxh64: xxh64(&index, 0),
    };
    bytes.extend_from_slice(&index);
    bytes.extend_from_slice(&footer.to_bytes());
    Ok(())
}

pub(super) fn cut(
    source: &mut (impl Read + Seek),
    original: &FileHeader,
    provenance: ArchiveProvenance,
    entries: &[BucketIndexEntry],
    end: u64,
) -> Result<Layout> {
    let count = end
        .checked_sub(original.slot_start)
        .ok_or_else(|| invalid("selection reversed"))?;
    check(
        original.format_version == 2
            && count < original.slot_count
            && count > 0
            && entries.len() >= 3,
        "expected a proper V2 archive prefix",
    )?;
    let ArchiveProvenance::V2(mut metadata) = provenance else {
        return Err(invalid("original is not single-runtime V2 provenance").into());
    };
    check(
        metadata.base.requested_slot_start == original.slot_start
            && metadata.base.requested_slot_count == original.slot_count,
        "wrong source provenance range",
    )?;
    metadata.base.requested_slot_count = count;
    let mut narrowed = original.clone();
    narrowed.slot_count = count;
    narrowed.meta.reserved = encode_archive_provenance(&ArchiveProvenance::V2(metadata))?;
    let mut front = header_bytes(&narrowed)?;

    let first = entries[0];
    let last = *entries.last().ok_or_else(|| invalid("no selection end"))?;
    let (first_h, mut first_payload) = unpack(&frame(source, first)?, first)?;
    check(
        first_h.slot_count == u32::from(original.bucket_slots),
        "wrong first bucket width",
    )?;
    narrow_epoch(&mut first_payload, original, count, first_h.slot_count)?;
    let first = pack(first_h, &first_payload)?;
    let first_offset = front.len() as u64;
    front.extend_from_slice(&first);
    drop(first_payload);

    let mut relocated = vec![BucketIndexEntry {
        first_slot: original.slot_start,
        offset: first_offset,
        len: first.len() as u64,
    }];
    let middle = entries[1].offset..last.offset;
    let mut body_offset = middle.start;
    for (index, entry) in entries[1..entries.len() - 1].iter().enumerate() {
        check(
            entry.offset == body_offset
                && entry.len > 0
                && entry.first_slot
                    == original.slot_start + (index as u64 + 1) * u64::from(original.bucket_slots),
            "middle bucket geometry changed",
        )?;
        relocated.push(BucketIndexEntry {
            offset: front.len() as u64 + entry.offset - middle.start,
            ..*entry
        });
        body_offset = entry.offset + entry.len;
    }
    check(
        body_offset == middle.end,
        "middle bucket span is not contiguous",
    )?;

    let last_bytes = frame(source, last)?;
    let (mut last_h, mut last_payload) = unpack(&last_bytes, last)?;
    let wanted = u32::try_from(
        end.checked_sub(last.first_slot)
            .ok_or_else(|| invalid("wrong final bucket"))?,
    )?;
    check(
        wanted > 0 && wanted < last_h.slot_count,
        "selection must end inside final bucket",
    )?;
    let (_, payload_bytes) = read_boundary(original, &last_bytes, last, wanted, 0)?;
    let cut = usize::try_from(payload_bytes)?;
    check(
        cut > 0 && cut < last_payload.len(),
        "invalid terminal slot frame offset",
    )?;
    last_payload.truncate(cut);
    last_h.slot_count = wanted;
    let mut back = pack(last_h, &last_payload)?;
    let end_offset = front.len() as u64 + middle.end - middle.start;
    let back_len = back.len() as u64;
    relocated.push(BucketIndexEntry {
        first_slot: last.first_slot,
        offset: end_offset,
        len: back_len,
    });
    append_index(&mut back, end_offset + back_len, &relocated)?;
    Ok(Layout {
        front,
        middle,
        back,
    })
}

struct Verify {
    digest: SemanticDigest,
    next_slot: u64,
    slot: u64,
    count: u64,
    last_block: Option<u64>,
    last_hash: [u8; 32],
    epoch_count: u64,
    normalize_epoch_to: u64,
    raw: Vec<u64>,
    first_raw: Option<u64>,
    next_raw: Option<u64>,
    error: Option<&'static str>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Verified {
    count: u64,
    pub(super) last_block: Option<u64>,
    pub(super) last_hash: [u8; 32],
    epoch_count: u64,
    pub(super) first_raw: Option<u64>,
    pub(super) next_raw: Option<u64>,
    pub(super) semantic: [u8; 32],
}

impl Verify {
    fn new(first: u64, hash: [u8; 32], normalize_epoch_to: u64) -> Self {
        Self {
            digest: SemanticDigest::new(),
            next_slot: first,
            slot: first,
            count: 0,
            last_block: None,
            last_hash: hash,
            epoch_count: 0,
            normalize_epoch_to,
            raw: Vec::new(),
            first_raw: None,
            next_raw: None,
            error: None,
        }
    }

    fn finish(self) -> Result<Verified> {
        if let Some(error) = self.error {
            return Err(invalid(error).into());
        }
        Ok(Verified {
            count: self.count,
            last_block: self.last_block,
            last_hash: self.last_hash,
            epoch_count: self.epoch_count,
            first_raw: self.first_raw,
            next_raw: self.next_raw,
            semantic: self.digest.finish()?,
        })
    }

    fn close_versions(&mut self) {
        self.raw.sort_unstable();
        for raw in self.raw.drain(..) {
            self.first_raw.get_or_insert(raw);
            if raw != *self.next_raw.get_or_insert(raw) || raw == u64::MAX {
                self.error
                    .get_or_insert("raw write cursor is not contiguous");
                break;
            }
            self.next_raw = Some(raw + 1);
        }
    }
}

impl SlotVisitor for Verify {
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        if slot != self.next_slot {
            self.error
                .get_or_insert("missing, duplicate or reversed slot");
        }
        self.slot = slot;
        self.digest.on_slot_start(slot, kind);
    }

    fn on_epoch(&mut self, meta: &EpochMeta) {
        self.epoch_count += 1;
        if self.epoch_count != 1 || meta.first_block_slot != self.slot {
            self.error
                .get_or_insert("duplicate or misplaced epoch notification");
        }
        self.raw
            .extend(meta.updates.updates().iter().map(|row| row.write_version));
        if self.normalize_epoch_to == 0 {
            self.digest.on_epoch(meta);
            return;
        }
        let mut narrowed = EpochMeta::new_boxed();
        let mut wire = Vec::new();
        if meta.encode_ext(&mut wire, None).is_err()
            || narrowed.decode_into(&mut wire.as_slice(), None).is_err()
        {
            self.error.get_or_insert("epoch normalization failed");
            return;
        }
        narrowed.slot_count = self.normalize_epoch_to;
        self.digest.on_epoch(&narrowed);
    }

    fn on_pre_account_update(&mut self, slot: u64, row: &AccountUpdateView<'_>) {
        self.raw.push(row.write_version);
        self.digest.on_pre_account_update(slot, row);
    }

    fn on_transaction(&mut self, slot: u64, index: u32, transaction: &Transaction) {
        self.raw.extend(
            transaction
                .account_updates()
                .iter()
                .map(|row| row.write_version),
        );
        self.digest.on_transaction(slot, index, transaction);
    }

    fn on_post_account_update(&mut self, slot: u64, row: &AccountUpdateView<'_>) {
        self.raw.push(row.write_version);
        self.digest.on_post_account_update(slot, row);
    }

    fn on_block(&mut self, block: &BlockNotification, entries: &[EntryRecord]) {
        if block.slot() != self.slot {
            self.error
                .get_or_insert("block crosses expected slot frame");
        }
        if let BlockNotification::Block(info) = block {
            if info.parent_blockhash.to_bytes() != self.last_hash
                || self
                    .last_block
                    .is_some_and(|prior| prior != info.parent_slot)
            {
                self.error
                    .get_or_insert("block ancestry crossed the previous retained record");
            }
            self.last_block = Some(info.slot);
            self.last_hash = info.blockhash.to_bytes();
        }
        self.close_versions();
        self.digest.on_block(block, entries);
        self.next_slot += 1;
        self.count += 1;
    }

    fn consumption(&self) -> jetstreamer_horizon::archive::Consumption {
        self.digest.consumption()
    }
}

fn read_boundary(
    header: &FileHeader,
    bytes: &[u8],
    entry: BucketIndexEntry,
    slots: u32,
    normalize: u64,
) -> Result<(Verified, u64)> {
    let handle = BucketHeader::decode_ext(&mut bytes.as_ref(), None)?;
    let mut visitor = Verify::new(
        entry.first_slot,
        handle.poh_start_hash.to_bytes(),
        normalize,
    );
    let mut decoder = BucketDecoder::for_file_header(header)?;
    decoder.verify_chain = true;
    decoder.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    decoder.load_indexed_bucket_bytes(bytes, entry)?;
    for _ in 0..slots {
        check(
            decoder.decode_slot_frame(entry.first_slot, &mut visitor)?,
            "short boundary selection",
        )?;
    }
    Ok((visitor.finish()?, decoder.byte_stats().total()))
}

pub(super) fn boundaries(
    source: &mut (impl Read + Seek),
    original: &FileHeader,
    entries: &[BucketIndexEntry],
    layout: &Layout,
    end: u64,
) -> Result<()> {
    let (selected, index) = {
        let chosen = ArchiveReader::open(Selected {
            source: &mut *source,
            bytes: layout,
            at: 0,
        })?;
        check(
            chosen.header().slot_count == end - original.slot_start,
            "selected byte range changed",
        )?;
        (chosen.header().clone(), chosen.bucket_index().to_vec())
    };
    check(
        index.len() >= 2 && entries.len() == index.len(),
        "missing boundary bucket",
    )?;
    for i in [0, index.len() - 1] {
        let before = entries[i];
        let after = index[i];
        let bytes = frame(source, before)?;
        let mut virtual_reader = Selected {
            source: &mut *source,
            bytes: layout,
            at: 0,
        };
        let candidate = frame(&mut virtual_reader, after)?;
        let width = u32::try_from((end - before.first_slot).min(u64::from(original.bucket_slots)))?;
        let (want, _) = read_boundary(original, &bytes, before, width, selected.slot_count)?;
        let (found, _) = read_boundary(&selected, &candidate, after, width, 0)?;
        check(
            found == want,
            "regenerated boundary differs semantically from retained source",
        )?;
    }
    Ok(())
}

pub(super) fn semantic_read<R: Read + Seek>(source: R, end: u64) -> Result<Verified> {
    let mut reader = ArchiveReader::open(source)?;
    let header = reader.header().clone();
    check(
        header.slot_start + header.slot_count == end && reader.has_complete_slot_coverage()?,
        "selected archive does not densely cover declared interval",
    )?;
    reader.verify_chain = true;
    reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    let mut visitor = Verify::new(header.slot_start, [0; 32], 0);
    for i in 0..reader.bucket_count() {
        reader.read_bucket_with_header(i, &mut visitor, |head, visitor| {
            let found = head.poh_start_hash.to_bytes();
            if i == 0 {
                visitor.last_hash = found;
            }
            if visitor.last_hash != found {
                return Err(ArchiveFormatError::PohMismatch {
                    slot: head.first_slot,
                });
            }
            Ok(())
        })?;
        if header.slot_count >= 100_000 && (i + 1).is_multiple_of(64) {
            eprintln!(
                "selected verification slots={} last_slot={}",
                visitor.count,
                visitor.next_slot - 1
            );
        }
    }
    let seen = visitor.finish()?;
    check(
        seen.count == header.slot_count && seen.epoch_count == 1,
        "wrong independent selected slot or epoch coverage",
    )?;
    Ok(seen)
}

pub(super) fn hashes(
    source: &mut (impl Read + Seek),
    layout: &Layout,
) -> Result<([u8; 32], [u8; 32], u64)> {
    source.seek(SeekFrom::Start(0))?;
    let mut source_sha = Sha256::new();
    let mut selected_sha = Sha256::new();
    selected_sha.update(&layout.front);
    let mut at = 0u64;
    let mut copied = 0u64;
    let mut buffer = vec![0; 8 << 20];
    loop {
        let size = source.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        let end = at + size as u64;
        source_sha.update(&buffer[..size]);
        let lo = at.max(layout.middle.start);
        let hi = end.min(layout.middle.end);
        if lo < hi {
            selected_sha.update(&buffer[(lo - at) as usize..(hi - at) as usize]);
            copied += hi - lo;
        }
        at = end;
    }
    check(copied == layout.middle_len(), "short selected source bytes")?;
    selected_sha.update(&layout.back);
    Ok((
        source_sha.finalize().into(),
        selected_sha.finalize().into(),
        at,
    ))
}

pub(super) fn hex(digest: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut out, "{byte:02x}").expect("in-memory hex digits");
    }
    out
}

pub(super) struct PrefixScope {
    pub(super) schema: &'static str,
    pub(super) path: &'static str,
    pub(super) epoch: u64,
    pub(super) first: u64,
    pub(super) physical_end: u64,
    pub(super) bytes: u64,
    pub(super) source_sha: &'static str,
    pub(super) seam: u64,
    pub(super) seam_hash: &'static str,
    pub(super) next_raw: Option<u64>,
    pub(super) check_identity: fn(&File) -> io::Result<()>,
}

pub(super) fn run() -> Result<()> {
    verify(&PrefixScope {
        schema: "horizon-epoch168-private-selected-prefix-evidence-v1",
        path: INPUT,
        epoch: 168,
        first: FIRST,
        physical_end: END,
        bytes: BYTES,
        source_sha: SOURCE_SHA,
        seam: SEAM,
        seam_hash: SEAM_HASH,
        next_raw: None,
        check_identity: original_identity,
    })
}

pub(super) fn verify(scope: &PrefixScope) -> Result<()> {
    let path = Path::new(scope.path);
    check(
        path.canonicalize()? == path,
        "source archive path crosses a link",
    )?;
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    (scope.check_identity)(&input)?;
    let (original, metadata, entries) = {
        let reader = ArchiveReader::open(PrefixView::open(
            &mut input,
            scope.epoch,
            scope.first,
            scope.physical_end,
        )?)?;
        let header = reader.header().clone();
        let p = reader
            .provenance()?
            .ok_or_else(|| invalid("source provenance missing"))?;
        let ranges = reader.bucket_index();
        let n = ranges.partition_point(|x| x.first_slot <= scope.seam);
        (header, p, ranges[..n].to_vec())
    };
    let layout = cut(&mut input, &original, metadata, &entries, scope.seam + 1)?;
    boundaries(&mut input, &original, &entries, &layout, scope.seam + 1)?;
    let (source_hash, selected_hash, bytes) = hashes(&mut input, &layout)?;
    check(
        bytes == scope.bytes && hex(&source_hash) == scope.source_sha,
        "source archive digest changed",
    )?;
    (scope.check_identity)(&input)?;
    eprintln!(
        "epoch {} source SHA-256 verified; independently decoding the selected prefix",
        scope.epoch
    );
    let selected = Selected {
        source: &mut input,
        bytes: &layout,
        at: 0,
    };
    let verified = semantic_read(selected, scope.seam + 1)?;
    let terminal = bs58::encode(verified.last_hash).into_string();
    check(
        verified.last_block == Some(scope.seam)
            && terminal == scope.seam_hash
            && scope
                .next_raw
                .is_none_or(|expected| verified.next_raw == Some(expected))
            && verified
                .first_raw
                .zip(verified.next_raw)
                .is_some_and(|(start, end)| start < end),
        "selected archive missed its write cursor or checkpoint",
    )?;
    (scope.check_identity)(&input)?;
    let reopened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    (scope.check_identity)(&reopened)?;
    println!(
        "{}",
        json!({
            "schema":scope.schema,
            "source_archive_sha256":scope.source_sha,"selected_archive_sha256":hex(&selected_hash),
            "selected_semantic_sha256":hex(&verified.semantic),"first_slot":scope.first,"last_slot":scope.seam,
            "terminal_blockhash":terminal,"raw_start":verified.first_raw,"raw_end_exclusive":verified.next_raw,
            "independently_decoded":true,"selected_archive_bytes":layout.len(),
            "unchanged_source_extent":{"offset":layout.middle.start,"length":layout.middle_len()},
            "physical_archive_bytes_written":0
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetstreamer_horizon::{
        archive::{
            ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveWriter, ArchiveWriterConfig,
            BootstrapStateKind, RuntimeAdmission, TransactionMetadataPolicy,
            reencode_archive_prefix,
        },
        block_metas::BlockMeta,
    };
    use std::io::Cursor;

    fn source() -> Vec<u8> {
        const START: u64 = 432_000;
        let seed = bs58::encode([8; 32]).into_string();
        let prototype = ArchiveProvenance::V2(ArchiveProvenanceV2 {
            base: ArchiveProvenanceV1 {
                generation_profile: "jetstreamer-node/historical-replay-v1".into(),
                runtime_profile: "solana-v1.4.25".into(),
                runtime_revision: "893cc7647248a3536fb6e6d0b5e51c71446b862d".into(),
                runtime_admission: RuntimeAdmission::Candidate,
                runtime_toolchain: "rustc1.46.0".into(),
                genesis_hash: seed.parse().unwrap(),
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_slot: START - 1,
                bootstrap_state_hash: seed.parse().unwrap(),
                requested_slot_start: START,
                requested_slot_count: 16,
                transaction_metadata: TransactionMetadataPolicy::runtime_reconstructed(),
            },
            worker_executable_sha256: [1; 32],
        });
        let config = ArchiveWriterConfig {
            bucket_slots: 4,
            compression: Compression::Zstd,
            ..Default::default()
        };
        let mut writer =
            ArchiveWriter::new_with_provenance(Vec::new(), 1, START, 16, config, &prototype)
                .unwrap();
        let mut head = seed.parse().unwrap();
        let mut parent = START - 1;
        writer.preserve_initial_poh_anchor(START, head).unwrap();
        for (i, slot) in (START..START + 16).enumerate() {
            if ![1, 5, 8, 12].contains(&i) {
                writer.write_skipped_slot(slot).unwrap();
                continue;
            }
            writer.begin_slot(slot).unwrap();
            if i == 1 {
                let mut epoch = EpochMeta::new_boxed();
                epoch.epoch = 1;
                epoch.start_slot = START;
                epoch.slot_count = 16;
                epoch.first_block_slot = slot;
                writer.write_epoch_meta(&epoch).unwrap();
            }
            let mut block = BlockMeta::new_boxed();
            block.slot = slot;
            block.parent_slot = parent;
            block.parent_blockhash = head;
            block.blockhash = bs58::encode([i as u8; 32]).into_string().parse().unwrap();
            writer.end_slot(&block, &[]).unwrap();
            head = block.blockhash;
            parent = slot;
        }
        writer.finish().unwrap().0
    }

    #[test]
    fn virtual_cut_matches_decoded_stream_and_actual_byte_sha() {
        let original = source();
        let raw = ArchiveReader::open(Cursor::new(&original)).unwrap();
        let entries = &raw.bucket_index()[..3];
        let end = raw.header().slot_start + 9;
        let mut reader = Cursor::new(&original);
        let virtual_layout = cut(
            &mut reader,
            raw.header(),
            raw.provenance().unwrap().unwrap(),
            entries,
            end,
        )
        .unwrap();
        boundaries(&mut reader, raw.header(), entries, &virtual_layout, end).unwrap();
        let mut physically_read = Vec::new();
        Selected {
            source: &mut reader,
            bytes: &virtual_layout,
            at: 0,
        }
        .read_to_end(&mut physically_read)
        .unwrap();
        let (src, selected, size) = hashes(&mut reader, &virtual_layout).unwrap();
        assert_eq!(src, Sha256::digest(&original).as_slice());
        assert_eq!(selected, Sha256::digest(&physically_read).as_slice());
        assert_eq!(size, original.len() as u64);
        assert_eq!(virtual_layout.len(), physically_read.len() as u64);
        let result = semantic_read(Cursor::new(&physically_read), end).unwrap();
        let (_, reference) = reencode_archive_prefix(
            Cursor::new(&original),
            Vec::new(),
            ArchiveWriterConfig {
                bucket_slots: 4,
                compression: Compression::Zstd,
                ..Default::default()
            },
            9,
        )
        .unwrap();
        assert_eq!(result.semantic, reference.output_semantic_sha256);
        assert_eq!(result.last_block, Some(end - 1));
        let start = virtual_layout.front.len();
        let old = virtual_layout.middle.start as usize..virtual_layout.middle.end as usize;
        assert_eq!(&physically_read[start..start + old.len()], &original[old]);
    }

    #[test]
    fn cursor_refuses_a_gap_or_duplicate() {
        for invalid in [vec![10, 12], vec![10, 10]] {
            let mut visitor = Verify::new(1, [1; 32], 0);
            visitor.raw = invalid;
            visitor.close_versions();
            assert!(visitor.finish().is_err());
        }
        let mut visitor = Verify::new(1, [1; 32], 0);
        visitor.raw = vec![12, 10, 11];
        visitor.close_versions();
        let result = visitor.finish().unwrap();
        assert_eq!(result.first_raw, Some(10));
        assert_eq!(result.next_raw, Some(13));
    }
}
