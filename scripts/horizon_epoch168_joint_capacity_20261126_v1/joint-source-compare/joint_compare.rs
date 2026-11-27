use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    mem,
    ops::Range,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{ArchiveReader, SemanticDigest, SlotKind, SlotVisitor},
    block_metas::BlockNotification,
    entries::EntryRecord,
    epochs::EpochMeta,
    transactions::Transaction,
};
use lencode::prelude::*;
use sha2::{Digest, Sha256};

use super::{END, FIRST, INPUT, PrefixView, invalid, original_identity};

const BOOTSTRAP: u64 = 72_991_436;
const SEAM: u64 = 72_994_766;
const ROOT: u64 = 73_007_829;
const TAIL_END: u64 = 73_015_142;
const PATH_ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1/full-metered-20261121-v1";
const BASE_ANCHOR: &str = "AcNuUz2ZRmkco618BioYzFNGYuUYh78W6PqD6oHxRXwk";
const SEAM_ANCHOR: &str = "5mMqY7Po42u2cB3L2X6VVvLFkbvPXiZXH2sYMnZiLpnU";

#[derive(Default, Debug, PartialEq, Eq)]
struct Versions {
    first_event: Option<u64>,
    first_raw: Option<u64>,
    next_raw: Option<u64>,
    slot: Vec<u64>,
}

impl Versions {
    fn normalize(&mut self, raw: u64) -> Option<u64> {
        self.slot.push(raw);
        let origin = *self.first_event.get_or_insert(raw);
        let relative = i128::from(raw) - i128::from(origin) + i128::from(1u64 << 63);
        relative.try_into().ok()
    }

    fn finish_slot(&mut self) -> io::Result<()> {
        self.slot.sort_unstable();
        for raw in self.slot.drain(..) {
            self.first_raw.get_or_insert(raw);
            if raw != *self.next_raw.get_or_insert(raw) {
                return Err(invalid("duplicate or missing raw account write version"));
            }
            self.next_raw = Some(
                raw.checked_add(1)
                    .ok_or_else(|| invalid("raw write cursor overflow"))?,
            );
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
struct Frame {
    slot: u64,
    digest: [u8; 32],
}

struct Overlap {
    range: Range<u64>,
    envelope: Option<Range<u64>>,
    envelope_count: usize,
    current: u64,
    parent_slot: u64,
    parent_hash: String,
    versions: Versions,
    digest: SemanticDigest,
    frames: Vec<Frame>,
    error: Option<&'static str>,
    transaction: Box<Transaction>,
    wire: Vec<u8>,
}

impl Overlap {
    fn new(range: Range<u64>, parent_hash: &str, envelope: Option<Range<u64>>) -> Self {
        Self {
            parent_slot: range.start - 1,
            current: range.start,
            range,
            envelope,
            envelope_count: 0,
            parent_hash: parent_hash.to_owned(),
            versions: Versions::default(),
            digest: SemanticDigest::new(),
            frames: Vec::new(),
            error: None,
            transaction: Transaction::new_boxed(),
            wire: Vec::new(),
        }
    }

    fn update_version(&mut self, raw: u64) -> u64 {
        self.versions.normalize(raw).unwrap_or_else(|| {
            self.error
                .get_or_insert("write-version normalization overflow");
            0
        })
    }

    fn validate(&self, count: u64) -> io::Result<()> {
        if let Some(reason) = self.error {
            return Err(invalid(reason));
        }
        if count != self.range.end - self.range.start
            || count != self.frames.len() as u64
            || self.envelope_count != usize::from(self.envelope.is_some())
            || self.parent_slot != self.range.end - 1
            || self.versions.first_raw.is_none()
        {
            return Err(invalid(
                "short overlap or missing terminal block or account writes",
            ));
        }
        Ok(())
    }
}

impl SlotVisitor for Overlap {
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        self.current = slot;
        if slot != self.range.start + self.frames.len() as u64 {
            self.error.get_or_insert("missing or repeated slot");
        }
        self.digest.on_slot_start(slot, kind);
    }

    fn on_epoch(&mut self, value: &EpochMeta) {
        self.envelope_count += 1;
        // The two focused archives have empty synthetic epoch envelopes.
        // Preserve every real epoch event by rejecting a differing shape.
        if self.envelope_count != 1
            || self.envelope.as_ref().is_none_or(|range| {
                value.epoch != 168
                    || value.start_slot != range.start
                    || value.first_block_slot != self.current
                    || value.slot_count != range.end - range.start
            })
            || self.parent_slot != self.range.start - 1
            || value.num_reward_partitions.is_some()
            || value.updates.iter().next().is_some()
        {
            self.error
                .get_or_insert("unexpected nonempty or misplaced epoch envelope");
        }
    }

    fn on_pre_account_update(&mut self, slot: u64, value: &AccountUpdateView<'_>) {
        let normalized = AccountUpdateView {
            write_version: self.update_version(value.write_version),
            ..*value
        };
        self.digest.on_pre_account_update(slot, &normalized);
    }

    fn on_transaction(&mut self, slot: u64, index: u32, value: &Transaction) {
        if value.account_updates().is_empty() {
            self.digest.on_transaction(slot, index, value);
            return;
        }
        self.wire.clear();
        let encoded = value.encode_ext(&mut self.wire, None);
        let mut input = self.wire.as_slice();
        if encoded.is_err()
            || self.transaction.decode_into(&mut input, None).is_err()
            || !input.is_empty()
        {
            self.error.get_or_insert("transaction copy failed");
            return;
        }
        self.transaction.clear_account_updates();
        for (meta, data) in value.iter_account_updates() {
            let normalized = AccountUpdateView {
                pubkey: meta.pubkey,
                lamports: meta.lamports,
                owner: meta.owner,
                executable: meta.executable,
                rent_epoch: meta.rent_epoch,
                write_version: self.update_version(meta.write_version),
                data,
            };
            if self.transaction.push_account_update(&normalized).is_err() {
                self.error
                    .get_or_insert("normalized transaction update failed");
                return;
            }
        }
        self.digest.on_transaction(slot, index, &self.transaction);
    }

    fn on_post_account_update(&mut self, slot: u64, value: &AccountUpdateView<'_>) {
        let normalized = AccountUpdateView {
            write_version: self.update_version(value.write_version),
            ..*value
        };
        self.digest.on_post_account_update(slot, &normalized);
    }

    fn on_block(&mut self, block: &BlockNotification, entries: &[EntryRecord]) {
        if let BlockNotification::Block(b) = block {
            if b.parent_slot != self.parent_slot
                || b.parent_blockhash.to_string() != self.parent_hash
            {
                self.error
                    .get_or_insert("block ancestry differs from the preceding checkpoint or block");
            }
            self.parent_slot = b.slot;
            self.parent_hash = b.blockhash.to_string();
        }
        if self.versions.finish_slot().is_err() {
            self.error
                .get_or_insert("invalid raw write-version continuity");
        }
        self.digest.on_block(block, entries);
        match mem::take(&mut self.digest).finish() {
            Ok(digest) => self.frames.push(Frame {
                slot: block.slot(),
                digest,
            }),
            Err(_) => {
                self.error.get_or_insert("overlap semantic encoding failed");
            }
        }
    }

    fn consumption(&self) -> jetstreamer_horizon::archive::Consumption {
        self.digest.consumption()
    }
}

type Failure = Box<dyn std::error::Error>;

fn read_range<R: Read + Seek>(
    source: R,
    range: Range<u64>,
    anchor: &str,
    envelope: Option<Range<u64>>,
) -> Result<Overlap, Failure> {
    let mut archive = ArchiveReader::open(source)?;
    archive.verify_chain = true;
    let mut result = Overlap::new(range, anchor, envelope);
    let count = archive.read_slots(
        result.range.start,
        result.range.end - result.range.start,
        &mut result,
    )?;
    result.validate(count)?;
    Ok(result)
}

fn hex(digest: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut result, "{byte:02x}").expect("in-memory hex encoding");
    }
    result
}

fn compare(label: &str, left: &Overlap, joint: &Overlap) -> Result<(), Failure> {
    assert_eq!(left.range, joint.range);
    for (a, b) in left.frames.iter().zip(&joint.frames) {
        if a != b {
            return Err(format!("{label} normalized event mismatch at slot {}", a.slot).into());
        }
    }
    if left.frames.len() != joint.frames.len() || left.parent_hash != joint.parent_hash {
        return Err(invalid("overlap length or terminal block differs").into());
    }
    let mut digest = Sha256::new();
    for frame in &left.frames {
        digest.update(frame.slot.to_le_bytes());
        digest.update(frame.digest);
    }
    println!(
        "{label} first_slot={} last_slot={} normalized_sha256={} terminal_blockhash={} source_raw_start={} source_raw_end_exclusive={} joint_raw_start={} joint_raw_end_exclusive={}",
        left.range.start,
        left.range.end - 1,
        hex(&digest.finalize()),
        left.parent_hash,
        left.versions.first_raw.unwrap(),
        left.versions.next_raw.unwrap(),
        joint.versions.first_raw.unwrap(),
        joint.versions.next_raw.unwrap()
    );
    Ok(())
}

fn file_identity(file: &File) -> io::Result<(u64, u64, u64, i64, i64, i64, i64)> {
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 {
        return Err(invalid("archive is not a single-link regular file"));
    }
    Ok((
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}

fn open(path: &Path) -> io::Result<File> {
    if path.canonicalize()? != path {
        return Err(invalid("archive path is indirect"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    file_identity(&file)?;
    Ok(file)
}

fn sha256(mut file: &File) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut sha = Sha256::new();
    io::copy(&mut file, &mut sha)?;
    Ok(hex(&sha.finalize()))
}

pub(super) fn run(expected_joint_digest: &str) -> Result<(), Failure> {
    if expected_joint_digest.len() != 64
        || !expected_joint_digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("supply the exact terminal joint archive SHA-256").into());
    }
    let run = Path::new(PATH_ROOT);
    let paths = [
        Path::new(INPUT).to_owned(),
        run.join("cold-retry6-20261126/output/epoch-168-tail.jet"),
        run.join("joint-checkpoint-reduced-20261126-v1/output/epoch-168-joint-checkpoints.jet"),
    ];
    let [prefix, tail, joint] = [open(&paths[0])?, open(&paths[1])?, open(&paths[2])?];
    original_identity(&prefix)?;
    let tail_id = file_identity(&tail)?;
    if tail_id
        != (
            64512, 109397511, 5777373749, 1795716875, 975019015, 1795716875, 975019015,
        )
    {
        return Err(invalid("retained tail identity differs").into());
    }
    let joint_id = file_identity(&joint)?;
    if sha256(&joint)? != expected_joint_digest {
        return Err(invalid("joint archive digest differs").into());
    }
    let before = BOOTSTRAP + 1..SEAM + 1;
    let after = SEAM + 1..ROOT + 1;
    let joint_range = BOOTSTRAP + 1..ROOT + 1;
    let p = read_range(
        PrefixView::open(&prefix, 168, FIRST, END)?,
        before.clone(),
        BASE_ANCHOR,
        None,
    )?;
    let j1 = read_range(&joint, before, BASE_ANCHOR, Some(joint_range))?;
    compare("predecessor_overlap", &p, &j1)?;
    if j1.parent_hash != SEAM_ANCHOR {
        return Err(invalid("joint prefix did not reach the known seam block").into());
    }
    let t = read_range(&tail, after.clone(), SEAM_ANCHOR, Some(SEAM + 1..TAIL_END))?;
    let j2 = read_range(&joint, after, SEAM_ANCHOR, None)?;
    compare("successor_overlap", &t, &j2)?;
    if j1.versions.next_raw != j2.versions.first_raw
        || j1.versions.first_raw != Some(53_555_937_580)
        || t.versions.first_raw != Some(53_573_751_636)
    {
        return Err(invalid(
            "checkpoint write cursors differ from the decoded account write ranges",
        )
        .into());
    }
    original_identity(&prefix)?;
    original_identity(&open(&paths[0])?)?;
    if file_identity(&tail)? != tail_id
        || file_identity(&open(&paths[1])?)? != tail_id
        || file_identity(&joint)? != joint_id
        || file_identity(&open(&paths[2])?)? != joint_id
    {
        return Err(invalid("source archive changed during comparison").into());
    }
    println!(
        "comparison_complete epoch=168 seam={SEAM} ordinary_root={ROOT} joint_sha256={expected_joint_digest}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_cursor_origins_normalize_equally_even_if_events_are_out_of_raw_order() {
        let mut a = Versions::default();
        let mut b = Versions::default();
        for (x, y) in [(103, 8105), (101, 8103), (102, 8104)] {
            assert_eq!(a.normalize(x), b.normalize(y));
        }
        a.finish_slot().unwrap();
        b.finish_slot().unwrap();
        assert_eq!((a.first_raw, a.next_raw), (Some(101), Some(104)));
        assert_eq!((b.first_raw, b.next_raw), (Some(8103), Some(8106)));
        assert_eq!(a.normalize(104), b.normalize(8106));
        a.finish_slot().unwrap();
        b.finish_slot().unwrap();
    }

    #[test]
    fn frame_digest_preserves_transaction_data_and_event_order() {
        fn frame(first: u64, fee: u64, reverse: bool) -> [u8; 32] {
            let slot = BOOTSTRAP + 1;
            let mut visitor = Overlap::new(slot..slot + 1, BASE_ANCHOR, None);
            visitor.on_slot_start(slot, SlotKind::Skipped);
            let mut tx = Transaction::new_boxed();
            tx.fee = fee;
            let mut updates = [(first, [1]), (first + 1, [2])];
            if reverse {
                updates.reverse();
            }
            for (version, data) in &updates {
                tx.push_account_update(&AccountUpdateView {
                    pubkey: Default::default(),
                    owner: Default::default(),
                    lamports: 1,
                    executable: false,
                    rent_epoch: 0,
                    write_version: *version,
                    data,
                })
                .unwrap();
            }
            visitor.on_transaction(slot, 0, &tx);
            let mut block = BlockNotification::new_boxed();
            if let BlockNotification::Skipped(skipped) = block.as_mut() {
                skipped.slot = slot;
            }
            visitor.on_block(&block, &[]);
            assert!(visitor.error.is_none());
            visitor.frames[0].digest
        }
        assert_eq!(frame(5, 42, false), frame(500, 42, false));
        assert_ne!(frame(5, 42, false), frame(500, 43, false));
        assert_ne!(frame(5, 42, false), frame(500, 42, true));
    }

    #[test]
    fn detects_missing_or_duplicate_versions_between_or_inside_frames() {
        let mut a = Versions::default();
        a.normalize(4);
        a.finish_slot().unwrap();
        a.normalize(6);
        assert!(a.finish_slot().is_err());

        let mut b = Versions::default();
        b.normalize(5);
        b.normalize(5);
        assert!(b.finish_slot().is_err());
    }
}
