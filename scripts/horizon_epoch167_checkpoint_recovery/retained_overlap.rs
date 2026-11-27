//! Decode the retained V2 frames spanning the authenticated restart checkpoint
//! through the last physical bucket. The stopped file has no index or footer.
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{
        BucketDecoder, BucketHeader, BucketIndexEntry, Consumption, FORMAT_VERSION_V2,
        MAX_FILE_HEADER_BYTES, SemanticDigest, SlotKind, SlotVisitor, parse_file_header,
    },
    block_metas::BlockNotification,
    entries::EntryRecord,
    epochs::EpochMeta,
    transactions::Transaction,
};
use lencode::prelude::*;

const SEAM: u64 = 72_509_256;
const END: u64 = 72_512_768;
const FIRST_BUCKET: u64 = 72_509_184;
const FIRST_OFFSET: u64 = 100_312_515_038;
const LENGTH: u64 = 101_301_229_551;
const PREVIOUS_HASH: &str = "EKyd3gpvdLwRzg7AnSvk4ueoSRnr2CHkZvRN25qeDT9";
const SEAM_HASH: &str = "1BK4wPkM1ZGbKrVAFdCzyXYWaB8bhPK7vBcfZqN8U1G";
const LAST_HASH: &str = "rHfcRAZeWMTKGpbcnHRTxKHcoLUR8p6XhbsCcSSWsuA";

fn require(value: bool, reason: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, reason))
    }
}

fn check_file(file: &File, path: &Path) -> io::Result<()> {
    let m = file.metadata()?;
    let p = path.symlink_metadata()?;
    require(
        m.is_file()
            && p.is_file()
            && path.canonicalize()? == path
            && (p.dev(), p.ino()) == (m.dev(), m.ino())
            && m.nlink() == 1
            && (m.dev(), m.ino(), m.len()) == (64512, 114491454, LENGTH)
            && (m.mtime(), m.mtime_nsec()) == (1795745919, 857606760)
            && (m.ctime(), m.ctime_nsec()) == (1795745919, 857606760),
        "retained source identity changed",
    )
}

#[derive(Default)]
struct Writes {
    pending: Vec<u64>,
    first: Option<u64>,
    next: Option<u64>,
}

impl Writes {
    fn close_slot(&mut self) -> io::Result<()> {
        self.pending.sort_unstable();
        for version in self.pending.drain(..) {
            self.first.get_or_insert(version);
            require(
                version == *self.next.get_or_insert(version),
                "noncontiguous account writes",
            )?;
            self.next = version.checked_add(1);
            require(self.next.is_some(), "account write cursor overflow")?;
        }
        Ok(())
    }
}

struct Window {
    slot: u64,
    ancestor: u64,
    hash: String,
    writes: Writes,
    raw_after_seam: Option<u64>,
    digest: SemanticDigest,
    blocks: u64,
    transactions: u64,
    valid: bool,
}

impl SlotVisitor for Window {
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        self.valid &= slot == self.slot;
        self.digest.on_slot_start(slot, kind);
    }
    fn on_epoch(&mut self, _: &EpochMeta) {
        self.valid = false; // This window lies strictly inside epoch 167.
    }
    fn on_transaction(&mut self, slot: u64, index: u32, tx: &Transaction) {
        self.transactions += 1;
        self.writes
            .pending
            .extend(tx.iter_account_updates().map(|(m, _)| m.write_version));
        self.digest.on_transaction(slot, index, tx);
    }
    fn on_pre_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        self.writes.pending.push(update.write_version);
        self.digest.on_pre_account_update(slot, update);
    }
    fn on_post_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        self.writes.pending.push(update.write_version);
        self.digest.on_post_account_update(slot, update);
    }
    fn on_block(&mut self, block: &BlockNotification, entries: &[EntryRecord]) {
        self.valid &= self.slot == block.slot() && self.writes.close_slot().is_ok();
        if let BlockNotification::Block(b) = block {
            self.valid &=
                b.parent_slot == self.ancestor && b.parent_blockhash.to_string() == self.hash;
            self.ancestor = b.slot;
            self.hash = b.blockhash.to_string();
            self.blocks += 1;
        }
        if self.slot == SEAM {
            self.valid &= self.ancestor == SEAM && self.hash == SEAM_HASH;
            self.raw_after_seam = self.writes.next;
        }
        self.digest.on_block(block, entries);
        self.slot += 1;
    }
    fn consumption(&self) -> Consumption {
        self.digest.consumption()
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let [_, path]: [String; 2] = std::env::args()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "expected retained epoch 167 file path")?;
    let path = Path::new(&path);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    check_file(&file, path)?;
    let mut header = Vec::new();
    (&mut file)
        .take(MAX_FILE_HEADER_BYTES + 18)
        .read_to_end(&mut header)?;
    let (header, _) = parse_file_header(&header)?;
    require(
        (
            header.epoch,
            header.slot_start,
            header.slot_count,
            header.bucket_slots,
            header.format_version,
        ) == (167, 72_144_000, 432_000, 128, FORMAT_VERSION_V2),
        "unexpected file header",
    )?;
    let mut decoder = BucketDecoder::for_file_header(&header)?;
    decoder.verify_chain = true;
    let mut window = Window {
        slot: SEAM,
        ancestor: SEAM - 1,
        hash: PREVIOUS_HASH.into(),
        writes: Writes::default(),
        raw_after_seam: None,
        digest: SemanticDigest::new(),
        blocks: 0,
        transactions: 0,
        valid: true,
    };
    decoder.set_consumption(window.consumption());
    file.seek(SeekFrom::Start(FIRST_OFFSET))?;
    let mut frame = Vec::new();
    for first in (FIRST_BUCKET..END).step_by(128) {
        let offset = file.stream_position()?;
        let header = BucketHeader::decode_ext(&mut file, None)?;
        let len = (file.stream_position()? - offset)
            .checked_add(header.stored_len)
            .ok_or("bucket length overflow")?;
        require(
            header.first_slot == first
                && header.slot_count == 128
                && len <= 768 << 20
                && offset.checked_add(len).is_some_and(|end| end <= LENGTH),
            "invalid bucket extent",
        )?;
        file.seek(SeekFrom::Start(offset))?;
        frame.resize(usize::try_from(len)?, 0);
        file.read_exact(&mut frame)?;
        decoder.load_indexed_bucket_bytes(
            &frame,
            BucketIndexEntry {
                first_slot: first,
                offset,
                len,
            },
        )?;
        while decoder.slots_remaining() > 0 {
            decoder.decode_slot_frame(SEAM, &mut window)?;
        }
        require(
            window.valid,
            "slot coverage, ancestry, checkpoint, or account write mismatch",
        )?;
    }
    require(
        file.stream_position()? == LENGTH
            && window.slot == END
            && window.ancestor == END - 1
            && window.hash == LAST_HASH,
        "physical terminal differs from finalized block",
    )?;
    check_file(&file, path)?;
    let digest = window.digest.finish()?;
    let digest = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    println!(
        "first_slot={SEAM} last_slot={} slots={} blocks={} transactions={} first_write={} seam_next_write={} raw_end_exclusive={} terminal_blockhash={} raw_event_sha256={digest}",
        END - 1,
        END - SEAM,
        window.blocks,
        window.transactions,
        window.writes.first.ok_or("no writes")?,
        window
            .raw_after_seam
            .ok_or("checkpoint contained no account writes")?,
        window.writes.next.ok_or("no terminal write cursor")?,
        window.hash
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn orders_within_slots_and_rejects_a_gap_or_repeat_across_slots() {
        for next in [37, 39, 41] {
            let mut writes = Writes {
                pending: vec![38, 37],
                ..Writes::default()
            };
            writes.close_slot().unwrap();
            assert_eq!((writes.first, writes.next), (Some(37), Some(39)));
            writes.pending.push(next);
            assert_eq!(writes.close_slot().is_ok(), next == 39);
        }
    }
}
