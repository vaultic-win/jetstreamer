//! Decode adjacent archive edges directly from an authenticated R2 inventory.
//! This is diagnostic evidence. It does not publish or retire archives.

use std::{
    env, fs,
    io::{self, BufReader, Read, Seek, SeekFrom},
    path::Path,
};

use jetstreamer_horizon::archive::{
    ArchiveReader, BlockNotification, Consumption, EntryRecord, SlotVisitor,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::runtime::Runtime;

#[path = "../../jetstreamer-firehose/src/firehose_horizon/pinned.rs"]
#[allow(dead_code)]
mod pinned;

type Error = Box<dyn std::error::Error>;

fn try_resize_read_buffer(buffer: &mut Vec<u8>, size: usize) -> io::Result<()> {
    buffer
        .try_reserve(size.saturating_sub(buffer.len()))
        .map_err(io::Error::other)?;
    buffer.resize(size, 0);
    Ok(())
}

struct RemoteFile<'a> {
    reader: pinned::Reader,
    runtime: &'a Runtime,
    offset: u64,
}

impl Read for RemoteFile<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.reader.len().saturating_sub(self.offset);
        let count = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if count == 0 {
            return Ok(0);
        }
        self.runtime
            .block_on(self.reader.read_at(self.offset, &mut buffer[..count]))?;
        self.offset += count as u64;
        Ok(count)
    }
}

fn seek_offset(current: u64, length: u64, position: SeekFrom) -> io::Result<u64> {
    match position {
        SeekFrom::Start(offset) => Some(offset),
        SeekFrom::Current(delta) => current.checked_add_signed(delta),
        SeekFrom::End(delta) => length.checked_add_signed(delta),
    }
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid archive offset"))
}

impl Seek for RemoteFile<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.offset = seek_offset(self.offset, self.reader.len(), position)?;
        Ok(self.offset)
    }
}

#[derive(Debug, Serialize)]
struct Block {
    slot: u64,
    parent_slot: u64,
    parent_blockhash: String,
    blockhash: String,
}

#[derive(Default)]
struct BucketEdges {
    first: Option<Block>,
    last: Option<Block>,
}

impl SlotVisitor for BucketEdges {
    fn on_block(&mut self, notification: &BlockNotification, _: &[EntryRecord]) {
        if let BlockNotification::Block(meta) = notification {
            let edge = || Block {
                slot: meta.slot,
                parent_slot: meta.parent_slot,
                parent_blockhash: meta.parent_blockhash.to_string(),
                blockhash: meta.blockhash.to_string(),
            };
            self.first.get_or_insert_with(edge);
            self.last = Some(edge());
        }
    }

    fn consumption(&self) -> Consumption {
        Consumption::all()
            .without_account_update_data()
            .without_block_account_update_arenas()
    }
}

#[derive(Debug, Serialize)]
struct Edges {
    epoch: u64,
    slot_start: u64,
    slot_count: u64,
    initial_anchor: String,
    first: Block,
    last: Block,
}

fn edges(source: impl Read + Seek, epoch: u64) -> Result<Edges, Error> {
    let mut archive = ArchiveReader::open(source)?;
    let header = archive.header().clone();
    let slot_start = epoch.checked_mul(432_000).ok_or("epoch slot overflow")?;
    if header.epoch != epoch || header.slot_start != slot_start || header.slot_count != 432_000 {
        return Err("archive header does not cover the requested full epoch".into());
    }
    let mut initial_anchor = None;
    let mut first = None;
    for bucket in 0..archive.bucket_count() {
        let mut visitor = BucketEdges::default();
        archive.read_bucket_with_header(bucket, &mut visitor, |bucket_header, _| {
            if bucket == 0 {
                initial_anchor = Some(bucket_header.poh_start_hash.to_string());
            }
            Ok(())
        })?;
        first = visitor.first;
        if first.is_some() {
            break;
        }
    }

    let mut last = None;
    for bucket in (0..archive.bucket_count()).rev() {
        let mut visitor = BucketEdges::default();
        archive.read_bucket(bucket, &mut visitor)?;
        last = visitor.last;
        if last.is_some() {
            break;
        }
    }
    Ok(Edges {
        epoch,
        slot_start,
        slot_count: header.slot_count,
        initial_anchor: initial_anchor.ok_or("archive has no initial PoH anchor")?,
        first: first.ok_or("archive has no first block")?,
        last: last.ok_or("archive has no last block")?,
    })
}

fn validate_boundary(left: &Edges, right: &Edges) -> Result<(), Error> {
    if left.epoch.checked_add(1) != Some(right.epoch)
        || left.slot_start.checked_add(left.slot_count) != Some(right.slot_start)
        || right.initial_anchor != left.last.blockhash
        || right.first.parent_slot != left.last.slot
        || right.first.parent_blockhash != left.last.blockhash
    {
        return Err(format!("archive boundary mismatch: left {left:?}, right {right:?}").into());
    }
    Ok(())
}

fn inventory_hash(path: &Path) -> Result<String, Error> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take((8 << 20) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 8 << 20 {
        return Err("archive inventory exceeds 8 MiB".into());
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn main() -> Result<(), Error> {
    let args: Vec<_> = env::args().skip(1).collect();
    let [origin, inventory_path, inventory_sha256, left, right] = args.as_slice() else {
        return Err("usage: pinned-boundary PUBLIC_ORIGIN INVENTORY INVENTORY_SHA256 LEFT_EPOCH RIGHT_EPOCH".into());
    };
    let left: u64 = left.parse()?;
    let right: u64 = right.parse()?;
    if left.checked_add(1) != Some(right) {
        return Err("the epochs must be adjacent and in ascending order".into());
    }
    let path = Path::new(inventory_path);
    if path.canonicalize()? != path || inventory_hash(path)? != *inventory_sha256 {
        return Err("archive inventory path or SHA-256 differs".into());
    }
    let inventory = pinned::PinnedArchives::load(origin, path)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let load = |epoch| -> Result<Edges, Error> {
        let reader = inventory.open(epoch, &client, None)?;
        edges(
            BufReader::with_capacity(
                64 << 10,
                RemoteFile {
                    reader,
                    runtime: &runtime,
                    offset: 0,
                },
            ),
            epoch,
        )
    };
    let left = load(left)?;
    let right = load(right)?;
    validate_boundary(&left, &right)?;
    if inventory_hash(path)? != *inventory_sha256 {
        return Err("archive inventory changed during inspection".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "schema": "jetstreamer-pinned-archive-boundary-evidence-v1",
            "public_origin": origin,
            "inventory_path": path,
            "inventory_sha256": inventory_sha256,
            "left": left,
            "right": right,
            "boundary_verified": true,
            "publication_authorized": false,
            "local_retirement_authorized": false,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_seek_keeps_u64_offsets_and_rejects_wrap() {
        let size = 180_000_000_000;
        assert_eq!(seek_offset(0, size, SeekFrom::End(-24)).unwrap(), size - 24);
        assert!(seek_offset(0, size, SeekFrom::Current(-1)).is_err());
        assert!(seek_offset(u64::MAX, size, SeekFrom::Current(1)).is_err());
    }
}
