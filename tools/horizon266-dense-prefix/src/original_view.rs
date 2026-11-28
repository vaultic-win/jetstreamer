use jetstreamer_horizon::archive::{
    ArchiveFormatError, ArchiveReader, BucketHeader, BucketIndexEntry, Footer, parse_file_header,
};
use lencode::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::{FileExt, MetadataExt},
    path::Path,
};
use xxhash_rust::xxh64::xxh64;

const FIRST: u64 = 114_912_000;
const RETAINED_BYTES: u64 = 5_085_745_842;
const RETAINED_BUCKETS: u64 = 90;
const WIDTH: u64 = 128;
const RAW_SHA: &str = "a58ca8569cf3d10b2a063f9b731ac94ce61945a48adf216cc1c65608d2e3111a";

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn ensure(ok: bool, label: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(label.into()) }
}

pub(super) fn pinned_source(file: &File, path: &Path) -> Result<()> {
    let handle = file.metadata()?;
    let path_entry = path.symlink_metadata()?;
    for m in [handle, path_entry] {
        ensure(
            m.is_file()
                && m.dev() == 1810
                && m.ino() == 19005466
                && m.len() == RETAINED_BYTES
                && m.mtime() == 1795409649
                && m.mtime_nsec() == 356579349
                && m.ctime() == 1795409649
                && m.ctime_nsec() == 356579349,
            "physical source identity changed",
        )?;
    }
    Ok(())
}

pub(super) fn rehash(file: &File, trailer: &[u8]) -> Result<String> {
    let mut src = View {
        file: file.try_clone()?,
        tail: &[],
        pos: 0,
    };
    let mut hash = Sha256::new();
    let mut chunk = vec![0; 1 << 20];
    loop {
        let got = src.read(&mut chunk)?;
        if got == 0 {
            break;
        }
        hash.update(&chunk[..got]);
    }
    ensure(
        format!("{:x}", hash.clone().finalize()) == RAW_SHA,
        "physical source SHA-256 mismatch",
    )?;
    hash.update(trailer);
    Ok(format!("{:x}", hash.finalize()))
}

#[derive(Debug)]
struct View<'a> {
    file: File,
    tail: &'a [u8],
    pos: u64,
}

impl Read for View<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = if self.pos < RETAINED_BYTES {
            let maximum = buffer.len().min((RETAINED_BYTES - self.pos) as usize);
            self.file.read_at(&mut buffer[..maximum], self.pos)?
        } else {
            self.tail
                .get((self.pos - RETAINED_BYTES) as usize..)
                .unwrap_or_default()
                .read(buffer)?
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for View<'_> {
    fn seek(&mut self, how: SeekFrom) -> io::Result<u64> {
        let limit = RETAINED_BYTES + self.tail.len() as u64;
        let destination = match how {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(delta) => i128::from(self.pos) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(limit) + i128::from(delta),
        };
        if !(0..=i128::from(limit)).contains(&destination) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek violates indexed view bounds",
            ));
        }
        self.pos = destination as u64;
        Ok(self.pos)
    }
}

fn derive(file: &File) -> Result<Vec<u8>> {
    let mut header_bytes = [0; 4096];
    file.read_exact_at(&mut header_bytes, 0)?;
    let (header, length) = parse_file_header(&header_bytes)?;
    ensure(
        header.epoch == 266
            && header.format_version == 2
            && header.slot_start == FIRST
            && header.slot_count == 432_000
            && u64::from(header.bucket_slots) == WIDTH,
        "file range changed",
    )?;
    ensure(
        matches!(
            ArchiveReader::open(file.try_clone()?),
            Err(ArchiveFormatError::BadMagic)
        ),
        "physical source unexpectedly has closing magic",
    )?;
    let mut index = Vec::new();
    let mut offset = length as u64;
    for ordinal in 0..RETAINED_BUCKETS {
        let mut prefix = [0; 128];
        file.read_exact_at(&mut prefix, offset)?;
        let mut cursor = lencode::io::Cursor::new(&prefix);
        let bucket = BucketHeader::decode_ext(&mut cursor, None)
            .map_err(|_| "retained bucket header invalid")?;
        let first_slot = FIRST + ordinal * WIDTH;
        ensure(
            bucket.first_slot == first_slot
                && u64::from(bucket.slot_count) == WIDTH
                && bucket.stored_len > 0
                && bucket.stored_len <= 384 << 20
                && bucket.uncompressed_len > 0
                && bucket.uncompressed_len <= 512 << 20,
            "retained bucket range or size changed",
        )?;
        let len = bucket.stored_len + cursor.position() as u64;
        let end = offset.checked_add(len).ok_or("bucket extent overflow")?;
        ensure(
            end <= RETAINED_BYTES,
            "retained bucket crosses physical EOF",
        )?;
        index.push(BucketIndexEntry {
            first_slot,
            offset,
            len,
        });
        offset = end;
    }
    ensure(
        offset == RETAINED_BYTES,
        "unexpected bytes after last retained bucket",
    )?;
    let mut tail = Vec::new();
    (index.len() as u64)
        .encode_ext(&mut tail, None)
        .map_err(|_| "index count encoding")?;
    for row in &index {
        row.encode_ext(&mut tail, None)
            .map_err(|_| "index entry encoding")?;
    }
    let footer = Footer {
        index_offset: RETAINED_BYTES,
        index_len: tail.len() as u64,
        bucket_count: index.len() as u64,
        index_xxh64: xxh64(&tail, 0),
    };
    tail.extend_from_slice(&footer.to_bytes());
    let mut accepted = ArchiveReader::open(View {
        file: file.try_clone()?,
        tail: &tail,
        pos: 0,
    })?;
    ensure(
        accepted.bucket_index().len() == index.len(),
        "native indexed view bucket count changed",
    )?;
    for (want, got) in index.iter().zip(accepted.bucket_index()) {
        ensure(
            (want.offset, want.len, want.first_slot) == (got.offset, got.len, got.first_slot),
            "native indexed view bucket entry changed",
        )?;
    }
    ensure(
        !accepted.has_complete_slot_coverage()?,
        "prefix unexpectedly satisfies full epoch coverage",
    )?;
    Ok(tail)
}

pub(super) fn open<'a>(file: &File, tail: &'a [u8]) -> Result<impl Read + Seek + 'a> {
    Ok(View {
        file: file.try_clone()?,
        tail,
        pos: 0,
    })
}

pub(super) fn verify_trailer(file: &File, tail: &[u8]) -> Result<()> {
    ensure(
        tail == derive(file)?,
        "stored trailer differs from native index reconstruction",
    )
}
