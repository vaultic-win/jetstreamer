use std::{
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
};

use jetstreamer_horizon::archive::{
    BucketHeader, BucketIndexEntry, FORMAT_VERSION_V2, Footer, MAX_FILE_HEADER_BYTES,
    parse_file_header, validate_bucket_index_layout,
};
use lencode::prelude::*;
use xxhash_rust::xxh64::xxh64;

mod joint_compare;

const FIRST: u64 = 72_576_000;
const END: u64 = 72_998_912;
const BYTES: u64 = 119_320_128_606;
const INPUT: &str = "/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1/full-metered-20261121-v1/cold-retry4-20261123/private/destination-ab320aeb1bd39ca9218ae95ef9e9b04e92f493e106c9a0e0b70582f6f568f51e/work/root-cohort-168-168/run-916123-1795399774038214572/archives/epoch-168.jet";

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// The original bytes and header are unchanged. Only the generated index and
// footer are visible beyond the physical EOF, through this read-only adapter.
struct PrefixView<R> {
    reader: R,
    body_len: u64,
    trailer: Cursor<Vec<u8>>,
    position: u64,
}

impl<R: Read + Seek> PrefixView<R> {
    fn open(
        mut reader: R,
        epoch: u64,
        start: u64,
        end: u64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let body_len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let mut prefix = Vec::new();
        reader
            .by_ref()
            .take(MAX_FILE_HEADER_BYTES + 18)
            .read_to_end(&mut prefix)?;
        let (header, header_end) = parse_file_header(&prefix)?;
        let width = u64::from(header.bucket_slots);
        let prefix_slots = end
            .checked_sub(start)
            .ok_or_else(|| invalid("reversed prefix"))?;
        if header.format_version != FORMAT_VERSION_V2
            || header.epoch != epoch
            || header.slot_start != start
            || width == 0
            || prefix_slots == 0
            || !prefix_slots.is_multiple_of(width)
            || prefix_slots >= header.slot_count
        {
            return Err(
                invalid("source is not a proper V2 archive prefix ending on a bucket").into(),
            );
        }

        let header_end = header_end as u64;
        let mut offset = header_end;
        let mut index = Vec::new();
        for slot in (start..end).step_by(width as usize) {
            if offset >= body_len {
                return Err(invalid("archive prefix ends before the expected bucket").into());
            }
            reader.seek(SeekFrom::Start(offset))?;
            let mut limited = reader.by_ref().take(body_len - offset);
            let bucket = BucketHeader::decode_ext(&mut limited, None)?;
            let header_len = body_len - offset - limited.limit();
            let frame_len = header_len
                .checked_add(bucket.stored_len)
                .ok_or_else(|| invalid("prefix bucket length overflow"))?;
            if bucket.first_slot != slot
                || u64::from(bucket.slot_count) != width
                || bucket.stored_len == 0
                || frame_len > body_len - offset
            {
                return Err(invalid("missing, partial, or misaligned prefix bucket").into());
            }
            index.push(BucketIndexEntry {
                first_slot: slot,
                offset,
                len: frame_len,
            });
            offset += frame_len;
        }
        if offset != body_len {
            return Err(invalid("unexpected bytes beyond complete prefix").into());
        }
        validate_bucket_index_layout(&header, header_end, offset, &index)?;
        let mut trailer = Vec::with_capacity(index.len() * 24 + 64);
        (index.len() as u64).encode_ext(&mut trailer, None)?;
        for entry in &index {
            entry.encode_ext(&mut trailer, None)?;
        }
        let footer = Footer {
            index_offset: body_len,
            index_len: trailer.len() as u64,
            bucket_count: index.len() as u64,
            index_xxh64: xxh64(&trailer, 0),
        };
        trailer.extend_from_slice(&footer.to_bytes());
        Ok(Self {
            reader,
            body_len,
            trailer: Cursor::new(trailer),
            position: 0,
        })
    }

    fn len(&self) -> u64 {
        self.body_len + self.trailer.get_ref().len() as u64
    }
}

impl<R: Read + Seek> Read for PrefixView<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = if self.position < self.body_len {
            self.reader.seek(SeekFrom::Start(self.position))?;
            let limit = usize::try_from(self.body_len - self.position).unwrap_or(usize::MAX);
            let count = buffer.len().min(limit);
            self.reader.read(&mut buffer[..count])?
        } else {
            self.trailer.set_position(self.position - self.body_len);
            self.trailer.read(buffer)?
        };
        self.position += count as u64;
        Ok(count)
    }
}

impl<R: Read + Seek> Seek for PrefixView<R> {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        let next = match seek {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => self.len().checked_add_signed(delta),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"))?;
        self.position = next;
        Ok(next)
    }
}

fn original_identity(file: &File) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.dev() != 64512
        || m.ino() != 103481863
        || m.len() != BYTES
        || (m.mtime(), m.mtime_nsec()) != (1795618061, 268866362)
        || (m.ctime(), m.ctime_nsec()) != (1795618061, 268866362)
        || m.nlink() != 1
    {
        return Err(invalid(
            "observed source differs from the closed retry4 file",
        ));
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argv: Vec<_> = std::env::args().skip(1).collect();
    match argv.as_slice() {
        [selector, sha256] if selector == "--compare-joint" => joint_compare::run(sha256),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected --compare-joint JOINT_ARCHIVE_SHA256",
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetstreamer_horizon::archive::{
        ArchiveReader, ArchiveWriter, ArchiveWriterConfig, FOOTER_LEN,
    };

    fn fixture() -> Vec<u8> {
        let config = ArchiveWriterConfig {
            bucket_slots: 2,
            ..ArchiveWriterConfig::default()
        };
        let mut writer = ArchiveWriter::new(Vec::new(), 7, 10, 4, config).unwrap();
        for slot in 10..14 {
            writer.write_skipped_slot(slot).unwrap();
        }
        writer.finish().unwrap().0
    }

    #[test]
    fn virtual_footer_opens_a_complete_prefix_without_changing_original_bytes() {
        let bytes = fixture();
        let complete = ArchiveReader::open(Cursor::new(&bytes)).unwrap();
        let second = complete.bucket_index()[1].offset as usize;
        let body = bytes[..second].to_vec();
        let mut prefix = PrefixView::open(Cursor::new(&body), 7, 10, 12).unwrap();
        let mut old = vec![0; body.len()];
        prefix.read_exact(&mut old).unwrap();
        assert_eq!(old, body);
        let mut new_footer = [0; FOOTER_LEN];
        prefix.seek(SeekFrom::End(-(FOOTER_LEN as i64))).unwrap();
        prefix.read_exact(&mut new_footer).unwrap();
        assert_eq!(Footer::from_bytes(&new_footer).unwrap().bucket_count, 1);
        let mut official = ArchiveReader::open(prefix).unwrap();
        assert_eq!(official.bucket_index()[0].first_slot, 10);
        assert!(!official.has_complete_slot_coverage().unwrap());
    }

    #[test]
    fn rejects_torn_or_extra_bytes_and_an_incorrect_requested_range() {
        let bytes = fixture();
        let complete = ArchiveReader::open(Cursor::new(&bytes)).unwrap();
        let second = complete.bucket_index()[1].offset as usize;
        for end in [second - 1, second + 1, bytes.len()] {
            assert!(PrefixView::open(Cursor::new(&bytes[..end]), 7, 10, 12).is_err());
        }
        assert!(PrefixView::open(Cursor::new(&bytes[..second]), 7, 10, 11).is_err());
        assert!(PrefixView::open(Cursor::new(&bytes[..second]), 8, 10, 12).is_err());
    }
}
