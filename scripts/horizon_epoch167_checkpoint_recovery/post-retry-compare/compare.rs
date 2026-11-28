//! Independently compare the retained and retry epoch 167 window in each archive's raw coordinates.
use std::{
    fs::{File, OpenOptions},
    io::SeekFrom,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

include!(concat!(env!("HORIZON_167_GENERATED"), "/normalized.rs"));

mod retained {
    include!(concat!(env!("HORIZON_167_GENERATED"), "/retained.rs"));
}

const SOURCE_PATH: &str = concat!(
    "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/",
    "replacement-source-index-v1-20261121/cold-source-index-v3-20261122/private/",
    "destination-e677f81687d92afb1ef9d81f2d57842d0c8bd0d94c6353aa87a7ddc53eb10d0f/",
    "work/root-cohort-167-167/run-660590-1795377153608080439/archives/epoch-167.jet"
);
const RETRY_PATH: &str = concat!(
    "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/",
    "checkpoint-inputs-20261127-v1/bounded-72509256-72515090-v2/output/",
    "epoch-167-checkpoint-bounded.jet"
);
const SOURCE_ARCHIVE_SHA: &str = "430561d1a97572e727e62e7c8d8991cac5adcfcd33f00e203525e1a7735ebea9";
const SEAM: u64 = 72_509_256;
const OVERLAP_END: u64 = 72_512_768;
const RETRY_END: u64 = 72_515_091;
const ANCHOR: &str = "1BK4wPkM1ZGbKrVAFdCzyXYWaB8bhPK7vBcfZqN8U1G";
const SOURCE_START: u64 = 52_685_674_983;
const SOURCE_END: u64 = 52_690_685_155;
const RETRY_START: u64 = 52_892_210_899;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

fn identity(file: &File, length: u64) -> io::Result<Identity> {
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.len() != length {
        return Err(invalid("retry is not the exact closed single-link archive"));
    }
    Ok(Identity {
        device: m.dev(),
        inode: m.ino(),
        length: m.len(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}

fn open_retry(path: &Path) -> io::Result<File> {
    if path.canonicalize()? != path {
        return Err(invalid("retry archive path is indirect"));
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

fn check_cursors(source: &Overlap, retry: &Overlap) -> io::Result<u64> {
    let expected_end = RETRY_START
        .checked_add(SOURCE_END - SOURCE_START)
        .ok_or_else(|| invalid("retry overlap cursor overflow"))?;
    if (source.versions.first_raw, source.versions.next_raw)
        != (Some(SOURCE_START), Some(SOURCE_END))
        || (retry.versions.first_raw, retry.versions.next_raw)
            != (Some(RETRY_START), Some(expected_end))
    {
        return Err(invalid(
            "decoded raw cursors do not match the independently recorded restart cursors",
        ));
    }
    Ok(RETRY_START - SOURCE_START)
}

fn run(length: u64, expected_sha: &str) -> Result<(), Failure> {
    let path = Path::new(RETRY_PATH);
    let mut file = open_retry(path)?;
    let retry_identity = identity(&file, length)?;
    let mut sha = Sha256::new();
    io::copy(&mut file, &mut sha)?;
    if hex(&sha.finalize()) != expected_sha {
        return Err(invalid("bounded retry archive differs from its terminal SHA-256").into());
    }
    file.seek(SeekFrom::Start(0))?;
    {
        let mut archive = ArchiveReader::open(&mut file)?;
        let header = archive.header();
        if header.epoch != 167
            || header.slot_start != SEAM + 1
            || header.slot_count != RETRY_END - SEAM - 1
            || !archive.has_complete_slot_coverage()?
        {
            return Err(
                invalid("bounded retry does not exactly cover its admitted checkpoints").into(),
            );
        }
    }
    file.seek(SeekFrom::Start(0))?;
    let source = retained::read(Path::new(SOURCE_PATH))?;
    eprintln!(
        "epoch 167 retained overlap decoded through slot {}",
        OVERLAP_END - 1
    );
    let retry = read_range(
        &mut file,
        SEAM + 1..OVERLAP_END,
        ANCHOR,
        Some(SEAM + 1..RETRY_END),
    )?;
    let delta = check_cursors(&source, &retry)?;
    if identity(&file, length)? != retry_identity
        || identity(&open_retry(path)?, length)? != retry_identity
    {
        return Err(invalid("bounded retry archive changed during comparison").into());
    }
    compare("epoch167_bounded_retry_overlap", &source, &retry)?;
    println!(
        "comparison_complete epoch=167 seam={SEAM} raw_cursor_delta={delta} source_archive_sha256={SOURCE_ARCHIVE_SHA} retry_archive_sha256={expected_sha}"
    );
    Ok(())
}

fn main() -> Result<(), Failure> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [length, digest] = args.as_slice() else {
        return Err("usage: horizon-167-bounded-overlap RETRY_BYTES RETRY_SHA256".into());
    };
    let bytes = length.parse::<u64>()?;
    if bytes == 0
        || bytes.to_string() != *length
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("supply the exact closed retry byte length and SHA-256").into());
    }
    run(bytes, digest)
}

#[test]
fn preserves_both_absolute_cursors_and_their_delta() {
    let mut source = Overlap::new(SEAM + 1..OVERLAP_END, ANCHOR, None);
    source.versions.first_raw = Some(SOURCE_START);
    source.versions.next_raw = Some(SOURCE_END);
    let mut retry = Overlap::new(SEAM + 1..OVERLAP_END, ANCHOR, None);
    retry.versions.first_raw = Some(RETRY_START);
    retry.versions.next_raw = Some(52_897_221_071);
    assert_eq!(check_cursors(&source, &retry).unwrap(), 206_535_916);
    retry.versions.next_raw = Some(52_897_221_070);
    assert!(check_cursors(&source, &retry).is_err());
}
