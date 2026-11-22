//! Bounded streaming verification of the CID-to-offset-and-size compact index for epochs 267 and 268.
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[cfg(not(epoch268))]
mod profile {
    pub(super) const SIZE: u64 = 10_392_794_246;
    pub(super) const CAR_SIZE: u64 = 428_826_209_761;
    pub(super) const BUCKETS: usize = 86_596;
    pub(super) const HEADER: usize = 130;
    pub(super) const SOURCE: &str = "/var/lib/jetstreamer/horizon267-cid-input-v173-a1/index.body";
    pub(super) const PREFIX: &[u8; 4096] = include_bytes!("267-cid-prefix.bin");
}
#[cfg(epoch268)]
mod profile {
    pub(super) const SIZE: u64 = 12_161_495_866;
    pub(super) const CAR_SIZE: u64 = 476_675_176_389;
    pub(super) const BUCKETS: usize = 300_000;
    pub(super) const HEADER: usize = 130;
    pub(super) const SOURCE: &str = "/var/lib/jetstreamer/horizon268-cid-input-v175-a1/index.body";
    pub(super) const PREFIX: &[u8; 4096] = include_bytes!("268-cid-prefix.bin");
}
use profile::*;

fn require(v: bool, why: &str) -> io::Result<()> {
    if v {
        Ok(())
    } else {
        Err(io::Error::other(why))
    }
}

fn little(b: &[u8]) -> u64 {
    let mut word = [0; 8];
    word[..b.len()].copy_from_slice(b);
    u64::from_le_bytes(word)
}

fn tree(
    rows: &[u8],
    width: usize,
    i: usize,
    low: Option<u64>,
    high: Option<u64>,
) -> io::Result<()> {
    let stride = width + 9;
    if i >= rows.len() / stride {
        return Ok(());
    }
    let p = i * stride;
    let hash = little(&rows[p..p + width]);
    require(
        low.is_none_or(|v| hash > v) && high.is_none_or(|v| hash < v),
        "search tree ordering",
    )?;
    let value = p + width;
    let offset = little(&rows[value..value + 6]);
    let length = little(&rows[value + 6..value + 9]);
    require(
        offset >= 59 && length >= 38 && offset + length <= CAR_SIZE,
        "CAR section bounds",
    )?;
    tree(rows, width, i * 2 + 1, low, Some(hash))?;
    tree(rows, width, i * 2 + 2, Some(hash), high)
}

fn inspect(file: File) -> io::Result<u64> {
    let mut r = BufReader::with_capacity(1 << 20, file);
    let mut prefix = [0; 4096];
    r.read_exact(&mut prefix)?;
    require(&prefix == PREFIX, "registered source header")?;
    r.seek(std::io::SeekFrom::Start(HEADER as u64))?;
    let mut directory = vec![0; 16 * BUCKETS];
    r.read_exact(&mut directory)?;
    let mut pos = (HEADER + directory.len()) as u64;
    let mut total = 0;
    let mut rows = Vec::new();
    for d in directory.chunks_exact(16) {
        let count = little(&d[4..8]);
        let width = d[8] as usize;
        require(
            count > 0 && (1..=8).contains(&width) && d[9] == 0 && little(&d[10..]) == pos,
            "bucket descriptor",
        )?;
        let n = count * (width as u64 + 9);
        require(n <= 1 << 20 && pos + n <= SIZE, "bucket length")?;
        rows.resize(n as usize, 0);
        r.read_exact(&mut rows)?;
        tree(&rows, width, 0, None, None)?;
        pos += n;
        total += count;
    }
    require(
        pos == SIZE && r.read(&mut [0u8])? == 0,
        "trailing or missing table bytes",
    )?;
    Ok(total)
}

fn run() -> io::Result<()> {
    require(std::env::args_os().len() == 1, "unexpected arguments")?;
    let p = Path::new(SOURCE);
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(0o400000)
        .open(p)?;
    let st = f.metadata()?;
    require(
        p.canonicalize()? == p
            && st.is_file()
            && st.len() == SIZE
            && st.uid() == 0
            && st.nlink() == 1
            && st.mode() & 0o777 == 0o400,
        "source custody",
    )?;
    let rows = inspect(f)?;
    let after = p.symlink_metadata()?;
    require(
        (
            st.dev(),
            st.ino(),
            st.mtime(),
            st.mtime_nsec(),
            st.ctime(),
            st.ctime_nsec(),
        ) == (
            after.dev(),
            after.ino(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ),
        "source changed",
    )?;
    println!(
        "{{\"entries\":{rows},\"buckets\":{BUCKETS},\"bytes\":{SIZE},\"car_bytes\":{CAR_SIZE},\"all_tree_keys_checked\":true,\"all_car_bounds_checked\":true}}"
    );
    Ok(())
}
fn main() -> io::Result<()> {
    run()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(key: u8, offset: u64, size: u32) -> Vec<u8> {
        let mut r = vec![key];
        r.extend(&offset.to_le_bytes()[..6]);
        r.extend(&size.to_le_bytes()[..3]);
        r
    }
    #[test]
    fn ordering_and_canonical_section_bounds() {
        let good = [
            row(8, 59, 128),
            row(4, CAR_SIZE - 38, 38),
            row(12, 999, 120),
        ]
        .concat();
        assert!(tree(&good, 1, 0, None, None).is_ok());
        for invalid in [
            row(10, 59, 100),
            row(4, 58, 100),
            row(4, 59, 37),
            row(4, CAR_SIZE - 50, 51),
        ] {
            let mut bad = good.clone();
            bad[10..20].copy_from_slice(&invalid);
            assert!(tree(&bad, 1, 0, None, None).is_err());
        }
    }
    #[test]
    fn rejects_descendant_outside_ancestor_domain() {
        let rows = [8, 4, 12, 1, 9].map(|k| row(k, 100, 60)).concat();
        assert!(tree(&rows, 1, 0, None, None).is_err());
    }
}
