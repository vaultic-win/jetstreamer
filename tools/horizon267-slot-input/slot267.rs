//! Complete slot-index structure check. The pinned prefix includes the full directory.
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[cfg(not(any(
    epoch268, epoch269, epoch270, epoch271, epoch272, epoch273, epoch274, epoch275, epoch276,
    epoch277, epoch278, epoch279, epoch280, epoch281, epoch282, epoch283, epoch284, epoch285,
    epoch286, epoch287, epoch288, epoch289, epoch290, epoch291, epoch292, epoch293, epoch294,
    epoch295, epoch296, epoch297, epoch298, epoch299, epoch300, epoch301
)))]
mod profile {
    pub(super) const EPOCH: u64 = 267;
    pub(super) const PREFIX: &[u8; 4096] = include_bytes!("267-slot-to-cid.bin");
    pub(super) const SIZE: usize = 15_166_712;
    pub(super) const EXPECTED: usize = 388_871;
    pub(super) const HEADER: usize = 119;
    pub(super) const BUCKETS: usize = 39;
}
#[cfg(epoch268)]
mod profile {
    pub(super) const EPOCH: u64 = 268;
    pub(super) const PREFIX: &[u8; 4096] = include_bytes!("268-slot-to-cid.bin");
    pub(super) const SIZE: usize = 16_006_150;
    pub(super) const EXPECTED: usize = 410_393;
    pub(super) const HEADER: usize = 119;
    pub(super) const BUCKETS: usize = 44;
}
#[cfg(epoch269)]
mod profile {
    pub(super) const EPOCH: u64 = 269;
    pub(super) const PREFIX: &[u8; 4096] = include_bytes!("269-slot-to-cid.bin");
    pub(super) const SIZE: usize = 16013365;
    pub(super) const EXPECTED: usize = 410578;
    pub(super) const HEADER: usize = 119;
    pub(super) const BUCKETS: usize = 44;
}
#[cfg(epoch270)]
mod profile {
    pub(super) const EPOCH: u64 = 270;
    pub(super) const PREFIX: &[u8; 4096] = include_bytes!("270-slot-to-cid.bin");
    pub(super) const SIZE: usize = 15728656;
    pub(super) const EXPECTED: usize = 403279;
    pub(super) const HEADER: usize = 119;
    pub(super) const BUCKETS: usize = 41;
}
#[cfg(any(
    epoch271, epoch272, epoch273, epoch274, epoch275, epoch276, epoch277, epoch278, epoch279,
    epoch280, epoch281, epoch282, epoch283, epoch284, epoch285, epoch286, epoch287, epoch288,
    epoch289, epoch290, epoch291, epoch292, epoch293, epoch294, epoch295, epoch296, epoch297,
    epoch298, epoch299, epoch300, epoch301
))]
pub mod compact_profiles;
#[cfg(any(
    epoch271, epoch272, epoch273, epoch274, epoch275, epoch276, epoch277, epoch278, epoch279,
    epoch280, epoch281, epoch282, epoch283, epoch284, epoch285, epoch286, epoch287, epoch288,
    epoch289, epoch290, epoch291, epoch292, epoch293, epoch294, epoch295, epoch296, epoch297,
    epoch298, epoch299, epoch300, epoch301
))]
mod profile {
    pub(super) use super::compact_profiles::{
        EPOCH, SLOT_BUCKETS as BUCKETS, SLOT_BYTES as SIZE, SLOT_ENTRIES as EXPECTED,
        SLOT_PREFIX as PREFIX,
    };
    pub(super) const HEADER: usize = 119;
}
#[cfg(any(
    all(epoch268, epoch269),
    all(epoch268, epoch270),
    all(epoch269, epoch270)
))]
compile_error!("choose a single epoch");
use profile::*;

fn check(condition: bool, reason: &'static str) -> Result<(), &'static str> {
    if condition { Ok(()) } else { Err(reason) }
}
fn little(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .enumerate()
        .fold(0, |acc, (n, b)| acc | (u64::from(*b) << (8 * n)))
}
// The production reader treats each bucket as a zero-based binary search tree.
fn tree(
    rows: &[u8],
    stride: usize,
    hash_width: usize,
    i: usize,
    low: Option<u64>,
    high: Option<u64>,
) -> Result<(), &'static str> {
    if i >= rows.len() / stride {
        return Ok(());
    }
    let p = i * stride;
    let hash = little(&rows[p..p + hash_width]);
    check(
        low.is_none_or(|v| v < hash) && high.is_none_or(|v| hash < v),
        "bucket search ordering",
    )?;
    check(
        rows[p + hash_width..p + hash_width + 4] == [1, 0x71, 0x12, 0x20],
        "CID type",
    )?;
    tree(rows, stride, hash_width, 2 * i + 1, low, Some(hash))?;
    tree(rows, stride, hash_width, 2 * i + 2, Some(hash), high)
}
fn inspect(data: &[u8]) -> Result<usize, &'static str> {
    check(
        data.len() == SIZE && data.starts_with(PREFIX),
        "size or pinned prefix",
    )?;
    let table_end = HEADER + 16 * BUCKETS;
    let mut intervals = Vec::with_capacity(BUCKETS);
    for d in data[HEADER..table_end].chunks_exact(16) {
        let n = little(&d[4..8]) as usize;
        let hash_width = d[8] as usize;
        check(
            n > 0 && (1..=8).contains(&hash_width) && d[9] == 0,
            "bucket dimensions",
        )?;
        let start = little(&d[10..]) as usize;
        let stride = hash_width + 36;
        let end = start
            .checked_add(n.checked_mul(stride).ok_or("bucket span")?)
            .ok_or("bucket offset")?;
        check(start >= table_end && end <= SIZE, "bucket outside payload")?;
        intervals.push((start, end, n, hash_width));
    }
    intervals.sort_unstable();
    let mut cursor = table_end;
    let mut count = 0;
    for (start, end, n, hash_width) in intervals {
        check(start == cursor, "gap or overlap")?;
        tree(
            &data[start..end],
            hash_width + 36,
            hash_width,
            0,
            None,
            None,
        )?;
        count += n;
        cursor = end;
    }
    check(
        count == EXPECTED && cursor == SIZE,
        "incomplete directory coverage",
    )?;
    Ok(count)
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.size(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn verify(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let named = fs::symlink_metadata(path)?;
    check(
        named.is_file()
            && named.nlink() == 1
            && named.len() == SIZE as u64
            && named.mode() & 0o222 == 0,
        "body must be closed read-only regular file",
    )?;
    let mut f: File = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000)
        .open(path)?; // Linux O_NOFOLLOW
    let id = identity(&named);
    check(identity(&f.metadata()?) == id, "body replaced before open")?;
    let mut data = Vec::with_capacity(SIZE + 1);
    (&mut f).take(SIZE as u64 + 1).read_to_end(&mut data)?;
    let entries = inspect(&data)?;
    check(
        identity(&f.metadata()?) == id && identity(&fs::symlink_metadata(path)?) == id,
        "body changed",
    )?;
    println!(
        "{{\"epoch\":{EPOCH},\"kind\":\"slot-to-cid\",\"bytes\":{SIZE},\"entries\":{entries},\"buckets\":{BUCKETS},\"all_cid_types_checked\":true,\"all_search_trees_checked\":true,\"car_lookups_verified\":false,\"admission_authorized\":false}}"
    );
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let p = args
        .next()
        .ok_or("expected a path to the complete, closed slot index")?;
    check(args.next().is_none(), "unexpected argument")?;
    verify(Path::new(&p))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(h: u8) -> Vec<u8> {
        let mut r = vec![0; 37];
        r[..5].copy_from_slice(&[h, 1, 0x71, 0x12, 0x20]);
        r
    }
    #[test]
    fn ordering_checks_ancestors_and_values() {
        let clean = [row(5), row(3), row(9), row(1), row(4)].concat();
        assert!(tree(&clean, 37, 1, 0, None, None).is_ok());
        for (i, b) in [(4 * 37, 6), (37, 5), (2 * 37 + 1, 9)] {
            let mut bad = clean.clone();
            bad[i] = b;
            assert!(tree(&bad, 37, 1, 0, None, None).is_err());
        }
    }
    #[test]
    fn pinned_directory_represents_the_exact_size_and_population() {
        let table = &PREFIX[HEADER..HEADER + 16 * BUCKETS];
        let mut edge = HEADER + 16 * BUCKETS;
        let mut count = 0;
        for d in table.chunks_exact(16) {
            assert_eq!(little(&d[10..]) as usize, edge);
            let n = little(&d[4..8]) as usize;
            edge += n * (usize::from(d[8]) + 36);
            count += n;
        }
        assert_eq!((count, edge), (EXPECTED, SIZE));
        assert!(inspect(PREFIX).is_err());
    }
}
