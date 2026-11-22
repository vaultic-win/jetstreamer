//! Bounded streaming verification of the CID-to-offset-and-size compact index for registered Horizon epochs.
use std::fs::OpenOptions;
use std::io::{self, BufReader, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[cfg(not(any(
    epoch268, epoch269, epoch270, epoch271, epoch272, epoch273, epoch274, epoch275, epoch276,
    epoch277, epoch278, epoch279, epoch280, epoch281, epoch282, epoch283, epoch284, epoch285,
    epoch286, epoch287, epoch288, epoch289, epoch290, epoch291, epoch292, epoch293, epoch294,
    epoch295, epoch296, epoch297, epoch298, epoch299, epoch300, epoch301
)))]
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
#[cfg(epoch269)]
mod profile {
    pub(super) const SIZE: u64 = 12000956422;
    pub(super) const CAR_SIZE: u64 = 472271953708;
    pub(super) const BUCKETS: usize = 300000;
    pub(super) const HEADER: usize = 130;
    pub(super) const PREFIX: &[u8; 4096] = include_bytes!("269-cid-prefix.bin");
}
#[cfg(epoch270)]
mod profile {
    pub(super) const SIZE: u64 = 11233794466;
    pub(super) const CAR_SIZE: u64 = 450199158585;
    pub(super) const BUCKETS: usize = 93603;
    pub(super) const HEADER: usize = 130;
    pub(super) const PREFIX: &[u8; 4096] = include_bytes!("270-cid-prefix.bin");
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
        CAR as CAR_SIZE, CID_BUCKETS as BUCKETS, CID_BYTES as SIZE, CID_PREFIX as PREFIX,
    };
    pub(super) const HEADER: usize = 130;
}
#[cfg(any(
    all(epoch268, epoch269),
    all(epoch268, epoch270),
    all(epoch269, epoch270)
))]
compile_error!("choose a single epoch");
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

fn inspect(input: impl Read) -> io::Result<u64> {
    let mut r = BufReader::with_capacity(1 << 20, input);
    let mut prefix = [0; 4096];
    r.read_exact(&mut prefix)?;
    require(&prefix == PREFIX, "registered source header")?;
    // The registered prefix overlaps the bucket directory. Reuse its bytes so
    // the same validation works on a file and on a bounded HTTP body.
    let mut r = prefix[HEADER..].chain(r);
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
    #[cfg(not(any(
        epoch269, epoch270, epoch271, epoch272, epoch273, epoch274, epoch275, epoch276, epoch277,
        epoch278, epoch279, epoch280, epoch281, epoch282, epoch283, epoch284, epoch285, epoch286,
        epoch287, epoch288, epoch289, epoch290, epoch291, epoch292, epoch293, epoch294, epoch295,
        epoch296, epoch297, epoch298, epoch299, epoch300, epoch301
    )))]
    let p = {
        require(std::env::args_os().len() == 1, "unexpected arguments")?;
        Path::new(SOURCE)
    };
    #[cfg(any(
        epoch269, epoch270, epoch271, epoch272, epoch273, epoch274, epoch275, epoch276, epoch277,
        epoch278, epoch279, epoch280, epoch281, epoch282, epoch283, epoch284, epoch285, epoch286,
        epoch287, epoch288, epoch289, epoch290, epoch291, epoch292, epoch293, epoch294, epoch295,
        epoch296, epoch297, epoch298, epoch299, epoch300, epoch301
    ))]
    let path = {
        let mut args = std::env::args_os().skip(1);
        let p = args
            .next()
            .ok_or(io::Error::other("expected qualified CID body"))?;
        require(args.next().is_none(), "unexpected arguments")?;
        p
    };
    #[cfg(any(
        epoch269, epoch270, epoch271, epoch272, epoch273, epoch274, epoch275, epoch276, epoch277,
        epoch278, epoch279, epoch280, epoch281, epoch282, epoch283, epoch284, epoch285, epoch286,
        epoch287, epoch288, epoch289, epoch290, epoch291, epoch292, epoch293, epoch294, epoch295,
        epoch296, epoch297, epoch298, epoch299, epoch300, epoch301
    ))]
    let p = {
        if path == "--cid-stdin" {
            report(inspect(io::stdin().lock())?);
            return Ok(());
        }
        Path::new(&path)
    };
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
    report(rows);
    Ok(())
}

fn report(rows: u64) {
    println!(
        "{{\"entries\":{rows},\"buckets\":{BUCKETS},\"bytes\":{SIZE},\"car_bytes\":{CAR_SIZE},\"all_tree_keys_checked\":true,\"all_car_bounds_checked\":true}}"
    );
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
