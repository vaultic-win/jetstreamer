//! Compare every raw range to the block section reached through both compact indexes.
//! Group block CID lookups by bucket to stream the large index once.
use std::fs::{self, File};
use std::io::{self, BufReader, Read};

#[link(name = "libxxhash.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn XXH64(data: *const u8, len: usize, seed: u64) -> u64;
}
fn xxh64(key: &[u8]) -> u64 {
    unsafe { XXH64(key.as_ptr(), key.len(), 0) }
}
fn le(bytes: &[u8]) -> u64 {
    let mut word = [0; 8];
    word[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(word)
}
fn require(v: bool, msg: &str) -> io::Result<()> {
    if v {
        Ok(())
    } else {
        Err(io::Error::other(msg))
    }
}
fn bucket_number(key: &[u8], count: usize) -> usize {
    let n = count as u64;
    let h = xxh64(key);
    let mut u = h % n;
    if (h - u) / n < u {
        u ^= u >> 33;
        u = u.wrapping_mul(0xff51afd7ed558ccd);
        u ^= u >> 33;
        u = u.wrapping_mul(0xc4ceb9fe1a85ec53);
        u ^= u >> 33;
    }
    (u % n) as usize
}
struct Bucket<'a>(&'a [u8]);
impl Bucket<'_> {
    fn offset(&self) -> usize {
        le(&self.0[10..16]) as usize
    }
    fn count(&self) -> usize {
        le(&self.0[4..8]) as usize
    }
    fn width(&self) -> usize {
        self.0[8] as usize
    }
    fn bytes(&self, value: usize) -> io::Result<usize> {
        require(
            (1..=8).contains(&self.width()) && self.count() > 0 && self.0[9] == 0,
            "bucket shape",
        )?;
        let n = self.count() * (value + self.width());
        require(n <= 1 << 20, "bucket size")?;
        Ok(n)
    }
    fn lookup<'a>(&self, key: &[u8], rows: &'a [u8], value: usize) -> Option<&'a [u8]> {
        let mut prefix = [0; 68];
        prefix[..4].copy_from_slice(&self.0[..4]);
        prefix[32..32 + key.len()].copy_from_slice(key);
        let width = self.width();
        let hash = xxh64(&prefix[..32 + key.len()]) & (u64::MAX >> (64 - width * 8));
        let stride = width + value;
        let mut i = 0;
        while i < self.count() {
            let row = &rows[i * stride..(i + 1) * stride];
            let v = le(&row[..width]);
            if v == hash {
                return Some(&row[width..]);
            }
            i = 2 * i + 1 + usize::from(v < hash);
        }
        None
    }
}
const SLOTS: usize = 432000;
#[cfg(not(any(
    epoch268, epoch269, epoch270, epoch271, epoch272, epoch273, epoch274, epoch275, epoch276,
    epoch277, epoch278, epoch279, epoch280, epoch281, epoch282, epoch283, epoch284, epoch285,
    epoch286, epoch287, epoch288, epoch289, epoch290, epoch291, epoch292, epoch293, epoch294,
    epoch295, epoch296, epoch297, epoch298, epoch299, epoch300, epoch301
)))]
mod profile {
    pub(super) const START: u64 = 115344000;
    pub(super) const CAR: u64 = 428826209761;
    pub(super) const SLOT_BYTES: usize = 15166712;
    pub(super) const CID_BYTES: u64 = 10392794246;
    pub(super) const SLOT_BUCKETS: usize = 39;
    pub(super) const CID_BUCKETS: usize = 86596;
    pub(super) const SLOT_PREFIX: &[u8; 4096] = include_bytes!("267-slot-to-cid.bin");
    pub(super) const CID_PREFIX: &[u8; 4096] = include_bytes!("267-cid-prefix.bin");
    pub(super) const MAX_EXAMPLES: usize = 256;
}
#[cfg(epoch268)]
mod profile {
    pub(super) const START: u64 = 115776000;
    pub(super) const CAR: u64 = 476675176389;
    pub(super) const SLOT_BYTES: usize = 16006150;
    pub(super) const CID_BYTES: u64 = 12161495866;
    pub(super) const SLOT_BUCKETS: usize = 44;
    pub(super) const CID_BUCKETS: usize = 300000;
    pub(super) const SLOT_PREFIX: &[u8; 4096] = include_bytes!("268-slot-to-cid.bin");
    pub(super) const CID_PREFIX: &[u8; 4096] = include_bytes!("268-cid-prefix.bin");
    pub(super) const MAX_EXAMPLES: usize = 4096;
}
#[cfg(epoch269)]
mod profile {
    pub(super) const START: u64 = 116208000;
    pub(super) const CAR: u64 = 472271953708;
    pub(super) const SLOT_BYTES: usize = 16013365;
    pub(super) const CID_BYTES: u64 = 12000956422;
    pub(super) const SLOT_BUCKETS: usize = 44;
    pub(super) const CID_BUCKETS: usize = 300000;
    pub(super) const SLOT_PREFIX: &[u8; 4096] = include_bytes!("269-slot-to-cid.bin");
    pub(super) const CID_PREFIX: &[u8; 4096] = include_bytes!("269-cid-prefix.bin");
    pub(super) const MAX_EXAMPLES: usize = 4096;
}
#[cfg(epoch270)]
mod profile {
    pub(super) const START: u64 = 116640000;
    pub(super) const CAR: u64 = 450199158585;
    pub(super) const SLOT_BYTES: usize = 15728656;
    pub(super) const CID_BYTES: u64 = 11233794466;
    pub(super) const SLOT_BUCKETS: usize = 41;
    pub(super) const CID_BUCKETS: usize = 93603;
    pub(super) const SLOT_PREFIX: &[u8; 4096] = include_bytes!("270-slot-to-cid.bin");
    pub(super) const CID_PREFIX: &[u8; 4096] = include_bytes!("270-cid-prefix.bin");
    pub(super) const MAX_EXAMPLES: usize = 4096;
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
        CAR, CID_BUCKETS, CID_BYTES, CID_PREFIX, SLOT_BUCKETS, SLOT_BYTES, SLOT_PREFIX,
    };
    pub(super) const START: u64 = super::compact_profiles::EPOCH * super::SLOTS as u64;
    pub(super) const MAX_EXAMPLES: usize = 4096;
}
#[cfg(any(
    all(epoch268, epoch269),
    all(epoch268, epoch270),
    all(epoch269, epoch270)
))]
compile_error!("choose a single epoch");
use profile::*;
fn compatible(raw: (u64, u64), block: Option<(u64, u64)>) -> bool {
    match block {
        None => raw == (0, 0),
        Some((b, n)) => {
            raw.0 >= 59
                && raw.1 > 0
                && b >= raw.0
                && n >= 38
                && b.checked_add(n)
                    .is_some_and(|end| Some(end) == raw.0.checked_add(raw.1) && end <= CAR)
        }
    }
}
fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    require(args.len() == 3, "expected RAW SLOT_INDEX CID_INDEX")?;
    require(
        fs::metadata(&args[0])?.len() == 12 * SLOTS as u64
            && fs::metadata(&args[1])?.len() == SLOT_BYTES as u64,
        "raw/slot input length",
    )?;
    let raw = fs::read(&args[0])?;
    let slot = fs::read(&args[1])?;
    require(
        raw.len() == 12 * SLOTS && slot.len() == SLOT_BYTES,
        "input lengths",
    )?;
    require(slot.starts_with(SLOT_PREFIX), "slot header")?;
    #[cfg(any(
        epoch269, epoch270, epoch271, epoch272, epoch273, epoch274, epoch275, epoch276, epoch277,
        epoch278, epoch279, epoch280, epoch281, epoch282, epoch283, epoch284, epoch285, epoch286,
        epoch287, epoch288, epoch289, epoch290, epoch291, epoch292, epoch293, epoch294, epoch295,
        epoch296, epoch297, epoch298, epoch299, epoch300, epoch301
    ))]
    if args[2] == "--cid-stdin" {
        return compare(&raw, &slot, io::stdin().lock());
    }
    let cid = File::open(&args[2])?;
    require(cid.metadata()?.len() == CID_BYTES, "CID file length")?;
    compare(&raw, &slot, cid)
}

fn compare(raw: &[u8], slot: &[u8], cid: impl Read) -> io::Result<()> {
    let mut reader = BufReader::with_capacity(1 << 20, cid);
    let mut prefix = [0; 4096];
    reader.read_exact(&mut prefix)?;
    require(&prefix == CID_PREFIX, "CID header")?;
    let mut reader = prefix[130..].chain(reader);
    let mut directory = vec![0; CID_BUCKETS * 16];
    reader.read_exact(&mut directory)?;
    let mut requests = vec![Vec::<(usize, [u8; 36])>::new(); CID_BUCKETS];
    let mut slot_hits = vec![false; SLOTS];
    for (i, hit) in slot_hits.iter_mut().enumerate() {
        let key = (START + i as u64).to_le_bytes();
        let d = 119 + 16 * bucket_number(&key, SLOT_BUCKETS);
        let b = Bucket(&slot[d..d + 16]);
        let start = b.offset();
        let size = b.bytes(36)?;
        let rows = slot
            .get(start..start + size)
            .ok_or_else(|| io::Error::other("slot bucket extent"))?;
        if let Some(cid) = b.lookup(&key, rows, 36) {
            let block: [u8; 36] = cid.try_into().unwrap();
            require(block[..4] == [1, 113, 18, 32], "block CID")?;
            requests[bucket_number(&block, CID_BUCKETS)].push((i, block));
            *hit = true;
        }
    }
    let mut sections = vec![None; SLOTS];
    let mut rows = Vec::new();
    let mut end = 130 + directory.len();
    for (d, queries) in directory.chunks_exact(16).zip(requests) {
        let b = Bucket(d);
        require(b.offset() == end, "CID bucket position")?;
        rows.resize(b.bytes(9)?, 0);
        reader.read_exact(&mut rows)?;
        end += rows.len();
        for (i, key) in queries {
            if let Some(v) = b.lookup(&key, &rows, 9) {
                sections[i] = Some((le(&v[..6]), le(&v[6..])))
            }
        }
    }
    require(
        end as u64 == CID_BYTES && reader.read(&mut [0])? == 0,
        "incorrect CID stream length",
    )?;
    let mut differences = 0;
    let mut present = 0;
    let mut missing_sections = 0;
    let mut overlaps = 0;
    let mut examples = Vec::new();
    let mut previous_end = 59;
    for (i, v) in raw.chunks_exact(12).enumerate() {
        let range = (le(&v[..8]), le(&v[8..]));
        let nonempty = range.1 != 0;
        let overlap = nonempty && range.0 < previous_end;
        if nonempty {
            present += 1;
            previous_end = range
                .0
                .checked_add(range.1)
                .ok_or_else(|| io::Error::other("raw range overflows"))?;
        }
        if overlap {
            overlaps += 1;
        }
        if slot_hits[i] && sections[i].is_none() {
            missing_sections += 1;
        }
        if overlap || slot_hits[i] != nonempty || !compatible(range, sections[i]) {
            differences += 1;
            if examples.len() < MAX_EXAMPLES {
                let (b, n) = sections[i].unwrap_or((0, 0));
                examples.push(format!(
                    "[{},{},{},{},{},{},{}]",
                    START + i as u64,
                    range.0,
                    range.1,
                    slot_hits[i],
                    b,
                    n,
                    overlap
                ));
            }
        }
    }
    let matches = slot_hits.iter().filter(|v| **v).count();
    println!(
        "{{\"slots\":{SLOTS},\"raw_present\":{present},\"compact_slot_hits\":{matches},\"missing_block_sections\":{missing_sections},\"raw_overlaps\":{overlaps},\"disagreements\":{differences},\"examples\":[{}]}}",
        examples.join(",")
    );
    Ok(())
}
fn main() -> io::Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(any(
        epoch268, epoch269, epoch270, epoch271, epoch272, epoch273, epoch274, epoch275, epoch276,
        epoch277, epoch278, epoch279, epoch280, epoch281, epoch282, epoch283, epoch284, epoch285,
        epoch286, epoch287, epoch288, epoch289, epoch290, epoch291, epoch292, epoch293, epoch294,
        epoch295, epoch296, epoch297, epoch298, epoch299, epoch300, epoch301
    )))]
    #[test]
    fn registration_matches_real_slot_and_cid_buckets() {
        let mut cid = [0; 36];
        for (i, b) in "01711220dc0082984ff37d01d494977e2d7fd1e4f65802c8c1d0741e32ae998d1e9b6d4a"
            .as_bytes()
            .chunks_exact(2)
            .enumerate()
        {
            cid[i] = u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap();
        }
        assert_eq!(bucket_number(&START.to_le_bytes(), 39), 10);
        assert_eq!(bucket_number(&cid, 86596), 42756);
    }
    #[cfg(any(
        epoch271, epoch272, epoch273, epoch274, epoch275, epoch276, epoch277, epoch278, epoch279,
        epoch280, epoch281, epoch282, epoch283, epoch284, epoch285, epoch286, epoch287, epoch288,
        epoch289, epoch290, epoch291, epoch292, epoch293, epoch294, epoch295, epoch296, epoch297,
        epoch298, epoch299, epoch300, epoch301
    ))]
    #[test]
    fn both_directories_start_at_the_registered_payload_offsets() {
        assert_eq!(le(&SLOT_PREFIX[129..135]), 119 + 16 * SLOT_BUCKETS as u64);
        assert_eq!(le(&CID_PREFIX[140..146]), 130 + 16 * CID_BUCKETS as u64);
        assert_eq!(le(&SLOT_PREFIX[..8]), le(&CID_PREFIX[..8]));
    }
    #[cfg(epoch269)]
    #[test]
    fn registered_269_geometry_and_hashes() {
        assert_eq!((START, START + SLOTS as u64 - 1), (116208000, 116639999));
        assert_eq!(bucket_number(&START.to_le_bytes(), SLOT_BUCKETS), 32);
        assert_eq!(bucket_number(&SLOT_PREFIX[826..862], CID_BUCKETS), 206988);
        assert_eq!(le(&CID_PREFIX[140..146]), 130 + 16 * CID_BUCKETS as u64);
        assert!(!compatible((u64::MAX, 2), Some((u64::MAX, 40))));
    }
    #[cfg(epoch270)]
    #[test]
    fn registered_270_geometry_and_hashes() {
        assert_eq!((START, START + SLOTS as u64 - 1), (116640000, 117071999));
        assert_eq!(bucket_number(&START.to_le_bytes(), SLOT_BUCKETS), 0);
        assert_eq!(bucket_number(&SLOT_PREFIX[778..814], CID_BUCKETS), 19078);
        assert_eq!(le(&CID_PREFIX[140..146]), 130 + 16 * CID_BUCKETS as u64);
        assert!(!compatible((u64::MAX, 2), Some((u64::MAX, 40))));
    }
    #[cfg(epoch268)]
    #[test]
    fn registered_268_geometry_and_hashes() {
        assert_eq!((START, START + SLOTS as u64 - 1), (115776000, 116207999));
        assert_eq!(bucket_number(&START.to_le_bytes(), SLOT_BUCKETS), 5);
        let cid = [
            1, 113, 18, 32, 3, 140, 168, 225, 41, 124, 182, 47, 169, 105, 180, 215, 62, 9, 141, 31,
            185, 197, 231, 139, 248, 105, 216, 73, 128, 198, 251, 6, 164, 141, 83, 53,
        ];
        assert_eq!(bucket_number(&cid, CID_BUCKETS), 270738);
        assert_eq!(
            le(&SLOT_PREFIX[119 + 10..119 + 16]),
            119 + 16 * SLOT_BUCKETS as u64
        );
        assert_eq!(
            le(&CID_PREFIX[130 + 10..130 + 16]),
            130 + 16 * CID_BUCKETS as u64
        );
        assert!(!compatible((u64::MAX, 2), Some((u64::MAX, 40))));
    }
    #[test]
    fn first_block_and_empty_and_wrong_ranges() {
        assert!(compatible((59, 18661324), Some((18658421, 2962))));
        assert!(compatible((0, 0), None));
        assert!(!compatible((59, 18661325), Some((18658421, 2962))));
        assert!(!compatible((99, 0), None));
        assert!(!compatible((59, CAR), Some((CAR, 59))));
    }
}
