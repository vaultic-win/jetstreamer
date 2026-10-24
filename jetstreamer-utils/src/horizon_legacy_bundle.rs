//! Private qualification input, never a promoted runtime or publication route.
//! The separately hash-bound index must come from the complete acquired 141census
//! and its verified PoH receipts. A bundle does not establish source equivalence:
//! compare each whole slot with independent source transactions before execution.

use {
    crate::horizon_legacy_poh::PohExpectation,
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    },
};

/// Exact completed original-shred acquisition used by this qualification profile.
pub const ACQUISITION_SHA256: &str =
    "0335b1131663c0f8df77b3cddb5f79e49af2956067ebc46af74b9a08adafb949";
/// Complete 18283-target PoH diagnostic; no failures or missing boundaries.
pub const POH_COMPLETION_SHA256: &str =
    "12cb942626d34662080dfc981dd0588b8baef39ee31e5fb35bd8fd1593e5cd4f";
/// Independent finalized gap census, including pre-epoch warmup targets.
pub const GAP_CENSUS_SHA256: &str =
    "11a6049bc9378b4e3e063e765ce2b908b621f5d7845a49d372aca509d6d37a9f";
/// Maximum concatenated input length; independent of index and per-slot bounds.
pub const MAX_DATA_BYTES: u64 = 32 << 30;
const MAX_INDEX_BYTES: u64 = 16 << 20;
const MAX_SLOT_BYTES: u64 = 64 << 20;

/// One contiguous record: LEu32 batch count, then LEu32 length + bytes per batch.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalSlotIndex {
    /// Visible post-gap block slot.
    pub slot: u64,
    /// Independently finalized parent before the skipped run.
    pub parent_slot: u64,
    /// Finalized parent's PoH hash, lowercase hex.
    pub parent_hash_hex: String,
    /// Finalized visible block's last PoH hash, lowercase hex.
    pub final_hash_hex: String,
    /// Byte offset in the concatenated data member.
    pub offset: u64,
    /// Exact framed-record length, including count and length words.
    pub length: u64,
    /// Whole-record SHA-256, lowercase hex.
    pub sha256: String,
    /// Original padded batch count in complete SlotMeta endpoint order.
    pub batch_count: u32,
}

/// Complete fixed-census index, separately authenticated before parsing.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalBundleIndex {
    /// Must be jetstreamer-epoch141-original-entry-bundle-v1.
    pub schema: String,
    /// Exact complete acquisition digest, not a provisional target digest.
    pub acquisition_sha256: String,
    /// Exact complete successful PoH diagnostic digest.
    pub poh_completion_sha256: String,
    /// Exact independent finalized gap-census digest.
    pub gap_census_sha256: String,
    /// Complete qualifying source interval's first slot.
    pub scope_first_slot: u64,
    /// Complete qualifying source interval's final slot.
    pub scope_last_slot: u64,
    /// Typed/native independently authenticated ticks per slot.
    pub ticks_per_slot: u64,
    /// Typed/native independently authenticated hashes per tick.
    pub hashes_per_tick: u64,
    /// Exact data member length.
    pub data_bytes: u64,
    /// Exact data member SHA-256.
    pub data_sha256: String,
    /// Complete sorted target census, not merely targets currently requested.
    pub slots: Vec<OriginalSlotIndex>,
}

fn is_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode_hash(s: &str) -> Result<[u8; 32], String> {
    if !is_sha(s) {
        return Err("invalid lowercase hash".into());
    }
    let mut hash = [0; 32];
    for (byte, pair) in hash.iter_mut().zip(s.as_bytes().as_chunks::<2>().0) {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(hash)
}

fn validate_records(
    index: &OriginalBundleIndex,
    count: usize,
    expected_boundaries: u64,
) -> Result<(), String> {
    if index.slots.len() != count
        || index.data_bytes == 0
        || index.data_bytes > MAX_DATA_BYTES
        || !is_sha(&index.data_sha256)
    {
        return Err("bundle complete count/data bound differs".into());
    }
    let mut offset = 0u64;
    let mut previous_slot = None;
    let mut boundaries = 0u64;
    for slot in &index.slots {
        let span = slot
            .slot
            .checked_sub(slot.parent_slot)
            .filter(|n| (2..=64).contains(n))
            .ok_or("invalid original post-gap parent")?;
        if slot.parent_slot < index.scope_first_slot
            || slot.slot > index.scope_last_slot
            || previous_slot
                .is_some_and(|previous| slot.parent_slot < previous || slot.slot <= previous)
            || slot.offset != offset
            || slot.length == 0
            || slot.length > MAX_SLOT_BYTES
            || !is_sha(&slot.sha256)
            || slot.batch_count == 0
            || slot.batch_count > 65_536
        {
            return Err("original slot scope/order/offset/bound differs".into());
        }
        decode_hash(&slot.parent_hash_hex)?;
        decode_hash(&slot.final_hash_hex)?;
        if slot.length < 4 + u64::from(slot.batch_count) * 12 {
            return Err("original record cannot contain its declared batches".into());
        }
        offset = offset
            .checked_add(slot.length)
            .filter(|n| *n <= index.data_bytes)
            .ok_or("original data offset overflow")?;
        boundaries = boundaries
            .checked_add(span)
            .ok_or("boundary count overflow")?;
        previous_slot = Some(slot.slot);
    }
    if offset != index.data_bytes || boundaries != expected_boundaries {
        return Err("incomplete original bundle coverage".into());
    }
    Ok(())
}

impl OriginalBundleIndex {
    /// Validate the exact complete 141profile, bounds and contiguous byte coverage.
    /// A caller still must authenticate this index's independently supplied SHA.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "jetstreamer-epoch141-original-entry-bundle-v1"
            || self.acquisition_sha256 != ACQUISITION_SHA256
            || self.poh_completion_sha256 != POH_COMPLETION_SHA256
            || self.gap_census_sha256 != GAP_CENSUS_SHA256
            || self.scope_first_slot != 60_911_751
            || self.scope_last_slot != 61_328_765
            || self.ticks_per_slot != 64
            || self.hashes_per_tick != 12_500
        {
            return Err("original bundle is not the complete pinned 141profile".into());
        }
        validate_records(self, 18_283, 84_597)
    }
}

type Identity = (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64);
fn identity(m: &fs::Metadata) -> Identity {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn io(e: std::io::Error) -> String {
    e.to_string()
}
fn open_immutable(path: &Path, maximum: u64) -> Result<(File, Identity), String> {
    if !path.is_absolute() || path.canonicalize().map_err(io)? != path {
        return Err("noncanonical bundle member".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(io)?;
    let m = file.metadata().map_err(io)?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o222 != 0
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > maximum
    {
        return Err("unsafe immutable bundle member".into());
    }
    let id = identity(&m);
    if identity(&fs::symlink_metadata(path).map_err(io)?) != id {
        return Err("bundle member changed at open".into());
    }
    Ok((file, id))
}

/// An authenticated open bundle descriptor plus its exact immutable index.
#[derive(Debug)]
pub struct OriginalEntryBundle {
    data: File,
    path: PathBuf,
    identity: Identity,
    index: OriginalBundleIndex,
}

/// Original batch bytes for one slot, still owing source equivalence before use.
pub struct OriginalSlot {
    /// Independently anchored scope/clock expected by the strict PoH verifier.
    pub expected: PohExpectation,
    /// Original complete padded batches; no tick or transaction is synthesized.
    pub batches: Vec<Vec<u8>>,
}

impl OriginalEntryBundle {
    /// Every independently pinned visible target, including snapshot warmup.
    pub fn targets(&self) -> impl Iterator<Item = u64> + '_ {
        self.index.slots.iter().map(|record| record.slot)
    }
    /// Inspect a target's authenticated anchors without rereading its data.
    /// This does not prove any independent source transaction equivalence.
    pub fn expectation(&self, slot: u64) -> Option<PohExpectation> {
        let index = self
            .index
            .slots
            .binary_search_by_key(&slot, |s| s.slot)
            .ok()?;
        let record = &self.index.slots[index];
        Some(PohExpectation {
            slot: record.slot,
            parent_slot: record.parent_slot,
            parent_hash: decode_hash(&record.parent_hash_hex).expect("validated index hash"),
            final_hash: decode_hash(&record.final_hash_hex).expect("validated index hash"),
            ticks_per_slot: self.index.ticks_per_slot,
            hashes_per_tick: self.index.hashes_per_tick,
        })
    }
    /// Authenticate both members, stream-hash all data, and retain the open inode.
    /// The guard runs at each 1 MiB chunk; any error returns no usable bundle.
    pub fn open(
        index_path: &Path,
        index_sha256: &str,
        data_path: &Path,
        data_sha256: &str,
        mut guard: impl FnMut() -> Result<(), String>,
    ) -> Result<Self, String> {
        if !is_sha(index_sha256) || !is_sha(data_sha256) {
            return Err("invalid supplied bundle digests".into());
        }
        guard()?;
        let (mut index_file, index_id) = open_immutable(index_path, MAX_INDEX_BYTES)?;
        let mut bytes = Vec::new();
        (&mut index_file)
            .take(MAX_INDEX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        if bytes.len() as u64 != index_id.2
            || format!("{:x}", Sha256::digest(&bytes)) != index_sha256
            || identity(&index_file.metadata().map_err(io)?) != index_id
            || identity(&fs::symlink_metadata(index_path).map_err(io)?) != index_id
        {
            return Err("bundle index digest/identity differs".into());
        }
        let index: OriginalBundleIndex =
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        index.validate()?;
        let (mut data, id) = open_immutable(data_path, MAX_DATA_BYTES)?;
        if id.2 != index.data_bytes || data_sha256 != index.data_sha256 {
            return Err("bundle data binding differs".into());
        }
        let mut hasher = Sha256::new();
        let mut chunk = vec![0; 1 << 20];
        let mut length = 0u64;
        loop {
            guard()?;
            let n = data.read(&mut chunk).map_err(io)?;
            if n == 0 {
                break;
            }
            length = length
                .checked_add(n as u64)
                .filter(|n| *n <= index.data_bytes)
                .ok_or("bundle data grew")?;
            hasher.update(&chunk[..n]);
        }
        if length != index.data_bytes || format!("{:x}", hasher.finalize()) != data_sha256 {
            return Err("whole bundle data digest differs".into());
        }
        let bundle = Self {
            data,
            path: data_path.into(),
            identity: id,
            index,
        };
        bundle.revalidate()?;
        guard()?;
        Ok(bundle)
    }

    fn revalidate(&self) -> Result<(), String> {
        if identity(&self.data.metadata().map_err(io)?) != self.identity
            || identity(&fs::symlink_metadata(&self.path).map_err(io)?) != self.identity
        {
            return Err("open bundle inode/path changed".into());
        }
        Ok(())
    }

    /// Read one exact target, rejecting changed data before returning any batches.
    /// `None` means this slot is outside the recovery census, not a skipped slot.
    pub fn read_slot(&mut self, slot: u64) -> Result<Option<OriginalSlot>, String> {
        self.revalidate()?;
        let Ok(index) = self.index.slots.binary_search_by_key(&slot, |s| s.slot) else {
            return Ok(None);
        };
        let record = &self.index.slots[index];
        self.data.seek(SeekFrom::Start(record.offset)).map_err(io)?;
        let mut bytes = vec![0; record.length as usize];
        self.data.read_exact(&mut bytes).map_err(io)?;
        if format!("{:x}", Sha256::digest(&bytes)) != record.sha256 {
            return Err("original slot data digest differs".into());
        }
        let expected = PohExpectation {
            slot: record.slot,
            parent_slot: record.parent_slot,
            parent_hash: decode_hash(&record.parent_hash_hex)?,
            final_hash: decode_hash(&record.final_hash_hex)?,
            ticks_per_slot: self.index.ticks_per_slot,
            hashes_per_tick: self.index.hashes_per_tick,
        };
        let count = u32::from_le_bytes(
            bytes
                .get(..4)
                .ok_or("missing record count")?
                .try_into()
                .map_err(|_| "invalid count word")?,
        );
        if count != record.batch_count {
            return Err("record/index batch count differs".into());
        }
        let mut offset = 4usize;
        let mut batches = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let word_end = offset.checked_add(4).ok_or("length word overflow")?;
            let length = u32::from_le_bytes(
                bytes
                    .get(offset..word_end)
                    .ok_or("missing batch length")?
                    .try_into()
                    .map_err(|_| "invalid length word")?,
            );
            if length < 8 {
                return Err("original batch is too short".into());
            }
            offset = word_end;
            let end = offset
                .checked_add(length as usize)
                .ok_or("batch offset overflow")?;
            batches.push(
                bytes
                    .get(offset..end)
                    .ok_or("batch exceeds slot record")?
                    .to_vec(),
            );
            offset = end;
        }
        if offset != bytes.len() {
            return Err("slot record not fully consumed".into());
        }
        self.revalidate()?;
        Ok(Some(OriginalSlot { expected, batches }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> OriginalBundleIndex {
        OriginalBundleIndex {
            schema: "jetstreamer-epoch141-original-entry-bundle-v1".into(),
            acquisition_sha256: ACQUISITION_SHA256.into(),
            poh_completion_sha256: POH_COMPLETION_SHA256.into(),
            gap_census_sha256: GAP_CENSUS_SHA256.into(),
            scope_first_slot: 100,
            scope_last_slot: 110,
            ticks_per_slot: 64,
            hashes_per_tick: 12500,
            data_bytes: 52,
            data_sha256: "a".repeat(64),
            slots: vec![
                OriginalSlotIndex {
                    slot: 103,
                    parent_slot: 100,
                    parent_hash_hex: "0".repeat(64),
                    final_hash_hex: "1".repeat(64),
                    offset: 0,
                    length: 28,
                    sha256: "b".repeat(64),
                    batch_count: 2,
                },
                OriginalSlotIndex {
                    slot: 106,
                    parent_slot: 104,
                    parent_hash_hex: "2".repeat(64),
                    final_hash_hex: "3".repeat(64),
                    offset: 28,
                    length: 24,
                    sha256: "c".repeat(64),
                    batch_count: 1,
                },
            ],
        }
    }
    #[test]
    fn exact_coverage_is_not_profile_promotion() {
        let index = fixture();
        validate_records(&index, 2, 5).unwrap();
        assert!(index.validate().is_err());
        assert!(validate_records(&index, 3, 5).is_err());
        assert!(validate_records(&index, 2, 6).is_err());
    }
    #[test]
    fn gaps_overlaps_duplicate_targets_wrong_parents_and_lengths_fail_closed() {
        for mutation in 0..9 {
            let mut index = fixture();
            match mutation {
                0 => index.slots[1].offset = 15,
                1 => index.slots[1].offset = 17,
                2 => index.slots[1].slot = 103,
                3 => index.slots[1].parent_slot = 102,
                4 => index.slots[0].batch_count = 0,
                5 => index.slots[0].batch_count = 3,
                6 => index.slots[0].sha256 = "A".repeat(64),
                7 => index.slots[1].final_hash_hex = "g".repeat(64),
                _ => index.data_bytes += 1,
            }
            assert!(
                validate_records(&index, 2, 5).is_err(),
                "mutation{mutation}"
            );
        }
    }
    #[test]
    fn serde_unknown_fields_and_invalid_hashes_are_rejected() {
        let mut value = serde_json::to_value(fixture()).unwrap();
        value["publication_authorized"] = serde_json::json!(true);
        assert!(serde_json::from_value::<OriginalBundleIndex>(value).is_err());
        assert_eq!(decode_hash(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(decode_hash(&"AB".repeat(32)).is_err());
        assert!(decode_hash("00").is_err());
    }
    #[test]
    fn immutable_open_rejects_writable_symlink_and_hardlink_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        fs::write(&path, b"data").unwrap();
        assert!(open_immutable(&path, 10).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(open_immutable(&link, 10).is_err());
        let hard = dir.path().join("hard");
        fs::hard_link(&path, &hard).unwrap();
        assert!(open_immutable(&hard, 10).is_err());
    }

    #[test]
    fn slot_reads_preserve_exact_batches_and_reject_digest_or_inode_changes() {
        // Exercise the private read implementation without bypassing production
        // open's root-owned immutable full-profile gates in any public API.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for _ in 0..2 {
            bytes.extend_from_slice(&8u32.to_le_bytes());
            bytes.extend_from_slice(&[1; 8]);
        }
        bytes.extend_from_slice(&[1; 24]);
        fs::write(&path, &bytes).unwrap();
        let file = File::open(&path).unwrap();
        let mut index = fixture();
        index.slots[0].sha256 = format!("{:x}", Sha256::digest(&bytes[..28]));
        let mut bundle = OriginalEntryBundle {
            identity: identity(&file.metadata().unwrap()),
            data: file,
            path: path.clone(),
            index,
        };
        assert!(bundle.read_slot(101).unwrap().is_none());
        let slot = bundle.read_slot(103).unwrap().unwrap();
        assert_eq!(slot.batches, vec![vec![1; 8], vec![1; 8]]);
        assert_eq!(slot.expected.parent_slot, 100);
        assert!(bundle.read_slot(106).is_err()); // Wrong separately bound record digest.
        let replacement = dir.path().join("replacement");
        fs::write(&replacement, &bytes).unwrap();
        fs::rename(replacement, &path).unwrap();
        assert!(bundle.read_slot(103).is_err()); // Same bytes, different inode.
    }
}
