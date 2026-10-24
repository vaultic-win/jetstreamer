//! Diagnostic-only assembly for the exact v1.4.25 legacy data-shred layout.
//!
//! Source: solana revision 893cc7647248a3536fb6e6d0b5e51c71446b862d,
//! ledger/src/shred.rs SHA-256
//! 37cb75ad5f03e22f8df82a14d97bdec8b850216feefd93d853289691a770e1d1.
//! This does not decode entries, authenticate signatures or a ledger generation,
//! prove live-state completeness, recover missing FEC shards, verify PoH, or
//! authorize replay/publication. Callers must independently resolve all native
//! column families, manifest/WAL/live files, and SlotMeta before supplying inputs.

const PAYLOAD_BYTES: usize = 1228;
const HEADER_BYTES: usize = 88;
const DATA_END: usize = PAYLOAD_BYTES - 89;
const DATA_BYTES: usize = DATA_END - HEADER_BYTES;
const MAX_SHREDS: usize = 65_536;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const DATA_COMPLETE: u8 = 0x40;
const LAST_IN_SLOT: u8 = 0x80;

/// Bounded complete-slot metadata decoded with the pinned v1.4.25 layout.
/// Its provenance and logical native-state resolution remain caller obligations.
#[derive(Debug, Eq, PartialEq)]
pub struct DiagnosticSlotMeta {
    /// Exact independently expected slot.
    pub slot: u64,
    /// Exact independently expected finalized parent.
    pub parent_slot: u64,
    /// Last data-shred index; all indexes zero through this value are owed.
    pub last_index: u32,
    /// Sorted data-complete endpoints, including the final data shred.
    pub completed_data_indexes: Vec<u32>,
    /// Recorded connectivity bit, not independently authenticated ancestry.
    pub is_connected: bool,
}

/// Decode the entire fixed-int SlotMeta record, rejecting partial or trailing data.
///
/// Layout source: ledger/src/blockstore_meta.rs at revision 893cc764, SHA256
/// `25e29134699e586f626a56b79e507c4e0b1e92b21d47684841cdd727abc80ba7`.
/// Require a known terminal index, fully consumed/received contiguous data range,
/// bounded unique child slots, and strictly ordered completed-data endpoints.
/// This is a stricter diagnostic complete-slot profile, not a runtime behavior
/// change, native liveness proof, signature verification or publication gate.
pub fn decode_v1_4_25_complete_slot_meta(
    bytes: &[u8],
    expected_slot: u64,
    expected_parent: u64,
) -> Result<DiagnosticSlotMeta, String> {
    struct Reader<'a> {
        bytes: &'a [u8],
        position: usize,
    }
    impl Reader<'_> {
        fn take(&mut self, n: usize) -> Result<&[u8], String> {
            let end = self
                .position
                .checked_add(n)
                .ok_or("SlotMeta offset overflow")?;
            let value = self
                .bytes
                .get(self.position..end)
                .ok_or("truncated SlotMeta")?;
            self.position = end;
            Ok(value)
        }
        fn integer(&mut self) -> Result<u64, String> {
            Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
        }
        fn count(&mut self) -> Result<usize, String> {
            let n = self.integer()?;
            if n > MAX_SHREDS as u64 {
                return Err("SlotMeta vector bound exceeded".into());
            }
            Ok(n as usize)
        }
    }
    if bytes.len() > 1024 * 1024
        || expected_slot
            .checked_sub(expected_parent)
            .is_none_or(|n| n == 0 || n > u16::MAX as u64)
    {
        return Err("invalid SlotMeta scope or size".into());
    }
    let mut reader = Reader { bytes, position: 0 };
    let slot = reader.integer()?;
    let consumed = reader.integer()?;
    let received = reader.integer()?;
    reader.integer()?; // first_shred_timestamp, not an authenticity clock.
    let last = reader.integer()?;
    let parent_slot = reader.integer()?;
    if slot != expected_slot
        || parent_slot != expected_parent
        || last >= MAX_SHREDS as u64
        || consumed != last + 1
        || received != consumed
    {
        return Err("incomplete or mismatching SlotMeta range".into());
    }
    let children = reader.count()?;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..children {
        let child = reader.integer()?;
        if child <= slot || !seen.insert(child) {
            return Err("invalid/duplicate SlotMeta child".into());
        }
    }
    let is_connected = match reader.take(1)?[0] {
        0 => false,
        1 => true,
        _ => return Err("invalid SlotMeta boolean".into()),
    };
    let count = reader.count()?;
    let mut completed_data_indexes = Vec::with_capacity(count);
    for _ in 0..count {
        let index = u32::from_le_bytes(reader.take(4)?.try_into().unwrap());
        if u64::from(index) > last || completed_data_indexes.last().is_some_and(|p| *p >= index) {
            return Err("invalid SlotMeta completed-data endpoints".into());
        }
        completed_data_indexes.push(index);
    }
    if reader.position != bytes.len() || completed_data_indexes.last().copied() != Some(last as u32)
    {
        return Err("incomplete or trailing SlotMeta record".into());
    }
    Ok(DiagnosticSlotMeta {
        slot,
        parent_slot,
        last_index: last as u32,
        completed_data_indexes,
        is_connected,
    })
}

/// One complete serialized entry-vector batch, including historical padding.
#[derive(Debug, Eq, PartialEq)]
pub struct PaddedEntryBatch {
    /// Inclusive first data-shred index in this batch.
    pub first_index: u32,
    /// Inclusive final data-shred index in this batch.
    pub last_index: u32,
    /// Raw v1.4.25 `Shredder::deshred` output; not yet validated entry bytes.
    pub bytes: Vec<u8>,
}

struct Header {
    slot: u64,
    index: u32,
    version: u16,
    parent_offset: u16,
    flags: u8,
}

fn header(payload: &[u8]) -> Result<Header, String> {
    if payload.len() != PAYLOAD_BYTES || payload[64] != 0xa5 {
        return Err("expected one exact 1228-byte legacy data shred".into());
    }
    let index = u32::from_le_bytes(payload[73..77].try_into().unwrap());
    let fec_start = u32::from_le_bytes(payload[79..83].try_into().unwrap());
    let size = usize::from(u16::from_le_bytes(payload[86..88].try_into().unwrap()));
    if fec_start > index || !(HEADER_BYTES..=DATA_END).contains(&size) {
        return Err("invalid legacy FEC index or declared data size".into());
    }
    Ok(Header {
        slot: u64::from_le_bytes(payload[65..73].try_into().unwrap()),
        index,
        version: u16::from_le_bytes(payload[77..79].try_into().unwrap()),
        parent_offset: u16::from_le_bytes(payload[83..85].try_into().unwrap()),
        flags: payload[85],
    })
}

/// Assemble all contiguous data shreds of one independently resolved complete slot.
///
/// `expected_last_index` must come from independently authenticated logical
/// SlotMeta, not from the greatest point key found in an SST prefix scan. This
/// routine rejects missing, duplicated, reordered, coding, inconsistent-parent,
/// mixed-version, incomplete or oversized input. It intentionally preserves the
/// entire padded data region: the pinned runtime does **not** clip deshredding to
/// `DataShredHeader.size`. Entry decoding and canonical boundary/PoH validation
/// remain mandatory independent gates before interpreting these diagnostic bytes.
pub fn assemble_v1_4_25_padded_batches(
    expected_slot: u64,
    expected_parent: u64,
    expected_last_index: u32,
    shreds: &[&[u8]],
) -> Result<Vec<PaddedEntryBatch>, String> {
    let expected_count = usize::try_from(expected_last_index)
        .ok()
        .and_then(|index| index.checked_add(1))
        .ok_or("legacy shred count overflow")?;
    let output_bytes = expected_count
        .checked_mul(DATA_BYTES)
        .ok_or("legacy assembled byte count overflow")?;
    if expected_count > MAX_SHREDS
        || output_bytes > MAX_OUTPUT_BYTES
        || shreds.len() != expected_count
    {
        return Err("incomplete or oversized complete-slot shred set".into());
    }
    let parent_offset = expected_slot
        .checked_sub(expected_parent)
        .and_then(|offset| u16::try_from(offset).ok())
        .filter(|offset| *offset != 0)
        .ok_or("invalid expected legacy parent relationship")?;
    let mut batches = Vec::new();
    let mut bytes = Vec::new();
    let mut first_index = 0;
    let mut version = None;
    for (index, payload) in shreds.iter().enumerate() {
        let h = header(payload)?;
        let last = h.flags & LAST_IN_SLOT != 0;
        if h.slot != expected_slot
            || h.index as usize != index
            || h.parent_offset != parent_offset
            || version.is_some_and(|version| version != h.version)
            || last != (h.index == expected_last_index)
        {
            return Err("legacy slot/index/parent/version/terminal binding mismatch".into());
        }
        version = Some(h.version);
        bytes.extend_from_slice(&payload[HEADER_BYTES..DATA_END]);
        if h.flags & DATA_COMPLETE != 0 || last {
            batches.push(PaddedEntryBatch {
                first_index,
                last_index: h.index,
                bytes: std::mem::take(&mut bytes),
            });
            first_index = h
                .index
                .checked_add(1)
                .ok_or("legacy batch index overflow")?;
        }
    }
    if !bytes.is_empty() || batches.is_empty() {
        return Err("incomplete legacy entry batch".into());
    }
    Ok(batches)
}

/// Bind assembled batches to a complete connected SlotMeta and all data endpoints.
/// The caller still owes authenticated native source state and canonical PoH gates.
pub fn assemble_v1_4_25_slot_from_meta(
    meta: &DiagnosticSlotMeta,
    shreds: &[&[u8]],
) -> Result<Vec<PaddedEntryBatch>, String> {
    if !meta.is_connected {
        return Err("SlotMeta ancestry is not recorded connected".into());
    }
    let batches =
        assemble_v1_4_25_padded_batches(meta.slot, meta.parent_slot, meta.last_index, shreds)?;
    if batches.iter().map(|b| b.last_index).collect::<Vec<_>>() != meta.completed_data_indexes {
        return Err("assembled endpoints differ from complete SlotMeta".into());
    }
    Ok(batches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::Options;
    use sha2::Digest;

    fn metadata(
        consumed: u64,
        received: u64,
        last: u64,
        children: Vec<u64>,
        completed: Vec<u32>,
    ) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&(
                60912004_u64,
                consumed,
                received,
                123_u64,
                last,
                60911999_u64,
                children,
                true,
                completed,
            ))
            .unwrap()
    }

    #[test]
    fn bounded_complete_slot_metadata_matches_fixed_integer_layout() {
        let bytes = metadata(4, 4, 3, vec![60912007, 60912005], vec![1, 3]);
        // Independent pinned SDK/bincode1.3.1 golden from its Rust 1.46 workspace.
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(&bytes)),
            "6b2bcca69ee61a560e719e0e58456ac5907e8e24c90434b90e9f8e12b25f6ec7"
        );
        let meta = decode_v1_4_25_complete_slot_meta(&bytes, 60912004, 60911999).unwrap();
        assert_eq!(meta.last_index, 3);
        assert_eq!(meta.completed_data_indexes, [1, 3]);
        assert!(meta.is_connected);
        for end in 0..bytes.len() {
            assert!(decode_v1_4_25_complete_slot_meta(&bytes[..end], 60912004, 60911999).is_err());
        }
        let mut extra = bytes;
        extra.push(0);
        assert!(decode_v1_4_25_complete_slot_meta(&extra, 60912004, 60911999).is_err());
    }

    #[test]
    fn metadata_rejects_partial_ranges_bad_endpoints_and_unbounded_vectors() {
        for bad in [
            metadata(3, 4, 3, vec![], vec![3]),
            metadata(4, 5, 3, vec![], vec![3]),
            metadata(0, 0, u64::MAX, vec![], vec![]),
            metadata(4, 4, 3, vec![], vec![1, 1, 3]),
            metadata(4, 4, 3, vec![], vec![1]),
            metadata(4, 4, 3, vec![60912005, 60912005], vec![3]),
            metadata(4, 4, 3, vec![60912004], vec![3]),
        ] {
            assert!(decode_v1_4_25_complete_slot_meta(&bad, 60912004, 60911999).is_err());
        }
        let mut bad = metadata(4, 4, 3, vec![], vec![3]);
        bad[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_v1_4_25_complete_slot_meta(&bad, 60912004, 60911999).is_err());
        let mut bad = metadata(4, 4, 3, vec![], vec![3]);
        bad[56] = 2;
        assert!(decode_v1_4_25_complete_slot_meta(&bad, 60912004, 60911999).is_err());
        assert!(
            decode_v1_4_25_complete_slot_meta(
                &metadata(4, 4, 3, vec![], vec![3]),
                60912004,
                60911998
            )
            .is_err()
        );
    }

    fn shred(index: u32, flags: u8, size: u16) -> Vec<u8> {
        // Fixed-int bincode field order of Signature + ShredCommonHeader +
        // DataShredHeader. Two raw [u8; 32] tuples reproduce Signature's 64 bytes.
        let header = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&(
                [0_u8; 32],
                [0_u8; 32],
                0xa5_u8,
                60912004_u64,
                index,
                1234_u16,
                0_u32,
                3_u16,
                flags,
                size,
            ))
            .unwrap();
        assert_eq!(header.len(), HEADER_BYTES);
        let mut payload = vec![0xee; PAYLOAD_BYTES];
        payload[..HEADER_BYTES].copy_from_slice(&header);
        payload[HEADER_BYTES..DATA_END].fill(index as u8);
        payload
    }

    fn assemble(shreds: &[Vec<u8>]) -> Result<Vec<PaddedEntryBatch>, String> {
        let refs: Vec<_> = shreds.iter().map(Vec::as_slice).collect();
        assemble_v1_4_25_padded_batches(60912004, 60912001, (shreds.len() - 1) as u32, &refs)
    }

    #[test]
    fn exact_padded_region_matches_pinned_deshred_not_declared_size() {
        let a = shred(0, 0, 1139);
        let b = shred(1, LAST_IN_SLOT, 89);
        let batches = assemble(&[a, b]).unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].first_index, 0);
        assert_eq!(batches[0].last_index, 1);
        assert_eq!(batches[0].bytes.len(), 2 * DATA_BYTES);
        assert_eq!(&batches[0].bytes[..DATA_BYTES], vec![0; DATA_BYTES]);
        assert_eq!(&batches[0].bytes[DATA_BYTES..], vec![1; DATA_BYTES]);
        assert!(!batches[0].bytes.contains(&0xee));
    }

    #[test]
    fn complete_flags_split_batches_and_last_flag_closes_slot() {
        let batches = assemble(&[
            shred(0, DATA_COMPLETE, 88),
            shred(1, LAST_IN_SLOT | DATA_COMPLETE, 1139),
        ])
        .unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].last_index, 0);
        assert_eq!(batches[1].first_index, 1);
        assert_eq!(batches[1].bytes.len(), DATA_BYTES);
    }

    #[test]
    fn assembled_slot_must_match_metadata_connectivity_and_every_endpoint() {
        let bytes = [shred(0, 0, 1139), shred(1, LAST_IN_SLOT, 1139)];
        let refs: Vec<_> = bytes.iter().map(Vec::as_slice).collect();
        let mut meta = DiagnosticSlotMeta {
            slot: 60912004,
            parent_slot: 60912001,
            last_index: 1,
            completed_data_indexes: vec![1],
            is_connected: true,
        };
        assert_eq!(
            assemble_v1_4_25_slot_from_meta(&meta, &refs).unwrap().len(),
            1
        );
        meta.completed_data_indexes = vec![0, 1];
        assert!(assemble_v1_4_25_slot_from_meta(&meta, &refs).is_err());
        meta.completed_data_indexes = vec![1];
        meta.is_connected = false;
        assert!(assemble_v1_4_25_slot_from_meta(&meta, &refs).is_err());
    }

    #[test]
    fn rejects_inconsistent_or_incomplete_shred_sets() {
        let good = vec![shred(0, 0, 1139), shred(1, LAST_IN_SLOT, 1139)];
        for (position, offset, value) in [
            (0, 64, 0x5a),
            (0, 65, 0),
            (0, 73, 1),
            (1, 73, 2),
            (1, 77, 0),
            (1, 83, 4),
            (0, 85, LAST_IN_SLOT),
            (1, 85, 0),
            (0, 87, 255),
            (0, 79, 1),
        ] {
            let mut bad = good.clone();
            bad[position][offset] = value;
            assert!(
                assemble(&bad).is_err(),
                "accepted position {position} offset {offset}"
            );
        }
        for size in [0, 64, 88, 1227, 1229] {
            let mut bad = good.clone();
            bad[0].resize(size, 0);
            assert!(assemble(&bad).is_err());
        }
        let mut bad = good.clone();
        bad.swap(0, 1);
        assert!(assemble(&bad).is_err());
        let mut bad = good.clone();
        bad[1] = bad[0].clone();
        assert!(assemble(&bad).is_err());
        let mut bad = good.clone();
        bad[0][86..88].copy_from_slice(&87_u16.to_le_bytes());
        assert!(assemble(&bad).is_err());
        assert!(
            assemble_v1_4_25_padded_batches(
                60912004,
                60912001,
                2,
                &[good[0].as_slice(), good[1].as_slice()]
            )
            .is_err()
        );
    }

    #[test]
    fn parent_and_allocation_bounds_fail_before_assembly() {
        let packet = shred(0, LAST_IN_SLOT, 88);
        for parent in [60912004, 60912005, 0] {
            assert!(assemble_v1_4_25_padded_batches(60912004, parent, 0, &[&packet]).is_err());
        }
        assert!(assemble_v1_4_25_padded_batches(60912004, 60912001, u32::MAX, &[]).is_err());
        assert!(assemble_v1_4_25_padded_batches(60912004, 60912001, 0, &[]).is_err());
        let count = MAX_OUTPUT_BYTES / DATA_BYTES + 1;
        assert!(
            assemble_v1_4_25_padded_batches(
                60912004,
                60912001,
                (count - 1) as u32,
                &vec![packet.as_slice(); count]
            )
            .is_err()
        );
    }
}
