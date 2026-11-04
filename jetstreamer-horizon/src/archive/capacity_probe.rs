//! In-memory capability evidence for historical post-transaction update bursts.
use super::{
    ArchiveFormatError, ArchiveReader, ArchiveWriter, ArchiveWriterConfig, Compression, SlotVisitor,
};
use crate::{
    account_updates::AccountUpdateView,
    block_metas::BlockMeta,
    limits::{MAX_SLOT_POST_UPDATE_DATA, MAX_SLOT_POST_UPDATES},
};
use std::{
    error::Error,
    io::{self, Cursor},
};

const SLOT: u64 = 96_540_992;
const RECORDS: usize = 16_385;
const DATA: &[u8] = &[0xa5; 16];

fn writer() -> Result<ArchiveWriter<Vec<u8>>, ArchiveFormatError> {
    let mut writer = ArchiveWriter::new(
        Vec::new(),
        223,
        SLOT,
        1,
        ArchiveWriterConfig {
            compression: Compression::None,
            ..Default::default()
        },
    )?;
    writer.begin_slot(SLOT)?;
    Ok(writer)
}

fn update(version: u64) -> AccountUpdateView<'static> {
    AccountUpdateView {
        pubkey: Default::default(),
        lamports: version,
        owner: Default::default(),
        executable: false,
        rent_epoch: 0,
        write_version: version,
        data: DATA,
    }
}

/// Exercise the linked writer and reader over the observed epoch-223 shape,
/// verify every record's attribution/data, and retain the finite count bound.
/// No filesystem, production archive, runtime, RPC, or remote storage is used.
pub fn post_update_capacity_probe() -> Result<String, Box<dyn Error>> {
    let mut observed = writer()?;
    for version in 0..RECORDS as u64 {
        observed.write_reencoded_post_update(&update(version))?;
    }
    let mut meta = BlockMeta::new_boxed();
    meta.slot = SLOT;
    observed.end_slot(&meta, &[])?;
    let (archive, _) = observed.finish()?;
    #[derive(Default)]
    struct Count {
        records: usize,
        bytes: usize,
        invalid: bool,
    }
    impl SlotVisitor for Count {
        fn on_post_account_update(&mut self, slot: u64, value: &AccountUpdateView<'_>) {
            self.invalid |= slot != SLOT
                || value.write_version != self.records as u64
                || value.lamports != self.records as u64
                || value.data != DATA;
            self.records += 1;
            self.bytes += value.data.len();
        }
    }
    let mut reader = ArchiveReader::open(Cursor::new(archive))?;
    let mut count = Count::default();
    reader.read_slots(0, u64::MAX, &mut count)?;
    if count.invalid || count.records != RECORDS || count.bytes != RECORDS * DATA.len() {
        return Err(
            io::Error::other("post-update capacity probe changed or dropped records/data").into(),
        );
    }
    let mut ceiling = writer()?;
    for version in 0..MAX_SLOT_POST_UPDATES as u64 {
        ceiling.write_reencoded_post_update(&update(version))?;
    }
    if !matches!(ceiling.write_reencoded_post_update(&update(MAX_SLOT_POST_UPDATES as u64)),
        Err(ArchiveFormatError::SectionTooLarge{section:"post-transaction account updates",bytes,limit})
            if bytes == MAX_SLOT_POST_UPDATES as u64 + 1 && limit == MAX_SLOT_POST_UPDATES as u64)
    {
        return Err(io::Error::other("post-update count ceiling did not fail closed").into());
    }
    Ok(format!(
        "{{\"schema\":\"jetstreamer-horizon-post-update-capacity-probe-v1\",\"slot\":{SLOT},\"decoded_records\":{},\"account_data_bytes\":{},\"maximum_post_updates\":{MAX_SLOT_POST_UPDATES},\"maximum_post_update_data_bytes\":{MAX_SLOT_POST_UPDATE_DATA},\"one_past_count_limit_rejected\":true,\"archive_mutations\":false,\"replay_launch_authorized\":false,\"publication_authorized\":false,\"remote_mutations\":false,\"r2_mutations\":false}}",
        count.records, count.bytes
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn observed_burst_roundtrips_with_data_and_count_bound_is_preserved() {
        let result = super::post_update_capacity_probe().unwrap();
        assert!(result.contains("\"decoded_records\":16385"));
        assert!(result.contains("\"account_data_bytes\":262160"));
        assert!(result.contains("\"maximum_post_updates\":32768"));
        assert!(result.contains("\"maximum_post_update_data_bytes\":16777216"));
        assert!(result.contains("\"one_past_count_limit_rejected\":true"));
        assert!(result.contains("\"publication_authorized\":false"));
    }
}
