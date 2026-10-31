//! In-memory decoder capability check; no archive/network/database access.
use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{ArchiveReader, ArchiveWriter, ArchiveWriterConfig, Compression, SlotVisitor},
    block_metas::BlockMeta,
    limits::{MAX_SLOT_PRE_UPDATE_DATA, MAX_SLOT_PRE_UPDATES},
};
use std::io::{self, Cursor};

const RECORDS: u64 = 71_524;
const DATA_BYTES: usize = 16;

/// Exercise the exact linked decoder over the observed count and nonempty data.
pub(super) fn probe() -> Result<String, Box<dyn std::error::Error>> {
    let mut writer = ArchiveWriter::new(
        Vec::new(),
        201,
        86_832_000,
        1,
        ArchiveWriterConfig {
            compression: Compression::None,
            ..Default::default()
        },
    )?;
    writer.begin_slot(86_832_000)?;
    for version in 0..RECORDS {
        writer.write_orphan_update(&AccountUpdateView {
            pubkey: Default::default(),
            lamports: version,
            owner: Default::default(),
            executable: false,
            rent_epoch: 0,
            write_version: version,
            data: &[0xa5; DATA_BYTES],
        })?;
    }
    let mut meta = BlockMeta::new_boxed();
    meta.slot = 86_832_000;
    writer.end_slot(&meta, &[])?;
    let (archive, _) = writer.finish()?;
    #[derive(Default)]
    struct Count {
        records: u64,
        bytes: u64,
        invalid: bool,
    }
    impl SlotVisitor for Count {
        fn on_pre_account_update(&mut self, _slot: u64, update: &AccountUpdateView<'_>) {
            self.invalid |= update.write_version != self.records
                || update.lamports != self.records
                || update.data != [0xa5; DATA_BYTES];
            self.records += 1;
            self.bytes += update.data.len() as u64;
        }
    }
    let mut reader = ArchiveReader::open(Cursor::new(archive))?;
    let mut count = Count::default();
    reader.read_slots(0, u64::MAX, &mut count)?;
    if count.invalid || count.records != RECORDS || count.bytes != RECORDS * DATA_BYTES as u64 {
        return Err(io::Error::other("capacity probe lost or changed update records/data").into());
    }
    // All interpolated values are integers; the fixed JSON string has no
    // user-controlled string fields. Keep stdout a single machine-readable line.
    Ok(format!(
        "{{\"schema\":\"jetstreamer-horizon-plugin-capacity-probe-v1\",\"decoded_records\":{},\"account_data_bytes\":{},\"maximum_pre_updates\":{},\"maximum_pre_update_data_bytes\":{},\"publication_authorized\":false,\"production_completion_authorized\":false,\"local_retirement_authorized\":false,\"remote_mutations\":false,\"r2_mutations\":false}}",
        count.records, count.bytes, MAX_SLOT_PRE_UPDATES, MAX_SLOT_PRE_UPDATE_DATA
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn observed_71524_record_probe_exercises_nonempty_account_bytes() {
        let result = super::probe().unwrap();
        assert!(result.contains("\"decoded_records\":71524"));
        assert!(result.contains("\"account_data_bytes\":1144384"));
        assert!(result.contains("\"publication_authorized\":false"));
        assert!(result.contains("\"r2_mutations\":false"));
    }
}
