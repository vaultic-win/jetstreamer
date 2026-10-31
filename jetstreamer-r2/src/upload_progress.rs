//! Application-level acknowledgements, never whole-object integrity evidence.

use {
    anyhow::{Result, ensure},
    std::collections::BTreeSet,
};

const CHECKPOINT_BYTES: u64 = 1024 * 1024 * 1024;

pub(super) struct UploadProgress {
    total: u64,
    part_size: u64,
    acknowledged: BTreeSet<u64>,
    bytes: u64,
    last_reported: Option<u64>,
}

impl UploadProgress {
    pub(super) fn new(total: u64, part_size: u64) -> Result<Self> {
        ensure!(
            total > 0 && part_size > 0,
            "empty multipart progress geometry"
        );
        ensure!(
            total.div_ceil(part_size) <= 10_000,
            "too many multipart parts"
        );
        Ok(Self {
            total,
            part_size,
            acknowledged: BTreeSet::new(),
            bytes: 0,
            last_reported: None,
        })
    }

    /// Call only after a successful response whose ETag matches the local MD5.
    /// Retries and duplicate acknowledgements cannot increase the byte count.
    pub(super) fn acknowledge(&mut self, index: u64) -> Result<Option<u64>> {
        ensure!(
            index < self.total.div_ceil(self.part_size),
            "part index outside archive"
        );
        if !self.acknowledged.insert(index) {
            return Ok(None);
        }
        self.bytes += (self.total - index * self.part_size).min(self.part_size);
        let report = self.last_reported.is_none_or(|previous| {
            self.bytes - previous >= CHECKPOINT_BYTES || self.bytes == self.total
        });
        if report {
            self.last_reported = Some(self.bytes);
            Ok(Some(self.bytes))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_order_tail_and_duplicates_count_only_distinct_bytes() {
        let mut progress =
            UploadProgress::new(2 * CHECKPOINT_BYTES + 17, CHECKPOINT_BYTES).unwrap();
        assert_eq!(progress.acknowledge(2).unwrap(), Some(17));
        assert_eq!(progress.acknowledge(2).unwrap(), None);
        assert_eq!(
            progress.acknowledge(1).unwrap(),
            Some(CHECKPOINT_BYTES + 17)
        );
        assert_eq!(
            progress.acknowledge(0).unwrap(),
            Some(2 * CHECKPOINT_BYTES + 17)
        );
        assert_eq!(progress.acknowledge(0).unwrap(), None);
    }

    #[test]
    fn invalid_parts_do_not_mutate_progress() {
        let mut progress = UploadProgress::new(17, 64).unwrap();
        assert!(progress.acknowledge(1).is_err());
        assert!(progress.acknowledge(u64::MAX).is_err());
        assert_eq!(progress.acknowledge(0).unwrap(), Some(17));
        assert!(UploadProgress::new(0, 1).is_err());
        assert!(UploadProgress::new(1, 0).is_err());
        assert!(UploadProgress::new(10_001, 1).is_err());
    }

    #[test]
    fn first_gib_and_final_checkpoints_are_bounded() {
        let part = CHECKPOINT_BYTES / 2;
        let mut progress = UploadProgress::new(2 * CHECKPOINT_BYTES, part).unwrap();
        assert_eq!(progress.acknowledge(0).unwrap(), Some(part));
        assert_eq!(progress.acknowledge(1).unwrap(), None);
        assert_eq!(progress.acknowledge(2).unwrap(), Some(3 * part));
        assert_eq!(progress.acknowledge(3).unwrap(), Some(4 * part));
    }
}
