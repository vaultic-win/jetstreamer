//! Application-level observations only; these logs are never integrity receipts.

const CHECKPOINT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Default)]
pub(super) struct ReadbackProgress {
    last_reported: Option<u64>,
}

impl ReadbackProgress {
    /// Call only after an ordered range has been written and fed into SHA-256.
    /// Retries and bytes merely received by a connection must not advance this.
    pub(super) fn checkpoint(&mut self, hashed_bytes: u64, total_bytes: u64) -> bool {
        if hashed_bytes == 0 || hashed_bytes > total_bytes {
            return false;
        }
        let report = match self.last_reported {
            None => true,
            Some(previous) => {
                hashed_bytes > previous
                    && (hashed_bytes - previous >= CHECKPOINT_BYTES || hashed_bytes == total_bytes)
            }
        };
        if report {
            self.last_reported = Some(hashed_bytes);
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_ordered_range_then_bounded_checkpoints_then_tail() {
        let mut progress = ReadbackProgress::default();
        let range = 64 * 1024 * 1024;
        let total = 3 * CHECKPOINT_BYTES + 17;
        assert!(!progress.checkpoint(0, total));
        assert!(progress.checkpoint(range, total));
        assert!(!progress.checkpoint(CHECKPOINT_BYTES, total));
        assert!(progress.checkpoint(CHECKPOINT_BYTES + range, total));
        assert!(!progress.checkpoint(2 * CHECKPOINT_BYTES, total));
        assert!(progress.checkpoint(2 * CHECKPOINT_BYTES + range, total));
        assert!(progress.checkpoint(total, total));
        assert!(!progress.checkpoint(total, total));
    }

    #[test]
    fn retries_regressions_and_out_of_bounds_cannot_advance_checkpoint() {
        let mut progress = ReadbackProgress::default();
        let total = 4 * CHECKPOINT_BYTES;
        assert!(!progress.checkpoint(total + 1, total));
        assert!(progress.checkpoint(CHECKPOINT_BYTES, total));
        assert!(!progress.checkpoint(CHECKPOINT_BYTES, total));
        assert!(!progress.checkpoint(CHECKPOINT_BYTES - 1, total));
        assert!(progress.checkpoint(2 * CHECKPOINT_BYTES, total));
    }

    #[test]
    fn short_objects_report_once_and_each_read_starts_fresh() {
        for _ in 0..2 {
            let mut progress = ReadbackProgress::default();
            assert!(!progress.checkpoint(0, 0));
            assert!(progress.checkpoint(17, 17));
            assert!(!progress.checkpoint(17, 17));
        }
    }
}
