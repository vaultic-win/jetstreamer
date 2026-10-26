//! Observational counters only: decoding progress is never verification evidence.

use std::{
    io::{self, Write},
    sync::atomic::{AtomicU64, Ordering},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) struct SegmentProgress {
    epoch: u64,
    started: Instant,
    decoded_buckets: AtomicU64,
    decoded_slots: AtomicU64,
    last_progress_millis: AtomicU64,
    last_report_millis: AtomicU64,
}

impl SegmentProgress {
    pub(crate) fn new(epoch: u64) -> Self {
        let progress = Self {
            epoch,
            started: Instant::now(),
            decoded_buckets: AtomicU64::new(0),
            decoded_slots: AtomicU64::new(0),
            last_progress_millis: AtomicU64::new(0),
            last_report_millis: AtomicU64::new(0),
        };
        progress.phase("source_validation_started");
        progress
    }

    fn elapsed_millis(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub(crate) fn decoded(&self, slots: u64) {
        self.record_decoded(slots, self.elapsed_millis());
    }

    fn record_decoded(&self, slots: u64, elapsed: u64) {
        self.decoded_slots.fetch_add(slots, Ordering::Relaxed);
        self.decoded_buckets.fetch_add(1, Ordering::Relaxed);
        self.last_progress_millis
            .fetch_max(elapsed, Ordering::Relaxed);
        if self.claim_report(elapsed) {
            self.phase("bucket_decode_progress");
        }
    }

    fn claim_report(&self, elapsed: u64) -> bool {
        let previous = self.last_report_millis.load(Ordering::Relaxed);
        elapsed.saturating_sub(previous) >= 60_000
            && self
                .last_report_millis
                .compare_exchange(previous, elapsed, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    pub(crate) fn phase(&self, phase: &'static str) {
        // Ignore sink failures: diagnostic output cannot change validation results.
        let _ = self.write_record(&mut io::stderr().lock(), phase);
    }

    fn write_record(&self, sink: &mut impl Write, phase: &str) -> io::Result<()> {
        let elapsed = self.elapsed_millis();
        let last_progress = self.last_progress_millis.load(Ordering::Relaxed);
        writeln!(
            sink,
            "operation=segment_source_validation epoch={} phase={} timestamp_unix_millis={} elapsed_millis={} decoded_buckets={} decoded_slots={} last_progress_millis={} since_progress_millis={} observational_only=true",
            self.epoch,
            phase,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            elapsed,
            self.decoded_buckets.load(Ordering::Relaxed),
            self.decoded_slots.load(Ordering::Relaxed),
            last_progress,
            elapsed.saturating_sub(last_progress),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reporting_does_not_fabricate_progress() {
        let progress = SegmentProgress::new(225);
        progress.record_decoded(128, 5);
        assert!(!progress.claim_report(59_999));
        assert!(progress.claim_report(60_000));
        assert!(!progress.claim_report(60_001));
        assert!(progress.claim_report(120_000));
        assert_eq!(progress.last_progress_millis.load(Ordering::Relaxed), 5);
        assert_eq!(progress.decoded_slots.load(Ordering::Relaxed), 128);
    }

    #[test]
    fn parallel_decoding_counts_each_bucket_once() {
        let progress = SegmentProgress::new(225);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    for _ in 0..100 {
                        progress.decoded(128);
                    }
                });
            }
        });
        assert_eq!(progress.decoded_buckets.load(Ordering::Relaxed), 1600);
        assert_eq!(progress.decoded_slots.load(Ordering::Relaxed), 204800);
        let mut output = Vec::new();
        progress
            .write_record(&mut output, "bucket_decode_progress")
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("decoded_buckets=1600 decoded_slots=204800"));
        assert!(output.contains("observational_only=true"));
        assert!(!output.contains("verified=true"));
    }

    #[test]
    fn pool_shares_one_reporting_budget() {
        let progress = SegmentProgress::new(225);
        let reports = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    if progress.claim_report(60_000) {
                        reports.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(reports.load(Ordering::Relaxed), 1);
    }
}
