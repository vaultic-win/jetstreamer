//! Plugin lifecycle and transaction progress for one Horizon slot range.
use std::collections::VecDeque;
use std::future::Future;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::HorizonPlugin;

#[derive(Default)]
pub(super) struct RangeLifecycle<'a> {
    active: VecDeque<&'a dyn HorizonPlugin>,
}

impl<'a> RangeLifecycle<'a> {
    pub(super) fn started(&mut self, plugin: &'a dyn HorizonPlugin) {
        self.active.push_back(plugin);
    }

    pub(super) fn finished(&mut self) {
        self.active.pop_front();
    }
}

impl Drop for RangeLifecycle<'_> {
    fn drop(&mut self) {
        for plugin in self.active.drain(..).rev() {
            plugin.on_abort_range();
        }
    }
}

/// Successful slot-range playback, including acknowledged writes and plugin finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeRunReport {
    /// The requested half-open Solana slot range.
    pub slots: Range<u64>,
    /// Number of global worker partitions returned by the firehose.
    pub workers: usize,
    /// Total transaction callbacks delivered across all worker partitions.
    pub transactions: u64,
    /// Wall-clock duration including setup, playback, write drain and finalization.
    pub elapsed: Duration,
}

// Each decode thread writes its own cache line. Only the periodic sampler
// and the final report need to read every counter.
#[repr(align(64))]
#[derive(Default)]
pub(super) struct TransactionCount(AtomicU64);

impl TransactionCount {
    pub(super) fn increment(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

pub(super) struct RangeProgress {
    counts: Vec<Arc<TransactionCount>>,
}

impl RangeProgress {
    pub(super) fn new(workers: usize) -> Self {
        Self {
            counts: (0..workers).map(|_| Arc::default()).collect(),
        }
    }

    pub(super) fn worker(&self, id: usize) -> Arc<TransactionCount> {
        self.counts[id].clone()
    }

    fn pulse(&self, elapsed: Duration) -> u64 {
        let transactions: u64 = self
            .counts
            .iter()
            .map(|c| c.0.load(Ordering::Relaxed))
            .sum();
        let seconds = elapsed.as_secs_f64();
        let tps = if elapsed.is_zero() {
            0.0
        } else {
            transactions as f64 / seconds
        };
        log::info!(target: super::LOG_TARGET,
            "horizon_tps elapsed_seconds={seconds:.6} transactions={transactions} overall_tps={tps:.3}");
        transactions
    }

    pub(super) async fn track(
        &self,
        slots: Range<u64>,
        work: impl Future<Output = Result<usize, Box<dyn std::error::Error + Send + Sync>>>,
    ) -> Result<RangeRunReport, Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();
        self.pulse(Duration::ZERO);
        let every = Duration::from_secs(30);
        let mut ticks = tokio::time::interval_at((start + every).into(), every);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(work);
        let workers = loop {
            tokio::select! {
                result = &mut work => break result?,
                _ = ticks.tick() => { self.pulse(start.elapsed()); }
            }
        };
        let elapsed = start.elapsed();
        Ok(RangeRunReport {
            slots,
            workers,
            transactions: self.pulse(elapsed),
            elapsed,
        })
    }
}
