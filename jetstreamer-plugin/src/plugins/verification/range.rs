//! Full-epoch verification over the global slot partitions of a Horizon range.
use std::collections::BTreeMap;
use std::ops::Range;

use super::*;
use jetstreamer_firehose::epochs::slot_to_epoch;

type EpochWorkers = Arc<Mutex<RunState>>;

struct ActiveRange {
    slots: Range<u64>,
    epochs: Mutex<BTreeMap<u64, EpochWorkers>>,
    error: Mutex<Option<String>>,
}

#[derive(Default)]
struct RangeState {
    active: Option<Arc<ActiveRange>>,
    reports: Vec<VerificationReport>,
}

/// Applies the full single-epoch verifier to the records delivered by a range
/// runner. Workers keep their global IDs and roll their verifier state at each
/// epoch boundary. Digests are comparable for identical range partitions.
#[derive(Default)]
pub struct RangeVerificationPlugin {
    state: Mutex<RangeState>,
}

impl RangeVerificationPlugin {
    /// Completed results in epoch order. A failed or unfinished run has none.
    pub fn take_reports(&self) -> Vec<VerificationReport> {
        std::mem::take(&mut lock_unpoisoned(&self.state).reports)
    }
}

impl HorizonPlugin for RangeVerificationPlugin {
    fn name(&self) -> &'static str {
        "Horizon range verification"
    }

    fn supports_slot_ranges(&self) -> bool {
        true
    }

    fn on_start_range(&self, _db: Arc<Client>, slots: Range<u64>) -> PluginFuture<'_> {
        async move {
            let mut state = lock_unpoisoned(&self.state);
            if state.active.is_some() {
                return Err(io::Error::other("range verification already active").into());
            }
            state.reports.clear();
            let slots_per_epoch = epoch_to_slot_range(1).0;
            if slots.is_empty()
                || !slots.start.is_multiple_of(slots_per_epoch)
                || !slots.end.is_multiple_of(slots_per_epoch)
            {
                return Err(io::Error::other("verification requires complete epochs").into());
            }
            state.active = Some(Arc::new(ActiveRange {
                slots,
                epochs: Mutex::default(),
                error: Mutex::default(),
            }));
            Ok(())
        }
        .boxed()
    }

    fn on_abort_range(&self) {
        lock_unpoisoned(&self.state).active.take();
    }

    fn on_start(&self, _db: Arc<Client>, _epoch: u64) -> PluginFuture<'_> {
        async { Err(io::Error::other("use run_range with the range verification plugin").into()) }
            .boxed()
    }

    fn spawn_worker(&self, thread_id: usize) -> Box<dyn PluginWorker> {
        Box::new(RangeWorker {
            thread_id,
            range: lock_unpoisoned(&self.state)
                .active
                .clone()
                .expect("range started"),
            current: None,
        })
    }

    fn on_finish_range(&self, _db: Arc<Client>, slots: Range<u64>) -> PluginFuture<'_> {
        async move {
            let mut state = lock_unpoisoned(&self.state);
            let active = state
                .active
                .clone()
                .ok_or_else(|| io::Error::other("range verification is idle"))?;
            if active.slots != slots {
                return Err(io::Error::other("range changed during verification").into());
            }
            if let Some(error) = lock_unpoisoned(&active.error).take() {
                return Err(io::Error::other(error).into());
            }
            let epochs = lock_unpoisoned(&active.epochs);
            let reports = (slot_to_epoch(slots.start)..=slot_to_epoch(slots.end - 1))
                .map(|epoch| {
                    let workers = epochs
                        .get(&epoch)
                        .ok_or_else(|| io::Error::other(format!("missing epoch {epoch}")))?;
                    let run = lock_unpoisoned(workers);
                    validate_worker_spans(&run).map_err(io::Error::other)?;
                    validate_run(&run).map_err(io::Error::other)
                })
                .collect::<io::Result<Vec<_>>>()?;
            state.active = None;
            state.reports = reports;
            Ok(())
        }
        .boxed()
    }
}

// Each worker already rejects non-increasing slots. Together with this check,
// its count witnesses every slot in its span exactly once, including skips.
fn validate_worker_spans(run: &RunState) -> Result<(), String> {
    let mut workers: Vec<_> = run.workers.iter().collect();
    workers.sort_unstable_by_key(|w| w.thread_id);
    let mut next_slot = run.start_slot;
    let mut last_id = None;
    for w in workers {
        let counts = &w.counts;
        let end = counts.last_slot.and_then(|slot| slot.checked_add(1));
        if Some(w.thread_id) == last_id
            || counts.first_slot != Some(next_slot)
            || end.is_none()
            || end.and_then(|n| n.checked_sub(next_slot)) != Some(counts.slots)
        {
            return Err(format!(
                "epoch {} worker {} has discontinuous coverage at slot {next_slot}",
                run.epoch, w.thread_id
            ));
        }
        next_slot = end.expect("validated last slot");
        last_id = Some(w.thread_id);
    }
    if next_slot != run.end_slot_exclusive {
        return Err(format!(
            "epoch {} ended at slot {next_slot}, expected {}",
            run.epoch, run.end_slot_exclusive
        ));
    }
    Ok(())
}

struct RangeWorker {
    thread_id: usize,
    range: Arc<ActiveRange>,
    current: Option<VerificationWorker>,
}

impl RangeWorker {
    fn worker_at(&mut self, slot: u64) -> Option<&mut VerificationWorker> {
        if !self
            .current
            .as_ref()
            .is_some_and(|w| (w.start_slot..w.end_slot_exclusive).contains(&slot))
        {
            if !self.range.slots.contains(&slot) {
                lock_unpoisoned(&self.range.error).get_or_insert_with(|| {
                    format!(
                        "unexpected callback for slot {slot} outside {:?}",
                        self.range.slots
                    )
                });
                return None;
            }
            let epoch = slot_to_epoch(slot);
            let shared = lock_unpoisoned(&self.range.epochs)
                .entry(epoch)
                .or_insert_with(|| Arc::new(Mutex::new(RunState::for_epoch(epoch))))
                .clone();
            self.current = Some(VerificationWorker::new(self.thread_id, shared));
        }
        self.current.as_mut()
    }
}

impl PluginWorker for RangeWorker {
    fn on_epoch(&mut self, meta: &EpochMeta) {
        if let Some(worker) = self.worker_at(meta.first_block_slot) {
            worker.on_epoch(meta);
        }
    }

    fn on_transaction(&mut self, slot: u64, tx_index: u32, tx: &Transaction) {
        if let Some(worker) = self.worker_at(slot) {
            worker.on_transaction(slot, tx_index, tx);
        }
    }

    fn on_block(&mut self, notification: &BlockNotification, entries: &[EntryRecord]) {
        if let Some(worker) = self.worker_at(notification.slot()) {
            worker.on_block(notification, entries);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn range_verifier_rejects_partial_or_missing_epochs_without_reports() {
        let verifier = RangeVerificationPlugin::default();
        let db = Arc::new(Client::default());
        assert!(
            verifier
                .on_start_range(db.clone(), 1..432_000)
                .await
                .is_err()
        );
        verifier
            .on_start_range(db.clone(), 0..864_000)
            .await
            .unwrap();
        assert!(
            verifier
                .on_finish_range(db.clone(), 0..864_000)
                .await
                .is_err()
        );
        assert!(verifier.take_reports().is_empty());
    }

    #[test]
    fn range_verifier_rejects_overlapping_spans_and_duplicate_worker_ids() {
        let mut run = RunState::for_epoch(0);
        run.end_slot_exclusive = 6;
        for (id, first, last) in [(4, 0, 2), (5, 3, 5)] {
            run.workers.push(WorkerResult {
                thread_id: id,
                counts: Counts {
                    slots: last - first + 1,
                    first_slot: Some(first),
                    last_slot: Some(last),
                    ..Counts::default()
                },
                digest: [0; 32],
                errors: vec![],
            });
        }
        assert!(validate_worker_spans(&run).is_ok());
        run.workers[1].thread_id = 4;
        assert!(validate_worker_spans(&run).is_err());
        run.workers[1].thread_id = 5;
        run.workers[1].counts.first_slot = Some(2);
        assert!(validate_worker_spans(&run).is_err());
    }
}
