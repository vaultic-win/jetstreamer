use super::*;
use jetstreamer_horizon::{
    archive::{ArchiveWriter, ArchiveWriterConfig},
    block_metas::BlockMeta,
};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

type Events = Arc<Mutex<Vec<(String, u64)>>>;

struct Recorder {
    events: Events,
    ranges: bool,
    fail_next_write: Arc<AtomicBool>,
}

impl HorizonPlugin for Recorder {
    fn name(&self) -> &'static str {
        "range-test"
    }

    fn supports_slot_ranges(&self) -> bool {
        self.ranges
    }

    fn on_start(&self, _: Arc<Client>, epoch: u64) -> PluginFuture<'_> {
        self.events.lock().unwrap().push(("start".into(), epoch));
        async { Ok(()) }.boxed()
    }

    fn on_finish(&self, _: Arc<Client>, epoch: u64) -> PluginFuture<'_> {
        self.events.lock().unwrap().push(("finish".into(), epoch));
        async { Ok(()) }.boxed()
    }

    fn on_abort_range(&self) {
        self.events.lock().unwrap().push(("abort".into(), 0));
    }

    fn spawn_worker(&self, id: usize) -> Box<dyn PluginWorker> {
        self.events
            .lock()
            .unwrap()
            .push(("worker".into(), id as u64));
        Box::new(Recorder {
            events: self.events.clone(),
            ranges: self.ranges,
            fail_next_write: self.fail_next_write.clone(),
        })
    }
}

impl PluginWorker for Recorder {
    fn on_transaction(&mut self, slot: u64, _: u32, _: &Transaction) {
        self.events
            .lock()
            .unwrap()
            .push(("transaction".into(), slot));
    }

    fn flush(&mut self, out: &Output) {
        let events = self.events.clone();
        let fail_next_write = self.fail_next_write.clone();
        out.submit(async move {
            events.lock().unwrap().push(("write".into(), 0));
            if fail_next_write.swap(false, Ordering::Relaxed) {
                return Err(clickhouse::error::Error::Custom(
                    "range write failure".into(),
                ));
            }
            Ok(())
        });
    }
}

fn archives() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (epoch, slot) in [(0, 431_999), (1, 432_000)] {
        let file = std::fs::File::create(dir.path().join(format!("epoch-{epoch}.jet"))).unwrap();
        let mut writer =
            ArchiveWriter::new(file, epoch, slot, 1, ArchiveWriterConfig::default()).unwrap();
        writer.begin_slot(slot).unwrap();
        writer.write_transaction(&Transaction::new_boxed()).unwrap();
        let mut block = BlockMeta::new_boxed();
        block.slot = slot;
        block.parent_slot = slot - 1;
        block.entry_count = 1;
        block.executed_transaction_count = 1;
        writer
            .end_slot(
                &block,
                &[EntryRecord {
                    num_hashes: 1,
                    tx_count: 1,
                }],
            )
            .unwrap();
        writer.finish().unwrap();
    }
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn range_runner_keeps_worker_over_boundary_and_finishes_after_ack() {
    let dir = archives();
    let events = Events::default();
    let mut runner = HorizonPluginRunner::new("http://localhost:8123", 1);
    runner.add_plugin(Arc::new(Recorder {
        events: events.clone(),
        ranges: true,
        fail_next_write: Arc::default(),
    }));
    let report = runner
        .run_range(JetSource::local(dir.path()), 431_999..432_001)
        .await
        .unwrap();
    assert_eq!(report.transactions, 2);
    assert_eq!(report.slots, 431_999..432_001);
    assert_eq!(report.workers, 1);
    assert_eq!(runner.outstanding_writes(), 0);
    assert_eq!(
        *events.lock().unwrap(),
        [
            ("start", 0),
            ("worker", 0),
            ("transaction", 431_999),
            ("transaction", 432_000),
            ("write", 0),
            ("finish", 1)
        ]
        .map(|(e, s)| (e.to_owned(), s))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn range_runner_requires_opt_in_before_hooks_and_propagates_insert_failure() {
    let dir = archives();
    let events = Events::default();
    let plugin = |ranges| {
        Arc::new(Recorder {
            events: events.clone(),
            ranges,
            fail_next_write: Arc::new(AtomicBool::new(true)),
        })
    };
    let mut runner = HorizonPluginRunner::new("http://localhost:8123", 1);
    runner.add_plugin(plugin(true)).add_plugin(plugin(false));
    let source = JetSource::local(dir.path());
    let err = runner
        .run_range(source.clone(), 431_999..432_001)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("does not support slot ranges"));
    assert!(events.lock().unwrap().is_empty());

    let mut runner = HorizonPluginRunner::new("http://localhost:8123", 1);
    runner.add_plugin(plugin(true));
    let err = runner
        .run_range(source.clone(), 431_999..432_001)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("range write failure"));
    assert_eq!(runner.outstanding_writes(), 0);
    assert_eq!(
        events.lock().unwrap().last(),
        Some(&("abort".to_owned(), 0))
    );
    let report = runner.run_range(source, 431_999..432_001).await.unwrap();
    assert_eq!(report.transactions, 2);
    assert_eq!(events.lock().unwrap().last(), Some(&("finish".into(), 1)));
}

#[tokio::test]
async fn range_runner_cancellation_aborts_only_plugins_that_started() {
    struct PendingStart;
    impl HorizonPlugin for PendingStart {
        fn name(&self) -> &'static str {
            "pending start"
        }
        fn supports_slot_ranges(&self) -> bool {
            true
        }
        fn on_start_range(&self, _: Arc<Client>, _: Range<u64>) -> PluginFuture<'_> {
            std::future::pending().boxed()
        }
        fn on_abort_range(&self) {
            panic!("a plugin with an unfinished start has no acquired state");
        }
        fn spawn_worker(&self, _: usize) -> Box<dyn PluginWorker> {
            unreachable!()
        }
    }
    let events = Events::default();
    let mut runner = HorizonPluginRunner::new("http://localhost:8123", 1);
    runner.add_plugin(Arc::new(Recorder {
        events: events.clone(),
        ranges: true,
        fail_next_write: Arc::default(),
    }));
    runner.add_plugin(Arc::new(PendingStart));
    let mut run = Box::pin(runner.run_range(JetSource::local("."), 1..2));
    assert!(futures_util::poll!(&mut run).is_pending());
    drop(run);
    assert_eq!(
        *events.lock().unwrap(),
        [("start".into(), 0), ("abort".into(), 0)]
    );
}
