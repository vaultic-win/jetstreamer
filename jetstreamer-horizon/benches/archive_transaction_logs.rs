//! Offline benchmark for transaction scratch reuse in the archive decoder.
//! Fixtures are built before timing; repeated reads exercise the same bucket.
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use jetstreamer_horizon::archive::{
    ArchiveReader, ArchiveWriter, ArchiveWriterConfig, Compression, EntryRecord, SlotVisitor,
};
use jetstreamer_horizon::block_metas::BlockMeta;
use jetstreamer_horizon::transactions::{LogMessages, Transaction};

const TRANSACTIONS: u32 = 256;

#[derive(Clone, Copy)]
enum Pattern {
    Populated,
    Empty,
    Absent,
    Mixed,
}

fn fixture(pattern: Pattern) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(
        Vec::new(),
        0,
        0,
        1,
        ArchiveWriterConfig {
            compression: Compression::None,
            ..Default::default()
        },
    )
    .unwrap();
    let mut tx = Transaction::new_boxed();
    writer.begin_slot(0).unwrap();
    for index in 0..TRANSACTIONS {
        let kind = match pattern {
            Pattern::Populated => 0,
            Pattern::Empty => 1,
            Pattern::Absent => 2,
            Pattern::Mixed => index % 4,
        };
        if kind == 2 {
            tx.log_messages = None;
        } else {
            let logs = tx.log_messages.get_or_insert_with(LogMessages::default);
            logs.clear();
            if kind != 1 {
                logs.push(b"Program example invoke [1]").unwrap();
                logs.push(b"Program log: deterministic archive benchmark")
                    .unwrap();
            }
        }
        tx.fee = u64::from(index);
        writer.write_transaction(&tx).unwrap();
    }
    let mut block = BlockMeta::new_boxed();
    block.executed_transaction_count = u64::from(TRANSACTIONS);
    writer
        .end_slot(
            &block,
            &[EntryRecord {
                num_hashes: 1,
                tx_count: TRANSACTIONS,
            }],
        )
        .unwrap();
    writer.finish().unwrap().0
}

#[derive(Default)]
struct Count(u32);

impl SlotVisitor for Count {
    fn on_transaction(&mut self, _slot: u64, _index: u32, tx: &Transaction) {
        black_box(tx.fee);
        black_box(tx.log_messages.as_ref().map(LogMessages::data_len));
        self.0 += 1;
    }
}

fn bench_logs(c: &mut Criterion) {
    let mut group = c.benchmark_group("archive/transaction_logs");
    group.throughput(Throughput::Elements(u64::from(TRANSACTIONS)));
    for (name, pattern) in [
        ("populated", Pattern::Populated),
        ("empty", Pattern::Empty),
        ("absent", Pattern::Absent),
        ("mixed", Pattern::Mixed),
    ] {
        let bytes = fixture(pattern);
        let mut reader = ArchiveReader::open(std::io::Cursor::new(bytes)).unwrap();
        group.bench_function(name, |b| {
            b.iter(|| {
                let mut count = Count::default();
                reader.read_bucket(0, &mut count).unwrap();
                assert_eq!(count.0, TRANSACTIONS);
                black_box(count.0);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_logs);
criterion_main!(benches);
