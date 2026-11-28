use super::*;
use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{ArchiveWriter, ArchiveWriterConfig},
    block_metas::BlockMeta,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn range_benchmark_counts_all_update_sources_with_and_without_payloads() {
    let mut writer =
        ArchiveWriter::new(Vec::new(), 0, 0, 2, ArchiveWriterConfig::default()).unwrap();
    writer.begin_slot(0).unwrap();
    let update = |key: u8| AccountUpdateView {
        pubkey: [key; 32].into(),
        owner: [7; 32].into(),
        lamports: 8,
        rent_epoch: 0,
        executable: false,
        write_version: u64::from(key),
        data: b"payload",
    };
    let mut epoch = EpochMeta::new_boxed();
    epoch.slot_count = 2;
    epoch.updates.push(&update(1)).unwrap();
    writer.write_epoch_meta(&epoch).unwrap();
    writer.write_orphan_update(&update(2)).unwrap();
    let mut tx = Transaction::new_boxed();
    tx.signatures.push(Default::default());
    tx.push_account_update(&update(3)).unwrap();
    writer.write_transaction(&tx).unwrap();
    writer.write_orphan_update(&update(4)).unwrap();
    let mut block = BlockMeta::new_boxed();
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
    writer.write_skipped_slot(1).unwrap();
    let (bytes, _) = writer.finish().unwrap();
    let src = JetSource::in_memory(0, bytes);
    for consumption in [
        Consumption::all().without_account_updates(),
        Consumption::all().without_account_update_data(),
        Consumption::all(),
    ] {
        let present = u64::from(consumption.account_updates);
        let consume_account_bytes = consumption.account_update_data;
        let counters = Arc::new(BenchCounters::default());
        let mut runner = HorizonPluginRunner::new("http://127.0.0.1:1", 2);
        runner.add_plugin(Arc::new(BenchPlugin {
            counters: counters.clone(),
            consumption,
        }));
        let run = runner.run_range(src.clone(), 0..2).await.unwrap();
        let report = counters.range_report(&run, consumption).unwrap();
        assert_eq!(report["slots"], 2);
        assert_eq!(report["blocks"], 1);
        assert_eq!(report["transactions"], 1);
        assert_eq!(report["transaction_updates"], present);
        assert_eq!(report["orphan_updates"], 2 * present);
        assert_eq!(report["epoch_updates"], present);
        assert_eq!(report["account_updates"], 4 * present);
        assert_eq!(
            report["account_data_bytes"],
            if consume_account_bytes { 28 } else { 0 }
        );
        assert_eq!(report["workers"], 2);
        assert_eq!(
            report["consume_account_updates"],
            consumption.account_updates
        );
        assert_eq!(report["consume_account_bytes"], consume_account_bytes);
        assert!(report["overall_tps"].as_f64().unwrap() > 0.0);
        let mut wrong = run.clone();
        wrong.transactions += 1;
        assert!(counters.range_report(&wrong, consumption).is_err());
        wrong = run;
        wrong.slots.end += 1;
        assert!(counters.range_report(&wrong, consumption).is_err());
    }
}
