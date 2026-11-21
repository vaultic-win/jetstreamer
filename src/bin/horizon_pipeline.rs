//! Runs horizon-native plugins over `.jet` archives — the `.jet` counterpart
//! to the main `jetstreamer` firehose→plugin CLI. Reads each epoch's archive
//! in parallel (locally or over the network via `rseek`) and persists plugin
//! output to ClickHouse.
//!
//! ```text
//! horizon-pipeline <epoch|start:end> <jet-dir-or-base-url> \
//!     [--threads N] [--slot-ranges] [--max-active-partitions N] [--clickhouse-dsn URL] [--bench|--verify-only]
//! ```
//!
//! `<jet-dir-or-base-url>` is a local directory of `epoch-<N>.jet` files, or
//! an `http(s)://` base URL serving them. `--bench` swaps the real plugins for
//! a counting-only plugin — the full framework path (dispatch, workers, flush
//! cycle) with no data written. Slot-range benchmarks report final counts and
//! throughput as one JSON line on stdout and do not start a ClickHouse server.
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use jetstreamer_firehose::epochs::epoch_to_slot_range;
use jetstreamer_firehose::firehose_horizon::{JetSource, PinnedArchives};
use jetstreamer_horizon::archive::{BlockNotification, EntryRecord};
use jetstreamer_horizon::epochs::EpochMeta;
use jetstreamer_horizon::transactions::Transaction;
use jetstreamer_plugin::horizon::{
    Consumption, HorizonPlugin, HorizonPluginRunner, Output, PluginWorker, RangeRunReport,
};
use jetstreamer_plugin::plugins::account_writes::AccountWritesPlugin;
use jetstreamer_plugin::plugins::pubkey_stats_horizon::PubkeyStatsHorizonPlugin;
use jetstreamer_plugin::plugins::verification::{
    RangeVerificationPlugin, VerificationPlugin, VerificationReport,
};

#[cfg(test)]
#[path = "horizon_pipeline/bench_tests.rs"]
mod bench_tests;

#[path = "horizon_pipeline/capacity.rs"]
mod capacity;

// jemalloc, for the same reason as jetstreamer-node: the decode path churns
// huge short-lived allocations across many threads, where glibc malloc costs
// kernel time (mmap/munmap per allocation) that grows with thread count.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const DEFAULT_DSN: &str = "http://localhost:8123";

/// Same policy as the main runner: the embedded ClickHouse helper is spawned
/// only when the DSN points at this machine.
fn should_spawn_for_dsn(dsn: &str) -> bool {
    let lower = dsn.to_ascii_lowercase();
    lower.contains("localhost") || lower.contains("127.0.0.1")
}

fn usage() -> ! {
    eprintln!(
        "usage: horizon-pipeline --archive-capacity-probe\n\
         or: horizon-pipeline <epoch|start:end> <jet-dir-or-base-url> \
         [--threads N] [--slot-ranges] [--max-active-partitions N] [--clickhouse-dsn URL] [--bench|--verify-only] \
         [--no-account-bytes|--no-account-updates] [--no-preload] [--archive-inventory PATH] [--verification-report PATH | --verification-report-dir DIR]\n\
         --verify-only runs the read-only Horizon verification plugin over \
         every decoded record and account-data byte; it does not start or \
         write to ClickHouse\n\
         --verification-report writes a new durable JSON result after successful \
         --verify-only playback of a single epoch; PATH must be absolute\n\
         --archive-inventory (with --bench or --verify-only) binds each anonymous HTTPS request to the archive ETag and length in PATH\n\
         --bench --slot-ranges prints final counting-plugin counters as JSON on stdout and skips embedded ClickHouse startup\n\
         --verification-report-dir writes epoch-N.json after each successful epoch in an existing absolute directory\n\
         --no-account-updates (with --bench): omit all account updates from plugin notifications\n\
         --no-account-bytes (with --bench): declare account-update data \
         unconsumed so the decoder skips diff reconstruction — benchmarks \
         the metadata-only fast path (update counts stay real, bytes read 0)\n\
         --no-preload (with --bench): read from disk even when the epoch \
         file would fit in RAM (metadata-only benches preload by default \
         and measure pure decode)\n\
         --slot-ranges partitions the complete range across workers; emits overall TPS every 30 seconds\n\
         --max-active-partitions limits simultaneous decoding in pinned slot-range runs; partition boundaries and worker IDs are preserved\n\
         --threads overrides JETSTREAMER_THREADS, otherwise defaults by declared plugin consumption: cores + 1/8 \
         when no plugin consumes account-update data (CPU-bound decode), \
         cores/2 when one does (memory-bandwidth-bound); preload likewise \
         auto-disables in the byte-consuming regime"
    );
    std::process::exit(2);
}

/// Invocation-wide totals the bench workers drain into at each flush.
#[derive(Default)]
struct BenchCounters {
    slots: AtomicU64,
    blocks: AtomicU64,
    txs: AtomicU64,
    tx_updates: AtomicU64,
    orphan_updates: AtomicU64,
    epoch_updates: AtomicU64,
    update_bytes: AtomicU64,
}

impl BenchCounters {
    fn range_report(
        &self,
        run: &RangeRunReport,
        consumption: Consumption,
    ) -> std::io::Result<serde_json::Value> {
        let slots = self.slots.load(Ordering::Relaxed);
        let transactions = self.txs.load(Ordering::Relaxed);
        let transaction_updates = self.tx_updates.load(Ordering::Relaxed);
        let orphan_updates = self.orphan_updates.load(Ordering::Relaxed);
        let epoch_updates = self.epoch_updates.load(Ordering::Relaxed);
        let account_data_bytes = self.update_bytes.load(Ordering::Relaxed);
        if slots != run.slots.end - run.slots.start || transactions != run.transactions {
            return Err(std::io::Error::other(
                "counting plugin totals differ from requested slots or dispatched transactions",
            ));
        }
        if !consumption.account_updates
            && [transaction_updates, orphan_updates, epoch_updates] != [0; 3]
        {
            return Err(std::io::Error::other(
                "counting plugin received unsubscribed account updates",
            ));
        }
        if !consumption.account_update_data && account_data_bytes != 0 {
            return Err(std::io::Error::other(
                "metadata-only counting plugin received account data bytes",
            ));
        }
        let seconds = run.elapsed.as_secs_f64();
        Ok(serde_json::json!({
            "schema": "horizon-range-benchmark-v1",
            "start_slot": run.slots.start, "end_slot_exclusive": run.slots.end,
            "workers": run.workers, "consume_account_updates": consumption.account_updates,
            "consume_account_bytes": consumption.account_update_data,
            "slots": slots, "blocks": self.blocks.load(Ordering::Relaxed), "transactions": transactions,
            "transaction_updates": transaction_updates, "orphan_updates": orphan_updates,
            "epoch_updates": epoch_updates, "account_updates": transaction_updates + orphan_updates + epoch_updates,
            "account_data_bytes": account_data_bytes, "elapsed_seconds": seconds,
            "overall_tps": if run.elapsed.is_zero() { 0.0 } else { transactions as f64 / seconds },
        }))
    }
}

/// `--bench` worker: counts locally on the hot path (no shared-state
/// contention) and drains into the shared totals on the framework's normal
/// flush cadence. Touches every account update's bytes so the measured rate
/// is the full decode + dispatch path; writes nothing.
#[derive(Default)]
struct BenchWorker {
    counters: Arc<BenchCounters>,
    slots: u64,
    blocks: u64,
    txs: u64,
    tx_updates: u64,
    orphan_updates: u64,
    epoch_updates: u64,
    update_bytes: u64,
}

impl PluginWorker for BenchWorker {
    fn on_epoch(&mut self, meta: &EpochMeta) {
        for (_, data) in meta.updates.iter() {
            self.epoch_updates += 1;
            self.update_bytes += data.len() as u64;
        }
    }

    fn on_transaction(&mut self, _slot: u64, _tx_index: u32, tx: &Transaction) {
        self.txs += 1;
        for (_meta, data) in tx.iter_account_updates() {
            self.tx_updates += 1;
            self.update_bytes += data.len() as u64;
        }
    }

    fn on_block(&mut self, notification: &BlockNotification, _entries: &[EntryRecord]) {
        self.slots += 1;
        if let BlockNotification::Block(meta) = notification {
            self.blocks += 1;
            for (_m, d) in meta.pre_updates.iter().chain(meta.post_updates.iter()) {
                self.orphan_updates += 1;
                self.update_bytes += d.len() as u64;
            }
        }
    }

    fn flush(&mut self, _out: &Output) {
        let c = &self.counters;
        c.slots
            .fetch_add(std::mem::take(&mut self.slots), Ordering::Relaxed);
        c.blocks
            .fetch_add(std::mem::take(&mut self.blocks), Ordering::Relaxed);
        c.txs
            .fetch_add(std::mem::take(&mut self.txs), Ordering::Relaxed);
        c.tx_updates
            .fetch_add(std::mem::take(&mut self.tx_updates), Ordering::Relaxed);
        c.orphan_updates
            .fetch_add(std::mem::take(&mut self.orphan_updates), Ordering::Relaxed);
        c.epoch_updates
            .fetch_add(std::mem::take(&mut self.epoch_updates), Ordering::Relaxed);
        c.update_bytes
            .fetch_add(std::mem::take(&mut self.update_bytes), Ordering::Relaxed);
    }
}

/// The counting-only plugin `--bench` swaps in for the real ones. Runs through
/// the standard `HorizonPluginRunner` and its normal flush lifecycle.
/// The worker creates no tables and submits no inserts.
struct BenchPlugin {
    counters: Arc<BenchCounters>,
    consumption: Consumption,
}

impl HorizonPlugin for BenchPlugin {
    fn supports_slot_ranges(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "TPS Bench"
    }

    fn spawn_worker(&self, _thread_id: usize) -> Box<dyn PluginWorker> {
        Box::new(BenchWorker {
            counters: self.counters.clone(),
            ..Default::default()
        })
    }

    fn consumption(&self) -> Consumption {
        self.consumption
    }
}

/// `MemAvailable` from `/proc/meminfo` (Linux; `None` elsewhere) — the
/// kernel's estimate of memory allocatable without swapping.
fn mem_available_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Headroom the preload leaves for decode scratches, the page cache, and
/// everything else on the box; the file is only preloaded when
/// `MemAvailable` covers its size plus this.
const PRELOAD_HEADROOM_BYTES: u64 = 48 * 1024 * 1024 * 1024;

/// Bench-only: if `epoch`'s `.jet` fits in RAM (with headroom), read it
/// fully into memory and return an in-memory source, so the measured rate
/// is pure decode with zero disk I/O. Returns `None` (with a log line
/// saying why) when it doesn't apply; the caller falls back to `src`.
async fn preload_epoch(src: &JetSource, epoch: u64) -> Option<JetSource> {
    let JetSource::LocalDir(dir) = src else {
        return None; // preloading only makes sense for local files
    };
    let path = dir.join(format!("epoch-{epoch}.jet"));
    let file_len = std::fs::metadata(&path).ok()?.len();
    let Some(available) = mem_available_bytes() else {
        log::info!("bench: no MemAvailable (non-Linux?); reading from disk");
        return None;
    };
    if available < file_len + PRELOAD_HEADROOM_BYTES {
        log::info!(
            "bench: epoch {epoch} not preloaded ({} file vs {} available); reading from disk",
            commas(file_len),
            commas(available)
        );
        return None;
    }
    log::info!(
        "bench: preloading epoch {epoch} into RAM ({} bytes)...",
        commas(file_len)
    );
    let start = Instant::now();
    let bytes = tokio::task::spawn_blocking(move || std::fs::read(&path))
        .await
        .ok()?
        .ok()?;
    let secs = start.elapsed().as_secs_f64();
    log::info!(
        "bench: preloaded epoch {epoch} in {secs:.1}s ({:.2} GB/s); decode will be disk-free",
        (bytes.len() as f64 / secs) / 1e9
    );
    Some(JetSource::in_memory(epoch, bytes))
}

/// Thousands separators for benchmark readability.
fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn parse_range(s: &str) -> (u64, u64) {
    let parse = |v: &str| v.parse::<u64>().unwrap_or_else(|_| usage());
    match s.split_once(':') {
        Some((a, b)) => (parse(a), parse(b)),
        None => {
            let e = parse(s);
            (e, e)
        }
    }
}

fn save_epoch_report(
    report: &VerificationReport,
    dir: &std::path::Path,
    source: &str,
    argv: &[String],
) -> std::io::Result<()> {
    let epoch = report.epoch;
    let temporary = dir.join(format!(".epoch-{epoch}-{}.pending", std::process::id()));
    report.write_json(&temporary, source, argv, epoch_to_slot_range(epoch))?;
    // Publish the complete, fsynced report atomically without replacing evidence.
    let published = std::fs::hard_link(&temporary, dir.join(format!("epoch-{epoch}.json")));
    std::fs::remove_file(&temporary)?;
    published?;
    std::fs::File::open(dir)?.sync_all()
}

/// Publish results only after plugin finalization and the runner's independent
/// dispatch count agree for the complete request.
fn finish_range_reports(
    verifier: &RangeVerificationPlugin,
    run: &jetstreamer_plugin::horizon::RangeRunReport,
    epochs: std::ops::RangeInclusive<u64>,
    source: &str,
    directory: Option<&std::path::Path>,
    single_file: Option<&std::path::Path>,
) -> std::io::Result<()> {
    let reports = verifier.take_reports();
    let transactions = reports.iter().try_fold(0_u64, |count, report| {
        count.checked_add(report.transactions)
    });
    if transactions != Some(run.transactions) || !reports.iter().map(|r| r.epoch).eq(epochs) {
        return Err(std::io::Error::other(
            "per-epoch verification reports disagree with the range runner",
        ));
    }
    let args = std::env::args().collect::<Vec<_>>();
    for report in reports {
        let epoch = report.epoch;
        if let Some(dir) = directory {
            save_epoch_report(&report, dir, source, &args)?;
        } else if let Some(path) = single_file {
            report.write_json(path, source, &args, epoch_to_slot_range(epoch))?;
        }
        log::info!(
            "horizon pipeline: epoch {epoch} verified, {} transactions",
            report.transactions
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    solana_logger::setup_with_default("info");

    let mut args = std::env::args().skip(1);
    let range = args.next().unwrap_or_else(|| usage());
    if range == "--post-update-capacity-probe" {
        if args.next().is_some() {
            usage();
        }
        match jetstreamer_horizon::archive::capacity_probe::post_update_capacity_probe() {
            Ok(result) => println!("{result}"),
            Err(error) => {
                eprintln!("post-update capacity probe failed: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if range == "--archive-capacity-probe" {
        if args.next().is_some() {
            usage();
        }
        match capacity::probe() {
            Ok(result) => println!("{result}"),
            Err(error) => {
                eprintln!("archive capacity probe failed: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    let location = args.next().unwrap_or_else(|| usage());
    let mut threads_override: Option<usize> = None;
    let mut max_active_partitions: Option<std::num::NonZeroUsize> = None;
    let mut dsn =
        std::env::var("JETSTREAMER_CLICKHOUSE_DSN").unwrap_or_else(|_| DEFAULT_DSN.to_string());
    let mut slot_ranges = false;
    let mut bench = false;
    let mut verify_only = false;
    let mut no_account_bytes = false;
    let mut no_account_updates = false;
    let mut no_preload = false;
    let mut verification_report = None;
    let mut report_directory = None;
    let mut archive_inventory = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--threads" => {
                threads_override = Some(
                    args.next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_else(|| usage()),
                );
            }
            "--max-active-partitions" => {
                max_active_partitions = Some(
                    args.next()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or_else(|| usage()),
                );
            }
            "--clickhouse-dsn" => dsn = args.next().unwrap_or_else(|| usage()),
            "--bench" => bench = true,
            "--slot-ranges" => slot_ranges = true,
            "--verify-only" => verify_only = true,
            "--verification-report" => {
                verification_report = Some(std::path::PathBuf::from(
                    args.next().unwrap_or_else(|| usage()),
                ));
            }
            "--verification-report-dir" => {
                report_directory = Some(std::path::PathBuf::from(
                    args.next().unwrap_or_else(|| usage()),
                ));
            }
            "--archive-inventory" => {
                archive_inventory = Some(std::path::PathBuf::from(
                    args.next().unwrap_or_else(|| usage()),
                ));
            }
            "--no-account-bytes" => no_account_bytes = true,
            "--no-account-updates" => no_account_updates = true,
            "--no-preload" => no_preload = true,
            _ => usage(),
        }
    }
    if max_active_partitions.is_some() && !(slot_ranges && archive_inventory.is_some()) {
        eprintln!("--max-active-partitions requires --slot-ranges and --archive-inventory");
        usage();
    }
    if no_account_updates && !bench {
        eprintln!("--no-account-updates only applies to --bench");
        usage();
    }
    if no_account_bytes && !bench {
        // The real plugins declare their own consumption; forcing bytes off
        // under them would silently zero account_write_stats.
        eprintln!("--no-account-bytes only applies to --bench");
        usage();
    }
    if no_preload && !bench {
        eprintln!("--no-preload only applies to --bench (preloading is bench-only)");
        usage();
    }
    if verify_only && (bench || no_account_bytes || no_preload) {
        eprintln!("--verify-only cannot be combined with benchmark-only flags");
        usage();
    }

    // First CTRL+C aborts the epoch loop (the embedded ClickHouse still gets
    // its graceful stop below); a second force-exits.
    let shutdown = Arc::new(tokio::sync::Notify::new());
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut first = true;
            while tokio::signal::ctrl_c().await.is_ok() {
                if first {
                    first = false;
                    eprintln!("CTRL+C received, shutting down... (press again to force-exit)");
                    shutdown.notify_one();
                } else {
                    eprintln!("CTRL+C received again, force-exiting");
                    std::process::exit(130);
                }
            }
        });
    }

    let (start_epoch, end_epoch) = parse_range(&range);
    if end_epoch < start_epoch || end_epoch >= u64::MAX / epoch_to_slot_range(1).0 {
        usage();
    }
    if let Some(dir) = &report_directory {
        if !verify_only || verification_report.is_some() || !dir.is_absolute() || !dir.is_dir() {
            usage();
        }
    }
    if let Some(path) = &verification_report {
        if !verify_only || start_epoch != end_epoch || !path.is_absolute() {
            eprintln!(
                "--verification-report requires --verify-only, one epoch, and an absolute path"
            );
            usage();
        }
        if path.try_exists().unwrap_or(true) {
            eprintln!("verification report path already exists or is inaccessible");
            std::process::exit(1);
        }
    }
    let src = if let Some(path) = &archive_inventory {
        if !(verify_only || bench) || !path.is_absolute() {
            usage();
        }
        let mut pins = PinnedArchives::load(&location, path).unwrap_or_else(|error| {
            eprintln!("error: invalid archive inventory: {error}");
            std::process::exit(1);
        });
        if let Some(limit) = max_active_partitions {
            pins = pins.with_max_active_partitions(limit);
        }
        JetSource::HttpPinned(pins)
    } else if location.starts_with("http://") || location.starts_with("https://") {
        JetSource::http(&location).unwrap_or_else(|err| {
            eprintln!("error: {err}");
            std::process::exit(1);
        })
    } else {
        JetSource::local(&location)
    };

    // Local DSN → spawn the embedded ClickHouse helper (binary unpacked into
    // bin/, same as the main jetstreamer runner) and wait until it's ready.
    // Range benchmarks use the normal runner and its lazy client. The counting
    // plugin never submits a query. Preserve the existing per-epoch bench setup.
    let range_bench = bench && slot_ranges;
    let spawn_clickhouse = !(verify_only || range_bench) && should_spawn_for_dsn(&dsn);
    let mut clickhouse_task = None;
    if spawn_clickhouse {
        let (mut ready_rx, clickhouse_future) =
            jetstreamer_utils::start().await.unwrap_or_else(|err| {
                eprintln!("error: failed to start embedded clickhouse: {err}");
                std::process::exit(1);
            });
        if ready_rx.recv().await.is_none() {
            eprintln!("error: clickhouse readiness channel closed unexpectedly");
            std::process::exit(1);
        }
        clickhouse_task = Some(tokio::spawn(async move {
            match clickhouse_future.await {
                Ok(()) => log::info!("ClickHouse process exited gracefully."),
                Err(()) => log::error!("ClickHouse process exited with an error."),
            }
        }));
    } else if verify_only {
        log::info!("verification-only mode; ClickHouse is disabled");
    } else if range_bench {
        log::info!("counting-only slot-range benchmark; ClickHouse is disabled");
    } else {
        log::info!("using external ClickHouse at {dsn} (no embedded spawn)");
    }

    let bench_consumption = if no_account_updates {
        Consumption::all().without_account_updates()
    } else if no_account_bytes {
        Consumption::all().without_account_update_data()
    } else {
        Consumption::all()
    };
    let bench_counters = Arc::new(BenchCounters::default());
    let verification_plugin = Arc::new(VerificationPlugin::new());
    let range_verifier = Arc::new(RangeVerificationPlugin::default());
    let plugins: Vec<Arc<dyn HorizonPlugin>> = if verify_only && slot_ranges {
        vec![range_verifier.clone()]
    } else if verify_only {
        vec![verification_plugin.clone()]
    } else if bench {
        vec![Arc::new(BenchPlugin {
            counters: bench_counters.clone(),
            consumption: bench_consumption,
        })]
    } else {
        vec![
            Arc::new(PubkeyStatsHorizonPlugin::new()),
            Arc::new(AccountWritesPlugin::new()),
        ]
    };

    // The combined consumption declaration decides the operating regime
    // (measured on a 64-core EPYC, epoch 941):
    // - metadata-only decode is CPU-bound: throughput climbs to ~cores + 1/8
    //   oversubscription (72 threads) and holds flat, and it drinks
    //   compressed input faster than the disk delivers, so preloading the
    //   epoch into RAM helps.
    // - materializing account-update data is memory-bandwidth-bound: the
    //   optimum is ~cores/2 (36 threads; more threads thrash cache below
    //   peak), input demand is well under disk speed, and a preloaded
    //   resident buffer only competes for DRAM — so no preload.
    let consumes_bytes = plugins
        .iter()
        .fold(Consumption::all().without_account_updates(), |acc, p| {
            acc.union(p.consumption())
        })
        .account_update_data;
    let threads = threads_override
        .or_else(|| {
            std::env::var("JETSTREAMER_THREADS").ok().map(|value| {
                value
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .unwrap_or_else(|| {
                        eprintln!("JETSTREAMER_THREADS must be a positive integer");
                        usage()
                    })
            })
        })
        .unwrap_or_else(|| {
            let cores = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(8);
            if consumes_bytes {
                (cores / 2).max(1)
            } else {
                cores + cores.div_ceil(8)
            }
        });
    if threads == 0 {
        usage();
    }
    let preload = !slot_ranges && bench && !no_preload && !consumes_bytes;
    if bench && !no_preload && consumes_bytes {
        log::info!(
            "bench: preload disabled (account-update data is consumed; materialized decode is \
             memory-bandwidth-bound and slower than disk feeds, so a resident buffer only \
             competes for DRAM)"
        );
    }

    let mut runner = HorizonPluginRunner::new(dsn, threads);
    for plugin in &plugins {
        runner.add_plugin(plugin.clone());
    }

    let mut failure = None;
    if slot_ranges {
        let slots = epoch_to_slot_range(start_epoch).0..epoch_to_slot_range(end_epoch).1 + 1;
        tokio::select! {
            result = runner.run_range(src.clone(), slots) => match result {
                Err(err) => failure = Some(err.to_string()),
                Ok(run) if verify_only => {
                    if let Err(err) = finish_range_reports(
                        &range_verifier,
                        &run,
                        start_epoch..=end_epoch,
                        &location,
                        report_directory.as_deref(),
                        verification_report.as_deref(),
                    ) {
                        failure = Some(format!("cannot finalize range verification: {err}"));
                    }
                }
                Ok(run) if bench => match bench_counters.range_report(&run, bench_consumption) {
                    Ok(report) => println!("{report}"),
                    Err(error) => failure = Some(format!("cannot finalize range benchmark: {error}")),
                },
                Ok(_) => {}
            },
            _ = shutdown.notified() => failure = Some("interrupted during slot-range playback".into()),
        }
    } else {
        for epoch in start_epoch..=end_epoch {
            let (lo, hi) = epoch_to_slot_range(epoch);
            log::info!(
                "horizon pipeline: epoch {epoch} (slots {lo}..={hi}) with {threads} threads"
            );
            // Bench, metadata-only: preload the epoch into RAM when it fits, so
            // the timed window below measures pure decode. The buffer is dropped
            // when the epoch's run completes, before the next preload.
            let epoch_src = if preload {
                preload_epoch(&src, epoch)
                    .await
                    .unwrap_or_else(|| src.clone())
            } else {
                src.clone()
            };
            let before = (
                bench_counters.slots.load(Ordering::Relaxed),
                bench_counters.blocks.load(Ordering::Relaxed),
                bench_counters.txs.load(Ordering::Relaxed),
                bench_counters.tx_updates.load(Ordering::Relaxed),
                bench_counters.orphan_updates.load(Ordering::Relaxed),
                bench_counters.update_bytes.load(Ordering::Relaxed),
                bench_counters.epoch_updates.load(Ordering::Relaxed),
            );
            let start = Instant::now();
            tokio::select! {
                res = runner.run(epoch_src, epoch, lo..hi + 1) => {
                    if let Err(err) = res {
                        failure = Some(format!("epoch {epoch}: {err}"));
                        break;
                    }
                }
                _ = shutdown.notified() => {
                    failure = Some(format!("interrupted by CTRL+C during epoch {epoch}"));
                    break;
                }
            }
            if let Some(dir) = &report_directory {
                let result = verification_plugin
                    .last_report()
                    .filter(|report| report.epoch == epoch)
                    .ok_or_else(|| {
                        std::io::Error::other("missing completed plugin verification result")
                    })
                    .and_then(|report| {
                        save_epoch_report(
                            &report,
                            dir,
                            &location,
                            &std::env::args().collect::<Vec<_>>(),
                        )
                    });
                if let Err(error) = result {
                    failure = Some(format!(
                        "epoch {epoch}: cannot persist plugin verification report: {error}"
                    ));
                    break;
                }
            }
            if bench {
                let elapsed = start.elapsed().as_secs_f64();
                let slots = bench_counters.slots.load(Ordering::Relaxed) - before.0;
                let blocks = bench_counters.blocks.load(Ordering::Relaxed) - before.1;
                let txs = bench_counters.txs.load(Ordering::Relaxed) - before.2;
                let tx_updates = bench_counters.tx_updates.load(Ordering::Relaxed) - before.3;
                let orphan_updates =
                    bench_counters.orphan_updates.load(Ordering::Relaxed) - before.4;
                let update_bytes = bench_counters.update_bytes.load(Ordering::Relaxed) - before.5;
                let epoch_updates = bench_counters.epoch_updates.load(Ordering::Relaxed) - before.6;
                let rate = |n: u64| commas((n as f64 / elapsed) as u64);
                log::info!(
                    "bench: epoch {epoch} done in {elapsed:.1}s — slots={} blocks={} txs={} \
                 tx_updates={} orphan_updates={} update_bytes={} epoch_updates={}",
                    commas(slots),
                    commas(blocks),
                    commas(txs),
                    commas(tx_updates),
                    commas(orphan_updates),
                    commas(update_bytes),
                    commas(epoch_updates),
                );
                log::info!(
                    "bench: epoch {epoch} rates — slots/s={} TPS={} updates/s={} update_MB/s={:.1}",
                    rate(slots),
                    rate(txs),
                    rate(tx_updates + orphan_updates + epoch_updates),
                    (update_bytes as f64 / elapsed) / 1_000_000.0,
                );
            } else {
                log::info!("horizon pipeline: epoch {epoch} complete");
            }
        }
    }

    // If the run was aborted mid-epoch, the cancelled run's detached writer
    // keeps draining submitted inserts in the background; give it a bounded
    // window to finish (acks are durable, so completed means persisted)
    // before stopping the server it is writing to. A graceful completion has
    // already drained to zero, so this is a no-op then.
    let mut waited = std::time::Duration::ZERO;
    const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(15);
    while runner.outstanding_writes() > 0 && waited < DRAIN_GRACE {
        if waited.is_zero() {
            log::info!(
                "draining {} outstanding clickhouse write(s) before shutdown...",
                runner.outstanding_writes()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        waited += std::time::Duration::from_millis(200);
    }
    let abandoned = runner.outstanding_writes();
    if abandoned > 0 {
        log::warn!(
            "abandoning {abandoned} unacknowledged clickhouse write(s) after {}s drain grace",
            DRAIN_GRACE.as_secs()
        );
    }

    // Stop the embedded server before exiting either way, so data is flushed
    // and the port is released.
    if spawn_clickhouse {
        jetstreamer_utils::stop().await;
        if let Some(task) = clickhouse_task {
            let _ = task.await;
        }
    }
    if let Some(err) = failure {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
    if let Some(path) = verification_report.filter(|_| !slot_ranges) {
        let result = verification_plugin
            .last_report()
            .filter(|report| report.epoch == start_epoch)
            .ok_or_else(|| std::io::Error::other("missing completed plugin verification result"))
            .and_then(|report| {
                report.write_json(
                    &path,
                    &location,
                    &std::env::args().collect::<Vec<_>>(),
                    epoch_to_slot_range(start_epoch),
                )
            });
        if let Err(err) = result {
            eprintln!("error: cannot persist plugin verification report: {err}");
            std::process::exit(1);
        }
    }
}
