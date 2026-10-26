//! Read-back integrity check for a horizon archive (`.jet`) file.
//!
//! Opens the archive (validating magic, header, footer, bucket index, and
//! prime-table compatibility), then streams every slot frame through the
//! reader. Streaming forces each bucket's xxh64 checksum to be verified on
//! load and checks both parent fields across canonical blocks. Every
//! transaction and account-update blob is fully
//! decoded (the diff decoder reconstructs account data), so a clean run is
//! end-to-end proof the file round-trips.
//!
//! Tallies block/skipped/transaction/orphan-update/epoch counts so they can
//! be compared against the writer's `horizon archive complete: …` line.
//!
//! Usage:
//! `cargo run --release -p jetstreamer-horizon --example verify_archive -- <path> [max_slots]`
//!
//! Use `--chain <path>...` for strict verification of ordered archives. It
//! carries the final canonical slot and blockhash across every file boundary.
//! Add `--segment` when verifying a proper subset of a larger ordered chain:
//! the first archive's incoming anchor and the last archive's trailing skipped
//! slots are deliberately deferred, while every boundary inside the segment
//! remains mandatory. A segment must contain at least two archives.
//! A parallel release audit may pair one successful non-full `--chain` pass
//! with `--full --internal-full` on every individual archive. The latter
//! verifies all within-archive structure and PoH while the former independently
//! proves the boundaries that individual jobs cannot share.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Cursor, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use jetstreamer_horizon::account_updates::AccountUpdateView;
use jetstreamer_horizon::archive::{
    ArchiveReader, ArchiveWriter, ArchiveWriterConfig, BlockNotification, Compression, EntryRecord,
    EpochMeta, PayloadByteStats, SlotVisitor,
};
use jetstreamer_horizon::block_metas::BlockMeta;
use jetstreamer_horizon::transactions::Transaction;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_hash::Hash;

// Reuse the historical runtime's differential-tested SHA-NI implementation
// for production verifier builds. PoH wire semantics are unchanged across
// the historical releases covered by Horizon.
#[cfg(not(test))]
#[path = "../../historical-runtime/v1_0_8/worker/src/poh_backend.rs"]
#[allow(
    dead_code,
    unexpected_cfgs,
    unsafe_op_in_unsafe_fn,
    clippy::chunks_exact_to_as_chunks,
    clippy::needless_borrow
)]
#[rustfmt::skip]
mod fast_poh;

// Keep this example's unit tests independent of the historical worker's own
// old-Solana test dependencies. Those tests exercise the same wrapper against
// `solana_entry::entry::next_hash`; release builds use the backend above.
#[cfg(test)]
mod fast_poh {
    use sha2::{Digest, Sha256};

    fn digest(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }

    pub fn next_hash(
        current: [u8; 32],
        num_hashes: u64,
        transaction_mixin: Option<[u8; 32]>,
    ) -> [u8; 32] {
        let mut current = current;
        let ordinary = if transaction_mixin.is_some() {
            num_hashes.saturating_sub(1)
        } else {
            num_hashes
        };
        for _ in 0..ordinary {
            current = digest(&[&current]);
        }
        transaction_mixin.map_or_else(|| current, |mixin| digest(&[&current, &mixin]))
    }
}

struct Tally {
    epochs: u64,
    blocks: u64,
    skipped: u64,
    transactions: u64,
    tx_account_updates: u64,
    orphan_updates: u64,
    entries: u64,
    rewards: u64,
    /// Reconstructed (raw, post-diff-decode) account-data bytes across all
    /// updates — the actual account-state volume the archive represents.
    raw_account_data_bytes: u64,
    /// Running totals to spot-check internal consistency.
    block_meta_tx_count: u64,
    last_slot: Option<u64>,
    /// Blockhash of the last decoded block, for soft chain-continuity checks.
    last_blockhash: Option<Hash>,
    /// Chain discontinuities found: (block slot, expected parent, actual parent).
    chain_breaks: Vec<(u64, Hash, Hash)>,
    /// Live-throughput tracking.
    start: Instant,
    last_report: Instant,
    last_report_txs: u64,
    slots_seen: u64,
    /// Total slot frames this run will read, for ETA.
    target_slots: u64,
}

impl Default for Tally {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            epochs: 0,
            blocks: 0,
            skipped: 0,
            transactions: 0,
            tx_account_updates: 0,
            orphan_updates: 0,
            entries: 0,
            rewards: 0,
            raw_account_data_bytes: 0,
            block_meta_tx_count: 0,
            last_slot: None,
            last_blockhash: None,
            chain_breaks: Vec::new(),
            start: now,
            last_report: now,
            last_report_txs: 0,
            slots_seen: 0,
            target_slots: 0,
        }
    }
}

/// Formats an integer with thousands separators (e.g. `1234567` → `1,234,567`).
fn commas(n: u64) -> String {
    let s = n.to_string();
    let len = s.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Formats a duration in seconds as `HH:MM:SS` (or `--:--:--` when unknown).
fn fmt_hms(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "--:--:--".to_string();
    }
    let s = secs as u64;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

/// Prints the transaction vs account-state payload-byte split + ratio.
fn report_byte_breakdown(bytes: PayloadByteStats, raw_account_data_bytes: u64) {
    let total = bytes.total().max(1);
    let pct = |b: u64| b as f64 * 100.0 / total as f64;
    println!("\n=== payload byte breakdown (uncompressed: deduped + diff-encoded, pre-zstd) ===");
    println!(
        "  transaction-field bytes: {:>16} ({:.1}%)",
        bytes.transaction_bytes,
        pct(bytes.transaction_bytes)
    );
    println!(
        "  account-update bytes:    {:>16} ({:.1}%)",
        bytes.account_update_bytes,
        pct(bytes.account_update_bytes)
    );
    println!(
        "  other (meta/entries):    {:>16} ({:.1}%)",
        bytes.other_bytes,
        pct(bytes.other_bytes)
    );
    println!("  total payload:           {:>16}", bytes.total());
    if bytes.transaction_bytes > 0 {
        println!(
            "  tx : account-state ratio (payload bytes): 1 : {:.2}",
            bytes.account_update_bytes as f64 / bytes.transaction_bytes as f64
        );
    }
    println!("  reconstructed (raw) account data: {raw_account_data_bytes} bytes");
    if bytes.account_update_bytes > 0 {
        println!(
            "  account-data dedupe+diff ratio (raw / in-archive): {:.1}x",
            raw_account_data_bytes as f64 / bytes.account_update_bytes as f64
        );
    }
}

/// Prints blockhash-chain continuity (linkage) breaks, separating genuine
/// mismatches from writer-resume artifacts (a zeroed `parent_blockhash` is the
/// stream's `Hash::default()` placeholder, stamped by the first block written
/// after a mid-epoch (re)start. The non-genesis chain never contains a zero
/// parent.
/// Returns the total number of breaks. Historical zero-parent placeholders are
/// identified separately, but they remain metadata failures.
fn report_chain_breaks(breaks: &[(u64, Hash, Hash)], blocks: u64) -> usize {
    let (artifacts, genuine): (Vec<_>, Vec<_>) = breaks
        .iter()
        .partition(|(_, _, got)| *got == Hash::default());
    println!("\n=== chain continuity ===");
    if breaks.is_empty() {
        println!(
            "  blockhash chain intact across all {} blocks",
            commas(blocks)
        );
        return 0;
    }
    if !genuine.is_empty() {
        println!(
            "  {} genuine chain break(s) — a block's parent_blockhash names a hash the \
             previous block in the archive does not have:",
            commas(genuine.len() as u64)
        );
        for (slot, exp, got) in genuine.iter().take(20) {
            println!("    slot {slot}: parent={got} but previous block hash was {exp}");
        }
        if genuine.len() > 20 {
            println!("    … and {} more", genuine.len() - 20);
        }
        println!(
            "  (the parent hash points at a block this archive does not contain — e.g. a slot \
             recorded as leader-skipped that the chain says had a real block. Genuine data gap.)"
        );
    }
    if !artifacts.is_empty() {
        println!(
            "  {} resume artifact(s) — parent_blockhash is zeroed (the writer's stream \
             (re)started at this slot and did not know the parent hash):",
            commas(artifacts.len() as u64)
        );
        for (slot, exp, _) in artifacts.iter().take(20) {
            println!("    slot {slot}: parent=zeroed; actual previous block hash was {exp}");
        }
        if artifacts.len() > 20 {
            println!("    … and {} more", artifacts.len() - 20);
        }
        println!(
            "  (blocks on both sides are present and decode; this historical metadata \
             placeholder is still counted as a verification failure.)"
        );
    }
    breaks.len()
}

impl SlotVisitor for Tally {
    fn on_epoch(&mut self, meta: &EpochMeta) {
        self.epochs += 1;
        eprintln!(
            "[verify] epoch notification: epoch={} start_slot={} slot_count={} first_block_slot={} updates={}",
            meta.epoch,
            meta.start_slot,
            meta.slot_count,
            meta.first_block_slot,
            meta.updates.len(),
        );
        self.orphan_updates += meta.updates.len() as u64;
        for (_, data) in meta.updates.iter() {
            self.raw_account_data_bytes += data.len() as u64;
        }
    }

    fn on_transaction(&mut self, _slot: u64, _tx_index: u32, tx: &Transaction) {
        self.transactions += 1;
        self.tx_account_updates += tx.account_updates().len() as u64;
        for (_, data) in tx.iter_account_updates() {
            self.raw_account_data_bytes += data.len() as u64;
        }
    }

    fn on_block(&mut self, notification: &BlockNotification, entries: &[EntryRecord]) {
        // Monotonic-slot sanity (the frame headers are authoritative).
        let slot = notification.slot();
        if let Some(last) = self.last_slot {
            assert!(
                slot > last,
                "slot frames not monotonic: {slot} after {last}"
            );
        }
        self.last_slot = Some(slot);

        match notification {
            BlockNotification::Skipped(_) => self.skipped += 1,
            BlockNotification::Block(meta) => {
                self.blocks += 1;
                self.entries += entries.len() as u64;
                self.rewards += meta.rewards.len() as u64;
                self.orphan_updates += meta.pre_updates.len() as u64;
                self.orphan_updates += meta.post_updates.len() as u64;
                for (_, data) in meta.pre_updates.iter().chain(meta.post_updates.iter()) {
                    self.raw_account_data_bytes += data.len() as u64;
                }
                self.block_meta_tx_count += meta.executed_transaction_count;

                // Soft blockhash-chain continuity: collect breaks instead of
                // aborting, so the whole archive is verified in one pass and
                // every discontinuity is reported (e.g. a slot recorded as
                // skipped that the chain says had a real block).
                if let Some(prev) = self.last_blockhash
                    && prev != Hash::default()
                    && meta.parent_blockhash != prev
                {
                    self.chain_breaks
                        .push((meta.slot, prev, meta.parent_blockhash));
                }
                self.last_blockhash = Some(meta.blockhash);
            }
        }

        self.slots_seen += 1;
        if self.last_report.elapsed().as_secs_f64() >= 3.0 {
            let now = Instant::now();
            let window = now.duration_since(self.last_report).as_secs_f64();
            let inst_tps = (self.transactions - self.last_report_txs) as f64 / window;
            let total_elapsed = self.start.elapsed().as_secs_f64().max(0.001);
            let avg_tps = self.transactions as f64 / total_elapsed;
            let pct = if self.target_slots > 0 {
                self.slots_seen as f64 * 100.0 / self.target_slots as f64
            } else {
                0.0
            };
            let slot_rate = self.slots_seen as f64 / total_elapsed;
            let remaining = self.target_slots.saturating_sub(self.slots_seen);
            let eta = remaining as f64 / slot_rate.max(1e-9);
            eprintln!(
                "[verify] {:.1}% | slot {} | {} slots, {} txs | decode tps: {} (inst) / {} (avg) | eta {}",
                pct,
                slot,
                commas(self.slots_seen),
                commas(self.transactions),
                commas(inst_tps.round() as u64),
                commas(avg_tps.round() as u64),
                fmt_hms(eta),
            );
            self.last_report = now;
            self.last_report_txs = self.transactions;
        }
    }
}

// ──────────────────────────── --full: PoH recompute ────────────────────────
//
// Full mode verifies the archive by recomputing every block's PoH hash
// from its stored `parent_blockhash`, folding `num_hashes` per entry and mixing
// in each entry's transaction signatures exactly as Solana does. Two phases:
//   1. per-block recompute (each block uses only its
//      own stored parent_blockhash + entries + transactions), then
//   2. a linkage pass: each block's parent fields must equal the previous
//      canonical block's slot and stored blockhash. The first block is anchored
//      by an explicit chain point or the slot-zero genesis sentinel.

use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;

/// Recomputes a block's blockhash from `parent` by folding each entry's
/// `num_hashes` and mixing in that entry's transaction signatures, using
/// Solana's canonical [`next_hash`](solana_entry::entry::next_hash). `sigs` is
/// the block's per-transaction signature lists in slot order.
fn recompute_blockhash(
    parent: &Hash,
    entries: &[EntryRecord],
    sigs: &[Vec<Signature>],
) -> Option<Hash> {
    let mut poh = *parent;
    let mut idx = 0usize;
    for entry in entries {
        let n = entry.tx_count as usize;
        let end = idx.checked_add(n)?;
        let entry_txs: Vec<VersionedTransaction> = sigs
            .get(idx..end)?
            .iter()
            .map(|s| VersionedTransaction {
                signatures: s.clone(),
                message: VersionedMessage::default(), // unused: only signatures are hashed
            })
            .collect();
        idx = end;
        let transaction_mixin = (!entry_txs.is_empty())
            .then(|| solana_entry::entry::hash_transactions(&entry_txs).to_bytes());
        poh = Hash::new_from_array(fast_poh::next_hash(
            poh.to_bytes(),
            entry.num_hashes,
            transaction_mixin,
        ));
    }
    (idx == sigs.len()).then_some(poh)
}

/// Recomputed identity of one block, for the linkage pass.
#[derive(Clone, Copy, Debug)]
struct BlockHashes {
    slot: u64,
    parent_slot: u64,
    parent_blockhash: Hash,
    blockhash: Hash,
    poh_ok: bool,
    /// Full-mode PoH could not be recomputed: the stored parent hash is the
    /// writer's zeroed resume placeholder, so there is no seed to fold from.
    poh_unseeded: bool,
    /// Slot zero starts from the genesis bank rather than an ordinary prior
    /// block. Its zero parent is a protocol sentinel, not a PoH seed from
    /// which the slot's terminal blockhash can be recomputed.
    genesis_poh_sentinel: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChainPoint {
    slot: u64,
    blockhash: Hash,
}

#[derive(Debug, PartialEq, Eq)]
struct ParentSlotMismatch {
    slot: u64,
    expected: Option<u64>,
    actual: u64,
}

fn genesis_sentinel(blocks: &[BlockHashes]) -> Option<ChainPoint> {
    blocks
        .first()
        .filter(|block| block.slot == 0)
        .map(|_| ChainPoint {
            slot: 0,
            blockhash: Hash::default(),
        })
}

fn is_genesis_poh_sentinel(slot: u64, parent_slot: u64, parent_blockhash: &Hash) -> bool {
    slot == 0 && parent_slot == 0 && *parent_blockhash == Hash::default()
}

fn find_parent_slot_mismatches(
    blocks: &[BlockHashes],
    initial_parent: Option<ChainPoint>,
) -> Vec<ParentSlotMismatch> {
    let mut mismatches = Vec::new();
    let mut previous = initial_parent;
    for block in blocks {
        let expected = previous.map(|point| point.slot);
        let invalid = expected.map_or(block.parent_slot >= block.slot, |expected| {
            block.parent_slot != expected
        });
        if invalid {
            mismatches.push(ParentSlotMismatch {
                slot: block.slot,
                expected,
                actual: block.parent_slot,
            });
        }
        previous = Some(ChainPoint {
            slot: block.slot,
            blockhash: block.blockhash,
        });
    }
    mismatches
}

fn find_hash_link_breaks(
    blocks: &[BlockHashes],
    initial_parent: Option<ChainPoint>,
) -> Vec<(u64, Hash, Hash)> {
    let mut breaks = Vec::new();
    let mut previous = initial_parent;
    for block in blocks {
        if let Some(expected) = previous
            && block.parent_blockhash != expected.blockhash
        {
            breaks.push((block.slot, expected.blockhash, block.parent_blockhash));
        }
        previous = Some(ChainPoint {
            slot: block.slot,
            blockhash: block.blockhash,
        });
    }
    breaks
}

#[derive(Debug, PartialEq, Eq)]
struct BlockCountMismatch {
    slot: u64,
    decoded_transactions: u64,
    metadata_transactions: u64,
    entry_transactions: Option<u64>,
    decoded_entries: u64,
    metadata_entries: u64,
}

fn block_count_mismatch(
    slot: u64,
    decoded_transactions: u64,
    metadata_transactions: u64,
    metadata_entries: u64,
    entries: &[EntryRecord],
) -> Option<BlockCountMismatch> {
    let entry_transactions = entries.iter().try_fold(0u64, |total, entry| {
        total.checked_add(u64::from(entry.tx_count))
    });
    let decoded_entries = entries.len() as u64;
    (metadata_transactions != decoded_transactions
        || entry_transactions != Some(decoded_transactions)
        || metadata_entries != decoded_entries)
        .then_some(BlockCountMismatch {
            slot,
            decoded_transactions,
            metadata_transactions,
            entry_transactions,
            decoded_entries,
            metadata_entries,
        })
}

fn exact_slot_counts(
    declared: u64,
    visited: u64,
    blocks: u64,
    skipped: u64,
    thread_ranges_complete: bool,
) -> bool {
    thread_ranges_complete && visited == declared && blocks.checked_add(skipped) == Some(declared)
}

/// Per-thread scan visitor. Always accumulates counts + per-block identities
/// (for the linkage pass); in `--full` mode it additionally buffers each
/// block's transaction signatures and recomputes its PoH hash.
#[derive(Default)]
struct ScanVisitor {
    full: bool,
    epochs: u64,
    skipped: u64,
    transactions: u64,
    tx_account_updates: u64,
    orphan_updates: u64,
    entries: u64,
    rewards: u64,
    raw_account_data_bytes: u64,
    block_meta_tx_count: u64,
    block_hashes: Vec<BlockHashes>,
    count_mismatches: Vec<BlockCountMismatch>,
    current_block_transactions: u64,
    /// `--full` only: current block's per-tx signature lists, in slot order.
    cur_sigs: Vec<Vec<Signature>>,
    progress: Option<Arc<AtomicU64>>,
}

impl ScanVisitor {
    fn new(full: bool, progress: Option<Arc<AtomicU64>>) -> Self {
        Self {
            full,
            progress,
            ..Default::default()
        }
    }

    fn merge(&mut self, o: ScanVisitor) {
        self.epochs += o.epochs;
        self.skipped += o.skipped;
        self.transactions += o.transactions;
        self.tx_account_updates += o.tx_account_updates;
        self.orphan_updates += o.orphan_updates;
        self.entries += o.entries;
        self.rewards += o.rewards;
        self.raw_account_data_bytes += o.raw_account_data_bytes;
        self.block_meta_tx_count += o.block_meta_tx_count;
        self.block_hashes.extend(o.block_hashes);
        self.count_mismatches.extend(o.count_mismatches);
    }
}

impl SlotVisitor for ScanVisitor {
    fn on_epoch(&mut self, meta: &EpochMeta) {
        self.epochs += 1;
        self.orphan_updates += meta.updates.len() as u64;
        for (_, data) in meta.updates.iter() {
            self.raw_account_data_bytes += data.len() as u64;
        }
    }

    fn on_transaction(&mut self, _slot: u64, _tx_index: u32, tx: &Transaction) {
        self.transactions += 1;
        self.current_block_transactions += 1;
        self.tx_account_updates += tx.account_updates().len() as u64;
        for (_, data) in tx.iter_account_updates() {
            self.raw_account_data_bytes += data.len() as u64;
        }
        if self.full {
            self.cur_sigs.push(tx.signatures.as_slice().to_vec());
        }
    }

    fn on_block(&mut self, notification: &BlockNotification, entries: &[EntryRecord]) {
        match notification {
            BlockNotification::Skipped(_) => self.skipped += 1,
            BlockNotification::Block(meta) => {
                self.entries += entries.len() as u64;
                self.rewards += meta.rewards.len() as u64;
                self.orphan_updates += meta.pre_updates.len() as u64;
                self.orphan_updates += meta.post_updates.len() as u64;
                for (_, data) in meta.pre_updates.iter().chain(meta.post_updates.iter()) {
                    self.raw_account_data_bytes += data.len() as u64;
                }
                self.block_meta_tx_count += meta.executed_transaction_count;
                if let Some(mismatch) = block_count_mismatch(
                    meta.slot,
                    self.current_block_transactions,
                    meta.executed_transaction_count,
                    meta.entry_count,
                    entries,
                ) {
                    self.count_mismatches.push(mismatch);
                }
                let genesis_poh_sentinel = self.full
                    && is_genesis_poh_sentinel(meta.slot, meta.parent_slot, &meta.parent_blockhash);
                let poh_unseeded =
                    self.full && meta.slot != 0 && meta.parent_blockhash == Hash::default();
                let poh_ok = !self.full
                    || genesis_poh_sentinel
                    || poh_unseeded
                    || recompute_blockhash(&meta.parent_blockhash, entries, &self.cur_sigs)
                        == Some(meta.blockhash);
                self.block_hashes.push(BlockHashes {
                    slot: meta.slot,
                    parent_slot: meta.parent_slot,
                    parent_blockhash: meta.parent_blockhash,
                    blockhash: meta.blockhash,
                    poh_ok,
                    poh_unseeded,
                    genesis_poh_sentinel,
                });
            }
        }
        if self.full {
            self.cur_sigs.clear();
        }
        self.current_block_transactions = 0;
        if let Some(p) = &self.progress {
            p.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
struct ScanOutcome {
    ok: bool,
    anchored: bool,
    epoch: u64,
    slot_start: u64,
    slot_count: u64,
    terminal: Option<ChainPoint>,
    last_block_slot: Option<u64>,
}

fn anchor_requirement_satisfied(anchored: bool, require_anchor: bool) -> bool {
    anchored || !require_anchor
}

fn tail_requirement_satisfied(
    last_block_slot: Option<u64>,
    end_slot_exclusive: u64,
    require_tail: bool,
) -> bool {
    !require_tail || last_block_slot == end_slot_exclusive.checked_sub(1)
}

/// Parallel verification across `threads`: each thread scans a disjoint bucket
/// range (counts, byte stats, per-block identities); in `full` mode it also
/// recomputes every block's PoH. After merging, a sequential linkage pass
/// checks both parent fields from the caller-provided anchor (or the slot-zero
/// genesis sentinel). The returned terminal point can anchor the next archive.
fn run_scan(
    path: &str,
    threads: usize,
    full: bool,
    expected_parent: Option<ChainPoint>,
    require_anchor: bool,
) -> ScanOutcome {
    run_scan_with_provenance(path, threads, full, expected_parent, require_anchor, None)
}

fn run_scan_with_provenance(
    path: &str,
    threads: usize,
    full: bool,
    expected_parent: Option<ChainPoint>,
    require_anchor: bool,
    expected_provenance_sha256: Option<&str>,
) -> ScanOutcome {
    let (slot_start, slot_count, bucket_slots, bucket_count, epoch, coverage_ok) = {
        let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
        let mut r = ArchiveReader::open(BufReader::with_capacity(1 << 20, file))
            .unwrap_or_else(|e| panic!("open archive: {e}"));
        validate_provenance_expectation(&r, expected_provenance_sha256)
            .unwrap_or_else(|error| panic!("validate archive provenance: {error}"));
        let h = r.header().clone();
        let coverage_ok = r
            .has_complete_slot_coverage()
            .unwrap_or_else(|e| panic!("validate slot coverage: {e}"));
        (
            h.slot_start,
            h.slot_count,
            h.bucket_slots as u64,
            r.bucket_count() as u64,
            h.epoch,
            coverage_ok,
        )
    };
    let threads = threads.max(1).min(bucket_count.max(1) as usize);
    let mode = if full { "full PoH verify" } else { "verify" };
    println!(
        "{mode}: epoch={epoch} slot_start={slot_start} slot_count={slot_count} \
         buckets={bucket_count} threads={threads}"
    );

    if !coverage_ok {
        println!("\nRESULT: FAIL: bucket headers do not densely cover the declared slot range");
        return ScanOutcome {
            ok: false,
            anchored: expected_parent.is_some(),
            epoch,
            slot_start,
            slot_count,
            terminal: expected_parent,
            last_block_slot: None,
        };
    }

    let progress = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let done = Arc::new(AtomicU64::new(0));
    let monitor = {
        let progress = progress.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            while done.load(Ordering::Relaxed) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let n = progress.load(Ordering::Relaxed);
                let el = start.elapsed().as_secs_f64().max(0.001);
                let rate = n as f64 / el;
                let eta = (slot_count.saturating_sub(n)) as f64 / rate.max(1e-9);
                eprintln!(
                    "[verify] {:.1}% | {} / {} slots | {} slots/s | eta {}",
                    n as f64 * 100.0 / slot_count.max(1) as f64,
                    commas(n),
                    commas(slot_count),
                    commas(rate.round() as u64),
                    fmt_hms(eta),
                );
            }
        })
    };

    // Parallel scan over disjoint bucket ranges. Each block is verified using
    // only its own stored data, so phase 1 needs no cross-thread coordination.
    let per_thread = bucket_count.div_ceil(threads as u64);
    let range_end = slot_start
        .checked_add(slot_count)
        .expect("validated archive slot range");
    let results: Vec<(ScanVisitor, PayloadByteStats, u64, u64)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads as u64)
            .filter_map(|t| {
                let b_start = t * per_thread;
                if b_start >= bucket_count {
                    return None;
                }
                let b_count = per_thread.min(bucket_count - b_start);
                let sub_start = slot_start + b_start * bucket_slots;
                let sub_count = (b_count * bucket_slots).min(range_end - sub_start);
                let path = path.to_string();
                let progress = progress.clone();
                Some(scope.spawn(move || {
                    let file = std::fs::File::open(&path).expect("open");
                    let mut reader = ArchiveReader::open(BufReader::with_capacity(8 << 20, file))
                        .expect("open archive");
                    let mut v = ScanVisitor::new(full, Some(progress));
                    let visited = reader
                        .read_slots(sub_start, sub_count, &mut v)
                        .unwrap_or_else(|e| panic!("read_slots failed: {e}"));
                    let bytes = reader.payload_byte_stats();
                    (v, bytes, visited, sub_count)
                }))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .collect()
    });
    done.store(1, Ordering::Relaxed);
    let _ = monitor.join();

    // Merge counts, byte stats, and per-block identities.
    let mut scan = ScanVisitor::new(full, None);
    let mut byte_stats = PayloadByteStats::default();
    let mut visited_total = 0u64;
    let mut thread_ranges_complete = true;
    for (v, bs, visited, expected) in results {
        byte_stats.transaction_bytes += bs.transaction_bytes;
        byte_stats.account_update_bytes += bs.account_update_bytes;
        byte_stats.other_bytes += bs.other_bytes;
        scan.merge(v);
        visited_total += visited;
        thread_ranges_complete &= visited == expected;
    }
    let mut blocks = std::mem::take(&mut scan.block_hashes);
    blocks.sort_unstable_by_key(|b| b.slot);
    let block_count = blocks.len() as u64;
    let slots = block_count.saturating_add(scan.skipped);
    let initial_parent = expected_parent.or_else(|| genesis_sentinel(&blocks));
    let anchored = initial_parent.is_some();
    let parent_slot_mismatches = find_parent_slot_mismatches(&blocks, initial_parent);
    let linkage_breaks = find_hash_link_breaks(&blocks, initial_parent);
    let zero_parent_slots: Vec<u64> = blocks
        .iter()
        .filter(|block| block.slot != 0 && block.parent_blockhash == Hash::default())
        .map(|block| block.slot)
        .collect();
    let poh_failures: Vec<u64> = blocks
        .iter()
        .filter(|b| !b.poh_ok)
        .map(|b| b.slot)
        .collect();
    let poh_unseeded: Vec<u64> = blocks
        .iter()
        .filter(|b| b.poh_unseeded)
        .map(|b| b.slot)
        .collect();
    let genesis_poh_sentinels: Vec<u64> = blocks
        .iter()
        .filter(|b| b.genesis_poh_sentinel)
        .map(|b| b.slot)
        .collect();

    let elapsed = start.elapsed().as_secs_f64();
    println!("\n=== verify summary ({elapsed:.1}s, {threads} threads) ===");
    println!("  slots (blk+skipped): {}", commas(slots));
    println!("  slot frames visited: {}", commas(visited_total));
    println!("  blocks:              {}", commas(block_count));
    println!("  skipped slots:       {}", commas(scan.skipped));
    println!("  epochs:              {}", commas(scan.epochs));
    println!("  transactions:        {}", commas(scan.transactions));
    println!("  tx account updates:  {}", commas(scan.tx_account_updates));
    println!("  orphan updates:      {}", commas(scan.orphan_updates));
    println!("  entries:             {}", commas(scan.entries));
    println!("  rewards:             {}", commas(scan.rewards));
    println!(
        "  block-meta tx total: {} (vs decoded {})",
        commas(scan.block_meta_tx_count),
        commas(scan.transactions)
    );
    if let Some(first) = blocks.first() {
        println!(
            "  first block:          slot={} parent_slot={} parent_blockhash={} blockhash={}",
            first.slot, first.parent_slot, first.parent_blockhash, first.blockhash
        );
    }
    if let Some(last) = blocks.last() {
        println!(
            "  last block:           slot={} parent_slot={} parent_blockhash={} blockhash={}",
            last.slot, last.parent_slot, last.parent_blockhash, last.blockhash
        );
    }

    if !parent_slot_mismatches.is_empty() {
        println!("\n=== parent-slot continuity ===");
        println!(
            "  {} parent-slot mismatch(es):",
            commas(parent_slot_mismatches.len() as u64)
        );
        for mismatch in parent_slot_mismatches.iter().take(20) {
            match mismatch.expected {
                Some(expected) => println!(
                    "    slot {}: parent_slot={} but previous canonical block slot was {}",
                    mismatch.slot, mismatch.actual, expected
                ),
                None => println!(
                    "    first block {}: parent_slot={} is not earlier",
                    mismatch.slot, mismatch.actual
                ),
            }
        }
        if parent_slot_mismatches.len() > 20 {
            println!("    and {} more", parent_slot_mismatches.len() - 20);
        }
    }

    if !scan.count_mismatches.is_empty() {
        println!("\n=== per-block count consistency ===");
        println!(
            "  {} block count mismatch(es):",
            commas(scan.count_mismatches.len() as u64)
        );
        for mismatch in scan.count_mismatches.iter().take(20) {
            println!(
                "    slot {}: transactions decoded={} metadata={} entries_sum={:?}; entries decoded={} metadata={}",
                mismatch.slot,
                mismatch.decoded_transactions,
                mismatch.metadata_transactions,
                mismatch.entry_transactions,
                mismatch.decoded_entries,
                mismatch.metadata_entries,
            );
        }
    }

    report_byte_breakdown(byte_stats, scan.raw_account_data_bytes);
    let hash_breaks = report_chain_breaks(&linkage_breaks, block_count);

    if full {
        println!("\n=== full PoH verification ===");
        let recomputed_ok = block_count
            - poh_failures.len() as u64
            - poh_unseeded.len() as u64
            - genesis_poh_sentinels.len() as u64;
        println!(
            "  PoH recompute: {} OK, {} mismatched{}{}",
            commas(recomputed_ok),
            commas(poh_failures.len() as u64),
            if poh_unseeded.is_empty() {
                String::new()
            } else {
                format!(
                    ", {} unverifiable (zeroed parent seed at resume points)",
                    commas(poh_unseeded.len() as u64)
                )
            },
            if genesis_poh_sentinels.is_empty() {
                String::new()
            } else {
                format!(
                    ", {} genesis sentinel(s) anchored without recomputation",
                    commas(genesis_poh_sentinels.len() as u64)
                )
            },
        );
        for slot in poh_failures.iter().take(20) {
            println!("    PoH mismatch at slot {slot} (recomputed hash != stored blockhash)");
        }
        match initial_parent {
            Some(point) => println!(
                "  chain anchor:        slot={} blockhash={}",
                point.slot, point.blockhash
            ),
            None => println!("  chain anchor:        NONE (first block's parent is unverified)"),
        }
    }

    let counts_ok = scan.block_meta_tx_count == scan.transactions;
    if !counts_ok {
        println!(
            "\n  WARNING: block-meta tx total ({}) != decoded transactions ({})",
            scan.block_meta_tx_count, scan.transactions
        );
    }

    let slots_ok = coverage_ok
        && exact_slot_counts(
            slot_count,
            visited_total,
            block_count,
            scan.skipped,
            thread_ranges_complete,
        );
    let internal_ok = slots_ok
        && hash_breaks == 0
        && parent_slot_mismatches.is_empty()
        && zero_parent_slots.is_empty()
        && poh_failures.is_empty()
        && poh_unseeded.is_empty()
        && scan.count_mismatches.is_empty()
        && counts_ok;
    // Full internal verification can deliberately leave the first boundary
    // unanchored when an independent ordered-chain pass proves that boundary.
    // Every within-archive link and every block's PoH is still checked here.
    let anchor_ok = anchor_requirement_satisfied(anchored, require_anchor);
    let ok = internal_ok && anchor_ok;
    if ok && anchored {
        let detail = if full && genesis_poh_sentinels.is_empty() {
            "every block's PoH recomputes to its stored blockhash and the chain links cleanly \
             from the anchor"
        } else if full {
            "every non-genesis block's PoH recomputes to its stored blockhash and the chain links \
             cleanly from the genesis sentinel"
        } else {
            "all buckets checksum-verified, every slot/transaction/update decoded, blockhash \
             chain intact, tallies consistent"
        };
        println!("\nRESULT: OK: {detail}.");
    } else if ok {
        println!(
            "\nRESULT: OK (internal only): all stored links verify; the first block is unanchored."
        );
    } else {
        println!(
            "\nRESULT: FAIL: {} hash-link break(s), {} parent-slot mismatch(es), {} zero-parent metadata defect(s), {} PoH mismatch(es), {} unseeded PoH block(s), {} count mismatch(es){}{}",
            hash_breaks,
            parent_slot_mismatches.len(),
            zero_parent_slots.len(),
            poh_failures.len(),
            poh_unseeded.len(),
            scan.count_mismatches.len(),
            if counts_ok {
                ""
            } else {
                ", aggregate tally mismatch"
            },
            if slots_ok {
                ""
            } else {
                ", incomplete slot coverage"
            },
        );
    }

    let terminal = blocks.last().map_or(expected_parent, |block| {
        Some(ChainPoint {
            slot: block.slot,
            blockhash: block.blockhash,
        })
    });
    ScanOutcome {
        ok,
        anchored,
        epoch,
        slot_start,
        slot_count,
        terminal,
        last_block_slot: blocks.last().map(|block| block.slot),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: verify_archive <path> [max_slots] [start_slot] [--full] [--internal-full] [--anchor SLOT HASH] [--expected-terminal SLOT HASH] [--expected-provenance-sha256 HEX] [--threads N]"
    );
    eprintln!(
        "       verify_archive --chain <path>... [--segment] [--full] [--anchor SLOT HASH] [--threads N]"
    );
    eprintln!("       verify_archive --capacity-probe");
    eprintln!(
        "       verify_archive --capacity-probe --receipt PATH --source-commit HEX --self-sha256 HEX --producer-node-sha256 HEX --producer-worker-sha256 HEX --producer-manifest-sha256 HEX --producer-manifest-fingerprint sha256:HEX"
    );
    eprintln!("  --full              recompute every block's PoH hash");
    eprintln!(
        "  --internal-full     with --full, verify all within-archive invariants without requiring an external boundary anchor; requires a separate successful --chain pass"
    );
    eprintln!("  --anchor SLOT HASH  trusted canonical block immediately before the range");
    eprintln!(
        "  --expected-terminal SLOT HASH  with --full, require this exact canonical final block; no partial/internal-only mode"
    );
    eprintln!(
        "  --expected-provenance-sha256 HEX  with strict --full, bind the canonical encoded provenance to independently derived source evidence (not publication admission)"
    );
    eprintln!("  --chain              verify ordered, contiguous archives as one chain");
    eprintln!(
        "  --segment            verify only the boundaries inside a multi-archive chain segment; defer both outer boundaries"
    );
    eprintln!("  --threads N          parallelism within each whole-file scan");
    std::process::exit(2);
}

/// Container decoding deliberately leaves optional provenance opaque. An
/// integrity verifier must parse it explicitly, including V4 restart mappings.
/// Structural acceptance is not canonical runtime or publication admission.
fn validate_structured_provenance<R: Read + std::io::Seek>(reader: &ArchiveReader<R>) {
    validate_provenance_expectation(reader, None)
        .unwrap_or_else(|error| panic!("validate archive provenance: {error}"));
}

fn validate_provenance_expectation<R: Read + std::io::Seek>(
    reader: &ArchiveReader<R>,
    expected_sha256: Option<&str>,
) -> Result<(), String> {
    if let Some(expected) = expected_sha256 {
        require_hex(expected, &[64], "--expected-provenance-sha256")?;
    }
    let provenance = reader.provenance().map_err(|error| error.to_string())?;
    if let Some(provenance) = provenance {
        let encoded = jetstreamer_horizon::archive::encode_archive_provenance(&provenance)
            .map_err(|error| error.to_string())?;
        let digest = format!("{:x}", Sha256::digest(&encoded));
        if expected_sha256.is_some_and(|expected| expected != digest) {
            return Err(format!("provenance SHA-256 mismatch: actual {digest}"));
        }
        println!(
            "archive provenance V{}: structurally valid; sha256={} (not runtime/publication admission)",
            provenance.version(),
            digest
        );
    } else if expected_sha256.is_some() {
        return Err("expected provenance is absent".into());
    }
    Ok(())
}

fn terminal_expectation_matches(actual: Option<ChainPoint>, expected: Option<ChainPoint>) -> bool {
    expected.is_none() || actual == expected
}

/// Prove that this exact verifier build can decode the historical pre-update
/// shape that exceeded the old 131,072-record inline capacity. The probe stays
/// in memory and never reads or mutates a production archive.
fn run_capacity_probe() -> i32 {
    const OBSERVED_PRE_UPDATES: usize = 131_073;
    const SLOT: u64 = 88_560_000;

    let mut writer = ArchiveWriter::new(
        Cursor::new(Vec::new()),
        205,
        SLOT,
        1,
        ArchiveWriterConfig {
            compression: Compression::None,
            ..Default::default()
        },
    )
    .expect("capacity probe writer initialization");
    writer.begin_slot(SLOT).expect("capacity probe slot");
    for write_version in 0..OBSERVED_PRE_UPDATES as u64 {
        writer
            .write_orphan_update(&AccountUpdateView {
                pubkey: Address::new_from_array([7; 32]),
                lamports: write_version,
                owner: Address::new_from_array([9; 32]),
                executable: false,
                rent_epoch: 0,
                write_version,
                data: &[],
            })
            .expect("capacity probe post-update write");
    }
    let mut meta = BlockMeta::new_boxed();
    meta.slot = SLOT;
    writer
        .end_slot(&meta, &[])
        .expect("capacity probe slot completion");
    let (archive, _) = writer.finish().expect("capacity probe archive completion");

    #[derive(Default)]
    struct CountPreUpdates(usize);
    impl SlotVisitor for CountPreUpdates {
        fn on_pre_account_update(&mut self, _slot: u64, _update: &AccountUpdateView<'_>) {
            self.0 += 1;
        }
    }

    let mut reader = ArchiveReader::open(Cursor::new(archive.into_inner()))
        .expect("capacity probe archive open");
    let mut count = CountPreUpdates::default();
    reader
        .read_slots(0, u64::MAX, &mut count)
        .expect("capacity probe archive decode");
    if count.0 != OBSERVED_PRE_UPDATES {
        eprintln!(
            "CAPACITY PROBE FAIL: decoded {} pre updates, expected {OBSERVED_PRE_UPDATES}",
            count.0
        );
        return 1;
    }
    println!("CAPACITY PROBE OK: decoded {OBSERVED_PRE_UPDATES} pre updates (old limit 131072)");
    0
}

fn require_hex(value: &str, lengths: &[usize], name: &str) -> Result<(), String> {
    if !lengths.contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be canonical lowercase hex"));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn option_value(args: &[String], name: &str) -> Result<String, String> {
    let index = args
        .iter()
        .position(|argument| argument == name)
        .ok_or_else(|| format!("missing {name}"))?;
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn write_capacity_probe_receipt(args: &[String]) -> Result<(), String> {
    const OBSERVED_PRE_UPDATES: u64 = 131_073;
    const OLD_INLINE_LIMIT: u64 = 131_072;
    const PROBE_SLOT: u64 = 88_560_000;
    const OUTPUT: &str = "CAPACITY PROBE OK: decoded 131073 pre updates (old limit 131072)";

    if unsafe { libc::geteuid() } != 0 {
        return Err("capacity-probe receipt must be written as root".to_owned());
    }
    let receipt = PathBuf::from(option_value(args, "--receipt")?);
    if !receipt.is_absolute() {
        return Err("--receipt must be absolute".to_owned());
    }
    let source_commit = option_value(args, "--source-commit")?;
    let expected_self_sha256 = option_value(args, "--self-sha256")?;
    let producer_node_sha256 = option_value(args, "--producer-node-sha256")?;
    let producer_worker_sha256 = option_value(args, "--producer-worker-sha256")?;
    let producer_manifest_sha256 = option_value(args, "--producer-manifest-sha256")?;
    let producer_manifest_fingerprint = option_value(args, "--producer-manifest-fingerprint")?;
    require_hex(&source_commit, &[40, 64], "--source-commit")?;
    for (name, value) in [
        ("--self-sha256", expected_self_sha256.as_str()),
        ("--producer-node-sha256", producer_node_sha256.as_str()),
        ("--producer-worker-sha256", producer_worker_sha256.as_str()),
        (
            "--producer-manifest-sha256",
            producer_manifest_sha256.as_str(),
        ),
    ] {
        require_hex(value, &[64], name)?;
    }
    let fingerprint_hex = producer_manifest_fingerprint
        .strip_prefix("sha256:")
        .ok_or_else(|| "--producer-manifest-fingerprint must start with sha256:".to_owned())?;
    require_hex(fingerprint_hex, &[64], "--producer-manifest-fingerprint")?;

    let executable =
        std::env::current_exe().map_err(|error| format!("resolve current executable: {error}"))?;
    let actual_self_sha256 = sha256_file(&executable)?;
    if actual_self_sha256 != expected_self_sha256 {
        return Err(format!(
            "running verifier SHA-256 mismatch: expected {expected_self_sha256}, got {actual_self_sha256}"
        ));
    }
    let parent = receipt
        .parent()
        .ok_or_else(|| "receipt has no parent".to_owned())?;
    let parent_metadata = parent
        .metadata()
        .map_err(|error| format!("stat receipt parent {}: {error}", parent.display()))?;
    if !parent_metadata.is_dir() || parent_metadata.uid() != 0 {
        return Err("receipt parent must be a root-owned directory".to_owned());
    }

    let recorded_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system time before Unix epoch: {error}"))?
        .as_secs();
    let document = serde_json::json!({
        "schema": "jetstreamer-horizon-verifier-capacity-probe-v1",
        "recorded_unix_seconds": recorded_unix_seconds,
        "source_commit": source_commit,
        "verifier_path": executable,
        "verifier_sha256": actual_self_sha256,
        "probe": {
            "slot": PROBE_SLOT,
            "phase": "pre-account-updates",
            "decoded_records": OBSERVED_PRE_UPDATES,
            "old_inline_limit": OLD_INLINE_LIMIT,
            "output": OUTPUT,
            "result": "pass"
        },
        "producer": {
            "node_sha256": producer_node_sha256,
            "worker_sha256": producer_worker_sha256,
            "manifest_sha256": producer_manifest_sha256,
            "manifest_fingerprint": producer_manifest_fingerprint
        },
        "authority": {
            "production_archive_reread_authorized": false,
            "replay_launch_authorized": false,
            "publication_authorized": false,
            "remote_mutations": false,
            "r2_mutations": false
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("serialize receipt: {error}"))?;
    bytes.push(b'\n');
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&receipt)
        .map_err(|error| format!("create receipt {}: {error}", receipt.display()))?;
    output
        .write_all(&bytes)
        .map_err(|error| format!("write receipt {}: {error}", receipt.display()))?;
    output
        .sync_all()
        .map_err(|error| format!("fsync receipt {}: {error}", receipt.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync receipt parent {}: {error}", parent.display()))?;
    let metadata = receipt
        .metadata()
        .map_err(|error| format!("stat receipt {}: {error}", receipt.display()))?;
    if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
        return Err("receipt ownership, mode, or link count changed after fsync".to_owned());
    }
    println!("CAPACITY PROBE RECEIPT: {}", receipt.display());
    Ok(())
}

fn parse_anchor(args: &[String], index: &mut usize) -> ChainPoint {
    let slot = args
        .get(*index + 1)
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| usage());
    let blockhash = args
        .get(*index + 2)
        .and_then(|value| Hash::from_str(value).ok())
        .unwrap_or_else(|| usage());
    *index += 2;
    ChainPoint { slot, blockhash }
}

fn run_ordered_chain(
    paths: &[String],
    threads: usize,
    full: bool,
    anchor: Option<ChainPoint>,
    segment: bool,
) -> i32 {
    if segment && paths.len() < 2 {
        println!("SEGMENT FAIL: at least two archives are required");
        return 1;
    }
    let mut previous = anchor;
    let mut previous_end: Option<u64> = None;
    let mut previous_epoch: Option<u64> = None;
    let mut chain_ok = true;
    let mut final_end = None;
    let mut final_block_slot = None;

    for (index, path) in paths.iter().enumerate() {
        println!("\n=== ordered archive: {path} ===");
        // A segment's first archive is intentionally allowed to omit its
        // incoming anchor. Every later archive must link to the terminal block
        // carried from its predecessor, which is the boundary evidence this
        // mode exists to produce.
        let require_anchor = !segment || index != 0 || anchor.is_some();
        let outcome = run_scan(path, threads, full, previous, require_anchor);
        let end = outcome
            .slot_start
            .checked_add(outcome.slot_count)
            .expect("validated archive slot range");
        if let Some(expected_start) = previous_end
            && outcome.slot_start != expected_start
        {
            println!(
                "CHAIN RANGE FAIL: archive starts at {}, expected {}",
                outcome.slot_start, expected_start
            );
            chain_ok = false;
        }
        if let Some(epoch) = previous_epoch
            && outcome.epoch != epoch.saturating_add(1)
        {
            println!(
                "CHAIN EPOCH FAIL: archive epoch is {}, expected {}",
                outcome.epoch,
                epoch.saturating_add(1)
            );
            chain_ok = false;
        }
        let boundary_anchor_ok = outcome.anchored || (segment && index == 0);
        chain_ok &= outcome.ok && boundary_anchor_ok;
        previous = outcome.terminal;
        previous_end = Some(end);
        previous_epoch = Some(outcome.epoch);
        final_end = Some(end);
        final_block_slot = outcome.last_block_slot;
    }

    if !segment
        && let Some(end) = final_end
        && final_block_slot != end.checked_sub(1)
    {
        println!(
            "CHAIN TAIL FAIL: no successor block proves skipped slots through {}",
            end.saturating_sub(1)
        );
        chain_ok = false;
    }

    if chain_ok && segment {
        println!(
            "\nSEGMENT RESULT: OK: every archive and internal boundary verifies; outer boundaries are deferred."
        );
        0
    } else if chain_ok {
        println!("\nCHAIN RESULT: OK: all ordered archives and boundaries verify.");
        0
    } else {
        println!("\nCHAIN RESULT: FAIL");
        1
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--post-update-capacity-probe") {
        if args.len() != 1 {
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
    if args.is_empty() {
        usage();
    }
    if args.first().map(String::as_str) == Some("--capacity-probe") {
        let result = run_capacity_probe();
        if result == 0
            && args.len() > 1
            && let Err(error) = write_capacity_probe_receipt(&args[1..])
        {
            eprintln!("CAPACITY PROBE RECEIPT FAIL: {error}");
            std::process::exit(1);
        }
        std::process::exit(result);
    }
    let mut full = false;
    let mut internal_full = false;
    let mut anchor = None;
    let mut expected_terminal = None;
    let mut expected_provenance_sha256 = None;
    let mut threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);

    if args[0] == "--chain" {
        let mut paths = Vec::new();
        let mut segment = false;
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--threads" => {
                    i += 1;
                    threads = args
                        .get(i)
                        .and_then(|value| value.parse().ok())
                        .unwrap_or_else(|| usage());
                }
                "--full" => full = true,
                "--segment" => segment = true,
                "--internal-full" => usage(),
                "--anchor" => anchor = Some(parse_anchor(&args, &mut i)),
                value if value.starts_with("--") => usage(),
                path => paths.push(path.to_string()),
            }
            i += 1;
        }
        if paths.is_empty() {
            usage();
        }
        std::process::exit(run_ordered_chain(&paths, threads, full, anchor, segment));
    }

    let path = args[0].clone();
    let mut positionals: Vec<u64> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--threads" => {
                i += 1;
                threads = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "--full" => full = true,
            "--internal-full" => internal_full = true,
            "--anchor" => anchor = Some(parse_anchor(&args, &mut i)),
            "--expected-terminal" => {
                if expected_terminal.is_some() {
                    usage();
                }
                expected_terminal = Some(parse_anchor(&args, &mut i));
            }
            "--expected-provenance-sha256" => {
                if expected_provenance_sha256.is_some() {
                    usage();
                }
                i += 1;
                let digest = args.get(i).unwrap_or_else(|| usage());
                require_hex(digest, &[64], "--expected-provenance-sha256")
                    .unwrap_or_else(|_| usage());
                expected_provenance_sha256 = Some(digest.as_str());
            }
            value if value.starts_with("--") => usage(),
            other => positionals.push(
                other
                    .parse()
                    .unwrap_or_else(|_| panic!("expected a number or flag, got `{other}`")),
            ),
        }
        i += 1;
    }
    let max_slots = positionals.first().copied().unwrap_or(u64::MAX);
    let start_slot_arg: Option<u64> = positionals.get(1).copied();

    if internal_full && (!full || anchor.is_some() || !positionals.is_empty()) {
        usage();
    }
    if expected_terminal.is_some() && (!full || internal_full || !positionals.is_empty()) {
        usage();
    }
    if expected_provenance_sha256.is_some() && (!full || internal_full || !positionals.is_empty()) {
        usage();
    }

    // `--full` and whole-file normal verification both run the parallel scanner.
    // A partial slice (max_slots / start_slot, for throughput sampling) keeps the
    // single-pass path below.
    if full {
        let outcome = run_scan_with_provenance(
            &path,
            threads,
            true,
            anchor,
            !internal_full,
            expected_provenance_sha256,
        );
        let end = outcome.slot_start.saturating_add(outcome.slot_count);
        let tail_ok = tail_requirement_satisfied(outcome.last_block_slot, end, !internal_full);
        if !tail_ok {
            println!(
                "STRICT TAIL FAIL: no successor block proves skipped slots through {}",
                end.saturating_sub(1)
            );
        } else if internal_full && outcome.last_block_slot != end.checked_sub(1) {
            println!(
                "INTERNAL TAIL: trailing skipped slots through {} require the ordered-chain pass",
                end.saturating_sub(1)
            );
        }
        let terminal_ok = terminal_expectation_matches(outcome.terminal, expected_terminal);
        if let Some(expected) = expected_terminal {
            println!(
                "CANONICAL TERMINAL {}: expected slot={} blockhash={}, actual={:?}",
                if terminal_ok { "OK" } else { "FAIL" },
                expected.slot,
                expected.blockhash,
                outcome.terminal
            );
        }
        std::process::exit(if outcome.ok && tail_ok && terminal_ok {
            0
        } else {
            1
        });
    }
    if max_slots == u64::MAX && start_slot_arg.is_none() {
        let outcome = run_scan(&path, threads, false, anchor, anchor.is_some());
        std::process::exit(if outcome.ok { 0 } else { 1 });
    }

    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    // Large buffer: streaming is forward and sequential, one bucket at a time.
    let source = BufReader::with_capacity(16 << 20, file);

    let start = Instant::now();
    let mut reader = ArchiveReader::open(source).unwrap_or_else(|e| panic!("open archive: {e}"));
    validate_structured_provenance(&reader);
    // The decoder's hard chain check aborts on the first mismatch; verify chain
    // continuity softly in the visitor instead, so the whole archive is read in
    // one pass and every break is reported (not just the first).
    reader.verify_chain = false;

    let header = reader.header();
    let slot_start = header.slot_start;
    let slot_count = header.slot_count;
    let epoch = header.epoch;
    let buckets = reader.bucket_count();
    println!(
        "opened {path} ({file_len} bytes): epoch={epoch} slot_start={slot_start} slot_count={slot_count} buckets={buckets}"
    );

    // Stream the whole archive (or up to max_slots). `read_slots` starts at
    // the first stored slot >= start_slot and walks forward; one call with a
    // large cap consumes the entire file.
    let read_from = start_slot_arg.unwrap_or(slot_start);
    let to_read = slot_count.min(max_slots);
    let mut tally = Tally {
        target_slots: to_read,
        ..Default::default()
    };
    let visited = reader
        .read_slots(read_from, to_read, &mut tally)
        .unwrap_or_else(|e| panic!("read_slots failed: {e}"));

    let elapsed = start.elapsed().as_secs_f64();
    let mib = file_len as f64 / (1024.0 * 1024.0);
    println!("\n=== verify_archive summary ===");
    println!(
        "read {visited} slot frames in {elapsed:.1}s ({:.0} MiB/s over file)",
        mib / elapsed.max(0.001)
    );
    println!("  epochs:              {}", tally.epochs);
    println!("  blocks:              {}", tally.blocks);
    println!("  skipped slots:       {}", tally.skipped);
    println!("  slots (blk+skipped): {}", tally.blocks + tally.skipped);
    println!("  transactions:        {}", tally.transactions);
    println!("  tx account updates:  {}", tally.tx_account_updates);
    println!("  orphan updates:      {}", tally.orphan_updates);
    println!("  entries:             {}", tally.entries);
    println!("  rewards:             {}", tally.rewards);
    println!(
        "  block-meta tx total: {} (vs decoded {})",
        tally.block_meta_tx_count, tally.transactions
    );

    report_byte_breakdown(reader.payload_byte_stats(), tally.raw_account_data_bytes);
    let breaks = report_chain_breaks(&tally.chain_breaks, tally.blocks);

    // This path only runs for a partial slice (whole-file verification goes
    // through the parallel scanner), so counts may be incomplete by design.
    if breaks == 0 {
        println!("\nRESULT: OK (partial read of {visited} slots).");
    } else {
        println!(
            "\nRESULT: partial read of {visited} slots with {breaks} chain break(s); see above."
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_provenance_binds_v4_restart_snapshot_and_raw_namespaces() {
        use jetstreamer_horizon::archive::{
            AccountsHashKind, ArchiveProvenance, ArchiveProvenanceV3, ArchiveProvenanceV4,
            BootstrapStateKind, RuntimeAdmission, RuntimeHandoffProvenance,
            RuntimeSegmentProvenance, RuntimeStateCheckpoint, StateCommitment, StateCommitmentKind,
            TransactionMetadataPolicy, WriteVersionNormalization, encode_archive_provenance,
        };
        let predecessor = RuntimeStateCheckpoint {
            slot: 10,
            bank_hash: Hash::new_from_array([2; 32]),
            accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
            accounts_hash: Hash::new_from_array([3; 32]),
            last_blockhash: Hash::new_from_array([4; 32]),
            capitalization: 100,
            transaction_count: 20,
            tick_height: 640,
            slot_complete: true,
            next_write_version: 1,
        };
        let segment = |slot, worker_start, archive_start| RuntimeSegmentProvenance {
            slot_start: slot,
            slot_count: 1,
            generation_profile: "independently-bound-generation".into(),
            runtime_profile: "same-runtime".into(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: "same-revision".into(),
            runtime_toolchain: "same-toolchain".into(),
            worker_executable_sha256: Some([5; 32]),
            write_versions: WriteVersionNormalization {
                worker_start,
                worker_end_exclusive: worker_start + 1,
                archive_start,
            },
        };
        let value = ArchiveProvenanceV4 {
            base: ArchiveProvenanceV3 {
                assembly_profile: "private-restart-test".into(),
                genesis_hash: Hash::new_from_array([6; 32]),
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_state: StateCommitment {
                    slot: 9,
                    kind: StateCommitmentKind::LegacyAccountsHash,
                    hash: Hash::new_from_array([7; 32]),
                },
                requested_slot_start: 10,
                requested_slot_count: 2,
                transaction_metadata: TransactionMetadataPolicy::observed(),
                runtime_segments: vec![segment(10, 0, 0), segment(11, 50, 1)],
                handoffs: vec![RuntimeHandoffProvenance {
                    boundary_slot: 11,
                    predecessor,
                    successor: RuntimeStateCheckpoint {
                        next_write_version: 50,
                        ..predecessor
                    },
                    successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                    successor_bootstrap_archive_sha256: [8; 32],
                    successor_bootstrap_write_count: 0,
                }],
            },
        };
        let expected = format!(
            "{:x}",
            Sha256::digest(
                encode_archive_provenance(&ArchiveProvenance::V4(value.clone())).unwrap()
            )
        );
        let reader_for = |provenance: ArchiveProvenanceV4| {
            let mut writer = ArchiveWriter::new_with_provenance(
                Vec::new(),
                1,
                10,
                2,
                ArchiveWriterConfig::default(),
                &provenance.into(),
            )
            .unwrap();
            writer.write_skipped_slot(10).unwrap();
            writer.write_skipped_slot(11).unwrap();
            ArchiveReader::open(Cursor::new(writer.finish().unwrap().0)).unwrap()
        };
        validate_provenance_expectation(&reader_for(value.clone()), Some(&expected)).unwrap();
        // Both mutations remain structurally valid. Only the independent
        // expectation detects substitution of the snapshot or raw namespace.
        let mut wrong_snapshot = value.clone();
        wrong_snapshot.base.handoffs[0].successor_bootstrap_archive_sha256 = [9; 32];
        assert!(
            validate_provenance_expectation(&reader_for(wrong_snapshot), Some(&expected)).is_err()
        );
        let mut wrong_cursor = value;
        wrong_cursor.base.runtime_segments[1]
            .write_versions
            .worker_start += 100;
        wrong_cursor.base.runtime_segments[1]
            .write_versions
            .worker_end_exclusive += 100;
        wrong_cursor.base.handoffs[0].successor.next_write_version += 100;
        assert!(
            validate_provenance_expectation(&reader_for(wrong_cursor), Some(&expected)).is_err()
        );
    }

    #[test]
    fn expected_provenance_rejects_missing_and_noncanonical_expectations() {
        let legacy = ArchiveReader::open(Cursor::new(write_archive(1, 10, &[None]))).unwrap();
        assert!(validate_provenance_expectation(&legacy, None).is_ok());
        for expected in [
            "a".repeat(64),
            "A".repeat(64),
            "a".repeat(63),
            String::new(),
        ] {
            assert!(validate_provenance_expectation(&legacy, Some(&expected)).is_err());
        }
    }

    #[test]
    fn canonical_terminal_requires_both_slot_and_hash() {
        let expected = ChainPoint {
            slot: 11,
            blockhash: Hash::new_from_array([3; 32]),
        };
        assert!(terminal_expectation_matches(Some(expected), Some(expected)));
        assert!(terminal_expectation_matches(None, None));
        assert!(!terminal_expectation_matches(None, Some(expected)));
        assert!(!terminal_expectation_matches(
            Some(ChainPoint {
                slot: 10,
                ..expected
            }),
            Some(expected)
        ));
        assert!(!terminal_expectation_matches(
            Some(ChainPoint {
                blockhash: Hash::new_from_array([4; 32]),
                ..expected
            }),
            Some(expected)
        ));
    }

    #[test]
    fn readback_scan_rejects_unknown_provenance_before_scanning_slots() {
        use jetstreamer_horizon::archive::{
            ARCHIVE_PROVENANCE_MAGIC, ArchiveProvenanceV1, BootstrapStateKind, RuntimeAdmission,
            TransactionMetadataPolicy,
        };
        let provenance = ArchiveProvenanceV1 {
            generation_profile: "test-generation".into(),
            runtime_profile: "test-runtime".into(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: "test-revision".into(),
            runtime_toolchain: "test-toolchain".into(),
            genesis_hash: Hash::new_from_array([5; 32]),
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_slot: 9,
            bootstrap_state_hash: Hash::new_from_array([7; 32]),
            requested_slot_start: 10,
            requested_slot_count: 1,
            transaction_metadata: TransactionMetadataPolicy::observed(),
        };
        let mut writer = ArchiveWriter::new_with_provenance(
            Vec::new(),
            1,
            10,
            1,
            ArchiveWriterConfig::default(),
            &provenance.into(),
        )
        .unwrap();
        writer.write_skipped_slot(10).unwrap();
        let (mut bytes, _) = writer.finish().unwrap();
        let reader = ArchiveReader::open(Cursor::new(bytes.clone())).unwrap();
        validate_structured_provenance(&reader);
        let offset = bytes
            .windows(ARCHIVE_PROVENANCE_MAGIC.len())
            .position(|window| window == ARCHIVE_PROVENANCE_MAGIC)
            .unwrap()
            + ARCHIVE_PROVENANCE_MAGIC.len();
        bytes[offset..offset + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        // Container framing still opens: the explicit verifier gate, not a
        // bucket checksum or unrelated decode failure, must reject this file.
        let reader = ArchiveReader::open(Cursor::new(bytes.clone())).unwrap();
        assert!(reader.provenance().is_err());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bad-provenance.jet");
        std::fs::write(&path, bytes).unwrap();
        assert!(
            std::panic::catch_unwind(|| {
                run_scan(path.to_str().unwrap(), 1, false, None, false)
            })
            .is_err()
        );
        let legacy = ArchiveReader::open(Cursor::new(write_archive(1, 10, &[None]))).unwrap();
        validate_structured_provenance(&legacy);
    }

    #[test]
    fn exact_verifier_capacity_probe_accepts_observed_131073_pre_updates() {
        assert_eq!(run_capacity_probe(), 0);
    }

    #[test]
    fn explicit_internal_pass_may_omit_an_external_anchor() {
        assert!(anchor_requirement_satisfied(true, true));
        assert!(anchor_requirement_satisfied(true, false));
        assert!(anchor_requirement_satisfied(false, false));
        assert!(!anchor_requirement_satisfied(false, true));
    }

    #[test]
    fn explicit_internal_pass_may_defer_trailing_skip_proof() {
        assert!(tail_requirement_satisfied(Some(9), 10, true));
        assert!(tail_requirement_satisfied(Some(8), 10, false));
        assert!(tail_requirement_satisfied(None, 10, false));
        assert!(!tail_requirement_satisfied(Some(8), 10, true));
        assert!(!tail_requirement_satisfied(None, 10, true));
    }

    fn sig(b: u8) -> Signature {
        Signature::from([b; 64])
    }

    fn block_hashes(slot: u64, parent_slot: u64) -> BlockHashes {
        BlockHashes {
            slot,
            parent_slot,
            parent_blockhash: Hash::default(),
            blockhash: Hash::default(),
            poh_ok: true,
            poh_unseeded: false,
            genesis_poh_sentinel: false,
        }
    }

    fn write_archive(epoch: u64, slot_start: u64, frames: &[Option<(u64, Hash, Hash)>]) -> Vec<u8> {
        let mut writer = ArchiveWriter::new(
            std::io::Cursor::new(Vec::new()),
            epoch,
            slot_start,
            frames.len() as u64,
            ArchiveWriterConfig::default(),
        )
        .unwrap();
        for (offset, frame) in frames.iter().enumerate() {
            let slot = slot_start + offset as u64;
            match frame {
                None => writer.write_skipped_slot(slot).unwrap(),
                Some((parent_slot, parent_blockhash, blockhash)) => {
                    writer.begin_slot(slot).unwrap();
                    let mut meta = BlockMeta::new_boxed();
                    meta.slot = slot;
                    meta.parent_slot = *parent_slot;
                    meta.parent_blockhash = *parent_blockhash;
                    meta.blockhash = *blockhash;
                    writer.end_slot(&meta, &[]).unwrap();
                }
            }
        }
        writer.finish().unwrap().0.into_inner()
    }

    #[test]
    fn parent_slots_follow_the_previous_canonical_block() {
        let valid = [block_hashes(0, 0), block_hashes(2, 0), block_hashes(5, 2)];
        assert!(find_parent_slot_mismatches(&valid, genesis_sentinel(&valid)).is_empty());

        let invalid = [block_hashes(10, 9), block_hashes(12, 8)];
        assert_eq!(
            find_parent_slot_mismatches(&invalid, None),
            vec![ParentSlotMismatch {
                slot: 12,
                expected: Some(10),
                actual: 8,
            }]
        );

        let invalid_first = [block_hashes(10, 10)];
        assert_eq!(
            find_parent_slot_mismatches(&invalid_first, None),
            vec![ParentSlotMismatch {
                slot: 10,
                expected: None,
                actual: 10,
            }]
        );
    }

    #[test]
    fn genesis_sentinel_checks_slot_and_zero_hash() {
        let blockhash = Hash::new_from_array([1; 32]);
        let mut blocks = [BlockHashes {
            slot: 0,
            parent_slot: 0,
            parent_blockhash: Hash::default(),
            blockhash,
            poh_ok: true,
            poh_unseeded: false,
            genesis_poh_sentinel: true,
        }];
        let sentinel = genesis_sentinel(&blocks);
        assert!(find_parent_slot_mismatches(&blocks, sentinel).is_empty());
        assert!(find_hash_link_breaks(&blocks, sentinel).is_empty());

        blocks[0].parent_blockhash = Hash::new_from_array([9; 32]);
        assert_eq!(find_hash_link_breaks(&blocks, sentinel).len(), 1);
    }

    #[test]
    fn full_poh_scan_exempts_only_the_canonical_genesis_sentinel() {
        assert!(is_genesis_poh_sentinel(0, 0, &Hash::default()));
        assert!(!is_genesis_poh_sentinel(0, 1, &Hash::default()));
        assert!(!is_genesis_poh_sentinel(
            0,
            0,
            &Hash::new_from_array([1; 32])
        ));
        assert!(!is_genesis_poh_sentinel(1, 0, &Hash::default()));
    }

    #[test]
    fn external_anchor_checks_both_parent_fields() {
        let anchor = ChainPoint {
            slot: 9,
            blockhash: Hash::new_from_array([3; 32]),
        };
        let mut blocks = [BlockHashes {
            slot: 10,
            parent_slot: 9,
            parent_blockhash: anchor.blockhash,
            blockhash: Hash::new_from_array([4; 32]),
            poh_ok: true,
            poh_unseeded: false,
            genesis_poh_sentinel: false,
        }];
        assert!(find_parent_slot_mismatches(&blocks, Some(anchor)).is_empty());
        assert!(find_hash_link_breaks(&blocks, Some(anchor)).is_empty());

        blocks[0].parent_slot = 8;
        assert_eq!(find_parent_slot_mismatches(&blocks, Some(anchor)).len(), 1);
        blocks[0].parent_slot = 9;
        blocks[0].parent_blockhash = Hash::new_from_array([5; 32]);
        assert_eq!(find_hash_link_breaks(&blocks, Some(anchor)).len(), 1);
    }

    #[test]
    fn exact_block_counts_are_required() {
        let entries = [
            EntryRecord {
                num_hashes: 1,
                tx_count: 1,
            },
            EntryRecord {
                num_hashes: 1,
                tx_count: 2,
            },
        ];
        assert!(block_count_mismatch(7, 3, 3, 2, &entries).is_none());
        assert!(block_count_mismatch(7, 3, 4, 2, &entries).is_some());
        assert!(block_count_mismatch(7, 2, 2, 2, &entries).is_some());
        assert!(block_count_mismatch(7, 3, 3, 1, &entries).is_some());
    }

    #[test]
    fn exact_slot_counts_are_required() {
        assert!(exact_slot_counts(300, 300, 290, 10, true));
        assert!(!exact_slot_counts(300, 299, 290, 10, true));
        assert!(!exact_slot_counts(300, 300, 289, 10, true));
        assert!(!exact_slot_counts(300, 300, 290, 10, false));
        assert!(!exact_slot_counts(u64::MAX, u64::MAX, u64::MAX, 1, true));
    }

    #[test]
    fn ordered_chain_rejects_zero_parent_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let first_path = dir.path().join("epoch-0.jet");
        let second_path = dir.path().join("epoch-1.jet");
        let genesis_blockhash = Hash::new_from_array([1; 32]);
        let child_blockhash = Hash::new_from_array([2; 32]);
        std::fs::write(
            &first_path,
            write_archive(0, 0, &[Some((0, Hash::default(), genesis_blockhash))]),
        )
        .unwrap();
        std::fs::write(
            &second_path,
            write_archive(1, 1, &[Some((0, Hash::default(), child_blockhash))]),
        )
        .unwrap();
        let paths = vec![
            first_path.to_string_lossy().into_owned(),
            second_path.to_string_lossy().into_owned(),
        ];
        assert_eq!(run_ordered_chain(&paths, 2, false, None, false), 1);
    }

    #[test]
    fn ordered_chain_accepts_carried_parent() {
        let dir = tempfile::tempdir().unwrap();
        let first_path = dir.path().join("epoch-0.jet");
        let second_path = dir.path().join("epoch-1.jet");
        let genesis_blockhash = Hash::new_from_array([1; 32]);
        let child_blockhash = Hash::new_from_array([2; 32]);
        std::fs::write(
            &first_path,
            write_archive(0, 0, &[Some((0, Hash::default(), genesis_blockhash))]),
        )
        .unwrap();
        std::fs::write(
            &second_path,
            write_archive(1, 1, &[Some((0, genesis_blockhash, child_blockhash))]),
        )
        .unwrap();
        let paths = vec![
            first_path.to_string_lossy().into_owned(),
            second_path.to_string_lossy().into_owned(),
        ];
        assert_eq!(run_ordered_chain(&paths, 2, false, None, false), 0);
    }

    #[test]
    fn ordered_chain_requires_successor_proof_for_trailing_skip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch-0.jet");
        std::fs::write(
            &path,
            write_archive(
                0,
                0,
                &[
                    Some((0, Hash::default(), Hash::new_from_array([1; 32]))),
                    None,
                ],
            ),
        )
        .unwrap();
        assert_eq!(
            run_ordered_chain(
                &[path.to_string_lossy().into_owned()],
                2,
                false,
                None,
                false,
            ),
            1
        );
    }

    #[test]
    fn ordered_segment_proves_internal_boundary_and_defers_outer_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let first_path = dir.path().join("epoch-5.jet");
        let second_path = dir.path().join("epoch-6.jet");
        let claimed_parent = Hash::new_from_array([9; 32]);
        let first_blockhash = Hash::new_from_array([1; 32]);
        let second_blockhash = Hash::new_from_array([2; 32]);
        std::fs::write(
            &first_path,
            write_archive(5, 10, &[Some((9, claimed_parent, first_blockhash))]),
        )
        .unwrap();
        std::fs::write(
            &second_path,
            write_archive(
                6,
                11,
                &[Some((10, first_blockhash, second_blockhash)), None],
            ),
        )
        .unwrap();
        let paths = vec![
            first_path.to_string_lossy().into_owned(),
            second_path.to_string_lossy().into_owned(),
        ];

        // Strict mode rejects the unanchored start and trailing skipped slot.
        assert_eq!(run_ordered_chain(&paths, 2, false, None, false), 1);
        // Segment mode verifies the 5 -> 6 boundary and deliberately leaves
        // those two outer proofs to adjacent segments.
        assert_eq!(run_ordered_chain(&paths, 2, false, None, true), 0);
    }

    #[test]
    fn ordered_segment_requires_an_actual_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch-5.jet");
        std::fs::write(
            &path,
            write_archive(5, 10, &[Some((9, Hash::new_unique(), Hash::new_unique()))]),
        )
        .unwrap();
        assert_eq!(
            run_ordered_chain(&[path.to_string_lossy().into_owned()], 2, false, None, true),
            1
        );
    }

    #[test]
    fn strict_scan_rejects_unanchored_non_genesis_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch-5.jet");
        let parent = ChainPoint {
            slot: 999,
            blockhash: Hash::new_from_array([1; 32]),
        };
        std::fs::write(
            &path,
            write_archive(
                5,
                1_000,
                &[Some((
                    parent.slot,
                    parent.blockhash,
                    Hash::new_from_array([2; 32]),
                ))],
            ),
        )
        .unwrap();

        let path = path.to_str().unwrap();
        assert!(!run_scan(path, 1, false, None, true).ok);
        assert!(run_scan(path, 1, false, Some(parent), true).ok);
    }

    #[test]
    fn full_internal_scan_accepts_only_the_deliberately_unanchored_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch-5.jet");
        let parent_hash = Hash::new_from_array([6; 32]);
        std::fs::write(
            &path,
            write_archive(5, 1_000, &[Some((999, parent_hash, parent_hash))]),
        )
        .unwrap();

        let path = path.to_str().unwrap();
        assert!(run_scan(path, 1, true, None, false).ok);
        assert!(!run_scan(path, 1, true, None, true).ok);
    }

    /// `recompute_blockhash` must split the flat per-tx signature list into
    /// entries by `tx_count` and fold them in order, identical to calling
    /// Solana's `next_hash` entry by entry.
    #[test]
    fn recompute_matches_reference_fold() {
        let parent = Hash::new_from_array([7u8; 32]);
        // tick(10) ++ tx-entry(5, 2 txs) ++ tick(8).
        let entries = vec![
            EntryRecord {
                num_hashes: 10,
                tx_count: 0,
            },
            EntryRecord {
                num_hashes: 5,
                tx_count: 2,
            },
            EntryRecord {
                num_hashes: 8,
                tx_count: 0,
            },
        ];
        // First tx has 1 signature, second has 2.
        let sigs = vec![vec![sig(1)], vec![sig(2), sig(3)]];

        // Reference fold straight through next_hash.
        let entry_txs: Vec<VersionedTransaction> = sigs
            .iter()
            .map(|s| VersionedTransaction {
                signatures: s.clone(),
                message: VersionedMessage::default(),
            })
            .collect();
        let mut poh = parent;
        poh = solana_entry::entry::next_hash(&poh, 10, &[]);
        poh = solana_entry::entry::next_hash(&poh, 5, &entry_txs);
        poh = solana_entry::entry::next_hash(&poh, 8, &[]);

        assert_eq!(recompute_blockhash(&parent, &entries, &sigs), Some(poh));
    }

    /// A wrong stored blockhash must not equal the recompute (sanity that the
    /// check actually discriminates).
    #[test]
    fn recompute_detects_tampering() {
        let parent = Hash::new_from_array([1u8; 32]);
        let entries = vec![EntryRecord {
            num_hashes: 3,
            tx_count: 1,
        }];
        let sigs = vec![vec![sig(9)]];
        let computed = recompute_blockhash(&parent, &entries, &sigs).unwrap();
        assert_ne!(computed, Hash::default());
        assert_ne!(computed, parent);
    }

    #[test]
    fn recompute_rejects_entry_transaction_count_mismatch() {
        let parent = Hash::new_from_array([1u8; 32]);
        let entries = vec![EntryRecord {
            num_hashes: 3,
            tx_count: 2,
        }];
        assert_eq!(
            recompute_blockhash(&parent, &entries, &[vec![sig(9)]]),
            None
        );

        let entries = vec![EntryRecord {
            num_hashes: 3,
            tx_count: 0,
        }];
        assert_eq!(
            recompute_blockhash(&parent, &entries, &[vec![sig(9)]]),
            None
        );
    }

    /// End-to-end smoke of the parallel scanner: build a real multi-bucket
    /// `.jet` and run normal (non-full) verification over it across threads.
    #[test]
    fn run_scan_parallel_smoke() {
        let (epoch, slot_start, n) = (5u64, 1_000u64, 300u64); // 3 buckets @ 128
        let mut w = ArchiveWriter::new(
            std::io::Cursor::new(Vec::new()),
            epoch,
            slot_start,
            n,
            ArchiveWriterConfig::default(),
        )
        .unwrap();
        for i in 0..n {
            w.write_skipped_slot(slot_start + i).unwrap();
        }
        let (sink, _) = w.finish().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("smoke.jet");
        std::fs::write(&path, sink.into_inner()).unwrap();

        // All-skipped archive: no blocks, so linkage is trivially intact and the
        // parallel scan/merge/report path should run clean and return OK.
        let outcome = run_scan(path.to_str().unwrap(), 4, false, None, false);
        assert!(outcome.ok);
    }
}
