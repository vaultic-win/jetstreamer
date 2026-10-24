//! Replay adapter for an isolated historical runtime worker.

use {
    super::{
        InFlightGuard, PHASE_ENTRY_COUNT, PHASE_EXECUTE_US, PHASE_POST_PROCESS_US, ReadyEntry,
        ReplayCursor, ReplayFailure, ReplayProgress, SnapshotVerifier, horizon, plugin,
    },
    crate::historical::{
        HistoricalAccountWrite, HistoricalCheckpoint, HistoricalEntryRequest,
        HistoricalEntryStreamItem, HistoricalInitializedSource, HistoricalRuntimeClient,
        HistoricalSnapshotExport, denormalize_transaction_error, encode_legacy_transaction,
        normalize_transaction_error,
    },
    jetstreamer_historical_protocol::{
        MAX_ENTRIES_PER_BATCH, TransactionError as HistoricalTransactionError,
    },
    log::info,
    solana_address::Address,
    solana_clock::Slot,
    solana_hash::Hash,
    solana_signature::Signature,
    std::{
        collections::BTreeSet,
        ops::Range,
        path::Path,
        sync::{Arc, Mutex, atomic::Ordering},
        time::Instant,
    },
};

#[cfg(feature = "epoch224-account-delta-diagnostic")]
use sha2::{Digest as _, Sha256};

const HISTORICAL_BATCH_MAX_SLOTS: usize = 4;
// Leave half of the 64 MiB frame for entry/vector framing and keep batches of
// unusually large transactions from turning one response into a huge burst.
const HISTORICAL_BATCH_TRANSACTION_BYTES: usize = 32 * 1024 * 1024;

#[cfg(feature = "epoch224-account-delta-diagnostic")]
const EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT: Slot = 96_767_525;

#[cfg(feature = "epoch224-account-delta-diagnostic")]
fn verify_epoch224_transaction_write_lamports(
    entry: &ReadyEntry,
    writes: &[HistoricalAccountWrite],
    seen: &mut BTreeSet<([u8; 64], [u8; 32])>,
) -> Result<(), String> {
    for write in writes {
        if write.slot != EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT {
            continue;
        }
        let Some(signature) = write.transaction_signature else {
            info!(
                "epoch224 freeze write: slot={} write_version={} pubkey={} lamports={} owner={} executable={} rent_epoch={} stored_hash={} data_sha256={:x}",
                write.slot,
                write.write_version,
                Address::new_from_array(write.pubkey),
                write.lamports,
                Address::new_from_array(write.owner),
                write.executable,
                write.rent_epoch,
                Hash::new_from_array(write.stored_hash),
                Sha256::digest(&write.data),
            );
            continue;
        };
        if entry.slot != EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT {
            return Err(format!(
                "epoch224 diagnostic transaction write for slot {} arrived with entry slot {}",
                write.slot, entry.slot
            ));
        }
        let mut matches = entry.txs.iter().enumerate().filter(|(_, scheduled)| {
            scheduled
                .tx
                .signatures
                .first()
                .is_some_and(|candidate| *candidate.as_array() == signature)
        });
        let (transaction_index, scheduled) = matches.next().ok_or_else(|| {
            format!(
                "epoch224 diagnostic write version {} has unknown transaction signature {}",
                write.write_version,
                Signature::from(signature)
            )
        })?;
        if matches.next().is_some() {
            return Err(format!(
                "epoch224 diagnostic signature {} maps to multiple source transactions",
                Signature::from(signature)
            ));
        }
        if scheduled.expected_status.is_none() || scheduled.reconstruct_fee {
            return Err(format!(
                "epoch224 diagnostic transaction {} lacks exact canonical metadata",
                transaction_index
            ));
        }
        let keys = scheduled.tx.message.static_account_keys();
        if scheduled.status_meta.pre_balances.len() != keys.len()
            || scheduled.status_meta.post_balances.len() != keys.len()
        {
            return Err(format!(
                "epoch224 diagnostic transaction {} balance vectors do not match its {} static keys",
                transaction_index,
                keys.len()
            ));
        }
        let mut key_matches = keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.to_bytes() == write.pubkey);
        let (account_index, _) = key_matches.next().ok_or_else(|| {
            format!(
                "epoch224 diagnostic write version {} pubkey {} is absent from transaction {}",
                write.write_version,
                Address::new_from_array(write.pubkey),
                transaction_index
            )
        })?;
        if key_matches.next().is_some() {
            return Err(format!(
                "epoch224 diagnostic transaction {} contains duplicate key {}",
                transaction_index,
                Address::new_from_array(write.pubkey)
            ));
        }
        let expected = scheduled.status_meta.post_balances[account_index];
        if write.lamports != expected {
            return Err(format!(
                "epoch224 diagnostic lamport mismatch at slot {} entry {} transaction {} signature {} pubkey {}: expected {}, observed {}, write version {}",
                entry.slot,
                entry.entry_index,
                entry.start_index + transaction_index,
                Signature::from(signature),
                Address::new_from_array(write.pubkey),
                expected,
                write.lamports,
                write.write_version,
            ));
        }
        // The epoch-224 diagnostic is sealed with the v1.6.20 worker. Its
        // conflict-free execution wave attributes one committed final account
        // image per writable message key; a repeated key inside one sanitized
        // transaction cannot reach commit. A second `(signature, pubkey)` is
        // therefore ambiguous evidence, not a value we may silently replace.
        if !seen.insert((signature, write.pubkey)) {
            return Err(format!(
                "epoch224 diagnostic transaction {} emitted duplicate final write for {}",
                transaction_index,
                Address::new_from_array(write.pubkey)
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "epoch224-account-delta-diagnostic")]
fn verify_epoch224_changed_lamport_writes(
    entry: &ReadyEntry,
    seen: &BTreeSet<([u8; 64], [u8; 32])>,
) -> Result<(), String> {
    if entry.slot != EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT {
        return Ok(());
    }
    for (transaction_index, scheduled) in entry.txs.iter().enumerate() {
        if scheduled.expected_status.is_none() || scheduled.reconstruct_fee {
            return Err(format!(
                "epoch224 diagnostic transaction {} lacks exact canonical metadata",
                transaction_index
            ));
        }
        let signature = scheduled
            .tx
            .signatures
            .first()
            .map(|value| *value.as_array())
            .ok_or_else(|| {
                format!(
                    "epoch224 diagnostic transaction {} has no signature",
                    transaction_index
                )
            })?;
        let keys = scheduled.tx.message.static_account_keys();
        if scheduled.status_meta.pre_balances.len() != keys.len()
            || scheduled.status_meta.post_balances.len() != keys.len()
        {
            return Err(format!(
                "epoch224 diagnostic transaction {} balance vectors do not match its {} static keys",
                transaction_index,
                keys.len()
            ));
        }
        for (account_index, key) in keys.iter().enumerate() {
            if scheduled.status_meta.pre_balances[account_index]
                != scheduled.status_meta.post_balances[account_index]
                && !seen.contains(&(signature, key.to_bytes()))
            {
                return Err(format!(
                    "epoch224 diagnostic missing write at slot {} entry {} transaction {} signature {} pubkey {}: pre {}, post {}",
                    entry.slot,
                    entry.entry_index,
                    entry.start_index + transaction_index,
                    Signature::from(signature),
                    key,
                    scheduled.status_meta.pre_balances[account_index],
                    scheduled.status_meta.post_balances[account_index],
                ));
            }
        }
    }
    Ok(())
}

fn apply_runtime_reconstructed_metadata(
    scheduled: &mut super::ScheduledTransaction,
    actual: &crate::historical::HistoricalTransactionOutcome,
) {
    scheduled.status_meta.status = match actual.error.as_ref() {
        Some(error) => Err(denormalize_transaction_error(error)),
        None => Ok(()),
    };
    if scheduled.reconstruct_fee {
        scheduled.status_meta.fee = actual.fee;
    }
}

/// Checkpoint identity retained for replay provenance and runtime handoff.
/// Account writes are deliberately excluded from this cloneable summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalCheckpointSummary {
    pub(crate) slot: Slot,
    pub(crate) bank_hash: [u8; 32],
    pub(crate) accounts_hash: [u8; 32],
    pub(crate) last_blockhash: [u8; 32],
    pub(crate) capitalization: u64,
    pub(crate) transaction_count: u64,
    pub(crate) tick_height: u64,
    pub(crate) slot_complete: bool,
    pub(crate) write_count: u64,
    pub(crate) next_write_version: u64,
}

impl TryFrom<&HistoricalCheckpoint> for HistoricalCheckpointSummary {
    type Error = String;

    fn try_from(checkpoint: &HistoricalCheckpoint) -> Result<Self, Self::Error> {
        let write_count = u64::try_from(checkpoint.writes.len()).map_err(|_| {
            format!(
                "historical checkpoint at slot {} has too many writes to summarize: {}",
                checkpoint.slot,
                checkpoint.writes.len()
            )
        })?;
        Ok(Self {
            slot: checkpoint.slot,
            bank_hash: checkpoint.bank_hash,
            accounts_hash: checkpoint.accounts_hash,
            last_blockhash: checkpoint.last_blockhash,
            capitalization: checkpoint.capitalization,
            transaction_count: checkpoint.transaction_count,
            tick_height: checkpoint.tick_height,
            slot_complete: checkpoint.slot_complete,
            write_count,
            next_write_version: checkpoint.next_write_version,
        })
    }
}

/// Minimal evidence produced by one uninterrupted historical runtime segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalReplayEvidence {
    pub(crate) bootstrap: HistoricalCheckpointSummary,
    pub(crate) terminal: HistoricalCheckpointSummary,
    /// Raw worker write versions emitted for slots at or after the segment's
    /// live start. The range is empty at the terminal cursor when no such
    /// writes were emitted.
    pub(crate) emitted_write_versions: Range<u64>,
}

/// Adapts the version-neutral worker protocol to Jetstreamer's ordered entry
/// stream and Horizon recorder.
///
/// Calls are lockstep and are made by the single ready-entry thread. Keeping
/// the mutex here still makes the ownership rule explicit and prevents final
/// checkpointing from racing a future caller.
pub(crate) struct HistoricalReplay {
    state: Mutex<HistoricalReplayState>,
    snapshot_verifier: Option<Arc<SnapshotVerifier>>,
    checkpoint_slots: Mutex<BTreeSet<Slot>>,
    failure: Arc<ReplayFailure>,
    cursor: Arc<ReplayCursor>,
    progress: Arc<ReplayProgress>,
    live_start_slot: Slot,
    diagnostic_warmup_target: Option<Slot>,
}

struct HistoricalReplayState {
    client: Option<HistoricalRuntimeClient>,
    current_slot: Slot,
    last_checkpoint_slot: Option<Slot>,
    bootstrap_checkpoint: Option<HistoricalCheckpointSummary>,
    terminal_checkpoint: Option<HistoricalCheckpointSummary>,
    emitted_write_versions: Option<Range<u64>>,
}

struct EncodedReadyEntry {
    entry: ReadyEntry,
    transactions: Vec<Vec<u8>>,
    transaction_bytes: usize,
}

impl HistoricalReplay {
    pub(crate) fn new(
        client: HistoricalRuntimeClient,
        snapshot_verifier: Option<Arc<SnapshotVerifier>>,
        failure: Arc<ReplayFailure>,
        cursor: Arc<ReplayCursor>,
        progress: Arc<ReplayProgress>,
        live_start_slot: Slot,
    ) -> Result<Self, String> {
        let current_slot = client.initialized().slot;
        let initialized_source = client.initialized().source;
        let checkpoint_slots: BTreeSet<Slot> = snapshot_verifier
            .as_ref()
            .map(|verifier| verifier.legacy_checkpoint_slots().into_iter().collect())
            .unwrap_or_default();
        let diagnostic_warmup_target = bounded_epoch223_warmup_target(
            client.executable_sha256(),
            current_slot,
            live_start_slot,
        )
        .or_else(|| {
            bounded_epoch227_comparison_target(
                client.executable_sha256(),
                current_slot,
                live_start_slot,
            )
        });
        if cfg!(feature = "epoch227-v1-6-25-diagnostic")
            && diagnostic_warmup_target != Some(98_091_122)
        {
            return Err(
                "bounded227 requires its exact worker, bootstrap and live-start scope".into(),
            );
        }
        if diagnostic_warmup_target.is_some() && !client.supports_entry_batches() {
            return Err("bounded diagnostic requires the approved batched worker".into());
        }
        if diagnostic_warmup_target
            .is_some_and(|target| !bounded_diagnostic_checkpoints(target, &checkpoint_slots))
        {
            return Err("bounded diagnostic retains both real canonical checkpoint gates".into());
        }
        let replay = Self {
            state: Mutex::new(HistoricalReplayState {
                client: Some(client),
                current_slot,
                last_checkpoint_slot: None,
                bootstrap_checkpoint: None,
                terminal_checkpoint: None,
                emitted_write_versions: None,
            }),
            snapshot_verifier,
            checkpoint_slots: Mutex::new(checkpoint_slots),
            failure,
            cursor,
            progress,
            live_start_slot,
            diagnostic_warmup_target,
        };

        // A loaded snapshot is already a complete bank, so prove and retain it
        // before accepting an entry. This also makes a wrong compiler-dependent
        // AppendVec interpretation fail immediately. A genesis bank at slot 0
        // is intentionally incomplete, however: its entries and ticks still
        // need to execute. It is checkpointed only after completion if slot 0
        // is in the verifier set; candidate admission still requires a trusted
        // post-execution checkpoint elsewhere in the requested range.
        if checkpoint_initialized_state(initialized_source) {
            replay.take_checkpoint_slot(current_slot);
            replay.checkpoint_current(current_slot)?;
        }
        Ok(replay)
    }

    /// Starts from an independently frozen snapshot checkpoint. The caller
    /// must already have compared the complete native tuple with its retained
    /// prefix; this constructor additionally consumes the exact canonical
    /// root expectation before accepting an entry. Archive bootstrap provenance
    /// remains SnapshotArchive, never CarriedBank.
    pub(crate) fn from_restored_checkpoint(
        client: HistoricalRuntimeClient,
        checkpoint: HistoricalCheckpointSummary,
        verifier: Arc<SnapshotVerifier>,
        failure: Arc<ReplayFailure>,
        cursor: Arc<ReplayCursor>,
        progress: Arc<ReplayProgress>,
        live_start_slot: Slot,
    ) -> Result<Self, String> {
        validate_restored_bootstrap(
            client.initialized(),
            &checkpoint,
            live_start_slot,
            verifier.checkpoint_count_in_range(checkpoint.slot, checkpoint.slot) == 1,
        )?;
        verifier.verify_legacy_accounts_hash(
            checkpoint.slot,
            Hash::new_from_array(checkpoint.accounts_hash),
        );
        verifier.finish()?;
        Self::from_carried(
            client,
            checkpoint,
            Some(verifier),
            failure,
            cursor,
            progress,
            live_start_slot,
        )
    }

    /// Resumes an already authenticated worker at an epoch boundary.
    ///
    /// The checkpoint is copied into the new segment as its bootstrap
    /// evidence. No snapshot is loaded and no checkpoint supplied by a
    /// transport object is promoted to a trust anchor.
    pub(crate) fn from_carried(
        client: HistoricalRuntimeClient,
        bootstrap_checkpoint: HistoricalCheckpointSummary,
        snapshot_verifier: Option<Arc<SnapshotVerifier>>,
        failure: Arc<ReplayFailure>,
        cursor: Arc<ReplayCursor>,
        progress: Arc<ReplayProgress>,
        live_start_slot: Slot,
    ) -> Result<Self, String> {
        validate_carried_bootstrap(client.initialized().slot, &bootstrap_checkpoint)?;
        let checkpoint_slots = snapshot_verifier
            .as_ref()
            .map(|verifier| verifier.legacy_checkpoint_slots().into_iter().collect())
            .unwrap_or_default();
        Ok(Self {
            state: Mutex::new(HistoricalReplayState {
                client: Some(client),
                current_slot: bootstrap_checkpoint.slot,
                last_checkpoint_slot: Some(bootstrap_checkpoint.slot),
                bootstrap_checkpoint: Some(bootstrap_checkpoint),
                terminal_checkpoint: None,
                emitted_write_versions: None,
            }),
            snapshot_verifier,
            checkpoint_slots: Mutex::new(checkpoint_slots),
            failure,
            cursor,
            progress,
            live_start_slot,
            diagnostic_warmup_target: None,
        })
    }

    pub(crate) fn process_ready_entries(&self, entries: Vec<ReadyEntry>) {
        let supports_entry_batches = self
            .state
            .lock()
            .expect("historical replay lock poisoned")
            .client
            .as_ref()
            .expect("historical client is present while replay is active")
            .supports_entry_batches();
        if supports_entry_batches {
            self.process_ready_entries_batched(entries);
        } else {
            self.process_ready_entries_sequential(entries);
        }
    }

    fn process_ready_entries_sequential(&self, entries: Vec<ReadyEntry>) {
        for mut entry in entries {
            if self.failure.shutdown_requested() {
                return;
            }
            let entry_start = Instant::now();
            let signature = entry
                .txs
                .first()
                .and_then(|scheduled| scheduled.tx.signatures.first())
                .map(ToString::to_string);
            self.cursor.start_inflight(
                entry.slot,
                entry.entry_index,
                entry.start_index,
                entry.tx_count,
                signature.clone(),
            );
            let inflight_guard = InFlightGuard {
                cursor: self.cursor.clone(),
            };
            self.cursor.update_inflight_stage("historical_encode");

            let encoded = match entry
                .txs
                .iter()
                .map(|scheduled| encode_legacy_transaction(&scheduled.tx))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(encoded) => encoded,
                Err(error) => {
                    self.failure.record(format!(
                        "historical transaction encoding failed at slot {} entry {}: {error}",
                        entry.slot, entry.entry_index
                    ));
                    return;
                }
            };

            self.cursor.update_inflight_stage("historical_execute");
            let execute_start = Instant::now();
            let processed = {
                let mut state = self.state.lock().expect("historical replay lock poisoned");
                let result = state
                    .client
                    .as_mut()
                    .expect("historical client is present while replay is active")
                    .process_entry(
                        entry.slot,
                        entry.entry_index as u64,
                        entry.num_hashes,
                        entry.hash.to_bytes(),
                        encoded,
                    );
                if result.is_ok() {
                    state.current_slot = entry.slot;
                    // Every accepted entry mutates the working bank, including
                    // later entries in the same slot. A cached checkpoint is
                    // reusable only while no entry has executed since it.
                    state.last_checkpoint_slot = None;
                    state.terminal_checkpoint = None;
                }
                result
            };
            PHASE_EXECUTE_US.fetch_add(
                execute_start.elapsed().as_micros() as u64,
                Ordering::Relaxed,
            );
            let processed = match processed {
                Ok(processed) => processed,
                Err(error) => {
                    self.failure.record(format!(
                        "historical worker failed at slot {} entry {}: {error}",
                        entry.slot, entry.entry_index
                    ));
                    return;
                }
            };

            self.cursor.update_inflight_stage("historical_verify");
            if let Err(error) = Self::verify_outcomes(&mut entry, &processed.outcomes) {
                self.failure.record(error);
                return;
            }
            if let Err(error) = self.record_writes(processed.writes) {
                self.failure.record(error);
                return;
            }

            let post_start = Instant::now();
            if entry.slot >= self.live_start_slot {
                plugin::notify_transaction_range(entry.slot, entry.start_index, entry.tx_count);
                if let Some(recorder) = horizon::recorder() {
                    let transactions = std::mem::take(&mut entry.txs)
                        .into_iter()
                        .map(|scheduled| (scheduled.tx, scheduled.status_meta))
                        .collect();
                    recorder.record_committed_entry(
                        entry.slot,
                        entry.entry_index,
                        entry.num_hashes,
                        transactions,
                    );
                }
            }
            self.cursor.update(
                entry.slot,
                entry.entry_index,
                entry.start_index,
                entry.tx_count,
                signature,
            );
            PHASE_POST_PROCESS_US
                .fetch_add(post_start.elapsed().as_micros() as u64, Ordering::Relaxed);
            PHASE_ENTRY_COUNT.fetch_add(1, Ordering::Relaxed);

            // The entry itself is complete. Checkpoint hashing is deliberately
            // supervised by the worker's much larger checkpoint timeout, not
            // the replay watchdog's per-entry budget.
            drop(inflight_guard);

            // Channel batches may end in the middle of a slot. The worker's
            // tick-height proof, rather than a queue boundary, determines when
            // the bank is safe to checkpoint and freeze.
            if processed.slot_complete
                && self.take_checkpoint_slot(entry.slot)
                && let Err(error) = self.checkpoint_current(entry.slot)
            {
                self.failure.record(error);
                return;
            }

            let elapsed = entry_start.elapsed();
            if elapsed >= super::ENTRY_EXEC_WARN_AFTER {
                info!(
                    "historical entry slot={} index={} txs={} took {:.3}s",
                    entry.slot,
                    entry.entry_index,
                    entry.tx_count,
                    elapsed.as_secs_f64()
                );
            }
        }
    }

    fn process_ready_entries_batched(&self, entries: Vec<ReadyEntry>) {
        let mut encoded = Vec::with_capacity(entries.len());
        for entry in entries {
            if self.failure.shutdown_requested() {
                return;
            }
            let transactions = match entry
                .txs
                .iter()
                .map(|scheduled| encode_legacy_transaction(&scheduled.tx))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(transactions) => transactions,
                Err(error) => {
                    self.failure.record(format!(
                        "historical transaction encoding failed at slot {} entry {}: {error}",
                        entry.slot, entry.entry_index
                    ));
                    return;
                }
            };
            let transaction_bytes = transactions.iter().fold(0usize, |total, transaction| {
                total.saturating_add(transaction.len()).saturating_add(8)
            });
            encoded.push(EncodedReadyEntry {
                entry,
                transactions,
                transaction_bytes,
            });
        }

        let mut checkpoints = self
            .checkpoint_slots
            .lock()
            .expect("historical checkpoint set lock poisoned")
            .clone();
        // Transport boundary only: do not add a synthetic canonical checkpoint.
        if let Some(target) = self.diagnostic_warmup_target {
            checkpoints.insert(target);
        }
        for batch in partition_entry_batches(encoded, &checkpoints) {
            if self.failure.shutdown_requested() {
                return;
            }
            if !self.process_ready_batch(batch) {
                return;
            }
        }
    }

    fn process_ready_batch(&self, mut batch: Vec<EncodedReadyEntry>) -> bool {
        let Some(first) = batch.first() else {
            return true;
        };
        let batch_len = batch.len();
        let first_slot = first.entry.slot;
        let first_entry_index = first.entry.entry_index;
        let first_signature = ready_entry_signature(&first.entry);
        self.cursor.start_inflight(
            first_slot,
            first_entry_index,
            first.entry.start_index,
            first.entry.tx_count,
            first_signature,
        );
        let execute_guard = InFlightGuard {
            cursor: self.cursor.clone(),
        };
        self.cursor
            .update_inflight_stage("historical_batch_execute");
        let execute_start = Instant::now();
        let last_slot = batch.last().expect("nonempty batch").entry.slot;
        let requests = batch
            .iter_mut()
            .map(|encoded| HistoricalEntryRequest {
                slot: encoded.entry.slot,
                entry_index: encoded.entry.entry_index as u64,
                num_hashes: encoded.entry.num_hashes,
                hash: encoded.entry.hash.to_bytes(),
                transactions: std::mem::take(&mut encoded.transactions),
            })
            .collect();
        let last_entry_index = batch.last().expect("nonempty batch").entry.entry_index;
        let mut entries = batch.into_iter();
        let mut current = entries.next().expect("nonempty batch");
        let mut current_outcomes = Vec::new();
        let mut outcomes_verified = false;
        #[cfg(feature = "epoch224-account-delta-diagnostic")]
        let mut epoch224_seen_transaction_writes = BTreeSet::new();
        let mut checkpoint_after = None;
        let processed = {
            let mut state = self.state.lock().expect("historical replay lock poisoned");
            let HistoricalReplayState {
                client,
                current_slot,
                last_checkpoint_slot,
                terminal_checkpoint,
                emitted_write_versions,
                ..
            } = &mut *state;
            client
                .as_mut()
                .expect("historical client is present while replay is active")
                .process_entries_with(requests, |item| {
                match item {
                    HistoricalEntryStreamItem::Outcomes {
                        slot,
                        entry_index,
                        outcomes,
                    } => {
                        if current.entry.slot != slot
                            || current.entry.entry_index as u64 != entry_index
                        {
                            return Err(format!(
                                "historical outcome stream identifies slot {slot} entry {entry_index}, expected slot {} entry {}",
                                current.entry.slot, current.entry.entry_index
                            ));
                        }
                        current_outcomes.extend(outcomes);
                    }
                    HistoricalEntryStreamItem::Writes {
                        slot,
                        entry_index,
                        writes,
                    } => {
                        if current.entry.slot != slot
                            || current.entry.entry_index as u64 != entry_index
                        {
                            return Err(format!(
                                "historical write stream identifies slot {slot} entry {entry_index}, expected slot {} entry {}",
                                current.entry.slot, current.entry.entry_index
                            ));
                        }
                        if !outcomes_verified {
                            Self::verify_outcomes(&mut current.entry, &current_outcomes)?;
                            outcomes_verified = true;
                        }
                        #[cfg(feature = "epoch224-account-delta-diagnostic")]
                        verify_epoch224_transaction_write_lamports(
                            &current.entry,
                            &writes,
                            &mut epoch224_seen_transaction_writes,
                        )?;
                        let extended = extend_emitted_write_versions(
                            emitted_write_versions.as_ref(),
                            self.live_start_slot,
                            &writes,
                        )?;
                        self.emit_writes(writes);
                        *emitted_write_versions = extended;
                    }
                    HistoricalEntryStreamItem::End {
                        slot,
                        entry_index,
                        slot_complete,
                        ..
                    } => {
                        if current.entry.slot != slot
                            || current.entry.entry_index as u64 != entry_index
                        {
                            return Err(format!(
                                "historical entry end identifies slot {slot} entry {entry_index}, expected slot {} entry {}",
                                current.entry.slot, current.entry.entry_index
                            ));
                        }
                        let entry = &mut current.entry;
                        let signature = ready_entry_signature(entry);
                        self.cursor.update_inflight_stage("historical_verify");
                        if !outcomes_verified {
                            Self::verify_outcomes(entry, &current_outcomes)?;
                        }
                        #[cfg(feature = "epoch224-account-delta-diagnostic")]
                        verify_epoch224_changed_lamport_writes(
                            entry,
                            &epoch224_seen_transaction_writes,
                        )?;

                        let post_start = Instant::now();
                        if entry.slot >= self.live_start_slot {
                            plugin::notify_transaction_range(
                                entry.slot,
                                entry.start_index,
                                entry.tx_count,
                            );
                            if let Some(recorder) = horizon::recorder() {
                                let transactions = std::mem::take(&mut entry.txs)
                                    .into_iter()
                                    .map(|scheduled| (scheduled.tx, scheduled.status_meta))
                                    .collect();
                                recorder.record_committed_entry(
                                    entry.slot,
                                    entry.entry_index,
                                    entry.num_hashes,
                                    transactions,
                                );
                            }
                        }
                        self.cursor.update(
                            entry.slot,
                            entry.entry_index,
                            entry.start_index,
                            entry.tx_count,
                            signature,
                        );
                        PHASE_POST_PROCESS_US.fetch_add(
                            post_start.elapsed().as_micros() as u64,
                            Ordering::Relaxed,
                        );
                        PHASE_ENTRY_COUNT.fetch_add(1, Ordering::Relaxed);
                        *current_slot = slot;
                        *last_checkpoint_slot = None;
                        *terminal_checkpoint = None;
                        if slot_complete && self.take_checkpoint_slot(slot) {
                            checkpoint_after = Some(slot);
                        }
                        self.pause_completed_bounded_warmup(slot, slot_complete)?;

                        current_outcomes.clear();
                        outcomes_verified = false;
                        #[cfg(feature = "epoch224-account-delta-diagnostic")]
                        epoch224_seen_transaction_writes.clear();
                        if let Some(next) = entries.next() {
                            current = next;
                            self.cursor.start_inflight(
                                current.entry.slot,
                                current.entry.entry_index,
                                current.entry.start_index,
                                current.entry.tx_count,
                                ready_entry_signature(&current.entry),
                            );
                            self.cursor
                                .update_inflight_stage("historical_batch_execute");
                        }
                    }
                }
                Ok(())
                })
        };
        let execute_elapsed = execute_start.elapsed();
        PHASE_EXECUTE_US.fetch_add(execute_elapsed.as_micros() as u64, Ordering::Relaxed);
        drop(execute_guard);
        match processed {
            Ok(()) => {}
            Err(error) => {
                self.failure.record(format!(
                    "historical worker batch failed from slot {} entry {} through slot {} entry {}: {error}",
                    first_slot,
                    first_entry_index,
                    last_slot,
                    last_entry_index,
                ));
                return false;
            }
        }
        if let Some(slot) = checkpoint_after
            && let Err(error) = self.checkpoint_current(slot)
        {
            self.failure.record(error);
            return false;
        }

        if execute_elapsed >= super::ENTRY_EXEC_WARN_AFTER {
            info!(
                "historical entry batch entries={} through_slot={} took {:.3}s",
                batch_len,
                last_slot,
                execute_elapsed.as_secs_f64(),
            );
        }
        true
    }

    pub(crate) fn verify_latest_bank(&self) -> Result<(), String> {
        let slot = self.current_slot()?;
        self.checkpoint_current(slot)
    }

    pub(crate) fn freeze_latest_bank(&self) -> Result<(), String> {
        let slot = self.current_slot()?;
        self.checkpoint_current(slot)
    }

    /// Returns replay evidence only for a fully checkpointed segment.
    pub(crate) fn evidence(&self) -> Result<HistoricalReplayEvidence, String> {
        if let Some(error) = self.failure.error_message() {
            return Err(format!(
                "historical replay evidence is unavailable after replay failure: {error}"
            ));
        }
        if let Some(verifier) = self.snapshot_verifier.as_ref()
            && let Some(error) = verifier.error_summary()
        {
            return Err(format!(
                "historical replay evidence is unavailable after checkpoint verification failure: {error}"
            ));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| "historical replay lock poisoned while reading evidence".to_string())?;
        assemble_evidence(
            state.bootstrap_checkpoint.as_ref(),
            state.terminal_checkpoint.as_ref(),
            state.current_slot,
            state.emitted_write_versions.as_ref(),
        )
    }

    pub(crate) fn export_snapshot(
        &self,
        slot: Slot,
        output_directory: &Path,
        expected_accounts_hash: [u8; 32],
        expected_archive_extension: &str,
    ) -> Result<HistoricalSnapshotExport, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "historical replay lock poisoned while exporting snapshot".to_string())?;
        if state.current_slot != slot {
            return Err(format!(
                "historical snapshot export requested for slot {slot}, current worker slot is {}",
                state.current_slot
            ));
        }
        let result = state
            .client
            .as_mut()
            .ok_or_else(|| "historical client was already carried into another epoch".to_string())?
            .export_snapshot(
                slot,
                output_directory,
                expected_accounts_hash,
                expected_archive_extension,
            );
        // Export is a one-use operation in both the parent client and worker.
        // Once attempted, the cached checkpoint can still serve as evidence,
        // but it no longer proves that an export seal is available. Force the
        // next `freeze_latest_bank` call to issue a fresh FreezeCheckpoint so
        // a failed export can be retried safely.
        consume_checkpoint_export_seal(&mut state.last_checkpoint_slot);
        result.map_err(|error| format!("historical snapshot export at slot {slot} failed: {error}"))
    }

    pub(crate) fn shutdown(&self) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| {
            "historical replay lock poisoned while shutting down worker".to_string()
        })?;
        match state.client.as_mut() {
            Some(client) => client
                .shutdown()
                .map_err(|error| format!("historical worker shutdown failed: {error}")),
            None => Ok(()),
        }
    }

    /// Transfers the live worker to the next epoch after terminal evidence is
    /// sealed. Calling this before a complete terminal checkpoint fails.
    pub(crate) fn take_client(&self) -> Result<HistoricalRuntimeClient, String> {
        let mut state = self.state.lock().map_err(|_| {
            "historical replay lock poisoned while carrying worker state".to_string()
        })?;
        assemble_evidence(
            state.bootstrap_checkpoint.as_ref(),
            state.terminal_checkpoint.as_ref(),
            state.current_slot,
            state.emitted_write_versions.as_ref(),
        )?;
        state
            .client
            .take()
            .ok_or_else(|| "historical client was already carried into another epoch".to_string())
    }

    fn current_slot(&self) -> Result<Slot, String> {
        self.state
            .lock()
            .map(|state| state.current_slot)
            .map_err(|_| "historical replay lock poisoned".to_string())
    }

    fn verify_outcomes(
        entry: &mut ReadyEntry,
        outcomes: &[crate::historical::HistoricalTransactionOutcome],
    ) -> Result<(), String> {
        if outcomes.len() != entry.txs.len() {
            return Err(format!(
                "historical outcome count mismatch at slot {} entry {}: expected {}, got {}",
                entry.slot,
                entry.entry_index,
                entry.txs.len(),
                outcomes.len()
            ));
        }
        for (offset, (scheduled, actual)) in entry.txs.iter().zip(outcomes).enumerate() {
            let expected_signature = scheduled
                .tx
                .signatures
                .first()
                .map(|signature| *signature.as_array());
            if actual.signature != expected_signature {
                return Err(format!(
                    "historical signature mismatch at slot {} entry {} transaction {}",
                    entry.slot,
                    entry.entry_index,
                    entry.start_index + offset
                ));
            }
        }

        for (offset, (scheduled, actual)) in entry.txs.iter_mut().zip(outcomes).enumerate() {
            if let Some(expected_status) = scheduled.expected_status.as_ref() {
                let expected_error: Option<HistoricalTransactionError> = expected_status
                    .as_ref()
                    .err()
                    .map(normalize_transaction_error)
                    .transpose()
                    .map_err(|error| {
                        format!(
                            "historical expected-status conversion failed at slot {} entry {} transaction {}: {error}",
                            entry.slot,
                            entry.entry_index,
                            entry.start_index + offset
                        )
                    })?;
                if actual.error != expected_error {
                    return Err(format!(
                        "historical execution mismatch at slot {} entry {} transaction {} signature {}: expected {:?}, got {:?}",
                        entry.slot,
                        entry.entry_index,
                        entry.start_index + offset,
                        scheduled
                            .tx
                            .signatures
                            .first()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "<none>".to_string()),
                        expected_error,
                        actual.error
                    ));
                }
                if scheduled.reconstruct_fee {
                    // The exact missing-frame exception carries an audited
                    // status but no canonical metadata. Keep the verified
                    // status and the runtime-associated fee.
                    apply_runtime_reconstructed_metadata(scheduled, actual);
                } else if actual.fee != scheduled.status_meta.fee {
                    return Err(format!(
                        "historical fee mismatch at slot {} entry {} transaction {}: expected {}, got {}",
                        entry.slot,
                        entry.entry_index,
                        entry.start_index + offset,
                        scheduled.status_meta.fee,
                        actual.fee,
                    ));
                }
            } else {
                // Missing or misassociated source status is not ground truth.
                // Preserve the historical executor's result in the generated
                // archive.
                // The source writer bug also paired the original transaction
                // with another transaction's durable-nonce fee calculator.
                // Exact missing-frame exceptions have no source fee at all.
                apply_runtime_reconstructed_metadata(scheduled, actual);
            }
        }
        Ok(())
    }

    fn take_checkpoint_slot(&self, slot: Slot) -> bool {
        self.checkpoint_slots
            .lock()
            .expect("historical checkpoint set lock poisoned")
            .remove(&slot)
    }

    fn checkpoint_current(&self, slot: Slot) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "historical replay lock poisoned while checkpointing".to_string())?;
        if state.current_slot != slot {
            return Err(format!(
                "historical checkpoint requested for slot {slot}, current worker slot is {}",
                state.current_slot
            ));
        }
        if !checkpoint_refresh_required(state.last_checkpoint_slot, slot) {
            return Ok(());
        }
        let checkpoint = state
            .client
            .as_mut()
            .ok_or_else(|| "historical client was already carried into another epoch".to_string())?
            .freeze_checkpoint(slot)
            .map_err(|error| format!("historical checkpoint at slot {slot} failed: {error}"))?;
        let emitted_write_versions = extend_emitted_write_versions(
            state.emitted_write_versions.as_ref(),
            self.live_start_slot,
            &checkpoint.writes,
        )?;
        let summary = HistoricalCheckpointSummary::try_from(&checkpoint)?;
        self.verify_checkpoint(&checkpoint);
        self.emit_writes(checkpoint.writes);
        state.emitted_write_versions = emitted_write_versions;
        if state.bootstrap_checkpoint.is_none() {
            state.bootstrap_checkpoint = Some(summary.clone());
        }
        state.terminal_checkpoint = Some(summary);
        state.last_checkpoint_slot = Some(slot);
        Ok(())
    }

    fn verify_checkpoint(&self, checkpoint: &HistoricalCheckpoint) {
        if let Some(verifier) = self.snapshot_verifier.as_ref() {
            verifier.verify_legacy_accounts_hash(
                checkpoint.slot,
                Hash::new_from_array(checkpoint.accounts_hash),
            );
        }
        info!(
            "historical checkpoint slot={} bank_hash={} accounts_hash={} last_blockhash={} capitalization={} transactions={} tick_height={} complete={} writes={} next_write_version={}",
            checkpoint.slot,
            Hash::new_from_array(checkpoint.bank_hash),
            Hash::new_from_array(checkpoint.accounts_hash),
            Hash::new_from_array(checkpoint.last_blockhash),
            checkpoint.capitalization,
            checkpoint.transaction_count,
            checkpoint.tick_height,
            checkpoint.slot_complete,
            checkpoint.writes.len(),
            checkpoint.next_write_version,
        );
    }

    fn record_writes(&self, writes: Vec<HistoricalAccountWrite>) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "historical replay lock poisoned while recording writes".to_string())?;
        let emitted_write_versions = extend_emitted_write_versions(
            state.emitted_write_versions.as_ref(),
            self.live_start_slot,
            &writes,
        )?;
        self.emit_writes(writes);
        state.emitted_write_versions = emitted_write_versions;
        Ok(())
    }

    fn emit_writes(&self, writes: Vec<HistoricalAccountWrite>) {
        for write in writes {
            self.progress.note_account_update_slot(write.slot);
            self.progress.inc_account_update();
            if write.slot < self.live_start_slot {
                continue;
            }
            plugin::notify_account_update_data_len(write.data.len());
            horizon::note_historical_account_update(
                write.slot,
                Address::new_from_array(write.pubkey),
                write.lamports,
                Address::new_from_array(write.owner),
                write.executable,
                write.rent_epoch,
                write.write_version,
                write.data,
                write.transaction_signature.map(Signature::from),
            );
        }
    }
    fn pause_completed_bounded_warmup(&self, slot: Slot, complete: bool) -> Result<(), String> {
        cooperate_bounded_warmup_stop(&self.failure, self.diagnostic_warmup_target, slot, complete)
    }
}
fn cooperate_bounded_warmup_stop(
    failure: &ReplayFailure,
    target: Option<Slot>,
    slot: Slot,
    complete: bool,
) -> Result<(), String> {
    if target != Some(slot) || !complete {
        return Ok(());
    }
    // Every outcome/write was checked before reaching this complete-slot
    // response. Never enqueue the worker's first forbidden batch. The
    // reviewed supervisor captures the stopped group, then resumes/drains it.
    failure.shutdown.store(true, Ordering::SeqCst);
    if cfg!(feature = "epoch227-v1-6-25-diagnostic") && slot == 98_091_122 {
        info!(target: "jetstreamer_node", "private epoch227 v1625 comparison complete slot={slot} complete=true");
    } else {
        info!(target: "jetstreamer_node", "private epoch223 warmup complete slot={slot} complete=true");
    }
    std::io::Write::flush(&mut std::io::stderr())
        .map_err(|e| format!("bounded warmup marker flush: {e}"))?;
    if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
        return Err("bounded warmup cooperative stop failed".into());
    }
    Ok(())
}

fn bounded_epoch223_warmup_target(
    worker: [u8; 32],
    bootstrap: Slot,
    live_start: Slot,
) -> Option<Slot> {
    // Only the separately sealed sixteen-slot worker, never a full prefix or
    // another runtime. Ordinary builds cannot activate the cooperative stop.
    const WORKER: [u8; 32] = [
        0x52, 0xd6, 0xc8, 0x6a, 0x81, 0x03, 0xb8, 0x96, 0x5c, 0xa6, 0x8e, 0xad, 0x96, 0xaf, 0x47,
        0x1a, 0x78, 0x99, 0xa0, 0xa0, 0xe6, 0xe6, 0x9c, 0x48, 0x98, 0x9b, 0x39, 0xfd, 0x5d, 0x92,
        0x2f, 0x0c,
    ];
    (cfg!(feature = "epoch223-v1-6-20-prefix-qualification")
        && worker == WORKER
        && bootstrap == 96_335_538
        && live_start == 96_336_000)
        .then_some(96_335_554)
}

fn bounded_epoch227_comparison_target(
    worker: [u8; 32],
    bootstrap: Slot,
    live_start: Slot,
) -> Option<Slot> {
    const WORKER: [u8; 32] = [
        0xd0, 0x1a, 0xdb, 0x19, 0x80, 0xee, 0x52, 0xa5, 0x9a, 0x7a, 0xff, 0x7a, 0x3a, 0x04, 0x96,
        0x74, 0x6c, 0xa3, 0x25, 0xe5, 0xfc, 0x65, 0x58, 0x17, 0xd9, 0xa7, 0x74, 0x3a, 0x19, 0x13,
        0xef, 0x62,
    ];
    (cfg!(feature = "epoch227-v1-6-25-diagnostic")
        && worker == WORKER
        && bootstrap == 98_063_464
        && live_start == 98_064_000)
        .then_some(98_091_122)
}

fn bounded_diagnostic_checkpoints(target: Slot, canonical: &BTreeSet<Slot>) -> bool {
    let required = match target {
        96_335_554 => [96_335_538, 96_767_522],
        98_091_122 => [98_063_464, 98_495_291],
        _ => return false,
    };
    required.iter().all(|slot| canonical.contains(slot))
}

fn ready_entry_signature(entry: &ReadyEntry) -> Option<String> {
    entry
        .txs
        .first()
        .and_then(|scheduled| scheduled.tx.signatures.first())
        .map(ToString::to_string)
}

fn partition_entry_batches(
    entries: Vec<EncodedReadyEntry>,
    checkpoint_slots: &BTreeSet<Slot>,
) -> Vec<Vec<EncodedReadyEntry>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_transaction_bytes = 0usize;
    let mut current_slots = 0usize;
    let mut last_slot = None;
    let mut checkpoint_boundary = None;

    for entry in entries {
        let slot = entry.entry.slot;
        let starts_new_slot = last_slot != Some(slot);
        let crosses_checkpoint = checkpoint_boundary
            .map(|checkpoint| slot > checkpoint)
            .unwrap_or(false);
        let exceeds_slots = starts_new_slot && current_slots >= HISTORICAL_BATCH_MAX_SLOTS;
        let exceeds_bytes = current_transaction_bytes.saturating_add(entry.transaction_bytes)
            > HISTORICAL_BATCH_TRANSACTION_BYTES;
        if !current.is_empty()
            && (current.len() >= MAX_ENTRIES_PER_BATCH
                || crosses_checkpoint
                || exceeds_slots
                || exceeds_bytes)
        {
            batches.push(current);
            current = Vec::new();
            current_transaction_bytes = 0;
            current_slots = 0;
            last_slot = None;
            checkpoint_boundary = None;
        }

        if last_slot != Some(slot) {
            current_slots += 1;
            last_slot = Some(slot);
        }
        current_transaction_bytes =
            current_transaction_bytes.saturating_add(entry.transaction_bytes);
        if checkpoint_slots.contains(&slot) {
            checkpoint_boundary = Some(slot);
        }
        current.push(entry);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

fn checkpoint_refresh_required(last_checkpoint_slot: Option<Slot>, slot: Slot) -> bool {
    last_checkpoint_slot != Some(slot)
}

fn checkpoint_initialized_state(source: HistoricalInitializedSource) -> bool {
    source == HistoricalInitializedSource::SnapshotArchive
}

fn validate_carried_bootstrap(
    initialized_slot: Slot,
    checkpoint: &HistoricalCheckpointSummary,
) -> Result<(), String> {
    if !checkpoint.slot_complete {
        return Err(format!(
            "carried historical checkpoint at slot {} is incomplete",
            checkpoint.slot
        ));
    }
    if initialized_slot > checkpoint.slot {
        return Err(format!(
            "carried historical checkpoint slot {} precedes worker initialization slot {}",
            checkpoint.slot, initialized_slot
        ));
    }
    Ok(())
}

fn validate_restored_bootstrap(
    initialized: &crate::historical::HistoricalInitialized,
    checkpoint: &HistoricalCheckpointSummary,
    live_start_slot: Slot,
    exact_root_present: bool,
) -> Result<(), String> {
    if initialized.source != HistoricalInitializedSource::SnapshotArchive
        || initialized.slot != checkpoint.slot
        || initialized.last_blockhash != checkpoint.last_blockhash
        || initialized.next_write_version != checkpoint.next_write_version
        || checkpoint.write_count != 0
        || !checkpoint.slot_complete
        || live_start_slot
            != checkpoint
                .slot
                .checked_add(1)
                .ok_or("checkpoint slot overflow")?
        || !exact_root_present
    {
        return Err("restored checkpoint must be an untouched complete snapshot with its exact canonical root".into());
    }
    Ok(())
}

fn consume_checkpoint_export_seal(last_checkpoint_slot: &mut Option<Slot>) {
    *last_checkpoint_slot = None;
}

fn extend_emitted_write_versions(
    current: Option<&Range<u64>>,
    live_start_slot: Slot,
    writes: &[HistoricalAccountWrite],
) -> Result<Option<Range<u64>>, String> {
    let mut extended = current.cloned();
    for write in writes {
        if write.slot < live_start_slot {
            continue;
        }
        let end = write.write_version.checked_add(1).ok_or_else(|| {
            format!(
                "historical live write version overflow at slot {} version {}",
                write.slot, write.write_version
            )
        })?;
        match extended.as_mut() {
            Some(range) if range.end != write.write_version => {
                return Err(format!(
                    "historical live write stream is not contiguous: expected version {}, got {} at slot {}",
                    range.end, write.write_version, write.slot
                ));
            }
            Some(range) => range.end = end,
            None => extended = Some(write.write_version..end),
        }
    }
    Ok(extended)
}

fn assemble_evidence(
    bootstrap: Option<&HistoricalCheckpointSummary>,
    terminal: Option<&HistoricalCheckpointSummary>,
    current_slot: Slot,
    emitted_write_versions: Option<&Range<u64>>,
) -> Result<HistoricalReplayEvidence, String> {
    let bootstrap = bootstrap
        .ok_or_else(|| "historical replay has no bootstrap checkpoint evidence".to_string())?;
    let terminal = terminal
        .ok_or_else(|| "historical replay has no terminal checkpoint evidence".to_string())?;
    if !bootstrap.slot_complete {
        return Err(format!(
            "historical bootstrap checkpoint at slot {} is incomplete",
            bootstrap.slot
        ));
    }
    if !terminal.slot_complete {
        return Err(format!(
            "historical terminal checkpoint at slot {} is incomplete",
            terminal.slot
        ));
    }
    if terminal.slot < bootstrap.slot {
        return Err(format!(
            "historical terminal checkpoint slot {} precedes bootstrap slot {}",
            terminal.slot, bootstrap.slot
        ));
    }
    if terminal.slot != current_slot {
        return Err(format!(
            "historical terminal checkpoint is stale: checkpoint slot {}, current worker slot {}",
            terminal.slot, current_slot
        ));
    }

    let emitted_write_versions = match emitted_write_versions {
        Some(range) => {
            if range.start >= range.end {
                return Err(format!(
                    "historical emitted write-version range is invalid: {}..{}",
                    range.start, range.end
                ));
            }
            if range.end != terminal.next_write_version {
                return Err(format!(
                    "historical terminal write cursor {} does not match emitted range end {}",
                    terminal.next_write_version, range.end
                ));
            }
            range.clone()
        }
        None => terminal.next_write_version..terminal.next_write_version,
    };

    Ok(HistoricalReplayEvidence {
        bootstrap: bootstrap.clone(),
        terminal: terminal.clone(),
        emitted_write_versions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded227_selection_rejects_full_worker_and_preserves_real_checkpoint_pair() {
        let bytes = |text: &str| {
            std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
        };
        let bounded = bytes("d01adb1980ee52a59a7aff7a3a0496746ca325e5fc655817d9a7743a1913ef62");
        assert_eq!(
            bounded_epoch227_comparison_target(bounded, 98_063_464, 98_064_000),
            cfg!(feature = "epoch227-v1-6-25-diagnostic").then_some(98_091_122)
        );
        for (worker, bootstrap, start) in [
            (bounded, 98_063_463, 98_064_000),
            (bounded, 98_063_464, 98_064_001),
            (
                bytes("7a831420bb1498ddb0268309ce69f615c7f0c6d90cfab940896a03dc38b5336a"),
                98_063_464,
                98_064_000,
            ),
            (
                bytes("710f6523d15b960f79d91935d18d581a341e04e649df26ccd0a2b31ae9bc3eeb"),
                98_063_464,
                98_064_000,
            ),
        ] {
            assert!(bounded_epoch227_comparison_target(worker, bootstrap, start).is_none());
        }
        let canonical = BTreeSet::from([98_063_464, 98_495_291]);
        assert!(bounded_diagnostic_checkpoints(98_091_122, &canonical));
        assert!(!bounded_diagnostic_checkpoints(98_091_123, &canonical));
        assert!(!bounded_diagnostic_checkpoints(
            98_091_122,
            &BTreeSet::from([98_063_464, 98_091_122])
        ));
        let mut transport = canonical.clone();
        transport.insert(98_091_122);
        let batches = partition_entry_batches(
            vec![
                encoded_ready(98_091_122, 0, 0),
                encoded_ready(98_091_122, 1, 0),
                encoded_ready(98_091_123, 0, 0),
            ],
            &transport,
        );
        assert_eq!(
            batch_slots(&batches),
            vec![vec![98_091_122, 98_091_122], vec![98_091_123]]
        );
        assert_eq!(canonical, BTreeSet::from([98_063_464, 98_495_291]));
        assert!(!canonical.contains(&98_091_122));
    }

    #[test]
    fn bounded_warmup_selection_is_exact_and_never_applies_to_full_prefix_worker() {
        let bytes = |text: &str| {
            std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
        };
        let worker = bytes("52d6c86a8103b8965ca68ead96af471a7899a0a0e6e69c48989b39fd5d922f0c");
        assert_eq!(
            bounded_epoch223_warmup_target(worker, 96_335_538, 96_336_000),
            cfg!(feature = "epoch223-v1-6-20-prefix-qualification").then_some(96_335_554)
        );
        assert!(bounded_epoch223_warmup_target(worker, 96_335_537, 96_336_000).is_none());
        assert!(bounded_epoch223_warmup_target(worker, 96_335_538, 96_336_001).is_none());
        assert!(
            bounded_epoch223_warmup_target(
                bytes("a651b7a6ee3c0d4f8359e1ea6cfcb96becf259d440ee744beb173b264de6af20"),
                96_335_538,
                96_336_000
            )
            .is_none()
        );
    }
    #[test]
    fn bounded_warmup_transport_split_does_not_create_a_canonical_checkpoint() {
        let canonical = BTreeSet::from([96_335_538, 96_767_522]);
        let mut transport = canonical.clone();
        transport.insert(96_335_554);
        let batches = partition_entry_batches(
            vec![
                encoded_ready(96_335_554, 0, 0),
                encoded_ready(96_335_554, 1, 0),
                encoded_ready(96_335_555, 0, 0),
            ],
            &transport,
        );
        assert_eq!(
            batch_slots(&batches),
            vec![vec![96_335_554, 96_335_554], vec![96_335_555]]
        );
        assert_eq!(canonical, BTreeSet::from([96_335_538, 96_767_522]));
    }
    #[test]
    fn bounded_warmup_stop_child() {
        if std::env::var("JETSTREAMER_TEST_BOUNDED_WARMUP_CHILD").as_deref() != Ok("yes") {
            return;
        }
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failure = ReplayFailure::new(shutdown.clone());
        cooperate_bounded_warmup_stop(&failure, Some(96_335_554), 96_335_554, true).unwrap();
        assert!(shutdown.load(Ordering::SeqCst));
        assert!(failure.error_message().is_none());
    }
    #[test]
    fn bounded_warmup_cooperatively_stops_until_supervisor_resumes_then_drains() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "historical_replay::tests::bounded_warmup_stop_child",
                "--nocapture",
            ])
            .env("JETSTREAMER_TEST_BOUNDED_WARMUP_CHILD", "yes")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let returned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = returned.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(5));
            if !guard.load(Ordering::SeqCst) {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        });
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        returned.store(true, Ordering::SeqCst);
        assert_eq!(waited, pid);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
        assert!(child.wait().unwrap().success());
    }

    fn encoded_ready(
        slot: Slot,
        entry_index: usize,
        transaction_bytes: usize,
    ) -> EncodedReadyEntry {
        EncodedReadyEntry {
            entry: ReadyEntry {
                slot,
                entry_index,
                start_index: 0,
                txs: Vec::new(),
                hash: Hash::default(),
                num_hashes: 1,
                tx_count: 0,
            },
            transactions: Vec::new(),
            transaction_bytes,
        }
    }

    fn batch_slots(batches: &[Vec<EncodedReadyEntry>]) -> Vec<Vec<Slot>> {
        batches
            .iter()
            .map(|batch| batch.iter().map(|entry| entry.entry.slot).collect())
            .collect()
    }

    fn account_write(slot: Slot, write_version: u64) -> HistoricalAccountWrite {
        HistoricalAccountWrite {
            slot,
            write_version,
            transaction_signature: None,
            pubkey: [0; 32],
            lamports: 0,
            owner: [0; 32],
            executable: false,
            rent_epoch: 0,
            data: Vec::new(),
            stored_hash: [0; 32],
        }
    }

    #[cfg(feature = "epoch224-account-delta-diagnostic")]
    fn epoch224_diagnostic_entry(
        slot: Slot,
        signature_byte: u8,
        key_byte: u8,
        pre_lamports: u64,
        post_lamports: u64,
    ) -> ReadyEntry {
        ReadyEntry {
            slot,
            entry_index: 8,
            start_index: 7,
            txs: vec![super::super::ScheduledTransaction {
                tx: solana_transaction::versioned::VersionedTransaction {
                    signatures: vec![Signature::from([signature_byte; 64])],
                    message: solana_message::VersionedMessage::Legacy(
                        solana_message::legacy::Message {
                            header: solana_message::MessageHeader {
                                num_required_signatures: 1,
                                ..Default::default()
                            },
                            account_keys: vec![Address::new_from_array([key_byte; 32])],
                            recent_blockhash: Hash::new_unique(),
                            instructions: vec![],
                        },
                    ),
                },
                expected_status: Some(Ok(())),
                reconstruct_fee: false,
                status_meta: solana_transaction_status::TransactionStatusMeta {
                    pre_balances: vec![pre_lamports],
                    post_balances: vec![post_lamports],
                    ..Default::default()
                },
            }],
            hash: Hash::default(),
            num_hashes: 1,
            tx_count: 1,
        }
    }

    #[cfg(feature = "epoch224-account-delta-diagnostic")]
    fn epoch224_transaction_write(
        signature_byte: u8,
        key_byte: u8,
        lamports: u64,
    ) -> HistoricalAccountWrite {
        HistoricalAccountWrite {
            transaction_signature: Some([signature_byte; 64]),
            pubkey: [key_byte; 32],
            lamports,
            ..account_write(EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT, 42)
        }
    }

    #[cfg(feature = "epoch224-account-delta-diagnostic")]
    #[test]
    fn epoch224_diagnostic_accepts_matching_transaction_write() {
        let entry =
            epoch224_diagnostic_entry(EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT, 3, 7, 100, 90);
        let write = epoch224_transaction_write(3, 7, 90);
        let mut seen = BTreeSet::new();

        verify_epoch224_transaction_write_lamports(&entry, std::slice::from_ref(&write), &mut seen)
            .unwrap();
        verify_epoch224_changed_lamport_writes(&entry, &seen).unwrap();
        assert!(seen.contains(&([3; 64], [7; 32])));
    }

    #[cfg(feature = "epoch224-account-delta-diagnostic")]
    #[test]
    fn epoch224_diagnostic_rejects_lamport_mismatch() {
        let entry =
            epoch224_diagnostic_entry(EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT, 3, 7, 100, 90);
        let error = verify_epoch224_transaction_write_lamports(
            &entry,
            &[epoch224_transaction_write(3, 7, 89)],
            &mut BTreeSet::new(),
        )
        .unwrap_err();

        assert!(error.contains("lamport mismatch"), "{error}");
        assert!(error.contains("expected 90, observed 89"), "{error}");
    }

    #[cfg(feature = "epoch224-account-delta-diagnostic")]
    #[test]
    fn epoch224_diagnostic_rejects_duplicate_final_write() {
        let entry =
            epoch224_diagnostic_entry(EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT, 3, 7, 100, 90);
        let write = epoch224_transaction_write(3, 7, 90);
        let mut seen = BTreeSet::new();
        verify_epoch224_transaction_write_lamports(&entry, std::slice::from_ref(&write), &mut seen)
            .unwrap();
        let error =
            verify_epoch224_transaction_write_lamports(&entry, &[write], &mut seen).unwrap_err();

        assert!(error.contains("duplicate final write"), "{error}");
    }

    #[cfg(feature = "epoch224-account-delta-diagnostic")]
    #[test]
    fn epoch224_diagnostic_rejects_missing_changed_key_write() {
        let entry =
            epoch224_diagnostic_entry(EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT, 3, 7, 100, 90);
        let error = verify_epoch224_changed_lamport_writes(&entry, &BTreeSet::new()).unwrap_err();

        assert!(error.contains("missing write"), "{error}");
        assert!(error.contains("pre 100, post 90"), "{error}");
    }

    #[cfg(feature = "epoch224-account-delta-diagnostic")]
    #[test]
    fn epoch224_diagnostic_rejects_missing_exact_metadata() {
        let mut entry =
            epoch224_diagnostic_entry(EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT, 3, 7, 100, 90);
        entry.txs[0].expected_status = None;
        let error = verify_epoch224_transaction_write_lamports(
            &entry,
            &[epoch224_transaction_write(3, 7, 90)],
            &mut BTreeSet::new(),
        )
        .unwrap_err();

        assert!(error.contains("lacks exact canonical metadata"), "{error}");
    }

    #[cfg(feature = "epoch224-account-delta-diagnostic")]
    #[test]
    fn epoch224_diagnostic_accepts_unattributed_freeze_write() {
        let entry =
            epoch224_diagnostic_entry(EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT, 3, 7, 100, 100);
        let mut freeze_write = account_write(EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT, 43);
        freeze_write.pubkey = [9; 32];
        freeze_write.lamports = 55;
        freeze_write.data = vec![1, 2, 3];
        let mut seen = BTreeSet::new();

        verify_epoch224_transaction_write_lamports(&entry, &[freeze_write], &mut seen).unwrap();
        verify_epoch224_changed_lamport_writes(&entry, &seen).unwrap();
        assert!(seen.is_empty());
    }

    #[cfg(feature = "epoch224-account-delta-diagnostic")]
    #[test]
    fn epoch224_diagnostic_rejects_signature_write_for_wrong_entry_slot() {
        let entry =
            epoch224_diagnostic_entry(EPOCH224_ACCOUNT_DELTA_DIAGNOSTIC_SLOT + 1, 3, 7, 100, 90);
        let error = verify_epoch224_transaction_write_lamports(
            &entry,
            &[epoch224_transaction_write(3, 7, 90)],
            &mut BTreeSet::new(),
        )
        .unwrap_err();

        assert!(error.contains("arrived with entry slot"), "{error}");
    }

    fn checkpoint_summary(slot: Slot, next_write_version: u64) -> HistoricalCheckpointSummary {
        HistoricalCheckpointSummary {
            slot,
            bank_hash: [1; 32],
            accounts_hash: [2; 32],
            last_blockhash: [3; 32],
            capitalization: 4,
            transaction_count: 5,
            tick_height: 6,
            slot_complete: true,
            write_count: 0,
            next_write_version,
        }
    }

    #[test]
    fn restored_bootstrap_requires_exact_unmodified_snapshot_and_real_root() {
        let checkpoint = checkpoint_summary(92_447_542, 94_273_483_349);
        let initialized = crate::historical::HistoricalInitialized {
            genesis_hash: jetstreamer_historical_protocol::MAINNET_GENESIS_HASH.into(),
            source: HistoricalInitializedSource::SnapshotArchive,
            slot: checkpoint.slot,
            last_blockhash: checkpoint.last_blockhash,
            ticks_per_slot: 64,
            next_write_version: checkpoint.next_write_version,
        };
        validate_restored_bootstrap(&initialized, &checkpoint, checkpoint.slot + 1, true).unwrap();
        assert!(
            validate_restored_bootstrap(&initialized, &checkpoint, checkpoint.slot + 1, false)
                .is_err()
        );
        assert!(
            validate_restored_bootstrap(&initialized, &checkpoint, checkpoint.slot + 2, true)
                .is_err()
        );
        for mutate in [
            |v: &mut crate::historical::HistoricalInitialized| {
                v.source = HistoricalInitializedSource::Genesis
            },
            |v: &mut crate::historical::HistoricalInitialized| v.slot -= 1,
            |v: &mut crate::historical::HistoricalInitialized| v.last_blockhash[0] ^= 1,
            |v: &mut crate::historical::HistoricalInitialized| v.next_write_version += 1,
        ] {
            let mut bad = initialized.clone();
            mutate(&mut bad);
            assert!(
                validate_restored_bootstrap(&bad, &checkpoint, checkpoint.slot + 1, true).is_err()
            );
        }
        let mut bad = checkpoint.clone();
        bad.write_count = 1;
        assert!(
            validate_restored_bootstrap(&initialized, &bad, checkpoint.slot + 1, true).is_err()
        );
        bad = checkpoint.clone();
        bad.slot_complete = false;
        assert!(
            validate_restored_bootstrap(&initialized, &bad, checkpoint.slot + 1, true).is_err()
        );
    }

    #[test]
    fn audited_missing_status_uses_the_historical_runtime_status_and_fee() {
        let audited_entry = || ReadyEntry {
            slot: 8_120_052,
            entry_index: 52,
            start_index: 79,
            txs: vec![super::super::ScheduledTransaction {
                tx: solana_transaction::versioned::VersionedTransaction::default(),
                expected_status: None,
                reconstruct_fee: true,
                status_meta: solana_transaction_status::TransactionStatusMeta::default(),
            }],
            hash: Hash::default(),
            num_hashes: 1,
            tx_count: 1,
        };
        let outcome = crate::historical::HistoricalTransactionOutcome {
            signature: None,
            error: None,
            fee: 5_000,
        };

        let mut entry = audited_entry();
        HistoricalReplay::verify_outcomes(&mut entry, std::slice::from_ref(&outcome)).unwrap();

        assert_eq!(
            entry.txs[0].status_meta,
            solana_transaction_status::TransactionStatusMeta {
                status: Ok(()),
                fee: 5_000,
                ..solana_transaction_status::TransactionStatusMeta::default()
            }
        );

        let mut entry = audited_entry();
        let failed_outcome = crate::historical::HistoricalTransactionOutcome {
            signature: None,
            error: Some(
                normalize_transaction_error(&solana_transaction::TransactionError::AccountNotFound)
                    .unwrap(),
            ),
            fee: 5_000,
        };
        HistoricalReplay::verify_outcomes(&mut entry, std::slice::from_ref(&failed_outcome))
            .unwrap();
        assert_eq!(
            entry.txs[0].status_meta.status,
            Err(solana_transaction::TransactionError::AccountNotFound)
        );
        assert_eq!(entry.txs[0].status_meta.fee, 5_000);
    }

    #[test]
    fn audited_canonical_metadata_preserves_ancillary_fields_but_uses_runtime_status_and_fee() {
        let expected_error = solana_transaction::TransactionError::InstructionError(
            0,
            solana_transaction::InstructionError::Custom(0),
        );
        let canonical_metadata = solana_transaction_status::TransactionStatusMeta {
            status: Err(expected_error.clone()),
            fee: 5_000,
            pre_balances: vec![10_000, 1],
            post_balances: vec![5_000, 1],
            ..solana_transaction_status::TransactionStatusMeta::default()
        };
        let audited_entry = || ReadyEntry {
            slot: 13_334_463,
            entry_index: 14,
            start_index: 13,
            txs: vec![super::super::ScheduledTransaction {
                tx: solana_transaction::versioned::VersionedTransaction::default(),
                expected_status: None,
                reconstruct_fee: true,
                status_meta: canonical_metadata.clone(),
            }],
            hash: Hash::default(),
            num_hashes: 1,
            tx_count: 1,
        };
        let outcome = crate::historical::HistoricalTransactionOutcome {
            signature: None,
            error: Some(normalize_transaction_error(&expected_error).unwrap()),
            fee: 7_000,
        };

        let mut entry = audited_entry();
        HistoricalReplay::verify_outcomes(&mut entry, std::slice::from_ref(&outcome)).unwrap();
        let mut expected_metadata = canonical_metadata.clone();
        expected_metadata.fee = 7_000;
        assert_eq!(entry.txs[0].status_meta, expected_metadata);

        let mut entry = audited_entry();
        let runtime_success = crate::historical::HistoricalTransactionOutcome {
            error: None,
            ..outcome
        };
        HistoricalReplay::verify_outcomes(&mut entry, std::slice::from_ref(&runtime_success))
            .unwrap();
        assert_eq!(entry.txs[0].status_meta.status, Ok(()));
        assert_eq!(entry.txs[0].status_meta.fee, 7_000);
        assert_eq!(entry.txs[0].status_meta.pre_balances, vec![10_000, 1]);
        assert_eq!(entry.txs[0].status_meta.post_balances, vec![5_000, 1]);
    }

    #[test]
    fn epoch_30_audited_hole_uses_runtime_status_association() {
        let vote_too_old = solana_transaction::TransactionError::InstructionError(
            0,
            solana_transaction::InstructionError::Custom(0),
        );
        let runtime_failure_signature: Signature =
            "3e4kde1Vo1EpM5bz8sctGmGnSgoxwi2TQVnKTvacCPL3SEud2QBkh6JG1Qs64LrH6kzCFwXrhg14SQK4yNEnA96r"
                .parse()
                .unwrap();
        let rpc_failure_signature: Signature =
            "BEGWJ7cztpfGAieC9mQQuuKWNee615fHVatKfssvQGdUjpJJHFtXSscoc1Kotucu4BmkEBmd9bmBq9FjmxmpKTb"
                .parse()
                .unwrap();
        let mut transactions = (0..15)
            .map(|_| super::super::ScheduledTransaction {
                tx: solana_transaction::versioned::VersionedTransaction::default(),
                expected_status: None,
                reconstruct_fee: true,
                status_meta: solana_transaction_status::TransactionStatusMeta::default(),
            })
            .collect::<Vec<_>>();
        transactions[1].tx.signatures = vec![runtime_failure_signature];
        transactions[13].tx.signatures = vec![rpc_failure_signature];

        let outcomes = (0..15)
            .map(|index| crate::historical::HistoricalTransactionOutcome {
                signature: transactions[index]
                    .tx
                    .signatures
                    .first()
                    .map(|signature| *signature.as_array()),
                error: (index == 1).then(|| normalize_transaction_error(&vote_too_old).unwrap()),
                fee: 5_000,
            })
            .collect::<Vec<_>>();
        let mut entry = ReadyEntry {
            slot: 13_334_463,
            entry_index: 14,
            start_index: 0,
            txs: transactions,
            hash: Hash::default(),
            num_hashes: 1,
            tx_count: 15,
        };

        HistoricalReplay::verify_outcomes(&mut entry, &outcomes).unwrap();
        assert_eq!(entry.txs[1].status_meta.status, Err(vote_too_old.clone()));
        assert_eq!(entry.txs[13].status_meta.status, Ok(()));
    }

    #[test]
    fn checkpoint_summary_records_write_count_without_retaining_writes() {
        let checkpoint = HistoricalCheckpoint {
            slot: 10,
            bank_hash: [1; 32],
            accounts_hash: [2; 32],
            last_blockhash: [3; 32],
            capitalization: 4,
            transaction_count: 5,
            tick_height: 6,
            slot_complete: true,
            writes: vec![account_write(10, 100), account_write(10, 101)],
            next_write_version: 102,
        };
        let summary = HistoricalCheckpointSummary::try_from(&checkpoint).unwrap();
        assert_eq!(summary.write_count, 2);
        assert_eq!(summary.next_write_version, 102);
    }

    #[test]
    fn entry_batches_stop_at_checkpoint_before_advancing_worker() {
        let entries = vec![
            encoded_ready(8, 0, 0),
            encoded_ready(9, 0, 0),
            encoded_ready(9, 1, 0),
            encoded_ready(10, 0, 0),
        ];
        let checkpoints = [9].into_iter().collect();
        let batches = partition_entry_batches(entries, &checkpoints);
        assert_eq!(batch_slots(&batches), vec![vec![8, 9, 9], vec![10]]);
    }

    #[test]
    fn entry_batches_bound_slot_span_and_payload_bytes() {
        let entries = (1..=6).map(|slot| encoded_ready(slot, 0, 0)).collect();
        let batches = partition_entry_batches(entries, &BTreeSet::new());
        assert_eq!(batch_slots(&batches), vec![vec![1, 2, 3, 4], vec![5, 6]]);

        let entries = vec![
            encoded_ready(1, 0, HISTORICAL_BATCH_TRANSACTION_BYTES),
            encoded_ready(1, 1, 1),
        ];
        let batches = partition_entry_batches(entries, &BTreeSet::new());
        assert_eq!(batch_slots(&batches), vec![vec![1], vec![1]]);
    }

    #[test]
    fn snapshot_export_attempt_requires_a_fresh_checkpoint_before_retry() {
        let slot = 42;
        let mut last_checkpoint_slot = Some(slot);
        assert!(!checkpoint_refresh_required(last_checkpoint_slot, slot));

        consume_checkpoint_export_seal(&mut last_checkpoint_slot);

        assert!(checkpoint_refresh_required(last_checkpoint_slot, slot));
    }

    #[test]
    fn incomplete_genesis_is_not_checkpointed_before_slot_zero_executes() {
        assert!(!checkpoint_initialized_state(
            HistoricalInitializedSource::Genesis
        ));
        assert!(checkpoint_initialized_state(
            HistoricalInitializedSource::SnapshotArchive
        ));
    }

    #[test]
    fn carried_worker_requires_a_complete_nonregressing_checkpoint() {
        let mut checkpoint = checkpoint_summary(20, 100);
        validate_carried_bootstrap(10, &checkpoint).unwrap();

        checkpoint.slot_complete = false;
        assert!(
            validate_carried_bootstrap(10, &checkpoint)
                .unwrap_err()
                .contains("is incomplete")
        );
        checkpoint.slot_complete = true;
        assert!(
            validate_carried_bootstrap(21, &checkpoint)
                .unwrap_err()
                .contains("precedes worker initialization")
        );
    }

    #[test]
    fn live_write_range_filters_warmup_and_extends_contiguously() {
        let first = extend_emitted_write_versions(
            None,
            10,
            &[
                account_write(9, 40),
                account_write(10, 41),
                account_write(10, 42),
            ],
        )
        .unwrap();
        assert_eq!(first, Some(41..43));

        let second = extend_emitted_write_versions(
            first.as_ref(),
            10,
            &[account_write(11, 43), account_write(11, 44)],
        )
        .unwrap();
        assert_eq!(second, Some(41..45));
    }

    #[test]
    fn live_write_range_rejects_a_gap() {
        let current = 41..45;
        let error = extend_emitted_write_versions(Some(&current), 10, &[account_write(11, 46)])
            .unwrap_err();
        assert!(error.contains("expected version 45, got 46"));
        assert_eq!(current, 41..45);
    }

    #[test]
    fn evidence_without_live_writes_uses_terminal_cursor_for_empty_range() {
        let bootstrap = checkpoint_summary(10, 100);
        let terminal = checkpoint_summary(20, 125);
        let evidence = assemble_evidence(Some(&bootstrap), Some(&terminal), 20, None).unwrap();
        assert_eq!(evidence.bootstrap, bootstrap);
        assert_eq!(evidence.terminal, terminal);
        assert_eq!(evidence.emitted_write_versions, 125..125);
    }

    #[test]
    fn evidence_requires_current_terminal_checkpoint_and_matching_cursor() {
        let bootstrap = checkpoint_summary(10, 100);
        let terminal = checkpoint_summary(20, 125);
        assert!(assemble_evidence(None, Some(&terminal), 20, None).is_err());
        assert!(assemble_evidence(Some(&bootstrap), None, 20, None).is_err());

        let stale = assemble_evidence(Some(&bootstrap), Some(&terminal), 21, Some(&(100..125)))
            .unwrap_err();
        assert!(stale.contains("terminal checkpoint is stale"));

        let cursor_mismatch =
            assemble_evidence(Some(&bootstrap), Some(&terminal), 20, Some(&(100..124)))
                .unwrap_err();
        assert!(cursor_mismatch.contains("does not match emitted range end"));
    }
}
