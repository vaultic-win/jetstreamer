//! Fixed private source adapter. Default builds cannot load or execute a bundle.
use std::path::{Path, PathBuf};

#[derive(Default)]
pub(super) struct Cli {
    index: Option<PathBuf>,
    index_sha256: Option<String>,
    data: Option<PathBuf>,
    data_sha256: Option<String>,
}

pub(super) fn recognizes(arg: &str) -> bool {
    [
        "--epoch141-original-index=",
        "--epoch141-original-index-sha256=",
        "--epoch141-original-data=",
        "--epoch141-original-data-sha256=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

impl Cli {
    pub(super) fn parse(&mut self, arg: &str) -> Result<(), String> {
        let (key, value) = arg
            .split_once('=')
            .ok_or("missing original-entry option value")?;
        if value.is_empty() {
            return Err("empty original-entry option".into());
        }
        let duplicate = match key {
            "--epoch141-original-index" => self.index.replace(value.into()).is_some(),
            "--epoch141-original-index-sha256" => self.index_sha256.replace(value.into()).is_some(),
            "--epoch141-original-data" => self.data.replace(value.into()).is_some(),
            "--epoch141-original-data-sha256" => self.data_sha256.replace(value.into()).is_some(),
            _ => return Err("unknown original-entry option".into()),
        };
        if duplicate {
            return Err(format!("duplicate {key}"));
        }
        Ok(())
    }
    #[cfg(not(feature = "epoch141-original-entry-qualification"))]
    fn supplied(&self) -> bool {
        self.index.is_some()
            || self.index_sha256.is_some()
            || self.data.is_some()
            || self.data_sha256.is_some()
    }
}

#[cfg(any(feature = "epoch141-original-entry-qualification", test))]
fn validate_scope(
    start: u64,
    end: u64,
    plan: Option<(u64, u64, u64)>,
    forbidden: bool,
    private: Option<(&Path, &Path, &Path)>,
) -> Result<(), String> {
    if start != 141 || end != 141 || plan != Some((60911751, 60911752, 61328765)) || forbidden {
        return Err("original-entry qualification requires exact 141/bootstrap60911751/terminal61328765, no cohort/recovery/carried route".into());
    }
    let root = Path::new("/home/sol/.jetstreamer-private");
    let Some((destination, output, scratch)) = private else {
        return Err(
            "original-entry qualification requires explicit private output and scratch".into(),
        );
    };
    if [destination, output, scratch].iter().any(|path| {
        !path.is_absolute()
            || !path.starts_with(root)
            || *path == root
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
    }) {
        return Err("original-entry qualification paths must stay beneath private root".into());
    }
    Ok(())
}

#[cfg(feature = "epoch141-original-entry-qualification")]
mod enabled {
    use super::*;
    use crate::{ReadyEntry, SlotExecutionBuffer};
    use jetstreamer_utils::{
        horizon_legacy_bundle::{OriginalEntryBundle, OriginalSlot},
        horizon_legacy_source::bind_v1_4_25_source_entries,
    };
    use std::sync::{Mutex, OnceLock};

    static INPUT: OnceLock<Mutex<Option<OriginalEntryBundle>>> = OnceLock::new();

    pub(crate) fn configure(
        cli: Cli,
        start: u64,
        end: u64,
        plan: Option<(u64, u64, u64)>,
        forbidden: bool,
        private: Option<(&Path, &Path, &Path)>,
    ) -> Result<(), String> {
        validate_scope(start, end, plan, forbidden, private)?;
        let (Some(index), Some(index_sha), Some(data), Some(data_sha)) =
            (cli.index, cli.index_sha256, cli.data, cli.data_sha256)
        else {
            return Err(
                "original-entry diagnostic build requires all four explicit bundle options".into(),
            );
        };
        let start = std::time::Instant::now();
        let bundle = OriginalEntryBundle::open(&index, &index_sha, &data, &data_sha, || {
            if start.elapsed().as_secs() > 1800 {
                Err("original bundle authentication deadline exceeded".into())
            } else {
                Ok(())
            }
        })?;
        INPUT
            .set(Mutex::new(Some(bundle)))
            .map_err(|_| "original input already initialized")?;
        log::info!(
            "authenticated private original-entry bundle index={} sha256={} data={} sha256={}; replay/publication still independently gated",
            index.display(),
            index_sha,
            data.display(),
            data_sha
        );
        Ok(())
    }

    pub(crate) fn take_bundle() -> Option<OriginalEntryBundle> {
        INPUT
            .get()
            .and_then(|input| input.lock().expect("original input lock").take())
    }

    pub(crate) fn validate_execution(
        epoch: u64,
        bootstrap: u64,
        terminal: u64,
        forbidden: bool,
    ) -> Result<(), String> {
        if epoch != 141
            || bootstrap != 60911751
            || terminal != 61328765
            || forbidden
            || INPUT
                .get()
                .is_none_or(|input| input.lock().map(|value| value.is_none()).unwrap_or(true))
        {
            return Err(
                "original-entry build cannot run an ordinary, carried or unbound replay".into(),
            );
        }
        Ok(())
    }

    /// No source transaction, scheduler count or pending entry is consumed here.
    pub(crate) fn complete_source(buffer: &SlotExecutionBuffer) -> Result<bool, String> {
        if buffer.processed_tx_count != 0 || buffer.processed_entry_count != 0 {
            return Err("partial original-entry source resume is unqualified".into());
        }
        let (Some(txs), Some(entries)) = (buffer.expected_tx_count, buffer.expected_entry_count)
        else {
            return Ok(false);
        };
        if txs > 65536
            || entries > 262144
            || buffer.txs.len() as u64 > txs
            || buffer.next_entry_index as u64 > entries
            || buffer.pending_entries.len() as u64 > entries
        {
            return Err("original-entry source slot exceeds exact metadata bounds".into());
        }
        if !buffer.original_source_anchors_verified
            || buffer.txs.len() as u64 != txs
            || buffer.pending_entries.len() as u64 != entries
            || buffer.next_entry_index as u64 != entries
            || buffer.txs.iter().any(Option::is_none)
        {
            return Ok(false);
        }
        let mut cursor = 0usize;
        for (index, entry) in buffer.pending_entries.iter().enumerate() {
            if entry.entry_index != index {
                return Err("source entry order differs".into());
            }
            if entry.tx_count > 0 {
                if entry.start_index != cursor {
                    return Err("source transaction grouping is not contiguous".into());
                }
                cursor = cursor
                    .checked_add(entry.tx_count)
                    .ok_or("source transaction range overflow")?;
                if cursor as u64 > txs {
                    return Err("source entry exceeds transaction sequence".into());
                }
            }
        }
        if cursor as u64 != txs {
            return Err("source entries do not cover complete transaction sequence".into());
        }
        Ok(true)
    }

    pub(crate) fn adapt(
        buffer: &mut SlotExecutionBuffer,
        original: &OriginalSlot,
    ) -> Result<Vec<ReadyEntry>, String> {
        adapt_with_count(buffer, original, |slot, count| {
            if let Some(recorder) = crate::horizon::recorder() {
                recorder.record_original_entry_count(slot, count)?;
            }
            Ok(())
        })
    }

    fn adapt_with_count(
        buffer: &mut SlotExecutionBuffer,
        original: &OriginalSlot,
        bind_count: impl FnOnce(u64, u64) -> Result<(), String>,
    ) -> Result<Vec<ReadyEntry>, String> {
        if !complete_source(buffer)? {
            return Err("original-entry adapter received an incomplete source slot".into());
        }
        let source = buffer
            .txs
            .iter()
            .map(|tx| {
                crate::historical::encode_legacy_transaction(
                    &tx.as_ref().expect("complete source").tx,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let start = std::time::Instant::now();
        let matched = bind_v1_4_25_source_entries(
            &original
                .batches
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
            &source.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            &original.expected,
            51_200_000,
            || {
                if start.elapsed().as_secs() > 90 {
                    Err("original source-slot equivalence deadline exceeded".into())
                } else {
                    Ok(())
                }
            },
        )?;
        bind_count(original.expected.slot, matched.entries.len() as u64)?;
        // Every fallible source/PoH/recorder gate is complete before the first take.
        let mut ready = Vec::with_capacity(matched.entries.len());
        for entry in matched.entries {
            let start = entry.transaction_start_index;
            let count = entry.transactions.len();
            let txs = (start..start + count)
                .map(|index| {
                    buffer.txs[index]
                        .take()
                        .expect("byte-verified source transaction")
                })
                .collect();
            ready.push(ReadyEntry {
                slot: original.expected.slot,
                entry_index: entry.entry_index,
                start_index: start,
                txs,
                hash: solana_hash::Hash::new_from_array(entry.metadata.hash),
                num_hashes: entry.metadata.num_hashes,
                tx_count: count,
            });
        }
        // Scheduler accounting continues to describe the complete CAR source;
        // the worker/recorder receive the separately verified original grouping.
        buffer.processed_tx_count = buffer.expected_tx_count.expect("complete source");
        buffer.processed_entry_count = buffer.expected_entry_count.expect("complete source");
        buffer.pending_entries.clear();
        log::info!(
            "qualified original source slot={} transactions={} original_entries={} hidden_boundaries={} poh_hashes={}",
            original.expected.slot,
            matched.matched_transactions,
            ready.len(),
            matched.poh.boundaries.len(),
            matched.poh.executed_hashes
        );
        Ok(ready)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{PendingEntry, ScheduledTransaction};
        use jetstreamer_utils::horizon_legacy_poh::PohExpectation;
        use sha2::{Digest, Sha256};

        fn transaction(signature: u8) -> Vec<u8> {
            let mut bytes = vec![1];
            bytes.extend_from_slice(&[signature; 64]);
            bytes.extend_from_slice(&[1, 0, 0, 1]);
            bytes.extend_from_slice(&[42; 32]);
            bytes.extend_from_slice(&[43; 32]);
            bytes.push(0);
            bytes
        }
        fn batch(hash: [u8; 32], tx: Option<&[u8]>) -> Vec<u8> {
            let mut bytes = 1u64.to_le_bytes().to_vec();
            bytes.extend_from_slice(&1u64.to_le_bytes());
            bytes.extend_from_slice(&hash);
            bytes.extend_from_slice(&u64::from(tx.is_some()).to_le_bytes());
            if let Some(tx) = tx {
                bytes.extend_from_slice(tx);
            }
            bytes
        }
        fn fixture() -> (SlotExecutionBuffer, OriginalSlot) {
            let mut buffer = SlotExecutionBuffer::default();
            let mut batches = Vec::new();
            let mut current = [9; 32];
            for signature in [1u8, 2] {
                let bytes = transaction(signature);
                let tx = bincode::deserialize(&bytes).unwrap();
                let status_meta = crate::TransactionStatusMeta {
                    fee: 100 + u64::from(signature),
                    ..Default::default()
                };
                buffer.txs.push(Some(ScheduledTransaction {
                    tx,
                    expected_status: Some(Ok(())),
                    reconstruct_fee: signature == 2,
                    status_meta,
                }));
                let leaf = Sha256::digest([vec![0], vec![signature; 64]].concat());
                current = Sha256::digest([current.as_slice(), leaf.as_slice()].concat()).into();
                batches.push(batch(current, Some(&bytes)));
                current = Sha256::digest(current).into();
                batches.push(batch(current, None));
            }
            buffer.expected_tx_count = Some(2);
            buffer.expected_entry_count = Some(1);
            buffer.next_entry_index = 1;
            buffer.original_source_anchors_verified = true;
            buffer.pending_entries.push_back(PendingEntry {
                entry_index: 0,
                start_index: 0,
                tx_count: 2,
                hash: solana_hash::Hash::new_from_array(current),
                num_hashes: 0,
            });
            let original = OriginalSlot {
                expected: PohExpectation {
                    slot: 102,
                    parent_slot: 100,
                    parent_hash: [9; 32],
                    final_hash: current,
                    ticks_per_slot: 1,
                    hashes_per_tick: 2,
                },
                batches,
            };
            (buffer, original)
        }
        #[test]
        fn whole_slot_regrouping_keeps_source_status_indexes_and_original_ticks() {
            let (mut buffer, original) = fixture();
            let mut count = None;
            let ready = adapt_with_count(&mut buffer, &original, |slot, n| {
                count = Some((slot, n));
                Ok(())
            })
            .unwrap();
            assert_eq!(count, Some((102, 4)));
            assert_eq!(
                ready
                    .iter()
                    .map(|e| (e.entry_index, e.start_index, e.tx_count, e.num_hashes))
                    .collect::<Vec<_>>(),
                [(0, 0, 1, 1), (1, 1, 0, 1), (2, 1, 1, 1), (3, 2, 0, 1)]
            );
            assert_eq!(ready[0].txs[0].status_meta.fee, 101);
            assert_eq!(ready[2].txs[0].status_meta.fee, 102);
            assert!(!ready[0].txs[0].reconstruct_fee);
            assert!(ready[2].txs[0].reconstruct_fee);
            assert_eq!(ready[0].txs[0].expected_status, Some(Ok(())));
            assert_eq!(
                ready.last().unwrap().hash.to_bytes(),
                original.expected.final_hash
            );
            assert_eq!(buffer.processed_entry_count, 1);
            assert_eq!(buffer.processed_tx_count, 2);
            assert!(buffer.should_finalize(102).unwrap());
        }
        #[test]
        fn incomplete_changed_reordered_resumed_or_bad_poh_source_consumes_nothing() {
            for mutation in 0..6 {
                let (mut buffer, mut original) = fixture();
                match mutation {
                    0 => buffer.original_source_anchors_verified = false,
                    1 => {
                        buffer.txs[1] = None;
                    }
                    2 => buffer.txs.swap(0, 1),
                    3 => buffer.pending_entries[0].start_index = 1,
                    4 => buffer.processed_entry_count = 1,
                    _ => original.expected.final_hash = [0; 32],
                }
                let before = buffer.txs.iter().map(Option::is_some).collect::<Vec<_>>();
                let mut count_called = false;
                assert!(
                    adapt_with_count(&mut buffer, &original, |_, _| {
                        count_called = true;
                        Ok(())
                    })
                    .is_err()
                );
                assert!(!count_called);
                assert_eq!(
                    buffer.txs.iter().map(Option::is_some).collect::<Vec<_>>(),
                    before
                );
                assert_eq!(buffer.pending_entries.len(), 1);
            }
        }
        #[test]
        fn recorder_refusal_precedes_consumption() {
            let (mut buffer, original) = fixture();
            assert!(
                adapt_with_count(&mut buffer, &original, |_, _| Err("already emitted".into()))
                    .is_err()
            );
            assert!(buffer.txs.iter().all(Option::is_some));
            assert_eq!(buffer.processed_tx_count, 0);
            assert_eq!(buffer.pending_entries.len(), 1);
        }

        #[test]
        fn source_cannot_skip_a_pinned_target_or_finish_with_an_incomplete_census() {
            use crate::{RestartTracker, SlotPresenceMap, SlotPresenceState, TransactionScheduler};
            use std::sync::Arc;
            let presence = Arc::new(SlotPresenceMap {
                start: 100,
                end_inclusive: 110,
                states: vec![SlotPresenceState::Missing; 11],
                next_present_after: vec![None; 11],
            });
            let scheduler =
                TransactionScheduler::new(100, presence, Arc::new(RestartTracker::new()), 0);
            {
                let mut state = scheduler.state.lock().unwrap();
                state.original_expected.insert(103);
                assert!(
                    scheduler
                        .record_parent_edge_locked(&mut state, 100, 106)
                        .unwrap_err()
                        .contains("independently pinned original target")
                );
                state.current_slot = 111;
            }
            assert!(
                scheduler
                    .verify_complete(110)
                    .unwrap_err()
                    .contains("incomplete original source census")
            );
            scheduler.state.lock().unwrap().original_matched.insert(103);
            scheduler.verify_complete(110).unwrap();
            scheduler.state.lock().unwrap().original_matched.insert(104);
            assert!(scheduler.verify_complete(110).is_err());
        }

        #[test]
        #[ignore = "root-private exact first-target acquisition and independent RPC fixtures; read-only adapter diagnostic, no Bank, archive, service observation or remote access"]
        fn actual_first_target_modern_wire_conversion_and_metadata_mapping() {
            use base64::{Engine, engine::general_purpose::STANDARD};
            use jetstreamer_utils::horizon_legacy_shred::{
                assemble_v1_4_25_padded_batches, decode_v1_4_25_complete_slot_meta,
            };
            use std::{
                fs::OpenOptions,
                io::Read,
                os::unix::fs::{MetadataExt, OpenOptionsExt},
            };
            fn read(path: &str, sha: Option<&str>) -> serde_json::Value {
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                    .open(path)
                    .unwrap();
                let before = file.metadata().unwrap();
                assert!(
                    before.is_file()
                        && before.uid() == 0
                        && before.nlink() == 1
                        && before.mode() & 0o022 == 0
                        && before.len() <= 32 << 20
                );
                let mut bytes = Vec::new();
                (&mut file)
                    .take((32 << 20) + 1)
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(bytes.len() as u64, before.len());
                if let Some(sha) = sha {
                    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), sha);
                }
                let id = |m: &std::fs::Metadata| {
                    (
                        m.dev(),
                        m.ino(),
                        m.len(),
                        m.mtime(),
                        m.mtime_nsec(),
                        m.ctime(),
                        m.ctime_nsec(),
                    )
                };
                assert_eq!(id(&before), id(&file.metadata().unwrap()));
                assert_eq!(id(&before), id(&std::fs::symlink_metadata(path).unwrap()));
                serde_json::from_slice(&bytes).unwrap()
            }
            let raw = read(
                "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v2/results/target-acquisitions/slot-60911776.json",
                Some("a911135ca8d32abf75db380e0bd13d9deda7ae789d522aeaa6977516126c5600"),
            );
            let poh = read(
                "/var/lib/jetstreamer/horizon-epoch141-census-poh-diagnostic-20261022-v2/targets/slot-60911776.json",
                Some("329ebed023c8bff71c885d1ee7aa34771b3e9d6e65b9dd59469fe4da21a7eeff"),
            );
            let source_proof = read(
                "/var/lib/jetstreamer/horizon-epoch141-source-equivalence-20261023-v1/completion.json",
                Some("27b1e6c8a2e9553712fc876148e29d4a76af405ca1303f1f445dc37703c17c59"),
            );
            let response = read(
                "/var/lib/jetstreamer/horizon-epoch141-source-equivalence-20261023-v1/response.json",
                None,
            );
            let bytes = STANDARD
                .decode(response["raw_base64"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&bytes)),
                source_proof["rpc_response_raw_sha256"].as_str().unwrap()
            );
            let source: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let anchors = &poh["finalized_metadata"];
            assert_eq!(source["result"]["parentSlot"], 60911771);
            assert_eq!(source["result"]["blockhash"], anchors["final_poh_hash"]);
            assert_eq!(
                source["result"]["previousBlockhash"],
                anchors["previous_poh_hash"]
            );
            let payload = |value: &serde_json::Value| {
                STANDARD
                    .decode(value["value_base64"].as_str().unwrap())
                    .unwrap()
            };
            let meta = decode_v1_4_25_complete_slot_meta(
                &payload(&raw["outcome"]["first_metadata"][0]),
                60911776,
                60911771,
            )
            .unwrap();
            let shreds: Vec<_> = raw["outcome"]["records"]
                .as_array()
                .unwrap()
                .iter()
                .skip(8)
                .map(payload)
                .collect();
            let batches = assemble_v1_4_25_padded_batches(
                60911776,
                60911771,
                meta.last_index,
                &shreds.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            )
            .unwrap();
            assert_eq!(
                batches.iter().map(|b| b.last_index).collect::<Vec<_>>(),
                meta.completed_data_indexes
            );
            let decode_hash = |v: &serde_json::Value| -> [u8; 32] {
                bs58::decode(v.as_str().unwrap())
                    .into_vec()
                    .unwrap()
                    .try_into()
                    .unwrap()
            };
            let original = OriginalSlot {
                expected: PohExpectation {
                    slot: 60911776,
                    parent_slot: 60911771,
                    parent_hash: decode_hash(&anchors["previous_poh_hash"]),
                    final_hash: decode_hash(&anchors["final_poh_hash"]),
                    ticks_per_slot: 64,
                    hashes_per_tick: 12500,
                },
                batches: batches.into_iter().map(|b| b.bytes).collect(),
            };
            let mut buffer = SlotExecutionBuffer::default();
            for (index, tx) in source["result"]["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
            {
                assert_eq!(tx["version"], "legacy");
                assert_eq!(tx["transaction"][1], "base64");
                let bytes = STANDARD
                    .decode(tx["transaction"][0].as_str().unwrap())
                    .unwrap();
                // Synthetic distinguishable metadata tests ownership only; this
                // diagnostic does not claim real execution/status/fee validation.
                buffer.txs.push(Some(ScheduledTransaction {
                    tx: bincode::deserialize(&bytes).unwrap(),
                    expected_status: None,
                    reconstruct_fee: false,
                    status_meta: crate::TransactionStatusMeta {
                        fee: index as u64,
                        ..Default::default()
                    },
                }));
            }
            assert_eq!(buffer.txs.len(), 991);
            buffer.expected_tx_count = Some(991);
            buffer.expected_entry_count = Some(1);
            buffer.next_entry_index = 1;
            buffer.original_source_anchors_verified = true;
            buffer.pending_entries.push_back(PendingEntry {
                entry_index: 0,
                start_index: 0,
                tx_count: 991,
                hash: solana_hash::Hash::new_from_array(original.expected.final_hash),
                num_hashes: 0,
            });
            let ready = adapt_with_count(&mut buffer, &original, |slot, n| {
                assert_eq!((slot, n), (60911776, 1309));
                Ok(())
            })
            .unwrap();
            assert_eq!(ready.len(), 1309);
            assert_eq!(ready.iter().filter(|e| e.tx_count == 0).count(), 320);
            assert_eq!(
                ready
                    .iter()
                    .flat_map(|e| e.txs.iter())
                    .map(|tx| tx.status_meta.fee)
                    .collect::<Vec<_>>(),
                (0..991).collect::<Vec<u64>>()
            );
            assert!(buffer.should_finalize(60911776).unwrap());
            eprintln!(
                "actual original-entry parent adapter:991exact transactions,1309entries,320ticks,5PoHboundaries; no Bank/archive/runtime promotion"
            );
        }
    }
}

pub(super) fn configure(
    cli: Cli,
    start: u64,
    end: u64,
    plan: Option<(u64, u64, u64)>,
    forbidden: bool,
    private: Option<(&Path, &Path, &Path)>,
) -> Result<(), String> {
    #[cfg(feature = "epoch141-original-entry-qualification")]
    {
        enabled::configure(cli, start, end, plan, forbidden, private)
    }
    #[cfg(not(feature = "epoch141-original-entry-qualification"))]
    {
        let _ = (start, end, plan, forbidden, private);
        if cli.supplied() {
            Err("original-entry options require the separate qualification build".into())
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "epoch141-original-entry-qualification")]
pub(super) use enabled::{adapt, complete_source, take_bundle, validate_execution};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_is_exact_and_never_enables_a_normal_build() {
        let mut cli = Cli::default();
        assert!(recognizes("--epoch141-original-index=/tmp/index"));
        cli.parse("--epoch141-original-index=/tmp/index").unwrap();
        assert!(cli.parse("--epoch141-original-index=/tmp/index").is_err());
        assert!(cli.parse("--epoch141-original-data=").is_err());
        #[cfg(not(feature = "epoch141-original-entry-qualification"))]
        assert!(
            configure(
                cli,
                141,
                141,
                Some((60911751, 60911752, 61328765)),
                false,
                None
            )
            .is_err()
        );
    }
    #[test]
    fn fixed_scope_rejects_ordinary_cohort_other_checkpoint_and_public_output() {
        let private = Path::new("/home/sol/.jetstreamer-private/epoch141-test");
        let paths = Some((private, private, private));
        validate_scope(141, 141, Some((60911751, 60911752, 61328765)), false, paths).unwrap();
        assert!(validate_scope(141, 141, None, false, paths).is_err());
        assert!(
            validate_scope(141, 141, Some((60911751, 60911752, 61328765)), true, paths).is_err()
        );
        assert!(
            validate_scope(141, 141, Some((60911751, 60911752, 61328764)), false, paths).is_err()
        );
        assert!(
            validate_scope(
                141,
                141,
                Some((60911751, 60911752, 61328765)),
                false,
                Some((
                    private,
                    Path::new("/home/sol/horizon/epoch-141.jet"),
                    private
                ))
            )
            .is_err()
        );
    }
}
