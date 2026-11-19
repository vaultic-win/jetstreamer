//! Native synthetic export/restore -> production recorder -> V4 -> full PoH.
//! This partial fixture grants no mainnet, full-epoch or admission authority.
#![allow(dead_code)]
#[path = "../jetstreamer-node/src/archive_checksum.rs"]
mod archive_checksum;
#[path = "../jetstreamer-node/src/checkpoint_bundle.rs"]
mod checkpoint_bundle;
mod checkpoint_live_client;
mod checkpoint_parent_handoff;
#[path = "../jetstreamer-node/src/checkpoint_prefix.rs"]
mod checkpoint_prefix;
#[path = "../jetstreamer-node/src/handoff_snapshot.rs"]
mod handoff_snapshot;
#[path = "../jetstreamer-node/src/segment_manifest.rs"]
mod segment_manifest;
#[path = "../jetstreamer-node/src/segment_progress.rs"]
mod segment_progress;
#[path = "../jetstreamer-node/src/slot_presence.rs"]
mod slot_presence;
use slot_presence::{SlotPresenceMap, SlotPresenceState};
#[path = "../jetstreamer-node/src/horizon.rs"]
mod horizon;
use jetstreamer_historical_protocol::{
    AccountWrite, Checkpoint, EntryProcessed, EntryRequest, SnapshotExport,
};
use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{
        AccountsHashKind, ArchiveProvenance, ArchiveProvenanceV1, ArchiveProvenanceV2,
        ArchiveProvenanceV3, ArchiveProvenanceV4, ArchiveReader, ArchiveWriterConfig,
        BootstrapStateKind, ChainMismatchPolicy, EpochMeta, RuntimeAdmission,
        RuntimeHandoffProvenance, RuntimeSegmentProvenance, RuntimeSegmentSource,
        RuntimeStateCheckpoint, SemanticDigest, SlotVisitor, StateCommitment, StateCommitmentKind,
        TransactionMetadataPolicy, WriteVersionNormalization, merge_checkpoint_restart_segments,
    },
    transactions::Transaction,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_hash::Hash;
use solana_runtime::bank::KeyedRewardsAndNumPartitions;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status::TransactionStatusMeta;
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
type Transcript = (
    String,
    Vec<u8>,
    Checkpoint,
    EntryRequest,
    EntryProcessed,
    Checkpoint,
    SnapshotExport,
    Vec<EntryRequest>,
    Vec<EntryProcessed>,
    Checkpoint,
    Checkpoint,
    Vec<EntryProcessed>,
    Checkpoint,
    u32,
    u32,
);
type Row = (
    u64,
    Option<Vec<u8>>,
    Vec<u8>,
    u64,
    Vec<u8>,
    bool,
    u64,
    Vec<u8>,
    u64,
);
fn require(ok: bool, error: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(error.into()) }
}
fn hash(bytes: &[u8]) -> Result<Hash> {
    Ok(Hash::new_from_array(bytes.try_into()?))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn create(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}
fn digest(path: &Path) -> Result<[u8; 32]> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = file.metadata()?;
    require(before.is_file(), "nonregular input")?;
    let mut sha = Sha256::new();
    let mut buf = vec![0; 128 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
    }
    let after = fs::symlink_metadata(path)?;
    require(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) == (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ),
        "input changed during hash",
    )?;
    Ok(sha.finalize().into())
}
fn checkpoint(c: &Checkpoint) -> Result<RuntimeStateCheckpoint> {
    require(c.slot_complete, "incomplete checkpoint")?;
    Ok(RuntimeStateCheckpoint {
        slot: c.slot,
        bank_hash: hash(&c.bank_hash)?,
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: hash(&c.accounts_hash)?,
        last_blockhash: hash(&c.last_blockhash)?,
        capitalization: c.capitalization,
        transaction_count: c.transaction_count,
        tick_height: c.tick_height,
        slot_complete: true,
        next_write_version: c.next_write_version,
    })
}
fn emit(w: &AccountWrite) -> Result<()> {
    horizon::note_historical_account_update(
        w.slot,
        Address::new_from_array(w.pubkey.as_slice().try_into()?),
        w.lamports,
        Address::new_from_array(w.owner.as_slice().try_into()?),
        w.executable,
        w.rent_epoch,
        w.write_version,
        w.data.clone(),
        w.transaction_signature
            .as_deref()
            .map(Signature::try_from)
            .transpose()?,
    );
    Ok(())
}
fn row(w: &AccountWrite, n: WriteVersionNormalization) -> Row {
    (
        w.slot,
        w.transaction_signature.clone(),
        w.pubkey.clone(),
        w.lamports,
        w.owner.clone(),
        w.executable,
        w.rent_epoch,
        w.data.clone(),
        n.archive_start + w.write_version - n.worker_start,
    )
}
fn segment(
    path: &Path,
    genesis: Hash,
    image: [u8; 32],
    start: &Checkpoint,
    end: &Checkpoint,
    entries: &[EntryRequest],
    results: &[EntryProcessed],
) -> Result<()> {
    let slot = end.slot;
    let early_prefix = start.slot == 0
        && std::env::var_os("JETSTREAMER_NATIVE_EARLY_PREFIX").as_deref() == Some("1".as_ref());
    let declared_count = if early_prefix { 3 } else { 1 };
    let source_path = if early_prefix {
        path.with_extension("closed-source.jet")
    } else {
        path.to_owned()
    };
    require(
        slot == start.slot + 1 && entries.len() == results.len() && !entries.is_empty(),
        "fixture extent mismatch",
    )?;
    let p = ArchiveProvenanceV2 {
        base: ArchiveProvenanceV1 {
            generation_profile: "synthetic/native-checkpoint-recorder-v1".into(),
            runtime_profile: "solana-v1.7.15".into(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: "4892eb4e1ad278d5249b6cda8983f88effb3e98b".into(),
            runtime_toolchain: "rustc1.52.1-test-image".into(),
            genesis_hash: genesis,
            bootstrap_state_kind: if start.slot == 0 {
                // The fixture starts after the already-frozen bank at slot 0;
                // it carries that bank into slot 1 rather than replaying genesis.
                BootstrapStateKind::CarriedBank
            } else {
                BootstrapStateKind::SnapshotArchive
            },
            bootstrap_slot: start.slot,
            bootstrap_state_hash: hash(&start.accounts_hash)?,
            requested_slot_start: slot,
            requested_slot_count: declared_count,
            transaction_metadata: TransactionMetadataPolicy::runtime_reconstructed_before(u64::MAX),
        },
        worker_executable_sha256: image,
    };
    let presence = Arc::new(SlotPresenceMap {
        start: slot,
        end_inclusive: slot + declared_count - 1,
        states: vec![SlotPresenceState::Present; declared_count as usize],
        next_present_after: vec![None; declared_count as usize],
    });
    horizon::init(
        &source_path,
        0,
        slot,
        declared_count,
        presence,
        &p.into(),
        Some((start.slot, hash(&start.last_blockhash)?)),
    )?;
    let recorder = horizon::recorder().ok_or("recorder absent")?;
    recorder.record_block_meta(
        slot,
        start.slot,
        &hash(&start.last_blockhash)?.to_string(),
        &hash(&end.last_blockhash)?.to_string(),
        &KeyedRewardsAndNumPartitions {
            keyed_rewards: vec![],
            num_partitions: None,
        },
        None,
        None,
        entries.iter().map(|e| e.transactions.len() as u64).sum(),
        entries.len() as u64,
    );
    let mut previous = hash(&start.last_blockhash)?;
    for (i, (entry, result)) in entries.iter().zip(results).enumerate() {
        require(
            entry.slot == slot
                && result.slot == slot
                && entry.entry_index == i as u64
                && result.entry_index == i as u64,
            "native entry identity mismatch",
        )?;
        require(
            entry.transactions.len() == result.outcomes.len(),
            "native outcome count mismatch",
        )?;
        let txs: Vec<VersionedTransaction> = entry
            .transactions
            .iter()
            .map(|bytes| bincode::deserialize(bytes))
            .collect::<std::result::Result<_, _>>()?;
        previous = solana_entry::entry::next_hash(&previous, entry.num_hashes, &txs);
        require(
            previous == hash(&entry.hash)?,
            "native PoH differs before recording",
        )?;
        for write in &result.writes {
            emit(write)?;
        }
        let mut committed = Vec::new();
        for (tx, outcome) in txs.into_iter().zip(&result.outcomes) {
            require(outcome.error.is_none(), "fixture transaction failed")?;
            require(
                tx.signatures.first().map(|s| s.as_ref()) == outcome.signature.as_deref(),
                "native signature mismatch",
            )?;
            committed.push((
                tx,
                TransactionStatusMeta {
                    fee: outcome.fee,
                    ..Default::default()
                },
            ));
        }
        recorder.record_committed_entry(
            slot,
            entry.entry_index.try_into()?,
            entry.num_hashes,
            committed,
        );
    }
    require(
        previous == hash(&end.last_blockhash)?,
        "terminal PoH differs",
    )?;
    for write in &end.writes {
        emit(write)?;
    }
    let stats = if early_prefix {
        let stats = horizon::close_checkpoint_prefix_source(&checkpoint(end)?)?
            .ok_or("missing recorder stats")?;
        let source_digest = digest(&source_path)?;
        let mut source = ArchiveReader::open(File::open(&source_path)?)?;
        require(
            !source.has_complete_slot_coverage()?,
            "early source falsely complete",
        )?;
        let mut range = checkpoint_prefix::ClosedPrefixRange {
            epoch: 0,
            first_slot: slot,
            intended_terminal: slot + declared_count - 1,
            selected_terminal: slot,
            terminal_blockhash: hash(&end.last_blockhash)?,
        };
        let rejected = path.with_extension("wrong-range.jet");
        range.intended_terminal += 1;
        require(
            checkpoint_prefix::convert_closed_prefix(&source_path, &rejected, &range).is_err(),
            "wrong original range accepted",
        )?;
        require(!rejected.exists(), "rejected range published an output")?;
        range.intended_terminal -= 1;
        let rejected = path.with_extension("wrong-terminal.jet");
        range.terminal_blockhash = Hash::new_from_array([0xee; 32]);
        require(
            checkpoint_prefix::convert_closed_prefix(&source_path, &rejected, &range).is_err(),
            "wrong terminal accepted",
        )?;
        require(!rejected.exists(), "rejected terminal published an output")?;
        range.terminal_blockhash = hash(&end.last_blockhash)?;
        let transformed = checkpoint_prefix::convert_closed_prefix(&source_path, path, &range)?;
        require(
            transformed.source_sha256 == source_digest,
            "conversion source hash differs",
        )?;
        require(
            transformed.prefix_sha256 == digest(path)?,
            "conversion output hash differs",
        )?;
        require(
            checkpoint_prefix::convert_closed_prefix(&source_path, path, &range).is_err(),
            "duplicate prefix replaced an output",
        )?;
        let mut reader = ArchiveReader::open(File::open(path)?)?;
        require(
            reader.has_complete_slot_coverage()?,
            "narrowed prefix incomplete",
        )?;
        let mut semantic = SemanticDigest::new();
        require(
            reader.read_slots(slot, 1, &mut semantic)? == 1,
            "prefix reread length",
        )?;
        require(
            semantic.finish()? == transformed.semantic_sha256,
            "prefix semantic reread differs",
        )?;
        require(
            digest(&source_path)? == source_digest,
            "closed source changed",
        )?;
        stats
    } else {
        horizon::finish_checkpoint_segment(&checkpoint(end)?)?.ok_or("missing recorder stats")?
    };
    require(
        stats.slots == 1 && stats.blocks == 1,
        "recorder did not close exact segment",
    )?;
    Ok(())
}
#[derive(Default)]
struct Observed {
    rows: Vec<Row>,
    epochs: Vec<(u64, u64, u64)>,
    transactions: Vec<(u64, Vec<u8>, u64)>,
}
impl Observed {
    fn update(&mut self, slot: u64, signature: Option<Vec<u8>>, u: &AccountUpdateView<'_>) {
        self.rows.push((
            slot,
            signature,
            u.pubkey.to_bytes().to_vec(),
            u.lamports,
            u.owner.to_bytes().to_vec(),
            u.executable,
            u.rent_epoch,
            u.data.to_vec(),
            u.write_version,
        ));
    }
}
impl SlotVisitor for Observed {
    fn on_epoch(&mut self, e: &EpochMeta) {
        assert!(e.updates.is_empty());
        self.epochs.push((e.epoch, e.start_slot, e.slot_count));
    }
    fn on_pre_account_update(&mut self, slot: u64, u: &AccountUpdateView<'_>) {
        self.update(slot, None, u);
    }
    fn on_post_account_update(&mut self, slot: u64, u: &AccountUpdateView<'_>) {
        self.update(slot, None, u);
    }
    fn on_transaction(&mut self, slot: u64, _: u32, tx: &Transaction) {
        let signature = tx
            .signatures
            .iter()
            .next()
            .expect("transaction signature")
            .as_ref()
            .to_vec();
        self.transactions.push((slot, signature.clone(), tx.fee));
        for (u, data) in tx.iter_account_updates() {
            self.update(
                slot,
                Some(signature.clone()),
                &AccountUpdateView {
                    pubkey: u.pubkey,
                    lamports: u.lamports,
                    owner: u.owner,
                    executable: u.executable,
                    rent_epoch: u.rent_epoch,
                    write_version: u.write_version,
                    data,
                },
            );
        }
    }
}
fn main() -> Result<()> {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    require(
        args.len() == 4,
        "usage: checkpoint_native_recorder TRANSCRIPT_ROOT EMPTY_OUTPUT FULL_VERIFIER NATIVE_TEST_IMAGE",
    )?;
    let (input, output, full, image) = (&args[0], &args[1], &args[2], &args[3]);
    for path in &args {
        require(
            path.is_absolute() && path.canonicalize()? == *path,
            "noncanonical fixture path",
        )?;
    }
    let meta = fs::symlink_metadata(output)?;
    require(
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "output ownership/mode mismatch",
    )?;
    let parent_phase = std::env::var(checkpoint_parent_handoff::PHASE).ok();
    require(
        matches!(
            parent_phase.as_deref(),
            None | Some("controller" | "export" | "resume" | "recover-publication")
        ),
        "unknown synthetic parent phase",
    )?;
    if parent_phase.is_some() {
        require(
            std::env::var_os("JETSTREAMER_NATIVE_LIVE_WORKER").is_some(),
            "parent restart requires live worker",
        )?;
    }
    if parent_phase.as_deref() == Some("controller") {
        return checkpoint_parent_handoff::controller(&args);
    }
    if !matches!(
        parent_phase.as_deref(),
        Some("resume" | "recover-publication")
    ) {
        require(
            fs::read_dir(output)?.next().is_none(),
            "output must be empty",
        )?;
    }
    let transcript_path = input.join("native-transcript.bin");
    let transcript_sha = digest(&transcript_path)?;
    let (
        schema,
        genesis,
        bootstrap,
        prefix_entry,
        prefix_result,
        boundary,
        export,
        suffix_entries,
        expected_results,
        terminal,
        restored,
        actual_results,
        actual_terminal,
        parent_pid,
        child_pid,
    ): Transcript = bincode::deserialize(&fs::read(&transcript_path)?)?;
    require(
        schema == "horizon-native-checkpoint-recorder-transcript-v1" && parent_pid != child_pid,
        "invalid native transcript",
    )?;
    require(
        expected_results == actual_results && terminal == actual_terminal,
        "fresh-process outcomes differ",
    )?;
    let mut expected_boundary = boundary.clone();
    expected_boundary.writes.clear();
    require(
        restored == expected_boundary,
        "complete restart checkpoint differs",
    )?;
    require(
        bootstrap.slot == 0 && boundary.slot == 1 && terminal.slot == 2,
        "unexpected synthetic range",
    )?;
    let snapshot = input.join("native-snapshot.tar.bz2");
    let mut snapshot_sha = digest(&snapshot)?;
    let baseline_snapshot_sha = snapshot_sha;
    let mut exported_snapshot = snapshot.clone();
    require(
        export.archive_sha256 == snapshot_sha
            && export.archive_size == fs::metadata(&snapshot)?.len()
            && export.slot == boundary.slot
            && export.accounts_hash == boundary.accounts_hash,
        "native snapshot binding differs",
    )?;
    let image_sha = digest(image)?;
    let full_sha = digest(full)?;
    let paths = [output.join("prefix.jet"), output.join("suffix.jet")];
    let live_worker = std::env::var_os("JETSTREAMER_NATIVE_LIVE_WORKER");
    if parent_phase.as_deref() == Some("recover-publication") {
        return checkpoint_parent_handoff::recover(
            input,
            output,
            Path::new(live_worker.as_ref().ok_or("missing live launcher")?),
            image,
            &genesis,
            &boundary,
        );
    }
    if let Some(launcher) = live_worker.as_ref() {
        let live_export = checkpoint_live_client::run(
            input,
            output,
            image,
            Path::new(&launcher),
            &genesis,
            &bootstrap,
            &prefix_entry,
            &prefix_result,
            &boundary,
            &suffix_entries,
            &expected_results,
            &terminal,
        )?;
        if parent_phase.as_deref() == Some("export") {
            return Ok(());
        }
        snapshot_sha = live_export.archive_sha256.as_slice().try_into()?;
        exported_snapshot = PathBuf::from(live_export.archive_path);
    } else {
        segment(
            &paths[0],
            hash(&genesis)?,
            image_sha,
            &bootstrap,
            &boundary,
            std::slice::from_ref(&prefix_entry),
            std::slice::from_ref(&prefix_result),
        )?;
        segment(
            &paths[1],
            hash(&genesis)?,
            image_sha,
            &restored,
            &actual_terminal,
            &suffix_entries,
            &actual_results,
        )?;
    }
    let writes = [
        prefix_result
            .writes
            .iter()
            .chain(&boundary.writes)
            .collect::<Vec<_>>(),
        actual_results
            .iter()
            .flat_map(|r| r.writes.iter())
            .chain(&actual_terminal.writes)
            .collect::<Vec<_>>(),
    ];
    let starts = [bootstrap.next_write_version, restored.next_write_version];
    let ends = [boundary.next_write_version, terminal.next_write_version];
    let mut archive_start = 1000;
    let mut segments = Vec::new();
    let mut expected_rows = Vec::new();
    for i in 0..2 {
        let normalization = WriteVersionNormalization {
            worker_start: starts[i],
            worker_end_exclusive: ends[i],
            archive_start,
        };
        require(ends[i] > starts[i], "fixture emitted no writes")?;
        for write in &writes[i] {
            require(
                write.write_version >= starts[i] && write.write_version < ends[i],
                "write outside native cursor interval",
            )?;
            expected_rows.push(row(write, normalization));
        }
        segments.push(RuntimeSegmentProvenance {
            slot_start: i as u64 + 1,
            slot_count: 1,
            generation_profile: "synthetic/native-checkpoint-recorder-v1".into(),
            runtime_profile: "solana-v1.7.15".into(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: "4892eb4e1ad278d5249b6cda8983f88effb3e98b".into(),
            runtime_toolchain: "rustc1.52.1-test-image".into(),
            worker_executable_sha256: Some(image_sha),
            write_versions: normalization,
        });
        archive_start += ends[i] - starts[i];
    }
    let p = ArchiveProvenanceV4 {
        base: ArchiveProvenanceV3 {
            assembly_profile: "synthetic/native-recorder-restart-v1".into(),
            genesis_hash: hash(&genesis)?,
            bootstrap_state_kind: BootstrapStateKind::CarriedBank,
            bootstrap_state: StateCommitment {
                slot: 0,
                kind: StateCommitmentKind::LegacyAccountsHash,
                hash: hash(&bootstrap.accounts_hash)?,
            },
            requested_slot_start: 1,
            requested_slot_count: 2,
            transaction_metadata: TransactionMetadataPolicy::runtime_reconstructed_before(u64::MAX),
            runtime_segments: segments,
            handoffs: vec![RuntimeHandoffProvenance {
                boundary_slot: 2,
                predecessor: checkpoint(&boundary)?,
                successor: checkpoint(&restored)?,
                successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                successor_bootstrap_archive_sha256: snapshot_sha,
                successor_bootstrap_write_count: 0,
            }],
        },
    };
    let source_shas = [digest(&paths[0])?, digest(&paths[1])?];
    let terminals = [
        hash(&boundary.last_blockhash)?,
        hash(&terminal.last_blockhash)?,
    ];
    let sources = || -> Result<Vec<RuntimeSegmentSource<File>>> {
        (0..2)
            .map(|i| {
                Ok(RuntimeSegmentSource::new(
                    File::open(&paths[i])?,
                    source_shas[i],
                    terminals[i],
                ))
            })
            .collect()
    };
    let archive = output.join("native-restarted.jet");
    let (file, stats) = merge_checkpoint_restart_segments(
        sources()?,
        create(&archive)?,
        ArchiveWriterConfig::default(),
        &p,
    )?;
    file.sync_all()?;
    require(
        stats.slots_merged == 2 && stats.source_archives == 2,
        "merge extent differs",
    )?;
    let mut reader = ArchiveReader::open(File::open(&archive)?)?;
    require(
        reader.provenance()? == Some(ArchiveProvenance::V4(p.clone())),
        "merge provenance differs",
    )?;
    require(
        reader.has_complete_slot_coverage()?,
        "incomplete merged range",
    )?;
    reader.verify_chain = true;
    reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    let mut observed = Observed::default();
    for bucket in 0..reader.bucket_count() {
        reader.read_bucket(bucket, &mut observed)?;
    }
    observed.rows.sort_by_key(|r| r.8);
    expected_rows.sort_by_key(|r| r.8);
    require(
        observed.rows == expected_rows,
        "native writes lost, changed, misattributed or misnormalized",
    )?;
    require(
        observed.epochs == vec![(0, 1, 2)],
        "merged metadata differs",
    )?;
    let expected_transactions: Vec<_> = suffix_entries
        .iter()
        .zip(&actual_results)
        .flat_map(|(e, r)| {
            r.outcomes
                .iter()
                .map(move |o| (e.slot, o.signature.clone().unwrap(), o.fee))
        })
        .collect();
    require(
        observed.transactions == expected_transactions,
        "native transaction metadata differs",
    )?;
    let anchor = hash(&bootstrap.last_blockhash)?.to_string();
    let end = hash(&terminal.last_blockhash)?.to_string();
    let status = Command::new(full)
        .arg(&archive)
        .args([
            "--full",
            "--threads",
            "2",
            "--anchor",
            "0",
            &anchor,
            "--expected-terminal",
            "2",
            &end,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(create(&output.join("full.stdout"))?))
        .stderr(Stdio::from(create(&output.join("full.stderr"))?))
        .status()?;
    require(status.success(), "full PoH rejected native merged archive")?;
    let mut wrong = p.clone();
    wrong.base.handoffs[0].successor.bank_hash = Hash::new_from_array([0x99; 32]);
    require(
        merge_checkpoint_restart_segments(
            sources()?,
            create(&output.join("rejected-checkpoint.partial"))?,
            ArchiveWriterConfig::default(),
            &wrong,
        )
        .is_err(),
        "changed restore checkpoint accepted",
    )?;
    require(
        digest(&transcript_path)? == transcript_sha
            && digest(&snapshot)? == baseline_snapshot_sha
            && digest(&exported_snapshot)? == snapshot_sha
            && digest(image)? == image_sha
            && digest(full)? == full_sha,
        "fixture or consumer changed",
    )?;
    let report = json!({"schema":"horizon-native-recorder-restart-result-v1","transcript_sha256":hex(&transcript_sha),
        "native_test_image_sha256":hex(&image_sha),"snapshot_sha256":hex(&snapshot_sha),"archive_sha256":hex(&digest(&archive)?),
        "full_verifier_sha256":hex(&full_sha),"source_sha256":source_shas.map(|s|hex(&s)),
        "baseline_parent_pid":parent_pid,"baseline_restore_pid":child_pid,"live_parent_ipc":live_worker.is_some(),"baseline_snapshot_sha256":hex(&baseline_snapshot_sha),
        "slot_start":1,"slot_count":2,"account_updates":observed.rows.len(),"transactions":observed.transactions.len(),
        "full_poh_passed":true,"changed_checkpoint_rejected":true,"full_epoch_verified":false,"mainnet_qualified":false,"admission_authorized":false});
    let mut file = create(&output.join("native-results.json"))?;
    file.write_all(&serde_json::to_vec_pretty(&report)?)?;
    file.sync_all()?;
    File::open(output)?.sync_all()?;
    println!("{report}");
    Ok(())
}
