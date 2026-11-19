//! Synthetic full-epoch V4 assembly through the qualified native reader.
//! No mainnet recovery, canonical checkpoint, admission or R2 authority.
use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{
        AccountsHashKind, ArchiveProvenance, ArchiveProvenanceV1, ArchiveProvenanceV2,
        ArchiveProvenanceV3, ArchiveProvenanceV4, ArchiveReader, ArchiveWriter,
        ArchiveWriterConfig, BootstrapStateKind, ChainMismatchPolicy, EntryRecord, EpochMeta,
        MultiSegmentMergeError, RuntimeAdmission, RuntimeHandoffProvenance,
        RuntimeSegmentProvenance, RuntimeSegmentSource, RuntimeStateCheckpoint, SlotVisitor,
        StateCommitment, StateCommitmentKind, TransactionMetadataPolicy, WriteVersionNormalization,
        merge_checkpoint_restart_segments,
    },
    block_metas::BlockMeta,
    transactions::Transaction,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const EPOCH: u64 = 265;
const FIRST: u64 = EPOCH * 432_000;
const COUNT: u64 = 432_000;
const HALF: u64 = COUNT / 2;
const DATA: &[u8] = b"synthetic V4";
fn require(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn create(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}
fn digest(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut sha = Sha256::new();
    let mut buf = vec![0; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
    }
    Ok(sha.finalize().into())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn text(path: &Path) -> Result<String> {
    Ok(path.to_str().ok_or("non-UTF8 path")?.into())
}
fn hash(byte: u8) -> Hash {
    Hash::new_from_array([byte; 32])
}

fn provenance(h: &[Hash; 5]) -> ArchiveProvenanceV4 {
    let checkpoint = RuntimeStateCheckpoint {
        slot: FIRST + HALF - 1,
        bank_hash: hash(0x31),
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: hash(0x32),
        last_blockhash: h[2],
        capitalization: 1_000_000,
        transaction_count: 2,
        tick_height: 64,
        slot_complete: true,
        next_write_version: 17,
    };
    ArchiveProvenanceV4 {
        base: ArchiveProvenanceV3 {
            assembly_profile: "synthetic/checkpoint-v4-playback-v1".into(),
            genesis_hash: hash(0x90),
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_state: StateCommitment {
                slot: FIRST - 1,
                kind: StateCommitmentKind::LegacyAccountsHash,
                hash: hash(0x91),
            },
            requested_slot_start: FIRST,
            requested_slot_count: COUNT,
            transaction_metadata: TransactionMetadataPolicy::observed(),
            runtime_segments: [10, 200]
                .into_iter()
                .enumerate()
                .map(|(i, start)| RuntimeSegmentProvenance {
                    slot_start: FIRST + i as u64 * HALF,
                    slot_count: HALF,
                    generation_profile: "synthetic/same-worker".into(),
                    runtime_profile: "solana-v1.7.15".into(),
                    runtime_admission: RuntimeAdmission::Candidate,
                    runtime_revision: "synthetic-not-a-mainnet-revision".into(),
                    runtime_toolchain: "synthetic".into(),
                    worker_executable_sha256: Some([0xa1; 32]),
                    write_versions: WriteVersionNormalization {
                        worker_start: start,
                        worker_end_exclusive: start + 7,
                        archive_start: 1000 + 7 * i as u64,
                    },
                })
                .collect(),
            handoffs: vec![RuntimeHandoffProvenance {
                boundary_slot: FIRST + HALF,
                predecessor: checkpoint,
                successor: RuntimeStateCheckpoint {
                    next_write_version: 200,
                    ..checkpoint
                },
                successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                successor_bootstrap_archive_sha256: [0xc3; 32],
                successor_bootstrap_write_count: 0,
            }],
        },
    }
}

fn source(path: &Path, p: &ArchiveProvenanceV4, index: usize, h: &[Hash; 5]) -> Result<()> {
    let s = &p.base.runtime_segments[index];
    let bootstrap = if index == 0 {
        p.base.bootstrap_state
    } else {
        StateCommitment {
            slot: p.base.handoffs[0].successor.slot,
            kind: StateCommitmentKind::LegacyAccountsHash,
            hash: p.base.handoffs[0].successor.accounts_hash,
        }
    };
    let provenance = ArchiveProvenanceV2 {
        base: ArchiveProvenanceV1 {
            generation_profile: s.generation_profile.clone(),
            runtime_profile: s.runtime_profile.clone(),
            runtime_admission: s.runtime_admission,
            runtime_revision: s.runtime_revision.clone(),
            runtime_toolchain: s.runtime_toolchain.clone(),
            genesis_hash: p.base.genesis_hash,
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_slot: bootstrap.slot,
            bootstrap_state_hash: bootstrap.hash,
            requested_slot_start: s.slot_start,
            requested_slot_count: s.slot_count,
            transaction_metadata: p.base.transaction_metadata,
        },
        worker_executable_sha256: s.worker_executable_sha256.unwrap(),
    };
    let mut w = ArchiveWriter::new_with_provenance(
        create(path)?,
        EPOCH,
        s.slot_start,
        HALF,
        ArchiveWriterConfig::default(),
        &provenance.into(),
    )?;
    w.preserve_initial_poh_anchor(s.slot_start, h[2 * index])?;
    let mut u = AccountUpdateView {
        pubkey: Default::default(),
        lamports: 1,
        owner: Default::default(),
        executable: false,
        rent_epoch: 0,
        write_version: s.write_versions.worker_start,
        data: DATA,
    };
    for offset in 0..HALF {
        let slot = s.slot_start + offset;
        if offset != 0 && offset != HALF - 1 {
            w.write_skipped_slot(slot)?;
            continue;
        }
        w.begin_slot(slot)?;
        if offset == 0 {
            let mut e = EpochMeta::new_boxed();
            e.epoch = EPOCH;
            e.start_slot = s.slot_start;
            e.slot_count = HALF;
            e.first_block_slot = s.slot_start;
            e.updates.push(&u)?;
            w.write_epoch_meta(&e)?;
            u.write_version += 1;
        }
        w.write_orphan_update(&u)?;
        u.write_version += 1;
        let mut tx = Transaction::new_boxed();
        tx.signatures.push(Signature::from([0x37; 64]));
        tx.push_account_update(&u)?;
        w.write_transaction(&tx)?;
        u.write_version += 1;
        w.write_orphan_update(&u)?;
        u.write_version += 1;
        let position = 2 * index + usize::from(offset != 0);
        let mut b = BlockMeta::new_boxed();
        b.slot = slot;
        b.parent_slot = if offset == 0 { slot - 1 } else { s.slot_start };
        b.parent_blockhash = h[position];
        b.blockhash = h[position + 1];
        b.executed_transaction_count = 1;
        b.entry_count = 1;
        w.end_slot(
            &b,
            &[EntryRecord {
                num_hashes: 1,
                tx_count: 1,
            }],
        )?;
    }
    require(
        u.write_version == s.write_versions.worker_end_exclusive,
        "raw cursor mismatch",
    )?;
    w.finish()?.0.sync_all()?;
    Ok(())
}
fn sources(
    paths: &[PathBuf; 2],
    digests: &[[u8; 32]; 2],
    terminals: [Hash; 2],
) -> Result<Vec<RuntimeSegmentSource<File>>> {
    paths
        .iter()
        .zip(digests)
        .zip(terminals)
        .map(|((p, d), h)| Ok(RuntimeSegmentSource::new(File::open(p)?, *d, h)))
        .collect()
}
#[derive(Default)]
struct Updates {
    versions: Vec<u64>,
    epochs: Vec<(u64, u64, u64, u64)>,
}
impl SlotVisitor for Updates {
    fn on_epoch(&mut self, e: &EpochMeta) {
        self.epochs
            .push((e.epoch, e.start_slot, e.slot_count, e.first_block_slot));
        self.versions
            .extend(e.updates.iter().map(|(u, _)| u.write_version));
    }
    fn on_pre_account_update(&mut self, _: u64, u: &AccountUpdateView<'_>) {
        self.versions.push(u.write_version);
    }
    fn on_transaction(&mut self, _: u64, _: u32, tx: &Transaction) {
        self.versions
            .extend(tx.iter_account_updates().map(|(u, _)| u.write_version));
    }
    fn on_post_account_update(&mut self, _: u64, u: &AccountUpdateView<'_>) {
        self.versions.push(u.write_version);
    }
}
fn run(exe: &Path, args: &[String], root: &Path, label: &str, expected: i32) -> Result<Value> {
    let before = digest(exe)?;
    let status = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(create(&root.join(format!("{label}.stdout")))?)
        .stderr(create(&root.join(format!("{label}.stderr")))?)
        .status()?;
    require(
        status.code() == Some(expected),
        &format!("unexpected {label} result: {status}"),
    )?;
    require(digest(exe)? == before, "reader changed during execution")?;
    Ok(json!({"executable":exe,"sha256":hex(&before),"arguments":args,"exit_code":status.code()}))
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    require(
        args.len() == 3,
        "usage: checkpoint_v4_playback NEW_PRIVATE_ROOT PIPELINE FULL_VERIFIER",
    )?;
    let (root, pipeline, full) = (&args[0], &args[1], &args[2]);
    for path in &args {
        require(path.is_absolute(), "absolute paths required")?;
    }
    require(
        pipeline.canonicalize()? == *pipeline && full.canonicalize()? == *full,
        "canonical executables required",
    )?;
    fs::DirBuilder::new().mode(0o700).create(root)?;
    require(root.canonicalize()? == *root, "canonical root required")?;
    let tx = VersionedTransaction {
        signatures: vec![Signature::from([0x37; 64])],
        message: VersionedMessage::default(),
    };
    let mut h = [hash(0x91); 5];
    for i in 0..4 {
        h[i + 1] = solana_entry::entry::next_hash(&h[i], 1, std::slice::from_ref(&tx));
    }
    let p = provenance(&h);
    p.validate()?;
    let paths = [root.join("prefix.jet"), root.join("suffix.jet")];
    for (i, path) in paths.iter().enumerate() {
        source(path, &p, i, &h)?;
    }
    let digests = [digest(&paths[0])?, digest(&paths[1])?];
    let terminals = [h[2], h[4]];
    let archive = root.join(format!("epoch-{EPOCH}.jet"));
    let (file, stats) = merge_checkpoint_restart_segments(
        sources(&paths, &digests, terminals)?,
        create(&archive)?,
        ArchiveWriterConfig::default(),
        &p,
    )?;
    file.sync_all()?;
    require(
        stats.source_archives == 2
            && stats.slots_merged == COUNT
            && stats.account_updates_rebased == 14,
        "merge totals mismatch",
    )?;
    let mut reader = ArchiveReader::open(File::open(&archive)?)?;
    require(
        reader.provenance()? == Some(ArchiveProvenance::V4(p.clone())),
        "V4 provenance lost",
    )?;
    reader.verify_chain = true;
    reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    let mut updates = Updates::default();
    for bucket in 0..reader.bucket_count() {
        reader.read_bucket(bucket, &mut updates)?;
    }
    require(
        updates.versions == (1000..1014).collect::<Vec<_>>(),
        "normalized updates differ",
    )?;
    require(
        updates.epochs == vec![(EPOCH, FIRST, COUNT, FIRST)],
        "duplicate or truncated epoch metadata",
    )?;
    let archive_digest = digest(&archive)?;
    let report = root.join("plugin.json");
    let plugin_args = vec![
        EPOCH.to_string(),
        text(root)?,
        "--verify-only".into(),
        "--threads".into(),
        "2".into(),
        "--verification-report".into(),
        text(&report)?,
    ];
    let mut checks = vec![run(pipeline, &plugin_args, root, "plugin", 0)?];
    let playback: Value = serde_json::from_reader(File::open(&report)?)?;
    let mut invocation = vec![text(pipeline)?];
    invocation.extend(plugin_args);
    require(
        playback["schema"] == "jetstreamer-horizon-plugin-playback-v1"
            && playback["full_epoch_verified"] == true
            && playback["source"] == json!(root)
            && playback["invocation"] == json!(invocation),
        "playback identity mismatch",
    )?;
    for (key, value) in [
        ("epoch", EPOCH),
        ("first_slot", FIRST),
        ("last_slot", FIRST + COUNT - 1),
        ("slots", COUNT),
        ("blocks", 4),
        ("skipped", COUNT - 4),
        ("entries", 4),
        ("transactions", 4),
        ("transaction_updates", 4),
        ("orphan_updates", 9),
        ("epoch_updates", 1),
        ("account_data_bytes", 14 * DATA.len() as u64),
    ] {
        require(
            playback["report"][key] == value,
            &format!("playback count mismatch: {key}"),
        )?;
    }
    let full_args = vec![
        text(&archive)?,
        "--full".into(),
        "--threads".into(),
        "2".into(),
        "--anchor".into(),
        (FIRST - 1).to_string(),
        h[0].to_string(),
        "--expected-terminal".into(),
        (FIRST + COUNT - 1).to_string(),
        h[4].to_string(),
    ];
    checks.push(run(full, &full_args, root, "full", 0)?);
    let mut wrong = full_args.clone();
    *wrong.last_mut().unwrap() = hash(0x99).to_string();
    checks.push(run(full, &wrong, root, "wrong-terminal", 1)?);
    for case in 0..4 {
        let mut expected = digests;
        let mut boundary = terminals;
        let mut changed = p.clone();
        match case {
            0 => expected[1] = [0x99; 32],
            1 => boundary[0] = hash(0x99),
            2 => boundary[1] = hash(0x99),
            3 => changed.base.handoffs[0].successor.bank_hash = hash(0x99),
            _ => unreachable!(),
        }
        let result = merge_checkpoint_restart_segments(
            sources(&paths, &expected, boundary)?,
            create(&root.join(format!("rejected-{case}.partial")))?,
            ArchiveWriterConfig::default(),
            &changed,
        );
        let error = result.err().ok_or("invalid merge accepted")?;
        require(
            matches!(
                (&error, case),
                (
                    MultiSegmentMergeError::SourceDigestMismatch { index: 1, .. },
                    0
                ) | (
                    MultiSegmentMergeError::SourceTerminalEvidenceMismatch { index: 0, .. },
                    1
                ) | (
                    MultiSegmentMergeError::TerminalBlockhashMismatch { index: 1, .. },
                    2
                ) | (MultiSegmentMergeError::InvalidDestinationProvenance(_), 3)
            ),
            &format!("unexpected rejection {case}: {error}"),
        )?;
        checks.push(json!({"negative_case":case,"error":error.to_string()}));
    }
    require(
        digest(&archive)? == archive_digest
            && digest(&paths[0])? == digests[0]
            && digest(&paths[1])? == digests[1],
        "fixture changed",
    )?;
    let mut receipt = create(&root.join("native-results.json"))?;
    serde_json::to_writer_pretty(
        &mut receipt,
        &json!({
            "schema":"horizon-checkpoint-v4-native-playback-v1","synthetic":true,
            "archive":archive,"archive_sha256":hex(&archive_digest),"checks":checks,
            "normalized_write_versions":updates.versions,"full_slot_count":COUNT,
            "publication_authorized":false,"canonical_archive_verified":false,
            "mainnet_restore_verified":false,"r2_readback_verified":false,"remote_mutations":false
        }),
    )?;
    receipt.write_all(b"\n")?;
    receipt.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}
