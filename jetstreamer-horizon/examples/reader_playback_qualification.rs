//! Native full-verifier/plugin checks using explicitly synthetic full-range archives.
//! No network, R2 writes, canonical epoch inputs or publication authority.
use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{ArchiveWriter, ArchiveWriterConfig, EntryRecord, EpochMeta},
    block_metas::BlockMeta,
    transactions::Transaction,
};
use serde_json::{Value, json};
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
const EPOCH: u64 = 251;
const FIRST: u64 = EPOCH * 432_000;
const SLOTS: u64 = 432_000;
const DATA: &[u8] = b"synthetic bytes!";

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

fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut file = create(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(path.parent().ok_or("missing parent")?)?.sync_all()?;
    Ok(())
}

fn digest(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut reader = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Expectations derive from fixed inputs and canonical PoH construction before
/// writing; they are never extracted from the resulting archive.
fn fixture(
    root: &Path,
    count: u64,
    missing_epoch: bool,
    wrong_poh: bool,
    skipped_tail: bool,
) -> Result<Hash> {
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let mut writer = ArchiveWriter::new(
        create(&root.join(format!("epoch-{EPOCH}.jet")))?,
        EPOCH,
        FIRST,
        count,
        ArchiveWriterConfig::default(),
    )?;
    let anchor = Hash::new_from_array([0x91; 32]);
    writer.preserve_initial_poh_anchor(FIRST, anchor)?;
    let signature = Signature::from([0x37; 64]);
    let wire_tx = VersionedTransaction {
        signatures: vec![signature],
        message: VersionedMessage::default(),
    };
    let first_hash = solana_entry::entry::next_hash(&anchor, 1, std::slice::from_ref(&wire_tx));
    let terminal = solana_entry::entry::next_hash(&first_hash, 1, std::slice::from_ref(&wire_tx));
    let mut update = AccountUpdateView {
        pubkey: Default::default(),
        lamports: 1,
        owner: Default::default(),
        executable: false,
        rent_epoch: 0,
        write_version: 1,
        data: DATA,
    };
    for offset in 0..count {
        let slot = FIRST + offset;
        if offset != 0 && offset != count - if skipped_tail { 5 } else { 1 } {
            writer.write_skipped_slot(slot)?;
            continue;
        }
        writer.begin_slot(slot)?;
        if offset == 0 && !missing_epoch {
            let mut meta = EpochMeta::new_boxed();
            meta.epoch = EPOCH;
            meta.start_slot = FIRST;
            meta.slot_count = count;
            meta.first_block_slot = FIRST;
            meta.updates.push(&update)?;
            writer.write_epoch_meta(&meta)?;
            update.write_version += 1;
        }
        writer.write_orphan_update(&update)?;
        update.write_version += 1;
        let mut tx = Transaction::new_boxed();
        tx.signatures.push(signature);
        tx.push_account_update(&update)?;
        writer.write_transaction(&tx)?;
        update.write_version += 1;
        writer.write_orphan_update(&update)?;
        update.write_version += 1;
        let mut block = BlockMeta::new_boxed();
        block.slot = slot;
        block.parent_slot = if offset == 0 { FIRST - 1 } else { FIRST };
        block.parent_blockhash = if offset == 0 { anchor } else { first_hash };
        block.blockhash = if offset == 0 {
            first_hash
        } else if wrong_poh {
            Hash::new_from_array([0x55; 32])
        } else {
            terminal
        };
        block.executed_transaction_count = 1;
        block.entry_count = 1;
        writer.end_slot(
            &block,
            &[EntryRecord {
                num_hashes: 1,
                tx_count: 1,
            }],
        )?;
    }
    let (file, _) = writer.finish()?;
    file.sync_all()?;
    Ok(terminal)
}

fn run(
    executable: &Path,
    args: &[String],
    root: &Path,
    label: &str,
    success: bool,
) -> Result<Value> {
    let stdout = root.join(format!("{label}.stdout"));
    let stderr = root.join(format!("{label}.stderr"));
    let before = digest(executable)?;
    let status = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(create(&stdout)?)
        .stderr(create(&stderr)?)
        .status()?;
    require(
        status.code() == Some(if success { 0 } else { 1 }),
        &format!("unexpected {label} result: {status}"),
    )?;
    require(
        digest(executable)? == before,
        "reader changed during native check",
    )?;
    Ok(
        json!({"executable":executable,"sha256":before,"arguments":args,
        "exit_code":status.code(),"expected_success":success,"stdout":stdout,"stderr":stderr}),
    )
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    require(
        args.len() == 3,
        "usage: reader_playback_qualification NEW_PRIVATE_ROOT PIPELINE FULL_VERIFIER",
    )?;
    let (root, pipeline, verifier) = (&args[0], &args[1], &args[2]);
    for path in &args {
        require(path.is_absolute(), "all paths must be absolute")?;
    }
    require(
        pipeline.canonicalize()? == *pipeline && verifier.canonicalize()? == *verifier,
        "reader paths must be canonical",
    )?;
    // Creation is deliberately no-clobber; a retry must preserve its failed attempt.
    fs::DirBuilder::new().mode(0o700).create(root)?;
    require(root.canonicalize()? == *root, "test root must be canonical")?;
    let mut checks = Vec::new();
    for (label, count, missing_epoch, wrong_poh, skipped_tail) in [
        ("complete", SLOTS, false, false, false),
        ("partial", SLOTS - 1, false, false, false),
        ("missing-epoch", SLOTS, true, false, false),
        ("wrong-poh", SLOTS, false, true, false),
        ("skipped-tail", SLOTS, false, false, true),
    ] {
        let source = root.join(label);
        let terminal = fixture(&source, count, missing_epoch, wrong_poh, skipped_tail)?;
        let archive = source.join(format!("epoch-{EPOCH}.jet"));
        let report = source.join("plugin.json");
        let to_string =
            |p: &Path| -> Result<String> { Ok(p.to_str().ok_or("non-UTF8 path")?.into()) };
        // Wrong PoH is a full-verifier negative case. The plugin validates
        // callbacks and coverage; it is not a replacement for the PoH verifier.
        if !wrong_poh {
            let invocation = vec![
                EPOCH.to_string(),
                to_string(&source)?,
                "--verify-only".into(),
                "--threads".into(),
                "2".into(),
                "--verification-report".into(),
                to_string(&report)?,
            ];
            let success = label == "complete" || skipped_tail;
            checks.push(run(pipeline, &invocation, &source, "plugin", success)?);
            if success {
                let value: Value = serde_json::from_reader(File::open(&report)?)?;
                let mut expected_invocation = vec![to_string(pipeline)?];
                expected_invocation.extend(invocation);
                require(
                    value["schema"] == "jetstreamer-horizon-plugin-playback-v1"
                        && value["full_epoch_verified"] == true
                        && value["source"] == json!(source)
                        && value["invocation"] == json!(expected_invocation),
                    "report identity mismatch",
                )?;
                for (field, expected) in [
                    ("epoch", EPOCH),
                    ("first_slot", FIRST),
                    ("last_slot", FIRST + SLOTS - 1),
                    ("slots", SLOTS),
                    ("blocks", 2),
                    ("skipped", SLOTS - 2),
                    ("entries", 2),
                    ("transactions", 2),
                    ("transaction_updates", 2),
                    ("orphan_updates", 4),
                    ("epoch_updates", 1),
                    ("account_data_bytes", 7 * DATA.len() as u64),
                ] {
                    require(
                        value["report"][field] == expected,
                        &format!("wrong report count: {field}"),
                    )?;
                }
            } else {
                require(
                    !report.try_exists()?,
                    "failed plugin created a success report",
                )?;
            }
        }
        if label == "complete" || wrong_poh || skipped_tail {
            let mut invocation = vec![
                to_string(&archive)?,
                "--full".into(),
                "--threads".into(),
                "2".into(),
                "--anchor".into(),
                (FIRST - 1).to_string(),
                Hash::new_from_array([0x91; 32]).to_string(),
                "--expected-terminal".into(),
                (FIRST + SLOTS - if skipped_tail { 5 } else { 1 }).to_string(),
                terminal.to_string(),
            ];
            if skipped_tail {
                checks.push(run(
                    verifier,
                    &invocation,
                    &source,
                    "missing-successor",
                    false,
                )?);
                invocation.extend([
                    "--expected-successor".into(),
                    (FIRST + SLOTS + 12).to_string(),
                    (FIRST + SLOTS - 5).to_string(),
                    terminal.to_string(),
                ]);
                let mut wrong = invocation.clone();
                *wrong.last_mut().unwrap() = Hash::new_from_array([0x55; 32]).to_string();
                checks.push(run(
                    verifier,
                    &wrong,
                    &source,
                    "wrong-successor-hash",
                    false,
                )?);
                let mut wrong = invocation.clone();
                let n = wrong.len();
                wrong[n - 2] = (FIRST + SLOTS - 6).to_string();
                checks.push(run(
                    verifier,
                    &wrong,
                    &source,
                    "wrong-successor-parent",
                    false,
                )?);
                let mut wrong = invocation.clone();
                let n = wrong.len();
                wrong[n - 3] = (FIRST + SLOTS - 1).to_string();
                checks.push(run(
                    verifier,
                    &wrong,
                    &source,
                    "successor-inside-epoch",
                    false,
                )?);
            }
            checks.push(run(verifier, &invocation, &source, "full", !wrong_poh)?);
        }
        checks.push(json!({"fixture":archive,"sha256":digest(&archive)?,"synthetic":true}));
    }
    write_json(
        &root.join("native-results.json"),
        &json!({
            "schema":"horizon-current-reader-native-qualification-v1", "checks":checks,
            "publication_authorized":false,"canonical_archive_verified":false,
            "r2_readback_verified":false,"remote_mutations":false,
        }),
    )?;
    Ok(())
}
