//! Collect the local archive committed by the admitted epoch 257 cohort.
//! The uploader still performs its own exact archive, reader, and R2 checks.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};

const EPOCH: u64 = 257;
const UNIT: &str = "horizon-qualify-257-singleton-v1.service";
const INVOCATION: &str = "56bd4392e9c04b758825b5c94dfc8f9a";
const PID: u64 = 4_128_343;
const NODE: &str = "/var/lib/jetstreamer/horizon257-full-producer-v222-a1/jetstreamer-node";
const RUN: &str = "/home/ubuntu/.jetstreamer-private/qualification-257-singleton-v1";
const HANDOFF: &str = "/var/lib/jetstreamer/horizon257-paired-reader-88315624-v1/handoff.json";
const HANDOFF_SHA: &str = "48983dfe40cfe490947204e8880e6c559fa6cd654594316c6f76cdf7d2565a00";
const FINGERPRINT: &str = "1db8722474c1b2b30d08c6956767d25bf7ee52e88bf43cb3d73b004eb622ea14";
const BOOTSTRAP: u64 = 111_022_755;
const CHECKPOINT: u64 = 111_455_524;
const EPOCH_END: u64 = 111_455_999;
const BOOTSTRAP_HASH: &str = "8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3";
const CHECKPOINT_HASH: &str = "EKfxe81ej53cPZXptcBTgvJLQwSZ3k4nqdaxyUGTRYCw";
const COMMIT_MARKER: &str =
    "root-checkpoint cohort 257-257 published 1 archive(s) with checksums in transaction ";

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn command(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new(program).args(args).output()?;
    ensure!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn current_invocation() -> Result<Option<Value>> {
    let output = command(
        "/usr/bin/systemctl",
        &[
            "show",
            UNIT,
            "-p",
            "ActiveState",
            "-p",
            "InvocationID",
            "-p",
            "MainPID",
            "-p",
            "ControlGroup",
        ],
    )?;
    let text = std::str::from_utf8(&output)?;
    let field = |name: &str| {
        text.lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .with_context(|| format!("missing manager field {name}"))
    };
    let invocation = field("InvocationID")?;
    let pid = field("MainPID")?.parse::<u64>()?;
    if field("ActiveState")? == "active" {
        ensure!(
            invocation == INVOCATION && pid == PID,
            "another replay owns {UNIT}"
        );
        return Ok(Some(json!({
            "epoch": EPOCH, "state": "replay-active", "unit": UNIT,
            "invocation_id": INVOCATION, "main_pid": PID, "archive_ready": false
        })));
    }
    ensure!(
        field("ActiveState")? == "inactive"
            && pid == 0
            && field("ControlGroup")?.is_empty()
            && (invocation.is_empty() || invocation == INVOCATION)
            && !Path::new("/sys/fs/cgroup/system.slice").join(UNIT).exists(),
        "epoch 257 producer has not cleanly drained"
    );
    Ok(None)
}

fn one_event(args: &[&str]) -> Result<Value> {
    let mut argv = vec!["--no-pager", "--quiet", "-o", "json"];
    argv.extend_from_slice(args);
    let raw = command("/usr/bin/journalctl", &argv)?;
    let mut rows = std::str::from_utf8(&raw)?.lines();
    let event = rows.next().context("missing producer journal evidence")?;
    ensure!(rows.next().is_none(), "ambiguous producer journal evidence");
    Ok(serde_json::from_str(event)?)
}

fn commit_message(message: &str) -> Result<(&str, &str)> {
    let (_, tail) = message
        .split_once(COMMIT_MARKER)
        .context("missing commit marker")?;
    let (id, receipt) = tail
        .split_once("; receipt ")
        .context("missing receipt path")?;
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid transaction identifier"
    );
    let receipt = receipt
        .strip_suffix(" is durable")
        .context("incomplete commit marker")?;
    ensure!(
        Path::new(receipt).is_absolute(),
        "relative native receipt path"
    );
    Ok((id, receipt))
}

fn identity(meta: &Metadata) -> Value {
    json!({
        "device": meta.dev(), "inode": meta.ino(), "length": meta.len(),
        "mode": meta.mode(), "uid": meta.uid(), "gid": meta.gid(), "link_count": meta.nlink(),
        "modified_seconds": meta.mtime(), "modified_nanoseconds": meta.mtime_nsec(),
        "changed_seconds": meta.ctime(), "changed_nanoseconds": meta.ctime_nsec()
    })
}

fn read_bound(path: &Path, limit: u64, uid: u32) -> Result<(Vec<u8>, Value)> {
    ensure!(
        path.canonicalize()? == path,
        "noncanonical {}",
        path.display()
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == uid
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= limit,
        "unsafe metadata file {}",
        path.display()
    );
    let before = identity(&meta);
    let mut bytes = Vec::new();
    (&file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == meta.len()
            && before == identity(&file.metadata()?)
            && before == identity(&fs::symlink_metadata(path)?),
        "metadata changed during read: {}",
        path.display()
    );
    Ok((bytes, before))
}

fn base58_bytes(hash: &str) -> Result<Value> {
    let bytes = bs58::decode(hash).into_vec()?;
    ensure!(bytes.len() == 32, "incorrect checkpoint hash length");
    Ok(json!(bytes))
}

fn validate_gate(receipt: &Value) -> Result<()> {
    let gate = &receipt["root_checkpoint_gate"];
    let [checkpoint] = gate["verified_manifest_checkpoints"]
        .as_array()
        .context("missing manifest checkpoints")?
        .as_slice()
    else {
        anyhow::bail!("expected the singleton checkpoint");
    };
    let [member] = gate["members"]
        .as_array()
        .context("missing native members")?
        .as_slice()
    else {
        anyhow::bail!("expected one native checkpoint member");
    };
    ensure!(
        gate["kind"] == "sealed-root-checkpoint-cohort"
            && gate["version"] == 1
            && checkpoint["slot"] == CHECKPOINT
            && checkpoint["accounts_hash"] == base58_bytes(CHECKPOINT_HASH)?
            && member["epoch"] == EPOCH
            && member["bootstrap"]["slot"] == BOOTSTRAP
            && member["bootstrap"]["accounts_hash"] == base58_bytes(BOOTSTRAP_HASH)?
            && member["bootstrap"]["slot_complete"] == true
            && member["terminal"]["slot_complete"] == true
            && member["terminal"]["slot"]
                .as_u64()
                .is_some_and(|slot| (CHECKPOINT..=EPOCH_END).contains(&slot)),
        "native receipt differs from the admitted epoch 257 checkpoint scope"
    );
    let raw = STANDARD.decode(
        receipt["publication_context_base64"]
            .as_str()
            .context("missing durable batch context")?,
    )?;
    let context: Value = serde_json::from_slice(&raw)?;
    let fingerprint = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&FINGERPRINT[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        context["schema"] == "jetstreamer-root-checkpoint-gate-context-v1"
            && context["manifest_fingerprint"] == json!(fingerprint)
            && context["epochs"] == json!([EPOCH])
            && context["gate"] == *gate,
        "durable transaction context differs from receipt"
    );
    Ok(())
}

fn collect() -> Result<Value> {
    if let Some(live) = current_invocation()? {
        return Ok(live);
    }
    let terminal = one_event(&[
        "_PID=1",
        &format!("UNIT={UNIT}"),
        &format!("INVOCATION_ID={INVOCATION}"),
        r"--grep=Deactivated successfully\.",
    ])?;
    ensure!(
        terminal["MESSAGE"] == format!("{UNIT}: Deactivated successfully."),
        "foreign manager result"
    );
    let native = one_event(&[
        &format!("_PID={PID}"),
        &format!("_SYSTEMD_INVOCATION_ID={INVOCATION}"),
        "--grep=root-checkpoint cohort 257-257 published 1 archive",
    ])?;
    ensure!(
        native["_EXE"] == NODE
            && native["_SYSTEMD_UNIT"] == UNIT
            && native["__REALTIME_TIMESTAMP"]
                .as_str()
                .context("missing native timestamp")?
                .parse::<u64>()?
                <= terminal["__REALTIME_TIMESTAMP"]
                    .as_str()
                    .context("missing manager timestamp")?
                    .parse::<u64>()?,
        "native commit is outside the admitted producer and terminal"
    );
    let (transaction, reported) = commit_message(
        native["MESSAGE"]
            .as_str()
            .context("missing native commit")?,
    )?;
    let destination = Path::new(RUN).join("output");
    let dest = fs::symlink_metadata(&destination)?;
    ensure!(
        destination.canonicalize()? == destination && dest.is_dir() && dest.uid() == 1000,
        "foreign archive directory"
    );
    let receipt = Path::new(RUN)
        .join("state")
        .join(format!(
            "destination-{}",
            sha256(destination.as_os_str().as_encoded_bytes())
        ))
        .join("evidence/archive-batches")
        .join(format!(
            "destination-{:016x}-{:016x}",
            dest.dev(),
            dest.ino()
        ))
        .join(format!("batch-{transaction}.json"));
    ensure!(
        Path::new(reported) == receipt,
        "journal points to a foreign native receipt"
    );
    let (body, _) = read_bound(&receipt, 4 << 20, 1000)?;
    let batch: Value = serde_json::from_slice(&body)?;
    ensure!(
        batch["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && batch["transaction_id"] == transaction
            && batch["manifest_fingerprint"] == format!("sha256:{FINGERPRINT}")
            && batch["epochs"] == json!([EPOCH])
            && batch["destination"]
                == json!({
                    "path_base64": STANDARD.encode(destination.as_os_str().as_encoded_bytes()),
                    "device": dest.dev(), "inode": dest.ino()
                })
            && batch["outcome"]["kind"] == "committed",
        "foreign or uncommitted native cohort receipt"
    );
    validate_gate(&batch)?;
    let [member] = batch["outcome"]["members"]
        .as_array()
        .context("missing committed member")?
        .as_slice()
    else {
        anyhow::bail!("expected the one committed epoch 257 archive");
    };
    let archive = destination.join("epoch-257.jet");
    let sidecar = destination.join("epoch-257.jet.sha256");
    let meta = fs::symlink_metadata(&archive)?;
    let digest = member["archive_sha256"]
        .as_str()
        .context("missing native archive digest")?;
    let (checksum, checksum_identity) = read_bound(&sidecar, 256, 1000)?;
    ensure!(
        member["epoch"] == EPOCH
            && member["archive_path_base64"]
                == STANDARD.encode(archive.as_os_str().as_encoded_bytes())
            && member["checksum_path_base64"]
                == STANDARD.encode(sidecar.as_os_str().as_encoded_bytes())
            && meta.is_file()
            && meta.uid() == 1000
            && meta.nlink() == 1
            && meta.mode() & 0o222 == 0
            && member["committed_archive"] == identity(&meta)
            && member["committed_checksum"] == checksum_identity
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && checksum == format!("{digest}  epoch-257.jet\n").as_bytes(),
        "native committed pair changed or is unsafe"
    );
    let (handoff, _) = read_bound(Path::new(HANDOFF), 1 << 20, 0)?;
    ensure!(
        sha256(&handoff) == HANDOFF_SHA,
        "publication handoff changed"
    );
    let handoff: Value = serde_json::from_slice(&handoff)?;
    let output = json!({
        "epoch": EPOCH, "schema": "foundation-epoch257-committed-cohort-source-v1",
        "state": "local-cohort-committed", "unit": UNIT, "invocation_id": INVOCATION,
        "publication_authorized": false, "archive": {"path": archive, "sha256": digest, "identity": identity(&meta)},
        "sidecar": {"path": sidecar, "sha256": sha256(&checksum), "identity": checksum_identity},
        "cohort_receipt": {"path": receipt, "sha256": sha256(&body)},
        "native_journal_cursor": native["__CURSOR"], "terminal_journal_cursor": terminal["__CURSOR"],
        "reader_plan": handoff["reader_plan"], "uploader": handoff["uploader"]
    });
    ensure!(
        current_invocation()?.is_none()
            && identity(&fs::symlink_metadata(&archive)?) == identity(&meta),
        "producer or archive changed during collection"
    );
    Ok(output)
}

fn main() -> Result<()> {
    ensure!(
        std::env::args_os().count() == 1,
        "usage: horizon-epoch257-commit-source"
    );
    let report = collect()?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_event_requires_complete_native_message() {
        let transaction = "a".repeat(64);
        let message = format!(
            "2026-11-25 INFO {COMMIT_MARKER}{transaction}; receipt /private/batch.json is durable"
        );
        assert_eq!(
            commit_message(&message).unwrap(),
            (transaction.as_str(), "/private/batch.json")
        );
        assert!(commit_message(&message.replace("/private/batch.json", "batch.json")).is_err());
        assert!(commit_message(message.trim_end_matches(" is durable")).is_err());
    }

    #[test]
    fn published_checkpoint_must_match_embedded_transaction_context() {
        let gate = json!({
            "kind": "sealed-root-checkpoint-cohort", "version": 1,
            "verified_manifest_checkpoints": [{"slot": CHECKPOINT, "accounts_hash": base58_bytes(CHECKPOINT_HASH).unwrap()}],
            "members": [{"epoch": EPOCH,
                "bootstrap": {"slot": BOOTSTRAP, "accounts_hash": base58_bytes(BOOTSTRAP_HASH).unwrap(), "slot_complete": true},
                "terminal": {"slot": EPOCH_END, "slot_complete": true}
            }]
        });
        let fingerprint = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&FINGERPRINT[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let context = json!({"schema":"jetstreamer-root-checkpoint-gate-context-v1",
            "manifest_fingerprint": fingerprint, "epochs": [EPOCH], "gate": gate});
        let mut receipt = json!({"root_checkpoint_gate": gate,
            "publication_context_base64": STANDARD.encode(serde_json::to_vec(&context).unwrap())});
        validate_gate(&receipt).unwrap();
        receipt["root_checkpoint_gate"]["members"][0]["terminal"]["slot"] = json!(CHECKPOINT);
        assert!(validate_gate(&receipt).is_err());
        receipt["root_checkpoint_gate"]["verified_manifest_checkpoints"][0]["slot"] =
            json!(CHECKPOINT + 1);
        assert!(validate_gate(&receipt).is_err());
    }
}
