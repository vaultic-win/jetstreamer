//! Collect the local archive committed by an admitted Foundation singleton cohort.
//! The uploader still performs its own exact archive, reader, and R2 checks.
mod handoff252;
mod hourly230;

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

struct Cohort {
    epoch: u64,
    unit: &'static str,
    invocation: &'static str,
    pid: u64,
    node: &'static str,
    run: &'static str,
    handoff: Option<(&'static str, &'static str)>,
    fingerprint: &'static str,
    bootstrap: u64,
    checkpoint: u64,
    epoch_end: u64,
    bootstrap_hash: &'static str,
    checkpoint_hash: &'static str,
}

const EPOCH_252: Cohort = Cohort {
    epoch: 252,
    unit: "horizon-qualify-252-regional-singleton-v1.service",
    invocation: "8a7f9d325707485f9dac1d56c2403e52",
    pid: 500_006,
    node: "/var/lib/jetstreamer/horizon252-regional-node-v268/jetstreamer-node",
    run: "/home/ubuntu/.jetstreamer-private/qualification-252-regional-singleton-v1",
    handoff: None,
    fingerprint: "e4705888ac93a44cf696c4c9ca94e5244c49591f225680d500022c1856aed788",
    bootstrap: 108_863_367,
    checkpoint: 109_295_460,
    epoch_end: 109_295_999,
    bootstrap_hash: "4hcGVnD196WHfscx9En2f4axXyUzW59ZKRZF5MZv8AAa",
    checkpoint_hash: "3VfnFx5Si2VsoCYfsBKVFVpiHDdqg3X1JWpyduakmDL3",
};

const EPOCH_257: Cohort = Cohort {
    epoch: 257,
    unit: "horizon-qualify-257-singleton-v1.service",
    invocation: "56bd4392e9c04b758825b5c94dfc8f9a",
    pid: 4_128_343,
    node: "/var/lib/jetstreamer/horizon257-full-producer-v222-a1/jetstreamer-node",
    run: "/home/ubuntu/.jetstreamer-private/qualification-257-singleton-v1",
    handoff: Some((
        "/var/lib/jetstreamer/horizon257-paired-reader-88315624-v1/handoff.json",
        "48983dfe40cfe490947204e8880e6c559fa6cd654594316c6f76cdf7d2565a00",
    )),
    fingerprint: "1db8722474c1b2b30d08c6956767d25bf7ee52e88bf43cb3d73b004eb622ea14",
    bootstrap: 111_022_755,
    checkpoint: 111_455_524,
    epoch_end: 111_455_999,
    bootstrap_hash: "8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3",
    checkpoint_hash: "EKfxe81ej53cPZXptcBTgvJLQwSZ3k4nqdaxyUGTRYCw",
};

const EPOCH_260: Cohort = Cohort {
    epoch: 260,
    unit: "horizon-qualify-260-singleton-v1.service",
    invocation: "754e0feaf1f042779dddada28038de19",
    pid: 2_469_976,
    node: "/var/lib/jetstreamer/horizon258-parent-88cfc82b-v1/jetstreamer-node",
    run: "/home/ubuntu/.jetstreamer-private/qualification-260-singleton-v1",
    handoff: None,
    fingerprint: "5072a10529e0aa6f80022b0dd00726562b88c83e08ec0de7efaf46d4e7dc9f23",
    bootstrap: 112_316_757,
    checkpoint: 112_751_309,
    epoch_end: 112_751_999,
    bootstrap_hash: "7bFgHyuoXhyvqhxdZ9bog5i6MrQanLNakePzbmhCLivi",
    checkpoint_hash: "GjFUHtRB29hxZoxWjEcQBm8w4nTNRtn3rKZTVsoFKZMX",
};

const EPOCH_261: Cohort = Cohort {
    epoch: 261,
    unit: "horizon-qualify-261-singleton-v1.service",
    invocation: "bca65ead67144a92af798fd8d1c8f533",
    pid: 3_912_288,
    node: "/var/lib/jetstreamer/horizon261-full-producer-v224-a1/jetstreamer-node",
    run: "/home/ubuntu/.jetstreamer-private/qualification-261-singleton-v1",
    handoff: None,
    fingerprint: "c5667ace6837b1f039bad3c4f66937ecad4f5d4596bb491ee5070292b59d7919",
    bootstrap: 112_751_208,
    checkpoint: 113_182_967,
    epoch_end: 113_183_999,
    bootstrap_hash: "Hgio4phsEt74AkKo6KdVmFzDoK35yS3fUkF6u3RkhSut",
    checkpoint_hash: "39EumnbfaaQdkf2ZMjL1uvVR9T9HcmE1RUP1xeCfpXVU",
};

const EPOCH_262: Cohort = Cohort {
    epoch: 262,
    unit: "horizon-qualify-262-singleton-v1.service",
    invocation: "de99f16b104046929862a90e77fd1d8f",
    pid: 2_030_776,
    node: "/var/lib/jetstreamer/horizon262-full-node-b9b95b02-v1/jetstreamer-node",
    run: "/home/ubuntu/.jetstreamer-private/qualification-262-singleton-v1",
    handoff: None,
    fingerprint: "8163fe7dc28e19a4c624242273e1188fd7767731bab26374af4561f067e27cfd",
    bootstrap: 113_182_967,
    checkpoint: 113_615_476,
    epoch_end: 113_615_999,
    bootstrap_hash: "39EumnbfaaQdkf2ZMjL1uvVR9T9HcmE1RUP1xeCfpXVU",
    checkpoint_hash: "9VhNZirsXzcu2X1P3PE9TbB9XNHJ383LVFuaMtDFguAo",
};

const EPOCH_288: Cohort = Cohort {
    epoch: 288,
    unit: "horizon-qualify-288-root-shrink-debt-v1.service",
    invocation: "88edf4dd09f343c9ac90cfff907c7b18",
    pid: 1_495_530,
    node: "/var/lib/jetstreamer/horizon288-node-v303/jetstreamer-node",
    run: "/home/ubuntu/.jetstreamer-private/qualification-288-full-shrink-debt-v1",
    handoff: None,
    fingerprint: "b476c8c2c2a9e838969b12d0aabccb3ba101defd62aa0e7851d46b2f0807fd3b",
    bootstrap: 124_415_782,
    checkpoint: 124_846_819,
    epoch_end: 124_847_999,
    bootstrap_hash: "ApsjgCndKc38Wv37guZpxbR7MuTs5WATjVtm3MeGSPM6",
    checkpoint_hash: "82QEwuM774K6MCdbCQydkufsLDrtg9AA1wSyumKVuLve",
};

fn commit_marker(epoch: u64) -> String {
    format!(
        "root-checkpoint cohort {epoch}-{epoch} published 1 archive(s) with checksums in transaction "
    )
}

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

fn current_invocation(cohort: &Cohort) -> Result<Option<Value>> {
    let output = command(
        "/usr/bin/systemctl",
        &[
            "show",
            cohort.unit,
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
            invocation == cohort.invocation && pid == cohort.pid,
            "another replay owns {}",
            cohort.unit
        );
        return Ok(Some(json!({
            "epoch": cohort.epoch, "state": "replay-active", "unit": cohort.unit,
            "invocation_id": cohort.invocation, "main_pid": cohort.pid, "archive_ready": false
        })));
    }
    ensure!(
        field("ActiveState")? == "inactive"
            && pid == 0
            && field("ControlGroup")?.is_empty()
            && (invocation.is_empty() || invocation == cohort.invocation)
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(cohort.unit)
                .exists(),
        "epoch {} producer has not cleanly drained",
        cohort.epoch
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

fn commit_message(message: &str, epoch: u64) -> Result<(&str, &str)> {
    let (_, tail) = message
        .split_once(&commit_marker(epoch))
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

fn validate_gate(receipt: &Value, cohort: &Cohort) -> Result<()> {
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
            && checkpoint["slot"] == cohort.checkpoint
            && checkpoint["accounts_hash"] == base58_bytes(cohort.checkpoint_hash)?
            && member["epoch"] == cohort.epoch
            && member["bootstrap"]["slot"] == cohort.bootstrap
            && member["bootstrap"]["accounts_hash"] == base58_bytes(cohort.bootstrap_hash)?
            && member["bootstrap"]["slot_complete"] == true
            && member["terminal"]["slot_complete"] == true
            && member["terminal"]["slot"]
                .as_u64()
                .is_some_and(|slot| (cohort.checkpoint..=cohort.epoch_end).contains(&slot)),
        "native receipt differs from the admitted epoch {} checkpoint scope",
        cohort.epoch
    );
    let raw = STANDARD.decode(
        receipt["publication_context_base64"]
            .as_str()
            .context("missing durable batch context")?,
    )?;
    let context: Value = serde_json::from_slice(&raw)?;
    let fingerprint = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&cohort.fingerprint[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        context["schema"] == "jetstreamer-root-checkpoint-gate-context-v1"
            && context["manifest_fingerprint"] == json!(fingerprint)
            && context["epochs"] == json!([cohort.epoch])
            && context["gate"] == *gate,
        "durable transaction context differs from receipt"
    );
    Ok(())
}

fn collect(cohort: &Cohort) -> Result<Value> {
    if let Some(live) = current_invocation(cohort)? {
        return Ok(live);
    }
    let terminal = one_event(&[
        "_PID=1",
        &format!("UNIT={}", cohort.unit),
        &format!("INVOCATION_ID={}", cohort.invocation),
        r"--grep=Deactivated successfully\.",
    ])?;
    ensure!(
        terminal["MESSAGE"] == format!("{}: Deactivated successfully.", cohort.unit),
        "foreign manager result"
    );
    let native = one_event(&[
        &format!("_PID={}", cohort.pid),
        &format!("_SYSTEMD_INVOCATION_ID={}", cohort.invocation),
        &format!(
            "--grep=root-checkpoint cohort {0}-{0} published 1 archive",
            cohort.epoch
        ),
    ])?;
    ensure!(
        native["_EXE"] == cohort.node
            && native["_SYSTEMD_UNIT"] == cohort.unit
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
        cohort.epoch,
    )?;
    let destination = Path::new(cohort.run).join("output");
    let dest = fs::symlink_metadata(&destination)?;
    ensure!(
        destination.canonicalize()? == destination && dest.is_dir() && dest.uid() == 1000,
        "foreign archive directory"
    );
    let receipt = Path::new(cohort.run)
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
            && batch["manifest_fingerprint"] == format!("sha256:{}", cohort.fingerprint)
            && batch["epochs"] == json!([cohort.epoch])
            && batch["destination"]
                == json!({
                    "path_base64": STANDARD.encode(destination.as_os_str().as_encoded_bytes()),
                    "device": dest.dev(), "inode": dest.ino()
                })
            && batch["outcome"]["kind"] == "committed",
        "foreign or uncommitted native cohort receipt"
    );
    validate_gate(&batch, cohort)?;
    let [member] = batch["outcome"]["members"]
        .as_array()
        .context("missing committed member")?
        .as_slice()
    else {
        anyhow::bail!("expected one committed epoch {} archive", cohort.epoch);
    };
    let archive_name = format!("epoch-{}.jet", cohort.epoch);
    let archive = destination.join(&archive_name);
    let sidecar = destination.join(format!("{archive_name}.sha256"));
    let meta = fs::symlink_metadata(&archive)?;
    let digest = member["archive_sha256"]
        .as_str()
        .context("missing native archive digest")?;
    let (checksum, checksum_identity) = read_bound(&sidecar, 256, 1000)?;
    ensure!(
        member["epoch"] == cohort.epoch
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
            && checksum == format!("{digest}  {archive_name}\n").as_bytes(),
        "native committed pair changed or is unsafe"
    );
    let mut output = json!({
        "epoch": cohort.epoch, "schema": format!("foundation-epoch{}-committed-cohort-source-v1", cohort.epoch),
        "state": "local-cohort-committed", "unit": cohort.unit, "invocation_id": cohort.invocation,
        "publication_authorized": false, "archive": {"path": archive, "sha256": digest, "identity": identity(&meta)},
        "sidecar": {"path": sidecar, "sha256": sha256(&checksum), "identity": checksum_identity},
        "cohort_receipt": {"path": receipt, "sha256": sha256(&body)},
        "native_journal_cursor": native["__CURSOR"], "terminal_journal_cursor": terminal["__CURSOR"]
    });
    if let Some((path, expected_sha256)) = cohort.handoff {
        let (handoff, _) = read_bound(Path::new(path), 1 << 20, 0)?;
        ensure!(
            sha256(&handoff) == expected_sha256,
            "publication handoff changed"
        );
        let handoff: Value = serde_json::from_slice(&handoff)?;
        output["reader_plan"] = handoff["reader_plan"].clone();
        output["uploader"] = handoff["uploader"].clone();
    }
    ensure!(
        current_invocation(cohort)?.is_none()
            && identity(&fs::symlink_metadata(&archive)?) == identity(&meta),
        "producer or archive changed during collection"
    );
    Ok(output)
}

const USAGE: &str = "usage: horizon-epoch257-commit-source [--epoch230-hourly | --epoch230-hourly-second | --epoch252 | --epoch260 | --epoch261 | --epoch262 | --epoch288 | --reconcile-epoch252 | --check-epoch252-delivery-deployment | --launch-epoch252-delivery QUOTE SHA256]";

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next();
    if mode.as_deref() == Some(std::ffi::OsStr::new("--launch-epoch252-delivery")) {
        let quote = args
            .next()
            .context("provide the epoch 252 delivery quote")?;
        let digest = args.next().context("provide the delivery quote SHA-256")?;
        ensure!(
            args.next().is_none(),
            "unexpected epoch 252 delivery argument"
        );
        let report = handoff252::delivery::launch(
            Path::new(&quote),
            digest.to_str().context("quote digest")?,
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    ensure!(args.next().is_none(), "{USAGE}");
    if let Some("--epoch230-hourly" | "--epoch230-hourly-second") =
        mode.as_deref().and_then(std::ffi::OsStr::to_str)
    {
        let second = mode.as_deref() == Some(std::ffi::OsStr::new("--epoch230-hourly-second"));
        println!(
            "{}",
            serde_json::to_string_pretty(&hourly230::collect(second)?)?
        );
        return Ok(());
    }
    if mode.as_deref() == Some(std::ffi::OsStr::new("--check-epoch252-delivery-deployment")) {
        let report = handoff252::delivery::check_installed_deployment()?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if mode.as_deref() == Some(std::ffi::OsStr::new("--reconcile-epoch252")) {
        println!("{}", serde_json::to_string_pretty(&handoff252::run()?)?);
        return Ok(());
    }
    let cohort = match mode.as_deref() {
        None => &EPOCH_257,
        Some(flag) if flag == "--epoch252" => &EPOCH_252,
        Some(flag) if flag == "--epoch260" => &EPOCH_260,
        Some(flag) if flag == "--epoch261" => &EPOCH_261,
        Some(flag) if flag == "--epoch262" => &EPOCH_262,
        Some(flag) if flag == "--epoch288" => &EPOCH_288,
        _ => anyhow::bail!("{USAGE}"),
    };
    let report = collect(cohort)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_event_requires_complete_native_message() {
        for cohort in [
            &EPOCH_252, &EPOCH_257, &EPOCH_260, &EPOCH_261, &EPOCH_262, &EPOCH_288,
        ] {
            let epoch = cohort.epoch;
            let transaction = "a".repeat(64);
            let marker = commit_marker(epoch);
            let message = format!(
                "2026-11-25 INFO {marker}{transaction}; receipt /private/batch.json is durable"
            );
            assert_eq!(
                commit_message(&message, epoch).unwrap(),
                (transaction.as_str(), "/private/batch.json")
            );
            assert!(
                commit_message(&message.replace("/private/batch.json", "batch.json"), epoch)
                    .is_err()
            );
            assert!(commit_message(message.trim_end_matches(" is durable"), epoch).is_err());
        }
    }

    #[test]
    fn published_checkpoint_must_match_embedded_transaction_context() {
        for (cohort, other) in [
            (&EPOCH_252, &EPOCH_257),
            (&EPOCH_257, &EPOCH_261),
            (&EPOCH_260, &EPOCH_262),
            (&EPOCH_261, &EPOCH_257),
            (&EPOCH_262, &EPOCH_260),
            (&EPOCH_288, &EPOCH_262),
        ] {
            let gate = json!({
                "kind": "sealed-root-checkpoint-cohort", "version": 1,
                "verified_manifest_checkpoints": [{"slot": cohort.checkpoint, "accounts_hash": base58_bytes(cohort.checkpoint_hash).unwrap()}],
                "members": [{"epoch": cohort.epoch,
                    "bootstrap": {"slot": cohort.bootstrap, "accounts_hash": base58_bytes(cohort.bootstrap_hash).unwrap(), "slot_complete": true},
                    "terminal": {"slot": cohort.epoch_end, "slot_complete": true}
                }]
            });
            let fingerprint = (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&cohort.fingerprint[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>();
            let context = json!({"schema":"jetstreamer-root-checkpoint-gate-context-v1",
                "manifest_fingerprint": fingerprint, "epochs": [cohort.epoch], "gate": gate});
            let mut receipt = json!({"root_checkpoint_gate": gate,
                "publication_context_base64": STANDARD.encode(serde_json::to_vec(&context).unwrap())});
            validate_gate(&receipt, cohort).unwrap();
            assert!(validate_gate(&receipt, other).is_err());
            receipt["root_checkpoint_gate"]["members"][0]["terminal"]["slot"] =
                json!(cohort.checkpoint);
            assert!(validate_gate(&receipt, cohort).is_err());
            receipt["root_checkpoint_gate"]["verified_manifest_checkpoints"][0]["slot"] =
                json!(cohort.checkpoint + 1);
            assert!(validate_gate(&receipt, cohort).is_err());
        }
    }
}
