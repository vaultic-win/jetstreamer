//! Read-only, fail-closed validation of a focused qualification artifact.

use {
    jetstreamer_horizon::archive::{ArchiveReader, ExpectedConflictWrite, verify_conflict_slot},
    jetstreamer_node::{
        archive_checksum::archive_checksum_path,
        segment_manifest::{
            SegmentRuntimeAdmission, read_and_validate_segment_manifest, segment_manifest_path,
            sha256_hex_string,
        },
    },
    serde_json::json,
    solana_address::Address,
    solana_signature::Signature,
    std::{
        env, fs,
        fs::{File, OpenOptions},
        io::{BufReader, Write as _},
        os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
        process,
        str::FromStr,
    },
};

#[derive(Debug, Eq, PartialEq)]
struct ConflictExpectation {
    slot: u64,
    account: Address,
    writes: [ExpectedConflictWrite; 2],
}

#[derive(Debug, Eq, PartialEq)]
struct Arguments {
    archive: PathBuf,
    private_root: PathBuf,
    receipt: Option<PathBuf>,
    expected_epoch: u64,
    expected_output_start_slot: u64,
    expected_bootstrap_slot: u64,
    expected_terminal_slot: u64,
    expected_runtime_profile: String,
    expected_worker_sha256: String,
    expected_conflict: Option<ConflictExpectation>,
}

fn usage(program: &str) -> String {
    format!(
        r#"Usage: {program} ARCHIVE \
  --private-root=PATH \
  --expected-epoch=N \
  --expected-output-start-slot=SLOT \
  --expected-bootstrap-slot=SLOT \
  --expected-terminal-slot=SLOT \
  --expected-runtime-profile=NAME \
  --expected-worker-sha256=HEX \
  [--receipt=/PRIVATE/epoch-N.validation.json] \
  [--expected-conflict-slot=SLOT \
   --expected-conflict-account=ADDRESS \
   --expected-conflict-first=INDEX,SIGNATURE,LAMPORTS \
   --expected-conflict-second=INDEX,SIGNATURE,LAMPORTS]"#
    )
}

fn take_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate --{name} option"));
    }
    Ok(())
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|error| format!("invalid --{name} value {value:?}: {error}"))
}

fn validate_sha256(value: &str) -> Result<String, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "--expected-worker-sha256 must be exactly 64 lowercase hexadecimal characters"
                .to_string(),
        );
    }
    Ok(value.to_owned())
}

fn parse_conflict_write(value: &str, name: &str) -> Result<ExpectedConflictWrite, String> {
    let mut fields = value.split(',');
    let transaction_index = fields
        .next()
        .ok_or_else(|| format!("--{name} is missing transaction index"))?
        .parse()
        .map_err(|error| format!("invalid --{name} transaction index: {error}"))?;
    let signature = fields
        .next()
        .ok_or_else(|| format!("--{name} is missing signature"))
        .and_then(|value| {
            Signature::from_str(value)
                .map_err(|error| format!("invalid --{name} signature: {error}"))
        })?;
    let lamports = fields
        .next()
        .ok_or_else(|| format!("--{name} is missing lamports"))?
        .parse()
        .map_err(|error| format!("invalid --{name} lamports: {error}"))?;
    if fields.next().is_some() {
        return Err(format!("--{name} must contain exactly three fields"));
    }
    Ok(ExpectedConflictWrite {
        transaction_index,
        signature,
        lamports,
    })
}

fn parse_arguments<I>(arguments: I) -> Result<Arguments, String>
where
    I: IntoIterator<Item = String>,
{
    let mut archive = None;
    let mut private_root = None;
    let mut expected_epoch = None;
    let mut receipt = None;
    let mut expected_output_start_slot = None;
    let mut expected_bootstrap_slot = None;
    let mut expected_terminal_slot = None;
    let mut expected_runtime_profile = None;
    let mut expected_worker_sha256 = None;
    let mut expected_conflict_slot = None;
    let mut expected_conflict_account = None;
    let mut expected_conflict_first = None;
    let mut expected_conflict_second = None;

    for argument in arguments {
        if let Some(value) = argument.strip_prefix("--private-root=") {
            if value.is_empty() {
                return Err("--private-root must not be empty".to_string());
            }
            take_once(&mut private_root, PathBuf::from(value), "private-root")?;
        } else if let Some(value) = argument.strip_prefix("--receipt=") {
            if value.is_empty() {
                return Err("--receipt must not be empty".into());
            }
            take_once(&mut receipt, PathBuf::from(value), "receipt")?;
        } else if let Some(value) = argument.strip_prefix("--expected-epoch=") {
            let value = parse_u64(value, "expected-epoch")?;
            take_once(&mut expected_epoch, value, "expected-epoch")?;
        } else if let Some(value) = argument.strip_prefix("--expected-output-start-slot=") {
            let value = parse_u64(value, "expected-output-start-slot")?;
            take_once(
                &mut expected_output_start_slot,
                value,
                "expected-output-start-slot",
            )?;
        } else if let Some(value) = argument.strip_prefix("--expected-bootstrap-slot=") {
            let value = parse_u64(value, "expected-bootstrap-slot")?;
            take_once(
                &mut expected_bootstrap_slot,
                value,
                "expected-bootstrap-slot",
            )?;
        } else if let Some(value) = argument.strip_prefix("--expected-terminal-slot=") {
            let value = parse_u64(value, "expected-terminal-slot")?;
            take_once(&mut expected_terminal_slot, value, "expected-terminal-slot")?;
        } else if let Some(value) = argument.strip_prefix("--expected-runtime-profile=") {
            if value.is_empty() {
                return Err("--expected-runtime-profile must not be empty".to_string());
            }
            take_once(
                &mut expected_runtime_profile,
                value.to_owned(),
                "expected-runtime-profile",
            )?;
        } else if let Some(value) = argument.strip_prefix("--expected-worker-sha256=") {
            let value = validate_sha256(value)?;
            take_once(&mut expected_worker_sha256, value, "expected-worker-sha256")?;
        } else if let Some(value) = argument.strip_prefix("--expected-conflict-slot=") {
            let value = parse_u64(value, "expected-conflict-slot")?;
            take_once(&mut expected_conflict_slot, value, "expected-conflict-slot")?;
        } else if let Some(value) = argument.strip_prefix("--expected-conflict-account=") {
            let value = Address::from_str(value)
                .map_err(|error| format!("invalid --expected-conflict-account: {error}"))?;
            take_once(
                &mut expected_conflict_account,
                value,
                "expected-conflict-account",
            )?;
        } else if let Some(value) = argument.strip_prefix("--expected-conflict-first=") {
            let value = parse_conflict_write(value, "expected-conflict-first")?;
            take_once(
                &mut expected_conflict_first,
                value,
                "expected-conflict-first",
            )?;
        } else if let Some(value) = argument.strip_prefix("--expected-conflict-second=") {
            let value = parse_conflict_write(value, "expected-conflict-second")?;
            take_once(
                &mut expected_conflict_second,
                value,
                "expected-conflict-second",
            )?;
        } else if argument.starts_with('-') {
            return Err(format!("unknown option {argument:?}"));
        } else {
            take_once(&mut archive, PathBuf::from(argument), "archive")?;
        }
    }

    let expected_conflict = match (
        expected_conflict_slot,
        expected_conflict_account,
        expected_conflict_first,
        expected_conflict_second,
    ) {
        (None, None, None, None) => None,
        (Some(slot), Some(account), Some(first), Some(second)) => {
            if first.transaction_index >= second.transaction_index {
                return Err(
                    "expected conflict transaction indices must be strictly increasing".to_string(),
                );
            }
            Some(ConflictExpectation {
                slot,
                account,
                writes: [first, second],
            })
        }
        _ => {
            return Err(
                "the four --expected-conflict-* options must be supplied together".to_string(),
            );
        }
    };

    Ok(Arguments {
        archive: archive.ok_or_else(|| "missing ARCHIVE".to_string())?,
        private_root: private_root.ok_or_else(|| "missing --private-root".to_string())?,
        receipt,
        expected_epoch: expected_epoch.ok_or_else(|| "missing --expected-epoch".to_string())?,
        expected_output_start_slot: expected_output_start_slot
            .ok_or_else(|| "missing --expected-output-start-slot".to_string())?,
        expected_bootstrap_slot: expected_bootstrap_slot
            .ok_or_else(|| "missing --expected-bootstrap-slot".to_string())?,
        expected_terminal_slot: expected_terminal_slot
            .ok_or_else(|| "missing --expected-terminal-slot".to_string())?,
        expected_runtime_profile: expected_runtime_profile
            .ok_or_else(|| "missing --expected-runtime-profile".to_string())?,
        expected_worker_sha256: expected_worker_sha256
            .ok_or_else(|| "missing --expected-worker-sha256".to_string())?,
        expected_conflict,
    })
}

fn require_private_regular(path: &Path, label: &str) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.permissions().mode() & 0o6000 != 0
    {
        return Err(format!(
            "{label} must be a singly linked owner-only regular file without set-ID bits: {}",
            path.display()
        ));
    }
    Ok(metadata)
}

fn require_private_root(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect private root {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o6000 != 0
    {
        return Err(format!(
            "private root must be a real directory, non-writable by group/other, and free of set-ID bits: {}",
            path.display()
        ));
    }
    Ok(())
}

fn require_absent(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        )),
        Ok(_) => Err(format!(
            "focused qualification {label} must be absent: {}",
            path.display()
        )),
    }
}

fn root_prefix_203(arguments: &Arguments) -> bool {
    arguments.archive.file_name().and_then(|name| name.to_str()) == Some("epoch-203-prefix.jet")
        && arguments.expected_epoch == 203
        && arguments.expected_output_start_slot == 87_696_000
        && arguments.expected_bootstrap_slot == 87_695_515
        && arguments.expected_terminal_slot == 88_127_580
        && arguments.expected_runtime_profile == "solana-v1.6.16"
        && arguments.expected_worker_sha256
            == "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"
}

fn complete_span_225(arguments: &Arguments) -> bool {
    arguments.private_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        && arguments
            .private_root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("qualification-225-v1625-"))
        && arguments.archive == arguments.private_root.join("output/epoch-225.jet")
        && arguments.expected_epoch == 225
        && arguments.expected_output_start_slot == 97_200_000
        && arguments.expected_bootstrap_slot == 97_199_617
        && arguments.expected_terminal_slot == 98_063_464
        && arguments.expected_runtime_profile == "solana-v1.6.25"
        && (arguments.expected_worker_sha256
            == "7cd48efc8719109a69fafcb3209a821ea9f07113e3fb0bfab49db23a6e77a146"
            || (arguments.expected_worker_sha256
                == "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd"
                && arguments
                    .private_root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("qualification-225-v1625-natural-root-shrink-budget-")
                    })))
}

fn retained_prefix_157(arguments: &Arguments) -> bool {
    arguments.private_root
        == Path::new(
            "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j/output/.epoch-157.jet.runtime-segments",
        )
        && arguments.archive
            == arguments
                .private_root
                .join("epoch-157.segment-00-67824000-68140177.jet")
        && arguments.expected_epoch == 157
        && arguments.expected_output_start_slot == 67_824_000
        && arguments.expected_bootstrap_slot == 67_823_809
        && arguments.expected_terminal_slot == 68_140_176
        && arguments.expected_runtime_profile == "solana-v1.5.6"
        && arguments.expected_worker_sha256
            == "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819"
}

fn validate_archive_name(arguments: &Arguments, archive: &Path) -> Result<(), String> {
    let expected_name = format!(
        "epoch-{}-through-{}.jet",
        arguments.expected_epoch, arguments.expected_terminal_slot
    );
    if archive.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
        && !(archive == arguments.archive
            && (root_prefix_203(arguments)
                || complete_span_225(arguments)
                || retained_prefix_157(arguments)))
    {
        return Err(format!(
            "qualification archive filename must be {expected_name}: {}",
            archive.display()
        ));
    }
    Ok(())
}

fn validate_complete_span_225_roots(
    arguments: &Arguments,
    bootstrap_accounts_hash: &str,
    terminal_accounts_hash: &str,
    revision: &str,
) -> Result<(), String> {
    if complete_span_225(arguments)
        && (bootstrap_accounts_hash != "HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi"
            || terminal_accounts_hash != "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR"
            || revision != "7de8a55b54d3e11058b82f9483bb405d143b455c")
    {
        return Err(
            "epoch225 complete span does not bind its canonical roots and runtime revision".into(),
        );
    }
    Ok(())
}

fn validate_prefix_root_identity(
    arguments: &Arguments,
    accounts_hash: &str,
    revision: &str,
) -> Result<(), String> {
    if root_prefix_203(arguments)
        && (accounts_hash != "4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"
            || revision != "86c26f843276581509c3434acc2efbf4202c44e0")
    {
        return Err(
            "epoch203 prefix does not bind its exact canonical root and runtime revision".into(),
        );
    }
    Ok(())
}

fn verify(arguments: &Arguments) -> Result<serde_json::Value, String> {
    require_private_root(&arguments.private_root)?;
    let private_root = fs::canonicalize(&arguments.private_root).map_err(|error| {
        format!(
            "failed to resolve private root {}: {error}",
            arguments.private_root.display()
        )
    })?;
    let archive = fs::canonicalize(&arguments.archive).map_err(|error| {
        format!(
            "failed to resolve archive {}: {error}",
            arguments.archive.display()
        )
    })?;
    if arguments.private_root != private_root {
        return Err(format!(
            "private root must be supplied as its exact canonical path: {}",
            private_root.display()
        ));
    }
    if arguments.archive != archive {
        return Err(format!(
            "archive must be supplied as its exact canonical path: {}",
            archive.display()
        ));
    }
    if !archive.starts_with(&private_root) || archive == private_root {
        return Err(format!(
            "archive is outside the required private root {}: {}",
            private_root.display(),
            archive.display()
        ));
    }

    validate_archive_name(arguments, &archive)?;

    let manifest_path = segment_manifest_path(&archive)
        .map_err(|error| format!("failed to resolve segment manifest path: {error}"))?;
    let checksum_path = archive_checksum_path(&archive)
        .map_err(|error| format!("failed to resolve checksum path: {error}"))?;
    let archive_before = require_private_regular(&archive, "qualification archive")?;
    let manifest_before = require_private_regular(&manifest_path, "qualification manifest")?;
    require_absent(&checksum_path, "canonical checksum sidecar")?;

    let manifest = read_and_validate_segment_manifest(&archive)
        .map_err(|error| format!("durable segment validation failed: {error}"))?;
    let expected_count = arguments
        .expected_terminal_slot
        .checked_sub(arguments.expected_output_start_slot)
        .and_then(|difference| difference.checked_add(1))
        .ok_or_else(|| "expected output slot range is invalid".to_string())?;
    let worker_sha256 = sha256_hex_string(&manifest.worker_executable_sha256);
    if manifest.epoch != arguments.expected_epoch
        || manifest.output_slot_start != arguments.expected_output_start_slot
        || manifest.output_slot_count != expected_count
        || manifest.bootstrap.slot != arguments.expected_bootstrap_slot
        || manifest.terminal.slot != arguments.expected_terminal_slot
        || manifest.runtime.runtime_profile != arguments.expected_runtime_profile
        || manifest.runtime.runtime_admission != SegmentRuntimeAdmission::Candidate
        || worker_sha256 != arguments.expected_worker_sha256
    {
        return Err(
            "validated segment manifest does not match the exact qualification expectations"
                .to_string(),
        );
    }
    validate_prefix_root_identity(
        arguments,
        &manifest.terminal.accounts_hash,
        &manifest.runtime.runtime_revision,
    )?;
    validate_complete_span_225_roots(
        arguments,
        &manifest.bootstrap.accounts_hash,
        &manifest.terminal.accounts_hash,
        &manifest.runtime.runtime_revision,
    )?;

    let conflict_write_gate = if let Some(expected) = &arguments.expected_conflict {
        let output_end = manifest
            .output_slot_start
            .checked_add(manifest.output_slot_count)
            .ok_or_else(|| "validated manifest output range overflows u64".to_string())?;
        if expected.slot < manifest.output_slot_start || expected.slot >= output_end {
            return Err(format!(
                "expected conflict slot {} is outside validated output range [{}, {})",
                expected.slot, manifest.output_slot_start, output_end
            ));
        }
        let file = File::open(&archive)
            .map_err(|error| format!("failed to open archive for conflict check: {error}"))?;
        let mut reader = ArchiveReader::open(BufReader::new(file))
            .map_err(|error| format!("failed to open archive for conflict check: {error}"))?;
        let observed = verify_conflict_slot(
            &mut reader,
            expected.slot,
            expected.account,
            expected.writes,
        )
        .map_err(|error| format!("canonical conflict-slot check failed: {error}"))?;
        Some(json!({
            "validation": "pass",
            "slot": expected.slot,
            "account": expected.account.to_string(),
            "writes": observed.map(|write| json!({
                "transaction_index": write.transaction_index,
                "signature": write.signature.to_string(),
                "lamports": write.lamports,
                "write_version": write.write_version,
            })),
        }))
    } else {
        None
    };

    let archive_after = require_private_regular(&archive, "qualification archive")?;
    let manifest_after = require_private_regular(&manifest_path, "qualification manifest")?;
    require_absent(&checksum_path, "canonical checksum sidecar")?;
    for (label, before, after) in [
        ("qualification archive", &archive_before, &archive_after),
        ("qualification manifest", &manifest_before, &manifest_after),
    ] {
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(format!("{label} changed during validation"));
        }
    }

    Ok(json!({
        "schema": "jetstreamer-focused-qualification-artifact-validation-v1",
        "validation": "pass",
        "archive": archive,
        "archive_bytes": archive_after.len(),
        "archive_mode": format!("{:04o}", archive_after.permissions().mode() & 0o7777),
        "archive_uid": archive_after.uid(),
        "archive_gid": archive_after.gid(),
        "archive_sha256": sha256_hex_string(&manifest.archive_sha256),
        "manifest": manifest_path,
        "manifest_bytes": manifest_after.len(),
        "manifest_mode": format!("{:04o}", manifest_after.permissions().mode() & 0o7777),
        "manifest_uid": manifest_after.uid(),
        "manifest_gid": manifest_after.gid(),
        "canonical_checksum_sidecar": checksum_path,
        "canonical_checksum_sidecar_absent": true,
        "epoch": manifest.epoch,
        "output_slot_start": manifest.output_slot_start,
        "output_slot_count": manifest.output_slot_count,
        "bootstrap_slot": manifest.bootstrap.slot,
        "terminal_slot": manifest.terminal.slot,
        "runtime_profile": manifest.runtime.runtime_profile,
        "runtime_revision": manifest.runtime.runtime_revision,
        "runtime_admission": "candidate",
        "worker_executable_sha256": worker_sha256,
        "conflict_write_gate": conflict_write_gate,
    }))
}

fn prepare_receipt_destination(path: &Path) -> Result<File, String> {
    let parent = path.parent().ok_or("receipt needs a parent")?;
    if !path.is_absolute()
        || !path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.ends_with(".validation.json"))
        || fs::canonicalize(parent).map_err(|e| e.to_string())? != parent
    {
        return Err(
            "receipt requires an absolute canonical private parent and .validation.json filename"
                .into(),
        );
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(parent)
        .map_err(|e| e.to_string())?;
    let meta = directory.metadata().map_err(|e| e.to_string())?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o6077 != 0 {
        return Err(
            "receipt parent must be owned by this reader, owner-only and without set-ID bits"
                .into(),
        );
    }
    require_absent(path, "validation receipt")?;
    Ok(directory)
}

fn verify_and_record(arguments: &Arguments) -> Result<serde_json::Value, String> {
    // Reject an unsafe/occupied destination before spending an archive reread.
    let directory = arguments
        .receipt
        .as_deref()
        .map(prepare_receipt_destination)
        .transpose()?;
    let receipt = verify(arguments)?;
    if let (Some(path), Some(directory)) = (&arguments.receipt, directory) {
        let current = prepare_receipt_destination(path)?;
        let before = directory.metadata().map_err(|e| e.to_string())?;
        let after = current.metadata().map_err(|e| e.to_string())?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err("receipt parent changed during independent validation".into());
        }
        let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| e.to_string())?;
        output
            .write_all(&bytes)
            .and_then(|_| output.sync_all())
            .map_err(|e| e.to_string())?;
        let named = fs::symlink_metadata(path.parent().ok_or("receipt parent missing")?)
            .map_err(|e| e.to_string())?;
        if !named.is_dir()
            || named.dev() != before.dev()
            || named.ino() != before.ino()
            || named.uid() != before.uid()
            || named.mode() & 0o6077 != 0
        {
            return Err("receipt parent changed during durable publication".into());
        }
        let written = output.metadata().map_err(|e| e.to_string())?;
        let named = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !named.is_file()
            || named.dev() != written.dev()
            || named.ino() != written.ino()
            || named.nlink() != 1
            || named.len() != bytes.len() as u64
            || named.uid() != unsafe { libc::geteuid() }
            || named.mode() & 0o7777 != 0o400
        {
            return Err(
                "validation receipt identity or permissions changed during publication".into(),
            );
        }
        directory.sync_all().map_err(|e| e.to_string())?;
    }
    Ok(receipt)
}

fn main() {
    let mut arguments = env::args();
    let program = arguments
        .next()
        .unwrap_or_else(|| "jetstreamer-qualification-verify".to_string());
    let remaining: Vec<_> = arguments.collect();
    if remaining.iter().any(|argument| argument == "--help") {
        println!("{}", usage(&program));
        return;
    }
    let arguments = parse_arguments(remaining).unwrap_or_else(|error| {
        eprintln!("error: {error}\n{}", usage(&program));
        process::exit(2);
    });
    match verify_and_record(&arguments) {
        Ok(receipt) => println!(
            "{}",
            serde_json::to_string_pretty(&receipt).expect("validation receipt is serializable")
        ),
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        jetstreamer_horizon::archive::{
            ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveWriter, ArchiveWriterConfig,
            BootstrapStateKind, RuntimeAdmission, TransactionMetadataPolicy,
        },
        jetstreamer_node::segment_manifest::{
            HistoricalSegmentManifest, SEGMENT_MANIFEST_SCHEMA_VERSION, SegmentCheckpointSummary,
            SegmentRuntimeIdentity, write_segment_manifest,
        },
        solana_hash::Hash,
        tempfile::TempDir,
    };

    const TEST_EPOCH: u64 = 1;
    const TEST_OUTPUT_START: u64 = 432_000;
    const TEST_BOOTSTRAP: u64 = 431_999;
    const TEST_TERMINAL: u64 = 432_001;
    const TEST_WORKER_DIGEST: [u8; 32] = [0x42; 32];

    fn valid_arguments() -> Vec<String> {
        vec![
            "/private/epoch-202-through-87695515.jet".to_string(),
            "--private-root=/private".to_string(),
            "--expected-epoch=202".to_string(),
            "--expected-output-start-slot=87264000".to_string(),
            "--expected-bootstrap-slot=87263434".to_string(),
            "--expected-terminal-slot=87695515".to_string(),
            "--expected-runtime-profile=solana-v1.6.16".to_string(),
            format!("--expected-worker-sha256={}", "a".repeat(64)),
        ]
    }

    #[test]
    fn exact_arguments_are_required() {
        let parsed = parse_arguments(valid_arguments()).unwrap();
        assert_eq!(parsed.expected_epoch, 202);
        assert_eq!(parsed.expected_terminal_slot, 87_695_515);

        let mut missing = valid_arguments();
        missing.retain(|argument| !argument.starts_with("--expected-bootstrap-slot="));
        assert!(
            parse_arguments(missing)
                .unwrap_err()
                .contains("missing --expected-bootstrap-slot")
        );

        let mut duplicate = valid_arguments();
        duplicate.push("--expected-epoch=203".to_string());
        assert!(
            parse_arguments(duplicate)
                .unwrap_err()
                .contains("duplicate --expected-epoch")
        );
    }

    #[test]
    fn worker_digest_must_be_canonical_lowercase_sha256() {
        assert!(validate_sha256(&"a".repeat(64)).is_ok());
        assert!(validate_sha256(&"A".repeat(64)).is_err());
        assert!(validate_sha256(&"a".repeat(63)).is_err());
        assert!(validate_sha256(&format!("{}g", "a".repeat(63))).is_err());
    }

    #[test]
    fn optional_receipt_is_explicit_private_and_no_clobber() {
        let mut raw = valid_arguments();
        raw.push("--receipt=/private/epoch-202.validation.json".into());
        assert_eq!(
            parse_arguments(raw.clone()).unwrap().receipt,
            Some(PathBuf::from("/private/epoch-202.validation.json"))
        );
        raw.push("--receipt=/private/other.validation.json".into());
        assert!(
            parse_arguments(raw)
                .unwrap_err()
                .contains("duplicate --receipt")
        );
        let root = TempDir::new().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let destination = root.path().join("epoch-1.validation.json");
        prepare_receipt_destination(&destination).unwrap();
        assert!(prepare_receipt_destination(&root.path().join("epoch-1.jet.sha256")).is_err());
        assert!(prepare_receipt_destination(Path::new("relative.validation.json")).is_err());
        fs::write(&destination, b"preserve existing receipt").unwrap();
        assert!(prepare_receipt_destination(&destination).is_err());
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"preserve existing receipt"
        );
        let target = root.path().join("target");
        fs::write(&target, b"preserve symlink target").unwrap();
        let link = root.path().join("linked.validation.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(prepare_receipt_destination(&link).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserve symlink target");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare_receipt_destination(&root.path().join("new.validation.json")).is_err());
    }

    #[test]
    fn root_prefix_filename_is_only_the_exact_private_203_checkpoint_scope() {
        let mut raw = valid_arguments();
        raw[0] = "/private/epoch-203-prefix.jet".into();
        for (key, value) in [
            ("epoch", "203"),
            ("output-start-slot", "87696000"),
            ("bootstrap-slot", "87695515"),
            ("terminal-slot", "88127580"),
            (
                "worker-sha256",
                "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a",
            ),
        ] {
            *raw.iter_mut()
                .find(|s| s.starts_with(&format!("--expected-{key}=")))
                .unwrap() = format!("--expected-{key}={value}");
        }
        let args = parse_arguments(raw.clone()).unwrap();
        assert!(root_prefix_203(&args));
        validate_archive_name(&args, &args.archive).unwrap();
        assert!(validate_archive_name(&args, Path::new("/private/epoch-204-prefix.jet")).is_err());
        let hash = "4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf";
        let revision = "86c26f843276581509c3434acc2efbf4202c44e0";
        validate_prefix_root_identity(&args, hash, revision).unwrap();
        assert!(validate_prefix_root_identity(&args, "wrong-root", revision).is_err());
        assert!(validate_prefix_root_identity(&args, hash, "wrong-revision").is_err());
        for (key, value) in [
            ("epoch", "204"),
            ("output-start-slot", "87695516"),
            ("bootstrap-slot", "87695514"),
            ("terminal-slot", "88127999"),
            ("runtime-profile", "solana-v1.6.25"),
            ("worker-sha256", &"a".repeat(64)),
        ] {
            let mut changed = raw.clone();
            *changed
                .iter_mut()
                .find(|s| s.starts_with(&format!("--expected-{key}=")))
                .unwrap() = format!("--expected-{key}={value}");
            let args = parse_arguments(changed).unwrap();
            assert!(!root_prefix_203(&args), "{key}");
            assert!(
                validate_archive_name(&args, &args.archive).is_err(),
                "{key}"
            );
        }
        let mut changed = raw;
        changed[0] = "/private/epoch-204-prefix.jet".into();
        let args = parse_arguments(changed).unwrap();
        assert!(validate_archive_name(&args, &args.archive).is_err());
    }

    fn complete_span_225_arguments() -> Vec<String> {
        let root = "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-test";
        vec![
            format!("{root}/output/epoch-225.jet"),
            format!("--private-root={root}"),
            "--expected-epoch=225".into(),
            "--expected-output-start-slot=97200000".into(),
            "--expected-bootstrap-slot=97199617".into(),
            "--expected-terminal-slot=98063464".into(),
            "--expected-runtime-profile=solana-v1.6.25".into(),
            "--expected-worker-sha256=7cd48efc8719109a69fafcb3209a821ea9f07113e3fb0bfab49db23a6e77a146".into(),
        ]
    }

    #[test]
    fn complete_span_225_filename_is_exact_private_scope_not_a_canonical_epoch() {
        let raw = complete_span_225_arguments();
        let args = parse_arguments(raw.clone()).unwrap();
        assert!(complete_span_225(&args));
        validate_archive_name(&args, &args.archive).unwrap();
        assert_eq!(
            args.expected_terminal_slot - args.expected_output_start_slot + 1,
            863_465
        );
        for (key, value) in [
            ("epoch", "224"),
            ("output-start-slot", "97200001"),
            ("bootstrap-slot", "97199618"),
            ("terminal-slot", "97631459"),
            ("runtime-profile", "solana-v1.6.20"),
            ("worker-sha256", &"a".repeat(64)),
        ] {
            let mut changed = raw.clone();
            *changed
                .iter_mut()
                .find(|s| s.starts_with(&format!("--expected-{key}=")))
                .unwrap() = format!("--expected-{key}={value}");
            let args = parse_arguments(changed).unwrap();
            assert!(!complete_span_225(&args), "{key}");
            assert!(
                validate_archive_name(&args, &args.archive).is_err(),
                "{key}"
            );
        }
        for root in [
            "/home/ubuntu/horizon",
            "/home/ubuntu/.jetstreamer-private/unrelated",
        ] {
            let mut args = parse_arguments(raw.clone()).unwrap();
            args.private_root = root.into();
            args.archive = args.private_root.join("output/epoch-225.jet");
            assert!(!complete_span_225(&args));
            assert!(validate_archive_name(&args, &args.archive).is_err());
        }
        assert!(validate_archive_name(&args, Path::new("/private/epoch-225.jet")).is_err());
    }

    #[test]
    fn capped_shrink_complete_span_225_stays_private_and_exact() {
        let root = "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-test";
        let mut args = parse_arguments(complete_span_225_arguments()).unwrap();
        args.private_root = root.into();
        args.archive = args.private_root.join("output/epoch-225.jet");
        args.expected_worker_sha256 =
            "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd".into();
        assert!(complete_span_225(&args));
        validate_archive_name(&args, &args.archive).unwrap();
        validate_complete_span_225_roots(
            &args,
            "HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi",
            "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR",
            "7de8a55b54d3e11058b82f9483bb405d143b455c",
        )
        .unwrap();
        args.expected_terminal_slot = 97_631_459;
        assert!(!complete_span_225(&args));
        assert!(validate_archive_name(&args, &args.archive).is_err());
        args.expected_terminal_slot = 98_063_464;
        args.expected_worker_sha256 = "a".repeat(64);
        assert!(!complete_span_225(&args));
        args.expected_worker_sha256 =
            "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd".into();
        args.private_root =
            "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-test".into();
        args.archive = args.private_root.join("output/epoch-225.jet");
        assert!(!complete_span_225(&args));
        assert!(validate_archive_name(&args, &args.archive).is_err());
    }

    #[test]
    fn complete_span_225_named_artifact_binds_both_roots_and_upstream_revision() {
        let args = parse_arguments(complete_span_225_arguments()).unwrap();
        let bootstrap = "HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi";
        let terminal = "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR";
        let revision = "7de8a55b54d3e11058b82f9483bb405d143b455c";
        validate_complete_span_225_roots(&args, bootstrap, terminal, revision).unwrap();
        for (bootstrap, terminal, revision) in [
            ("wrong-bootstrap", terminal, revision),
            (bootstrap, "wrong-terminal", revision),
            (bootstrap, terminal, "wrong-revision"),
        ] {
            assert!(
                validate_complete_span_225_roots(&args, bootstrap, terminal, revision).is_err()
            );
        }
    }

    #[test]
    fn retained157_segment_keeps_exact_path_runtime_and_slot_bindings() {
        let private_root = PathBuf::from(
            "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j/output/.epoch-157.jet.runtime-segments",
        );
        let args = Arguments {
            archive: private_root.join("epoch-157.segment-00-67824000-68140177.jet"),
            private_root,
            receipt: None,
            expected_epoch: 157,
            expected_output_start_slot: 67824000,
            expected_bootstrap_slot: 67823809,
            expected_terminal_slot: 68140176,
            expected_runtime_profile: "solana-v1.5.6".into(),
            expected_worker_sha256:
                "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819".into(),
            expected_conflict: None,
        };
        assert!(retained_prefix_157(&args));
        validate_archive_name(&args, &args.archive).unwrap();
        let mut bad = args;
        bad.expected_terminal_slot = 68255999;
        assert!(!retained_prefix_157(&bad));
        assert!(validate_archive_name(&bad, &bad.archive).is_err());
        bad.expected_terminal_slot = 68140176;
        bad.expected_output_start_slot = 67823810;
        assert!(validate_archive_name(&bad, &bad.archive).is_err());
        bad.expected_output_start_slot = 67824000;
        bad.expected_worker_sha256 = "f".repeat(64);
        assert!(validate_archive_name(&bad, &bad.archive).is_err());
    }

    #[test]
    fn conflict_expectations_are_all_or_none_and_ordered() {
        let account = Address::new_from_array([3; 32]);
        let first_signature = Signature::from([1; 64]);
        let second_signature = Signature::from([2; 64]);
        let mut arguments = valid_arguments();
        arguments.extend([
            format!("--expected-conflict-slot={TEST_OUTPUT_START}"),
            format!("--expected-conflict-account={account}"),
            format!("--expected-conflict-first=7,{first_signature},11"),
            format!("--expected-conflict-second=8,{second_signature},10"),
        ]);
        let parsed = parse_arguments(arguments.clone()).unwrap();
        let conflict = parsed.expected_conflict.unwrap();
        assert_eq!(conflict.slot, TEST_OUTPUT_START);
        assert_eq!(conflict.account, account);
        assert_eq!(conflict.writes[0].transaction_index, 7);
        assert_eq!(conflict.writes[1].transaction_index, 8);

        arguments.retain(|argument| !argument.starts_with("--expected-conflict-account="));
        assert!(
            parse_arguments(arguments)
                .unwrap_err()
                .contains("must be supplied together")
        );

        let mut reversed = valid_arguments();
        reversed.extend([
            format!("--expected-conflict-slot={TEST_OUTPUT_START}"),
            format!("--expected-conflict-account={account}"),
            format!("--expected-conflict-first=8,{first_signature},11"),
            format!("--expected-conflict-second=7,{second_signature},10"),
        ]);
        assert!(
            parse_arguments(reversed)
                .unwrap_err()
                .contains("strictly increasing")
        );
    }

    fn hash(byte: u8) -> Hash {
        Hash::new_from_array([byte; 32])
    }

    fn runtime_identity() -> SegmentRuntimeIdentity {
        SegmentRuntimeIdentity {
            generation_profile: "jetstreamer-node/historical-replay-v1".to_string(),
            runtime_profile: "solana-v1.6.16".to_string(),
            runtime_admission: SegmentRuntimeAdmission::Candidate,
            runtime_revision: "86c26f843276581509c3434acc2efbf4202c44e0".to_string(),
            runtime_toolchain: "rustc 1.51.0 (2fd73fabe 2021-03-23)".to_string(),
            runtime_target: "x86_64-unknown-linux-gnu".to_string(),
            genesis_hash: hash(5).to_string(),
        }
    }

    fn write_qualification_fixture(directory: &TempDir) -> PathBuf {
        let runtime = runtime_identity();
        let provenance = ArchiveProvenanceV2 {
            base: ArchiveProvenanceV1 {
                generation_profile: runtime.generation_profile.clone(),
                runtime_profile: runtime.runtime_profile.clone(),
                runtime_admission: RuntimeAdmission::Candidate,
                runtime_revision: runtime.runtime_revision.clone(),
                runtime_toolchain: runtime.runtime_toolchain.clone(),
                genesis_hash: hash(5),
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_slot: TEST_BOOTSTRAP,
                bootstrap_state_hash: hash(9),
                requested_slot_start: TEST_OUTPUT_START,
                requested_slot_count: TEST_TERMINAL - TEST_OUTPUT_START + 1,
                transaction_metadata: TransactionMetadataPolicy::observed(),
            },
            worker_executable_sha256: TEST_WORKER_DIGEST,
        };
        let mut writer = ArchiveWriter::new_with_provenance(
            Vec::new(),
            TEST_EPOCH,
            TEST_OUTPUT_START,
            TEST_TERMINAL - TEST_OUTPUT_START + 1,
            ArchiveWriterConfig::default(),
            &provenance.into(),
        )
        .unwrap();
        for slot in TEST_OUTPUT_START..=TEST_TERMINAL {
            writer.write_skipped_slot(slot).unwrap();
        }
        let (bytes, _) = writer.finish().unwrap();
        let archive = directory
            .path()
            .join(format!("epoch-{TEST_EPOCH}-through-{TEST_TERMINAL}.jet"));
        fs::write(&archive, bytes).unwrap();
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o600)).unwrap();

        let checkpoint = |slot, byte| SegmentCheckpointSummary {
            slot,
            bank_hash: hash(byte).to_string(),
            accounts_hash: hash(byte + 1).to_string(),
            last_blockhash: hash(byte + 2).to_string(),
            capitalization: 1_000,
            transaction_count: 50,
            tick_height: 12_000,
            slot_complete: true,
            write_count: 0,
            next_write_version: 100,
        };
        let manifest = HistoricalSegmentManifest {
            schema_version: SEGMENT_MANIFEST_SCHEMA_VERSION,
            epoch: TEST_EPOCH,
            output_slot_start: TEST_OUTPUT_START,
            output_slot_count: TEST_TERMINAL - TEST_OUTPUT_START + 1,
            runtime,
            worker_executable_sha256: TEST_WORKER_DIGEST,
            archive_sha256: [0; 32],
            bootstrap_archive_sha256: None,
            bootstrap: checkpoint(TEST_BOOTSTRAP, 8),
            terminal: checkpoint(TEST_TERMINAL, 11),
            emitted_raw_write_versions: 100..100,
        };
        let (manifest_path, _) = write_segment_manifest(&archive, manifest).unwrap();
        fs::set_permissions(manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
        archive
    }

    #[test]
    fn artifact_validation_is_deep_private_and_sidecar_free() {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let archive = write_qualification_fixture(&directory);
        let mut arguments = Arguments {
            archive: archive.clone(),
            private_root: directory.path().to_path_buf(),
            receipt: None,
            expected_epoch: TEST_EPOCH,
            expected_output_start_slot: TEST_OUTPUT_START,
            expected_bootstrap_slot: TEST_BOOTSTRAP,
            expected_terminal_slot: TEST_TERMINAL,
            expected_runtime_profile: "solana-v1.6.16".to_string(),
            expected_worker_sha256: sha256_hex_string(&TEST_WORKER_DIGEST),
            expected_conflict: None,
        };
        let receipt = verify(&arguments).unwrap();
        assert_eq!(receipt["validation"], "pass");
        assert_eq!(receipt["canonical_checksum_sidecar_absent"], true);
        assert!(receipt["conflict_write_gate"].is_null());
        let archive_bytes = fs::read(&archive).unwrap();
        let destination = directory.path().join("epoch-1.validation.json");
        arguments.receipt = Some(destination.clone());
        let stored = verify_and_record(&arguments).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&destination).unwrap()).unwrap(),
            stored
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert!(verify_and_record(&arguments).is_err());
        assert_eq!(fs::read(&archive).unwrap(), archive_bytes);

        arguments.expected_conflict = Some(ConflictExpectation {
            slot: TEST_OUTPUT_START,
            account: Address::new_from_array([3; 32]),
            writes: [
                ExpectedConflictWrite {
                    transaction_index: 7,
                    signature: Signature::from([1; 64]),
                    lamports: 11,
                },
                ExpectedConflictWrite {
                    transaction_index: 8,
                    signature: Signature::from([2; 64]),
                    lamports: 10,
                },
            ],
        });
        assert!(verify(&arguments).unwrap_err().contains("expected a block"));
        arguments.expected_conflict = None;

        let checksum = archive_checksum_path(&archive).unwrap();
        fs::write(&checksum, b"publication marker must be rejected\n").unwrap();
        fs::set_permissions(checksum, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            verify(&arguments)
                .unwrap_err()
                .contains("canonical checksum sidecar must be absent")
        );
        let absent = directory.path().join("failed.validation.json");
        arguments.receipt = Some(absent.clone());
        assert!(verify_and_record(&arguments).is_err());
        assert!(!absent.exists());
    }
}
