//! Progressively deliver verified Horizon archives through `jetstreamer-r2`.
//!
//! This coordinator owns only local gate selection and polling. The invoked
//! Rust uploader remains the sole owner of archive hashing, R2 integrity,
//! durable delivery receipts, and optional local retirement.

use {
    anyhow::{Context, Result, anyhow, bail, ensure},
    serde_json::Value,
    std::{
        collections::BTreeSet,
        env,
        fs::{self, File, OpenOptions},
        io::Read,
        os::{
            fd::AsRawFd as _,
            unix::{
                fs::{MetadataExt as _, OpenOptionsExt as _},
                process::ExitStatusExt as _,
            },
        },
        path::{Path, PathBuf},
        process::{Command, ExitStatus},
        thread,
        time::Duration,
    },
};

const DEFAULT_POLL_SECONDS: u64 = 300;
const DEFAULT_CONCURRENCY: u64 = 4;
const DEFAULT_LEGACY_PART_SIZE_MIB: u64 = 5;
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_SIDECAR_BYTES: u64 = 512;

#[derive(Clone, Debug)]
struct Gate {
    directory: PathBuf,
    verifier_sha256: BTreeSet<String>,
    script_sha256: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct Config {
    uploader: PathBuf,
    horizon_directory: PathBuf,
    receipt_directory: PathBuf,
    public_receipt_directory: Option<PathBuf>,
    first_epoch: u64,
    last_epoch: u64,
    poll_seconds: u64,
    concurrency: u64,
    legacy_part_size_mib: u64,
    delete_local: bool,
    local_mutation_lock: Option<PathBuf>,
    full: Gate,
    plugin: Gate,
    boundary: Gate,
    defer_epochs: Vec<(u64, u64)>,
}

#[derive(Debug)]
struct LocalPair {
    digest: String,
    archive_length: u64,
    archive_modified_nanoseconds: i128,
}

#[derive(Clone, Debug)]
struct R2ReceiptEvidence {
    bucket: String,
    digest: String,
    archive_length: u64,
    archive_etag: String,
}

#[derive(Debug)]
struct MutationLock(File);

impl MutationLock {
    fn acquire(path: Option<&Path>) -> Result<Option<Self>> {
        let Some(path) = path else {
            return Ok(None);
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("failed to open local-mutation lock {}", path.display()))?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "local-mutation lock is not regular");
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "local-mutation lock has wrong owner"
        );
        ensure!(
            metadata.nlink() == 1,
            "local-mutation lock has multiple links"
        );
        ensure!(
            metadata.mode() & 0o077 == 0,
            "local-mutation lock is not private"
        );
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        ensure!(
            result == 0,
            "failed to acquire local-mutation lock: {}",
            std::io::Error::last_os_error()
        );
        let current = fs::symlink_metadata(path)?;
        ensure!(
            current.dev() == metadata.dev() && current.ino() == metadata.ino(),
            "local-mutation lock namespace changed"
        );
        Ok(Some(Self(file)))
    }
}

impl Drop for MutationLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn usage() -> ! {
    eprintln!(concat!(
        "usage: jetstreamer-r2-progressive UPLOADER HORIZON_DIRECTORY RECEIPT_DIRECTORY ",
        "FIRST_EPOCH LAST_EPOCH [--poll-seconds N] [--concurrency N] ",
        "[--legacy-part-size-mib N] [--delete-local] [--local-mutation-lock PATH] ",
        "[--public-receipt-directory DIR] ",
        "--full-receipt-directory DIR --full-verifier-sha256 HASH[,HASH...] ",
        "--full-verifier-script-sha256 HASH[,HASH...] --plugin-receipt-directory DIR ",
        "--plugin-pipeline-sha256 HASH[,HASH...] ",
        "--plugin-verifier-script-sha256 HASH[,HASH...] ",
        "--boundary-receipt-directory DIR --boundary-verifier-sha256 HASH[,HASH...] ",
        "--boundary-verifier-script-sha256 HASH[,HASH...] [--defer-epochs START-END]..."
    ));
    std::process::exit(2);
}

fn next_utf8(args: &mut impl Iterator<Item = std::ffi::OsString>, option: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow!("missing value for {option}"))?
        .into_string()
        .map_err(|_| anyhow!("value for {option} is not UTF-8"))
}

fn option_value(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    option: &str,
    inline_value: Option<&str>,
) -> Result<String> {
    match inline_value {
        Some(value) => {
            ensure!(!value.is_empty(), "missing value for {option}");
            Ok(value.to_owned())
        }
        None => next_utf8(args, option),
    }
}

fn parse_positive(value: &str, option: &str) -> Result<u64> {
    let parsed = value.parse().with_context(|| format!("invalid {option}"))?;
    ensure!(parsed > 0, "{option} must be positive");
    Ok(parsed)
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_allowlist(value: &str, option: &str) -> Result<BTreeSet<String>> {
    let values: Vec<_> = value.split(',').collect();
    ensure!(
        !values.is_empty() && values.iter().all(|value| is_lower_hex_digest(value)),
        "{option} requires a comma-separated lowercase SHA-256 allowlist"
    );
    let unique: BTreeSet<_> = values.iter().map(|value| (*value).to_owned()).collect();
    ensure!(
        unique.len() == values.len(),
        "duplicate {option} allowlist entry"
    );
    Ok(unique)
}

fn parse_epoch_range(value: &str) -> Result<(u64, u64)> {
    let (first, last) = value
        .split_once('-')
        .ok_or_else(|| anyhow!("invalid epoch range"))?;
    let first: u64 = first.parse().context("invalid epoch range")?;
    let last: u64 = last.parse().context("invalid epoch range")?;
    ensure!(last >= first, "invalid epoch range");
    Ok((first, last))
}

fn take_required<T>(value: Option<T>, name: &str) -> Result<T> {
    value.ok_or_else(|| anyhow!("{name} is required"))
}

fn absolute_existing_directory(path: PathBuf, name: &str) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "{name} must be absolute");
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("failed to inspect {name} {}", path.display()))?;
    ensure!(metadata.is_dir(), "{name} is not a directory");
    Ok(path)
}

fn absolute_existing_file(path: PathBuf, name: &str) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "{name} must be absolute");
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("failed to inspect {name} {}", path.display()))?;
    ensure!(metadata.is_file(), "{name} is not a regular file");
    Ok(path)
}

fn parse_args() -> Result<Config> {
    let mut args = env::args_os().skip(1);
    let uploader = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    let horizon_directory = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    let receipt_directory = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    let first_epoch = args
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| usage())
        .parse()
        .context("invalid first epoch")?;
    let last_epoch = args
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| usage())
        .parse()
        .context("invalid last epoch")?;
    ensure!(last_epoch >= first_epoch, "invalid inclusive epoch range");

    let mut poll_seconds = DEFAULT_POLL_SECONDS;
    let mut concurrency = DEFAULT_CONCURRENCY;
    let mut legacy_part_size_mib = DEFAULT_LEGACY_PART_SIZE_MIB;
    let mut delete_local = false;
    let mut local_mutation_lock = None;
    let mut public_receipt_directory = None;
    let mut full_directory = None;
    let mut full_verifier = None;
    let mut full_script = None;
    let mut plugin_directory = None;
    let mut plugin_verifier = None;
    let mut plugin_script = None;
    let mut boundary_directory = None;
    let mut boundary_verifier = None;
    let mut boundary_script = None;
    let mut defer_epochs = Vec::new();
    while let Some(argument) = args.next() {
        let argument = argument
            .into_string()
            .map_err(|_| anyhow!("argument is not UTF-8"))?;
        let (option, inline_value) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(option, value)| {
                (option, Some(value))
            });
        match option {
            "--poll-seconds" => {
                poll_seconds =
                    parse_positive(&option_value(&mut args, option, inline_value)?, option)?
            }
            "--concurrency" => {
                concurrency =
                    parse_positive(&option_value(&mut args, option, inline_value)?, option)?
            }
            "--legacy-part-size-mib" => {
                legacy_part_size_mib =
                    parse_positive(&option_value(&mut args, option, inline_value)?, option)?
            }
            "--delete-local" => {
                ensure!(
                    inline_value.is_none(),
                    "--delete-local does not take a value"
                );
                delete_local = true;
            }
            "--local-mutation-lock" => {
                local_mutation_lock = Some(PathBuf::from(option_value(
                    &mut args,
                    option,
                    inline_value,
                )?))
            }
            "--public-receipt-directory" => {
                public_receipt_directory = Some(PathBuf::from(option_value(
                    &mut args,
                    option,
                    inline_value,
                )?))
            }
            "--full-receipt-directory" => {
                full_directory = Some(PathBuf::from(option_value(
                    &mut args,
                    option,
                    inline_value,
                )?))
            }
            "--full-verifier-sha256" => {
                full_verifier = Some(parse_allowlist(
                    &option_value(&mut args, option, inline_value)?,
                    option,
                )?)
            }
            "--full-verifier-script-sha256" => {
                full_script = Some(parse_allowlist(
                    &option_value(&mut args, option, inline_value)?,
                    option,
                )?)
            }
            "--plugin-receipt-directory" => {
                plugin_directory = Some(PathBuf::from(option_value(
                    &mut args,
                    option,
                    inline_value,
                )?))
            }
            "--plugin-pipeline-sha256" => {
                plugin_verifier = Some(parse_allowlist(
                    &option_value(&mut args, option, inline_value)?,
                    option,
                )?)
            }
            "--plugin-verifier-script-sha256" => {
                plugin_script = Some(parse_allowlist(
                    &option_value(&mut args, option, inline_value)?,
                    option,
                )?)
            }
            "--boundary-receipt-directory" => {
                boundary_directory = Some(PathBuf::from(option_value(
                    &mut args,
                    option,
                    inline_value,
                )?))
            }
            "--boundary-verifier-sha256" => {
                boundary_verifier = Some(parse_allowlist(
                    &option_value(&mut args, option, inline_value)?,
                    option,
                )?)
            }
            "--boundary-verifier-script-sha256" => {
                boundary_script = Some(parse_allowlist(
                    &option_value(&mut args, option, inline_value)?,
                    option,
                )?)
            }
            "--defer-epochs" => defer_epochs.push(parse_epoch_range(&option_value(
                &mut args,
                option,
                inline_value,
            )?)?),
            _ => bail!("unknown argument: {argument}"),
        }
    }

    let uploader = absolute_existing_file(uploader, "uploader")?;
    let horizon_directory = absolute_existing_directory(horizon_directory, "Horizon directory")?;
    let receipt_directory = absolute_existing_directory(receipt_directory, "receipt directory")?;
    let public_receipt_directory = public_receipt_directory
        .map(|directory| absolute_existing_directory(directory, "public receipt directory"))
        .transpose()?;
    let full = Gate {
        directory: absolute_existing_directory(
            take_required(full_directory, "--full-receipt-directory")?,
            "full receipt directory",
        )?,
        verifier_sha256: take_required(full_verifier, "--full-verifier-sha256")?,
        script_sha256: take_required(full_script, "--full-verifier-script-sha256")?,
    };
    let plugin = Gate {
        directory: absolute_existing_directory(
            take_required(plugin_directory, "--plugin-receipt-directory")?,
            "plugin receipt directory",
        )?,
        verifier_sha256: take_required(plugin_verifier, "--plugin-pipeline-sha256")?,
        script_sha256: take_required(plugin_script, "--plugin-verifier-script-sha256")?,
    };
    let boundary = Gate {
        directory: absolute_existing_directory(
            take_required(boundary_directory, "--boundary-receipt-directory")?,
            "boundary receipt directory",
        )?,
        verifier_sha256: take_required(boundary_verifier, "--boundary-verifier-sha256")?,
        script_sha256: take_required(boundary_script, "--boundary-verifier-script-sha256")?,
    };
    if let Some(lock) = &local_mutation_lock {
        ensure!(lock.is_absolute(), "--local-mutation-lock must be absolute");
        ensure!(
            lock.parent() == Some(receipt_directory.as_path()),
            "--local-mutation-lock must be directly inside the receipt directory"
        );
    }
    Ok(Config {
        uploader,
        horizon_directory,
        receipt_directory,
        public_receipt_directory,
        first_epoch,
        last_epoch,
        poll_seconds,
        concurrency,
        legacy_part_size_mib,
        delete_local,
        local_mutation_lock,
        full,
        plugin,
        boundary,
        defer_epochs,
    })
}

fn read_regular(path: &Path, maximum_bytes: u64) -> Result<Option<Vec<u8>>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to open {}", path.display()));
        }
    };
    let before = file.metadata()?;
    ensure!(
        before.is_file(),
        "expected a regular file: {}",
        path.display()
    );
    ensure!(
        before.len() <= maximum_bytes,
        "file is too large: {}",
        path.display()
    );
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "file changed while reading: {}",
        path.display()
    );
    let current = fs::symlink_metadata(path)
        .with_context(|| format!("failed to re-observe {}", path.display()))?;
    ensure!(
        current.is_file()
            && current.dev() == after.dev()
            && current.ino() == after.ino()
            && current.len() == after.len()
            && current.mtime() == after.mtime()
            && current.mtime_nsec() == after.mtime_nsec(),
        "file namespace changed while reading: {}",
        path.display()
    );
    Ok(Some(bytes))
}

fn archive_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file(),
                "expected a regular file: {}",
                path.display()
            );
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn local_pair(directory: &Path, epoch: u64) -> Result<Option<LocalPair>> {
    let archive = directory.join(format!("epoch-{epoch}.jet"));
    let sidecar = directory.join(format!("epoch-{epoch}.jet.sha256"));
    let archive_metadata = archive_metadata(&archive)?;
    let sidecar_bytes = read_regular(&sidecar, MAX_SIDECAR_BYTES)?;
    let (Some(archive_metadata), Some(sidecar_bytes)) = (archive_metadata, sidecar_bytes) else {
        return Ok(None);
    };
    let archive_after = fs::symlink_metadata(&archive)?;
    ensure!(
        archive_after.is_file()
            && archive_after.dev() == archive_metadata.dev()
            && archive_after.ino() == archive_metadata.ino()
            && archive_after.len() == archive_metadata.len()
            && archive_after.mtime() == archive_metadata.mtime()
            && archive_after.mtime_nsec() == archive_metadata.mtime_nsec(),
        "archive changed while discovering pair: {}",
        archive.display()
    );
    let sidecar = std::str::from_utf8(&sidecar_bytes).context("checksum sidecar is not UTF-8")?;
    let suffix = format!("  epoch-{epoch}.jet\n");
    let digest = sidecar
        .strip_suffix(&suffix)
        .ok_or_else(|| anyhow!("non-canonical checksum sidecar"))?;
    ensure!(
        is_lower_hex_digest(digest),
        "non-canonical checksum sidecar"
    );
    Ok(Some(LocalPair {
        digest: digest.to_owned(),
        archive_length: archive_metadata.len(),
        archive_modified_nanoseconds: i128::from(archive_metadata.mtime()) * 1_000_000_000
            + i128::from(archive_metadata.mtime_nsec()),
    }))
}

fn r2_receipt_evidence(path: &Path, epoch: u64) -> Option<R2ReceiptEvidence> {
    let Ok(Some(bytes)) = read_regular(path, MAX_RECEIPT_BYTES) else {
        return None;
    };
    let Ok(receipt) = serde_json::from_slice::<Value>(&bytes) else {
        return None;
    };
    let valid = receipt.get("schema").and_then(Value::as_str)
        == Some("jetstreamer-horizon-r2-receipt-v1")
        && receipt.get("epoch").and_then(Value::as_u64) == Some(epoch)
        && receipt.get("archive_key").and_then(Value::as_str)
            == Some(&format!("epoch-{epoch}.jet"))
        && receipt.get("checksum_key").and_then(Value::as_str)
            == Some(&format!("epoch-{epoch}.jet.sha256"))
        && receipt
            .get("archive_sha256")
            .and_then(Value::as_str)
            .is_some_and(is_lower_hex_digest)
        && receipt
            .get("archive_length")
            .and_then(Value::as_u64)
            .is_some_and(|length| length > 0)
        && receipt
            .get("archive_etag")
            .and_then(Value::as_str)
            .is_some_and(|etag| !etag.is_empty())
        && receipt
            .get("bucket")
            .and_then(Value::as_str)
            .is_some_and(|bucket| !bucket.is_empty())
        && receipt
            .get("verified_unix_seconds")
            .and_then(Value::as_u64)
            .is_some()
        && (receipt
            .get("remote_sha256_readback")
            .and_then(Value::as_bool)
            == Some(true)
            || receipt
                .get("r2_composite_sha256")
                .and_then(Value::as_str)
                .is_some_and(|digest| !digest.is_empty()));
    if !valid {
        return None;
    }
    Some(R2ReceiptEvidence {
        bucket: receipt
            .get("bucket")
            .and_then(Value::as_str)
            .expect("validated bucket")
            .to_owned(),
        digest: receipt
            .get("archive_sha256")
            .and_then(Value::as_str)
            .expect("validated digest")
            .to_owned(),
        archive_length: receipt
            .get("archive_length")
            .and_then(Value::as_u64)
            .expect("validated archive length"),
        archive_etag: receipt
            .get("archive_etag")
            .and_then(Value::as_str)
            .expect("validated archive ETag")
            .to_owned(),
    })
}

fn receipt_matches(path: &Path, epoch: u64, digest: &str, pair: &LocalPair) -> bool {
    let Some(evidence) = r2_receipt_evidence(path, epoch) else {
        return false;
    };
    let Ok(Some(bytes)) = read_regular(path, MAX_RECEIPT_BYTES) else {
        return false;
    };
    let Ok(receipt) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    evidence.digest == digest
        && evidence.archive_length == pair.archive_length
        && receipt
            .get("verified_unix_seconds")
            .and_then(Value::as_u64)
            .is_some_and(|value| {
                i128::from(value) * 1_000_000_000 >= pair.archive_modified_nanoseconds
            })
}

fn public_receipt_matches(path: &Path, epoch: u64, r2: &R2ReceiptEvidence) -> bool {
    let Ok(Some(bytes)) = read_regular(path, MAX_RECEIPT_BYTES) else {
        return false;
    };
    let Ok(receipt) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    receipt.get("schema").and_then(Value::as_str)
        == Some("jetstreamer-horizon-r2-public-read-receipt-v1")
        && receipt.get("bucket").and_then(Value::as_str) == Some(&r2.bucket)
        && receipt.get("epoch").and_then(Value::as_u64) == Some(epoch)
        && receipt.get("archive_key").and_then(Value::as_str) == Some(&format!("epoch-{epoch}.jet"))
        && receipt.get("checksum_key").and_then(Value::as_str)
            == Some(&format!("epoch-{epoch}.jet.sha256"))
        && receipt.get("archive_sha256").and_then(Value::as_str) == Some(&r2.digest)
        && receipt.get("archive_length").and_then(Value::as_u64) == Some(r2.archive_length)
        && receipt.get("archive_etag").and_then(Value::as_str) == Some(&r2.archive_etag)
        && receipt
            .get("public_base_url")
            .and_then(Value::as_str)
            .is_some_and(|url| url.starts_with("https://"))
        && receipt
            .get("verified_unix_seconds")
            .and_then(Value::as_u64)
            .is_some()
}

fn exact_words(path: &Path, count: usize) -> Result<Option<Vec<String>>> {
    let Some(bytes) = read_regular(path, MAX_RECEIPT_BYTES)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes).context("gate receipt is not UTF-8")?;
    ensure!(
        text.ends_with('\n') && !text[..text.len() - 1].contains('\n'),
        "non-canonical gate receipt"
    );
    let fields: Vec<_> = text[..text.len() - 1]
        .split(' ')
        .map(ToOwned::to_owned)
        .collect();
    ensure!(
        fields.len() == count && fields.iter().all(|field| is_lower_hex_digest(field)),
        "non-canonical gate receipt"
    );
    Ok(Some(fields))
}

fn gate_receipt_matches(gate: &Gate, epoch: u64, suffix: &str, digest: &str) -> bool {
    let path = gate.directory.join(format!("epoch-{epoch}.{suffix}.ok"));
    matches!(
        exact_words(&path, 3),
        Ok(Some(fields))
            if fields[0] == digest
                && gate.verifier_sha256.contains(&fields[1])
                && gate.script_sha256.contains(&fields[2])
    )
}

fn boundary_receipt_matches(
    gate: &Gate,
    left_epoch: u64,
    right_epoch: u64,
    digest: &str,
    digest_field: usize,
) -> bool {
    let path = gate
        .directory
        .join(format!("boundary-{left_epoch}-{right_epoch}.ok"));
    matches!(
        exact_words(&path, 4),
        Ok(Some(fields))
            if fields[digest_field] == digest
                && gate.verifier_sha256.contains(&fields[2])
                && gate.script_sha256.contains(&fields[3])
    )
}

fn publication_allowed(config: &Config, epoch: u64, digest: &str) -> bool {
    gate_receipt_matches(&config.full, epoch, "full", digest)
        && gate_receipt_matches(&config.plugin, epoch, "plugin", digest)
}

fn adjacent_boundaries_allowed(config: &Config, epoch: u64, digest: &str) -> bool {
    (epoch == 0 || boundary_receipt_matches(&config.boundary, epoch - 1, epoch, digest, 1))
        && epoch.checked_add(1).is_some_and(|right| {
            boundary_receipt_matches(&config.boundary, epoch, right, digest, 0)
        })
}

fn retirement_allowed(
    config: &Config,
    epoch: u64,
    digest: &str,
    authenticated_readback: bool,
) -> bool {
    config.delete_local
        && authenticated_readback
        && !config
            .defer_epochs
            .iter()
            .any(|&(first, last)| first <= epoch && epoch <= last)
        && publication_allowed(config, epoch, digest)
        && adjacent_boundaries_allowed(config, epoch, digest)
}

fn sync_command(config: &Config, epoch: u64, delete_local: bool) -> Command {
    let mut command = Command::new(&config.uploader);
    command
        .arg("sync")
        .arg(&config.horizon_directory)
        .arg("--epochs")
        .arg(format!("{epoch}-{epoch}"))
        .arg("--receipt-directory")
        .arg(&config.receipt_directory)
        .arg("--legacy-part-size-mib")
        .arg(config.legacy_part_size_mib.to_string())
        .arg("--concurrency")
        .arg(config.concurrency.to_string());
    if delete_local {
        command.arg("--delete-local");
    }
    command
}

fn run_sync(config: &Config, epoch: u64, delete_local: bool) -> Result<()> {
    println!("epoch {epoch}: progressive R2 sync started");
    let status = sync_command(config, epoch, delete_local)
        .status()
        .with_context(|| format!("failed to start uploader for epoch {epoch}"))?;
    ensure!(
        status.success(),
        "uploader failed for epoch {epoch}: {}",
        status_text(status)
    );
    println!("epoch {epoch}: progressive R2 sync complete");
    Ok(())
}

fn public_verify_command(config: &Config, public_receipt_directory: &Path, epoch: u64) -> Command {
    let mut command = Command::new(&config.uploader);
    command
        .arg("public-verify")
        .arg(&config.horizon_directory)
        .arg("--epochs")
        .arg(format!("{epoch}-{epoch}"))
        .arg("--public-receipt-directory")
        .arg(public_receipt_directory);
    command
}

fn run_public_verify(config: &Config, epoch: u64) -> Result<bool> {
    let public_receipt_directory = config
        .public_receipt_directory
        .as_deref()
        .ok_or_else(|| anyhow!("public verification was not configured"))?;
    println!("epoch {epoch}: anonymous public verification started");
    let status = public_verify_command(config, public_receipt_directory, epoch)
        .status()
        .with_context(|| format!("failed to start public verifier for epoch {epoch}"))?;
    if !status.success() {
        let receipt_path = public_receipt_directory.join(format!("epoch-{epoch}.public.json"));
        if archive_metadata(&receipt_path)?.is_some() {
            bail!(
                "public verification failed for epoch {epoch} with an existing public-read receipt: {}",
                status_text(status)
            );
        }
        println!(
            "epoch {epoch}: waiting for anonymous public access ({})",
            status_text(status)
        );
        return Ok(false);
    }
    println!("epoch {epoch}: anonymous public verification complete");
    Ok(true)
}

fn status_text(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| format!("exit code {code}"))
        .or_else(|| status.signal().map(|signal| format!("signal {signal}")))
        .unwrap_or_else(|| "unknown status".to_owned())
}

fn run(config: &Config) -> Result<()> {
    loop {
        let mut incomplete = 0_u64;
        for epoch in config.first_epoch..=config.last_epoch {
            let _lock = MutationLock::acquire(config.local_mutation_lock.as_deref())?;
            let pair = local_pair(&config.horizon_directory, epoch)?;
            let receipt_path = config
                .receipt_directory
                .join(format!("epoch-{epoch}.r2.json"));
            let r2_evidence = if let Some(pair) = &pair {
                if !receipt_matches(&receipt_path, epoch, &pair.digest, pair) {
                    if !publication_allowed(config, epoch, &pair.digest) {
                        incomplete += 1;
                        println!("epoch {epoch}: waiting for exact full and plugin receipts");
                        continue;
                    }
                    run_sync(config, epoch, false)?;
                }
                let evidence = r2_receipt_evidence(&receipt_path, epoch).ok_or_else(|| {
                    anyhow!("epoch {epoch}: uploader did not write a valid R2 receipt")
                })?;
                ensure!(
                    evidence.digest == pair.digest
                        && evidence.archive_length == pair.archive_length,
                    "epoch {epoch}: authenticated R2 receipt differs from the local pair"
                );
                evidence
            } else {
                let Some(evidence) = r2_receipt_evidence(&receipt_path, epoch) else {
                    incomplete += 1;
                    continue;
                };
                evidence
            };

            if let Some(public_receipt_directory) = &config.public_receipt_directory {
                if !run_public_verify(config, epoch)? {
                    incomplete += 1;
                    continue;
                }
                let public_receipt_path =
                    public_receipt_directory.join(format!("epoch-{epoch}.public.json"));
                ensure!(
                    public_receipt_matches(&public_receipt_path, epoch, &r2_evidence),
                    "epoch {epoch}: public-read receipt does not match the authenticated R2 receipt"
                );
            }

            if let Some(pair) = &pair
                && retirement_allowed(config, epoch, &pair.digest, true)
            {
                run_sync(config, epoch, true)?;
            }
        }
        if incomplete == 0 {
            println!(
                "epochs {}-{}: every epoch has matching authenticated R2 evidence{}",
                config.first_epoch,
                config.last_epoch,
                if config.public_receipt_directory.is_some() {
                    " and anonymous readback"
                } else {
                    ""
                }
            );
            return Ok(());
        }
        thread::sleep(Duration::from_secs(config.poll_seconds));
    }
}

fn main() -> Result<()> {
    let config = parse_args()?;
    run(&config)
}

#[cfg(test)]
mod tests {
    use {super::*, std::io::Write as _, tempfile::TempDir};

    fn digest(byte: &str) -> String {
        byte.repeat(64)
    }

    #[test]
    fn option_values_accept_inline_and_separate_forms() {
        let mut no_arguments = Vec::<std::ffi::OsString>::new().into_iter();
        assert_eq!(
            option_value(&mut no_arguments, "--poll-seconds", Some("17")).unwrap(),
            "17"
        );

        let mut one_argument = vec![std::ffi::OsString::from("23")].into_iter();
        assert_eq!(
            option_value(&mut one_argument, "--poll-seconds", None).unwrap(),
            "23"
        );

        let mut no_arguments = Vec::<std::ffi::OsString>::new().into_iter();
        assert!(
            option_value(&mut no_arguments, "--poll-seconds", Some(""))
                .unwrap_err()
                .to_string()
                .contains("missing value")
        );
    }

    fn gate(path: &Path, verifier: &str, script: &str) -> Gate {
        Gate {
            directory: path.to_owned(),
            verifier_sha256: BTreeSet::from([verifier.to_owned()]),
            script_sha256: BTreeSet::from([script.to_owned()]),
        }
    }

    fn test_config(root: &Path) -> Config {
        for name in [
            "horizon",
            "receipts",
            "public-receipts",
            "full",
            "plugin",
            "boundary",
        ] {
            fs::create_dir(root.join(name)).unwrap();
        }
        let uploader = root.join("uploader");
        File::create(&uploader).unwrap();
        let verifier = digest("c");
        let script = digest("e");
        Config {
            uploader,
            horizon_directory: root.join("horizon"),
            receipt_directory: root.join("receipts"),
            public_receipt_directory: Some(root.join("public-receipts")),
            first_epoch: 7,
            last_epoch: 7,
            poll_seconds: 1,
            concurrency: 4,
            legacy_part_size_mib: 5,
            delete_local: true,
            local_mutation_lock: None,
            full: gate(&root.join("full"), &verifier, &script),
            plugin: gate(&root.join("plugin"), &verifier, &script),
            boundary: gate(&root.join("boundary"), &verifier, &script),
            defer_epochs: Vec::new(),
        }
    }

    #[test]
    fn lock_is_private_regular_and_reusable() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("mutation.lock");
        drop(MutationLock::acquire(Some(&path)).unwrap());
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o077, 0);
        drop(MutationLock::acquire(Some(&path)).unwrap());
    }

    #[test]
    fn local_pair_requires_canonical_matching_sidecar() {
        let temporary = TempDir::new().unwrap();
        let archive = temporary.path().join("epoch-123.jet");
        fs::write(&archive, b"archive").unwrap();
        let checksum = digest("a");
        fs::write(
            temporary.path().join("epoch-123.jet.sha256"),
            format!("{checksum}  epoch-123.jet\n"),
        )
        .unwrap();
        assert_eq!(
            local_pair(temporary.path(), 123).unwrap().unwrap().digest,
            checksum
        );
        fs::write(
            temporary.path().join("epoch-123.jet.sha256"),
            format!("{} *epoch-123.jet\n", digest("a")),
        )
        .unwrap();
        assert!(local_pair(temporary.path(), 123).is_err());
    }

    #[test]
    fn receipt_binds_current_local_identity() {
        let temporary = TempDir::new().unwrap();
        fs::write(temporary.path().join("epoch-7.jet"), b"archive").unwrap();
        let checksum = digest("d");
        fs::write(
            temporary.path().join("epoch-7.jet.sha256"),
            format!("{checksum}  epoch-7.jet\n"),
        )
        .unwrap();
        let pair = local_pair(temporary.path(), 7).unwrap().unwrap();
        let receipt = serde_json::json!({
            "schema": "jetstreamer-horizon-r2-receipt-v1",
            "bucket": "bucket",
            "epoch": 7,
            "archive_key": "epoch-7.jet",
            "checksum_key": "epoch-7.jet.sha256",
            "archive_sha256": checksum,
            "archive_length": pair.archive_length,
            "archive_etag": "etag",
            "verified_unix_seconds":
                (pair.archive_modified_nanoseconds.max(0) / 1_000_000_000) as u64 + 1,
            "remote_sha256_readback": true,
        });
        let path = temporary.path().join("epoch-7.r2.json");
        fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(receipt_matches(&path, 7, &pair.digest, &pair));
        let same_second_pair = LocalPair {
            digest: pair.digest.clone(),
            archive_length: pair.archive_length,
            archive_modified_nanoseconds: 2_000_000_001,
        };
        let mut same_second_receipt = receipt.clone();
        same_second_receipt["verified_unix_seconds"] = Value::from(2);
        fs::write(&path, serde_json::to_vec(&same_second_receipt).unwrap()).unwrap();
        assert!(!receipt_matches(&path, 7, &pair.digest, &same_second_pair));
        let mut changed = receipt;
        changed["archive_length"] = Value::from(pair.archive_length + 1);
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(!receipt_matches(&path, 7, &pair.digest, &pair));
    }

    #[test]
    fn incomplete_pair_is_not_eligible() {
        let temporary = TempDir::new().unwrap();
        fs::write(temporary.path().join("epoch-9.jet"), b"partial").unwrap();
        assert!(local_pair(temporary.path(), 9).unwrap().is_none());
    }

    #[test]
    fn publication_and_retirement_have_distinct_gates() {
        let temporary = TempDir::new().unwrap();
        let mut config = test_config(temporary.path());
        let checksum = digest("a");
        let verifier = digest("c");
        let script = digest("e");
        fs::write(
            config.full.directory.join("epoch-7.full.ok"),
            format!("{checksum} {verifier} {script}\n"),
        )
        .unwrap();
        fs::write(
            config.plugin.directory.join("epoch-7.plugin.ok"),
            format!("{checksum} {verifier} {script}\n"),
        )
        .unwrap();
        fs::write(
            config.boundary.directory.join("boundary-6-7.ok"),
            format!("{} {checksum} {verifier} {script}\n", digest("0")),
        )
        .unwrap();
        fs::write(
            config.boundary.directory.join("boundary-7-8.ok"),
            format!("{checksum} {} {verifier} {script}\n", digest("1")),
        )
        .unwrap();
        assert!(publication_allowed(&config, 7, &checksum));
        assert!(!retirement_allowed(&config, 7, &checksum, false));
        assert!(retirement_allowed(&config, 7, &checksum, true));
        fs::remove_file(config.boundary.directory.join("boundary-7-8.ok")).unwrap();
        assert!(publication_allowed(&config, 7, &checksum));
        assert!(!retirement_allowed(&config, 7, &checksum, true));
        config.defer_epochs.push((7, 9));
        assert!(!retirement_allowed(&config, 7, &checksum, true));
    }

    #[test]
    fn authenticated_only_mode_does_not_require_public_origin_evidence() {
        let temporary = TempDir::new().unwrap();
        let mut config = test_config(temporary.path());
        config.public_receipt_directory = None;
        let checksum = digest("a");
        let verifier = digest("c");
        let script = digest("e");
        fs::write(
            config.full.directory.join("epoch-7.full.ok"),
            format!("{checksum} {verifier} {script}\n"),
        )
        .unwrap();
        fs::write(
            config.plugin.directory.join("epoch-7.plugin.ok"),
            format!("{checksum} {verifier} {script}\n"),
        )
        .unwrap();
        fs::write(
            config.boundary.directory.join("boundary-6-7.ok"),
            format!("{} {checksum} {verifier} {script}\n", digest("0")),
        )
        .unwrap();
        fs::write(
            config.boundary.directory.join("boundary-7-8.ok"),
            format!("{checksum} {} {verifier} {script}\n", digest("1")),
        )
        .unwrap();
        assert!(publication_allowed(&config, 7, &checksum));
        assert!(retirement_allowed(&config, 7, &checksum, true));
    }

    #[test]
    fn delete_local_is_delegated_to_rust_uploader() {
        let temporary = TempDir::new().unwrap();
        let config = test_config(temporary.path());
        let command = sync_command(&config, 7, true);
        let arguments: Vec<_> = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert!(arguments.contains(&"--delete-local".to_owned()));
        assert_eq!(command.get_program(), config.uploader.as_os_str());
    }

    #[test]
    fn public_verification_is_delegated_to_rust_uploader() {
        let temporary = TempDir::new().unwrap();
        let config = test_config(temporary.path());
        let public_receipt_directory = config.public_receipt_directory.as_deref().unwrap();
        let command = public_verify_command(&config, public_receipt_directory, 7);
        let arguments: Vec<_> = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            arguments,
            vec![
                "public-verify".to_owned(),
                config.horizon_directory.to_string_lossy().into_owned(),
                "--epochs".to_owned(),
                "7-7".to_owned(),
                "--public-receipt-directory".to_owned(),
                public_receipt_directory.to_string_lossy().into_owned(),
            ]
        );
        assert_eq!(command.get_program(), config.uploader.as_os_str());
    }

    #[test]
    fn public_receipt_must_match_authenticated_evidence() {
        let temporary = TempDir::new().unwrap();
        let checksum = digest("a");
        let receipt = serde_json::json!({
            "schema": "jetstreamer-horizon-r2-public-read-receipt-v1",
            "bucket": "bucket",
            "epoch": 7,
            "archive_key": "epoch-7.jet",
            "checksum_key": "epoch-7.jet.sha256",
            "public_base_url": "https://archive.example.com/",
            "public_archive_url": "https://archive.example.com/epoch-7.jet",
            "public_checksum_url": "https://archive.example.com/epoch-7.jet.sha256",
            "archive_length": 123,
            "archive_etag": "etag",
            "archive_sha256": checksum,
            "verified_unix_seconds": 1,
        });
        let path = temporary.path().join("epoch-7.public.json");
        fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        let evidence = R2ReceiptEvidence {
            bucket: "bucket".to_owned(),
            digest: checksum,
            archive_length: 123,
            archive_etag: "etag".to_owned(),
        };
        assert!(public_receipt_matches(&path, 7, &evidence));
        let mut wrong_length = evidence.clone();
        wrong_length.archive_length = 124;
        assert!(!public_receipt_matches(&path, 7, &wrong_length));
        assert!(!public_receipt_matches(&path, 8, &evidence));
    }

    #[test]
    fn allowlists_are_strict_and_unique() {
        assert_eq!(parse_allowlist(&digest("a"), "--hash").unwrap().len(), 1);
        assert!(parse_allowlist("ABC", "--hash").is_err());
        let repeated = format!("{0},{0}", digest("a"));
        assert!(parse_allowlist(&repeated, "--hash").is_err());
    }

    #[test]
    fn gate_receipts_require_single_canonical_line() {
        let temporary = TempDir::new().unwrap();
        let verifier = digest("c");
        let script = digest("e");
        let checksum = digest("a");
        let gate = gate(temporary.path(), &verifier, &script);
        let path = temporary.path().join("epoch-7.full.ok");
        let mut file = File::create(&path).unwrap();
        writeln!(file, "{checksum} {verifier} {script}").unwrap();
        assert!(gate_receipt_matches(&gate, 7, "full", &checksum));
        fs::write(&path, format!("{checksum}  {verifier} {script}\n")).unwrap();
        assert!(!gate_receipt_matches(&gate, 7, "full", &checksum));
    }
}
