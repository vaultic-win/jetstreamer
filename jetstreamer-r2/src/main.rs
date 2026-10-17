//! Upload verified Horizon archives to Cloudflare R2, restore verified copies,
//! and retire local copies.
//!
//! The archive API surface is intentionally append-only. The sole remote
//! deletion operation is the fail-closed removal of a mutable
//! `epoch-N.epoch-status.json` after the canonical archive and sidecar have
//! durable authenticated completion evidence. A local archive is removed only after its exact
//! SHA-256 sidecar, length, multipart ETag, and immutable metadata have been
//! observed in R2 and a private receipt has been fsynced. The sidecar is
//! published last and serves as the remote completion marker.

use {
    anyhow::{Context, Result, anyhow, bail, ensure},
    aws_credential_types::{Credentials, provider::SharedCredentialsProvider},
    aws_sdk_s3::{
        Client,
        config::{BehaviorVersion, Builder as S3ConfigBuilder, RequestChecksumCalculation},
        primitives::ByteStream,
        types::{ChecksumMode, ChecksumType, CompletedMultipartUpload, CompletedPart},
    },
    aws_types::region::Region,
    base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD},
    md5::Md5,
    reqwest::{
        Client as HttpClient, StatusCode,
        header::{CONTENT_LENGTH, CONTENT_RANGE, ETAG, RANGE},
        redirect::Policy as RedirectPolicy,
    },
    serde::{Deserialize, Serialize},
    serde_json::Value,
    sha2::{Digest as _, Sha256},
    std::{
        collections::BTreeSet,
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::unix::{fs::MetadataExt as _, fs::OpenOptionsExt as _},
        path::{Path, PathBuf},
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
    url::Url,
};

const DEFAULT_PART_SIZE: u64 = 64 * 1024 * 1024;
const DEFAULT_CONCURRENCY: usize = 8;
const MAX_SIDECAR_BYTES: u64 = 512;
const MAX_STATUS_BYTES: u64 = 16 * 1024;
const MAX_OBSERVER_RECEIPT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PART_ATTEMPTS: usize = 8;
const MAX_REMOTE_READ_ATTEMPTS: usize = 64;
const MAX_REMOTE_READ_RANGE_SIZE: u64 = 64 * 1024 * 1024;
const MIN_REMOTE_READ_RANGE_SIZE: u64 = 8 * 1024 * 1024;
const REMOTE_READ_BUFFER_BUDGET: u64 = 512 * 1024 * 1024;
const RECEIPT_SCHEMA: &str = "jetstreamer-horizon-r2-receipt-v1";
const PUBLIC_RECEIPT_SCHEMA: &str = "jetstreamer-horizon-r2-public-read-receipt-v1";
const STATUS_RECEIPT_SCHEMA: &str =
    "jetstreamer-horizon-r2-status-authenticated-publication-receipt-v1";
const STATUS_DELETION_RECEIPT_SCHEMA: &str =
    "jetstreamer-horizon-r2-status-authenticated-deletion-receipt-v1";

#[derive(Debug)]
struct Config {
    command: Command,
    directory: PathBuf,
    epochs: BTreeSet<u64>,
    receipt_directory: Option<PathBuf>,
    public_receipt_directory: Option<PathBuf>,
    delete_local: bool,
    part_size: u64,
    legacy_part_size: Option<u64>,
    concurrency: usize,
    legacy_etag_only: bool,
    overwrite_existing: bool,
    repair_orphaned_archive: bool,
    observer_receipt: Option<PathBuf>,
    observer_sha256: Option<String>,
    expected_controller_invocation_id: Option<String>,
    expected_producer_invocation_id: Option<String>,
    elapsed_execution_millis: Option<u64>,
    estimated_remaining_millis: Option<u64>,
    phase: Option<String>,
    archive_receipt_directory: Option<PathBuf>,
    status_publication_receipt: Option<PathBuf>,
    status_publication_sha256: Option<String>,
    latest_status_publication_receipt: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Inventory,
    PublicVerify,
    RetireLocal,
    Sync,
    Verify,
    Restore,
    StatusPublish,
    StatusDelete,
}

#[derive(Clone, Debug)]
struct R2Config {
    endpoint: String,
    bucket: String,
    access_key: String,
    secret_key: String,
}

#[derive(Clone, Debug)]
struct PublicConfig {
    base_url: Url,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

#[derive(Debug)]
struct LocalArchive {
    epoch: u64,
    archive_path: PathBuf,
    sidecar_path: PathBuf,
    identity: FileIdentity,
    sidecar_identity: FileIdentity,
    length: u64,
    sha256_hex: String,
    sidecar: Vec<u8>,
}

#[derive(Debug)]
struct LocalProof {
    sha256_hex: String,
    multipart_etag: String,
    composite_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Receipt {
    schema: String,
    bucket: String,
    epoch: u64,
    archive_key: String,
    checksum_key: String,
    archive_length: u64,
    archive_sha256: String,
    archive_etag: String,
    r2_composite_sha256: Option<String>,
    #[serde(default)]
    remote_sha256_readback: bool,
    multipart_part_size: u64,
    verified_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PublicReceipt {
    schema: String,
    bucket: String,
    epoch: u64,
    archive_key: String,
    checksum_key: String,
    public_base_url: String,
    public_archive_url: String,
    public_checksum_url: String,
    archive_length: u64,
    archive_etag: String,
    archive_sha256: String,
    verified_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EpochStatus {
    epoch: u64,
    jet_size_bytes: u64,
    elapsed_execution_millis: u64,
    estimated_remaining_millis: u64,
    sampled_at_utc: String,
    phase: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StatusPublicationReceipt {
    schema: String,
    bucket: String,
    epoch: u64,
    key: String,
    status: EpochStatus,
    object_etag: String,
    previous_object_etag: Option<String>,
    observer_receipt: PathBuf,
    observer_receipt_sha256: String,
    controller_invocation_id: String,
    producer_invocation_id: String,
    authenticated_readback: bool,
    verified_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StatusDeletionReceipt {
    schema: String,
    bucket: String,
    epoch: u64,
    key: String,
    deleted_object_etag: String,
    deleted_status: EpochStatus,
    status_publication_receipt: PathBuf,
    status_publication_receipt_sha256: String,
    archive_receipt: PathBuf,
    archive_receipt_sha256: String,
    archive_sha256: String,
    archive_etag: String,
    conditional_delete_request_sent: bool,
    authenticated_ready_pair_before: bool,
    authenticated_status_absent_after: bool,
    authenticated_ready_pair_after: bool,
    verified_unix_seconds: u64,
}

fn usage() -> ! {
    eprintln!(concat!(
        "usage: horizon-r2 <inventory|public-verify|retire-local|sync|verify|restore|status-publish|status-delete> DIRECTORY [--epochs START-END] ",
        "[--receipt-directory DIRECTORY] [--public-receipt-directory DIRECTORY] [--delete-local] [--part-size-mib N] ",
        "[--legacy-part-size-mib N] [--legacy-etag-only] [--overwrite-existing] ",
        "[--repair-orphaned-archive] ",
        "[--concurrency N] [--observer-receipt FILE] [--observer-sha256 HEX] ",
        "[--expected-controller-invocation-id ID] [--expected-producer-invocation-id ID] ",
        "[--elapsed-execution-millis N] [--estimated-remaining-millis N] [--phase PHASE] ",
        "[--archive-receipt-directory DIRECTORY] [--status-publication-receipt FILE] ",
        "[--status-publication-sha256 HEX] [--latest-status-publication-receipt]"
    ));
    std::process::exit(2);
}

fn parse_args() -> Result<Config> {
    let mut args = env::args_os().skip(1);
    let command = match args
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("inventory") => Command::Inventory,
        Some("public-verify") => Command::PublicVerify,
        Some("retire-local") => Command::RetireLocal,
        Some("sync") => Command::Sync,
        Some("verify") => Command::Verify,
        Some("restore") => Command::Restore,
        Some("status-publish") => Command::StatusPublish,
        Some("status-delete") => Command::StatusDelete,
        _ => usage(),
    };
    let directory = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    let mut epochs = None;
    let mut receipt_directory = None;
    let mut public_receipt_directory = None;
    let mut delete_local = false;
    let mut part_size = DEFAULT_PART_SIZE;
    let mut legacy_part_size = None;
    let mut concurrency = DEFAULT_CONCURRENCY;
    let mut legacy_etag_only = false;
    let mut overwrite_existing = false;
    let mut repair_orphaned_archive = false;
    let mut observer_receipt = None;
    let mut observer_sha256 = None;
    let mut expected_controller_invocation_id = None;
    let mut expected_producer_invocation_id = None;
    let mut elapsed_execution_millis = None;
    let mut estimated_remaining_millis = None;
    let mut phase = None;
    let mut archive_receipt_directory = None;
    let mut status_publication_receipt = None;
    let mut status_publication_sha256 = None;
    let mut latest_status_publication_receipt = false;
    while let Some(argument) = args.next() {
        let argument = argument
            .into_string()
            .map_err(|_| anyhow!("argument is not UTF-8"))?;
        let mut value = || {
            args.next()
                .ok_or_else(|| anyhow!("missing value for {argument}"))?
                .into_string()
                .map_err(|_| anyhow!("value for {argument} is not UTF-8"))
        };
        match argument.as_str() {
            "--epochs" => epochs = Some(parse_epoch_range(&value()?)?),
            "--receipt-directory" => receipt_directory = Some(PathBuf::from(value()?)),
            "--public-receipt-directory" => {
                public_receipt_directory = Some(PathBuf::from(value()?))
            }
            "--delete-local" => delete_local = true,
            "--part-size-mib" => part_size = parse_mib(&value()?)?,
            "--legacy-part-size-mib" => legacy_part_size = Some(parse_mib(&value()?)?),
            "--legacy-etag-only" => legacy_etag_only = true,
            "--overwrite-existing" => overwrite_existing = true,
            "--repair-orphaned-archive" => repair_orphaned_archive = true,
            "--observer-receipt" => observer_receipt = Some(PathBuf::from(value()?)),
            "--observer-sha256" => observer_sha256 = Some(value()?),
            "--expected-controller-invocation-id" => {
                expected_controller_invocation_id = Some(value()?)
            }
            "--expected-producer-invocation-id" => expected_producer_invocation_id = Some(value()?),
            "--elapsed-execution-millis" => {
                elapsed_execution_millis = Some(
                    value()?
                        .parse()
                        .context("invalid --elapsed-execution-millis")?,
                )
            }
            "--estimated-remaining-millis" => {
                estimated_remaining_millis = Some(
                    value()?
                        .parse()
                        .context("invalid --estimated-remaining-millis")?,
                )
            }
            "--phase" => phase = Some(value()?),
            "--archive-receipt-directory" => {
                archive_receipt_directory = Some(PathBuf::from(value()?))
            }
            "--status-publication-receipt" => {
                status_publication_receipt = Some(PathBuf::from(value()?))
            }
            "--status-publication-sha256" => status_publication_sha256 = Some(value()?),
            "--latest-status-publication-receipt" => latest_status_publication_receipt = true,
            "--concurrency" => {
                concurrency = value()?.parse().context("invalid --concurrency")?;
                ensure!(
                    (1..=64).contains(&concurrency),
                    "concurrency must be 1..=64"
                );
            }
            _ => bail!("unknown argument: {argument}"),
        }
    }
    ensure!(
        directory.is_absolute(),
        "archive directory must be absolute"
    );
    if !matches!(command, Command::Inventory | Command::PublicVerify) {
        ensure!(
            receipt_directory.is_some(),
            "--receipt-directory is required"
        );
    }
    if let Some(receipt_directory) = &receipt_directory {
        ensure!(
            receipt_directory.is_absolute(),
            "receipt directory must be absolute"
        );
    }
    if command == Command::PublicVerify {
        ensure!(
            public_receipt_directory.is_some(),
            "--public-receipt-directory is required"
        );
    }
    if let Some(public_receipt_directory) = &public_receipt_directory {
        ensure!(
            public_receipt_directory.is_absolute(),
            "public receipt directory must be absolute"
        );
    }
    if let Some(observer_receipt) = &observer_receipt {
        ensure!(
            observer_receipt.is_absolute(),
            "observer receipt path must be absolute"
        );
    }
    if let Some(archive_receipt_directory) = &archive_receipt_directory {
        ensure!(
            archive_receipt_directory.is_absolute(),
            "archive receipt directory must be absolute"
        );
    }
    if let Some(status_publication_receipt) = &status_publication_receipt {
        ensure!(
            status_publication_receipt.is_absolute(),
            "status publication receipt path must be absolute"
        );
    }
    ensure!(
        public_receipt_directory.is_none() || command == Command::PublicVerify,
        "--public-receipt-directory is valid only with public-verify"
    );
    ensure!(
        !delete_local || command == Command::Sync,
        "--delete-local is valid only with sync"
    );
    ensure!(
        !overwrite_existing || command == Command::Sync,
        "--overwrite-existing is valid only with sync"
    );
    ensure!(
        !repair_orphaned_archive || command == Command::Sync,
        "--repair-orphaned-archive is valid only with sync"
    );
    ensure!(
        !repair_orphaned_archive || !overwrite_existing,
        "--repair-orphaned-archive and --overwrite-existing are mutually exclusive"
    );
    ensure!(
        !legacy_etag_only || matches!(command, Command::Sync | Command::Verify),
        "--legacy-etag-only is valid only with sync or verify"
    );
    let status_options_present = observer_receipt.is_some()
        || observer_sha256.is_some()
        || expected_controller_invocation_id.is_some()
        || expected_producer_invocation_id.is_some()
        || elapsed_execution_millis.is_some()
        || estimated_remaining_millis.is_some()
        || phase.is_some();
    ensure!(
        command == Command::StatusPublish || !status_options_present,
        "status publication options are valid only with status-publish"
    );
    let status_delete_options_present = archive_receipt_directory.is_some()
        || status_publication_receipt.is_some()
        || status_publication_sha256.is_some()
        || latest_status_publication_receipt;
    ensure!(
        command == Command::StatusDelete || !status_delete_options_present,
        "status deletion options are valid only with status-delete"
    );
    if command == Command::StatusPublish {
        ensure!(observer_receipt.is_some(), "--observer-receipt is required");
        ensure!(observer_sha256.is_some(), "--observer-sha256 is required");
        ensure!(
            expected_controller_invocation_id.is_some(),
            "--expected-controller-invocation-id is required"
        );
        ensure!(
            expected_producer_invocation_id.is_some(),
            "--expected-producer-invocation-id is required"
        );
        ensure!(
            elapsed_execution_millis.is_some(),
            "--elapsed-execution-millis is required"
        );
        ensure!(
            estimated_remaining_millis.is_some(),
            "--estimated-remaining-millis is required"
        );
        ensure!(phase.is_some(), "--phase is required");
        ensure!(
            !delete_local && !overwrite_existing && !repair_orphaned_archive && !legacy_etag_only,
            "archive mutation/legacy options are invalid with status-publish"
        );
        let observer_sha256 = observer_sha256.as_deref().expect("checked");
        ensure!(
            is_lower_hex(observer_sha256, 64),
            "--observer-sha256 must be 64 lowercase hexadecimal characters"
        );
        for (label, invocation_id) in [
            (
                "--expected-controller-invocation-id",
                expected_controller_invocation_id
                    .as_deref()
                    .expect("checked"),
            ),
            (
                "--expected-producer-invocation-id",
                expected_producer_invocation_id.as_deref().expect("checked"),
            ),
        ] {
            ensure!(
                is_lower_hex(invocation_id, 32),
                "{label} must be 32 lowercase hexadecimal characters"
            );
        }
        ensure!(
            matches!(
                phase.as_deref().expect("checked"),
                "replay" | "verification" | "upload" | "readback"
            ),
            "--phase must be replay, verification, upload, or readback"
        );
    }
    if command == Command::StatusDelete {
        ensure!(
            archive_receipt_directory.is_some(),
            "--archive-receipt-directory is required"
        );
        ensure!(
            matches!(
                (
                    status_publication_receipt.is_some(),
                    status_publication_sha256.is_some(),
                    latest_status_publication_receipt,
                ),
                (true, true, false) | (false, false, true)
            ),
            "status-delete requires either the exact publication receipt and SHA-256 or --latest-status-publication-receipt"
        );
        ensure!(
            !delete_local && !overwrite_existing && !repair_orphaned_archive && !legacy_etag_only,
            "archive mutation/legacy options are invalid with status-delete"
        );
        if let Some(status_publication_sha256) = status_publication_sha256.as_deref() {
            ensure!(
                is_lower_hex(status_publication_sha256, 64),
                "--status-publication-sha256 must be 64 lowercase hexadecimal characters"
            );
        }
    }
    let epochs = match (command, epochs) {
        (Command::Inventory, None) => bail!("inventory requires --epochs START-END"),
        (Command::PublicVerify, None) => bail!("public-verify requires --epochs START-END"),
        (Command::RetireLocal, None) => bail!("retire-local requires --epochs START-END"),
        (Command::Restore, None) => bail!("restore requires --epochs START-END"),
        (Command::StatusPublish, None) => bail!("status-publish requires --epochs N-N"),
        (Command::StatusDelete, None) => bail!("status-delete requires --epochs N-N"),
        (_, Some(epochs)) => epochs,
        (_, None) => discover_local_epochs(&directory)?,
    };
    ensure!(!epochs.is_empty(), "no Horizon epochs selected");
    ensure!(
        !matches!(command, Command::StatusPublish | Command::StatusDelete) || epochs.len() == 1,
        "status-publish and status-delete require exactly one epoch"
    );
    Ok(Config {
        command,
        directory,
        epochs,
        receipt_directory,
        public_receipt_directory,
        delete_local,
        part_size,
        legacy_part_size,
        concurrency,
        legacy_etag_only,
        overwrite_existing,
        repair_orphaned_archive,
        observer_receipt,
        observer_sha256,
        expected_controller_invocation_id,
        expected_producer_invocation_id,
        elapsed_execution_millis,
        estimated_remaining_millis,
        phase,
        archive_receipt_directory,
        status_publication_receipt,
        status_publication_sha256,
        latest_status_publication_receipt,
    })
}

fn discover_local_epochs(directory: &Path) -> Result<BTreeSet<u64>> {
    let mut epochs = BTreeSet::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read archive directory {}", directory.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(epoch) = name
            .strip_prefix("epoch-")
            .and_then(|value| value.strip_suffix(".jet"))
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        if directory
            .join(format!("epoch-{epoch}.jet.sha256"))
            .is_file()
        {
            epochs.insert(epoch);
        }
    }
    Ok(epochs)
}

fn parse_epoch_range(value: &str) -> Result<BTreeSet<u64>> {
    let (first, last) = value
        .split_once('-')
        .ok_or_else(|| anyhow!("epoch range must be START-END"))?;
    let first: u64 = first.parse().context("invalid first epoch")?;
    let last: u64 = last.parse().context("invalid last epoch")?;
    ensure!(first <= last, "epoch range is reversed");
    ensure!(last - first < 10_000, "epoch range is unreasonably large");
    Ok((first..=last).collect())
}

fn parse_observer_claim_range(value: &str) -> Result<BTreeSet<u64>> {
    if value.contains('-') {
        return parse_epoch_range(value);
    }
    let epoch: u64 = value.parse().context("invalid observer epoch claim")?;
    ensure!(
        value == epoch.to_string(),
        "observer singleton epoch claim is not canonical"
    );
    Ok(BTreeSet::from([epoch]))
}

fn parse_mib(value: &str) -> Result<u64> {
    let mib: u64 = value.parse().context("invalid MiB value")?;
    ensure!(
        (5..=5 * 1024).contains(&mib),
        "part size must be 5..=5120 MiB"
    );
    mib.checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow!("part size overflow"))
}

fn r2_config_from_env() -> Result<R2Config> {
    let raw = env::var("HORIZON_S3_ENDPOINT").context("HORIZON_S3_ENDPOINT is unset")?;
    let url = Url::parse(&raw).context("invalid HORIZON_S3_ENDPOINT")?;
    ensure!(url.scheme() == "https", "R2 endpoint must use HTTPS");
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "R2 endpoint has query/fragment"
    );
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("R2 endpoint has no host"))?;
    ensure!(
        host.ends_with(".r2.cloudflarestorage.com"),
        "unexpected R2 endpoint host"
    );
    let bucket = url.path().trim_matches('/').to_string();
    ensure!(
        !bucket.is_empty() && !bucket.contains('/'),
        "R2 endpoint must contain one bucket path"
    );
    let endpoint = format!("{}://{}", url.scheme(), host);
    Ok(R2Config {
        endpoint,
        bucket,
        access_key: env::var("HORIZON_ACCESS_KEY_ID").context("HORIZON_ACCESS_KEY_ID is unset")?,
        secret_key: env::var("HORIZON_SECRET_ACCESS_KEY")
            .context("HORIZON_SECRET_ACCESS_KEY is unset")?,
    })
}

fn parse_public_config(raw: &str) -> Result<PublicConfig> {
    let mut base_url = Url::parse(raw).context("invalid HORIZON_PUBLIC_BASE_URL")?;
    ensure!(
        base_url.scheme() == "https",
        "public R2 origin must use HTTPS"
    );
    ensure!(
        base_url.username().is_empty() && base_url.password().is_none(),
        "public R2 origin must not contain credentials"
    );
    ensure!(
        base_url.query().is_none() && base_url.fragment().is_none(),
        "public R2 origin has query/fragment"
    );
    ensure!(
        base_url.port().is_none() || base_url.port() == Some(443),
        "public R2 origin must use the standard HTTPS port"
    );
    let host = base_url
        .host_str()
        .ok_or_else(|| anyhow!("public R2 origin has no host"))?;
    ensure!(
        !host.ends_with(".r2.cloudflarestorage.com"),
        "the authenticated R2 S3 API endpoint cannot be used as a public origin"
    );
    ensure!(
        matches!(base_url.path(), "" | "/"),
        "public R2 origin must name the bucket root"
    );
    base_url.set_path("/");
    Ok(PublicConfig { base_url })
}

fn public_config_from_env() -> Result<PublicConfig> {
    let raw = env::var("HORIZON_PUBLIC_BASE_URL").context("HORIZON_PUBLIC_BASE_URL is unset")?;
    parse_public_config(&raw)
}

fn public_object_url(public: &PublicConfig, key: &str) -> Result<Url> {
    ensure!(
        !key.is_empty() && !key.contains('/') && !key.contains('?') && !key.contains('#'),
        "invalid public object key"
    );
    public
        .base_url
        .join(key)
        .context("failed to construct public object URL")
}

fn s3_client(config: &R2Config) -> Client {
    let credentials = Credentials::new(
        config.access_key.clone(),
        config.secret_key.clone(),
        None,
        None,
        "horizon-r2",
    );
    let sdk = S3ConfigBuilder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("auto"))
        .credentials_provider(SharedCredentialsProvider::new(credentials))
        .endpoint_url(&config.endpoint)
        .force_path_style(true)
        // R2 rejects a PutObject request that combines our explicit
        // Content-MD5 with the SDK's optional default CRC32 checksum.
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .build();
    Client::from_conf(sdk)
}

fn identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

fn regular_identity(path: &Path) -> Result<FileIdentity> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.nlink() == 1,
        "file has multiple links: {}",
        path.display()
    );
    Ok(identity(&metadata))
}

fn read_local_archive(directory: &Path, epoch: u64) -> Result<LocalArchive> {
    let archive_path = directory.join(format!("epoch-{epoch}.jet"));
    let sidecar_path = directory.join(format!("epoch-{epoch}.jet.sha256"));
    let identity = regular_identity(&archive_path)?;
    let sidecar_identity = regular_identity(&sidecar_path)?;
    ensure!(
        sidecar_identity.length <= MAX_SIDECAR_BYTES,
        "oversized checksum sidecar"
    );
    let sidecar = fs::read(&sidecar_path).context("failed to read checksum sidecar")?;
    let digest = parse_canonical_sidecar(epoch, &sidecar)
        .ok_or_else(|| anyhow!("noncanonical checksum sidecar"))?;
    ensure!(
        regular_identity(&sidecar_path)? == sidecar_identity,
        "sidecar changed while read"
    );
    Ok(LocalArchive {
        epoch,
        archive_path,
        sidecar_path,
        identity,
        sidecar_identity,
        length: identity.length,
        sha256_hex: digest,
        sidecar,
    })
}

fn hash_and_etag(path: &Path, expected: FileIdentity, part_size: u64) -> Result<LocalProof> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed before hashing"
    );
    let mut sha256 = Sha256::new();
    let mut part_digests = Vec::new();
    let mut part_sha256_digests = Vec::new();
    let mut remaining = expected.length;
    let mut buffer = vec![0u8; usize::try_from(part_size.min(8 * 1024 * 1024))?];
    while remaining > 0 {
        let this_part = remaining.min(part_size);
        let mut part_remaining = this_part;
        let mut md5 = Md5::new();
        let mut part_sha256 = Sha256::new();
        while part_remaining > 0 {
            let take = usize::try_from(part_remaining.min(buffer.len() as u64))?;
            file.read_exact(&mut buffer[..take])?;
            sha256.update(&buffer[..take]);
            md5.update(&buffer[..take]);
            part_sha256.update(&buffer[..take]);
            part_remaining -= take as u64;
        }
        part_digests.push(md5.finalize().to_vec());
        part_sha256_digests.push(part_sha256.finalize().to_vec());
        remaining -= this_part;
    }
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed while hashing"
    );
    ensure!(
        regular_identity(path)? == expected,
        "archive namespace changed while hashing"
    );
    let sha256_hex = format!("{:x}", sha256.finalize());
    Ok(LocalProof {
        sha256_hex,
        multipart_etag: multipart_etag(&part_digests),
        composite_sha256: composite_sha256(&part_sha256_digests),
    })
}

fn multipart_etag(part_digests: &[Vec<u8>]) -> String {
    let mut md5 = Md5::new();
    for digest in part_digests {
        md5.update(digest);
    }
    format!("{:x}-{}", md5.finalize(), part_digests.len())
}

fn composite_sha256(part_digests: &[Vec<u8>]) -> String {
    let mut sha256 = Sha256::new();
    for digest in part_digests {
        sha256.update(digest);
    }
    BASE64_STANDARD.encode(sha256.finalize())
}

fn composite_checksum_matches(observed: &str, expected: &str, parts: u64) -> bool {
    observed == expected || observed == format!("{expected}-{parts}")
}

fn normalize_etag(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_canonical_utc(value: &str) -> bool {
    value.len() == 20
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[13] == b':'
        && value.as_bytes()[16] == b':'
        && value.as_bytes()[19] == b'Z'
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

fn read_stable_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "{label} is not a regular file");
    ensure!(before.nlink() == 1, "{label} has multiple hard links");
    ensure!(before.len() <= maximum, "{label} exceeds size bound");
    let mut bytes = Vec::with_capacity(usize::try_from(before.len())?);
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "{label} exceeds size bound");
    let after = file.metadata()?;
    ensure!(
        identity(&before) == identity(&after),
        "{label} changed while read"
    );
    ensure!(
        regular_identity(path)? == identity(&after),
        "{label} namespace changed while read"
    );
    Ok(bytes)
}

async fn remote_sidecar(client: &Client, bucket: &str, key: &str) -> Result<Option<Vec<u8>>> {
    match client.get_object().bucket(bucket).key(key).send().await {
        Ok(response) => {
            let bytes = response.body.collect().await?.into_bytes();
            ensure!(
                bytes.len() <= MAX_SIDECAR_BYTES as usize,
                "remote sidecar is oversized"
            );
            Ok(Some(bytes.to_vec()))
        }
        Err(error) if error.as_service_error().is_some_and(|e| e.is_no_such_key()) => Ok(None),
        Err(error) => Err(error).context("failed to fetch remote sidecar"),
    }
}

#[derive(Debug)]
struct RemoteArchive {
    length: u64,
    etag: String,
    metadata_sha256: Option<String>,
    composite_sha256: Option<String>,
    checksum_type: Option<ChecksumType>,
    multipart_part_size: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum InventoryState {
    Missing,
    ArchiveOnly,
    SidecarOnly,
    InvalidSidecar,
    MetadataMismatch,
    ReadyPair,
}

#[derive(Debug, Serialize)]
struct InventoryEntry {
    epoch: u64,
    state: InventoryState,
    archive_length: Option<u64>,
    archive_etag: Option<String>,
    archive_metadata_sha256: Option<String>,
    sidecar_sha256: Option<String>,
    native_composite_sha256: bool,
}

#[derive(Debug, Serialize)]
struct InventoryReport {
    schema: &'static str,
    first_epoch: u64,
    last_epoch: u64,
    requested_epochs: usize,
    ready_pairs: usize,
    archive_only: usize,
    missing: usize,
    anomalies: usize,
    entries: Vec<InventoryEntry>,
}

fn parse_canonical_sidecar(epoch: u64, sidecar: &[u8]) -> Option<String> {
    let expected_suffix = format!("  epoch-{epoch}.jet\n");
    if sidecar.len() != 64 + expected_suffix.len() || &sidecar[64..] != expected_suffix.as_bytes() {
        return None;
    }
    let digest = std::str::from_utf8(&sidecar[..64]).ok()?;
    if !digest
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    Some(digest.to_owned())
}

fn classify_inventory_entry(
    epoch: u64,
    archive: Option<RemoteArchive>,
    sidecar: Option<Vec<u8>>,
) -> InventoryEntry {
    let sidecar_sha256 = sidecar
        .as_deref()
        .and_then(|bytes| parse_canonical_sidecar(epoch, bytes));
    let state = match (&archive, &sidecar, &sidecar_sha256) {
        (None, None, _) => InventoryState::Missing,
        (Some(_), None, _) => InventoryState::ArchiveOnly,
        (None, Some(_), _) => InventoryState::SidecarOnly,
        (Some(_), Some(_), None) => InventoryState::InvalidSidecar,
        (Some(archive), Some(_), Some(digest))
            if archive
                .metadata_sha256
                .as_deref()
                .is_some_and(|metadata| metadata != digest) =>
        {
            InventoryState::MetadataMismatch
        }
        (Some(_), Some(_), Some(_)) => InventoryState::ReadyPair,
    };
    InventoryEntry {
        epoch,
        state,
        archive_length: archive.as_ref().map(|value| value.length),
        archive_etag: archive.as_ref().map(|value| value.etag.clone()),
        archive_metadata_sha256: archive
            .as_ref()
            .and_then(|value| value.metadata_sha256.clone()),
        sidecar_sha256,
        native_composite_sha256: archive
            .as_ref()
            .is_some_and(|value| value.composite_sha256.is_some()),
    }
}

async fn inventory_epoch(client: &Client, r2: &R2Config, epoch: u64) -> Result<InventoryEntry> {
    let archive_key = format!("epoch-{epoch}.jet");
    let checksum_key = format!("epoch-{epoch}.jet.sha256");
    let archive = head_archive(client, &r2.bucket, &archive_key).await?;
    let sidecar = remote_sidecar(client, &r2.bucket, &checksum_key).await?;
    Ok(classify_inventory_entry(epoch, archive, sidecar))
}

fn inventory_report(entries: Vec<InventoryEntry>) -> InventoryReport {
    let first_epoch = entries.first().map_or(0, |entry| entry.epoch);
    let last_epoch = entries.last().map_or(0, |entry| entry.epoch);
    let count = |state| entries.iter().filter(|entry| entry.state == state).count();
    let ready_pairs = count(InventoryState::ReadyPair);
    let archive_only = count(InventoryState::ArchiveOnly);
    let missing = count(InventoryState::Missing);
    let anomalies = entries.len() - ready_pairs - archive_only - missing;
    InventoryReport {
        schema: "jetstreamer-horizon-r2-inventory-v1",
        first_epoch,
        last_epoch,
        requested_epochs: entries.len(),
        ready_pairs,
        archive_only,
        missing,
        anomalies,
        entries,
    }
}

fn parse_public_content_range(value: &str) -> Result<u64> {
    let total = value
        .strip_prefix("bytes 0-0/")
        .ok_or_else(|| anyhow!("public archive returned an unexpected Content-Range"))?;
    let total = total
        .parse::<u64>()
        .context("public archive Content-Range has an invalid length")?;
    ensure!(total > 0, "public archive is empty");
    Ok(total)
}

async fn verify_public_pair(
    http: &HttpClient,
    public: &PublicConfig,
    bucket: &str,
    epoch: u64,
    archive: &RemoteArchive,
    sidecar: &[u8],
) -> Result<PublicReceipt> {
    let archive_key = format!("epoch-{epoch}.jet");
    let checksum_key = format!("epoch-{epoch}.jet.sha256");
    let archive_url = public_object_url(public, &archive_key)?;
    let checksum_url = public_object_url(public, &checksum_key)?;

    let archive_response = http
        .get(archive_url.clone())
        .header(RANGE, "bytes=0-0")
        .send()
        .await
        .context("anonymous public archive GET failed")?;
    ensure!(
        archive_response.status() == StatusCode::PARTIAL_CONTENT,
        "anonymous public archive GET returned HTTP {}",
        archive_response.status()
    );
    let public_archive_length = parse_public_content_range(
        archive_response
            .headers()
            .get(CONTENT_RANGE)
            .ok_or_else(|| anyhow!("public archive response has no Content-Range"))?
            .to_str()
            .context("public archive Content-Range is not ASCII")?,
    )?;
    ensure!(
        public_archive_length == archive.length,
        "public archive length differs from authenticated R2"
    );
    let public_archive_etag = normalize_etag(
        archive_response
            .headers()
            .get(ETAG)
            .ok_or_else(|| anyhow!("public archive response has no ETag"))?
            .to_str()
            .context("public archive ETag is not ASCII")?,
    );
    ensure!(
        public_archive_etag == archive.etag,
        "public archive ETag differs from authenticated R2"
    );
    ensure!(
        archive_response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            == Some("1"),
        "public archive range response does not contain exactly one byte"
    );
    ensure!(
        archive_response.bytes().await?.len() == 1,
        "public archive range body does not contain exactly one byte"
    );

    let checksum_response = http
        .get(checksum_url.clone())
        .send()
        .await
        .context("anonymous public sidecar GET failed")?;
    ensure!(
        checksum_response.status() == StatusCode::OK,
        "anonymous public sidecar GET returned HTTP {}",
        checksum_response.status()
    );
    let public_sidecar_length = checksum_response
        .headers()
        .get(CONTENT_LENGTH)
        .ok_or_else(|| anyhow!("public sidecar response has no Content-Length"))?
        .to_str()
        .context("public sidecar Content-Length is not ASCII")?
        .parse::<u64>()
        .context("public sidecar Content-Length is invalid")?;
    ensure!(
        public_sidecar_length <= MAX_SIDECAR_BYTES,
        "public sidecar is oversized"
    );
    let public_sidecar = checksum_response.bytes().await?;
    ensure!(
        public_sidecar.len() == usize::try_from(public_sidecar_length)?,
        "public sidecar body length differs from Content-Length"
    );
    ensure!(
        public_sidecar.as_ref() == sidecar,
        "public sidecar differs from authenticated R2"
    );
    let archive_sha256 = parse_canonical_sidecar(epoch, sidecar)
        .ok_or_else(|| anyhow!("authenticated R2 sidecar is not canonical"))?;
    if let Some(metadata_sha256) = &archive.metadata_sha256 {
        ensure!(
            metadata_sha256 == &archive_sha256,
            "authenticated R2 archive metadata differs from its sidecar"
        );
    }

    Ok(PublicReceipt {
        schema: PUBLIC_RECEIPT_SCHEMA.to_owned(),
        bucket: bucket.to_owned(),
        epoch,
        archive_key,
        checksum_key,
        public_base_url: public.base_url.as_str().to_owned(),
        public_archive_url: archive_url.as_str().to_owned(),
        public_checksum_url: checksum_url.as_str().to_owned(),
        archive_length: archive.length,
        archive_etag: archive.etag.clone(),
        archive_sha256,
        verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    })
}

async fn public_verify_epoch(
    s3: &Client,
    http: &HttpClient,
    r2: &R2Config,
    public: &PublicConfig,
    receipt_directory: &Path,
    epoch: u64,
) -> Result<PathBuf> {
    let archive_key = format!("epoch-{epoch}.jet");
    let checksum_key = format!("epoch-{epoch}.jet.sha256");
    let archive = head_archive(s3, &r2.bucket, &archive_key)
        .await?
        .ok_or_else(|| anyhow!("authenticated R2 archive is missing"))?;
    let sidecar = remote_sidecar(s3, &r2.bucket, &checksum_key)
        .await?
        .ok_or_else(|| anyhow!("authenticated R2 sidecar is missing"))?;
    let receipt = verify_public_pair(http, public, &r2.bucket, epoch, &archive, &sidecar).await?;
    write_public_receipt(receipt_directory, &receipt)
}

#[derive(Debug)]
struct MutableRemoteObject {
    bytes: Vec<u8>,
    etag: String,
}

async fn get_mutable_object(
    client: &Client,
    bucket: &str,
    key: &str,
) -> Result<Option<MutableRemoteObject>> {
    match client.get_object().bucket(bucket).key(key).send().await {
        Ok(response) => {
            let length = u64::try_from(response.content_length().unwrap_or(-1))
                .context("mutable R2 object has invalid length")?;
            ensure!(length <= MAX_STATUS_BYTES, "mutable R2 object is oversized");
            let etag = response
                .e_tag()
                .ok_or_else(|| anyhow!("mutable R2 object has no ETag"))?;
            let etag = normalize_etag(etag).to_owned();
            ensure!(!etag.is_empty(), "mutable R2 object has an empty ETag");
            let bytes = response.body.collect().await?.into_bytes().to_vec();
            ensure!(
                u64::try_from(bytes.len())? == length,
                "mutable R2 object length changed during readback"
            );
            Ok(Some(MutableRemoteObject { bytes, etag }))
        }
        Err(error) if error.as_service_error().is_some_and(|e| e.is_no_such_key()) => Ok(None),
        Err(error) => Err(error).context("failed to fetch mutable R2 object"),
    }
}

fn observer_string<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str> {
    let mut current = value;
    for name in path {
        current = current
            .get(*name)
            .ok_or_else(|| anyhow!("observer receipt omits {}", path.join(".")))?;
    }
    current
        .as_str()
        .ok_or_else(|| anyhow!("observer receipt {} is not a string", path.join(".")))
}

fn observer_u64(value: &Value, path: &[&str]) -> Result<u64> {
    let mut current = value;
    for name in path {
        current = current
            .get(*name)
            .ok_or_else(|| anyhow!("observer receipt omits {}", path.join(".")))?;
    }
    current
        .as_u64()
        .ok_or_else(|| anyhow!("observer receipt {} is not a u64", path.join(".")))
}

fn validate_observer_binding(
    bytes: &[u8],
    expected_sha256: &str,
    epoch: u64,
    expected_controller_invocation_id: &str,
    expected_producer_invocation_id: &str,
) -> Result<String> {
    ensure!(
        hex_lower(&Sha256::digest(bytes)) == expected_sha256,
        "observer receipt SHA-256 mismatch"
    );
    let value: Value = serde_json::from_slice(bytes).context("invalid observer receipt JSON")?;
    ensure!(
        observer_string(&value, &["schema"])? == "jetstreamer-horizon-live-resource-sample-v2",
        "unsupported observer receipt schema"
    );
    let sampled_at_utc = observer_string(&value, &["recorded_at_utc"])?;
    ensure!(
        is_canonical_utc(sampled_at_utc),
        "observer receipt recorded_at_utc is not canonical UTC"
    );
    for name in [
        "producer_or_controller_signals_sent",
        "service_state_changed",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            value
                .get("mutation")
                .and_then(|mutation| mutation.get(name))
                .and_then(Value::as_bool)
                == Some(false),
            "observer receipt reports mutation or omits mutation.{name}"
        );
    }
    let replays = value
        .get("replays")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("observer receipt replays is not an array"))?;
    let mut matches = replays.iter().filter(|replay| {
        replay
            .get("range")
            .and_then(Value::as_str)
            .and_then(|range| parse_observer_claim_range(range).ok())
            .is_some_and(|epochs| epochs.contains(&epoch))
    });
    let replay = matches
        .next()
        .ok_or_else(|| anyhow!("observer receipt has no replay claim for epoch {epoch}"))?;
    ensure!(
        matches.next().is_none(),
        "observer receipt has overlapping replay claims for epoch {epoch}"
    );
    ensure!(
        replay
            .get("invocation_binding_stable")
            .and_then(Value::as_bool)
            == Some(true),
        "observer invocation binding is not stable"
    );
    for point in ["controller_before", "controller_after"] {
        ensure!(
            observer_string(replay, &[point, "invocation_id"])?
                == expected_controller_invocation_id,
            "observer controller invocation ID mismatch"
        );
        ensure!(
            observer_u64(replay, &[point, "restarts"])? == 0,
            "observer controller has restarted"
        );
    }
    for point in ["producer_before", "producer_after"] {
        ensure!(
            observer_string(replay, &[point, "invocation_id"])? == expected_producer_invocation_id,
            "observer producer invocation ID mismatch"
        );
        ensure!(
            observer_u64(replay, &[point, "restarts"])? == 0,
            "observer producer has restarted"
        );
    }
    ensure!(
        observer_string(replay, &["useful_work", "journal_invocation_id"])?
            == expected_producer_invocation_id,
        "observer progress is bound to a different producer invocation"
    );
    Ok(sampled_at_utc.to_owned())
}

fn current_jet_size(directory: &Path, epoch: u64) -> Result<u64> {
    let path = directory.join(format!("epoch-{epoch}.jet"));
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file(),
                "current .jet is not a regular file"
            );
            ensure!(
                metadata.nlink() == 1,
                "current .jet has multiple hard links"
            );
            Ok(metadata.len())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error).with_context(|| format!("failed to stat {}", path.display())),
    }
}

fn status_receipt_path(directory: &Path, status: &EpochStatus) -> PathBuf {
    let timestamp = status
        .sampled_at_utc
        .bytes()
        .filter(|byte| byte.is_ascii_digit())
        .map(char::from)
        .collect::<String>();
    directory.join(format!("epoch-{}.status-{timestamp}.json", status.epoch))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusPublicationAction {
    Replace,
    RecoverReceipt,
}

fn validate_status_publication_after_sidecar(
    action: StatusPublicationAction,
    sidecar_is_committed: bool,
) -> Result<()> {
    ensure!(
        !sidecar_is_committed || action == StatusPublicationAction::RecoverReceipt,
        "canonical sidecar is already committed; status replacement is forbidden"
    );
    Ok(())
}

fn status_publication_action(
    previous: &EpochStatus,
    proposed: &EpochStatus,
) -> Result<StatusPublicationAction> {
    validate_epoch_status(previous, proposed.epoch)?;
    validate_epoch_status(proposed, proposed.epoch)?;
    ensure!(
        previous.epoch == proposed.epoch,
        "existing status object names a different epoch"
    );
    if previous.sampled_at_utc == proposed.sampled_at_utc {
        ensure!(
            previous == proposed,
            "existing status sample has the proposed timestamp but different content"
        );
        return Ok(StatusPublicationAction::RecoverReceipt);
    }
    ensure!(
        previous.sampled_at_utc < proposed.sampled_at_utc,
        "existing status sample is not older than the proposed sample"
    );
    Ok(StatusPublicationAction::Replace)
}

fn validate_epoch_status(status: &EpochStatus, expected_epoch: u64) -> Result<()> {
    ensure!(
        status.epoch == expected_epoch,
        "status object names a different epoch"
    );
    ensure!(
        is_canonical_utc(&status.sampled_at_utc),
        "status object sampled_at_utc is not canonical UTC"
    );
    ensure!(
        matches!(
            status.phase.as_str(),
            "replay" | "verification" | "upload" | "readback"
        ),
        "status object phase is invalid"
    );
    Ok(())
}

fn epoch_status_bytes(status: &EpochStatus) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(status)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= MAX_STATUS_BYTES as usize,
        "status payload is oversized"
    );
    Ok(bytes)
}

fn write_status_receipt(directory: &Path, receipt: &StatusPublicationReceipt) -> Result<PathBuf> {
    fs::create_dir_all(directory)?;
    fs::set_permissions(
        directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let final_path = status_receipt_path(directory, &receipt.status);
    if final_path.exists() {
        let before = regular_identity(&final_path)?;
        ensure!(
            before.length <= MAX_STATUS_BYTES,
            "status receipt is oversized"
        );
        let existing: StatusPublicationReceipt = serde_json::from_slice(&fs::read(&final_path)?)?;
        ensure!(
            regular_identity(&final_path)? == before,
            "status receipt changed while read"
        );
        ensure!(existing == *receipt, "existing status receipt differs");
        return Ok(final_path);
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(&format!(".epoch-{}.status.", receipt.epoch))
        .suffix(".tmp")
        .tempfile_in(directory)?;
    temporary
        .as_file_mut()
        .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), receipt)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist_noclobber(&final_path).map_err(|error| {
        anyhow!(
            "failed to publish {}: {}",
            final_path.display(),
            error.error
        )
    })?;
    File::open(directory)?.sync_all()?;
    Ok(final_path)
}

async fn status_publish(
    s3: &Client,
    r2: &R2Config,
    config: &Config,
    epoch: u64,
) -> Result<PathBuf> {
    let observer_receipt = config.observer_receipt.as_deref().expect("validated");
    let observer_bytes = read_stable_bounded(
        observer_receipt,
        MAX_OBSERVER_RECEIPT_BYTES,
        "observer receipt",
    )?;
    let sampled_at_utc = validate_observer_binding(
        &observer_bytes,
        config.observer_sha256.as_deref().expect("validated"),
        epoch,
        config
            .expected_controller_invocation_id
            .as_deref()
            .expect("validated"),
        config
            .expected_producer_invocation_id
            .as_deref()
            .expect("validated"),
    )?;
    let status = EpochStatus {
        epoch,
        jet_size_bytes: current_jet_size(&config.directory, epoch)?,
        elapsed_execution_millis: config.elapsed_execution_millis.expect("validated"),
        estimated_remaining_millis: config.estimated_remaining_millis.expect("validated"),
        sampled_at_utc,
        phase: config.phase.clone().expect("validated"),
    };
    validate_epoch_status(&status, epoch)?;
    let status_bytes = epoch_status_bytes(&status)?;
    let key = format!("epoch-{epoch}.epoch-status.json");
    let previous = get_mutable_object(s3, &r2.bucket, &key).await?;
    let action = if let Some(previous) = &previous {
        let previous_status: EpochStatus =
            serde_json::from_slice(&previous.bytes).context("existing status JSON is invalid")?;
        status_publication_action(&previous_status, &status)?
    } else {
        StatusPublicationAction::Replace
    };
    let checksum_key = format!("epoch-{epoch}.jet.sha256");
    let sidecar_is_committed = remote_sidecar(s3, &r2.bucket, &checksum_key)
        .await?
        .is_some();
    validate_status_publication_after_sidecar(action, sidecar_is_committed)?;
    if action == StatusPublicationAction::Replace {
        let content_md5 = BASE64_STANDARD.encode(Md5::digest(&status_bytes));
        let request = s3
            .put_object()
            .bucket(&r2.bucket)
            .key(&key)
            .content_type("application/json; charset=utf-8")
            .cache_control("no-store")
            .content_md5(content_md5)
            .body(ByteStream::from(status_bytes.clone()));
        let request = if let Some(previous) = &previous {
            request.if_match(format!("\"{}\"", previous.etag))
        } else {
            request.if_none_match("*")
        };
        request
            .send()
            .await
            .map_err(|error| anyhow!("conditional status publication failed: {error:?}"))?;
    }
    let authenticated = get_mutable_object(s3, &r2.bucket, &key)
        .await?
        .ok_or_else(|| anyhow!("status object disappeared after publication"))?;
    ensure!(
        authenticated.bytes == status_bytes,
        "authenticated status readback differs from uploaded bytes"
    );
    let receipt = StatusPublicationReceipt {
        schema: STATUS_RECEIPT_SCHEMA.to_owned(),
        bucket: r2.bucket.clone(),
        epoch,
        key,
        status,
        object_etag: authenticated.etag,
        previous_object_etag: previous.map(|value| value.etag),
        observer_receipt: observer_receipt.to_path_buf(),
        observer_receipt_sha256: config.observer_sha256.clone().expect("validated"),
        controller_invocation_id: config
            .expected_controller_invocation_id
            .clone()
            .expect("validated"),
        producer_invocation_id: config
            .expected_producer_invocation_id
            .clone()
            .expect("validated"),
        authenticated_readback: true,
        verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    write_status_receipt(
        config
            .receipt_directory
            .as_deref()
            .expect("status-publish requires receipt directory"),
        &receipt,
    )
}

fn status_deletion_receipt_path(directory: &Path, epoch: u64) -> PathBuf {
    directory.join(format!("epoch-{epoch}.status-deletion.json"))
}

fn write_status_deletion_receipt(
    directory: &Path,
    receipt: &StatusDeletionReceipt,
) -> Result<PathBuf> {
    fs::create_dir_all(directory)?;
    fs::set_permissions(
        directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let final_path = status_deletion_receipt_path(directory, receipt.epoch);
    if final_path.exists() {
        let before = regular_identity(&final_path)?;
        ensure!(
            before.length <= MAX_STATUS_BYTES,
            "status deletion receipt is oversized"
        );
        let existing: StatusDeletionReceipt = serde_json::from_slice(&fs::read(&final_path)?)?;
        ensure!(
            regular_identity(&final_path)? == before,
            "status deletion receipt changed while read"
        );
        ensure!(
            existing == *receipt,
            "existing status deletion receipt differs"
        );
        return Ok(final_path);
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(&format!(".epoch-{}.status-deletion.", receipt.epoch))
        .suffix(".tmp")
        .tempfile_in(directory)?;
    temporary
        .as_file_mut()
        .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), receipt)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist_noclobber(&final_path).map_err(|error| {
        anyhow!(
            "failed to publish {}: {}",
            final_path.display(),
            error.error
        )
    })?;
    File::open(directory)?.sync_all()?;
    Ok(final_path)
}

fn read_bound_status_publication_receipt(
    directory: &Path,
    path: &Path,
    expected_sha256: &str,
    bucket: &str,
    epoch: u64,
) -> Result<(StatusPublicationReceipt, String)> {
    let bytes = read_stable_bounded(path, MAX_STATUS_BYTES, "status publication receipt")?;
    let actual_sha256 = hex_lower(&Sha256::digest(&bytes));
    ensure!(
        actual_sha256 == expected_sha256,
        "status publication receipt SHA-256 mismatch"
    );
    let receipt =
        validate_status_publication_receipt_bytes(directory, path, &bytes, bucket, epoch)?;
    Ok((receipt, actual_sha256))
}

fn validate_status_publication_receipt_bytes(
    directory: &Path,
    path: &Path,
    bytes: &[u8],
    bucket: &str,
    epoch: u64,
) -> Result<StatusPublicationReceipt> {
    let receipt: StatusPublicationReceipt =
        serde_json::from_slice(bytes).context("invalid status publication receipt JSON")?;
    ensure!(
        receipt.schema == STATUS_RECEIPT_SCHEMA,
        "unsupported status publication receipt schema"
    );
    ensure!(
        receipt.bucket == bucket,
        "status receipt names a different bucket"
    );
    ensure!(
        receipt.epoch == epoch,
        "status receipt names a different epoch"
    );
    ensure!(
        receipt.key == format!("epoch-{epoch}.epoch-status.json"),
        "status receipt contains a noncanonical object key"
    );
    ensure!(
        receipt.authenticated_readback,
        "status receipt lacks authenticated readback"
    );
    ensure!(
        !receipt.object_etag.is_empty(),
        "status receipt has an empty object ETag"
    );
    validate_epoch_status(&receipt.status, epoch)?;
    ensure!(
        path == status_receipt_path(directory, &receipt.status),
        "status publication receipt path is noncanonical"
    );
    Ok(receipt)
}

fn latest_status_publication_receipt(
    directory: &Path,
    bucket: &str,
    epoch: u64,
) -> Result<(StatusPublicationReceipt, PathBuf, String)> {
    let prefix = format!("epoch-{epoch}.status-");
    let mut latest: Option<(StatusPublicationReceipt, PathBuf, String)> = None;
    for entry in fs::read_dir(directory).with_context(|| {
        format!(
            "failed to read status receipt directory {}",
            directory.display()
        )
    })? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(timestamp) = name
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(".json"))
        else {
            continue;
        };
        if timestamp.len() != 14 || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let path = entry.path();
        let bytes = read_stable_bounded(&path, MAX_STATUS_BYTES, "status publication receipt")?;
        let receipt =
            validate_status_publication_receipt_bytes(directory, &path, &bytes, bucket, epoch)?;
        let digest = hex_lower(&Sha256::digest(&bytes));
        if latest.as_ref().is_none_or(|(current, _, _)| {
            current.status.sampled_at_utc < receipt.status.sampled_at_utc
        }) {
            latest = Some((receipt, path, digest));
        }
    }
    latest
        .ok_or_else(|| anyhow!("no canonical status publication receipt exists for epoch {epoch}"))
}

async fn validate_authenticated_ready_pair(
    client: &Client,
    bucket: &str,
    receipt: &Receipt,
) -> Result<()> {
    let remote = head_archive(client, bucket, &receipt.archive_key)
        .await?
        .ok_or_else(|| anyhow!("remote archive is missing"))?;
    validate_remote_against_receipt(&remote, receipt)?;
    ensure!(
        remote_sidecar(client, bucket, &receipt.checksum_key)
            .await?
            .as_deref()
            == Some(canonical_sidecar(receipt).as_slice()),
        "remote checksum sidecar differs from the durable R2 receipt"
    );
    Ok(())
}

async fn status_delete(s3: &Client, r2: &R2Config, config: &Config, epoch: u64) -> Result<PathBuf> {
    let status_receipt_directory = config
        .receipt_directory
        .as_deref()
        .expect("status-delete requires receipt directory");
    let (publication, status_publication_receipt, publication_sha256) =
        if config.latest_status_publication_receipt {
            latest_status_publication_receipt(status_receipt_directory, &r2.bucket, epoch)?
        } else {
            let path = config
                .status_publication_receipt
                .as_deref()
                .expect("validated");
            let (publication, digest) = read_bound_status_publication_receipt(
                status_receipt_directory,
                path,
                config
                    .status_publication_sha256
                    .as_deref()
                    .expect("validated"),
                &r2.bucket,
                epoch,
            )?;
            (publication, path.to_path_buf(), digest)
        };

    let archive_receipt_directory = config
        .archive_receipt_directory
        .as_deref()
        .expect("validated");
    let archive_receipt_path = receipt_path(archive_receipt_directory, epoch);
    let archive_receipt = read_restore_receipt(archive_receipt_directory, &r2.bucket, epoch)?;
    ensure!(
        archive_receipt.remote_sha256_readback || archive_receipt.r2_composite_sha256.is_some(),
        "R2 receipt lacks a durable whole-object SHA-256 proof"
    );
    let archive_receipt_bytes = read_stable_bounded(
        &archive_receipt_path,
        MAX_STATUS_BYTES,
        "archive R2 receipt",
    )?;
    let rebound_archive_receipt: Receipt = serde_json::from_slice(&archive_receipt_bytes)?;
    ensure!(
        rebound_archive_receipt == archive_receipt,
        "archive R2 receipt changed between validation reads"
    );
    let archive_receipt_sha256 = hex_lower(&Sha256::digest(&archive_receipt_bytes));

    validate_authenticated_ready_pair(s3, &r2.bucket, &archive_receipt).await?;

    let key = format!("epoch-{epoch}.epoch-status.json");
    let deletion_receipt_path = status_deletion_receipt_path(status_receipt_directory, epoch);
    if deletion_receipt_path.exists() {
        let bytes = read_stable_bounded(
            &deletion_receipt_path,
            MAX_STATUS_BYTES,
            "status deletion receipt",
        )?;
        let existing: StatusDeletionReceipt = serde_json::from_slice(&bytes)?;
        ensure!(
            existing.schema == STATUS_DELETION_RECEIPT_SCHEMA
                && existing.bucket == r2.bucket
                && existing.epoch == epoch
                && existing.key == key
                && existing.deleted_object_etag == publication.object_etag
                && existing.deleted_status == publication.status
                && existing.status_publication_receipt == status_publication_receipt
                && existing.status_publication_receipt_sha256 == publication_sha256
                && existing.archive_receipt == archive_receipt_path
                && existing.archive_receipt_sha256 == archive_receipt_sha256
                && existing.archive_sha256 == archive_receipt.archive_sha256
                && existing.archive_etag == archive_receipt.archive_etag
                && existing.authenticated_ready_pair_before
                && existing.authenticated_status_absent_after
                && existing.authenticated_ready_pair_after,
            "existing status deletion receipt differs from the bound completion evidence"
        );
        ensure!(
            get_mutable_object(s3, &r2.bucket, &key).await?.is_none(),
            "status object reappeared after its deletion receipt"
        );
        validate_authenticated_ready_pair(s3, &r2.bucket, &archive_receipt).await?;
        return Ok(deletion_receipt_path);
    }
    let current = get_mutable_object(s3, &r2.bucket, &key).await?;
    let conditional_delete_request_sent = if let Some(current) = current {
        ensure!(
            current.etag == publication.object_etag,
            "current status ETag differs from the bound publication receipt"
        );
        ensure!(
            current.bytes == epoch_status_bytes(&publication.status)?,
            "current status bytes differ from the bound publication receipt"
        );
        s3.delete_object()
            .bucket(&r2.bucket)
            .key(&key)
            .if_match(format!("\"{}\"", current.etag))
            .send()
            .await
            .map_err(|error| anyhow!("conditional status deletion failed: {error:?}"))?;
        true
    } else {
        false
    };

    ensure!(
        get_mutable_object(s3, &r2.bucket, &key).await?.is_none(),
        "status object still exists after deletion"
    );
    validate_authenticated_ready_pair(s3, &r2.bucket, &archive_receipt).await?;

    let deletion_receipt = StatusDeletionReceipt {
        schema: STATUS_DELETION_RECEIPT_SCHEMA.to_owned(),
        bucket: r2.bucket.clone(),
        epoch,
        key,
        deleted_object_etag: publication.object_etag,
        deleted_status: publication.status,
        status_publication_receipt,
        status_publication_receipt_sha256: publication_sha256,
        archive_receipt: archive_receipt_path,
        archive_receipt_sha256,
        archive_sha256: archive_receipt.archive_sha256,
        archive_etag: archive_receipt.archive_etag,
        conditional_delete_request_sent,
        authenticated_ready_pair_before: true,
        authenticated_status_absent_after: true,
        authenticated_ready_pair_after: true,
        verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    write_status_deletion_receipt(status_receipt_directory, &deletion_receipt)
}

async fn head_archive(client: &Client, bucket: &str, key: &str) -> Result<Option<RemoteArchive>> {
    match client
        .head_object()
        .bucket(bucket)
        .key(key)
        .checksum_mode(ChecksumMode::Enabled)
        .send()
        .await
    {
        Ok(response) => {
            let length = u64::try_from(response.content_length().unwrap_or(-1))
                .context("remote archive has invalid length")?;
            let etag = response
                .e_tag()
                .ok_or_else(|| anyhow!("remote archive has no ETag"))?;
            Ok(Some(RemoteArchive {
                length,
                etag: normalize_etag(etag).to_owned(),
                metadata_sha256: response.metadata().and_then(|m| m.get("sha256").cloned()),
                composite_sha256: response.checksum_sha256().map(str::to_owned),
                checksum_type: response.checksum_type().cloned(),
                multipart_part_size: response
                    .metadata()
                    .and_then(|metadata| metadata.get("multipart-part-size"))
                    .map(|value| value.parse::<u64>())
                    .transpose()
                    .context("remote multipart-part-size metadata is invalid")?,
            }))
        }
        Err(error) if error.as_service_error().is_some_and(|e| e.is_not_found()) => Ok(None),
        Err(error) => Err(error).context("failed to stat remote archive"),
    }
}

fn read_part(
    path: &Path,
    expected: FileIdentity,
    offset: u64,
    length: usize,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed before part read"
    );
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0u8; length];
    file.read_exact(&mut bytes)?;
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed during part read"
    );
    let digest = Md5::digest(&bytes).to_vec();
    let sha256 = Sha256::digest(&bytes).to_vec();
    Ok((bytes, digest, sha256))
}

async fn upload_archive(
    client: &Client,
    bucket: &str,
    local: &LocalArchive,
    part_size: u64,
    concurrency: usize,
    overwrite_existing: bool,
) -> Result<(String, String)> {
    let key = format!("epoch-{}.jet", local.epoch);
    let created = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(&key)
        .content_type("application/octet-stream")
        .metadata("sha256", &local.sha256_hex)
        .metadata("horizon-format", "jet")
        .metadata("multipart-part-size", part_size.to_string())
        .send()
        .await
        .context("failed to create multipart upload")?;
    let upload_id = created
        .upload_id()
        .ok_or_else(|| anyhow!("R2 returned no upload ID"))?
        .to_owned();
    let operation = async {
        let part_count = local.length.div_ceil(part_size);
        ensure!(
            part_count > 0 && part_count <= 10_000,
            "invalid multipart part count"
        );
        let mut tasks = tokio::task::JoinSet::new();
        let mut next_part = 0u64;
        let mut uploaded = Vec::with_capacity(usize::try_from(part_count)?);
        while next_part < part_count || !tasks.is_empty() {
            while next_part < part_count && tasks.len() < concurrency {
                let part_index = next_part;
                next_part += 1;
                let client = client.clone();
                let bucket = bucket.to_owned();
                let key = key.clone();
                let upload_id = upload_id.clone();
                let path = local.archive_path.clone();
                let expected = local.identity;
                let offset = part_index * part_size;
                let length = usize::try_from((local.length - offset).min(part_size))?;
                tasks.spawn(async move {
                    let (bytes, digest, sha256) = tokio::task::spawn_blocking(move || {
                        read_part(&path, expected, offset, length)
                    })
                    .await??;
                    let content_md5 = BASE64_STANDARD.encode(&digest);
                    let part_number = i32::try_from(part_index + 1)?;
                    let mut response = None;
                    let mut last_error = None;
                    for attempt in 1..=MAX_PART_ATTEMPTS {
                        match client
                            .upload_part()
                            .bucket(&bucket)
                            .key(&key)
                            .upload_id(&upload_id)
                            .part_number(part_number)
                            .content_length(i64::try_from(length)?)
                            .content_md5(&content_md5)
                            .body(ByteStream::from(bytes.clone()))
                            .send()
                            .await
                        {
                            Ok(output) => {
                                response = Some(output);
                                break;
                            }
                            Err(error) => {
                                last_error = Some(format!("{error:?}"));
                                if attempt < MAX_PART_ATTEMPTS {
                                    tokio::time::sleep(std::time::Duration::from_secs(
                                        (1u64 << (attempt - 1)).min(30),
                                    ))
                                    .await;
                                }
                            }
                        }
                    }
                    let response = response.ok_or_else(|| {
                        anyhow!(
                            "R2 part {part_number} failed after {MAX_PART_ATTEMPTS} attempts: {}",
                            last_error.unwrap_or_else(|| "unknown error".to_owned())
                        )
                    })?;
                    let etag = response
                        .e_tag()
                        .ok_or_else(|| anyhow!("R2 part has no ETag"))?;
                    let digest_hex = hex_lower(&digest);
                    // R2 documents each part ETag as the MD5 of that part.
                    ensure!(normalize_etag(etag) == digest_hex, "R2 part ETag mismatch");
                    Ok::<_, anyhow::Error>((part_index, etag.to_owned(), digest, sha256))
                });
            }
            if let Some(result) = tasks.join_next().await {
                uploaded.push(result??);
            }
        }
        uploaded.sort_by_key(|item| item.0);
        let expected_etag = multipart_etag(
            &uploaded
                .iter()
                .map(|item| item.2.clone())
                .collect::<Vec<_>>(),
        );
        let expected_composite_sha256 = composite_sha256(
            &uploaded
                .iter()
                .map(|item| item.3.clone())
                .collect::<Vec<_>>(),
        );
        let parts = uploaded
            .into_iter()
            .map(|(index, etag, _, _)| {
                CompletedPart::builder()
                    .part_number(i32::try_from(index + 1).expect("part count bounded"))
                    .e_tag(etag)
                    .build()
            })
            .collect::<Vec<_>>();
        let request = client
            .complete_multipart_upload()
            .bucket(bucket)
            .key(&key)
            .upload_id(&upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build(),
            );
        let request = if overwrite_existing {
            request
        } else {
            request.if_none_match("*")
        };
        let response = request
            .send()
            .await
            .map_err(|error| anyhow!("failed to complete multipart upload: {error:?}"))?;
        let actual = response
            .e_tag()
            .ok_or_else(|| anyhow!("completed object has no ETag"))?;
        ensure!(
            normalize_etag(actual) == expected_etag,
            "completed multipart ETag mismatch"
        );
        Ok::<_, anyhow::Error>((expected_etag, expected_composite_sha256))
    }
    .await;
    if operation.is_err() {
        // This only discards an incomplete multipart staging area. It can never
        // remove or alter a completed R2 object.
        if let Err(error) = client
            .abort_multipart_upload()
            .bucket(bucket)
            .key(&key)
            .upload_id(&upload_id)
            .send()
            .await
        {
            eprintln!("warning: failed to abort incomplete multipart upload for {key}: {error:?}");
        }
    }
    operation
}

async fn put_sidecar(
    client: &Client,
    bucket: &str,
    local: &LocalArchive,
    overwrite_existing: bool,
) -> Result<()> {
    let key = format!("epoch-{}.jet.sha256", local.epoch);
    let content_md5 = BASE64_STANDARD.encode(Md5::digest(&local.sidecar));
    let request = client
        .put_object()
        .bucket(bucket)
        .key(&key)
        .content_type("text/plain; charset=us-ascii")
        .content_md5(content_md5)
        .body(ByteStream::from(local.sidecar.clone()));
    let request = if overwrite_existing {
        request
    } else {
        request.if_none_match("*")
    };
    match request.send().await {
        Ok(_) => Ok(()),
        Err(error) => {
            // A racing append-only writer may have won. It is acceptable only
            // if the canonical object is already byte-for-byte identical.
            if remote_sidecar(client, bucket, &key).await?.as_deref() == Some(&local.sidecar) {
                Ok(())
            } else {
                Err(error).context("failed to create immutable checksum sidecar")
            }
        }
    }
}

fn receipt_path(directory: &Path, epoch: u64) -> PathBuf {
    directory.join(format!("epoch-{epoch}.r2.json"))
}

fn write_receipt(directory: &Path, receipt: &Receipt, overwrite_existing: bool) -> Result<PathBuf> {
    fs::create_dir_all(directory)?;
    fs::set_permissions(
        directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let final_path = receipt_path(directory, receipt.epoch);
    if final_path.exists() {
        let existing: Receipt = serde_json::from_slice(&fs::read(&final_path)?)?;
        if same_receipt_evidence(&existing, receipt) {
            return Ok(final_path);
        }
        ensure!(
            overwrite_existing,
            "existing R2 receipt differs for epoch {}",
            receipt.epoch
        );
    }
    let temporary = directory.join(format!(
        ".epoch-{}.r2.{}.tmp",
        receipt.epoch,
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    serde_json::to_writer_pretty(&mut file, receipt)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temporary, &final_path)?;
    File::open(directory)?.sync_all()?;
    Ok(final_path)
}

fn same_receipt_evidence(left: &Receipt, right: &Receipt) -> bool {
    left.schema == right.schema
        && left.bucket == right.bucket
        && left.epoch == right.epoch
        && left.archive_key == right.archive_key
        && left.checksum_key == right.checksum_key
        && left.archive_length == right.archive_length
        && left.archive_sha256 == right.archive_sha256
        && left.archive_etag == right.archive_etag
        && left.r2_composite_sha256 == right.r2_composite_sha256
        && left.remote_sha256_readback == right.remote_sha256_readback
        && left.multipart_part_size == right.multipart_part_size
}

fn public_receipt_path(directory: &Path, epoch: u64) -> PathBuf {
    directory.join(format!("epoch-{epoch}.public.json"))
}

fn same_public_receipt_evidence(left: &PublicReceipt, right: &PublicReceipt) -> bool {
    left.schema == right.schema
        && left.bucket == right.bucket
        && left.epoch == right.epoch
        && left.archive_key == right.archive_key
        && left.checksum_key == right.checksum_key
        && left.public_base_url == right.public_base_url
        && left.public_archive_url == right.public_archive_url
        && left.public_checksum_url == right.public_checksum_url
        && left.archive_length == right.archive_length
        && left.archive_etag == right.archive_etag
        && left.archive_sha256 == right.archive_sha256
}

fn write_public_receipt(directory: &Path, receipt: &PublicReceipt) -> Result<PathBuf> {
    fs::create_dir_all(directory)?;
    fs::set_permissions(
        directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let final_path = public_receipt_path(directory, receipt.epoch);
    if final_path.exists() {
        let before = regular_identity(&final_path)?;
        ensure!(before.length <= 16 * 1024, "oversized public-read receipt");
        let existing: PublicReceipt = serde_json::from_slice(&fs::read(&final_path)?)?;
        ensure!(
            regular_identity(&final_path)? == before,
            "public-read receipt changed while read"
        );
        ensure!(
            same_public_receipt_evidence(&existing, receipt),
            "existing public-read receipt differs for epoch {}",
            receipt.epoch
        );
        return Ok(final_path);
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(&format!(".epoch-{}.public.", receipt.epoch))
        .suffix(".tmp")
        .tempfile_in(directory)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), receipt)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist_noclobber(&final_path).map_err(|error| {
        anyhow!(
            "failed to publish {}: {}",
            final_path.display(),
            error.error
        )
    })?;
    File::open(directory)?.sync_all()?;
    Ok(final_path)
}

fn read_restore_receipt(directory: &Path, bucket: &str, epoch: u64) -> Result<Receipt> {
    let path = receipt_path(directory, epoch);
    let before = regular_identity(&path)?;
    ensure!(before.length <= 16 * 1024, "oversized R2 receipt");
    let receipt: Receipt = serde_json::from_slice(&fs::read(&path)?)?;
    ensure!(
        regular_identity(&path)? == before,
        "R2 receipt changed while read"
    );
    ensure!(
        receipt.schema == RECEIPT_SCHEMA,
        "unsupported R2 receipt schema"
    );
    ensure!(
        receipt.bucket == bucket,
        "R2 receipt names a different bucket"
    );
    ensure!(receipt.epoch == epoch, "R2 receipt names a different epoch");
    ensure!(
        receipt.archive_key == format!("epoch-{epoch}.jet")
            && receipt.checksum_key == format!("epoch-{epoch}.jet.sha256"),
        "R2 receipt contains noncanonical object keys"
    );
    ensure!(
        receipt.archive_length > 0,
        "R2 receipt has an empty archive"
    );
    ensure!(
        receipt.archive_sha256.len() == 64
            && receipt
                .archive_sha256
                .bytes()
                .all(|byte| { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() }),
        "R2 receipt has an invalid archive SHA-256"
    );
    ensure!(
        receipt.multipart_part_size >= 5 * 1024 * 1024,
        "R2 receipt has an invalid multipart part size"
    );
    Ok(receipt)
}

fn canonical_sidecar(receipt: &Receipt) -> Vec<u8> {
    format!("{}  epoch-{}.jet\n", receipt.archive_sha256, receipt.epoch).into_bytes()
}

fn validate_restored_archive(path: &Path, receipt: &Receipt) -> Result<()> {
    let identity = regular_identity(path)?;
    ensure!(
        identity.length == receipt.archive_length,
        "restored archive length mismatch"
    );
    let proof = hash_and_etag(path, identity, receipt.multipart_part_size)?;
    ensure!(
        proof.sha256_hex == receipt.archive_sha256,
        "restored archive SHA-256 mismatch"
    );
    ensure!(
        proof.multipart_etag == receipt.archive_etag,
        "restored archive multipart ETag mismatch"
    );
    Ok(())
}

fn validate_restored_sidecar(path: &Path, expected: &[u8]) -> Result<()> {
    let identity = regular_identity(path)?;
    ensure!(
        identity.length <= MAX_SIDECAR_BYTES,
        "restored sidecar is oversized"
    );
    ensure!(fs::read(path)? == expected, "restored sidecar mismatch");
    ensure!(
        regular_identity(path)? == identity,
        "restored sidecar changed while read"
    );
    Ok(())
}

fn validate_remote_against_receipt(remote: &RemoteArchive, receipt: &Receipt) -> Result<()> {
    ensure!(
        remote.length == receipt.archive_length,
        "remote archive length differs from receipt"
    );
    ensure!(
        remote.etag == receipt.archive_etag,
        "remote archive ETag differs from receipt"
    );
    if let Some(metadata_sha256) = &remote.metadata_sha256 {
        ensure!(
            metadata_sha256 == &receipt.archive_sha256,
            "remote archive SHA-256 metadata differs from receipt"
        );
    }
    if let Some(expected) = &receipt.r2_composite_sha256 {
        ensure!(
            remote.checksum_type == Some(ChecksumType::Composite)
                && remote.composite_sha256.as_ref() == Some(expected),
            "remote composite SHA-256 differs from receipt"
        );
    }
    Ok(())
}

fn persist_noclobber(mut temporary: tempfile::NamedTempFile, destination: &Path) -> Result<()> {
    temporary.as_file_mut().sync_all()?;
    fs::set_permissions(
        temporary.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o440),
    )?;
    temporary.persist_noclobber(destination).map_err(|error| {
        anyhow!(
            "failed to publish {}: {}",
            destination.display(),
            error.error
        )
    })?;
    Ok(())
}

fn remote_read_ranges(expected_length: u64, concurrency: usize) -> Vec<(u64, u64)> {
    let range_size = (REMOTE_READ_BUFFER_BUDGET / concurrency.max(1) as u64)
        .clamp(MIN_REMOTE_READ_RANGE_SIZE, MAX_REMOTE_READ_RANGE_SIZE);
    let mut ranges = Vec::new();
    let mut start = 0u64;
    while start < expected_length {
        let end = start.saturating_add(range_size).min(expected_length);
        ranges.push((start, end));
        start = end;
    }
    ranges
}

#[derive(Clone, Copy)]
struct RemoteReadSpec<'a> {
    bucket: &'a str,
    key: &'a str,
    etag: &'a str,
    expected_length: u64,
    expected_sha256: &'a str,
    concurrency: usize,
}

async fn read_remote_range(
    client: &Client,
    spec: RemoteReadSpec<'_>,
    start: u64,
    end: u64,
) -> Result<Vec<u8>> {
    ensure!(
        start < end && end <= spec.expected_length,
        "invalid remote range"
    );
    let range_length = end - start;
    let range = format!("bytes={start}-{}", end - 1);
    let expected_content_range = format!("bytes {start}-{}/{}", end - 1, spec.expected_length);
    let mut failures = 0usize;
    loop {
        let response = match client
            .get_object()
            .bucket(spec.bucket)
            .key(spec.key)
            .if_match(format!("\"{}\"", spec.etag))
            .range(&range)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                failures += 1;
                ensure!(
                    failures <= MAX_REMOTE_READ_ATTEMPTS,
                    "remote range {range} failed after {MAX_REMOTE_READ_ATTEMPTS} attempts: {error:?}"
                );
                eprintln!(
                    "warning: remote range {range} retry {failures}/{MAX_REMOTE_READ_ATTEMPTS}: {error:?}"
                );
                tokio::time::sleep(std::time::Duration::from_secs(
                    (1u64 << failures.saturating_sub(1).min(5)).min(30),
                ))
                .await;
                continue;
            }
        };
        ensure!(
            response
                .content_length()
                .and_then(|value| u64::try_from(value).ok())
                == Some(range_length),
            "remote range {range} length mismatch"
        );
        ensure!(
            response.content_range() == Some(expected_content_range.as_str()),
            "remote range {range} Content-Range mismatch"
        );
        ensure!(
            response.e_tag().map(normalize_etag) == Some(spec.etag),
            "remote range {range} ETag mismatch"
        );
        match response.body.collect().await {
            Ok(bytes) => {
                let bytes = bytes.into_bytes();
                ensure!(
                    bytes.len() == usize::try_from(range_length)?,
                    "remote range {range} body length mismatch"
                );
                return Ok(bytes.to_vec());
            }
            Err(error) => {
                failures += 1;
                ensure!(
                    failures <= MAX_REMOTE_READ_ATTEMPTS,
                    "remote range {range} remained incomplete after {MAX_REMOTE_READ_ATTEMPTS} attempts: {error}"
                );
                eprintln!(
                    "warning: remote range {range} stream retry {failures}/{MAX_REMOTE_READ_ATTEMPTS}: {error}"
                );
                tokio::time::sleep(std::time::Duration::from_secs(
                    (1u64 << failures.saturating_sub(1).min(5)).min(30),
                ))
                .await;
            }
        }
    }
}

async fn read_remote_sha256_resumable<W: Write>(
    client: &Client,
    spec: RemoteReadSpec<'_>,
    writer: &mut W,
) -> Result<()> {
    use futures_util::{StreamExt as _, stream};

    let mut digest = Sha256::new();
    let mut received = 0u64;
    // `buffered` polls several range requests concurrently but yields them in
    // input order. The writer and whole-object digest therefore still see one
    // canonical byte stream.
    let downloads = stream::iter(remote_read_ranges(spec.expected_length, spec.concurrency))
        .map(|(start, end)| async move {
            read_remote_range(client, spec, start, end)
                .await
                .map(|bytes| (start, bytes))
        })
        .buffered(spec.concurrency);
    futures_util::pin_mut!(downloads);
    while let Some(download) = downloads.next().await {
        let (start, bytes) = download?;
        ensure!(start == received, "remote ranges arrived out of order");
        writer.write_all(&bytes)?;
        digest.update(&bytes);
        received = received
            .checked_add(u64::try_from(bytes.len())?)
            .ok_or_else(|| anyhow!("remote read length overflow"))?;
    }
    ensure!(
        received == spec.expected_length,
        "remote read was truncated"
    );
    ensure!(
        format!("{:x}", digest.finalize()) == spec.expected_sha256,
        "remote SHA-256 mismatch"
    );
    Ok(())
}

async fn restore_epoch(client: &Client, r2: &R2Config, config: &Config, epoch: u64) -> Result<()> {
    let receipt = read_restore_receipt(
        config
            .receipt_directory
            .as_deref()
            .expect("restore requires a receipt directory"),
        &r2.bucket,
        epoch,
    )?;
    let archive_path = config.directory.join(&receipt.archive_key);
    let sidecar_path = config.directory.join(&receipt.checksum_key);
    let expected_sidecar = canonical_sidecar(&receipt);

    let remote = head_archive(client, &r2.bucket, &receipt.archive_key)
        .await?
        .ok_or_else(|| anyhow!("remote archive is missing"))?;
    validate_remote_against_receipt(&remote, &receipt)?;
    ensure!(
        remote_sidecar(client, &r2.bucket, &receipt.checksum_key)
            .await?
            .as_deref()
            == Some(expected_sidecar.as_slice()),
        "remote checksum sidecar differs from receipt"
    );

    let archive_exists = archive_path
        .try_exists()
        .context("failed to inspect restore destination")?;
    let sidecar_exists = sidecar_path
        .try_exists()
        .context("failed to inspect restore destination")?;
    if archive_exists {
        validate_restored_archive(&archive_path, &receipt)?;
    }
    if sidecar_exists {
        validate_restored_sidecar(&sidecar_path, &expected_sidecar)?;
    }
    if archive_exists && sidecar_exists {
        eprintln!("epoch {epoch}: verified local restore already exists");
        return Ok(());
    }

    if !archive_exists {
        eprintln!(
            "epoch {epoch}: restoring {} bytes from R2",
            receipt.archive_length
        );
        let mut temporary = tempfile::Builder::new()
            .prefix(&format!(".epoch-{epoch}.restore."))
            .tempfile_in(&config.directory)?;
        let spec = RemoteReadSpec {
            bucket: &r2.bucket,
            key: &receipt.archive_key,
            etag: &receipt.archive_etag,
            expected_length: receipt.archive_length,
            expected_sha256: &receipt.archive_sha256,
            concurrency: config.concurrency,
        };
        read_remote_sha256_resumable(client, spec, temporary.as_file_mut())
            .await
            .context("failed to restore and hash R2 archive")?;
        persist_noclobber(temporary, &archive_path)?;
    }

    if !sidecar_exists {
        let mut temporary = tempfile::Builder::new()
            .prefix(&format!(".epoch-{epoch}.sidecar.restore."))
            .tempfile_in(&config.directory)?;
        temporary.as_file_mut().write_all(&expected_sidecar)?;
        persist_noclobber(temporary, &sidecar_path)?;
    }
    File::open(&config.directory)?.sync_all()?;

    validate_restored_archive(&archive_path, &receipt)?;
    validate_restored_sidecar(&sidecar_path, &expected_sidecar)?;
    let remote = head_archive(client, &r2.bucket, &receipt.archive_key)
        .await?
        .ok_or_else(|| anyhow!("remote archive disappeared after restore"))?;
    validate_remote_against_receipt(&remote, &receipt)?;
    ensure!(
        remote_sidecar(client, &r2.bucket, &receipt.checksum_key)
            .await?
            .as_deref()
            == Some(expected_sidecar.as_slice()),
        "remote checksum sidecar changed during restore"
    );
    eprintln!(
        "epoch {epoch}: restored and verified in {}",
        config.directory.display()
    );
    Ok(())
}

async fn verify_remote_sha256(
    client: &Client,
    bucket: &str,
    key: &str,
    etag: &str,
    expected_length: u64,
    expected_sha256: &str,
    concurrency: usize,
) -> Result<()> {
    let spec = RemoteReadSpec {
        bucket,
        key,
        etag,
        expected_length,
        expected_sha256,
        concurrency,
    };
    read_remote_sha256_resumable(client, spec, &mut std::io::sink())
        .await
        .context("failed remote SHA-256 readback")
}

fn revalidate_local(local: &LocalArchive) -> Result<()> {
    ensure!(
        regular_identity(&local.archive_path)? == local.identity,
        "archive changed before retirement"
    );
    ensure!(
        regular_identity(&local.sidecar_path)? == local.sidecar_identity,
        "sidecar changed before retirement"
    );
    ensure!(
        fs::read(&local.sidecar_path)? == local.sidecar,
        "sidecar bytes changed before retirement"
    );
    Ok(())
}

fn retire_local(local: &LocalArchive) -> Result<()> {
    revalidate_local(local)?;
    // The sidecar is the readiness marker in both local and remote
    // namespaces. Remove it first so a crash can leave only an explicitly
    // incomplete archive, never a completion marker whose archive vanished.
    fs::remove_file(&local.sidecar_path)?;
    fs::remove_file(&local.archive_path)?;
    File::open(
        local
            .archive_path
            .parent()
            .unwrap_or_else(|| Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

fn validate_local_retirement_proof(
    local: &LocalArchive,
    proof: &LocalProof,
    receipt: &Receipt,
) -> Result<()> {
    ensure!(
        receipt.remote_sha256_readback || receipt.r2_composite_sha256.is_some(),
        "R2 receipt lacks a durable whole-object SHA-256 proof"
    );
    ensure!(
        local.epoch == receipt.epoch
            && local.length == receipt.archive_length
            && local.sha256_hex == receipt.archive_sha256
            && local.sidecar == canonical_sidecar(receipt),
        "local archive pair differs from the R2 receipt"
    );
    ensure!(
        proof.sha256_hex == receipt.archive_sha256,
        "local archive SHA-256 differs from the R2 receipt"
    );
    ensure!(
        proof.multipart_etag == receipt.archive_etag,
        "local archive multipart ETag differs from the R2 receipt"
    );
    if let Some(expected) = receipt.r2_composite_sha256.as_deref() {
        ensure!(
            composite_checksum_matches(
                expected,
                &proof.composite_sha256,
                local.length.div_ceil(receipt.multipart_part_size),
            ),
            "local archive composite SHA-256 differs from the R2 receipt"
        );
    }
    Ok(())
}

async fn retire_verified_local_epoch(
    client: &Client,
    r2: &R2Config,
    config: &Config,
    epoch: u64,
) -> Result<()> {
    let receipt = read_restore_receipt(
        config
            .receipt_directory
            .as_deref()
            .expect("local retirement requires a receipt directory"),
        &r2.bucket,
        epoch,
    )?;
    ensure!(
        receipt.remote_sha256_readback || receipt.r2_composite_sha256.is_some(),
        "R2 receipt lacks a durable whole-object SHA-256 proof"
    );
    let local = read_local_archive(&config.directory, epoch)?;
    let path = local.archive_path.clone();
    let expected = local.identity;
    let part_size = receipt.multipart_part_size;
    let proof =
        tokio::task::spawn_blocking(move || hash_and_etag(&path, expected, part_size)).await??;
    validate_local_retirement_proof(&local, &proof, &receipt)?;
    revalidate_local(&local)?;

    let remote = head_archive(client, &r2.bucket, &receipt.archive_key)
        .await?
        .ok_or_else(|| anyhow!("remote archive is missing"))?;
    validate_remote_against_receipt(&remote, &receipt)?;
    ensure!(
        remote_sidecar(client, &r2.bucket, &receipt.checksum_key)
            .await?
            .as_deref()
            == Some(local.sidecar.as_slice()),
        "remote checksum sidecar differs from the R2 receipt"
    );
    let final_remote = head_archive(client, &r2.bucket, &receipt.archive_key)
        .await?
        .ok_or_else(|| anyhow!("remote archive disappeared before local retirement"))?;
    validate_remote_against_receipt(&final_remote, &receipt)?;
    revalidate_local(&local)?;
    retire_local(&local)?;
    eprintln!("epoch {epoch}: durable R2 receipt and remote pair revalidated, local pair retired");
    Ok(())
}

fn validate_remote_pair_state(
    has_archive: bool,
    remote_sidecar: Option<&[u8]>,
    local_sidecar: &[u8],
    repair_orphaned_archive: bool,
) -> Result<bool> {
    if has_archive || remote_sidecar.is_none() {
        return Ok(false);
    }
    ensure!(
        repair_orphaned_archive,
        "remote completion sidecar exists without its archive"
    );
    ensure!(
        remote_sidecar == Some(local_sidecar),
        "orphaned remote completion sidecar differs from the verified local sidecar"
    );
    Ok(true)
}

async fn sync_epoch(client: &Client, r2: &R2Config, config: &Config, epoch: u64) -> Result<()> {
    let local = read_local_archive(&config.directory, epoch)?;
    let archive_key = format!("epoch-{epoch}.jet");
    let checksum_key = format!("epoch-{epoch}.jet.sha256");
    let existing = head_archive(client, &r2.bucket, &archive_key).await?;
    let existing_sidecar = remote_sidecar(client, &r2.bucket, &checksum_key).await?;
    let repairing_orphan = validate_remote_pair_state(
        existing.is_some(),
        existing_sidecar.as_deref(),
        &local.sidecar,
        config.repair_orphaned_archive,
    )
    .with_context(|| format!("invalid remote pair state for epoch {epoch}"))?;
    let was_existing = existing.is_some() && !config.overwrite_existing;
    let effective_part_size = if let Some(remote) = &existing {
        if config.overwrite_existing {
            config.part_size
        } else {
            remote
                .multipart_part_size
                .or(config.legacy_part_size)
                .ok_or_else(|| {
                    anyhow!("epoch {epoch} already exists but has no part-size metadata and --legacy-part-size-mib was not supplied")
                })?
        }
    } else {
        config.part_size
    };
    eprintln!("epoch {epoch}: hashing {}", local.archive_path.display());
    let path = local.archive_path.clone();
    let expected = local.identity;
    let proof =
        tokio::task::spawn_blocking(move || hash_and_etag(&path, expected, effective_part_size))
            .await??;
    ensure!(
        proof.sha256_hex == local.sha256_hex,
        "local SHA-256 mismatch for epoch {epoch}"
    );
    let (etag, _upload_composite_sha256) = if let Some(remote) =
        existing.filter(|_| !config.overwrite_existing)
    {
        ensure!(
            remote.length == local.length,
            "remote length mismatch for epoch {epoch}"
        );
        ensure!(
            remote.etag == proof.multipart_etag,
            "remote ETag mismatch for epoch {epoch}"
        );
        if let Some(metadata_sha256) = remote.metadata_sha256 {
            ensure!(
                metadata_sha256 == local.sha256_hex,
                "remote SHA-256 metadata mismatch"
            );
        }
        if let Some(checksum) = remote.composite_sha256.as_deref() {
            ensure!(
                remote.checksum_type == Some(ChecksumType::Composite),
                "unexpected remote checksum type"
            );
            ensure!(
                composite_checksum_matches(
                    checksum,
                    &proof.composite_sha256,
                    local.length.div_ceil(effective_part_size)
                ),
                "remote composite SHA-256 mismatch for epoch {epoch}"
            );
        }
        (remote.etag, remote.composite_sha256)
    } else {
        ensure!(
            config.command == Command::Sync,
            "remote archive is missing for epoch {epoch}"
        );
        if repairing_orphan {
            eprintln!("epoch {epoch}: repairing missing archive bound by matching remote sidecar");
        }
        eprintln!("epoch {epoch}: uploading {} bytes", local.length);
        let (etag, _locally_expected_composite_checksum) = upload_archive(
            client,
            &r2.bucket,
            &local,
            config.part_size,
            config.concurrency,
            config.overwrite_existing,
        )
        .await?;
        (etag, None)
    };
    let remote = head_archive(client, &r2.bucket, &archive_key)
        .await?
        .ok_or_else(|| anyhow!("remote archive disappeared for epoch {epoch}"))?;
    ensure!(
        remote.length == local.length && remote.etag == etag,
        "remote archive changed after verification"
    );
    if remote.metadata_sha256.is_some() {
        ensure!(
            remote.metadata_sha256.as_deref() == Some(local.sha256_hex.as_str()),
            "remote metadata changed"
        );
    }
    if let Some(checksum) = remote.composite_sha256.as_deref() {
        ensure!(
            remote.checksum_type == Some(ChecksumType::Composite),
            "remote checksum type changed"
        );
        ensure!(
            composite_checksum_matches(
                checksum,
                &proof.composite_sha256,
                local.length.div_ceil(effective_part_size),
            ),
            "remote composite SHA-256 changed after verification"
        );
    }
    let native_sha256_proven = remote.composite_sha256.is_some();
    let remote_sha256_readback =
        if native_sha256_proven || (was_existing && config.legacy_etag_only) {
            false
        } else {
            eprintln!("epoch {epoch}: reading the completed R2 object back for whole-file SHA-256");
            verify_remote_sha256(
                client,
                &r2.bucket,
                &archive_key,
                &etag,
                local.length,
                &local.sha256_hex,
                config.concurrency,
            )
            .await?;
            true
        };
    revalidate_local(&local)?;

    // The sidecar is the public completion marker. Publish it only after the
    // complete archive has passed every available remote integrity proof and
    // the source files have been revalidated. Consumers may therefore treat a
    // canonical sidecar as meaning that the corresponding archive was fully
    // uploaded and verified by this publisher.
    match remote_sidecar(client, &r2.bucket, &checksum_key).await? {
        Some(_) if config.overwrite_existing => {
            put_sidecar(client, &r2.bucket, &local, true).await?
        }
        Some(bytes) => ensure!(
            bytes == local.sidecar,
            "remote sidecar mismatch for epoch {epoch}"
        ),
        None if config.command == Command::Sync => {
            put_sidecar(client, &r2.bucket, &local, false).await?
        }
        None => bail!("remote sidecar is missing for epoch {epoch}"),
    }
    ensure!(
        remote_sidecar(client, &r2.bucket, &checksum_key)
            .await?
            .as_deref()
            == Some(&local.sidecar),
        "remote sidecar readback failed"
    );
    let final_remote = head_archive(client, &r2.bucket, &archive_key)
        .await?
        .ok_or_else(|| anyhow!("remote archive disappeared after sidecar publication"))?;
    ensure!(
        final_remote.length == local.length && final_remote.etag == etag,
        "remote archive changed during sidecar publication"
    );
    if final_remote.metadata_sha256.is_some() {
        ensure!(
            final_remote.metadata_sha256.as_deref() == Some(local.sha256_hex.as_str()),
            "remote metadata changed during sidecar publication"
        );
    }
    if native_sha256_proven {
        ensure!(
            final_remote.checksum_type == Some(ChecksumType::Composite)
                && final_remote
                    .composite_sha256
                    .as_deref()
                    .is_some_and(|checksum| composite_checksum_matches(
                        checksum,
                        &proof.composite_sha256,
                        local.length.div_ceil(effective_part_size),
                    )),
            "remote composite SHA-256 changed during sidecar publication"
        );
    }
    let receipt = Receipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        bucket: r2.bucket.clone(),
        epoch,
        archive_key,
        checksum_key,
        archive_length: local.length,
        archive_sha256: local.sha256_hex.clone(),
        archive_etag: etag,
        r2_composite_sha256: final_remote.composite_sha256,
        remote_sha256_readback,
        multipart_part_size: effective_part_size,
        verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    let receipt_path = write_receipt(
        config
            .receipt_directory
            .as_deref()
            .expect("delivery requires a receipt directory"),
        &receipt,
        config.overwrite_existing,
    )?;
    if config.delete_local {
        retire_local(&local)?;
        eprintln!(
            "epoch {epoch}: verified in R2, receipt {}, local pair retired",
            receipt_path.display()
        );
    } else {
        eprintln!(
            "epoch {epoch}: verified in R2, receipt {}",
            receipt_path.display()
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = parse_args()?;
    ensure!(
        config.command == Command::Inventory || config.directory.is_dir(),
        "archive directory does not exist"
    );
    let r2 = r2_config_from_env()?;
    let client = s3_client(&r2);
    if config.command == Command::Inventory {
        let mut entries = Vec::with_capacity(config.epochs.len());
        for &epoch in &config.epochs {
            entries.push(
                inventory_epoch(&client, &r2, epoch)
                    .await
                    .with_context(|| format!("epoch {epoch} R2 inventory failed"))?,
            );
        }
        let report = inventory_report(entries);
        println!("{}", serde_json::to_string_pretty(&report)?);
        ensure!(
            report.anomalies == 0,
            "R2 inventory contains {} anomalous pair state(s)",
            report.anomalies
        );
        return Ok(());
    }
    if config.command == Command::PublicVerify {
        let public = public_config_from_env()?;
        let http = HttpClient::builder()
            .no_proxy()
            .redirect(RedirectPolicy::none())
            .timeout(Duration::from_secs(60))
            .build()
            .context("failed to construct anonymous public-read client")?;
        let receipt_directory = config
            .public_receipt_directory
            .as_deref()
            .expect("public-verify requires a public receipt directory");
        for &epoch in &config.epochs {
            let receipt_path =
                public_verify_epoch(&client, &http, &r2, &public, receipt_directory, epoch)
                    .await
                    .with_context(|| format!("epoch {epoch} public verification failed"))?;
            eprintln!(
                "epoch {epoch}: anonymously readable, receipt {}",
                receipt_path.display()
            );
        }
        return Ok(());
    }
    if config.command == Command::StatusPublish {
        let epoch = *config.epochs.first().expect("one status epoch validated");
        let receipt_path = status_publish(&client, &r2, &config, epoch)
            .await
            .with_context(|| format!("epoch {epoch} status publication failed"))?;
        eprintln!(
            "epoch {epoch}: status conditionally published and authenticated-readback verified, receipt {}",
            receipt_path.display()
        );
        return Ok(());
    }
    if config.command == Command::StatusDelete {
        let epoch = *config.epochs.first().expect("one status epoch validated");
        let receipt_path = status_delete(&client, &r2, &config, epoch)
            .await
            .with_context(|| format!("epoch {epoch} status deletion failed"))?;
        eprintln!(
            "epoch {epoch}: status conditionally deleted after authenticated ready-pair proof, receipt {}",
            receipt_path.display()
        );
        return Ok(());
    }
    for &epoch in &config.epochs {
        match config.command {
            Command::RetireLocal => retire_verified_local_epoch(&client, &r2, &config, epoch)
                .await
                .with_context(|| format!("epoch {epoch} verified local retirement failed"))?,
            Command::Restore => restore_epoch(&client, &r2, &config, epoch)
                .await
                .with_context(|| format!("epoch {epoch} R2 restore failed"))?,
            Command::Sync | Command::Verify => sync_epoch(&client, &r2, &config, epoch)
                .await
                .with_context(|| format!("epoch {epoch} R2 delivery failed"))?,
            Command::Inventory
            | Command::PublicVerify
            | Command::StatusPublish
            | Command::StatusDelete => {
                unreachable!("read-only command handled above")
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges_and_mib() {
        assert_eq!(parse_epoch_range("7-9").unwrap(), BTreeSet::from([7, 8, 9]));
        assert!(parse_epoch_range("9-7").is_err());
        assert_eq!(parse_mib("64").unwrap(), 64 * 1024 * 1024);
        assert!(parse_mib("4").is_err());
    }

    #[test]
    fn public_origin_is_distinct_from_the_authenticated_s3_api() {
        let managed = parse_public_config("https://pub-0123456789abcdef.r2.dev").unwrap();
        assert_eq!(
            managed.base_url.as_str(),
            "https://pub-0123456789abcdef.r2.dev/"
        );
        let custom = parse_public_config("https://archive.example.com/").unwrap();
        assert_eq!(
            public_object_url(&custom, "epoch-7.jet").unwrap().as_str(),
            "https://archive.example.com/epoch-7.jet"
        );
        assert!(
            parse_public_config(
                "https://995827f79dbd061b8d4fd07b4ca04414.r2.cloudflarestorage.com/solana-archive-with-accounts-data"
            )
            .is_err()
        );
        for invalid in [
            "http://archive.example.com/",
            "https://user@archive.example.com/",
            "https://archive.example.com/prefix/",
            "https://archive.example.com/?signature=secret",
        ] {
            assert!(parse_public_config(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn public_archive_range_is_exact_and_nonempty() {
        assert_eq!(parse_public_content_range("bytes 0-0/123").unwrap(), 123);
        for invalid in ["bytes 0-1/123", "bytes 0-0/0", "bytes */123", "invalid"] {
            assert!(
                parse_public_content_range(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn status_schema_is_exact_and_observer_binding_is_stable() {
        let controller = "ab".repeat(16);
        let producer = "cd".repeat(16);
        let observer = serde_json::json!({
            "schema": "jetstreamer-horizon-live-resource-sample-v2",
            "recorded_at_utc": "2026-10-17T01:10:00Z",
            "mutation": {
                "producer_or_controller_signals_sent": false,
                "service_state_changed": false,
                "remote_mutations": false,
                "r2_mutations": false
            },
            "replays": [{
                "range": "216-219",
                "invocation_binding_stable": true,
                "controller_before": {"invocation_id": controller, "restarts": 0},
                "controller_after": {"invocation_id": controller, "restarts": 0},
                "producer_before": {"invocation_id": producer, "restarts": 0},
                "producer_after": {"invocation_id": producer, "restarts": 0},
                "useful_work": {"journal_invocation_id": producer}
            }]
        });
        let bytes = serde_json::to_vec(&observer).unwrap();
        let digest = hex_lower(&Sha256::digest(&bytes));
        assert_eq!(
            validate_observer_binding(&bytes, &digest, 218, &controller, &producer).unwrap(),
            "2026-10-17T01:10:00Z"
        );
        assert!(validate_observer_binding(&bytes, &digest, 220, &controller, &producer).is_err());

        let mut singleton_observer = observer.clone();
        singleton_observer["replays"][0]["range"] = Value::from("218");
        let singleton_bytes = serde_json::to_vec(&singleton_observer).unwrap();
        let singleton_digest = hex_lower(&Sha256::digest(&singleton_bytes));
        assert_eq!(
            validate_observer_binding(
                &singleton_bytes,
                &singleton_digest,
                218,
                &controller,
                &producer
            )
            .unwrap(),
            "2026-10-17T01:10:00Z"
        );
        assert!(
            validate_observer_binding(
                &singleton_bytes,
                &singleton_digest,
                219,
                &controller,
                &producer
            )
            .is_err()
        );

        let exact = br#"{
            "epoch": 218,
            "jet_size_bytes": 0,
            "elapsed_execution_millis": 123,
            "estimated_remaining_millis": 456,
            "sampled_at_utc": "2026-10-17T01:10:00Z",
            "phase": "replay"
        }"#;
        let status: EpochStatus = serde_json::from_slice(exact).unwrap();
        assert_eq!(status.epoch, 218);
        validate_epoch_status(&status, 218).unwrap();
        assert!(validate_epoch_status(&status, 219).is_err());
        let mut invalid_status = status.clone();
        invalid_status.phase = "unknown".to_owned();
        assert!(validate_epoch_status(&invalid_status, 218).is_err());
        invalid_status = status.clone();
        invalid_status.sampled_at_utc = "2026-10-17 01:10:00Z".to_owned();
        assert!(validate_epoch_status(&invalid_status, 218).is_err());
        let mut with_extra: Value = serde_json::from_slice(exact).unwrap();
        with_extra["extra"] = Value::from(true);
        assert!(serde_json::from_value::<EpochStatus>(with_extra).is_err());
    }

    #[test]
    fn status_timestamp_and_receipt_name_are_canonical() {
        assert!(is_canonical_utc("2026-10-17T01:10:00Z"));
        for invalid in [
            "2026-10-17 01:10:00Z",
            "2026-10-17T01:10:00+00:00",
            "2026-10-17T01:10:00z",
        ] {
            assert!(!is_canonical_utc(invalid));
        }
        let status = EpochStatus {
            epoch: 218,
            jet_size_bytes: 0,
            elapsed_execution_millis: 1,
            estimated_remaining_millis: 2,
            sampled_at_utc: "2026-10-17T01:10:00Z".to_owned(),
            phase: "replay".to_owned(),
        };
        assert_eq!(
            status_receipt_path(Path::new("/private"), &status),
            Path::new("/private/epoch-218.status-20261017011000.json")
        );
        let mut older = status.clone();
        older.sampled_at_utc = "2026-10-17T00:40:00Z".to_owned();
        assert_eq!(
            status_publication_action(&older, &status).unwrap(),
            StatusPublicationAction::Replace
        );
        assert!(status_publication_action(&status, &older).is_err());
        assert_eq!(
            status_publication_action(&status, &status).unwrap(),
            StatusPublicationAction::RecoverReceipt
        );
        let mut conflicting = status.clone();
        conflicting.jet_size_bytes = 1;
        assert!(status_publication_action(&status, &conflicting).is_err());
        older.epoch = 219;
        assert!(status_publication_action(&older, &status).is_err());
        validate_status_publication_after_sidecar(StatusPublicationAction::Replace, false).unwrap();
        assert!(
            validate_status_publication_after_sidecar(StatusPublicationAction::Replace, true)
                .is_err()
        );
        validate_status_publication_after_sidecar(StatusPublicationAction::RecoverReceipt, true)
            .unwrap();
    }

    fn status_publication_receipt(epoch: u64) -> StatusPublicationReceipt {
        StatusPublicationReceipt {
            schema: STATUS_RECEIPT_SCHEMA.to_owned(),
            bucket: "bucket".to_owned(),
            epoch,
            key: format!("epoch-{epoch}.epoch-status.json"),
            status: EpochStatus {
                epoch,
                jet_size_bytes: 123,
                elapsed_execution_millis: 456,
                estimated_remaining_millis: 789,
                sampled_at_utc: "2026-10-17T01:10:00Z".to_owned(),
                phase: "replay".to_owned(),
            },
            object_etag: "etag".to_owned(),
            previous_object_etag: None,
            observer_receipt: PathBuf::from("/private/observer.json"),
            observer_receipt_sha256: "ab".repeat(32),
            controller_invocation_id: "cd".repeat(16),
            producer_invocation_id: "ef".repeat(16),
            authenticated_readback: true,
            verified_unix_seconds: 1,
        }
    }

    #[test]
    fn status_deletion_binds_the_exact_canonical_publication_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let receipt = status_publication_receipt(218);
        let path = write_status_receipt(directory.path(), &receipt).unwrap();
        let bytes = fs::read(&path).unwrap();
        let digest = hex_lower(&Sha256::digest(&bytes));
        let (read, read_digest) =
            read_bound_status_publication_receipt(directory.path(), &path, &digest, "bucket", 218)
                .unwrap();
        assert_eq!(read, receipt);
        assert_eq!(read_digest, digest);
        assert!(
            read_bound_status_publication_receipt(
                directory.path(),
                &path,
                &"00".repeat(32),
                "bucket",
                218,
            )
            .is_err()
        );
        assert!(
            read_bound_status_publication_receipt(directory.path(), &path, &digest, "other", 218,)
                .is_err()
        );

        let mut newer = receipt.clone();
        newer.status.sampled_at_utc = "2026-10-17T01:40:00Z".to_owned();
        newer.object_etag = "newer-etag".to_owned();
        let newer_path = write_status_receipt(directory.path(), &newer).unwrap();
        let newer_digest = hex_lower(&Sha256::digest(fs::read(&newer_path).unwrap()));
        fs::write(
            status_deletion_receipt_path(directory.path(), 218),
            b"not a status publication receipt\n",
        )
        .unwrap();
        let (latest, latest_path, latest_digest) =
            latest_status_publication_receipt(directory.path(), "bucket", 218).unwrap();
        assert_eq!(latest, newer);
        assert_eq!(latest_path, newer_path);
        assert_eq!(latest_digest, newer_digest);
    }

    #[test]
    fn status_deletion_receipt_is_private_durable_and_no_clobber() {
        let directory = tempfile::tempdir().unwrap();
        let publication = status_publication_receipt(218);
        let receipt = StatusDeletionReceipt {
            schema: STATUS_DELETION_RECEIPT_SCHEMA.to_owned(),
            bucket: "bucket".to_owned(),
            epoch: 218,
            key: publication.key.clone(),
            deleted_object_etag: publication.object_etag.clone(),
            deleted_status: publication.status.clone(),
            status_publication_receipt: PathBuf::from("/private/status.json"),
            status_publication_receipt_sha256: "01".repeat(32),
            archive_receipt: PathBuf::from("/private/archive.json"),
            archive_receipt_sha256: "02".repeat(32),
            archive_sha256: "03".repeat(32),
            archive_etag: "archive-etag".to_owned(),
            conditional_delete_request_sent: true,
            authenticated_ready_pair_before: true,
            authenticated_status_absent_after: true,
            authenticated_ready_pair_after: true,
            verified_unix_seconds: 1,
        };
        let path = write_status_deletion_receipt(directory.path(), &receipt).unwrap();
        assert_eq!(
            path,
            status_deletion_receipt_path(directory.path(), receipt.epoch)
        );
        assert_eq!(
            fs::metadata(directory.path()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        write_status_deletion_receipt(directory.path(), &receipt).unwrap();
        let mut different = receipt;
        different.archive_etag = "different".to_owned();
        assert!(write_status_deletion_receipt(directory.path(), &different).is_err());
    }

    fn public_receipt(epoch: u64) -> PublicReceipt {
        PublicReceipt {
            schema: PUBLIC_RECEIPT_SCHEMA.to_owned(),
            bucket: "bucket".to_owned(),
            epoch,
            archive_key: format!("epoch-{epoch}.jet"),
            checksum_key: format!("epoch-{epoch}.jet.sha256"),
            public_base_url: "https://archive.example.com/".to_owned(),
            public_archive_url: format!("https://archive.example.com/epoch-{epoch}.jet"),
            public_checksum_url: format!("https://archive.example.com/epoch-{epoch}.jet.sha256"),
            archive_length: 123,
            archive_etag: "etag".to_owned(),
            archive_sha256: "ab".repeat(32),
            verified_unix_seconds: 1,
        }
    }

    #[test]
    fn public_receipt_is_no_clobber_and_time_is_not_identity() {
        let directory = tempfile::tempdir().unwrap();
        let receipt = public_receipt(7);
        write_public_receipt(directory.path(), &receipt).unwrap();

        let mut later = receipt.clone();
        later.verified_unix_seconds = 2;
        write_public_receipt(directory.path(), &later).unwrap();

        let mut mismatch = later;
        mismatch.archive_etag = "different".to_owned();
        assert!(write_public_receipt(directory.path(), &mismatch).is_err());
        let stored: PublicReceipt = serde_json::from_slice(
            &fs::read(public_receipt_path(directory.path(), receipt.epoch)).unwrap(),
        )
        .unwrap();
        assert_eq!(stored, receipt);
    }

    #[test]
    fn remote_read_ranges_are_contiguous_and_memory_bounded() {
        assert!(remote_read_ranges(0, 8).is_empty());
        for concurrency in [1, 4, 8, 64] {
            let length = 3 * MAX_REMOTE_READ_RANGE_SIZE + 17;
            let ranges = remote_read_ranges(length, concurrency);
            assert_eq!(ranges.first().map(|range| range.0), Some(0));
            assert_eq!(ranges.last().map(|range| range.1), Some(length));
            for pair in ranges.windows(2) {
                assert_eq!(pair[0].1, pair[1].0);
            }
            let largest = ranges.iter().map(|(start, end)| end - start).max().unwrap();
            assert!((MIN_REMOTE_READ_RANGE_SIZE..=MAX_REMOTE_READ_RANGE_SIZE).contains(&largest));
            assert!(largest * concurrency as u64 <= REMOTE_READ_BUFFER_BUDGET);
        }
    }

    #[test]
    fn discovers_sparse_local_pairs_only() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("epoch-1.jet"), b"one").unwrap();
        fs::write(directory.path().join("epoch-1.jet.sha256"), b"sidecar").unwrap();
        fs::write(directory.path().join("epoch-2.jet"), b"partial").unwrap();
        fs::write(directory.path().join("unrelated"), b"ignored").unwrap();
        assert_eq!(
            discover_local_epochs(directory.path()).unwrap(),
            BTreeSet::from([1])
        );
    }

    fn inventory_archive(metadata_sha256: Option<&str>) -> RemoteArchive {
        RemoteArchive {
            length: 123,
            etag: "etag".to_owned(),
            metadata_sha256: metadata_sha256.map(str::to_owned),
            composite_sha256: None,
            checksum_type: None,
            multipart_part_size: Some(64 * 1024 * 1024),
        }
    }

    fn inventory_sidecar(epoch: u64, digest: &str) -> Vec<u8> {
        format!("{digest}  epoch-{epoch}.jet\n").into_bytes()
    }

    #[test]
    fn inventory_classifies_remote_pair_states_without_mutation() {
        let digest = "ab".repeat(32);
        assert_eq!(
            classify_inventory_entry(7, None, None).state,
            InventoryState::Missing
        );
        assert_eq!(
            classify_inventory_entry(7, Some(inventory_archive(None)), None).state,
            InventoryState::ArchiveOnly
        );
        assert_eq!(
            classify_inventory_entry(7, None, Some(inventory_sidecar(7, &digest))).state,
            InventoryState::SidecarOnly
        );
        assert_eq!(
            classify_inventory_entry(
                7,
                Some(inventory_archive(None)),
                Some(b"not canonical".to_vec()),
            )
            .state,
            InventoryState::InvalidSidecar
        );
        assert_eq!(
            classify_inventory_entry(
                7,
                Some(inventory_archive(Some(&"cd".repeat(32)))),
                Some(inventory_sidecar(7, &digest)),
            )
            .state,
            InventoryState::MetadataMismatch
        );
        let ready = classify_inventory_entry(
            7,
            Some(inventory_archive(Some(&digest))),
            Some(inventory_sidecar(7, &digest)),
        );
        assert_eq!(ready.state, InventoryState::ReadyPair);
        assert_eq!(ready.sidecar_sha256.as_deref(), Some(digest.as_str()));
    }

    #[test]
    fn inventory_report_counts_ready_staged_missing_and_anomalous_epochs() {
        let digest = "ab".repeat(32);
        let entries = vec![
            classify_inventory_entry(
                7,
                Some(inventory_archive(Some(&digest))),
                Some(inventory_sidecar(7, &digest)),
            ),
            classify_inventory_entry(8, Some(inventory_archive(None)), None),
            classify_inventory_entry(9, None, None),
            classify_inventory_entry(10, None, Some(inventory_sidecar(10, &digest))),
        ];
        let report = inventory_report(entries);
        assert_eq!(report.first_epoch, 7);
        assert_eq!(report.last_epoch, 10);
        assert_eq!(report.requested_epochs, 4);
        assert_eq!(report.ready_pairs, 1);
        assert_eq!(report.archive_only, 1);
        assert_eq!(report.missing, 1);
        assert_eq!(report.anomalies, 1);
    }

    #[test]
    fn orphaned_remote_sidecar_repair_requires_an_exact_local_match() {
        let sidecar = b"digest  epoch-7.jet\n";
        assert!(!validate_remote_pair_state(true, Some(sidecar), sidecar, false).unwrap());
        assert!(!validate_remote_pair_state(false, None, sidecar, false).unwrap());
        assert!(validate_remote_pair_state(false, Some(sidecar), sidecar, false).is_err());
        assert!(validate_remote_pair_state(false, Some(b"other"), sidecar, true).is_err());
        assert!(validate_remote_pair_state(false, Some(sidecar), sidecar, true).unwrap());
    }

    #[test]
    fn receipt_time_is_not_part_of_identity() {
        let receipt = Receipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            bucket: "bucket".to_owned(),
            epoch: 7,
            archive_key: "epoch-7.jet".to_owned(),
            checksum_key: "epoch-7.jet.sha256".to_owned(),
            archive_length: 10,
            archive_sha256: "ab".repeat(32),
            archive_etag: "etag".to_owned(),
            r2_composite_sha256: None,
            remote_sha256_readback: false,
            multipart_part_size: 5 * 1024 * 1024,
            verified_unix_seconds: 1,
        };
        let mut later = receipt.clone();
        later.verified_unix_seconds = 2;
        assert!(same_receipt_evidence(&receipt, &later));
    }

    #[test]
    fn local_retirement_requires_a_durable_receipt_and_exact_local_proof() {
        let directory = tempfile::tempdir().unwrap();
        let epoch = 7;
        let archive_path = directory.path().join("epoch-7.jet");
        let sidecar_path = directory.path().join("epoch-7.jet.sha256");
        fs::write(&archive_path, b"verified archive").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"verified archive"));
        fs::write(&sidecar_path, format!("{digest}  epoch-7.jet\n")).unwrap();
        let local = read_local_archive(directory.path(), epoch).unwrap();
        let part_size = 5 * 1024 * 1024;
        let proof = hash_and_etag(&archive_path, local.identity, part_size).unwrap();
        let mut receipt = Receipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            bucket: "bucket".to_owned(),
            epoch,
            archive_key: "epoch-7.jet".to_owned(),
            checksum_key: "epoch-7.jet.sha256".to_owned(),
            archive_length: local.length,
            archive_sha256: digest,
            archive_etag: proof.multipart_etag.clone(),
            r2_composite_sha256: None,
            remote_sha256_readback: true,
            multipart_part_size: part_size,
            verified_unix_seconds: 1,
        };
        validate_local_retirement_proof(&local, &proof, &receipt).unwrap();

        receipt.remote_sha256_readback = false;
        assert!(validate_local_retirement_proof(&local, &proof, &receipt).is_err());
        receipt.remote_sha256_readback = true;
        receipt.archive_etag = "different".to_owned();
        assert!(validate_local_retirement_proof(&local, &proof, &receipt).is_err());
    }

    #[test]
    fn local_retirement_removes_completion_marker_and_archive() {
        let directory = tempfile::tempdir().unwrap();
        let archive_path = directory.path().join("epoch-7.jet");
        let sidecar_path = directory.path().join("epoch-7.jet.sha256");
        fs::write(&archive_path, b"archive").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"archive"));
        fs::write(&sidecar_path, format!("{digest}  epoch-7.jet\n")).unwrap();
        let local = read_local_archive(directory.path(), 7).unwrap();
        retire_local(&local).unwrap();
        assert!(!sidecar_path.exists());
        assert!(!archive_path.exists());
    }

    #[test]
    fn receipt_replacement_requires_explicit_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let receipt = Receipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            bucket: "bucket".to_owned(),
            epoch: 7,
            archive_key: "epoch-7.jet".to_owned(),
            checksum_key: "epoch-7.jet.sha256".to_owned(),
            archive_length: 10,
            archive_sha256: "ab".repeat(32),
            archive_etag: "old-etag".to_owned(),
            r2_composite_sha256: None,
            remote_sha256_readback: true,
            multipart_part_size: 5 * 1024 * 1024,
            verified_unix_seconds: 1,
        };
        write_receipt(directory.path(), &receipt, false).unwrap();

        let mut replacement = receipt.clone();
        replacement.archive_etag = "new-etag".to_owned();
        replacement.verified_unix_seconds = 2;
        assert!(write_receipt(directory.path(), &replacement, false).is_err());
        write_receipt(directory.path(), &replacement, true).unwrap();

        let stored: Receipt = serde_json::from_slice(
            &fs::read(receipt_path(directory.path(), replacement.epoch)).unwrap(),
        )
        .unwrap();
        assert_eq!(stored, replacement);
    }

    #[test]
    fn restore_receipt_accepts_legacy_evidence_for_fresh_readback() {
        let directory = tempfile::tempdir().unwrap();
        let receipt = Receipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            bucket: "bucket".to_owned(),
            epoch: 7,
            archive_key: "epoch-7.jet".to_owned(),
            checksum_key: "epoch-7.jet.sha256".to_owned(),
            archive_length: 10,
            archive_sha256: "ab".repeat(32),
            archive_etag: "etag".to_owned(),
            r2_composite_sha256: None,
            remote_sha256_readback: false,
            multipart_part_size: 5 * 1024 * 1024,
            verified_unix_seconds: 1,
        };
        fs::write(
            receipt_path(directory.path(), receipt.epoch),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_restore_receipt(directory.path(), "bucket", 7).unwrap(),
            receipt
        );

        let mut proven = receipt.clone();
        proven.remote_sha256_readback = true;
        fs::write(
            receipt_path(directory.path(), proven.epoch),
            serde_json::to_vec(&proven).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_restore_receipt(directory.path(), "bucket", 7).unwrap(),
            proven
        );
        assert!(read_restore_receipt(directory.path(), "other", 7).is_err());
    }

    #[test]
    fn restore_publish_never_clobbers_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("epoch-7.jet");
        fs::write(&destination, b"existing").unwrap();
        let mut temporary = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        temporary.write_all(b"replacement").unwrap();
        assert!(persist_noclobber(temporary, &destination).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"existing");
    }

    #[test]
    fn restored_archive_is_bound_to_receipt_hash_and_etag() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("epoch-7.jet");
        fs::write(&path, b"archive").unwrap();
        let part_size = 5 * 1024 * 1024;
        let proof = hash_and_etag(&path, regular_identity(&path).unwrap(), part_size).unwrap();
        let receipt = Receipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            bucket: "bucket".to_owned(),
            epoch: 7,
            archive_key: "epoch-7.jet".to_owned(),
            checksum_key: "epoch-7.jet.sha256".to_owned(),
            archive_length: 7,
            archive_sha256: proof.sha256_hex,
            archive_etag: proof.multipart_etag,
            r2_composite_sha256: None,
            remote_sha256_readback: true,
            multipart_part_size: part_size,
            verified_unix_seconds: 1,
        };
        validate_restored_archive(&path, &receipt).unwrap();

        fs::write(&path, b"changed").unwrap();
        assert!(validate_restored_archive(&path, &receipt).is_err());
    }

    #[test]
    fn validates_canonical_sidecar() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("epoch-7.jet");
        fs::write(&archive, b"archive").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"archive"));
        fs::write(
            directory.path().join("epoch-7.jet.sha256"),
            format!("{digest}  epoch-7.jet\n"),
        )
        .unwrap();
        let local = read_local_archive(directory.path(), 7).unwrap();
        assert_eq!(local.sha256_hex, digest);
    }

    #[test]
    fn computes_standard_multipart_etag() {
        let parts = vec![Md5::digest(b"a").to_vec(), Md5::digest(b"b").to_vec()];
        let mut combined = Md5::new();
        combined.update(&parts[0]);
        combined.update(&parts[1]);
        assert_eq!(
            multipart_etag(&parts),
            format!("{:x}-2", combined.finalize())
        );
    }

    #[test]
    fn renders_part_digest_as_etag_hex_without_rehashing() {
        let digest = Md5::digest(b"part");
        assert_eq!(hex_lower(&digest), format!("{digest:x}"));
    }

    #[test]
    fn hash_proof_binds_sha_and_etag() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive");
        fs::write(&path, b"abcdefgh").unwrap();
        let proof = hash_and_etag(&path, regular_identity(&path).unwrap(), 5).unwrap();
        assert_eq!(
            proof.sha256_hex,
            format!("{:x}", Sha256::digest(b"abcdefgh"))
        );
        let expected =
            multipart_etag(&[Md5::digest(b"abcde").to_vec(), Md5::digest(b"fgh").to_vec()]);
        assert_eq!(proof.multipart_etag, expected);
        let expected_sha = composite_sha256(&[
            Sha256::digest(b"abcde").to_vec(),
            Sha256::digest(b"fgh").to_vec(),
        ]);
        assert_eq!(proof.composite_sha256, expected_sha);
    }

    #[test]
    fn source_confines_remote_deletion_to_one_status_object_operation() {
        let source = include_str!("main.rs");
        let singular = concat!(".delete_", "object()");
        let plural = concat!(".delete_", "objects()");
        assert_eq!(source.matches(singular).count(), 1);
        assert!(!source.contains(plural));
        let start = source.find("async fn status_delete(").unwrap();
        let end = source[start..].find("\nasync fn head_archive(").unwrap() + start;
        let status_delete = &source[start..end];
        assert!(status_delete.contains(singular));
        assert!(status_delete.contains("format!(\"epoch-{epoch}.epoch-status.json\")"));
        let ready_pair_before = status_delete
            .find("validate_authenticated_ready_pair(s3, &r2.bucket, &archive_receipt).await?")
            .unwrap();
        let deletion = status_delete.find(singular).unwrap();
        let ready_pair_after = status_delete
            .rfind("validate_authenticated_ready_pair(s3, &r2.bucket, &archive_receipt).await?")
            .unwrap();
        assert!(ready_pair_before < deletion && deletion < ready_pair_after);
    }

    #[test]
    fn sidecar_publication_follows_archive_integrity_proof() {
        let source = include_str!("main.rs");
        let start = source.find("async fn sync_epoch(").unwrap();
        let end = source[start..].find("\nasync fn main(").unwrap() + start;
        let sync_epoch = &source[start..end];
        let remote_readback = sync_epoch.find("verify_remote_sha256(").unwrap();
        let local_revalidation = sync_epoch.find("revalidate_local(&local)").unwrap();
        let sidecar_publication = sync_epoch.find("put_sidecar(").unwrap();
        assert!(remote_readback < sidecar_publication);
        assert!(local_revalidation < sidecar_publication);
        assert!(
            sync_epoch.contains("validate_remote_pair_state(")
                && sync_epoch.contains("existing_sidecar.as_deref()")
                && sync_epoch.contains("&local.sidecar"),
            "orphan completion markers must be checked against the local sidecar"
        );
    }
}
