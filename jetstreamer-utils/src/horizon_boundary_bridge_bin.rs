//! Verify one boundary between archives owned by different Horizon ranges.
//!
//! The normal progressive verifier intentionally owns one contiguous range.  This
//! tool closes the boundary between two independently produced ranges without
//! copying either archive or weakening the normal full-verification evidence.

use {
    anyhow::{Context, Result, anyhow, ensure},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeSet,
        env,
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::fd::AsRawFd,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    },
};

const PLAN_SCHEMA: &str = "jetstreamer-horizon-boundary-bridge-plan-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-horizon-boundary-bridge-receipt-v1";
const MAX_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024;
const MAX_VERIFIER_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    left_epoch: u64,
    right_epoch: u64,
    verifier: BoundExecutable,
    full_receipt_allowlist: FullReceiptAllowlist,
    expected_artifact_uid: u32,
    left: ArchiveEvidence,
    right: ArchiveEvidence,
    receipt_directories: Vec<ReceiptDirectory>,
    private_receipt: PrivateReceipt,
    authority: Authority,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundExecutable {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FullReceiptAllowlist {
    verifier_sha256: Vec<String>,
    script_sha256: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveEvidence {
    archive: PathBuf,
    sidecar: PathBuf,
    full_receipt: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptDirectory {
    path: PathBuf,
    expected_uid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateReceipt {
    path: PathBuf,
    expected_parent_uid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    archive_publication_authorized: bool,
    local_archive_retirement_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Debug)]
struct Arguments {
    plan: PathBuf,
    plan_sha256: String,
    self_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
    modified_nanoseconds: i128,
    changed_nanoseconds: i128,
    links: u64,
    uid: u32,
    gid: u32,
    mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedArchive {
    epoch: u64,
    digest: String,
    archive: PathBuf,
    sidecar: PathBuf,
    full_receipt: PathBuf,
    archive_identity: FileIdentity,
    sidecar_identity: FileIdentity,
    full_receipt_identity: FileIdentity,
    full_verifier_sha256: String,
    full_script_sha256: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    recorded_unix_seconds: u64,
    plan: BoundFile,
    bridge: BridgeReceipt,
    left: ArchiveReceipt,
    right: ArchiveReceipt,
    canonical_receipt_sha256: String,
    canonical_receipt_paths: Vec<String>,
    authority: ReceiptAuthority,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundFile {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BridgeReceipt {
    executable_sha256: String,
    verifier_path: String,
    verifier_sha256: String,
    verifier_status: i32,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveReceipt {
    epoch: u64,
    digest: String,
    archive: String,
    sidecar: String,
    full_receipt: String,
    archive_identity: FileIdentity,
    sidecar_identity: FileIdentity,
    full_receipt_identity: FileIdentity,
    full_verifier_sha256: String,
    full_script_sha256: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptAuthority {
    boundary_verified: bool,
    archive_publication_authorized: bool,
    local_archive_retirement_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn usage(program: &str) -> ! {
    eprintln!("usage: {program} PLAN.json --plan-sha256 HEX --self-sha256 HEX");
    std::process::exit(2);
}

fn parse_arguments() -> Arguments {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let Some(plan) = arguments.next().map(PathBuf::from) else {
        usage(&program);
    };
    let mut plan_sha256 = None;
    let mut self_sha256 = None;
    while let Some(argument) = arguments.next() {
        match argument.to_string_lossy().as_ref() {
            "--plan-sha256" => {
                plan_sha256 = arguments.next().map(|v| v.to_string_lossy().into_owned())
            }
            "--self-sha256" => {
                self_sha256 = arguments.next().map(|v| v.to_string_lossy().into_owned())
            }
            _ => usage(&program),
        }
    }
    Arguments {
        plan,
        plan_sha256: plan_sha256.unwrap_or_else(|| usage(&program)),
        self_sha256: self_sha256.unwrap_or_else(|| usage(&program)),
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_regular(path: &Path, maximum: u64) -> Result<(Vec<u8>, FileIdentity)> {
    ensure!(
        path.is_absolute(),
        "path must be absolute: {}",
        path.display()
    );
    ensure!(
        path.canonicalize()? == path,
        "path is not canonical: {}",
        path.display()
    );
    let before =
        fs::symlink_metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    ensure!(
        before.file_type().is_file(),
        "not a regular file: {}",
        path.display()
    );
    ensure!(
        before.len() <= maximum,
        "file exceeds size bound: {}",
        path.display()
    );
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let opened = file.metadata()?;
    let mut bytes = Vec::with_capacity(opened.len().try_into().unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    let observed_identity = identity(&before)?;
    ensure!(
        observed_identity == identity(&opened)?
            && observed_identity == identity(&after)?
            && observed_identity == identity(&current)?,
        "file changed while reading: {}",
        path.display()
    );
    Ok((bytes, observed_identity))
}

fn identity(metadata: &fs::Metadata) -> Result<FileIdentity> {
    let modified = metadata.modified()?.duration_since(UNIX_EPOCH)?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        modified_nanoseconds: i128::from(modified.as_secs()) * 1_000_000_000
            + i128::from(modified.subsec_nanos()),
        changed_nanoseconds: i128::from(metadata.ctime()) * 1_000_000_000
            + i128::from(metadata.ctime_nsec()),
        links: metadata.nlink(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: format!("{:04o}", metadata.permissions().mode() & 0o7777),
    })
}

fn inspect_archive(path: &Path, expected_uid: u32) -> Result<FileIdentity> {
    ensure!(path.is_absolute(), "archive path must be absolute");
    ensure!(
        path.canonicalize()? == path,
        "archive path is not canonical"
    );
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect archive {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "archive is not a regular file"
    );
    ensure!(metadata.uid() == expected_uid, "archive owner mismatch");
    ensure!(metadata.nlink() == 1, "archive must be singly linked");
    ensure!(metadata.len() > 0, "archive is empty");
    ensure!(
        metadata.permissions().mode() & 0o022 == 0,
        "archive is group/other writable"
    );
    identity(&metadata)
}

fn parse_sidecar(bytes: &[u8], epoch: u64) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("sidecar is not UTF-8")?;
    let suffix = format!("  epoch-{epoch}.jet\n");
    ensure!(
        text.len() == 64 + suffix.len() && text.ends_with(&suffix),
        "non-canonical sidecar"
    );
    let digest = &text[..64];
    ensure!(is_digest(digest), "sidecar digest is invalid");
    Ok(digest.to_owned())
}

fn parse_full_receipt(
    bytes: &[u8],
    digest: &str,
    allowlist: &FullReceiptAllowlist,
) -> Result<(String, String)> {
    let text = std::str::from_utf8(bytes).context("full receipt is not UTF-8")?;
    ensure!(
        text.ends_with('\n') && !text[..text.len() - 1].contains('\n'),
        "non-canonical full receipt"
    );
    let fields: Vec<_> = text[..text.len() - 1].split(' ').collect();
    ensure!(
        fields.len() == 3 && fields.iter().all(|field| is_digest(field)),
        "invalid full receipt"
    );
    ensure!(fields[0] == digest, "full receipt digest mismatch");
    ensure!(
        allowlist
            .verifier_sha256
            .iter()
            .any(|value| value == fields[1]),
        "full verifier is not approved"
    );
    ensure!(
        allowlist
            .script_sha256
            .iter()
            .any(|value| value == fields[2]),
        "full verifier script is not approved"
    );
    Ok((fields[1].to_owned(), fields[2].to_owned()))
}

fn validate_archive(
    evidence: &ArchiveEvidence,
    epoch: u64,
    expected_uid: u32,
    allowlist: &FullReceiptAllowlist,
) -> Result<ValidatedArchive> {
    ensure!(
        evidence
            .archive
            .file_name()
            .and_then(|value| value.to_str())
            == Some(&format!("epoch-{epoch}.jet")),
        "archive name does not match epoch"
    );
    let expected_sidecar = format!("{}.sha256", evidence.archive.display());
    ensure!(
        evidence.sidecar == Path::new(&expected_sidecar),
        "sidecar path mismatch"
    );
    ensure!(
        evidence
            .full_receipt
            .file_name()
            .and_then(|value| value.to_str())
            == Some(&format!("epoch-{epoch}.full.ok")),
        "full receipt name does not match epoch"
    );
    let archive_identity = inspect_archive(&evidence.archive, expected_uid)?;
    let (sidecar_bytes, sidecar_identity) = read_regular(&evidence.sidecar, MAX_EVIDENCE_BYTES)?;
    ensure!(
        sidecar_identity.uid == expected_uid,
        "sidecar owner mismatch"
    );
    ensure!(sidecar_identity.links == 1, "sidecar must be singly linked");
    ensure!(
        u32::from_str_radix(&sidecar_identity.mode, 8)? & 0o022 == 0,
        "sidecar is group/other writable"
    );
    let digest = parse_sidecar(&sidecar_bytes, epoch)?;
    let (receipt_bytes, full_receipt_identity) =
        read_regular(&evidence.full_receipt, MAX_EVIDENCE_BYTES)?;
    ensure!(
        full_receipt_identity.uid == expected_uid,
        "full receipt owner mismatch"
    );
    ensure!(
        full_receipt_identity.links == 1,
        "full receipt must be singly linked"
    );
    ensure!(
        u32::from_str_radix(&full_receipt_identity.mode, 8)? & 0o022 == 0,
        "full receipt is group/other writable"
    );
    let (full_verifier_sha256, full_script_sha256) =
        parse_full_receipt(&receipt_bytes, &digest, allowlist)?;
    Ok(ValidatedArchive {
        epoch,
        digest,
        archive: evidence.archive.clone(),
        sidecar: evidence.sidecar.clone(),
        full_receipt: evidence.full_receipt.clone(),
        archive_identity,
        sidecar_identity,
        full_receipt_identity,
        full_verifier_sha256,
        full_script_sha256,
    })
}

fn validate_directory(directory: &ReceiptDirectory) -> Result<()> {
    ensure!(
        directory.path.is_absolute(),
        "receipt directory must be absolute"
    );
    ensure!(
        directory.path.canonicalize()? == directory.path,
        "receipt directory is not canonical"
    );
    let metadata = fs::symlink_metadata(&directory.path)
        .with_context(|| format!("cannot inspect {}", directory.path.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "receipt path is not a directory"
    );
    ensure!(
        metadata.uid() == directory.expected_uid,
        "receipt directory owner mismatch"
    );
    ensure!(
        metadata.permissions().mode() & 0o022 == 0,
        "receipt directory is group/other writable"
    );
    Ok(())
}

fn fsync_directory(path: &Path) -> Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    directory.sync_all()?;
    Ok(())
}

fn publish_noclobber(path: &Path, bytes: &[u8], expected_parent_uid: u32) -> Result<()> {
    ensure!(path.is_absolute(), "output path must be absolute");
    let parent = path.parent().context("output has no parent")?;
    ensure!(
        parent.canonicalize()? == parent,
        "output parent is not canonical"
    );
    let parent_metadata = fs::symlink_metadata(parent)?;
    ensure!(
        parent_metadata.file_type().is_dir(),
        "output parent is not a directory"
    );
    ensure!(
        parent_metadata.uid() == expected_parent_uid,
        "output parent owner mismatch"
    );
    ensure!(
        parent_metadata.permissions().mode() & 0o022 == 0,
        "output parent is group/other writable"
    );
    match read_regular(path, MAX_EVIDENCE_BYTES) {
        Ok((existing, existing_identity)) => {
            ensure!(
                existing_identity.uid == expected_parent_uid,
                "existing output owner mismatch"
            );
            ensure!(
                existing_identity.links == 1,
                "existing output is hard-linked"
            );
            ensure!(
                u32::from_str_radix(&existing_identity.mode, 8)? & 0o022 == 0,
                "existing output is group/other writable"
            );
            ensure!(
                existing == bytes,
                "existing output differs: {}",
                path.display()
            );
            return Ok(());
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|value| value.kind() == std::io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("receipt"),
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let chown_result =
        unsafe { libc::fchown(file.as_raw_fd(), expected_parent_uid, parent_metadata.gid()) };
    ensure!(
        chown_result == 0,
        "cannot set output ownership: {}",
        std::io::Error::last_os_error()
    );
    file.sync_all()?;
    fs::hard_link(&temporary, path)
        .with_context(|| format!("cannot publish {} without clobber", path.display()))?;
    fs::remove_file(&temporary)?;
    fsync_directory(parent)?;
    let (published, published_identity) = read_regular(path, MAX_EVIDENCE_BYTES)?;
    ensure!(published == bytes, "published output bytes changed");
    ensure!(
        published_identity.uid == expected_parent_uid,
        "published output owner mismatch"
    );
    ensure!(
        published_identity.links == 1,
        "published output is hard-linked"
    );
    ensure!(
        u32::from_str_radix(&published_identity.mode, 8)? & 0o022 == 0,
        "published output is group/other writable"
    );
    Ok(())
}

fn hash_regular(path: &Path, maximum: u64) -> Result<String> {
    let (bytes, _) = read_regular(path, maximum)?;
    Ok(sha256(&bytes))
}

fn archive_receipt(value: &ValidatedArchive) -> ArchiveReceipt {
    ArchiveReceipt {
        epoch: value.epoch,
        digest: value.digest.clone(),
        archive: value.archive.display().to_string(),
        sidecar: value.sidecar.display().to_string(),
        full_receipt: value.full_receipt.display().to_string(),
        archive_identity: value.archive_identity.clone(),
        sidecar_identity: value.sidecar_identity.clone(),
        full_receipt_identity: value.full_receipt_identity.clone(),
        full_verifier_sha256: value.full_verifier_sha256.clone(),
        full_script_sha256: value.full_script_sha256.clone(),
    }
}

struct ExistingPrivateExpectation<'a> {
    plan_path: &'a Path,
    plan_sha256: &'a str,
    executable_sha256: &'a str,
    verifier_path: &'a Path,
    verifier_sha256: &'a str,
    left: &'a ArchiveReceipt,
    right: &'a ArchiveReceipt,
    canonical_receipt_sha256: &'a str,
    canonical_receipt_paths: &'a [String],
}

fn validate_existing_private_receipt(
    bytes: &[u8],
    expected: &ExistingPrivateExpectation<'_>,
) -> Result<()> {
    let value: Receipt =
        serde_json::from_slice(bytes).context("invalid existing private receipt")?;
    ensure!(
        value.schema == RECEIPT_SCHEMA,
        "private receipt schema mismatch"
    );
    ensure!(
        value.recorded_unix_seconds > 0,
        "private receipt timestamp is invalid"
    );
    ensure!(
        value.plan.path == expected.plan_path.display().to_string()
            && value.plan.sha256 == expected.plan_sha256,
        "private receipt plan binding mismatch"
    );
    ensure!(
        value.bridge.executable_sha256 == expected.executable_sha256
            && value.bridge.verifier_path == expected.verifier_path.display().to_string()
            && value.bridge.verifier_sha256 == expected.verifier_sha256
            && value.bridge.verifier_status == 0,
        "private receipt executable binding mismatch"
    );
    ensure!(
        &value.left == expected.left && &value.right == expected.right,
        "private receipt archive binding mismatch"
    );
    ensure!(
        value.canonical_receipt_sha256 == expected.canonical_receipt_sha256,
        "private receipt canonical digest mismatch"
    );
    ensure!(
        value.canonical_receipt_paths == expected.canonical_receipt_paths,
        "private receipt output paths mismatch"
    );
    ensure!(
        value.authority.boundary_verified
            && !value.authority.archive_publication_authorized
            && !value.authority.local_archive_retirement_authorized
            && !value.authority.remote_mutations
            && !value.authority.r2_mutations,
        "private receipt authority mismatch"
    );
    Ok(())
}

fn main() -> Result<()> {
    let arguments = parse_arguments();
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "boundary bridge must run as root"
    );
    ensure!(
        is_digest(&arguments.plan_sha256) && is_digest(&arguments.self_sha256),
        "invalid SHA-256 argument"
    );
    let self_path = PathBuf::from("/proc/self/exe").canonicalize()?;
    ensure!(
        hash_regular(&self_path, 64 * 1024 * 1024)? == arguments.self_sha256,
        "running executable digest mismatch"
    );
    let (plan_bytes, plan_identity) = read_regular(&arguments.plan, MAX_PLAN_BYTES)?;
    ensure!(
        plan_identity.uid == 0 && plan_identity.mode == "0400" && plan_identity.links == 1,
        "plan must be root-owned, singly linked, and mode 0400"
    );
    ensure!(
        sha256(&plan_bytes) == arguments.plan_sha256,
        "plan digest mismatch"
    );
    let plan: Plan = serde_json::from_slice(&plan_bytes).context("invalid plan JSON")?;
    ensure!(plan.schema == PLAN_SCHEMA, "plan schema mismatch");
    ensure!(
        plan.right_epoch
            == plan
                .left_epoch
                .checked_add(1)
                .context("left epoch overflow")?,
        "epochs are not adjacent"
    );
    ensure!(
        !plan.authority.archive_publication_authorized,
        "plan may not authorize archive publication"
    );
    ensure!(
        !plan.authority.local_archive_retirement_authorized,
        "plan may not authorize local retirement"
    );
    ensure!(
        !plan.authority.remote_mutations && !plan.authority.r2_mutations,
        "plan may not authorize remote mutation"
    );
    ensure!(is_digest(&plan.verifier.sha256), "invalid verifier digest");
    ensure!(
        !plan.full_receipt_allowlist.verifier_sha256.is_empty()
            && !plan.full_receipt_allowlist.script_sha256.is_empty(),
        "full receipt allowlist is empty"
    );
    ensure!(
        plan.full_receipt_allowlist
            .verifier_sha256
            .iter()
            .all(|value| is_digest(value))
            && plan
                .full_receipt_allowlist
                .script_sha256
                .iter()
                .all(|value| is_digest(value)),
        "invalid full receipt allowlist"
    );
    ensure!(
        !plan.receipt_directories.is_empty(),
        "no receipt directories configured"
    );
    let unique: BTreeSet<_> = plan
        .receipt_directories
        .iter()
        .map(|value| value.path.clone())
        .collect();
    ensure!(
        unique.len() == plan.receipt_directories.len(),
        "duplicate receipt directory"
    );
    for directory in &plan.receipt_directories {
        validate_directory(directory)?;
    }
    let verifier_metadata = fs::symlink_metadata(&plan.verifier.path)?;
    ensure!(
        verifier_metadata.file_type().is_file()
            && verifier_metadata.uid() == 0
            && verifier_metadata.nlink() == 1
            && verifier_metadata.permissions().mode() & 0o222 == 0
            && verifier_metadata.permissions().mode() & 0o111 != 0,
        "verifier identity is unsafe"
    );
    ensure!(
        hash_regular(&plan.verifier.path, 64 * 1024 * 1024)? == plan.verifier.sha256,
        "verifier digest mismatch"
    );

    let left = validate_archive(
        &plan.left,
        plan.left_epoch,
        plan.expected_artifact_uid,
        &plan.full_receipt_allowlist,
    )?;
    let right = validate_archive(
        &plan.right,
        plan.right_epoch,
        plan.expected_artifact_uid,
        &plan.full_receipt_allowlist,
    )?;
    let before_left = left.clone();
    let before_right = right.clone();
    let output = Command::new(&plan.verifier.path)
        .arg("--verify-pair")
        .arg(&left.archive)
        .arg(&right.archive)
        .output()
        .context("failed to execute boundary verifier")?;
    ensure!(
        output.stdout.len() + output.stderr.len() <= MAX_VERIFIER_OUTPUT_BYTES,
        "verifier output exceeds bound"
    );
    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        return Err(anyhow!("boundary verifier failed with {}", output.status));
    }
    let left = validate_archive(
        &plan.left,
        plan.left_epoch,
        plan.expected_artifact_uid,
        &plan.full_receipt_allowlist,
    )?;
    let right = validate_archive(
        &plan.right,
        plan.right_epoch,
        plan.expected_artifact_uid,
        &plan.full_receipt_allowlist,
    )?;
    ensure!(
        left == before_left && right == before_right,
        "archive evidence changed during verification"
    );
    ensure!(
        hash_regular(&plan.verifier.path, 64 * 1024 * 1024)? == plan.verifier.sha256,
        "verifier changed during verification"
    );
    ensure!(
        hash_regular(&self_path, 64 * 1024 * 1024)? == arguments.self_sha256,
        "bridge executable changed during verification"
    );

    let canonical = format!(
        "{} {} {} {}\n",
        left.digest, right.digest, plan.verifier.sha256, arguments.self_sha256
    )
    .into_bytes();
    let receipt_name = format!("boundary-{}-{}.ok", plan.left_epoch, plan.right_epoch);
    let mut canonical_paths = Vec::new();
    for directory in &plan.receipt_directories {
        let path = directory.path.join(&receipt_name);
        publish_noclobber(&path, &canonical, directory.expected_uid)?;
        canonical_paths.push(path.display().to_string());
    }
    let private_parent = plan
        .private_receipt
        .path
        .parent()
        .context("private receipt has no parent")?;
    ensure!(
        plan.private_receipt.path.is_absolute() && private_parent.canonicalize()? == private_parent,
        "private receipt path is not absolute and canonical"
    );
    let private_parent_metadata = fs::symlink_metadata(private_parent)?;
    ensure!(
        private_parent_metadata.file_type().is_dir()
            && private_parent_metadata.uid() == plan.private_receipt.expected_parent_uid
            && private_parent_metadata.permissions().mode() & 0o077 == 0,
        "private receipt parent is not owner-only"
    );
    let canonical_receipt_sha256 = sha256(&canonical);
    let left_receipt = archive_receipt(&left);
    let right_receipt = archive_receipt(&right);
    match read_regular(&plan.private_receipt.path, MAX_EVIDENCE_BYTES) {
        Ok((existing, existing_identity)) => {
            ensure!(
                existing_identity.uid == plan.private_receipt.expected_parent_uid,
                "existing private receipt owner mismatch"
            );
            ensure!(
                existing_identity.links == 1
                    && u32::from_str_radix(&existing_identity.mode, 8)? & 0o077 == 0,
                "existing private receipt is not owner-only and singly linked"
            );
            validate_existing_private_receipt(
                &existing,
                &ExistingPrivateExpectation {
                    plan_path: &arguments.plan,
                    plan_sha256: &arguments.plan_sha256,
                    executable_sha256: &arguments.self_sha256,
                    verifier_path: &plan.verifier.path,
                    verifier_sha256: &plan.verifier.sha256,
                    left: &left_receipt,
                    right: &right_receipt,
                    canonical_receipt_sha256: &canonical_receipt_sha256,
                    canonical_receipt_paths: &canonical_paths,
                },
            )?;
            println!(
                "{}",
                serde_json::json!({
                    "private_receipt": plan.private_receipt.path,
                    "private_receipt_sha256": sha256(&existing),
                    "boundary": format!("{}-{}", plan.left_epoch, plan.right_epoch),
                    "canonical_receipt_sha256": canonical_receipt_sha256,
                    "outcome": "already-verified",
                    "remote_mutations": false,
                    "r2_mutations": false
                })
            );
            return Ok(());
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|value| value.kind() == std::io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    let receipt = Receipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        recorded_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        plan: BoundFile {
            path: arguments.plan.display().to_string(),
            sha256: arguments.plan_sha256,
        },
        bridge: BridgeReceipt {
            executable_sha256: arguments.self_sha256,
            verifier_path: plan.verifier.path.display().to_string(),
            verifier_sha256: plan.verifier.sha256,
            verifier_status: output.status.code().unwrap_or_default(),
        },
        left: left_receipt,
        right: right_receipt,
        canonical_receipt_sha256: canonical_receipt_sha256.clone(),
        canonical_receipt_paths: canonical_paths,
        authority: ReceiptAuthority {
            boundary_verified: true,
            archive_publication_authorized: false,
            local_archive_retirement_authorized: false,
            remote_mutations: false,
            r2_mutations: false,
        },
    };
    let receipt_bytes = serde_json::to_vec_pretty(&receipt)?;
    let mut receipt_with_newline = receipt_bytes;
    receipt_with_newline.push(b'\n');
    publish_noclobber(
        &plan.private_receipt.path,
        &receipt_with_newline,
        plan.private_receipt.expected_parent_uid,
    )?;
    println!(
        "{}",
        serde_json::json!({
            "private_receipt": plan.private_receipt.path,
            "private_receipt_sha256": sha256(&receipt_with_newline),
            "boundary": format!("{}-{}", plan.left_epoch, plan.right_epoch),
        "canonical_receipt_sha256": canonical_receipt_sha256,
            "remote_mutations": false,
            "r2_mutations": false
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> FileIdentity {
        FileIdentity {
            device: 1,
            inode: 2,
            bytes: 3,
            modified_nanoseconds: 4,
            changed_nanoseconds: 5,
            links: 1,
            uid: 6,
            gid: 7,
            mode: "0400".to_owned(),
        }
    }

    fn test_archive_receipt(epoch: u64, digest: &str) -> ArchiveReceipt {
        ArchiveReceipt {
            epoch,
            digest: digest.to_owned(),
            archive: format!("/archive/epoch-{epoch}.jet"),
            sidecar: format!("/archive/epoch-{epoch}.jet.sha256"),
            full_receipt: format!("/receipts/epoch-{epoch}.full.ok"),
            archive_identity: test_identity(),
            sidecar_identity: test_identity(),
            full_receipt_identity: test_identity(),
            full_verifier_sha256: "d".repeat(64),
            full_script_sha256: "e".repeat(64),
        }
    }

    #[test]
    fn sidecar_requires_canonical_epoch_name_and_newline() {
        let digest = "a".repeat(64);
        assert_eq!(
            parse_sidecar(format!("{digest}  epoch-215.jet\n").as_bytes(), 215).unwrap(),
            digest
        );
        assert!(parse_sidecar(format!("{digest}  epoch-216.jet\n").as_bytes(), 215).is_err());
        assert!(parse_sidecar(format!("{digest} epoch-215.jet\n").as_bytes(), 215).is_err());
    }

    #[test]
    fn full_receipt_is_digest_and_allowlist_bound() {
        let digest = "a".repeat(64);
        let verifier = "b".repeat(64);
        let script = "c".repeat(64);
        let allowlist = FullReceiptAllowlist {
            verifier_sha256: vec![verifier.clone()],
            script_sha256: vec![script.clone()],
        };
        assert_eq!(
            parse_full_receipt(
                format!("{digest} {verifier} {script}\n").as_bytes(),
                &digest,
                &allowlist
            )
            .unwrap(),
            (verifier, script)
        );
        assert!(
            parse_full_receipt(
                format!("{} {} {}\n", "d".repeat(64), "b".repeat(64), "c".repeat(64)).as_bytes(),
                &digest,
                &allowlist
            )
            .is_err()
        );
    }

    #[test]
    fn no_clobber_publication_is_idempotent_and_rejects_mismatch() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let output = directory.path().join("boundary-214-215.ok");
        let uid = unsafe { libc::geteuid() };
        publish_noclobber(&output, b"first\n", uid).unwrap();
        publish_noclobber(&output, b"first\n", uid).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"first\n");
        let metadata = fs::symlink_metadata(&output).unwrap();
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        assert!(publish_noclobber(&output, b"second\n", uid).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"first\n");
    }

    #[test]
    fn no_clobber_publication_rejects_symlink_output() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = directory.path().join("target");
        let output = directory.path().join("boundary-214-215.ok");
        fs::write(&target, b"receipt\n").unwrap();
        symlink(&target, &output).unwrap();
        let uid = unsafe { libc::geteuid() };

        assert!(publish_noclobber(&output, b"receipt\n", uid).is_err());
        assert!(
            fs::symlink_metadata(&output)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"receipt\n");
    }

    #[test]
    fn existing_private_receipt_requires_complete_exact_binding() {
        let plan_path = Path::new("/plans/boundary-214-215.json");
        let verifier_path = Path::new("/bin/archive-boundaries");
        let plan_sha256 = "a".repeat(64);
        let executable_sha256 = "b".repeat(64);
        let verifier_sha256 = "c".repeat(64);
        let canonical_receipt_sha256 = "f".repeat(64);
        let canonical_receipt_paths = vec![
            "/left/receipts/boundary-214-215.ok".to_owned(),
            "/right/receipts/boundary-214-215.ok".to_owned(),
        ];
        let left = test_archive_receipt(214, &"1".repeat(64));
        let right = test_archive_receipt(215, &"2".repeat(64));
        let receipt = Receipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            recorded_unix_seconds: 1,
            plan: BoundFile {
                path: plan_path.display().to_string(),
                sha256: plan_sha256.clone(),
            },
            bridge: BridgeReceipt {
                executable_sha256: executable_sha256.clone(),
                verifier_path: verifier_path.display().to_string(),
                verifier_sha256: verifier_sha256.clone(),
                verifier_status: 0,
            },
            left,
            right,
            canonical_receipt_sha256: canonical_receipt_sha256.clone(),
            canonical_receipt_paths: canonical_receipt_paths.clone(),
            authority: ReceiptAuthority {
                boundary_verified: true,
                archive_publication_authorized: false,
                local_archive_retirement_authorized: false,
                remote_mutations: false,
                r2_mutations: false,
            },
        };
        let bytes = serde_json::to_vec(&receipt).unwrap();
        let expectation = ExistingPrivateExpectation {
            plan_path,
            plan_sha256: &plan_sha256,
            executable_sha256: &executable_sha256,
            verifier_path,
            verifier_sha256: &verifier_sha256,
            left: &receipt.left,
            right: &receipt.right,
            canonical_receipt_sha256: &canonical_receipt_sha256,
            canonical_receipt_paths: &canonical_receipt_paths,
        };
        validate_existing_private_receipt(&bytes, &expectation).unwrap();

        let mut wrong_path = serde_json::to_value(&receipt).unwrap();
        wrong_path["bridge"]["verifier_path"] = serde_json::json!("/bin/wrong");
        assert!(
            validate_existing_private_receipt(
                &serde_json::to_vec(&wrong_path).unwrap(),
                &expectation
            )
            .is_err()
        );

        let mut extra_field = serde_json::to_value(&receipt).unwrap();
        extra_field["unexpected"] = serde_json::json!(true);
        assert!(
            validate_existing_private_receipt(
                &serde_json::to_vec(&extra_field).unwrap(),
                &expectation
            )
            .is_err()
        );
    }
}
