use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        env,
        ffi::OsStr,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
        path::{Path, PathBuf},
        process::{Command, Output},
        time::{SystemTime, UNIX_EPOCH},
    },
};

const PLAN_SCHEMA: &str = "jetstreamer-focused-package-capability-plan-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-private-focused-package-capability-v1";
const MAX_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_LOG_BYTES: usize = 16 * 1024 * 1024;
const EPOCH_SLOTS: u64 = 432_000;
const MIN_SNAPSHOT_SLOT: u64 = 86_831_488;
const MAX_SLOT_EXCLUSIVE: u64 = 92_448_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    bootstrap_slot: u64,
    terminal_slot: u64,
    package: PathBuf,
    package_receipt: PathBuf,
    package_receipt_sha256: String,
    package_sha256sums_sha256: String,
    node_sha256: String,
    worker_sha256: String,
    snapshot_name: String,
    snapshot_sha256: String,
    checkpoint_name: String,
    checkpoint_sha256: String,
    probe_attempt: u32,
    probe_root: PathBuf,
    receipt: PathBuf,
    run_uid: u32,
    run_gid: u32,
}

#[derive(Debug)]
struct Arguments {
    plan: PathBuf,
    plan_sha256: String,
    self_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct FileIdentity {
    path: String,
    bytes: u64,
    sha256: String,
    device: u64,
    inode: u64,
    links: u64,
    uid: u32,
    gid: u32,
    mode: String,
}

#[derive(Debug, Serialize)]
struct ProbeReceipt {
    schema: &'static str,
    recorded_unix_seconds: u64,
    invocation_id: String,
    plan_path: String,
    plan_sha256: String,
    probe_sha256: String,
    epoch: u64,
    plan: PlanReceipt,
    deployment: DeploymentReceipt,
    probe: ProbeEvidence,
    assessment: Assessment,
    mutations: Mutations,
}

#[derive(Debug, Serialize)]
struct PlanReceipt {
    bootstrap_slot: u64,
    output_slot_start: u64,
    epoch_end_slot: u64,
    terminal_slot: u64,
    successor_tail_slots: u64,
    complete_epoch_span_covered: bool,
    private_verification_tail: bool,
}

#[derive(Debug, Serialize)]
struct DeploymentReceipt {
    path: String,
    package_receipt: String,
    package_receipt_sha256: String,
    sha256sums_sha256: String,
    node: FileIdentity,
    worker: FileIdentity,
    snapshot: FileIdentity,
    checkpoint: FileIdentity,
    bootstrap_is_direct_singly_linked_member: bool,
}

#[derive(Debug, Serialize)]
struct ProbeEvidence {
    root: String,
    log: String,
    log_sha256: String,
    exit_status: i32,
    snapshot_override: String,
    snapshot_intentionally_absent: bool,
    worker_spawned: bool,
    replay_started: bool,
    archive_created: bool,
    sidecar_created: bool,
    segment_manifest_created: bool,
    live_process_references: Vec<String>,
    cleanup_pending: bool,
}

#[derive(Debug, Serialize)]
struct Assessment {
    exact_package_node_complete_span_route_passed: bool,
    package_member_hashes_passed: bool,
    snapshot_schema_or_contents_tested: bool,
    fresh_resource_admission_passed: bool,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    r2_upload_authorized: bool,
}

#[derive(Debug, Serialize)]
struct Mutations {
    local_archive_mutations: bool,
    local_cache_deletions: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn usage(program: &str) -> String {
    format!("usage: {program} --plan PATH --plan-sha256 HEX --self-sha256 HEX")
}

fn parse_args() -> Result<Arguments> {
    let mut args = env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| "jetstreamer-focused-capability-probe".into());
    let mut values = BTreeMap::<String, PathBuf>::new();
    while let Some(flag) = args.next() {
        let flag = flag
            .to_str()
            .context("arguments must be valid UTF-8")?
            .to_string();
        ensure!(
            matches!(flag.as_str(), "--plan" | "--plan-sha256" | "--self-sha256"),
            "{}\nunknown option {flag}",
            usage(&program.to_string_lossy())
        );
        let value = args
            .next()
            .with_context(|| format!("missing value for {flag}"))?;
        ensure!(
            values.insert(flag, value.into()).is_none(),
            "duplicate option"
        );
    }
    let take = |name: &str| -> Result<PathBuf> {
        values
            .get(name)
            .cloned()
            .with_context(|| format!("missing {name}"))
    };
    Ok(Arguments {
        plan: take("--plan")?,
        plan_sha256: take("--plan-sha256")?.to_string_lossy().into_owned(),
        self_sha256: take("--self-sha256")?.to_string_lossy().into_owned(),
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn hash_reader(mut reader: impl Read) -> Result<(String, u64)> {
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    // Keep the large streaming buffer off the main thread's default stack.
    let mut buffer = vec![0u8; 8 * 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        bytes = bytes
            .checked_add(count as u64)
            .context("file length overflow")?;
    }
    Ok((format!("{:x}", digest.finalize()), bytes))
}

fn open_nofollow(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))
}

fn exact_file(path: &Path, expected_uid: u32, immutable: bool) -> Result<FileIdentity> {
    ensure!(
        path.is_absolute(),
        "path is not absolute: {}",
        path.display()
    );
    let canonical = path
        .canonicalize()
        .with_context(|| format!("cannot canonicalize {}", path.display()))?;
    ensure!(canonical == path, "path is not exact: {}", path.display());
    let file = open_nofollow(path)?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "not a regular file: {}", path.display());
    ensure!(
        before.nlink() == 1,
        "file is not singly linked: {}",
        path.display()
    );
    ensure!(
        before.uid() == expected_uid,
        "unexpected owner: {}",
        path.display()
    );
    if immutable {
        ensure!(
            before.mode() & 0o222 == 0,
            "file is writable: {}",
            path.display()
        );
    }
    let (sha256, bytes) = hash_reader(&file)?;
    let after = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    let identity = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        )
    };
    ensure!(
        current.is_file()
            && !current.file_type().is_symlink()
            && identity(&before) == identity(&after)
            && identity(&before) == identity(&current),
        "file changed while hashing: {}",
        path.display()
    );
    ensure!(bytes == before.len(), "short hash read: {}", path.display());
    Ok(FileIdentity {
        path: path.display().to_string(),
        bytes,
        sha256,
        device: before.dev(),
        inode: before.ino(),
        links: before.nlink(),
        uid: before.uid(),
        gid: before.gid(),
        mode: format!("{:04o}", before.mode() & 0o7777),
    })
}

fn read_plan(path: &Path, expected_sha256: &str) -> Result<Plan> {
    ensure!(is_sha256(expected_sha256), "invalid plan SHA-256");
    let metadata = fs::symlink_metadata(path)?;
    ensure!(metadata.len() <= MAX_PLAN_BYTES, "plan is too large");
    let identity = exact_file(path, 0, true)?;
    ensure!(identity.sha256 == expected_sha256, "plan SHA-256 mismatch");
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).context("invalid plan JSON")
}

fn validate_package_receipt(plan: &Plan) -> Result<String> {
    ensure!(
        is_sha256(&plan.package_receipt_sha256),
        "invalid package receipt SHA-256"
    );
    let identity = exact_file(&plan.package_receipt, 0, true)?;
    ensure!(
        identity.sha256 == plan.package_receipt_sha256,
        "package receipt SHA-256 mismatch"
    );
    let receipt: serde_json::Value = serde_json::from_slice(&fs::read(&plan.package_receipt)?)?;
    ensure!(
        matches!(
            receipt.get("schema").and_then(|value| value.as_str()),
            Some("jetstreamer-private-immutable-complete-span-package-v1")
                | Some("jetstreamer-private-configured-immutable-complete-span-package-v1")
        ),
        "unexpected package receipt schema"
    );
    ensure!(
        receipt.get("epoch").and_then(|value| value.as_u64()) == Some(plan.epoch),
        "package receipt epoch mismatch"
    );
    let package = receipt
        .get("package")
        .and_then(|value| value.as_object())
        .context("package receipt lacks package evidence")?;
    ensure!(
        package.get("path").and_then(|value| value.as_str())
            == Some(plan.package.to_string_lossy().as_ref()),
        "package receipt path mismatch"
    );
    ensure!(
        package
            .get("sha256sums_sha256")
            .and_then(|value| value.as_str())
            == Some(plan.package_sha256sums_sha256.as_str()),
        "package receipt SHA256SUMS mismatch"
    );
    let members = package
        .get("members")
        .and_then(|value| value.as_object())
        .context("package receipt lacks member evidence")?;
    for (name, digest) in [
        ("jetstreamer-node", &plan.node_sha256),
        (
            "jetstreamer-historical-worker-v1-6-16-store8",
            &plan.worker_sha256,
        ),
        (plan.snapshot_name.as_str(), &plan.snapshot_sha256),
        (plan.checkpoint_name.as_str(), &plan.checkpoint_sha256),
    ] {
        ensure!(
            members
                .get(name)
                .and_then(|value| value.get("sha256"))
                .and_then(|value| value.as_str())
                == Some(digest.as_str()),
            "package receipt member mismatch for {name}"
        );
    }
    let attestation = receipt
        .get("attestation")
        .and_then(|value| value.as_object())
        .context("package receipt lacks attestation")?;
    for (key, expected) in [
        ("package_ready", true),
        ("complete_epoch_span_covered", true),
        ("launch_authorized", false),
        ("publication_authorized", false),
        ("r2_upload_authorized", false),
        ("remote_mutations", false),
        ("r2_mutations", false),
    ] {
        ensure!(
            attestation.get(key).and_then(|value| value.as_bool()) == Some(expected),
            "package receipt attestation mismatch for {key}"
        );
    }
    Ok(identity.sha256)
}

fn verify_self(expected_sha256: &str) -> Result<String> {
    ensure!(is_sha256(expected_sha256), "invalid self SHA-256");
    let executable = fs::read_link("/proc/self/exe")?;
    let identity = exact_file(&executable, 0, true)?;
    ensure!(
        identity.sha256 == expected_sha256,
        "running executable SHA-256 mismatch"
    );
    Ok(identity.sha256)
}

fn exact_directory(path: &Path, expected_uid: u32, immutable: bool) -> Result<fs::Metadata> {
    ensure!(path.is_absolute(), "directory path is not absolute");
    ensure!(path.canonicalize()? == path, "directory path is not exact");
    let metadata = fs::symlink_metadata(path)?;
    ensure!(metadata.is_dir(), "not a directory: {}", path.display());
    ensure!(metadata.uid() == expected_uid, "unexpected directory owner");
    if immutable {
        ensure!(metadata.mode() & 0o222 == 0, "directory is writable");
    }
    Ok(metadata)
}

fn parse_sha256sums(path: &Path) -> Result<BTreeMap<String, String>> {
    let text = fs::read_to_string(path)?;
    let mut entries = BTreeMap::new();
    for line in text.lines() {
        let (digest, name) = line
            .split_once("  ")
            .with_context(|| format!("invalid SHA256SUMS line: {line:?}"))?;
        ensure!(is_sha256(digest), "invalid SHA256SUMS digest");
        ensure!(
            !name.contains('/') && name != "." && name != "..",
            "unsafe member name"
        );
        ensure!(
            entries
                .insert(name.to_string(), digest.to_string())
                .is_none(),
            "duplicate member"
        );
    }
    ensure!(!entries.is_empty(), "empty SHA256SUMS");
    Ok(entries)
}

fn require_member(
    package: &Path,
    entries: &BTreeMap<String, String>,
    name: &str,
    expected: &str,
    executable: bool,
) -> Result<FileIdentity> {
    ensure!(!name.contains('/'), "member name contains a slash");
    ensure!(is_sha256(expected), "invalid expected member SHA-256");
    ensure!(
        entries.get(name).map(String::as_str) == Some(expected),
        "SHA256SUMS member mismatch for {name}"
    );
    let identity = exact_file(&package.join(name), 0, true)?;
    ensure!(
        identity.sha256 == expected,
        "member SHA-256 mismatch for {name}"
    );
    if executable {
        ensure!(
            u32::from_str_radix(&identity.mode, 8)? & 0o111 != 0,
            "member is not executable: {name}"
        );
    }
    Ok(identity)
}

fn mkdir_owned(path: &Path, uid: u32, gid: u32) -> Result<()> {
    fs::create_dir(path).with_context(|| format!("cannot create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    ensure!(
        unsafe { libc::chown(c_path.as_ptr(), uid, gid) } == 0,
        "chown failed for {}",
        path.display()
    );
    Ok(())
}

fn fsync_directory(path: &Path) -> Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(path)?;
    directory.sync_all()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fsync_directory(path.parent().context("output has no parent")?)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn expected_log_markers(plan: &Plan, missing_snapshot: &Path) -> [String; 4] {
    let output_slot_start = plan.epoch * EPOCH_SLOTS;
    [
        format!(
            "focused qualification requested: epoch {}, bootstrap {}, replay {}..={}",
            plan.epoch,
            plan.bootstrap_slot,
            plan.bootstrap_slot + 1,
            plan.terminal_slot
        ),
        format!(
            "epoch {}: selected execution profile solana-v1.6.16 (Candidate) from slots {}..{}",
            plan.epoch,
            output_slot_start,
            plan.terminal_slot + 1
        ),
        "execution=solana-v1.6.16-epochs-203-213-focused-qualification-candidate".to_string(),
        format!("failed to read snapshot {}", missing_snapshot.display()),
    ]
}

fn validate_output(plan: &Plan, missing_snapshot: &Path, output: &Output) -> Result<()> {
    ensure!(
        output.status.code() == Some(1),
        "probe exit status was not 1"
    );
    let log = combined_output(output)?;
    let text = String::from_utf8_lossy(&log);
    for marker in expected_log_markers(plan, missing_snapshot) {
        ensure!(
            text.contains(&marker),
            "probe did not reach expected gate: {marker}"
        );
    }
    ensure!(
        !text.to_ascii_lowercase().contains("replaying"),
        "probe unexpectedly started replay"
    );
    Ok(())
}

fn combined_output(output: &Output) -> Result<Vec<u8>> {
    let length = output
        .stdout
        .len()
        .checked_add(output.stderr.len())
        .context("probe log length overflow")?;
    ensure!(length <= MAX_LOG_BYTES, "probe log exceeded limit");
    let mut log = Vec::with_capacity(length);
    log.extend_from_slice(&output.stdout);
    log.extend_from_slice(&output.stderr);
    Ok(log)
}

fn is_artifact(path: &Path) -> bool {
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
    name.ends_with(".jet")
        || name.ends_with(".jet.sha256")
        || name.to_ascii_lowercase().contains("segment-manifest")
}

fn walk_artifacts(root: &Path, found: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(!metadata.file_type().is_symlink(), "symlink in probe tree");
        if metadata.is_dir() {
            walk_artifacts(&path, found)?;
        } else if metadata.is_file() && is_artifact(&path) {
            found.push(path);
        } else {
            ensure!(metadata.is_file(), "unexpected probe member type");
        }
    }
    Ok(())
}

fn content_references(content: &[u8], needle: &[u8]) -> bool {
    let mut offset = 0usize;
    let boundaries = b"/\0\n\r\t '\";|&()<>[]{}";
    while let Some(relative) = content[offset..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let index = offset + relative;
        let end = index + needle.len();
        if end == content.len() || boundaries.contains(&content[end]) {
            return true;
        }
        offset = index + 1;
    }
    false
}

fn path_is_at_or_below(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn process_references(probe_root: &Path, worker: &Path) -> Result<Vec<String>> {
    let mut references = Vec::new();
    let probe_bytes = probe_root.as_os_str().as_bytes();
    let worker_bytes = worker.as_os_str().as_bytes();
    let own_pid = std::process::id().to_string();
    for entry in fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let pid = entry.file_name();
        let pid_text = pid.to_string_lossy();
        if pid_text == own_pid || !pid_text.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let process = entry.path();
        for name in ["cmdline", "maps"] {
            match fs::read(process.join(name)) {
                Ok(content) => {
                    if content_references(&content, probe_bytes)
                        || content_references(&content, worker_bytes)
                    {
                        references.push(format!("pid {pid_text} {name}"));
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
                    ) => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("cannot inspect pid {pid_text} {name}"));
                }
            }
        }
        for name in ["cwd", "root", "exe"] {
            match fs::read_link(process.join(name)) {
                Ok(target) => {
                    let target = PathBuf::from(
                        target
                            .as_os_str()
                            .to_string_lossy()
                            .trim_end_matches(" (deleted)"),
                    );
                    if path_is_at_or_below(&target, probe_root) || target == worker {
                        references.push(format!("pid {pid_text} {name}"));
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
                    ) => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("cannot inspect pid {pid_text} {name}"));
                }
            }
        }
        match fs::read_dir(process.join("fd")) {
            Ok(descriptors) => {
                for descriptor in descriptors {
                    let descriptor = descriptor?;
                    match fs::read_link(descriptor.path()) {
                        Ok(target) => {
                            let target = PathBuf::from(
                                target
                                    .as_os_str()
                                    .to_string_lossy()
                                    .trim_end_matches(" (deleted)"),
                            );
                            if path_is_at_or_below(&target, probe_root) || target == worker {
                                references.push(format!(
                                    "pid {pid_text} fd {}",
                                    descriptor.file_name().to_string_lossy()
                                ));
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
                            ) => {}
                        Err(error) => {
                            return Err(error)
                                .with_context(|| format!("cannot inspect pid {pid_text} fd"));
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot inspect pid {pid_text} descriptors"));
            }
        }
    }
    Ok(references)
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(plan.schema == PLAN_SCHEMA, "plan schema mismatch");
    ensure!(
        (203..=212).contains(&plan.epoch),
        "epoch outside focused capability range"
    );
    ensure!(
        plan.terminal_slot > (plan.epoch + 1) * EPOCH_SLOTS - 1
            && plan.terminal_slot < MAX_SLOT_EXCLUSIVE,
        "terminal slot does not cover the epoch"
    );
    ensure!(
        (MIN_SNAPSHOT_SLOT..plan.epoch * EPOCH_SLOTS).contains(&plan.bootstrap_slot),
        "bootstrap does not precede epoch output"
    );
    ensure!(
        plan.package.is_absolute()
            && plan.package_receipt.is_absolute()
            && plan.probe_root.is_absolute()
            && plan.receipt.is_absolute(),
        "plan paths must be absolute"
    );
    let expected_package = format!(
        "/var/lib/jetstreamer/horizon-focused-{}-complete-span-store8-ca2e38b-v1",
        plan.epoch
    );
    ensure!(
        plan.package.to_str() == Some(expected_package.as_str()),
        "package path is not canonical for the epoch"
    );
    validate_campaign_receipt_path(
        &plan.package_receipt,
        &format!(
            "epoch{}-complete-span-store8-immutable-package-ca2e38b-",
            plan.epoch
        ),
    )
    .context("package receipt path is not canonical for the epoch")?;
    let expected_probe_root = format!(
        "/home/ubuntu/.jetstreamer-private/qualification-{}/package-capability-probe-rust-ca2e38b-v{}",
        plan.epoch, plan.probe_attempt
    );
    ensure!(
        plan.probe_root.to_str() == Some(expected_probe_root.as_str()),
        "probe root is not canonical for the epoch"
    );
    validate_campaign_receipt_path(
        &plan.receipt,
        &format!(
            "epoch{}-complete-span-package-capability-ca2e38b-rust-",
            plan.epoch
        ),
    )
    .context("receipt path is not canonical for the epoch")?;
    ensure!(
        plan.run_uid == 1000 && plan.run_gid == 1000,
        "unexpected probe identity"
    );
    ensure!(
        (1..=32).contains(&plan.probe_attempt),
        "probe attempt is outside the bounded range"
    );
    for digest in [
        &plan.package_sha256sums_sha256,
        &plan.node_sha256,
        &plan.worker_sha256,
        &plan.snapshot_sha256,
        &plan.checkpoint_sha256,
    ] {
        ensure!(is_sha256(digest), "plan contains invalid SHA-256");
    }
    for name in [&plan.snapshot_name, &plan.checkpoint_name] {
        ensure!(
            !name.contains('/') && !name.is_empty(),
            "unsafe package member name"
        );
    }
    ensure!(
        plan.snapshot_name
            .starts_with(&format!("snapshot-{}-", plan.bootstrap_slot)),
        "snapshot filename does not bind bootstrap slot"
    );
    ensure!(
        plan.checkpoint_name == format!("epoch-hashes-{}-complete-span.txt", plan.epoch),
        "checkpoint filename is not canonical"
    );
    Ok(())
}

fn validate_campaign_receipt_path(path: &Path, prefix: &str) -> Result<()> {
    ensure!(
        path.parent()
            == Some(Path::new(
                "/home/ubuntu/.jetstreamer-private/campaign-state"
            )),
        "unexpected receipt parent"
    );
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid receipt filename")?;
    ensure!(
        name.starts_with(prefix) && name.ends_with(".json"),
        "unexpected receipt filename"
    );
    let suffix = &name[prefix.len()..name.len() - ".json".len()];
    ensure!(
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "invalid receipt filename suffix"
    );
    Ok(())
}

fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "probe must run as root");
    let arguments = parse_args()?;
    let probe_sha256 = verify_self(&arguments.self_sha256)?;
    let plan = read_plan(&arguments.plan, &arguments.plan_sha256)?;
    validate_plan(&plan)?;
    let invocation_id = env::var("INVOCATION_ID").context("INVOCATION_ID is required")?;
    ensure!(
        invocation_id.len() == 32 && invocation_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid invocation ID"
    );

    let package_metadata = exact_directory(&plan.package, 0, true)?;
    ensure!(
        package_metadata.mode() & 0o7777 == 0o555,
        "package mode is not 0555"
    );
    let sums_path = plan.package.join("SHA256SUMS");
    let sums_identity = exact_file(&sums_path, 0, true)?;
    ensure!(
        sums_identity.sha256 == plan.package_sha256sums_sha256,
        "package SHA256SUMS changed"
    );
    let sums = parse_sha256sums(&sums_path)?;
    let package_receipt_sha256 = validate_package_receipt(&plan)?;
    let node = require_member(
        &plan.package,
        &sums,
        "jetstreamer-node",
        &plan.node_sha256,
        true,
    )?;
    let worker = require_member(
        &plan.package,
        &sums,
        "jetstreamer-historical-worker-v1-6-16-store8",
        &plan.worker_sha256,
        true,
    )?;
    let snapshot = require_member(
        &plan.package,
        &sums,
        &plan.snapshot_name,
        &plan.snapshot_sha256,
        false,
    )?;
    let checkpoint = require_member(
        &plan.package,
        &sums,
        &plan.checkpoint_name,
        &plan.checkpoint_sha256,
        false,
    )?;

    ensure!(!plan.probe_root.exists(), "probe root already exists");
    ensure!(!plan.receipt.exists(), "receipt already exists");
    let probe_parent = plan
        .probe_root
        .parent()
        .context("probe root has no parent")?;
    let probe_parent_metadata = exact_directory(probe_parent, plan.run_uid, false)?;
    ensure!(
        probe_parent_metadata.mode() & 0o077 == 0,
        "probe parent is not owner-only"
    );
    mkdir_owned(&plan.probe_root, plan.run_uid, plan.run_gid)?;
    let destination = plan.probe_root.join("dest");
    let private_root = plan.probe_root.join("run-state");
    let scratch = plan.probe_root.join("scratch");
    for directory in [&destination, &private_root, &scratch] {
        mkdir_owned(directory, plan.run_uid, plan.run_gid)?;
    }
    fsync_directory(&plan.probe_root)?;

    let missing_snapshot = plan.probe_root.join("missing").join(&plan.snapshot_name);
    ensure!(
        !missing_snapshot.exists(),
        "deliberately absent snapshot exists"
    );
    let archive = destination.join(format!(
        "epoch-{}-through-{}.jet",
        plan.epoch, plan.terminal_slot
    ));
    let mut command = Command::new(&node.path);
    command
        .arg(plan.epoch.to_string())
        .arg(&destination)
        .arg("--verify")
        .arg(format!("--qualification-end-slot={}", plan.terminal_slot))
        .arg(format!("--snapshot-archive={}", missing_snapshot.display()))
        .arg(format!("--epoch-hashes={}", checkpoint.path))
        .arg(format!("--horizon-output={}", archive.display()))
        .arg(format!("--replay-scratch={}", scratch.display()))
        .env("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1")
        .env("JETSTREAMER_HISTORICAL_WORKER_V1_6_16", &worker.path)
        .env("JETSTREAMER_PRIVATE_RUN_ROOT", &private_root)
        .env("RUST_LOG", "info")
        .env("SOLANA_RAYON_THREADS", "16")
        .current_dir(&plan.package);
    let run_uid = plan.run_uid;
    let run_gid = plan.run_gid;
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(run_gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(run_uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command
        .output()
        .context("failed to execute exact package node")?;
    validate_output(&plan, &missing_snapshot, &output)?;
    let combined_log = combined_output(&output)?;
    let log = plan.probe_root.join("probe.log");
    let log_sha256 = write_new(&log, &combined_log, 0o400)?;
    let mut artifacts = Vec::new();
    walk_artifacts(&plan.probe_root, &mut artifacts)?;
    ensure!(
        artifacts.is_empty(),
        "probe created replay artifacts: {artifacts:?}"
    );
    let references = process_references(&plan.probe_root, Path::new(&worker.path))?;
    ensure!(
        references.is_empty(),
        "probe left live process references: {references:?}"
    );

    let epoch_end = (plan.epoch + 1) * EPOCH_SLOTS - 1;
    let receipt = ProbeReceipt {
        schema: RECEIPT_SCHEMA,
        recorded_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        invocation_id,
        plan_path: arguments.plan.display().to_string(),
        plan_sha256: arguments.plan_sha256,
        probe_sha256,
        epoch: plan.epoch,
        plan: PlanReceipt {
            bootstrap_slot: plan.bootstrap_slot,
            output_slot_start: plan.epoch * EPOCH_SLOTS,
            epoch_end_slot: epoch_end,
            terminal_slot: plan.terminal_slot,
            successor_tail_slots: plan.terminal_slot - epoch_end,
            complete_epoch_span_covered: true,
            private_verification_tail: true,
        },
        deployment: DeploymentReceipt {
            path: plan.package.display().to_string(),
            package_receipt: plan.package_receipt.display().to_string(),
            package_receipt_sha256,
            sha256sums_sha256: sums_identity.sha256,
            node,
            worker,
            snapshot,
            checkpoint,
            bootstrap_is_direct_singly_linked_member: true,
        },
        probe: ProbeEvidence {
            root: plan.probe_root.display().to_string(),
            log: log.display().to_string(),
            log_sha256,
            exit_status: 1,
            snapshot_override: missing_snapshot.display().to_string(),
            snapshot_intentionally_absent: true,
            worker_spawned: false,
            replay_started: false,
            archive_created: false,
            sidecar_created: false,
            segment_manifest_created: false,
            live_process_references: references,
            cleanup_pending: true,
        },
        assessment: Assessment {
            exact_package_node_complete_span_route_passed: true,
            package_member_hashes_passed: true,
            snapshot_schema_or_contents_tested: false,
            fresh_resource_admission_passed: false,
            replay_launch_authorized: false,
            publication_authorized: false,
            r2_upload_authorized: false,
        },
        mutations: Mutations {
            local_archive_mutations: false,
            local_cache_deletions: false,
            remote_mutations: false,
            r2_mutations: false,
        },
    };
    let data = serde_json::to_vec_pretty(&receipt)?;
    let mut data_with_newline = data;
    data_with_newline.push(b'\n');
    let receipt_parent_metadata = exact_directory(
        plan.receipt.parent().context("receipt has no parent")?,
        0,
        false,
    )?;
    ensure!(
        receipt_parent_metadata.mode() & 0o077 == 0,
        "receipt parent is not owner-only"
    );
    let receipt_sha256 = write_new(&plan.receipt, &data_with_newline, 0o400)?;
    println!(
        "{}",
        serde_json::json!({
            "receipt": plan.receipt,
            "receipt_sha256": receipt_sha256,
            "epoch": plan.epoch,
            "replay_started": false,
            "replay_launch_authorized": false,
            "publication_authorized": false,
            "r2_mutations": false,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn plan() -> Plan {
        Plan {
            schema: PLAN_SCHEMA.to_string(),
            epoch: 209,
            bootstrap_slot: 90_287_519,
            terminal_slot: 91_151_575,
            package: "/var/lib/jetstreamer/horizon-focused-209-complete-span-store8-ca2e38b-v1".into(),
            package_receipt: "/home/ubuntu/.jetstreamer-private/campaign-state/epoch209-complete-span-store8-immutable-package-ca2e38b-20261016-v1.json".into(),
            package_receipt_sha256: "f".repeat(64),
            package_sha256sums_sha256: "0".repeat(64),
            node_sha256: "1".repeat(64),
            worker_sha256: "2".repeat(64),
            snapshot_name: "snapshot-90287519-Hash.tar.zst".to_string(),
            snapshot_sha256: "3".repeat(64),
            checkpoint_name: "epoch-hashes-209-complete-span.txt".to_string(),
            checkpoint_sha256: "4".repeat(64),
            probe_attempt: 4,
            probe_root: "/home/ubuntu/.jetstreamer-private/qualification-209/package-capability-probe-rust-ca2e38b-v4".into(),
            receipt: "/home/ubuntu/.jetstreamer-private/campaign-state/epoch209-complete-span-package-capability-ca2e38b-rust-20261016-v1.json".into(),
            run_uid: 1000,
            run_gid: 1000,
        }
    }

    fn output(text: &str, code: i32) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: text.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn accepts_expected_missing_snapshot_gate() {
        let plan = plan();
        let missing = plan.probe_root.join("missing").join(&plan.snapshot_name);
        let text = expected_log_markers(&plan, &missing).join("\n");
        validate_output(&plan, &missing, &output(&text, 1)).unwrap();
    }

    #[test]
    fn accepts_expected_gate_on_stderr() {
        let plan = plan();
        let missing = plan.probe_root.join("missing").join(&plan.snapshot_name);
        let mut output = output("", 1);
        output.stderr = expected_log_markers(&plan, &missing)
            .join("\n")
            .into_bytes();
        validate_output(&plan, &missing, &output).unwrap();
    }

    #[test]
    fn rejects_replay_marker() {
        let plan = plan();
        let missing = plan.probe_root.join("missing").join(&plan.snapshot_name);
        let text = format!(
            "{}\nreplaying slot 1",
            expected_log_markers(&plan, &missing).join("\n")
        );
        assert!(validate_output(&plan, &missing, &output(&text, 1)).is_err());
    }

    #[test]
    fn rejects_wrong_exit_status() {
        let plan = plan();
        let missing = plan.probe_root.join("missing").join(&plan.snapshot_name);
        let text = expected_log_markers(&plan, &missing).join("\n");
        assert!(validate_output(&plan, &missing, &output(&text, 0)).is_err());
    }

    #[test]
    fn descendant_path_matching_is_boundary_safe() {
        let root = Path::new("/tmp/probe");
        assert!(path_is_at_or_below(Path::new("/tmp/probe/a"), root));
        assert!(!path_is_at_or_below(Path::new("/tmp/probe-other"), root));
    }

    #[test]
    fn accepts_canonical_plan_and_rejects_worker_bound_overflow() {
        let mut plan = plan();
        validate_plan(&plan).unwrap();
        plan.terminal_slot = MAX_SLOT_EXCLUSIVE;
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn accepts_epoch_203_with_unique_receipts() {
        let mut current = plan();
        current.epoch = 203;
        current.bootstrap_slot = 87_695_515;
        current.terminal_slot = 88_559_361;
        current.package =
            "/var/lib/jetstreamer/horizon-focused-203-complete-span-store8-ca2e38b-v1".into();
        current.package_receipt = "/home/ubuntu/.jetstreamer-private/campaign-state/epoch203-complete-span-store8-immutable-package-ca2e38b-20261017-v1.json".into();
        current.snapshot_name =
            "snapshot-87695515-CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX.tar.zst".into();
        current.checkpoint_name = "epoch-hashes-203-complete-span.txt".into();
        current.probe_root = "/home/ubuntu/.jetstreamer-private/qualification-203/package-capability-probe-rust-ca2e38b-v5".into();
        current.probe_attempt = 5;
        current.receipt = "/home/ubuntu/.jetstreamer-private/campaign-state/epoch203-complete-span-package-capability-ca2e38b-rust-20261017-v1.json".into();
        validate_plan(&current).unwrap();
    }

    #[test]
    fn rejects_noncanonical_receipt_suffixes() {
        let mut bad = plan();
        bad.package_receipt = "/home/ubuntu/.jetstreamer-private/campaign-state/epoch209-complete-span-store8-immutable-package-ca2e38b-.json".into();
        assert!(validate_plan(&bad).is_err());
        let mut bad = plan();
        bad.receipt = "/home/ubuntu/.jetstreamer-private/campaign-state/epoch209-complete-span-package-capability-ca2e38b-rust-bad.name.json".into();
        assert!(validate_plan(&bad).is_err());
    }

    #[test]
    fn hashes_input_larger_than_the_default_thread_stack() {
        let input = vec![0x5au8; 9 * 1024 * 1024];
        let (digest, bytes) = hash_reader(input.as_slice()).unwrap();
        assert_eq!(bytes, input.len() as u64);
        assert_eq!(digest, format!("{:x}", Sha256::digest(&input)));
    }
}
