use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt},
            prelude::OsStrExt,
        },
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    },
};

const PLAN_SCHEMA: &str = "jetstreamer-focused-package-attestation-plan-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-private-configured-immutable-complete-span-package-v1";
const DEPLOYMENT_RECEIPT_SCHEMA: &str = "jetstreamer-sealed-deployment-receipt-v1";
const MANIFEST_SCHEMA: &str = "jetstreamer-private-focused-qualification-deployment-v5";
const MAX_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MINIMUM_FREE_BYTES: u64 = 4_700_000_000_000;
const EPOCH_SLOTS: u64 = 432_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    package: PathBuf,
    source_snapshot: PathBuf,
    snapshot_name: String,
    snapshot_sha256: String,
    checkpoint_name: String,
    checkpoint_sha256: String,
    sha256sums_sha256: String,
    deployment_receipt_sha256: String,
    manifest_sha256: String,
    epoch_end_slot: u64,
    terminal_root_slot: u64,
    successor_tail_slots: u64,
    receipt: PathBuf,
}

#[derive(Debug)]
struct Arguments {
    plan: PathBuf,
    plan_sha256: String,
    self_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct FileIdentity {
    sha256: String,
    bytes: u64,
    device: u64,
    inode: u64,
    links: u64,
    uid: u32,
    gid: u32,
    mode: String,
}

#[derive(Debug, Deserialize)]
struct DeploymentReceipt {
    schema: String,
    destination: String,
    members: Vec<DeploymentMember>,
    publication_authorized: bool,
    replay_launch_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Debug, Deserialize)]
struct DeploymentMember {
    name: String,
    sha256: String,
    bytes: u64,
    mode: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    schema: String,
    epoch: u64,
    bootstrap: Bootstrap,
    checkpoint: Checkpoint,
    focused_plan: FocusedPlan,
    gates: Gates,
    mutations: ManifestMutations,
}

#[derive(Debug, Deserialize)]
struct Bootstrap {
    filename: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Checkpoint {
    filename: String,
    sha256: String,
    terminal_slot: u64,
}

#[derive(Debug, Deserialize)]
struct FocusedPlan {
    epoch: u64,
    output_slot_start: u64,
    epoch_end_slot: u64,
    terminal_root_slot: u64,
    complete_epoch_span_covered: bool,
    private_verification_tail: bool,
    successor_tail_slots: u64,
    canonical_sidecar_authorized: bool,
}

#[derive(Debug, Deserialize)]
struct Gates {
    complete_epoch_span_covered: bool,
    exact_node_complete_span_capability_passed: bool,
    source_content_revalidated: bool,
    immutable_package_sealed: bool,
    fresh_replay_resource_admission_passed: bool,
    launch_authorized: bool,
    plugin_verification_authorized: bool,
    publication_authorized: bool,
    r2_upload_authorized: bool,
}

#[derive(Debug, Deserialize)]
struct ManifestMutations {
    new_replay_launched: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Debug, Serialize)]
struct Receipt {
    schema: &'static str,
    recorded_unix_seconds: u64,
    epoch: u64,
    configuration: ConfigurationReceipt,
    plan: PlanReceipt,
    package: PackageReceipt,
    snapshot_copy: SnapshotCopyReceipt,
    resource_check: ResourceCheck,
    attestation: Attestation,
    attester: Attester,
}

#[derive(Debug, Serialize)]
struct ConfigurationReceipt {
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct PlanReceipt {
    epoch_end_slot: u64,
    terminal_root_slot: u64,
    successor_tail_slots: u64,
    complete_epoch_span_covered: bool,
    private_verification_tail: bool,
}

#[derive(Debug, Serialize)]
struct PackageReceipt {
    path: String,
    device: u64,
    inode: u64,
    mode: String,
    sha256sums_sha256: String,
    deployment_seal_receipt_sha256: String,
    deployment_manifest_sha256: String,
    members: BTreeMap<String, FileIdentity>,
}

#[derive(Debug, Serialize)]
struct SnapshotCopyReceipt {
    source_path: String,
    source_device: u64,
    source_inode: u64,
    source_links: u64,
    package_path: String,
    package_device: u64,
    package_inode: u64,
    package_links: u64,
    distinct_inode: bool,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct ResourceCheck {
    filesystem_free_bytes: u64,
    minimum_free_bytes: u64,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct Attestation {
    package_ready: bool,
    complete_epoch_span_covered: bool,
    fresh_replay_resource_admission_passed: bool,
    launch_authorized: bool,
    new_replay_launched: bool,
    plugin_verification_authorized: bool,
    publication_authorized: bool,
    r2_upload_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Debug, Serialize)]
struct Attester {
    sha256: String,
}

fn usage(program: &str) -> String {
    format!("usage: {program} --plan PATH --plan-sha256 HEX --self-sha256 HEX")
}

fn parse_args() -> Result<Arguments> {
    let mut args = env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| "jetstreamer-focused-package-attest".into());
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
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_reader(mut reader: impl Read) -> Result<(String, u64)> {
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
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

fn exact_file(path: &Path, expected_uid: u32, immutable: bool) -> Result<FileIdentity> {
    ensure!(
        path.is_absolute(),
        "path is not absolute: {}",
        path.display()
    );
    ensure!(
        path.canonicalize()? == path,
        "path is not exact: {}",
        path.display()
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
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
        sha256,
        bytes,
        device: before.dev(),
        inode: before.ino(),
        links: before.nlink(),
        uid: before.uid(),
        gid: before.gid(),
        mode: format!("{:04o}", before.mode() & 0o7777),
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(metadata.len() <= MAX_JSON_BYTES, "JSON file is too large");
    serde_json::from_slice(&fs::read(path)?).context("invalid JSON")
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
            !name.is_empty() && !name.contains('/') && name != "." && name != "..",
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

fn validate_receipt_path(path: &Path, epoch: u64) -> Result<()> {
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
        .context("invalid receipt name")?;
    let prefix = format!("epoch{epoch}-complete-span-store8-immutable-package-ca2e38b-");
    ensure!(
        name.starts_with(&prefix) && name.ends_with(".json"),
        "unexpected receipt name"
    );
    let suffix = &name[prefix.len()..name.len() - 5];
    ensure!(
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "invalid receipt suffix"
    );
    Ok(())
}

fn canonical_package_path(epoch: u64) -> String {
    // Epochs 207 and 209 were resealed after their original packages were found
    // to carry obsolete complete-span evidence. Keep that correction narrowly
    // allowlisted so a plan cannot select an arbitrary package revision.
    let revision = if matches!(epoch, 207 | 209) {
        "v2"
    } else {
        "v1"
    };
    format!("/var/lib/jetstreamer/horizon-focused-{epoch}-complete-span-store8-ca2e38b-{revision}")
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(plan.schema == PLAN_SCHEMA, "plan schema mismatch");
    ensure!(
        (203..=212).contains(&plan.epoch),
        "epoch outside approved focused range"
    );
    let expected_package = canonical_package_path(plan.epoch);
    ensure!(
        plan.package.to_str() == Some(&expected_package),
        "non-canonical package path"
    );
    ensure!(
        plan.source_snapshot.is_absolute(),
        "source snapshot path is not absolute"
    );
    ensure!(
        plan.snapshot_name.starts_with("snapshot-") && !plan.snapshot_name.contains('/'),
        "unsafe snapshot name"
    );
    ensure!(
        plan.checkpoint_name == format!("epoch-hashes-{}-complete-span.txt", plan.epoch),
        "checkpoint name mismatch"
    );
    for digest in [
        &plan.snapshot_sha256,
        &plan.checkpoint_sha256,
        &plan.sha256sums_sha256,
        &plan.deployment_receipt_sha256,
        &plan.manifest_sha256,
    ] {
        ensure!(is_sha256(digest), "invalid plan SHA-256");
    }
    ensure!(
        plan.epoch_end_slot == (plan.epoch + 1) * EPOCH_SLOTS - 1,
        "epoch end mismatch"
    );
    ensure!(
        plan.terminal_root_slot > plan.epoch_end_slot,
        "terminal root does not cover epoch"
    );
    ensure!(
        plan.terminal_root_slot - plan.epoch_end_slot == plan.successor_tail_slots,
        "successor tail mismatch"
    );
    validate_receipt_path(&plan.receipt, plan.epoch)?;
    Ok(())
}

fn validate_manifest(plan: &Plan, manifest: &Manifest) -> Result<()> {
    ensure!(
        manifest.schema == MANIFEST_SCHEMA,
        "manifest schema mismatch"
    );
    ensure!(manifest.epoch == plan.epoch, "manifest epoch mismatch");
    ensure!(
        manifest.bootstrap.filename == plan.snapshot_name,
        "manifest snapshot name mismatch"
    );
    ensure!(
        manifest.bootstrap.sha256 == plan.snapshot_sha256,
        "manifest snapshot hash mismatch"
    );
    ensure!(
        manifest.checkpoint.filename == plan.checkpoint_name,
        "manifest checkpoint name mismatch"
    );
    ensure!(
        manifest.checkpoint.sha256 == plan.checkpoint_sha256,
        "manifest checkpoint hash mismatch"
    );
    ensure!(
        manifest.checkpoint.terminal_slot == plan.terminal_root_slot,
        "manifest checkpoint terminal mismatch"
    );
    let focused = &manifest.focused_plan;
    ensure!(focused.epoch == plan.epoch, "focused epoch mismatch");
    ensure!(
        focused.output_slot_start == plan.epoch * EPOCH_SLOTS,
        "focused output start mismatch"
    );
    ensure!(
        focused.epoch_end_slot == plan.epoch_end_slot,
        "focused epoch end mismatch"
    );
    ensure!(
        focused.terminal_root_slot == plan.terminal_root_slot,
        "focused terminal mismatch"
    );
    ensure!(
        focused.successor_tail_slots == plan.successor_tail_slots,
        "focused tail mismatch"
    );
    ensure!(
        focused.complete_epoch_span_covered,
        "focused span is incomplete"
    );
    ensure!(
        focused.private_verification_tail,
        "verification tail is not private"
    );
    ensure!(
        !focused.canonical_sidecar_authorized,
        "canonical sidecar unexpectedly authorized"
    );
    let gates = &manifest.gates;
    ensure!(
        gates.complete_epoch_span_covered,
        "complete-span gate failed"
    );
    ensure!(
        gates.exact_node_complete_span_capability_passed,
        "node capability gate failed"
    );
    ensure!(
        gates.source_content_revalidated,
        "source revalidation gate failed"
    );
    ensure!(gates.immutable_package_sealed, "package seal gate failed");
    ensure!(
        !gates.fresh_replay_resource_admission_passed,
        "resource admission unexpectedly passed"
    );
    ensure!(!gates.launch_authorized, "launch unexpectedly authorized");
    ensure!(
        !gates.plugin_verification_authorized,
        "plugin unexpectedly authorized"
    );
    ensure!(
        !gates.publication_authorized,
        "publication unexpectedly authorized"
    );
    ensure!(
        !gates.r2_upload_authorized,
        "R2 upload unexpectedly authorized"
    );
    ensure!(
        !manifest.mutations.new_replay_launched,
        "manifest records a replay launch"
    );
    ensure!(
        !manifest.mutations.remote_mutations,
        "manifest records remote mutations"
    );
    ensure!(
        !manifest.mutations.r2_mutations,
        "manifest records R2 mutations"
    );
    Ok(())
}

fn validate_deployment_receipt(
    plan: &Plan,
    receipt: &DeploymentReceipt,
    members: &BTreeMap<String, FileIdentity>,
) -> Result<()> {
    ensure!(
        receipt.schema == DEPLOYMENT_RECEIPT_SCHEMA,
        "deployment receipt schema mismatch"
    );
    ensure!(
        receipt.destination == plan.package.to_string_lossy(),
        "deployment destination mismatch"
    );
    ensure!(
        !receipt.publication_authorized,
        "deployment publication unexpectedly authorized"
    );
    ensure!(
        !receipt.replay_launch_authorized,
        "deployment replay unexpectedly authorized"
    );
    ensure!(
        !receipt.remote_mutations,
        "deployment receipt records remote mutations"
    );
    ensure!(
        !receipt.r2_mutations,
        "deployment receipt records R2 mutations"
    );
    let mut seen = BTreeSet::new();
    for member in &receipt.members {
        ensure!(
            seen.insert(member.name.clone()),
            "duplicate deployment member"
        );
        let actual = members
            .get(&member.name)
            .with_context(|| format!("deployment member absent: {}", member.name))?;
        ensure!(
            actual.sha256 == member.sha256,
            "deployment member hash mismatch: {}",
            member.name
        );
        ensure!(
            actual.bytes == member.bytes,
            "deployment member size mismatch: {}",
            member.name
        );
        ensure!(
            actual.mode == member.mode,
            "deployment member mode mismatch: {}",
            member.name
        );
    }
    let expected: BTreeSet<_> = members
        .keys()
        .filter(|name| !matches!(name.as_str(), "SHA256SUMS" | "deployment-seal-receipt.json"))
        .cloned()
        .collect();
    ensure!(seen == expected, "deployment receipt member set mismatch");
    Ok(())
}

fn filesystem_free_bytes(path: &Path) -> Result<u64> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c_path.as_ptr(), value.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let value = unsafe { value.assume_init() };
    (value.f_bavail as u64)
        .checked_mul(value.f_frsize as u64)
        .context("free-space overflow")
}

fn fsync_directory(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(path)?
        .sync_all()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fsync_directory(path.parent().context("receipt has no parent")?)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "attester must run as root");
    let arguments = parse_args()?;
    ensure!(is_sha256(&arguments.plan_sha256), "invalid plan SHA-256");
    ensure!(is_sha256(&arguments.self_sha256), "invalid self SHA-256");
    let executable = fs::read_link("/proc/self/exe")?;
    let self_identity = exact_file(&executable, 0, true)?;
    ensure!(
        self_identity.sha256 == arguments.self_sha256,
        "running executable SHA-256 mismatch"
    );
    let plan_metadata = fs::symlink_metadata(&arguments.plan)?;
    ensure!(plan_metadata.len() <= MAX_PLAN_BYTES, "plan is too large");
    let plan_identity = exact_file(&arguments.plan, 0, true)?;
    ensure!(
        plan_identity.sha256 == arguments.plan_sha256,
        "plan SHA-256 mismatch"
    );
    let plan: Plan = read_json(&arguments.plan)?;
    validate_plan(&plan)?;
    ensure!(!plan.receipt.exists(), "fresh receipt path required");

    ensure!(
        plan.package.canonicalize()? == plan.package,
        "package path is not exact"
    );
    let package_metadata = fs::symlink_metadata(&plan.package)?;
    ensure!(package_metadata.is_dir(), "package is not a directory");
    ensure!(
        package_metadata.uid() == 0 && package_metadata.gid() == 0,
        "package owner mismatch"
    );
    ensure!(
        package_metadata.mode() & 0o7777 == 0o555,
        "package mode is not 0555"
    );

    let sums_identity = exact_file(&plan.package.join("SHA256SUMS"), 0, true)?;
    ensure!(
        sums_identity.sha256 == plan.sha256sums_sha256,
        "SHA256SUMS identity mismatch"
    );
    let sums = parse_sha256sums(&plan.package.join("SHA256SUMS"))?;
    let actual_names: BTreeSet<String> = fs::read_dir(&plan.package)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?;
    let mut expected_names: BTreeSet<String> = sums.keys().cloned().collect();
    expected_names.insert("SHA256SUMS".to_string());
    ensure!(
        actual_names == expected_names,
        "package member set does not match SHA256SUMS"
    );

    let mut members = BTreeMap::new();
    members.insert("SHA256SUMS".to_string(), sums_identity);
    for (name, expected) in &sums {
        let identity = exact_file(&plan.package.join(name), 0, true)?;
        ensure!(
            identity.sha256 == *expected,
            "package member hash mismatch: {name}"
        );
        members.insert(name.clone(), identity);
    }
    for (name, digest) in [
        (&plan.snapshot_name, &plan.snapshot_sha256),
        (&plan.checkpoint_name, &plan.checkpoint_sha256),
        (
            &"deployment-seal-receipt.json".to_string(),
            &plan.deployment_receipt_sha256,
        ),
        (
            &"deployment-manifest.json".to_string(),
            &plan.manifest_sha256,
        ),
    ] {
        ensure!(
            members.get(name).map(|value| value.sha256.as_str()) == Some(digest),
            "required member mismatch: {name}"
        );
    }

    let deployment: DeploymentReceipt =
        read_json(&plan.package.join("deployment-seal-receipt.json"))?;
    validate_deployment_receipt(&plan, &deployment, &members)?;
    let manifest: Manifest = read_json(&plan.package.join("deployment-manifest.json"))?;
    validate_manifest(&plan, &manifest)?;

    ensure!(
        plan.source_snapshot.canonicalize()? == plan.source_snapshot,
        "source snapshot path is not exact"
    );
    let source_metadata = fs::symlink_metadata(&plan.source_snapshot)?;
    ensure!(
        source_metadata.is_file() && !source_metadata.file_type().is_symlink(),
        "source snapshot is not a regular file"
    );
    ensure!(
        source_metadata.nlink() == 1,
        "source snapshot is not singly linked"
    );
    let package_snapshot = members
        .get(&plan.snapshot_name)
        .context("snapshot member missing")?
        .clone();
    ensure!(
        source_metadata.len() == package_snapshot.bytes,
        "source and package snapshot lengths differ"
    );
    ensure!(
        (source_metadata.dev(), source_metadata.ino())
            != (package_snapshot.device, package_snapshot.inode),
        "package snapshot is not a distinct inode"
    );

    let plan_after = exact_file(&arguments.plan, 0, true)?;
    ensure!(
        plan_after.sha256 == arguments.plan_sha256,
        "plan changed during attestation"
    );
    let free = filesystem_free_bytes(&plan.package)?;
    ensure!(
        free >= MINIMUM_FREE_BYTES,
        "package attestation no longer leaves protected free space"
    );

    let receipt = Receipt {
        schema: RECEIPT_SCHEMA,
        recorded_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        epoch: plan.epoch,
        configuration: ConfigurationReceipt {
            path: arguments.plan.display().to_string(),
            sha256: arguments.plan_sha256,
        },
        plan: PlanReceipt {
            epoch_end_slot: plan.epoch_end_slot,
            terminal_root_slot: plan.terminal_root_slot,
            successor_tail_slots: plan.successor_tail_slots,
            complete_epoch_span_covered: true,
            private_verification_tail: true,
        },
        package: PackageReceipt {
            path: plan.package.display().to_string(),
            device: package_metadata.dev(),
            inode: package_metadata.ino(),
            mode: format!("{:04o}", package_metadata.mode() & 0o7777),
            sha256sums_sha256: plan.sha256sums_sha256,
            deployment_seal_receipt_sha256: plan.deployment_receipt_sha256,
            deployment_manifest_sha256: plan.manifest_sha256,
            members,
        },
        snapshot_copy: SnapshotCopyReceipt {
            source_path: plan.source_snapshot.display().to_string(),
            source_device: source_metadata.dev(),
            source_inode: source_metadata.ino(),
            source_links: source_metadata.nlink(),
            package_path: plan.package.join(&plan.snapshot_name).display().to_string(),
            package_device: package_snapshot.device,
            package_inode: package_snapshot.inode,
            package_links: package_snapshot.links,
            distinct_inode: true,
            sha256: plan.snapshot_sha256,
        },
        resource_check: ResourceCheck {
            filesystem_free_bytes: free,
            minimum_free_bytes: MINIMUM_FREE_BYTES,
            passed: true,
        },
        attestation: Attestation {
            package_ready: true,
            complete_epoch_span_covered: true,
            fresh_replay_resource_admission_passed: false,
            launch_authorized: false,
            new_replay_launched: false,
            plugin_verification_authorized: false,
            publication_authorized: false,
            r2_upload_authorized: false,
            remote_mutations: false,
            r2_mutations: false,
        },
        attester: Attester {
            sha256: self_identity.sha256,
        },
    };
    let bytes = serde_json::to_vec_pretty(&receipt)?;
    let mut bytes_with_newline = bytes;
    bytes_with_newline.push(b'\n');
    let digest = write_new(&plan.receipt, &bytes_with_newline)?;
    println!(
        "{}",
        serde_json::json!({"path": plan.receipt, "sha256": digest})
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

    fn valid_plan(epoch: u64) -> Plan {
        let epoch_end_slot = (epoch + 1) * EPOCH_SLOTS - 1;
        Plan {
            schema: PLAN_SCHEMA.to_string(),
            epoch,
            package: canonical_package_path(epoch).into(),
            source_snapshot: format!("/private/snapshot-{epoch}-test.tar.zst").into(),
            snapshot_name: format!("snapshot-{epoch}-test.tar.zst"),
            snapshot_sha256: "a".repeat(64),
            checkpoint_name: format!("epoch-hashes-{epoch}-complete-span.txt"),
            checkpoint_sha256: "b".repeat(64),
            sha256sums_sha256: "c".repeat(64),
            deployment_receipt_sha256: "d".repeat(64),
            manifest_sha256: "e".repeat(64),
            epoch_end_slot,
            terminal_root_slot: epoch_end_slot + 1,
            successor_tail_slots: 1,
            receipt: format!(
                "/home/ubuntu/.jetstreamer-private/campaign-state/epoch{epoch}-complete-span-store8-immutable-package-ca2e38b-test.json"
            )
            .into(),
        }
    }

    #[test]
    fn digest_validation_is_lowercase_only() {
        assert!(is_sha256(&"a".repeat(64)));
        assert!(is_sha256(&"9".repeat(64)));
        assert!(!is_sha256(&"A".repeat(64)));
        assert!(!is_sha256(&"a".repeat(63)));
    }

    #[test]
    fn plan_rejects_noncanonical_tail() {
        let mut plan = valid_plan(210);
        plan.successor_tail_slots = 2;
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn corrected_package_revisions_are_narrowly_allowlisted() {
        assert_eq!(
            canonical_package_path(207),
            "/var/lib/jetstreamer/horizon-focused-207-complete-span-store8-ca2e38b-v2"
        );
        assert_eq!(
            canonical_package_path(209),
            "/var/lib/jetstreamer/horizon-focused-209-complete-span-store8-ca2e38b-v2"
        );
        assert!(validate_plan(&valid_plan(207)).is_ok());
        assert!(validate_plan(&valid_plan(209)).is_ok());

        let mut obsolete_207 = valid_plan(207);
        obsolete_207.package =
            "/var/lib/jetstreamer/horizon-focused-207-complete-span-store8-ca2e38b-v1".into();
        assert!(validate_plan(&obsolete_207).is_err());

        let mut unapproved_205 = valid_plan(205);
        unapproved_205.package =
            "/var/lib/jetstreamer/horizon-focused-205-complete-span-store8-ca2e38b-v2".into();
        assert!(validate_plan(&unapproved_205).is_err());
    }
}
