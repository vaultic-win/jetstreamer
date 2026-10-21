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

const PLAN_SCHEMA_V1: &str = "jetstreamer-focused-package-attestation-plan-v1";
const PLAN_SCHEMA_V2: &str = "jetstreamer-focused-package-attestation-plan-v2";
const PLAN_SCHEMA_V3: &str = "jetstreamer-focused-package-attestation-plan-v3";
const RECEIPT_SCHEMA: &str = "jetstreamer-private-configured-immutable-complete-span-package-v1";
const RECEIPT_SCHEMA_V2: &str = "jetstreamer-private-configured-immutable-complete-span-package-v2";
const CAPABILITY_RECEIPT_SCHEMA: &str = "jetstreamer-private-focused-package-capability-v1";
const DEPLOYMENT_RECEIPT_SCHEMA: &str = "jetstreamer-sealed-deployment-receipt-v1";
const MANIFEST_SCHEMA: &str = "jetstreamer-private-focused-qualification-deployment-v5";
const CENTURY_FLOOR_SCHEMA: &str = "jetstreamer-horizon-century-jet-floor-v2";
const R2_RECEIPT_SCHEMA: &str = "jetstreamer-horizon-r2-receipt-v1";
const HORIZON_R2_BUCKET: &str = "solana-archive-with-accounts-data";
const MAX_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;
const LEGACY_MINIMUM_FREE_BYTES: u64 = 4_700_000_000_000;
const EPOCH_SLOTS: u64 = 432_000;
const SHRINK225_PACKAGE: &str =
    "/var/lib/jetstreamer/horizon-focused-225-complete-span-v1-6-25-shrink-budget-v1";

fn shrink225_package(plan: &Plan) -> bool {
    plan.epoch == 225 && plan.package == Path::new(SHRINK225_PACKAGE)
}

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
    #[serde(default)]
    capability_receipt: Option<PathBuf>,
    #[serde(default)]
    capability_receipt_sha256: Option<String>,
    #[serde(default)]
    century_floor_evidence: Option<PathBuf>,
    #[serde(default)]
    century_floor_evidence_sha256: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    capability_evidence: Option<CapabilityEvidence>,
    attestation: Attestation,
    attester: Attester,
}

#[derive(Debug, Serialize)]
struct CapabilityEvidence {
    path: String,
    sha256: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    century_floor_evidence: Option<CenturyFloorEvidenceReceipt>,
}

#[derive(Debug, Serialize)]
struct CenturyFloorEvidenceReceipt {
    path: String,
    sha256: String,
    first_epoch: u64,
    last_epoch: u64,
    sample_count: u64,
    sum_jet_size_bytes: u64,
    floor_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CenturyFloorEvidence {
    schema: String,
    century: Century,
    samples: Vec<CenturyFloorSample>,
    arithmetic: CenturyFloorArithmetic,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Century {
    first_epoch: u64,
    last_epoch: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CenturyFloorSample {
    epoch: u64,
    jet_size_bytes: u64,
    archive_sha256: String,
    r2_receipt_name: String,
    r2_receipt_sha256: String,
    full_receipt_name: String,
    full_receipt_sha256: String,
    plugin_receipt_name: String,
    plugin_receipt_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CenturyFloorArithmetic {
    sample_count: u64,
    sum_jet_size_bytes: u64,
    floor_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct R2Receipt {
    schema: String,
    bucket: String,
    epoch: u64,
    archive_key: String,
    checksum_key: String,
    archive_length: u64,
    archive_sha256: String,
    archive_etag: String,
    r2_composite_sha256: Option<String>,
    remote_sha256_readback: bool,
    multipart_part_size: u64,
    verified_unix_seconds: u64,
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

fn safe_member_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && name != "." && name != ".."
}

fn validate_attester_bundle(directory: &Path) -> Result<BTreeMap<String, FileIdentity>> {
    ensure!(
        directory.canonicalize()? == directory,
        "attester deployment path is not exact"
    );
    let directory_metadata = fs::symlink_metadata(directory)?;
    ensure!(
        directory_metadata.is_dir()
            && directory_metadata.uid() == 0
            && directory_metadata.gid() == 0
            && directory_metadata.mode() & 0o7777 == 0o555,
        "attester deployment identity or mode mismatch"
    );

    let sums_path = directory.join("SHA256SUMS");
    let sums_identity = exact_file(&sums_path, 0, true)?;
    let sums = parse_sha256sums(&sums_path)?;
    let actual_names: BTreeSet<String> = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?;
    let mut expected_names: BTreeSet<String> = sums.keys().cloned().collect();
    expected_names.insert("SHA256SUMS".to_string());
    ensure!(
        actual_names == expected_names,
        "attester deployment member set does not match SHA256SUMS"
    );

    let mut members = BTreeMap::new();
    members.insert("SHA256SUMS".to_string(), sums_identity);
    for (name, expected_sha256) in &sums {
        let identity = exact_file(&directory.join(name), 0, true)?;
        ensure!(
            identity.sha256 == *expected_sha256,
            "attester deployment member hash mismatch: {name}"
        );
        members.insert(name.clone(), identity);
    }

    let receipt: DeploymentReceipt = read_json(&directory.join("deployment-seal-receipt.json"))?;
    ensure!(
        receipt.schema == DEPLOYMENT_RECEIPT_SCHEMA,
        "attester deployment receipt schema mismatch"
    );
    ensure!(
        receipt.destination == directory.to_string_lossy(),
        "attester deployment receipt destination mismatch"
    );
    ensure!(
        !receipt.publication_authorized
            && !receipt.replay_launch_authorized
            && !receipt.remote_mutations
            && !receipt.r2_mutations,
        "attester deployment receipt grants unexpected authority"
    );
    let mut receipt_names = BTreeSet::new();
    for member in &receipt.members {
        ensure!(
            receipt_names.insert(member.name.clone()),
            "duplicate attester deployment receipt member"
        );
        let actual = members
            .get(&member.name)
            .with_context(|| format!("attester deployment member absent: {}", member.name))?;
        ensure!(
            actual.sha256 == member.sha256
                && actual.bytes == member.bytes
                && actual.mode == member.mode,
            "attester deployment receipt member mismatch: {}",
            member.name
        );
    }
    let expected_receipt_names: BTreeSet<_> = members
        .keys()
        .filter(|name| !matches!(name.as_str(), "SHA256SUMS" | "deployment-seal-receipt.json"))
        .cloned()
        .collect();
    ensure!(
        receipt_names == expected_receipt_names,
        "attester deployment receipt member set mismatch"
    );
    Ok(members)
}

fn validate_century_floor_document(evidence: &CenturyFloorEvidence) -> Result<(u64, u64, u64)> {
    ensure!(
        evidence.schema == CENTURY_FLOOR_SCHEMA,
        "century-floor evidence schema mismatch"
    );
    ensure!(
        evidence.century.first_epoch == 200 && evidence.century.last_epoch == 300,
        "century-floor range mismatch"
    );
    ensure!(!evidence.samples.is_empty(), "empty century-floor census");

    let mut prior_epoch = None;
    let mut sum = 0u128;
    let mut receipt_names = BTreeSet::new();
    for sample in &evidence.samples {
        ensure!(
            (evidence.century.first_epoch..=evidence.century.last_epoch).contains(&sample.epoch),
            "century-floor sample epoch outside century"
        );
        if let Some(prior) = prior_epoch {
            ensure!(
                sample.epoch > prior,
                "century-floor sample epochs are duplicate or unsorted"
            );
        }
        prior_epoch = Some(sample.epoch);
        ensure!(
            sample.jet_size_bytes > 0,
            "zero-length century-floor sample"
        );
        ensure!(
            is_sha256(&sample.archive_sha256)
                && is_sha256(&sample.r2_receipt_sha256)
                && is_sha256(&sample.full_receipt_sha256)
                && is_sha256(&sample.plugin_receipt_sha256),
            "invalid century-floor sample SHA-256"
        );
        for name in [
            &sample.r2_receipt_name,
            &sample.full_receipt_name,
            &sample.plugin_receipt_name,
        ] {
            ensure!(safe_member_name(name), "unsafe century-floor receipt name");
            ensure!(
                receipt_names.insert(name.clone()),
                "duplicate century-floor receipt member"
            );
        }
        sum = sum
            .checked_add(sample.jet_size_bytes as u128)
            .context("century-floor sum overflow")?;
    }

    let count = u64::try_from(evidence.samples.len()).context("century-floor count overflow")?;
    let numerator = sum
        .checked_mul(2)
        .context("century-floor multiply overflow")?;
    let floor = numerator
        .checked_add(count as u128 - 1)
        .context("century-floor rounding overflow")?
        / count as u128;
    let sum_u64 = u64::try_from(sum).context("century-floor sum exceeds u64")?;
    let floor_u64 = u64::try_from(floor).context("century-floor result exceeds u64")?;
    ensure!(
        evidence.arithmetic.sample_count == count
            && evidence.arithmetic.sum_jet_size_bytes == sum_u64
            && evidence.arithmetic.floor_bytes == floor_u64,
        "century-floor arithmetic mismatch"
    );
    Ok((count, sum_u64, floor_u64))
}

fn validate_r2_receipt(sample: &CenturyFloorSample, receipt: &R2Receipt) -> Result<()> {
    ensure!(
        receipt.schema == R2_RECEIPT_SCHEMA,
        "R2 receipt schema mismatch"
    );
    ensure!(
        receipt.bucket == HORIZON_R2_BUCKET,
        "R2 receipt bucket mismatch"
    );
    ensure!(receipt.epoch == sample.epoch, "R2 receipt epoch mismatch");
    ensure!(
        receipt.archive_key == format!("epoch-{}.jet", sample.epoch)
            && receipt.checksum_key == format!("epoch-{}.jet.sha256", sample.epoch),
        "R2 receipt object key mismatch"
    );
    ensure!(
        receipt.archive_length == sample.jet_size_bytes,
        "R2 receipt archive length mismatch"
    );
    ensure!(
        receipt.archive_sha256 == sample.archive_sha256,
        "R2 receipt archive SHA-256 mismatch"
    );
    ensure!(
        !receipt.archive_etag.is_empty()
            && receipt.multipart_part_size > 0
            && receipt.verified_unix_seconds > 0,
        "R2 receipt lacks durable object evidence"
    );
    ensure!(
        receipt.remote_sha256_readback,
        "R2 receipt lacks authenticated whole-object readback"
    );
    if let Some(composite) = receipt.r2_composite_sha256.as_deref() {
        ensure!(is_sha256(composite), "invalid R2 composite SHA-256");
    }
    Ok(())
}

fn validate_text_receipt(bytes: &[u8], expected_archive_sha256: &str) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("receipt is not UTF-8")?;
    let fields: Vec<_> = text.split_whitespace().collect();
    ensure!(
        fields.len() == 3,
        "receipt must contain exactly three digests"
    );
    ensure!(
        fields.iter().all(|field| is_sha256(field)),
        "invalid receipt digest"
    );
    ensure!(
        fields[0] == expected_archive_sha256,
        "receipt archive SHA-256 mismatch"
    );
    Ok(())
}

fn validate_receipt_path(path: &Path, epoch: u64, shrink225: bool) -> Result<()> {
    ensure!(
        !shrink225 || epoch == 225,
        "foreign capped-shrink receipt profile"
    );
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
    let prefix = if epoch == 224 {
        "epoch224-complete-span-v1-6-25-immutable-package-01879c4-".to_string()
    } else if shrink225 {
        "epoch225-complete-span-v1-6-25-immutable-package-shrink-budget-".to_string()
    } else if epoch == 225 {
        "epoch225-complete-span-v1-6-25-immutable-package-63a2717-".to_string()
    } else {
        format!("epoch{epoch}-complete-span-store8-immutable-package-ca2e38b-")
    };
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
    if epoch == 225 {
        return "/var/lib/jetstreamer/horizon-focused-225-complete-span-v1-6-25-63a2717-v1"
            .to_string();
    }
    if epoch == 224 {
        return "/var/lib/jetstreamer/horizon-focused-224-complete-span-v1-6-25-01879c4-v1"
            .to_string();
    }
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
    ensure!(
        matches!(
            plan.schema.as_str(),
            PLAN_SCHEMA_V1 | PLAN_SCHEMA_V2 | PLAN_SCHEMA_V3
        ),
        "plan schema mismatch"
    );
    ensure!(
        (203..=212).contains(&plan.epoch) || matches!(plan.epoch, 224 | 225),
        "epoch outside approved focused range"
    );
    if plan.epoch == 224 {
        ensure!(
            plan.schema == PLAN_SCHEMA_V3,
            "epoch 224 requires century-floor evidence"
        );
        ensure!(
            plan.snapshot_name
                == "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst"
                && plan.snapshot_sha256
                    == "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1"
                && plan.checkpoint_sha256
                    == "916a4d9414db22338d55eef537cb630fa47f86dc993c7d8be585cd2afa4bb8a4"
                && plan.epoch_end_slot == 97_199_999
                && plan.terminal_root_slot == 97_631_459
                && plan.successor_tail_slots == 431_460,
            "epoch 224 snapshot or complete-span checkpoint binding mismatch"
        );
    }
    if plan.epoch == 225 {
        ensure!(
            plan.schema == PLAN_SCHEMA_V3,
            "epoch 225 requires century-floor evidence"
        );
        ensure!(
            plan.snapshot_name
                == "snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst"
                && plan.snapshot_sha256
                    == "094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d"
                && plan.checkpoint_sha256
                    == "1dd033b1df75c58abe07098c48be763ee10ad5d4b4c749efa6c0240a13e7f403"
                && plan.epoch_end_slot == 97_631_999
                && plan.terminal_root_slot == 98_063_464
                && plan.successor_tail_slots == 431_465,
            "epoch 225 snapshot or complete-span checkpoint binding mismatch"
        );
    }
    match plan.schema.as_str() {
        PLAN_SCHEMA_V1 => {
            ensure!(
                plan.capability_receipt.is_none() && plan.capability_receipt_sha256.is_none(),
                "v1 plan cannot carry external capability evidence"
            );
            ensure!(
                plan.century_floor_evidence.is_none()
                    && plan.century_floor_evidence_sha256.is_none(),
                "v1 plan cannot carry century-floor evidence"
            );
        }
        PLAN_SCHEMA_V2 => {
            ensure!(
                plan.epoch == 203,
                "external capability evidence is approved only for epoch 203"
            );
            let capability = plan
                .capability_receipt
                .as_ref()
                .context("v2 plan lacks capability receipt")?;
            ensure!(
                capability
                    == Path::new(
                        "/home/ubuntu/.jetstreamer-private/campaign-state/epoch203-complete-span-package-capability-ca2e38b-rust-20261017-v1.json"
                    ),
                "unexpected epoch-203 capability receipt"
            );
            ensure!(
                plan.capability_receipt_sha256
                    .as_deref()
                    .is_some_and(is_sha256),
                "invalid capability receipt SHA-256"
            );
            ensure!(
                plan.century_floor_evidence.is_none()
                    && plan.century_floor_evidence_sha256.is_none(),
                "v2 plan cannot carry century-floor evidence"
            );
        }
        PLAN_SCHEMA_V3 => {
            if plan.epoch == 203 {
                let capability = plan
                    .capability_receipt
                    .as_ref()
                    .context("epoch-203 v3 plan lacks capability receipt")?;
                ensure!(
                    capability
                        == Path::new(
                            "/home/ubuntu/.jetstreamer-private/campaign-state/epoch203-complete-span-package-capability-ca2e38b-rust-20261017-v1.json"
                        ),
                    "unexpected epoch-203 capability receipt"
                );
                ensure!(
                    plan.capability_receipt_sha256
                        .as_deref()
                        .is_some_and(is_sha256),
                    "invalid capability receipt SHA-256"
                );
            } else {
                ensure!(
                    plan.capability_receipt.is_none() && plan.capability_receipt_sha256.is_none(),
                    "external capability evidence is approved only for epoch 203"
                );
            }
            let evidence = plan
                .century_floor_evidence
                .as_ref()
                .context("v3 plan lacks century-floor evidence")?;
            ensure!(
                evidence.is_absolute(),
                "v3 century-floor evidence path is not absolute"
            );
            ensure!(
                plan.century_floor_evidence_sha256
                    .as_deref()
                    .is_some_and(is_sha256),
                "invalid century-floor evidence SHA-256"
            );
        }
        _ => unreachable!(),
    }
    let expected_package = if shrink225_package(plan) {
        SHRINK225_PACKAGE.to_string()
    } else {
        canonical_package_path(plan.epoch)
    };
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
    validate_receipt_path(&plan.receipt, plan.epoch, shrink225_package(plan))?;
    Ok(())
}

fn validate_manifest(
    plan: &Plan,
    manifest: &Manifest,
    external_capability_validated: bool,
) -> Result<()> {
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
    if plan.epoch == 225 {
        // This package must be attested before its exact-package capability
        // probe. Do not claim an unperformed probe or borrow another package's
        // evidence. The receipt still denies launch and every publication gate.
        ensure!(
            !gates.exact_node_complete_span_capability_passed && !external_capability_validated,
            "epoch 225 initial attestation must precede its independent capability probe"
        );
    } else {
        ensure!(
            gates.exact_node_complete_span_capability_passed || external_capability_validated,
            "node capability gate failed"
        );
    }
    if external_capability_validated {
        ensure!(
            matches!(plan.schema.as_str(), PLAN_SCHEMA_V2 | PLAN_SCHEMA_V3) && plan.epoch == 203,
            "external capability evidence escaped its narrow exception"
        );
    }
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

fn validate_epoch225_binaries(
    epoch: u64,
    shrink225: bool,
    members: &BTreeMap<String, FileIdentity>,
) -> Result<()> {
    ensure!(
        !shrink225 || epoch == 225,
        "foreign capped-shrink binary profile"
    );
    if epoch != 225 {
        return Ok(());
    }
    for (name, expected) in [
        (
            "jetstreamer-node",
            "945f36fe11824263258ad561dba106e377148b702f2c615522b171c4ba97ed3b",
        ),
        (
            "jetstreamer-historical-worker-v1-6-25",
            if shrink225 {
                "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd"
            } else {
                "7cd48efc8719109a69fafcb3209a821ea9f07113e3fb0bfab49db23a6e77a146"
            },
        ),
    ] {
        ensure!(
            members.get(name).is_some_and(|m| m.sha256 == expected),
            "epoch 225 must use its exact complete-span binary: {name}"
        );
    }
    Ok(())
}

fn json_at<'a>(value: &'a serde_json::Value, pointer: &str) -> Result<&'a serde_json::Value> {
    value
        .pointer(pointer)
        .with_context(|| format!("capability receipt lacks {pointer}"))
}

fn json_string<'a>(value: &'a serde_json::Value, pointer: &str) -> Result<&'a str> {
    json_at(value, pointer)?
        .as_str()
        .with_context(|| format!("capability receipt field is not a string: {pointer}"))
}

fn json_u64(value: &serde_json::Value, pointer: &str) -> Result<u64> {
    json_at(value, pointer)?
        .as_u64()
        .with_context(|| format!("capability receipt field is not an unsigned integer: {pointer}"))
}

fn json_bool(value: &serde_json::Value, pointer: &str) -> Result<bool> {
    json_at(value, pointer)?
        .as_bool()
        .with_context(|| format!("capability receipt field is not a boolean: {pointer}"))
}

fn validate_capability_member(
    receipt: &serde_json::Value,
    pointer: &str,
    expected_path: &Path,
    actual: &FileIdentity,
) -> Result<()> {
    ensure!(
        json_string(receipt, &format!("{pointer}/path"))? == expected_path.to_string_lossy(),
        "capability member path mismatch: {pointer}"
    );
    ensure!(
        json_string(receipt, &format!("{pointer}/sha256"))? == actual.sha256,
        "capability member SHA-256 mismatch: {pointer}"
    );
    for (name, observed, expected) in [
        (
            "bytes",
            json_u64(receipt, &format!("{pointer}/bytes"))?,
            actual.bytes,
        ),
        (
            "device",
            json_u64(receipt, &format!("{pointer}/device"))?,
            actual.device,
        ),
        (
            "inode",
            json_u64(receipt, &format!("{pointer}/inode"))?,
            actual.inode,
        ),
        (
            "links",
            json_u64(receipt, &format!("{pointer}/links"))?,
            actual.links,
        ),
        (
            "uid",
            json_u64(receipt, &format!("{pointer}/uid"))?,
            actual.uid as u64,
        ),
        (
            "gid",
            json_u64(receipt, &format!("{pointer}/gid"))?,
            actual.gid as u64,
        ),
    ] {
        ensure!(
            observed == expected,
            "capability member {name} mismatch: {pointer}"
        );
    }
    ensure!(
        json_string(receipt, &format!("{pointer}/mode"))? == actual.mode,
        "capability member mode mismatch: {pointer}"
    );
    Ok(())
}

fn validate_external_capability(
    plan: &Plan,
    members: &BTreeMap<String, FileIdentity>,
) -> Result<Option<CapabilityEvidence>> {
    if plan.schema == PLAN_SCHEMA_V1 || (plan.schema == PLAN_SCHEMA_V3 && plan.epoch != 203) {
        return Ok(None);
    }
    ensure!(
        matches!(plan.schema.as_str(), PLAN_SCHEMA_V2 | PLAN_SCHEMA_V3) && plan.epoch == 203,
        "plan schema mismatch"
    );
    let path = plan
        .capability_receipt
        .as_ref()
        .context("v2 plan lacks capability receipt")?;
    let expected_sha256 = plan
        .capability_receipt_sha256
        .as_deref()
        .context("v2 plan lacks capability receipt SHA-256")?;
    let identity = exact_file(path, 0, true)?;
    ensure!(
        identity.sha256 == expected_sha256,
        "capability receipt SHA-256 mismatch"
    );
    let receipt: serde_json::Value = read_json(path)?;
    ensure!(
        json_string(&receipt, "/schema")? == CAPABILITY_RECEIPT_SCHEMA,
        "capability receipt schema mismatch"
    );
    ensure!(
        json_u64(&receipt, "/epoch")? == plan.epoch,
        "capability receipt epoch mismatch"
    );
    ensure!(
        json_string(&receipt, "/deployment/path")? == plan.package.to_string_lossy(),
        "capability deployment path mismatch"
    );
    ensure!(
        json_string(&receipt, "/deployment/sha256sums_sha256")? == plan.sha256sums_sha256,
        "capability SHA256SUMS mismatch"
    );
    ensure!(
        json_u64(&receipt, "/plan/output_slot_start")? == plan.epoch * EPOCH_SLOTS,
        "capability output start mismatch"
    );
    ensure!(
        json_u64(&receipt, "/plan/epoch_end_slot")? == plan.epoch_end_slot,
        "capability epoch end mismatch"
    );
    ensure!(
        json_u64(&receipt, "/plan/terminal_slot")? == plan.terminal_root_slot,
        "capability terminal mismatch"
    );
    ensure!(
        json_u64(&receipt, "/plan/successor_tail_slots")? == plan.successor_tail_slots,
        "capability successor tail mismatch"
    );
    ensure!(
        json_bool(&receipt, "/plan/complete_epoch_span_covered")?
            && json_bool(&receipt, "/plan/private_verification_tail")?,
        "capability span or private-tail gate failed"
    );

    let package_receipt_path = Path::new(json_string(&receipt, "/deployment/package_receipt")?);
    let package_receipt_sha256 = json_string(&receipt, "/deployment/package_receipt_sha256")?;
    ensure!(
        is_sha256(package_receipt_sha256),
        "invalid package receipt SHA-256"
    );
    let package_receipt_identity = exact_file(package_receipt_path, 0, true)?;
    ensure!(
        package_receipt_identity.sha256 == package_receipt_sha256,
        "capability package receipt SHA-256 mismatch"
    );
    let package_receipt: serde_json::Value = read_json(package_receipt_path)?;
    ensure!(
        json_string(&package_receipt, "/schema")? == RECEIPT_SCHEMA,
        "capability package receipt schema mismatch"
    );
    ensure!(
        json_u64(&package_receipt, "/epoch")? == plan.epoch,
        "capability package receipt epoch mismatch"
    );
    ensure!(
        json_string(&package_receipt, "/package/path")? == plan.package.to_string_lossy(),
        "capability package receipt deployment mismatch"
    );

    let node = members
        .get("jetstreamer-node")
        .context("node member missing")?;
    validate_capability_member(
        &receipt,
        "/deployment/node",
        &plan.package.join("jetstreamer-node"),
        node,
    )?;
    let worker_names: Vec<_> = members
        .keys()
        .filter(|name| name.starts_with("jetstreamer-historical-worker-"))
        .collect();
    ensure!(
        worker_names.len() == 1,
        "capability worker member is ambiguous"
    );
    let worker_name = worker_names[0];
    validate_capability_member(
        &receipt,
        "/deployment/worker",
        &plan.package.join(worker_name),
        members.get(worker_name).context("worker member missing")?,
    )?;
    validate_capability_member(
        &receipt,
        "/deployment/snapshot",
        &plan.package.join(&plan.snapshot_name),
        members
            .get(&plan.snapshot_name)
            .context("snapshot member missing")?,
    )?;
    validate_capability_member(
        &receipt,
        "/deployment/checkpoint",
        &plan.package.join(&plan.checkpoint_name),
        members
            .get(&plan.checkpoint_name)
            .context("checkpoint member missing")?,
    )?;
    ensure!(
        json_bool(
            &receipt,
            "/deployment/bootstrap_is_direct_singly_linked_member"
        )?,
        "capability bootstrap identity gate failed"
    );

    for pointer in [
        "/probe/snapshot_intentionally_absent",
        "/assessment/exact_package_node_complete_span_route_passed",
        "/assessment/package_member_hashes_passed",
    ] {
        ensure!(
            json_bool(&receipt, pointer)?,
            "capability gate failed: {pointer}"
        );
    }
    for pointer in [
        "/probe/worker_spawned",
        "/probe/replay_started",
        "/probe/archive_created",
        "/probe/sidecar_created",
        "/probe/segment_manifest_created",
        "/assessment/snapshot_schema_or_contents_tested",
        "/assessment/fresh_resource_admission_passed",
        "/assessment/replay_launch_authorized",
        "/assessment/publication_authorized",
        "/assessment/r2_upload_authorized",
        "/mutations/local_archive_mutations",
        "/mutations/local_cache_deletions",
        "/mutations/remote_mutations",
        "/mutations/r2_mutations",
    ] {
        ensure!(
            !json_bool(&receipt, pointer)?,
            "capability mutation or authority set: {pointer}"
        );
    }
    ensure!(
        json_u64(&receipt, "/probe/exit_status")? == 1,
        "capability probe exit status mismatch"
    );
    ensure!(
        json_at(&receipt, "/probe/live_process_references")?
            .as_array()
            .is_some_and(Vec::is_empty),
        "capability probe retained live process references"
    );
    ensure!(
        json_bool(&receipt, "/probe/cleanup_pending")?,
        "capability probe cleanup state mismatch"
    );

    Ok(Some(CapabilityEvidence {
        path: path.display().to_string(),
        sha256: identity.sha256,
    }))
}

fn validate_century_floor_evidence(
    plan: &Plan,
    plan_path: &Path,
    plan_identity: &FileIdentity,
    executable: &Path,
    self_identity: &FileIdentity,
) -> Result<(u64, Option<CenturyFloorEvidenceReceipt>)> {
    if plan.schema != PLAN_SCHEMA_V3 {
        return Ok((LEGACY_MINIMUM_FREE_BYTES, None));
    }

    let deployment = executable
        .parent()
        .context("running executable has no parent")?;
    ensure!(
        plan_path.parent() == Some(deployment),
        "v3 plan is not a direct member of the attester deployment"
    );
    let evidence_path = plan
        .century_floor_evidence
        .as_ref()
        .context("v3 plan lacks century-floor evidence")?;
    ensure!(
        evidence_path.parent() == Some(deployment),
        "century-floor evidence is not a direct member of the attester deployment"
    );
    let evidence_sha256 = plan
        .century_floor_evidence_sha256
        .as_deref()
        .context("v3 plan lacks century-floor evidence SHA-256")?;

    let members = validate_attester_bundle(deployment)?;
    let executable_name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid attester executable name")?;
    ensure!(
        members
            .get(executable_name)
            .is_some_and(|identity| identity.sha256 == self_identity.sha256),
        "running attester is not bound by its deployment"
    );
    let plan_name = plan_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid v3 plan member name")?;
    ensure!(
        members
            .get(plan_name)
            .is_some_and(|identity| identity.sha256 == plan_identity.sha256),
        "v3 plan is not hash-bound by the attester deployment"
    );
    let evidence_name = evidence_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid century-floor evidence member name")?;
    let evidence_identity = members
        .get(evidence_name)
        .context("century-floor evidence is absent from attester deployment")?;
    ensure!(
        evidence_identity.sha256 == evidence_sha256,
        "century-floor evidence SHA-256 mismatch"
    );

    let evidence: CenturyFloorEvidence = read_json(evidence_path)?;
    let (sample_count, sum_jet_size_bytes, floor_bytes) =
        validate_century_floor_document(&evidence)?;
    for sample in &evidence.samples {
        for (name, expected_sha256) in [
            (&sample.r2_receipt_name, &sample.r2_receipt_sha256),
            (&sample.full_receipt_name, &sample.full_receipt_sha256),
            (&sample.plugin_receipt_name, &sample.plugin_receipt_sha256),
        ] {
            let member = members
                .get(name)
                .with_context(|| format!("century-floor receipt member absent: {name}"))?;
            ensure!(
                member.sha256 == *expected_sha256,
                "century-floor receipt member SHA-256 mismatch: {name}"
            );
        }

        let r2_receipt: R2Receipt = read_json(&deployment.join(&sample.r2_receipt_name))?;
        validate_r2_receipt(sample, &r2_receipt)?;
        validate_text_receipt(
            &fs::read(deployment.join(&sample.full_receipt_name))?,
            &sample.archive_sha256,
        )?;
        validate_text_receipt(
            &fs::read(deployment.join(&sample.plugin_receipt_name))?,
            &sample.archive_sha256,
        )?;
    }

    Ok((
        floor_bytes,
        Some(CenturyFloorEvidenceReceipt {
            path: evidence_path.display().to_string(),
            sha256: evidence_identity.sha256.clone(),
            first_epoch: evidence.century.first_epoch,
            last_epoch: evidence.century.last_epoch,
            sample_count,
            sum_jet_size_bytes,
            floor_bytes,
        }),
    ))
}

#[allow(clippy::unnecessary_cast)] // libc statvfs field widths vary by target.
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
    let (minimum_free_bytes, century_floor_evidence) = validate_century_floor_evidence(
        &plan,
        &arguments.plan,
        &plan_identity,
        &executable,
        &self_identity,
    )?;

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
    validate_epoch225_binaries(plan.epoch, shrink225_package(&plan), &members)?;
    let capability_evidence = validate_external_capability(&plan, &members)?;
    let manifest: Manifest = read_json(&plan.package.join("deployment-manifest.json"))?;
    validate_manifest(&plan, &manifest, capability_evidence.is_some())?;

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
        free >= minimum_free_bytes,
        "package attestation no longer leaves protected free space"
    );

    let receipt = Receipt {
        schema: if plan.schema == PLAN_SCHEMA_V3 {
            RECEIPT_SCHEMA_V2
        } else {
            RECEIPT_SCHEMA
        },
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
            minimum_free_bytes,
            passed: true,
            century_floor_evidence,
        },
        capability_evidence,
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
            schema: PLAN_SCHEMA_V1.to_string(),
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
            capability_receipt: None,
            capability_receipt_sha256: None,
            century_floor_evidence: None,
            century_floor_evidence_sha256: None,
        }
    }

    fn floor_sample(epoch: u64, jet_size_bytes: u64) -> CenturyFloorSample {
        CenturyFloorSample {
            epoch,
            jet_size_bytes,
            archive_sha256: format!("{:064x}", epoch),
            r2_receipt_name: format!("epoch-{epoch}.r2.json"),
            r2_receipt_sha256: "a".repeat(64),
            full_receipt_name: format!("epoch-{epoch}.full.ok"),
            full_receipt_sha256: "b".repeat(64),
            plugin_receipt_name: format!("epoch-{epoch}.plugin.ok"),
            plugin_receipt_sha256: "c".repeat(64),
        }
    }

    #[test]
    fn epoch224_attestation_is_exact_and_requires_century_floor() {
        let mut plan = valid_plan(224);
        plan.schema = PLAN_SCHEMA_V3.into();
        plan.snapshot_name =
            "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst".into();
        plan.snapshot_sha256 =
            "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1".into();
        plan.checkpoint_sha256 =
            "916a4d9414db22338d55eef537cb630fa47f86dc993c7d8be585cd2afa4bb8a4".into();
        plan.terminal_root_slot = 97_631_459;
        plan.successor_tail_slots = 431_460;
        plan.receipt = "/home/ubuntu/.jetstreamer-private/campaign-state/epoch224-complete-span-v1-6-25-immutable-package-01879c4-test.json".into();
        plan.century_floor_evidence = Some("/sealed/century-floor.json".into());
        plan.century_floor_evidence_sha256 = Some("f".repeat(64));
        assert!(validate_plan(&plan).is_ok());
        plan.century_floor_evidence = None;
        assert!(validate_plan(&plan).is_err());
        plan.century_floor_evidence = Some("/sealed/century-floor.json".into());
        plan.successor_tail_slots -= 1;
        assert!(validate_plan(&plan).is_err());
        plan.successor_tail_slots += 1;
        plan.snapshot_sha256 = "a".repeat(64);
        assert!(validate_plan(&plan).is_err());
        plan.snapshot_sha256 =
            "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1".into();
        plan.schema = PLAN_SCHEMA_V1.into();
        assert!(validate_plan(&plan).is_err());
        plan.schema = PLAN_SCHEMA_V3.into();
        plan.terminal_root_slot -= 1;
        assert!(validate_plan(&plan).is_err());
        plan.terminal_root_slot += 1;
        plan.checkpoint_sha256 = "b".repeat(64);
        assert!(validate_plan(&plan).is_err());
        plan.checkpoint_sha256 =
            "916a4d9414db22338d55eef537cb630fa47f86dc993c7d8be585cd2afa4bb8a4".into();
        plan.package = "/var/lib/jetstreamer/arbitrary".into();
        assert!(validate_plan(&plan).is_err());
        assert!(validate_plan(&valid_plan(223)).is_err());
        assert!(validate_plan(&valid_plan(225)).is_err());
    }

    fn valid_floor_evidence() -> CenturyFloorEvidence {
        CenturyFloorEvidence {
            schema: CENTURY_FLOOR_SCHEMA.to_string(),
            century: Century {
                first_epoch: 200,
                last_epoch: 300,
            },
            samples: vec![floor_sample(201, 100), floor_sample(202, 101)],
            arithmetic: CenturyFloorArithmetic {
                sample_count: 2,
                sum_jet_size_bytes: 201,
                floor_bytes: 201,
            },
        }
    }

    fn epoch225_plan() -> Plan {
        let mut plan = valid_plan(225);
        plan.schema = PLAN_SCHEMA_V3.into();
        plan.snapshot_name =
            "snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst".into();
        plan.snapshot_sha256 =
            "094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d".into();
        plan.checkpoint_sha256 =
            "1dd033b1df75c58abe07098c48be763ee10ad5d4b4c749efa6c0240a13e7f403".into();
        plan.terminal_root_slot = 98_063_464;
        plan.successor_tail_slots = 431_465;
        plan.receipt = "/home/ubuntu/.jetstreamer-private/campaign-state/epoch225-complete-span-v1-6-25-immutable-package-63a2717-test.json".into();
        plan.century_floor_evidence = Some("/sealed/century-floor.json".into());
        plan.century_floor_evidence_sha256 = Some("f".repeat(64));
        plan
    }

    #[test]
    fn shrink225_package_is_separate_and_keeps_all_v3_scope_and_floor_gates() {
        let mut plan = epoch225_plan();
        plan.package = SHRINK225_PACKAGE.into();
        assert!(shrink225_package(&plan));
        assert!(validate_plan(&plan).is_err()); // Cannot borrow the old receipt.
        plan.receipt = "/home/ubuntu/.jetstreamer-private/campaign-state/epoch225-complete-span-v1-6-25-immutable-package-shrink-budget-test.json".into();
        validate_plan(&plan).unwrap();
        plan.century_floor_evidence = None;
        assert!(validate_plan(&plan).is_err());
        plan.century_floor_evidence = Some("/sealed/century-floor.json".into());
        plan.schema = PLAN_SCHEMA_V1.into();
        assert!(validate_plan(&plan).is_err());
        plan.schema = PLAN_SCHEMA_V3.into();
        plan.terminal_root_slot = 97_631_459;
        assert!(validate_plan(&plan).is_err());
        plan.terminal_root_slot = 98_063_464;
        plan.package = canonical_package_path(225).into();
        assert!(!shrink225_package(&plan));
        assert!(validate_plan(&plan).is_err()); // Legacy package cannot borrow new receipt.
        plan.package = "/var/lib/jetstreamer/horizon-focused-225-other".into();
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn epoch225_attestation_pins_complete_span_and_checkpoint_bytes() {
        let mut plan = epoch225_plan();
        validate_plan(&plan).unwrap();
        let checkpoints = include_bytes!(
            "../../historical-runtime/v1_6_25/epoch225-complete-span-epoch-hashes.txt"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(checkpoints)),
            plan.checkpoint_sha256
        );
        plan.terminal_root_slot = 97_631_459;
        assert!(validate_plan(&plan).is_err());
        plan = epoch225_plan();
        plan.snapshot_sha256 = "a".repeat(64);
        assert!(validate_plan(&plan).is_err());
        plan = epoch225_plan();
        plan.century_floor_evidence = None;
        assert!(validate_plan(&plan).is_err());
        plan = epoch225_plan();
        plan.schema = PLAN_SCHEMA_V1.into();
        assert!(validate_plan(&plan).is_err());
        plan = epoch225_plan();
        plan.package = canonical_package_path(224).into();
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn epoch225_initial_attestation_does_not_claim_capability_or_launch() {
        let plan = epoch225_plan();
        let manifest = serde_json::json!({
            "schema":MANIFEST_SCHEMA,"epoch":225,
            "bootstrap":{"filename":plan.snapshot_name,"sha256":plan.snapshot_sha256},
            "checkpoint":{"filename":plan.checkpoint_name,"sha256":plan.checkpoint_sha256,"terminal_slot":plan.terminal_root_slot},
            "focused_plan":{"epoch":225,"output_slot_start":97_200_000,"epoch_end_slot":97_631_999,
                "terminal_root_slot":98_063_464,"complete_epoch_span_covered":true,"private_verification_tail":true,
                "successor_tail_slots":431_465,"canonical_sidecar_authorized":false},
            "gates":{"complete_epoch_span_covered":true,"exact_node_complete_span_capability_passed":false,
                "source_content_revalidated":true,"immutable_package_sealed":true,"fresh_replay_resource_admission_passed":false,
                "launch_authorized":false,"plugin_verification_authorized":false,"publication_authorized":false,"r2_upload_authorized":false},
            "mutations":{"new_replay_launched":false,"remote_mutations":false,"r2_mutations":false}});
        let decode = |v| serde_json::from_value::<Manifest>(v).unwrap();
        validate_manifest(&plan, &decode(manifest.clone()), false).unwrap();
        assert!(validate_manifest(&plan, &decode(manifest.clone()), true).is_err());
        for key in [
            "exact_node_complete_span_capability_passed",
            "fresh_replay_resource_admission_passed",
            "launch_authorized",
            "plugin_verification_authorized",
            "publication_authorized",
            "r2_upload_authorized",
        ] {
            let mut invalid = manifest.clone();
            invalid["gates"][key] = serde_json::json!(true);
            assert!(validate_manifest(&plan, &decode(invalid), false).is_err());
        }
    }

    #[test]
    fn epoch225_binaries_are_not_borrowed_from_the_bounded_comparison() {
        let identity = |sha: &str| FileIdentity {
            sha256: sha.into(),
            bytes: 1,
            device: 1,
            inode: 1,
            links: 1,
            uid: 0,
            gid: 0,
            mode: "0555".into(),
        };
        let mut members = BTreeMap::from([
            (
                "jetstreamer-node".into(),
                identity("945f36fe11824263258ad561dba106e377148b702f2c615522b171c4ba97ed3b"),
            ),
            (
                "jetstreamer-historical-worker-v1-6-25".into(),
                identity("7cd48efc8719109a69fafcb3209a821ea9f07113e3fb0bfab49db23a6e77a146"),
            ),
        ]);
        validate_epoch225_binaries(225, false, &members).unwrap();
        assert!(validate_epoch225_binaries(225, true, &members).is_err());
        members
            .get_mut("jetstreamer-historical-worker-v1-6-25")
            .unwrap()
            .sha256 = "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd".into();
        validate_epoch225_binaries(225, true, &members).unwrap();
        assert!(validate_epoch225_binaries(225, false, &members).is_err());
        members.get_mut("jetstreamer-node").unwrap().sha256 =
            "3915f57819e5822e7112ee1932dc47caf5e9812605ad56cc309976e4f681f242".into();
        assert!(validate_epoch225_binaries(225, true, &members).is_err());
        assert!(validate_epoch225_binaries(224, true, &members).is_err());
        assert!(validate_epoch225_binaries(224, false, &members).is_ok());
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

    #[test]
    fn external_capability_plan_is_narrowly_limited_to_epoch_203() {
        let mut current = valid_plan(203);
        current.schema = PLAN_SCHEMA_V2.to_string();
        current.capability_receipt = Some(
            "/home/ubuntu/.jetstreamer-private/campaign-state/epoch203-complete-span-package-capability-ca2e38b-rust-20261017-v1.json".into(),
        );
        current.capability_receipt_sha256 = Some("f".repeat(64));
        assert!(validate_plan(&current).is_ok());

        let mut missing = current;
        missing.capability_receipt_sha256 = None;
        assert!(validate_plan(&missing).is_err());

        let mut wrong_epoch = valid_plan(204);
        wrong_epoch.schema = PLAN_SCHEMA_V2.to_string();
        wrong_epoch.capability_receipt = Some(
            "/home/ubuntu/.jetstreamer-private/campaign-state/epoch203-complete-span-package-capability-ca2e38b-rust-20261017-v1.json".into(),
        );
        wrong_epoch.capability_receipt_sha256 = Some("f".repeat(64));
        assert!(validate_plan(&wrong_epoch).is_err());
    }

    #[test]
    fn v3_plan_requires_both_floor_evidence_fields() {
        let mut current = valid_plan(203);
        current.schema = PLAN_SCHEMA_V3.to_string();
        current.capability_receipt = Some(
            "/home/ubuntu/.jetstreamer-private/campaign-state/epoch203-complete-span-package-capability-ca2e38b-rust-20261017-v1.json".into(),
        );
        current.capability_receipt_sha256 = Some("f".repeat(64));
        current.century_floor_evidence =
            Some("/var/lib/jetstreamer/focused-attester/century-floor.json".into());
        current.century_floor_evidence_sha256 = Some("1".repeat(64));
        assert!(validate_plan(&current).is_ok());

        let mut missing_hash = current;
        missing_hash.century_floor_evidence_sha256 = None;
        assert!(validate_plan(&missing_hash).is_err());

        let mut legacy = valid_plan(203);
        legacy.schema = PLAN_SCHEMA_V2.to_string();
        legacy.capability_receipt = Some(
            "/home/ubuntu/.jetstreamer-private/campaign-state/epoch203-complete-span-package-capability-ca2e38b-rust-20261017-v1.json".into(),
        );
        legacy.capability_receipt_sha256 = Some("f".repeat(64));
        legacy.century_floor_evidence =
            Some("/var/lib/jetstreamer/focused-attester/century-floor.json".into());
        legacy.century_floor_evidence_sha256 = Some("1".repeat(64));
        assert!(validate_plan(&legacy).is_err());

        let mut ordinary = valid_plan(210);
        ordinary.schema = PLAN_SCHEMA_V3.to_string();
        ordinary.century_floor_evidence =
            Some("/var/lib/jetstreamer/focused-attester/century-floor.json".into());
        ordinary.century_floor_evidence_sha256 = Some("1".repeat(64));
        assert!(validate_plan(&ordinary).is_ok());

        ordinary.capability_receipt = Some(
            "/home/ubuntu/.jetstreamer-private/campaign-state/epoch203-complete-span-package-capability-ca2e38b-rust-20261017-v1.json".into(),
        );
        ordinary.capability_receipt_sha256 = Some("f".repeat(64));
        assert!(validate_plan(&ordinary).is_err());
    }

    #[test]
    fn century_floor_recomputes_ceil_two_times_mean() {
        let evidence = valid_floor_evidence();
        assert_eq!(
            validate_century_floor_document(&evidence).unwrap(),
            (2, 201, 201)
        );
    }

    #[test]
    fn century_floor_rejects_malformed_or_duplicate_census() {
        let mut empty = valid_floor_evidence();
        empty.samples.clear();
        empty.arithmetic.sample_count = 0;
        empty.arithmetic.sum_jet_size_bytes = 0;
        empty.arithmetic.floor_bytes = 0;
        assert!(validate_century_floor_document(&empty).is_err());

        let mut duplicate = valid_floor_evidence();
        duplicate.samples[1].epoch = duplicate.samples[0].epoch;
        assert!(validate_century_floor_document(&duplicate).is_err());

        let mut outside = valid_floor_evidence();
        outside.samples[0].epoch = 199;
        assert!(validate_century_floor_document(&outside).is_err());
    }

    #[test]
    fn century_floor_rejects_bad_arithmetic_and_u64_overflow() {
        let mut bad = valid_floor_evidence();
        bad.arithmetic.floor_bytes += 1;
        assert!(validate_century_floor_document(&bad).is_err());

        let mut overflow = valid_floor_evidence();
        overflow.samples[0].jet_size_bytes = u64::MAX;
        overflow.samples[1].jet_size_bytes = u64::MAX;
        assert!(validate_century_floor_document(&overflow).is_err());
    }

    #[test]
    fn century_floor_receipts_must_match_archive_identity() {
        let sample = floor_sample(201, 100);
        let mut r2 = R2Receipt {
            schema: R2_RECEIPT_SCHEMA.to_string(),
            bucket: HORIZON_R2_BUCKET.to_string(),
            epoch: 201,
            archive_key: "epoch-201.jet".to_string(),
            checksum_key: "epoch-201.jet.sha256".to_string(),
            archive_length: 100,
            archive_sha256: sample.archive_sha256.clone(),
            archive_etag: "etag".to_string(),
            r2_composite_sha256: None,
            remote_sha256_readback: true,
            multipart_part_size: 5,
            verified_unix_seconds: 1,
        };
        assert!(validate_r2_receipt(&sample, &r2).is_ok());
        r2.archive_length += 1;
        assert!(validate_r2_receipt(&sample, &r2).is_err());

        let valid_text = format!(
            "{} {} {}\n",
            sample.archive_sha256,
            "d".repeat(64),
            "e".repeat(64)
        );
        assert!(validate_text_receipt(valid_text.as_bytes(), &sample.archive_sha256).is_ok());
        let mismatch = format!("{} {} {}\n", "f".repeat(64), "d".repeat(64), "e".repeat(64));
        assert!(validate_text_receipt(mismatch.as_bytes(), &sample.archive_sha256).is_err());
    }

    #[test]
    fn ordinary_v3_plan_uses_internal_manifest_capability() {
        let mut plan = valid_plan(210);
        plan.schema = PLAN_SCHEMA_V3.to_string();
        plan.century_floor_evidence =
            Some("/var/lib/jetstreamer/focused-attester/century-floor.json".into());
        plan.century_floor_evidence_sha256 = Some("1".repeat(64));
        assert!(validate_plan(&plan).is_ok());
        assert!(
            validate_external_capability(&plan, &BTreeMap::new())
                .unwrap()
                .is_none()
        );
    }
}
