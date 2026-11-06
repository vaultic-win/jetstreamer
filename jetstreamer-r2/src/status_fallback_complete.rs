//! Separate completion adapter for the original Root-owned 235/237 fallback
//! publications. It never constructs a native StatusPublicationReceipt. Raw
//! published bytes, their digest and ETag remain the destructive boundary.
use super::*;
use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
};

const PLAN_SCHEMA: &str = "jetstreamer-r2-fallback-complete-status-plan-v1";
const INTENT_SCHEMA: &str = "jetstreamer-r2-fallback-complete-status-delete-intent-v1";
const DELETION_SCHEMA: &str = "jetstreamer-r2-fallback-complete-status-deletion-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    bucket: String,
    epoch: u64,
    completion: Bound,
    archive_receipt: Bound,
    deletion_intent: PathBuf,
    deletion_receipt: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Owner {
    agent: String,
    kind: String,
    original_uploader_closed: Option<bool>,
    ready_pair: Option<Bound>,
    activity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    schema: String,
    epoch: u64,
    bucket: Option<String>,
    key: Option<String>,
    sampled_at_utc: Option<String>,
    intent: Bound,
    after_sha256: String,
    new_etag: String,
    conditional_put: bool,
    authenticated_exact_byte_readback: bool,
    actual_owner: Owner,
    status: Option<EpochStatus>,
    archive_or_sidecar_mutations: Option<bool>,
    estimated_remaining_millis_zero_only_after_genuine_verified_ready_pair: Option<bool>,
    canonical_pair_ready: Option<bool>,
    qualified_status_delete_pending: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationIntent {
    schema: String,
    epoch: Option<u64>,
    bucket: Option<String>,
    key: Option<String>,
    before: Option<Bound>,
    expected_etag: String,
    replacement: Bound,
    prior_owned_completion: Option<Bound>,
    prior: Option<PathBuf>,
    actual_owner: Owner,
    ready_pair: Bound,
    finite_execution_window_seconds: Option<u64>,
    no_archive_sidecar_mutations: Option<bool>,
    qualified_conditional_status_delete_pending: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct Terminal {
    #[serde(rename = "Id")]
    unit: String,
    #[serde(rename = "ActiveState")]
    active: String,
    #[serde(rename = "SubState")]
    sub: String,
    #[serde(rename = "Job")]
    job: String,
    #[serde(rename = "InvocationID")]
    invocation: String,
    #[serde(rename = "MainPID")]
    main_pid: String,
    #[serde(rename = "ControlPID")]
    control_pid: String,
    #[serde(rename = "Result")]
    result: String,
    #[serde(rename = "NRestarts")]
    restarts: String,
    #[serde(rename = "ExecMainStatus")]
    exit_status: String,
    #[serde(rename = "ControlGroup")]
    cgroup: String,
}

#[derive(Debug, Deserialize)]
struct Ready235 {
    schema: String,
    #[serde(rename = "Main_accepted")]
    accepted: bool,
    epoch: u64,
    original_uploader_iid: String,
    actual_terminal_properties: Terminal,
    #[serde(rename = "original_PID_and_cgroup_absent")]
    original_pid_and_cgroup_absent: bool,
    #[serde(rename = "qualified_Rust_archive_receipt")]
    qualified_rust_archive_receipt: Bound,
    receipt: Receipt,
    authenticated_remote_archive_length: u64,
    authenticated_remote_archive_etag: String,
    authenticated_remote_sidecar_etag: String,
    authenticated_exact_sidecar_bytes_sha256: String,
    remote_sidecar_matches_local_canonical_checksum_byte_for_byte: bool,
    #[serde(rename = "canonical_R2_ready_pair_verified")]
    canonical_r2_ready_pair_verified: bool,
    local_retirement_authorized: bool,
}

#[derive(Debug, Deserialize)]
struct Ready237 {
    schema: String,
    #[serde(rename = "Main_accepted")]
    accepted: bool,
    original_uploader_invocation_id: String,
    terminal_native: Terminal,
    #[serde(rename = "original_PIDs_absent")]
    original_pids_absent: bool,
    remote_receipt: Bound,
    remote_receipt_contents: Receipt,
    archive_and_exact_canonical_sidecar_reobserved: bool,
    archive_etag: String,
    sidecar_etag: String,
    no_local_retirement_authority: bool,
    no_archive_sidecar_mutation: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeleteIntent {
    schema: String,
    plan: Bound,
    bucket: String,
    epoch: u64,
    key: String,
    completion: Bound,
    publication_intent: Bound,
    payload: Bound,
    ready_pair: Bound,
    archive_receipt: Bound,
    archive_sha256: String,
    archive_etag: String,
    raw_payload_sha256: String,
    object_etag: String,
    status: EpochStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeletionReceipt {
    schema: String,
    intent: Bound,
    binding: DeleteIntent,
    conditional_delete_request_sent_in_this_invocation: bool,
    recovered_absence_from_matching_durable_intent: bool,
    authenticated_ready_pair_before: bool,
    authenticated_status_absent_after: bool,
    authenticated_ready_pair_after: bool,
    verified_unix_seconds: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct Adapted {
    binding: DeleteIntent,
    raw_payload: Vec<u8>,
}

fn digest(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn profile(epoch: u64) -> Result<(&'static str, &'static str, &'static str)> {
    match epoch {
        235 => Ok((
            "verified-ready-pair-status-cleanup",
            "horizon-upload-235-no-delete-v1.service",
            "38cae2f1dff9447bb4b83e6cfe11a75c",
        )),
        237 => Ok((
            "ready-pair-completion-status-cleanup",
            "horizon-upload-237-no-delete-v3.service",
            "13da397d47274927a89e655e72012c3e",
        )),
        _ => bail!("fallback completion profile supports only epochs 235 and 237"),
    }
}

fn quoted_etag(raw: &str) -> Result<String> {
    let inner = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .context("fallback status ETag must retain its original quotes")?;
    ensure!(
        inner.len() == 32
            && inner
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid fallback status ETag"
    );
    Ok(inner.to_owned())
}

fn calendar_timestamp(value: &str) -> Result<()> {
    ensure!(
        is_canonical_utc(value),
        "status timestamp is not canonical UTC"
    );
    let number = |a, b| value[a..b].parse::<u32>().context("invalid UTC component");
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    ensure!(
        year >= 1970
            && (1..=days).contains(&day)
            && number(11, 13)? < 24
            && number(14, 16)? < 60
            && number(17, 19)? < 60,
        "invalid status calendar timestamp"
    );
    Ok(())
}

fn terminal(row: &Terminal, unit: &str, invocation: &str) -> Result<()> {
    ensure!(
        row.unit == unit
            && row.active == "inactive"
            && row.sub == "dead"
            && row.job.is_empty()
            && (row.invocation.is_empty() || row.invocation == invocation)
            && row.main_pid == "0"
            && row.control_pid == "0"
            && row.result == "success"
            && row.restarts == "0"
            && row.exit_status == "0"
            && row.cgroup.is_empty(),
        "ready proof does not bind the original successful closed uploader"
    );
    Ok(())
}

fn validate_archive(receipt: &Receipt, bucket: &str, epoch: u64) -> Result<()> {
    ensure!(
        receipt.schema == RECEIPT_SCHEMA
            && receipt.bucket == bucket
            && receipt.epoch == epoch
            && receipt.archive_key == format!("epoch-{epoch}.jet")
            && receipt.checksum_key == format!("epoch-{epoch}.jet.sha256")
            && receipt.archive_length > 0
            && valid_digest(&receipt.archive_sha256)
            && !receipt.archive_etag.is_empty()
            && receipt.multipart_part_size >= 5 * 1024 * 1024
            && (receipt.remote_sha256_readback || receipt.r2_composite_sha256.is_some()),
        "archive receipt lacks canonical durable whole-object completion evidence"
    );
    Ok(())
}

fn matching_ready(bytes: &[u8], bound: &Bound, archive: &Receipt, epoch: u64) -> Result<()> {
    let (_, unit, invocation) = profile(epoch)?;
    if epoch == 235 {
        let ready: Ready235 = serde_json::from_slice(bytes)?;
        ensure!(
            ready.schema == "horizon235-genuine-ready-pair-Main-acceptance870-v1"
                && ready.accepted
                && ready.epoch == epoch
                && ready.original_uploader_iid == invocation
                && ready.original_pid_and_cgroup_absent
                && ready.qualified_rust_archive_receipt == *bound
                && ready.receipt == *archive
                && ready.authenticated_remote_archive_length == archive.archive_length
                && normalize_etag(&ready.authenticated_remote_archive_etag) == archive.archive_etag
                && !ready.authenticated_remote_sidecar_etag.is_empty()
                && ready.authenticated_exact_sidecar_bytes_sha256
                    == digest(&canonical_sidecar(archive))
                && ready.remote_sidecar_matches_local_canonical_checksum_byte_for_byte
                && ready.canonical_r2_ready_pair_verified
                && !ready.local_retirement_authorized,
            "235 ready proof differs from the exact archive receipt"
        );
        terminal(&ready.actual_terminal_properties, unit, invocation)?;
    } else {
        let ready: Ready237 = serde_json::from_slice(bytes)?;
        ensure!(
            ready.schema == "horizon237-genuine-ready-pair909-acceptance-v1"
                && ready.accepted
                && ready.original_uploader_invocation_id == invocation
                && ready.original_pids_absent
                && ready.remote_receipt == *bound
                && ready.remote_receipt_contents == *archive
                && ready.archive_and_exact_canonical_sidecar_reobserved
                && normalize_etag(&ready.archive_etag) == archive.archive_etag
                && !ready.sidecar_etag.is_empty()
                && ready.no_local_retirement_authority
                && ready.no_archive_sidecar_mutation,
            "237 ready proof differs from the exact archive receipt"
        );
        terminal(&ready.terminal_native, unit, invocation)?;
    }
    Ok(())
}

fn adapt(
    plan: &Plan,
    plan_bound: &Bound,
    completion_raw: &[u8],
    intent_raw: &[u8],
    payload_raw: &[u8],
    ready_raw: &[u8],
    archive: &Receipt,
) -> Result<Adapted> {
    ensure!(
        plan.schema == PLAN_SCHEMA && !plan.bucket.is_empty(),
        "invalid fallback completion plan"
    );
    let (kind, _, _) = profile(plan.epoch)?;
    let completion: Completion = serde_json::from_slice(completion_raw)?;
    let intent: PublicationIntent = serde_json::from_slice(intent_raw)?;
    let status: EpochStatus = serde_json::from_slice(payload_raw)?;
    let key = format!("epoch-{}.epoch-status.json", plan.epoch);
    ensure!(
        digest(completion_raw) == plan.completion.sha256
            && digest(intent_raw) == completion.intent.sha256
            && digest(payload_raw) == completion.after_sha256
            && completion.after_sha256 == intent.replacement.sha256
            && digest(ready_raw) == intent.ready_pair.sha256,
        "fallback completion/intent/raw payload/ready-proof digest mismatch"
    );
    ensure!(
        completion.schema == "horizon-repair-status-cadence-refresh-completion-v2"
            && completion.epoch == plan.epoch
            && completion.conditional_put
            && completion.authenticated_exact_byte_readback
            && completion
                .bucket
                .as_deref()
                .is_none_or(|b| b == plan.bucket)
            && completion.key.as_deref().is_none_or(|k| k == key)
            && intent.bucket.as_deref().is_none_or(|b| b == plan.bucket)
            && intent.epoch.is_none_or(|e| e == plan.epoch)
            && intent.key.as_deref().is_none_or(|k| k == key),
        "fallback completion has wrong epoch/key/bucket or lacks conditional authenticated publication"
    );
    ensure!(
        completion.actual_owner == intent.actual_owner
            && completion.actual_owner.agent == "/root"
            && completion.actual_owner.kind == kind,
        "foreign or changed fallback completion owner"
    );
    if plan.epoch == 235 {
        ensure!(
            intent.schema == "horizon235-ready-status-correction-intent-v1"
                && intent.epoch == Some(235)
                && intent.key.as_deref() == Some(key.as_str())
                && completion.key.as_deref() == Some(key.as_str())
                && completion.status.is_none()
                && completion.sampled_at_utc.as_deref() == Some(status.sampled_at_utc.as_str())
                && completion.actual_owner.original_uploader_closed == Some(true)
                && completion.actual_owner.ready_pair.as_ref() == Some(&intent.ready_pair)
                && completion.archive_or_sidecar_mutations == Some(false)
                && completion
                    .estimated_remaining_millis_zero_only_after_genuine_verified_ready_pair
                    == Some(true)
                && intent.before.is_some()
                && intent.prior_owned_completion.is_some()
                && intent.no_archive_sidecar_mutations == Some(true)
                && intent
                    .finite_execution_window_seconds
                    .is_some_and(|s| s > 0 && s <= 180),
            "235 fallback completion profile is incomplete"
        );
    } else {
        ensure!(
            intent.schema == "horizon237-zero-complete-status909-intent-v1"
                && completion.status.as_ref() == Some(&status)
                && completion.canonical_pair_ready == Some(true)
                && completion.qualified_status_delete_pending == Some(true)
                && intent.qualified_conditional_status_delete_pending == Some(true)
                && intent.prior.is_some(),
            "237 fallback completion profile is incomplete"
        );
    }
    quoted_etag(&intent.expected_etag)?;
    let etag = quoted_etag(&completion.new_etag)?;
    ensure!(
        status.epoch == plan.epoch
            && status.estimated_remaining_millis == 0
            && matches!(
                status.phase.as_str(),
                "replay" | "verification" | "upload" | "readback"
            ),
        "completion adapter requires an exact zero-remaining supported status"
    );
    calendar_timestamp(&status.sampled_at_utc)?;
    validate_archive(archive, &plan.bucket, plan.epoch)?;
    ensure!(
        status.jet_size_bytes == archive.archive_length,
        "completion status length differs from the ready archive"
    );
    matching_ready(ready_raw, &plan.archive_receipt, archive, plan.epoch)?;
    Ok(Adapted {
        binding: DeleteIntent {
            schema: INTENT_SCHEMA.into(),
            plan: plan_bound.clone(),
            bucket: plan.bucket.clone(),
            epoch: plan.epoch,
            key,
            completion: plan.completion.clone(),
            publication_intent: completion.intent,
            payload: intent.replacement,
            ready_pair: intent.ready_pair,
            archive_receipt: plan.archive_receipt.clone(),
            archive_sha256: archive.archive_sha256.clone(),
            archive_etag: archive.archive_etag.clone(),
            raw_payload_sha256: completion.after_sha256,
            object_etag: etag,
            status,
        },
        raw_payload: payload_raw.to_vec(),
    })
}

#[derive(Debug, Eq, PartialEq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    length: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

fn file_identity(m: &fs::Metadata) -> Identity {
    Identity {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        length: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}

// Descriptor-relative opens reject symlinks in every path component. Reopening
// the same absolute path after the bounded read detects renamed parent chains.
fn nofollow_open(path: &Path, directory: bool) -> Result<File> {
    let raw = path.to_str().context("evidence path is not UTF-8")?;
    ensure!(
        raw.starts_with('/') && raw.len() <= 4096 && raw != "/",
        "evidence path must be absolute and bounded"
    );
    let parts: Vec<_> = raw[1..].split('/').collect();
    ensure!(
        parts
            .iter()
            .all(|p| !p.is_empty() && *p != "." && *p != ".."),
        "evidence path is not canonical"
    );
    let mut parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for (i, part) in parts.iter().enumerate() {
        let final_part = i + 1 == parts.len();
        let name = CString::new(part.as_bytes())?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if !final_part || directory {
                libc::O_DIRECTORY
            } else {
                0
            };
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        ensure!(
            fd >= 0,
            "nofollow evidence open failed: {}",
            std::io::Error::last_os_error()
        );
        parent = unsafe { File::from_raw_fd(fd) };
    }
    Ok(parent)
}

fn read_evidence(path: &Path, root_only: bool) -> Result<Vec<u8>> {
    let mut file = nofollow_open(path, false)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.len() <= MAX_STATUS_BYTES
            && (!root_only || (before.uid() == 0 && before.mode() & 0o222 == 0)),
        "proof must be bounded, singly linked, Root-owned and nonwritable"
    );
    let mut raw = Vec::new();
    (&mut file)
        .take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut raw)?;
    let reopened = nofollow_open(path, false)?;
    ensure!(
        raw.len() as u64 == before.len()
            && file_identity(&before) == file_identity(&file.metadata()?)
            && file_identity(&before) == file_identity(&reopened.metadata()?),
        "evidence inode/owner/mode/length/timestamps changed"
    );
    Ok(raw)
}

fn bound_bytes(bound: &Bound, root_only: bool) -> Result<Vec<u8>> {
    ensure!(valid_digest(&bound.sha256), "invalid evidence SHA-256");
    let raw = read_evidence(&bound.path, root_only)?;
    ensure!(
        digest(&raw) == bound.sha256,
        "bound evidence SHA-256 mismatch"
    );
    Ok(raw)
}

fn load(plan: &Plan, plan_bound: &Bound) -> Result<(Adapted, Receipt)> {
    let completion_raw = bound_bytes(&plan.completion, true)?;
    let completion: Completion = serde_json::from_slice(&completion_raw)?;
    let intent_raw = bound_bytes(&completion.intent, true)?;
    let intent: PublicationIntent = serde_json::from_slice(&intent_raw)?;
    let payload = bound_bytes(&intent.replacement, true)?;
    let ready = bound_bytes(&intent.ready_pair, true)?;
    let archive_raw = bound_bytes(&plan.archive_receipt, false)?;
    let archive: Receipt = serde_json::from_slice(&archive_raw)?;
    let parent = plan
        .archive_receipt
        .path
        .parent()
        .context("archive receipt parent missing")?;
    ensure!(
        plan.archive_receipt.path == receipt_path(parent, plan.epoch),
        "archive receipt filename is not canonical"
    );
    ensure!(
        read_restore_receipt(parent, &plan.bucket, plan.epoch)? == archive,
        "archive receipt changed between independent validations"
    );
    Ok((
        adapt(
            plan,
            plan_bound,
            &completion_raw,
            &intent_raw,
            &payload,
            &ready,
            &archive,
        )?,
        archive,
    ))
}

fn private_parent(path: &Path) -> Result<File> {
    let parent = path.parent().context("deletion evidence parent missing")?;
    let handle = nofollow_open(parent, true)?;
    let m = handle.metadata()?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "deletion evidence parent must already be Root-private 0700"
    );
    Ok(handle)
}

fn persist<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent_handle = private_parent(path)?;
    let parent = path.parent().context("deletion evidence parent missing")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o400))?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    ensure!(
        file_identity(&parent_handle.metadata()?)
            == file_identity(&nofollow_open(parent, true)?.metadata()?),
        "deletion directory changed before publication"
    );
    temporary
        .persist_noclobber(path)
        .map_err(|e| anyhow!("no-clobber deletion evidence: {}", e.error))?;
    parent_handle.sync_all()?;
    Ok(())
}

fn optional_evidence(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_evidence(path, true).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("cannot inspect fallback deletion evidence"),
    }
}

fn preflight_destination(path: &Path) -> Result<()> {
    let directory = private_parent(path)?;
    let parent = path.parent().context("missing deletion directory")?;
    let mut probe = tempfile::Builder::new()
        .prefix(".fallback-status-write-probe-")
        .tempfile_in(parent)?;
    probe.write_all(b"fallback-status-preflight\n")?;
    probe.as_file().sync_all()?;
    probe.close()?;
    ensure!(
        file_identity(&directory.metadata()?)
            == file_identity(&nofollow_open(parent, true)?.metadata()?),
        "fallback receipt directory changed during preflight"
    );
    directory.sync_all()?;
    Ok(())
}

fn matches_object(object: &MutableRemoteObject, adapted: &Adapted) -> Result<()> {
    ensure!(
        object.etag == adapted.binding.object_etag
            && object.bytes == adapted.raw_payload
            && digest(&object.bytes) == adapted.binding.raw_payload_sha256,
        "current status bytes/ETag differ; newer reports must not be deleted"
    );
    Ok(())
}

fn absence_allowed(present: bool, durable_intent_matches: bool) -> Result<()> {
    ensure!(
        present || durable_intent_matches,
        "unexplained status absence is not fallback deletion completion"
    );
    Ok(())
}

async fn delete_exact(s3: &Client, bucket: &str, adapted: &Adapted) -> Result<()> {
    profile(adapted.binding.epoch)?;
    ensure!(
        adapted.binding.bucket == bucket
            && adapted.binding.key == format!("epoch-{}.epoch-status.json", adapted.binding.epoch)
            && adapted.binding.status.epoch == adapted.binding.epoch
            && adapted.binding.status.estimated_remaining_millis == 0
            && matches!(
                adapted.binding.status.phase.as_str(),
                "replay" | "verification" | "upload" | "readback"
            )
            && digest(&adapted.raw_payload) == adapted.binding.raw_payload_sha256
            && serde_json::from_slice::<EpochStatus>(&adapted.raw_payload)?
                == adapted.binding.status,
        "destructive request does not name the bound canonical zero status"
    );
    quoted_etag(&format!("\"{}\"", adapted.binding.object_etag))?;
    calendar_timestamp(&adapted.binding.status.sampled_at_utc)?;
    // All remote deletion still passes through the original singular helper.
    conditional_delete_epoch_status(
        s3,
        bucket,
        adapted.binding.epoch,
        &adapted.binding.object_etag,
    )
    .await
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        (args.len() == 7 || (args.len() == 8 && args[7] == "--check-only"))
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256",
        "usage: jetstreamer-r2 status-delete-fallback-complete PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "fallback completion cleanup requires Root"
    );
    ensure!(valid_digest(&args[6]), "invalid executable SHA-256");
    let mut executable = File::open("/proc/self/exe")?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = executable.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    ensure!(
        hex_lower(&hash.finalize()) == args[6],
        "fallback cleanup executable digest mismatch"
    );
    let plan_bound = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let plan_raw = bound_bytes(&plan_bound, true)?;
    let plan: Plan = serde_json::from_slice(&plan_raw)?;
    profile(plan.epoch)?;
    ensure!(
        plan.deletion_intent.file_name()
            == Some(std::ffi::OsStr::new(&format!(
                "epoch-{}.fallback-status-delete-intent.json",
                plan.epoch
            )))
            && plan.deletion_receipt.file_name()
                == Some(std::ffi::OsStr::new(&format!(
                    "epoch-{}.fallback-status-deletion.json",
                    plan.epoch
                ))),
        "fallback deletion evidence filenames must be canonical"
    );
    private_parent(&plan.deletion_intent)?;
    private_parent(&plan.deletion_receipt)?;
    let (adapted, archive) = load(&plan, &plan_bound)?;
    preflight_destination(&plan.deletion_intent)?;
    preflight_destination(&plan.deletion_receipt)?;
    if args.len() == 8 {
        println!(
            "{}",
            serde_json::json!({"local_fallback_adapter_validated":true,"epoch":plan.epoch,
            "authenticated_remote_ready_pair_checked":false,"remote_mutations":false})
        );
        return Ok(());
    }
    let r2 = r2_config_from_env()?;
    ensure!(
        r2.bucket == plan.bucket,
        "fallback cleanup environment names a different bucket"
    );
    let s3 = s3_client(&r2);
    validate_authenticated_ready_pair(&s3, &r2.bucket, &archive).await?;
    let prior_intent = match optional_evidence(&plan.deletion_intent)? {
        Some(raw) => {
            ensure!(
                serde_json::from_slice::<DeleteIntent>(&raw)? == adapted.binding,
                "existing fallback deletion intent differs"
            );
            true
        }
        None => false,
    };
    let current = get_mutable_object(&s3, &r2.bucket, &adapted.binding.key).await?;
    absence_allowed(current.is_some(), prior_intent)?;
    if let Some(raw_done) = optional_evidence(&plan.deletion_receipt)? {
        let done: DeletionReceipt = serde_json::from_slice(&raw_done)?;
        let raw_intent = read_evidence(&plan.deletion_intent, true)?;
        ensure!(
            prior_intent
                && current.is_none()
                && done.schema == DELETION_SCHEMA
                && done.binding == adapted.binding
                && done.intent
                    == (Bound {
                        path: plan.deletion_intent.clone(),
                        sha256: digest(&raw_intent)
                    })
                && done.authenticated_ready_pair_before
                && done.authenticated_status_absent_after
                && done.authenticated_ready_pair_after,
            "existing fallback deletion receipt differs or status reappeared"
        );
        validate_authenticated_ready_pair(&s3, &r2.bucket, &archive).await?;
        println!("{}", plan.deletion_receipt.display());
        return Ok(());
    }
    if let Some(object) = &current {
        matches_object(object, &adapted)?;
    }
    if !prior_intent {
        persist(&plan.deletion_intent, &adapted.binding)?;
    }
    // Re-read all original raw proofs and the qualified archive receipt before
    // the request. No native-schema translation or payload reserialization.
    ensure!(
        bound_bytes(&plan_bound, true)? == plan_raw,
        "fallback cleanup plan changed before deletion"
    );
    let (rechecked, rechecked_archive) = load(&plan, &plan_bound)?;
    ensure!(
        rechecked == adapted && rechecked_archive == archive,
        "fallback proof changed before deletion"
    );
    let raw_intent_before = read_evidence(&plan.deletion_intent, true)?;
    ensure!(
        serde_json::from_slice::<DeleteIntent>(&raw_intent_before)? == adapted.binding,
        "durable fallback deletion intent changed before deletion"
    );
    if current.is_some() {
        delete_exact(&s3, &r2.bucket, &adapted).await?;
    }
    ensure!(
        get_mutable_object(&s3, &r2.bucket, &adapted.binding.key)
            .await?
            .is_none(),
        "fallback status remains after conditional deletion"
    );
    validate_authenticated_ready_pair(&s3, &r2.bucket, &archive).await?;
    ensure!(
        bound_bytes(&plan_bound, true)? == plan_raw,
        "fallback cleanup plan changed after deletion"
    );
    let (after, after_archive) = load(&plan, &plan_bound)?;
    ensure!(
        after == adapted && after_archive == archive,
        "fallback proof changed after deletion"
    );
    let raw_intent = read_evidence(&plan.deletion_intent, true)?;
    ensure!(
        raw_intent == raw_intent_before
            && serde_json::from_slice::<DeleteIntent>(&raw_intent)? == adapted.binding,
        "durable fallback deletion intent changed"
    );
    persist(
        &plan.deletion_receipt,
        &DeletionReceipt {
            schema: DELETION_SCHEMA.into(),
            intent: Bound {
                path: plan.deletion_intent.clone(),
                sha256: digest(&raw_intent),
            },
            binding: adapted.binding,
            conditional_delete_request_sent_in_this_invocation: current.is_some(),
            recovered_absence_from_matching_durable_intent: current.is_none(),
            authenticated_ready_pair_before: true,
            authenticated_status_absent_after: true,
            authenticated_ready_pair_after: true,
            verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        },
    )?;
    println!("{}", plan.deletion_receipt.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Documents {
        plan: Plan,
        plan_bound: Bound,
        completion: Value,
        intent: Value,
        payload: Vec<u8>,
        ready: Value,
        archive: Receipt,
    }

    impl Documents {
        fn bind(&mut self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let ready = serde_json::to_vec(&self.ready).unwrap();
            self.intent["ready_pair"]["sha256"] = json!(digest(&ready));
            if self.plan.epoch == 235 {
                self.intent["actual_owner"]["ready_pair"] = self.intent["ready_pair"].clone();
                self.completion["actual_owner"]["ready_pair"] = self.intent["ready_pair"].clone();
            }
            self.intent["replacement"]["sha256"] = json!(digest(&self.payload));
            self.completion["after_sha256"] = json!(digest(&self.payload));
            let intent = serde_json::to_vec(&self.intent).unwrap();
            self.completion["intent"]["sha256"] = json!(digest(&intent));
            let completion = serde_json::to_vec(&self.completion).unwrap();
            self.plan.completion.sha256 = digest(&completion);
            (completion, intent, ready)
        }

        fn adapted(&mut self) -> Result<Adapted> {
            let (completion, intent, ready) = self.bind();
            adapt(
                &self.plan,
                &self.plan_bound,
                &completion,
                &intent,
                &self.payload,
                &ready,
                &self.archive,
            )
        }
    }

    fn documents(epoch: u64) -> Documents {
        let (kind, unit, iid) = profile(epoch).unwrap();
        let archive = Receipt {
            schema: RECEIPT_SCHEMA.into(),
            bucket: "test-bucket".into(),
            epoch,
            archive_key: format!("epoch-{epoch}.jet"),
            checksum_key: format!("epoch-{epoch}.jet.sha256"),
            archive_length: 9001,
            archive_sha256: "a".repeat(64),
            archive_etag: "archive-etag-2".into(),
            r2_composite_sha256: None,
            remote_sha256_readback: true,
            multipart_part_size: 67108864,
            verified_unix_seconds: 1793953908,
        };
        let archive_bound = Bound {
            path: format!("/private/epoch-{epoch}.r2.json").into(),
            sha256: "b".repeat(64),
        };
        let ready_bound = json!({"path":"/root/private/ready.json","sha256":""});
        let mut owner = json!({"agent":"/root","kind":kind});
        if epoch == 235 {
            owner["original_uploader_closed"] = json!(true);
            owner["ready_pair"] = ready_bound.clone();
            owner["activity"] = json!("verified ready pair cleanup");
        }
        let status = EpochStatus {
            epoch,
            jet_size_bytes: 9001,
            elapsed_execution_millis: 4000,
            estimated_remaining_millis: 0,
            sampled_at_utc: "2026-11-06T08:37:56Z".into(),
            phase: "readback".into(),
        };
        // Deliberately unlike native pretty serialization: exact original byte
        // order and whitespace must remain the comparison after adaptation.
        let payload = format!("{{\"phase\":\"readback\",\"sampled_at_utc\":\"2026-11-06T08:37:56Z\",\"estimated_remaining_millis\":0,\"elapsed_execution_millis\":4000,\"jet_size_bytes\":9001,\"epoch\":{epoch}}}\n").into_bytes();
        let terminal = json!({"Id":unit,"ActiveState":"inactive","SubState":"dead","Job":"","InvocationID":"",
            "MainPID":"0","ControlPID":"0","Result":"success","NRestarts":"0","ExecMainStatus":"0","ControlGroup":""});
        let ready = if epoch == 235 {
            json!({"schema":"horizon235-genuine-ready-pair-Main-acceptance870-v1","Main_accepted":true,"epoch":235,
                "original_uploader_iid":iid,"actual_terminal_properties":terminal,"original_PID_and_cgroup_absent":true,
                "qualified_Rust_archive_receipt":archive_bound,"receipt":archive,
                "authenticated_remote_archive_length":9001,"authenticated_remote_archive_etag":"\"archive-etag-2\"",
                "authenticated_remote_sidecar_etag":"\"sidecar\"","authenticated_exact_sidecar_bytes_sha256":digest(&canonical_sidecar(&archive)),
                "remote_sidecar_matches_local_canonical_checksum_byte_for_byte":true,"canonical_R2_ready_pair_verified":true,
                "local_retirement_authorized":false})
        } else {
            json!({"schema":"horizon237-genuine-ready-pair909-acceptance-v1","Main_accepted":true,
                "original_uploader_invocation_id":iid,"terminal_native":terminal,"original_PIDs_absent":true,
                "remote_receipt":archive_bound,"remote_receipt_contents":archive,
                "archive_and_exact_canonical_sidecar_reobserved":true,"archive_etag":"\"archive-etag-2\"",
                "sidecar_etag":"\"sidecar\"","no_local_retirement_authority":true,"no_archive_sidecar_mutation":true})
        };
        let mut completion = json!({"schema":"horizon-repair-status-cadence-refresh-completion-v2","epoch":epoch,
            "intent":{"path":"/root/private/publication-intent.json","sha256":""},"after_sha256":"",
            "new_etag":"\"55ab3e28ef90da4cd01c3915c88fb2e0\"","conditional_put":true,
            "authenticated_exact_byte_readback":true,"actual_owner":owner});
        let mut intent = json!({"schema":if epoch == 235 {"horizon235-ready-status-correction-intent-v1"} else {"horizon237-zero-complete-status909-intent-v1"},
            "expected_etag":"\"b3bdd97ad61337202168616703564113\"","replacement":{"path":"/root/private/raw-status.json","sha256":""},
            "actual_owner":owner,"ready_pair":ready_bound});
        if epoch == 235 {
            completion["key"] = json!("epoch-235.epoch-status.json");
            completion["sampled_at_utc"] = json!(status.sampled_at_utc);
            completion["archive_or_sidecar_mutations"] = json!(false);
            completion["estimated_remaining_millis_zero_only_after_genuine_verified_ready_pair"] =
                json!(true);
            intent["epoch"] = json!(235);
            intent["key"] = json!("epoch-235.epoch-status.json");
            intent["before"] = json!({"path":"/root/private/before.json","sha256":"c".repeat(64)});
            intent["prior_owned_completion"] =
                json!({"path":"/root/private/prior.json","sha256":"d".repeat(64)});
            intent["finite_execution_window_seconds"] = json!(180);
            intent["no_archive_sidecar_mutations"] = json!(true);
        } else {
            completion["status"] = json!(status);
            completion["canonical_pair_ready"] = json!(true);
            completion["qualified_status_delete_pending"] = json!(true);
            intent["qualified_conditional_status_delete_pending"] = json!(true);
            intent["prior"] = json!("/root/private/prior.json");
        }
        Documents {
            plan: Plan {
                schema: PLAN_SCHEMA.into(),
                bucket: "test-bucket".into(),
                epoch,
                completion: Bound {
                    path: "/root/private/completion.json".into(),
                    sha256: String::new(),
                },
                archive_receipt: archive_bound,
                deletion_intent: "/root/private/delete-intent.json".into(),
                deletion_receipt: "/root/private/delete-completion.json".into(),
            },
            plan_bound: Bound {
                path: "/root/private/plan.json".into(),
                sha256: "e".repeat(64),
            },
            completion,
            intent,
            payload,
            ready,
            archive,
        }
    }

    #[test]
    fn both_original_fallback_shapes_preserve_raw_order_and_bytes() {
        for epoch in [235, 237] {
            let mut d = documents(epoch);
            let p = d.adapted().unwrap();
            assert_ne!(
                p.raw_payload,
                epoch_status_bytes(&p.binding.status).unwrap()
            );
            matches_object(
                &MutableRemoteObject {
                    bytes: d.payload.clone(),
                    etag: p.binding.object_etag.clone(),
                },
                &p,
            )
            .unwrap();
            assert_eq!(p.binding.key, format!("epoch-{epoch}.epoch-status.json"));
        }
    }

    #[test]
    fn independently_rebound_wrong_owner_flags_keys_bucket_and_schema_still_fail() {
        for epoch in [235, 237] {
            let edits: Vec<Box<dyn Fn(&mut Documents)>> = vec![
                Box::new(|d| d.completion["epoch"] = json!(999)),
                Box::new(|d| d.completion["key"] = json!("epoch-235.jet")),
                Box::new(|d| d.intent["key"] = json!("epoch-235.jet.sha256")),
                Box::new(|d| d.completion["bucket"] = json!("foreign")),
                Box::new(|d| d.intent["bucket"] = json!("foreign")),
                Box::new(|d| d.completion["conditional_put"] = json!(false)),
                Box::new(|d| {
                    d.completion
                        .as_object_mut()
                        .unwrap()
                        .remove("authenticated_exact_byte_readback");
                }),
                Box::new(|d| d.completion["authenticated_exact_byte_readback"] = json!(false)),
                Box::new(|d| d.completion["schema"] = json!(STATUS_RECEIPT_SCHEMA)),
                Box::new(|d| d.intent["schema"] = json!("invented-intent")),
                Box::new(|d| {
                    d.completion["actual_owner"]["kind"] = json!("replay");
                    d.intent["actual_owner"]["kind"] = json!("replay");
                }),
                Box::new(|d| {
                    d.completion["actual_owner"]["agent"] = json!("foreign");
                    d.intent["actual_owner"]["agent"] = json!("foreign");
                }),
                Box::new(|d| d.completion["new_etag"] = json!("unquoted")),
                Box::new(|d| d.ready["schema"] = json!("invented-ready-proof")),
                Box::new(|d| d.ready["Main_accepted"] = json!(false)),
                Box::new(|d| d.archive.remote_sha256_readback = false),
            ];
            for edit in edits {
                let mut d = documents(epoch);
                edit(&mut d);
                assert!(d.adapted().is_err());
            }
        }
    }

    #[test]
    fn all_six_status_fields_are_required_with_integers_and_supported_zero_phase() {
        let fields = [
            "epoch",
            "jet_size_bytes",
            "elapsed_execution_millis",
            "estimated_remaining_millis",
            "sampled_at_utc",
            "phase",
        ];
        for field in fields {
            let mut d = documents(235);
            let mut status: Value = serde_json::from_slice(&d.payload).unwrap();
            status.as_object_mut().unwrap().remove(field);
            d.payload = serde_json::to_vec(&status).unwrap();
            assert!(d.adapted().is_err());
        }
        for (field, bad) in [
            ("epoch", json!(237)),
            ("jet_size_bytes", json!(9002)),
            ("elapsed_execution_millis", json!("4000")),
            ("jet_size_bytes", json!(-1)),
            ("estimated_remaining_millis", json!(1)),
            ("estimated_remaining_millis", json!(null)),
            ("phase", json!("finalization")),
            ("phase", json!("READBACK")),
            ("sampled_at_utc", json!("2026-02-30T08:37:56Z")),
        ] {
            let mut d = documents(235);
            let mut status: Value = serde_json::from_slice(&d.payload).unwrap();
            status[field] = bad;
            d.payload = serde_json::to_vec(&status).unwrap();
            assert!(d.adapted().is_err(), "{field}");
        }
        let mut d = documents(237);
        d.completion["status"]["jet_size_bytes"] = json!(42);
        assert!(d.adapted().is_err());
        assert!(calendar_timestamp("2024-02-29T23:59:59Z").is_ok());
        assert!(calendar_timestamp("2026-11-06T24:00:00Z").is_err());
    }

    #[test]
    fn changed_raw_payload_digest_or_newer_remote_etag_is_never_deleted() {
        let mut d = documents(237);
        let (completion, intent, ready) = d.bind();
        let mut changed_payload = d.payload.clone();
        changed_payload.push(b' ');
        assert!(
            adapt(
                &d.plan,
                &d.plan_bound,
                &completion,
                &intent,
                &changed_payload,
                &ready,
                &d.archive
            )
            .is_err()
        );
        let p = d.adapted().unwrap();
        assert!(
            matches_object(
                &MutableRemoteObject {
                    bytes: d.payload.clone(),
                    etag: "newer-report".into()
                },
                &p
            )
            .is_err()
        );
        assert!(
            matches_object(
                &MutableRemoteObject {
                    bytes: epoch_status_bytes(&p.binding.status).unwrap(),
                    etag: p.binding.object_etag.clone()
                },
                &p
            )
            .is_err()
        );
        let mut corrupted = completion;
        corrupted.push(b' ');
        assert!(
            adapt(
                &d.plan,
                &d.plan_bound,
                &corrupted,
                &intent,
                &d.payload,
                &ready,
                &d.archive
            )
            .is_err()
        );
        assert!(absence_allowed(false, false).is_err());
        assert!(absence_allowed(false, true).is_ok());
    }

    #[test]
    fn matching_ready_proof_cannot_be_foreign_restarted_or_unverified() {
        for epoch in [235, 237] {
            let terminal_key = if epoch == 235 {
                "actual_terminal_properties"
            } else {
                "terminal_native"
            };
            for (field, bad) in [
                ("Id", "foreign.service"),
                ("NRestarts", "1"),
                ("MainPID", "123"),
                ("Result", "exit-code"),
                ("InvocationID", "foreign"),
            ] {
                let mut d = documents(epoch);
                d.ready[terminal_key][field] = json!(bad);
                assert!(d.adapted().is_err());
            }
            let mut d = documents(epoch);
            let receipt_key = if epoch == 235 {
                "receipt"
            } else {
                "remote_receipt_contents"
            };
            d.ready[receipt_key]["bucket"] = json!("foreign");
            assert!(d.adapted().is_err());
            let ready_flags: &[&str] = if epoch == 235 {
                &[
                    "original_PID_and_cgroup_absent",
                    "remote_sidecar_matches_local_canonical_checksum_byte_for_byte",
                    "canonical_R2_ready_pair_verified",
                ]
            } else {
                &[
                    "original_PIDs_absent",
                    "archive_and_exact_canonical_sidecar_reobserved",
                    "no_local_retirement_authority",
                    "no_archive_sidecar_mutation",
                ]
            };
            for flag in ready_flags {
                let mut d = documents(epoch);
                d.ready[*flag] = json!(false);
                assert!(d.adapted().is_err(), "false ready flag {flag}");
                let mut d = documents(epoch);
                d.ready.as_object_mut().unwrap().remove(*flag);
                assert!(d.adapted().is_err(), "missing ready flag {flag}");
            }
        }
    }

    #[test]
    fn nofollow_reader_rejects_symlink_components_hardlinks_and_writable_root_proofs() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let t = tempfile::tempdir().unwrap();
        let payload = t.path().join("proof.json");
        fs::write(&payload, b"{}").unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(read_evidence(&payload, false).unwrap(), b"{}");
        assert_eq!(
            read_evidence(&payload, true).is_ok(),
            unsafe { libc::geteuid() } == 0
        );
        let alias = t.path().join("alias.json");
        symlink(&payload, &alias).unwrap();
        assert!(read_evidence(&alias, false).is_err());
        let directory_alias = t.path().join("alias-directory");
        symlink(t.path(), &directory_alias).unwrap();
        assert!(read_evidence(&directory_alias.join("proof.json"), false).is_err());
        let link = t.path().join("hardlink.json");
        fs::hard_link(&payload, &link).unwrap();
        assert!(read_evidence(&payload, false).is_err());
        fs::remove_file(&link).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_evidence(&payload, true).is_err());
    }

    #[tokio::test]
    async fn real_sdk_request_is_exact_status_key_if_match_and_412_is_fatal() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let started = Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(started.elapsed() < Duration::from_secs(10));
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buffer).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buffer[..n]);
            }
            let body = "<Error><Code>PreconditionFailed</Code></Error>";
            write!(stream, "HTTP/1.1 412 Precondition Failed\r\ncontent-type: application/xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", body.len(), body).unwrap();
            String::from_utf8(request).unwrap()
        });
        let mut d = documents(237);
        let adapted = d.adapted().unwrap();
        let r2 = R2Config {
            endpoint,
            bucket: "test-bucket".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
        };
        assert!(
            delete_exact(&s3_client(&r2), &r2.bucket, &adapted)
                .await
                .is_err()
        );
        let request = server.join().unwrap().to_lowercase();
        assert!(
            request
                .lines()
                .next()
                .unwrap()
                .starts_with("delete /test-bucket/epoch-237.epoch-status.json")
        );
        assert!(request.contains("if-match: \"55ab3e28ef90da4cd01c3915c88fb2e0\"\r\n"));
    }

    #[tokio::test]
    async fn destructive_boundary_rejects_archive_sidecar_foreign_bucket_and_nonzero_before_sdk() {
        let mut d = documents(235);
        let mut p = d.adapted().unwrap();
        let r2 = R2Config {
            endpoint: "http://127.0.0.1:1".into(),
            bucket: "test-bucket".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
        };
        for key in [
            "epoch-235.jet",
            "epoch-235.jet.sha256",
            "prefix/epoch-235.epoch-status.json",
        ] {
            p.binding.key = key.into();
            assert!(delete_exact(&s3_client(&r2), &r2.bucket, &p).await.is_err());
        }
        p = d.adapted().unwrap();
        assert!(delete_exact(&s3_client(&r2), "foreign", &p).await.is_err());
        p.binding.status.estimated_remaining_millis = 1;
        assert!(delete_exact(&s3_client(&r2), &r2.bucket, &p).await.is_err());
    }

    #[test]
    #[ignore = "requires Root; run only in qualification sandbox"]
    fn root_receipts_never_clobber_existing_durable_evidence() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = t.path().join("receipt.json");
        persist(&path, &json!({"original":true})).unwrap();
        assert!(persist(&path, &json!({"replacement":true})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&read_evidence(&path, true).unwrap()).unwrap(),
            json!({"original":true})
        );
    }
}
