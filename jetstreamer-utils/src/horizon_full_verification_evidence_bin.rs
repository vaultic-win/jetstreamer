//! Collect a fail-closed full-verification receipt from one exact terminal systemd invocation.
//!
//! The tool never mutates the archive, creates a sidecar, launches replay, or accesses R2. It
//! binds an immutable verifier and unit file to the exact invocation journal, preserves that
//! journal output as a root-only durable log, and emits the recovery schema consumed by
//! `jetstreamer-segment-recover`.

use {
    serde::{Deserialize, Serialize},
    sha2::{Digest as _, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        ffi::OsStr,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
        process::Command,
    },
};

#[path = "horizon_full_verification_transient.rs"]
mod transient;

const PLAN_SCHEMA: &str = "jetstreamer-horizon-full-verification-evidence-plan-v1";
const RECEIPT_SCHEMA: &str = "horizon-private-full-verification-v1";
const SEAL_RECEIPT_SCHEMA: &str = "jetstreamer-sealed-deployment-receipt-v1";
const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_UNIT_BYTES: u64 = 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug)]
struct Arguments {
    plan: PathBuf,
    plan_sha256: String,
    self_sha256: String,
    check_only: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    archive: ArchivePlan,
    verifier: Evidence,
    unit: UnitPlan,
    deployment_seal_receipt: Evidence,
    output_log: PathBuf,
    output_receipt: PathBuf,
    authority: Authority,
    #[serde(default)]
    transient: Option<transient::Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchivePlan {
    path: PathBuf,
    bytes: u64,
    uid: u32,
    gid: u32,
    mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitPlan {
    name: String,
    invocation_id: String,
    installed_file: Evidence,
    #[serde(default)]
    runtime_unit_link: Option<PathBuf>,
    threads: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    archive_mutations: bool,
    sidecar_created: bool,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Debug, Deserialize)]
struct SealReceipt {
    schema: String,
    destination: PathBuf,
    members: Vec<SealMember>,
    publication_authorized: bool,
    replay_launch_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Debug, Deserialize)]
struct SealMember {
    name: String,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
}

#[derive(Debug, Serialize)]
struct ReceiptArchive<'a> {
    path: &'a Path,
    bytes: u64,
    uid: u32,
    gid: u32,
    mode: String,
}

#[derive(Debug, Serialize)]
struct ReceiptEvidence<'a> {
    path: &'a Path,
    sha256: &'a str,
}

#[derive(Debug, Serialize)]
struct ReceiptUnit<'a> {
    name: &'a str,
    invocation_id: &'a str,
    current_invocation_id: &'a str,
    identity_source: &'static str,
    result: &'static str,
    exec_main_status: u64,
    restarts: u64,
    journal_records: u64,
    journal_pid: u64,
    journal_first_realtime_timestamp_us: u64,
    journal_last_realtime_timestamp_us: u64,
    deactivated_realtime_timestamp_us: u64,
    finished_realtime_timestamp_us: u64,
}

#[derive(Debug)]
struct SystemdState {
    exec_status: u64,
    restarts: u64,
    current_invocation_id: String,
}

#[derive(Debug, Eq, PartialEq)]
struct InvocationJournalAudit {
    records: u64,
    pid: u64,
    first_realtime_timestamp_us: u64,
    last_realtime_timestamp_us: u64,
    deactivated_realtime_timestamp_us: u64,
    finished_realtime_timestamp_us: u64,
}

#[derive(Debug, Deserialize)]
struct JournalRecord {
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime_timestamp: Option<String>,
    #[serde(rename = "MESSAGE")]
    message: Option<String>,
    #[serde(rename = "_SYSTEMD_UNIT")]
    systemd_unit: Option<String>,
    #[serde(rename = "UNIT")]
    unit: Option<String>,
    #[serde(rename = "_SYSTEMD_INVOCATION_ID")]
    invocation_id: Option<String>,
    #[serde(rename = "_EXE")]
    executable: Option<String>,
    #[serde(rename = "_CMDLINE")]
    command_line: Option<String>,
    #[serde(rename = "_PID")]
    pid: Option<String>,
    #[serde(rename = "JOB_RESULT")]
    job_result: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReceiptCommand {
    full: bool,
    internal_full: bool,
    threads: u64,
}

#[derive(Debug, Serialize)]
struct ReceiptResult<'a> {
    line: &'a str,
}

#[derive(Debug, Serialize)]
struct Receipt<'a> {
    schema: &'static str,
    status: &'static str,
    epoch: u64,
    archive: ReceiptArchive<'a>,
    verifier: ReceiptEvidence<'a>,
    log: ReceiptEvidence<'a>,
    unit: ReceiptUnit<'a>,
    command: ReceiptCommand,
    result: ReceiptResult<'a>,
    plan: ReceiptEvidence<'a>,
    collector_sha256: &'a str,
    archive_mutations: bool,
    sidecar_created: bool,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} PLAN.json --plan-sha256 HEX --self-sha256 HEX [--check-only (transient v2/v3 only)]"
    )
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "jetstreamer-horizon-full-verification-evidence".to_string());
    let plan = arguments.next().ok_or_else(|| usage(&program))?;
    if arguments.next().as_deref() != Some(OsStr::new("--plan-sha256")) {
        return Err(usage(&program));
    }
    let plan_sha256 = arguments
        .next()
        .ok_or_else(|| usage(&program))?
        .into_string()
        .map_err(|_| "plan SHA-256 is not UTF-8".to_string())?;
    if arguments.next().as_deref() != Some(OsStr::new("--self-sha256")) {
        return Err(usage(&program));
    }
    let self_sha256 = arguments
        .next()
        .ok_or_else(|| usage(&program))?
        .into_string()
        .map_err(|_| "self SHA-256 is not UTF-8".to_string())?;
    let check_only = match arguments.next() {
        None => false,
        Some(value) if value == "--check-only" => true,
        Some(_) => return Err(usage(&program)),
    };
    if arguments.next().is_some() {
        return Err(usage(&program));
    }
    Ok(Arguments {
        plan: PathBuf::from(plan),
        plan_sha256,
        self_sha256,
        check_only,
    })
}

fn lowercase_hex(value: &str, bytes: usize, field: &str) -> Result<(), String> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{field} must contain {} lowercase hex digits",
            bytes * 2
        ));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn identity(metadata: &fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.size(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.permissions().mode() & 0o7777,
        links: metadata.nlink(),
        mtime_seconds: metadata.mtime(),
        mtime_nanoseconds: metadata.mtime_nsec(),
    }
}

fn open_regular_nofollow(path: &Path, max_bytes: u64) -> Result<(File, Identity), String> {
    if !path.is_absolute() {
        return Err(format!("path is not absolute: {}", path.display()));
    }
    let before =
        fs::symlink_metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
    if !before.is_file() || before.nlink() != 1 || before.size() > max_bytes {
        return Err(format!("unsafe regular file identity: {}", path.display()));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("canonicalize {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!(
            "path is not exact and canonical: {}",
            path.display()
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("fstat {}: {error}", path.display()))?;
    if identity(&before) != identity(&opened) {
        return Err(format!("file changed while opening: {}", path.display()));
    }
    Ok((file, identity(&opened)))
}

fn read_hashed(path: &Path, expected: &str, max_bytes: u64) -> Result<(Vec<u8>, Identity), String> {
    lowercase_hex(expected, 32, &format!("{} SHA-256", path.display()))?;
    let (mut file, before) = open_regular_nofollow(path, max_bytes)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let after = identity(
        &file
            .metadata()
            .map_err(|error| format!("fstat {}: {error}", path.display()))?,
    );
    if before != after {
        return Err(format!("file changed while reading: {}", path.display()));
    }
    let actual = hex(&Sha256::digest(&bytes));
    if actual != expected {
        return Err(format!(
            "SHA-256 mismatch for {}: expected {expected}, got {actual}",
            path.display()
        ));
    }
    Ok((bytes, after))
}

fn hash_executable(path: &Path, expected: &str) -> Result<Identity, String> {
    let (_, identity) = read_hashed(path, expected, 128 * 1024 * 1024)?;
    let metadata = fs::metadata(path)
        .map_err(|error| format!("stat executable {}: {error}", path.display()))?;
    if identity.uid != 0 || identity.mode & 0o222 != 0 || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(format!(
            "executable must be root-owned, executable, and non-writable: {}",
            path.display()
        ));
    }
    Ok(identity)
}

fn require_root_sealed_file(identity: Identity, label: &str) -> Result<(), String> {
    if identity.uid != 0
        || identity.links != 1
        || identity.mode & 0o400 == 0
        || identity.mode & 0o222 != 0
    {
        return Err(format!(
            "{label} must be root-owned, singly linked, owner-readable, and non-writable"
        ));
    }
    Ok(())
}

fn validate_output_path(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() || path.exists() {
        return Err(format!(
            "{label} must be an absent absolute path: {}",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} has no parent"))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("stat {label} parent {}: {error}", parent.display()))?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{label} parent must be a root-owned owner-only directory"
        ));
    }
    Ok(())
}

fn parse_systemctl_show(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "systemctl output is not UTF-8".to_string())?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| format!("malformed systemctl property: {line}"))?;
        if fields.insert(name.to_string(), value.to_string()).is_some() {
            return Err(format!("duplicate systemctl property: {name}"));
        }
    }
    Ok(fields)
}

fn field<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    fields
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("systemctl output is missing {name}"))
}

fn parse_u64_field(fields: &BTreeMap<String, String>, name: &str) -> Result<u64, String> {
    field(fields, name)?
        .parse()
        .map_err(|_| format!("systemctl {name} is not a u64"))
}

fn unit_fragment_path(plan: &Plan) -> Result<&Path, String> {
    let Some(link) = plan.unit.runtime_unit_link.as_deref() else {
        return Ok(&plan.unit.installed_file.path);
    };
    if link.parent() != Some(Path::new("/run/systemd/system"))
        || link.file_name() != Some(OsStr::new(&plan.unit.name))
        || plan.unit.installed_file.path.file_name() != link.file_name()
        || plan.unit.installed_file.path.parent() != plan.verifier.path.parent()
    {
        return Err("runtime unit link escapes the exact sealed unit namespace".into());
    }
    let parent = fs::symlink_metadata(link.parent().unwrap())
        .map_err(|error| format!("stat runtime unit parent: {error}"))?;
    let metadata =
        fs::symlink_metadata(link).map_err(|error| format!("stat runtime unit link: {error}"))?;
    if !parent.is_dir()
        || parent.uid() != 0
        || parent.mode() & 0o022 != 0
        || !metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || fs::read_link(link).map_err(|error| format!("read runtime unit link: {error}"))?
            != plan.unit.installed_file.path
        || plan
            .unit
            .installed_file
            .path
            .canonicalize()
            .map_err(|error| format!("canonical sealed unit: {error}"))?
            != plan.unit.installed_file.path
    {
        return Err("runtime unit link is not root-owned and bound to the sealed member".into());
    }
    Ok(link)
}

fn systemd_state(plan: &Plan) -> Result<SystemdState, String> {
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            plan.unit.name.as_str(),
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=ExecMainStatus",
            "--property=NRestarts",
            "--property=InvocationID",
            "--property=FragmentPath",
            "--no-pager",
        ])
        .output()
        .map_err(|error| format!("execute systemctl: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "systemctl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let fields = parse_systemctl_show(&output.stdout)?;
    let expected_fragment = unit_fragment_path(plan)?.to_string_lossy();
    let current_invocation_id = field(&fields, "InvocationID")?;
    if field(&fields, "LoadState")? != "loaded"
        || field(&fields, "ActiveState")? != "inactive"
        || field(&fields, "SubState")? != "dead"
        || field(&fields, "Result")? != "success"
        || (!current_invocation_id.is_empty() && current_invocation_id != plan.unit.invocation_id)
        || field(&fields, "FragmentPath")? != expected_fragment
    {
        return Err("systemd unit is not the exact clean terminal invocation".to_string());
    }
    let status = parse_u64_field(&fields, "ExecMainStatus")?;
    let restarts = parse_u64_field(&fields, "NRestarts")?;
    if status != 0 || restarts != 0 {
        return Err("systemd unit did not terminate successfully without restarts".to_string());
    }
    Ok(SystemdState {
        exec_status: status,
        restarts,
        current_invocation_id: current_invocation_id.to_string(),
    })
}

fn exact_command_line(plan: &Plan) -> String {
    format!(
        "{} {} --full --internal-full --threads {}",
        plan.verifier.path.display(),
        plan.archive.path.display(),
        plan.unit.threads
    )
}

fn exact_exec_start_line(plan: &Plan) -> String {
    format!("ExecStart={}", exact_command_line(plan))
}

fn validate_unit_file(plan: &Plan, bytes: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "unit file is not UTF-8".to_string())?;
    let expected = exact_exec_start_line(plan);
    let matching: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("ExecStart="))
        .collect();
    if matching.as_slice() != [expected.as_str()] || !text.lines().any(|line| line == "Restart=no")
    {
        return Err(
            "unit file does not contain the exact non-restarting verifier command".to_string(),
        );
    }
    Ok(())
}

fn required_journal_u64(value: Option<&str>, field_name: &str) -> Result<u64, String> {
    value
        .ok_or_else(|| format!("journal record is missing {field_name}"))?
        .parse()
        .map_err(|_| format!("journal {field_name} is not a u64"))
}

fn validate_invocation_journal_metadata(
    plan: &Plan,
    bytes: &[u8],
) -> Result<InvocationJournalAudit, String> {
    let expected_command = exact_command_line(plan);
    let deactivated_message = format!("{}: Deactivated successfully.", plan.unit.name);
    let finished_prefix = format!("Finished {} - ", plan.unit.name);
    let mut records = 0_u64;
    let mut pids = BTreeSet::new();
    let mut first_timestamp = u64::MAX;
    let mut last_timestamp = 0_u64;
    let mut deactivated_timestamps = Vec::new();
    let mut finished_timestamps = Vec::new();

    for (index, line) in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let record: JournalRecord = serde_json::from_slice(line)
            .map_err(|error| format!("invalid unit journal JSON record {index}: {error}"))?;
        if record.systemd_unit.as_deref() == Some(plan.unit.name.as_str()) {
            if record.invocation_id.as_deref() != Some(plan.unit.invocation_id.as_str()) {
                return Err(
                    "unit journal contains a different or unbound service invocation".to_string(),
                );
            }
            if record.executable.as_deref() != Some(plan.verifier.path.to_string_lossy().as_ref())
                || record.command_line.as_deref() != Some(expected_command.as_str())
            {
                return Err(
                    "exact invocation journal executable or command line is not sealed".to_string(),
                );
            }
            let timestamp =
                required_journal_u64(record.realtime_timestamp.as_deref(), "__REALTIME_TIMESTAMP")?;
            let pid = required_journal_u64(record.pid.as_deref(), "_PID")?;
            records = records
                .checked_add(1)
                .ok_or_else(|| "unit journal record count overflowed".to_string())?;
            pids.insert(pid);
            first_timestamp = first_timestamp.min(timestamp);
            last_timestamp = last_timestamp.max(timestamp);
        }

        if record.unit.as_deref() == Some(plan.unit.name.as_str())
            && record.pid.as_deref() == Some("1")
            && record.executable.as_deref() == Some("/usr/lib/systemd/systemd")
        {
            let timestamp =
                required_journal_u64(record.realtime_timestamp.as_deref(), "__REALTIME_TIMESTAMP")?;
            if record.message.as_deref() == Some(deactivated_message.as_str()) {
                deactivated_timestamps.push(timestamp);
            }
            if record
                .message
                .as_deref()
                .is_some_and(|message| message.starts_with(&finished_prefix))
                && record.job_result.as_deref() == Some("done")
            {
                finished_timestamps.push(timestamp);
            }
        }
    }

    if records == 0 || pids.len() != 1 {
        return Err(
            "unit journal does not bind exactly one nonempty verifier process identity".to_string(),
        );
    }
    if deactivated_timestamps.len() != 1 || finished_timestamps.len() != 1 {
        return Err(
            "unit journal lacks exactly one clean deactivation and successful finish event"
                .to_string(),
        );
    }
    let deactivated_timestamp = deactivated_timestamps[0];
    let finished_timestamp = finished_timestamps[0];
    if last_timestamp > deactivated_timestamp || deactivated_timestamp > finished_timestamp {
        return Err("unit journal terminal events are out of order".to_string());
    }

    Ok(InvocationJournalAudit {
        records,
        pid: *pids.iter().next().expect("validated singleton PID"),
        first_realtime_timestamp_us: first_timestamp,
        last_realtime_timestamp_us: last_timestamp,
        deactivated_realtime_timestamp_us: deactivated_timestamp,
        finished_realtime_timestamp_us: finished_timestamp,
    })
}

fn collect_invocation_journal_metadata(plan: &Plan) -> Result<InvocationJournalAudit, String> {
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "--all",
            "--unit",
            plan.unit.name.as_str(),
        ])
        .output()
        .map_err(|error| format!("execute journalctl unit metadata query: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "journalctl unit metadata query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if output.stdout.is_empty() || output.stdout.len() > MAX_JOURNAL_BYTES {
        return Err("unit journal metadata is empty or exceeds the sealed bound".to_string());
    }
    validate_invocation_journal_metadata(plan, &output.stdout)
}

fn collect_journal(invocation_id: &str) -> Result<Vec<u8>, String> {
    let selector = format!("_SYSTEMD_INVOCATION_ID={invocation_id}");
    let output = Command::new("/usr/bin/journalctl")
        .args(["--no-pager", "--output=cat", selector.as_str()])
        .output()
        .map_err(|error| format!("execute journalctl: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "journalctl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if output.stdout.is_empty() || output.stdout.len() > MAX_JOURNAL_BYTES {
        return Err("exact invocation journal is empty or exceeds the sealed bound".to_string());
    }
    Ok(output.stdout)
}

fn result_line(journal: &[u8]) -> Result<&str, String> {
    let text =
        std::str::from_utf8(journal).map_err(|_| "journal output is not UTF-8".to_string())?;
    let lines: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("RESULT:"))
        .collect();
    if lines.len() != 1 || !lines[0].starts_with("RESULT: OK (internal only):") {
        return Err(
            "journal does not contain exactly one successful internal result line".to_string(),
        );
    }
    if !text.contains("=== verify summary (") || !text.contains("=== full PoH verification ===") {
        return Err("journal lacks the complete verification summaries".to_string());
    }
    Ok(lines[0])
}

fn fsync_parent(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync directory {}: {error}", path.display()))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("fsync {}: {error}", path.display()))?;
    fsync_parent(path.parent().expect("validated output parent"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("fstat {}: {error}", path.display()))?;
    if metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(format!(
            "unsafe published output identity: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_seal_receipt(plan: &Plan, bytes: &[u8]) -> Result<(), String> {
    let receipt: SealReceipt = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid deployment seal receipt: {error}"))?;
    if receipt.schema != SEAL_RECEIPT_SCHEMA
        || receipt.publication_authorized
        || receipt.replay_launch_authorized
        || receipt.remote_mutations
        || receipt.r2_mutations
    {
        return Err("deployment seal receipt grants forbidden authority".to_string());
    }
    if plan.verifier.path.parent() != Some(receipt.destination.as_path()) {
        return Err("verifier is outside the sealed deployment destination".to_string());
    }
    let verifier_name = plan
        .verifier
        .path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "verifier filename is not UTF-8".to_string())?;
    let installed_name = plan
        .unit
        .installed_file
        .path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "unit filename is not UTF-8".to_string())?;
    let verifier_matches = receipt
        .members
        .iter()
        .filter(|member| member.name == verifier_name && member.sha256 == plan.verifier.sha256)
        .count();
    let unit_matches = receipt
        .members
        .iter()
        .filter(|member| {
            member.name == installed_name && member.sha256 == plan.unit.installed_file.sha256
        })
        .count();
    if verifier_matches != 1 || unit_matches != 1 {
        return Err(
            "deployment seal receipt does not bind the verifier and unit exactly once".to_string(),
        );
    }
    Ok(())
}

fn run() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("collector must run as root".to_string());
    }
    let arguments = parse_arguments()?;
    lowercase_hex(&arguments.plan_sha256, 32, "plan SHA-256")?;
    lowercase_hex(&arguments.self_sha256, 32, "self SHA-256")?;

    let (plan_bytes, plan_identity) =
        read_hashed(&arguments.plan, &arguments.plan_sha256, MAX_JSON_BYTES)?;
    require_root_sealed_file(plan_identity, "plan")?;
    let plan: Plan = serde_json::from_slice(&plan_bytes)
        .map_err(|error| format!("invalid plan JSON: {error}"))?;
    if plan.schema == transient::PLAN_SCHEMA || plan.schema == transient::CHAIN_PLAN_SCHEMA {
        return transient::run(&arguments, &plan);
    }
    if plan.schema != PLAN_SCHEMA
        || plan.transient.is_some()
        || arguments.check_only
        || plan.epoch == 0
        || plan.unit.threads == 0
        || plan.unit.threads > 64
        || plan.authority.archive_mutations
        || plan.authority.sidecar_created
        || plan.authority.replay_launch_authorized
        || plan.authority.publication_authorized
        || plan.authority.remote_mutations
        || plan.authority.r2_mutations
    {
        return Err("plan schema, bounds, or fail-closed authority is invalid".to_string());
    }
    if plan.unit.name.contains('/') || !plan.unit.name.ends_with(".service") {
        return Err("unit name must be a simple .service name".to_string());
    }
    lowercase_hex(&plan.unit.invocation_id, 16, "unit invocation ID")?;
    validate_output_path(&plan.output_log, "output log")?;
    validate_output_path(&plan.output_receipt, "output receipt")?;
    if plan.output_log.parent() != plan.output_receipt.parent() {
        return Err("output log and receipt must share one sealed parent".to_string());
    }

    let current_exe =
        env::current_exe().map_err(|error| format!("resolve current executable: {error}"))?;
    hash_executable(&current_exe, &arguments.self_sha256)?;
    hash_executable(&plan.verifier.path, &plan.verifier.sha256)?;
    let (unit_bytes, unit_identity) = read_hashed(
        &plan.unit.installed_file.path,
        &plan.unit.installed_file.sha256,
        MAX_UNIT_BYTES,
    )?;
    require_root_sealed_file(unit_identity, "installed unit")?;
    validate_unit_file(&plan, &unit_bytes)?;
    let (seal_bytes, seal_identity) = read_hashed(
        &plan.deployment_seal_receipt.path,
        &plan.deployment_seal_receipt.sha256,
        MAX_JSON_BYTES,
    )?;
    require_root_sealed_file(seal_identity, "deployment seal receipt")?;
    validate_seal_receipt(&plan, &seal_bytes)?;

    let archive_metadata = fs::symlink_metadata(&plan.archive.path)
        .map_err(|error| format!("stat archive {}: {error}", plan.archive.path.display()))?;
    let archive_before = identity(&archive_metadata);
    let planned_mode = u32::from_str_radix(&plan.archive.mode, 8)
        .map_err(|_| "archive mode must be canonical octal".to_string())?;
    if !archive_metadata.is_file()
        || archive_before.links != 1
        || archive_before.bytes != plan.archive.bytes
        || archive_before.uid != plan.archive.uid
        || archive_before.gid != plan.archive.gid
        || archive_before.mode != planned_mode
        || plan.archive.mode != format!("{:04o}", planned_mode)
    {
        return Err("archive identity does not match the sealed plan".to_string());
    }
    let canonical_archive = plan
        .archive
        .path
        .canonicalize()
        .map_err(|error| format!("canonicalize archive: {error}"))?;
    if canonical_archive != plan.archive.path {
        return Err("archive path is not exact and canonical".to_string());
    }
    let sidecar = PathBuf::from(format!("{}.sha256", plan.archive.path.display()));
    if sidecar.exists() {
        return Err("canonical checksum sidecar must remain absent".to_string());
    }

    let systemd = systemd_state(&plan)?;
    let journal_audit = collect_invocation_journal_metadata(&plan)?;
    let identity_source = if systemd.current_invocation_id == plan.unit.invocation_id {
        "systemd-current-and-terminal-journal"
    } else {
        "systemd-cleared-after-terminal-journal"
    };
    let journal = collect_journal(&plan.unit.invocation_id)?;
    let result = result_line(&journal)?.to_string();
    write_new(&plan.output_log, &journal)?;
    let log_sha256 = hex(&Sha256::digest(&journal));

    let archive_after = identity(
        &fs::symlink_metadata(&plan.archive.path)
            .map_err(|error| format!("restat archive: {error}"))?,
    );
    unit_fragment_path(&plan)?;
    if archive_before != archive_after || sidecar.exists() {
        return Err("archive changed or a sidecar appeared during evidence collection".to_string());
    }

    let receipt = Receipt {
        schema: RECEIPT_SCHEMA,
        status: "passed",
        epoch: plan.epoch,
        archive: ReceiptArchive {
            path: &plan.archive.path,
            bytes: archive_before.bytes,
            uid: archive_before.uid,
            gid: archive_before.gid,
            mode: format!("{:04o}", archive_before.mode),
        },
        verifier: ReceiptEvidence {
            path: &plan.verifier.path,
            sha256: &plan.verifier.sha256,
        },
        log: ReceiptEvidence {
            path: &plan.output_log,
            sha256: &log_sha256,
        },
        unit: ReceiptUnit {
            name: &plan.unit.name,
            invocation_id: &plan.unit.invocation_id,
            current_invocation_id: &systemd.current_invocation_id,
            identity_source,
            result: "success",
            exec_main_status: systemd.exec_status,
            restarts: systemd.restarts,
            journal_records: journal_audit.records,
            journal_pid: journal_audit.pid,
            journal_first_realtime_timestamp_us: journal_audit.first_realtime_timestamp_us,
            journal_last_realtime_timestamp_us: journal_audit.last_realtime_timestamp_us,
            deactivated_realtime_timestamp_us: journal_audit.deactivated_realtime_timestamp_us,
            finished_realtime_timestamp_us: journal_audit.finished_realtime_timestamp_us,
        },
        command: ReceiptCommand {
            full: true,
            internal_full: true,
            threads: plan.unit.threads,
        },
        result: ReceiptResult { line: &result },
        plan: ReceiptEvidence {
            path: &arguments.plan,
            sha256: &arguments.plan_sha256,
        },
        collector_sha256: &arguments.self_sha256,
        archive_mutations: false,
        sidecar_created: false,
        replay_launch_authorized: false,
        publication_authorized: false,
        remote_mutations: false,
        r2_mutations: false,
    };
    let mut receipt_bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| format!("serialize receipt: {error}"))?;
    receipt_bytes.push(b'\n');
    write_new(&plan.output_receipt, &receipt_bytes)?;

    let final_archive = identity(
        &fs::symlink_metadata(&plan.archive.path)
            .map_err(|error| format!("final archive stat: {error}"))?,
    );
    if final_archive != archive_before || sidecar.exists() {
        return Err("archive changed after durable receipt publication".to_string());
    }
    println!(
        "{}",
        serde_json::json!({
            "outcome": "full-verification-evidence-created",
            "epoch": plan.epoch,
            "invocation_id": plan.unit.invocation_id,
            "log": plan.output_log,
            "log_sha256": log_sha256,
            "receipt": plan.output_receipt,
            "receipt_sha256": hex(&Sha256::digest(&receipt_bytes)),
            "archive_mutations": false,
            "sidecar_created": false,
            "r2_mutations": false
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_fragment_has_no_implicit_runtime_link_or_namespace_escape() {
        let mut plan = test_plan();
        assert_eq!(
            unit_fragment_path(&plan).unwrap(),
            plan.unit.installed_file.path
        );
        plan.unit.runtime_unit_link = Some("/tmp/example.service".into());
        assert!(unit_fragment_path(&plan).is_err());
        plan.unit.runtime_unit_link = Some("/run/systemd/system/other.service".into());
        assert!(unit_fragment_path(&plan).is_err());
    }

    #[test]
    #[ignore = "root-only read-only check of exact sealed retained-prefix runtime links"]
    fn root_sealed_retained_prefix_runtime_links_bind_only_their_exact_members() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        for epoch in [220, 221, 222] {
            let mut plan = test_plan();
            plan.unit.name =
                format!("horizon-independent-full-read-{epoch}-retained-prefix-v1.service");
            plan.verifier.path =
                "/var/lib/jetstreamer/horizon-retained220-222-full-prepared-v1/verify_archive"
                    .into();
            plan.unit.installed_file.path =
                plan.verifier.path.parent().unwrap().join(&plan.unit.name);
            plan.unit.runtime_unit_link =
                Some(Path::new("/run/systemd/system").join(&plan.unit.name));
            assert_eq!(
                unit_fragment_path(&plan).unwrap(),
                plan.unit.runtime_unit_link.as_deref().unwrap()
            );
            plan.unit.installed_file.path = plan.verifier.path.clone();
            assert!(unit_fragment_path(&plan).is_err());
        }
    }

    fn test_plan() -> Plan {
        Plan {
            schema: PLAN_SCHEMA.to_string(),
            epoch: 140,
            archive: ArchivePlan {
                path: PathBuf::from("/private/epoch-140.jet"),
                bytes: 1,
                uid: 1,
                gid: 1,
                mode: "0440".to_string(),
            },
            verifier: Evidence {
                path: PathBuf::from("/opt/verify_archive"),
                sha256: "00".repeat(32),
            },
            unit: UnitPlan {
                name: "example.service".to_string(),
                invocation_id: "0123456789abcdef0123456789abcdef".to_string(),
                installed_file: Evidence {
                    path: PathBuf::from("/etc/systemd/system/example.service"),
                    sha256: "11".repeat(32),
                },
                runtime_unit_link: None,
                threads: 8,
            },
            deployment_seal_receipt: Evidence {
                path: PathBuf::from("/opt/deployment-seal-receipt.json"),
                sha256: "22".repeat(32),
            },
            output_log: PathBuf::from("/private/full-verification.log"),
            output_receipt: PathBuf::from("/private/full-verification.json"),
            authority: Authority {
                archive_mutations: false,
                sidecar_created: false,
                replay_launch_authorized: false,
                publication_authorized: false,
                remote_mutations: false,
                r2_mutations: false,
            },
            transient: None,
        }
    }

    fn terminal_unit_journal(invocation_id: &str) -> Vec<u8> {
        format!(
            concat!(
                "{{\"__REALTIME_TIMESTAMP\":\"100\",\"MESSAGE\":\"start\",",
                "\"_SYSTEMD_UNIT\":\"example.service\",",
                "\"_SYSTEMD_INVOCATION_ID\":\"{}\",",
                "\"_EXE\":\"/opt/verify_archive\",",
                "\"_CMDLINE\":\"/opt/verify_archive /private/epoch-140.jet --full --internal-full --threads 8\",",
                "\"_PID\":\"42\"}}\n",
                "{{\"__REALTIME_TIMESTAMP\":\"200\",\"MESSAGE\":\"RESULT: OK (internal only): verified\",",
                "\"_SYSTEMD_UNIT\":\"example.service\",",
                "\"_SYSTEMD_INVOCATION_ID\":\"{}\",",
                "\"_EXE\":\"/opt/verify_archive\",",
                "\"_CMDLINE\":\"/opt/verify_archive /private/epoch-140.jet --full --internal-full --threads 8\",",
                "\"_PID\":\"42\"}}\n",
                "{{\"__REALTIME_TIMESTAMP\":\"201\",",
                "\"MESSAGE\":\"example.service: Deactivated successfully.\",",
                "\"UNIT\":\"example.service\",\"_EXE\":\"/usr/lib/systemd/systemd\",\"_PID\":\"1\"}}\n",
                "{{\"__REALTIME_TIMESTAMP\":\"202\",",
                "\"MESSAGE\":\"Finished example.service - example.\",",
                "\"UNIT\":\"example.service\",\"_EXE\":\"/usr/lib/systemd/systemd\",",
                "\"_PID\":\"1\",\"JOB_RESULT\":\"done\"}}\n"
            ),
            invocation_id, invocation_id
        )
        .into_bytes()
    }

    #[test]
    fn parses_terminal_systemctl_properties() {
        let fields = parse_systemctl_show(
            b"LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainStatus=0\nNRestarts=0\nInvocationID=0123456789abcdef0123456789abcdef\nFragmentPath=/etc/systemd/system/example.service\n",
        )
        .unwrap();
        assert_eq!(field(&fields, "ActiveState").unwrap(), "inactive");
        assert_eq!(parse_u64_field(&fields, "ExecMainStatus").unwrap(), 0);
    }

    #[test]
    fn extracts_exact_internal_success_line() {
        let journal = b"=== verify summary (1.0s, 8 threads) ===\n=== full PoH verification ===\nRESULT: OK (internal only): all stored links verify; the first block is unanchored.\n";
        assert_eq!(
            result_line(journal).unwrap(),
            "RESULT: OK (internal only): all stored links verify; the first block is unanchored."
        );
    }

    #[test]
    fn rejects_ambiguous_result_lines() {
        let journal = b"=== verify summary (1.0s, 8 threads) ===\n=== full PoH verification ===\nRESULT: OK (internal only): one\nRESULT: OK (internal only): two\n";
        assert!(result_line(journal).is_err());
    }

    #[test]
    fn binds_cleared_terminal_invocation_to_exact_journal_and_manager_success() {
        let audit = validate_invocation_journal_metadata(
            &test_plan(),
            &terminal_unit_journal("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        assert_eq!(
            audit,
            InvocationJournalAudit {
                records: 2,
                pid: 42,
                first_realtime_timestamp_us: 100,
                last_realtime_timestamp_us: 200,
                deactivated_realtime_timestamp_us: 201,
                finished_realtime_timestamp_us: 202,
            }
        );
    }

    #[test]
    fn rejects_unit_journal_from_a_different_invocation() {
        let error = validate_invocation_journal_metadata(
            &test_plan(),
            &terminal_unit_journal("ffffffffffffffffffffffffffffffff"),
        )
        .unwrap_err();
        assert!(error.contains("different or unbound service invocation"));
    }

    #[test]
    fn rejects_terminal_journal_without_successful_manager_finish() {
        let bytes = terminal_unit_journal("0123456789abcdef0123456789abcdef");
        let text = String::from_utf8(bytes).unwrap();
        let truncated = text
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        let error = validate_invocation_journal_metadata(&test_plan(), &truncated).unwrap_err();
        assert!(error.contains("successful finish event"));
    }
}
