//! Plan-bound retirement of one terminal Horizon replay scratch tree.
//!
//! This tool is intentionally narrow: it preserves the independently validated
//! private archive and segment manifest, mutates no remote storage, and removes
//! only the exact scratch directory named by a root-owned immutable plan.

use {
    anyhow::{Context, Result, anyhow, ensure},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    sha2::{Digest as _, Sha256},
    std::{
        collections::BTreeMap,
        env,
        ffi::OsStr,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            ffi::OsStrExt as _,
            fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        },
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    },
};

const PLAN_SCHEMA: &str = "jetstreamer-horizon-scratch-retirement-plan-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-horizon-scratch-retirement-receipt-v1";
const VALIDATION_SCHEMA: &str = "jetstreamer-focused-qualification-artifact-validation-v1";
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;
const PRIVATE_ROOT: &str = "/home/ubuntu/.jetstreamer-private";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    private_root: PathBuf,
    scratch: PathBuf,
    producer: UnitBinding,
    validator: UnitBinding,
    validation_receipt: Evidence,
    expected_epoch: u64,
    expected_archive: PathBuf,
    intent_receipt: PathBuf,
    completion_receipt: PathBuf,
    authority: Authority,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitBinding {
    unit: String,
    invocation_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    local_scratch_retirement_authorized: bool,
    archive_deletion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
struct UnitState {
    unit: String,
    invocation_id: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    result: String,
    main_pid: u64,
    restarts: u64,
    exec_main_code: i64,
    exec_main_status: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
struct FileIdentity {
    path: PathBuf,
    bytes: u64,
    uid: u32,
    gid: u32,
    mode: String,
    device: u64,
    inode: u64,
    links: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct Receipt {
    schema: String,
    status: String,
    recorded_unix_millis: u128,
    plan_path: PathBuf,
    plan_sha256: String,
    tool_sha256: String,
    scratch: FileIdentity,
    producer: UnitState,
    validator: UnitState,
    validation_receipt: PathBuf,
    validation_receipt_sha256: String,
    epoch: u64,
    archive: PathBuf,
    archive_sha256: String,
    manifest: PathBuf,
    available_bytes_before: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    available_bytes_after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    intent_receipt: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    intent_receipt_sha256: Option<String>,
    archive_deletion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: jetstreamer-horizon-retire-scratch --plan PATH --plan-sha256 HEX --self-sha256 HEX"
    );
    std::process::exit(2);
}

fn parse_args() -> (PathBuf, String, String) {
    let mut args = env::args_os().skip(1);
    let mut plan = None;
    let mut plan_sha256 = None;
    let mut self_sha256 = None;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--plan") => plan = args.next().map(PathBuf::from),
            Some("--plan-sha256") => {
                plan_sha256 = args.next().and_then(|value| value.into_string().ok())
            }
            Some("--self-sha256") => {
                self_sha256 = args.next().and_then(|value| value.into_string().ok())
            }
            _ => usage(),
        }
    }
    (
        plan.unwrap_or_else(|| usage()),
        plan_sha256.unwrap_or_else(|| usage()),
        self_sha256.unwrap_or_else(|| usage()),
    )
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_reader(mut reader: impl Read) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn read_secure(path: &Path, maximum: u64, required_uid: u32, owner_only: bool) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute(),
        "path is not absolute: {}",
        path.display()
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "not a regular file: {}", path.display());
    ensure!(
        before.nlink() == 1,
        "file has multiple links: {}",
        path.display()
    );
    ensure!(
        before.uid() == required_uid,
        "unexpected owner: {}",
        path.display()
    );
    let mode = before.permissions().mode() & 0o777;
    ensure!(
        mode & 0o022 == 0,
        "file is group/world writable: {}",
        path.display()
    );
    if owner_only {
        ensure!(
            mode & 0o077 == 0,
            "file is not owner-only: {}",
            path.display()
        );
    }
    ensure!(
        before.len() <= maximum,
        "file exceeds size bound: {}",
        path.display()
    );
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "file exceeds size bound");
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
    Ok(bytes)
}

fn file_sha256(path: &Path) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    sha256_reader(file)
}

fn stable_file_sha256(path: &Path) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.nlink() == 1,
        "hash input identity is unsafe"
    );
    let digest = sha256_reader(&file)?;
    let after = file.metadata()?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "hash input changed during revalidation"
    );
    Ok(digest)
}

fn verify_self(expected: &str) -> Result<()> {
    ensure!(valid_sha256(expected), "invalid self SHA-256");
    let executable = File::open("/proc/self/exe")?;
    ensure!(
        sha256_reader(executable)? == expected,
        "running executable SHA-256 mismatch"
    );
    Ok(())
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(plan.schema == PLAN_SCHEMA, "plan schema mismatch");
    ensure!(
        plan.private_root.is_absolute(),
        "private root is not absolute"
    );
    ensure!(
        plan.private_root == Path::new(PRIVATE_ROOT),
        "plan names an unexpected private root"
    );
    ensure!(plan.scratch.is_absolute(), "scratch path is not absolute");
    ensure!(
        plan.scratch.file_name() == Some(OsStr::new("scratch")),
        "scratch basename must be exact"
    );
    ensure!(
        plan.expected_archive.is_absolute(),
        "archive path is not absolute"
    );
    ensure!(
        plan.validation_receipt.path.is_absolute(),
        "validation receipt is not absolute"
    );
    ensure!(
        valid_sha256(&plan.validation_receipt.sha256),
        "invalid validation receipt SHA-256"
    );
    ensure!(
        plan.intent_receipt.is_absolute() && plan.completion_receipt.is_absolute(),
        "receipt paths must be absolute"
    );
    ensure!(
        plan.intent_receipt != plan.completion_receipt,
        "intent and completion paths must differ"
    );
    ensure!(
        plan.producer.unit != plan.validator.unit,
        "producer and validator units must differ"
    );
    for preserved in [
        &plan.expected_archive,
        &plan.validation_receipt.path,
        &plan.intent_receipt,
        &plan.completion_receipt,
    ] {
        ensure!(
            preserved.starts_with(&plan.private_root),
            "preserved evidence is outside the private root: {}",
            preserved.display()
        );
        ensure!(
            !path_or_descendant(preserved, &plan.scratch),
            "preserved evidence may not be beneath scratch: {}",
            preserved.display()
        );
    }
    ensure!(
        plan.authority.local_scratch_retirement_authorized,
        "plan does not authorize scratch retirement"
    );
    ensure!(
        !plan.authority.archive_deletion_authorized,
        "plan authorizes archive deletion"
    );
    ensure!(
        !plan.authority.remote_mutations && !plan.authority.r2_mutations,
        "plan authorizes remote mutation"
    );
    for unit in [&plan.producer, &plan.validator] {
        ensure!(
            valid_unit_name(&unit.unit),
            "invalid systemd unit: {}",
            unit.unit
        );
        ensure!(
            unit.invocation_id.len() == 32
                && unit.invocation_id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid invocation ID"
        );
    }
    Ok(())
}

fn valid_unit_name(unit: &str) -> bool {
    unit.ends_with(".service")
        && !unit.is_empty()
        && unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'@' | b'-'))
}

fn parse_systemctl(stdout: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(stdout)?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("malformed systemctl output"))?;
        ensure!(
            fields.insert(key.to_string(), value.to_string()).is_none(),
            "duplicate systemctl field"
        );
    }
    Ok(fields)
}

fn number(fields: &BTreeMap<String, String>, key: &str) -> Result<u64> {
    fields
        .get(key)
        .ok_or_else(|| anyhow!("systemctl omitted {key}"))?
        .parse()
        .with_context(|| format!("invalid systemctl field {key}"))
}

fn signed_number(fields: &BTreeMap<String, String>, key: &str) -> Result<i64> {
    fields
        .get(key)
        .ok_or_else(|| anyhow!("systemctl omitted {key}"))?
        .parse()
        .with_context(|| format!("invalid systemctl field {key}"))
}

fn sample_unit(binding: &UnitBinding) -> Result<UnitState> {
    let output = Command::new("systemctl")
        .args([
            "show",
            binding.unit.as_str(),
            "--property=LoadState,ActiveState,SubState,Result,MainPID,InvocationID,NRestarts,ExecMainCode,ExecMainStatus",
        ])
        .output()?;
    ensure!(
        output.status.success(),
        "systemctl failed for {}",
        binding.unit
    );
    let fields = parse_systemctl(&output.stdout)?;
    let state = UnitState {
        unit: binding.unit.clone(),
        invocation_id: fields.get("InvocationID").cloned().unwrap_or_default(),
        load_state: fields.get("LoadState").cloned().unwrap_or_default(),
        active_state: fields.get("ActiveState").cloned().unwrap_or_default(),
        sub_state: fields.get("SubState").cloned().unwrap_or_default(),
        result: fields.get("Result").cloned().unwrap_or_default(),
        main_pid: number(&fields, "MainPID")?,
        restarts: number(&fields, "NRestarts")?,
        exec_main_code: signed_number(&fields, "ExecMainCode")?,
        exec_main_status: signed_number(&fields, "ExecMainStatus")?,
    };
    ensure!(
        state.invocation_id == binding.invocation_id,
        "{} invocation changed",
        binding.unit
    );
    ensure!(
        state.load_state == "loaded",
        "{} is not loaded",
        binding.unit
    );
    ensure!(
        state.active_state == "inactive" && state.sub_state == "dead",
        "{} is not terminal",
        binding.unit
    );
    ensure!(
        state.result == "success",
        "{} did not succeed",
        binding.unit
    );
    ensure!(
        state.main_pid == 0 && state.restarts == 0 && state.exec_main_status == 0,
        "{} terminal state is unsafe",
        binding.unit
    );
    Ok(state)
}

fn identity(path: &Path, require_directory: bool) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "symlink is forbidden: {}",
        path.display()
    );
    if require_directory {
        ensure!(metadata.is_dir(), "not a directory: {}", path.display());
    } else {
        ensure!(metadata.is_file(), "not a file: {}", path.display());
    }
    Ok(FileIdentity {
        path: path.to_path_buf(),
        bytes: metadata.len(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: format!("{:04o}", metadata.permissions().mode() & 0o7777),
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
    })
}

fn metadata_if_exists(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn require_private_receipt_path(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("receipt lacks parent"))?;
    let resolved = fs::canonicalize(parent)?;
    ensure!(resolved == parent, "receipt parent is not canonical");
    let metadata = fs::metadata(parent)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0,
        "receipt parent identity is unsafe"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "receipt parent is not owner-only"
    );
    Ok(())
}

fn is_mountpoint(path: &Path) -> Result<bool> {
    let bytes = fs::read("/proc/self/mountinfo")?;
    let needle = path.as_os_str().as_bytes();
    for line in bytes.split(|byte| *byte == b'\n') {
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        if fields.len() > 4 && fields[4] == needle {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_scratch(plan: &Plan) -> Result<FileIdentity> {
    let root = fs::canonicalize(&plan.private_root)?;
    ensure!(root == plan.private_root, "private root is not canonical");
    let parent = fs::canonicalize(
        plan.scratch
            .parent()
            .ok_or_else(|| anyhow!("scratch lacks parent"))?,
    )?;
    ensure!(
        parent.starts_with(&root) && parent != root,
        "scratch is outside a qualification subtree"
    );
    let resolved = fs::canonicalize(&plan.scratch)?;
    ensure!(resolved == plan.scratch, "scratch path is not canonical");
    ensure!(!is_mountpoint(&resolved)?, "scratch is a mount point");
    identity(&resolved, true)
}

fn value_u64(value: &Value, pointer: &str) -> Result<u64> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("invalid {pointer}"))
}

fn value_str<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("invalid {pointer}"))
}

fn validate_artifact_identity(value: &Value, prefix: &str, path: &Path) -> Result<FileIdentity> {
    ensure!(
        fs::canonicalize(path)? == path,
        "artifact path is not canonical: {}",
        path.display()
    );
    let observed = identity(path, false)?;
    ensure!(
        observed.links == 1,
        "artifact has multiple links: {}",
        path.display()
    );
    ensure!(
        observed.bytes == value_u64(value, &format!("/{prefix}_bytes"))?,
        "artifact size changed"
    );
    ensure!(
        observed.uid as u64 == value_u64(value, &format!("/{prefix}_uid"))?,
        "artifact uid changed"
    );
    ensure!(
        observed.gid as u64 == value_u64(value, &format!("/{prefix}_gid"))?,
        "artifact gid changed"
    );
    ensure!(
        observed.mode == value_str(value, &format!("/{prefix}_mode"))?,
        "artifact mode changed"
    );
    Ok(observed)
}

fn validate_validation(plan: &Plan) -> Result<(String, PathBuf)> {
    ensure!(
        fs::canonicalize(&plan.validation_receipt.path)? == plan.validation_receipt.path,
        "validation receipt path is not canonical"
    );
    let bytes = read_secure(&plan.validation_receipt.path, MAX_JSON_BYTES, 0, true)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == plan.validation_receipt.sha256,
        "validation receipt SHA-256 mismatch"
    );
    let value: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        value_str(&value, "/schema")? == VALIDATION_SCHEMA,
        "validation schema mismatch"
    );
    ensure!(
        value_str(&value, "/validation")? == "pass",
        "validation did not pass"
    );
    ensure!(
        value_u64(&value, "/epoch")? == plan.expected_epoch,
        "validation epoch mismatch"
    );
    ensure!(
        value_str(&value, "/archive")? == plan.expected_archive.to_string_lossy(),
        "validation archive mismatch"
    );
    ensure!(
        value
            .pointer("/canonical_checksum_sidecar_absent")
            .and_then(Value::as_bool)
            == Some(true),
        "canonical sidecar was not proven absent"
    );
    let sidecar = PathBuf::from(value_str(&value, "/canonical_checksum_sidecar")?);
    let expected_sidecar = PathBuf::from(format!("{}.sha256", plan.expected_archive.display()));
    ensure!(
        sidecar == expected_sidecar,
        "validation receipt names an unexpected canonical sidecar"
    );
    ensure!(
        metadata_if_exists(&sidecar)?.is_none(),
        "unexpected canonical sidecar exists"
    );
    let archive_sha256 = value_str(&value, "/archive_sha256")?.to_string();
    ensure!(
        valid_sha256(&archive_sha256),
        "invalid validated archive SHA-256"
    );
    validate_artifact_identity(&value, "archive", &plan.expected_archive)?;
    ensure!(
        stable_file_sha256(&plan.expected_archive)? == archive_sha256,
        "validated archive SHA-256 changed before scratch retirement"
    );
    let manifest = PathBuf::from(value_str(&value, "/manifest")?);
    ensure!(
        !path_or_descendant(&manifest, &plan.scratch),
        "validated manifest may not be beneath scratch"
    );
    validate_artifact_identity(&value, "manifest", &manifest)?;
    Ok((archive_sha256, manifest))
}

fn path_or_descendant(candidate: &Path, root: &Path) -> bool {
    candidate == root || candidate.starts_with(root)
}

fn encoded_reference(content: &[u8], needle: &[u8]) -> bool {
    let boundaries = b"/\0\n\r\t '\";|&()<>[]{}";
    let mut start = 0;
    while start <= content.len() {
        let Some(relative) = content[start..]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            return false;
        };
        let index = start + relative;
        let end = index + needle.len();
        if end == content.len() || boundaries.contains(&content[end]) {
            return true;
        }
        start = index + 1;
    }
    false
}

fn read_proc_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn read_proc_link(path: &Path) -> Result<Option<PathBuf>> {
    match fs::read_link(path) {
        Ok(target) => {
            let text = target.to_string_lossy();
            Ok(Some(PathBuf::from(
                text.strip_suffix(" (deleted)").unwrap_or(&text),
            )))
        }
        Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn process_references(scratch: &Path, proc_root: &Path) -> Result<Vec<String>> {
    let needle = scratch.as_os_str().as_bytes();
    let mut references = Vec::new();
    for entry in fs::read_dir(proc_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        else {
            continue;
        };
        if pid.parse::<u32>().ok() == Some(std::process::id()) {
            continue;
        }
        let process = entry.path();
        for (file, label) in [("cmdline", "command line"), ("maps", "memory maps")] {
            if read_proc_file(&process.join(file))?
                .is_some_and(|bytes| encoded_reference(&bytes, needle))
            {
                references.push(format!("pid {pid} {label}"));
            }
        }
        for link in ["cwd", "root", "exe"] {
            if read_proc_link(&process.join(link))?
                .is_some_and(|target| path_or_descendant(&target, scratch))
            {
                references.push(format!("pid {pid} {link}"));
            }
        }
        match fs::read_dir(process.join("fd")) {
            Ok(descriptors) => {
                for descriptor in descriptors {
                    let descriptor = descriptor?;
                    if read_proc_link(&descriptor.path())?
                        .is_some_and(|target| path_or_descendant(&target, scratch))
                    {
                        references.push(format!(
                            "pid {pid} fd {}",
                            descriptor.file_name().to_string_lossy()
                        ));
                    }
                }
            }
            Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound) => {}
            Err(error) => {
                return Err(error).with_context(|| format!("cannot inspect pid {pid} descriptors"));
            }
        }
    }
    Ok(references)
}

fn available_bytes(path: &Path) -> Result<u64> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
    ensure!(result == 0, "statvfs failed for {}", path.display());
    let stats = unsafe { stats.assume_init() };
    Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
}

fn now_millis() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

fn write_noclobber(path: &Path, value: &Receipt) -> Result<()> {
    require_private_receipt_path(path)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(path.parent().expect("validated receipt parent"))?.sync_all()?;
    Ok(())
}

fn read_receipt(path: &Path) -> Result<Receipt> {
    let bytes = read_secure(path, MAX_JSON_BYTES, 0, true)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn same_common(receipt: &Receipt, expected: &Receipt) -> bool {
    receipt.schema == RECEIPT_SCHEMA
        && receipt.plan_path == expected.plan_path
        && receipt.plan_sha256 == expected.plan_sha256
        && receipt.tool_sha256 == expected.tool_sha256
        && receipt.scratch == expected.scratch
        && receipt.producer == expected.producer
        && receipt.validator == expected.validator
        && receipt.validation_receipt == expected.validation_receipt
        && receipt.validation_receipt_sha256 == expected.validation_receipt_sha256
        && receipt.epoch == expected.epoch
        && receipt.archive == expected.archive
        && receipt.archive_sha256 == expected.archive_sha256
        && receipt.manifest == expected.manifest
        && !receipt.archive_deletion_authorized
        && !receipt.remote_mutations
        && !receipt.r2_mutations
}

fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "scratch retirement must run as root"
    );
    let (plan_path, plan_sha256, self_sha256) = parse_args();
    ensure!(valid_sha256(&plan_sha256), "invalid plan SHA-256");
    verify_self(&self_sha256)?;
    ensure!(
        fs::canonicalize(&plan_path)? == plan_path,
        "plan path is not canonical"
    );
    let plan_bytes = read_secure(&plan_path, MAX_JSON_BYTES, 0, false)?;
    ensure!(
        format!("{:x}", Sha256::digest(&plan_bytes)) == plan_sha256,
        "plan SHA-256 mismatch"
    );
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    validate_plan(&plan)?;
    require_private_receipt_path(&plan.intent_receipt)?;
    require_private_receipt_path(&plan.completion_receipt)?;

    let intent_exists = metadata_if_exists(&plan.intent_receipt)?.is_some();
    let completion_exists = metadata_if_exists(&plan.completion_receipt)?.is_some();
    ensure!(
        !completion_exists || intent_exists,
        "completion exists without intent"
    );
    let scratch_exists = metadata_if_exists(&plan.scratch)?.is_some();
    let scratch = if scratch_exists {
        validate_scratch(&plan)?
    } else {
        ensure!(
            intent_exists,
            "scratch is absent without a durable deletion intent"
        );
        read_receipt(&plan.intent_receipt)?.scratch
    };
    let producer = sample_unit(&plan.producer)?;
    let validator = sample_unit(&plan.validator)?;
    let (archive_sha256, manifest) = validate_validation(&plan)?;
    let references = process_references(&plan.scratch, Path::new("/proc"))?;
    ensure!(
        references.is_empty(),
        "live process references scratch: {}",
        references.join("; ")
    );
    let available_before = if intent_exists {
        read_receipt(&plan.intent_receipt)?.available_bytes_before
    } else {
        available_bytes(plan.scratch.parent().expect("validated scratch parent"))?
    };
    let common = Receipt {
        schema: RECEIPT_SCHEMA.to_string(),
        status: "deletion-intent-fsynced".to_string(),
        recorded_unix_millis: now_millis()?,
        plan_path: plan_path.clone(),
        plan_sha256: plan_sha256.clone(),
        tool_sha256: self_sha256.clone(),
        scratch: scratch.clone(),
        producer,
        validator,
        validation_receipt: plan.validation_receipt.path.clone(),
        validation_receipt_sha256: plan.validation_receipt.sha256.clone(),
        epoch: plan.expected_epoch,
        archive: plan.expected_archive.clone(),
        archive_sha256,
        manifest,
        available_bytes_before: available_before,
        available_bytes_after: None,
        intent_receipt: None,
        intent_receipt_sha256: None,
        archive_deletion_authorized: false,
        remote_mutations: false,
        r2_mutations: false,
    };
    if intent_exists {
        let prior = read_receipt(&plan.intent_receipt)?;
        ensure!(
            prior.status == "deletion-intent-fsynced" && same_common(&prior, &common),
            "intent receipt binding mismatch"
        );
    } else {
        write_noclobber(&plan.intent_receipt, &common)?;
    }
    let intent_sha256 = file_sha256(&plan.intent_receipt)?;
    if completion_exists {
        let completion = read_receipt(&plan.completion_receipt)?;
        ensure!(
            completion.status == "deleted" && same_common(&completion, &common),
            "completion receipt binding mismatch"
        );
        ensure!(
            completion.intent_receipt.as_ref() == Some(&plan.intent_receipt),
            "completion intent path mismatch"
        );
        ensure!(
            completion.intent_receipt_sha256.as_deref() == Some(&intent_sha256),
            "completion intent SHA-256 mismatch"
        );
        ensure!(
            metadata_if_exists(&plan.scratch)?.is_none(),
            "completion exists while scratch remains"
        );
        println!("{}", serde_json::to_string(&completion)?);
        return Ok(());
    }
    if metadata_if_exists(&plan.scratch)?.is_some() {
        ensure!(
            validate_scratch(&plan)? == scratch,
            "scratch identity changed after intent"
        );
        let references = process_references(&plan.scratch, Path::new("/proc"))?;
        ensure!(
            references.is_empty(),
            "live process acquired scratch after intent: {}",
            references.join("; ")
        );
        fs::remove_dir_all(&plan.scratch)?;
        ensure!(
            metadata_if_exists(&plan.scratch)?.is_none(),
            "scratch deletion did not complete"
        );
        File::open(plan.scratch.parent().expect("validated scratch parent"))?.sync_all()?;
    }
    let completion = Receipt {
        status: "deleted".to_string(),
        recorded_unix_millis: now_millis()?,
        available_bytes_after: Some(available_bytes(&plan.expected_archive)?),
        intent_receipt: Some(plan.intent_receipt.clone()),
        intent_receipt_sha256: Some(intent_sha256),
        ..common
    };
    write_noclobber(&plan.completion_receipt, &completion)?;
    println!("{}", serde_json::to_string(&completion)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn encoded_reference_respects_path_boundaries() {
        let scratch = b"/private/run/scratch";
        assert!(encoded_reference(
            b"tool\0/private/run/scratch/store\0",
            scratch
        ));
        assert!(encoded_reference(b"/private/run/scratch\n", scratch));
        assert!(!encoded_reference(
            b"/private/run/scratch-store8/file\0",
            scratch
        ));
    }

    #[test]
    fn process_scan_finds_exact_command_map_and_descriptor_references() {
        let temporary = TempDir::new().unwrap();
        let scratch = temporary.path().join("scratch");
        let process = temporary.path().join("123");
        let referenced = scratch.join("store");
        fs::create_dir(&scratch).unwrap();
        fs::write(&referenced, b"data").unwrap();
        fs::create_dir(&process).unwrap();
        fs::write(process.join("cmdline"), scratch.as_os_str().as_bytes()).unwrap();
        fs::write(process.join("maps"), referenced.as_os_str().as_bytes()).unwrap();
        fs::create_dir(process.join("fd")).unwrap();
        symlink(temporary.path(), process.join("cwd")).unwrap();
        symlink(temporary.path(), process.join("root")).unwrap();
        symlink(temporary.path().join("binary"), process.join("exe")).unwrap();
        symlink(&referenced, process.join("fd/5")).unwrap();
        assert_eq!(
            process_references(&scratch, temporary.path())
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn process_scan_ignores_sibling_prefixes() {
        let temporary = TempDir::new().unwrap();
        let scratch = temporary.path().join("scratch");
        let sibling = temporary.path().join("scratch-store8");
        let process = temporary.path().join("123");
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(&sibling).unwrap();
        fs::create_dir(&process).unwrap();
        fs::write(process.join("cmdline"), sibling.as_os_str().as_bytes()).unwrap();
        fs::write(
            process.join("maps"),
            sibling.join("store").as_os_str().as_bytes(),
        )
        .unwrap();
        assert!(
            process_references(&scratch, temporary.path())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn unit_names_are_constrained() {
        assert!(valid_unit_name("horizon-example@206.service"));
        assert!(!valid_unit_name("horizon example.service"));
        assert!(!valid_unit_name("horizon-example.timer"));
    }

    #[test]
    fn plan_rejects_preserved_artifacts_beneath_scratch() {
        let private_root = PathBuf::from(PRIVATE_ROOT);
        let scratch = private_root.join("qualification/scratch");
        let plan = Plan {
            schema: PLAN_SCHEMA.into(),
            private_root: private_root.clone(),
            scratch: scratch.clone(),
            producer: UnitBinding {
                unit: "producer.service".into(),
                invocation_id: "a".repeat(32),
            },
            validator: UnitBinding {
                unit: "validator.service".into(),
                invocation_id: "b".repeat(32),
            },
            validation_receipt: Evidence {
                path: private_root.join("validation.json"),
                sha256: "c".repeat(64),
            },
            expected_epoch: 206,
            expected_archive: scratch.join("epoch-206.jet"),
            intent_receipt: private_root.join("receipts/intent.json"),
            completion_receipt: private_root.join("receipts/completion.json"),
            authority: Authority {
                local_scratch_retirement_authorized: true,
                archive_deletion_authorized: false,
                remote_mutations: false,
                r2_mutations: false,
            },
        };
        assert!(
            validate_plan(&plan)
                .unwrap_err()
                .to_string()
                .contains("preserved evidence")
        );
    }

    #[test]
    fn common_receipt_comparison_ignores_time_and_phase_specific_fields() {
        let state = UnitState {
            unit: "example.service".into(),
            invocation_id: "a".repeat(32),
            load_state: "loaded".into(),
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            result: "success".into(),
            main_pid: 0,
            restarts: 0,
            exec_main_code: 1,
            exec_main_status: 0,
        };
        let identity = FileIdentity {
            path: "/private/run/scratch".into(),
            bytes: 0,
            uid: 0,
            gid: 0,
            mode: "0700".into(),
            device: 1,
            inode: 2,
            links: 2,
        };
        let make = |status: &str| Receipt {
            schema: RECEIPT_SCHEMA.into(),
            status: status.into(),
            recorded_unix_millis: 1,
            plan_path: "/plan".into(),
            plan_sha256: "a".repeat(64),
            tool_sha256: "b".repeat(64),
            scratch: identity.clone(),
            producer: state.clone(),
            validator: state.clone(),
            validation_receipt: "/validation".into(),
            validation_receipt_sha256: "c".repeat(64),
            epoch: 206,
            archive: "/archive".into(),
            archive_sha256: "d".repeat(64),
            manifest: "/manifest".into(),
            available_bytes_before: 10,
            available_bytes_after: None,
            intent_receipt: None,
            intent_receipt_sha256: None,
            archive_deletion_authorized: false,
            remote_mutations: false,
            r2_mutations: false,
        };
        assert!(same_common(
            &make("deleted"),
            &make("deletion-intent-fsynced")
        ));
    }
}
