// Shared immutable-file verification mechanics; scope is binary-local and exact.
// Creates one private canonical-name copy, never a checksum or public file.
// Requires a sealed plan and terminal producer; independent full and plugin
// scans must bind the same unchanged bytes. No replay or R2 operations exist.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

include!("private203_scan_admission.rs");

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    producer_outcome: Evidence,
    provenance_expectation: Evidence,
    #[serde(default)]
    boundary_metadata: Option<Evidence>,
    full_verifier: Evidence,
    plugin: Evidence,
    // Pre-created root-private directory, outside HORIZON_DIR and all packages.
    private_directory: PathBuf,
    // Protects older growth, century floor, and all remaining diagnostic budgets.
    protected_free_bytes: u64,
    maximum_archive_bytes: u64,
    threads: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}

fn hex(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical digest"
    );
    Ok(())
}

fn open_file(path: &Path, root_only: bool) -> Result<File> {
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "noncanonical file path"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o022 == 0,
        "unsafe file identity"
    );
    if root_only {
        ensure!(m.uid() == 0, "evidence must be root-owned");
    }
    ensure!(
        identity(&fs::symlink_metadata(path)?) == identity(&m),
        "file changed while opening"
    );
    Ok(file)
}

fn unchanged(path: &Path, file: &File, before: &Identity) -> Result<()> {
    ensure!(
        &identity(&file.metadata()?) == before && &identity(&fs::symlink_metadata(path)?) == before,
        "file identity changed"
    );
    Ok(())
}

fn measure(path: &Path, root_only: bool) -> Result<(String, Identity)> {
    let mut file = open_file(path, root_only)
        .with_context(|| format!("open bound file {}", path.display()))?;
    let before = identity(&file.metadata()?);
    let digest = hash_open(&mut file)?;
    unchanged(path, &file, &before)?;
    Ok((digest, before))
}

fn hash_open(file: &mut File) -> Result<String> {
    let mut sha = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        sha.update(&buffer[..n]);
    }
    Ok(format!("{:x}", sha.finalize()))
}

fn checked(evidence: &Evidence) -> Result<()> {
    hex(&evidence.sha256)?;
    ensure!(
        measure(&evidence.path, true)?.0 == evidence.sha256,
        "evidence digest mismatch: {}",
        evidence.path.display()
    );
    Ok(())
}

fn read_json(evidence: &Evidence) -> Result<Value> {
    hex(&evidence.sha256)?;
    let mut file = open_file(&evidence.path, true)?;
    let before = identity(&file.metadata()?);
    ensure!(before.len <= 4 * 1024 * 1024, "JSON too large");
    let mut bytes = Vec::new();
    (&mut file)
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    unchanged(&evidence.path, &file, &before)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == evidence.sha256,
        "JSON digest mismatch"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn validate_boundary_metadata(plan: &Plan) -> Result<()> {
    if let Some(binding) = &plan.boundary_metadata {
        let v = read_json(binding)?;
        ensure!(
            v["schema"] == BOUNDARY_SCHEMA
                && v["epoch"] == EPOCH
                && v["derived"]["candidate_anchor"]["slot"] == ANCHOR_SLOT
                && v["derived"]["candidate_anchor"]["blockhash"] == ANCHOR_HASH
                && v["derived"]["expected_terminal"]["slot"] == TERMINAL_SLOT
                && v["derived"]["expected_terminal"]["blockhash"] == TERMINAL_HASH
                && v["raw_rpc_responses_rehashed"] == true
                && v["archive_opened"] == false
                && v["independent_full_poh_verified"] == false
                && v["publication_authorized"] == false,
            "boundary candidate evidence differs or falsely claims archive verification"
        );
        let responses = v["responses"]
            .as_object()
            .context("boundary response census")?;
        ensure!(
            responses.len() == 4,
            "incomplete independent boundary response set"
        );
        for response in responses.values() {
            read_json(&serde_json::from_value(response.clone())?)?;
        }
    }
    Ok(())
}
fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(plan.schema == PLAN_SCHEMA, "wrong plan schema");
    match (BOUNDARY_METADATA, &plan.boundary_metadata) {
        (None, None) => {}
        (Some(expected), Some(boundary)) if boundary.sha256 == expected => {}
        _ => anyhow::bail!("boundary metadata does not belong to this exact profile"),
    }
    ensure!(
        plan.provenance_expectation.sha256 == EXPECTATION
            && plan.full_verifier.sha256 == FULL
            && plan.plugin.sha256 == PLUGIN,
        "unreviewed verifier or provenance expectation"
    );
    ensure!(
        plan.threads == 8
            && plan.protected_free_bytes >= MIN_PROTECTED
            && plan.maximum_archive_bytes > 0
            && plan.maximum_archive_bytes <= 128 * 1024 * 1024 * 1024,
        "invalid resource bounds"
    );
    ensure!(
        plan.private_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && plan
                .private_directory
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(PRIVATE_PREFIX)),
        "not the exact private scan namespace"
    );
    Ok(())
}

fn validate_outcome(value: &Value) -> Result<()> {
    ensure!(
        value["schema"] == OUTCOME_SCHEMA
            && value["producer_unit"] == UNIT
            && value["producer_invocation_id"] == INVOCATION
            && value["private_output"] == SOURCE
            && value["node_sha256"] == NODE
            && value["plan"]["sha256"] == PRODUCER_PLAN
            && value["prefix_archive_sha256"] == PREFIX
            && value["suffix_archive_sha256"] == SUFFIX
            && value["restart_snapshot_sha256"] == SNAPSHOT
            && value["assembly"]["source_archives"] == 2
            && value["assembly"]["slots_merged"] == 432_000
            && value["assembly"]["provenance_version"] == 4
            && value["fresh_prefix_full_validation_passed"] == true
            && value["fresh_native_checkpoint_matches"] == true
            && value["canonical_root_slot"] == ROOT_SLOT,
        "producer outcome does not bind the exact complete assembly"
    );
    if let Some(expected) = PRIOR_NATIVE {
        ensure!(
            value["prior_native_result_sha256"] == expected,
            "wrong independently checked native result"
        );
    }
    if let Some(expected) = REMAINING_SUFFIX {
        ensure!(
            value["remaining_slots"].as_u64() == Some(expected),
            "wrong independently bound suffix span"
        );
    }
    for field in [
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(
            value[field] == false,
            "producer outcome must remain non-authorizing"
        );
    }
    Ok(())
}

fn validate_terminal(text: &str) -> Result<()> {
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').context("invalid service state")?;
        ensure!(
            fields.insert(key, value).is_none(),
            "duplicate service field"
        );
    }
    for (key, expected) in [
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
    ] {
        ensure!(
            fields.get(key) == Some(&expected),
            "producer not clean terminal: {key}"
        );
    }
    ensure!(
        matches!(fields.get("InvocationID"), Some(&"") | Some(&INVOCATION)),
        "foreign producer invocation"
    );
    // Stopping a successful RemainAfterExit unit can clear both fields.
    // terminal() still requires the exact producer completion and subsequent
    // clean manager-deactivation journal; zero is never a standalone proof.
    ensure!(
        fields.get("ExecMainCode") == Some(&"1")
            || (fields.get("ExecMainCode") == Some(&"0")
                && fields.get("InvocationID") == Some(&"")
                && fields.get("ActiveState") == Some(&"inactive")
                && fields.get("SubState") == Some(&"dead")),
        "producer not clean terminal: ExecMainCode"
    );
    ensure!(
        fields.get("LoadState") == Some(&"loaded")
            || (fields.get("LoadState") == Some(&"not-found")
                && fields.get("ExecMainCode") == Some(&"0")
                && fields.get("InvocationID") == Some(&"")
                && fields.get("ActiveState") == Some(&"inactive")
                && fields.get("SubState") == Some(&"dead")),
        "invalid producer load state"
    );
    ensure!(
        matches!(
            fields.get("ActiveState"),
            Some(&"inactive") | Some(&"active")
        ) && matches!(fields.get("SubState"), Some(&"dead") | Some(&"exited")),
        "producer remains live"
    );
    Ok(())
}

fn validate_terminal_journal(bytes: &[u8]) -> Result<Value> {
    let mut completion = None;
    let mut deactivation = None;
    let mut records = 0u64;
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let record: Value = serde_json::from_slice(line)?;
        if record["_SYSTEMD_UNIT"] == UNIT {
            ensure!(
                record["_SYSTEMD_INVOCATION_ID"] == INVOCATION,
                "foreign or unbound producer journal"
            );
            records += 1;
            if record["MESSAGE"]
                .as_str()
                .is_some_and(|m| m.contains(COMPLETION_MARKER))
            {
                ensure!(
                    record["_EXE"] == PRODUCER_EXE && record["_PID"] == PRODUCER_PID,
                    "completion is not from the exact producer"
                );
                ensure!(
                    completion
                        .replace(
                            record["__REALTIME_TIMESTAMP"]
                                .as_str()
                                .context("missing completion time")?
                                .parse::<u64>()?
                        )
                        .is_none(),
                    "duplicate producer completion"
                );
            }
        }
        if record["UNIT"] == UNIT
            && record["_PID"] == "1"
            && record["_EXE"] == "/usr/lib/systemd/systemd"
            && record["MESSAGE"] == format!("{UNIT}: Deactivated successfully.")
        {
            ensure!(
                deactivation
                    .replace(
                        record["__REALTIME_TIMESTAMP"]
                            .as_str()
                            .context("missing deactivation time")?
                            .parse::<u64>()?
                    )
                    .is_none(),
                "duplicate producer deactivation"
            );
        }
    }
    let completed = completion.context("no bound assembly completion journal")?;
    let deactivated = deactivation.context("no clean manager deactivation journal")?;
    ensure!(
        records > 0 && completed <= deactivated,
        "invalid terminal journal order"
    );
    Ok(
        json!({"journal_sha256":format!("{:x}",Sha256::digest(bytes)),"producer_records":records,"completion_timestamp_us":completed,"deactivation_timestamp_us":deactivated,"invocation_id":INVOCATION}),
    )
}

fn terminal() -> Result<Value> {
    let output = Command::new("/usr/bin/systemctl").args(["show", UNIT, "--property=LoadState,InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ExecMainCode,ActiveState,SubState"]).output()?;
    ensure!(output.status.success(), "service observation failed");
    let text = String::from_utf8(output.stdout)?;
    validate_terminal(&text)?;
    // Inactive services commonly clear InvocationID. Bind their retained clean
    // terminal properties to the original process and manager journal instead
    // of treating an empty ID as either success or a replay failure.
    let mut child = Command::new("/usr/bin/journalctl")
        .args([
            "--unit",
            UNIT,
            "--output=json",
            "--no-pager",
            "--lines=100000",
        ])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .context("no journal pipe")?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() > 64 * 1024 * 1024 {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("terminal journal read failed or exceeded bound");
    }
    ensure!(
        child.wait()?.success(),
        "terminal journal observation failed"
    );
    let journal = validate_terminal_journal(&bytes)?;
    Ok(json!({"systemctl":text,"journal":journal}))
}

fn require_absent(path: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "path must be absent: {}",
        path.display()
    );
    Ok(())
}

fn private_dir(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "noncanonical directory"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "directory must be root-private 0700"
    );
    Ok(())
}

fn write_new(path: &Path, value: &Value) -> Result<()> {
    private_dir(path.parent().context("no receipt parent")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

fn free_bytes(path: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .context("free-space overflow")
}

fn full_args(archive: &Path) -> Vec<String> {
    [
        archive.to_string_lossy().into_owned(),
        "--full".into(),
        "--anchor".into(),
        ANCHOR_SLOT.to_string(),
        ANCHOR_HASH.into(),
        "--expected-terminal".into(),
        TERMINAL_SLOT.to_string(),
        TERMINAL_HASH.into(),
        "--threads".into(),
        "8".into(),
        "--expected-provenance-sha256".into(),
        PROVENANCE.into(),
    ]
    .into()
}

fn plugin_args(directory: &Path) -> Vec<String> {
    vec![
        format!("{EPOCH}:{EPOCH}"),
        directory.to_string_lossy().into_owned(),
        "--threads".into(),
        "8".into(),
        "--verify-only".into(),
    ]
}

fn scan(binary: &Evidence, args: &[String], log_path: &Path) -> Result<Value> {
    checked(binary)?;
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(log_path)?;
    let started = Instant::now();
    let status = Command::new(&binary.path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?)
        .status()?;
    log.sync_all()?;
    File::open(log_path.parent().unwrap())?.sync_all()?;
    checked(binary)?;
    ensure!(
        status.success(),
        "private scan failed; retained log {}: {status}",
        log_path.display()
    );
    let (sha256, identity) = measure(log_path, true)?;
    Ok(
        json!({"binary":binary,"arguments":args,"exit_code":0,"elapsed_millis":u64::try_from(started.elapsed().as_millis())?,"log":{"path":log_path,"sha256":sha256,"identity":identity}}),
    )
}

fn run(plan_binding: Evidence, self_sha256: &str) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "must run as root");
    hex(self_sha256)?;
    let mut executable = File::open("/proc/self/exe")?;
    let executable_identity = identity(&executable.metadata()?);
    ensure!(
        executable_identity.uid == 0
            && executable_identity.links == 1
            && executable_identity.mode & 0o022 == 0,
        "unsafe running executable"
    );
    ensure!(
        hash_open(&mut executable)? == self_sha256
            && identity(&executable.metadata()?) == executable_identity,
        "self digest mismatch"
    );
    let plan: Plan = serde_json::from_value(read_json(&plan_binding)?)?;
    validate_plan(&plan)?;
    let dir = &plan.private_directory;
    private_dir(dir)?;
    ensure!(
        fs::read_dir(dir)?.next().is_none(),
        "private directory must be empty; preserve prior attempts"
    );
    let before_terminal = terminal()?;
    let outcome = read_json(&plan.producer_outcome)?;
    validate_outcome(&outcome)?;
    let expected = read_json(&plan.provenance_expectation)?;
    ensure!(
        expected["schema"] == EXPECTATION_SCHEMA
            && expected["expected_provenance_sha256"] == PROVENANCE
            && expected["source_manifest_scope_validated"] == true
            && expected["assembled_target_opened"] == false,
        "invalid independent provenance expectation"
    );
    validate_boundary_metadata(&plan)?;
    checked(&plan.full_verifier)?;
    checked(&plan.plugin)?;
    admit_private203_scan(&plan, &plan_binding, self_sha256)?;
    let source_path = Path::new(SOURCE);
    let mut source = open_file(source_path, false)?;
    let source_identity = identity(&source.metadata()?);
    ensure!(
        source_identity.len > 0 && source_identity.len <= plan.maximum_archive_bytes,
        "source length outside bound"
    );
    ensure!(
        free_bytes(dir)?
            .checked_sub(source_identity.len)
            .is_some_and(|remaining| remaining >= plan.protected_free_bytes),
        "copy would violate protected free space"
    );
    let archive = dir.join(ARCHIVE_NAME);
    require_absent(&source_path.with_extension("jet.sha256"))?;
    require_absent(&archive.with_extension("jet.sha256"))?;
    write_new(
        &dir.join("intent.json"),
        &json!({"schema":INTENT_SCHEMA,"plan":plan_binding,"runner_sha256":self_sha256,"source_identity":source_identity,"producer_terminal":before_terminal,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let copy_started = Instant::now();
    let mut staged = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&archive)?;
    ensure!(
        std::io::copy(&mut source, &mut staged)? == source_identity.len,
        "source copy length changed"
    );
    staged.sync_all()?;
    staged.set_permissions(fs::Permissions::from_mode(0o400))?;
    staged.sync_all()?;
    File::open(dir)?.sync_all()?;
    unchanged(source_path, &source, &source_identity)?;
    ensure!(
        free_bytes(dir)? >= plan.protected_free_bytes,
        "protected free space changed"
    );
    let (digest, stage_identity) = measure(&archive, true)?;
    // Independently hash the retained source, not only the copied output.
    ensure!(
        measure(source_path, false)?.0 == digest,
        "source and copy digests differ"
    );
    let copy_millis = u64::try_from(copy_started.elapsed().as_millis())?;
    let full = scan(
        &plan.full_verifier,
        &full_args(&archive),
        &dir.join("full.log"),
    )?;
    ensure!(
        measure(&archive, true)? == (digest.clone(), stage_identity.clone()),
        "archive changed during full scan"
    );
    write_new(
        &dir.join("full.json"),
        &json!({"schema":FULL_SCHEMA,"archive_sha256":digest,"archive_identity":stage_identity,"full":full,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let args = plugin_args(dir);
    let plugin = scan(&plan.plugin, &args, &dir.join("plugin.log"))?;
    ensure!(
        measure(&archive, true)? == (digest.clone(), stage_identity.clone()),
        "archive changed during plugin scan"
    );
    unchanged(source_path, &source, &source_identity)?;
    require_absent(&archive.with_extension("jet.sha256"))?;
    require_absent(&source_path.with_extension("jet.sha256"))?;
    let after_terminal = terminal()?;
    checked(&plan.producer_outcome)?;
    checked(&plan.provenance_expectation)?;
    let mut verification = json!({"schema":VERIFICATION_SCHEMA,"epoch":EPOCH,"plan":plan_binding,"runner_sha256":self_sha256,"producer_outcome":plan.producer_outcome,"producer_terminal":after_terminal,"provenance_expectation":plan.provenance_expectation,"expected_provenance_sha256":PROVENANCE,"source_path":source_path,"source_identity":source_identity,"archive_path":archive,"archive_sha256":digest,"archive_identity":stage_identity,"copy_and_hash_millis":copy_millis,"full":full,"plugin":plugin,"independent_final_archive_verification_passed":true,"current_plugin_verification_passed":true,"runtime_admission_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false});
    if let Some(boundary) = &plan.boundary_metadata {
        verification["boundary_metadata"] = serde_json::to_value(boundary)?;
    }
    write_new(&dir.join("verification.json"), &verification)?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: jetstreamer-epoch{EPOCH}-private-verify PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    run(
        Evidence {
            path: args[0].clone().into(),
            sha256: args[2].clone(),
        },
        &args[4],
    )
}
