//! Plan-bound retirement of reproducible state from one failed Horizon diagnostic.
//!
//! The legacy profile accepts only its two known disposable subtrees. An explicit
//! restore-only epoch213 profile accepts only its isolated scratch directory and
//! requires a zero-entry stopped probe with retained inputs and no archive.
//! A closed epoch223 v3 profile retires only its failed restore scratch, retaining
//! and rehashing the immutable inputs and original failure evidence.
//! All profiles prove terminal identity, revalidate sealed outcome evidence, and
//! scan command/maps/cwd/root/exe/fd references before deletion.

use {
    anyhow::{anyhow, ensure, Context, Result},
    serde::{Deserialize, Serialize},
    serde_json::{json, Value},
    sha2::{Digest as _, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
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

const PLAN_SCHEMA: &str = "jetstreamer-horizon-failed-diagnostic-retirement-plan-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-horizon-failed-diagnostic-retirement-receipt-v1";
const OUTCOME_SCHEMA: &str = "jetstreamer-horizon-epoch224-singleton-diagnostic-outcome-v1";
const RESTORE_OUTCOME_SCHEMA: &str = "jetstreamer-horizon-native-restore-probe-failure-v1";
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    #[serde(default)]
    restore_only_probe: bool,
    #[serde(default)]
    warmup223_v3: bool,
    private_root: PathBuf,
    run_root: PathBuf,
    targets: Vec<PathBuf>,
    producer: UnitExpectation,
    guard: UnitExpectation,
    inactive_units: Vec<String>,
    outcome: Evidence,
    #[serde(default)]
    guard_stop_intent: Option<Evidence>,
    #[serde(default)]
    guard_stop_completion: Option<Evidence>,
    evidence: Vec<Evidence>,
    intent_receipt: PathBuf,
    completion_receipt: PathBuf,
    authority: Authority,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitExpectation {
    unit: String,
    invocation_id: String,
    active_state: String,
    sub_state: String,
    result: String,
    exec_main_status: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    local_failed_diagnostic_retirement_authorized: bool,
    preserve_run_root: bool,
    archive_publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
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

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct TreeIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: String,
    physical_bytes: u64,
    apparent_bytes: u64,
    regular_files: u64,
    directories: u64,
}

fn usage() -> ! {
    eprintln!(
        "usage: jetstreamer-horizon-retire-failed-diagnostic --plan PATH --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    std::process::exit(2);
}

fn parse_args() -> (PathBuf, String, String, bool) {
    let mut args = env::args_os().skip(1);
    let mut plan = None;
    let mut plan_sha256 = None;
    let mut self_sha256 = None;
    let mut check_only = false;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--plan") => plan = args.next().map(PathBuf::from),
            Some("--plan-sha256") => {
                plan_sha256 = args.next().and_then(|value| value.into_string().ok())
            }
            Some("--self-sha256") => {
                self_sha256 = args.next().and_then(|value| value.into_string().ok())
            }
            Some("--check-only") if !check_only => check_only = true,
            _ => usage(),
        }
    }
    (
        plan.unwrap_or_else(|| usage()),
        plan_sha256.unwrap_or_else(|| usage()),
        self_sha256.unwrap_or_else(|| usage()),
        check_only,
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

fn file_sha256(path: &Path) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    sha256_reader(file)
}

fn read_secure(path: &Path, maximum: u64, required_uid: u32) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute(),
        "path is not absolute: {}",
        path.display()
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.nlink() == 1,
        "unsafe file identity"
    );
    ensure!(before.uid() == required_uid, "unexpected file owner");
    ensure!(
        before.permissions().mode() & 0o022 == 0,
        "writable evidence file"
    );
    ensure!(before.len() <= maximum, "evidence file exceeds size limit");
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "evidence file exceeds size limit"
    );
    let after = file.metadata()?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "evidence changed while reading"
    );
    Ok(bytes)
}

fn verify_self(expected: &str) -> Result<()> {
    ensure!(valid_sha256(expected), "invalid self SHA-256");
    ensure!(
        sha256_reader(File::open("/proc/self/exe")?)? == expected,
        "running executable SHA-256 mismatch"
    );
    Ok(())
}

fn valid_unit_name(value: &str) -> bool {
    (value.ends_with(".service") || value.ends_with(".timer"))
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'@' | b'-'))
}

fn path_or_descendant(candidate: &Path, root: &Path) -> bool {
    candidate == root || candidate.starts_with(root)
}

const WARMUP223_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-prefix-warmup-a1f6239d-v3";
const WARMUP223_UNIT: &str = "horizon-qualify-223-warmup-resource-a1f6239d-v3.service";
const WARMUP223_IID: &str = "1fffc79d92ad458a9a4d334a48b40dfc";

fn validate_warmup223_profile(plan: &Plan) -> Result<()> {
    ensure!(
        !plan.restore_only_probe
            && plan.run_root == Path::new(WARMUP223_ROOT)
            && plan.producer.unit == WARMUP223_UNIT
            && plan.producer.invocation_id == WARMUP223_IID
            && plan.producer.active_state == "failed"
            && plan.producer.sub_state == "failed"
            && plan.producer.result == "exit-code"
            && plan.producer.exec_main_status == 1
            && plan.guard.unit == "horizon-warmup223-protective-v3.service"
            && plan.inactive_units == ["horizon-warmup223-protective-v3.timer"]
            && plan.outcome.path
                == Path::new("/var/lib/jetstreamer/horizon-warmup223-terminal-v3/failure.json")
            && plan.outcome.sha256
                == "7f1671b6f74946f2fc4f2b2fd13569b59c4015739889080dc395db2191c18c73",
        "warmup cleanup must bind the exact failed v3 attempt"
    );
    for (path, sha) in [
        (
            "/var/lib/jetstreamer/horizon-warmup223-terminal-v3/launch.json",
            "742656ca51cc60e14800ab76b379de384d3341d26696f33c7c992de772eeba6d",
        ),
        (
            "/var/lib/jetstreamer/horizon-warmup223-terminal-v3/guard-stop.json",
            "27eb179b252aaeae09d39c0242c6306da3f3cb87adc53ca1e308699b0b5ba1b8",
        ),
        (
            "/var/lib/jetstreamer/horizon-cold223-input-proof-v1/input-proof.json",
            "b0ee9a5136e075d0c1605573cc78e154a3059351e0e0f961068211f344c5387f",
        ),
    ] {
        ensure!(
            plan.evidence
                .iter()
                .any(|e| e.path == Path::new(path) && e.sha256 == sha),
            "warmup retained lineage missing:{path}"
        );
    }
    Ok(())
}

fn validate_warmup223_outcome(plan: &Plan, outcome: &Value) -> Result<()> {
    validate_warmup223_profile(plan)?;
    ensure!(
        outcome["invocation_id"] == WARMUP223_IID
            && outcome["unit"] == WARMUP223_UNIT
            && outcome["success"] == false
            && outcome["target_reached"] == false
            && outcome["observed_slot"].is_null()
            && outcome["first_progress"].is_null()
            && outcome["last_progress"].is_null()
            && outcome["capture"].is_null()
            && outcome["error"] == "physical scan time bound exceeded"
            && outcome["authority"]["r2_mutations"] == false
            && outcome["authority"]["publication_authorized"] == false,
        "warmup failure is not an unexecuted failed restore"
    );
    ensure!(
        fs::read_dir(plan.run_root.join("output"))?.next().is_none(),
        "warmup output must be retained and reviewed separately"
    );
    for name in [
        "target-capture.json",
        "target-stop.json",
        "native-checkpoint.json",
        "result.json",
    ] {
        ensure!(
            matches!(fs::symlink_metadata(plan.run_root.join("receipts").join(name)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "warmup has a successful/checkpoint artifact:{name}"
        );
    }
    // Reproducibility must survive scratch deletion, independent of a stale
    // receipt saying that the source existed earlier. These inputs are sealed.
    for (path, sha) in [
        ("/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst", "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665"),
        ("/var/lib/jetstreamer/horizon-223-warmup-e3d48954-v1/historical-worker", "b99691fd5995fe5f06e508cfd8f156b8e5cb7342ddab503fb2383e42e712d025"),
        ("/var/lib/jetstreamer/horizon-223-prefix-preflight-a928381d-v1/jetstreamer-node", "90474659be2a4a7d1cc9d4dfe3d5ab1587adb1b388b83163b2bf16c771624f66"),
        ("/var/lib/jetstreamer/horizon-223-prefix-preflight-a928381d-v1/epoch-hashes-223-prefix.txt", "9ce886d556f70e84386dbf1b2c4abc4b4fb7ea57064b903e50ff6b34479a0c15"),
        ("/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/genesis.tar.bz2", "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"),
    ] {
        let path = Path::new(path);
        let m = fs::symlink_metadata(path)?;
        ensure!(m.is_file() && m.uid() == 0 && m.mode() & 0o222 == 0
            && file_sha256(path)? == sha, "warmup retained input differs:{}", path.display());
    }
    Ok(())
}

fn disposable_targets(plan: &Plan) -> Result<BTreeSet<PathBuf>> {
    if plan.warmup223_v3 {
        validate_warmup223_profile(plan)?;
        Ok(BTreeSet::from([plan.run_root.join("scratch")]))
    } else if plan.restore_only_probe {
        let name = plan
            .run_root
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("");
        ensure!(
            plan.run_root.parent() == Some(plan.private_root.as_path())
                && name.starts_with("checkpoint-restore-probe-213-")
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && plan
                    .producer
                    .unit
                    .starts_with("horizon-qualify-213-native-restore-probe-")
                && plan
                    .guard
                    .unit
                    .starts_with("horizon-native-restore-probe-213-guard-"),
            "restore-only retirement must bind an isolated epoch213 native probe"
        );
        Ok(BTreeSet::from([plan.run_root.join("scratch")]))
    } else {
        Ok(BTreeSet::from([
            plan.run_root.join("output/compact-indexes"),
            plan.run_root.join("replay-state"),
        ]))
    }
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(plan.schema == PLAN_SCHEMA, "plan schema mismatch");
    ensure!(
        plan.private_root == Path::new("/home/ubuntu/.jetstreamer-private"),
        "unexpected private root"
    );
    ensure!(plan.run_root.is_absolute(), "run root is not absolute");
    ensure!(
        plan.run_root.starts_with(&plan.private_root),
        "run root escapes private root"
    );
    let expected = disposable_targets(plan)?;
    let actual = plan.targets.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        plan.targets.len() == expected.len() && actual == expected,
        "target set is not the exact disposable diagnostic set"
    );
    ensure!(
        plan.intent_receipt != plan.completion_receipt,
        "receipt paths collide"
    );
    for receipt in [&plan.intent_receipt, &plan.completion_receipt] {
        ensure!(
            receipt.is_absolute() && receipt.starts_with(&plan.private_root),
            "receipt path escapes private root"
        );
        ensure!(
            !plan
                .targets
                .iter()
                .any(|target| path_or_descendant(receipt, target)),
            "receipt is beneath a deletion target"
        );
    }
    ensure!(
        valid_unit_name(&plan.producer.unit) && valid_unit_name(&plan.guard.unit),
        "invalid bound unit name"
    );
    ensure!(
        plan.producer.invocation_id.len() == 32 && plan.guard.invocation_id.len() == 32,
        "invalid invocation ID"
    );
    ensure!(
        plan.inactive_units.iter().all(|unit| valid_unit_name(unit)),
        "invalid inactive unit name"
    );
    ensure!(
        valid_sha256(&plan.outcome.sha256),
        "invalid outcome SHA-256"
    );
    if plan.restore_only_probe {
        ensure!(
            plan.guard_stop_intent.is_some() && plan.guard_stop_completion.is_some(),
            "restore-only cleanup requires exact guard stop intent and completion"
        );
    } else {
        ensure!(
            plan.guard_stop_intent.is_none() && plan.guard_stop_completion.is_none(),
            "legacy cleanup does not accept restore-only guard evidence"
        );
    }
    for item in bound_evidence(plan) {
        ensure!(
            item.path.is_absolute()
                && (item.path.starts_with(&plan.private_root)
                    || ((plan.restore_only_probe || plan.warmup223_v3)
                        && item.path.starts_with(Path::new("/var/lib/jetstreamer"))))
                && valid_sha256(&item.sha256),
            "invalid evidence binding"
        );
        ensure!(
            !plan
                .targets
                .iter()
                .any(|target| path_or_descendant(&item.path, target)),
            "evidence is beneath a deletion target"
        );
    }
    ensure!(
        plan.authority.local_failed_diagnostic_retirement_authorized,
        "retirement is not authorized"
    );
    ensure!(
        plan.authority.preserve_run_root,
        "run root preservation is not required"
    );
    ensure!(
        !plan.authority.archive_publication_authorized,
        "plan authorizes archive publication"
    );
    ensure!(
        !plan.authority.remote_mutations && !plan.authority.r2_mutations,
        "plan authorizes remote mutation"
    );
    Ok(())
}

fn bound_evidence(plan: &Plan) -> Vec<&Evidence> {
    std::iter::once(&plan.outcome)
        .chain(plan.guard_stop_intent.iter())
        .chain(plan.guard_stop_completion.iter())
        .chain(plan.evidence.iter())
        .collect()
}

fn parse_systemctl(stdout: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(stdout)?.lines() {
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

fn collected_guard(state: &UnitState) -> bool {
    state.load_state == "not-found"
        && state.invocation_id.is_empty()
        && state.active_state == "inactive"
        && state.sub_state == "dead"
        && state.main_pid == 0
        && state.restarts == 0
        && state.result == "success"
        && state.exec_main_code == 0
        && state.exec_main_status == 0
}

fn sample_unit(expectation: &UnitExpectation, allow_collected_guard: bool) -> Result<UnitState> {
    let output = Command::new("systemctl")
        .args(["show", &expectation.unit, "--property=LoadState,ActiveState,SubState,Result,MainPID,InvocationID,NRestarts,ExecMainCode,ExecMainStatus"])
        .output()?;
    ensure!(
        output.status.success(),
        "systemctl failed for {}",
        expectation.unit
    );
    let fields = parse_systemctl(&output.stdout)?;
    let number = |key: &str| -> Result<u64> {
        Ok(fields
            .get(key)
            .ok_or_else(|| anyhow!("missing {key}"))?
            .parse()?)
    };
    let signed = |key: &str| -> Result<i64> {
        Ok(fields
            .get(key)
            .ok_or_else(|| anyhow!("missing {key}"))?
            .parse()?)
    };
    let state = UnitState {
        unit: expectation.unit.clone(),
        invocation_id: fields.get("InvocationID").cloned().unwrap_or_default(),
        load_state: fields.get("LoadState").cloned().unwrap_or_default(),
        active_state: fields.get("ActiveState").cloned().unwrap_or_default(),
        sub_state: fields.get("SubState").cloned().unwrap_or_default(),
        result: fields.get("Result").cloned().unwrap_or_default(),
        main_pid: number("MainPID")?,
        restarts: number("NRestarts")?,
        exec_main_code: signed("ExecMainCode")?,
        exec_main_status: signed("ExecMainStatus")?,
    };
    // A qualified restore-only/warmup guard may be collected. Never synthesize
    // its old invocation as live state; independently require its timer inactive.
    if allow_collected_guard && collected_guard(&state) {
        return Ok(state);
    }
    ensure!(state.load_state == "loaded", "bound unit is not loaded");
    ensure!(
        state.invocation_id == expectation.invocation_id,
        "bound invocation changed"
    );
    ensure!(
        state.active_state == expectation.active_state && state.sub_state == expectation.sub_state,
        "bound unit is not in the expected terminal state"
    );
    ensure!(
        state.result == expectation.result
            && state.exec_main_status == expectation.exec_main_status,
        "bound unit result changed"
    );
    ensure!(
        state.main_pid == 0 && state.restarts == 0,
        "bound unit has a process or restart"
    );
    Ok(state)
}

fn require_inactive_unit(unit: &str) -> Result<Value> {
    let output = Command::new("systemctl")
        .args([
            "show",
            unit,
            "--property=LoadState,ActiveState,SubState,Result,MainPID",
        ])
        .output()?;
    ensure!(
        output.status.success(),
        "cannot inspect inactive unit {unit}"
    );
    let fields = parse_systemctl(&output.stdout)?;
    ensure!(
        fields.get("ActiveState").map(String::as_str) == Some("inactive"),
        "unit {unit} is active"
    );
    ensure!(
        fields
            .get("MainPID")
            .is_none_or(|value| value.is_empty() || value == "0"),
        "unit {unit} has a process"
    );
    Ok(
        json!({"unit": unit, "load_state": fields.get("LoadState"), "active_state": fields.get("ActiveState"), "sub_state": fields.get("SubState"), "result": fields.get("Result")}),
    )
}

fn require_no_jobs(units: &BTreeSet<String>) -> Result<()> {
    let output = Command::new("systemctl")
        .args(["list-jobs", "--no-legend", "--plain"])
        .output()?;
    ensure!(output.status.success(), "cannot inspect systemd jobs");
    let text = std::str::from_utf8(&output.stdout)?;
    for line in text.lines() {
        ensure!(
            !units
                .iter()
                .any(|unit| line.split_whitespace().any(|field| field == unit)),
            "a bound unit has a pending systemd job"
        );
    }
    Ok(())
}

fn tree_identity(path: &Path) -> Result<TreeIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "target is not an exact directory"
    );
    ensure!(
        fs::canonicalize(path)? == path,
        "target path is not canonical"
    );
    let device = metadata.dev();
    let mut physical_bytes = metadata.blocks().saturating_mul(512);
    let mut apparent_bytes = metadata.len();
    let mut regular_files = 0_u64;
    let mut directories = 1_u64;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let child = entry.path();
            let child_metadata = fs::symlink_metadata(&child)?;
            ensure!(
                !child_metadata.file_type().is_symlink(),
                "symlink found beneath target: {}",
                child.display()
            );
            ensure!(
                child_metadata.dev() == device,
                "target crosses a filesystem boundary"
            );
            physical_bytes =
                physical_bytes.saturating_add(child_metadata.blocks().saturating_mul(512));
            apparent_bytes = apparent_bytes.saturating_add(child_metadata.len());
            if child_metadata.is_dir() {
                directories += 1;
                pending.push(child);
            } else {
                ensure!(
                    child_metadata.is_file(),
                    "unsupported member beneath target: {}",
                    child.display()
                );
                regular_files += 1;
            }
        }
    }
    Ok(TreeIdentity {
        path: path.to_path_buf(),
        device,
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: format!("{:04o}", metadata.permissions().mode() & 0o7777),
        physical_bytes,
        apparent_bytes,
        regular_files,
        directories,
    })
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
        let end = start + relative + needle.len();
        if end == content.len() || boundaries.contains(&content[end]) {
            return true;
        }
        start += relative + 1;
    }
    false
}

fn read_proc_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn read_proc_link(path: &Path) -> Result<Option<PathBuf>> {
    match fs::read_link(path) {
        Ok(target) => {
            let rendered = target.to_string_lossy();
            Ok(Some(PathBuf::from(
                rendered.strip_suffix(" (deleted)").unwrap_or(&rendered),
            )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn process_references(targets: &[PathBuf]) -> Result<Vec<String>> {
    let mut references = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
            .map(str::to_string)
        else {
            continue;
        };
        if pid.parse::<u32>().ok() == Some(std::process::id()) {
            continue;
        }
        let process = entry.path();
        for target in targets {
            let needle = target.as_os_str().as_bytes();
            for (name, label) in [("cmdline", "command"), ("maps", "maps")] {
                if read_proc_file(&process.join(name))?
                    .is_some_and(|bytes| encoded_reference(&bytes, needle))
                {
                    references.push(format!("pid {pid} {label} {}", target.display()));
                }
            }
            for name in ["cwd", "root", "exe"] {
                if read_proc_link(&process.join(name))?
                    .is_some_and(|value| path_or_descendant(&value, target))
                {
                    references.push(format!("pid {pid} {name} {}", target.display()));
                }
            }
            match fs::read_dir(process.join("fd")) {
                Ok(descriptors) => {
                    for descriptor in descriptors {
                        let descriptor = descriptor?;
                        if read_proc_link(&descriptor.path())?
                            .is_some_and(|value| path_or_descendant(&value, target))
                        {
                            references.push(format!(
                                "pid {pid} fd {} {}",
                                descriptor.file_name().to_string_lossy(),
                                target.display()
                            ));
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("cannot inspect pid {pid} descriptors"));
                }
            }
        }
    }
    Ok(references)
}

fn fsync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn write_noclobber(path: &Path, value: &Value) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("receipt has no parent"))?;
    let metadata = fs::metadata(parent)?;
    ensure!(
        fs::canonicalize(parent)? == parent
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o077 == 0,
        "unsafe receipt directory"
    );
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fsync_directory(parent)
}

fn available_bytes(path: &Path) -> Result<u64> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let stats = unsafe { stats.assume_init() };
    Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
}

fn now_millis() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

fn validate_restore_outcome(plan: &Plan, outcome: &Value) -> Result<()> {
    ensure!(
        outcome
            .pointer("/scope/restore_only")
            .and_then(Value::as_bool)
            == Some(true)
            && outcome
                .pointer("/scope/replay_entries_sent")
                .and_then(Value::as_u64)
                == Some(0)
            && outcome
                .pointer("/scope/archive_created")
                .and_then(Value::as_bool)
                == Some(false)
            && outcome
                .pointer("/scope/snapshot_source_retained")
                .and_then(Value::as_bool)
                == Some(true)
            && outcome
                .pointer("/scope/worker_source_retained")
                .and_then(Value::as_bool)
                == Some(true)
            && outcome
                .pointer("/scope/guard_stop_completed")
                .and_then(Value::as_bool)
                == Some(true)
            && outcome.pointer("/run_root").and_then(Value::as_str) == plan.run_root.to_str(),
        "restore-only outcome must preserve reproducibility and prove a zero-entry stopped probe"
    );
    Ok(())
}

fn read_bound_json(item: &Evidence) -> Result<Value> {
    let bytes = read_secure(&item.path, MAX_JSON_BYTES, 0)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == item.sha256,
        "guard stop evidence SHA-256 mismatch"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn validate_restore_stop_chain(plan: &Plan, intent: &Value, completion: &Value) -> Result<()> {
    let intent_path = &plan
        .guard_stop_intent
        .as_ref()
        .context("missing stop intent")?
        .path;
    ensure!(
        intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && intent["producer_invocation_id"] == plan.producer.invocation_id
            && intent["sample"]["guard_invocation_id"] == plan.guard.invocation_id
            && intent["sample"]["producer_invocation_id"] == plan.producer.invocation_id
            && intent["sample"]["producer"]["invocation_id"] == plan.producer.invocation_id
            && intent["sample"]["producer"]["restarts"] == 0
            && completion["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && completion["producer_invocation_id"] == plan.producer.invocation_id
            && completion["intent"].as_str() == intent_path.to_str()
            && completion["plan_sha256"].as_str().is_some_and(valid_sha256)
            && completion["plan_sha256"] == intent["plan_sha256"]
            && completion["terminal"]["invocation_id"] == plan.producer.invocation_id
            && completion["terminal"]["pid"] == 0
            && completion["terminal"]["restarts"] == 0
            && completion["terminal"]["active"] == plan.producer.active_state
            && completion["terminal"]["sub"] == plan.producer.sub_state
            && completion["terminal"]["result"] == plan.producer.result
            && completion["scratch_deleted"] == false
            && completion["r2_mutations"] == false
            && completion["remote_mutations"] == false,
        "restore-only guard stop chain does not bind the exact terminal attempt"
    );
    Ok(())
}

fn stable_evidence(plan: &Plan) -> Result<Value> {
    let run_metadata = fs::symlink_metadata(&plan.run_root)?;
    ensure!(
        run_metadata.is_dir()
            && !run_metadata.file_type().is_symlink()
            && fs::canonicalize(&plan.run_root)? == plan.run_root,
        "unsafe run root"
    );
    let outcome_bytes = read_secure(&plan.outcome.path, MAX_JSON_BYTES, 0)?;
    ensure!(
        format!("{:x}", Sha256::digest(&outcome_bytes)) == plan.outcome.sha256,
        "outcome SHA-256 mismatch"
    );
    let outcome: Value = serde_json::from_slice(&outcome_bytes)?;
    ensure!(
        outcome.pointer("/schema").and_then(Value::as_str)
            == Some(if plan.warmup223_v3 {
                "jetstreamer-private-epoch223-warmup-resource-v1"
            } else if plan.restore_only_probe {
                RESTORE_OUTCOME_SCHEMA
            } else {
                OUTCOME_SCHEMA
            }),
        "outcome schema mismatch"
    );
    if plan.restore_only_probe {
        validate_restore_outcome(plan, &outcome)?;
        let intent = read_bound_json(
            plan.guard_stop_intent
                .as_ref()
                .context("missing stop intent")?,
        )?;
        let completion = read_bound_json(
            plan.guard_stop_completion
                .as_ref()
                .context("missing stop completion")?,
        )?;
        validate_restore_stop_chain(plan, &intent, &completion)?;
        ensure!(
            matches!(fs::symlink_metadata(plan.run_root.join("receipts/native-checkpoint.json")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "failed restore probe has a checkpoint receipt; review its successful result separately"
        );
    }
    if plan.warmup223_v3 {
        validate_warmup223_outcome(plan, &outcome)?;
    } else {
        ensure!(
            outcome
                .pointer(
                    "/authority/scratch_retirement_authorized_after_clean_process_reference_scan"
                )
                .and_then(Value::as_bool)
                == Some(true),
            "outcome does not authorize cleanup"
        );
        ensure!(
            outcome
                .pointer("/authority/r2_mutations")
                .and_then(Value::as_bool)
                == Some(false),
            "outcome permits R2 mutation"
        );
        ensure!(
            outcome
                .pointer("/producer/invocation_id")
                .and_then(Value::as_str)
                == Some(&plan.producer.invocation_id),
            "outcome producer mismatch"
        );
    }
    let mut evidence = Vec::new();
    let mut seen = BTreeSet::new();
    for item in bound_evidence(plan) {
        ensure!(seen.insert(item.path.clone()), "duplicate evidence path");
        let bytes = read_secure(&item.path, MAX_JSON_BYTES, 0)?;
        let observed = format!("{:x}", Sha256::digest(&bytes));
        ensure!(
            observed == item.sha256,
            "evidence SHA-256 mismatch: {}",
            item.path.display()
        );
        evidence.push(json!({"path": item.path, "sha256": observed}));
    }
    let producer = sample_unit(&plan.producer, false)?;
    let guard = sample_unit(&plan.guard, plan.restore_only_probe || plan.warmup223_v3)?;
    let mut inactive = Vec::new();
    for unit in &plan.inactive_units {
        inactive.push(require_inactive_unit(unit)?);
    }
    let units = std::iter::once(plan.producer.unit.clone())
        .chain(std::iter::once(plan.guard.unit.clone()))
        .chain(plan.inactive_units.iter().cloned())
        .collect::<BTreeSet<_>>();
    require_no_jobs(&units)?;
    let targets = plan
        .targets
        .iter()
        .map(|path| tree_identity(path))
        .collect::<Result<Vec<_>>>()?;
    let references = process_references(&plan.targets)?;
    ensure!(
        references.is_empty(),
        "live process references cleanup targets: {references:?}"
    );
    Ok(json!({
        "run_root": plan.run_root,
        "run_root_device": run_metadata.dev(),
        "run_root_inode": run_metadata.ino(),
        "targets": targets,
        "producer": producer,
        "guard": guard,
        "inactive_units": inactive,
        "evidence": evidence,
        "process_reference_scan": {"coverage": ["command", "maps", "cwd", "root", "exe", "file-descriptors"], "references": []},
        "pending_systemd_jobs": []
    }))
}

fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "must run as root");
    let (plan_path, expected_plan_sha256, expected_self_sha256, check_only) = parse_args();
    verify_self(&expected_self_sha256)?;
    ensure!(valid_sha256(&expected_plan_sha256), "invalid plan SHA-256");
    let plan_bytes = read_secure(&plan_path, MAX_JSON_BYTES, 0)?;
    ensure!(
        format!("{:x}", Sha256::digest(&plan_bytes)) == expected_plan_sha256,
        "plan SHA-256 mismatch"
    );
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    validate_plan(&plan)?;
    ensure!(
        !plan.intent_receipt.exists() && !plan.completion_receipt.exists(),
        "fresh receipt paths are required"
    );
    let evidence = stable_evidence(&plan)?;
    let tool_sha256 = expected_self_sha256.clone();
    let common = json!({
        "schema": RECEIPT_SCHEMA,
        "plan": plan_path,
        "plan_sha256": expected_plan_sha256,
        "tool_sha256": tool_sha256,
        "evidence": evidence,
        "run_root_preserved": true,
        "archive_publication_authorized": false,
        "remote_mutations": false,
        "r2_mutations": false
    });
    if check_only {
        println!(
            "{}",
            serde_json::to_string(&json!({"status": "check-passed", "receipt": common}))?
        );
        return Ok(());
    }
    let before = available_bytes(&plan.run_root)?;
    let intent = json!({"status": "intent-fsynced", "recorded_unix_millis": now_millis()?, "available_bytes_before": before, "receipt": common});
    write_noclobber(&plan.intent_receipt, &intent)?;
    let second = stable_evidence(&plan)?;
    ensure!(second == evidence, "cleanup evidence changed after intent");
    for target in &plan.targets {
        fs::remove_dir_all(target)
            .with_context(|| format!("cannot remove {}", target.display()))?;
        fsync_directory(
            target
                .parent()
                .ok_or_else(|| anyhow!("target lacks parent"))?,
        )?;
    }
    ensure!(plan.run_root.exists(), "run root was not preserved");
    ensure!(
        plan.targets.iter().all(|target| !target.exists()),
        "a cleanup target remains"
    );
    let completion = json!({
        "status": "complete",
        "recorded_unix_millis": now_millis()?,
        "available_bytes_before": before,
        "available_bytes_after": available_bytes(&plan.run_root)?,
        "intent_receipt": plan.intent_receipt,
        "intent_receipt_sha256": file_sha256(&plan.intent_receipt)?,
        "targets_absent": true,
        "receipt": common
    });
    write_noclobber(&plan.completion_receipt, &completion)?;
    println!("{}", serde_json::to_string(&completion)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warmup_plan() -> Plan {
        let mut plan = restore_plan();
        plan.restore_only_probe = false;
        plan.warmup223_v3 = true;
        plan.run_root = WARMUP223_ROOT.into();
        plan.targets = vec![plan.run_root.join("scratch")];
        plan.producer = UnitExpectation {
            unit: WARMUP223_UNIT.into(),
            invocation_id: WARMUP223_IID.into(),
            active_state: "failed".into(),
            sub_state: "failed".into(),
            result: "exit-code".into(),
            exec_main_status: 1,
        };
        plan.guard.unit = "horizon-warmup223-protective-v3.service".into();
        plan.inactive_units = vec!["horizon-warmup223-protective-v3.timer".into()];
        plan.guard_stop_intent = None;
        plan.guard_stop_completion = None;
        plan.outcome = Evidence {
            path: "/var/lib/jetstreamer/horizon-warmup223-terminal-v3/failure.json".into(),
            sha256: "7f1671b6f74946f2fc4f2b2fd13569b59c4015739889080dc395db2191c18c73".into(),
        };
        plan.evidence = [
            (
                "/var/lib/jetstreamer/horizon-warmup223-terminal-v3/launch.json",
                "742656ca51cc60e14800ab76b379de384d3341d26696f33c7c992de772eeba6d",
            ),
            (
                "/var/lib/jetstreamer/horizon-warmup223-terminal-v3/guard-stop.json",
                "27eb179b252aaeae09d39c0242c6306da3f3cb87adc53ca1e308699b0b5ba1b8",
            ),
            (
                "/var/lib/jetstreamer/horizon-cold223-input-proof-v1/input-proof.json",
                "b0ee9a5136e075d0c1605573cc78e154a3059351e0e0f961068211f344c5387f",
            ),
        ]
        .into_iter()
        .map(|(path, sha256)| Evidence {
            path: path.into(),
            sha256: sha256.into(),
        })
        .collect();
        plan
    }

    #[test]
    fn failed_warmup_cleanup_cannot_borrow_a_live_or_different_attempt() {
        let mut plan = warmup_plan();
        validate_plan(&plan).unwrap();
        plan.run_root =
            "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-prefix-warmup-5072b7ba-v4"
                .into();
        plan.targets = vec![plan.run_root.join("scratch")];
        assert!(validate_plan(&plan).is_err());
        let mut plan = warmup_plan();
        plan.producer.invocation_id = "a".repeat(32);
        assert!(validate_plan(&plan).is_err());
        let mut plan = warmup_plan();
        plan.restore_only_probe = true;
        assert!(validate_plan(&plan).is_err());
        let mut plan = warmup_plan();
        plan.outcome.sha256 = "a".repeat(64);
        assert!(validate_plan(&plan).is_err());
        let mut plan = warmup_plan();
        plan.evidence.pop();
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn failed_warmup_retains_receipts_output_and_run_root() {
        for name in ["", "receipts", "output", "scratch/child"] {
            let mut plan = warmup_plan();
            plan.targets = vec![plan.run_root.join(name)];
            assert!(validate_plan(&plan).is_err());
        }
        let mut plan = warmup_plan();
        plan.inactive_units.clear();
        assert!(validate_plan(&plan).is_err());
        let plan = warmup_plan();
        assert!(validate_warmup223_outcome(&plan, &json!({"success":true})).is_err());
    }

    fn restore_plan() -> Plan {
        let root = PathBuf::from(
            "/home/ubuntu/.jetstreamer-private/checkpoint-restore-probe-213-example-v1",
        );
        Plan {
            schema: PLAN_SCHEMA.into(),
            restore_only_probe: true,
            warmup223_v3: false,
            private_root: "/home/ubuntu/.jetstreamer-private".into(),
            targets: vec![root.join("scratch")],
            producer: UnitExpectation {
                unit: "horizon-qualify-213-native-restore-probe-example-v1.service".into(),
                invocation_id: "a".repeat(32),
                active_state: "failed".into(),
                sub_state: "failed".into(),
                result: "signal".into(),
                exec_main_status: 15,
            },
            guard: UnitExpectation {
                unit: "horizon-native-restore-probe-213-guard-example-v1.service".into(),
                invocation_id: "b".repeat(32),
                active_state: "inactive".into(),
                sub_state: "dead".into(),
                result: "success".into(),
                exec_main_status: 0,
            },
            inactive_units: vec!["horizon-native-restore-probe-213-guard-example-v1.timer".into()],
            outcome: Evidence {
                path: root.join("outcome.json"),
                sha256: "a".repeat(64),
            },
            guard_stop_intent: Some(Evidence {
                path: root.join("guard-stop-intent.json"),
                sha256: "c".repeat(64),
            }),
            guard_stop_completion: Some(Evidence {
                path: root.join("guard-stop-completion.json"),
                sha256: "d".repeat(64),
            }),
            evidence: vec![],
            intent_receipt: root.join("intent.json"),
            completion_receipt: root.join("complete.json"),
            authority: Authority {
                local_failed_diagnostic_retirement_authorized: true,
                preserve_run_root: true,
                archive_publication_authorized: false,
                remote_mutations: false,
                r2_mutations: false,
            },
            run_root: root,
        }
    }

    #[test]
    fn native_restore_retirement_is_limited_to_exact_scratch() {
        let mut plan = restore_plan();
        validate_plan(&plan).unwrap();
        for target in [
            plan.run_root.clone(),
            plan.run_root.join("receipts"),
            plan.run_root.join("scratch-old"),
            plan.run_root.join("scratch/child"),
        ] {
            plan.targets = vec![target];
            assert!(validate_plan(&plan).is_err());
        }
    }

    #[test]
    fn native_restore_flag_cannot_retire_an_ordinary_replay() {
        let mut plan = restore_plan();
        plan.producer.unit = "horizon-qualify-213-replay.service".into();
        assert!(validate_plan(&plan).is_err());
        let mut plan = restore_plan();
        plan.run_root = plan.private_root.join("production-213-singleton");
        plan.targets = vec![plan.run_root.join("scratch")];
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn sealed_restore_evidence_may_live_in_the_root_deployment_tree() {
        let mut plan = restore_plan();
        plan.outcome.path = "/var/lib/jetstreamer/restore-evidence/outcome.json".into();
        validate_plan(&plan).unwrap();
        plan.outcome.path = "/tmp/restore-evidence/outcome.json".into();
        assert!(validate_plan(&plan).is_err());
        plan.restore_only_probe = false;
        plan.guard_stop_intent = None;
        plan.guard_stop_completion = None;
        plan.targets = vec![
            plan.run_root.join("output/compact-indexes"),
            plan.run_root.join("replay-state"),
        ];
        plan.outcome.path = "/var/lib/jetstreamer/restore-evidence/outcome.json".into();
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn legacy_retirement_still_requires_both_original_disposable_trees() {
        let mut plan = restore_plan();
        plan.restore_only_probe = false;
        plan.guard_stop_intent = None;
        plan.guard_stop_completion = None;
        assert!(validate_plan(&plan).is_err());
        plan.targets = vec![
            plan.run_root.join("output/compact-indexes"),
            plan.run_root.join("replay-state"),
        ];
        validate_plan(&plan).unwrap();
        plan.targets.pop();
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn restore_outcome_rejects_every_missing_or_false_reproducibility_gate() {
        let plan = restore_plan();
        let valid = json!({"run_root": plan.run_root, "scope": {
            "restore_only": true, "replay_entries_sent": 0, "archive_created": false,
            "snapshot_source_retained": true, "worker_source_retained": true,
            "guard_stop_completed": true}});
        validate_restore_outcome(&plan, &valid).unwrap();
        for field in [
            "restore_only",
            "replay_entries_sent",
            "archive_created",
            "snapshot_source_retained",
            "worker_source_retained",
            "guard_stop_completed",
        ] {
            let mut missing = valid.clone();
            missing["scope"].as_object_mut().unwrap().remove(field);
            assert!(validate_restore_outcome(&plan, &missing).is_err());
            let mut changed = valid.clone();
            changed["scope"][field] = match field {
                "replay_entries_sent" => json!(1),
                "archive_created" => json!(true),
                _ => json!(false),
            };
            assert!(validate_restore_outcome(&plan, &changed).is_err());
        }
        let mut wrong_root = valid;
        wrong_root["run_root"] = json!("/home/ubuntu/.jetstreamer-private/other");
        assert!(validate_restore_outcome(&plan, &wrong_root).is_err());
    }

    #[test]
    fn collected_guard_never_accepts_a_replacement_or_live_unit() {
        let mut state = UnitState {
            unit: "guard.service".into(),
            invocation_id: "".into(),
            load_state: "not-found".into(),
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            result: "success".into(),
            main_pid: 0,
            restarts: 0,
            exec_main_code: 0,
            exec_main_status: 0,
        };
        assert!(collected_guard(&state));
        state.invocation_id = "a".repeat(32);
        assert!(!collected_guard(&state));
        state.invocation_id.clear();
        state.main_pid = 1;
        assert!(!collected_guard(&state));
        state.main_pid = 0;
        state.load_state = "loaded".into();
        assert!(!collected_guard(&state));
    }

    #[test]
    fn exact_guard_stop_chain_is_required_even_after_collection() {
        let plan = restore_plan();
        let intent = json!({"schema": "jetstreamer-horizon-standalone-stop-intent-v1",
            "producer_invocation_id": plan.producer.invocation_id, "plan_sha256": "e".repeat(64),
            "sample": {"guard_invocation_id": plan.guard.invocation_id,
                "producer_invocation_id": plan.producer.invocation_id,
                "producer": {"invocation_id": plan.producer.invocation_id, "restarts": 0}}});
        let completion = json!({"schema": "jetstreamer-horizon-standalone-stop-completion-v1",
            "producer_invocation_id": plan.producer.invocation_id, "plan_sha256": "e".repeat(64),
            "intent": plan.guard_stop_intent.as_ref().unwrap().path,
            "terminal": {"invocation_id": plan.producer.invocation_id, "pid": 0, "restarts": 0,
                "active": "failed", "sub": "failed", "result": "signal"},
            "scratch_deleted": false, "r2_mutations": false, "remote_mutations": false});
        validate_restore_stop_chain(&plan, &intent, &completion).unwrap();
        for pointer in [
            "/producer_invocation_id",
            "/plan_sha256",
            "/intent",
            "/terminal/invocation_id",
            "/terminal/pid",
            "/terminal/restarts",
            "/terminal/active",
            "/terminal/result",
            "/r2_mutations",
        ] {
            let mut bad = completion.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(validate_restore_stop_chain(&plan, &intent, &bad).is_err());
        }
        let mut bad_intent = intent;
        bad_intent["sample"]["guard_invocation_id"] = json!("f".repeat(32));
        assert!(validate_restore_stop_chain(&plan, &bad_intent, &completion).is_err());
    }

    #[test]
    fn exact_boundary_reference_does_not_match_sibling() {
        let needle = b"/tmp/replay-state";
        assert!(encoded_reference(b"/tmp/replay-state/file", needle));
        assert!(encoded_reference(b"/tmp/replay-state\0", needle));
        assert!(!encoded_reference(b"/tmp/replay-state-old/file", needle));
    }

    #[test]
    fn sha256_requires_lowercase_hex() {
        assert!(valid_sha256(&"a".repeat(64)));
        assert!(!valid_sha256(&"A".repeat(64)));
        assert!(!valid_sha256(&"a".repeat(63)));
    }

    #[test]
    fn unit_names_are_constrained() {
        assert!(valid_unit_name("horizon-example.service"));
        assert!(valid_unit_name("horizon-example.timer"));
        assert!(!valid_unit_name("horizon example.service"));
        assert!(!valid_unit_name("horizon-example.path"));
    }
}
