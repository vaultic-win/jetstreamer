//! Invocation-bound disk/VMA stop guard for a non-restarting standalone replay.
//! Not an adaptive-controller guard: it never launches, restarts, or deletes work.
use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    },
};

#[path = "horizon_standalone_guard_handoff.rs"]
mod handoff;
#[path = "horizon_standalone_guard_native227.rs"]
mod native227;
#[path = "horizon_standalone_guard_root.rs"]
mod root_budget;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    invocation_id: String,
    filesystem: PathBuf,
    minimum_free_bytes: u64,
    worker_root: PathBuf,
    maximum_worker_vmas: u64,
    #[serde(default)]
    maximum_root_physical_bytes: Option<u64>,
    receipt_directory: PathBuf,
    #[serde(default)]
    bounded_measurement: Option<handoff::BoundedMeasurement>,
    #[serde(default)]
    bounded_canary: Option<BoundedCanary>,
    #[serde(default)]
    native_main: Option<native227::Binding>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundedCanary {
    expected_uid: u32,
    target_stop_intent: PathBuf,
    maximum_drainage_seconds: u64,
}

fn read_canary_evidence(path: &Path, uid: u32, maximum: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical canary evidence"
    );
    let parent = path.parent().context("canary evidence parent")?;
    let directory = fs::symlink_metadata(parent)?;
    ensure!(
        directory.is_dir() && directory.uid() == uid && directory.mode() & 0o077 == 0,
        "unsafe canary evidence directory"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == uid
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= maximum,
        "unsafe canary evidence"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "canary evidence replaced"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "canary evidence changed"
    );
    Ok(bytes)
}

fn canary_scope(unit: &str) -> Result<(&'static str, u64)> {
    ensure!(
        unit.ends_with(".service")
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid bounded-canary unit"
    );
    if unit.starts_with("horizon-qualify-225-bounded-resource-") {
        Ok((
            "jetstreamer-private-epoch225-canary-target-stop-v1",
            97_202_500,
        ))
    } else if unit.starts_with("horizon-qualify-224-bounded-resource-") {
        Ok((
            "jetstreamer-private-epoch224-canary-target-stop-v1",
            96_800_000,
        ))
    } else if unit.starts_with("horizon-qualify-205-bounded-resource-") {
        Ok((
            "jetstreamer-private-epoch205-canary-target-stop-v1",
            88_584_000,
        ))
    } else if unit.starts_with("horizon-qualify-203-bounded-resource-") {
        Ok((
            "jetstreamer-private-epoch203-canary-target-stop-v1",
            87_720_000,
        ))
    } else {
        anyhow::bail!("unknown bounded-canary unit")
    }
}

fn validate_canary_target(
    unit: &str,
    intent: &Value,
    capture: &Value,
    invocation: &str,
    root: &Path,
    now: u64,
    maximum_age: u64,
) -> Result<()> {
    let (schema, target) = canary_scope(unit)?;
    ensure!(
        intent["schema"] == schema
            && intent["invocation_id"] == invocation
            && intent["target_slot"] == target
            && intent["observed_slot"]
                .as_u64()
                .is_some_and(|s| (target..=target + 1000).contains(&s))
            && intent["child_pid"]
                .as_u64()
                .is_some_and(|p| p > 1 && p <= i32::MAX as u64)
            && intent["scratch_snapshot_captured"] == true
            && intent["external_signal"] == 0,
        "invalid canary target-stop scope"
    );
    let written = intent["written_unix_seconds"]
        .as_u64()
        .context("target-stop time")?;
    ensure!(
        written <= now && now - written <= maximum_age,
        "canary drainage interval expired or future-dated"
    );
    let capture_path = root.join("receipts/target-capture.json");
    ensure!(
        intent["capture_path"].as_str() == capture_path.to_str(),
        "wrong canary capture path"
    );
    let expected = intent["capture_canonical_json_sha256"]
        .as_str()
        .context("capture digest")?;
    ensure!(
        digest(expected) && sha(&serde_json::to_vec(capture)?) == expected,
        "canary capture digest mismatch"
    );
    let scratch = root.join("scratch");
    let accounts = Path::new(
        capture["accounts_state"]["path"]
            .as_str()
            .context("accounts-state path")?,
    );
    ensure!(
        capture["scratch"]["path"].as_str() == scratch.to_str()
            && accounts.starts_with(&scratch)
            && accounts.file_name().is_some_and(|n| n == "accounts-state")
            && !accounts.components().any(|c| matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            ))
            && capture["scratch"]["physical_bytes"]
                .as_u64()
                .is_some_and(|b| b <= 256u64 << 30)
            && capture["accounts_state"]["regular_files"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && capture["cgroup"].as_object().is_some_and(|m| !m.is_empty()),
        "invalid captured canary resources"
    );
    Ok(())
}

fn canary_target(p: &Plan, c: &BoundedCanary, now: u64) -> Result<Option<Value>> {
    match fs::symlink_metadata(&c.target_stop_intent) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let intent_raw = read_canary_evidence(&c.target_stop_intent, c.expected_uid, 64 << 10)?;
    let capture_raw = read_canary_evidence(
        &p.worker_root.join("receipts/target-capture.json"),
        c.expected_uid,
        64 << 20,
    )?;
    let intent: Value = serde_json::from_slice(&intent_raw)?;
    let capture: Value = serde_json::from_slice(&capture_raw)?;
    validate_canary_target(
        &p.unit,
        &intent,
        &capture,
        &p.invocation_id,
        &p.worker_root,
        now,
        c.maximum_drainage_seconds,
    )?;
    Ok(Some(
        json!({"intent":intent,"intent_sha256":sha(&intent_raw),"capture_sha256":sha(&capture_raw)}),
    ))
}

fn pinned_canary_target(
    p: &Plan,
    c: &BoundedCanary,
    now: u64,
    plan_sha: &str,
) -> Result<Option<Value>> {
    let Some(evidence) = canary_target(p, c, now)? else {
        return Ok(None);
    };
    let pin_path = p.receipt_directory.join("canary-target-handoff-pin.json");
    match fs::symlink_metadata(&pin_path) {
        Ok(_) => {
            let pin: Value = serde_json::from_slice(&read_private(&pin_path)?)?;
            ensure!(
                handoff_pin_matches(&pin, plan_sha, &p.invocation_id, &evidence),
                "canary target evidence changed after first accepted observation"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => persist(
            &pin_path,
            &json!({"schema":"jetstreamer-horizon-bounded-handoff-pin-v1","plan_sha256":plan_sha,"producer_invocation_id":p.invocation_id,"target_handoff":evidence,"remote_mutations":false,"r2_mutations":false}),
        )?,
        Err(error) => return Err(error.into()),
    }
    Ok(Some(evidence))
}

fn canary_trip_reason(
    workers: usize,
    valid_target: bool,
    evidence_error: bool,
) -> Option<&'static str> {
    if evidence_error {
        Some("canary-target-evidence-failed")
    } else if workers == 0 && !valid_target {
        Some("zero-workers-before-target")
    } else {
        None
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Unit {
    load_state: String,
    invocation_id: String,
    active: String,
    sub: String,
    result: String,
    restarts: u64,
    restart_policy: String,
    kill_mode: String,
    delegated: bool,
    cgroup: String,
    pid: u64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identity(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_private(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence path"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= 1024 * 1024,
        "unsafe guard evidence"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "evidence replaced"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "guard evidence changed"
    );
    Ok(bytes)
}

fn persist(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        parent.is_absolute()
            && parent.canonicalize()? == parent
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0,
        "receipts require a canonical root-private directory"
    );
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| anyhow::anyhow!("receipt exists or cannot publish: {error}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn sample(unit: &str) -> Result<Unit> {
    let output = Command::new("systemctl").args(["show", unit, "--property=Id,LoadState,InvocationID,ActiveState,SubState,Result,NRestarts,Restart,KillMode,Delegate,ControlGroup,MainPID"]).output()?;
    ensure!(output.status.success(), "cannot observe guarded unit");
    let fields: BTreeMap<_, _> = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(|line| line.split_once('=').context("malformed unit state"))
        .collect::<Result<_>>()?;
    let get = |key| {
        fields
            .get(key)
            .copied()
            .with_context(|| format!("missing {key}"))
    };
    ensure!(
        get("Id")? == unit && matches!(get("LoadState")?, "loaded" | "not-found"),
        "unit state unavailable or mismatched"
    );
    Ok(Unit {
        load_state: get("LoadState")?.into(),
        invocation_id: get("InvocationID")?.into(),
        active: get("ActiveState")?.into(),
        sub: get("SubState")?.into(),
        result: get("Result")?.into(),
        restarts: get("NRestarts")?.parse()?,
        restart_policy: get("Restart")?.into(),
        kill_mode: get("KillMode")?.into(),
        delegated: get("Delegate")? != "no",
        cgroup: get("ControlGroup")?.into(),
        pid: get("MainPID")?.parse()?,
    })
}

fn bound(unit: &Unit, expected: &str) -> Result<()> {
    ensure!(
        unit.load_state == "loaded"
            && unit.invocation_id == expected
            && unit.restarts == 0
            && unit.restart_policy == "no"
            && unit.kill_mode == "control-group"
            && !unit.delegated,
        "invocation, restart count, or standalone restart policy changed"
    );
    Ok(())
}

fn active(unit: &Unit) -> bool {
    matches!(
        unit.active.as_str(),
        "active" | "activating" | "deactivating"
    ) && unit.pid != 0
}

fn stop_if_bound<F>(unit: &Unit, expected_invocation: &str, stop: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    bound(unit, expected_invocation)?;
    if active(unit) {
        stop()?;
    }
    Ok(())
}

fn collected(unit: &Unit) -> bool {
    unit.load_state == "not-found"
        && unit.active == "inactive"
        && unit.sub == "dead"
        && unit.pid == 0
        && unit.cgroup.is_empty()
        && unit.invocation_id.is_empty()
        && unit.restarts == 0
}

fn cgroup_pids(root: &Path) -> Result<Vec<u32>> {
    let metadata = fs::symlink_metadata(root)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "unsafe cgroup"
    );
    let mut pids = Vec::new();
    for line in fs::read_to_string(root.join("cgroup.procs"))?.lines() {
        pids.push(line.parse()?);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            pids.extend(cgroup_pids(&entry.path())?);
        }
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

fn workers(unit: &Unit, worker_root: &Path) -> Result<Vec<(u32, u64)>> {
    workers_from_roots(
        unit,
        worker_root,
        Path::new("/sys/fs/cgroup"),
        Path::new("/proc"),
    )
}

fn workers_from_roots(
    unit: &Unit,
    worker_root: &Path,
    cgroup_root: &Path,
    proc_root: &Path,
) -> Result<Vec<(u32, u64)>> {
    ensure!(
        unit.cgroup.starts_with('/')
            && !unit.cgroup.starts_with("//")
            && unit.cgroup != "/"
            && !unit
                .cgroup
                .split('/')
                .any(|part| part == ".." || part == "."),
        "unsafe cgroup path"
    );
    let mut workers = Vec::new();
    for pid in cgroup_pids(&cgroup_root.join(&unit.cgroup[1..]))? {
        let process = proc_root.join(pid.to_string());
        let executable = match fs::read_link(process.join("exe")) {
            Ok(path) => path,
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let name = executable.file_name().unwrap_or_default().to_string_lossy();
        if executable.starts_with(worker_root)
            || name.starts_with("historical-worker")
            || name.starts_with("jetstreamer-historical-worker")
        {
            ensure!(
                name == "historical-worker",
                "unexpected worker executable name"
            );
            ensure!(
                executable.starts_with(worker_root),
                "worker escaped the bound generation"
            );
            let maps = fs::read_to_string(process.join("maps"))?;
            workers.push((pid, maps.lines().count() as u64));
        }
    }
    Ok(workers)
}

fn trip_reason(
    free: u64,
    floor: u64,
    workers: &[(u32, u64)],
    max_vmas: u64,
) -> Option<&'static str> {
    if free < floor {
        Some("filesystem-floor")
    } else if workers.len() > 1 {
        Some("multiple-workers")
    } else if workers.iter().any(|(_, vmas)| *vmas > max_vmas) {
        Some("worker-vma-ceiling")
    } else {
        None
    }
}

fn measurement_trip_reason(
    free: u64,
    floor: u64,
    workers: &[(u32, u64)],
    max_vmas: u64,
    bounded_measurement: bool,
    valid_handoff: bool,
) -> Option<&'static str> {
    trip_reason(free, floor, workers, max_vmas).or_else(|| {
        (bounded_measurement && workers.is_empty() && !valid_handoff)
            .then_some("missing-or-invalid-target-handoff")
    })
}

fn intent_matches(intent: &Value, plan_sha: &str, invocation: &str) -> bool {
    intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
        && intent["plan_sha256"] == plan_sha
        && intent["producer_invocation_id"] == invocation
}

fn handoff_pin_matches(pin: &Value, plan_sha: &str, invocation: &str, handoff: &Value) -> bool {
    pin["schema"] == "jetstreamer-horizon-bounded-handoff-pin-v1"
        && pin["plan_sha256"] == plan_sha
        && pin["producer_invocation_id"] == invocation
        && pin["target_handoff"] == *handoff
        && pin["remote_mutations"] == false
        && pin["r2_mutations"] == false
}

fn supported_unit(plan: &Plan) -> bool {
    if let Some(native) = &plan.native_main {
        return plan.filesystem == Path::new("/") && native227::validate(plan, native).is_ok();
    }
    if plan.unit == "horizon-singleton-227-capped-710f6523-v1.service" {
        return cfg!(feature = "epoch227-singleton-guard")
            && plan.filesystem == Path::new("/")
            && plan.worker_root
                == Path::new("/home/ubuntu/.jetstreamer-private/singleton-227-capped-710f6523-v1")
            && plan.maximum_root_physical_bytes == Some(471_798_691_840)
            && plan.maximum_worker_vmas == 3_500_000
            && plan.bounded_measurement.is_none()
            && plan.bounded_canary.is_none();
    }
    if plan.unit.starts_with("horizon-qualify-") {
        return true;
    }
    // Only the separately admitted203 native comparator may use this namespace.
    // Do not extend this to arbitrary native units or bounded-stop exemptions.
    plan.unit == "horizon-native-203-0158-v1.service"
        && plan.worker_root
            == Path::new("/home/ubuntu/.jetstreamer-private/epoch203-native-0158-v1")
        && plan.filesystem == Path::new("/")
        && plan.minimum_free_bytes >= 2_687_830_606_739
        && plan.maximum_worker_vmas == 3_500_000
        && plan.bounded_measurement.is_none()
        && plan.bounded_canary.is_none()
        && plan.maximum_root_physical_bytes.is_none()
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(
        plan.bounded_measurement.is_none() || plan.bounded_canary.is_none(),
        "choose exactly one bounded guard profile"
    );
    if let Some(c) = &plan.bounded_canary {
        ensure!(
            canary_scope(&plan.unit).is_ok()
                && c.expected_uid == 1000
                && c.target_stop_intent == plan.worker_root.join("receipts/target-stop.json")
                && (60..=180).contains(&c.maximum_drainage_seconds),
            "invalid bounded-canary guard scope"
        );
    }
    ensure!(
        plan.schema == "jetstreamer-horizon-standalone-guard-plan-v1"
            && supported_unit(plan)
            && plan.unit.ends_with(".service")
            && plan
                .unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
            && identity(&plan.invocation_id)
            && plan.minimum_free_bytes > 0
            && plan.maximum_worker_vmas > 0,
        "invalid standalone guard plan"
    );
    ensure!(
        plan.maximum_root_physical_bytes.is_none_or(|n| n > 0),
        "root physical budget must be nonzero"
    );
    if let Some(native) = &plan.native_main {
        native227::validate(plan, native)?;
    }
    Ok(())
}

fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "guard requires root");
    let args: Vec<_> = env::args().collect();
    ensure!(
        (args.len() == 6
            || (args.len() == 7
                && matches!(
                    args[6].as_str(),
                    "--root-capability-only" | "--validate-plan-only"
                )))
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256",
        "usage: guard PLAN --plan-sha256 HEX --self-sha256 HEX [--root-capability-only]"
    );
    let capability_only = args.get(6).is_some_and(|a| a == "--root-capability-only");
    ensure!(digest(&args[3]) && digest(&args[5]), "invalid digest");
    let executable = fs::read("/proc/self/exe")?;
    ensure!(
        sha(&executable) == args[5],
        "guard executable digest mismatch"
    );
    let bytes = read_private(Path::new(&args[1]))?;
    ensure!(sha(&bytes) == args[3], "guard plan digest mismatch");
    let plan: Plan = serde_json::from_slice(&bytes)?;
    validate_plan(&plan)?;
    if args.get(6).is_some_and(|a| a == "--validate-plan-only") {
        println!(
            "{}",
            json!({"schema":"jetstreamer-horizon-standalone-static-plan-validation-v1","plan_sha256":args[3],"self_sha256":args[5],"validated":true,"unit":plan.unit,"resource_samples_taken":0,"replay_launch_authorized":false,"protective_guard_proven":false,"producer_signaled":false,"remote_mutations":false,"r2_mutations":false})
        );
        return Ok(());
    }
    ensure!(
        !capability_only
            || (plan.maximum_root_physical_bytes.is_some()
                && plan.bounded_canary.is_none()
                && plan.bounded_measurement.is_none()),
        "root capability needs an explicit own-tree budget and no target-stop profile"
    );
    for path in [&plan.filesystem, &plan.worker_root, &plan.receipt_directory] {
        ensure!(
            path.is_absolute() && path.canonicalize()? == *path && path.is_dir(),
            "guard path must be canonical directory"
        );
    }
    ensure!(
        plan.worker_root != Path::new("/") && plan.worker_root != plan.filesystem,
        "worker root must name an isolated generation"
    );
    if let Some(measurement) = &plan.bounded_measurement {
        measurement.validate(&plan.worker_root)?;
    }
    let invocation = env::var("INVOCATION_ID").context("guard must run in systemd")?;
    ensure!(identity(&invocation), "invalid guard invocation");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let intent_path = plan.receipt_directory.join("stop-intent.json");
    let completion_path = plan.receipt_directory.join("stop-completion.json");
    let intent = match fs::symlink_metadata(&intent_path) {
        Ok(_) => {
            let intent: Value = serde_json::from_slice(&read_private(&intent_path)?)?;
            ensure!(
                intent_matches(&intent, &args[3], &plan.invocation_id),
                "foreign stop intent"
            );
            Some(intent)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let before = sample(&plan.unit)?;
    ensure!(
        !capability_only || (intent.is_none() && active(&before)),
        "root capability cannot recover stop intents or inspect a terminal owner"
    );
    // systemd may collect a successfully stopped transient unit before the next
    // timer fire. Absence is accepted only for a previously authenticated stop
    // intent, with the exact old cgroup now absent. Never apply this exception
    // to a new live invocation under the same unit name.
    if collected(&before) {
        let intent = intent
            .as_ref()
            .context("guarded producer disappeared without a stop intent")?;
        let cgroup = intent
            .pointer("/sample/producer/cgroup")
            .and_then(Value::as_str)
            .context("stop intent omits original cgroup")?;
        ensure!(
            cgroup.starts_with('/')
                && cgroup != "/"
                && !cgroup.split('/').any(|p| p == "." || p == ".."),
            "unsafe prior cgroup"
        );
        match fs::symlink_metadata(Path::new("/sys/fs/cgroup").join(&cgroup[1..])) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => anyhow::bail!("original cgroup still present or unreadable"),
        }
        match fs::symlink_metadata(&completion_path) {
            Ok(_) => {
                let completion: Value = serde_json::from_slice(&read_private(&completion_path)?)?;
                ensure!(
                    completion["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
                        && completion["plan_sha256"] == args[3]
                        && completion["producer_invocation_id"] == plan.invocation_id,
                    "foreign stop completion"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => persist(
                &completion_path,
                &json!({"schema":"jetstreamer-horizon-standalone-stop-completion-v1","plan_sha256":args[3],
                    "producer_invocation_id":plan.invocation_id,"terminal":before,"intent":intent_path,
                    "prior_cgroup_verified_absent":cgroup,"scratch_deleted":false,"remote_mutations":false,"r2_mutations":false}),
            )?,
            Err(error) => return Err(error.into()),
        }
        let receipt = json!({"schema":"jetstreamer-horizon-standalone-stop-revalidated-v1","plan_sha256":args[3],
            "producer_invocation_id":plan.invocation_id,"guard_invocation_id":invocation,"terminal":before,
            "prior_cgroup_verified_absent":cgroup,"completion":completion_path,"remote_mutations":false,"r2_mutations":false});
        persist(
            &plan
                .receipt_directory
                .join(format!("sample-{invocation}.json")),
            &receipt,
        )?;
        println!("{receipt}");
        return Ok(());
    }
    bound(&before, &plan.invocation_id)?;
    let filesystem = std::ffi::CString::new(plan.filesystem.as_os_str().as_encoded_bytes())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(filesystem.as_ptr(), &mut stat) } == 0,
        "statvfs failed"
    );
    let available = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .context("free bytes overflow")?;
    let observed_workers = if active(&before) {
        if let Some(native) = &plan.native_main {
            native227::observe(&before, native)
        } else {
            workers(&before, &plan.worker_root)
        }
    } else {
        Ok(Vec::new())
    };
    // Unreadable maps, escaped workers, and cgroup failures are reasons to stop,
    // never evidence that the unit has no worker.
    let error = observed_workers.as_ref().err().map(ToString::to_string);
    let worker_list = observed_workers.unwrap_or_default();
    let root_observation = if active(&before) {
        plan.maximum_root_physical_bytes
            .map(|limit| root_budget::observe(&plan.worker_root, limit))
    } else {
        None
    };
    let root_error = root_observation
        .as_ref()
        .and_then(|r| r.as_ref().err())
        .map(ToString::to_string);
    let root_observation = root_observation.and_then(Result::ok);
    let target_observation = if active(&before) && error.is_none() {
        plan.bounded_canary
            .as_ref()
            .map(|c| pinned_canary_target(&plan, c, now, &args[3]))
    } else {
        None
    };
    let target_error = target_observation
        .as_ref()
        .and_then(|r| r.as_ref().err())
        .map(ToString::to_string);
    let valid_target = target_observation
        .as_ref()
        .is_some_and(|r| matches!(r, Ok(Some(_))));
    let handoff = if active(&before) && error.is_none() && worker_list.is_empty() {
        plan.bounded_measurement
            .as_ref()
            .map(|measurement| -> Result<Value> {
                let evidence = measurement.read(&plan.invocation_id, now)?;
                let pin_path = plan.receipt_directory.join("target-handoff-pin.json");
                match fs::symlink_metadata(&pin_path) {
                    Ok(_) => {
                        let pin: Value = serde_json::from_slice(&read_private(&pin_path)?)?;
                        ensure!(handoff_pin_matches(&pin,&args[3],&plan.invocation_id,&evidence),
                            "target handoff changed after first workerless observation");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => persist(
                        &pin_path,
                        &json!({"schema":"jetstreamer-horizon-bounded-handoff-pin-v1",
                            "plan_sha256":args[3],"producer_invocation_id":plan.invocation_id,
                            "target_handoff":evidence,"remote_mutations":false,"r2_mutations":false}),
                    )?,
                    Err(error) => return Err(error.into()),
                }
                Ok(evidence)
            })
    } else {
        None
    };
    let handoff_error = handoff
        .as_ref()
        .and_then(|result| result.as_ref().err())
        .map(ToString::to_string);
    let handoff_evidence = handoff.and_then(Result::ok);
    let reason = if intent.is_some() {
        Some("resume-stop-intent")
    } else if error.is_some() {
        Some("worker-observation-failed")
    } else if root_error.is_some() {
        Some("root-physical-observation-failed")
    } else if root_observation.as_ref().is_some_and(|r| r.exceeds_budget) {
        Some("root-physical-budget")
    } else if active(&before) {
        measurement_trip_reason(
            available,
            plan.minimum_free_bytes,
            &worker_list,
            plan.maximum_worker_vmas,
            plan.bounded_measurement.is_some(),
            handoff_evidence.is_some(),
        )
        .or_else(|| {
            plan.bounded_canary.as_ref().and_then(|_| {
                canary_trip_reason(worker_list.len(), valid_target, target_error.is_some())
            })
        })
    } else {
        None
    };
    let after = sample(&plan.unit)?;
    bound(&after, &plan.invocation_id)?;
    ensure!(
        before == after,
        "producer identity or state changed during guard sample"
    );
    let evidence = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1", "recorded_unix_seconds":now,
        "plan":args[1],"plan_sha256":args[3],"guard_sha256":args[5],"guard_invocation_id":invocation,
        "producer":after,"producer_invocation_id":plan.invocation_id,"available_bytes":available,
        "minimum_free_bytes":plan.minimum_free_bytes,"maximum_worker_vmas":plan.maximum_worker_vmas,
        "producer_stop_enabled":!capability_only,"maximum_root_physical_bytes":plan.maximum_root_physical_bytes,
        "root_physical_observation":root_observation,"root_physical_observation_error":root_error,
        "workers":worker_list,"worker_observation_error":error,"trip_reason":reason,
        "bounded_measurement":plan.bounded_measurement.is_some(),
        "bounded_canary":plan.bounded_canary,"canary_target_stop_valid":valid_target,"canary_target_error":target_error,
        "target_handoff":handoff_evidence,"target_handoff_error":handoff_error,
        "native_main":plan.native_main,"remote_mutations":false,"r2_mutations":false,"scratch_deleted":false});
    if publish_root_capability(capability_only, &evidence, reason, |capability| {
        persist(
            &plan
                .receipt_directory
                .join(format!("root-capability-{invocation}.json")),
            capability,
        )?;
        println!("{capability}");
        Ok(())
    })? {
        return Ok(());
    }
    persist(
        &plan
            .receipt_directory
            .join(format!("sample-{invocation}.json")),
        &evidence,
    )?;
    if let Some(reason) = reason {
        if intent.is_none() {
            persist(
                &intent_path,
                &json!({"schema":"jetstreamer-horizon-standalone-stop-intent-v1",
                "plan_sha256":args[3],"producer_invocation_id":plan.invocation_id,"reason":reason,"sample":evidence}),
            )?;
        }
        let current = sample(&plan.unit)?;
        stop_if_bound(&current, &plan.invocation_id, || {
            let stopped = Command::new("systemctl")
                .args(["stop", &plan.unit])
                .output()?;
            ensure!(
                stopped.status.success(),
                "guard could not stop producer: {}",
                String::from_utf8_lossy(&stopped.stderr)
            );
            Ok(())
        })?;
        let terminal = sample(&plan.unit)?;
        if collected(&terminal) {
            ensure!(
                current.cgroup.starts_with('/')
                    && current.cgroup != "/"
                    && !current.cgroup.split('/').any(|p| p == "." || p == ".."),
                "unsafe stopped cgroup"
            );
            match fs::symlink_metadata(Path::new("/sys/fs/cgroup").join(&current.cgroup[1..])) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => anyhow::bail!("stopped producer cgroup remains present or unreadable"),
            }
        } else {
            bound(&terminal, &plan.invocation_id)?;
        }
        ensure!(
            !active(&terminal) && terminal.pid == 0,
            "producer remains live after stop"
        );
        match fs::symlink_metadata(&completion_path) {
            Ok(_) => {
                let completion: Value = serde_json::from_slice(&read_private(&completion_path)?)?;
                ensure!(
                    completion["plan_sha256"] == args[3]
                        && completion["producer_invocation_id"] == plan.invocation_id,
                    "foreign stop completion"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => persist(
                &completion_path,
                &json!({"schema":"jetstreamer-horizon-standalone-stop-completion-v1","plan_sha256":args[3],
                    "producer_invocation_id":plan.invocation_id,"terminal":terminal,"intent":intent_path,
                    "scratch_deleted":false,"remote_mutations":false,"r2_mutations":false}),
            )?,
            Err(error) => return Err(error.into()),
        }
    }
    println!("{evidence}");
    Ok(())
}

// A successful capability is handled here; a failed capability propagates an
// error here. Neither outcome can fall through to the protective stop path.
fn publish_root_capability<F>(
    enabled: bool,
    evidence: &Value,
    reason: Option<&str>,
    publish: F,
) -> Result<bool>
where
    F: FnOnce(&Value) -> Result<()>,
{
    if !enabled {
        return Ok(false);
    }
    let capability = json!({"schema":"jetstreamer-horizon-root-budget-capability-v1",
        "sample":evidence,"passed":reason.is_none(),"producer_signaled":false,
        "stop_authorized":false,"protective_guard_proven":false,"remote_mutations":false,"r2_mutations":false});
    publish(&capability)?;
    ensure!(
        reason.is_none(),
        "root budget capability failed; producer was not signaled"
    );
    Ok(true)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_capability_never_falls_through_to_the_producer_stop_path() {
        use std::cell::Cell;
        let published = Cell::new(false);
        assert!(
            !publish_root_capability(false, &json!({}), Some("reserve"), |_| {
                published.set(true);
                Ok(())
            })
            .unwrap()
        );
        assert!(!published.get());
        assert!(
            publish_root_capability(true, &json!({"producer_stop_enabled":false}), None, |r| {
                assert_eq!(r["passed"], true);
                assert_eq!(r["stop_authorized"], false);
                published.set(true);
                Ok(())
            })
            .unwrap()
        );
        assert!(published.get());
        assert!(
            publish_root_capability(true, &json!({}), Some("root-physical-budget"), |r| {
                assert_eq!(r["passed"], false);
                assert_eq!(r["protective_guard_proven"], false);
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn complete_native_plans_pass_the_same_validator_used_before_runtime_observation() {
        for (unit, root, exe, sha, enabled) in [
            (
                "archive-207-v1616-native-input-actual-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input207-v1616-capped-v1",
                "/var/lib/jetstreamer/horizon-207-native-input-optimized-3a2a-v1/native-input-test",
                "3a2a21e2987ee7c66785bfc64f1caaf4dfc000871ef692278ed83b3f63c65948",
                cfg!(feature = "epoch207-native-main-guard"),
            ),
            (
                "horizon-native-input-227-capped-710f6523-v1.service",
                "/home/ubuntu/.jetstreamer-private/native-input227-v1620-capped-v1",
                "/var/lib/jetstreamer/horizon-227-native-test-optimized-v1/native-input-test",
                "1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3",
                cfg!(feature = "epoch227-native-main-guard"),
            ),
        ] {
            let value = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":unit,"invocation_id":"a".repeat(32),
                "filesystem":"/","minimum_free_bytes":1,"worker_root":root,"maximum_worker_vmas":3500000,
                "maximum_root_physical_bytes":300_000_000_000u64,"receipt_directory":"/sealed/receipts",
                "native_main":{"executable":exe,"sha256":sha,"main_pid":42}});
            let plan: Plan = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(validate_plan(&plan).is_ok(), enabled, "{unit}");
            for (pointer, replacement) in [
                ("/schema", json!("unknown")),
                ("/unit", json!("horizon-qualify-unknown.service")),
                ("/invocation_id", json!("invalid")),
                ("/filesystem", json!("/other")),
                ("/minimum_free_bytes", json!(0)),
                ("/worker_root", json!("/other")),
                ("/maximum_worker_vmas", json!(1)),
                ("/maximum_root_physical_bytes", json!(1)),
                ("/native_main/executable", json!("/other")),
                ("/native_main/sha256", json!("b".repeat(64))),
                ("/native_main/main_pid", json!(1)),
                ("/native_main", Value::Null),
            ] {
                let mut bad = value.clone();
                *bad.pointer_mut(pointer).unwrap() = replacement;
                let bad: Plan = serde_json::from_value(bad).unwrap();
                assert!(validate_plan(&bad).is_err(), "{unit}:{pointer}");
            }
        }
    }
    #[test]
    fn full227_plan_requires_its_separate_feature_and_complete_resource_tuple() {
        let value = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1",
            "unit":"horizon-singleton-227-capped-710f6523-v1.service","invocation_id":"a".repeat(32),
            "filesystem":"/","minimum_free_bytes":1,
            "worker_root":"/home/ubuntu/.jetstreamer-private/singleton-227-capped-710f6523-v1",
            "maximum_worker_vmas":3500000,"maximum_root_physical_bytes":471_798_691_840u64,
            "receipt_directory":"/sealed/receipts"});
        let plan: Plan = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            validate_plan(&plan).is_ok(),
            cfg!(feature = "epoch227-singleton-guard")
        );
        for (pointer, replacement) in [
            ("/schema", json!("unknown")),
            ("/unit", json!("horizon-singleton-228-capped.service")),
            ("/invocation_id", json!("invalid")),
            ("/filesystem", json!("/other")),
            ("/minimum_free_bytes", json!(0)),
            ("/worker_root", json!("/other")),
            ("/maximum_worker_vmas", json!(3_500_001)),
            ("/maximum_root_physical_bytes", json!(300_000_000_000u64)),
        ] {
            let mut bad = value.clone();
            *bad.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                validate_plan(&serde_json::from_value(bad).unwrap()).is_err(),
                "{pointer}"
            );
        }
        for (key, replacement) in [
            (
                "bounded_measurement",
                json!({"producer_uid":1000,"target_slot":98495999,"intent_path":"/tmp/intent","maximum_drain_seconds":180}),
            ),
            (
                "bounded_canary",
                json!({"expected_uid":1000,"target_stop_intent":"/tmp/intent","maximum_drainage_seconds":180}),
            ),
            (
                "native_main",
                json!({"executable":"/other","sha256":"a".repeat(64),"main_pid":42}),
            ),
        ] {
            let mut bad = value.clone();
            bad[key] = replacement;
            let bad: Plan = serde_json::from_value(bad).unwrap();
            assert!(validate_plan(&bad).is_err(), "{key}");
        }
    }
    #[test]
    fn native203_guard_namespace_is_exact_and_keeps_all_resource_gates() {
        let mut p = Plan {
            schema: "jetstreamer-horizon-standalone-guard-plan-v1".into(),
            unit: "horizon-native-203-0158-v1.service".into(),
            invocation_id: "a".repeat(32),
            filesystem: "/".into(),
            minimum_free_bytes: 2_687_830_606_739,
            worker_root: "/home/ubuntu/.jetstreamer-private/epoch203-native-0158-v1".into(),
            maximum_worker_vmas: 3_500_000,
            maximum_root_physical_bytes: None,
            native_main: None,
            receipt_directory: "/sealed/receipts".into(),
            bounded_measurement: None,
            bounded_canary: None,
        };
        assert!(supported_unit(&p));
        p.unit = "horizon-native-203-other.service".into();
        assert!(!supported_unit(&p));
        p.unit = "horizon-native-203-0158-v1.service".into();
        p.minimum_free_bytes -= 1;
        assert!(!supported_unit(&p));
        p.minimum_free_bytes += 1;
        p.maximum_worker_vmas += 1;
        assert!(!supported_unit(&p));
        p.maximum_worker_vmas -= 1;
        p.worker_root = "/home/ubuntu/.jetstreamer-private/other".into();
        assert!(!supported_unit(&p));
        p.worker_root = "/home/ubuntu/.jetstreamer-private/epoch203-native-0158-v1".into();
        p.bounded_canary = Some(BoundedCanary {
            expected_uid: 1000,
            target_stop_intent: "/tmp/intent".into(),
            maximum_drainage_seconds: 180,
        });
        assert!(!supported_unit(&p));
    }
    fn unit() -> Unit {
        Unit {
            load_state: "loaded".into(),
            invocation_id: "a".repeat(32),
            active: "active".into(),
            sub: "running".into(),
            result: "success".into(),
            restarts: 0,
            restart_policy: "no".into(),
            kill_mode: "control-group".into(),
            delegated: false,
            cgroup: "/system.slice/test.service".into(),
            pid: 1,
        }
    }

    #[test]
    fn actual_stop_callsite_never_signals_replacement_or_restarted_invocation() {
        let calls = std::cell::Cell::new(0);
        let stop = || {
            calls.set(calls.get() + 1);
            Ok(())
        };
        let mut state = unit();
        assert!(stop_if_bound(&state, &"b".repeat(32), stop).is_err());
        assert_eq!(calls.get(), 0);
        state.restarts = 1;
        assert!(stop_if_bound(&state, &"a".repeat(32), stop).is_err());
        assert_eq!(calls.get(), 0);
        state.restarts = 0;
        stop_if_bound(&state, &"a".repeat(32), stop).unwrap();
        assert_eq!(calls.get(), 1);
        state.active = "inactive".into();
        state.sub = "dead".into();
        state.pid = 0;
        stop_if_bound(&state, &"a".repeat(32), stop).unwrap();
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn first_workerless_handoff_is_pinned_and_cannot_be_renewed_or_transferred() {
        let handoff = json!({"sha256":"first","written_unix_seconds":1000.25});
        let pin = json!({"schema":"jetstreamer-horizon-bounded-handoff-pin-v1",
            "plan_sha256":"plan","producer_invocation_id":"a".repeat(32),
            "target_handoff":handoff,"remote_mutations":false,"r2_mutations":false});
        assert!(handoff_pin_matches(&pin, "plan", &"a".repeat(32), &handoff));
        let renewed = json!({"sha256":"new","written_unix_seconds":1100.25});
        assert!(!handoff_pin_matches(
            &pin,
            "plan",
            &"a".repeat(32),
            &renewed
        ));
        assert!(!handoff_pin_matches(
            &pin,
            "plan",
            &"b".repeat(32),
            &handoff
        ));
        assert!(!handoff_pin_matches(
            &pin,
            "other-plan",
            &"a".repeat(32),
            &handoff
        ));
    }

    #[test]
    fn target_handoff_only_relaxes_zero_worker_draining_not_any_safety_trip() {
        assert_eq!(
            measurement_trip_reason(100, 100, &[], 500, false, false),
            None
        );
        assert_eq!(
            measurement_trip_reason(100, 100, &[], 500, true, false),
            Some("missing-or-invalid-target-handoff")
        );
        assert_eq!(
            measurement_trip_reason(100, 100, &[], 500, true, true),
            None
        );
        assert_eq!(
            measurement_trip_reason(99, 100, &[], 500, true, true),
            Some("filesystem-floor")
        );
        assert_eq!(
            measurement_trip_reason(100, 100, &[(1, 1), (2, 1)], 500, true, true),
            Some("multiple-workers")
        );
        assert_eq!(
            measurement_trip_reason(100, 100, &[(1, 501)], 500, true, true),
            Some("worker-vma-ceiling")
        );
        assert_eq!(
            measurement_trip_reason(100, 100, &[(1, 500)], 500, true, false),
            None
        );
    }

    #[test]
    fn nested_fake_cgroup_recognizes_bound_copy_and_rejects_unreadable_or_escaped_workers() {
        let root = tempfile::tempdir().unwrap();
        let cgroups = root.path().join("cgroups");
        let proc = root.path().join("proc");
        let scratch = root.path().join("scratch");
        let group = cgroups.join("system.slice/test.service");
        fs::create_dir_all(group.join("nested")).unwrap();
        fs::create_dir_all(proc.join("7")).unwrap();
        fs::write(group.join("cgroup.procs"), "7\n").unwrap();
        fs::write(group.join("nested/cgroup.procs"), "7\n").unwrap();
        std::os::unix::fs::symlink(
            scratch.join(".historical-runtime/test/bound-worker/historical-worker"),
            proc.join("7/exe"),
        )
        .unwrap();
        fs::write(proc.join("7/maps"), "map1\nmap2\n").unwrap();
        let state = unit();
        assert_eq!(
            workers_from_roots(&state, &scratch, &cgroups, &proc).unwrap(),
            vec![(7, 2)]
        );
        fs::remove_file(proc.join("7/maps")).unwrap();
        assert!(workers_from_roots(&state, &scratch, &cgroups, &proc).is_err());
        fs::write(proc.join("7/maps"), "map\n").unwrap();
        fs::remove_file(proc.join("7/exe")).unwrap();
        std::os::unix::fs::symlink(
            root.path()
                .join("scratch-store8/bound-worker/historical-worker"),
            proc.join("7/exe"),
        )
        .unwrap();
        assert!(workers_from_roots(&state, &scratch, &cgroups, &proc).is_err());
        fs::remove_file(proc.join("7/exe")).unwrap();
        std::os::unix::fs::symlink(
            scratch.join("bound-worker/historical-worker"),
            proc.join("7/exe"),
        )
        .unwrap();
        fs::create_dir_all(proc.join("8")).unwrap();
        fs::write(proc.join("8/maps"), "map\n").unwrap();
        std::os::unix::fs::symlink(
            scratch.join("bound-worker/historical-worker"),
            proc.join("8/exe"),
        )
        .unwrap();
        fs::write(group.join("nested/cgroup.procs"), "7\n8\n").unwrap();
        assert_eq!(
            workers_from_roots(&state, &scratch, &cgroups, &proc)
                .unwrap()
                .len(),
            2
        );
        let mut escaped = state;
        escaped.cgroup = "//system.slice/test.service".into();
        assert!(workers_from_roots(&escaped, &scratch, &cgroups, &proc).is_err());
    }
    #[test]
    fn canary_zero_worker_exception_requires_fresh_valid_target_evidence() {
        assert_eq!(canary_trip_reason(1, false, false), None);
        assert_eq!(
            canary_trip_reason(0, false, false),
            Some("zero-workers-before-target")
        );
        assert_eq!(canary_trip_reason(0, true, false), None);
        assert_eq!(
            canary_trip_reason(0, true, true),
            Some("canary-target-evidence-failed")
        );
        assert_eq!(
            canary_trip_reason(1, false, true),
            Some("canary-target-evidence-failed")
        );
        assert_eq!(
            trip_reason(100, 100, &[(1, 1), (2, 1)], 500),
            Some("multiple-workers")
        );
    }
    fn target_fixture(root: &Path) -> (Value, Value) {
        let capture = json!({"scratch":{"path":root.join("scratch"),"physical_bytes":4096},"accounts_state":{"path":root.join("scratch/runtime/accounts-state"),"regular_files":1},"cgroup":{"memory.current":"100\n"}});
        let intent = json!({"schema":"jetstreamer-private-epoch225-canary-target-stop-v1","invocation_id":"a".repeat(32),"target_slot":97202500,"observed_slot":97202505,"child_pid":123,"written_unix_seconds":1000,"scratch_snapshot_captured":true,"external_signal":0,"capture_path":root.join("receipts/target-capture.json"),"capture_canonical_json_sha256":sha(&serde_json::to_vec(&capture).unwrap())});
        (intent, capture)
    }
    #[test]
    fn canary_target_binds_scope_time_capture_and_absence_of_external_signal() {
        let root = Path::new("/private/canary");
        let (intent, capture) = target_fixture(root);
        validate_canary_target(
            "horizon-qualify-225-bounded-resource-test.service",
            &intent,
            &capture,
            &"a".repeat(32),
            root,
            1100,
            180,
        )
        .unwrap();
        assert!(
            validate_canary_target(
                "horizon-qualify-225-bounded-resource-test.service",
                &intent,
                &capture,
                &"b".repeat(32),
                root,
                1100,
                180
            )
            .is_err()
        );
        assert!(
            validate_canary_target(
                "horizon-qualify-225-bounded-resource-test.service",
                &intent,
                &capture,
                &"a".repeat(32),
                root,
                999,
                180
            )
            .is_err()
        );
        assert!(
            validate_canary_target(
                "horizon-qualify-225-bounded-resource-test.service",
                &intent,
                &capture,
                &"a".repeat(32),
                root,
                1181,
                180
            )
            .is_err()
        );
        for (key, value) in [
            ("target_slot", json!(97202501)),
            ("observed_slot", json!(97202500 - 1)),
            ("external_signal", json!(2)),
            ("scratch_snapshot_captured", json!(false)),
            ("child_pid", json!(1)),
            ("capture_path", json!("/other")),
            ("capture_canonical_json_sha256", json!("0".repeat(64))),
        ] {
            let mut bad = intent.clone();
            bad[key] = value;
            assert!(
                validate_canary_target(
                    "horizon-qualify-225-bounded-resource-test.service",
                    &bad,
                    &capture,
                    &"a".repeat(32),
                    root,
                    1100,
                    180
                )
                .is_err(),
                "{key}"
            );
        }
        let mut substituted = capture.clone();
        substituted["accounts_state"]["regular_files"] = json!(2);
        assert!(
            validate_canary_target(
                "horizon-qualify-225-bounded-resource-test.service",
                &intent,
                &substituted,
                &"a".repeat(32),
                root,
                1100,
                180
            )
            .is_err()
        );
        let mut escaped = capture.clone();
        escaped["accounts_state"]["path"] = json!("/other/accounts-state");
        let mut forged = intent.clone();
        forged["capture_canonical_json_sha256"] =
            json!(sha(&serde_json::to_vec(&escaped).unwrap()));
        assert!(
            validate_canary_target(
                "horizon-qualify-225-bounded-resource-test.service",
                &forged,
                &escaped,
                &"a".repeat(32),
                root,
                1100,
                180
            )
            .is_err()
        );
    }
    #[test]
    fn epoch224_target_handoff_is_separate_bounded_and_cannot_be_renewed() {
        let root = Path::new("/private/canary");
        let (mut intent, capture) = target_fixture(root);
        let unit = "horizon-qualify-224-bounded-resource-test.service";
        assert!(
            validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1100, 180)
                .is_err()
        );
        intent["schema"] = json!("jetstreamer-private-epoch224-canary-target-stop-v1");
        intent["target_slot"] = json!(96_800_000);
        intent["observed_slot"] = json!(96_800_005);
        validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1100, 180).unwrap();
        for other in [
            "horizon-qualify-203-bounded-resource-test.service",
            "horizon-qualify-225-bounded-resource-test.service",
        ] {
            assert!(
                validate_canary_target(other, &intent, &capture, &"a".repeat(32), root, 1100, 180)
                    .is_err()
            );
        }
        assert!(
            validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1181, 180)
                .is_err()
        );
        intent["observed_slot"] = json!(96_801_001);
        assert!(
            validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1100, 180)
                .is_err()
        );
    }

    #[test]
    fn epoch203_target_cannot_borrow_epoch225_handoff_or_renew_it() {
        let root = Path::new("/private/canary");
        let (mut intent, capture) = target_fixture(root);
        let unit = "horizon-qualify-203-bounded-resource-test.service";
        assert!(
            validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1100, 180)
                .is_err()
        );
        intent["schema"] = json!("jetstreamer-private-epoch203-canary-target-stop-v1");
        intent["target_slot"] = json!(87_720_000);
        intent["observed_slot"] = json!(87_720_005);
        validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1100, 180).unwrap();
        assert!(
            validate_canary_target(
                "horizon-qualify-225-bounded-resource-test.service",
                &intent,
                &capture,
                &"a".repeat(32),
                root,
                1100,
                180
            )
            .is_err()
        );
        assert!(
            validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1181, 180)
                .is_err()
        );
        intent["observed_slot"] = json!(87_721_001);
        assert!(
            validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1100, 180)
                .is_err()
        );
        for bad in [
            "horizon-qualify-204-bounded-resource-test.service",
            "horizon-qualify-203-bounded-resource-test.timer",
            "horizon-qualify-203-bounded-resource-test@.service",
        ] {
            assert!(canary_scope(bad).is_err());
        }
    }

    #[test]
    fn epoch205_handoff_is_exact_fresh_and_cannot_borrow_other_canaries() {
        let root = Path::new("/private/canary");
        let (mut intent, capture) = target_fixture(root);
        let unit = "horizon-qualify-205-bounded-resource-test.service";
        assert!(
            validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1100, 180)
                .is_err()
        );
        intent["schema"] = json!("jetstreamer-private-epoch205-canary-target-stop-v1");
        intent["target_slot"] = json!(88_584_000);
        intent["observed_slot"] = json!(88_584_005);
        validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1100, 180).unwrap();
        for other in [
            "horizon-qualify-203-bounded-resource-test.service",
            "horizon-qualify-224-bounded-resource-test.service",
            "horizon-qualify-225-bounded-resource-test.service",
        ] {
            assert!(
                validate_canary_target(other, &intent, &capture, &"a".repeat(32), root, 1100, 180)
                    .is_err()
            );
        }
        assert!(
            validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1181, 180)
                .is_err()
        );
        intent["observed_slot"] = json!(88_585_001);
        assert!(
            validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1100, 180)
                .is_err()
        );
        intent["target_slot"] = json!(88_991_050);
        assert!(
            validate_canary_target(unit, &intent, &capture, &"a".repeat(32), root, 1100, 180)
                .is_err()
        );
    }
    #[test]
    fn canary_evidence_is_private_readonly_and_never_a_symlink() {
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = t.path().join("intent.json");
        fs::write(&path, b"{}").unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(read_canary_evidence(&path, uid, 100).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(read_canary_evidence(&path, uid, 100).unwrap(), b"{}");
        assert!(read_canary_evidence(&path, uid + 1, 100).is_err());
        assert!(read_canary_evidence(&path, uid, 1).is_err());
        let alias = t.path().join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(read_canary_evidence(&alias, uid, 100).is_err());
    }
    #[test]
    fn canary_capture_then_intent_handoff_is_atomic_and_substitution_fails() {
        let t = tempfile::tempdir().unwrap();
        let receipts = t.path().join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let (intent, capture) = target_fixture(t.path());
        let p:Plan=serde_json::from_value(json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":"horizon-qualify-225-bounded-resource-test.service","invocation_id":"a".repeat(32),"filesystem":"/","minimum_free_bytes":1,"worker_root":t.path(),"maximum_worker_vmas":3500000,"receipt_directory":t.path(),"bounded_canary":{"expected_uid":unsafe{libc::geteuid()},"target_stop_intent":receipts.join("target-stop.json"),"maximum_drainage_seconds":180}})).unwrap();
        let c = p.bounded_canary.as_ref().unwrap();
        let capture_path = receipts.join("target-capture.json");
        fs::write(&capture_path, serde_json::to_vec_pretty(&capture).unwrap()).unwrap();
        fs::set_permissions(&capture_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(canary_target(&p, c, 1100).unwrap().is_none());
        fs::write(
            &c.target_stop_intent,
            serde_json::to_vec_pretty(&intent).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&c.target_stop_intent, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(canary_target(&p, c, 1100).unwrap().is_some());
        let replacement = receipts.join("replacement.json");
        fs::write(&replacement, b"{}").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o400)).unwrap();
        fs::rename(replacement, &capture_path).unwrap();
        assert!(canary_target(&p, c, 1100).is_err());
    }
    #[test]
    fn pinned_canary_target_cannot_renew_its_timestamp() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let receipts = t.path().join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let (mut intent, capture) = target_fixture(t.path());
        let p:Plan=serde_json::from_value(json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":"horizon-qualify-225-bounded-resource-test.service","invocation_id":"a".repeat(32),"filesystem":"/","minimum_free_bytes":1,"worker_root":t.path(),"maximum_worker_vmas":3500000,"receipt_directory":t.path(),"bounded_canary":{"expected_uid":0,"target_stop_intent":receipts.join("target-stop.json"),"maximum_drainage_seconds":180}})).unwrap();
        let c = p.bounded_canary.as_ref().unwrap();
        let capture_path = receipts.join("target-capture.json");
        fs::write(&capture_path, serde_json::to_vec_pretty(&capture).unwrap()).unwrap();
        fs::set_permissions(&capture_path, fs::Permissions::from_mode(0o400)).unwrap();
        fs::write(
            &c.target_stop_intent,
            serde_json::to_vec_pretty(&intent).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&c.target_stop_intent, fs::Permissions::from_mode(0o400)).unwrap();
        pinned_canary_target(&p, c, 1100, "plan").unwrap().unwrap();
        pinned_canary_target(&p, c, 1100, "plan").unwrap().unwrap();
        intent["written_unix_seconds"] = json!(1100);
        let replacement = receipts.join("renewed.json");
        fs::write(&replacement, serde_json::to_vec_pretty(&intent).unwrap()).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o400)).unwrap();
        fs::rename(replacement, &c.target_stop_intent).unwrap();
        assert!(pinned_canary_target(&p, c, 1101, "plan").is_err());
    }
    #[test]
    fn nested_cgroup_census_recognizes_the_actual_copied_worker_and_maps() {
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("generation");
        fs::create_dir(&root).unwrap();
        let exe = root.join("historical-worker");
        fs::copy("/bin/sleep", &exe).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o555)).unwrap();
        let mut child = Owned(Command::new(&exe).arg("20").spawn().unwrap());
        // spawn() synchronizes exec error reporting, not this fixture's /proc
        // executable/map observations. Establish those prerequisites separately;
        // do not retry the guard under test or relax its zero-worker behavior.
        let proc_path = Path::new("/proc").join(child.0.id().to_string());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "fixture exited before readiness"
            );
            let actual_exe = fs::read_link(proc_path.join("exe"));
            let maps = fs::read_to_string(proc_path.join("maps"));
            if actual_exe.as_ref().is_ok_and(|path| path == &exe)
                && maps.as_ref().is_ok_and(|text| {
                    text.lines()
                        .any(|line| line.split_whitespace().last() == exe.to_str())
                })
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "copied-worker fixture never became observable: exe={actual_exe:?}, maps={maps:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let cg = t.path().join("actual");
        fs::create_dir(&cg).unwrap();
        fs::write(cg.join("cgroup.procs"), b"").unwrap();
        let nested = cg.join("child");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("cgroup.procs"), format!("{}\n", child.0.id())).unwrap();
        let pids = cgroup_pids(&cg).unwrap();
        assert_eq!(pids, vec![child.0.id()]);
        let mut state = unit();
        state.cgroup = "/actual".into();
        let found = workers_from_roots(&state, &root, t.path(), Path::new("/proc")).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, child.0.id());
        assert!(found[0].1 > 0);
        assert!(
            workers_from_roots(
                &state,
                &t.path().join("foreign"),
                t.path(),
                Path::new("/proc")
            )
            .is_err()
        );
    }
    #[test]
    fn changed_invocation_or_restart_policy_is_never_stopped() {
        let mut state = unit();
        assert!(bound(&state, &"a".repeat(32)).is_ok());
        assert!(bound(&state, &"b".repeat(32)).is_err());
        state.restarts = 1;
        assert!(bound(&state, &"a".repeat(32)).is_err());
        state.restarts = 0;
        state.restart_policy = "on-failure".into();
        assert!(bound(&state, &"a".repeat(32)).is_err());
        state.restart_policy = "no".into();
        state.kill_mode = "process".into();
        assert!(bound(&state, &"a".repeat(32)).is_err());
        state.kill_mode = "control-group".into();
        state.delegated = true;
        assert!(bound(&state, &"a".repeat(32)).is_err());
    }
    #[test]
    fn collected_exception_cannot_match_a_replacement_or_live_process() {
        let mut state = unit();
        state.load_state = "not-found".into();
        state.active = "inactive".into();
        state.sub = "dead".into();
        state.pid = 0;
        state.cgroup.clear();
        state.invocation_id.clear();
        assert!(collected(&state));
        state.load_state = "loaded".into();
        assert!(!collected(&state));
        state.load_state = "not-found".into();
        state.pid = 1;
        assert!(!collected(&state));
    }
    #[test]
    fn reserve_vma_and_multiple_worker_trips() {
        assert_eq!(trip_reason(99, 100, &[], 500), Some("filesystem-floor"));
        assert_eq!(
            trip_reason(100, 100, &[(1, 501)], 500),
            Some("worker-vma-ceiling")
        );
        assert_eq!(
            trip_reason(100, 100, &[(1, 1), (2, 1)], 500),
            Some("multiple-workers")
        );
        assert_eq!(trip_reason(100, 100, &[], 500), None);
        assert_eq!(trip_reason(100, 100, &[(1, 500)], 500), None);
    }
    #[test]
    fn interrupted_stop_is_bound_to_exact_plan_and_producer() {
        let intent = json!({"schema":"jetstreamer-horizon-standalone-stop-intent-v1","plan_sha256":"a","producer_invocation_id":"b"});
        assert!(intent_matches(&intent, "a", "b"));
        assert!(!intent_matches(&intent, "different", "b"));
        assert!(!intent_matches(&intent, "a", "different"));
    }
    #[test]
    fn no_clobber_receipts_preserve_existing_evidence() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("receipt.json");
        persist(&path, &json!({"first":true})).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(persist(&path, &json!({"second":true})).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}
