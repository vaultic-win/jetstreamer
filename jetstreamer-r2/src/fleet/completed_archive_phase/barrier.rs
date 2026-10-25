//! Producer-bound startup rendezvous. No child or archive work precedes release.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};
pub(super) const RELEASE: &str = "jetstreamer-completed-archive-phase-startup-release-v1";
const PLAN: &str = "jetstreamer-completed-archive-phase-startup-plan-v1";
const WAIT_SECONDS: u64 = 300;
const RELEASE_AGE: u64 = 15;
const GUARD_AGE: u64 = 30;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Startup {
    schema: String,
    epoch: u64,
    phase: Phase,
    unit: String,
    guard_unit: String,
    guard: BoundFile,
    launcher: BoundFile,
    child_argv: Vec<String>,
    child_program: BoundFile,
    interpreter: Option<BoundFile>,
    archive_directory: PathBuf,
    pub(super) release: PathBuf,
    maximum_wait_seconds: u64,
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("completed barrier integer absent: {k}"))
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("completed barrier string absent: {k}"))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub(super) fn native_text(path: impl AsRef<Path>, maximum: u64) -> Result<String> {
    let mut bytes = Vec::new();
    File::open(path.as_ref())?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "completed startup native metadata exceeds its byte bound"
    );
    Ok(String::from_utf8(bytes)?)
}
fn read_plan(binding: &BoundFile) -> Result<Startup> {
    ensure!(
        fs::symlink_metadata(&binding.path)?.mode() & 0o222 == 0,
        "completed startup plan remains writable"
    );
    Ok(serde_json::from_slice(&bound_bytes(binding, 64 << 10, 0)?)?)
}
fn plan_shape(p: &Startup) -> Result<()> {
    let role = p.phase.name();
    ensure!(
        p.schema == PLAN
            && (201..=300).contains(&p.epoch)
            && pipeline_scope(
                match p.phase {
                    Phase::Full => "full-verification",
                    Phase::Plugin => "plugin-verification",
                    Phase::Upload => "upload-readback",
                },
                &p.unit
            ) == Some(p.epoch)
            && guard_scope(&p.guard_unit, p.epoch, p.epoch)
            && p.guard_unit
                .starts_with(&format!("horizon-generic{}-{role}-protective-", p.epoch))
            && p.maximum_wait_seconds == WAIT_SECONDS
            && !p.child_argv.is_empty()
            && p.child_argv.len() <= 64
            && p.child_argv.iter().all(|a| !a.is_empty()
                && a.len() <= 4096
                && a.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/-_.=,".contains(&b)))
            && p.child_argv[0] == token(&p.child_program.path)?
            && p.release.file_name().is_some_and(|n| n == "release.json")
            && p.release.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.release
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(
                    |n| n.starts_with(&format!("horizon-generic{}-{role}-release-", p.epoch))
                ),
        "completed startup plan scope or bounded wait differs"
    );
    for b in [&p.guard, &p.launcher, &p.child_program] {
        token(&b.path)?;
        ensure!(
            is_lower_hex(&b.sha256, 64),
            "completed startup artifact digest differs"
        );
    }
    token(&p.release)?;
    token(&p.archive_directory)?;
    ensure!(
        if p.phase == Phase::Upload {
            p.interpreter.is_none()
        } else {
            p.interpreter.as_ref().is_some_and(|b| {
                b.path == Path::new("/usr/bin/bash") && is_lower_hex(&b.sha256, 64)
            })
        },
        "completed startup interpreter differs"
    );
    Ok(())
}
pub(super) fn validate_plan(s: &Spec, argv: &[String]) -> Result<Startup> {
    let p = read_plan(&s.startup_plan)?;
    plan_matches(s, &p, argv)?;
    Ok(p)
}
fn plan_matches(s: &Spec, p: &Startup, argv: &[String]) -> Result<()> {
    plan_shape(&p)?;
    let role = if s.phase == Phase::Upload {
        "progressive"
    } else {
        s.phase.name()
    };
    ensure!(
        p.epoch == s.epoch
            && p.phase == s.phase
            && p.unit == s.units[s.phase.name()]
            && p.guard_unit == s.guard_units[s.phase.name()]
            && p.guard == s.programs["guard"].artifact
            && p.launcher == s.programs["launcher"].artifact
            && p.child_program == s.programs[role].artifact
            && p.child_argv == argv
            && p.interpreter == s.interpreter
            && p.archive_directory == Path::new(singleton209::ROOT).join("output"),
        "completed startup plan changed its admitted phase/child/guard"
    );
    Ok(())
}
fn release_parent(p: &Startup) -> Result<()> {
    let parent = p
        .release
        .parent()
        .context("completed startup release parent absent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 1000
            && m.mode() & 0o7777 == 0o2750,
        "completed startup release directory must be canonical root:ubuntu mode 2750"
    );
    Ok(())
}
pub(super) fn before_admission(s: &Spec, argv: &[String]) -> Result<()> {
    let p = validate_plan(s, argv)?;
    release_parent(&p)?;
    ensure!(
        fs::symlink_metadata(&p.release).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "completed startup attempt already has a release"
    );
    Ok(())
}
pub(super) fn launcher_argv(s: &Spec) -> Vec<String> {
    vec![
        s.programs["launcher"].artifact.path.display().to_string(),
        "run-completed-archive-phase".into(),
        s.startup_plan.path.display().to_string(),
        "--spec-sha256".into(),
        s.startup_plan.sha256.clone(),
        "--self-sha256".into(),
        s.programs["launcher"].artifact.sha256.clone(),
    ]
}
fn release_custody(p: &Startup) -> Result<()> {
    release_parent(p)?;
    let m = fs::symlink_metadata(&p.release)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 1000
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o440
            && p.release.canonicalize()? == p.release,
        "completed startup release is not root:ubuntu immutable mode 0440"
    );
    Ok(())
}
fn release_value(p: &Startup, binding: Option<&BoundFile>) -> Result<(BoundFile, Value)> {
    release_custody(p)?;
    let raw = read_stable_bounded(&p.release, 4 << 20, "completed immutable startup release")?;
    let b = BoundFile {
        path: p.release.clone(),
        sha256: hex_lower(&Sha256::digest(&raw)),
    };
    ensure!(
        binding.is_none_or(|old| *old == b),
        "completed startup release digest/path differs"
    );
    release_custody(p)?;
    Ok((b, serde_json::from_slice(&raw)?))
}
pub(super) fn saved_release(s: &Spec, binding: &BoundFile) -> Result<Value> {
    let p = read_plan(&s.startup_plan)?;
    plan_shape(&p)?;
    Ok(release_value(&p, Some(binding))?.1)
}
pub(super) fn release_shape(v: &Value, s: &Spec, a: &Value) -> Result<()> {
    let p: Startup = serde_json::from_value(v["startup_plan_contents"].clone())?;
    plan_matches(
        s,
        &p,
        &serde_json::from_value::<Vec<String>>(v["argv"].clone())?,
    )?;
    let issued = n(v, "captured_unix_seconds")?;
    ensure!(
        v["schema"] == RELEASE
            && a["schema"] == RECEIPT
            && a["admitted"] == true
            && a["issuer_sha256"] == s.programs["launcher"].artifact.sha256
            && a["epoch"] == s.epoch
            && a["phase"] == s.phase.name()
            && a["startup_plan"] == private157::binding(&s.startup_plan)
            && a["argv"] == v["argv"]
            && v["epoch"] == s.epoch
            && v["phase"] == s.phase.name()
            && v["issuer_sha256"] == s.programs["launcher"].artifact.sha256
            && v["phase_spec"] == a["spec"]
            && v["admission"] == a["binding"]
            && v["admission_contents"] == *a
            && v["phase_spec_contents"] == serde_json::to_value(s)?
            && v["startup_plan"] == private157::binding(&s.startup_plan)
            && v["unit"] == p.unit
            && v["owner"]["Id"] == p.unit
            && v["owner"]["InvocationID"] == v["invocation_id"]
            && v["owner"]["ActiveState"] == "active"
            && v["owner"]["SubState"] == "running"
            && v["owner"]["NRestarts"] == "0"
            && v["owner"]["MainPID"]
                .as_str()
                .and_then(|p| p.parse::<u64>().ok())
                == v["process"]["pid"].as_u64()
            && v["process"]["executable"] == serde_json::to_value(&p.launcher.path)?
            && v["process"]["executable_sha256"] == p.launcher.sha256
            && v["process"]["cmdline"] == serde_json::to_value(launcher_argv(s))?
            && v["process"]["source_read_only_mount"] == true
            && v["process"]["pid"].as_u64().is_some_and(|n| n > 1)
            && v["process"]["start_ticks"].as_u64().is_some_and(|n| n > 0)
            && v["process"]["cgroup"] == format!("/system.slice/{}", p.unit)
            && v["owner"]["ControlGroup"] == v["process"]["cgroup"]
            && v["guard_latest_completion"]["binding"] == v["guard_sample"]
            && v["guard_sample_contents"]["plan"] == v["guard_plan"]["path"]
            && v["guard_sample_contents"]["plan_sha256"] == v["guard_plan"]["sha256"]
            && v["guard_unit"] == p.guard_unit
            && v["child_execution_authorized"] == true
            && v["publication_authorized"] == false
            && v["local_retirement_authorized"] == false
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "completed startup release lacks exact admitted waiting owner and independent guard"
    );
    launch::clock_shape(&v["process"])?;
    let native_start = n(&v["process"]["native_start_clock"], "started_unix_seconds")?;
    ensure!(
        native_start.saturating_add(1) >= n(a, "recorded_unix_seconds")?
            && native_start <= n(&v["guard_sample_contents"], "recorded_unix_seconds")?
            && v["guard_latest_completion"]["history"]["events"][0]["_BOOT_ID"]
                == string(&v["process"]["native_start_clock"], "boot_id")?.replace('-', ""),
        "completed startup waiting process and first guard clocks/boot differ"
    );
    launch::guard_shape(
        s,
        a,
        &v["guard_plan_contents"],
        &v["guard_sample_contents"],
        &v["owner"],
        issued,
    )?;
    warmup223::validate_selected_guard_events(
        &v["guard_latest_completion"]["history"],
        &v["guard_sample_contents"],
        v["guard_latest_completion"]["history"]["events"]
            .as_array()
            .context("completed startup guard events absent")?,
    )?;
    ensure!(
        v["guard_latest_completion"]["history"]["executable"]
            == serde_json::to_value(&p.guard.path)?
            && n(&v["guard_sample_contents"], "recorded_unix_seconds")? <= issued
            && issued - n(&v["guard_sample_contents"], "recorded_unix_seconds")? <= GUARD_AGE,
        "completed startup release first guard is not fresh"
    );
    Ok(())
}
pub(super) fn issue(s: &Spec, output: &Path, v: &Value) -> Result<()> {
    let p = validate_plan(
        s,
        &serde_json::from_value::<Vec<String>>(v["argv"].clone())?,
    )?;
    ensure!(
        unsafe { libc::geteuid() } == 0 && output == p.release,
        "completed startup release issuer/output differs"
    );
    release_shape(v, s, &v["admission_contents"])?;
    ensure!(
        v["startup_plan_contents"] == serde_json::to_value(&p)?,
        "completed startup release copied another startup plan"
    );
    release_parent(&p)?;
    let mut bytes = serde_json::to_vec_pretty(v)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= 4 << 20,
        "completed startup release exceeds metadata bound"
    );
    let parent = p
        .release
        .parent()
        .context("completed startup release parent absent")?;
    let mut t = tempfile::NamedTempFile::new_in(parent)?;
    ensure!(
        t.as_file().metadata()?.gid() == 1000,
        "completed startup release parent did not inherit ubuntu group"
    );
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(0o440))?;
    t.write_all(&bytes)?;
    t.as_file().sync_all()?;
    t.persist_noclobber(output)
        .map_err(|e| anyhow!("completed startup release already exists: {e}"))?;
    File::open(parent)?.sync_all()?;
    release_custody(&p)
}
pub(super) fn transition_shape(
    v: &Value,
    s: &Spec,
    a: &Value,
    process: &Value,
    owner: &Value,
    captured: u64,
) -> Result<()> {
    release_shape(v, s, a)?;
    ensure!(
        n(v, "captured_unix_seconds")? <= captured
            && v["owner"]["InvocationID"] == owner["InvocationID"]
            && v["owner"]["MainPID"] == owner["MainPID"]
            && v["process"]["pid"] == process["pid"]
            && v["process"]["start_ticks"] == process["start_ticks"]
            && v["process"]["native_start_clock"] == process["native_start_clock"]
            && v["process"]["cgroup"] == process["cgroup"],
        "completed startup exec transition changed PID/start ticks/IID/cgroup"
    );
    Ok(())
}
fn properties(name: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    use std::process::Stdio;
    let mut child = ProcessCommand::new("/usr/bin/systemctl")
        .args(["show", name, "--no-pager", &format!("--property={fields}")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    while child.try_wait()?.is_none() {
        if start.elapsed() >= Duration::from_secs(2) {
            child.kill()?;
            child.wait()?;
            bail!("completed startup manager query exceeded two seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success()
            && output.stdout.len() <= 64 << 10
            && output.stderr.len() <= 64 << 10,
        "completed startup manager reply failed or exceeded bound"
    );
    let mut p = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (k, v) = line
            .split_once('=')
            .context("completed startup manager assignment malformed")?;
        ensure!(
            p.insert(k.to_owned(), v.to_owned()).is_none(),
            "completed startup manager key repeated"
        );
    }
    Ok(p)
}
fn self_snapshot(p: &Startup) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 1000 && unsafe { libc::getegid() } == 1000,
        "completed startup barrier must remain the unprivileged phase"
    );
    let status = native_text("/proc/self/status", 64 << 10)?;
    let fields = status
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k, v.trim()))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        fields.get("NoNewPrivs") == Some(&"1")
            && ["CapEff", "CapBnd", "CapAmb"]
                .iter()
                .all(|k| fields.get(k).is_some_and(|v| v.bytes().all(|b| b == b'0'))),
        "completed startup barrier gained capabilities"
    );
    let iid = env::var("INVOCATION_ID").context("completed startup lacks native invocation")?;
    ensure!(
        is_lower_hex(&iid, 32) && iid.bytes().any(|b| b != b'0'),
        "completed startup invocation malformed"
    );
    let pid = std::process::id();
    let ticks = launch::start_ticks(&native_text("/proc/self/stat", 64 << 10)?)?;
    let group = format!("/system.slice/{}", p.unit);
    ensure!(
        native_text("/proc/self/cgroup", 64 << 10)? == format!("0::{group}\n"),
        "completed startup native cgroup differs"
    );
    let root = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    let (high, max, _) = p.phase.profile();
    let mut limits = BTreeMap::new();
    for (file, wanted) in [
        ("memory.high", high.to_string()),
        ("memory.max", max.to_string()),
        ("memory.swap.max", "0".into()),
        ("pids.max", "512".into()),
        ("cpu.max", "800000 100000".into()),
    ] {
        let actual = native_text(root.join(file), 1024)?.trim().to_owned();
        ensure!(
            actual == wanted,
            "completed startup native hard cap differs: {file}"
        );
        limits.insert(file, actual);
    }
    let mount = p
        .archive_directory
        .to_str()
        .context("completed startup archive path encoding differs")?;
    ensure!(
        native_text("/proc/self/mountinfo", 4 << 20)?
            .lines()
            .any(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                fields.get(4).copied() == Some(mount)
                    && fields
                        .get(5)
                        .is_some_and(|v| v.split(',').any(|f| f == "ro"))
            }),
        "completed startup archive mount is not read-only"
    );
    ensure!(
        UNSAFE_ENVIRONMENT
            .iter()
            .all(|key| env::var_os(key).is_none()),
        "completed startup unsafe inherited environment"
    );
    Ok(
        json!({"pid":pid,"invocation_id":iid,"start_ticks":ticks,"native_start_clock":launch::native_start_clock(ticks)?,
        "cgroup":group,"native_limits":limits}),
    )
}
fn consume_shape(p: &Startup, v: &Value, actual: &Value, at: u64) -> Result<Spec> {
    let s: Spec = serde_json::from_value(v["phase_spec_contents"].clone())?;
    shape(&s)?;
    release_shape(v, &s, &v["admission_contents"])?;
    plan_matches(&s, p, &p.child_argv)?;
    ensure!(
        v["startup_plan_contents"] == serde_json::to_value(p)?
            && n(v, "captured_unix_seconds")? <= at
            && at - n(v, "captured_unix_seconds")? <= RELEASE_AGE
            && n(&v["guard_sample_contents"], "recorded_unix_seconds")? <= at
            && at - n(&v["guard_sample_contents"], "recorded_unix_seconds")? <= GUARD_AGE
            && v["invocation_id"] == actual["invocation_id"]
            && v["process"]["pid"] == actual["pid"]
            && v["process"]["start_ticks"] == actual["start_ticks"]
            && v["process"]["native_start_clock"] == actual["native_start_clock"]
            && v["process"]["cgroup"] == actual["cgroup"]
            && v["process"]["native_limits"] == actual["native_limits"],
        "completed startup release expired or belongs to a different native process"
    );
    Ok(s)
}
fn current_manager(p: &Startup, s: &Spec, v: &Value, actual: &Value) -> Result<()> {
    let own = properties(
        &p.unit,
        "Id,LoadState,InvocationID,MainPID,NRestarts,ActiveState,SubState,ControlGroup,ExecStart,Restart,KillMode,Delegate,DropInPaths,NeedDaemonReload,Transient",
    )?;
    singleton227_capture::require(
        &own,
        &[
            ("Id", &p.unit),
            ("LoadState", "loaded"),
            ("NRestarts", "0"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("DropInPaths", ""),
            ("NeedDaemonReload", "no"),
            ("Transient", "no"),
        ],
    )?;
    ensure!(
        own["InvocationID"] == actual["invocation_id"]
            && own["MainPID"] == n(actual, "pid")?.to_string()
            && own["ControlGroup"] == actual["cgroup"]
            && assembly204_recovery::delivery_command_matches(
                &own["ExecStart"],
                &format!(
                    "{{ path={} ; argv[]={} ; ignore_errors=no }}",
                    p.launcher.path.display(),
                    launcher_argv(s).join(" ")
                )
            ),
        "completed startup manager owner/command changed"
    );
    let guard = properties(
        &p.guard_unit,
        "Id,LoadState,InvocationID,MainPID,NRestarts,ActiveState,SubState,Result,ExecMainStatus,ExecStart,DropInPaths,NeedDaemonReload,Transient",
    )?;
    singleton227_capture::require(
        &guard,
        &[
            ("Id", &p.guard_unit),
            ("LoadState", "loaded"),
            ("MainPID", "0"),
            ("NRestarts", "0"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("DropInPaths", ""),
            ("NeedDaemonReload", "no"),
            ("Transient", "no"),
        ],
    )?;
    ensure!(
        (guard["InvocationID"].is_empty()
            || guard["InvocationID"] == v["guard_sample_contents"]["guard_invocation_id"])
            && pipeline_status::same_exec_start(
                &guard["ExecStart"],
                string(
                    &v["guard_latest_completion"]["history"],
                    "expected_exec_start"
                )?
            ),
        "completed startup first guard was replaced or changed"
    );
    let timer = properties(
        &p.guard_unit.replace(".service", ".timer"),
        "ActiveState,SubState,Triggers",
    )?;
    singleton227_capture::require(
        &timer,
        &[
            ("ActiveState", "active"),
            ("SubState", "waiting"),
            ("Triggers", &p.guard_unit),
        ],
    )?;
    Ok(())
}
fn wait_release(
    deadline: Duration,
    mut elapsed: impl FnMut() -> Duration,
    mut load: impl FnMut() -> Result<Option<Value>>,
    mut pause: impl FnMut(),
) -> Result<Value> {
    loop {
        ensure!(
            elapsed() < deadline,
            "completed startup timed out without child execution"
        );
        if let Some(value) = load()? {
            return Ok(value);
        }
        pause();
    }
}
pub(super) fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 7 && args[3] == "--spec-sha256" && args[5] == "--self-sha256",
        "usage: run-completed-archive-phase STARTUP_PLAN --spec-sha256 HEX --self-sha256 HEX"
    );
    let started = Instant::now();
    let own = fs::metadata("/proc/self/exe")?;
    ensure!(
        own.uid() == 0
            && own.nlink() == 1
            && own.mode() & 0o222 == 0
            && own.len() <= 256 << 20
            && is_lower_hex(&args[6], 64)
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "completed startup helper is not immutable/self-bound"
    );
    let binding = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let p = read_plan(&binding)?;
    plan_shape(&p)?;
    ensure!(
        fs::read_link("/proc/self/exe")? == p.launcher.path && args[6] == p.launcher.sha256,
        "completed startup running launcher differs"
    );
    release_parent(&p)?;
    let actual = self_snapshot(&p)?;
    let value = wait_release(
        Duration::from_secs(p.maximum_wait_seconds),
        || started.elapsed(),
        || match fs::symlink_metadata(&p.release) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(_) => Ok(Some(release_value(&p, None)?.1)),
        },
        || std::thread::sleep(Duration::from_millis(100)),
    )?;
    let s = consume_shape(&p, &value, &actual, now()?)?;
    warmup223::validate_completed_guard_history(
        &value["guard_latest_completion"]["history"],
        &value["guard_sample_contents"],
    )?;
    ensure!(
        s.startup_plan == binding,
        "completed startup release names another startup plan"
    );
    current_manager(&p, &s, &value, &actual)?;
    ensure!(
        fs::symlink_metadata(&p.child_program.path)?.mode() & 0o222 == 0,
        "completed startup child program remains writable"
    );
    bound_bytes(&p.child_program, 256 << 20, 0)?;
    if let Some(interpreter) = &p.interpreter {
        bound_bytes(interpreter, 32 << 20, 0)?;
    }
    let final_actual = self_snapshot(&p)?;
    ensure!(
        actual == final_actual && started.elapsed() < Duration::from_secs(p.maximum_wait_seconds),
        "completed startup identity/caps changed or wait expired"
    );
    consume_shape(&p, &value, &final_actual, now()?)?;
    current_manager(&p, &s, &value, &final_actual)?;
    Err(ProcessCommand::new(&p.child_argv[0])
        .args(&p.child_argv[1..])
        .exec()
        .into())
}

#[cfg(test)]
pub(super) fn fixture_release(s: &Spec, a: &Value, base: &Value) -> Value {
    let child: Vec<String> = serde_json::from_value(base["argv"].clone()).unwrap();
    let role = if s.phase == Phase::Upload {
        "progressive"
    } else {
        s.phase.name()
    };
    let startup = Startup {
        schema: PLAN.into(),
        epoch: s.epoch,
        phase: s.phase,
        unit: s.units[s.phase.name()].clone(),
        guard_unit: s.guard_units[s.phase.name()].clone(),
        guard: s.programs["guard"].artifact.clone(),
        launcher: s.programs["launcher"].artifact.clone(),
        child_argv: child,
        child_program: s.programs[role].artifact.clone(),
        interpreter: s.interpreter.clone(),
        archive_directory: Path::new(singleton209::ROOT).join("output"),
        release: format!(
            "/var/lib/jetstreamer/horizon-generic209-{}-release-test/release.json",
            s.phase.name()
        )
        .into(),
        maximum_wait_seconds: WAIT_SECONDS,
    };
    let mut release = base.clone();
    release["schema"] = json!(RELEASE);
    release["startup_plan"] = private157::binding(&s.startup_plan);
    release["startup_plan_contents"] = serde_json::to_value(&startup).unwrap();
    release["phase_spec_contents"] = serde_json::to_value(s).unwrap();
    release["admission_contents"] = a.clone();
    release["child_execution_authorized"] = json!(true);
    release["publication_authorized"] = json!(false);
    release["local_retirement_authorized"] = json!(false);
    release["remote_mutations"] = json!(false);
    release["r2_mutations"] = json!(false);
    release["process"]["executable"] = serde_json::to_value(&startup.launcher.path).unwrap();
    release["process"]["executable_sha256"] = json!(startup.launcher.sha256);
    release["process"]["cmdline"] = json!(launcher_argv(s));
    release["captured_unix_seconds"] = json!(912);
    let sample = &release["guard_sample_contents"];
    let iid = sample["guard_invocation_id"].as_str().unwrap();
    let name = &startup.guard_unit;
    let boot = release["process"]["native_start_clock"]["boot_id"]
        .as_str()
        .unwrap()
        .replace('-', "");
    let command = format!(
        "{} {} --plan-sha256 {} --self-sha256 {}",
        startup.guard.path.display(),
        sample["plan"].as_str().unwrap(),
        sample["plan_sha256"].as_str().unwrap(),
        startup.guard.sha256
    );
    let start = json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"_BOOT_ID":boot,
        "MESSAGE_ID":"7d4958e842da4a758f6c1cdc7b36dcc5","MESSAGE":format!("Starting {name} - fixture"),"__REALTIME_TIMESTAMP":"909000000"});
    let stdout = json!({"_PID":"2","_UID":"0","_SYSTEMD_UNIT":name,"_SYSTEMD_INVOCATION_ID":iid,"_BOOT_ID":boot,
        "MESSAGE":serde_json::to_string(sample).unwrap(),"__REALTIME_TIMESTAMP":"910000000"});
    let done = json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"_BOOT_ID":boot,
        "MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{name}: Deactivated successfully."),"__REALTIME_TIMESTAMP":"910000001"});
    let finish = json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"_BOOT_ID":boot,
        "MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","JOB_RESULT":"done",
        "MESSAGE":format!("Finished {name} - [systemd-run] {command}."),"__REALTIME_TIMESTAMP":"910000002"});
    let expected = format!(
        "{{ path={} ; argv[]={command} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
        startup.guard.path.display()
    );
    release["guard_latest_completion"] = json!({"binding":release["guard_sample"],"history":{
        "schema":"jetstreamer-completed-guard-history-v1","unit":name,"guard_invocation_id":iid,
        "minimum_sampled_seconds":900,"selected_unix_seconds":912,"maximum_age_seconds":1800,"executable":startup.guard.path,
        "expected_exec_start":expected,"events":[start,stdout,done,finish]}});
    release
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    fn fixture() -> (Spec, Value, Value, Startup, Value) {
        let (s, a, child, _) = super::super::launch::tests::fixture();
        let release = child["startup_release_contents"].clone();
        let plan: Startup =
            serde_json::from_value(release["startup_plan_contents"].clone()).unwrap();
        let mut actual = release["process"].clone();
        actual["invocation_id"] = release["invocation_id"].clone();
        (s, a, release, plan, actual)
    }
    #[test]
    fn completed_barrier_plan_is_acyclic_phase_exact_and_bounded_before_release() {
        let (s, _, _, p, _) = fixture();
        plan_shape(&p).unwrap();
        plan_matches(&s, &p, &p.child_argv).unwrap();
        let unit_command = launcher_argv(&s);
        assert!(unit_command.contains(&s.startup_plan.sha256));
        let mut future_spec = s.clone();
        future_spec.unit_file.sha256 = "9".repeat(64);
        assert!(!launcher_argv(&future_spec).contains(&future_spec.unit_file.sha256));
        let value = serde_json::to_value(&p).unwrap();
        assert!(
            value.get("phase_spec").is_none()
                && value.get("admission").is_none()
                && value.get("unit_file").is_none()
        );
        for wait in [0, 299, 301, 900] {
            let mut changed = p.clone();
            changed.maximum_wait_seconds = wait;
            assert!(plan_shape(&changed).is_err());
        }
        let mut changed = p.clone();
        changed.child_argv[0] = "/sealed/foreign".into();
        assert!(plan_shape(&changed).is_err());
        let mut changed = p.clone();
        changed.guard_unit = s.guard_units["plugin"].clone();
        assert!(plan_shape(&changed).is_err());
        let mut changed = p;
        changed.launcher.sha256 = "0".repeat(64);
        assert!(plan_matches(&s, &changed, &changed.child_argv).is_err());
        let mut changed = value;
        changed["unconditional_exec"] = json!(true);
        assert!(serde_json::from_value::<Startup>(changed).is_err());
    }
    #[test]
    fn completed_barrier_first_guard_release_rejects_missing_tripped_foreign_and_stale_proof() {
        let (s, a, good, _, _) = fixture();
        release_shape(&good, &s, &a).unwrap();
        for (key, value) in [
            ("guard_latest_completion", Value::Null),
            ("child_execution_authorized", json!(false)),
            ("issuer_sha256", json!("a".repeat(64))),
            ("captured_unix_seconds", json!(942)),
        ] {
            let mut changed = good.clone();
            changed[key] = value;
            assert!(release_shape(&changed, &s, &a).is_err(), "accepted {key}");
        }
        for (key, value) in [
            ("producer_invocation_id", json!("d".repeat(32))),
            ("trip_reason", json!("floor")),
            ("producer_stop_enabled", json!(false)),
            ("workers", json!([[99, 100]])),
            ("recorded_unix_seconds", json!(899)),
            ("guard_sha256", json!("e".repeat(64))),
        ] {
            let mut changed = good.clone();
            changed["guard_sample_contents"][key] = value;
            assert!(release_shape(&changed, &s, &a).is_err(), "accepted {key}");
        }
        let mut changed = good;
        changed["guard_latest_completion"]["history"]["events"][3]["JOB_RESULT"] = json!("failed");
        assert!(release_shape(&changed, &s, &a).is_err());
    }
    #[test]
    fn completed_barrier_consumption_expires_and_requires_same_real_native_process() {
        let (s, _, good, p, actual) = fixture();
        assert_eq!(
            consume_shape(&p, &good, &actual, 920).unwrap().epoch,
            s.epoch
        );
        for at in [911, 928, 2000] {
            assert!(consume_shape(&p, &good, &actual, at).is_err());
        }
        for (key, value) in [
            ("pid", json!(43)),
            ("start_ticks", json!(124)),
            ("invocation_id", json!("d".repeat(32))),
            ("cgroup", json!("/foreign")),
        ] {
            let mut changed = actual.clone();
            changed[key] = value;
            assert!(
                consume_shape(&p, &good, &changed, 920).is_err(),
                "accepted {key}"
            );
        }
        let mut changed = actual;
        changed["native_limits"]["memory.max"] = json!("max");
        assert!(consume_shape(&p, &good, &changed, 920).is_err());
    }
    #[test]
    fn completed_barrier_exec_transition_keeps_pid_start_ticks_iid_and_cgroup() {
        let (s, a, release, _, _) = fixture();
        let (_, _, child, _) = super::super::launch::tests::fixture();
        transition_shape(&release, &s, &a, &child["process"], &child["owner"], 920).unwrap();
        for (key, value) in [
            ("pid", json!(43)),
            ("start_ticks", json!(124)),
            ("cgroup", json!("/foreign")),
        ] {
            let mut changed = child["process"].clone();
            changed[key] = value;
            assert!(
                transition_shape(&release, &s, &a, &changed, &child["owner"], 920).is_err(),
                "accepted {key}"
            );
        }
        let mut owner = child["owner"].clone();
        owner["InvocationID"] = json!("d".repeat(32));
        assert!(transition_shape(&release, &s, &a, &child["process"], &owner, 920).is_err());
        assert!(
            transition_shape(&release, &s, &a, &child["process"], &child["owner"], 911).is_err()
        );
    }
    #[test]
    fn completed_barrier_timeout_missing_and_malformed_release_never_execute_child() {
        let clock = Cell::new(0u64);
        let child_executions = Cell::new(0);
        let result = wait_release(
            Duration::from_secs(2),
            || Duration::from_secs(clock.get()),
            || Ok(None),
            || clock.set(clock.get() + 1),
        )
        .map(|_| {
            child_executions.set(1);
        });
        assert!(result.is_err());
        assert_eq!(clock.get(), 2);
        assert_eq!(child_executions.get(), 0);
        let attempts = Cell::new(0);
        let result = wait_release(
            Duration::from_secs(2),
            || Duration::ZERO,
            || {
                attempts.set(attempts.get() + 1);
                bail!("malformed immutable release")
            },
            || panic!("invalid release must not fall back or wait"),
        )
        .map(|_| {
            child_executions.set(1);
        });
        assert!(result.is_err());
        assert_eq!(attempts.get(), 1);
        assert_eq!(child_executions.get(), 0);
    }
}
