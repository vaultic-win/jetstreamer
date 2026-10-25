//! Genuine exact223 repair ownership and status-only publication.
//! No replay, qualification, archive, sidecar, or resource admission authority.
use super::*;
use std::os::unix::fs::PermissionsExt;
mod model;
mod resource;
use model::{ORIGIN_IID, ORIGIN_UNIT, Policy, Progress};
const CLAIM: &str = "epoch223-demotion-repair";
const TASK: &str = "jetstreamer-epoch223-demotion-active-task-v1";
const FROZEN: &str = "jetstreamer-epoch223-demotion-status-observation-v1";
const TERMINAL: &str = "jetstreamer-epoch223-demotion-task-terminal-v1";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    unit: String,
    invocation_id: String,
    pid: u32,
    start_ticks: u64,
    cgroup: String,
    boot_id: String,
    executable: BoundFile,
    expected_exec_start: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Task {
    schema: String,
    epoch: u64,
    job_kind: String,
    actor: Actor,
    runtime_plan: BoundFile,
    actor_launch: BoundFile,
    role_qualification: BoundFile,
    guard: BoundFile,
    guard_qualification: BoundFile,
    predecessor_task: Option<BoundFile>,
    predecessor_terminal: Option<BoundFile>,
    origin_clock: BoundFile,
    eta_policy: BoundFile,
    original_start_unix_millis: u64,
    actor_start_unix_millis: u64,
    captured_unix_millis: u64,
    run_root: PathBuf,
    run_root_device: u64,
    run_root_inode: u64,
    cgroup_device: u64,
    cgroup_inode: u64,
    manager: Value,
    capture_spec: BoundFile,
    capture_spec_source: BoundFile,
    capture_executable_sha256: String,
    publication_authorized: bool,
    r2_mutations: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    schema: String,
    job_kind: String,
    actor: Actor,
    runtime_plan: BoundFile,
    actor_launch: BoundFile,
    role_qualification: BoundFile,
    guard: BoundFile,
    guard_qualification: BoundFile,
    predecessor_task: Option<BoundFile>,
    predecessor_terminal: Option<BoundFile>,
    origin_clock: BoundFile,
    eta_policy: BoundFile,
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    schema: String,
    mode: String,
    task: BoundFile,
    observer: BoundFile,
    fleet: BoundFile,
    predecessor: Option<BoundFile>,
    event: Option<BoundFile>,
    estimate_receipt: PathBuf,
    receipt_directory: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalSpec {
    schema: String,
    task: BoundFile,
    manager_journal: BoundFile,
    output: PathBuf,
}

pub(super) fn scope(phase: &str, name: &str) -> bool {
    phase == CLAIM
        && (name.starts_with("horizon-native-input-223-demotion-")
            || name.starts_with("horizon-qualify-223-demotion-bracket-"))
        && name.ends_with(".service")
        && name.len() <= 255
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn millis() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
fn bounded(program: &str, args: &[String], maximum: usize) -> Result<Vec<u8>> {
    use std::{process::Stdio, thread};
    let mut child = ProcessCommand::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().context("223 metadata stdout")?;
    let stderr = child.stderr.take().context("223 metadata stderr")?;
    let read = move |stream: Box<dyn Read + Send>, limit: usize| -> Result<Vec<u8>> {
        let mut out = Vec::new();
        stream.take((limit + 1) as u64).read_to_end(&mut out)?;
        ensure!(out.len() <= limit, "223 metadata command output bound");
        Ok(out)
    };
    let a = thread::spawn(move || read(Box::new(stdout), maximum));
    let b = thread::spawn(move || read(Box::new(stderr), 65536));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(5) {
            child.kill()?;
            child.wait()?;
            bail!("223 metadata command timed out");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let bytes = a
        .join()
        .map_err(|_| anyhow!("223 metadata reader panicked"))??;
    let _ = b
        .join()
        .map_err(|_| anyhow!("223 metadata stderr reader panicked"))??;
    let collected = program == "/usr/bin/systemctl"
        && std::str::from_utf8(&bytes).is_ok_and(|text| {
            text.lines().any(|s| s == "LoadState=not-found")
                && text.lines().any(|s| s == "ActiveState=inactive")
        });
    ensure!(status.success() || collected, "223 metadata command failed");
    Ok(bytes)
}
fn manager(name: &str) -> Result<Value> {
    ensure!(
        scope(CLAIM, name) || guard_name(name),
        "223 manager is outside repair scope"
    );
    let bytes=bounded("/usr/bin/systemctl",&["show".into(),name.into(),"--no-pager".into(),
        "--property=Id,LoadState,Type,User,Restart,ActiveState,SubState,InvocationID,NRestarts,Result,ExecMainStatus,ExecStart,ControlGroup,MainPID,MemoryHigh,MemoryMax,MemorySwapMax,ExecMainStartTimestampMonotonic".into()],65536)?;
    let mut out = serde_json::Map::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let (key, value) = line.split_once('=').context("223 manager property")?;
        ensure!(
            out.insert(key.into(), Value::String(value.into()))
                .is_none(),
            "223 duplicate manager property"
        );
    }
    ensure!(
        out.get("Id").and_then(Value::as_str) == Some(name),
        "223 manager names another unit"
    );
    Ok(Value::Object(out))
}
fn command(a: &Actor, plan: &BoundFile, kind: &str) -> String {
    let middle = if kind == "native-input" {
        "supervise-epoch223-demotion-native "
    } else {
        ""
    };
    let flag = if kind == "native-input" {
        "--spec-sha256"
    } else {
        "--plan-sha256"
    };
    format!(
        "{{ path={} ; argv[]={} {middle}{} {flag} {} --self-sha256 {} ; ignore_errors=no }}",
        a.executable.path.display(),
        a.executable.path.display(),
        plan.path.display(),
        plan.sha256,
        a.executable.sha256
    )
}
fn actor_shape(a: &Actor, kind: &str, plan: &BoundFile) -> Result<()> {
    ensure!(
        scope(CLAIM, &a.unit)
            && private_prefix::iid(&a.invocation_id)
            && a.invocation_id != "0".repeat(32)
            && a.pid > 1
            && a.start_ticks > 0
            && a.cgroup == format!("/system.slice/{}", a.unit)
            && matches!(kind, "native-input" | "bracket")
            && (kind == "native-input") == a.unit.starts_with("horizon-native-input-")
            && a.expected_exec_start == command(a, plan, kind),
        "223 task actor/actual role command differs"
    );
    Ok(())
}
fn live_shape(a: &Actor, row: &Value) -> bool {
    row["Id"] == a.unit
        && row["LoadState"] == "loaded"
        && row["InvocationID"] == a.invocation_id
        && row["NRestarts"] == "0"
        && row["ActiveState"] == "active"
        && row["SubState"] == "running"
        && row["MainPID"].as_str().and_then(|n| n.parse::<u32>().ok()) == Some(a.pid)
        && row["ControlGroup"] == a.cgroup
        && row["ExecStart"]
            .as_str()
            .is_some_and(|s| same_command(s, &a.expected_exec_start))
}
fn same_command(a: &str, b: &str) -> bool {
    a.split(" ; start_time=")
        .next()
        .unwrap_or(a)
        .trim_end_matches(" }")
        == b.trim_end_matches(" }")
}
fn observe(a: &Actor, kind: &str) -> Result<Value> {
    let before = manager(&a.unit)?;
    ensure!(
        live_shape(a, &before)
            && before["Type"] == "exec"
            && before["Restart"] == "no"
            && before["User"]
                == if matches!(kind, "native-input" | "guard") {
                    "root"
                } else {
                    "ubuntu"
                },
        "223 task is not a real live producer"
    );
    let stat = fs::read_to_string(format!("/proc/{}/stat", a.pid))?;
    ensure!(
        stat.rsplit_once(')')
            .context("223 proc stat")?
            .1
            .split_whitespace()
            .nth(19)
            .context("223 process start ticks")?
            .parse::<u64>()?
            == a.start_ticks
            && fs::read_link(format!("/proc/{}/exe", a.pid))? == a.executable.path
            && fs::read_to_string(format!("/proc/{}/cgroup", a.pid))?.trim()
                == format!("0::{}", a.cgroup)
            && fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == a.boot_id,
        "223 task process was reused"
    );
    let meta = fs::symlink_metadata(&a.executable.path)?;
    ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o222 == 0
            && a.executable.path.canonicalize()? == a.executable.path
            && meta.len() <= 256 << 20,
        "223 task ELF not sealed"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&a.executable.path)?;
    let mut sha = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(total <= 256 << 20, "223 task ELF bound");
        sha.update(&buf[..n]);
    }
    let after = fs::symlink_metadata(&a.executable.path)?;
    ensure!(
        hex_lower(&sha.finalize()) == a.executable.sha256
            && total == meta.len()
            && meta.dev() == after.dev()
            && meta.ino() == after.ino()
            && meta.mtime() == after.mtime()
            && meta.mtime_nsec() == after.mtime_nsec()
            && manager(&a.unit)? == before,
        "223 task executable/manager changed during capture"
    );
    Ok(before)
}
fn origin(binding: &BoundFile) -> Result<u64> {
    let value = bound_json(binding)?;
    let journal: BoundFile = serde_json::from_value(value["manager_journal"].clone())?;
    let bytes = read_stable_bounded(&journal.path, 16 << 20, "223 original PID1 journal")?;
    let start = model::origin(&bytes)?;
    let failed: BoundFile = serde_json::from_value(value["failed_origin"].clone())?;
    bound_json(&failed)?;
    ensure!(
        value["schema"] == "jetstreamer-epoch223-e70a-origin-clock-v1"
            && value["unit"] == ORIGIN_UNIT
            && value["invocation_id"] == ORIGIN_IID
            && value["repair_closed"] == false
            && value["original_start_unix_millis"] == start
            && journal.sha256 == "58e40c27ef840b8843b531d4ce372e955ae55c878638651979672904706c627f"
            && hex_lower(&Sha256::digest(&bytes)) == journal.sha256
            && value["failed_origin"]["sha256"]
                == "f1aa68c425b6bfad05417d196f20bae77de0f67c0bb61d19556f77946e2083ba",
        "223 elapsed clock does not bind original failed e70a invocation"
    );
    Ok(start)
}
fn task(binding: &BoundFile) -> Result<Task> {
    let t: Task = serde_json::from_value(bound_json(binding)?)?;
    validate_task_value(&t)?;
    let capture: Capture = serde_json::from_value(bound_json(&t.capture_spec)?)?;
    ensure!(
        capture.output == binding.path,
        "223 task copy is not its original capture destination"
    );
    Ok(t)
}

pub(super) fn capture() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-demotion223-repair-task")?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "223 task capture requires root"
    );
    let p: Capture = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        p.schema == "jetstreamer-epoch223-demotion-task-capture-spec-v1",
        "223 task capture spec"
    );
    actor_shape(&p.actor, &p.job_kind, &p.runtime_plan)?;
    if p.output.try_exists()? {
        let owned = task(&serde_json::from_value(private157::file_binding(
            &p.output,
        )?)?)?;
        ensure!(
            owned.capture_spec_source == binding
                && serde_json::to_value(&owned.actor)? == serde_json::to_value(&p.actor)?,
            "223 task capture retry changes actual owner/spec"
        );
        observe(&owned.actor, &owned.job_kind)?;
        observe(&guard_for(&owned)?, "guard")?;
        partial_bytes(&owned)?;
        println!("{}", p.output.display());
        return Ok(());
    }
    let manager = observe(&p.actor, &p.job_kind)?;
    let now = millis()?;
    let start_micros = manager["ExecMainStartTimestampMonotonic"]
        .as_str()
        .context("223 manager start")?
        .parse::<u64>()?;
    let mut clock = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, clock.as_mut_ptr()) } == 0,
        "223 actual monotonic clock"
    );
    let clock = unsafe { clock.assume_init() };
    let mono = u64::try_from(clock.tv_sec)?
        .checked_mul(1000)
        .and_then(|n| n.checked_add(u64::try_from(clock.tv_nsec).ok()? / 1_000_000))
        .context("223 monotonic overflow")?;
    let started = now
        .checked_sub(
            mono.checked_sub(start_micros / 1000)
                .context("223 task start is future")?,
        )
        .context("223 task start underflow")?;
    let runtime = bound_json(&p.runtime_plan)?;
    let run_root = runtime_root(&runtime, &p.job_kind)?;
    let root = fs::symlink_metadata(&run_root)?;
    ensure!(
        root.is_dir()
            && root.uid() == 1000
            && root.mode() & 0o077 == 0
            && run_root.canonicalize()? == run_root,
        "223 task root is not original owner-private directory"
    );
    let cgroup = fs::symlink_metadata(
        Path::new("/sys/fs/cgroup").join(p.actor.cgroup.trim_start_matches('/')),
    )?;
    let mut value = json!({"schema":TASK,"epoch":223,"job_kind":p.job_kind,"actor":p.actor,"runtime_plan":p.runtime_plan,
        "actor_launch":p.actor_launch,"role_qualification":p.role_qualification,"guard":p.guard,"guard_qualification":p.guard_qualification,
        "predecessor_task":p.predecessor_task,"predecessor_terminal":p.predecessor_terminal,"origin_clock":p.origin_clock,"eta_policy":p.eta_policy,
        "original_start_unix_millis":origin(&p.origin_clock)?,"actor_start_unix_millis":started,"captured_unix_millis":now,
        "cgroup_device":cgroup.dev(),"cgroup_inode":cgroup.ino(),"run_root":run_root,"run_root_device":root.dev(),"run_root_inode":root.ino(),"manager":manager,"capture_spec":binding,"capture_spec_source":binding,"capture_executable_sha256":self_sha,"publication_authorized":false,"r2_mutations":false});
    // Validate the entire candidate before durable publication; the actual
    // owner is rechecked after, never substituted with this metadata helper.
    let candidate: Task = serde_json::from_value(value.clone())?;
    validate_task_value(&candidate)?;
    let guard = guard_for(&candidate)?;
    observe(&guard, "guard")?;
    ensure!(
        observe(&p.actor, &p.job_kind)? == manager,
        "223 owner changed before task commit"
    );
    let source = read_stable_bounded(
        &binding.path,
        1 << 20,
        "223 actual non-sensitive capture spec",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&source)) == binding.sha256,
        "223 capture source spec changed"
    );
    let copy = p.output.with_file_name(format!(
        "{}.capture-spec.json",
        p.output
            .file_name()
            .context("223 task output name")?
            .to_string_lossy()
    ));
    let copied = readable_metadata(&copy, &source)?;
    value["capture_spec"] = private157::binding(&copied);
    validate_task_value(&serde_json::from_value(value.clone())?)?;
    let mut bytes = serde_json::to_vec_pretty(&value)?;
    bytes.push(b'\n');
    readable_metadata(&p.output, &bytes)?;
    Ok(())
}
fn validate_task_value(t: &Task) -> Result<()> {
    actor_shape(&t.actor, &t.job_kind, &t.runtime_plan)?;
    let runtime = bound_json(&t.runtime_plan)?;
    ensure!(
        t.run_root == runtime_root(&runtime, &t.job_kind)?
            && t.run_root_device > 0
            && t.run_root_inode > 0
            && t.cgroup_device > 0
            && t.cgroup_inode > 0,
        "223 task original directory identity missing"
    );
    ensure!(
        t.capture_spec.sha256 == t.capture_spec_source.sha256
            && bound_json(&t.capture_spec)? == bound_json(&t.capture_spec_source)?,
        "223 readable capture copy is not the exact original spec"
    );
    let capture: Capture = serde_json::from_value(bound_json(&t.capture_spec)?)?;
    ensure!(
        capture.schema == "jetstreamer-epoch223-demotion-task-capture-spec-v1"
            && capture.job_kind == t.job_kind
            && serde_json::to_value(&capture.actor)? == serde_json::to_value(&t.actor)?
            && capture.runtime_plan == t.runtime_plan
            && capture.actor_launch == t.actor_launch
            && capture.guard == t.guard
            && capture.guard_qualification == t.guard_qualification
            && capture.role_qualification == t.role_qualification
            && capture.origin_clock == t.origin_clock
            && capture.eta_policy == t.eta_policy
            && capture.predecessor_task == t.predecessor_task
            && capture.predecessor_terminal == t.predecessor_terminal,
        "223 task does not bind its actual root capture spec"
    );
    let accountant = if t.job_kind == "native-input" {
        &runtime["accounting_executable"]
    } else {
        &runtime["prerequisites"]["accounting_executable"]
    };
    let qualification = if t.job_kind == "native-input" {
        &runtime["accounting_qualification"]
    } else {
        &runtime["prerequisites"]["accounting_qualification"]
    };
    let qualification = bound_json(&serde_json::from_value(qualification.clone())?)?;
    ensure!(
        accountant["sha256"] == t.capture_executable_sha256
            && qualification["executable_sha256"] == t.capture_executable_sha256
            && qualification["demotion223_status_owner_capture_qualified"] == true,
        "223 genuine task capture helper has not been independently qualified"
    );
    let launch = bound_json(&t.actor_launch)?;
    let qual = bound_json(&t.role_qualification)?;
    ensure!(
        t.schema == TASK
            && t.epoch == 223
            && !t.publication_authorized
            && !t.r2_mutations
            && t.original_start_unix_millis == origin(&t.origin_clock)?
            && t.actor_start_unix_millis >= t.original_start_unix_millis
            && t.captured_unix_millis >= t.actor_start_unix_millis
            && live_shape(&t.actor, &t.manager)
            && qual["schema"] == "jetstreamer-epoch223-demotion-role-qualification-v1"
            && qual["executable_sha256"] == t.actor.executable.sha256
            && qual["producer_roles_qualified"] == true
            && launch["runtime_plan"] == private157::binding(&t.runtime_plan)
            && launch["actor"] == serde_json::to_value(&t.actor)?,
        "223 task is not captured real qualified ownership"
    );
    if t.job_kind == "native-input" {
        ensure!(
            runtime["schema"] == "jetstreamer-epoch223-demotion-native-supervisor-plan-v1"
                && runtime["unit"] == t.actor.unit
                && runtime["bootstrap_slot"] == 96_335_538u64
                && runtime["harness"]["sha256"]
                    == "a280b1f48f0bb430c482e01a03b4b800ee8f95f326590059e4cdf4873b14a22b"
                && launch["schema"] == "jetstreamer-epoch223-demotion-native-start-v1"
                && qual["native_supervisor_qualified"] == true,
            "223 native task borrows another harness/role"
        );
    } else {
        ensure!(
            runtime["schema"] == "jetstreamer-epoch223-demotion-runtime-plan-v3"
                && runtime["mode"] == "bracket"
                && runtime["plan"]["unit"] == t.actor.unit
                && runtime["plan"]["terminal_slot"] == 96_544_588u64
                && runtime["plan"]["target_slot"] == 96_544_588u64
                && launch["schema"] == "jetstreamer-epoch223-demotion-actor-launch-v1",
            "223 bracket task borrows full-root authority"
        );
    }
    if t.job_kind == "bracket" {
        let native: BoundFile =
            serde_json::from_value(runtime["prerequisites"]["native_input"].clone())?;
        let proof = bound_json(&native)?;
        let launch: BoundFile = serde_json::from_value(proof["launch"].clone())?;
        let launch = bound_json(&launch)?;
        let native_task = task(&serde_json::from_value(launch["status_task"].clone())?)?;
        ensure!(
            proof["schema"] == "jetstreamer-epoch223-demotion-native-input-proof-v1"
                && proof["harness_sha256"]
                    == "a280b1f48f0bb430c482e01a03b4b800ee8f95f326590059e4cdf4873b14a22b"
                && proof["manager_success"] == true
                && proof["restart_count"] == 0
                && proof["success"] == true
                && proof["actual_invocation_id"] == native_task.actor.invocation_id
                && native_task.job_kind == "native-input"
                && native_task.origin_clock == t.origin_clock
                && native_task.original_start_unix_millis == t.original_start_unix_millis
                && proof["full_epoch_qualified"] == false
                && proof["publication_authorized"] == false,
            "223 bracket task has no actual new-harness bootstrap/task lineage"
        );
    }
    guard_for(t)?;
    ensure!(
        t.predecessor_task.is_some() == t.predecessor_terminal.is_some(),
        "223 partial task handoff"
    );
    if let Some(previous) = &t.predecessor_task {
        let old = task(previous)?;
        ensure!(
            matches!(old.job_kind.as_str(), "native-input" | "bracket")
                && old.origin_clock == t.origin_clock
                && old.original_start_unix_millis == t.original_start_unix_millis,
            "223 unsupported or clock-reset task handoff"
        );
        let terminal = bound_json(
            t.predecessor_terminal
                .as_ref()
                .context("223 previous terminal")?,
        )?;
        terminal_task(&terminal)?;
        ensure!(
            terminal["task"] == private157::binding(previous),
            "223 terminal handoff names another task"
        );
        if t.job_kind == "bracket" {
            let native: BoundFile =
                serde_json::from_value(runtime["prerequisites"]["native_input"].clone())?;
            let proof = bound_json(&native)?;
            if old.job_kind == "native-input" {
                ensure!(
                    terminal["manager"]["Result"] == "success"
                        && terminal["manager"]["ExecMainStatus"] == "0"
                        && proof["actual_invocation_id"] == old.actor.invocation_id,
                    "223 native-to-bracket handoff lacks clean actual native completion"
                );
            } else {
                let prior = bound_json(&old.runtime_plan)?;
                ensure!(
                    prior["prerequisites"]["native_input"] == private157::binding(&native),
                    "223 bracket retry changes its native proof without qualification"
                );
            }
            ensure!(
                proof["schema"] == "jetstreamer-epoch223-demotion-native-input-proof-v1"
                    && proof["harness_sha256"]
                        == "a280b1f48f0bb430c482e01a03b4b800ee8f95f326590059e4cdf4873b14a22b"
                    && proof["success"] == true
                    && proof["full_epoch_qualified"] == false
                    && proof["publication_authorized"] == false,
                "223 handoff borrows old harness/full-root authority"
            );
        }
    }
    let policy: Policy = serde_json::from_value(bound_json(&t.eta_policy)?)?;
    for evidence in &policy.evidence {
        bound_json(evidence)?;
    }
    model::estimate(
        &policy,
        &t.job_kind,
        t.original_start_unix_millis,
        t.actor_start_unix_millis,
        t.captured_unix_millis,
        &[],
    )?;
    Ok(())
}

pub(super) fn validate_claim(c: &PipelineClaim, current: Option<&Value>) -> Result<()> {
    ensure!(
        c.epoch == 223 && scope(&c.phase, &c.unit) && c.evidence.len() == 1,
        "223 repair claim scope/evidence differs"
    );
    let t = task(&c.evidence[0])?;
    ensure!(
        c.unit == t.actor.unit
            && c.invocation_id == t.actor.invocation_id
            && c.expected_exec_start == t.actor.expected_exec_start,
        "223 repair claim is not the captured actual actor"
    );
    if let Some(row) = current {
        ensure!(live_shape(&t.actor, row), "223 claimed live task changed");
        observe(&t.actor, &t.job_kind)?;
    }
    Ok(())
}
pub(super) fn binding_scope(b: &pipeline_status::Binding, epoch: u64, phase: &str) -> Result<()> {
    ensure!(
        epoch == 223
            && scope(&b.claim_phase, &b.unit)
            && matches!(phase, "verification" | "replay")
            && (!b.unit.starts_with("horizon-native-input-") || phase == "verification")
            && b.origin_unit == ORIGIN_UNIT
            && b.origin_invocation_id == ORIGIN_IID,
        "223 status scope/original clock differs"
    );
    Ok(())
}

fn runtime_root(value: &Value, kind: &str) -> Result<PathBuf> {
    let name = if kind == "native-input" {
        &value["run_root"]
    } else {
        &value["plan"]["run_root"]
    };
    let path = PathBuf::from(name.as_str().context("223 actual runtime root")?);
    let prefix = if kind == "native-input" {
        "native-input223-v1620-demotion-"
    } else {
        "qualification-223-demotion-bracket-"
    };
    ensure!(
        path.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(prefix)),
        "223 task directory escapes its actual role"
    );
    Ok(path)
}

fn guard_name(name: &str) -> bool {
    name.starts_with("horizon-guard-223-demotion-")
        && name.ends_with(".service")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn guard_for(t: &Task) -> Result<Actor> {
    let value = bound_json(&t.guard)?;
    let a: Actor = serde_json::from_value(value["actor"].clone())?;
    let plan: BoundFile = serde_json::from_value(value["guard_plan"].clone())?;
    let body = bound_json(&plan)?;
    let qualification = bound_json(&t.guard_qualification)?;
    ensure!(
        guard_name(&a.unit)
            && a.pid != t.actor.pid
            && a.invocation_id != t.actor.invocation_id
            && value["schema"] == "jetstreamer-epoch223-demotion-guard-ready-v1"
            && value["watched_runner"] == serde_json::to_value(&t.actor)?
            && value["producer_stop_enabled"] == true
            && value["protective_guard_proven"] == true
            && value["publication_authorized"] == false
            && body["runtime_plan"] == private157::binding(&t.runtime_plan)
            && body["guard_unit"] == a.unit
            && body["ready_output"].as_str() == t.guard.path.to_str()
            && qualification["schema"] == "jetstreamer-epoch223-demotion-role-qualification-v1"
            && qualification["executable_sha256"] == a.executable.sha256
            && qualification["protective_guard_qualified"] == true
            && (t.job_kind != "native-input"
                || qualification["native_input_guard_qualified"] == true),
        "223 task has no original qualified independent guard"
    );
    let expected = format!(
        "{{ path={} ; argv[]={} guard-epoch223-demotion {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no }}",
        a.executable.path.display(),
        a.executable.path.display(),
        plan.path.display(),
        plan.sha256,
        a.executable.sha256
    );
    ensure!(
        a.expected_exec_start == expected,
        "223 protective task guard command differs"
    );
    Ok(a)
}

fn registered(p: &Publication, t: &Task, f: &Value, o: &Value) -> Result<()> {
    ensure!(
        f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_sha256"] == p.observer.sha256
            && f["observer_receipt"].as_str() == p.observer.path.to_str()
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "223 status needs accepted coordinated observer/fleet"
    );
    let plan: Plan = serde_json::from_value(bound_json(&serde_json::from_value(
        json!({"path":f["plan"],"sha256":f["plan_sha256"]}),
    )?)?)?;
    ensure!(
        p.receipt_directory == plan.status_receipt_directory,
        "223 status history must use its accepted fleet directory"
    );
    let claims = plan
        .pipeline_claims
        .iter()
        .filter(|c| c.epoch == 223 && scope(&c.phase, &c.unit))
        .collect::<Vec<_>>();
    let matching = claims
        .iter()
        .filter(|c| c.unit == t.actor.unit && c.invocation_id == t.actor.invocation_id)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1
            && matching[0].evidence == vec![p.task.clone()]
            && live_shape(&t.actor, &f["unit_census"][&t.actor.unit]),
        "223 status task is not registered actual fleet owner"
    );
    let active = f["active"]
        .as_array()
        .context("223 fleet active census")?
        .iter()
        .filter(|row| row["epoch"] == 223)
        .collect::<Vec<_>>();
    ensure!(
        active.len() == 1
            && active[0]["phase"] == CLAIM
            && active[0]["unit"]["InvocationID"] == t.actor.invocation_id,
        "223 repair has another actual owner or unresolved delivery"
    );
    let entry = f["inventory"]["entries"]
        .as_array()
        .context("223 inventory entries")?
        .iter()
        .filter(|v| v["epoch"] == 223)
        .collect::<Vec<_>>();
    ensure!(
        entry.len() == 1 && entry[0]["state"] == "missing",
        "223 repair status cannot replace remote ready/staged data"
    );
    Ok(())
}
fn partial_bytes(t: &Task) -> Result<u64> {
    let root = fs::symlink_metadata(&t.run_root)?;
    ensure!(
        root.dev() == t.run_root_device
            && root.ino() == t.run_root_inode
            && root.uid() == 1000
            && root.mode() & 0o077 == 0
            && t.run_root.canonicalize()? == t.run_root,
        "223 status original run-root replaced"
    );
    if t.job_kind == "native-input" {
        return Ok(0);
    }
    let path = t.run_root.join("output/epoch-223.jet");
    let before = match fs::symlink_metadata(&path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let opened = file.metadata()?;
    let after = fs::symlink_metadata(&path)?;
    ensure!(
        [&before, &opened, &after].iter().all(|m| m.is_file()
            && m.uid() == 1000
            && m.nlink() == 1
            && m.mode() & 0o077 == 0
            && m.dev() == before.dev()
            && m.ino() == before.ino())
            && after.len() >= before.len(),
        "223 partial jet was linked, replaced or shrank"
    );
    Ok(before.len())
}
fn parsed_progress(bytes: &[u8], t: &Task, sampled: u64) -> Result<Vec<Progress>> {
    let rows = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.len() < 8192,
        "223 journal progress truncated; no replacement status published"
    );
    let mut out = Vec::new();
    for row in rows {
        ensure!(
            row["_SYSTEMD_INVOCATION_ID"] == t.actor.invocation_id
                && row["_SYSTEMD_UNIT"] == t.actor.unit,
            "223 progress journal belongs to another actor"
        );
        let stamp = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("223 actual progress clock")?
            .parse::<u64>()?;
        ensure!(
            stamp / 1000
                >= t.actor_start_unix_millis
                    .max(sampled.saturating_sub(1_800_000))
                && stamp / 1000 <= sampled,
            "223 progress is newer than coordinated cutoff"
        );
        if let Some(text) = row["MESSAGE"].as_str().and_then(|s| {
            s.split_once(" jetstreamer_node] progress slot ")
                .and_then(|(prefix, tail)| {
                    let mut words = prefix.split_whitespace();
                    (words.next().is_some_and(|s| s.starts_with('['))
                        && words.next() == Some("INFO")
                        && words.next().is_none())
                    .then_some(tail)
                })
        }) {
            ensure!(
                t.job_kind == "bracket",
                "native input cannot report entry replay"
            );
            let token = text
                .split_whitespace()
                .next()
                .context("223 progress slot token")?;
            let (slot, terminal) = token
                .split_once('/')
                .context("223 actual bracket interval")?;
            out.push(Progress {
                slot: slot.parse()?,
                terminal: terminal.trim_end_matches(',').parse()?,
                unix_micros: stamp,
            });
        }
    }
    Ok(out)
}
fn progress(t: &Task, sampled: u64, directory: &Path) -> Result<(Vec<Progress>, BoundFile)> {
    let path = directory.join(format!(
        "progress-{}-{sampled}.jsonl",
        t.actor.invocation_id
    ));
    let bytes = if path.try_exists()? {
        read_stable_bounded(&path, 16 << 20, "223 frozen actual progress")?
    } else {
        let bytes = bounded(
            "/usr/bin/journalctl",
            &[
                format!("_SYSTEMD_INVOCATION_ID={}", t.actor.invocation_id),
                "--output=json".into(),
                "--no-pager".into(),
                "--lines=8192".into(),
                format!(
                    "--since=@{}",
                    t.actor_start_unix_millis
                        .max(sampled.saturating_sub(1_800_000))
                        / 1000
                ),
                format!("--until=@{}", sampled / 1000),
            ],
            16 << 20,
        )?;
        parsed_progress(&bytes, t, sampled)?;
        let parent = validate_output_destination(&path)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        temp.write_all(&bytes)?;
        temp.as_file().sync_all()?;
        temp.persist_noclobber(&path)
            .map_err(|e| anyhow!("223 progress receipt occupied:{e}"))?;
        File::open(parent)?.sync_all()?;
        bytes
    };
    let out = parsed_progress(&bytes, t, sampled)?;
    Ok((
        out,
        BoundFile {
            path,
            sha256: hex_lower(&Sha256::digest(&bytes)),
        },
    ))
}

fn binding(p: &Publication, t: &Task) -> pipeline_status::Binding {
    pipeline_status::Binding {
        unit: t.actor.unit.clone(),
        invocation_id: t.actor.invocation_id.clone(),
        expected_exec_start: t.actor.expected_exec_start.clone(),
        claim_phase: CLAIM.into(),
        origin_unit: ORIGIN_UNIT.into(),
        origin_invocation_id: ORIGIN_IID.into(),
        model_path: p.estimate_receipt.clone(),
        model_sha256: String::new(),
        fleet_path: p.fleet.path.clone(),
        fleet_sha256: p.fleet.sha256.clone(),
    }
}
fn phase_schema(value: &Value) -> bool {
    matches!(
        value["schema"].as_str(),
        Some(
            "jetstreamer-epoch223-demotion-native-spawn-accepted-v1"
                | "jetstreamer-epoch223-demotion-spawn-accepted-v1"
        )
    )
}
fn phase_sample(t: &Task, event: &Value) -> Result<u64> {
    ensure!(
        phase_schema(event)
            && event["runner"] == serde_json::to_value(&t.actor)?
            && event["original_start_unix_millis"] == t.original_start_unix_millis
            && event["native_execution_authorized"] == true,
        "223 phase event does not belong to actual hash-complete owner"
    );
    let binding: BoundFile = serde_json::from_value(event["grant"].clone())?;
    let grant = bound_json(&binding)?;
    let capture: Capture = serde_json::from_value(bound_json(&t.capture_spec)?)?;
    let task_binding: BoundFile =
        serde_json::from_value(private157::file_binding(&capture.output)?)?;
    ensure!(
        grant["runner"] == serde_json::to_value(&t.actor)?
            && grant["runtime_plan"] == private157::binding(&t.runtime_plan)
            && grant["status_task"] == private157::binding(&task_binding)
            && grant["native_execution_authorized"] == true
            && grant["publication_authorized"] == false
            && grant["r2_mutations"] == false,
        "223 phase event borrows another grant/status task"
    );
    let now = grant["recorded_unix_millis"]
        .as_u64()
        .context("223 actual phase grant clock")?;
    ensure!(
        now >= t.captured_unix_millis,
        "223 phase event predates genuine task"
    );
    Ok(now)
}
fn cadence(
    p: &Publication,
    t: &Task,
    o: &Value,
    sampled: u64,
    old: Option<&StatusPublicationReceipt>,
) -> Result<()> {
    ensure!(
        matches!(p.mode.as_str(), "routine" | "launch-event" | "phase-event"),
        "223 unsupported metadata event"
    );
    if p.mode == "launch-event" {
        ensure!(
            p.event.as_ref() == Some(&p.task)
                && sampled == t.captured_unix_millis
                && old.is_none_or(|r| r
                    .pipeline_binding
                    .as_ref()
                    .map(|b| b.invocation_id.as_str())
                    .unwrap_or(&r.producer_invocation_id)
                    != t.actor.invocation_id),
            "223 launch event is not a new actual task"
        );
        return Ok(());
    }
    if p.mode == "phase-event" {
        let event = bound_json(
            p.event
                .as_ref()
                .context("223 genuine phase event missing")?,
        )?;
        ensure!(
            phase_sample(t, &event)? == sampled,
            "223 phase event clock changed"
        );
        ensure!(
            old.is_none_or(
                |r| utc_seconds(&r.status.sampled_at_utc).is_ok_and(|prior| prior < sampled / 1000)
            ),
            "223 phase event is already covered by a newer/equal status sample"
        );
        return Ok(());
    }
    ensure!(
        p.event.is_none(),
        "223 routine cannot borrow lifecycle exception"
    );
    if let Some(old) = old {
        let prior = utc_seconds(&old.status.sampled_at_utc)?
            .checked_mul(1000)
            .context("223 previous time overflow")?;
        ensure!(sampled >= prior, "223 status cannot move backwards");
        let requested = o["observation_reason"] == "user-requested-status"
            && o["routine_minimum_interval_enforced"] == false;
        ensure!(
            requested || sampled - prior >= 1_800_000,
            "223 autonomous status refresh is less than30 minutes"
        );
    }
    Ok(())
}
pub(super) async fn publish() -> Result<()> {
    let (plan_binding, _) = publication203::parsed_args("status-publish-demotion223-repair")?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "223 repair publication requires root"
    );
    let p: Publication = serde_json::from_value(bound_json(&plan_binding)?)?;
    ensure!(
        p.schema == "jetstreamer-epoch223-demotion-status-plan-v1",
        "223 publication model schema"
    );
    let t = task(&p.task)?;
    let o = bound_json(&p.observer)?;
    let f = bound_json(&p.fleet)?;
    registered(&p, &t, &f, &o)?;
    let observer_ms = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("223 coordinated UTC")?,
    )?
    .checked_mul(1000)
    .context("223 observer clock overflow")?;
    let sampled = if p.mode == "launch-event" {
        t.captured_unix_millis
    } else if p.mode == "phase-event" {
        phase_sample(
            &t,
            &bound_json(p.event.as_ref().context("223 actual phase event")?)?,
        )?
    } else {
        observer_ms
    };
    let now = millis()?;
    ensure!(
        observer_ms <= sampled
            && sampled <= now
            && now - observer_ms <= 1_800_000
            && (p.mode == "routine" || now - sampled <= 300_000),
        "223 stale/future coordinated event"
    );
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    let latest = latest_status_publication_receipt(&p.receipt_directory, &r2.bucket, 223);
    let old = match latest {
        Ok((r, path, sha)) => {
            if r.observer_receipt == p.estimate_receipt {
                let bytes = read_stable_bounded(
                    &p.estimate_receipt,
                    MAX_OBSERVER_RECEIPT_BYTES,
                    "223 completed publication retry",
                )?;
                let value: Value = serde_json::from_slice(&bytes)?;
                ensure!(
                    value["plan"] == private157::binding(&plan_binding)
                        && r.status.sampled_at_utc == publication203::utc(sampled / 1000)?,
                    "223 completed retry plan changed"
                );
                let owned = frozen_owner(&r)?;
                ensure!(
                    serde_json::to_value(&owned.actor)? == serde_json::to_value(&t.actor)?,
                    "223 retry names another owner"
                );
                let before = observe(&t.actor, &t.job_kind)?;
                let guard = guard_for(&t)?;
                observe(&guard, "guard")?;
                let (etag, _) = publish_bound(&s3, &r2, &r.status, Some(&r.object_etag)).await?;
                ensure!(
                    etag == r.object_etag && before == observe(&t.actor, &t.job_kind)?,
                    "223 completed retry changed remote version or owner"
                );
                observe(&guard, "guard")?;
                println!("{}", path.display());
                return Ok(());
            }
            ensure!(
                p.predecessor.as_ref() == Some(&BoundFile { path, sha256: sha }),
                "223 publisher must bind the exact latest status receipt"
            );
            Some(r)
        }
        Err(e) => {
            let candidates =
                fs::read_dir(&p.receipt_directory)?.collect::<std::io::Result<Vec<_>>>()?;
            ensure!(
                !candidates.iter().any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("epoch-223.status-")),
                "223 existing status history is invalid/unreadable: {e:#}"
            );
            ensure!(
                p.predecessor.is_none(),
                "223 declared prior status receipt unavailable: {e:#}"
            );
            None
        }
    };
    cadence(&p, &t, &o, sampled, old.as_ref())?;
    let first = observe(&t.actor, &t.job_kind)?;
    let guard = guard_for(&t)?;
    observe(&guard, "guard")?;
    let evidence = if p.estimate_receipt.try_exists()? {
        let v = bound_json(&serde_json::from_value(private157::file_binding(
            &p.estimate_receipt,
        )?)?)?;
        ensure!(
            v["plan"] == private157::binding(&plan_binding),
            "223 retry frozen estimate belongs to another model"
        );
        v
    } else {
        let (window, journal) = progress(
            &t,
            sampled,
            p.estimate_receipt.parent().context("223 estimate parent")?,
        )?;
        let policy: Policy = serde_json::from_value(bound_json(&t.eta_policy)?)?;
        let estimate = model::estimate(
            &policy,
            &t.job_kind,
            t.original_start_unix_millis,
            t.actor_start_unix_millis,
            sampled,
            &window,
        )?;
        let resources = resource::sample(&t, &first)?;
        let status = EpochStatus {
            epoch: 223,
            jet_size_bytes: partial_bytes(&t)?,
            elapsed_execution_millis: estimate.elapsed_millis,
            estimated_remaining_millis: estimate.remaining_millis,
            sampled_at_utc: publication203::utc(sampled / 1000)?,
            phase: estimate.phase.clone(),
        };
        let v = json!({"schema":FROZEN,"plan":private157::binding(&plan_binding),"task":p.task,"observer":p.observer,"fleet":p.fleet,
            "policy":t.eta_policy,"journal":journal,"progress":window,"resources":resources,"estimate":estimate,"status":status,
            "sampled_unix_millis":sampled,"actual_owner":t.actor,"original_start_unix_millis":t.original_start_unix_millis,
            "resource_samples_taken":0,"archive_or_sidecar_mutation_authorized":false});
        private157::immutable_receipt(&p.estimate_receipt, &v)?;
        v
    };
    let status: EpochStatus = serde_json::from_value(evidence["status"].clone())?;
    validate_epoch_status(&status, 223)?;
    validate_frozen(&evidence, &p, &t)?;
    ensure!(
        first == observe(&t.actor, &t.job_kind)?,
        "223 owner changed before publication"
    );
    observe(&guard, "guard")?;
    preflight_status_receipt_write(&p.receipt_directory)?;
    let source: BoundFile = serde_json::from_value(private157::file_binding(&p.estimate_receipt)?)?;
    let mut owner = binding(&p, &t);
    owner.model_sha256 = source.sha256.clone();
    owner.validate(223, &status.phase)?;
    let (etag, previous) = publish_bound(
        &s3,
        &r2,
        &status,
        old.as_ref().map(|r| r.object_etag.as_str()),
    )
    .await?;
    let receipt = StatusPublicationReceipt {
        schema: PIPELINE_STATUS_RECEIPT_SCHEMA.into(),
        bucket: r2.bucket,
        epoch: 223,
        key: "epoch-223.epoch-status.json".into(),
        status,
        object_etag: etag,
        previous_object_etag: previous,
        observer_receipt: source.path,
        observer_receipt_sha256: source.sha256,
        controller_invocation_id: String::new(),
        producer_invocation_id: String::new(),
        authenticated_readback: true,
        verified_unix_seconds: now / 1000,
        pipeline_binding: Some(owner),
    };
    let path = status_receipt_path(&p.receipt_directory, &receipt.status);
    if path.try_exists()? {
        let prior: StatusPublicationReceipt = serde_json::from_slice(&read_stable_bounded(
            &path,
            MAX_STATUS_BYTES,
            "223 status receipt retry",
        )?)?;
        ensure!(
            prior.status == receipt.status
                && prior.object_etag == receipt.object_etag
                && prior.pipeline_binding == receipt.pipeline_binding
                && prior.observer_receipt_sha256 == receipt.observer_receipt_sha256
                && prior.authenticated_readback,
            "223 status retry differs"
        );
    } else {
        write_status_receipt(&p.receipt_directory, &receipt)?;
    }
    ensure!(
        first == observe(&t.actor, &t.job_kind)?,
        "223 owner changed during publication; preserve receipt for lifecycle reconciliation"
    );
    observe(&guard, "guard")?;
    println!("{}", path.display());
    Ok(())
}
fn validate_frozen(v: &Value, p: &Publication, t: &Task) -> Result<()> {
    resource::validate_saved(t, &v["resources"])?;
    let window: Vec<Progress> = serde_json::from_value(v["progress"].clone())?;
    let journal: BoundFile = serde_json::from_value(v["journal"].clone())?;
    let bytes = read_stable_bounded(&journal.path, 16 << 20, "223 frozen journal bytes")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == journal.sha256,
        "223 frozen progress digest differs"
    );
    let policy: Policy = serde_json::from_value(bound_json(&t.eta_policy)?)?;
    let sampled = v["sampled_unix_millis"]
        .as_u64()
        .context("223 frozen cutoff")?;
    ensure!(
        parsed_progress(&bytes, t, sampled)? == window,
        "223 frozen rate does not reproduce actual journal"
    );
    let o = bound_json(&p.observer)?;
    let f = bound_json(&p.fleet)?;
    registered(p, t, &f, &o)?;
    let expected_sample = if p.mode == "launch-event" {
        t.captured_unix_millis
    } else if p.mode == "phase-event" {
        phase_sample(
            t,
            &bound_json(p.event.as_ref().context("223 frozen phase event")?)?,
        )?
    } else {
        utc_seconds(
            o["recorded_at_utc"]
                .as_str()
                .context("223 original coordinated cutoff")?,
        )?
        .checked_mul(1000)
        .context("223 cutoff overflow")?
    };
    ensure!(sampled == expected_sample, "223 frozen cutoff changed");
    let estimate = model::estimate(
        &policy,
        &t.job_kind,
        t.original_start_unix_millis,
        t.actor_start_unix_millis,
        sampled,
        &window,
    )?;
    let status: EpochStatus = serde_json::from_value(v["status"].clone())?;
    ensure!(
        v["schema"] == FROZEN
            && v["task"] == private157::binding(&p.task)
            && v["observer"] == private157::binding(&p.observer)
            && v["fleet"] == private157::binding(&p.fleet)
            && v["policy"] == private157::binding(&t.eta_policy)
            && v["actual_owner"] == serde_json::to_value(&t.actor)?
            && status.epoch == 223
            && status.elapsed_execution_millis == estimate.elapsed_millis
            && status.estimated_remaining_millis == estimate.remaining_millis
            && status.phase == estimate.phase
            && status.sampled_at_utc == publication203::utc(sampled / 1000)?
            && v["estimate"] == serde_json::to_value(estimate)?,
        "223 frozen sidecar-inclusive estimate does not reproduce actual ownership/model"
    );
    Ok(())
}
fn frozen_owner(receipt: &StatusPublicationReceipt) -> Result<Task> {
    let b = receipt
        .pipeline_binding
        .as_ref()
        .context("223 typed pipeline binding missing")?;
    binding_scope(b, receipt.epoch, &receipt.status.phase)?;
    let bytes = read_stable_bounded(
        &receipt.observer_receipt,
        MAX_OBSERVER_RECEIPT_BYTES,
        "223 frozen status",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == receipt.observer_receipt_sha256,
        "223 frozen status digest"
    );
    let v: Value = serde_json::from_slice(&bytes)?;
    let p: Publication =
        serde_json::from_value(bound_json(&serde_json::from_value(v["plan"].clone())?)?)?;
    let t = task(&p.task)?;
    validate_frozen(&v, &p, &t)?;
    let mut expected = binding(&p, &t);
    expected.model_sha256 = receipt.observer_receipt_sha256.clone();
    ensure!(
        *b == expected
            && b.model_path == receipt.observer_receipt
            && v["status"] == serde_json::to_value(&receipt.status)?
            && receipt.controller_invocation_id.is_empty()
            && receipt.producer_invocation_id.is_empty()
            && receipt.schema == PIPELINE_STATUS_RECEIPT_SCHEMA
            && receipt.authenticated_readback,
        "223 status receipt does not reproduce actual task and original clock"
    );
    Ok(t)
}
pub(super) fn inactive_owner(
    receipt: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    if receipt
        .pipeline_binding
        .as_ref()
        .is_none_or(|b| b.claim_phase != CLAIM)
    {
        return Ok(None);
    }
    let t = frozen_owner(receipt)?;
    Ok(Some((t.actor.unit, t.actor.invocation_id)))
}
pub(super) fn matches(
    receipt: &StatusPublicationReceipt,
    epoch: u64,
    census: &BTreeMap<String, Value>,
) -> bool {
    epoch == 223
        && frozen_owner(receipt).is_ok_and(|t| {
            census
                .get(&t.actor.unit)
                .is_some_and(|r| live_shape(&t.actor, r))
                && guard_for(&t)
                    .is_ok_and(|g| census.get(&g.unit).is_some_and(|r| live_shape(&g, r)))
        })
}

fn terminal_shape(a: &Actor, row: &Value) -> bool {
    row["Id"] == a.unit
        && row["MainPID"] == "0"
        && ((row["LoadState"] == "not-found"
            && row["ActiveState"] == "inactive"
            && row["SubState"] == "dead"
            && row["InvocationID"] == "")
            || (row["InvocationID"] == a.invocation_id
                && row["NRestarts"] == "0"
                && matches!(row["ActiveState"].as_str(), Some("inactive" | "failed"))
                && matches!(row["SubState"].as_str(), Some("dead" | "failed"))))
}
fn terminal_journal(bytes: &[u8], a: &Actor) -> Result<u64> {
    let rows = serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let rows = rows
        .iter()
        .filter(|r| r["_PID"] == "1" && r["_UID"] == "0" && r["UNIT"] == a.unit)
        .collect::<Vec<_>>();
    ensure!(
        rows.last()
            .is_some_and(|r| r["INVOCATION_ID"] == a.invocation_id),
        "223 latest PID1 lifecycle is a replacement or missing"
    );
    let mut started = None;
    let mut stopped = None;
    for (index, row) in rows.iter().enumerate() {
        if row["INVOCATION_ID"] != a.invocation_id {
            continue;
        }
        let message = row["MESSAGE"]
            .as_str()
            .context("223 terminal PID1 message")?;
        if message.starts_with(&format!("Started {} - ", a.unit)) {
            ensure!(
                started.replace(index).is_none(),
                "223 restarted/duplicate native task lifecycle"
            );
        }
        if message == format!("{}: Deactivated successfully.", a.unit)
            || message.starts_with(&format!("{}: Failed with result ", a.unit))
            || (message.starts_with(&format!("Stopped {} - ", a.unit))
                && row["JOB_RESULT"] == "done")
        {
            stopped = Some((
                index,
                row["__REALTIME_TIMESTAMP"]
                    .as_str()
                    .context("223 actual terminal clock")?
                    .parse::<u64>()?
                    / 1000,
            ));
        }
        ensure!(
            !message.contains("Scheduled restart job"),
            "223 repair restart cannot be silently retired"
        );
    }
    let (index, time) = stopped.context("223 genuine PID1 terminal event missing")?;
    ensure!(
        time > 0 && started.is_some_and(|start| index > start),
        "223 terminal event precedes actual start"
    );
    Ok(time)
}
fn terminal_task(e: &Value) -> Result<(Task, u64)> {
    ensure!(
        e["schema"] == TERMINAL
            && e["epoch"] == 223
            && e["archive_completion_claimed"] == false
            && e["publication_authorized"] == false
            && e["r2_mutations"] == false,
        "223 task terminal scope/authority differs"
    );
    let t = task(&serde_json::from_value(e["task"].clone())?)?;
    let journal: BoundFile = serde_json::from_value(e["manager_journal"].clone())?;
    let bytes = read_stable_bounded(
        &journal.path,
        16 << 20,
        "223 genuine task PID1 terminal journal",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == journal.sha256,
        "223 terminal journal digest changed"
    );
    let time = terminal_journal(&bytes, &t.actor)?;
    ensure!(
        terminal_shape(&t.actor, &e["manager"])
            && e["terminal_unix_millis"] == time
            && e["recorded_unix_millis"]
                .as_u64()
                .is_some_and(|n| n >= time),
        "223 task terminal manager/clock differs"
    );
    Ok((t, time))
}
pub(super) fn capture_terminal() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-demotion223-task-terminal")?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "223 terminal capture requires root"
    );
    let p: TerminalSpec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        p.schema == "jetstreamer-epoch223-demotion-task-terminal-spec-v1",
        "223 terminal capture spec differs"
    );
    let t = task(&p.task)?;
    let before = manager(&t.actor.unit)?;
    ensure!(
        terminal_shape(&t.actor, &before),
        "223 task is still live/replaced; do not remove its countdown"
    );
    let bytes = read_stable_bounded(
        &p.manager_journal.path,
        16 << 20,
        "223 supplied actual terminal journal",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == p.manager_journal.sha256,
        "223 terminal journal binding differs"
    );
    let time = terminal_journal(&bytes, &t.actor)?;
    let value = json!({"schema":TERMINAL,"epoch":223,"task":p.task,"manager":before,"manager_journal":p.manager_journal,
        "terminal_unix_millis":time,"recorded_unix_millis":millis()?,"capture_spec":binding,"capture_executable_sha256":self_sha,
        "archive_completion_claimed":false,"publication_authorized":false,"r2_mutations":false});
    terminal_task(&value)?;
    ensure!(
        manager(&t.actor.unit)? == before,
        "223 terminal actor changed during capture"
    );
    private157::immutable_receipt(&p.output, &value)?;
    Ok(())
}
pub(super) fn cleanup_time(epoch: u64, e: &Value) -> Result<Option<u64>> {
    if e["schema"] != TERMINAL {
        return Ok(None);
    }
    ensure!(epoch == 223, "223 terminal proof used for another epoch");
    let (_, time) = terminal_task(e)?;
    Ok(Some(time / 1000))
}
pub(super) fn cleanup_current(
    epoch: u64,
    e: &Value,
    current: &BTreeMap<String, Value>,
    owners: &[(String, String)],
) -> Result<bool> {
    if e["schema"] != TERMINAL {
        return Ok(false);
    }
    ensure!(epoch == 223, "223 cleanup epoch differs");
    let (t, _) = terminal_task(e)?;
    ensure!(
        owners == [(t.actor.unit.clone(), t.actor.invocation_id.clone())]
            && current
                .get(&t.actor.unit)
                .is_some_and(|r| terminal_shape(&t.actor, r)),
        "223 cleanup owner is active, replaced or not the captured terminal task"
    );
    Ok(true)
}

pub(super) fn event_schema(value: &Value) -> bool {
    value["schema"] == TASK || value["schema"] == TERMINAL || phase_schema(value)
}
fn event_task(plan: &Plan, event: &Value) -> Result<Task> {
    let binding = plan
        .metadata_event
        .as_ref()
        .context("223 lifecycle binding missing")?;
    if event["schema"] == TASK {
        return task(binding);
    }
    if event["schema"] == TERMINAL {
        return Ok(terminal_task(event)?.0);
    }
    ensure!(phase_schema(event), "223 unknown lifecycle event");
    let rows = plan
        .pipeline_claims
        .iter()
        .filter(|c| {
            c.epoch == 223
                && scope(&c.phase, &c.unit)
                && event["runner"]["unit"] == c.unit
                && event["runner"]["invocation_id"] == c.invocation_id
        })
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1 && rows[0].evidence.len() == 1,
        "223 phase event lacks one registered actual task"
    );
    let t = task(&rows[0].evidence[0])?;
    phase_sample(&t, event)?;
    Ok(t)
}

pub(super) fn event_predecessor(
    previous: &Value,
    plan: &Plan,
    current_binding: &BoundFile,
    event: &Value,
    sample: &str,
    now: u64,
) -> Result<()> {
    ensure!(
        event_schema(event)
            && plan.first_epoch == 201
            && plan.last_epoch == 300
            && previous["schema"] == SCHEMA
            && previous["first_epoch"] == 201
            && previous["last_epoch"] == 300
            && previous["sampled_at_utc"] == sample
            && previous["observer_sha256"] == plan.observer.sha256
            && previous["observer_receipt"].as_str() == plan.observer.path.to_str()
            && plan.admission_transition_guard.is_none(),
        "223 lifecycle must retain exact accepted complete observer and predecessor"
    );
    let t = event_task(plan, event)?;
    let recorded = if event["schema"] == TASK {
        t.captured_unix_millis
    } else if phase_schema(event) {
        phase_sample(&t, event)?
    } else {
        event["recorded_unix_millis"]
            .as_u64()
            .context("223 terminal event clock")?
    };
    let cutoff = utc_seconds(sample)?
        .checked_mul(1000)
        .context("223 lifecycle cutoff overflow")?;
    ensure!(
        cutoff <= recorded
            && recorded / 1000 <= now
            && now - recorded / 1000 <= 300
            && recorded - cutoff <= 1_800_000,
        "223 lifecycle event is not immediate/fresh relative to coordinated sample"
    );
    let old_binding: BoundFile =
        serde_json::from_value(json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}))?;
    let old = bound_json(&old_binding)?;
    let current = bound_json(current_binding)?;
    let old_claims = old["pipeline_claims"]
        .as_array()
        .context("223 previous complete pipeline claims")?;
    let exact = |row: &Value| {
        row["epoch"] == 223
            && row["phase"] == CLAIM
            && row["unit"] == t.actor.unit
            && row["invocation_id"] == t.actor.invocation_id
    };
    let new_claims = current["pipeline_claims"]
        .as_array()
        .context("223 current complete pipeline claims")?;
    if event["schema"] == TASK {
        ensure!(
            !old_claims.iter().any(exact) && new_claims.iter().filter(|r| exact(r)).count() == 1,
            "223 launch event must add exactly the genuine new task"
        );
    } else {
        ensure!(
            old_claims.iter().filter(|r| exact(r)).count() == 1 && new_claims == old_claims,
            "223 terminal event must preserve original task claim, not erase history"
        );
    }
    let g = guard_for(&t)?;
    ensure!(
        normalized_plan(current, &old, &t.actor, &g, event["schema"] == TASK)?
            == normalized_plan(old.clone(), &old, &t.actor, &g, false)?,
        "223 lifecycle changed another owner, resource policy, gate or campaign plan"
    );
    Ok(())
}
fn normalized_plan(
    mut value: Value,
    old: &Value,
    actor: &Actor,
    guard: &Actor,
    strip_new: bool,
) -> Result<Value> {
    value
        .as_object_mut()
        .context("223 fleet plan object")?
        .remove("previous_fleet");
    value
        .as_object_mut()
        .context("223 fleet plan object")?
        .remove("metadata_event");
    value["gates"]["223"]
        .as_object_mut()
        .context("223 repair gate")?
        .remove("next_action");
    if strip_new {
        value["pipeline_claims"]
            .as_array_mut()
            .context("223 new claims")?
            .retain(|r| {
                !(r["epoch"] == 223
                    && r["phase"] == CLAIM
                    && r["unit"] == actor.unit
                    && r["invocation_id"] == actor.invocation_id)
            });
        let old_names = old["tracked_units"]
            .as_array()
            .context("223 old tracked units")?;
        value["tracked_units"]
            .as_array_mut()
            .context("223 tracked units")?
            .retain(|name| {
                old_names.contains(name)
                    || !(name.as_str() == Some(actor.unit.as_str())
                        || name.as_str() == Some(guard.unit.as_str()))
            });
    }
    Ok(value)
}

pub(super) fn event_census(plan: &Plan, current: &BTreeMap<String, Value>) -> Result<()> {
    let Some(binding) = &plan.metadata_event else {
        return Ok(());
    };
    let event = bound_json(binding)?;
    if !event_schema(&event) {
        return Ok(());
    }
    let t = event_task(plan, &event)?;
    let guard = guard_for(&t)?;
    let previous = bound_json(
        plan.previous_fleet
            .as_ref()
            .context("223 event predecessor")?,
    )?;
    let old = previous["unit_census"]
        .as_object()
        .context("223 original complete unit census")?;
    for (name, row) in current {
        if name == &t.actor.unit || name == &guard.unit {
            continue;
        }
        let old = old
            .get(name)
            .context("223 lifecycle introduced an unrelated unit")?;
        let mut normalized = row.clone();
        if row["ExecStart"]
            .as_str()
            .zip(old["ExecStart"].as_str())
            .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b))
        {
            normalized["ExecStart"] = old["ExecStart"].clone();
        }
        ensure!(
            normalized == *old,
            "223 lifecycle changed another live owner:{name}"
        );
    }
    ensure!(
        old.keys().all(|name| current.contains_key(name)),
        "223 lifecycle dropped an existing owner"
    );
    if event["schema"] == TASK || phase_schema(&event) {
        ensure!(
            current
                .get(&t.actor.unit)
                .is_some_and(|r| live_shape(&t.actor, r))
                && current
                    .get(&guard.unit)
                    .is_some_and(|r| live_shape(&guard, r)),
            "223 launch task/guard absent from actual census"
        );
    } else {
        ensure!(
            current
                .get(&t.actor.unit)
                .is_some_and(|r| terminal_shape(&t.actor, r)),
            "223 terminal event owner is active or replaced"
        );
    }
    Ok(())
}

pub(super) fn resource_contract(c: &PipelineClaim) -> Result<Value> {
    validate_claim(c, None)?;
    let t = task(&c.evidence[0])?;
    let row = observe(&t.actor, &t.job_kind)?;
    let guard = guard_for(&t)?;
    observe(&guard, "guard")?;
    resource::sample(&t, &row)
}

pub(super) fn discovered(name: &str) -> bool {
    scope(CLAIM, name) || guard_name(name)
}
pub(super) fn claim_names(c: &PipelineClaim) -> Result<BTreeSet<String>> {
    validate_claim(c, None)?;
    let t = task(&c.evidence[0])?;
    Ok([t.actor.unit.clone(), guard_for(&t)?.unit]
        .into_iter()
        .collect())
}

async fn publish_bound(
    s3: &Client,
    r2: &R2Config,
    status: &EpochStatus,
    prior: Option<&str>,
) -> Result<(String, Option<String>)> {
    // A prior Put may have succeeded before its local receipt fsync. Exact
    // frozen bytes permit only authenticated receipt recovery; all changes
    // remain conditional on the owned predecessor version.
    let object = get_mutable_object(s3, &r2.bucket, "epoch-223.epoch-status.json").await?;
    let expected = if object
        .as_ref()
        .is_some_and(|o| epoch_status_bytes(status).is_ok_and(|bytes| o.bytes == bytes))
    {
        object.as_ref().map(|o| o.etag.as_str())
    } else {
        prior
    };
    publish_epoch_status_bound_previous(s3, r2, status, expected).await
}

fn readable_metadata(path: &Path, bytes: &[u8]) -> Result<BoundFile> {
    ensure!(
        bytes.len() <= 1 << 20 && path.is_absolute(),
        "223 non-sensitive readable metadata bound"
    );
    let parent = path.parent().context("223 readable metadata parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o755 && parent.canonicalize()? == parent,
        "223 task metadata requires its own pre-created root-owned0755 directory; never relax private evidence"
    );
    if path.try_exists()? {
        let old = read_stable_bounded(path, 1 << 20, "223 readable metadata idempotent retry")?;
        let own = fs::symlink_metadata(path)?;
        ensure!(
            old == bytes && own.uid() == 0 && own.nlink() == 1 && own.mode() & 0o777 == 0o444,
            "223 existing task/spec is not an identical immutable receipt"
        );
    } else {
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o444))?;
        temp.write_all(bytes)?;
        temp.as_file().sync_all()?;
        let after = fs::symlink_metadata(parent)?;
        ensure!(
            after.dev() == m.dev()
                && after.ino() == m.ino()
                && after.uid() == 0
                && after.mode() & 0o777 == 0o755,
            "223 readable metadata parent changed"
        );
        temp.persist_noclobber(path)
            .map_err(|e| anyhow!("223 task metadata occupied:{e}"))?;
        File::open(parent)?.sync_all()?;
    }
    Ok(BoundFile {
        path: path.into(),
        sha256: hex_lower(&Sha256::digest(bytes)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bound(name: &str) -> BoundFile {
        BoundFile {
            path: format!("/sealed/fixture/{name}").into(),
            sha256: "a".repeat(64),
        }
    }
    fn fixture(kind: &str) -> (Task, Publication) {
        let name = if kind == "native-input" {
            "horizon-native-input-223-demotion-fixture.service"
        } else {
            "horizon-qualify-223-demotion-bracket-fixture.service"
        };
        let plan = bound("runtime.json");
        let mut actor = Actor {
            unit: name.into(),
            invocation_id: "b".repeat(32),
            pid: 11,
            start_ticks: 22,
            cgroup: format!("/system.slice/{name}"),
            boot_id: "fixture-boot".into(),
            executable: bound("utility"),
            expected_exec_start: String::new(),
        };
        actor.expected_exec_start = command(&actor, &plan, kind);
        let row = json!({"Id":name,"InvocationID":actor.invocation_id,"LoadState":"loaded","ActiveState":"active","SubState":"running",
            "NRestarts":"0","MainPID":"11","ControlGroup":actor.cgroup,"ExecStart":actor.expected_exec_start});
        let t = Task {
            schema: TASK.into(),
            epoch: 223,
            job_kind: kind.into(),
            actor,
            runtime_plan: plan,
            actor_launch: bound("launch"),
            role_qualification: bound("qualification"),
            guard: bound("guard"),
            guard_qualification: bound("guard-qualification"),
            predecessor_task: None,
            predecessor_terminal: None,
            origin_clock: bound("origin"),
            eta_policy: bound("policy"),
            original_start_unix_millis: 1,
            actor_start_unix_millis: 2,
            captured_unix_millis: 3,
            run_root: "/fixture".into(),
            run_root_device: 1,
            run_root_inode: 2,
            cgroup_device: 3,
            cgroup_inode: 4,
            manager: row,
            capture_spec: bound("capture"),
            capture_spec_source: bound("capture"),
            capture_executable_sha256: "a".repeat(64),
            publication_authorized: false,
            r2_mutations: false,
        };
        let p = Publication {
            schema: "jetstreamer-epoch223-demotion-status-plan-v1".into(),
            mode: "routine".into(),
            task: bound("task"),
            observer: bound("observer"),
            fleet: bound("fleet"),
            predecessor: None,
            event: None,
            estimate_receipt: "/private/estimate".into(),
            receipt_directory: "/private/receipts".into(),
        };
        (t, p)
    }
    fn publication(t: &Task, p: &Publication) -> StatusPublicationReceipt {
        StatusPublicationReceipt {
            schema: PIPELINE_STATUS_RECEIPT_SCHEMA.into(),
            bucket: "fixture".into(),
            epoch: 223,
            key: "epoch-223.epoch-status.json".into(),
            status: EpochStatus {
                epoch: 223,
                jet_size_bytes: 0,
                elapsed_execution_millis: 1,
                estimated_remaining_millis: 1,
                sampled_at_utc: "2026-10-25T00:00:00Z".into(),
                phase: "verification".into(),
            },
            object_etag: "fixture".into(),
            previous_object_etag: None,
            observer_receipt: p.estimate_receipt.clone(),
            observer_receipt_sha256: "a".repeat(64),
            controller_invocation_id: String::new(),
            producer_invocation_id: String::new(),
            authenticated_readback: true,
            verified_unix_seconds: 1,
            pipeline_binding: Some(binding(p, t)),
        }
    }
    #[test]
    fn actual_owner_shape_rejects_replacement_restart_pid_and_sleeping_intent() {
        let (mut t, _) = fixture("native-input");
        actor_shape(&t.actor, &t.job_kind, &t.runtime_plan).unwrap();
        assert!(live_shape(&t.actor, &t.manager));
        for (key, value) in [
            ("InvocationID", json!("c".repeat(32))),
            ("NRestarts", json!("1")),
            ("MainPID", json!("12")),
            ("ActiveState", json!("inactive")),
            ("ControlGroup", json!("/foreign")),
        ] {
            let mut row = t.manager.clone();
            row[key] = value;
            assert!(!live_shape(&t.actor, &row), "{key}");
        }
        t.actor.expected_exec_start =
            "{ path=/bin/sleep ; argv[]=/bin/sleep 99999 ; ignore_errors=no }".into();
        assert!(actor_shape(&t.actor, &t.job_kind, &t.runtime_plan).is_err());
        assert!(!scope(CLAIM, ORIGIN_UNIT));
        assert!(!scope(
            CLAIM,
            "horizon-native-input-224-demotion-fixture.service"
        ));
    }
    #[test]
    fn status_binding_keeps_e70_clock_and_native_is_never_entry_replay() {
        let (t, p) = fixture("native-input");
        let mut b = binding(&p, &t);
        b.model_sha256 = "a".repeat(64);
        b.validate(223, "verification").unwrap();
        assert!(b.validate(223, "replay").is_err());
        for phase in ["upload", "readback", "qualification", "publication"] {
            assert!(b.validate(223, phase).is_err());
        }
        b.origin_invocation_id = t.actor.invocation_id.clone();
        assert!(b.validate(223, "verification").is_err());
        let (t, p) = fixture("bracket");
        let mut b = binding(&p, &t);
        b.model_sha256 = "a".repeat(64);
        b.validate(223, "replay").unwrap();
        assert!(b.validate(224, "replay").is_err());
    }
    #[test]
    fn thirty_minute_refresh_has_only_explicit_user_and_genuine_lifecycle_exceptions() {
        let (mut t, mut p) = fixture("native-input");
        let old = publication(&t, &p);
        let prior = utc_seconds(&old.status.sampled_at_utc).unwrap() * 1000;
        let routine =
            json!({"observation_reason":"routine","routine_minimum_interval_enforced":true});
        assert!(cadence(&p, &t, &routine, prior + 1_799_999, Some(&old)).is_err());
        cadence(&p, &t, &routine, prior + 1_800_000, Some(&old)).unwrap();
        let request = json!({"observation_reason":"user-requested-status","routine_minimum_interval_enforced":false});
        cadence(&p, &t, &request, prior + 1000, Some(&old)).unwrap();
        assert!(cadence(&p, &t, &request, prior - 1, Some(&old)).is_err());
        p.mode = "launch-event".into();
        p.event = Some(p.task.clone());
        t.captured_unix_millis = prior + 1000;
        assert!(cadence(&p, &t, &routine, t.captured_unix_millis, Some(&old)).is_err());
        t.actor.invocation_id = "d".repeat(32);
        cadence(&p, &t, &routine, t.captured_unix_millis, Some(&old)).unwrap();
        p.mode = "queued-plan".into();
        assert!(cadence(&p, &t, &routine, prior + 1000, None).is_err());
    }
    #[test]
    fn journal_progress_is_invocation_bound_and_requires_the_real_node_logger() {
        let (t, _) = fixture("bracket");
        let row = |message: &str| {
            json!({"_SYSTEMD_UNIT":t.actor.unit,"_SYSTEMD_INVOCATION_ID":t.actor.invocation_id,
            "__REALTIME_TIMESTAMP":"1000000","MESSAGE":message})
        };
        let good =
            row("[2026-10-25T00:00:00Z INFO jetstreamer_node] progress slot 96335539/96544588");
        assert_eq!(
            parsed_progress(&serde_json::to_vec(&good).unwrap(), &t, 1000)
                .unwrap()
                .len(),
            1
        );
        let injected = row(
            "Program log: [2026-10-25T00:00:00Z INFO jetstreamer_node] progress slot 96544588/96544588",
        );
        assert!(
            parsed_progress(&serde_json::to_vec(&injected).unwrap(), &t, 1000)
                .unwrap()
                .is_empty()
        );
        let mut foreign = good.clone();
        foreign["_SYSTEMD_INVOCATION_ID"] = json!("e".repeat(32));
        assert!(parsed_progress(&serde_json::to_vec(&foreign).unwrap(), &t, 1000).is_err());
        assert!(parsed_progress(&serde_json::to_vec(&good).unwrap(), &t, 999).is_err());
        let (native, _) = fixture("native-input");
        let mut impossible = good;
        impossible["_SYSTEMD_UNIT"] = json!(native.actor.unit);
        assert!(parsed_progress(&serde_json::to_vec(&impossible).unwrap(), &native, 1000).is_err());
    }
    #[test]
    fn positive_terminal_history_rejects_a_newer_owner_and_a_live_task() {
        let (t, _) = fixture("native-input");
        let row = |message: String, time: &str| {
            json!({"_PID":"1","_UID":"0","UNIT":t.actor.unit,
            "INVOCATION_ID":t.actor.invocation_id,"MESSAGE":message,"__REALTIME_TIMESTAMP":time})
        };
        let started = row(format!("Started {} - fixture.", t.actor.unit), "1000000");
        let stopped = row(
            format!("{}: Deactivated successfully.", t.actor.unit),
            "2000000",
        );
        let bytes = format!("{}\n{}\n", started, stopped);
        assert_eq!(terminal_journal(bytes.as_bytes(), &t.actor).unwrap(), 2000);
        let mut later = started.clone();
        later["INVOCATION_ID"] = json!("f".repeat(32));
        assert!(terminal_journal(format!("{bytes}{later}\n").as_bytes(), &t.actor).is_err());
        assert!(!terminal_shape(&t.actor, &t.manager));
        let collected = json!({"Id":t.actor.unit,"LoadState":"not-found","ActiveState":"inactive","SubState":"dead","MainPID":"0","InvocationID":""});
        assert!(terminal_shape(&t.actor, &collected));
        let mut replaced = collected;
        replaced["LoadState"] = json!("loaded");
        replaced["InvocationID"] = json!("f".repeat(32));
        assert!(!terminal_shape(&t.actor, &replaced));
    }
    #[test]
    fn same_sample_events_cannot_change_other_owners_floors_or_private_gates() {
        let (t, _) = fixture("native-input");
        let mut guard = t.actor.clone();
        guard.unit = "horizon-guard-223-demotion-fixture.service".into();
        let old = json!({"tracked_units":["legacy.service"],"pipeline_claims":[],"gates":{"223":{"state":"failed-needs-repair","next_action":"old"}},
            "reserve_bytes":123,"other_owner":{"unit":"legacy.service","iid":"unchanged"}});
        let mut current = old.clone();
        current["tracked_units"] = json!(["legacy.service", t.actor.unit, guard.unit]);
        current["pipeline_claims"] = json!([{"epoch":223,"phase":CLAIM,"unit":t.actor.unit,"invocation_id":t.actor.invocation_id}]);
        current["gates"]["223"]["next_action"] = json!("new actual task");
        assert_eq!(
            normalized_plan(current.clone(), &old, &t.actor, &guard, true).unwrap(),
            normalized_plan(old.clone(), &old, &t.actor, &guard, false).unwrap()
        );
        for (field, value) in [
            ("reserve_bytes", json!(1)),
            (
                "other_owner",
                json!({"unit":"legacy.service","iid":"replacement"}),
            ),
        ] {
            let mut bad = current.clone();
            bad[field] = value;
            assert_ne!(
                normalized_plan(bad, &old, &t.actor, &guard, true).unwrap(),
                normalized_plan(old.clone(), &old, &t.actor, &guard, false).unwrap()
            );
        }
        current["gates"]["223"]["state"] = json!("post-replay-pipeline");
        assert_ne!(
            normalized_plan(current, &old, &t.actor, &guard, true).unwrap(),
            normalized_plan(old.clone(), &old, &t.actor, &guard, false).unwrap()
        );
    }
}
