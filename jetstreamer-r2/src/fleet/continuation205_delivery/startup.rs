//! Continuation 205 same-process rendezvous. No archive bytes are read before release.
use super::peer::{CANONICAL, binding, id, is_live, issuer, no_file, sealed, write_bound as write};
use super::*;
use std::io::Read;
use std::time::{Duration, Instant};
const WAIT: u64 = 300;
const RELEASE_AGE: u64 = 15;
const GUARD_AGE: u64 = 30;
pub(super) const GUARD_MEMORY: u64 = 1 << 30;
const ROOT_CAP: u64 = OUTPUT_MAX * 3 + (128 << 20);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    stage: downstream::Stage,
    runner: BoundFile,
    runner_seal: BoundFile,
    preparation: BoundFile,
    guard: BoundFile,
    guard_seal: BoundFile,
    guard_unit: String,
    guard_receipt_directory: PathBuf,
    guard_plan_path: PathBuf,
    waiting: PathBuf,
    release: PathBuf,
    maximum_wait_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSpec {
    schema: String,
    stage_spec: BoundFile,
    waiting: BoundFile,
    guard_plan: BoundFile,
    resource_basis: Value,
    capacity_output: PathBuf,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn distinct_roots(control: &Path, writable: &[&Path]) -> Result<()> {
    ensure!(
        writable
            .iter()
            .all(|root| !control.starts_with(root) && !root.starts_with(control)),
        "205 startup control custody overlaps a writable root"
    );
    Ok(())
}
fn native_deadline(process: &Value, at: u64) -> Result<()> {
    let begin = n(&process["clock"], "started_unix_seconds")?;
    ensure!(
        begin <= at && at - begin < WAIT,
        "205 native waiting process exceeded startup deadline"
    );
    Ok(())
}
fn unit(name: &str) -> Result<Value> {
    Ok(serde_json::to_value(
        completed_archive_phase::root205_properties(
            name,
            "Id,LoadState,Type,ActiveState,SubState,InvocationID,NRestarts,Result,ExecMainStatus,ExecStart,ControlGroup,MainPID",
        )?,
    )?)
}
fn guard_name(stage: downstream::Stage) -> Result<&'static str> {
    use downstream::Stage;
    Ok(match stage {
        Stage::Full => "horizon-205-delivery-full-protective-v1.service",
        Stage::Plugin => "horizon-205-delivery-plugin-protective-v1.service",
        Stage::Boundary => "horizon-205-delivery-boundary-protective-v1.service",
        Stage::Import => "horizon-205-delivery-import-protective-v1.service",
        Stage::Upload => "horizon-205-delivery-upload-protective-v1.service",
        Stage::Assembly => bail!("205 continuation delivery has no assembly startup authority"),
    })
}
fn plan(x: &downstream::StageSpec) -> Result<(BoundFile, Plan)> {
    let binding = x
        .startup
        .as_ref()
        .context("205 downstream requires a root startup plan")?;
    let p: Plan = serde_json::from_value(read(binding)?)?;
    ensure!(
        p.schema == "jetstreamer-root205-delivery-startup-plan-v1"
            && p.stage == x.stage
            && p.maximum_wait_seconds == WAIT
            && p.guard_unit == guard_name(x.stage)?
            && p.waiting == x.output_directory.join("waiting.json")
            && p.release.file_name().is_some_and(|n| n == "release.json")
            && !p.release.starts_with(&x.output_directory)
            && !p.release.starts_with(&x.scan_directory)
            && p.guard_receipt_directory != x.output_directory
            && p.guard_receipt_directory != x.scan_directory,
        "205 root startup plan scope differs"
    );
    private(&p.guard_receipt_directory)?;
    let mut writable = vec![x.output_directory.as_path(), x.scan_directory.as_path()];
    if x.stage == downstream::Stage::Import {
        writable.push(Path::new(CANONICAL));
    }
    if matches!(
        x.stage,
        downstream::Stage::Import | downstream::Stage::Upload
    ) {
        writable.push(Path::new(
            "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock",
        ));
    }
    for control in [
        p.guard_receipt_directory.as_path(),
        p.release.parent().context("205 release parent")?,
        p.guard_plan_path
            .parent()
            .context("205 guard plan parent")?,
    ] {
        distinct_roots(control, &writable)?;
    }
    distinct_roots(
        p.release.parent().context("205 release parent")?,
        &[p.guard_receipt_directory.as_path()],
    )?;
    ensure!(
        p.guard_plan_path
            .file_name()
            .is_some_and(|n| n == "guard-plan.json")
            && p.guard_plan_path.parent() != Some(x.output_directory.as_path())
            && p.guard_plan_path.parent() != Some(x.scan_directory.as_path())
            && p.guard_plan_path.parent() != Some(p.guard_receipt_directory.as_path())
            && p.guard_plan_path.parent() != Some(Path::new(ROOT)),
        "205 startup guard plan must be outside writable payload roots"
    );
    private(
        p.guard_plan_path
            .parent()
            .context("205 guard plan parent missing")?,
    )?;
    ensure!(
        p.guard_receipt_directory != Path::new(ROOT)
            && p.release.parent() != Some(Path::new(ROOT))
            && p.release.parent() != Some(p.guard_receipt_directory.as_path()),
        "205 startup release or guard receipts escaped separate custody roots"
    );
    private(p.release.parent().context("205 release parent missing")?)?;
    sealed(&p.runner, 256 << 20)?;
    assembly204_recovery::deployed_delivery_member(&p.runner_seal, &p.runner, 256 << 20)?;
    assembly204_recovery::deployed_delivery_member(&p.guard_seal, &p.guard, 256 << 20)?;
    delivery::validate_stage(&p.preparation, x)?;
    Ok((binding.clone(), p))
}
pub(super) fn before_admission(x: &downstream::StageSpec) -> Result<()> {
    let (_, p) = plan(x)?;
    no_file(&p.waiting)?;
    no_file(&p.release)
}
fn native(path: impl AsRef<Path>, maximum: u64) -> Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "205 startup native metadata exceeded bound"
    );
    Ok(String::from_utf8(bytes)?)
}
fn native_credentials(raw: &str) -> Result<Value> {
    let fields = raw
        .lines()
        .filter_map(|l| l.split_once(':'))
        .collect::<BTreeMap<_, _>>();
    for key in ["Uid", "Gid"] {
        ensure!(
            fields
                .get(key)
                .is_some_and(|v| v.split_whitespace().collect::<Vec<_>>() == ["0", "0", "0", "0"]),
            "205 native root credentials differ"
        );
    }
    for key in ["CapEff", "CapPrm", "CapBnd", "CapAmb"] {
        ensure!(
            fields
                .get(key)
                .is_some_and(|v| v.trim() == "0000000000080002"),
            "205 exact native capabilities differ: {key}"
        );
    }
    Ok(
        json!({"uid":0,"gid":0,"effective":"0000000000080002","permitted":"0000000000080002","bounding":"0000000000080002","ambient":"0000000000080002"}),
    )
}
fn snapshot(
    x: &downstream::StageSpec,
    spec: &BoundFile,
    p: &Plan,
    owner: &Value,
    waiting: bool,
) -> Result<Value> {
    let pid = s(owner, "MainPID")?.parse::<u32>()?;
    ensure!(
        pid > 1 && is_live(owner) && owner["Id"] == x.stage.unit(),
        "205 startup owner is not live"
    );
    let proc = Path::new("/proc").join(pid.to_string());
    let ticks =
        completed_archive_phase::root205_start_ticks(&native(proc.join("stat"), 64 << 10)?)?;
    let exe = fs::read_link(proc.join("exe"))?;
    let cmd = native(proc.join("cmdline"), 64 << 10)?.into_bytes();
    let environment = native(proc.join("environ"), 1 << 20)?;
    let credential_digest = completed_archive_phase::root205_credential_digest(
        &environment,
        x.environment_file.as_ref(),
    )?;
    for entry in environment.split('\0') {
        let key = entry.split('=').next().unwrap_or("");
        ensure!(
            ![
                "LD_PRELOAD",
                "LD_AUDIT",
                "LD_LIBRARY_PATH",
                "BASH_ENV",
                "ENV",
                "PYTHONPATH",
                "PYTHONHOME",
                "RUBYOPT",
                "PERL5OPT",
                "GCONV_PATH"
            ]
            .contains(&key),
            "205 startup inherited unsafe execution variable"
        );
    }
    let capabilities = native_credentials(&native(proc.join("status"), 64 << 10)?)?;
    let expected = vec![
        p.runner.path.display().to_string(),
        "run-continuation205-delivery-stage".into(),
        spec.path.display().to_string(),
        "--spec-sha256".into(),
        spec.sha256.clone(),
        "--self-sha256".into(),
        p.runner.sha256.clone(),
    ];
    let mut encoded = expected.join("\0").into_bytes();
    encoded.push(0);
    ensure!(
        exe == p.runner.path
            && cmd == encoded
            && hex_lower(&Sha256::digest(fs::read(proc.join("exe"))?)) == p.runner.sha256,
        "205 startup running ELF or argv differs"
    );
    let group = format!("/system.slice/{}", x.stage.unit());
    ensure!(
        owner["ControlGroup"] == group
            && native(proc.join("cgroup"), 64 << 10)?.trim() == format!("0::{group}"),
        "205 startup cgroup differs"
    );
    let root = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    let mut limits = BTreeMap::new();
    for (key, value) in [
        ("memory.max", x.stage.memory().to_string()),
        ("memory.high", (x.stage.memory() / 4 * 3).to_string()),
        ("memory.swap.max", "0".into()),
        ("pids.max", "512".into()),
        ("cpu.max", "800000 100000".into()),
    ] {
        let actual = native(root.join(key), 1024)?.trim().to_owned();
        ensure!(actual == value, "205 startup native cap differs: {key}");
        limits.insert(key, actual);
    }
    let tasks = native(root.join("cgroup.procs"), 64 << 10)?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        tasks.contains(&pid) && tasks.len() <= 512 && (!waiting || tasks == [pid]),
        "205 waiter has already started another process"
    );
    let mount = native(proc.join("mountinfo"), 4 << 20)?;
    let source_mount_proof =
        completed_archive_phase::delivery_source_readonly_mount(Path::new(ROOT), &mount)?;
    ensure!(
        completed_archive_phase::root205_start_ticks(&native(proc.join("stat"), 64 << 10)?)?
            == ticks,
        "205 startup PID changed during snapshot"
    );
    Ok(
        json!({"pid":pid,"start_ticks":ticks,"clock":completed_archive_phase::root205_start_clock(ticks)?,
        "invocation_id":owner["InvocationID"],"cgroup":group,"limits":limits,"runner":p.runner,"argv":expected,
        "source_mount_proof":source_mount_proof,"credential_environment_sha256":credential_digest,"native_credentials":capabilities}),
    )
}
fn fresh(release: u64, guard: u64, at: u64, elapsed: Duration) -> Result<()> {
    ensure!(
        elapsed < Duration::from_secs(WAIT)
            && release <= at
            && at - release <= RELEASE_AGE
            && guard <= at
            && at - guard <= GUARD_AGE,
        "205 startup release/guard expired or wait deadline crossed"
    );
    Ok(())
}
fn release_matches(
    r: &Value,
    spec: &BoundFile,
    pb: &BoundFile,
    actual: &Value,
    waiting: &BoundFile,
) -> Result<()> {
    ensure!(
        r["schema"] == "jetstreamer-root205-delivery-release-v1"
            && r["stage_spec"] == private157::binding(spec)
            && r["startup_plan"] == private157::binding(pb)
            && r["process"] == *actual
            && r["waiting"] == private157::binding(waiting),
        "205 release belongs to another waiting owner"
    );
    deny(&r["authority"])
}
fn guard_shape(
    p: &Plan,
    x: &downstream::StageSpec,
    a: &Value,
    plan_binding: &BoundFile,
    g: &Value,
    sample: &Value,
    owner: &Value,
) -> Result<()> {
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && g["unit"] == x.stage.unit()
            && g["invocation_id"] == owner["InvocationID"]
            && g["filesystem"] == "/"
            && g["worker_root"] == serde_json::to_value(&x.scan_directory)?
            && g["receipt_directory"] == serde_json::to_value(&p.guard_receipt_directory)?
            && g["minimum_free_bytes"] == a["minimum_free_bytes"]
            && g["maximum_root_physical_bytes"] == ROOT_CAP
            && g["maximum_worker_vmas"] == 3500000
            && ["native_main", "bounded_measurement", "bounded_canary"]
                .iter()
                .all(|k| g.get(*k).is_none_or(Value::is_null)),
        "205 startup guard plan differs from fresh resource admission"
    );
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["plan"] == serde_json::to_value(&plan_binding.path)?
            && sample["plan_sha256"] == plan_binding.sha256
            && sample["guard_sha256"] == p.guard.sha256
            && id(s(sample, "guard_invocation_id")?)
            && sample["producer_invocation_id"] == owner["InvocationID"]
            && sample["producer"]["invocation_id"] == owner["InvocationID"]
            && sample["producer"]["pid"] == s(owner, "MainPID")?.parse::<u64>()?
            && sample["producer"]["restarts"] == 0
            && sample["producer"]["restart_policy"] == "no"
            && sample["producer"]["kill_mode"] == "control-group"
            && sample["producer"]["delegated"] == false
            && sample["producer"]["active"] == "active"
            && sample["producer"]["sub"] == "running"
            && sample["producer"]["cgroup"] == owner["ControlGroup"]
            && sample["producer_stop_enabled"] == true
            && sample["minimum_free_bytes"] == g["minimum_free_bytes"]
            && n(sample, "available_bytes")? >= n(g, "minimum_free_bytes")?
            && sample["workers"].as_array().is_some_and(Vec::is_empty)
            && sample["bounded_measurement"] == false
            && sample["maximum_root_physical_bytes"] == ROOT_CAP
            && sample["maximum_worker_vmas"] == 3500000
            && sample["remote_mutations"] == false
            && sample["r2_mutations"] == false
            && sample["root_physical_observation"]["exceeds_budget"] == false
            && n(
                &sample["root_physical_observation"],
                "conservative_physical_bytes"
            )? <= ROOT_CAP
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error",
                "target_handoff_error",
                "native_main",
                "bounded_canary"
            ]
            .iter()
            .all(|k| sample.get(*k).is_some_and(Value::is_null)),
        "205 startup lacks actual stop-enabled successful guard"
    );
    Ok(())
}
fn guard_manager(p: &Plan, binding: &BoundFile, g: &Value, sample: &Value) -> Result<Value> {
    let props = completed_archive_phase::root205_properties(
        &p.guard_unit,
        "Id,Type,User,Restart,KillMode,Delegate,NRestarts,MainPID,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,Result,ExecMainStatus,ActiveState,SubState,DropInPaths,NeedDaemonReload,Transient,InvocationID,ReadWritePaths,ExecStart,ExecCondition,ExecStartPre,ExecStartPost,ExecReload,ExecStop,ExecStopPost,OnSuccess,OnFailure,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment",
    )?;
    singleton227_capture::require(
        &props,
        &[
            ("Id", &p.guard_unit),
            ("Type", "oneshot"),
            ("User", "root"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("NRestarts", "0"),
            ("MainPID", "0"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("MemoryMax", "1073741824"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "256"),
            ("CPUQuotaPerSecUSec", "1s"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("DropInPaths", ""),
            ("NeedDaemonReload", "no"),
            ("Transient", "no"),
        ],
    )?;
    completed_archive_phase::root205_guard_controls(&props)?;
    ensure!(
        (props["InvocationID"].is_empty()
            || props["InvocationID"] == sample["guard_invocation_id"])
            && props["ReadWritePaths"] == s(g, "receipt_directory")?,
        "205 startup guard namespace/invocation changed"
    );
    let expected = format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no }}",
        p.guard.path.display(),
        p.guard.path.display(),
        binding.path.display(),
        binding.sha256,
        p.guard.sha256
    );
    ensure!(
        peer::command_matches(&props["ExecStart"], &expected),
        "205 guard command changed"
    );
    Ok(
        json!({"properties":props,"timer":completed_archive_phase::root205_guard_timer(&p.guard_unit)?}),
    )
}
pub(super) fn capacity_waiter(
    x: &downstream::StageSpec,
    spec: &BoundFile,
    waiting: &BoundFile,
    expected: &Value,
) -> Result<(String, Value)> {
    let (pb, p) = plan(x)?;
    no_file(&p.release)?;
    let saved = read(waiting)?;
    ensure!(
        waiting.path == p.waiting
            && saved["schema"] == "jetstreamer-root205-delivery-waiting-v1"
            && saved["stage_spec"] == private157::binding(spec)
            && saved["startup_plan"] == private157::binding(&pb)
            && saved["process"] == *expected,
        "205 capacity context is not the exact issued waiting marker"
    );
    let admission = downstream::saved_admission(x, spec, BYTES)?;
    let a = read(&admission)?;
    ensure!(
        a["runner"] == private157::binding(&p.runner),
        "205 capacity waiter changed admitted runner"
    );
    downstream::installed_stage(
        x,
        spec,
        &p.runner,
        &serde_json::from_value(a["unit_file"].clone())?,
        &p.runner.sha256,
    )?;
    let actual = snapshot(x, spec, &p, &unit(x.stage.unit())?, true)?;
    ensure!(
        actual == *expected,
        "205 capacity waiter PID/ticks/IID/native scope changed"
    );
    native_deadline(&actual, now()?)?;
    Ok((p.guard_unit, actual))
}
pub(super) fn release(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let r: ReleaseSpec = serde_json::from_value(v.clone())?;
    ensure!(
        r.schema == "jetstreamer-root205-delivery-release-spec-v1",
        "205 release spec schema"
    );
    let x = downstream::stage_spec(&read(&r.stage_spec)?)?;
    let (pb, p) = plan(&x)?;
    ensure!(
        p.runner.sha256 == self_sha && fs::read_link("/proc/self/exe")? == p.runner.path,
        "205 release issuer differs from runner"
    );
    no_file(&p.release)?;
    let waiting = read(&r.waiting)?;
    ensure!(
        r.waiting.path == p.waiting
            && waiting["stage_spec"] == private157::binding(&r.stage_spec)
            && waiting["startup_plan"] == private157::binding(&pb),
        "205 waiting marker binding differs"
    );
    let (completion, _) = lineage::load_source(&x.source)?;
    downstream::gates(&x)?;
    let admission =
        downstream::issued_admission(&x, &r.stage_spec, n(&completion, "archive_bytes")?)?;
    let a = read(&admission)?;
    downstream::installed_stage(
        &x,
        &r.stage_spec,
        &p.runner,
        &serde_json::from_value(a["unit_file"].clone())?,
        self_sha,
    )?;
    let owner = unit(x.stage.unit())?;
    let process = snapshot(&x, &r.stage_spec, &p, &owner, true)?;
    native_deadline(&process, now()?)?;
    ensure!(waiting["process"] == process, "205 waiter was replaced");
    let cap = capacity::waiting_stage_capacity(
        &r.resource_basis,
        &x,
        &r.stage_spec,
        &r.waiting,
        &process,
    )?;
    let capacity = write(&r.capacity_output, &cap)?;
    let g = read(&r.guard_plan)?;
    ensure!(
        r.guard_plan.path == p.guard_plan_path,
        "205 first guard changed its planned metadata path"
    );
    // Selection comes only from actual completed PID1/guard output, never a
    // caller's chosen sample or an asserted guard-success boolean.
    let latest = warmup223::completed_guard_binding(
        &p.guard_unit,
        &p.guard_receipt_directory,
        n(&process["clock"], "started_unix_seconds")?,
        now()?,
    )?;
    let sample_binding: BoundFile = serde_json::from_value(latest["binding"].clone())?;
    let sample = read(&sample_binding)?;
    ensure!(
        n(&process["clock"], "started_unix_seconds")?.saturating_add(1)
            >= n(&a, "recorded_unix_seconds")?
            && n(&process["clock"], "started_unix_seconds")?
                <= n(&sample, "recorded_unix_seconds")?
            && latest["history"]["events"][0]["_BOOT_ID"]
                == s(&process["clock"], "boot_id")?.replace('-', ""),
        "205 waiter/admission/first guard clocks or boot differ"
    );
    guard_shape(&p, &x, &cap, &r.guard_plan, &g, &sample, &owner)?;
    warmup223::validate_completed_guard_history(&latest["history"], &sample)?;
    ensure!(
        latest["history"]["executable"] == serde_json::to_value(&p.guard.path)?,
        "205 guard PID1 executable differs"
    );
    let manager = guard_manager(&p, &r.guard_plan, &g, &sample)?;
    ensure!(
        snapshot(&x, &r.stage_spec, &p, &unit(x.stage.unit())?, true)? == process,
        "205 waiter changed during release"
    );
    let at = now()?;
    native_deadline(&process, at)?;
    ensure!(
        n(&cap, "recorded_unix_seconds")? <= at
            && at - n(&cap, "recorded_unix_seconds")? <= RELEASE_AGE,
        "205 fresh capacity expired during first guard capture"
    );
    fresh(at, n(&sample, "recorded_unix_seconds")?, at, Duration::ZERO)?;
    write(
        &p.release,
        &json!({"schema":"jetstreamer-root205-delivery-release-v1","stage_spec":r.stage_spec,
        "startup_plan":pb,"waiting":r.waiting,"process":process,"owner":owner,"admission":admission,
        "capacity":capacity,"capacity_contents":cap,"guard_plan":r.guard_plan,"guard_plan_contents":g,
        "guard_sample":sample_binding,"guard_sample_contents":sample,"guard_history":latest["history"],"guard_manager":manager,
        "released_unix_seconds":at,"issuer":issuer(spec,self_sha),"authority":denied()}),
    )?;
    Ok(())
}
pub(super) fn wait(
    x: &downstream::StageSpec,
    spec: &BoundFile,
    self_sha: &str,
    started: Instant,
) -> Result<BoundFile> {
    let (pb, p) = plan(x)?;
    ensure!(p.runner.sha256 == self_sha, "205 waiter runner differs");
    no_file(&p.release)?;
    let owner = peer::current_actor(x.stage, spec, self_sha)?;
    let actual = snapshot(x, spec, &p, &owner, true)?;
    native_deadline(&actual, now()?)?;
    ensure!(
        started.elapsed() < Duration::from_secs(WAIT),
        "205 pre-wait metadata exhausted startup deadline"
    );
    write(
        &p.waiting,
        &json!({"schema":"jetstreamer-root205-delivery-waiting-v1","stage_spec":spec,
        "startup_plan":pb,"process":actual,"owner":owner,"authority":denied()}),
    )?;
    loop {
        ensure!(
            started.elapsed() < Duration::from_secs(WAIT),
            "205 startup timed out without release"
        );
        match fs::symlink_metadata(&p.release) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(250))
            }
            Err(e) => return Err(e.into()),
        }
    }
    let release_binding = binding(&p.release)?;
    let r = read(&release_binding)?;
    release_matches(&r, spec, &pb, &actual, &binding(&p.waiting)?)?;
    let capacity: BoundFile = serde_json::from_value(r["capacity"].clone())?;
    ensure!(
        read(&capacity)? == r["capacity_contents"],
        "205 released resource proof changed"
    );
    capacity::validate_provenance(&r["capacity_contents"])?;
    let (source, _) = lineage::load_source(&x.source)?;
    let candidate = capacity::candidate_with_anchor(
        x.stage,
        n(&source, "archive_bytes")?,
        downstream::anchor_reserve(x)?,
    )?;
    capacity::validate_capacity(
        &r["capacity_contents"],
        candidate.memory_max_bytes,
        candidate.additional_bytes,
    )?;
    let gp: BoundFile = serde_json::from_value(r["guard_plan"].clone())?;
    let gs: BoundFile = serde_json::from_value(r["guard_sample"].clone())?;
    let g = read(&gp)?;
    let sample = read(&gs)?;
    ensure!(
        g == r["guard_plan_contents"] && sample == r["guard_sample_contents"],
        "205 released guard metadata changed"
    );
    guard_shape(&p, x, &r["capacity_contents"], &gp, &g, &sample, &owner)?;
    warmup223::validate_completed_guard_history(&r["guard_history"], &sample)?;
    ensure!(
        r["guard_history"]["unit"] == p.guard_unit
            && r["guard_history"]["executable"] == serde_json::to_value(&p.guard.path)?,
        "205 consumed first guard unit or ELF changed"
    );
    guard_manager(&p, &gp, &g, &sample)?;
    let admission: BoundFile = serde_json::from_value(r["admission"].clone())?;
    let a = read(&admission)?;
    ensure!(
        admission == downstream::issued_admission(x, spec, n(&source, "archive_bytes")?)?
            && r["issuer"]["executable_sha256"] == p.runner.sha256,
        "205 consumed release changed actual admission or issuer"
    );
    downstream::installed_stage(
        x,
        spec,
        &p.runner,
        &serde_json::from_value(a["unit_file"].clone())?,
        self_sha,
    )?;
    ensure!(
        snapshot(x, spec, &p, &unit(x.stage.unit())?, true)? == actual,
        "205 waiter PID/ticks/IID/caps changed"
    );
    ensure!(
        native209_admission::actual_memory()?
            >= n(
                &r["capacity_contents"]["memory_after"],
                "minimum_available_memory_bytes"
            )?
            && singleton227_admission::disk_free()?
                >= n(&r["capacity_contents"], "required_initial_free_bytes")?,
        "205 startup no longer has its complete memory and disk envelope"
    );
    // This is deliberately after the final potentially slow manager query.
    native_deadline(&actual, now()?)?;
    fresh(
        n(&r, "released_unix_seconds")?,
        n(&sample, "recorded_unix_seconds")?,
        now()?,
        started.elapsed(),
    )?;
    native_deadline(&actual, now()?)?;
    let consumed = write(
        &x.output_directory.join("startup-consumed.json"),
        &json!({
        "schema":"jetstreamer-root205-delivery-startup-consumed-v1","release":release_binding,"process":actual,
        "consumed_unix_seconds":now()?,"authority":denied()}),
    )?;
    fresh(
        n(&r, "released_unix_seconds")?,
        n(&sample, "recorded_unix_seconds")?,
        now()?,
        started.elapsed(),
    )?;
    native_deadline(&actual, now()?)?;
    Ok(consumed)
}

fn saved_consumption(x: &downstream::StageSpec) -> Result<(BoundFile, Value)> {
    let (pb, p) = plan(x)?;
    let consumed = binding(&x.output_directory.join("startup-consumed.json"))?;
    let c = read(&consumed)?;
    let rb: BoundFile = serde_json::from_value(c["release"].clone())?;
    ensure!(rb.path == p.release, "205 consumed release path changed");
    let r = read(&rb)?;
    let wb: BoundFile = serde_json::from_value(r["waiting"].clone())?;
    ensure!(
        wb.path == p.waiting
            && r["startup_plan"] == private157::binding(&pb)
            && c["schema"] == "jetstreamer-root205-delivery-startup-consumed-v1"
            && r["schema"] == "jetstreamer-root205-delivery-release-v1"
            && c["process"] == r["process"]
            && read(&wb)?["process"] == r["process"],
        "205 startup consumption does not preserve exact waiting owner"
    );
    deny(&c["authority"])?;
    deny(&r["authority"])?;
    let cap: BoundFile = serde_json::from_value(r["capacity"].clone())?;
    ensure!(
        read(&cap)? == r["capacity_contents"],
        "205 saved startup capacity changed"
    );
    capacity::validate_provenance(&r["capacity_contents"])?;
    let (source, _) = lineage::load_source(&x.source)?;
    let candidate = capacity::candidate_with_anchor(
        x.stage,
        n(&source, "archive_bytes")?,
        downstream::anchor_reserve(x)?,
    )?;
    capacity::validate_capacity(
        &r["capacity_contents"],
        candidate.memory_max_bytes,
        candidate.additional_bytes,
    )?;
    fresh(
        n(&r, "released_unix_seconds")?,
        n(&r["guard_sample_contents"], "recorded_unix_seconds")?,
        n(&c, "consumed_unix_seconds")?,
        Duration::ZERO,
    )?;
    native_deadline(&r["process"], n(&c, "consumed_unix_seconds")?)?;
    let gs: BoundFile = serde_json::from_value(r["guard_sample"].clone())?;
    let gp: BoundFile = serde_json::from_value(r["guard_plan"].clone())?;
    ensure!(
        read(&gs)? == r["guard_sample_contents"] && read(&gp)? == r["guard_plan_contents"],
        "205 historical first guard changed"
    );
    guard_shape(
        &p,
        x,
        &r["capacity_contents"],
        &gp,
        &r["guard_plan_contents"],
        &r["guard_sample_contents"],
        &r["owner"],
    )?;
    warmup223::validate_completed_guard_history(&r["guard_history"], &r["guard_sample_contents"])?;
    ensure!(
        r["guard_history"]["unit"] == p.guard_unit
            && r["guard_history"]["executable"] == serde_json::to_value(&p.guard.path)?
            && r["issuer"]["executable_sha256"] == p.runner.sha256,
        "205 historical first guard ELF differs"
    );
    Ok((consumed, r))
}
pub(super) fn current_protection(
    x: &downstream::StageSpec,
    spec: &BoundFile,
    owner: &Value,
    at: u64,
) -> Result<Value> {
    let (pb, p) = plan(x)?;
    let guard_memory = json!({"unit":p.guard_unit,"memory_max_bytes":GUARD_MEMORY,"memory_current_bytes":0,
        "remaining_hard_memory_growth_bytes":GUARD_MEMORY,"accounting":"full independent oneshot guard cap; no allocation credit"});
    if fs::symlink_metadata(x.output_directory.join("startup-consumed.json"))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        let w = read(&binding(&p.waiting)?)?;
        let actual = snapshot(x, spec, &p, owner, true)?;
        let begin = n(&actual["clock"], "started_unix_seconds")?;
        let gp = binding(&p.guard_plan_path)?;
        let g = read(&gp)?;
        ensure!(
            g["unit"] == x.stage.unit()
                && g["invocation_id"] == owner["InvocationID"]
                && g["worker_root"] == serde_json::to_value(&x.scan_directory)?
                && g["receipt_directory"] == serde_json::to_value(&p.guard_receipt_directory)?,
            "205 waiting guard plan does not protect this exact holder"
        );
        let guard = unit(&p.guard_unit)?;
        let manager = guard_manager(
            &p,
            &gp,
            &g,
            &json!({"guard_invocation_id":guard["InvocationID"]}),
        )?;
        ensure!(
            w["schema"] == "jetstreamer-root205-delivery-waiting-v1"
                && w["startup_plan"] == private157::binding(&pb)
                && w["stage_spec"] == private157::binding(spec)
                && w["process"] == actual
                && begin <= at
                && at - begin < WAIT
                && unit(&p.guard_unit)?["MainPID"] == "0",
            "205 pre-release holder is not a bounded childless waiting owner"
        );
        return Ok(
            json!({"waiting":binding(&p.waiting)?,"waiting_contents":w,"payload_started":false,
            "guard_manager":manager,"guard_memory":guard_memory}),
        );
    }
    let (consumed, r) = saved_consumption(x)?;
    ensure!(
        r["stage_spec"] == private157::binding(spec)
            && snapshot(x, spec, &p, owner, false)? == r["process"],
        "205 running delivery changed its waiting identity"
    );
    let gp: BoundFile = serde_json::from_value(r["guard_plan"].clone())?;
    let g = read(&gp)?;
    let latest = warmup223::completed_guard_binding(
        &p.guard_unit,
        &p.guard_receipt_directory,
        n(&r, "released_unix_seconds")?,
        at,
    )?;
    let sample = read(&serde_json::from_value(latest["binding"].clone())?)?;
    guard_shape(&p, x, &r["capacity_contents"], &gp, &g, &sample, owner)?;
    warmup223::validate_completed_guard_history(&latest["history"], &sample)?;
    ensure!(
        latest["history"]["executable"] == serde_json::to_value(&p.guard.path)?,
        "205 current guard ELF differs"
    );
    let manager = guard_manager(&p, &gp, &g, &sample)?;
    Ok(
        json!({"startup_consumed":consumed,"first_release":r,"latest_guard":latest,"guard_manager":manager,
        "guard_memory":guard_memory}),
    )
}
pub(super) fn guard_for_stage(stage: downstream::Stage) -> Result<&'static str> {
    guard_name(stage)
}
pub(super) fn validate_outcome(
    x: &downstream::StageSpec,
    spec: &BoundFile,
    o: &Value,
) -> Result<()> {
    let (consumed, r) = saved_consumption(x)?;
    ensure!(
        o["startup_release"] == private157::binding(&consumed)
            && r["stage_spec"] == private157::binding(spec)
            && o["invocation_id"] == r["process"]["invocation_id"],
        "205 successful stage lost its genuine same-process startup release"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root205_startup_deadline_and_final_guard_freshness_are_strict() {
        fresh(100, 90, 110, Duration::from_secs(299)).unwrap();
        for (r, g, at, elapsed) in [
            (100, 90, 116, 299),
            (100, 90, 121, 299),
            (100, 90, 110, 300),
            (111, 90, 110, 299),
            (100, 111, 110, 299),
        ] {
            assert!(fresh(r, g, at, Duration::from_secs(elapsed)).is_err());
        }
        // A slow final manager query cannot authorize payload after release age.
        assert!(fresh(100, 100, 116, Duration::from_secs(20)).is_err());
    }
    #[test]
    fn root205_stage_guards_have_exact_distinct_delivery_names() {
        let stages = [
            downstream::Stage::Full,
            downstream::Stage::Plugin,
            downstream::Stage::Boundary,
            downstream::Stage::Import,
            downstream::Stage::Upload,
        ];
        let names = stages
            .into_iter()
            .map(|s| guard_name(s).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), 5);
        assert!(names.iter().all(|n| n.starts_with("horizon-205-delivery-")));
        assert!(guard_name(downstream::Stage::Assembly).is_err());
    }
    #[test]
    fn root205_release_binds_pid_ticks_iid_clock_cgroup_caps_and_exact_spec() {
        let b = |name: &str| BoundFile {
            path: PathBuf::from(format!("/sealed/{name}.json")),
            sha256: "a".repeat(64),
        };
        let spec = b("stage");
        let pb = b("startup");
        let waiting = b("waiting");
        let actual = json!({"pid":42,"start_ticks":123,"clock":{"boot_id":"boot"},"invocation_id":"b".repeat(32),
            "cgroup":"/system.slice/root205.service","limits":{"memory.max":"68719476736"}});
        let r = json!({"schema":"jetstreamer-root205-delivery-release-v1","stage_spec":spec,"startup_plan":pb,
            "waiting":waiting,"process":actual,"authority":denied()});
        release_matches(&r, &spec, &pb, &actual, &waiting).unwrap();
        for pointer in [
            "/process/pid",
            "/process/start_ticks",
            "/process/clock/boot_id",
            "/process/invocation_id",
            "/process/cgroup",
            "/process/limits/memory.max",
            "/stage_spec/sha256",
            "/startup_plan/path",
            "/waiting/sha256",
        ] {
            let mut changed = r.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(
                release_matches(&changed, &spec, &pb, &actual, &waiting).is_err(),
                "{pointer}"
            );
        }
        let mut changed = r.clone();
        changed["authority"]["publication_authorized"] = json!(true);
        assert!(release_matches(&changed, &spec, &pb, &actual, &waiting).is_err());
    }
    #[test]
    fn root205_guard_rejects_wrong_owner_floor_disabled_stop_and_partial_error_evidence() {
        let b = BoundFile {
            path: "/sealed/b.json".into(),
            sha256: "a".repeat(64),
        };
        let x:downstream::StageSpec=serde_json::from_value(json!({
            "schema":"jetstreamer-continuation205-delivery-stage-spec-v1","context":{"fleet":b,"observer":b},
            "stage":"full","source":{"kind":"Continuation205","completion":b},"startup":b,
            "gates":[],"tool":null,"tool_qualification":null,"anchor_tool":null,"anchor_tool_qualification":null,
            "admission":"/sealed/admission.json","output_directory":"/sealed/output","scan_directory":"/sealed/scan",
            "upload_receipt":null,"neighbors":[]})).unwrap();
        let p = Plan {
            schema: "unused".into(),
            stage: downstream::Stage::Full,
            runner: b.clone(),
            runner_seal: b.clone(),
            preparation: b.clone(),
            guard: b.clone(),
            guard_seal: b.clone(),
            guard_unit: guard_name(x.stage).unwrap().into(),
            guard_receipt_directory: "/sealed/guard".into(),
            guard_plan_path: "/sealed/guard-plan.json".into(),
            waiting: "/sealed/waiting.json".into(),
            release: "/sealed/release.json".into(),
            maximum_wait_seconds: WAIT,
        };
        let owner = json!({"Id":x.stage.unit(),"InvocationID":"b".repeat(32),"MainPID":"42",
            "ControlGroup":format!("/system.slice/{}",x.stage.unit())});
        let a = json!({"minimum_free_bytes":100});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":x.stage.unit(),
            "invocation_id":owner["InvocationID"],"filesystem":"/","worker_root":x.scan_directory,
            "receipt_directory":p.guard_receipt_directory,"minimum_free_bytes":100,"maximum_root_physical_bytes":ROOT_CAP,
            "maximum_worker_vmas":3500000});
        let sample = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","plan":b.path,"plan_sha256":b.sha256,
            "guard_sha256":p.guard.sha256,"guard_invocation_id":"c".repeat(32),"producer_invocation_id":owner["InvocationID"],
            "producer":{"invocation_id":owner["InvocationID"],"pid":42,"restarts":0,"restart_policy":"no","kill_mode":"control-group",
                "delegated":false,"active":"active","sub":"running","cgroup":owner["ControlGroup"]},
            "producer_stop_enabled":true,"minimum_free_bytes":100,"available_bytes":100,"workers":[],"bounded_measurement":false,
            "maximum_root_physical_bytes":ROOT_CAP,"maximum_worker_vmas":3500000,"remote_mutations":false,"r2_mutations":false,
            "root_physical_observation":{"exceeds_budget":false,"conservative_physical_bytes":0},
            "trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"canary_target_error":null,
            "target_handoff_error":null,"native_main":null,"bounded_canary":null});
        guard_shape(&p, &x, &a, &b, &g, &sample, &owner).unwrap();
        for (pointer, value) in [
            ("/producer_stop_enabled", json!(false)),
            ("/producer/pid", json!(43)),
            ("/producer/invocation_id", json!("foreign")),
            ("/available_bytes", json!(99)),
            ("/trip_reason", json!("floor")),
            ("/guard_invocation_id", json!("0".repeat(32))),
            ("/workers", json!([{}])),
        ] {
            let mut bad = sample.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                guard_shape(&p, &x, &a, &b, &g, &bad, &owner).is_err(),
                "{pointer}"
            );
        }
        let mut bad = g.clone();
        bad["minimum_free_bytes"] = json!(99);
        assert!(guard_shape(&p, &x, &a, &b, &bad, &sample, &owner).is_err());
        let mut bad = sample;
        bad.as_object_mut().unwrap().remove("canary_target_error");
        assert!(guard_shape(&p, &x, &a, &b, &g, &bad, &owner).is_err());
    }
    #[test]
    fn root205_custody_rejects_nested_writable_guard_and_canonical_import_roots() {
        let writes = [
            Path::new("/var/lib/jetstreamer/horizon-205-delivery-output"),
            Path::new(CANONICAL),
        ];
        distinct_roots(
            Path::new("/var/lib/jetstreamer/horizon-205-delivery-release"),
            &writes,
        )
        .unwrap();
        for control in [
            "/var/lib/jetstreamer/horizon-205-delivery-output/release",
            "/var/lib/jetstreamer",
            "/home/ubuntu/horizon/release",
        ] {
            assert!(distinct_roots(Path::new(control), &writes).is_err());
        }
        assert!(
            distinct_roots(
                Path::new("/private/guard/release"),
                &[Path::new("/private/guard")]
            )
            .is_err()
        );
    }
    #[test]
    fn root205_native_deadline_cannot_restart_after_slow_pre_wait_metadata() {
        let process = json!({"clock":{"started_unix_seconds":100}});
        native_deadline(&process, 399).unwrap();
        assert!(native_deadline(&process, 400).is_err());
        assert!(native_deadline(&process, 99).is_err());
        assert!(native_deadline(&process, 1000).is_err());
    }
    #[test]
    fn root205_native_credentials_require_exact_ptrace_and_traversal_only() {
        let raw = "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t0000000000080002\nCapPrm:\t0000000000080002\nCapBnd:\t0000000000080002\nCapAmb:\t0000000000080002\n";
        native_credentials(raw).unwrap();
        for changed in [
            raw.replace("Uid:\t0\t0\t0\t0", "Uid:\t0\t1000\t0\t0"),
            raw.replace("Gid:\t0\t0\t0\t0", "Gid:\t1000\t1000\t1000\t1000"),
            raw.replace("0000000000080002", "0000000000000002"),
            raw.replace("0000000000080002", "0000000000080003"),
            raw.replace("CapAmb:\t0000000000080002\n", ""),
        ] {
            assert!(native_credentials(&changed).is_err());
        }
    }
}
