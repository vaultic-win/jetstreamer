//! Capture actual execution identity before a completed phase can gate its peer.
use super::*;
const LAUNCH: &str = "jetstreamer-completed-archive-phase-launch-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    schema: String,
    phase_spec: BoundFile,
    admission: BoundFile,
    guard_plan: BoundFile,
    guard_sample: Option<BoundFile>,
    startup_release: Option<BoundFile>,
    output: PathBuf,
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("completed launch integer missing: {k}"))
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("completed launch string missing: {k}"))
}
fn process_matches(
    phase: Phase,
    expected: &[String],
    executable: &Path,
    actual: &[String],
) -> Result<()> {
    ensure!(!expected.is_empty(), "completed launch argv missing");
    let matches = if phase == Phase::Upload {
        executable == Path::new(&expected[0]) && actual == expected
    } else {
        executable == Path::new("/usr/bin/bash")
            && actual.len() == expected.len() + 1
            && matches!(
                actual.first().map(String::as_str),
                Some("bash" | "/bin/bash" | "/usr/bin/bash")
            )
            && actual[1..] == *expected
    };
    ensure!(
        matches,
        "completed launch actual process executable/argv differs"
    );
    Ok(())
}
pub(super) fn start_ticks(raw: &str) -> Result<u64> {
    let (_, rest) = raw
        .rsplit_once(") ")
        .context("completed launch malformed process stat")?;
    rest.split_whitespace()
        .nth(19)
        .context("completed launch process start time absent")?
        .parse()
        .context("completed launch process start time invalid")
}
pub(super) fn native_start_clock(ticks: u64) -> Result<Value> {
    let boot = barrier::native_text("/proc/sys/kernel/random/boot_id", 128)?
        .trim()
        .to_owned();
    let seconds = barrier::native_text("/proc/stat", 4 << 20)?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))
        .context("completed launch native boot clock absent")?
        .parse::<u64>()?;
    let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })?;
    ensure!(hz > 0, "completed launch native tick frequency absent");
    let started = seconds
        .checked_add(ticks / hz)
        .context("completed launch native start overflow")?;
    Ok(
        json!({"boot_id":boot,"boot_unix_seconds":seconds,"clock_ticks_per_second":hz,"started_unix_seconds":started}),
    )
}
pub(super) fn clock_shape(process: &Value) -> Result<()> {
    let clock = &process["native_start_clock"];
    let hz = n(clock, "clock_ticks_per_second")?;
    let boot = string(clock, "boot_id")?;
    ensure!(
        hz > 0
            && boot.len() == 36
            && boot.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
            && n(clock, "boot_unix_seconds")?.checked_add(n(process, "start_ticks")? / hz)
                == Some(n(clock, "started_unix_seconds")?),
        "completed launch native start clock is inconsistent"
    );
    Ok(())
}
pub(super) fn process(s: &Spec, owner: &Value, argv: &[String]) -> Result<Value> {
    process_as(s, owner, argv, false)
}
fn process_as(s: &Spec, owner: &Value, argv: &[String], waiting: bool) -> Result<Value> {
    let pid = string(owner, "MainPID")?.parse::<u32>()?;
    ensure!(pid > 1, "completed launch has no live main process");
    let proc = Path::new("/proc").join(pid.to_string());
    let tick = start_ticks(&fs::read_to_string(proc.join("stat"))?)?;
    let native_start_clock = native_start_clock(tick)?;
    let exe = fs::read_link(proc.join("exe"))?;
    let raw = fs::read(proc.join("cmdline"))?;
    ensure!(
        raw.len() <= 64 << 10 && raw.last() == Some(&0),
        "completed launch cmdline unavailable"
    );
    let args = raw[..raw.len() - 1]
        .split(|b| *b == 0)
        .map(|b| Ok(std::str::from_utf8(b)?.to_owned()))
        .collect::<Result<Vec<String>>>()?;
    if waiting {
        ensure!(
            exe == s.programs["launcher"].artifact.path && args == barrier::launcher_argv(s),
            "completed barrier actual executable/argv differs"
        );
    } else {
        process_matches(s.phase, argv, &exe, &args)?;
    }
    let executable_sha256 = hex_lower(&Sha256::digest(fs::read(proc.join("exe"))?));
    let expected_executable = if waiting {
        &s.programs["launcher"].artifact
    } else if s.phase == Phase::Upload {
        &s.programs["progressive"].artifact
    } else {
        s.interpreter
            .as_ref()
            .context("completed launch interpreter is unbound")?
    };
    ensure!(
        exe == expected_executable.path && executable_sha256 == expected_executable.sha256,
        "completed launch running executable digest differs"
    );

    let environment = fs::read(proc.join("environ"))?;
    ensure!(
        environment.len() <= 1 << 20,
        "completed launch environment exceeds bound"
    );
    let mut actual = BTreeMap::new();
    for entry in environment.split(|b| *b == 0).filter(|b| !b.is_empty()) {
        let entry =
            std::str::from_utf8(entry).context("completed launch environment encoding differs")?;
        let (key, value) = entry
            .split_once('=')
            .context("completed launch environment assignment differs")?;
        ensure!(
            actual.insert(key.to_owned(), value.to_owned()).is_none(),
            "completed launch environment repeats a key"
        );
    }
    ensure!(
        UNSAFE_ENVIRONMENT
            .iter()
            .all(|key| !actual.contains_key(*key)),
        "completed launch inherited an unsafe execution variable"
    );
    let credential_digest = if let Some(binding) = &s.environment_file {
        let wanted = credential_values(&bound_bytes(binding, 64 << 10, 0)?)?;
        ensure!(
            wanted
                .iter()
                .all(|(key, value)| actual.get(key) == Some(value)),
            "completed launch credential environment differs from its bound file"
        );
        Some(hex_lower(&Sha256::digest(serde_json::to_vec(&wanted)?)))
    } else {
        None
    };
    let name = &s.units[s.phase.name()];
    let cgroup = format!("/system.slice/{name}");
    ensure!(
        owner["ControlGroup"] == cgroup
            && fs::read_to_string(proc.join("cgroup"))? == format!("0::{cgroup}\n"),
        "completed launch process cgroup differs"
    );
    let group = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
    let (high, max, _) = s.phase.profile();
    let mut limits = BTreeMap::new();
    for (key, want) in [
        ("memory.high", high.to_string()),
        ("memory.max", max.to_string()),
        ("memory.swap.max", "0".into()),
        ("pids.max", "512".into()),
        ("cpu.max", "800000 100000".into()),
    ] {
        let actual = fs::read_to_string(group.join(key))?.trim().to_owned();
        ensure!(
            actual == want,
            "completed launch native limit differs: {key}"
        );
        limits.insert(key, actual);
    }
    let pids = fs::read_to_string(group.join("cgroup.procs"))?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    ensure!(
        pids.contains(&pid) && pids.len() <= 512,
        "completed launch main process is outside native task census"
    );
    let archive = match &s.origin {
        Origin::Singleton209 { .. } => Path::new(singleton209::ROOT).join("output"),
    };
    let mounts = fs::read_to_string(proc.join("mountinfo"))?;
    ensure!(
        mounts.lines().any(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            fields.get(4).copied() == archive.to_str()
                && fields
                    .get(5)
                    .is_some_and(|v| v.split(',').any(|f| f == "ro"))
        }),
        "completed launch actual archive mount is not read-only"
    );
    let references = jetstreamer_horizon_observe::process_references::scan(
        Path::new("/proc"),
        Path::new(singleton209::ROOT),
    )?;
    for reference in &references.references {
        let words = reference.split_whitespace().collect::<Vec<_>>();
        ensure!(
            words.first() == Some(&"pid")
                && words
                    .get(1)
                    .and_then(|p| p.parse::<u32>().ok())
                    .is_some_and(|p| pids.contains(&p)),
            "completed archive has an unowned live process reference"
        );
    }
    ensure!(
        start_ticks(&fs::read_to_string(proc.join("stat"))?)? == tick
            && fs::read_link(proc.join("exe"))? == exe
            && fs::read(proc.join("cmdline"))? == raw,
        "completed launch main process changed during capture"
    );
    Ok(
        json!({"pid":pid,"executable":exe,"executable_sha256":executable_sha256,"cmdline":args,"start_ticks":tick,"native_start_clock":native_start_clock,"cgroup":cgroup,"native_limits":limits,"credential_values_not_recorded":true,"credential_environment_sha256":credential_digest,"source_read_only_mount":true,"source_reference_census":references,"native_memory_current":fs::read_to_string(group.join("memory.current"))?.trim(),"native_memory_peak":fs::read_to_string(group.join("memory.peak"))?.trim()}),
    )
}
pub(super) fn read_sample(binding: &BoundFile, plan: &Value) -> Result<Value> {
    let raw = bound_bytes(binding, 4 << 20, 0)?;
    let sample: Value = serde_json::from_slice(&raw)?;
    let iid = string(&sample, "guard_invocation_id")?;
    ensure!(
        is_lower_hex(iid, 32)
            && binding.path
                == Path::new(string(plan, "receipt_directory")?).join(format!("sample-{iid}.json")),
        "completed launch sample is outside its actual guard receipt namespace"
    );
    Ok(sample)
}
pub(super) fn guard_shape(
    s: &Spec,
    admission: &Value,
    plan: &Value,
    sample: &Value,
    owner: &Value,
    now: u64,
) -> Result<()> {
    let at = n(admission, "recorded_unix_seconds")?;
    let guarded = n(sample, "recorded_unix_seconds")?;
    let iid = string(owner, "InvocationID")?;
    ensure!(
        is_lower_hex(iid, 32)
            && is_lower_hex(string(sample, "guard_invocation_id")?, 32)
            && at <= guarded
            && guarded <= now
            && now - at <= 900,
        "completed launch admission/first guard clock or IID differs"
    );
    sample_shape(s, admission, plan, sample, owner)
}
pub(super) fn current_guard_shape(
    s: &Spec,
    admission: &Value,
    plan: &Value,
    sample: &Value,
    owner: &Value,
    minimum: u64,
    now: u64,
) -> Result<()> {
    let guarded = n(sample, "recorded_unix_seconds")?;
    ensure!(
        guarded >= minimum
            && guarded >= n(admission, "recorded_unix_seconds")?
            && guarded <= now
            && now - guarded <= 1800,
        "completed peer latest guard is stale or predates the coordinated sample"
    );
    sample_shape(s, admission, plan, sample, owner)
}
fn sample_shape(
    s: &Spec,
    admission: &Value,
    plan: &Value,
    sample: &Value,
    owner: &Value,
) -> Result<()> {
    let iid = string(owner, "InvocationID")?;
    let pid = string(owner, "MainPID")?.parse::<u64>()?;
    ensure!(
        is_lower_hex(iid, 32) && is_lower_hex(string(sample, "guard_invocation_id")?, 32),
        "completed guard IID differs"
    );
    ensure!(
        plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["unit"] == s.units[s.phase.name()]
            && plan["invocation_id"] == iid
            && plan["filesystem"] == "/"
            && plan["worker_root"] == serde_json::to_value(&s.state_root)?
            && plan["minimum_free_bytes"] == admission["capacity"]["minimum_free_bytes"]
            && plan["maximum_root_physical_bytes"] == METADATA
            && plan["maximum_worker_vmas"] == 3500000
            && ["native_main", "bounded_measurement", "bounded_canary"]
                .iter()
                .all(|k| plan.get(*k).is_none_or(Value::is_null)),
        "completed launch guard plan differs"
    );
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["guard_sha256"] == s.programs["guard"].artifact.sha256
            && sample["producer_invocation_id"] == iid
            && sample["producer"]["invocation_id"] == iid
            && sample["producer"]["pid"] == pid
            && sample["producer"]["restarts"] == 0
            && sample["producer"]["restart_policy"] == "no"
            && sample["producer"]["kill_mode"] == "control-group"
            && sample["producer"]["delegated"] == false
            && sample["producer"]["active"] == "active"
            && sample["producer"]["sub"] == "running"
            && sample["producer"]["cgroup"] == owner["ControlGroup"]
            && sample["producer_stop_enabled"] == true
            && sample["minimum_free_bytes"] == plan["minimum_free_bytes"]
            && sample["available_bytes"]
                .as_u64()
                .is_some_and(|n| plan["minimum_free_bytes"].as_u64().is_some_and(|f| n >= f))
            && sample["workers"].as_array().is_some_and(Vec::is_empty)
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
            .all(|k| sample.get(*k).is_some_and(Value::is_null))
            && sample["bounded_measurement"] == false
            && sample["maximum_worker_vmas"] == 3500000
            && sample["maximum_root_physical_bytes"] == METADATA
            && sample["remote_mutations"] == false
            && sample["r2_mutations"] == false
            && sample["root_physical_observation"]["maximum_physical_bytes"] == METADATA
            && sample["root_physical_observation"]["exceeds_budget"] == false
            && sample["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= METADATA),
        "completed launch lacks a successful stop-enabled no-worker guard"
    );
    Ok(())
}
fn guard_manager(
    s: &Spec,
    plan_binding: &BoundFile,
    plan: &Value,
    sample: &Value,
    admitted: u64,
) -> Result<Value> {
    let name = &s.guard_units[s.phase.name()];
    let p = singleton227_capture::properties(
        name,
        "Id,InvocationID,MainPID,NRestarts,Type,User,Restart,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec,ExecStart,Result,ExecMainStatus,ActiveState,SubState,DropInPaths,NeedDaemonReload,Transient",
    )?;
    singleton227_capture::require(
        &p,
        &[
            ("Id", name),
            ("Type", "oneshot"),
            ("User", "root"),
            ("Restart", "no"),
            ("NRestarts", "0"),
            ("MainPID", "0"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("MemoryMax", "1073741824"),
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
    ensure!(
        p["InvocationID"] == sample["guard_invocation_id"] || p["InvocationID"].is_empty(),
        "completed launch first guard has been replaced"
    );
    ensure!(
        p["ReadWritePaths"] == string(plan, "receipt_directory")?,
        "completed launch guard writable namespace differs"
    );
    let artifact = &s.programs["guard"].artifact;
    let expected = format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no }}",
        artifact.path.display(),
        artifact.path.display(),
        plan_binding.path.display(),
        plan_binding.sha256,
        artifact.sha256
    );
    ensure!(
        assembly204_recovery::delivery_command_matches(&p["ExecStart"], &expected),
        "completed launch guard command differs"
    );
    let timer = singleton227_capture::properties(
        &name.replace(".service", ".timer"),
        "ActiveState,SubState",
    )?;
    singleton227_capture::require(
        &timer,
        &[("ActiveState", "active"), ("SubState", "waiting")],
    )?;
    let (rows, sha) = singleton227_capture::journal(name)?;
    ensure!(
        !rows.is_empty() && rows.len() < 256,
        "completed launch guard manager history truncated"
    );
    let success = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == *name
                && r["INVOCATION_ID"] == sample["guard_invocation_id"]
                && r["MESSAGE"] == format!("{name}: Deactivated successfully.")
        })
        .collect::<Vec<_>>();
    ensure!(
        success.len() == 1
            && rows
                .iter()
                .filter(|r| r["_PID"] == "1" && r["_UID"] == "0" && r["UNIT"] == *name)
                .all(|r| {
                    r["__REALTIME_TIMESTAMP"]
                        .as_str()
                        .and_then(|v| v.parse::<u64>().ok())
                        .is_some_and(|t| {
                            t / 1_000_000 < admitted
                                || (r["MESSAGE_ID"] != "be02cf6855d2428ba40df7e9d022f03d"
                                    && !r["MESSAGE"].as_str().unwrap_or("").contains("Failed"))
                        })
                }),
        "completed launch first guard did not finish cleanly"
    );
    Ok(json!({"properties":p,"timer":timer,"manager_completion":success[0],"journal_sha256":sha}))
}
fn saved_shape(v: &Value, s: &Spec, phase: Phase, self_sha: &str, a: &Value) -> Result<()> {
    barrier::transition_shape(
        &v["startup_release_contents"],
        s,
        a,
        &v["process"],
        &v["owner"],
        n(v, "captured_unix_seconds")?,
    )?;
    ensure!(
        v["startup_plan"] == private157::binding(&s.startup_plan)
            && v["guard_plan"] == v["startup_release_contents"]["guard_plan"]
            && v["guard_sample"] == v["startup_release_contents"]["guard_sample"],
        "completed phase changed its protected startup origin"
    );
    clock_shape(&v["process"])?;
    let started = n(&v["process"]["native_start_clock"], "started_unix_seconds")?;
    ensure!(
        started.saturating_add(1) >= n(a, "recorded_unix_seconds")?
            && started <= n(&v["guard_sample_contents"], "recorded_unix_seconds")?,
        "completed phase native process started outside its admission/first guard interval"
    );
    ensure!(
        v["schema"] == LAUNCH
            && v["epoch"] == s.epoch
            && v["phase"] == phase.name()
            && v["issuer_sha256"] == self_sha
            && v["unit"] == s.units[phase.name()]
            && v["phase_spec"] == a["spec"]
            && v["admission"] == a["binding"]
            && v["argv"] == a["argv"]
            && v["owner"]["InvocationID"] == v["invocation_id"]
            && v["owner"]["Id"] == s.units[phase.name()]
            && v["owner"]["NRestarts"] == "0"
            && v["owner"]["ActiveState"] == "active"
            && v["owner"]["SubState"] == "running"
            && v["owner"]["MainPID"]
                .as_str()
                .and_then(|p| p.parse::<u64>().ok())
                == v["process"]["pid"].as_u64()
            && v["process"]["start_ticks"].as_u64().is_some_and(|n| n > 0)
            && v["process"]["source_read_only_mount"] == true,
        "completed phase launch did not capture its admitted actual owner"
    );
    let argv: Vec<String> = serde_json::from_value(v["argv"].clone())?;
    let args: Vec<String> = serde_json::from_value(v["process"]["cmdline"].clone())?;
    process_matches(
        phase,
        &argv,
        Path::new(string(&v["process"], "executable")?),
        &args,
    )?;
    let expected_executable = if phase == Phase::Upload {
        &s.programs["progressive"].artifact
    } else {
        s.interpreter
            .as_ref()
            .context("completed launch interpreter missing")?
    };
    ensure!(
        v["process"]["executable_sha256"] == expected_executable.sha256,
        "completed phase saved running executable differs"
    );
    let profile = phase.profile();
    for (key, value) in [
        ("memory.high", profile.0.to_string()),
        ("memory.max", profile.1.to_string()),
        ("memory.swap.max", "0".into()),
        ("pids.max", "512".into()),
        ("cpu.max", "800000 100000".into()),
    ] {
        ensure!(
            v["process"]["native_limits"][key] == value,
            "completed phase saved native limit differs"
        );
    }
    ensure!(
        v["guard_unit"] == s.guard_units[phase.name()]
            && v["guard_manager"]["manager_completion"]["_PID"] == "1"
            && v["guard_manager"]["manager_completion"]["_UID"] == "0"
            && v["guard_manager"]["manager_completion"]["UNIT"] == s.guard_units[phase.name()]
            && v["guard_manager"]["manager_completion"]["INVOCATION_ID"]
                == v["guard_sample_contents"]["guard_invocation_id"]
            && v["guard_manager"]["manager_completion"]["MESSAGE"]
                == format!("{}: Deactivated successfully.", s.guard_units[phase.name()]),
        "completed phase saved first guard manager binding differs"
    );
    let mut prior = s.clone();
    prior.phase = phase;
    guard_shape(
        &prior,
        a,
        &v["guard_plan_contents"],
        &v["guard_sample_contents"],
        &v["owner"],
        n(v, "captured_unix_seconds")?,
    )?;
    Ok(())
}
pub(super) fn validate_saved(v: &Value, s: &Spec, phase: Phase, self_sha: &str) -> Result<Value> {
    let admission: BoundFile = serde_json::from_value(v["admission"].clone())?;
    let mut a = read(&admission)?;
    a["binding"] = private157::binding(&admission);
    let prior_binding: BoundFile = serde_json::from_value(v["phase_spec"].clone())?;
    let prior: Spec = serde_json::from_value(read(&prior_binding)?)?;
    shape(&prior)?;
    let left = serde_json::to_value(&prior)?;
    let right = serde_json::to_value(s)?;
    for key in [
        "epoch",
        "origin",
        "tools",
        "decoder_capacity",
        "programs",
        "units",
        "guard_units",
        "state_root",
        "r2_receipt_directory",
        "upload_lock",
    ] {
        ensure!(
            left[key] == right[key],
            "completed phase captured launch belongs to a different delivery core"
        );
    }
    ensure!(
        prior.phase == phase,
        "completed phase captured phase differs"
    );
    saved_shape(v, &prior, phase, self_sha, &a)?;
    let plan: BoundFile = serde_json::from_value(v["guard_plan"].clone())?;
    let sample: BoundFile = serde_json::from_value(v["guard_sample"].clone())?;
    ensure!(
        read(&plan)? == v["guard_plan_contents"]
            && read_sample(&sample, &v["guard_plan_contents"])? == v["guard_sample_contents"],
        "completed phase saved first guard binding changed"
    );
    ensure!(
        v["guard_sample_contents"]["plan_sha256"] == plan.sha256
            && v["guard_sample_contents"]["plan"] == serde_json::to_value(&plan.path)?,
        "completed phase saved guard plan identity differs"
    );
    let startup: BoundFile = serde_json::from_value(v["startup_release"].clone())?;
    ensure!(
        barrier::saved_release(&prior, &startup)? == v["startup_release_contents"],
        "completed saved startup release changed"
    );
    Ok(v.clone())
}
fn selected_guard_sample(
    supplied: Option<&BoundFile>,
    waiting: bool,
    latest: &Value,
    startup: Option<&Value>,
) -> Result<BoundFile> {
    let selected: BoundFile = serde_json::from_value(if waiting {
        latest["binding"].clone()
    } else {
        startup.context("completed child capture lacks startup release")?["guard_sample"].clone()
    })?;
    ensure!(
        supplied.is_none_or(|bound| *bound == selected),
        "completed explicitly bound guard sample differs from its genuine startup source"
    );
    Ok(selected)
}
fn collect(
    c: &Capture,
    binding: &BoundFile,
    self_sha: &str,
    waiting: bool,
    startup: Option<&Value>,
) -> Result<(Spec, Value)> {
    let s: Spec = serde_json::from_value(read(&c.phase_spec)?)?;
    shape(&s)?;
    let mut admission = read(&c.admission)?;
    admission["binding"] = private157::binding(&c.admission);
    ensure!(
        admission["schema"] == RECEIPT
            && admission["admitted"] == true
            && admission["issuer_sha256"] == self_sha
            && s.programs["launcher"].artifact.sha256 == self_sha
            && admission["spec"] == private157::binding(&c.phase_spec)
            && admission["epoch"] == s.epoch
            && admission["phase"] == s.phase.name(),
        "completed launch admission binding differs"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let owner = unit(&s.units[s.phase.name()])?;
    ensure!(
        owner["LoadState"] == "loaded"
            && owner["ActiveState"] == "active"
            && owner["SubState"] == "running"
            && owner["NRestarts"] == "0",
        "completed launch is not an active zero-restart owner"
    );
    let argv: Vec<String> = serde_json::from_value(admission["argv"].clone())?;
    let effective = check_unit(&s, &argv)?;
    let snapshot = process_as(&s, &owner, &argv, waiting)?;
    let plan = read(&c.guard_plan)?;
    let latest = if waiting {
        warmup223::completed_guard_binding(
            &s.guard_units[s.phase.name()],
            Path::new(string(&plan, "receipt_directory")?),
            n(&admission, "recorded_unix_seconds")?,
            now,
        )?
    } else {
        Value::Null
    };
    let selected_sample =
        selected_guard_sample(c.guard_sample.as_ref(), waiting, &latest, startup)?;
    let sample = read_sample(&selected_sample, &plan)?;
    ensure!(
        sample["plan_sha256"] == c.guard_plan.sha256
            && sample["plan"] == serde_json::to_value(&c.guard_plan.path)?,
        "completed launch first guard plan binding differs"
    );
    guard_shape(&s, &admission, &plan, &sample, &owner, now)?;
    let manager = guard_manager(
        &s,
        &c.guard_plan,
        &plan,
        &sample,
        n(&admission, "recorded_unix_seconds")?,
    )?;
    ensure!(
        owner == unit(&s.units[s.phase.name()])?
            && effective == check_unit(&s, &argv)?
            && snapshot["start_ticks"] == process_as(&s, &owner, &argv, waiting)?["start_ticks"],
        "completed launch owner changed during first guard capture"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    guard_shape(&s, &admission, &plan, &sample, &owner, now)?;
    let launch = json!({"schema":if waiting {barrier::RELEASE}else{LAUNCH},"epoch":s.epoch,"phase":s.phase,"issuer_sha256":self_sha,"capture_spec":private157::binding(binding),"phase_spec":c.phase_spec,"admission":c.admission,
        "unit":s.units[s.phase.name()],"invocation_id":owner["InvocationID"],"owner":owner,"effective_unit":effective,"argv":argv,"process":snapshot,
        "guard_unit":s.guard_units[s.phase.name()],"guard_plan":c.guard_plan,"guard_sample":selected_sample,"guard_plan_contents":plan,"guard_sample_contents":sample,"guard_manager":manager,"captured_unix_seconds":now,
        "startup_plan":s.startup_plan,"startup_plan_contents":barrier::validate_plan(&s,&argv)?,"phase_spec_contents":s,"admission_contents":admission,"guard_latest_completion":latest,"child_execution_authorized":waiting,
        "publication_authorized":false,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
    Ok((s, launch))
}
pub(super) fn release() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("release-completed-archive-phase")?;
    let c: Capture = serde_json::from_value(read(&binding)?)?;
    ensure!(
        c.schema == "jetstreamer-completed-archive-phase-release-spec-v1"
            && c.startup_release.is_none(),
        "completed startup release spec differs"
    );
    let (s, value) = collect(&c, &binding, &self_sha, true, None)?;
    barrier::issue(&s, &c.output, &value)
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-completed-archive-phase")?;
    let c: Capture = serde_json::from_value(read(&binding)?)?;
    ensure!(
        c.schema == "jetstreamer-completed-archive-phase-capture-spec-v1",
        "completed launch capture schema differs"
    );
    validate_output_destination(&c.output)?;
    let spec: Spec = serde_json::from_value(read(&c.phase_spec)?)?;
    shape(&spec)?;
    let (startup, release) = barrier::resolve_release(&spec, c.startup_release.as_ref())?;
    let (s, mut value) = collect(&c, &binding, &self_sha, false, Some(&release))?;
    value["startup_release"] = private157::binding(&startup);
    value["startup_release_contents"] = release;
    saved_shape(&value, &s, s.phase, &self_sha, &value["admission_contents"])?;
    private157::immutable_receipt(&c.output, &value)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(in crate::fleet::completed_archive_phase) fn fixture() -> (Spec, Value, Value, String) {
        let mut s = super::super::tests::fixture(Phase::Full);
        let helper = "f".repeat(64);
        s.programs.get_mut("launcher").unwrap().artifact.sha256 = helper.clone();
        let iid = "b".repeat(32);
        let guard_iid = "c".repeat(32);
        let argv = command(&s, &Path::new(singleton209::ROOT).join("output")).unwrap();
        let name = &s.units["full"];
        let group = format!("/system.slice/{name}");
        let owner = json!({"Id":name,"LoadState":"loaded","InvocationID":iid,"MainPID":"42","NRestarts":"0","ActiveState":"active","SubState":"running","ControlGroup":group});
        let admission = json!({"schema":RECEIPT,"admitted":true,"issuer_sha256":helper,"epoch":209,"phase":"full","startup_plan":private157::binding(&s.startup_plan),"binding":{"path":"/sealed/admission.json","sha256":"a".repeat(64)},"spec":{"path":"/sealed/spec.json","sha256":"a".repeat(64)},"argv":argv,"recorded_unix_seconds":900,"capacity":{"minimum_free_bytes":100}});
        let plan = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":name,"invocation_id":iid,"filesystem":"/","worker_root":s.state_root,"minimum_free_bytes":100,"maximum_root_physical_bytes":METADATA,"maximum_worker_vmas":3500000});
        let sample = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","recorded_unix_seconds":910,"guard_invocation_id":guard_iid,"guard_sha256":s.programs["guard"].artifact.sha256,"producer_invocation_id":iid,
            "producer":{"invocation_id":iid,"pid":42,"restarts":0,"restart_policy":"no","kill_mode":"control-group","delegated":false,"active":"active","sub":"running","cgroup":group},"producer_stop_enabled":true,
            "minimum_free_bytes":100,"available_bytes":1000,"workers":[],"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"bounded_measurement":false,
            "maximum_worker_vmas":3500000,"maximum_root_physical_bytes":METADATA,"canary_target_error":null,"target_handoff_error":null,"native_main":null,"bounded_canary":null,"remote_mutations":false,"r2_mutations":false,
            "root_physical_observation":{"maximum_physical_bytes":METADATA,"conservative_physical_bytes":4096,"exceeds_budget":false}});
        let mut process_args = vec!["bash".to_owned()];
        process_args.extend(argv.clone());
        let mut launch = json!({"schema":LAUNCH,"epoch":209,"phase":"full","issuer_sha256":helper,"unit":name,"invocation_id":iid,"owner":owner,"phase_spec":admission["spec"],"admission":admission["binding"],"argv":argv,
            "process":{"pid":42,"executable":"/usr/bin/bash","executable_sha256":s.interpreter.as_ref().unwrap().sha256,"cmdline":process_args,"start_ticks":123,"cgroup":group,"native_start_clock":{"boot_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","boot_unix_seconds":900,"clock_ticks_per_second":100,"started_unix_seconds":901},"source_read_only_mount":true,"native_limits":{"memory.high":(16u64<<30).to_string(),"memory.max":(32u64<<30).to_string(),"memory.swap.max":"0","pids.max":"512","cpu.max":"800000 100000"}},
            "guard_unit":s.guard_units["full"],"guard_plan_contents":plan,"guard_sample_contents":sample,"captured_unix_seconds":920,
            "guard_manager":{"manager_completion":{"_PID":"1","_UID":"0","UNIT":s.guard_units["full"],"INVOCATION_ID":guard_iid,"MESSAGE":format!("{}: Deactivated successfully.",s.guard_units["full"])}}});
        launch["startup_plan"] = private157::binding(&s.startup_plan);
        launch["guard_plan"] = json!({"path":"/sealed/guard-plan.json","sha256":"a".repeat(64)});
        launch["guard_sample"] =
            json!({"path":format!("/sealed/sample-{guard_iid}.json"),"sha256":"a".repeat(64)});
        launch["guard_sample_contents"]["plan"] = launch["guard_plan"]["path"].clone();
        launch["guard_sample_contents"]["plan_sha256"] = launch["guard_plan"]["sha256"].clone();
        launch["startup_release"] = json!({"path":"/var/lib/jetstreamer/horizon-generic209-full-release-test/release.json","sha256":"a".repeat(64)});
        launch["startup_release_contents"] = barrier::fixture_release(&s, &admission, &launch);
        (s, admission, launch, helper)
    }
    #[test]
    fn completed_launch_binds_real_script_interpreter_and_rejects_historical_command_rewrites() {
        let (s, a, good, helper) = fixture();
        saved_shape(&good, &s, Phase::Full, &helper, &a).unwrap();
        let mut changed = good.clone();
        changed["process"]["cmdline"][1] = json!("/sealed/old-script");
        assert!(saved_shape(&changed, &s, Phase::Full, &helper, &a).is_err());
        let mut changed = good.clone();
        changed["process"]["executable_sha256"] = json!("d".repeat(64));
        assert!(saved_shape(&changed, &s, Phase::Full, &helper, &a).is_err());
        let mut changed = good.clone();
        changed["process"]["executable"] = json!("/usr/bin/foreign");
        assert!(saved_shape(&changed, &s, Phase::Full, &helper, &a).is_err());
        let mut changed = good;
        changed["process"]["native_limits"]["memory.max"] = json!("max");
        assert!(saved_shape(&changed, &s, Phase::Full, &helper, &a).is_err());
    }
    #[test]
    fn completed_launch_requires_live_owner_and_fresh_same_admission_first_guard() {
        let (s, a, good, helper) = fixture();
        for (field, value) in [
            ("ActiveState", "inactive"),
            ("InvocationID", "foreign"),
            ("MainPID", "0"),
            ("NRestarts", "1"),
        ] {
            let mut bad = good.clone();
            bad["owner"][field] = json!(value);
            assert!(saved_shape(&bad, &s, Phase::Full, &helper, &a).is_err());
        }
        let mut bad = good.clone();
        bad["guard_sample_contents"]["producer_invocation_id"] = json!("d".repeat(32));
        assert!(saved_shape(&bad, &s, Phase::Full, &helper, &a).is_err());
        let mut bad = good.clone();
        bad["guard_sample_contents"]["recorded_unix_seconds"] = json!(899);
        assert!(saved_shape(&bad, &s, Phase::Full, &helper, &a).is_err());
        let mut bad = good.clone();
        bad["guard_sample_contents"]["producer_stop_enabled"] = json!(false);
        assert!(saved_shape(&bad, &s, Phase::Full, &helper, &a).is_err());
        let mut bad = good;
        bad["guard_manager"]["manager_completion"]["INVOCATION_ID"] = json!("d".repeat(32));
        assert!(saved_shape(&bad, &s, Phase::Full, &helper, &a).is_err());
    }
    #[test]
    fn completed_launch_native_start_clock_cannot_invent_postsample_process_presence() {
        let (_, _, good, _) = fixture();
        clock_shape(&good["process"]).unwrap();
        for (key, value) in [
            ("started_unix_seconds", json!(1001)),
            ("clock_ticks_per_second", json!(0)),
            ("boot_id", json!("foreign")),
        ] {
            let mut changed = good["process"].clone();
            changed["native_start_clock"][key] = value;
            assert!(clock_shape(&changed).is_err(), "accepted {key}");
        }
    }
    #[test]
    fn completed_launch_current_guard_requires_fresh_same_owner_no_worker_protection() {
        let (s, a, good, _) = fixture();
        let plan = &good["guard_plan_contents"];
        let owner = &good["owner"];
        let mut sample = good["guard_sample_contents"].clone();
        assert!(current_guard_shape(&s, &a, plan, &sample, owner, 9000, 10000).is_err());
        sample["recorded_unix_seconds"] = json!(9990);
        current_guard_shape(&s, &a, plan, &sample, owner, 9000, 10000).unwrap();
        for (key, value) in [
            ("recorded_unix_seconds", json!(8999)),
            ("producer_invocation_id", json!("f".repeat(32))),
            ("producer_stop_enabled", json!(false)),
            ("workers", json!([[42, 100]])),
            ("trip_reason", json!("floor")),
            ("maximum_root_physical_bytes", json!(METADATA + 1)),
            ("worker_observation_error", json!("failed")),
        ] {
            let mut changed = sample.clone();
            changed[key] = value;
            assert!(
                current_guard_shape(&s, &a, plan, &changed, owner, 9000, 10000).is_err(),
                "accepted {key}"
            );
        }
    }
    #[test]
    fn completed_launch_intrinsic_guard_selection_never_falls_back_to_supplied_or_future_evidence()
    {
        let first = BoundFile {
            path: "/sealed/first-sample.json".into(),
            sha256: "a".repeat(64),
        };
        let future = BoundFile {
            path: "/sealed/later-sample.json".into(),
            sha256: "b".repeat(64),
        };
        let latest = json!({"binding":first});
        let startup = json!({"guard_sample":first});
        assert_eq!(
            selected_guard_sample(None, true, &latest, None).unwrap(),
            first
        );
        assert!(selected_guard_sample(Some(&future), true, &latest, None).is_err());
        assert!(selected_guard_sample(Some(&first), true, &Value::Null, None).is_err());
        let later = json!({"binding":future});
        assert_eq!(
            selected_guard_sample(None, false, &later, Some(&startup)).unwrap(),
            first
        );
        assert!(selected_guard_sample(Some(&future), false, &later, Some(&startup)).is_err());
        assert!(selected_guard_sample(Some(&first), false, &later, None).is_err());
    }
    #[test]
    fn completed_launch_cannot_use_a_caller_iid_in_place_of_actual_launch_capture() {
        let old = json!({"phase":"full","admission":{"path":"/sealed/admission.json","sha256":"a".repeat(64)},"invocation_id":"b".repeat(32)});
        assert!(serde_json::from_value::<Prior>(old).is_err());
        assert!(process_matches(Phase::Full, &[], Path::new("/usr/bin/bash"), &[]).is_err());
    }
}
