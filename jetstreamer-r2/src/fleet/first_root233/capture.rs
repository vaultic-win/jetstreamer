//! Capture an actual guarded node, not a synthesized or diagnostic-only launch.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    admission: BoundFile,
    guard: BoundFile,
    guard_plan: BoundFile,
    output: PathBuf,
}

pub(super) fn properties() -> Result<BTreeMap<String, String>> {
    singleton227_capture::properties(
        UNIT,
        "Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,AllowedCPUs,CPUAffinity,RuntimeMaxUSec,LimitFSIZE,LimitFSIZESoft,ProtectHome,ProtectSystem,ProtectControlGroups,NoNewPrivileges,PrivateTmp,PrivateNetwork,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,Environment,OOMPolicy,OOMScoreAdjust,UMask,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainStatus,Result,ActiveState,SubState,NRestarts,ExecStart",
    )
}

pub(super) fn kernel_saved(v: &Value) -> Result<()> {
    let page = v["page_size_bytes"]
        .as_u64()
        .filter(|n| n.is_power_of_two() && (4096..=65536).contains(n))
        .context("first root 233 page size absent or unsupported")?;
    let expected = |n: u64| n / page * page;
    ensure!(
        v["memory_max_bytes"] == expected(MEMORY)
            && v["memory_high_bytes"] == expected(150_000_000_000)
            && v["memory_swap_max_bytes"] == 0
            && v["tasks_max"] == 512
            && v["cpu_period_microseconds"]
                .as_u64()
                .filter(|p| *p > 0)
                .and_then(|p| p.checked_mul(8))
                == v["cpu_quota_microseconds"].as_u64()
            && v["effective_cpus"] == "8-15",
        "first root 233 effective kernel memory, task, or CPU cap differs"
    );
    Ok(())
}
pub(super) fn kernel_limits() -> Result<Value> {
    let root = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{UNIT}"));
    ensure!(
        root.canonicalize()? == root,
        "first root 233 cgroup was redirected"
    );
    let number =
        |name: &str| -> Result<u64> { Ok(fs::read_to_string(root.join(name))?.trim().parse()?) };
    let cpu = fs::read_to_string(root.join("cpu.max"))?;
    let fields = cpu
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(fields.len() == 2, "first root 233 CPU cap shape differs");
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let v = json!({"page_size_bytes":u64::try_from(page)?,"memory_max_bytes":number("memory.max")?,
        "memory_high_bytes":number("memory.high")?,"memory_swap_max_bytes":number("memory.swap.max")?,
        "tasks_max":number("pids.max")?,"cpu_quota_microseconds":fields[0],"cpu_period_microseconds":fields[1],
        "effective_cpus":fs::read_to_string(root.join("cpuset.cpus.effective"))?.trim()});
    kernel_saved(&v)?;
    Ok(v)
}

pub(super) fn guard_valid(
    a: &Value,
    g: &Value,
    p: &Value,
    plan_sha: &str,
    time: u64,
) -> Result<String> {
    admission::validate_saved(a)?;
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("first root 233 admission clock absent")?;
    let guarded = g["recorded_unix_seconds"]
        .as_u64()
        .context("first root 233 guard clock absent")?;
    let invocation = g["producer_invocation_id"]
        .as_str()
        .context("first root 233 guard invocation absent")?;
    ensure!(
        private_prefix::iid(invocation)
            && admitted <= guarded
            && guarded <= time
            && time - admitted <= 900
            && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && p["unit"] == UNIT
            && p["invocation_id"] == invocation
            && p["filesystem"] == "/"
            && p["worker_root"] == ROOT
            && p["receipt_directory"] == GUARD_RECEIPTS
            && p["minimum_free_bytes"] == a["guard_minimum_free_bytes"]
            && p["maximum_root_physical_bytes"] == TREE_STOP
            && p["maximum_worker_vmas"] == 3500000
            && ["native_main", "bounded_canary", "bounded_measurement"]
                .iter()
                .all(|k| p.get(*k).is_none_or(Value::is_null))
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == GUARD_SHA
            && g["plan_sha256"] == plan_sha
            && g["producer"]["invocation_id"] == invocation
            && g["producer"]["restarts"] == 0
            && g["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["pid"].as_u64().is_some_and(|p| p > 1)
            && g["producer_stop_enabled"] == true
            && g["maximum_worker_vmas"] == 3500000
            && g["maximum_root_physical_bytes"] == TREE_STOP
            && g["root_physical_observation"]["maximum_physical_bytes"] == TREE_STOP
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= TREE_STOP)
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(p["minimum_free_bytes"].as_u64())
                .is_some_and(|(n, f)| n >= f)
            && g["workers"].as_array().is_some_and(|w| w.len() == 1)
            && g["workers"][0][0].as_u64().is_some_and(|p| p > 1)
            && g["workers"][0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3500000)
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error",
                "target_handoff_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "first root 233 guard lost its exact scope, owner, floor, tree budget, or healthy worker"
    );
    Ok(invocation.into())
}

fn manager(plan: &BoundFile, g: &BoundFile, admitted: u64, time: u64) -> Result<Value> {
    let selected =
        warmup223::completed_guard_binding(PROTECTIVE, Path::new(GUARD_RECEIPTS), admitted, time)?;
    ensure!(
        selected["binding"] == private157::binding(g),
        "first root 233 first guard is not the latest completed fire"
    );
    let p = singleton227_capture::properties(
        PROTECTIVE,
        "Type,User,Restart,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec,TimeoutStartUSec,ExecStart",
    )?;
    singleton227_capture::require(
        &p,
        &[
            ("Type", "oneshot"),
            ("User", "root"),
            ("Restart", "no"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("ReadWritePaths", GUARD_RECEIPTS),
            ("MemoryMax", "1073741824"),
            ("TasksMax", "256"),
            ("CPUQuotaPerSecUSec", "1s"),
            ("TimeoutStartUSec", "1min 30s"),
        ],
    )?;
    let command = format!(
        "{{ path={GUARD} ; argv[]={GUARD} {} --plan-sha256 {} --self-sha256 {GUARD_SHA}",
        plan.path.display(),
        plan.sha256
    );
    ensure!(
        p.get("ExecStart")
            .is_some_and(|s| private_prefix::same_command(&json!(s), &command)),
        "first root 233 protective executable or plan differs"
    );
    let timer = singleton227_capture::properties(
        &PROTECTIVE.replace(".service", ".timer"),
        "ActiveState,SubState,TimersMonotonic",
    )?;
    ensure!(
        timer.get("ActiveState").is_some_and(|s| s == "active"),
        "first root 233 protective timer is inactive"
    );
    Ok(json!({"completed_selection":selected,"properties":p,"timer":timer}))
}

pub(super) fn worker_saved(w: &Value, g: &Value) -> Result<()> {
    let exe = w["executable"]
        .as_str()
        .context("first root 233 captured worker path absent")?;
    ensure!(
        w["pid"] == g["workers"][0][0]
            && w["sha256"] == WORKER_SHA
            && Path::new(exe).starts_with(Path::new(ROOT).join("scratch"))
            && Path::new(exe).ends_with("bound-worker/historical-worker")
            && w["uid"] == 1000
            && w["nlink"] == 1
            && w["bytes"] == 6511712
            && w["mode"].as_u64().is_some_and(|m| m & 0o222 == 0)
            && w["cgroup"] == format!("0::/system.slice/{UNIT}")
            && w["cpus_allowed_list"] == "8-15"
            && w["effective_cgroup_cpus"] == "8-15"
            && w["process_stat_before"] == w["process_stat_after"]
            && w["process_stat_before"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "first root 233 worker executable, PID lifetime, digest, or CPU assignment differs"
    );
    Ok(())
}
fn worker(g: &Value) -> Result<Value> {
    let pid = g["workers"][0][0]
        .as_u64()
        .context("first root 233 actual worker PID absent")?;
    let process = PathBuf::from(format!("/proc/{pid}"));
    let stat = fs::read_to_string(process.join("stat"))?;
    // The numeric starttime is stable even though CPU counters in stat change.
    let start = |s: &str| -> Result<String> {
        s.rsplit_once(')')
            .and_then(|(_, tail)| tail.split_whitespace().nth(19))
            .map(str::to_owned)
            .context("first root 233 process starttime absent")
    };
    let executable = fs::read_link(process.join("exe"))?;
    let meta = fs::metadata(process.join("exe"))?;
    let status = fs::read_to_string(process.join("status"))?;
    let cpus = status
        .lines()
        .find_map(|s| s.strip_prefix("Cpus_allowed_list:").map(str::trim))
        .context("first root 233 worker affinity absent")?;
    let cgroup = fs::read_to_string(process.join("cgroup"))?;
    let effective = fs::read_to_string(format!(
        "/sys/fs/cgroup/system.slice/{UNIT}/cpuset.cpus.effective"
    ))?;
    let bytes = fs::read(process.join("exe"))?;
    ensure!(
        bytes.len() == 6511712,
        "first root 233 copied worker size differs"
    );
    let w = json!({"pid":pid,"executable":executable,"sha256":hex_lower(&Sha256::digest(&bytes)),
        "uid":meta.uid(),"nlink":meta.nlink(),"mode":meta.mode(),"bytes":meta.len(),
        "cgroup":cgroup.trim(),"cpus_allowed_list":cpus,"effective_cgroup_cpus":effective.trim(),
        "process_stat_before":start(&stat)?,"process_stat_after":start(&fs::read_to_string(process.join("stat"))?)?});
    worker_saved(&w, g)?;
    ensure!(
        fs::read_link(process.join("exe"))? == executable,
        "first root 233 worker changed during capture"
    );
    Ok(w)
}

fn clock_anchor(start: &str) -> Result<Value> {
    let mut t = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) } == 0,
        "first root 233 monotonic anchor unavailable"
    );
    let t = unsafe { t.assume_init() };
    let mono = u64::try_from(t.tv_sec)?
        .checked_mul(1000)
        .and_then(|s| s.checked_add(u64::try_from(t.tv_nsec).ok()? / 1_000_000))
        .context("first root 233 monotonic anchor overflow")?;
    let wall = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let started = start.parse::<u64>()?;
    private_prefix::elapsed(wall / 1000, wall, mono, started)?;
    Ok(json!({"wall_millis":wall,"monotonic_millis":mono,"producer_start_monotonic_us":started}))
}

pub(super) fn run() -> Result<()> {
    let (bound, self_sha) = publication203::parsed_args("capture-first-root233")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&bound)?)?;
    ensure!(
        s.schema == "jetstreamer-first-root233-capture-spec-v1",
        "first root 233 capture spec differs"
    );
    admission::output(&s.output, "launch.json", "horizon-first-root233-capture-")?;
    prerequisites()?;
    let a = native209::immutable_json(&s.admission)?;
    ensure!(
        a["admission_helper_sha256"] == self_sha,
        "first root 233 capture must use the same qualified R2 generation as admission"
    );
    let g = bound_json(&s.guard)?;
    let p = native209::immutable_json(&s.guard_plan)?;
    let time = now()?;
    let invocation = guard_valid(&a, &g, &p, &s.guard_plan.sha256, time)?;
    let completed = manager(
        &s.guard_plan,
        &s.guard,
        a["recorded_unix_seconds"]
            .as_u64()
            .context("first root 233 admission clock absent")?,
        time,
    )?;
    let f = bound_json(&serde_json::from_value(a["fleet"].clone())?)?;
    let mut names = f["unit_census"]
        .as_object()
        .context("first root 233 prior census absent")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(UNIT.into());
    let before = census(&names, 201, 300)?;
    private_prefix::capture_census(&f, &before, UNIT, &invocation, &command())?;
    let own = &before[UNIT];
    ensure!(
        own["MainPID"].as_str().and_then(|s| s.parse::<u64>().ok())
            == g["producer"]["pid"].as_u64(),
        "first root 233 node PID changed since protective fire"
    );
    let props = properties()?;
    sandbox(&props)?;
    let kernel = kernel_limits()?;
    let node = fs::read(format!(
        "/proc/{}/exe",
        g["producer"]["pid"]
            .as_u64()
            .context("first root 233 node PID absent")?
    ))?;
    ensure!(
        hex_lower(&Sha256::digest(&node)) == NODE_SHA,
        "first root 233 actual node digest differs"
    );
    let worker = worker(&g)?;
    let anchor = clock_anchor(
        props
            .get("ExecMainStartTimestampMonotonic")
            .context("first root 233 original start absent")?,
    )?;
    let mut v = scope();
    v["schema"] = json!(SCHEMA);
    v["launched"] = json!(true);
    v["entry_replay"] = json!(true);
    v["ordinary_replay_claim"] = json!(false);
    v["public_sidecar_countdown_authorized"] = json!(true);
    v["expected_exec_start"] = own["ExecStart"].clone();
    v["sandbox"] = json!(props);
    v["kernel_limits"] = kernel.clone();
    v["worker_binding"] = worker;
    let captured = anchor["wall_millis"]
        .as_u64()
        .context("first root 233 capture wall clock absent")?
        / 1000;
    v["clock_anchor"] = anchor;
    v["recorded_unix_seconds"] = json!(captured);
    v["sampled_at_utc"] = json!(publication203::utc(captured)?);
    v["admission"] = private157::binding(&s.admission);
    v["guard"] = private157::binding(&s.guard);
    v["guard_plan"] = private157::binding(&s.guard_plan);
    v["guard_manager"] = completed;
    v["observer"] = a["observer"].clone();
    v["fleet"] = a["fleet"].clone();
    v["guard_minimum_free_bytes"] = a["guard_minimum_free_bytes"].clone();
    v["capture_spec"] = private157::binding(&bound);
    v["capture_helper_sha256"] = json!(self_sha);
    v["resource_samples_taken"] = json!(0);
    v["evidence"] = json!({"units":[{"unit":UNIT,"invocation_id":invocation,"main_pid":g["producer"]["pid"],"restarts":0}]});
    deny_fields(&mut v);
    let claim = DiagnosticClaim {
        epoch: 233,
        unit: UNIT.into(),
        invocation_id: invocation.clone(),
        scratch_path: ROOT.into(),
        launch_receipt: binding(
            s.output
                .to_str()
                .context("first root 233 output is not UTF-8")?,
            &"0".repeat(64),
        ),
    };
    bindings(&claim, &v)?;
    let after = census(&names, 201, 300)?;
    private_prefix::capture_census(&f, &after, UNIT, &invocation, &command())?;
    ensure!(
        before == after && properties()? == props && kernel_limits()? == kernel,
        "first root 233 owner or sandbox changed during capture"
    );
    private157::immutable_receipt(&s.output, &v)
}
