pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == PHASE && unit == UNIT
}
pub(super) fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub(super) fn props(unit: &str, fields: &str) -> Result<Value> {
    Ok(json!(singleton227_capture::properties(unit, fields)?))
}
pub(super) fn startup(b: &BoundFile) -> Result<(Value, Value)> {
    namespace(
        &b.path,
        epoch_name!("horizon-native", "-execution-"),
        "guarded-startup-handoff.json",
    )?;
    let h = validate_saved_handoff(&b.path, &b.sha256)?;
    let a = sealed(&binding(&h["admission"])?)?;
    let r = sealed(&binding(&a["review"])?)?;
    let source = sealed(&binding(&a["source_publication"])?)?;
    let window = sealed(&binding(&h["peer_window"])?)?;
    ensure!(
        a["mode"] == "native-cold"
            && a["operation"] == "native-cold"
            && a["epoch"] == EPOCH
            && a["unit"] == UNIT
            && a["maximum_root_physical_bytes"] == PROFILE.scratch
            && a["candidate_incremental_peak_bytes"] == DISK_RESERVATION
            && valid_expiry(&a)?
            && r["schema"] == epoch_name!("horizon-native", "-launch-review-v1")
            && r["Main_accepted"] == true
            && r["single_campaign_controller_confirmed"] == true
            && [
                "operation",
                "epoch",
                "observer",
                "fleet",
                "boot_id",
                "source_publication",
                "cpu_affinity"
            ]
            .iter()
            .all(|k| r[*k] == a[*k])
            && window["schema"] == "horizon-singleton211-original-peer-window-v1"
            && window["review"] == a["review"]
            && window["boot_id"] == a["boot_id"]
            && window["peers"].is_array()
            && source["schema"] == epoch_name!("horizon-native", "-source-publication-v1"),
        "native bootstrap original review/peer/source mismatch"
    );
    let f = bound_json(&binding(&a["fleet"])?)?;
    let o = bound_json(&binding(&a["observer"])?)?;
    ensure!(
        f["schema"] == crate::fleet::SCHEMA
            && f["observer_receipt"] == a["observer"]["path"]
            && f["observer_sha256"] == a["observer"]["sha256"]
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["recorded_at_utc"] == f["sampled_at_utc"],
        "native bootstrap admitted observer/fleet mismatch"
    );
    let file = binding(&h["unit_file"])?;
    FsEvidence.bytes(&file, 65536)?;
    let fragment = Path::new(text(&h["producer"], "FragmentPath")?);
    if EPOCH == 257 && fragment == Path::new("/etc/systemd/system").join(UNIT) {
        // The original link can be retired and reused for a new invocation.
        // Its sealed preparation retains the exact target and file hash.
        let preparation = sealed(&binding(&r["preparation"])?)?;
        ensure!(
            preparation["units"][UNIT] == h["unit_file"]
                && preparation["attempt"] == r["attempt"]
                && preparation["operation"] == r["operation"],
            "native bootstrap original producer preparation changed"
        );
    } else {
        ensure!(fragment.canonicalize()? == file.path, "native bootstrap producer file changed");
    }
    Ok((h, a))
}
pub(super) fn helper(a: &Value, sha: &str, actual: bool) -> Result<()> {
    let source = sealed(&binding(&a["source_publication"])?)?;
    let mut roles = source["artifacts"]
        .as_array()
        .context("native bootstrap published artifacts")?
        .iter()
        .filter(|r| r["role"] == "fleet");
    let actor = roles.next().context("native bootstrap fleet helper")?;
    let image = binding(&actor["artifact"])?;
    ensure!(
        roles.next().is_none() && hex(sha, 64) && image.sha256 == sha,
        "native bootstrap fleet helper changed"
    );
    let provenance = sealed(&binding(&actor["provenance"])?)?;
    ensure!(
        provenance["artifact"] == actor["artifact"]
            && provenance["source_commit"] == actor["source_commit"]
            && provenance["all_source_dependencies_enumerated"] == true,
        "native bootstrap fleet helper source changed"
    );
    if actual {
        ensure!(
            std::env::current_exe()?.canonicalize()? == image.path,
            "native bootstrap executing fleet helper differs"
        );
    }
    Ok(())
}
pub(super) fn retention(h: &Value) -> Result<Value> {
    let v = props(
        RETAIN,
        "Id,LoadState,ActiveState,SubState,After,IgnoreOnIsolate,DefaultDependencies,DropInPaths,Job,Wants,Requires,BindsTo,Upholds,FragmentPath",
    )?;
    let historical = &h["retention"];
    for k in [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "IgnoreOnIsolate",
        "DefaultDependencies",
        "DropInPaths",
        "Job",
        "Wants",
        "Requires",
        "BindsTo",
        "Upholds",
        "FragmentPath",
    ] {
        ensure!(
            text(&v, k)? == text(historical, k)?,
            "native bootstrap retention changed {k}"
        );
    }
    ensure!(
        text(&v, "After")?
            .split_whitespace()
            .collect::<BTreeSet<_>>()
            == BTreeSet::from([UNIT, GUARD_UNIT, TIMER]),
        "native bootstrap retention owner"
    );
    Ok(v)
}
pub(super) fn properties() -> Result<Value> {
    props(
        UNIT,
        "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecStart,ControlGroup,ExecMainPID,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,FragmentPath,DropInPaths,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,CPUAffinity,ReadWritePaths,Environment,EnvironmentFiles,TriggeredBy,Job",
    )
}
pub(super) fn live_owner(h: &Value) -> Result<Value> {
    let before = properties()?;
    ensure!(
        Path::new(text(&before, "FragmentPath")?).canonicalize()? == binding(&h["unit_file"])?.path,
        "live native bootstrap producer file changed"
    );
    let historical = &h["producer"];
    for k in [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "InvocationID",
        "MainPID",
        "ControlPID",
        "NRestarts",
        "Result",
        "ControlGroup",
        "FragmentPath",
        "DropInPaths",
        "Restart",
        "KillMode",
        "Delegate",
        "MemoryHigh",
        "MemoryMax",
        "MemorySwapMax",
        "TasksMax",
        "CPUQuotaPerSecUSec",
        "CPUAffinity",
        "ReadWritePaths",
        "Environment",
        "EnvironmentFiles",
        "Job",
    ] {
        ensure!(
            text(&before, k)? == text(historical, k)?,
            "native bootstrap manager changed {k}"
        );
    }
    ensure!(
        pipeline_status::same_exec_start(
            text(historical, "ExecStart")?,
            text(&before, "ExecStart")?
        ),
        "native bootstrap exec changed"
    );
    let group = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    let ids = fs::read_to_string(group.join("cgroup.procs"))?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    native265_process::live_for(
        &ids,
        num(h, "main_pid")?,
        &h["guard_plan"],
        UNIT,
        TEST,
        TEST_SHA,
        PROFILE.worker,
    )?;
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    ensure!(page.is_power_of_two(), "invalid kernel page size");
    for (k, limit) in [
        ("memory.high", 100_000_000_000u64),
        ("memory.max", PROFILE.memory),
        ("memory.swap.max", 0),
    ] {
        ensure!(
            fs::read_to_string(group.join(k))?.trim().parse::<u64>()? == limit / page * page,
            "native bootstrap kernel limit changed {k}"
        );
    }
    retention(h)?;
    guard::live(h)?;
    ensure!(
        before == properties()?,
        "native bootstrap owner changed during capture"
    );
    Ok(before)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    startup_handoff: BoundFile,
    output: PathBuf,
}
fn origin(h: &Value, a: &Value, s: &Spec, b: &BoundFile, actor: &str, wall: u64) -> Result<Value> {
    ensure!(
        s.schema == RUN_SPEC
            && num(h, "recorded_unix_seconds")? <= wall
            && wall - num(h, "recorded_unix_seconds")? <= 300,
        "native bootstrap stale/foreign capture"
    );
    let mut v = json!({"schema":SCHEMA,"epoch":EPOCH,"unit":UNIT,"invocation_id":h["invocation_id"],"main_pid":h["main_pid"],"expected_exec_start":h["producer"]["ExecStart"],"private_run_root":ROOT,"bootstrap_slot":SLOT,
        "native_input_qualified":false,"ordinary_replay_claim":false,"resource_samples_taken":0,"replay_entries":0,"recorded_unix_seconds":wall,"sampled_at_utc":publication203::utc(wall)?,
        "capture_helper_sha256":actor,"capture_spec":private157::binding(b),"startup_handoff":private157::binding(&s.startup_handoff),"admission":h["admission"],"fleet":a["fleet"],"observer":a["observer"],"boot_id":a["boot_id"],"peer_window":h["peer_window"]});
    deny(&mut v);
    Ok(v)
}
pub(super) fn claim(c: &PipelineClaim) -> Result<()> {
    ensure!(
        c.epoch == EPOCH && scope(&c.phase, &c.unit) && c.evidence.len() == 1,
        "native bootstrap running claim scope"
    );
    let b = &c.evidence[0];
    namespace(
        &b.path,
        epoch_name!("horizon-native", "-running-"),
        "intent.json",
    )?;
    let v = sealed(b)?;
    if UNIT == native266::UNIT && v["schema"] == native266_recovery::SCHEMA {
        return native266_recovery::claim(c,&v);
    }
    let sb = binding(&v["capture_spec"])?;
    let s: Spec = serde_json::from_value(sealed(&sb)?)?;
    ensure!(
        s.output == b.path,
        "native bootstrap changed origin destination"
    );
    let (h, a) = startup(&s.startup_handoff)?;
    let actor = text(&v, "capture_helper_sha256")?;
    helper(&a, actor, false)?;
    ensure!(
        v == origin(&h, &a, &s, &sb, actor, num(&v, "recorded_unix_seconds")?)?
            && c.invocation_id == text(&h, "invocation_id")?
            && c.expected_exec_start == text(&h["producer"], "ExecStart")?,
        "native bootstrap substituted running origin"
    );
    Ok(())
}
pub(super) fn live(c: &PipelineClaim, current: &Value) -> Result<()> {
    claim(c)?;
    let v = sealed(&c.evidence[0])?;
    let (h, a) = startup(&binding(&v["startup_handoff"])?)?;
    ensure!(
        a["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "native bootstrap live boot"
    );
    let manager = live_owner(&h)?;
    for k in [
        "Id",
        "InvocationID",
        "MainPID",
        "ControlGroup",
        "NRestarts",
        "ActiveState",
        "SubState",
    ] {
        ensure!(
            text(current, k)? == text(&manager, k)?,
            "native bootstrap fleet owner differs {k}"
        );
    }
    Ok(())
}
pub(super) fn capture() -> Result<()> {
    let (b, actor) = publication203::parsed_args(epoch_name!("capture-native", "-input"))?;
    let s: Spec = serde_json::from_value(sealed(&b)?)?;
    namespace(
        &s.output,
        epoch_name!("horizon-native", "-running-"),
        "intent.json",
    )?;
    let (h, a) = startup(&s.startup_handoff)?;
    helper(&a, &actor, true)?;
    ensure!(
        a["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "native bootstrap capture boot"
    );
    let f = bound_json(&binding(&a["fleet"])?)?;
    let names = f["unit_census"]
        .as_object()
        .context("native bootstrap admitted peers")?
        .keys()
        .cloned()
        .chain(std::iter::once(UNIT.to_owned()))
        .collect();
    let before = census(&names, 201, 300)?;
    native265_capture::peers(&f, &before, UNIT)?;
    live_owner(&h)?;
    let v = origin(&h, &a, &s, &b, &actor, now()?)?;
    ensure!(
        census(&names, 201, 300)? == before,
        "native bootstrap capture peers changed"
    );
    private157::immutable_receipt(&s.output, &v)
}

pub(super) fn validate_inactive(
    f: &Value,
    current: &BTreeMap<String, Value>,
    owners: &[(String, String)],
) -> Result<()> {
    let b = native265::binding(&f["metadata_event"])?;
    let v = native265::sealed(&b)?;
    let unit = UNIT;
    ensure!(
        owners.len() == 1
            && owners[0].0 == unit
            && v["invocation_id"] == owners[0].1
            && v["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "native bootstrap inactive owner mismatch"
    );
    terminal::validate(&v, &b)?;
    for u in [
        &f["unit_census"][unit],
        current
            .get(unit)
            .context("native bootstrap inactive owner omitted")?,
    ] {
        terminal::matches(u, &v)?;
    }
    let p = event::prior(f)?;
    let g = p
        .gates
        .get(&EPOCH)
        .context("native bootstrap inactive gate")?;
    ensure!(
        g.evidence.contains(&b)
            && (if v["native_input_qualified"] == true {
                g.state == "blocked-qualification"
            } else {
                g.state == "failed-needs-repair" && v["repair_backlog_retained"] == true
            }),
        "native bootstrap inactive decision lost backlog"
    );
    Ok(())
}
