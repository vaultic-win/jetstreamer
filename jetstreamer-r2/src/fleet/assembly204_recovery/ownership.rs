//! Positive recovery owner frames preserve the original epoch clock. A caller
//! cannot select a different invocation, borrow a guard or assert readback.
use super::*;
mod peer;
pub(in crate::fleet) use peer::{
    peer_current, peer_guards, peer_limits, peer_names, peer_observation, peer_resources, peer_view,
};
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::fleet) struct Claim {
    pub epoch: u64,
    pub recovery_plan: BoundFile,
    pub admission: BoundFile,
    pub launch: BoundFile,
    pub actor_launch: BoundFile,
    pub frame: BoundFile,
    pub eta_policy: BoundFile,
}
fn now_millis() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()
        .context("204 clock overflow")
}
pub(super) fn command_matches(actual: &str, expected: &str) -> bool {
    let actual = actual
        .split(" ; start_time=")
        .next()
        .unwrap_or(actual)
        .trim_end_matches(" }");
    actual == expected.trim_end_matches(" }")
}
pub(super) fn no_overlap(actor: Option<downstream::Stage>) -> Result<()> {
    let mut names = BTreeSet::from([OLD_UNIT.into(), OLD_GUARD.into(), UNIT.into(), GUARD.into()]);
    names.extend(downstream::Stage::all().iter().map(|s| s.unit().into()));
    let current = census(&names, 201, 300)?;
    let old = current.get(OLD_UNIT).context("204 original omitted")?;
    ensure!(
        is_idle(old) && (old["InvocationID"] == OLD_IID || old["InvocationID"] == ""),
        "204 original live/replaced"
    );
    ensure!(
        is_idle(current.get(OLD_GUARD).context("204 old guard omitted")?),
        "204 old guard live"
    );
    inactive_status::no_pending_owner_trigger(OLD_UNIT, false)?;
    for (name, row) in &current {
        let permitted = actor.is_some_and(|s| {
            name == s.unit() || (s == downstream::Stage::Assembly && name == GUARD)
        });
        if !permitted
            && name
                .split(|c: char| !c.is_ascii_digit())
                .any(|n| n == "204")
        {
            ensure!(
                !is_live(row)
                    && row["ActiveState"] != "activating"
                    && row["ActiveState"] != "reloading",
                "204 overlapping original/downstream/replacement owner: {name}"
            );
            inactive_status::no_pending_owner_trigger(name, false)?;
        }
    }
    Ok(())
}
fn kernel(owner: &Value, memory: u64) -> Result<Value> {
    let name = s(owner, "Id")?;
    let p = singleton227_capture::properties(
        name,
        "MemoryMax,MemoryHigh,MemoryCurrent,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,Restart,RuntimeMaxUSec,Type,User,ProtectSystem,ProtectHome,NoNewPrivileges",
    )?;
    ensure!(
        p.get("MemoryMax").and_then(|s| s.parse::<u64>().ok()) == Some(memory)
            && p.get("MemorySwapMax").map(String::as_str) == Some("0")
            && p.get("Restart").map(String::as_str) == Some("no"),
        "204 effective hard memory/swap/restart differs"
    );
    let guard = memory == GUARD_MEMORY;
    for (key, value) in [
        ("RuntimeMaxUSec", if guard { "9h" } else { "8h" }),
        ("CPUQuotaPerSecUSec", if guard { "1s" } else { "8s" }),
        ("TasksMax", if guard { "64" } else { "512" }),
        ("Type", "exec"),
        ("User", "root"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("NoNewPrivileges", "yes"),
    ] {
        ensure!(
            p.get(key).map(String::as_str) == Some(value),
            "204 effective kernel/lifecycle property differs: {key}"
        );
    }
    let group = Path::new("/sys/fs/cgroup").join(s(owner, "ControlGroup")?.trim_start_matches('/'));
    ensure!(
        group.starts_with("/sys/fs/cgroup/system.slice"),
        "204 cgroup scope"
    );
    let max = fs::read_to_string(group.join("memory.max"))?
        .trim()
        .parse::<u64>()?;
    let current = fs::read_to_string(group.join("memory.current"))?
        .trim()
        .parse::<u64>()?;
    ensure!(
        max == memory
            && current <= max
            && fs::read_to_string(group.join("memory.swap.max"))?.trim() == "0",
        "204 cgroup hard memory differs"
    );
    Ok(
        json!({"unit":name,"invocation_id":owner["InvocationID"],"memory_max_bytes":max,
        "memory_current_bytes":current,"remaining_hard_memory_growth_bytes":max-current,"systemd_properties":p}),
    )
}
pub(super) fn current_actor(
    stage: downstream::Stage,
    spec: &BoundFile,
    self_sha: &str,
) -> Result<Value> {
    ensure!(
        env::var("TOKIO_WORKER_THREADS").as_deref() == Ok("4"),
        "204 stage runtime worker bound differs"
    );
    let row = unit(stage.unit())?;
    ensure!(
        is_live(&row)
            && row["InvocationID"] == env::var("INVOCATION_ID")?
            && row["MainPID"] == std::process::id().to_string(),
        "204 runner is not exact systemd main owner"
    );
    let command = format!(
        "{{ path={} ; argv[]={} run-assembly204-recovery-stage {} --spec-sha256 {} --self-sha256 {} ; ignore_errors=no }}",
        fs::read_link("/proc/self/exe")?.display(),
        fs::read_link("/proc/self/exe")?.display(),
        spec.path.display(),
        spec.sha256,
        self_sha
    );
    ensure!(
        command_matches(s(&row, "ExecStart")?, &command),
        "204 actual stage command differs"
    );
    kernel(&row, stage.memory())?;
    Ok(row)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchSpec {
    schema: String,
    stage: downstream::Stage,
    recovery_plan: BoundFile,
    admission: BoundFile,
    stage_spec: Option<BoundFile>,
    output_directory: PathBuf,
}
pub(super) fn capture_launch(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let x: LaunchSpec = serde_json::from_value(v.clone())?;
    ensure!(
        x.schema == "jetstreamer-epoch204-assembly-recovery-launch-spec-v1",
        "204 launch spec"
    );
    let p = read(&x.recovery_plan)?;
    custody::plan_scope(&p)?;
    let admission = read(&x.admission)?;
    capacity::validate_issued(&admission, &x.recovery_plan, &p)?;
    let sampled = n(&admission, "sampled_unix_millis")?;
    let now = now_millis()?;
    if x.stage == downstream::Stage::Assembly {
        ensure!(
            sampled <= now && now - sampled <= 900_000,
            "204 assembly admission expired before launch"
        );
    }
    no_overlap(Some(x.stage))?;
    let owner = unit(x.stage.unit())?;
    ensure!(
        is_live(&owner) && id(s(&owner, "InvocationID")?),
        "204 actual recovery owner missing"
    );
    let guard = if x.stage == downstream::Stage::Assembly {
        unit(GUARD)?
    } else {
        Value::Null
    };
    let producer_limits = kernel(&owner, x.stage.memory())?;
    let mut stage_admission = None;
    let guard_limits = if x.stage == downstream::Stage::Assembly {
        ensure!(
            is_live(&guard) && id(s(&guard, "InvocationID")?),
            "204 independent guard missing"
        );
        let exe = fs::read_link(format!("/proc/{}/exe", s(&owner, "MainPID")?))?;
        let command = |guard: bool| {
            format!(
                "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {}{} ; ignore_errors=no }}",
                exe.display(),
                exe.display(),
                x.recovery_plan.path.display(),
                x.recovery_plan.sha256,
                s(&p, "executable_sha256").unwrap_or(""),
                if guard { " --guard" } else { "" }
            )
        };
        ensure!(
            command_matches(s(&owner, "ExecStart")?, &command(false))
                && command_matches(s(&guard, "ExecStart")?, &command(true)),
            "204 helper/independent guard command differs"
        );
        ensure!(
            hex_lower(&Sha256::digest(fs::read(&exe)?)) == s(&p, "executable_sha256")?,
            "204 actual helper executable changed"
        );
        kernel(&guard, GUARD_MEMORY)?
    } else {
        let b = x
            .stage_spec
            .as_ref()
            .context("204 downstream launch spec missing")?;
        let stage = read(b)?;
        downstream::validate_stage_owner(&stage, b, x.stage)?;
        let exe = fs::read_link(format!("/proc/{}/exe", s(&owner, "MainPID")?))?;
        ensure!(
            hex_lower(&Sha256::digest(fs::read(&exe)?)) == self_sha,
            "204 downstream actor is another executable"
        );
        let command = format!(
            "{{ path={} ; argv[]={} run-assembly204-recovery-stage {} --spec-sha256 {} --self-sha256 {} ; ignore_errors=no }}",
            exe.display(),
            exe.display(),
            b.path.display(),
            b.sha256,
            self_sha
        );
        ensure!(
            command_matches(s(&owner, "ExecStart")?, &command),
            "204 captured downstream actual command differs"
        );
        let path: PathBuf = serde_json::from_value(stage["admission"].clone())?;
        let bound = binding(&path)?;
        let issued = read(&bound)?;
        ensure!(
            issued["stage_spec"] == private157::binding(b)
                && issued["stage"] == serde_json::to_value(x.stage)?,
            "204 stage admission launch join"
        );
        stage_admission = Some(bound);
        Value::Null
    };
    let raw = manager(x.stage.unit())?;
    let started = manager_shape(&raw, x.stage.unit(), s(&owner, "InvocationID")?, false)?;
    custody::write_bytes(&x.output_directory.join("launch-manager.jsonl"), &raw)?;
    let journal = binding(&x.output_directory.join("launch-manager.jsonl"))?;
    no_overlap(Some(x.stage))?;
    same_owner(&owner, &unit(x.stage.unit())?)?;
    write(
        &x.output_directory.join("launch.json"),
        &json!({"schema":"jetstreamer-epoch204-assembly-recovery-launch-v1","epoch":204,
        "stage":x.stage,"unit":x.stage.unit(),"invocation_id":owner["InvocationID"],"main_pid":owner["MainPID"],
        "expected_exec_start":owner["ExecStart"],"owner":owner,"guard_unit":if x.stage==downstream::Stage::Assembly {GUARD}else{""},
        "guard_invocation_id":guard["InvocationID"],"guard":guard,"producer_limits":producer_limits,"guard_limits":guard_limits,
        "recovery_plan":x.recovery_plan,"admission":x.admission,"stage_admission":stage_admission,"stage_spec":x.stage_spec,"manager_journal":journal,
        "started_unix_millis":started,"epoch_started_unix_millis":ORIGIN,"issuer":issuer(spec,self_sha),"authority":denied()}),
    )?;
    Ok(())
}
pub(super) fn validate_launch(
    l: &Value,
    plan: &BoundFile,
    p: &Value,
    admission: &BoundFile,
) -> Result<()> {
    ensure!(
        l["schema"] == "jetstreamer-epoch204-assembly-recovery-launch-v1"
            && l["epoch"] == 204
            && l["stage"] == "assembly"
            && l["unit"] == UNIT
            && id(s(l, "invocation_id")?)
            && l["guard_unit"] == GUARD
            && id(s(l, "guard_invocation_id")?)
            && l["recovery_plan"] == private157::binding(plan)
            && l["admission"] == private157::binding(admission)
            && l["epoch_started_unix_millis"] == ORIGIN
            && p["epoch"] == 204
            && l["producer_limits"]["memory_max_bytes"] == MEMORY
            && l["guard_limits"]["memory_max_bytes"] == GUARD_MEMORY,
        "204 assembly launch is not exact guarded issue"
    );
    let raw = sealed(
        &serde_json::from_value(l["manager_journal"].clone())?,
        8 << 20,
    )?;
    ensure!(
        l["started_unix_millis"] == manager_shape(&raw, UNIT, s(l, "invocation_id")?, false)?,
        "204 launch clock differs"
    );
    deny(&l["authority"])
}
fn manager(name: &str) -> Result<Vec<u8>> {
    let result = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "_PID=1",
            &format!("UNIT={name}"),
        ])
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 8 << 20,
        "204 manager capture incomplete"
    );
    Ok(result.stdout)
}
pub(super) fn manager_shape(raw: &[u8], name: &str, iid: &str, success: bool) -> Result<u64> {
    ensure!(id(iid), "204 manager invocation invalid");
    let mut start = None;
    let mut finish = None;
    let mut previous = 0;
    let mut count = 0;
    for line in std::str::from_utf8(raw)?.lines() {
        count += 1;
        ensure!(count <= 16384, "204 manager row bound");
        let row: Value = serde_json::from_str(line)?;
        let at = s(&row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == name
                && row["INVOCATION_ID"] == iid
                && at >= previous,
            "204 manager scope/order differs"
        );
        previous = at;
        if row["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf" {
            ensure!(
                at > 0 && start.replace(at).is_none(),
                "204 manager duplicate start"
            );
        }
        if success {
            let message = s(&row, "MESSAGE")?;
            ensure!(
                !message.contains(": Failed")
                    && !message.starts_with("Stopping ")
                    && !message.starts_with("Stopped ")
                    && !message.contains(": Killing")
                    && row["EXIT_STATUS"].as_str().is_none_or(|s| s == "0"),
                "204 manager reports stop/failure"
            );
            if row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448" {
                ensure!(
                    message == format!("{name}: Deactivated successfully.")
                        && start.is_some_and(|s| at > s)
                        && finish.replace(at).is_none(),
                    "204 invalid natural terminal"
                );
            }
        }
    }
    if success {
        finish.context("204 actual natural success missing")?;
    }
    Ok(start.context("204 exact start missing")? / 1000)
}
pub(super) fn validate_success_terminal(t: &Value, name: &str, iid: &str) -> Result<()> {
    ensure!(
        t["schema"] == "jetstreamer-epoch204-assembly-recovery-success-terminal-v1"
            && t["unit"] == name
            && t["invocation_id"] == iid
            && t["result"] == "natural_success"
            && t["cgroup_empty"] == true
            && t["current_unit"]["Result"] == "success"
            && t["current_unit"]["ExecMainStatus"] == "0"
            && is_idle(&t["current_unit"])
            && t["current_unit"]["InvocationID"] == iid,
        "204 distinct recovery success terminal required"
    );
    let raw = sealed(
        &serde_json::from_value(t["manager_journal"].clone())?,
        8 << 20,
    )?;
    manager_shape(&raw, name, iid, true)?;
    deny(&t["authority"])
}
pub(super) fn capture_success_terminal(
    name: &str,
    iid: &str,
    outcome: &Path,
    directory: &Path,
    spec: &BoundFile,
    self_sha: &str,
) -> Result<()> {
    private(directory)?;
    no_overlap(None)?;
    let before = unit(name)?;
    ensure!(
        is_idle(&before)
            && before["InvocationID"] == iid
            && before["Result"] == "success"
            && before["ExecMainStatus"] == "0",
        "204 actor did not naturally succeed"
    );
    inactive_status::no_pending_owner_trigger(name, false)?;
    let group = capped204205_work::empty_terminal_cgroup(name)?;
    let raw = manager(name)?;
    manager_shape(&raw, name, iid, true)?;
    let refs =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        refs.references.is_empty(),
        "204 terminal output retains live process references"
    );
    let file = custody::open_source(outcome)?;
    ensure!(
        file.metadata()?.len() <= 16 << 20
            && file.metadata()?.uid() == 0
            && file.metadata()?.nlink() == 1,
        "204 outcome custody invalid"
    );
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    custody::write_bytes(&directory.join("success-manager.jsonl"), &raw)?;
    ensure!(
        unit(name)? == before,
        "204 success owner changed during capture"
    );
    let t = json!({"schema":"jetstreamer-epoch204-assembly-recovery-success-terminal-v1","unit":name,"invocation_id":iid,
        "result":"natural_success","current_unit":before,"manager_journal":binding(&directory.join("success-manager.jsonl"))?,
        "outcome":binding(outcome)?,"cgroup_empty":true,"cgroup":group,"issuer":issuer(spec,self_sha),"authority":denied()});
    validate_success_terminal(&t, name, iid)?;
    write(&directory.join("terminal.json"), &t)?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkSpec {
    schema: String,
    claim: Claim,
    observer: BoundFile,
    previous_fleet: BoundFile,
    output: PathBuf,
}
pub(super) fn guard_shape(
    g: &Value,
    p: &Value,
    plan: &BoundFile,
    l: &Value,
    now: u64,
) -> Result<()> {
    let sampled = n(g, "recorded_unix_millis")?;
    let started = n(g, "started_unix_millis")?;
    ensure!(
        g["schema"] == "jetstreamer-epoch204-assembly-recovery-guard-heartbeat-v1"
            && g["epoch"] == 204
            && g["plan_sha256"] == plan.sha256
            && g["source_capture"] == p["source_capture"]
            && g["guard_spec"] == p["guard_spec"]
            && g["producer_unit"] == UNIT
            && g["producer_invocation_id"] == l["invocation_id"]
            && g["guard_unit"] == GUARD
            && g["guard_invocation_id"] == l["guard_invocation_id"]
            && g["trip"] == false
            && g["producer_stop_enabled"] == true
            && g["source_custody_unchanged"] == true
            && g["original_owner_idle"] == true
            && sampled <= now
            && now - sampled <= 15_000
            && started <= sampled
            && started.checked_add(DURATION).is_some_and(|end| now <= end)
            && g["kernel_memory_max_bytes"] == MEMORY
            && g["kernel_memory_high_bytes"] == 48u64 << 30
            && g["memory_swap_max_bytes"] == 0
            && g["cpu_quota_usec_per_second"] == 8_000_000
            && g["tasks_max"] == 512
            && g["maximum_millis"] == DURATION
            && g["maximum_output_bytes"] == OUTPUT_MAX,
        "204 actual independent recovery guard differs/stale/tripped"
    );
    Ok(())
}
pub(super) fn capture_work(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let w: WorkSpec = serde_json::from_value(v.clone())?;
    ensure!(
        w.schema == "jetstreamer-epoch204-assembly-recovery-work-spec-v1",
        "204 work spec"
    );
    let p = read(&w.claim.recovery_plan)?;
    custody::plan_scope(&p)?;
    let origin = read(&w.claim.launch)?;
    validate_launch(&origin, &w.claim.recovery_plan, &p, &w.claim.admission)?;
    let launch = read(&w.claim.actor_launch)?;
    let stage: downstream::Stage = serde_json::from_value(launch["stage"].clone())?;
    no_overlap(Some(stage))?;
    let names = names(&w.claim)?;
    let before = census(&names, 201, 300)?;
    let owner = before.get(stage.unit()).context("204 actor omitted")?;
    same_owner(&launch["owner"], owner)?;
    ensure!(is_live(owner), "204 current work actor inactive");
    let observer = bound_json(&w.observer)?;
    let previous = bound_json(&w.previous_fleet)?;
    ensure!(
        previous["observer_receipt"] == w.observer.path.to_string_lossy().as_ref()
            && previous["observer_sha256"] == w.observer.sha256,
        "204 work context must be accepted coordinated observer"
    );
    let producer = kernel(owner, stage.memory())?;
    let guard = if stage == downstream::Stage::Assembly {
        let g = before
            .get(GUARD)
            .context("204 frame independent guard omitted")?;
        same_owner(&launch["guard"], g)?;
        ensure!(is_live(g), "204 frame guard inactive");
        kernel(g, GUARD_MEMORY)?
    } else {
        Value::Null
    };
    let guard_snapshot = if stage == downstream::Stage::Assembly {
        let path = Path::new(ROOT).join("guard-heartbeat.json");
        let before = fs::symlink_metadata(&path)?;
        ensure!(
            before.is_file()
                && before.uid() == 0
                && before.nlink() == 1
                && before.mode() & 0o022 == 0,
            "204 live guard heartbeat custody"
        );
        let bytes = read_stable_bounded(&path, 1 << 20, "204 actual live guard heartbeat")?;
        let heartbeat: Value = serde_json::from_slice(&bytes)?;
        guard_shape(
            &heartbeat,
            &p,
            &w.claim.recovery_plan,
            &launch,
            now_millis()?,
        )?;
        let output = w.output.with_extension("guard.json");
        custody::write_bytes(&output, &bytes)?;
        Some(binding(&output)?)
    } else {
        None
    };
    let phase = if stage == downstream::Stage::Upload {
        actual_transport_phase(owner)?
    } else {
        stage.public_phase().into()
    };
    let sampled = now_millis()?;
    let output_bytes = match fs::symlink_metadata(OUTPUT) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e.into()),
    };
    ensure!(
        output_bytes <= OUTPUT_MAX,
        "204 observed output exceeded cap"
    );
    let after = census(&names, 201, 300)?;
    ensure!(before == after, "204 work census changed");
    let frame = json!({"schema":"jetstreamer-epoch204-assembly-recovery-work-v1","epoch":204,"stage":stage,"phase":phase,
        "recovery_plan":w.claim.recovery_plan,"launch":w.claim.launch,"actor_launch":w.claim.actor_launch,
        "unit_census_before":before,"unit_census_after":after,"observer":w.observer,"previous_fleet":w.previous_fleet,
        "sampled_unix_millis":sampled,"sampled_at_utc":millis_utc(sampled)?,"epoch_started_unix_millis":ORIGIN,
        "observer_sampled_at_utc":observer["recorded_at_utc"],"observer_is_context":true,"new_resource_samples":0,
        "guard_snapshot":guard_snapshot,"stage_admission":launch["stage_admission"],"producer_limits":producer,"guard_limits":guard,"output_bytes":output_bytes,"issuer":issuer(spec,self_sha),"authority":denied()});
    write(&w.output, &frame)?;
    Ok(())
}
pub(super) fn millis_utc(at: u64) -> Result<String> {
    let seconds: libc::time_t = (at / 1000).try_into()?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    ensure!(
        !unsafe { libc::gmtime_r(&seconds, &mut tm) }.is_null(),
        "204 UTC conversion"
    );
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}
fn actual_transport_phase(owner: &Value) -> Result<String> {
    let result = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            &format!("_SYSTEMD_INVOCATION_ID={}", s(owner, "InvocationID")?),
        ])
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 16 << 20,
        "204 transport journal incomplete"
    );
    let mut phase = "upload";
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let row: Value = serde_json::from_str(line)?;
        ensure!(
            row["_SYSTEMD_UNIT"] == s(owner, "Id")?
                && row["_SYSTEMD_INVOCATION_ID"] == s(owner, "InvocationID")?,
            "204 transport journal owner differs"
        );
        if let Some(message) = row["MESSAGE"]
            .as_str()
            .and_then(|m| serde_json::from_str::<Value>(m).ok())
        {
            if message["event"] == "r2-readback-start" && message["key"] == "epoch-204.jet" {
                phase = "readback";
            }
        }
    }
    Ok(phase.into())
}
pub(in crate::fleet) fn names(c: &Claim) -> Result<BTreeSet<String>> {
    ensure!(c.epoch == 204, "204 recovery claim epoch");
    let mut names = BTreeSet::from([OLD_UNIT.into(), OLD_GUARD.into(), UNIT.into(), GUARD.into()]);
    names.extend(downstream::Stage::all().iter().map(|s| s.unit().into()));
    Ok(names)
}
pub(in crate::fleet) fn row(
    c: &Claim,
    observer: &Value,
    current: &BTreeMap<String, Value>,
    now: u64,
) -> Result<Value> {
    let p = read(&c.recovery_plan)?;
    custody::plan_scope(&p)?;
    let a = read(&c.admission)?;
    capacity::validate_issued(&a, &c.recovery_plan, &p)?;
    let terminal: BoundFile = serde_json::from_value(p["original_terminal"].clone())?;
    let old = read(&terminal)?;
    custody::validate_terminal_saved(&old)?;
    let capture = read(&serde_json::from_value(p["source_capture"].clone())?)?;
    custody::validate_source_capture(
        &capture,
        &serde_json::from_value(p["original_plan"].clone())?,
        &terminal,
        &serde_json::from_value(p["suffix_proof"].clone())?,
        n(&old, "finished_unix_millis")?,
    )?;
    let origin = read(&c.launch)?;
    validate_launch(&origin, &c.recovery_plan, &p, &c.admission)?;
    let actor = read(&c.actor_launch)?;
    let frame = read(&c.frame)?;
    let policy = read(&c.eta_policy)?;
    let stage: downstream::Stage = serde_json::from_value(actor["stage"].clone())?;
    ensure!(
        frame["schema"] == "jetstreamer-epoch204-assembly-recovery-work-v1"
            && frame["epoch"] == 204
            && frame["recovery_plan"] == private157::binding(&c.recovery_plan)
            && frame["launch"] == private157::binding(&c.launch)
            && frame["actor_launch"] == private157::binding(&c.actor_launch)
            && frame["stage"] == actor["stage"]
            && frame["unit_census_before"] == frame["unit_census_after"]
            && frame["epoch_started_unix_millis"] == ORIGIN,
        "204 recovery frame lineage differs"
    );
    let at = n(&frame, "sampled_unix_millis")?;
    ensure!(
        at / 1000 <= now && now - at / 1000 <= 900,
        "204 work frame stale/future"
    );
    let o = bound_json(&serde_json::from_value(frame["observer"].clone())?)?;
    ensure!(
        o == *observer,
        "204 recovery frame has another coordinated observer"
    );
    let owner = current
        .get(stage.unit())
        .context("204 current actor missing")?;
    ensure!(is_live(owner), "204 actor no longer live");
    same_owner(&actor["owner"], owner)?;
    same_owner(&frame["unit_census_after"][stage.unit()], owner)?;
    let old = current.get(OLD_UNIT).context("204 original omitted")?;
    ensure!(
        is_idle(old) && (old["InvocationID"] == OLD_IID || old["InvocationID"] == ""),
        "204 original live/replaced"
    );
    if stage == downstream::Stage::Assembly {
        let guard = current
            .get(GUARD)
            .context("204 independent guard omitted")?;
        ensure!(is_live(guard), "204 independent guard not live");
        same_owner(&actor["guard"], guard)?;
    }
    ensure!(
        policy["schema"] == "jetstreamer-epoch204-assembly-recovery-eta-policy-v1"
            && policy["epoch"] == 204
            && policy["actor_launch"] == private157::binding(&c.actor_launch)
            && policy["frame"] == private157::binding(&c.frame)
            && policy["status_receipt_directory"] == STATUS_DIRECTORY
            && is_lower_hex(s(&policy, "publisher_sha256")?, 64)
            && policy["planning_evidence"]
                .as_array()
                .is_some_and(|e| !e.is_empty()),
        "204 ETA model lacks actual frame and planning basis"
    );
    for evidence in policy["planning_evidence"]
        .as_array()
        .context("204 ETA planning basis")?
    {
        read(&serde_json::from_value(evidence.clone())?)?;
    }
    let remaining = n(&policy, "estimated_remaining_millis")?;
    ensure!(
        remaining > 0 && remaining <= 7 * 86_400_000,
        "204 definite ETA missing/out of bounds"
    );
    let phase = s(&frame, "phase")?;
    ensure!(
        phase == stage.public_phase()
            || (stage == downstream::Stage::Upload && phase == "readback"),
        "204 unsupported recovery wire phase"
    );
    deny(&frame["authority"])?;
    deny(&policy["authority"])?;
    let status = EpochStatus {
        epoch: 204,
        jet_size_bytes: n(&frame, "output_bytes")?,
        elapsed_execution_millis: at.checked_sub(ORIGIN).context("204 epoch clock reset")?,
        estimated_remaining_millis: remaining,
        sampled_at_utc: s(&frame, "sampled_at_utc")?.into(),
        phase: phase.into(),
    };
    Ok(
        json!({"epoch":204,"phase":"assembly-recovery204","live":true,"unit":owner,"current_stage":stage,
        "expected_exec_start":actor["expected_exec_start"],"frame":c.frame,"actor_launch":c.actor_launch,
        "origin_launch":c.launch,"eta_policy":c.eta_policy,"status":status,"recovery_plan":c.recovery_plan,
        "producer_limits":frame["producer_limits"],"guard_limits":frame["guard_limits"],"epoch_started_unix_millis":ORIGIN,
        "ordinary_replay_claim":false,"source_failure_remains_failure":true,"authority":denied()}),
    )
}
pub(in crate::fleet) fn status_matches(
    r: &StatusPublicationReceipt,
    epoch: u64,
    rows: &[Value],
) -> bool {
    epoch == 204
        && r.authenticated_readback
        && rows.iter().any(|row| {
            row["live"] == true
                && serde_json::to_value(&r.status).is_ok_and(|v| v == row["status"])
                && r.pipeline_binding.as_ref().is_some_and(|b| {
                    b.claim_phase == "assembly-recovery204"
                        && b.live_matches(&row["unit"])
                        && row["frame"]["path"] == b.fleet_path.to_string_lossy().as_ref()
                        && row["frame"]["sha256"] == b.fleet_sha256
                        && row["eta_policy"]["sha256"] == b.model_sha256
                })
        })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishSpec {
    schema: String,
    claim: Claim,
}
pub(super) async fn publish(v: &Value, _spec: &BoundFile, self_sha: &str) -> Result<()> {
    let x: PublishSpec = serde_json::from_value(v.clone())?;
    ensure!(
        x.schema == "jetstreamer-epoch204-assembly-recovery-publish-spec-v1",
        "204 publish spec"
    );
    let frame = read(&x.claim.frame)?;
    let observer = bound_json(&serde_json::from_value(frame["observer"].clone())?)?;
    let names = names(&x.claim)?;
    let before = census(&names, 201, 300)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let row = row(&x.claim, &observer, &before, now)?;
    let policy = read(&x.claim.eta_policy)?;
    ensure!(
        policy["publisher_sha256"] == self_sha,
        "204 reviewed publisher changed"
    );
    let origin = read(&x.claim.launch)?;
    let owner = &row["unit"];
    let status: EpochStatus = serde_json::from_value(row["status"].clone())?;
    let binding = pipeline_status::Binding {
        unit: s(owner, "Id")?.into(),
        invocation_id: s(owner, "InvocationID")?.into(),
        expected_exec_start: s(&row, "expected_exec_start")?.into(),
        claim_phase: "assembly-recovery204".into(),
        origin_unit: UNIT.into(),
        origin_invocation_id: s(&origin, "invocation_id")?.into(),
        model_path: x.claim.eta_policy.path,
        model_sha256: x.claim.eta_policy.sha256,
        fleet_path: x.claim.frame.path.clone(),
        fleet_sha256: x.claim.frame.sha256.clone(),
    };
    binding.validate(204, &status.phase)?;
    ensure!(
        census(&names, 201, 300)? == before,
        "204 owner changed before publication"
    );
    let r2 = r2_config_from_env()?;
    let client = s3_client(&r2);
    ensure!(
        get_mutable_object(&client, &r2.bucket, "epoch-204.jet.sha256")
            .await?
            .is_none(),
        "204 ready pair requires status cleanup"
    );
    preflight_status_receipt_write(Path::new(STATUS_DIRECTORY))?;
    let (etag, old) = publish_epoch_status(&client, &r2, &status).await?;
    write_status_receipt(
        Path::new(STATUS_DIRECTORY),
        &StatusPublicationReceipt {
            schema: PIPELINE_STATUS_RECEIPT_SCHEMA.into(),
            bucket: r2.bucket,
            epoch: 204,
            key: "epoch-204.epoch-status.json".into(),
            status,
            object_etag: etag,
            previous_object_etag: old,
            observer_receipt: x.claim.frame.path,
            observer_receipt_sha256: x.claim.frame.sha256,
            controller_invocation_id: String::new(),
            producer_invocation_id: String::new(),
            authenticated_readback: true,
            verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            pipeline_binding: Some(binding),
        },
    )?;
    Ok(())
}
/// Failure remains a separate terminal fact and can never satisfy a Gate.
pub(super) fn validate_failure_terminal(t: &Value) -> Result<()> {
    let name = s(t, "unit")?;
    let iid = s(t, "invocation_id")?;
    ensure!(
        scope(name, 204, 204)
            && name != GUARD
            && t["schema"] == "jetstreamer-epoch204-assembly-recovery-failure-terminal-v1"
            && t["result"] == "failed_or_stopped"
            && t["cgroup_empty"] == true
            && is_idle(&t["current_unit"])
            && t["current_unit"]["InvocationID"] == iid,
        "204 failure terminal scope differs"
    );
    let raw = sealed(
        &serde_json::from_value(t["manager_journal"].clone())?,
        8 << 20,
    )?;
    failure_shape(&raw, name, iid)?;
    deny(&t["authority"])
}
fn failure_shape(raw: &[u8], name: &str, iid: &str) -> Result<()> {
    manager_shape(raw, name, iid, false)?;
    let mut failed = false;
    let mut stopped = false;
    let mut success = false;
    let mut start = None;
    for line in std::str::from_utf8(raw)?.lines() {
        let r: Value = serde_json::from_str(line)?;
        let at = s(&r, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        if r["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf" {
            start = Some(at);
        }
        let failure = matches!(
            r["MESSAGE_ID"].as_str(),
            Some("be02cf6855d2428ba40df7e9d022f03d" | "d9b373ed55a64feb8242e02dbe79a49c")
        );
        let stop = r["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286"
            && r["JOB_TYPE"] == "stop"
            && r["JOB_RESULT"] == "done";
        if failure || stop {
            ensure!(
                start.is_some_and(|s| at > s),
                "204 failure/stop precedes start"
            );
            if failure {
                ensure!(
                    s(&r, "MESSAGE")?
                        .strip_prefix(&format!("{name}: Failed with result '"))
                        .and_then(|s| s.strip_suffix("'."))
                        .is_some_and(|s| matches!(
                            s,
                            "resources"
                                | "protocol"
                                | "timeout"
                                | "exit-code"
                                | "signal"
                                | "core-dump"
                                | "watchdog"
                                | "start-limit-hit"
                                | "oom-kill"
                        ))
                        && r["JOB_RESULT"] != "done",
                    "204 invalid failed event"
                );
            }
        }
        failed |= failure;
        stopped |= stop;
        success |= r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448";
    }
    ensure!(
        (failed || stopped) && (!success || (stopped && !failed)),
        "204 actual failure/controlled stop missing or contradicted"
    );
    Ok(())
}
pub(super) fn capture_failure_terminal(
    name: &str,
    iid: &str,
    directory: &Path,
    spec: &BoundFile,
    self_sha: &str,
) -> Result<()> {
    private(directory)?;
    no_overlap(None)?;
    let before = unit(name)?;
    ensure!(
        is_idle(&before) && before["InvocationID"] == iid,
        "204 failed owner changed/not terminal"
    );
    inactive_status::no_pending_owner_trigger(name, false)?;
    let group = capped204205_work::empty_terminal_cgroup(name)?;
    let raw = manager(name)?;
    failure_shape(&raw, name, iid)?;
    custody::write_bytes(&directory.join("failure-manager.jsonl"), &raw)?;
    ensure!(
        unit(name)? == before,
        "204 failure owner changed during capture"
    );
    let result = json!({"schema":"jetstreamer-epoch204-assembly-recovery-failure-terminal-v1","unit":name,"invocation_id":iid,
        "result":"failed_or_stopped","current_unit":before,"manager_journal":binding(&directory.join("failure-manager.jsonl"))?,
        "cgroup_empty":true,"cgroup":group,"issuer":issuer(spec,self_sha),"authority":denied()});
    validate_failure_terminal(&result)?;
    write(&directory.join("terminal.json"), &result)?;
    Ok(())
}
