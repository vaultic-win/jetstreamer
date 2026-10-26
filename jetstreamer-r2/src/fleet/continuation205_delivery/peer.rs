//! Typed continuation 205 delivery owners. A bounded waiter and every later
//! stage retain their complete disk envelope and independent guard reservation.
use super::*;
use std::os::unix::fs::MetadataExt;

pub(super) const CANONICAL: &str = "/home/ubuntu/horizon";
const PHASE: &str = "continuation-delivery205";
const STATUS_DIRECTORY: &str = "/home/ubuntu/.jetstreamer-private/r2-status-receipts";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::fleet) struct Claim {
    pub epoch: u64,
    pub stage_spec: BoundFile,
    pub actor_launch: BoundFile,
    pub frame: BoundFile,
    pub eta_policy: BoundFile,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchSpec {
    schema: String,
    stage_spec: BoundFile,
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkSpec {
    schema: String,
    epoch: u64,
    stage_spec: BoundFile,
    actor_launch: BoundFile,
    observer: BoundFile,
    previous_fleet: BoundFile,
    output: PathBuf,
}
pub(super) fn id(value: &str) -> bool {
    is_lower_hex(value, 32) && value.bytes().any(|v| v != b'0')
}
pub(super) fn binding(path: &Path) -> Result<BoundFile> {
    Ok(BoundFile {
        path: path.into(),
        sha256: hex_lower(&Sha256::digest(read_stable_bounded(
            path,
            16 << 20,
            "205 metadata binding",
        )?)),
    })
}
pub(super) fn no_file(path: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "205 refuses existing output: {}",
        path.display()
    );
    Ok(())
}
pub(super) fn sealed(b: &BoundFile, maximum: u64) -> Result<()> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= maximum
            && is_lower_hex(&b.sha256, 64),
        "205 sealed artifact custody differs"
    );
    let raw = read_stable_bounded(&b.path, maximum, "205 sealed artifact")?;
    let after = fs::symlink_metadata(&b.path)?;
    ensure!(
        hex_lower(&Sha256::digest(raw)) == b.sha256
            && m.dev() == after.dev()
            && m.ino() == after.ino()
            && m.len() == after.len()
            && m.mtime() == after.mtime()
            && m.mtime_nsec() == after.mtime_nsec()
            && m.ctime() == after.ctime()
            && m.ctime_nsec() == after.ctime_nsec(),
        "205 sealed artifact changed"
    );
    Ok(())
}
pub(super) fn write_bound(path: &Path, value: &Value) -> Result<BoundFile> {
    write(path, value)?;
    binding(path)
}
pub(super) fn issuer(spec: &BoundFile, self_sha: &str) -> Value {
    json!({"executable_sha256":self_sha,"spec":spec,"invocation_id":env::var("INVOCATION_ID").ok(),"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH).map(|d|d.as_secs()).unwrap_or(0),"reviewed_rust_issuer":true})
}
pub(super) fn is_live(v: &Value) -> bool {
    v["LoadState"] == "loaded"
        && v["ActiveState"] == "active"
        && v["SubState"] == "running"
        && v["NRestarts"] == "0"
        && v["MainPID"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|p| p > 1)
}
pub(super) fn command_matches(actual: &str, expected: &str) -> bool {
    assembly204_recovery::delivery_command_matches(actual, expected)
}
fn stages() -> [downstream::Stage; 5] {
    use downstream::Stage;
    [
        Stage::Full,
        Stage::Plugin,
        Stage::Boundary,
        Stage::Import,
        Stage::Upload,
    ]
}
fn unit(name: &str) -> Result<Value> {
    Ok(serde_json::to_value(
        completed_archive_phase::root205_properties(
            name,
            "Id,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,ControlGroup,ExecStart,Result,ExecMainStatus",
        )?,
    )?)
}
pub(super) fn same_owner(old: &Value, current: &Value) -> Result<()> {
    for k in [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "InvocationID",
        "NRestarts",
        "ControlGroup",
    ] {
        ensure!(
            !old[k].is_null() && old[k] == current[k],
            "205 owner changed: {k}"
        );
    }
    ensure!(
        command_matches(s(current, "ExecStart")?, s(old, "ExecStart")?),
        "205 owner command changed"
    );
    Ok(())
}
pub(super) fn current_actor(
    stage: downstream::Stage,
    spec: &BoundFile,
    self_sha: &str,
) -> Result<Value> {
    ensure!(
        env::var("TOKIO_WORKER_THREADS").as_deref() == Ok("4"),
        "205 runtime thread bound differs"
    );
    let owner = unit(stage.unit())?;
    ensure!(
        is_live(&owner)
            && owner["InvocationID"] == env::var("INVOCATION_ID")?
            && s(&owner, "MainPID")?.parse::<u32>()? == std::process::id(),
        "205 runner is not the exact installed main process"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let expected = format!(
        "{{ path={} ; argv[]={} run-continuation205-delivery-stage {} --spec-sha256 {} --self-sha256 {} ; ignore_errors=no }}",
        exe.display(),
        exe.display(),
        spec.path.display(),
        spec.sha256,
        self_sha
    );
    ensure!(
        command_matches(s(&owner, "ExecStart")?, &expected),
        "205 installed runner command differs"
    );
    kernel(&owner, stage.memory())?;
    Ok(owner)
}
fn kernel(owner: &Value, memory: u64) -> Result<Value> {
    let name = s(owner, "Id")?;
    let p = completed_archive_phase::root205_properties(
        name,
        "MemoryMax,MemoryHigh,MemoryCurrent,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,Restart,RuntimeMaxUSec,Type,User,ProtectSystem,ProtectHome,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities",
    )?;
    singleton227_capture::require(
        &p,
        &[
            ("MemoryMax", &memory.to_string()),
            ("MemoryHigh", &(memory / 4 * 3).to_string()),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("TasksMax", "512"),
            ("Restart", "no"),
            ("RuntimeMaxUSec", "8h"),
            ("Type", "exec"),
            ("User", "root"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", "cap_dac_override cap_sys_ptrace"),
            ("AmbientCapabilities", "cap_dac_override cap_sys_ptrace"),
        ],
    )?;
    let group = format!("/system.slice/{name}");
    ensure!(
        owner["ControlGroup"] == group,
        "205 cgroup identity differs"
    );
    let root = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    let max = fs::read_to_string(root.join("memory.max"))?
        .trim()
        .parse::<u64>()?;
    let current = fs::read_to_string(root.join("memory.current"))?
        .trim()
        .parse::<u64>()?;
    ensure!(
        max == memory
            && current <= max
            && fs::read_to_string(root.join("memory.swap.max"))?.trim() == "0",
        "205 native hard memory differs"
    );
    Ok(
        json!({"unit":name,"invocation_id":owner["InvocationID"],"memory_max_bytes":max,"memory_current_bytes":current,"remaining_hard_memory_growth_bytes":max-current,"systemd_properties":p}),
    )
}
fn closed(current: &BTreeMap<String, Value>, selected: downstream::Stage) -> Result<()> {
    let original = current
        .get(UNIT)
        .context("205 completed producer omitted")?;
    ensure!(
        original["MainPID"] == "0"
            && original["NRestarts"] == "0"
            && original["ActiveState"] == "inactive"
            && original["SubState"] == "dead"
            && original["Result"] == "success"
            && original["ExecMainStatus"] == "0"
            && original["InvocationID"] == IID,
        "205 original producer changed or lacks natural success"
    );
    for stage in stages() {
        let owner = current
            .get(stage.unit())
            .context("205 stage omitted from complete census")?;
        if stage == selected {
            ensure!(is_live(owner), "205 selected owner inactive");
        } else {
            ensure!(
                owner["MainPID"] == "0"
                    && owner["NRestarts"] == "0"
                    && matches!(owner["ActiveState"].as_str(), Some("inactive" | "failed"))
                    && matches!(owner["SubState"].as_str(), Some("dead" | "failed")),
                "205 stages overlap"
            );
            inactive_status::no_pending_owner_trigger(
                stage.unit(),
                owner["LoadState"] == "not-found",
            )?;
            let guard_name = startup::guard_for_stage(stage)?;
            let guard = current
                .get(guard_name)
                .context("205 other stage guard omitted")?;
            ensure!(
                guard["MainPID"] == "0"
                    && matches!(guard["ActiveState"].as_str(), Some("inactive" | "failed")),
                "205 other stage guard remains live"
            );
            inactive_status::no_pending_owner_trigger(
                guard_name,
                guard["LoadState"] == "not-found",
            )?;
        }
    }
    for (name, owner) in current {
        if name
            .split(|c: char| !c.is_ascii_digit())
            .any(|part| part == "205")
            && name != selected.unit()
            && name != startup::guard_for_stage(selected)?
        {
            ensure!(
                owner["MainPID"] == "0"
                    && matches!(owner["ActiveState"].as_str(), Some("inactive" | "failed")),
                "205 overlapping or foreign current owner: {name}"
            );
        }
    }
    Ok(())
}
pub(in crate::fleet) fn names(c: &Claim) -> Result<BTreeSet<String>> {
    ensure!(c.epoch == 205, "205 delivery claim epoch differs");
    let mut names = BTreeSet::from([UNIT.into()]);
    for stage in stages() {
        names.insert(stage.unit().into());
        names.insert(startup::guard_for_stage(stage)?.into());
    }
    Ok(names)
}
fn census_names(f: &Value) -> Result<BTreeSet<String>> {
    let mut names = f["unit_census"]
        .as_object()
        .context("205 context census missing")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(UNIT.into());
    for stage in stages() {
        names.insert(stage.unit().into());
        names.insert(startup::guard_for_stage(stage)?.into());
    }
    Ok(names)
}
fn clock() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn validate_launch(
    launch: &Value,
    spec: &BoundFile,
    x: &downstream::StageSpec,
    owner: &Value,
) -> Result<()> {
    let (source, _) = lineage::load_source(&x.source)?;
    ensure!(
        launch["schema"] == "jetstreamer-continuation205-delivery-launch-v1"
            && launch["epoch"] == 205
            && launch["stage_spec"] == private157::binding(spec)
            && launch["stage"] == serde_json::to_value(x.stage)?
            && launch["invocation_id"] == owner["InvocationID"]
            && launch["epoch_started_unix_millis"] == source["epoch_started_unix_millis"],
        "205 launch lineage differs"
    );
    same_owner(&launch["owner"], owner)?;
    deny(&launch["authority"])
}
pub(super) fn capture_launch(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let l: LaunchSpec = serde_json::from_value(v.clone())?;
    ensure!(
        l.schema == "jetstreamer-continuation205-delivery-launch-spec-v1",
        "205 launch spec schema"
    );
    let x = downstream::stage_spec(&read(&l.stage_spec)?)?;
    let (source, _) = lineage::load_source(&x.source)?;
    downstream::gates(&x)?;
    let admission = downstream::issued_admission(&x, &l.stage_spec, n(&source, "archive_bytes")?)?;
    let owner = unit(x.stage.unit())?;
    let protection = startup::current_protection(&x, &l.stage_spec, &owner, clock()? / 1000)?;
    let raw = manager(x.stage.unit())?;
    let started = manager_start(&raw, x.stage.unit(), s(&owner, "InvocationID")?)?;
    let path = l.output.with_extension("manager.json");
    let journal = write_bound(&path, &json!({"raw":std::str::from_utf8(&raw)?}))?;
    write(
        &l.output,
        &json!({"schema":"jetstreamer-continuation205-delivery-launch-v1","epoch":205,"stage":x.stage,"stage_spec":l.stage_spec,"stage_admission":admission,"owner":owner,"invocation_id":owner["InvocationID"],"expected_exec_start":owner["ExecStart"],"started_unix_millis":started,"epoch_started_unix_millis":source["epoch_started_unix_millis"],"manager_journal":journal,"startup_protection":protection,"issuer":issuer(spec,self_sha),"authority":denied()}),
    )
}
fn manager(name: &str) -> Result<Vec<u8>> {
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .env("LC_ALL", "C")
        .args([
            "--no-pager",
            "--output=json",
            "_PID=1",
            &format!("UNIT={name}"),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 8 << 20,
        "205 complete PID 1 history unavailable"
    );
    Ok(out.stdout)
}
fn manager_start(raw: &[u8], name: &str, iid: &str) -> Result<u64> {
    ensure!(
        raw.len() <= 8 << 20 && is_lower_hex(iid, 32) && iid.bytes().any(|v| v != b'0'),
        "205 manager identity/bound differs"
    );
    let mut starts = Vec::new();
    let mut rows = Vec::new();
    let mut cursors = BTreeSet::new();
    let mut previous = 0;
    for line in std::str::from_utf8(raw)?.lines() {
        let row: Value = serde_json::from_str(line)?;
        let at = s(&row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == name
                && at >= previous
                && cursors.insert(s(&row, "__CURSOR")?.to_owned()),
            "205 PID 1 history identity/order differs"
        );
        previous = at;
        if row["INVOCATION_ID"] == iid && row["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf" {
            starts.push(at);
        }
        rows.push((at, row));
        ensure!(rows.len() <= 16384, "205 PID 1 row bound exceeded");
    }
    ensure!(
        starts.len() == 1 && starts[0] > 0,
        "205 exact PID 1 start missing/duplicated"
    );
    for (_, row) in rows.iter().filter(|(at, _)| *at >= starts[0]) {
        ensure!(
            row["INVOCATION_ID"] == iid,
            "205 replacement invocation after captured start"
        );
        let message = s(row, "MESSAGE")?;
        ensure!(
            !message.starts_with("Stopping ")
                && !message.starts_with("Stopped ")
                && !message.contains(": Failed")
                && !message.contains(": Killing")
                && row["MESSAGE_ID"] != "7ad2d189f7e94e70a38c781354912448",
            "205 live actor has terminal/stop history"
        );
    }
    Ok(starts[0] / 1000)
}
fn launch_history(launch: &Value, stage: downstream::Stage) -> Result<()> {
    let saved = read(&serde_json::from_value(launch["manager_journal"].clone())?)?;
    let raw = s(&saved, "raw")?.as_bytes();
    let iid = s(launch, "invocation_id")?;
    ensure!(
        manager_start(raw, stage.unit(), iid)? == n(launch, "started_unix_millis")?,
        "205 saved manager clock differs"
    );
    let current = manager(stage.unit())?;
    manager_start(&current, stage.unit(), iid)?;
    // Additional same-invocation diagnostics may appear; the immutable launch
    // records must remain an exact ordered prefix of the fresh complete history.
    let parse = |bytes: &[u8]| -> Result<Vec<Value>> {
        Ok(serde_json::Deserializer::from_slice(bytes)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()?)
    };
    let old = parse(raw)?;
    let fresh = parse(&current)?;
    ensure!(
        fresh.starts_with(&old),
        "205 captured PID 1 history was replaced or truncated"
    );
    Ok(())
}
fn utc(at: u64) -> Result<String> {
    let seconds: libc::time_t = (at / 1000).try_into()?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    ensure!(
        !unsafe { libc::gmtime_r(&seconds, &mut tm) }.is_null(),
        "205 UTC conversion failed"
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
pub(in crate::fleet) fn row(
    c: &Claim,
    observer: &Value,
    current: &BTreeMap<String, Value>,
    now: u64,
) -> Result<Value> {
    ensure!(c.epoch == 205, "205 claim epoch differs");
    let x = downstream::stage_spec(&read(&c.stage_spec)?)?;
    let (source, _) = lineage::load_source(&x.source)?;
    downstream::gates(&x)?;
    let admission = downstream::saved_admission(&x, &c.stage_spec, n(&source, "archive_bytes")?)?;
    let launch = read(&c.actor_launch)?;
    let frame = read(&c.frame)?;
    closed(current, x.stage)?;
    let owner = current
        .get(x.stage.unit())
        .context("205 live actor omitted")?;
    validate_launch(&launch, &c.stage_spec, &x, owner)?;
    launch_history(&launch, x.stage)?;
    ensure!(
        launch["stage_admission"] == private157::binding(&admission)
            && frame["schema"] == "jetstreamer-continuation205-delivery-work-v1"
            && frame["epoch"] == 205
            && frame["stage"] == launch["stage"]
            && frame["stage_spec"] == private157::binding(&c.stage_spec)
            && frame["actor_launch"] == private157::binding(&c.actor_launch)
            && frame["stage_admission"] == launch["stage_admission"]
            && frame["epoch_started_unix_millis"] == source["epoch_started_unix_millis"]
            && frame["unit_census_before"] == frame["unit_census_after"],
        "205 frame lineage differs"
    );
    let at = n(&frame, "sampled_unix_millis")?;
    ensure!(
        at / 1000 <= now && now - at / 1000 <= 900,
        "205 frame stale/future"
    );
    let observer_bound: BoundFile = serde_json::from_value(frame["observer"].clone())?;
    ensure!(
        bound_json(&observer_bound)? == *observer,
        "205 frame uses another coordinated observer"
    );
    let prior: BoundFile = serde_json::from_value(frame["previous_fleet"].clone())?;
    let accepted = assembly204_recovery::accepted_context(&prior, &observer_bound)?;
    ensure!(
        census_names(&accepted)?
            .iter()
            .all(|name| current.contains_key(name)),
        "205 frame omits complete accepted census"
    );
    same_owner(&frame["unit_census_after"][x.stage.unit()], owner)?;
    startup::current_protection(&x, &c.stage_spec, owner, now)?;
    let policy = read(&c.eta_policy)?;
    ensure!(
        policy["schema"] == "jetstreamer-continuation205-delivery-eta-policy-v1"
            && policy["epoch"] == 205
            && policy["actor_launch"] == private157::binding(&c.actor_launch)
            && policy["frame"] == private157::binding(&c.frame)
            && policy["status_receipt_directory"] == STATUS_DIRECTORY
            && is_lower_hex(s(&policy, "publisher_sha256")?, 64),
        "205 ETA policy identity differs"
    );
    let planning = policy["planning_evidence"]
        .as_array()
        .context("205 ETA planning evidence absent")?;
    ensure!(!planning.is_empty(), "205 ETA planning evidence empty");
    for binding in planning {
        read(&serde_json::from_value(binding.clone())?)?;
    }
    let remaining = n(&policy, "estimated_remaining_millis")?;
    ensure!(
        remaining > 0 && remaining <= 7 * 86_400_000,
        "205 definite ETA outside supported bounds"
    );
    deny(&policy["authority"])?;
    deny(&frame["authority"])?;
    let origin = n(&source, "epoch_started_unix_millis")?;
    let phase = s(&frame, "phase")?;
    ensure!(
        phase == x.stage.public_phase()
            || (x.stage == downstream::Stage::Upload && phase == "readback"),
        "205 frame has unsupported delivery phase"
    );
    let status = EpochStatus {
        epoch: 205,
        jet_size_bytes: n(&source, "archive_bytes")?,
        elapsed_execution_millis: at
            .checked_sub(origin)
            .context("205 original epoch clock reset")?,
        estimated_remaining_millis: remaining,
        sampled_at_utc: utc(at)?,
        phase: phase.into(),
    };
    Ok(
        json!({"epoch":205,"phase":PHASE,"live":true,"unit":owner,"current_stage":x.stage,"expected_exec_start":launch["expected_exec_start"],"frame":c.frame,"actor_launch":c.actor_launch,"stage_spec":c.stage_spec,"eta_policy":c.eta_policy,"status":status,"epoch_started_unix_millis":origin,"producer_limits":frame["producer_limits"],"ordinary_replay_claim":false,"authority":denied()}),
    )
}
struct Peer {
    claim: Claim,
    row: Value,
    frame: Value,
    launch: Value,
    stage: downstream::Stage,
}
fn selected(row: &Value) -> bool {
    row["phase"] == PHASE
        || row["unit"]["Id"]
            .as_str()
            .is_some_and(|n| stages().iter().any(|s| s.unit() == n))
}
fn accepted(f: &Value) -> Result<Vec<Peer>> {
    let active = f["active"]
        .as_array()
        .context("205 fleet active roster absent")?;
    let rows = active.iter().filter(|r| selected(r)).collect::<Vec<_>>();
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(
        rows.len() == 1,
        "205 delivery has duplicate accepted owners"
    );
    let plan = bound_json(&BoundFile {
        path: s(f, "plan")?.into(),
        sha256: s(f, "plan_sha256")?.into(),
    })?;
    let c: Claim = serde_json::from_value(plan["continuation205_delivery"].clone())?;
    let frame = read(&c.frame)?;
    ensure!(
        frame["observer"]["path"] == f["observer_receipt"]
            && frame["observer"]["sha256"] == f["observer_sha256"],
        "205 fleet observer differs"
    );
    let observer = bound_json(&serde_json::from_value(frame["observer"].clone())?)?;
    let current = serde_json::from_value(f["unit_census"].clone())?;
    let expected = row(&c, &observer, &current, n(f, "recorded_unix_seconds")?)?;
    ensure!(
        expected == *rows[0] && expected["live"] == true,
        "205 accepted peer row was not authenticated"
    );
    let launch = read(&c.actor_launch)?;
    let stage = serde_json::from_value(launch["stage"].clone())?;
    Ok(vec![Peer {
        claim: c,
        row: expected,
        frame,
        launch,
        stage,
    }])
}
pub(in crate::fleet) fn peer_names(f: &Value) -> Result<BTreeSet<String>> {
    Ok(accepted(f)?.iter().map(|p| p.stage.unit().into()).collect())
}
pub(in crate::fleet) fn peer_view(f: &Value) -> Result<Value> {
    let peers = accepted(f)?;
    let mut view = f.clone();
    view["active"]
        .as_array_mut()
        .context("205 peer active view absent")?
        .retain(|row| !peers.iter().any(|p| p.row == *row));
    Ok(view)
}
pub(in crate::fleet) fn peer_observation(f: &Value, o: &Value) -> Result<()> {
    for p in accepted(f)? {
        ensure!(
            bound_json(&serde_json::from_value(p.frame["observer"].clone())?)? == *o,
            "205 peer observation differs"
        );
        observation_window(&p.launch, &p.frame, o)?;
    }
    Ok(())
}
fn observation_window(launch: &Value, frame: &Value, observer: &Value) -> Result<bool> {
    let at = utc_seconds(s(observer, "recorded_at_utc")?)?
        .checked_mul(1000)
        .context("205 observation clock overflow")?;
    let start = n(launch, "started_unix_millis")?;
    ensure!(
        start > 0
            && n(frame, "sampled_unix_millis")? >= at
            && start <= n(frame, "sampled_unix_millis")?,
        "205 native main/frame clock does not cover accepted observation"
    );
    Ok(start <= at)
}
pub(in crate::fleet) fn peer_memory_owners(
    f: &Value,
    o: &Value,
) -> Result<BTreeMap<String, Value>> {
    peer_observation(f, o)?;
    // Delivery actors are native main processes, never fabricated replay workers.
    Ok(BTreeMap::new())
}
pub(in crate::fleet) fn peer_guards(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
) -> Result<BTreeMap<String, BoundFile>> {
    let names = peer_names(f)?;
    Ok(bounds
        .iter()
        .filter(|(n, _)| !names.contains(*n))
        .map(|(n, b)| (n.clone(), b.clone()))
        .collect())
}
fn current(p: &Peer, census: &BTreeMap<String, Value>, at: u64) -> Result<Value> {
    closed(census, p.stage)?;
    let owner = census
        .get(p.stage.unit())
        .context("205 peer owner omitted")?;
    same_owner(&p.launch["owner"], owner)?;
    let x = downstream::stage_spec(&read(&p.claim.stage_spec)?)?;
    launch_history(&p.launch, p.stage)?;
    startup::current_protection(&x, &p.claim.stage_spec, owner, at)
}
pub(in crate::fleet) fn peer_current(
    f: &Value,
    census: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>> {
    let mut view = census.clone();
    for p in accepted(f)? {
        current(&p, census, clock()? / 1000)?;
        view.remove(startup::guard_for_stage(p.stage)?);
    }
    Ok(view)
}
fn protection(
    p: &Peer,
    bounds: &BTreeMap<String, BoundFile>,
    census: &BTreeMap<String, Value>,
    at: u64,
) -> Result<Value> {
    let bound = bounds
        .get(p.stage.unit())
        .context("205 protected owner frame omitted")?;
    ensure!(
        *bound == p.claim.frame,
        "205 protection must bind exact accepted frame"
    );
    let frame = read(bound)?;
    let sampled = n(&frame, "sampled_unix_millis")? / 1000;
    ensure!(
        sampled <= at && at - sampled <= 900,
        "205 protected frame stale/future"
    );
    let covered = observation_window(
        &p.launch,
        &frame,
        &bound_json(&serde_json::from_value(frame["observer"].clone())?)?,
    )?;
    let current = current(p, census, at)?;
    Ok(
        json!({"frame":bound,"frame_contents":frame,"root205_startup":current,"included_in_coordinated_whole_host_sample":covered}),
    )
}
fn actor_accounting(mut actor: Value, covered: bool) -> Result<Value> {
    let max = n(&actor, "memory_max_bytes")?;
    let current = n(&actor, "memory_current_bytes")?;
    ensure!(current <= max, "205 current memory exceeds hard cap");
    let credit = if covered { current } else { 0 };
    actor["remaining_hard_memory_growth_bytes"] = json!(max - credit);
    actor["included_in_coordinated_whole_host_sample"] = json!(covered);
    actor["memory_current_credit_bytes"] = json!(credit);
    actor["rss_credit_bytes"] = json!(0);
    actor["accounting"] = json!(if covered {
        "coordinated whole-host sample includes native actor; hard cap minus actual current"
    } else {
        "native actor began after coordinated sample; charge full hard cap without current or RSS credit"
    });
    Ok(actor)
}
fn guard_memory() -> Value {
    json!({"memory_max_bytes":startup::GUARD_MEMORY,"memory_current_bytes":0,"remaining_hard_memory_growth_bytes":startup::GUARD_MEMORY,"accounting":"full independent continuation 205 guard cap; no allocation credit"})
}
pub(in crate::fleet) fn peer_limits(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
    census: &BTreeMap<String, Value>,
    at: u64,
) -> Result<Value> {
    let mut limits = serde_json::Map::new();
    for p in accepted(f)? {
        let proof = protection(&p, bounds, census, at)?;
        let actor = actor_accounting(
            kernel(
                census
                    .get(p.stage.unit())
                    .context("205 peer limits owner absent")?,
                p.stage.memory(),
            )?,
            proof["included_in_coordinated_whole_host_sample"] == true,
        )?;
        limits.insert(
            p.stage.unit().into(),
            json!({"producer":actor,"guard":guard_memory()}),
        );
    }
    Ok(json!(limits))
}
pub(in crate::fleet) fn peer_resources(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
    census: &BTreeMap<String, Value>,
    at: u64,
) -> Result<(u64, Vec<Value>, u64, Vec<Value>)> {
    let mut disk = 0u64;
    let mut memory = 0u64;
    let mut de = Vec::new();
    let mut me = Vec::new();
    for p in accepted(f)? {
        let proof = protection(&p, bounds, census, at)?;
        let actor = actor_accounting(
            kernel(
                census
                    .get(p.stage.unit())
                    .context("205 resource owner absent")?,
                p.stage.memory(),
            )?,
            proof["included_in_coordinated_whole_host_sample"] == true,
        )?;
        let admission = read(&serde_json::from_value(p.frame["stage_admission"].clone())?)?;
        let capacity = read(&serde_json::from_value(admission["capacity"].clone())?)?;
        capacity::validate_provenance(&capacity)?;
        let x = downstream::stage_spec(&read(&p.claim.stage_spec)?)?;
        let (source, _) = lineage::load_source(&x.source)?;
        let candidate = capacity::candidate_with_anchor(
            p.stage,
            n(&source, "archive_bytes")?,
            downstream::anchor_reserve(&x)?,
        )?;
        capacity::validate_capacity(
            &capacity,
            candidate.memory_max_bytes,
            candidate.additional_bytes,
        )?;
        let admitted = n(&capacity, "additional_bytes")?;
        let guard = guard_memory();
        let growth = n(&actor, "remaining_hard_memory_growth_bytes")?
            .checked_add(startup::GUARD_MEMORY)
            .context("205 guard memory overflow")?;
        disk = disk
            .checked_add(admitted)
            .context("205 disk total overflow")?;
        memory = memory
            .checked_add(growth)
            .context("205 memory total overflow")?;
        de.push(json!({"epoch":205,"unit":p.stage.unit(),"remaining_growth_bytes":admitted,"allocation_credit_bytes":0,"protection":proof}));
        me.push(json!({"epoch":205,"unit":p.stage.unit(),"invocation_id":p.launch["invocation_id"],"producer":actor,"guard":guard,"remaining_hard_memory_growth_bytes":growth,"accounting":"native hard growth with current credit only after coordinated sample coverage, plus full independent guard cap; no RSS credit"}));
    }
    Ok((disk, de, memory, me))
}
pub(in crate::fleet) fn qualification_successor(
    f: &Value,
    census: &BTreeMap<String, Value>,
    name: &str,
    iid: &str,
    launch: &BoundFile,
) -> Result<()> {
    let peers = accepted(f)?;
    ensure!(
        peers.len() == 1,
        "205 qualification successor requires one accepted owner"
    );
    let p = &peers[0];
    ensure!(
        p.stage.unit() == name
            && p.row["unit"]["InvocationID"] == iid
            && p.claim.actor_launch == *launch,
        "205 qualification successor identity differs"
    );
    current(p, census, clock()? / 1000)?;
    Ok(())
}

pub(in crate::fleet) fn status_matches(
    r: &StatusPublicationReceipt,
    epoch: u64,
    rows: &[Value],
) -> bool {
    epoch == 205
        && r.authenticated_readback
        && rows.iter().any(|row| {
            row["live"] == true
                && serde_json::to_value(&r.status).is_ok_and(|v| v == row["status"])
                && r.pipeline_binding.as_ref().is_some_and(|b| {
                    b.claim_phase == PHASE
                        && b.live_matches(&row["unit"])
                        && row["frame"]["path"] == b.fleet_path.to_string_lossy().as_ref()
                        && row["frame"]["sha256"] == b.fleet_sha256
                        && row["eta_policy"]["path"] == b.model_path.to_string_lossy().as_ref()
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
    let p: PublishSpec = serde_json::from_value(v.clone())?;
    ensure!(
        p.schema == "jetstreamer-continuation205-delivery-publish-spec-v1",
        "205 status publish schema differs"
    );
    let frame = read(&p.claim.frame)?;
    let observer_binding: BoundFile = serde_json::from_value(frame["observer"].clone())?;
    let observer = bound_json(&observer_binding)?;
    let prior: BoundFile = serde_json::from_value(frame["previous_fleet"].clone())?;
    let fleet = assembly204_recovery::accepted_context(&prior, &observer_binding)?;
    let names = census_names(&fleet)?;
    let before = census(&names, 201, 300)?;
    let row = row(&p.claim, &observer, &before, clock()? / 1000)?;
    let policy = read(&p.claim.eta_policy)?;
    ensure!(
        policy["publisher_sha256"] == self_sha,
        "205 status publisher changed"
    );
    let owner = &row["unit"];
    let status: EpochStatus = serde_json::from_value(row["status"].clone())?;
    let binding = pipeline_status::Binding {
        unit: s(owner, "Id")?.into(),
        invocation_id: s(owner, "InvocationID")?.into(),
        expected_exec_start: s(&row, "expected_exec_start")?.into(),
        claim_phase: PHASE.into(),
        origin_unit: UNIT.into(),
        origin_invocation_id: IID.into(),
        model_path: p.claim.eta_policy.path,
        model_sha256: p.claim.eta_policy.sha256,
        fleet_path: p.claim.frame.path.clone(),
        fleet_sha256: p.claim.frame.sha256.clone(),
    };
    binding.validate(205, &status.phase)?;
    ensure!(
        census(&names, 201, 300)? == before,
        "205 status owner census changed"
    );
    let r2 = r2_config_from_env()?;
    let client = s3_client(&r2);
    ensure!(
        get_mutable_object(&client, &r2.bucket, "epoch-205.jet.sha256")
            .await?
            .is_none(),
        "205 ready pair requires status cleanup"
    );
    preflight_status_receipt_write(Path::new(STATUS_DIRECTORY))?;
    let (etag, old) = publish_epoch_status(&client, &r2, &status).await?;
    write_status_receipt(
        Path::new(STATUS_DIRECTORY),
        &StatusPublicationReceipt {
            schema: PIPELINE_STATUS_RECEIPT_SCHEMA.into(),
            bucket: r2.bucket,
            epoch: 205,
            key: "epoch-205.epoch-status.json".into(),
            status,
            object_etag: etag,
            previous_object_etag: old,
            observer_receipt: p.claim.frame.path,
            observer_receipt_sha256: p.claim.frame.sha256,
            controller_invocation_id: String::new(),
            producer_invocation_id: String::new(),
            authenticated_readback: true,
            verified_unix_seconds: clock()? / 1000,
            pipeline_binding: Some(binding),
        },
    )?;
    Ok(())
}

fn fresh_sample(sampled: u64, now: u64) -> Result<()> {
    ensure!(
        sampled <= now && now - sampled <= 1800,
        "205 coordinated observer is stale or future-dated"
    );
    Ok(())
}

pub(super) fn capture_work(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let w: WorkSpec = serde_json::from_value(v.clone())?;
    ensure!(
        w.schema == "jetstreamer-continuation205-delivery-work-spec-v1" && w.epoch == 205,
        "205 work spec schema/epoch differs"
    );
    let x = downstream::stage_spec(&read(&w.stage_spec)?)?;
    let fleet = assembly204_recovery::accepted_context(&w.previous_fleet, &w.observer)?;
    let observer = bound_json(&w.observer)?;
    let sampled = utc_seconds(s(&observer, "recorded_at_utc")?)?;
    fresh_sample(sampled, clock()? / 1000)?;
    let before = census(&census_names(&fleet)?, 201, 300)?;
    closed(&before, x.stage)?;
    let owner = before.get(x.stage.unit()).context("205 actor missing")?;
    let launch = read(&w.actor_launch)?;
    validate_launch(&launch, &w.stage_spec, &x, owner)?;
    let protection = startup::current_protection(&x, &w.stage_spec, owner, clock()? / 1000)?;
    let producer = kernel(owner, x.stage.memory())?;
    let phase = if x.stage == downstream::Stage::Upload {
        transport_phase(owner)?
    } else {
        x.stage.public_phase().into()
    };
    let at = clock()?;
    let after = census(&census_names(&fleet)?, 201, 300)?;
    ensure!(before == after, "205 work census changed");
    write(
        &w.output,
        &json!({"schema":"jetstreamer-continuation205-delivery-work-v1","epoch":205,"stage":x.stage,"phase":phase,"stage_spec":w.stage_spec,"actor_launch":w.actor_launch,"stage_admission":launch["stage_admission"],"observer":w.observer,"previous_fleet":w.previous_fleet,"unit_census_before":before,"unit_census_after":after,"sampled_unix_millis":at,"epoch_started_unix_millis":launch["epoch_started_unix_millis"],"producer_limits":producer,"startup_protection":protection,"new_resource_samples":0,"issuer":issuer(spec,self_sha),"authority":denied()}),
    )
}
fn transport_phase(owner: &Value) -> Result<String> {
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .env("LC_ALL", "C")
        .args([
            "--no-pager",
            "--output=json",
            &format!("_SYSTEMD_INVOCATION_ID={}", s(owner, "InvocationID")?),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16 << 20,
        "205 transport journal incomplete"
    );
    let mut phase = "upload";
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let row: Value = serde_json::from_str(line)?;
        ensure!(
            row["_SYSTEMD_UNIT"] == s(owner, "Id")?
                && row["_SYSTEMD_INVOCATION_ID"] == s(owner, "InvocationID")?,
            "205 transport journal owner differs"
        );
        if let Some(event) = row["MESSAGE"]
            .as_str()
            .and_then(|m| serde_json::from_str::<Value>(m).ok())
            && event["event"] == "r2-readback-start"
            && event["key"] == "epoch-205.jet"
        {
            phase = "readback";
        }
    }
    Ok(phase.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation205_work_requires_fresh_nonfuture_observer() {
        assert!(super::fresh_sample(100, 100).is_ok());
        assert!(super::fresh_sample(100, 1900).is_ok());
        assert!(super::fresh_sample(100, 1901).is_err());
        assert!(super::fresh_sample(101, 100).is_err());
        assert!(super::fresh_sample(u64::MAX, 0).is_err());
    }
    #[test]
    fn continuation205_owner_allows_manager_display_changes_but_preserves_identity_and_argv() {
        let command = "{ path=/sealed/helper ; argv[]=/sealed/helper run ; ignore_errors=no";
        let owner = json!({"Id":"horizon-full-verify-205-continuation-delivery-v1.service","LoadState":"loaded","ActiveState":"active","SubState":"running","MainPID":"42","InvocationID":"a".repeat(32),"NRestarts":"0","ControlGroup":"/system.slice/horizon-full-verify-205-continuation-delivery-v1.service","ExecStart":format!("{command} ; start_time=[old] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }}")});
        let mut fresh = owner.clone();
        fresh["ExecStart"] = json!(format!(
            "{command} ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
        ));
        same_owner(&owner, &fresh).unwrap();
        for key in [
            "Id",
            "LoadState",
            "ActiveState",
            "SubState",
            "MainPID",
            "InvocationID",
            "NRestarts",
            "ControlGroup",
            "ExecStart",
        ] {
            let mut bad = fresh.clone();
            bad[key] = json!("foreign");
            assert!(same_owner(&owner, &bad).is_err(), "{key}");
        }
    }
    fn rows() -> Vec<Value> {
        vec![
            json!({"_PID":"1","_UID":"0","UNIT":"horizon-205-delivery-full-v1.service","INVOCATION_ID":"a".repeat(32),"__REALTIME_TIMESTAMP":"1000000","__CURSOR":"first","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":"Started Full."}),
        ]
    }
    fn raw(rows: &[Value]) -> Vec<u8> {
        rows.iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect::<String>()
            .into_bytes()
    }
    #[test]
    fn continuation205_peer_requires_exact_live_pid1_start_without_replacement_or_terminal() {
        let name = "horizon-205-delivery-full-v1.service";
        let iid = "a".repeat(32);
        let valid = rows();
        assert_eq!(manager_start(&raw(&valid), name, &iid).unwrap(), 1000);
        for (key, value) in [
            ("_PID", json!("2")),
            ("_UID", json!("1000")),
            ("UNIT", json!("foreign")),
            ("INVOCATION_ID", json!("b".repeat(32))),
            ("MESSAGE_ID", json!("foreign")),
        ] {
            let mut changed = valid.clone();
            changed[0][key] = value;
            assert!(manager_start(&raw(&changed), name, &iid).is_err(), "{key}");
        }
        for (key, value) in [
            ("INVOCATION_ID", json!("b".repeat(32))),
            ("MESSAGE", json!("Stopping Full.")),
            ("MESSAGE_ID", json!("7ad2d189f7e94e70a38c781354912448")),
        ] {
            let mut changed = valid.clone();
            let mut next = valid[0].clone();
            next["__REALTIME_TIMESTAMP"] = json!("2000000");
            next["__CURSOR"] = json!("second");
            next["MESSAGE_ID"] = json!("diagnostic");
            next[key] = value;
            changed.push(next);
            assert!(manager_start(&raw(&changed), name, &iid).is_err(), "{key}");
        }
    }
    #[test]
    fn continuation205_peer_cannot_take_memory_credit_before_its_host_sample() {
        let launch = json!({"started_unix_millis":1000000});
        let frame = json!({"sampled_unix_millis":1001000});
        let observer = json!({"recorded_at_utc":"1970-01-01T00:16:40Z"});
        assert!(observation_window(&launch, &frame, &observer).unwrap());
        assert!(
            !observation_window(&json!({"started_unix_millis":1000001}), &frame, &observer)
                .unwrap()
        );
        assert!(
            observation_window(&launch, &json!({"sampled_unix_millis":999999}), &observer).is_err()
        );
    }
    #[test]
    fn continuation205_peer_closed_claim_requires_real_final_frame_and_eta_binding() {
        let b = json!({"path":"/sealed/metadata.json","sha256":"a".repeat(64)});
        let claim = json!({"epoch":205,"stage_spec":b,"actor_launch":b,"frame":b,"eta_policy":b});
        serde_json::from_value::<Claim>(claim.clone()).unwrap();
        for key in ["stage_spec", "actor_launch", "frame", "eta_policy"] {
            let mut bad = claim.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<Claim>(bad).is_err());
        }
        let first = json!({"schema":"jetstreamer-continuation205-delivery-work-spec-v1","epoch":205,"stage_spec":b,"actor_launch":b,"observer":b,"previous_fleet":b,"output":"/sealed/frame.json"});
        serde_json::from_value::<WorkSpec>(first.clone()).unwrap();
        let mut future = first;
        future["frame"] = b;
        assert!(serde_json::from_value::<WorkSpec>(future).is_err());
    }
    #[test]
    fn continuation205_post_sample_waiter_and_running_actor_keep_full_hard_cap_and_guard() {
        for max in [64u64 << 30, 16u64 << 30] {
            let actor = json!({"memory_max_bytes":max,"memory_current_bytes":3u64<<30});
            let pre = actor_accounting(actor.clone(), false).unwrap();
            assert_eq!(pre["remaining_hard_memory_growth_bytes"], max);
            assert_eq!(pre["memory_current_credit_bytes"], 0);
            assert_eq!(pre["rss_credit_bytes"], 0);
            assert_eq!(
                n(&pre, "remaining_hard_memory_growth_bytes").unwrap()
                    + n(&guard_memory(), "remaining_hard_memory_growth_bytes").unwrap(),
                max + (1u64 << 30)
            );
            let covered = actor_accounting(actor, true).unwrap();
            assert_eq!(
                covered["remaining_hard_memory_growth_bytes"],
                max - (3u64 << 30)
            );
        }
        assert!(
            actor_accounting(
                json!({"memory_max_bytes":1,"memory_current_bytes":2}),
                false
            )
            .is_err()
        );
    }
}
