//! Exact post-suffix203/older225 guard-policy preparation, never replay admission.
//! Preserve old protection until separately captured replacement timer proofs.
use super::continuation203 as c;
use super::*;
const STATE: &str = "/var/lib/jetstreamer/horizon-ownroot203-rebase-preparation-v1";
const DEST: &str = "/var/lib/jetstreamer/horizon-ownroot203-rebase-plans-v1";
const UNIT225: &str = "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service";
const IID225: &str = "4cd76ae1353a4411885b997f04306402";
const IID203: &str = "ddf3ed2de8b040758ee7a0d696159afd";
const OLD203: &str = "horizon-qualify-203-shrink-root-prefix-resource-f9fc5a0-v1.service";
const OLD205: &str = "horizon-qualify-205-bounded-resource-0136-v1.service";
const NEW_GUARD_SHA: &str = "134904cf2e28ce3ede1dd85a6878e40a407443580d4e83a50cb30efc29fd28be";
const OLD225_GUARD_SHA: &str = "cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560";
const ROOT225: &str = "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1";
const RECEIPTS203: &str = "/var/lib/jetstreamer/horizon-ownroot203-rebased-guard-receipts-v1";
const RECEIPTS225: &str = "/var/lib/jetstreamer/horizon-ownroot225-rebased-guard-receipts-v1";
const OLD_GROWTH: u64 = 960 << 30;
const REMAINING225: u64 = 640 << 30;
const BUFFER: u64 = 64 << 30;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    fleet_plan: BoundFile,
    floor: BoundFile,
    old203_ready: BoundFile,
    old203_result: BoundFile,
    terminal205: BoundFile,
    capability203: BoundFile,
    runtime_extension: BoundFile,
    old_guard203: BoundFile,
    old_guard225: BoundFile,
}
fn bindings(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == "jetstreamer-ownroot203-guard-rebase-spec-v1",
        "wrong guard rebase scope"
    );
    for (b, expected) in [
        (
            &s.floor,
            "b77b70205043c49d4c8ead819c7938e4eb461a43e5547d45af60ca0054e55271",
        ),
        (
            &s.old203_ready,
            "02618d6608caac667ed7f7cb9a05510768090eca4ae1612a3fdc0d894eff2ee9",
        ),
        (
            &s.old203_result,
            "b2e5d62548e88dd743f6abbc52d7883d78ae486e38523ae1426d0827d422fb05",
        ),
        (
            &s.terminal205,
            "0cd7e0223c3b10c6e5ef83b34f76a0eb2320f611960c475d2b99091dfee02637",
        ),
        (
            &s.capability203,
            "470e143791654d9233fb2b1e838c8b982db5ad052fede9c2db1629090302efa0",
        ),
        (
            &s.runtime_extension,
            "dc41e902d91c5a7589171c5714ecca71a852272094362e50aa5d6bb6f6c20c02",
        ),
        (
            &s.old_guard203,
            "3bc56075c11efa8ada7096c3fa6560ac4992105db1439d1f0250bfe156c2bb7d",
        ),
        (
            &s.old_guard225,
            "8c1342136ebd342737a1aefdb41228b07f55e68a216e1e556ae16c098fe0c257",
        ),
    ] {
        ensure!(b.sha256 == expected, "203 rebase changed required evidence");
    }
    Ok(())
}
fn terminal_evidence(ready: &Value, result: &Value, terminal205: &Value) -> Result<()> {
    ensure!(
        ready["schema"] == "jetstreamer-private-epoch203-prefix-reader-handoff-v1"
            && ready["producer_unit"] == OLD203
            && ready["producer_invocation_id"] == "748ffa40e0a2408da0a10fc9e160cf0a"
            && ready["producer_manager_success_proven"] == true
            && ready["producer_result_sha256"]
                == "b2e5d62548e88dd743f6abbc52d7883d78ae486e38523ae1426d0827d422fb05"
            && ready["replay_launch_authorized"] == false
            && ready["publication_authorized"] == false
            && result["schema"] == "jetstreamer-private-epoch203-shrink-root-prefix-resource-v1"
            && result["unit"] == OLD203
            && result["invocation_id"] == ready["producer_invocation_id"]
            && result["success"] == true
            && result["child_return_code"] == 0
            && result["external_signal"] == 0
            && result["error"].is_null()
            && result["capture_error"].is_null()
            && result["natural_parent_completion_required"] == true
            && result["producer_canonical_root_prefix_present"] == true
            && result["producer_segment_manifest_sha256"]
                == "983ecabfc9c36e261a66641b8a039e5e1834198b0c9a07552db38457e67e5722",
        "old203 growth release needs exact natural terminal proof, not a live prefix"
    );
    ensure!(
        terminal205["schema"] == "jetstreamer-private-epoch205-bounded-resource-v1"
            && terminal205["unit"] == OLD205
            && terminal205["invocation_id"] == "e03b74cf861c4d9ba2fc09c34c479537"
            && terminal205["success"] == true
            && terminal205["target_reached"] == true
            && terminal205["child_return_code"] == 1
            && terminal205["external_signal"] == 0
            && terminal205["error"].is_null(),
        "205 bounded owner is not clean terminal"
    );
    Ok(())
}
fn inactive(u: &Value) -> Result<()> {
    ensure!(
        u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && u["Result"] == "success",
        "released owner is not terminal; retain its debt"
    );
    Ok(())
}
fn complete_live_census() -> Result<()> {
    let names = BTreeSet::from([c::UNIT.to_owned(), UNIT225.to_owned()]);
    // The shared census rejects any additional unbound live controller,
    // qualification, verifier or uploader before a reservation is released.
    let owners = census(&names, 201, 300)?;
    ensure!(
        owners.values().all(|u| u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["NRestarts"] == "0"),
        "guard rebase census lost a live owner"
    );
    Ok(())
}
fn budgets(floor: u64, old203: &Value, old225: &Value) -> Result<(u64, u64)> {
    ensure!(
        old203["unit"] == c::UNIT
            && old203["invocation_id"] == IID203
            && old203["minimum_free_bytes"] == 3284969447424u64
            && old203["worker_root"] == c::ROOT
            && old225["unit"] == UNIT225
            && old225["invocation_id"] == IID225
            && old225["minimum_free_bytes"] == 1347800810387u64
            && old225["worker_root"] == ROOT225
            && old203["maximum_worker_vmas"] == 3500000
            && old225["maximum_worker_vmas"] == 3500000
            && old203.get("bounded_canary").is_none()
            && old225.get("bounded_canary").is_none(),
        "203/225 original guard plans differ"
    );
    ensure!(
        248_289_182_611u64
            .checked_add(OLD_GROWTH)
            .and_then(|n| n.checked_add(BUFFER))
            == Some(1_347_800_810_387),
        "old225 reservation arithmetic differs"
    );
    let floor225 = floor.checked_add(BUFFER).context("225 rebase overflow")?;
    let floor203 = floor225
        .checked_add(REMAINING225)
        .context("203 rebase overflow")?;
    Ok((floor203, floor225))
}
fn capability(v: &Value, now: u64) -> Result<()> {
    let g = &v["sample"];
    ensure!(
        v["schema"] == "jetstreamer-horizon-root-budget-capability-v1"
            && v["passed"] == true
            && v["producer_signaled"] == false
            && v["protective_guard_proven"] == false
            && v["stop_authorized"] == false
            && g["producer_stop_enabled"] == false
            && g["guard_sha256"] == NEW_GUARD_SHA
            && g["producer_invocation_id"] == IID203
            && g["producer"]["pid"] == 3634151
            && g["producer"]["active"] == "active"
            && g["producer"]["restarts"] == 0
            && g["maximum_root_physical_bytes"] == c::PEAK
            && g["root_physical_observation"]["maximum_physical_bytes"] == c::PEAK
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation_error"].is_null()
            && g["trip_reason"].is_null()
            && g["workers"].as_array().is_some_and(Vec::is_empty)
            && g["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 3600),
        "203 needs exact no-stop post-suffix own-tree capability, never fake first-fire proof"
    );
    Ok(())
}
pub(super) fn prepare() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 7
            && a[3] == "--spec-sha256"
            && a[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: prepare-ownroot203-rebase SPEC --spec-sha256 SHA --self-sha256 SHA"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let em = fs::symlink_metadata(&exe)?;
    ensure!(
        em.uid() == 0
            && em.nlink() == 1
            && em.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == a[6],
        "203 rebase helper unsealed"
    );
    let sb = BoundFile {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let s: Spec = serde_json::from_value(bound_json(&sb)?)?;
    bindings(&s)?;
    let observer = bound_json(&s.observer)?;
    let fleet = bound_json(&s.fleet)?;
    let fleet_plan = bound_json(&s.fleet_plan)?;
    let time = utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("rebase observer time")?,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && time <= now
            && now - time <= 1800
            && fleet["schema"] == SCHEMA
            && fleet["first_epoch"] == 201
            && fleet["last_epoch"] == 300
            && fleet["observer_sha256"] == s.observer.sha256
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && fleet["plan"].as_str() == s.fleet_plan.path.to_str()
            && fleet["plan_sha256"] == s.fleet_plan.sha256
            && fleet_plan["observer"] == private157::binding(&s.observer)
            && fleet["inventory"]["anomalies"] == 0,
        "guard rebase needs fresh accepted complete-range census"
    );
    let active = fleet["active"].as_array().context("rebase active census")?;
    ensure!(
        active.len() == 2
            && active.iter().all(|u| (u["epoch"] == 203
                && u["producer"]["InvocationID"] == IID203)
                || (u["epoch"] == 225 && u["producer"]["InvocationID"] == IID225)),
        "guard rebase cannot discard another live claim"
    );
    terminal_evidence(
        &bound_json(&s.old203_ready)?,
        &bound_json(&s.old203_result)?,
        &bound_json(&s.terminal205)?,
    )?;
    let old203 = unit(OLD203)?;
    let old205 = unit(OLD205)?;
    inactive(&old203)?;
    inactive(&old205)?;
    let owner203 = unit(c::UNIT)?;
    let owner225 = unit(UNIT225)?;
    let claim: DiagnosticClaim = serde_json::from_value(
        fleet_plan["diagnostics"]
            .as_array()
            .context("rebase diagnostics")?
            .iter()
            .find(|v| v["unit"] == c::UNIT)
            .context("203 claim missing")?
            .clone(),
    )?;
    c::validate_live(&claim, &owner203, Some(&s.runtime_extension))?;
    ensure!(
        owner203["InvocationID"] == IID203
            && owner225["InvocationID"] == IID225
            && owner225["MainPID"] == "2637480"
            && owner225["NRestarts"] == "0"
            && owner225["ActiveState"] == "active"
            && owner225["SubState"] == "running",
        "203/225 owners changed"
    );
    let floor = super::continuation203_admission::floor(&bound_json(&s.floor)?, &fleet)?;
    let (stop203, stop225) = budgets(
        floor,
        &bound_json(&s.old_guard203)?,
        &bound_json(&s.old_guard225)?,
    )?;
    capability(&bound_json(&s.capability203)?, now)?;
    let available = observer["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("rebase free bytes")?;
    ensure!(
        stop203.checked_add(c::PEAK).is_some_and(|n| available >= n),
        "rebase cannot fit intact256GiB own-tree envelope"
    );
    let plan203 = Path::new(STATE).join("guard-203.json");
    let plan225 = Path::new(STATE).join("guard-225.json");
    let policy = Path::new(STATE).join("policy.json");
    let seal = Path::new(STATE).join("seal-plan.json");
    for path in [&plan203, &plan225, &policy, &seal] {
        validate_output_destination(path)?;
    }
    ensure!(
        unit(c::UNIT)? == owner203
            && unit(UNIT225)? == owner225
            && unit(OLD203)? == old203
            && unit(OLD205)? == old205,
        "guard rebase owners changed during preparation"
    );
    complete_live_census()?;
    private157::immutable_receipt(
        &plan203,
        &json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1",
        "unit":c::UNIT,"invocation_id":IID203,"filesystem":"/","minimum_free_bytes":stop203,"worker_root":c::ROOT,
        "maximum_worker_vmas":3500000,"maximum_root_physical_bytes":c::PEAK,"receipt_directory":RECEIPTS203}),
    )?;
    private157::immutable_receipt(
        &plan225,
        &json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1",
        "unit":UNIT225,"invocation_id":IID225,"filesystem":"/","minimum_free_bytes":stop225,"worker_root":ROOT225,
        "maximum_worker_vmas":3500000,"receipt_directory":RECEIPTS225}),
    )?;
    private157::immutable_receipt(
        &policy,
        &json!({"schema":"jetstreamer-ownroot203-guard-rebase-policy-v1",
        "spec":private157::binding(&sb),"helper_sha256":a[6],"observer":private157::binding(&s.observer),
        "fleet":private157::binding(&s.fleet),"old203_ready":private157::binding(&s.old203_ready),
        "old203_result":private157::binding(&s.old203_result),"terminal205":private157::binding(&s.terminal205),
        "runtime_extension":private157::binding(&s.runtime_extension),"capability203":private157::binding(&s.capability203),
        "old_guard203":private157::binding(&s.old_guard203),"old_guard225":private157::binding(&s.old_guard225),
        "owners":{"203":owner203,"225":owner225,"old203":old203,"old205":old205},
        "floor":private157::binding(&s.floor),"century_floor_bytes":floor,"guard_buffer_bytes":BUFFER,
        "released_old203_remaining_bytes":OLD_GROWTH,"older225_remaining_bytes":REMAINING225,
        "new203_own_root_physical_limit_bytes":c::PEAK,"new203_stop_floor_bytes":stop203,"new225_stop_floor_bytes":stop225,
        "new203_guard_sha256":NEW_GUARD_SHA,"unchanged225_guard_sha256":OLD225_GUARD_SHA,
        "new203_guard_plan":private157::file_binding(&plan203)?,"new225_guard_plan":private157::file_binding(&plan225)?,
        "required_order":"prove new225 timer while old225 remains; prove new203 protective timer while old203 remains; capture exact first fires, then stop only superseded timers",
        "replacement_guard_start_authorized":true,"superseded_guard_stop_authorized":false,
        "first_protective_fires_proven":false,"producer_signal_authorized":false,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,"recorded_unix_seconds":now}),
    )?;
    let members = [
        (&plan203, "guard-203.json"),
        (&plan225, "guard-225.json"),
        (&policy, "policy.json"),
    ]
    .into_iter()
    .map(|(p, n)| {
        Ok(json!({"source":p,"name":n,"sha256":private157::file_binding(p)?["sha256"],"mode":256}))
    })
    .collect::<Result<Vec<_>>>()?;
    private157::immutable_receipt(
        &seal,
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":members}),
    )?;
    println!(
        "{}",
        json!({"policy":private157::file_binding(&policy)?,"seal_plan":private157::file_binding(&seal)?,
        "new203_stop_floor_bytes":stop203,"new225_stop_floor_bytes":stop225,"guards_changed":false,"replay_launch_authorized":false})
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    schema: String,
    policy: BoundFile,
    guard203: BoundFile,
    guard225: BoundFile,
}
const TIMER203: &str = "horizon-ownroot203-protective-v1.timer";
const TIMER225: &str = "horizon-ownroot225-protective-v1.timer";
const SERVICE203: &str = "horizon-ownroot203-protective-v1.service";
const SERVICE225: &str = "horizon-ownroot225-protective-v1.service";
const OLD_TIMER203: &str = "horizon-continuation203-guard-ed66145-v1.timer";
const OLD_TIMER225: &str = "horizon-225-rebased-guard-0037-v1.timer";
const OLD_SERVICE203: &str = "horizon-continuation203-guard-ed66145-v1.service";
const OLD_SERVICE225: &str = "horizon-225-rebased-guard-0037-v1.service";

fn timer_rows() -> Result<Vec<Value>> {
    let o = ProcessCommand::new("systemctl")
        .args(["list-timers", "--all", "--output=json", "--no-pager"])
        .output()?;
    ensure!(o.status.success(), "cannot authenticate guard timers");
    Ok(serde_json::from_slice(&o.stdout)?)
}
fn timer_active(name: &str) -> Result<bool> {
    let o = ProcessCommand::new("systemctl")
        .args(["show", name, "--property=ActiveState", "--value"])
        .output()?;
    ensure!(o.status.success(), "guard timer unavailable:{name}");
    Ok(std::str::from_utf8(&o.stdout)?.trim() == "active")
}
fn new_guard(
    g: &Value,
    epoch: u64,
    plan_sha: &str,
    started: u64,
    now: u64,
    floor: u64,
) -> Result<()> {
    let path = format!("{DEST}/guard-{epoch}.json");
    let p: BoundFile = serde_json::from_value(private157::file_binding(Path::new(&path))?)?;
    ensure!(
        p.sha256 == plan_sha,
        "replacement guard plan digest differs"
    );
    new_guard_shape(g, epoch, plan_sha, started, now, floor, &bound_json(&p)?)
}
fn new_guard_shape(
    g: &Value,
    epoch: u64,
    plan_sha: &str,
    started: u64,
    now: u64,
    floor: u64,
    v: &Value,
) -> Result<()> {
    ensure!(matches!(epoch, 203 | 225), "unsupported guardian role");
    let (iid, pid, sha, root, dir) = if epoch == 203 {
        (IID203, 3634151, NEW_GUARD_SHA, c::ROOT, RECEIPTS203)
    } else {
        (IID225, 2637480, OLD225_GUARD_SHA, ROOT225, RECEIPTS225)
    };
    let plan_path = format!("{DEST}/guard-{epoch}.json");
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == sha
            && g["producer_invocation_id"] == iid
            && g["producer"]["invocation_id"] == iid
            && g["producer"]["pid"] == pid
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["restarts"] == 0
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer"]["result"] == "success"
            && g["plan"] == plan_path
            && g["plan_sha256"] == plan_sha
            && g["minimum_free_bytes"] == floor
            && g["maximum_worker_vmas"] == 3500000
            && g["trip_reason"].is_null()
            && g["worker_observation_error"].is_null()
            && g["bounded_measurement"] == false
            && g["bounded_canary"].is_null()
            && g["canary_target_error"].is_null()
            && g["r2_mutations"] == false
            && g["remote_mutations"] == false
            && g["available_bytes"].as_u64().is_some_and(|n| n > floor)
            && g["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n >= started && n <= now && now - n <= 180),
        "replacement{epoch} requires fresh actual protective guard, not capability or plan"
    );
    ensure!(
        v["unit"] == if epoch == 203 { c::UNIT } else { UNIT225 }
            && v["invocation_id"] == iid
            && v["minimum_free_bytes"] == floor
            && v["worker_root"] == root
            && v["receipt_directory"] == dir
            && v["maximum_worker_vmas"] == 3500000,
        "replacement guard deployed plan differs"
    );
    let workers = g["workers"]
        .as_array()
        .context("replacement guard worker census")?;
    if epoch == 203 {
        ensure!(
            g["producer_stop_enabled"] == true
                && g["maximum_root_physical_bytes"] == c::PEAK
                && v["maximum_root_physical_bytes"] == c::PEAK
                && workers.is_empty()
                && g["root_physical_observation"]["maximum_physical_bytes"] == c::PEAK
                && g["root_physical_observation"]["exceeds_budget"] == false
                && g["root_physical_observation"]["conservative_physical_bytes"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n <= c::PEAK)
                && g["root_physical_observation_error"].is_null(),
            "203 own-tree guard is not protective"
        );
    } else {
        ensure!(
            workers.len() == 1
                && workers[0][0].as_u64().is_some_and(|n| n > 0)
                && workers[0][1].as_u64().is_some_and(|n| n > 0 && n < 3500000)
                && v.get("maximum_root_physical_bytes").is_none(),
            "225 guard must preserve real worker/VMA protection"
        );
    }
    Ok(())
}
fn guard_command(
    current: &Value,
    binary: &str,
    plan: &str,
    plan_sha: &str,
    binary_sha: &str,
) -> Result<()> {
    let expected = format!(
        "{{ path={binary} ; argv[]={binary} {plan} --plan-sha256 {plan_sha} --self-sha256 {binary_sha}"
    );
    ensure!(
        current["ExecStart"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .is_some_and(|(command, _)| command == expected),
        "guardian command differs"
    );
    let bytes = read_stable_bounded(Path::new(binary), 16 << 20, "guardian executable")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == binary_sha,
        "guardian executable changed"
    );
    Ok(())
}
fn replacement_sandbox(service: &str, receipts: &str) -> Result<()> {
    let o=ProcessCommand::new("systemctl").args(["show",service,"--no-pager",
        "--property=Type,User,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,MemoryMax,CPUQuotaPerSecUSec,TasksMax"]).output()?;
    ensure!(o.status.success(), "replacement sandbox unreadable");
    let text = std::str::from_utf8(&o.stdout)?;
    let properties: BTreeMap<_, _> = text
        .lines()
        .map(|s| s.split_once('=').context("guard sandbox property"))
        .collect::<Result<_>>()?;
    for (key, expected) in [
        ("Type", "oneshot"),
        ("User", "root"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", "cap_dac_override cap_sys_ptrace"),
        ("AmbientCapabilities", "cap_dac_override cap_sys_ptrace"),
        ("ReadWritePaths", receipts),
        ("MemoryMax", "1073741824"),
        ("CPUQuotaPerSecUSec", "1s"),
        ("TasksMax", "256"),
    ] {
        ensure!(
            properties.get(key) == Some(&expected),
            "replacement sandbox differs:{key}"
        );
    }
    Ok(())
}
fn recurrence_shape(monotonic: &str, calendar: &str) -> Result<()> {
    let lines: Vec<_> = monotonic.lines().filter(|l| !l.trim().is_empty()).collect();
    ensure!(
        lines.len() == 2
            && lines
                .iter()
                .any(|l| l.starts_with("{ OnUnitActiveUSec=1min ; next_elapse="))
            && lines
                .iter()
                .any(|l| l.starts_with("{ OnActiveUSec=2s ; next_elapse="))
            && calendar.trim().is_empty(),
        "replacement guardian must recur every60s, not merely fire once"
    );
    Ok(())
}
fn recurring_timer(timer: &str) -> Result<()> {
    let m = ProcessCommand::new("systemctl")
        .args(["show", timer, "--property=TimersMonotonic", "--value"])
        .output()?;
    let c = ProcessCommand::new("systemctl")
        .args(["show", timer, "--property=TimersCalendar", "--value"])
        .output()?;
    let a = ProcessCommand::new("systemctl")
        .args(["show", timer, "--property=AccuracyUSec", "--value"])
        .output()?;
    ensure!(
        m.status.success()
            && c.status.success()
            && a.status.success()
            && std::str::from_utf8(&a.stdout)?.trim() == "1s",
        "replacement timer precision unreadable/wrong"
    );
    recurrence_shape(
        std::str::from_utf8(&m.stdout)?,
        std::str::from_utf8(&c.stdout)?,
    )
}
fn guard_completion(epoch: u64, g: &Value, started: u64) -> Result<Value> {
    let (timer, service) = if epoch == 203 {
        (TIMER203, SERVICE203)
    } else {
        (TIMER225, SERVICE225)
    };
    let row = timer_rows()?
        .into_iter()
        .find(|v| v["unit"] == timer)
        .context("replacement timer missing")?;
    recurring_timer(timer)?;
    ensure!(
        timer_active(timer)?
            && row["activates"] == service
            && row["last"]
                .as_u64()
                .is_some_and(|n| n >= started.saturating_mul(1_000_000)),
        "replacement timer never actually fired"
    );
    let current = unit(service)?;
    let (binary, sha, receipts) = if epoch == 203 {
        (
            "/var/lib/jetstreamer/horizon-ownroot203-capability-8623b37c-v1/jetstreamer-horizon-standalone-guard",
            NEW_GUARD_SHA,
            RECEIPTS203,
        )
    } else {
        (
            "/var/lib/jetstreamer/horizon-225-natural-root-guard-v1/jetstreamer-horizon-standalone-guard",
            OLD225_GUARD_SHA,
            RECEIPTS225,
        )
    };
    guard_command(
        &current,
        binary,
        &format!("{DEST}/guard-{epoch}.json"),
        g["plan_sha256"].as_str().context("guard plan SHA")?,
        sha,
    )?;
    replacement_sandbox(service, receipts)?;
    ensure!(
        current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "inactive",
        "replacement guard has not finished successfully"
    );
    let iid = g["guard_invocation_id"]
        .as_str()
        .context("guard invocation")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "bad guard invocation"
    );
    let match_iid = format!("INVOCATION_ID={iid}");
    let o = ProcessCommand::new("journalctl")
        .args([
            "--unit",
            service,
            &match_iid,
            "--no-pager",
            "--output=json",
            "--grep",
            "Deactivated successfully",
        ])
        .output()?;
    ensure!(o.status.success(), "replacement guard journal unreadable");
    let rows: Vec<Value> = std::str::from_utf8(&o.stdout)?
        .lines()
        .filter(|l| !l.is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        rows.len() == 1
            && rows[0]["INVOCATION_ID"] == iid
            && rows[0]["_PID"] == "1"
            && rows[0]["UNIT"] == service,
        "replacement guard lacks exact PID1 completion"
    );
    Ok(json!({"timer":row,"service":current,"manager_completion":rows}))
}
pub(super) fn capture() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 7
            && a[3] == "--spec-sha256"
            && a[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: capture-ownroot203-rebase SPEC --spec-sha256 SHA --self-sha256 SHA"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let em = fs::symlink_metadata(&exe)?;
    ensure!(
        em.uid() == 0
            && em.nlink() == 1
            && em.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == a[6],
        "guard handoff helper unsealed"
    );
    let hb = BoundFile {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let h: Handoff = serde_json::from_value(bound_json(&hb)?)?;
    ensure!(
        h.schema == "jetstreamer-ownroot203-guard-handoff-spec-v1"
            && h.policy.path == Path::new(DEST).join("policy.json")
            && h.guard203.path.parent() == Some(Path::new(RECEIPTS203))
            && h.guard225.path.parent() == Some(Path::new(RECEIPTS225)),
        "foreign guard handoff scope"
    );
    let p = bound_json(&h.policy)?;
    ensure!(
        p["schema"] == "jetstreamer-ownroot203-guard-rebase-policy-v1"
            && p["replacement_guard_start_authorized"] == true
            && p["superseded_guard_stop_authorized"] == false
            && p["first_protective_fires_proven"] == false
            && p["replay_launch_authorized"] == false
            && p["publication_authorized"] == false
            && p["r2_mutations"] == false,
        "invalid prepared guard policy"
    );
    let s: Spec = serde_json::from_value(bound_json(&serde_json::from_value(p["spec"].clone())?)?)?;
    bindings(&s)?;
    terminal_evidence(
        &bound_json(&s.old203_ready)?,
        &bound_json(&s.old203_result)?,
        &bound_json(&s.terminal205)?,
    )?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sampled = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("handoff sample time")?,
    )?;
    ensure!(
        sampled <= now
            && now - sampled <= 1800
            && f["observer_sha256"] == s.observer.sha256
            && p["observer"] == private157::binding(&s.observer)
            && p["fleet"] == private157::binding(&s.fleet),
        "stale guard handoff"
    );
    let floor = super::continuation203_admission::floor(&bound_json(&s.floor)?, &f)?;
    let (floor203, floor225) = budgets(
        floor,
        &bound_json(&s.old_guard203)?,
        &bound_json(&s.old_guard225)?,
    )?;
    ensure!(
        p["new203_stop_floor_bytes"] == floor203
            && p["new225_stop_floor_bytes"] == floor225
            && p["new203_own_root_physical_limit_bytes"] == c::PEAK
            && p["older225_remaining_bytes"] == REMAINING225,
        "guard handoff cannot weaken prepared budgets"
    );
    inactive(&unit(OLD203)?)?;
    inactive(&unit(OLD205)?)?;
    let before203 = unit(c::UNIT)?;
    let before225 = unit(UNIT225)?;
    ensure!(
        before203 == p["owners"]["203"] && before225 == p["owners"]["225"],
        "guard handoff owner changed"
    );
    let started = p["recorded_unix_seconds"].as_u64().context("policy time")?;
    let g203 = bound_json(&h.guard203)?;
    let g225 = bound_json(&h.guard225)?;
    new_guard(
        &g203,
        203,
        p["new203_guard_plan"]["sha256"]
            .as_str()
            .context("203 guard plan SHA")?,
        started,
        now,
        floor203,
    )?;
    new_guard(
        &g225,
        225,
        p["new225_guard_plan"]["sha256"]
            .as_str()
            .context("225 guard plan SHA")?,
        started,
        now,
        floor225,
    )?;
    let fire203 = guard_completion(203, &g203, started)?;
    let fire225 = guard_completion(225, &g225, started)?;
    ensure!(
        g225["recorded_unix_seconds"]
            .as_u64()
            .zip(g203["recorded_unix_seconds"].as_u64())
            .is_some_and(|(a, b)| a <= b),
        "replacement225 must be proved before203"
    );
    for timer in [OLD_TIMER203, OLD_TIMER225] {
        ensure!(
            timer_active(timer)?,
            "old protection was removed before new proofs"
        );
    }
    let old_timers = timer_rows()?;
    for (timer, service) in [
        (OLD_TIMER203, OLD_SERVICE203),
        (OLD_TIMER225, OLD_SERVICE225),
    ] {
        ensure!(
            old_timers
                .iter()
                .any(|r| r["unit"] == timer && r["activates"] == service),
            "superseded timer belongs to a different service"
        );
    }
    guard_command(
        &unit(OLD_SERVICE203)?,
        "/var/lib/jetstreamer/horizon-205-bounded-preparation-candidate-v1/jetstreamer-horizon-standalone-guard",
        s.old_guard203.path.to_str().context("old203 guard path")?,
        &s.old_guard203.sha256,
        c::GUARD_SHA,
    )?;
    guard_command(
        &unit(OLD_SERVICE225)?,
        "/var/lib/jetstreamer/horizon-225-natural-root-guard-v1/jetstreamer-horizon-standalone-guard",
        s.old_guard225.path.to_str().context("old225 guard path")?,
        &s.old_guard225.sha256,
        OLD225_GUARD_SHA,
    )?;
    let intent = Path::new(STATE).join("retire-old-intent.json");
    let output = Path::new(STATE).join("handoff.json");
    validate_output_destination(&intent)?;
    validate_output_destination(&output)?;
    private157::immutable_receipt(
        &intent,
        &json!({"schema":"jetstreamer-ownroot203-retire-guard-intent-v1",
        "handoff_spec":private157::binding(&hb),"policy":private157::binding(&h.policy),"helper_sha256":a[6],
        "guard203":private157::binding(&h.guard203),"guard225":private157::binding(&h.guard225),
        "fire203":fire203,"fire225":fire225,"before203":before203,"before225":before225,
        "stop_only":[OLD_TIMER203,OLD_SERVICE203,OLD_TIMER225,OLD_SERVICE225],"producer_signal_authorized":false}),
    )?;
    ensure!(
        unit(c::UNIT)? == before203 && unit(UNIT225)? == before225,
        "producer changed before old guard retirement"
    );
    complete_live_census()?;
    let stopped = ProcessCommand::new("systemctl")
        .args([
            "stop",
            OLD_TIMER203,
            OLD_SERVICE203,
            OLD_TIMER225,
            OLD_SERVICE225,
        ])
        .output()?;
    ensure!(
        stopped.status.success(),
        "could not retire exact superseded guards"
    );
    ensure!(
        !timer_active(OLD_TIMER203)?
            && !timer_active(OLD_TIMER225)?
            && timer_active(TIMER203)?
            && timer_active(TIMER225)?,
        "guard timer handoff incomplete"
    );
    ensure!(
        unit(c::UNIT)? == before203 && unit(UNIT225)? == before225,
        "producer changed during guardian handoff"
    );
    private157::immutable_receipt(
        &output,
        &json!({"schema":"jetstreamer-ownroot203-guard-handoff-v1",
        "policy":private157::binding(&h.policy),"intent":private157::file_binding(&intent)?,"helper_sha256":a[6],
        "new203_guard_plan":private157::file_binding(&Path::new(DEST).join("guard-203.json"))?,
        "new225_guard_plan":private157::file_binding(&Path::new(DEST).join("guard-225.json"))?,
        "new203_guard_sha256":NEW_GUARD_SHA,"unchanged225_guard_sha256":OLD225_GUARD_SHA,
        "new203_stop_floor_bytes":floor203,"new225_stop_floor_bytes":floor225,"century_floor_bytes":floor,
        "older225_remaining_bytes":REMAINING225,"new203_own_root_physical_limit_bytes":c::PEAK,
        "exact_new_protective_fires_proven":true,"only_superseded_guard_units_retired":true,
        "producer_restarted":false,"producer_signaled_by_handoff":false,"producer_hard_limits_changed":false,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()}),
    )?;
    println!("203/225 guardian handoff complete; producers preserved, no new replay admission");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn releases_only_old_growth_and_keeps_own_peak_and_older225_claim() {
        let a = json!({"unit":c::UNIT,"invocation_id":IID203,"minimum_free_bytes":3284969447424u64,"worker_root":c::ROOT,"maximum_worker_vmas":3500000});
        let b = json!({"unit":UNIT225,"invocation_id":IID225,"minimum_free_bytes":1347800810387u64,"worker_root":ROOT225,"maximum_worker_vmas":3500000});
        let (x, y) = budgets(248289182611, &a, &b).unwrap();
        assert_eq!(y, 317008659347);
        assert_eq!(x, 1004203426707);
        assert_eq!(x - y, REMAINING225);
        let mut bad = b.clone();
        bad["invocation_id"] = json!("other");
        assert!(budgets(248289182611, &a, &bad).is_err());
        assert!(budgets(u64::MAX, &a, &b).is_err());
    }
    #[test]
    fn terminal_owner_cannot_be_a_live_or_failed_attempt() {
        let mut v = json!({"ActiveState":"inactive","SubState":"dead","MainPID":"0","NRestarts":"0","Result":"success"});
        inactive(&v).unwrap();
        v["MainPID"] = json!("123");
        assert!(inactive(&v).is_err());
        v["MainPID"] = json!("0");
        v["Result"] = json!("exit-code");
        assert!(inactive(&v).is_err());
        assert!(terminal_evidence(&json!({}), &json!({}), &json!({})).is_err());
    }
    #[test]
    fn capability_is_not_protective_guard_or_replay_authority() {
        let mut v = json!({"schema":"jetstreamer-horizon-root-budget-capability-v1","passed":true,
            "producer_signaled":false,"protective_guard_proven":false,"stop_authorized":false,
            "sample":{"producer_stop_enabled":false,"guard_sha256":NEW_GUARD_SHA,"producer_invocation_id":IID203,
            "producer":{"pid":3634151,"active":"active","restarts":0},"maximum_root_physical_bytes":c::PEAK,
            "root_physical_observation":{"maximum_physical_bytes":c::PEAK,"exceeds_budget":false},
            "root_physical_observation_error":null,"trip_reason":null,"workers":[],"recorded_unix_seconds":1000}});
        capability(&v, 1001).unwrap();
        assert!(capability(&v, 4601).is_err());
        v["protective_guard_proven"] = json!(true);
        assert!(capability(&v, 1001).is_err());
    }
    #[test]
    fn actual203_fire_must_be_protective_and_keep_every_own_tree_gate() {
        let sha = "a".repeat(64);
        let p = json!({"unit":c::UNIT,"invocation_id":IID203,"minimum_free_bytes":1004203426707u64,
            "worker_root":c::ROOT,"receipt_directory":RECEIPTS203,"maximum_worker_vmas":3500000,
            "maximum_root_physical_bytes":c::PEAK});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_sha256":NEW_GUARD_SHA,
            "producer_invocation_id":IID203,"producer":{"invocation_id":IID203,"pid":3634151,
            "active":"active","sub":"running","load_state":"loaded","restarts":0,"restart_policy":"no","kill_mode":"control-group",
            "delegated":false,"result":"success"},"plan":format!("{DEST}/guard-203.json"),"plan_sha256":sha,
            "minimum_free_bytes":1004203426707u64,"maximum_worker_vmas":3500000,"trip_reason":null,
            "worker_observation_error":null,"bounded_measurement":false,"bounded_canary":null,
            "canary_target_error":null,"r2_mutations":false,"remote_mutations":false,"available_bytes":3500000000000u64,
            "recorded_unix_seconds":1000,"workers":[],"producer_stop_enabled":true,"maximum_root_physical_bytes":c::PEAK,
            "root_physical_observation":{"maximum_physical_bytes":c::PEAK,"exceeds_budget":false,"conservative_physical_bytes":1024},
            "root_physical_observation_error":null});
        new_guard_shape(&g, 203, &sha, 999, 1001, 1004203426707, &p).unwrap();
        for (key, bad) in [
            ("producer_stop_enabled", json!(false)),
            ("maximum_root_physical_bytes", json!(1)),
            ("trip_reason", json!("reserve")),
            ("workers", json!([[1, 1]])),
            ("root_physical_observation_error", json!("unreadable")),
        ] {
            let mut wrong = g.clone();
            wrong[key] = bad;
            assert!(
                new_guard_shape(&wrong, 203, &sha, 999, 1001, 1004203426707, &p).is_err(),
                "{key}"
            );
        }
        assert!(new_guard_shape(&g, 203, &sha, 1002, 1003, 1004203426707, &p).is_err());
        assert!(new_guard_shape(&g, 203, &sha, 999, 1200, 1004203426707, &p).is_err());
    }
    #[test]
    fn single_fire_or_extra_timer_triggers_are_not_continuous_protection() {
        let good =
            "{ OnActiveUSec=2s ; next_elapse=1s }\n{ OnUnitActiveUSec=1min ; next_elapse=2min }\n";
        recurrence_shape(good, "").unwrap();
        assert!(recurrence_shape("{ OnActiveUSec=2s ; next_elapse=1s }\n", "").is_err());
        assert!(recurrence_shape(good, "calendar").is_err());
        assert!(recurrence_shape(&good.replace("1min", "30min"), "").is_err());
    }
}
