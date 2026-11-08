//! Attended held-owner enrollment only. Worker release is a separate exact gate.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentSpec {
    schema: String,
    input_policy: Bound,
    admission: Bound,
    guard_plan: Bound,
    parent_service: Bound,
    guard_service: Bound,
    fallback_service: Bound,
    timer_source: Bound,
    first_guard: Bound,
    fleet_handoff: Bound,
    output: PathBuf,
}
pub(super) fn native(name: &str) -> Result<Value> {
    ensure!(
        [PARENT128, GUARD128, STOP128, TIMER128].contains(&name),
        "bounded enrollment native scope"
    );
    let out=ProcessCommand::new("/usr/bin/timeout").args(["--signal=TERM","--kill-after=2s","8s","/usr/bin/systemctl","--system","show",name,"--no-pager","--property=Id,InvocationID,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,MemoryAccounting,Group,TimersMonotonic,NextElapseUSecMonotonic,LastTriggerUSecMonotonic,TimeoutStartUSec,ProtectSystem,ProtectHome,PrivateNetwork,KillMode,Delegate,CapabilityBoundingSet,AmbientCapabilities,NRestarts,Restart,Job,Type,User,NoNewPrivileges,ExecStart,FragmentPath,DropInPaths,Unit,OnFailure,Result,ExecMainStatus"])
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("SYSTEMD_HOST").output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 65536,
        "bounded enrollment native query"
    );
    parse_native_fields(std::str::from_utf8(&out.stdout)?)
}
fn parse_native_fields(raw:&str)->Result<Value> {
    let mut m=serde_json::Map::new();
    let mut timers=Vec::new();
    for line in raw.lines() {
        let (key,value)=line.split_once('=').context("native framing")?;
        if key=="TimersMonotonic" {
            timers.push(value.to_owned());
        } else {
            ensure!(m.insert(key.into(),json!(value)).is_none(),"duplicate bounded native field");
        }
    }
    if !timers.is_empty() {
        ensure!(timers.len()<=2 && (timers.len()==1 || timers.iter().all(|v|v.starts_with("{ ") && v.ends_with(" }"))),"malformed bounded timer field multiplicity");
        m.insert("TimersMonotonic".into(),json!(timers.join("\n")));
    }
    Ok(Value::Object(m))
}
pub(super) fn source(n: &Value, b: &Bound) -> Result<()> {
    let raw = storage::bytes(b, 1 << 20, true)?;
    let path = n["FragmentPath"]
        .as_str()
        .context("loaded native fragment")?;
    ensure!(
        n["DropInPaths"] == ""
            && Path::new(path).canonicalize()? == b.path
            && fs::read(path)? == raw,
        "bounded loaded source differs from immutable member"
    );
    prepared_source(
        std::str::from_utf8(&raw)?,
        n["Id"].as_str().context("bounded source unit")?,
    )?;
    Ok(())
}
pub(super) fn command(n: &Value, expected: &[String]) -> Result<()> {
    let actual = n["ExecStart"]
        .as_str()
        .context("bounded native command")?
        .split_once(" ; ignore_errors=")
        .context("bounded native argv framing")?
        .0;
    ensure!(
        actual == format!("{{ path={} ; argv[]={}", expected[0], expected.join(" ")),
        "bounded command differs"
    );
    Ok(())
}
pub(super) fn parent_argv() -> Vec<String> {
    let r = "/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/work";
    vec![NODE_IMAGE.into(),"163".into(),format!("{r}/ledger"),"--verify".into(),"--qualification-end-slot=70416000".into(),"--snapshot-archive=/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/inputs/snapshot-70415741-2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY.tar.zst".into(),"--epoch-hashes=/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/inputs/checkpoint-names.txt".into(),format!("--horizon-output={r}/output/first-output.jet"),format!("--replay-scratch={r}/scratch")]
}
pub(super) fn parent(n: &Value) -> Result<(String, u64, u64)> {
    ensure!(
        n["Id"] == PARENT128
            && n["LoadState"] == "loaded"
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["MemoryAccounting"] == "yes"
            && n["Group"] == "horizon"
            && n["MemoryMax"].as_str() == Some(HARD128.to_string().as_str())
            && n["MemorySwapMax"] == "0"
            && n["RuntimeMaxUSec"] == "1h"
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["Job"] == ""
            && n["ControlPID"] == "0"
            && n["ControlGroup"] == format!("/system.slice/{PARENT128}")
            && n["CPUQuotaPerSecUSec"] == "8s"
            && n["TasksMax"] == "1024"
            && n["User"] == "sol"
            && n["Type"] == "exec",
        "bounded parent native profile"
    );
    command(n, &parent_argv())?;
    let iid = n["InvocationID"]
        .as_str()
        .context("bounded IID")?
        .to_owned();
    ensure!(storage::hex(&iid, 32), "bounded IID shape");
    let pid = n["MainPID"]
        .as_str()
        .context("bounded PID")?
        .parse::<u64>()?;
    ensure!(pid > 1, "bounded PID absent");
    artifact(NODE_IMAGE, NODE_SHA)?;
    let proc = fs::metadata(format!("/proc/{pid}/exe"))?;
    let image = fs::metadata(NODE_IMAGE)?;
    ensure!(
        (proc.dev(), proc.ino()) == (image.dev(), image.ino()),
        "bounded parent mapped image"
    );
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    let expected = parent_argv().join("\0") + "\0";
    ensure!(raw == expected.as_bytes(), "bounded mapped argv");
    let ticks = process_ticks(pid)?;
    Ok((iid, pid, ticks))
}
pub(super) fn process_ticks(pid: u64) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(stat
        .rsplit_once(") ")
        .context("bounded stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("bounded start ticks")?
        .parse::<u64>()?)
}
fn original_guard(g: &Value, iid: &str, plan: &Bound) -> Result<()> {
    let n = &g["original_native"];
    let j = &g["original_PID1_success_event"];
    ensure!(
        g["schema"] == "epoch163-first-output128-original-first-guard-v1"
            && g["parent_invocation_id"] == iid
            && g["plan"] == json!(plan)
            && g["program"] == json!({"path":BOUNDED_GUARD_IMAGE,"sha256":BOUNDED_GUARD_SHA})
            && g["original_PID1_success"] == true
            && g["original_outer_reaped"] == true
            && g["original_cgroup_empty"] == true
            && g["original_descriptors_drained"] == true
            && n["Id"] == GUARD128
            && n["MainPID"] == "0"
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Result"] == "success"
            && n["ExecMainStatus"] == "0"
            && n["Job"] == ""
            && j["_PID"] == "1"
            && j["_UID"] == "0"
            && j["UNIT"] == GUARD128
            && j["INVOCATION_ID"] == n["InvocationID"]
            && storage::hex(n["InvocationID"].as_str().unwrap_or(""), 32)
            && j["MESSAGE"] == format!("{GUARD128}: Deactivated successfully.")
            && j["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448",
        "bounded original first guard incomplete/crossed"
    );
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let (sb, image) = actor128("enroll-first163128", ENROLL128)?;
    let s: EnrollmentSpec = serde_json::from_value(immutable(&sb)?)?;
    ensure!(
        s.schema == "epoch163-first-output128-enrollment-spec-v1"
            && s.output
                == Path::new(
                    "/var/lib/jetstreamer/horizon-epoch163-first-output128-enrollment-20261106-v1/enrollment.json"
                ),
        "bounded enrollment scope/output"
    );
    let a = immutable(&s.admission)?;
    ensure!(
        a["schema"] == "epoch163-first-output128-full-admission-v1"
            && a["input_policy"] == json!(s.input_policy)
            && a["admitted"] == true
            && now()? <= n(&a, "expires_unix_seconds")?
            && a["parent_program"] == json!({"path":NODE_IMAGE,"sha256":NODE_SHA}),
        "bounded original admission expired or crossed"
    );
    let policy = immutable(&s.input_policy)?;
    scope128(&policy)?;
    let before = native(PARENT128)?;
    let (iid, pid, ticks) = parent(&before)?;
    source(&before, &s.parent_service)?;
    let gp = immutable(&s.guard_plan)?;
    ensure!(
        gp["schema"] == "epoch163-first-output128-memory-DATA-reserve-vma-guard-plan-v1"
            && gp["parent_unit"] == PARENT128
            && gp["parent_invocation_id"] == iid
            && gp["parent_start_ticks"] == ticks
            && gp["input_policy"] == json!(s.input_policy)
            && gp["admission"] == json!(s.admission)
            && gp["selected_memory_receipt"] == a["memory_receipt"]
            && gp["selected_data_receipt"] == a["data_receipt"]
            && gp["minimum_free_bytes"] == a["minimum_free_bytes"],
        "bounded actual guard plan crossed"
    );
    let fire = immutable(&s.first_guard)?;
    original_guard(&fire, &iid, &s.guard_plan)?;
    let guard = native(GUARD128)?;
    let fallback = native(STOP128)?;
    auxiliary(&guard, GUARD128, &s.guard_service, &s.guard_plan, true)?;
    auxiliary(&fallback, STOP128, &s.fallback_service, &s.guard_plan, true)?;
    ensure!(
        guard["InvocationID"] == fire["original_native"]["InvocationID"],
        "bounded original first-guard invocation changed"
    );
    let timer = native(TIMER128)?;
    timer_profile(&timer, &s.timer_source, false)?;
    current_guard(
        &guard,
        &json!({"parent_invocation_id":iid,"admission_value":a}),
    )?;
    let mut admission_bound = a.clone();
    admission_bound["original_admission_binding"] = json!(s.admission);
    let handoff = immutable(&s.fleet_handoff)?;
    let actual_handoff =
        integration::observer_handoff(&handoff, &admission_bound, &s.input_policy, &iid)?;
    let after = native(PARENT128)?;
    ensure!(
        before == after && parent(&after)? == (iid.clone(), pid, ticks),
        "bounded actual parent changed during enrollment"
    );
    ensure!(
        now()? <= n(&a, "expires_unix_seconds")?,
        "bounded original enrollment clock expired"
    );
    save(
        &s.output,
        &json!({"schema":"epoch163-first-output128-fleet-enrollment-v1","spec":sb,"self":image,"input_policy":s.input_policy,
        "admission":s.admission,"admission_value":a,"parent_unit":PARENT128,"parent_invocation_id":iid,"parent_pid":pid,"parent_start_ticks":ticks,
        "parent_before":before,"parent_after":after,"parent_service":s.parent_service,"first_guard":s.first_guard,"guard_plan":s.guard_plan,
        "guard_service":s.guard_service,"fallback_service":s.fallback_service,"timer_source":s.timer_source,"fleet_handoff":s.fleet_handoff,"actual_observer_handoff":actual_handoff,
        "complete_current_claim_census":true,"common_observer_and_fleet_handoff_qualified":true,
        "parent_hard_bytes":HARD128,"guard_bytes":2u64<<30,"fallback_bytes":512u64<<20,"candidate_DATA_bytes":768u64<<30,
        "recorded_unix_seconds":now()?,"timer_activation_and_exact_release_still_required":true,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let enrollment = immutable(&Bound {
        path: s.output.clone(),
        sha256: storage::sha(&fs::read(&s.output)?),
    })?;
    let first_guard_capsule = capsule("first-guard-capsule.json", &json!({
        "schema":"epoch163-first-output128-original-first-guard-v1", "original_first_guard":s.first_guard,
        "parent_invocation_id":iid,"program":{"path":BOUNDED_GUARD_IMAGE,"sha256":BOUNDED_GUARD_SHA},
        "original_PID1_success":true,"original_outer_reaped":true,"original_cgroup_empty":true,"original_descriptors_drained":true}))?;
    let compact = json!({"schema":enrollment["schema"],"parent_unit":PARENT128,"parent_invocation_id":iid,
        "parent_pid":pid,"parent_start_ticks":ticks,"admission":s.admission,"input_policy":s.input_policy,
        "first_guard":first_guard_capsule,"timer_source":s.timer_source,"complete_current_claim_census":true,
        "common_observer_and_fleet_handoff_qualified":true,"publication_authorized":false,"r2_mutations":false});
    capsule("enrollment-capsule.json", &compact)?;
    Ok(())
}

/// Feed this explicit registration into the complete raw builder. Termination
/// alone releases neither hard memory nor DATA; a separate original-completion
/// disposition must be qualified before the caller removes the retained row.
pub(in crate::fleet) fn allocation(plan: &Value) -> Result<Vec<Value>> {
    let Some(b) = integration::declared(plan)? else {
        return Ok(vec![]);
    };
    let e = immutable(&b)?;
    ensure!(
        e["schema"] == "epoch163-first-output128-fleet-enrollment-v1"
            && e["parent_unit"] == PARENT128,
        "bounded registration shape"
    );
    let a = immutable(&to_bound(&e["admission"])?)?;
    ensure!(
        e["admission_value"] == a
            && e["self"] == a["self"]
            && e["input_policy"] == a["input_policy"]
            && e["publication_authorized"] == false
            && e["r2_mutations"] == false
            && e["complete_current_claim_census"] == true
            && e["common_observer_and_fleet_handoff_qualified"] == true,
        "bounded retained enrollment/issuer/admission lineage crossed"
    );
    let first = immutable(&to_bound(&e["first_guard"])?)?;
    original_guard(
        &first,
        e["parent_invocation_id"]
            .as_str()
            .context("bounded retained IID")?,
        &to_bound(&e["guard_plan"])?,
    )?;
    let node = native(PARENT128)?;
    source(&node, &to_bound(&e["parent_service"])?)?;
    let active = matches!(node["ActiveState"].as_str(), Some("active" | "activating"));
    if active {
        let (iid, pid, ticks) = parent(&node)?;
        ensure!(
            iid == e["parent_invocation_id"]
                && pid == n(&e, "parent_pid")?
                && ticks == n(&e, "parent_start_ticks")?,
            "bounded enrolled owner replaced"
        );
    } else {
        terminal_parent(&node, &e)?;
    }
    ensure!(
        a["parent_hard_bytes"] == HARD128
            && a["guard_bytes"] == 2u64 << 30
            && a["fallback_bytes"] == 512u64 << 20,
        "bounded original hard obligations changed"
    );
    let auxiliary_nodes = retained_protection(&e, &node, active)?;
    let mut rows = vec![
        json!({"unit":PARENT128,"invocation_id":e["parent_invocation_id"],"state":if active{"private-first-output128"}else{"terminal-retained-private-first-output128"},
        "memory_max_bytes":HARD128+AUX128,"parent_hard_limit_bytes":HARD128,"guard_memory_bytes":2u64<<30,"fallback_memory_bytes":512u64<<20,
        "data_reservation_bytes":768u64<<30,"native_pool_suballocation":false,"ordinary_replay_claim":false,
        "first163128_registration":b,"guard_floor_bytes":a["minimum_free_bytes"],"memory_credit_bytes":0,"DATA_credit_bytes":0,
        "terminal_outcome_is_not_release_authority":true}),
    ];
    for (unit, hard) in [(GUARD128, 2u64 << 30), (STOP128, 512u64 << 20)] {
        let native = &auxiliary_nodes[unit];
        rows.push(json!({"unit":unit,"invocation_id":native["InvocationID"],"memory_max_bytes":0,"data_reservation_bytes":0,
            "actual_memory_hard_limit_bytes":hard,"included_once_in_first128_parent_claim":true,"native_pool_suballocation":false,
            "first163128_registration":b}));
    }
    // Every authenticated peer consumed by the complete raw builder has an
    // explicit source table. These are original bound metadata, not input bodies.
    let sources = [json!(b), e["admission"].clone(), e["first_guard"].clone(),
        e["guard_plan"].clone(), e["parent_service"].clone(), e["guard_service"].clone(),
        e["fallback_service"].clone(), e["timer_source"].clone()];
    for row in &mut rows { row["source_bindings"]=json!(sources); }
    Ok(rows)
}
/// A terminal row stays charged and cannot silently hide a replacement.
pub(super) fn terminal_parent(node: &Value, e: &Value) -> Result<()> {
    integration::raw_profile(node)?;
    ensure!(
        matches!(node["ActiveState"].as_str(), Some("inactive" | "failed"))
            && matches!(node["SubState"].as_str(), Some("dead" | "failed"))
            && node["MainPID"] == "0"
            && node["ControlPID"] == "0"
            && node["Job"] == ""
            && node["NRestarts"] == "0"
            && node["InvocationID"] == e["parent_invocation_id"],
        "bounded terminal identity uncertain/replaced"
    );
    Ok(())
}
fn auxiliary(
    node: &Value,
    unit: &str,
    member: &Bound,
    plan: &Bound,
    success_required: bool,
) -> Result<()> {
    source(node, member)?;
    artifact(BOUNDED_GUARD_IMAGE, BOUNDED_GUARD_SHA)?;
    let expected_caps=if unit==GUARD128 {"cap_dac_override cap_sys_ptrace"} else {"cap_dac_override"};
    let (cap, mode) = if unit == GUARD128 {
        ("2147483648", "check")
    } else {
        ("536870912", "stop")
    };
    ensure!(
        node["Id"] == unit
            && node["LoadState"] == "loaded"
            && node["Type"] == "oneshot"
            && node["User"] == "root"
            && node["Group"] == "root"
            && node["MemoryAccounting"] == "yes"
            && node["MemoryMax"] == cap
            && node["MemorySwapMax"] == "0"
            && node["Restart"] == "no"
            && node["NRestarts"] == "0"
            && node["CPUQuotaPerSecUSec"] == "1s"
            && node["TasksMax"] == "256"
            && node["NoNewPrivileges"] == "yes"
            && node["ProtectSystem"] == "strict"
            && node["ProtectHome"] == "read-only"
            && node["PrivateNetwork"] == "yes"
            && node["KillMode"] == "control-group"
            && node["Delegate"] == "no"
            && node["CapabilityBoundingSet"] == expected_caps
            && node["AmbientCapabilities"] == expected_caps
            && node["TimeoutStartUSec"] == "1min 30s"
            && node["MainPID"] == "0"
            && node["ControlPID"] == "0"
            && node["Job"] == ""
            && ((node["ActiveState"] == "inactive" && node["SubState"] == "dead")
                || (!success_required
                    && node["ActiveState"] == "failed"
                    && node["SubState"] == "failed"))
            && (!success_required
                || (node["Result"] == "success" && node["ExecMainStatus"] == "0"))
            && (unit != GUARD128 || node["OnFailure"] == STOP128),
        "bounded auxiliary profile or success changed"
    );
    command(
        node,
        &[
            BOUNDED_GUARD_IMAGE.into(),
            mode.into(),
            plan.path.display().to_string(),
            "--plan-sha256".into(),
            plan.sha256.clone(),
            "--self-sha256".into(),
            BOUNDED_GUARD_SHA.into(),
        ],
    )
}
pub(super) fn timer_profile(timer: &Value, member: &Bound, armed: bool) -> Result<()> {
    source(timer, member)?;
    ensure!(
        timer["Id"] == TIMER128
            && timer["LoadState"] == "loaded"
            && timer["Unit"] == GUARD128
            && timer["Job"] == ""
            && timer["ActiveState"] == if armed { "active" } else { "inactive" }
            && timer["SubState"] == if armed { "waiting" } else { "dead" },
        "bounded timer state/source changed"
    );
    if armed {
        ensure!(
            storage::hex(timer["InvocationID"].as_str().unwrap_or(""), 32),
            "bounded timer IID absent"
        );
        let lines = timer["TimersMonotonic"]
            .as_str()
            .context("bounded timer schedule")?
            .lines()
            .collect::<Vec<_>>();
        ensure!(
            lines.len() == 2
                && lines
                    .iter()
                    .filter(|l| l.starts_with("{ OnActiveUSec=1s ; next_elapse="))
                    .count()
                    == 1
                && lines
                    .iter()
                    .filter(|l| l.starts_with("{ OnUnitInactiveUSec=30s ; next_elapse="))
                    .count()
                    == 1,
            "bounded timer recurring schedule changed"
        );
        let deadline = systemd_micros(
            timer["NextElapseUSecMonotonic"]
                .as_str()
                .context("bounded timer deadline")?,
        )?;
        let clock = monotonic_micros()?;
        ensure!(
            deadline
                .checked_sub(clock)
                .is_some_and(|delta| delta <= 32_000_000),
            "bounded guard next deadline absent, overdue or too far away"
        );
    }
    Ok(())
}
fn systemd_micros(raw: &str) -> Result<u64> {
    let mut total = 0u64;
    let mut count = 0;
    for token in raw.split_whitespace() {
        let split = token
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .context("bounded timespan unit absent")?;
        let (number, unit) = token.split_at(split);
        let scale = match unit {
            "w" => 604_800_000_000u64,
            "d" => 86_400_000_000,
            "h" => 3_600_000_000,
            "min" => 60_000_000,
            "s" => 1_000_000,
            "ms" => 1000,
            "us" => 1,
            _ => anyhow::bail!("bounded timespan unit"),
        };
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        ensure!(
            !whole.is_empty()
                && fraction.len() <= 6
                && fraction.bytes().all(|c| c.is_ascii_digit()),
            "bounded timespan fraction"
        );
        let part = whole
            .parse::<u64>()?
            .checked_mul(scale)
            .context("bounded timespan overflow")?;
        let frac = if fraction.is_empty() {
            0
        } else {
            fraction
                .parse::<u64>()?
                .checked_mul(scale)
                .context("bounded fraction overflow")?
                / 10u64.pow(fraction.len() as u32)
        };
        total = total
            .checked_add(part)
            .and_then(|v| v.checked_add(frac))
            .context("bounded timespan total overflow")?;
        count += 1;
    }
    ensure!(count > 0, "bounded empty timespan");
    Ok(total)
}
fn prepared_source(raw: &str, unit: &str) -> Result<()> {
    let fixture = match unit {
        PARENT128 => include_str!("fixtures/parent-prepared.service"),
        GUARD128 => include_str!("fixtures/guard-prepared.service"),
        STOP128 => include_str!("fixtures/fallback-prepared.service"),
        TIMER128 => include_str!("fixtures/timer-prepared.timer"),
        _ => anyhow::bail!("bounded prepared source unit"),
    };
    let mut expected = fixture
        .lines()
        .filter(|l| !l.starts_with("ConditionPathExists="))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let actual = raw.lines().collect::<Vec<_>>();
    ensure!(
        actual.len() == expected.len(),
        "bounded prepared service line count changed"
    );
    for (a, b) in actual.iter().zip(expected.iter_mut()) {
        if let Some(value) = a.strip_prefix("Environment=JETSTREAMER_FIRST163128_PLAN=") {
            ensure!(
                unit == PARENT128
                    && b.starts_with("Environment=JETSTREAMER_FIRST163128_PLAN=")
                    && value.starts_with("/usr/local/lib/jetstreamer/")
                    && !value.contains(char::is_whitespace),
                "bounded runtime plan path"
            );
            *b = a.to_string();
        } else if let Some(value) =
            a.strip_prefix("Environment=JETSTREAMER_FIRST163128_PLAN_SHA256=")
        {
            ensure!(
                unit == PARENT128
                    && b.starts_with("Environment=JETSTREAMER_FIRST163128_PLAN_SHA256=")
                    && storage::hex(value, 64),
                "bounded runtime plan digest"
            );
            *b = a.to_string();
        } else if a.starts_with("ExecStart=") && [GUARD128, STOP128].contains(&unit) {
            // Exact immutable guard plan/image argv are independently checked by auxiliary().
            ensure!(
                b.starts_with("ExecStart=") && !a.contains("UNRESOLVED"),
                "bounded guard service unresolved"
            );
            *b = a.to_string();
        }
    }
    ensure!(
        actual
            .iter()
            .copied()
            .eq(expected.iter().map(String::as_str)),
        "bounded finalized service differs from canonical isolated template"
    );
    Ok(())
}
fn monotonic_micros() -> Result<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } == 0
            && t.tv_sec >= 0
            && t.tv_nsec >= 0,
        "bounded monotonic clock"
    );
    (t.tv_sec as u64)
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(t.tv_nsec as u64 / 1000))
        .context("bounded monotonic overflow")
}
fn guard_event(row: &Value, g: &Value, e: &Value, clock: u64) -> Result<Option<Value>> {
    if row["_SYSTEMD_UNIT"] != GUARD128
        || row["_SYSTEMD_INVOCATION_ID"] != g["InvocationID"]
        || row["_UID"] != "0"
        || row["_EXE"] != BOUNDED_GUARD_IMAGE
    {
        return Ok(None);
    }
    let Ok(v) = serde_json::from_str::<Value>(row["MESSAGE"].as_str().unwrap_or("")) else {
        return Ok(None);
    };
    let at = row["__MONOTONIC_TIMESTAMP"]
        .as_str()
        .context("bounded guard original monotonic time")?
        .parse::<u64>()?;
    ensure!(
        clock.checked_sub(at).is_some_and(|age| age <= 45_000_000)
            && v["armed"] == true
            && v["memory_continuity_validated"] == true
            && v["parent_invocation_id"] == e["parent_invocation_id"]
            && n(&v, "available_bytes")? >= n(&e["admission_value"], "minimum_free_bytes")?,
        "bounded current guard result stale/crossed/unarmed"
    );
    Ok(Some(v))
}
fn current_guard(g: &Value, e: &Value) -> Result<()> {
    ensure!(
        storage::hex(g["InvocationID"].as_str().unwrap_or(""), 32),
        "bounded current guard IID"
    );
    let o = ProcessCommand::new("/usr/bin/timeout")
        .args([
            "--signal=TERM",
            "--kill-after=2s",
            "8s",
            "/usr/bin/journalctl",
            "--all",
            "--no-pager",
            "--output=json",
            "--lines=64",
            "-u",
            GUARD128,
        ])
        .output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() <= 2 << 20,
        "bounded current guard journal"
    );
    let mut payloads = 0;
    let mut pid1 = 0;
    let clock = monotonic_micros()?;
    for line in o.stdout.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
        let row: Value = serde_json::from_slice(line)?;
        payloads += usize::from(guard_event(&row, g, e, clock)?.is_some());
        if row["_PID"] == "1"
            && row["_UID"] == "0"
            && row["UNIT"] == GUARD128
            && row["INVOCATION_ID"] == g["InvocationID"]
            && row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && row["MESSAGE"] == format!("{GUARD128}: Deactivated successfully.")
        {
            pid1 += 1;
        }
    }
    ensure!(
        payloads == 1 && pid1 == 1,
        "bounded current genuine guard success missing/duplicated"
    );
    Ok(())
}
fn held_window(e: &Value, t: u64) -> Result<()> {
    ensure!(
        t.checked_sub(n(e, "recorded_unix_seconds")?)
            .is_some_and(|age| age <= 150)
            && t <= n(&e["admission_value"], "expires_unix_seconds")?,
        "bounded held pre-release window expired"
    );
    Ok(())
}
pub(super) fn held_owner(e: &Value, parent: &Value) -> Result<()> {
    held_window(e, now()?)?;
    let root =
        Path::new("/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/work");
    let release = root.join(format!(
        "release-{}.json",
        e["parent_invocation_id"]
            .as_str()
            .context("bounded held IID")?
    ));
    ensure!(
        !release.try_exists()?,
        "bounded released owner cannot borrow held protection"
    );
    for rel in ["scratch", "output"] {
        let path = root.join(rel);
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.is_dir()
                && m.uid() == 1001
                && m.mode() & 0o777 == 0o700
                && path.canonicalize()? == path
                && fs::read_dir(path)?.next().is_none(),
            "bounded held work already used or foreign"
        );
    }
    let cgroup = parent["ControlGroup"]
        .as_str()
        .context("bounded held cgroup")?;
    let procs = fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/cgroup.procs"))?;
    let pids = procs
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        pids == vec![n(e, "parent_pid")?],
        "bounded held owner already has worker/other child"
    );
    Ok(())
}
pub(super) fn retained_protection(e: &Value, parent: &Value, active: bool) -> Result<Value> {
    let guard = native(GUARD128)?;
    let fallback = native(STOP128)?;
    let timer = native(TIMER128)?;
    let plan = to_bound(&e["guard_plan"])?;
    auxiliary(
        &guard,
        GUARD128,
        &to_bound(&e["guard_service"])?,
        &plan,
        active,
    )?;
    auxiliary(
        &fallback,
        STOP128,
        &to_bound(&e["fallback_service"])?,
        &plan,
        active,
    )?;
    let armed = timer["ActiveState"] == "active";
    timer_profile(&timer, &to_bound(&e["timer_source"])?, armed)?;
    if active {
        current_guard(&guard, e)?;
        if !armed {
            held_owner(e, parent)?;
            let first = immutable(&to_bound(&e["first_guard"])?)?;
            ensure!(
                guard["InvocationID"] == first["original_native"]["InvocationID"],
                "bounded unarmed held guard changed"
            );
        }
    }
    ensure!(
        native(PARENT128)? == *parent
            && native(GUARD128)? == guard
            && native(STOP128)? == fallback
            && native(TIMER128)? == timer,
        "bounded retained parent/protection changed during validation"
    );
    let mut rows = serde_json::Map::new();
    rows.insert(GUARD128.into(), guard);
    rows.insert(STOP128.into(), fallback);
    rows.insert(TIMER128.into(), timer);
    Ok(Value::Object(rows))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_parent_template_keeps_horizon_group_and_every_isolation_line() {
        let original = include_str!("fixtures/parent-prepared.service");
        let finished = original
            .lines()
            .filter(|l| !l.starts_with("ConditionPathExists="))
            .collect::<Vec<_>>()
            .join("\n")
            .replace(
                "UNRESOLVED_NORMAL_RUNTIME_PLAN_PATH",
                "/usr/local/lib/jetstreamer/test/runtime-plan.json",
            )
            .replace("UNRESOLVED_ACTUAL_RUNTIME_PLAN_SHA256", &"a".repeat(64));
        prepared_source(&finished, PARENT128).unwrap();
        assert!(
            prepared_source(&finished.replace("Group=horizon", "Group=sol"), PARENT128).is_err()
        );
        assert!(
            prepared_source(
                &finished.replace("ProtectSystem=strict", "ProtectSystem=full"),
                PARENT128
            )
            .is_err()
        );
        assert!(
            prepared_source(
                &finished.replace("ReadWritePaths=", "ReadOnlyPaths="),
                PARENT128
            )
            .is_err()
        );
        assert!(prepared_source(&finished.replace("ProtectSystem=strict", "Environment=JETSTREAMER_FIRST163128_PLAN=/usr/local/lib/jetstreamer/test/other.json"), PARENT128).is_err());
        assert!(prepared_source(original, PARENT128).is_err());
        assert!(finished.contains(&format!("ExecStart={}", parent_argv().join(" "))));
    }
    #[test]
    fn current_guard_receipt_rejects_stale_crossed_unarmed_and_low_floor() {
        let iid = "a".repeat(32);
        let giid = "b".repeat(32);
        let g = json!({"InvocationID":giid});
        let e = json!({"parent_invocation_id":iid,"admission_value":{"minimum_free_bytes":100}});
        let payload = json!({"armed":true,"memory_continuity_validated":true,"parent_invocation_id":iid,"available_bytes":100});
        let row = json!({"_SYSTEMD_UNIT":GUARD128,"_SYSTEMD_INVOCATION_ID":giid,"_UID":"0","_EXE":BOUNDED_GUARD_IMAGE,
            "__MONOTONIC_TIMESTAMP":"1000000","MESSAGE":payload.to_string()});
        assert!(guard_event(&row, &g, &e, 2_000_000).unwrap().is_some());
        assert!(guard_event(&row, &g, &e, 46_000_001).is_err());
        assert!(guard_event(&row, &g, &e, 999_999).is_err());
        for (key, value) in [
            ("armed", json!(false)),
            ("memory_continuity_validated", json!(false)),
            ("parent_invocation_id", json!("c".repeat(32))),
            ("available_bytes", json!(99)),
        ] {
            let mut p = payload.clone();
            p[key] = value;
            let mut r = row.clone();
            r["MESSAGE"] = json!(p.to_string());
            assert!(guard_event(&r, &g, &e, 2_000_000).is_err());
        }
        let mut r = row;
        r["_EXE"] = json!("/other/guard");
        assert!(guard_event(&r, &g, &e, 2_000_000).unwrap().is_none());
    }
    #[test]
    fn systemd_deadlines_are_exact_finite_microseconds() {
        assert_eq!(
            systemd_micros("1w 2d 3h 4min 5.123456s").unwrap(),
            788_645_123_456
        );
        for invalid in [
            "",
            "infinity",
            "1s garbage",
            "NaNs",
            "1.0000001s",
            "18446744073709551615w",
        ] {
            assert!(systemd_micros(invalid).is_err(), "{invalid}");
        }
    }
    #[test]
    fn held_route_requires_its_own_live_window_and_admission_expiry() {
        let e = json!({"recorded_unix_seconds":100,"admission_value":{"expires_unix_seconds":240}});
        held_window(&e, 100).unwrap();
        held_window(&e, 240).unwrap();
        assert!(held_window(&e, 99).is_err());
        assert!(held_window(&e, 241).is_err());
        let mut old = e.clone();
        old["admission_value"]["expires_unix_seconds"] = json!(300);
        assert!(held_window(&old, 251).is_err());
        old["recorded_unix_seconds"] = json!("100");
        assert!(held_window(&old, 110).is_err());
    }
    #[test]
    fn first_guard_requires_original_pid1_scope_and_every_drain() {
        let p = Bound {
            path: "/test/guard-plan".into(),
            sha256: "a".repeat(64),
        };
        let iid = "b".repeat(32);
        let giid = "c".repeat(32);
        let g = json!({"schema":"epoch163-first-output128-original-first-guard-v1","parent_invocation_id":iid,"plan":p,
            "program":{"path":BOUNDED_GUARD_IMAGE,"sha256":BOUNDED_GUARD_SHA},"original_PID1_success":true,"original_outer_reaped":true,
            "original_cgroup_empty":true,"original_descriptors_drained":true,
            "original_native":{"Id":GUARD128,"InvocationID":giid,"MainPID":"0","ControlPID":"0","NRestarts":"0","Result":"success","ExecMainStatus":"0","Job":""},
            "original_PID1_success_event":{"_PID":"1","_UID":"0","UNIT":GUARD128,"INVOCATION_ID":giid,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{GUARD128}: Deactivated successfully.")}});
        original_guard(&g, &iid, &p).unwrap();
        for path in [
            "/original_outer_reaped",
            "/original_cgroup_empty",
            "/original_descriptors_drained",
        ] {
            let mut x = g.clone();
            *x.pointer_mut(path).unwrap() = json!(false);
            assert!(original_guard(&x, &iid, &p).is_err());
        }
        let mut x = g;
        x["original_PID1_success_event"]["_PID"] = json!("2");
        assert!(original_guard(&x, &iid, &p).is_err());
    }
}

#[cfg(test)]
mod native_timer_fields_tests {
    use super::*;
    #[test]
    fn repeated_timer_entries_preserve_each_event_while_scalar_duplicates_reject() {
        let raw="Id=example.timer\nTimersMonotonic={ OnUnitInactiveUSec=30s ; next_elapse=31s }\nTimersMonotonic={ OnActiveUSec=1s ; next_elapse=1s }\nUnit=example.service\n";
        let v=parse_native_fields(raw).unwrap();
        assert_eq!(v["Id"],"example.timer");
        assert_eq!(v["TimersMonotonic"].as_str().unwrap().lines().count(),2);
        assert!(parse_native_fields("Id=a\nId=b\n").is_err());
        assert!(parse_native_fields("TimersMonotonic=\nTimersMonotonic=\n").is_err());
        assert!(parse_native_fields(&(raw.to_owned()+"TimersMonotonic={ OnActiveUSec=2s ; next_elapse=2s }\n")).is_err());
    }
    #[test]
    #[ignore = "Root-only actual existing timer formatter check; no first128 timer mutation or launch"]
    fn actual_existing_timer_native_formatter_preserves_repeated_entries_and_exact_original_identity()->Result<()> {
        let out=ProcessCommand::new("/usr/bin/systemctl").args(["show","jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.timer","--no-pager","--property=Id,InvocationID,TimersMonotonic,Unit"])
            .env("LC_ALL","C").env_remove("SYSTEMD_HOST").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").output()?;
        ensure!(out.status.success() && out.stderr.is_empty() && out.stdout.len()<65536,"actual existing timer metadata command");
        let raw=std::str::from_utf8(&out.stdout)?;
        ensure!(raw.lines().filter(|line|line.starts_with("TimersMonotonic=")).count()==2,"actual host formatter must expose two repeated properties");
        let v=parse_native_fields(raw)?;
        ensure!(v["Id"]=="jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.timer" && v["InvocationID"]=="97aeff8897434ed5ad89dd56c3fb17d1" && v["Unit"]=="jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.service","actual original timer identity crossed");
        let rows=v["TimersMonotonic"].as_str().context("actual timer rows")?.lines().collect::<Vec<_>>();
        ensure!(rows.len()==2 && rows.iter().filter(|x|x.starts_with("{ OnActiveUSec=1s ; next_elapse=")).count()==1 && rows.iter().filter(|x|x.starts_with("{ OnUnitActiveUSec=30s ; next_elapse=")).count()==1,"actual host timer events dropped or changed");
        Ok(())
    }
}
