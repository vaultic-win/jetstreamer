//! Typed real native enrollment. No service control or observation cadence.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    admission: Bound,
    guard_plan: Bound,
    guard_service: Bound,
    fallback_service: Bound,
    timer_source: Bound,
    output: PathBuf,
}
fn string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    ensure!(
        pointer.starts_with('/') && pointer.len() > 1,
        "direct163 string field requires a non-root JSON pointer"
    );
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .with_context(|| format!("direct163 missing or non-string field at {pointer}"))
}
const NATIVE_FIELDS: &str = "--property=Id,LoadState,InvocationID,MainPID,ControlPID,NRestarts,Restart,ActiveState,SubState,Result,ExecMainStatus,ControlGroup,MemoryAccounting,MemoryMax,MemoryHigh,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,User,Group,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ProtectSystem,ProtectHome,PrivateNetwork,KillMode,Delegate,Job,Type,RemainAfterExit,TimeoutStartUSec,ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,FragmentPath,DropInPaths,OnFailure,Unit,Triggers,TriggeredBy,TimersMonotonic";
fn native(name: &str) -> Result<Value> {
    ensure!(
        [UNIT, GUARD, STOP, TIMER].contains(&name),
        "direct163 foreign native target"
    );
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args(["show", name, "--no-pager", NATIVE_FIELDS])
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env_remove("SYSTEMD_HOST")
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "direct163 native query failed"
    );
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("direct163 native framing")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "direct163 duplicate native property"
        );
    }
    Ok(Value::Object(m))
}
fn args(n: &Value) -> Result<String> {
    let raw = string(n, "/ExecStart")?;
    let (id, _) = raw
        .split_once(" ; ignore_errors=")
        .context("direct163 command identity")?;
    Ok(id.to_owned())
}
fn expected(program: &str, argv: &[String]) -> String {
    format!("{{ path={program} ; argv[]={}", argv.join(" "))
}
fn parent_args() -> Vec<String> {
    vec![format!("{PACKAGE}/jetstreamer-node"),"163-163".into(),format!("{ROOT}/archives"),"--verify".into(),"--root-checkpoint-cohort".into(),format!("--cohort-manifest={PACKAGE}/preflight-163-singleton-v4.json"),"--cohort-manifest-fingerprint=sha256:b36df9a809a2415d529baf2992b913ea535ed982434026e5ed515b5348d08344".into()]
}
fn ticks(pid: u64) -> Result<u64> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    raw.rsplit_once(')')
        .context("direct163 process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("direct163 start ticks")?
        .parse::<u64>()
        .map_err(Into::into)
}
fn mapped(pid: u64, program: &str, digest: &str, argv: &[String]) -> Result<()> {
    artifact(program, digest)?;
    let actual = fs::File::open(format!("/proc/{pid}/exe"))?.metadata()?;
    let source = fs::metadata(program)?;
    ensure!(
        (actual.dev(), actual.ino()) == (source.dev(), source.ino()),
        "direct163 mapped image changed"
    );
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(
        raw.len() <= 1 << 20 && raw.last() == Some(&0),
        "direct163 cmdline framing"
    );
    let values = raw[..raw.len() - 1]
        .split(|b| *b == 0)
        .map(|v| Ok(std::str::from_utf8(v)?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(values == argv, "direct163 actual argv changed");
    Ok(())
}
pub(in crate::fleet) fn raw_profile(n: &Value) -> Result<()> {
    ensure!(
        n["Id"] == UNIT
            && n["LoadState"] == "loaded"
            && n["Type"] == "exec"
            && n["User"] == "sol"
            && n["MemoryAccounting"] == "yes"
            && n["MemoryMax"] == "206158430208"
            && n["MemorySwapMax"] == "0"
            && n["CPUQuotaPerSecUSec"] == "8s"
            && n["TasksMax"] == "1024"
            && n["Restart"] == "no"
            && n["NRestarts"] == "0"
            && n["ControlGroup"] == format!("/system.slice/{UNIT}")
            && args(n)? == expected(&format!("{PACKAGE}/jetstreamer-node"), &parent_args()),
        "direct163 parent native profile"
    );
    Ok(())
}
fn parent(n: &Value, iid: Option<&str>) -> Result<Value> {
    raw_profile(n)?;
    let id = string(n, "/InvocationID")?;
    let pid = string(n, "/MainPID")?.parse::<u64>()?;
    ensure!(
        is_lower_hex(id, 32)
            && iid.is_none_or(|v| v == id)
            && pid > 1
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["ControlPID"] == "0"
            && n["Job"] == ""
            && n["Group"] == "horizon"
            && n["NoNewPrivileges"] == "yes"
            && n["CapabilityBoundingSet"] == ""
            && n["AmbientCapabilities"] == "",
        "direct163 exact live owner"
    );
    mapped(
        pid,
        &format!("{PACKAGE}/jetstreamer-node"),
        NODE_SHA,
        &parent_args(),
    )?;
    Ok(
        json!({"unit":UNIT,"iid":id,"pid":pid,"start_ticks":ticks(pid)?,"role":"diagnostic-replay",
        "first_epoch":163,"last_epoch":163,"restarts":0,"identity_stable":true,
        "guard_required":false,"has_memory_accounting":true}),
    )
}
fn source(n: &Value, b: &Bound) -> Result<()> {
    storage::bytes(b, 1 << 20, true)?;
    let path = Path::new(string(n, "/FragmentPath")?);
    ensure!(
        path.canonicalize()? == b.path && n["DropInPaths"] == "",
        "direct163 effective service source changed"
    );
    for k in ["ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost"] {
        ensure!(
            n[k].as_str().is_none_or(|v| v.is_empty()),
            "direct163 unbound executable lifecycle hook"
        );
    }
    Ok(())
}
fn auxiliary(
    n: &Value,
    name: &str,
    cap: &str,
    verb: &str,
    plan: &Bound,
    src: &Bound,
) -> Result<()> {
    source(n, src)?;
    artifact(GUARD_IMAGE, GUARD_SHA)?;
    ensure!(
        n["Id"] == name
            && n["LoadState"] == "loaded"
            && n["Type"] == "oneshot"
            && n["User"] == "root"
            && n["Group"] == "root"
            && n["Restart"] == "no"
            && n["NRestarts"] == "0"
            && n["MemoryAccounting"] == "yes"
            && n["MemoryMax"] == cap
            && n["MemorySwapMax"] == "0"
            && n["CPUQuotaPerSecUSec"] == "1s"
            && n["TasksMax"] == "512"
            && n["TimeoutStartUSec"] == "3min"
            && n["NoNewPrivileges"] == "yes"
            && n["ProtectSystem"] == "strict"
            && n["ProtectHome"] == "read-only"
            && n["PrivateNetwork"] == "yes"
            && n["KillMode"] == "control-group"
            && n["Delegate"] == "no"
            && n["CapabilityBoundingSet"] == "cap_dac_override cap_sys_ptrace"
            && n["AmbientCapabilities"] == "cap_dac_override cap_sys_ptrace",
        "direct163 auxiliary exact finite profile"
    );
    let argv = vec![
        GUARD_IMAGE.into(),
        verb.into(),
        plan.path.to_string_lossy().into_owned(),
        "--plan-sha256".into(),
        plan.sha256.clone(),
        "--self-sha256".into(),
        GUARD_SHA.into(),
    ];
    ensure!(
        args(n)? == expected(GUARD_IMAGE, &argv),
        "direct163 auxiliary command changed"
    );
    Ok(())
}
fn timer(n: &Value, source_bound: &Bound, expected_iid: Option<&str>) -> Result<()> {
    source(n, source_bound)?;
    ensure!(
        n["Id"] == TIMER
            && n["LoadState"] == "loaded"
            && n["ActiveState"] == "active"
            && n["SubState"] == "waiting"
            && n["Unit"] == GUARD
            && n["InvocationID"]
                .as_str()
                .is_some_and(|v| is_lower_hex(v, 32) && expected_iid.is_none_or(|e| e == v)),
        "direct163 timer identity"
    );
    let rows = string(n, "/TimersMonotonic")?.lines().collect::<Vec<_>>();
    ensure!(
        rows.len() == 2
            && rows
                .iter()
                .any(|r| r.starts_with("{ OnActiveUSec=1s ; next_elapse="))
            && rows
                .iter()
                .any(|r| r.starts_with("{ OnUnitActiveUSec=30s ; next_elapse=")),
        "direct163 timer schedule"
    );
    Ok(())
}
fn original_start(iid: &str) -> Result<Value> {
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args(["--all", "--no-pager", "--output=json", "-u", UNIT, "_PID=1"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 8 << 20,
        "direct163 original parent journal"
    );
    let rows = out
        .stdout
        .split(|b| *b == b'\n')
        .filter(|v| !v.is_empty())
        .map(io_json)
        .collect::<Result<Vec<_>>>()?;
    let selected = rows
        .into_iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["INVOCATION_ID"] == iid
                && r["UNIT"] == UNIT
                && r["JOB_TYPE"] == "start"
                && r["JOB_RESULT"] == "done"
        })
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "direct163 needs exactly one original PID 1 started result"
    );
    Ok(selected[0].clone())
}
fn io_json(b: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice(b)?)
}
fn first_fire(g: &Value, parent_iid: &str, floor: u64, t: u64) -> Result<Value> {
    ensure!(
        g["MainPID"] == "0"
            && g["ControlPID"] == "0"
            && g["Job"] == ""
            && g["Result"] == "success"
            && g["ExecMainStatus"] == "0"
            && g["ActiveState"] == "inactive"
            && g["SubState"] == "dead",
        "direct163 guard not successfully drained"
    );
    let iid = string(g, "/InvocationID")?;
    ensure!(is_lower_hex(iid, 32), "direct163 guard IID");
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--all",
            "--no-pager",
            "--output=json",
            "--lines=64",
            "-u",
            GUARD,
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "direct163 guard journal"
    );
    let mut selected = None;
    for raw in out.stdout.split(|b| *b == b'\n').filter(|v| !v.is_empty()) {
        let row = io_json(raw)?;
        if row["_SYSTEMD_UNIT"] == GUARD
            && row["_SYSTEMD_INVOCATION_ID"] == iid
            && row["_UID"] == "0"
            && row["_EXE"] == GUARD_IMAGE
        {
            let Ok(payload) = serde_json::from_str::<Value>(row["MESSAGE"].as_str().unwrap_or(""))
            else {
                continue;
            };
            fire_payload(&row, &payload, iid, parent_iid, floor, t)?;
            ensure!(
                selected
                    .replace(json!({"journal":row,"payload":payload}))
                    .is_none(),
                "direct163 duplicate guard result"
            );
        }
    }
    selected.context("direct163 actual guard first fire missing")
}
fn plan_shape(p: &Value, a: &Value, iid: &str) -> Result<()> {
    ensure!(
        p["schema"] == "epoch163-direct-parent-memory-DATA-reserve-vma-guard-plan-v2"
            && p["parent_unit"] == UNIT
            && p["parent_invocation_id"] == iid
            && p["parent_program"]
                == json!({"path":format!("{PACKAGE}/jetstreamer-node"),"sha256":NODE_SHA})
            && p["parent_argv"] == json!(parent_args())
            && p["guard_timer"] == TIMER
            && p["filesystem"] == "/home/sol"
            && p["output_directory"] == "/var/lib/jetstreamer/epoch163-singleton-20261104-v1/guard"
            && p["minimum_free_bytes"] == a["minimum_free_bytes"]
            && p["maximum_worker_vmas"] == 3000000
            && p["selected_memory_receipt"] == a["memory_receipt"]
            && p["selected_memory_original_completion"] == a["memory_completion"]
            && p["selected_data_receipt"] == a["data_receipt"]
            && p["selected_data_original_completion"] == a["data_completion"],
        "direct163 guard plan changed admission or owner"
    );
    Ok(())
}
pub(super) async fn run() -> Result<()> {
    let (binding, self_sha) = parsed("enroll-direct163")?;
    let s: Spec = serde_json::from_value(immutable(&binding)?)?;
    ensure!(
        s.schema == "horizon-direct163-enrollment-spec-v1" && s.output == Path::new(REGISTER),
        "direct163 enrollment scope"
    );
    let a = immutable(&s.admission)?;
    let t = now()?;
    ensure!(
        a["schema"] == "horizon-direct163-full-admission-v1"
            && a["admitted"] == true
            && a["attended_launch_only"] == true
            && n(&a, "recorded_unix_seconds")? <= t
            && t < n(&a, "expires_unix_seconds")?,
        "direct163 admission expired"
    );
    let parent_before = native(UNIT)?;
    let owner = parent(&parent_before, None)?;
    let iid = string(&owner, "/iid")?;
    source(&parent_before, &to_bound(&a["parent_service"])?)?;
    let plan = immutable(&s.guard_plan)?;
    plan_shape(&plan, &a, iid)?;
    let g = quiet_guard()?;
    auxiliary(
        &g,
        GUARD,
        "2147483648",
        "check",
        &s.guard_plan,
        &s.guard_service,
    )?;
    ensure!(g["OnFailure"] == STOP, "direct163 fallback not bound");
    let stop = native(STOP)?;
    auxiliary(
        &stop,
        STOP,
        "536870912",
        "stop",
        &s.guard_plan,
        &s.fallback_service,
    )?;
    ensure!(
        stop["MainPID"] == "0"
            && stop["ControlPID"] == "0"
            && stop["Job"] == ""
            && stop["ActiveState"] == "inactive"
            && stop["InvocationID"] == ""
            && stop["Result"] == "success"
            && stop["ExecMainStatus"] == "0",
        "direct163 fallback already executed"
    );
    let tm = native(TIMER)?;
    timer(&tm, &s.timer_source, None)?;
    let fire = first_fire(&g, iid, n(&a, "minimum_free_bytes")?, t)?;
    let start = original_start(iid)?;
    ensure!(
        parent_before == native(UNIT)? && g == native(GUARD)?,
        "direct163 launch capture raced native identity"
    );
    let _ = parent(&native(UNIT)?, Some(iid))?;
    save(
        &s.output,
        &json!({"schema":"horizon-direct163-typed-enrollment-v1","spec":binding,"self_sha256":self_sha,
        "admission":s.admission,"admission_value":a,"parent_owner":owner,"parent_native":parent_before,
        "parent_original_PID1_start":start,"parent_service":a["parent_service"],"guard_plan":s.guard_plan,
        "guard_service":s.guard_service,"fallback_service":s.fallback_service,"timer_source":s.timer_source,
        "worker_discovery_root":format!("{ROOT}/private"),"worker_executable_basename":"historical-worker",
        "guard_first_fire":fire,"guard_native":g,"fallback_native":stop,"timer_native":tm,
        "recorded_unix_seconds":t,"unattended_authorized":true,"publication_authorized":false,"r2_mutations":false}),
    )
}
fn selected(plan: &Value) -> Result<Option<Bound>> {
    let Some(declared) = plan.get("diagnostics") else {
        return Ok(None);
    };
    let rows = declared
        .as_array()
        .context("direct163 fleet diagnostic declarations")?;
    let matches = rows
        .iter()
        .filter(|r| r["unit"] == UNIT || (r["epoch"] == 163 && r["unit"] != super::first128::PARENT128))
        .collect::<Vec<_>>();
    ensure!(matches.len() <= 1, "direct163 duplicate epoch or owner");
    let Some(row) = matches.first() else {
        return Ok(None);
    };
    ensure!(
        row["unit"] == UNIT && row["epoch"] == 163,
        "direct163 foreign claim alias"
    );
    let binding = to_bound(&row["launch_receipt"])?;
    ensure!(
        binding.path == Path::new(REGISTER),
        "direct163 registration path"
    );
    Ok(Some(binding))
}
fn live(plan: &Value) -> Result<Option<Value>> {
    let selected = selected(plan)?;
    if selected.is_none() {
        return Ok(None);
    }
    let registration = selected.context("direct163 registration")?;
    let e = immutable(&registration)?;
    ensure!(
        e["schema"] == "horizon-direct163-typed-enrollment-v1"
            && e["unattended_authorized"] == true
            && e["publication_authorized"] == false
            && e["r2_mutations"] == false,
        "direct163 enrollment authority"
    );
    let a = immutable(&to_bound(&e["admission"])?)?;
    ensure!(
        a == e["admission_value"] && a["admitted"] == true,
        "direct163 immutable admission"
    );
    let current_native = native(UNIT)?;
    let iid = string(&e["parent_owner"], "/iid")?;
    source(&current_native, &to_bound(&e["parent_service"])?)?;
    // Terminal work retains every scheduling, hard-cap and DATA promise. It
    // cannot fabricate a live owner or release capacity from a disappeared PID.
    if !diagnostic_stage_running(&current_native) {
        terminal_identity(&current_native, iid)?;
        let cgroup = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
        if cgroup.exists() {
            ensure!(
                fs::read_to_string(cgroup.join("cgroup.procs"))?
                    .trim()
                    .is_empty()
                    && fs::read_to_string(cgroup.join("cgroup.events"))?
                        .lines()
                        .any(|line| line == "populated 0"),
                "direct163 terminal cgroup retains a worker"
            );
        }
        let _start = original_start(iid)?;
        no_replacement_start(iid)?;
        let pb = to_bound(&e["guard_plan"])?;
        plan_shape(&immutable(&pb)?, &a, iid)?;
        let g = quiet_guard()?;
        auxiliary(
            &g,
            GUARD,
            "2147483648",
            "check",
            &pb,
            &to_bound(&e["guard_service"])?,
        )?;
        let st = native(STOP)?;
        auxiliary(
            &st,
            STOP,
            "536870912",
            "stop",
            &pb,
            &to_bound(&e["fallback_service"])?,
        )?;
        let tm = native(TIMER)?;
        let ts = to_bound(&e["timer_source"])?;
        source(&tm, &ts)?;
        if tm["ActiveState"] == "active" {
            timer(&tm, &ts, Some(string(&e["timer_native"], "/InvocationID")?))?;
        } else {
            ensure!(
                tm["Id"] == TIMER
                    && tm["Unit"] == GUARD
                    && tm["LoadState"] == "loaded"
                    && tm["ActiveState"] == "inactive"
                    && tm["SubState"] == "dead"
                    && (tm["InvocationID"] == e["timer_native"]["InvocationID"]
                        || tm["InvocationID"] == ""),
                "direct163 terminal timer custody"
            );
        }
        return Ok(Some(
            json!({"registration":registration,"owner":e["parent_owner"],
            "parent_native":current_native,"guard_native":g,"fallback_native":st,
            "admission":a,"terminal":true,"memory_or_DATA_credit_bytes":0}),
        ));
    }
    let owner = parent(&current_native, Some(iid))?;
    ensure!(owner == e["parent_owner"], "direct163 parent replaced");
    let pb = to_bound(&e["guard_plan"])?;
    let p = immutable(&pb)?;
    plan_shape(&p, &a, iid)?;
    let g = quiet_guard()?;
    auxiliary(
        &g,
        GUARD,
        "2147483648",
        "check",
        &pb,
        &to_bound(&e["guard_service"])?,
    )?;
    ensure!(g["OnFailure"] == STOP, "direct163 fallback changed");
    let st = native(STOP)?;
    auxiliary(
        &st,
        STOP,
        "536870912",
        "stop",
        &pb,
        &to_bound(&e["fallback_service"])?,
    )?;
    ensure!(
        st["ActiveState"] == "inactive"
            && st["MainPID"] == "0"
            && st["ControlPID"] == "0"
            && st["Job"] == ""
            && st["InvocationID"] == e["fallback_native"]["InvocationID"]
            && st["Result"] == "success"
            && st["ExecMainStatus"] == "0",
        "direct163 failed fallback became active"
    );
    let tm = native(TIMER)?;
    timer(
        &tm,
        &to_bound(&e["timer_source"])?,
        Some(string(&e["timer_native"], "/InvocationID")?),
    )?;
    let fire = first_fire(&g, iid, n(&a, "minimum_free_bytes")?, now()?)?;
    let value = json!({"registration":registration,"owner":owner,"parent_native":current_native,"guard_native":g,"fallback_native":st,"guard_fire":fire,"admission":a});
    Ok(Some(value))
}
pub(in crate::fleet) fn allocation(plan: &Value) -> Result<Vec<Value>> {
    let Some(e) = live(plan)? else {
        return Ok(Vec::new());
    };
    allocation_rows(&e)
}
fn allocation_rows(e: &Value) -> Result<Vec<Value>> {
    let a = &e["admission"];
    let owner = &e["owner"];
    let total = n(&a["candidate_memory"], "candidate_scheduling_total_bytes")?;
    ensure!(
        n(&a["candidate_memory"], "guard_memory_bytes")? == 2 << 30
            && n(&a["candidate_memory"], "failure_stop_memory_bytes")? == 512 << 20,
        "direct163 auxiliary charge changed"
    );
    let mut rows = vec![
        json!({"unit":UNIT,"invocation_id":owner["iid"],"memory_max_bytes":total,
        "data_reservation_bytes":DATA_BYTES,"parent_hard_limit_bytes":192u64<<30,"guard_memory_bytes":2u64<<30,
        "fallback_memory_bytes":512u64<<20,"native_pool_suballocation":false,"direct163_registration":e["registration"],
        "guard_floor_bytes":a["minimum_free_bytes"]}),
    ];
    for (unit, native, hard) in [
        (GUARD, &e["guard_native"], 2u64 << 30),
        (STOP, &e["fallback_native"], 512u64 << 20),
    ] {
        rows.push(json!({"unit":unit,"invocation_id":native["InvocationID"],"memory_max_bytes":0,
            "data_reservation_bytes":0,"actual_memory_hard_limit_bytes":hard,"included_once_in_direct163_parent_claim":true,
            "native_pool_suballocation":false,"direct163_registration":e["registration"]}));
    }
    Ok(rows)
}
pub(in crate::fleet) fn owned_owner(plan: &Value) -> Result<Option<Value>> {
    Ok(live(plan)?
        .filter(|v| v["terminal"] != true)
        .map(|v| v["owner"].clone()))
}
pub(in crate::fleet) fn guard_floor(rows: &[Value]) -> Result<u64> {
    rows.iter()
        .filter(|r| r["unit"] == UNIT)
        .try_fold(0u64, |sum, r| Ok(sum.max(n(r, "guard_floor_bytes")?)))
}
pub(in crate::fleet) fn normalize_peers(a: &[Value], b: &[Value]) -> Result<bool> {
    let normalize = |rows: &[Value]| -> Result<Vec<Value>> {
        let mut rows = rows.to_vec();
        for r in &mut rows {
            if r["unit"] == GUARD {
                ensure!(
                    r["direct163_registration"]["path"] == REGISTER
                        && r["included_once_in_direct163_parent_claim"] == true,
                    "direct163 guard peer authentication"
                );
                r["invocation_id"] = Value::Null;
            }
        }
        Ok(rows)
    };
    Ok(normalize(a)? == normalize(b)?)
}
pub(in crate::fleet) fn launch_matches(claim: &DiagnosticClaim, receipt: &Value) -> bool {
    claim.epoch == 163
        && claim.unit == UNIT
        && claim.scratch_path == Path::new(ROOT).join("private")
        && claim.launch_receipt.path == Path::new(REGISTER)
        && receipt["schema"] == "horizon-direct163-typed-enrollment-v1"
        && receipt["parent_owner"]["unit"] == UNIT
        && receipt["parent_owner"]["iid"] == claim.invocation_id
        && receipt["unattended_authorized"] == true
        && receipt["publication_authorized"] == false
        && receipt["r2_mutations"] == false
}

pub(in crate::fleet) fn comparison_census(
    plan: &Value,
    a: &Value,
    b: &Value,
) -> Result<(Value, Value)> {
    if selected(plan)?.is_none() {
        return Ok((a.clone(), b.clone()));
    }
    let _authenticated = live(plan)?.context("direct163 census enrollment missing")?;
    let mut pair = [a.clone(), b.clone()];
    for row in &mut pair {
        let guard = row[GUARD]
            .as_object_mut()
            .context("direct163 native census guard absent")?;
        for key in [
            "InvocationID",
            "MainPID",
            "ControlPID",
            "ActiveState",
            "SubState",
            "ControlGroup",
            "ExecMainCode",
            "ExecMainPID",
            "ExecMainStartTimestamp",
            "ExecMainExitTimestamp",
        ] {
            guard.remove(key);
        }
        // Source/command and all hard caps remain in the comparison view. Only
        // successful per-fire execution metadata is normalized; raw rows stay raw.
        let command = guard
            .get("ExecStart")
            .context("direct163 census command")?
            .as_str()
            .context("direct163 census command type")?;
        let id = command
            .split_once(" ; ignore_errors=")
            .context("direct163 census command framing")?
            .0
            .to_owned();
        guard.insert("ExecStart".into(), json!(id));
        let timer = row[TIMER]
            .as_object_mut()
            .context("direct163 census timer absent")?;
        timer.remove("TimersMonotonic");
    }
    ensure!(
        pair[0][GUARD] == pair[1][GUARD] && pair[0][TIMER] == pair[1][TIMER],
        "direct163 guard/timer static policy changed"
    );
    Ok((pair[0].clone(), pair[1].clone()))
}
pub(in crate::fleet) fn validate_transition(
    previous: &Value,
    plan: &Plan,
    event: &Value,
    sample: &str,
    t: u64,
) -> Result<()> {
    ensure!(
        event["schema"] == "horizon-direct163-typed-enrollment-v1"
            && event["unattended_authorized"] == true
            && event["admission_value"]["current"]["observer"] == json!(plan.observer)
            && previous["observer_receipt"] == plan.observer.path.to_string_lossy().as_ref()
            && previous["observer_sha256"] == plan.observer.sha256
            && previous["sampled_at_utc"] == sample
            && n(event, "recorded_unix_seconds")? <= t
            && t - n(event, "recorded_unix_seconds")? <= 300,
        "direct163 same-sample enrollment transition"
    );
    let added = plan
        .diagnostics
        .iter()
        .filter(|d| d.unit == UNIT)
        .collect::<Vec<_>>();
    ensure!(
        added.len() == 1 && launch_matches(added[0], event),
        "direct163 same-sample launch claim"
    );
    let old = bound_json(&BoundFile {
        path: string(previous, "/plan")?.into(),
        sha256: string(previous, "/plan_sha256")?.into(),
    })?;
    for prior in old["diagnostics"]
        .as_array()
        .context("direct163 predecessor diagnostics")?
    {
        ensure!(
            plan.diagnostics
                .iter()
                .filter(|d| d.unit == prior["unit"]
                    && Some(d.epoch) == prior["epoch"].as_u64()
                    && d.invocation_id == prior["invocation_id"]
                    && d.scratch_path == Path::new(prior["scratch_path"].as_str().unwrap_or(""))
                    && json!(d.launch_receipt) == prior["launch_receipt"])
                .count()
                == 1,
            "direct163 transition changed old diagnostic"
        );
    }
    ensure!(
        plan.diagnostics.len()
            == old["diagnostics"]
                .as_array()
                .context("direct163 old diagnostics")?
                .len()
                + 1,
        "direct163 transition added foreign claims"
    );
    for (epoch, gate) in &plan.gates {
        if *epoch != 163 {
            let old = &old["gates"][&epoch.to_string()];
            ensure!(
                gate.state == old["state"]
                    && gate.next_action == old["next_action"]
                    && json!(gate.evidence) == old["evidence"],
                "direct163 transition changed unrelated gate"
            );
        }
    }
    let v = serde_json::from_value::<Value>(
        json!({"diagnostics":plan.diagnostics.iter().map(|d|json!({"epoch":d.epoch,"unit":d.unit,"launch_receipt":d.launch_receipt})).collect::<Vec<_>>()}),
    )?;
    allocation(&v)?;
    Ok(())
}

fn fire_payload(
    row: &Value,
    payload: &Value,
    guard_iid: &str,
    parent_iid: &str,
    floor: u64,
    t: u64,
) -> Result<()> {
    let at = string(row, "/__REALTIME_TIMESTAMP")?.parse::<u64>()? / 1_000_000;
    ensure!(
        row["_SYSTEMD_UNIT"] == GUARD
            && row["_SYSTEMD_INVOCATION_ID"] == guard_iid
            && row["_UID"] == "0"
            && row["_EXE"] == GUARD_IMAGE
            && is_lower_hex(guard_iid, 32)
            && at <= t
            && t - at <= 180
            && payload["armed"] == true
            && payload["parent_invocation_id"] == parent_iid
            && payload["memory_continuity_validated"] == true
            && n(payload, "available_bytes")? >= floor
            && payload["worker_vmas"].as_u64().is_none_or(|v| v <= 3000000)
            && (payload["worker_vmas"].is_null() || payload["worker_vmas"].is_u64()),
        "direct163 first guard payload/freshness"
    );
    Ok(())
}
#[cfg(test)]
#[path = "enrollment_tests.rs"]
mod tests;

fn terminal_identity(native: &Value, iid: &str) -> Result<()> {
    ensure!(
        native["Id"] == UNIT
            && native["MainPID"] == "0"
            && native["ControlPID"] == "0"
            && native["NRestarts"] == "0"
            && native["Job"] == ""
            && (native["InvocationID"] == iid || native["InvocationID"] == "")
            && !matches!(
                native["ActiveState"].as_str(),
                Some("active" | "activating" | "deactivating" | "reloading")
            ),
        "direct163 terminal owner not positively drained or replaced"
    );
    Ok(())
}
fn no_replacement_start(iid: &str) -> Result<()> {
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args(["--all", "--no-pager", "--output=json", "-u", UNIT, "_PID=1"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 8 << 20,
        "direct163 terminal original history"
    );
    let mut seen = false;
    for raw in out.stdout.split(|v| *v == b'\n').filter(|v| !v.is_empty()) {
        let row = io_json(raw)?;
        if row["_PID"] == "1" && row["UNIT"] == UNIT && row["JOB_TYPE"] == "start" {
            if row["INVOCATION_ID"] == iid {
                seen = true;
            } else {
                ensure!(!seen, "direct163 later replacement start");
            }
        }
    }
    ensure!(seen, "direct163 original start history lost");
    Ok(())
}

fn quiet_guard() -> Result<Value> {
    let initial = native(GUARD)?;
    let iid = initial["InvocationID"].clone();
    let start = std::time::Instant::now();
    let mut current = initial;
    while matches!(
        current["ActiveState"].as_str(),
        Some("active" | "activating" | "deactivating")
    ) {
        ensure!(
            current["Id"] == GUARD
                && current["Type"] == "oneshot"
                && current["MemoryMax"] == "2147483648"
                && current["MemorySwapMax"] == "0"
                && current["NRestarts"] == "0"
                && current["Restart"] == "no"
                && start.elapsed() < Duration::from_secs(10),
            "direct163 guard did not finish inside qualified quiet window"
        );
        std::thread::sleep(Duration::from_millis(250));
        current = native(GUARD)?;
        ensure!(
            current["InvocationID"] == iid,
            "direct163 quiet window crossed guard invocation"
        );
    }
    Ok(current)
}
