//! Peer evidence may bind a completed success while its exact successor runs.
//! Launch capture retains its stricter inactive protective-service contract.
use super::*;
const SCHEMA: &str = "jetstreamer-canary227-peer-guard-manager-v1";
const DIRECTORY: &str = "/var/lib/jetstreamer/horizon-canary227-selection-v2-guard-receipts-v1";
const START: &str = "7d4958e842da4a758f6c1cdc7b36dcc5";
const PROPERTIES: &str = "Id,LoadState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,NRestarts,Type,User,Restart,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,MemoryMax,MemorySwapMax,CapabilityBoundingSet,AmbientCapabilities,TasksMax,CPUQuotaPerSecUSec,ExecStart,Result,ActiveState,SubState,ControlGroup";

fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("canary guard integer missing: {key}"))
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("canary guard string missing: {key}"))
}
fn command(plan: &BoundFile) -> String {
    format!(
        "{} {} --plan-sha256 {} --self-sha256 {}",
        c::GUARD,
        plan.path.display(),
        plan.sha256,
        c::GUARD_SHA
    )
}
fn clock(v: &Value) -> Result<u64> {
    Ok(text(v, "__REALTIME_TIMESTAMP")?.parse()?)
}
fn manager_event(v: &Value) -> bool {
    v["_PID"] == "1" && v["_UID"] == "0" && v["UNIT"] == PROTECTIVE
}
fn sandbox(p: &Value, plan: &BoundFile) -> Result<()> {
    let properties: BTreeMap<String, String> = serde_json::from_value(p.clone())?;
    singleton227_capture::require(
        &properties,
        &[
            ("Id", PROTECTIVE),
            ("LoadState", "loaded"),
            ("Type", "oneshot"),
            ("User", "root"),
            ("Restart", "no"),
            ("NRestarts", "0"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("ReadWritePaths", DIRECTORY),
            ("MemoryMax", "1073741824"),
            ("TasksMax", "256"),
            ("CPUQuotaPerSecUSec", "1s"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
        ],
    )
    .context("bounded canary peer guard sandbox")?;
    let expected = format!(
        "{{ path={} ; argv[]={} ; ignore_errors=no }}",
        c::GUARD,
        command(plan)
    );
    ensure!(
        c::same_command(&p["ExecStart"], &json!(expected)),
        "canary peer guard immutable command differs"
    );
    Ok(())
}
fn timer(v: &Value) -> Result<()> {
    let p: BTreeMap<String, String> = serde_json::from_value(v.clone())?;
    singleton227_capture::require(&p, &[("ActiveState", "active"), ("SubState", "waiting")])
        .context("bounded canary peer protective timer")
}

/// Replays saved evidence without inventing a current manager state.
pub(super) fn validate_saved(v: &Value, g: &Value) -> Result<()> {
    ensure!(v["schema"] == SCHEMA, "canary peer guard manager schema");
    let plan: BoundFile = serde_json::from_value(v["guard_plan"].clone())?;
    let bytes = text(v, "guard_plan_bytes")?.as_bytes();
    let gp: Value = serde_json::from_slice(bytes)?;
    ensure!(
        hex_lower(&Sha256::digest(bytes)) == plan.sha256
            && g["plan"] == plan.path.to_string_lossy().as_ref()
            && g["plan_sha256"] == plan.sha256
            && g["guard_sha256"] == c::GUARD_SHA
            && gp["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && gp["unit"] == c::UNIT
            && gp["invocation_id"] == g["producer_invocation_id"]
            && gp["receipt_directory"] == DIRECTORY,
        "canary peer guard plan/receipt binding differs"
    );
    let p = &v["properties"];
    sandbox(p, &plan)?;
    sandbox(&v["properties_after"], &plan)?;
    ensure!(
        p == &v["properties_after"],
        "canary peer guard changed across manager bracket"
    );
    timer(&v["timer"])?;
    timer(&v["timer_after"])?;
    ensure!(
        v["timer"] == v["timer_after"],
        "canary peer guard timer changed"
    );
    ensure!(
        v["completed_guard"] == v["completed_guard_after"],
        "canary completed guard selection changed"
    );
    let history = &v["completed_guard"]["history"];
    let selected: BoundFile = serde_json::from_value(v["completed_guard"]["binding"].clone())?;
    ensure!(
        selected.path
            == Path::new(DIRECTORY)
                .join(format!("sample-{}.json", text(g, "guard_invocation_id")?))
            && history["maximum_age_seconds"] == 1800,
        "canary peer guard receipt scope or age policy differs"
    );
    ensure!(
        history["selected_unix_seconds"]
            .as_u64()
            .is_some_and(|now| number(v, "captured_unix_millis")
                .is_ok_and(|captured| captured / 1000 >= now && captured / 1000 - now <= 30))
            && v["journal_sha256"]
                .as_str()
                .is_some_and(|sha| is_lower_hex(sha, 64)),
        "canary peer guard evidence exceeds its bounded transaction"
    );
    let rows = v["manager_events"]
        .as_array()
        .context("canary peer manager events")?;
    warmup223::validate_selected_guard_events(history, g, rows)?;
    ensure!(
        history["unit"] == PROTECTIVE
            && history["guard_invocation_id"] == g["guard_invocation_id"]
            && history["executable"] == c::GUARD
            && v["completed_guard"]["binding"]["sha256"]
                == hex_lower(&Sha256::digest(text(v, "guard_receipt_bytes")?.as_bytes()))
            && serde_json::from_str::<Value>(text(v, "guard_receipt_bytes")?)? == *g,
        "canary completed guard provenance differs"
    );
    let events = history["events"]
        .as_array()
        .context("canary completed history")?;
    let done = events.get(2).context("canary completed success")?;
    let finish = events.last().context("canary completed finish")?;
    ensure!(
        v["manager_completion"] == *done,
        "canary completed success changed"
    );
    match (text(p, "ActiveState")?, text(p, "SubState")?) {
        ("inactive", "dead") => {
            ensure!(
                p["InvocationID"] == g["guard_invocation_id"]
                    && p["MainPID"] == "0"
                    && p["ControlPID"] == "0"
                    && v["successor"].is_null()
                    && v["process_before"].is_null()
                    && v["process_after"].is_null(),
                "canary idle guard is not the selected success"
            );
        }
        ("activating", "start") => validate_successor(v, p, rows, finish, &plan)?,
        _ => bail!("canary peer protective service has an unsupported lifecycle state"),
    }
    Ok(())
}

fn validate_successor(
    v: &Value,
    p: &Value,
    rows: &[Value],
    finish: &Value,
    plan: &BoundFile,
) -> Result<()> {
    let current = &p["InvocationID"];
    ensure!(
        iid(current) && current != &finish["INVOCATION_ID"],
        "canary successor IID missing or reused"
    );
    let starts = rows
        .iter()
        .filter(|r| manager_event(r) && r["MESSAGE_ID"] == START)
        .collect::<Vec<_>>();
    let successor = &v["successor"];
    let matching = starts
        .iter()
        .filter(|r| r["INVOCATION_ID"] == *current)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1
            && **matching[0] == *successor
            && successor["JOB_TYPE"] == "start"
            && successor["_BOOT_ID"] == finish["_BOOT_ID"]
            && successor["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with(&format!(
                    "Starting {PROTECTIVE} - [systemd-run] {}",
                    c::GUARD
                )))
            && clock(successor)? > clock(finish)?
            && clock(successor)? / 1000 <= number(v, "captured_unix_millis")?,
        "canary successor lacks its exact later PID1 start"
    );
    let finished_at = clock(finish)?;
    for row in rows.iter().filter(|r| manager_event(r)) {
        if clock(row)? <= finished_at {
            continue;
        }
        if row["MESSAGE_ID"] == START {
            ensure!(
                row == successor,
                "another canary guard started during the bracket"
            );
        } else {
            // No terminal, failure or state-transition event may follow the
            // selected completed success while a successor is claimed running.
            ensure!(
                row["INVOCATION_ID"] != *current,
                "canary successor already has a manager completion or failure"
            );
        }
    }
    ensure!(
        rows.iter().all(|r| !(r["_SYSTEMD_UNIT"] == PROTECTIVE
            && r["_SYSTEMD_INVOCATION_ID"] == *current)),
        "canary successor already emitted result or failure output"
    );
    let process = &v["process_before"];
    ensure!(
        process == &v["process_after"],
        "canary guard process identity changed"
    );
    let pid = number(process, "pid")?;
    let expected_pid = pid.to_string();
    ensure!(
        pid > 1
            && number(process, "start_ticks")? > 0
            && number(process, "uid")? == 0
            && process["invocation_id"] == *current
            && process["executable"] == c::GUARD
            && process["cgroup"] == format!("0::/system.slice/{PROTECTIVE}")
            && process["argv"] == json!(command(plan).split_whitespace().collect::<Vec<_>>())
            && number(process, "executable_device")? > 0
            && number(process, "executable_inode")? > 0
            && process["executable_sha256"] == c::GUARD_SHA
            && p["ControlGroup"] == format!("/system.slice/{PROTECTIVE}")
            && p["ExecMainPID"].as_str() == Some(expected_pid.as_str())
            && p["ExecMainStartTimestampMonotonic"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
            && p["ExecMainCode"] == "0",
        "canary successor process does not bind its exact immutable guard"
    );
    // The dated root-captured activating/start frame confirms that this oneshot
    // uses MainPID=ExecMainPID and ControlPID=0; do not accept arbitrary PIDs.
    ensure!(
        p["MainPID"].as_str() == Some(expected_pid.as_str()) && p["ControlPID"] == "0",
        "canary successor PID ownership differs"
    );
    Ok(())
}

fn process(p: &Value, plan: &BoundFile) -> Result<Value> {
    let pid = text(p, "ExecMainPID")?.parse::<u64>()?;
    ensure!(pid > 1, "canary successor has no positive execution PID");
    let root = Path::new("/proc").join(pid.to_string());
    let ticks = || -> Result<u64> {
        let stat = fs::read_to_string(root.join("stat"))?;
        Ok(stat
            .rsplit_once(") ")
            .context("canary guard stat framing")?
            .1
            .split_whitespace()
            .nth(19)
            .context("canary guard process start")?
            .parse()?)
    };
    let start = ticks()?;
    let uid = fs::metadata(&root)?.uid();
    let exe = fs::read_link(root.join("exe"))?;
    let actual = fs::metadata(root.join("exe"))?;
    let frozen = fs::symlink_metadata(c::GUARD)?;
    ensure!(
        exe == Path::new(c::GUARD)
            && Path::new(c::GUARD).canonicalize()? == Path::new(c::GUARD)
            && frozen.is_file()
            && actual.dev() == frozen.dev()
            && actual.ino() == frozen.ino()
            && frozen.uid() == 0
            && frozen.nlink() == 1
            && frozen.mode() & 0o222 == 0,
        "canary successor executable custody differs"
    );
    let executable_sha = private157::file_binding(Path::new(c::GUARD))?["sha256"].clone();
    let argv = fs::read(root.join("cmdline"))?;
    let expected = command(plan)
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut expected_bytes = expected.join("\0").into_bytes();
    expected_bytes.push(0);
    ensure!(
        argv == expected_bytes,
        "canary successor actual argv differs"
    );
    let environment = fs::read(root.join("environ"))?;
    ensure!(
        environment.len() <= 1 << 20,
        "canary guard environment exceeds bound"
    );
    let invocation = environment
        .split(|b| *b == 0)
        .filter_map(|s| s.strip_prefix(b"INVOCATION_ID="))
        .collect::<Vec<_>>();
    ensure!(
        invocation.len() == 1 && invocation[0] == text(p, "InvocationID")?.as_bytes(),
        "canary successor process IID differs"
    );
    let cgroup = fs::read_to_string(root.join("cgroup"))?;
    ensure!(
        ticks()? == start && fs::metadata(&root)?.uid() == uid,
        "canary successor changed during process capture"
    );
    Ok(
        json!({"pid":pid,"start_ticks":start,"uid":uid,"invocation_id":p["InvocationID"],
        "executable":exe,"executable_device":actual.dev(),"executable_inode":actual.ino(),
        "executable_sha256":executable_sha,"argv":expected,"cgroup":cgroup.trim()}),
    )
}

pub(super) fn capture(
    g: &Value,
    plan: &BoundFile,
    completed: &Value,
    sample: u64,
    now: u64,
) -> Result<Value> {
    let gp = native209::immutable_json(plan)?;
    let plan_bytes = read_stable_bounded(&plan.path, 1 << 20, "canary guard plan")?;
    ensure!(
        hex_lower(&Sha256::digest(&plan_bytes)) == plan.sha256,
        "canary guard plan changed"
    );
    let binding: BoundFile = serde_json::from_value(completed["binding"].clone())?;
    let receipt_bytes = read_stable_bounded(&binding.path, 1 << 20, "canary guard receipt")?;
    ensure!(
        hex_lower(&Sha256::digest(&receipt_bytes)) == binding.sha256,
        "canary guard receipt changed"
    );
    let p = serde_json::to_value(singleton227_capture::properties(PROTECTIVE, PROPERTIES)?)?;
    let timer_name = PROTECTIVE.replace(".service", ".timer");
    let timer = serde_json::to_value(singleton227_capture::properties(
        &timer_name,
        "ActiveState,SubState",
    )?)?;
    let before = if p["ActiveState"] == "activating" && p["SubState"] == "start" {
        process(&p, plan)?
    } else {
        Value::Null
    };
    let (rows, sha) = singleton227_capture::journal(PROTECTIVE)?;
    let after = if before.is_null() {
        Value::Null
    } else {
        process(&p, plan)?
    };
    let p_after = serde_json::to_value(singleton227_capture::properties(PROTECTIVE, PROPERTIES)?)?;
    let timer_after = serde_json::to_value(singleton227_capture::properties(
        &timer_name,
        "ActiveState,SubState",
    )?)?;
    let selected_after = warmup223::completed_guard_binding(
        PROTECTIVE,
        Path::new(
            gp["receipt_directory"]
                .as_str()
                .context("canary guard receipt directory")?,
        ),
        sample,
        now,
    )?;
    let successor = rows
        .iter()
        .find(|r| {
            manager_event(r) && r["MESSAGE_ID"] == START && r["INVOCATION_ID"] == p["InvocationID"]
        })
        .cloned()
        .unwrap_or(Value::Null);
    let success = completed["history"]["events"]
        .get(2)
        .context("canary completed success event")?
        .clone();
    let v = json!({"schema":SCHEMA,"properties":p,"properties_after":p_after,"timer":timer,"timer_after":timer_after,
        "completed_guard":completed,"completed_guard_after":selected_after,"manager_completion":success,
        "manager_events":rows,"journal_sha256":sha,"successor":if before.is_null(){Value::Null}else{successor},
        "process_before":before,"process_after":after,"guard_plan":private157::binding(plan),
        "guard_plan_bytes":String::from_utf8(plan_bytes)?,"guard_receipt_bytes":String::from_utf8(receipt_bytes)?,
        "captured_unix_millis":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64});
    validate_saved(&v, g)?;
    Ok(v)
}

#[cfg(test)]
pub(super) fn fixture(ongoing: bool) -> (Value, Value) {
    let owner = "a".repeat(32);
    let selected = "b".repeat(32);
    let successor = "c".repeat(32);
    let boot = "d".repeat(32);
    let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1",
        "unit":c::UNIT,"invocation_id":owner,"receipt_directory":DIRECTORY});
    let plan_bytes = gp.to_string();
    let plan = BoundFile {
        path: "/sealed/guard-plan.json".into(),
        sha256: hex_lower(&Sha256::digest(plan_bytes.as_bytes())),
    };
    let g = json!({"plan":plan.path,"plan_sha256":plan.sha256,"guard_sha256":c::GUARD_SHA,
        "guard_invocation_id":selected,"recorded_unix_seconds":1001,
        "producer_invocation_id":owner,"producer":{"invocation_id":owner}});
    let guard_bytes = g.to_string();
    let binding = json!({"path":format!("{DIRECTORY}/sample-{selected}.json"),"sha256":hex_lower(&Sha256::digest(guard_bytes.as_bytes()))});
    let event = |id: &str, iid: &str, time: &str, message: String| {
        json!({"_PID":"1","_UID":"0","UNIT":PROTECTIVE,"INVOCATION_ID":iid,
            "_BOOT_ID":boot,"MESSAGE_ID":id,"__REALTIME_TIMESTAMP":time,"MESSAGE":message})
    };
    let start = event(
        START,
        &selected,
        "1000000000",
        format!("Starting {PROTECTIVE} - [systemd-run] {}", command(&plan)),
    );
    let stdout = json!({"_UID":"0","_PID":"40","_SYSTEMD_UNIT":PROTECTIVE,
        "_SYSTEMD_INVOCATION_ID":selected,"_BOOT_ID":boot,
        "__REALTIME_TIMESTAMP":"1001000000","MESSAGE":guard_bytes});
    let done = event(
        "7ad2d189f7e94e70a38c781354912448",
        &selected,
        "1002000000",
        format!("{PROTECTIVE}: Deactivated successfully."),
    );
    let mut finish = event(
        "39f53479d3a045ac8e11786248231fbf",
        &selected,
        "1002000001",
        format!("Finished {PROTECTIVE} - [systemd-run] {}.", command(&plan)),
    );
    finish["JOB_RESULT"] = json!("done");
    let mut next = event(
        START,
        &successor,
        "1003000000",
        format!("Starting {PROTECTIVE} - [systemd-run] {}...", c::GUARD),
    );
    next["JOB_TYPE"] = json!("start");
    let completed = json!({"binding":binding,"history":{
        "schema":"jetstreamer-completed-guard-history-v1","unit":PROTECTIVE,
        "guard_invocation_id":selected,"minimum_sampled_seconds":1000,
        "selected_unix_seconds":1003,"maximum_age_seconds":1800,"executable":c::GUARD,
        "expected_exec_start":format!("{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",c::GUARD,command(&plan)),
        "events":[start,stdout,done,finish]}});
    let p = json!({"Id":PROTECTIVE,"LoadState":"loaded","InvocationID":if ongoing {&successor}else{&selected},
        "MainPID":if ongoing {"42"}else{"0"},"ControlPID":"0","ExecMainPID":"42",
        "ExecMainCode":if ongoing {"0"}else{"1"},"ExecMainStatus":"0",
        "ExecMainStartTimestampMonotonic":"1003000","NRestarts":"0","Type":"oneshot",
        "User":"root","Restart":"no","ProtectSystem":"strict","ProtectHome":"read-only",
        "PrivateNetwork":"yes","NoNewPrivileges":"yes","ReadWritePaths":DIRECTORY,
        "MemoryMax":"1073741824","MemorySwapMax":"infinity","CapabilityBoundingSet":"historical broad set",
        "AmbientCapabilities":"","TasksMax":"256","CPUQuotaPerSecUSec":"1s",
        "ExecStart":format!("{{ path={} ; argv[]={} ; ignore_errors=no }}",c::GUARD,command(&plan)),
        "Result":"success","ActiveState":if ongoing {"activating"}else{"inactive"},
        "SubState":if ongoing {"start"}else{"dead"},"ControlGroup":format!("/system.slice/{PROTECTIVE}")});
    let process = if ongoing {
        json!({"pid":42,"start_ticks":123,"uid":0,"invocation_id":successor,
        "executable":c::GUARD,"executable_device":1,"executable_inode":2,"executable_sha256":c::GUARD_SHA,
        "argv":command(&plan).split_whitespace().collect::<Vec<_>>(),"cgroup":format!("0::/system.slice/{PROTECTIVE}")})
    } else {
        Value::Null
    };
    let mut rows = completed["history"]["events"].as_array().unwrap().clone();
    if ongoing {
        rows.push(next.clone());
    }
    (
        json!({"schema":SCHEMA,"properties":p,"properties_after":p,"timer":{"ActiveState":"active","SubState":"waiting"},
        "timer_after":{"ActiveState":"active","SubState":"waiting"},"completed_guard":completed,
        "completed_guard_after":completed,"manager_completion":done,"manager_events":rows,
        "journal_sha256":"e".repeat(64),"successor":if ongoing{next}else{Value::Null},
        "process_before":process,"process_after":process,"guard_plan":private157::binding(&plan),
        "guard_plan_bytes":plan_bytes,"guard_receipt_bytes":guard_bytes,"captured_unix_millis":1003500}),
        g,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_and_exact_running_successor_are_distinct_from_launch_capture() {
        for ongoing in [false, true] {
            let (proof, g) = fixture(ongoing);
            validate_saved(&proof, &g).unwrap();
            let p = serde_json::from_value(proof["properties"].clone()).unwrap();
            assert_eq!(
                canary227_capture::completed_service_state(&p).is_ok(),
                !ongoing
            );
        }
    }
    #[test]
    fn arbitrary_states_wrong_ownership_or_immutable_inputs_are_rejected() {
        let (proof, g) = fixture(true);
        for (key, value) in [
            ("ActiveState", "active"),
            ("SubState", "exited"),
            ("InvocationID", ""),
            ("MainPID", "0"),
            ("ControlPID", "42"),
            ("ExecMainPID", "43"),
            ("ExecMainCode", "1"),
            ("ExecMainStatus", "1"),
            ("NRestarts", "1"),
            ("User", "ubuntu"),
            ("MemoryMax", "0"),
            ("ReadWritePaths", "/other"),
            ("ExecStart", "/another-program"),
            ("ControlGroup", "/other"),
        ] {
            let mut bad = proof.clone();
            bad["properties"][key] = json!(value);
            bad["properties_after"][key] = json!(value);
            assert!(validate_saved(&bad, &g).is_err(), "{key}");
        }
        for (pointer, value) in [
            ("/process_after/start_ticks", json!(124)),
            ("/process_after/pid", json!(43)),
            ("/properties_after/InvocationID", json!("f".repeat(32))),
            ("/timer_after/ActiveState", json!("inactive")),
            (
                "/completed_guard_after/binding/sha256",
                json!("f".repeat(64)),
            ),
            ("/guard_plan/sha256", json!("f".repeat(64))),
            ("/successor/_PID", json!("2")),
            ("/successor/INVOCATION_ID", json!("f".repeat(32))),
            ("/successor/__REALTIME_TIMESTAMP", json!("1000000000")),
        ] {
            let mut bad = proof.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_saved(&bad, &g).is_err(), "{pointer}");
        }
        for (key, value) in [
            ("uid", json!(1000)),
            ("executable", json!("/another-program")),
            ("executable_sha256", json!("f".repeat(64))),
            ("cgroup", json!("0::/other")),
            ("invocation_id", json!("f".repeat(32))),
            ("argv", json!([])),
        ] {
            let mut bad = proof.clone();
            bad["process_before"][key] = value.clone();
            bad["process_after"][key] = value;
            assert!(validate_saved(&bad, &g).is_err(), "{key}");
        }
    }
    #[test]
    fn latest_failure_new_completion_output_and_missing_start_never_fall_back() {
        let (proof, g) = fixture(true);
        let mut missing = proof.clone();
        missing["manager_events"].as_array_mut().unwrap().pop();
        assert!(validate_saved(&missing, &g).is_err());
        for event in [
            json!({"_PID":"1","_UID":"0","UNIT":PROTECTIVE,"INVOCATION_ID":"c".repeat(32),
                "__REALTIME_TIMESTAMP":"1003100000","RESULT":"exit-code","MESSAGE":"failed"}),
            json!({"_PID":"1","_UID":"0","UNIT":PROTECTIVE,"INVOCATION_ID":"c".repeat(32),
                "__REALTIME_TIMESTAMP":"1003100000","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf",
                "JOB_RESULT":"done","MESSAGE":format!("Finished {PROTECTIVE} - new command.")}),
            json!({"_SYSTEMD_UNIT":PROTECTIVE,"_SYSTEMD_INVOCATION_ID":"c".repeat(32),"MESSAGE":"result"}),
        ] {
            let mut bad = proof.clone();
            bad["manager_events"].as_array_mut().unwrap().push(event);
            assert!(validate_saved(&bad, &g).is_err());
        }
    }
    #[test]
    fn successor_event_must_itself_prove_exact_pid1_identity_boot_command_and_order() {
        let (proof, g) = fixture(true);
        for (key, value) in [
            ("_PID", json!("2")),
            ("_UID", json!("1000")),
            ("UNIT", json!("another.service")),
            ("INVOCATION_ID", json!("f".repeat(32))),
            ("JOB_TYPE", json!("restart")),
            ("_BOOT_ID", json!("f".repeat(32))),
            ("__REALTIME_TIMESTAMP", json!("1000000000")),
            ("MESSAGE", json!("Starting another program")),
        ] {
            let mut bad = proof.clone();
            bad["successor"][key] = value.clone();
            let last = bad["manager_events"]
                .as_array_mut()
                .unwrap()
                .last_mut()
                .unwrap();
            last[key] = value;
            assert!(validate_saved(&bad, &g).is_err(), "{key}");
        }
        let mut duplicate = proof.clone();
        let event = duplicate["successor"].clone();
        duplicate["manager_events"]
            .as_array_mut()
            .unwrap()
            .push(event);
        assert!(validate_saved(&duplicate, &g).is_err());
    }
}
