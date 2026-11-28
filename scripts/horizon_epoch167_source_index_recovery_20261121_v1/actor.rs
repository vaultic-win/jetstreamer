use super::*;
pub fn sample() -> Result<Value> {
    let m = native(UNIT)?;
    let iid = st(&m, "InvocationID")?;
    let pid = st(&m, "MainPID")?.parse::<u64>()?;
    ensure!(
        hex(iid, 32)
            && pid > 1
            && m["ActiveState"] == "active"
            && m["SubState"] == "running"
            && m["Job"] == ""
            && m["NRestarts"] == "0"
            && m["ControlPID"] == "0"
            && m["CPUQuotaPerSecUSec"] == "9s"
            && m["MemoryMax"] == (68u64 << 30).to_string()
            && m["MemorySwapMax"] == "0",
        "different node limits or generation"
    );
    let p = Path::new("/proc").join(pid.to_string());
    let (_, ticks, group) = proc_row(pid)?;
    let image = source::node();
    let bytes = fs::read(p.join("cmdline"))?;
    let args: Vec<&[u8]> = bytes.split(|x| *x == 0).filter(|s| !s.is_empty()).collect();
    let profile = source::profile()?;
    let argv = profile["producer_argv"]
        .as_array()
        .context("producer argv")?;
    let start = argv
        .iter()
        .position(|x| x == &json!(source::node_arg()))
        .context("node command")?;
    #[cfg(epoch168_cold_rebook)]
    let (image, start, stage) = if same(&p.join("exe"), Path::new("/usr/bin/python3"))? {
        let held = start.checked_sub(3).context("held invocation")?;
        ensure!(
            argv[held] == "/usr/bin/python3"
                && argv[held + 1] == "-IB"
                && argv[held + 2] == format!("{}/gate.py", source::ALIAS)
                && members(UNIT)? == vec![pid],
            "foreign held command"
        );
        (Path::new("/usr/bin/python3").to_owned(), held, "held")
    } else {
        (image, start, "node")
    };
    ensure!(
        group == format!("0::/system.slice/{UNIT}")
            && same(&p.join("exe"), &image)?
            && same(&p.join("fd/1"), &run().join("producer.log"))?
            && args
                == argv[start..]
                    .iter()
                    .map(|v| v.as_str().unwrap_or_default().as_bytes())
                    .collect::<Vec<_>>()
            && members(UNIT)?.contains(&pid),
        "different live node"
    );
    let meta = fs::metadata(image)?;
    let value = json!({"producer_unit":UNIT,"producer_pid":pid,"producer_invocation_id":iid,"start_ticks":ticks,"MainPID":m["MainPID"],"InvocationID":iid,"MainStartTicks":ticks,"exe_device":meta.dev(),"exe_inode":meta.ino(),"cgroup":m["ControlGroup"]});
    #[cfg(epoch168_cold_rebook)]
    let value = {
        let mut v = value;
        v["stage"] = json!(stage);
        v
    };
    Ok(value)
}
pub fn guard(actor: &Value, plan: &Value) -> Result<(Value, Value)> {
    let actual = bound(plan, &base().join("ACTUAL_GUARD_PLAN.json"))?;
    ensure!(
        actual["invocation_id"] == actor["producer_invocation_id"]
            && actual["unit"] == UNIT
            && actual["worker_root"] == LANE
            && actual["maximum_root_physical_bytes"] == CAP,
        "different native guard plan"
    );
    let timer = native(TIMER)?;
    let unit = TIMER.replace(".timer", ".service");
    let ctl = native(&unit)?;
    ensure!(
        timer["ActiveState"] == "active"
            && timer["Triggers"] == unit
            && hex(st(&timer, "InvocationID")?, 32)
            && ctl["TriggeredBy"] == TIMER
            && ctl["CPUQuotaPerSecUSec"]
                == (if cfg!(epoch168_cold_rebook) {
                    "250ms"
                } else {
                    "1s"
                })
            && ctl["MemoryMax"] == (1u64 << 30).to_string()
            && ctl["MemorySwapMax"] == "0",
        "different native guard/timer"
    );
    let log = base().join("guard.stdout");
    let mut f = File::open(log)?;
    let len = f.metadata()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(2 << 20)))?;
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    let row = b
        .split(|x| *x == b'\n')
        .rev()
        .find_map(|l| serde_json::from_slice::<Value>(l).ok())
        .context("guard stdout")?;
    let id = st(&row, "guard_invocation_id")?;
    ensure!(hex(id, 32), "guard iid");
    let (v, sr) = doc(
        &base()
            .join("guard-receipts")
            .join(format!("sample-{id}.json")),
        None,
    )?;
    ensure!(
        v == row
            && v["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && v["producer_invocation_id"] == actor["producer_invocation_id"]
            && v["producer"]["pid"] == actor["producer_pid"]
            && v["producer"]["restarts"] == 0
            && v["producer_stop_enabled"] == true
            && v["producer"]["active"] == "active"
            && v["plan_sha256"] == plan["sha256"]
            && v["guard_sha256"] == GUARD_SHA
            && v["trip_reason"].is_null()
            && v["worker_observation_error"].is_null()
            && v["root_physical_observation_error"].is_null()
            && v["DATA_fulfillment_observation_error"].is_null()
            && v["DATA_fulfillment"].is_object()
            && v["root_physical_observation"]["exceeds_budget"] == false
            && now()?
                .checked_sub(n(&v, "recorded_unix_seconds")?)
                .is_some_and(|t| t <= 120),
        "invalid guard proof"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut waited = false;
    loop {
        let events = command(
            "/usr/bin/journalctl",
            &[
                "--no-pager",
                "-ojson",
                "--output-fields=_PID,UNIT,INVOCATION_ID,JOB_RESULT",
                "_PID=1",
                &format!("UNIT={unit}"),
                &format!("INVOCATION_ID={id}"),
                "-n12",
            ],
            10,
        )?;
        if guard_job_done(&events, &unit, id)? {
            break;
        }
        // The guard writes its sample immediately before PID1 publishes its job result.
        let manager = native(&unit)?;
        ensure!(
            Instant::now() < deadline && guard_job_pending(&manager, id),
            "missing PID1 completion for original guard {unit} {id}"
        );
        waited = true;
        thread::sleep(Duration::from_millis(100));
    }
    if waited {
        let current = native(TIMER)?;
        ensure!(
            current["InvocationID"] == timer["InvocationID"]
                && current["ActiveState"] == "active"
                && current["Triggers"] == unit
                && sample()? == *actor
                && now()?
                    .checked_sub(n(&v, "recorded_unix_seconds")?)
                    .is_some_and(|age| age <= 120),
            "guard timer, producer or sample changed while waiting for PID1"
        );
    }
    Ok((json!({"receipt":sr,"guard_invocation":id,"timer":timer}), v))
}

fn guard_job_done(events: &[u8], unit: &str, id: &str) -> Result<bool> {
    let mut done = false;
    for line in events
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let event: Value = serde_json::from_slice(line)?;
        if event["_PID"] == "1"
            && event["UNIT"] == unit
            && event["INVOCATION_ID"] == id
            && let Some(result) = event["JOB_RESULT"].as_str()
        {
            ensure!(
                result == "done",
                "PID1 reported {result} for guard {unit} {id}"
            );
            done = true;
        }
    }
    Ok(done)
}

fn guard_job_pending(manager: &Value, id: &str) -> bool {
    matches!(
        manager["ActiveState"].as_str(),
        Some("activating" | "active" | "deactivating" | "inactive")
    ) && (manager["InvocationID"] == id
        || (manager["InvocationID"] == "" && manager["ActiveState"] == "inactive"))
}

pub fn worker() -> Result<Value> {
    let (ad, ar) = doc(&base().join("ACTUAL_ADMISSION_AND_PROTECTION.json"), None)?;
    let a = sample()?;
    ensure!(
        ad["producer_invocation_id"] == a["producer_invocation_id"]
            && ad["producer_pid"] == a["producer_pid"]
            && ad["start_ticks"] == a["start_ticks"],
        "different admission"
    );
    let (guard, v) = guard(&a, &ad["actual_guard_plan"])?;
    let list = v["workers"].as_array().context("workers")?;
    ensure!(
        list.len() == 1,
        "expected exactly one protected historical worker"
    );
    let pid = list[0][0].as_u64().context("worker pid")?;
    let p = Path::new("/proc").join(pid.to_string());
    let (parent, ticks, group) = proc_row(pid)?;
    let exe = fs::read_link(p.join("exe"))?;
    let owner = n(&a, "producer_pid")?;
    let image = source::worker_image();
    ensure!(
        parent == owner
            && group == format!("0::/system.slice/{UNIT}")
            && exe.starts_with(run().join("private"))
            && exe.file_name() == Some(std::ffi::OsStr::new("historical-worker"))
            && same(&p.join("exe"), &exe)?
            && members(UNIT)?.len() == 2,
        "foreign worker"
    );
    let f = File::open(p.join("exe"))?;
    let mut h = Sha256::new();
    std::io::copy(&mut &f, &mut h)?;
    let ws = format!("{:x}", h.finalize());
    #[cfg(epoch168_cold_rebook)]
    let expected = source::WORKER_SHA;
    #[cfg(not(epoch168_cold_rebook))]
    let expected = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
    ensure!(
        ws == expected
            && file_digest(&image)? == ws
            && proc_row(pid)? == (parent, ticks, group)
            && sample()? == a,
        "worker changed before promotion"
    );
    let scratch = exe
        .ancestors()
        .find(|q| q.file_name() == Some(std::ffi::OsStr::new("scratch")))
        .context("scratch root")?;
    let logfile = run().join("producer.log");
    let log = fs::metadata(&logfile)?;
    let mut value = a.clone();
    value["epoch"] = EPOCH.into();
    value["admission"] = ar;
    value["worker_pid"] = pid.into();
    value["worker_start_ticks"] = ticks.into();
    value["worker_sha256"] = ws.into();
    value["worker_guard"] = guard;
    value["observer_row"] = json!({"range":EPOCH.to_string(),"controller_unit":UNIT,"producer_unit":UNIT,"scratch_path":scratch,"expected_controller_invocation_id":a["producer_invocation_id"],"expected_producer_invocation_id":a["producer_invocation_id"],"worker_executable_basename":"historical-worker","append_log":{"device":log.dev(),"inode":log.ino(),"path":logfile}});
    value["schema"] = format!("horizon-{EPOCH}-first-protected-worker-v1").into();
    value["measured_transaction_replay"] = false.into();
    if base().join("FIRST_PROTECTED_WORKER.json").try_exists()? {
        let (old, b) = doc(&base().join("FIRST_PROTECTED_WORKER.json"), None)?;
        ensure!(
            old["worker_pid"] == pid
                && old["worker_start_ticks"] == ticks
                && old["admission"] == value["admission"],
            "different previous protected worker"
        );
        return Ok(b);
    }
    record("FIRST_PROTECTED_WORKER.json", &value)
}

#[cfg(test)]
mod guard_job_tests {
    use super::*;

    fn row(pid: &str, unit: &str, id: &str, result: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"_PID":pid,"UNIT":unit,"INVOCATION_ID":id,"JOB_RESULT":result}))
            .unwrap()
    }

    #[test]
    fn requires_the_original_job_even_if_the_sample_was_emitted_first() {
        for events in [
            vec![],
            row("1", "guard", "old", "done"),
            row("1", "other", "selected", "done"),
            row("42", "guard", "selected", "done"),
        ] {
            assert!(!guard_job_done(&events, "guard", "selected").unwrap());
        }
        assert!(
            guard_job_done(&row("1", "guard", "selected", "done"), "guard", "selected").unwrap()
        );
        assert!(
            guard_job_done(
                &row("1", "guard", "selected", "failed"),
                "guard",
                "selected"
            )
            .is_err()
        );
    }

    #[test]
    fn waits_only_for_the_same_guard_or_its_just_collected_exit() {
        for (iid, state, expected) in [
            ("selected", "activating", true),
            ("selected", "deactivating", true),
            ("", "inactive", true),
            ("selected", "failed", false),
            ("new", "active", false),
            ("", "active", false),
        ] {
            assert_eq!(
                guard_job_pending(&json!({"InvocationID":iid,"ActiveState":state}), "selected"),
                expected
            );
        }
    }
}
