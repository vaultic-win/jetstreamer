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
        "different 167 node limits or generation"
    );
    let p = Path::new("/proc").join(pid.to_string());
    let (_, ticks, group) = proc_row(pid)?;
    let image = rt(PKG).join("deployment/jetstreamer-node");
    let bytes = fs::read(p.join("cmdline"))?;
    let args: Vec<&[u8]> = bytes.split(|x| *x == 0).filter(|s| !s.is_empty()).collect();
    let profile = source::profile()?;
    let argv = profile["producer_argv"]
        .as_array()
        .context("producer argv")?;
    let start=argv.iter().position(|x|x=="/usr/local/lib/jetstreamer/horizon-independent167-singleton-package-20261109-v1/jetstreamer-node").context("node command")?;
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
        "different live 167 node"
    );
    let meta = fs::metadata(image)?;
    Ok(
        json!({"producer_unit":UNIT,"producer_pid":pid,"producer_invocation_id":iid,"start_ticks":ticks,"MainPID":m["MainPID"],"InvocationID":iid,"MainStartTicks":ticks,"exe_device":meta.dev(),"exe_inode":meta.ino(),"cgroup":m["ControlGroup"]}),
    )
}
pub fn guard(actor: &Value, plan: &Value) -> Result<(Value, Value)> {
    let timer = native(TIMER)?;
    let unit = TIMER.replace(".timer", ".service");
    let ctl = native(&unit)?;
    ensure!(
        timer["ActiveState"] == "active"
            && timer["Triggers"] == unit
            && hex(st(&timer, "InvocationID")?, 32)
            && ctl["TriggeredBy"] == TIMER
            && ctl["CPUQuotaPerSecUSec"] == "1s"
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
    ensure!(
        events
            .split(|x| *x == b'\n')
            .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
            .any(|e| e["UNIT"] == unit && e["INVOCATION_ID"] == id && e["JOB_RESULT"] == "done"),
        "first native guard not completed by PID1"
    );
    Ok((json!({"receipt":sr,"guard_invocation":id,"timer":timer}), v))
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
    let image = rt(PKG).join("deployment/jetstreamer-historical-worker-v1-5-6");
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
    ensure!(
        ws == "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819"
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
    value["epoch"] = 167.into();
    value["admission"] = ar;
    value["worker_pid"] = pid.into();
    value["worker_start_ticks"] = ticks.into();
    value["worker_sha256"] = ws.into();
    value["worker_guard"] = guard;
    value["observer_row"] = json!({"range":"167","controller_unit":UNIT,"producer_unit":UNIT,"scratch_path":scratch,"expected_controller_invocation_id":a["producer_invocation_id"],"expected_producer_invocation_id":a["producer_invocation_id"],"worker_executable_basename":"historical-worker","append_log":{"device":log.dev(),"inode":log.ino(),"path":logfile}});
    value["schema"] = "horizon-167-first-protected-worker-v1".into();
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
