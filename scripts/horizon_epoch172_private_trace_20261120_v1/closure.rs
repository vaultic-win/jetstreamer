//! Freeze one stopped metered diagnostic. No archive admission or capacity is released.
use super::*;

fn link(v: &Value, expected: &Path) -> Result<Value> {
    ensure!(Path::new(at(v, "path")?) == expected, "wrong receipt path");
    json_pin(expected, at(v, "sha256")?)
}

fn drained(unit: &str, id: Option<&str>) -> Result<Value> {
    let state = show(unit)?;
    ensure!(
        matches!(state["ActiveState"].as_str(), Some("inactive" | "failed"))
            && state["Job"] == ""
            && ["MainPID", "ControlPID", "NRestarts"]
                .iter()
                .all(|k| state[*k].is_null() || state[*k] == "0")
            && id.is_none_or(|id| state["InvocationID"] == "" || state["InvocationID"] == id),
        "live or replaced unit {unit}"
    );
    let group = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    if group.try_exists()? {
        let mut dirs = vec![group];
        while let Some(dir) = dirs.pop() {
            ensure!(
                fs::read_to_string(dir.join("cgroup.procs"))?
                    .trim()
                    .is_empty(),
                "occupied cgroup {unit}"
            );
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    dirs.push(entry.path());
                }
            }
        }
    }
    Ok(state)
}

fn stable_log(stage: &Value) -> Result<Value> {
    let log = Path::new(DEST).join("producer.log");
    ensure!(log.canonicalize()? == log, "noncanonical producer log");
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&log)?;
    let meta = f.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == 1001
            && meta.gid() == 1003
            && meta.mode() & 0o7777 == 0o600
            && stage["log_inode"] == meta.ino()
            && stage["log_device"] == meta.dev(),
        "staged log was replaced"
    );
    let mut hash = Sha256::new();
    let bytes = std::io::copy(&mut f, &mut hash)?;
    let key = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        bytes == meta.len()
            && key(&meta) == key(&f.metadata()?)
            && key(&meta) == key(&fs::symlink_metadata(&log)?),
        "log changed on terminal read"
    );
    Ok(
        json!({"path":log,"device":meta.dev(),"inode":meta.ino(),"bytes":bytes,"sha256":format!("{:x}",hash.finalize())}),
    )
}

fn pid1_terminal(iid: &str) -> Result<(Vec<Value>, bool)> {
    let rows = run(
        "/usr/bin/journalctl",
        &[
            "--no-pager".into(),
            "-ojson".into(),
            "--output-fields=_PID,UNIT,INVOCATION_ID,MESSAGE_ID,UNIT_RESULT,EXIT_CODE,EXIT_STATUS"
                .into(),
            "_PID=1".into(),
            format!("UNIT={UNIT}"),
            format!("INVOCATION_ID={iid}"),
        ],
        bounded(),
    )?;
    let mut terminal = vec![];
    for line in rows.lines() {
        let r: Value = serde_json::from_str(line)?;
        ensure!(
            r["_PID"] == "1" && r["UNIT"] == UNIT && r["INVOCATION_ID"] == iid,
            "foreign native journal entry"
        );
        if !r["UNIT_RESULT"].is_null()
            || !r["EXIT_CODE"].is_null()
            || r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
        {
            terminal.push(r);
        }
    }
    ensure!(!terminal.is_empty(), "no terminal PID 1 evidence");
    let failed = terminal.iter().any(|r| {
        r["UNIT_RESULT"].as_str().is_some_and(|v| v != "success")
            || r["EXIT_STATUS"].as_str().is_some_and(|v| v != "0")
    });
    let exited = terminal.iter().any(|r| {
        r["UNIT_RESULT"] == "success" || r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
    });
    Ok((terminal, exited && !failed))
}

pub(super) fn collect(admission_sha: &str, provenance: Value) -> Result<Value> {
    let base = Path::new(BASE);
    let admission = base.join("ACTUAL_ADMISSION_AND_PROTECTION.json");
    let a = json_pin(&admission, admission_sha)?;
    let ar = binding(&admission, admission_sha);
    let iid = at(&a, "producer_invocation_id")?;
    let pid = a["producer_pid"].as_u64().context("producer pid")?;
    ensure!(
        guard172::iid(iid) && a["producer_unit"] == UNIT && a["epoch"] == EPOCH,
        "wrong admission identity"
    );
    let stage = link(&a["snapshot_staging"], &base.join("VERIFIED_STAGING.json"))?;
    let token = link(
        &a["gate_release"],
        &base.join("AUTHORIZED_GATED_PAYLOAD.json"),
    )?;
    let first = link(&a["first_guard"], &base.join("FIRST_GUARD.json"))?;
    let fit = link(
        &a["post_guard_capacity"],
        &base.join("POST_GUARD_CAPACITY.json"),
    )?;
    let plan = link(
        &token["actual_guard_plan"],
        &base.join(format!("guard-plan-{iid}/guard-plan.json")),
    )?;
    let sample_ref = &first["receipt"];
    let sampled = json_pin(
        Path::new(at(sample_ref, "path")?),
        at(sample_ref, "sha256")?,
    )?;
    let floor = plan["minimum_free_bytes"].as_u64().context("guard floor")?;
    first_sample(
        &sampled,
        iid,
        pid,
        at(&token["actual_guard_plan"], "sha256")?,
        floor,
    )?;
    ensure!(
        first["genuine_first_timer_driven_success"] == true
            && token["guard_sample"] == a["first_guard"]
            && token["capacity"] == a["post_guard_capacity"]
            && token["producer_invocation_id"] == iid
            && plan == guard172::plan(iid, floor)?
            && stage["actual_native"]["InvocationID"] == iid
            && token["protected_timer"]["Id"] == TIMER
            && stage["protected_timer"] == token["protected_timer"]
            && fit["resource_promise_ending_bytes"] == 0
            && fit["closed_unpatched_predecessor"]["sha256"] == PREDECESSOR_SHA,
        "admission/guard evidence disagree"
    );
    let tid = at(&stage["protected_timer"], "InvocationID")?;
    let end = || -> Result<Value> {
        Ok(
            json!({"producer":drained(UNIT,Some(iid))?,"timer":drained(TIMER,Some(tid))?,"guard":drained(GUARD_SERVICE,None)?}),
        )
    };
    let pre: Value = serde_json::from_slice(&read_root(&base.join("PREFLIGHT.json"))?)?;
    ensure!(
        pre["provenance"] == provenance && pre["fleet"] == token["fleet"],
        "controller differs from actual launch"
    );
    let signed_inputs = &stage["verified_by_sealed_payload"];
    let inputs = Path::new(DEST).join("inputs.json");
    ensure!(
        inputs.canonicalize()? == inputs && signed_inputs["path"].as_str() == inputs.to_str(),
        "staged input path changed"
    );
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&inputs)?;
    let im = input.metadata()?;
    ensure!(
        im.is_file()
            && im.nlink() == 1
            && im.uid() == 1001
            && im.gid() == 1003
            && im.mode() & 0o7777 == 0o400
            && im.len() <= 8192,
        "staged input receipt changed"
    );
    let mut buf = Vec::new();
    input.take(8193).read_to_end(&mut buf)?;
    ensure!(
        signed_inputs["sha256"] == digest(&buf),
        "staged input digest changed"
    );
    let native = end()?;
    let (journal, success) = pid1_terminal(iid)?;
    let intent = Path::new(RECEIPTS).join("stop-intent.json");
    let completed = Path::new(RECEIPTS).join("stop-completion.json");
    let stop = if intent.try_exists()? || completed.try_exists()? {
        let b = read_root(&intent)?;
        let c = read_root(&completed)?;
        let iv: Value = serde_json::from_slice(&b)?;
        let cv: Value = serde_json::from_slice(&c)?;
        ensure!(
            iv["producer_invocation_id"] == iid
                && cv["producer_invocation_id"] == iid
                && cv["terminal"]["pid"] == 0
                && cv["intent"].as_str() == intent.to_str(),
            "incomplete guard stop"
        );
        Some(
            json!({"intent":binding(&intent,&digest(&b)),"completion":binding(&completed,&digest(&c))}),
        )
    } else {
        None
    };
    let before = stable_log(&stage)?;
    let out = Command::new(Path::new(PACKAGE).join(TRACE))
        .arg("progress")
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 1 << 20,
        "cannot authenticate phased trace"
    );
    let comparison: Value = serde_json::from_slice(&out.stdout)?;
    ensure!(
        comparison["producer_invocation_id"] == iid
            && comparison["log_inode"] == before["inode"]
            && comparison["archive_verified"] == false
            && before == stable_log(&stage)?
            && native == end()?,
        "terminal evidence changed"
    );
    let passed = comparison["focused_checks_passed"] == true && success && stop.is_none();
    let result = json!({"schema":format!("epoch{EPOCH}-metered-diagnostic-closure-v2"),"producer_unit":UNIT,"producer_invocation_id":iid,
        "admission":ar,"provenance":provenance,"guard_stop":stop,"first_guard":a["first_guard"],"staging":a["snapshot_staging"],
        "post_guard_capacity":a["post_guard_capacity"],"previous_closure":fit["closed_unpatched_predecessor"],
        "native_terminal":native,"pid1_terminal_records":journal,"log":before,"comparison":comparison,"focused_diagnostic_passed":passed,
        "resource_credit_bytes":0,"resource_promise_ending_bytes":0,"archive_verified":false,"publication_authorized":false,"r2_mutations":false});
    let dest = base.join("CLOSURE.json");
    if dest.try_exists()? {
        let data = read_root(&dest)?;
        ensure!(
            serde_json::from_slice::<Value>(&data)? == result,
            "conflicting existing closure"
        );
        return Ok(binding(&dest, &digest(&data)));
    }
    record(base, "CLOSURE.json", &result)
}
