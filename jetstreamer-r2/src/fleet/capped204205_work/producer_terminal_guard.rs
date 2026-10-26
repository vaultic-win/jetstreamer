//! Exact original 205 guard failure after its producer's natural completion.
//! This capability grants inactivity only; generic terminal/live gates stay closed.
use super::*;
const SCHEMA: &str = "jetstreamer-capped205-producer-terminal-guard-v1";
fn failed(v: &Value) -> bool {
    v["LoadState"] == "loaded"
        && v["ActiveState"] == "failed"
        && v["SubState"] == "failed"
        && v["MainPID"] == "0"
        && v["NRestarts"] == "0"
        && v["Result"] == "exit-code"
        && v["ExecMainStatus"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|n| n > 0)
        && v["InvocationID"].as_str().is_some_and(id)
}
fn identity(p: &Value, l: &Value, guard: &Value, expected: &str) -> Result<()> {
    let name = string(p, "guard_unit")?;
    let old = &l["unit_census"][name];
    ensure!(p["epoch"] == 205 && l["epoch"] == 205
        && name.starts_with("horizon-guard-205-capped-continuation-") && name.ends_with(".service")
        && l["guard_unit"] == name && id(string(l, "guard_invocation_id")?)
        && old["Id"] == name && live(old) && old["NRestarts"] == "0"
        && old["InvocationID"] == l["guard_invocation_id"]
        && guard["Id"] == name && failed(guard) && guard["InvocationID"] == old["InvocationID"]
        && canonical_digest(&p["guard_sha256"]) && p["guard_sha256"] == l["guard_sha256"]
        && evidence::command_matches(expected, string(old, "ExecStart")?)
        && evidence::command_matches(expected, string(guard, "ExecStart")?),
        "producer-terminal guard is live, replaced, restarted or differs from exact original plan/launch");
    Ok(())
}
fn history(
    p: &Value,
    l: &Value,
    terminal: &Value,
    producer_raw: &[u8],
    guard_raw: &[u8],
) -> Result<()> {
    ensure!(
        terminal["outcome"] == "natural_success"
            && terminal["unit"] == p["producer_unit"]
            && terminal["invocation_id"] == l["invocation_id"]
            && idle(&terminal["current_unit"])
            && terminal["current_unit"]["Result"] == "success"
            && terminal["current_unit"]["ExecMainStatus"] == "0",
        "guard failure requires actual producer natural completion"
    );
    let producer = string(p, "producer_unit")?;
    let iid = string(l, "invocation_id")?;
    capture::manager_history(producer_raw, producer, iid, true)?;
    let mut finish = None;
    for line in std::str::from_utf8(producer_raw)?.lines() {
        let row: Value = serde_json::from_str(line)?;
        if row["INVOCATION_ID"] == iid && row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448" {
            finish = Some(string(&row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?);
        }
    }
    let finish = finish.context("producer natural terminal event missing")?;
    let name = string(p, "guard_unit")?;
    let guard_iid = string(l, "guard_invocation_id")?;
    let start = capture::manager_history(guard_raw, name, guard_iid, false)?
        .checked_mul(1000)
        .context("terminal guard clock overflow")?;
    ensure!(
        start <= finish,
        "original guard started after producer completion"
    );
    let mut failed_at = None;
    for line in std::str::from_utf8(guard_raw)?.lines() {
        let row: Value = serde_json::from_str(line)?;
        if row["INVOCATION_ID"] == guard_iid
            && row["MESSAGE_ID"] == "d9b373ed55a64feb8242e02dbe79a49c"
            && row["MESSAGE"] == format!("{name}: Failed with result 'exit-code'.")
        {
            let at = string(&row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
            ensure!(
                at > finish && failed_at.replace(at).is_none(),
                "guard failure did not uniquely follow producer completion"
            );
        }
    }
    ensure!(
        failed_at.is_some(),
        "exact original guard PID 1 failed-result event missing"
    );
    Ok(())
}
fn context(p: &Value, frame: &Value, proof: &Value) -> Result<()> {
    ensure!(
        frame["downstream_actors"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && frame["authenticated_other_host_handoffs"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "producer-terminal guard cannot cover active downstream or other-host handoff"
    );
    for job in proof["pending_job_units"]
        .as_array()
        .context("terminal guard queued-job census missing")?
    {
        let name = job.as_str().context("invalid terminal guard queued job")?;
        ensure!(
            !capture::epoch_scope(205, name)
                && !name
                    .split(|c: char| !c.is_ascii_digit())
                    .any(|part| part == "205"),
            "terminal guard has pending replacement/handoff"
        );
    }
    let name = string(p, "guard_unit")?;
    let group = &proof["cgroup"];
    ensure!(
        group["path"] == format!("/sys/fs/cgroup/system.slice/{name}")
            && (group["state"] == "absent"
                || (group["state"] == "unpopulated" && canonical_digest(&group["events_sha256"]))),
        "terminal guard cgroup is populated or unbound"
    );
    denied(proof)
}
fn authenticate(
    p: &Value,
    l: &Value,
    current: &BTreeMap<String, Value>,
    terminal: &Value,
    guard_raw: &[u8],
) -> Result<()> {
    let a = evidence::bound(&serde_json::from_value(l["admission"].clone())?, true)?;
    let plan: BoundFile = serde_json::from_value(l["producer_plan"].clone())?;
    let expected = evidence::expected_guard_command(p, &a, &plan, string(l, "invocation_id")?)?;
    let guard = current
        .get(string(p, "guard_unit")?)
        .context("original terminal guard omitted")?;
    identity(p, l, guard, &expected)?;
    evidence::executable(&serde_json::from_value(
        a["capability_evidence"]["control"].clone(),
    )?)?;
    evidence::terminal_proof(p, l, terminal)?;
    ensure!(
        current.get(string(p, "producer_unit")?) == Some(&terminal["current_unit"]),
        "terminal guard producer differs from complete current census"
    );
    let producer_raw = evidence::bytes(
        &serde_json::from_value(terminal["manager_journal"].clone())?,
        true,
    )?;
    ensure!(
        records_equal(
            &producer_raw,
            &capture::journal(string(p, "producer_unit")?)?
        )?,
        "producer manager history changed after natural completion"
    );
    history(p, l, terminal, &producer_raw, guard_raw)
}
pub(super) fn capture(
    p: &Value,
    l: &Value,
    current: &BTreeMap<String, Value>,
    terminal: &Value,
    actors: &[Actor],
    handoffs: &[BoundFile],
    out: &Path,
) -> Result<Value> {
    if p["epoch"] != 205 || terminal.is_null() || !actors.is_empty() || !handoffs.is_empty() {
        return Ok(Value::Null);
    }
    let name = string(p, "guard_unit")?;
    let guard = current
        .get(name)
        .context("terminal guard missing from complete census")?;
    if !failed(guard) {
        return Ok(Value::Null);
    }
    let terminal_value = evidence::bound(&serde_json::from_value(terminal.clone())?, true)?;
    if terminal_value["outcome"] != "natural_success" {
        return Ok(Value::Null);
    }
    let raw = capture::journal(name)?;
    authenticate(p, l, current, &terminal_value, &raw)?;
    let journal = out.join("producer-terminal-guard-manager.json");
    capture::write_sealed(&journal, &json!({"raw":std::str::from_utf8(&raw)?}))?;
    let jobs = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "list-jobs",
            "--no-legend",
            "--no-pager",
            "--plain",
            "--full",
        ])
        .output()?;
    ensure!(
        jobs.status.success() && jobs.stdout.len() <= 4 << 20,
        "terminal guard queued-job census unavailable"
    );
    inactive_status::no_pending_owner_trigger(name, false)?;
    let v = json!({"schema":SCHEMA,"epoch":205,"unit":name,"current_unit":guard,
        "launch_guard_invocation_id":l["guard_invocation_id"],"terminal_snapshot":terminal,
        "manager_journal":{"path":journal,"sha256":capture::file_sha(&journal)?},
        "pending_job_units":inactive_status::queued_job_units(&jobs.stdout)?,"cgroup":capture::group(name)?,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    context(
        p,
        &json!({"downstream_actors":[],"authenticated_other_host_handoffs":[]}),
        &v,
    )?;
    let path = out.join("producer-terminal-guard.json");
    capture::write_sealed(&path, &v)?;
    Ok(private157::binding(&BoundFile {
        path,
        sha256: capture::file_sha(&out.join("producer-terminal-guard.json"))?,
    }))
}
pub(super) fn validate(
    p: &Value,
    f: &Value,
    current: &BTreeMap<String, Value>,
) -> Result<Option<String>> {
    let Some(b) = f.get("producer_terminal_guard").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let v = evidence::bound(&serde_json::from_value(b.clone())?, true)?;
    let l = evidence::bound(&serde_json::from_value(f["launch"].clone())?, true)?;
    let terminal = evidence::bound(
        &serde_json::from_value(v["terminal_snapshot"].clone())?,
        true,
    )?;
    let name = string(p, "guard_unit")?;
    ensure!(
        v["schema"] == SCHEMA
            && v["epoch"] == 205
            && v["unit"] == name
            && v["terminal_snapshot"] == f["terminal_snapshot"]
            && v["current_unit"] == current[name]
            && v["launch_guard_invocation_id"] == l["guard_invocation_id"],
        "terminal guard proof changed identity or terminal"
    );
    context(p, f, &v)?;
    let journal = evidence::bound(&serde_json::from_value(v["manager_journal"].clone())?, true)?;
    authenticate(
        p,
        &l,
        current,
        &terminal,
        string(&journal, "raw")?.as_bytes(),
    )?;
    Ok(Some(name.into()))
}
pub(super) fn current(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    let Some(b) = f.get("producer_terminal_guard").filter(|v| !v.is_null()) else {
        return Ok(());
    };
    let v = evidence::bound(&serde_json::from_value(b.clone())?, true)?;
    let name = string(&v, "unit")?;
    ensure!(
        current.get(name) == Some(&v["current_unit"]),
        "original terminal guard changed current identity"
    );
    let terminal = evidence::bound(
        &serde_json::from_value(v["terminal_snapshot"].clone())?,
        true,
    )?;
    let producer_raw = evidence::bytes(
        &serde_json::from_value(terminal["manager_journal"].clone())?,
        true,
    )?;
    ensure!(
        records_equal(
            &producer_raw,
            &capture::journal(string(&terminal, "unit")?)?
        )?,
        "producer was replaced after natural terminal guard capture"
    );
    let saved = evidence::bound(&serde_json::from_value(v["manager_journal"].clone())?, true)?;
    ensure!(
        records_equal(string(&saved, "raw")?.as_bytes(), &capture::journal(name)?)?,
        "original terminal guard manager history changed"
    );
    inactive_status::no_pending_owner_trigger(name, false)?;
    ensure!(
        capture::group(name)? == v["cgroup"],
        "original terminal guard cgroup changed"
    );
    Ok(())
}

fn records_equal(left: &[u8], right: &[u8]) -> Result<bool> {
    fn parse(raw: &[u8]) -> Result<Vec<Value>> {
        ensure!(
            raw.len() <= 8 << 20,
            "terminal guard journal comparison bound"
        );
        let rows = serde_json::Deserializer::from_slice(raw)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            !rows.is_empty() && rows.len() <= 16384 && rows.iter().all(Value::is_object),
            "terminal guard journal comparison shape"
        );
        Ok(rows)
    }
    Ok(parse(left)? == parse(right)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    type Fixture = (Value, Value, Value, Value, Vec<Value>, Vec<Value>, String);
    fn fixture() -> Fixture {
        let name = "horizon-guard-205-capped-continuation-test.service";
        let producer = "horizon-qualify-205-capped-continuation-test.service";
        let command = "{ path=/sealed/guard ; argv[]=/sealed/guard guard /sealed/plan".to_owned();
        let display = format!("{command} ; ignore_errors=no }}");
        let piid = "1".repeat(32);
        let giid = "2".repeat(32);
        let p = json!({"epoch":205,"producer_unit":producer,"guard_unit":name,"guard_sha256":"a".repeat(64)});
        let old = json!({"Id":name,"LoadState":"loaded","ActiveState":"active","SubState":"running","MainPID":"42",
            "NRestarts":"0","InvocationID":giid,"ExecStart":display});
        let l = json!({"epoch":205,"guard_unit":name,"guard_invocation_id":giid,"invocation_id":piid,
            "guard_sha256":p["guard_sha256"],"unit_census":{name:old}});
        let current = json!({"Id":name,"LoadState":"loaded","ActiveState":"failed","SubState":"failed","MainPID":"0",
            "NRestarts":"0","Result":"exit-code","ExecMainStatus":"1","InvocationID":giid,"ExecStart":display});
        let terminal = json!({"outcome":"natural_success","unit":producer,"invocation_id":piid,
            "current_unit":{"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","NRestarts":"0","Result":"success","ExecMainStatus":"0"}});
        let row = |unit: &str, iid: &str, at: &str, cursor: &str, event: &str, message: &str| {
            json!({"_PID":"1","_UID":"0","UNIT":unit,
            "INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":at,"__CURSOR":cursor,"MESSAGE_ID":event,"MESSAGE":message})
        };
        let pr = vec![
            row(
                producer,
                &piid,
                "1000000",
                "p1",
                "39f53479d3a045ac8e11786248231fbf",
                "Started producer.",
            ),
            row(
                producer,
                &piid,
                "3000000",
                "p2",
                "7ad2d189f7e94e70a38c781354912448",
                &format!("{producer}: Deactivated successfully."),
            ),
        ];
        let gr = vec![
            row(
                name,
                &giid,
                "2000000",
                "g1",
                "39f53479d3a045ac8e11786248231fbf",
                "Started guard.",
            ),
            row(
                name,
                &giid,
                "4000000",
                "g2",
                "d9b373ed55a64feb8242e02dbe79a49c",
                &format!("{name}: Failed with result 'exit-code'."),
            ),
        ];
        (p, l, current, terminal, pr, gr, command)
    }
    fn raw(rows: &[Value]) -> Vec<u8> {
        rows.iter()
            .map(|v| serde_json::to_string(v).unwrap() + "\n")
            .collect::<String>()
            .into_bytes()
    }
    #[test]
    fn producer_terminal_guard_accepts_exact_original_failure_after_natural_success() {
        let (p, l, current, t, pr, gr, command) = fixture();
        identity(&p, &l, &current, &command).unwrap();
        history(&p, &l, &t, &raw(&pr), &raw(&gr)).unwrap();
        assert!(idle(&current)); // A generic idle predicate alone is not this capability.
    }
    #[test]
    fn producer_terminal_guard_rejects_live_restarted_replaced_foreign_and_changed_executable() {
        let (p, l, current, _, _, _, command) = fixture();
        for (key, value) in [
            ("MainPID", "42"),
            ("NRestarts", "1"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("InvocationID", "3"),
            ("ExecStart", "foreign"),
        ] {
            let mut bad = current.clone();
            bad[key] = json!(value);
            assert!(identity(&p, &l, &bad, &command).is_err(), "{key}");
        }
        let mut bad = l.clone();
        bad["guard_sha256"] = json!("b".repeat(64));
        assert!(identity(&p, &bad, &current, &command).is_err());
        for epoch in [204, 209, 223] {
            let mut bad = p.clone();
            bad["epoch"] = json!(epoch);
            assert!(identity(&bad, &l, &current, &command).is_err());
        }
        let mut bad = l;
        bad["guard_invocation_id"] = json!("3".repeat(32));
        assert!(identity(&p, &bad, &current, &command).is_err());
    }
    #[test]
    fn producer_terminal_guard_requires_exact_ordered_pid1_success_then_failure() {
        let (p, l, _, t, pr, gr, _) = fixture();
        assert!(history(&p, &l, &t, &raw(&pr[..1]), &raw(&gr)).is_err());
        assert!(history(&p, &l, &t, &raw(&pr), &raw(&gr[..1])).is_err());
        for key in [
            "_PID",
            "_UID",
            "UNIT",
            "INVOCATION_ID",
            "MESSAGE_ID",
            "MESSAGE",
        ] {
            let mut bad = gr.clone();
            bad[1][key] = json!("foreign");
            assert!(history(&p, &l, &t, &raw(&pr), &raw(&bad)).is_err(), "{key}");
        }
        let mut early = gr.clone();
        early[1]["__REALTIME_TIMESTAMP"] = json!("2500000");
        assert!(history(&p, &l, &t, &raw(&pr), &raw(&early)).is_err());
        let mut replacement = gr.clone();
        let mut row = gr[0].clone();
        row["INVOCATION_ID"] = json!("3".repeat(32));
        row["__REALTIME_TIMESTAMP"] = json!("5000000");
        row["__CURSOR"] = json!("g3");
        replacement.push(row);
        assert!(history(&p, &l, &t, &raw(&pr), &raw(&replacement)).is_err());
        let mut failed = t;
        failed["outcome"] = json!("failed_or_stopped");
        assert!(history(&p, &l, &failed, &raw(&pr), &raw(&gr)).is_err());
    }
    #[test]
    fn producer_terminal_guard_rejects_pending_handoff_populated_cgroup_and_changed_history() {
        let (p, _, _, _, _, gr, _) = fixture();
        let name = string(&p, "guard_unit").unwrap();
        let f = json!({"downstream_actors":[],"authenticated_other_host_handoffs":[]});
        let v = json!({"pending_job_units":[],"cgroup":{"path":format!("/sys/fs/cgroup/system.slice/{name}"),"state":"absent"},
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
        context(&p, &f, &v).unwrap();
        for field in ["downstream_actors", "authenticated_other_host_handoffs"] {
            let mut bad = f.clone();
            bad[field] = json!([{}]);
            assert!(context(&p, &bad, &v).is_err());
        }
        let mut bad = v.clone();
        bad["pending_job_units"] = json!(["horizon-qualify-205-replacement.service"]);
        assert!(context(&p, &f, &bad).is_err());
        let mut bad = v;
        bad["cgroup"]["state"] = json!("populated");
        assert!(context(&p, &f, &bad).is_err());
        assert!(records_equal(&raw(&gr), &raw(&gr)).unwrap());
        let mut reversed = gr;
        reversed.reverse();
        assert!(!records_equal(
            &raw(&reversed),
            &raw(&reversed.iter().rev().cloned().collect::<Vec<_>>())
        )
        .unwrap());
    }
}
