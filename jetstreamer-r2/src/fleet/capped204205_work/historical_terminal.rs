//! Historical failed units retain restart counters. They are exempted only by
//! independent terminal ownership evidence, never by weakening live/idle gates.
use super::*;

fn candidate(name: &str, v: &Value) -> bool {
    v["Id"] == name
        && v["LoadState"] == "loaded"
        && v["ActiveState"] == "failed"
        && v["SubState"] == "failed"
        && v["MainPID"] == "0"
        && v["Result"] == "exit-code"
        && v["ExecMainStatus"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|s| s > 0)
        && v["NRestarts"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n > 0)
        && v["InvocationID"].as_str().is_some_and(id)
}
// This capability exists only for failed historical capped204/205 owners.
// Modern native223 failures retain their independent narrow release contract;
// no generic terminal helper or live-owner gate gains a modern failure branch.
struct HistoricalFailedOwner<'a> {
    name: &'a str,
    invocation: &'a str,
}
impl<'a> HistoricalFailedOwner<'a> {
    fn new(epoch: u64, name: &'a str, current: &'a Value) -> Result<Self> {
        ensure!(
            (204..=205).contains(&epoch)
                && capture::epoch_scope(epoch, name)
                && candidate(name, current),
            "historical failed-owner capability requires exact failed current state and capped epoch scope"
        );
        Ok(Self {
            name,
            invocation: string(current, "InvocationID")?,
        })
    }
    fn authenticate(&self, raw: &[u8]) -> Result<()> {
        // Shared identity, bounded row count, unique start, ordering, cursor,
        // UNIT/PID/UID/IID and no-replacement checks remain unchanged.
        let start = capture::manager_history(raw, self.name, self.invocation, false)?
            .checked_mul(1000)
            .context("historical terminal clock overflow")?;
        let mut failed = false;
        for line in std::str::from_utf8(raw)?.lines() {
            let row: Value = serde_json::from_str(line)?;
            let at = string(&row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
            failed |= at >= start
                && row["INVOCATION_ID"] == self.invocation
                && row["MESSAGE_ID"] == "d9b373ed55a64feb8242e02dbe79a49c"
                && row["MESSAGE"] == format!("{}: Failed with result 'exit-code'.", self.name);
        }
        ensure!(
            failed,
            "exact historical PID 1 failed-result event missing for unit {}, invocation {}",
            self.name,
            self.invocation
        );
        Ok(())
    }
}

fn excluded(p: &Value, actors: &[Actor], name: &str) -> bool {
    p["producer_unit"] == name || p["guard_unit"] == name || actors.iter().any(|a| a.unit == name)
}
fn proof(epoch: u64, name: &str, current: &Value, v: &Value) -> Result<()> {
    ensure!(
        candidate(name, current) && capture::epoch_scope(epoch, name),
        "historical terminal exception is not a failed no-PID owner"
    );
    ensure!(
        v["schema"] == "jetstreamer-capped204205-historical-terminal-owner-v1"
            && v["epoch"] == epoch
            && v["unit"] == name
            && v["current_unit"] == *current
            && v["manager_journal_complete"] == true
            && v["pending_owner_triggers_absent"] == true,
        "historical terminal proof differs from exact current census"
    );
    let pending = v["pending_job_units"]
        .as_array()
        .context("historical queued-job census missing")?;
    for job in pending {
        let job = job.as_str().context("invalid historical queued-job unit")?;
        ensure!(
            job != name && !capture::epoch_scope(epoch, job),
            "historical terminal owner has queued replacement work"
        );
    }
    let expected_path = Path::new("/sys/fs/cgroup/system.slice").join(name);
    ensure!(
        v["cgroup"]["path"].as_str() == expected_path.to_str()
            && (v["cgroup"]["state"] == "absent"
                || (v["cgroup"]["state"] == "unpopulated"
                    && canonical_digest(&v["cgroup"]["events_sha256"]))),
        "historical terminal cgroup remains populated or is unbound"
    );
    denied(v)
}
pub(super) fn capture(
    epoch: u64,
    p: &Value,
    actors: &[Actor],
    census: &BTreeMap<String, Value>,
    out: &Path,
) -> Result<Value> {
    let mut proofs = serde_json::Map::new();
    for (name, current) in census {
        if !capture::epoch_scope(epoch, name) || idle(current) || excluded(p, actors, name) {
            continue;
        }
        let invocation = current["InvocationID"].as_str().unwrap_or("<missing>");
        let v = (|| -> Result<Value> {
            ensure!(
                candidate(name, current),
                "unregistered historical owner is not positively terminal"
            );
            inactive_status::no_pending_owner_trigger(name, false)?;
            let jobs = ProcessCommand::new("/usr/bin/systemctl")
                .args([
                    "list-jobs",
                    "--no-legend",
                    "--no-pager",
                    "--plain",
                    "--full",
                ])
                .output()?;
            ensure!(jobs.status.success(), "historical queued-job query failed");
            let pending = inactive_status::queued_job_units(&jobs.stdout)?;
            let raw = capture::journal(name)?;
            HistoricalFailedOwner::new(epoch, name, current)?.authenticate(&raw)?;
            let journal_path = out.join(format!(
                "historical-{}-manager.json",
                string(current, "InvocationID")?
            ));
            // Reuse sealed bounded metadata publication, with the journal encoded as
            // JSON text so the exact durable raw bytes are recovered independently.
            let journal_value = json!({"raw":std::str::from_utf8(&raw)?});
            capture::write_sealed(&journal_path, &journal_value)?;
            let v = json!({"schema":"jetstreamer-capped204205-historical-terminal-owner-v1",
                "epoch":epoch,"unit":name,"current_unit":current,"manager_journal_complete":true,
                "manager_journal":{"path":journal_path,"sha256":capture::file_sha(&journal_path)?},
                "pending_owner_triggers_absent":true,"pending_job_units":pending,"cgroup":capture::group(name)?,
                "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
            proof(epoch, name, current, &v)?;
            Ok(v)
        })()
        .with_context(|| {
            format!("historical terminal capture for epoch {epoch}, unit {name}, invocation {invocation}")
        })?;
        proofs.insert(name.clone(), v);
    }
    Ok(Value::Object(proofs))
}
pub(super) fn validate(
    epoch: u64,
    p: &Value,
    actors: &[Actor],
    frame: &Value,
    census: &BTreeMap<String, Value>,
) -> Result<BTreeSet<String>> {
    let Some(proofs) = frame.get("historical_terminal_owners") else {
        return Ok(BTreeSet::new());
    };
    let mut accepted = BTreeSet::new();
    for (name, v) in proofs
        .as_object()
        .context("invalid historical terminal proof map")?
    {
        ensure!(
            !excluded(p, actors, name),
            "historical exception cannot cover actual producer/guard/downstream"
        );
        let current = census
            .get(name)
            .context("historical terminal owner missing from current census")?;
        proof(epoch, name, current, v)?;
        let journal =
            evidence::bound(&serde_json::from_value(v["manager_journal"].clone())?, true)?;
        HistoricalFailedOwner::new(epoch, name, current)?
            .authenticate(string(&journal, "raw")?.as_bytes())?;
        accepted.insert(name.clone());
    }
    Ok(accepted)
}
pub(super) fn current(frame: &Value, census: &BTreeMap<String, Value>) -> Result<()> {
    if let Some(proofs) = frame.get("historical_terminal_owners") {
        for (name, v) in proofs.as_object().context("invalid historical proof map")? {
            ensure!(
                census.get(name) == Some(&v["current_unit"]),
                "historical terminal identity changed"
            );
            inactive_status::no_pending_owner_trigger(name, false)?;
            ensure!(
                capture::group(name)? == v["cgroup"],
                "historical terminal cgroup changed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn failed_owner(name: &str, iid: &str) -> Value {
        json!({"Id":name,"LoadState":"loaded","ActiveState":"failed","SubState":"failed",
            "MainPID":"0","Result":"exit-code","ExecMainStatus":"1","NRestarts":"2","InvocationID":iid})
    }
    fn scoped_terminal(raw: &[u8], name: &str, iid: &str) -> Result<()> {
        let current = failed_owner(name, iid);
        HistoricalFailedOwner::new(205, name, &current)?.authenticate(raw)
    }
    #[test]
    fn restart_history_requires_exact_terminal_ownership_and_no_queued_job() {
        let name = "horizon-qualify-205-replay.service";
        let owner = json!({"Id":name,"LoadState":"loaded","ActiveState":"failed","SubState":"failed",
            "MainPID":"0","Result":"exit-code","ExecMainStatus":"1","NRestarts":"2","InvocationID":"1".repeat(32)});
        let value = json!({"schema":"jetstreamer-capped204205-historical-terminal-owner-v1","epoch":205,"unit":name,
            "current_unit":owner,"manager_journal_complete":true,"pending_owner_triggers_absent":true,"pending_job_units":[],
            "cgroup":{"state":"absent","path":format!("/sys/fs/cgroup/system.slice/{name}")},
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
        assert!(!idle(&owner));
        proof(205, name, &owner, &value).unwrap();
        for (key, changed) in [
            ("ActiveState", "active"),
            ("SubState", "auto-restart"),
            ("MainPID", "42"),
            ("Result", "success"),
            ("InvocationID", ""),
        ] {
            let mut bad_owner = owner.clone();
            bad_owner[key] = json!(changed);
            let mut bad = value.clone();
            bad["current_unit"] = bad_owner.clone();
            assert!(proof(205, name, &bad_owner, &bad).is_err(), "{key}");
        }
        let mut queued = value.clone();
        queued["pending_job_units"] = json!([name]);
        assert!(proof(205, name, &owner, &queued).is_err());
        let mut populated = value.clone();
        populated["cgroup"]["state"] = json!("populated");
        assert!(proof(205, name, &owner, &populated).is_err());
        let mut changed = value.clone();
        changed["current_unit"]["NRestarts"] = json!("3");
        assert!(proof(205, name, &owner, &changed).is_err());
        let p = json!({"producer_unit":name,"guard_unit":"guard"});
        assert!(excluded(&p, &[], name));
    }
    #[test]
    fn historical_terminal_requires_the_exact_pid1_invocation_end() {
        let name = "horizon-qualify-205-replay.service";
        let iid = "1".repeat(32);
        let row = |time: &str, cursor: &str, id: &str, message_id: &str, message: &str| {
            json!({
                "_PID":"1","_UID":"0","UNIT":name,"__REALTIME_TIMESTAMP":time,
                "__CURSOR":cursor,"INVOCATION_ID":id,"MESSAGE_ID":message_id,"MESSAGE":message
            })
        };
        let started = row(
            "1000000",
            "a",
            &iid,
            "39f53479d3a045ac8e11786248231fbf",
            "Started historical worker.",
        );
        let failed = row(
            "2000000",
            "b",
            &iid,
            "d9b373ed55a64feb8242e02dbe79a49c",
            &format!("{name}: Failed with result 'exit-code'."),
        );
        let raw = format!("{started}\n{failed}\n");
        scoped_terminal(raw.as_bytes(), name, &iid).unwrap();
        assert!(scoped_terminal(format!("{started}\n").as_bytes(), name, &iid).is_err());
        let replacement = row(
            "3000000",
            "c",
            &"2".repeat(32),
            "39f53479d3a045ac8e11786248231fbf",
            "Started replacement.",
        );
        assert!(scoped_terminal(format!("{raw}{replacement}\n").as_bytes(), name, &iid).is_err());
        assert!(scoped_terminal(raw.as_bytes(), name, &"2".repeat(32)).is_err());
    }
    #[test]
    fn historical205_genuine_failed_result_is_distinct_from_failed_to_start() {
        let unit = "horizon-qualify-205-replay.service";
        let iid = "e32e088b878b41fe8df96c4ba8415940";
        let row = |at: &str, cursor: &str, event: &str, message: &str| {
            json!({"_PID":"1","_UID":"0","UNIT":unit,"INVOCATION_ID":iid,
                "__REALTIME_TIMESTAMP":at,"__CURSOR":cursor,"MESSAGE_ID":event,"MESSAGE":message})
        };
        // Actual PID 1 event shapes, IDs, invocation and times from the preserved
        // historical 205 failure. Failed-to-start also followed the result event;
        // it must neither replace that result nor count as terminal by itself.
        let started = row(
            "1791078028570847",
            "actual205-start",
            "39f53479d3a045ac8e11786248231fbf",
            "Started horizon-qualify-205-replay.service - Horizon epoch 205 focused v1.6.16 canonical checkpoint replay.",
        );
        let exited = row(
            "1791078723913707",
            "actual205-exit",
            "98e322203f7a4ed290d09fe03c09fe15",
            "horizon-qualify-205-replay.service: Main process exited, code=exited, status=1/FAILURE",
        );
        let failed = row(
            "1791078723914139",
            "actual205-result",
            "d9b373ed55a64feb8242e02dbe79a49c",
            "horizon-qualify-205-replay.service: Failed with result 'exit-code'.",
        );
        let failed_start = row(
            "1791078754042136",
            "actual205-start-limit",
            "be02cf6855d2428ba40df7e9d022f03d",
            "Failed to start horizon-qualify-205-replay.service - Horizon epoch 205 focused v1.6.16 canonical checkpoint replay.",
        );
        let raw = format!("{started}\n{exited}\n{failed}\n{failed_start}\n");
        scoped_terminal(raw.as_bytes(), unit, iid).unwrap();
        let missing = format!("{started}\n{exited}\n{failed_start}\n");
        let error = scoped_terminal(missing.as_bytes(), unit, iid).unwrap_err();
        assert!(error.to_string().contains(unit) && error.to_string().contains(iid));
        let mut false_result = failed.clone();
        false_result["MESSAGE_ID"] = json!("be02cf6855d2428ba40df7e9d022f03d");
        assert!(
            scoped_terminal(format!("{started}\n{false_result}\n").as_bytes(), unit, iid).is_err()
        );
        let mut false_start = failed_start.clone();
        false_start["MESSAGE_ID"] = json!("d9b373ed55a64feb8242e02dbe79a49c");
        assert!(
            scoped_terminal(format!("{started}\n{false_start}\n").as_bytes(), unit, iid).is_err()
        );
        for (key, bad) in [
            ("_PID", "2"),
            ("_UID", "1000"),
            ("UNIT", "foreign.service"),
            ("INVOCATION_ID", "22222222222222222222222222222222"),
        ] {
            let mut forged = failed.clone();
            forged[key] = json!(bad);
            assert!(
                scoped_terminal(format!("{started}\n{forged}\n").as_bytes(), unit, iid).is_err(),
                "{key}"
            );
        }
        assert!(scoped_terminal(format!("{failed}\n").as_bytes(), unit, iid).is_err());
    }
    #[test]
    fn historical_failure_scope_never_promotes_modern_native223_or_live_owners() {
        let name = "horizon-qualify-205-replay.service";
        let iid = "e32e088b878b41fe8df96c4ba8415940";
        let good = failed_owner(name, iid);
        HistoricalFailedOwner::new(205, name, &good).unwrap();
        for (key, value) in [
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("MainPID", "42"),
            ("Result", "success"),
            ("NRestarts", "0"),
            ("ExecMainStatus", "0"),
            ("InvocationID", ""),
        ] {
            let mut bad = good.clone();
            bad[key] = json!(value);
            assert!(
                HistoricalFailedOwner::new(205, name, &bad).is_err(),
                "{key}"
            );
        }
        let native = "horizon-qualify-223-v1620-root-prefix-resource-full-v1.service";
        let native_state = failed_owner(native, iid);
        assert!(HistoricalFailedOwner::new(205, native, &native_state).is_err());
        assert!(HistoricalFailedOwner::new(223, native, &native_state).is_err());
        assert!(HistoricalFailedOwner::new(203, name, &good).is_err());
    }
}
