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
        capture::manager_terminal(&raw, name, string(current, "InvocationID")?)?;
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
        capture::manager_terminal(
            string(&journal, "raw")?.as_bytes(),
            name,
            string(current, "InvocationID")?,
        )?;
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
            "be02cf6855d2428ba40df7e9d022f03d",
            &format!("{name}: Failed with result 'exit-code'."),
        );
        let raw = format!("{started}\n{failed}\n");
        capture::manager_terminal(raw.as_bytes(), name, &iid).unwrap();
        assert!(capture::manager_terminal(format!("{started}\n").as_bytes(), name, &iid).is_err());
        let replacement = row(
            "3000000",
            "c",
            &"2".repeat(32),
            "39f53479d3a045ac8e11786248231fbf",
            "Started replacement.",
        );
        assert!(
            capture::manager_terminal(format!("{raw}{replacement}\n").as_bytes(), name, &iid)
                .is_err()
        );
        assert!(capture::manager_terminal(raw.as_bytes(), name, &"2".repeat(32)).is_err());
    }
}
