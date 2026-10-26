//! A single failed historical qualifier can leave the completed Full209 census.
//! This does not release native223, a live owner, or any archive/publication gate.
use super::*;
const UNIT: &str = "horizon-qualify-209-replay.service";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    current_unit: Value,
    manager_journal: BoundFile,
}
impl Proof {
    pub(super) fn covers(&self, name: &str, current: &Value) -> bool {
        name == UNIT && current == &self.current_unit && candidate(current)
    }
    pub(super) fn validate_current(&self, census: &BTreeMap<String, Value>) -> Result<()> {
        let current = census
            .get(UNIT)
            .context("historical 209 qualifier omitted from complete census")?;
        ensure!(
            self.covers(UNIT, current),
            "historical 209 qualifier differs from exact failed owner"
        );
        let saved = sealed(&self.manager_journal, 8 << 20)?;
        authenticate(current, &saved)?;
        let actual = ownership::manager(UNIT)?;
        authenticate(current, &actual)?;
        ensure!(
            ownership::manager_records_equal(&saved, &actual)?,
            "historical 209 PID 1 history changed"
        );
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
            "historical 209 queued-job census unavailable"
        );
        let pending = inactive_status::queued_job_units(&jobs.stdout)?;
        no_pending(&pending)?;
        inactive_status::no_pending_owner_trigger(UNIT, false)?;
        capped204205_work::empty_terminal_cgroup(UNIT)?;
        // Re-read after history/cgroup checks. A replacement cannot borrow the
        // independently bound failed invocation while cleanup is in progress.
        ensure!(
            unit(UNIT)? == *current,
            "historical 209 owner changed during cleanup"
        );
        Ok(())
    }
}
fn no_pending(pending: &[&str]) -> Result<()> {
    ensure!(
        !pending.iter().any(|name| name
            .split(|c: char| !c.is_ascii_digit())
            .any(|part| part == "209")),
        "historical 209 has queued replacement work"
    );
    Ok(())
}
fn candidate(current: &Value) -> bool {
    current["Id"] == UNIT
        && current["LoadState"] == "loaded"
        && current["ActiveState"] == "failed"
        && current["SubState"] == "failed"
        && current["MainPID"] == "0"
        && current["Result"] == "exit-code"
        && current["InvocationID"].as_str().is_some_and(id)
        && current["ExecMainStatus"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|n| n > 0)
        && current["NRestarts"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some()
}
fn authenticate(current: &Value, raw: &[u8]) -> Result<()> {
    ensure!(
        candidate(current) && raw.len() <= 8 << 20,
        "historical 209 failed state or journal bound differs"
    );
    let iid = s(current, "InvocationID")?;
    let start = capped204205_work::exact_manager_history(raw, UNIT, iid)?
        .checked_mul(1000)
        .context("historical 209 start clock overflow")?;
    let mut failures = 0;
    for line in std::str::from_utf8(raw)?.lines() {
        let row: Value = serde_json::from_str(line)?;
        let at = s(&row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        if at >= start
            && row["INVOCATION_ID"] == iid
            && row["MESSAGE_ID"] == "d9b373ed55a64feb8242e02dbe79a49c"
            && row["MESSAGE"] == format!("{UNIT}: Failed with result 'exit-code'.")
        {
            ensure!(at > start, "historical 209 failure precedes start");
            failures += 1;
        }
    }
    ensure!(
        failures == 1,
        "exact historical 209 PID 1 failure missing or duplicated"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Vec<Value>) {
        let iid = "1".repeat(32);
        let current = json!({"Id":UNIT,"LoadState":"loaded","ActiveState":"failed","SubState":"failed","MainPID":"0",
            "Result":"exit-code","ExecMainStatus":"1","NRestarts":"2","InvocationID":iid});
        let row = |time: &str, cursor: &str, event: &str, message: &str| {
            json!({"_PID":"1","_UID":"0","UNIT":UNIT,
            "INVOCATION_ID":iid,"__CURSOR":cursor,"__REALTIME_TIMESTAMP":time,"MESSAGE_ID":event,"MESSAGE":message})
        };
        (
            current,
            vec![
                row(
                    "1000000",
                    "a",
                    "39f53479d3a045ac8e11786248231fbf",
                    "Started qualifier.",
                ),
                row(
                    "2000000",
                    "b",
                    "d9b373ed55a64feb8242e02dbe79a49c",
                    &format!("{UNIT}: Failed with result 'exit-code'."),
                ),
            ],
        )
    }
    fn raw(rows: &[Value]) -> Vec<u8> {
        rows.iter()
            .map(|v| serde_json::to_string(v).unwrap() + "\n")
            .collect::<String>()
            .into_bytes()
    }
    #[test]
    fn historical209_cleanup_accepts_only_bound_failed_qualifier() {
        let (current, rows) = fixture();
        authenticate(&current, &raw(&rows)).unwrap();
        let proof = Proof {
            current_unit: current.clone(),
            manager_journal: BoundFile {
                path: "/fixture/journal".into(),
                sha256: "a".repeat(64),
            },
        };
        assert!(proof.covers(UNIT, &current));
        for (key, value) in [
            ("Id", "horizon-qualify-223-replay.service"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("MainPID", "42"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("InvocationID", ""),
            ("NRestarts", "unknown"),
        ] {
            let mut bad = current.clone();
            bad[key] = json!(value);
            assert!(authenticate(&bad, &raw(&rows)).is_err(), "{key}");
            assert!(!proof.covers(UNIT, &bad), "{key}");
        }
        assert!(!proof.covers("horizon-full-209-new.service", &current));
    }
    #[test]
    fn historical209_cleanup_keeps_other_epochs_and_queued_replacements_protected() {
        no_pending(&[]).unwrap();
        no_pending(&["healthy207.service"]).unwrap();
        for name in [
            UNIT,
            "horizon-full-209-new.service",
            "horizon-guard-209-next.timer",
        ] {
            assert!(no_pending(&[name]).is_err(), "{name}");
        }
        let (current, rows) = fixture();
        for name in [
            "horizon-qualify-204-replay.service",
            "horizon-qualify-205-replay.service",
            "horizon-qualify-223-replay.service",
        ] {
            let mut foreign = current.clone();
            foreign["Id"] = json!(name);
            assert!(authenticate(&foreign, &raw(&rows)).is_err(), "{name}");
        }
    }
    #[test]
    fn historical209_cleanup_rejects_missing_forged_reordered_and_replacement_history() {
        let (current, rows) = fixture();
        assert!(authenticate(&current, &raw(&rows[..1])).is_err());
        for key in [
            "_PID",
            "_UID",
            "UNIT",
            "INVOCATION_ID",
            "MESSAGE",
            "MESSAGE_ID",
            "__CURSOR",
        ] {
            let mut bad = rows.clone();
            bad[1][key] = json!("foreign");
            // A fresh cursor is valid; duplication is the rejected case.
            if key == "__CURSOR" {
                bad[1][key] = bad[0][key].clone();
            }
            assert!(authenticate(&current, &raw(&bad)).is_err(), "{key}");
        }
        let mut reversed = rows.clone();
        reversed.reverse();
        assert!(authenticate(&current, &raw(&reversed)).is_err());
        let mut replacement = rows.clone();
        let mut row = rows[0].clone();
        row["INVOCATION_ID"] = json!("2".repeat(32));
        row["__REALTIME_TIMESTAMP"] = json!("3000000");
        row["__CURSOR"] = json!("c");
        replacement.push(row);
        assert!(authenticate(&current, &raw(&replacement)).is_err());
        assert!(authenticate(
            &current,
            &raw(&[rows[0].clone(), rows[1].clone(), rows[1].clone()])
        )
        .is_err());
    }
}
