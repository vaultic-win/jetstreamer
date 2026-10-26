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
    let rows = serde_json::Deserializer::from_slice(raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    failed_process_and_optional_start_limit_tail(current, &rows, start)
}
fn failed_process_and_optional_start_limit_tail(
    current: &Value,
    rows: &[Value],
    start: u64,
) -> Result<()> {
    let iid = s(current, "InvocationID")?;
    let active = rows
        .iter()
        .filter(|r| {
            r["INVOCATION_ID"] == iid
                && r["__REALTIME_TIMESTAMP"]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|v| v >= start)
        })
        .collect::<Vec<_>>();
    let positions = |event: &str| {
        active
            .iter()
            .enumerate()
            .filter(|(_, r)| r["MESSAGE_ID"] == event)
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
    };
    let starts = positions("39f53479d3a045ac8e11786248231fbf");
    let exits = positions("98e322203f7a4ed290d09fe03c09fe15");
    let failures = positions("d9b373ed55a64feb8242e02dbe79a49c");
    ensure!(
        starts.len() == 1
            && exits.len() == 1
            && matches!(failures.len(), 1 | 2)
            && starts[0] < exits[0]
            && exits[0] < failures[0],
        "historical 209 needs exactly one actual Started/process exit before genuine failure"
    );
    let exit = active[exits[0]];
    let status = s(current, "ExecMainStatus")?;
    ensure!(
        exit["EXIT_CODE"] == "exited"
            && exit["EXIT_STATUS"] == status
            && s(exit, "MESSAGE")?.starts_with(&format!(
                "{UNIT}: Main process exited, code=exited, status={status}/"
            )),
        "historical 209 actual process exit differs from failed current owner"
    );
    for &i in &failures {
        ensure!(
            active[i]["MESSAGE"] == format!("{UNIT}: Failed with result 'exit-code'."),
            "historical 209 failed-result message differs"
        );
    }
    ensure!(
        !active
            .iter()
            .skip(starts[0] + 1)
            .any(|r| r["MESSAGE_ID"] == "7d4958e842da4a758f6c1cdc7b36dcc5"),
        "historical 209 attempted another process start after the actual Started event"
    );
    let resource = |r: &Value| {
        r["MESSAGE_ID"] == "ae8f7b866b0347b9af31fe1c80b127c0"
            && r["MESSAGE"]
                .as_str()
                .is_some_and(|m| m.starts_with(&format!("{UNIT}: Consumed ")))
    };
    if failures.len() == 1 {
        ensure!(
            active.iter().skip(failures[0] + 1).all(|r| resource(r)),
            "historical 209 has an incomplete or foreign post-failure lifecycle tail"
        );
        return Ok(());
    }
    // Only the real start-limit tail can explain a second result without a new
    // Started/process exit. This does not exempt arbitrary duplicate failures.
    let schedules = positions("5eb03494b6584870a536b337290809b3");
    let limits = active
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r.get("MESSAGE_ID").is_none()
                && r["MESSAGE"] == format!("{UNIT}: Start request repeated too quickly.")
        })
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    let failed_starts = positions("be02cf6855d2428ba40df7e9d022f03d");
    ensure!(
        current["NRestarts"] == "2"
            && schedules.len() == 1
            && limits.len() == 1
            && failed_starts.len() == 1,
        "historical 209 duplicate result lacks the exact restart-counter-2 start-limit tail"
    );
    let schedule = schedules[0];
    let limit = limits[0];
    let failed_start = failed_starts[0];
    ensure!(
        failures[0] < schedule
            && schedule + 1 == limit
            && limit + 1 == failures[1]
            && failures[1] + 1 == failed_start
            && active[schedule]["N_RESTARTS"] == "2"
            && active[schedule]["MESSAGE"]
                == format!("{UNIT}: Scheduled restart job, restart counter is at 2.")
            && active[failed_start]["JOB_TYPE"] == "start"
            && active[failed_start]["JOB_RESULT"] == "failed"
            && s(active[failed_start], "MESSAGE")?
                .starts_with(&format!("Failed to start {UNIT} - "))
            && s(active[failed_start], "MESSAGE")?.ends_with('.'),
        "historical 209 start-limit event ordering/counter/job differs"
    );
    let mut resources = 0;
    for (i, r) in active.iter().enumerate().skip(failures[0] + 1) {
        if [schedule, limit, failures[1], failed_start].contains(&i) {
            continue;
        }
        ensure!(
            resource(r),
            "historical 209 start-limit tail contains another lifecycle event"
        );
        resources += 1;
    }
    ensure!(
        resources <= 2,
        "historical 209 start-limit tail has excessive resource records"
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
                {
                    let mut exit = row(
                        "1500000",
                        "exit",
                        "98e322203f7a4ed290d09fe03c09fe15",
                        &format!("{UNIT}: Main process exited, code=exited, status=1/FAILURE"),
                    );
                    exit["EXIT_CODE"] = json!("exited");
                    exit["EXIT_STATUS"] = json!("1");
                    exit
                },
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
    const ACTUAL: &[u8] = include_bytes!("fixtures/historical209-start-limit-tail.jsonl");
    fn actual_current() -> Value {
        let (mut current, _) = fixture();
        current["InvocationID"] = json!("9b604ab4bb274ccfbcca0c2301ba604e");
        current
    }
    #[test]
    fn historical209_genuine_start_limit_tail_retains_one_started_exit_and_two_typed_results() {
        authenticate(&actual_current(), ACTUAL).unwrap();
        let rows = serde_json::Deserializer::from_slice(ACTUAL)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let iid = actual_current()["InvocationID"]
            .as_str()
            .unwrap()
            .to_owned();
        let active = rows
            .iter()
            .filter(|r| r["INVOCATION_ID"] == iid)
            .collect::<Vec<_>>();
        assert_eq!(
            active
                .iter()
                .filter(|r| r["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf")
                .count(),
            1
        );
        assert_eq!(
            active
                .iter()
                .filter(|r| r["MESSAGE_ID"] == "98e322203f7a4ed290d09fe03c09fe15")
                .count(),
            1
        );
        assert_eq!(
            active
                .iter()
                .filter(|r| r["MESSAGE_ID"] == "d9b373ed55a64feb8242e02dbe79a49c")
                .count(),
            2
        );
    }
    #[test]
    fn historical209_start_limit_tail_rejects_unexplained_duplicates_missing_counter_and_wrong_jobs(
    ) {
        let rows = serde_json::Deserializer::from_slice(ACTUAL)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let current = actual_current();
        let iid = current["InvocationID"].as_str().unwrap();
        for event in [
            "5eb03494b6584870a536b337290809b3",
            "be02cf6855d2428ba40df7e9d022f03d",
            "98e322203f7a4ed290d09fe03c09fe15",
        ] {
            let bad = rows
                .iter()
                .filter(|r| !(r["INVOCATION_ID"] == iid && r["MESSAGE_ID"] == event))
                .cloned()
                .collect::<Vec<_>>();
            assert!(authenticate(&current, &raw(&bad)).is_err(), "{event}");
        }
        let tail = rows
            .iter()
            .position(|r| r["INVOCATION_ID"] == iid && r["N_RESTARTS"] == "2")
            .unwrap();
        for (at, key, value) in [
            (tail, "N_RESTARTS", json!("3")),
            (tail + 3, "JOB_RESULT", json!("done")),
            (tail + 1, "MESSAGE", json!("foreign")),
            (tail + 2, "INVOCATION_ID", json!("3".repeat(32))),
        ] {
            let mut bad = rows.clone();
            bad[at][key] = value;
            assert!(authenticate(&current, &raw(&bad)).is_err(), "{key}");
        }
        let mut bad = rows.clone();
        bad.swap(tail, tail + 1);
        assert!(authenticate(&current, &raw(&bad)).is_err());
        let mut bad = rows.clone();
        bad.push(rows[tail + 2].clone());
        assert!(authenticate(&current, &raw(&bad)).is_err());
        let mut third = rows.clone();
        let mut event = rows[tail + 2].clone();
        event["__REALTIME_TIMESTAMP"] = json!("1791084368793000");
        event["__CURSOR"] = json!("third-result");
        third.push(event);
        assert!(authenticate(&current, &raw(&third)).is_err());
        let (ordinary, mut bare) = fixture();
        let mut duplicate = bare.last().unwrap().clone();
        duplicate["__REALTIME_TIMESTAMP"] = json!("2200000");
        duplicate["__CURSOR"] = json!("unexplained-second-result");
        bare.push(duplicate);
        assert!(authenticate(&ordinary, &raw(&bare)).is_err());
        let mut restarted = current.clone();
        restarted["NRestarts"] = json!("3");
        assert!(authenticate(&restarted, ACTUAL).is_err());
        let mut later = rows.clone();
        let mut next = rows[tail].clone();
        next["INVOCATION_ID"] = json!("3".repeat(32));
        next["__REALTIME_TIMESTAMP"] = json!("1791084368793000");
        next["__CURSOR"] = json!("replacement");
        later.push(next);
        assert!(authenticate(&current, &raw(&later)).is_err());
    }
}
