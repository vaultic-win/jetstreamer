//! A oneshot's current IID may precede its receipt or already be cleared.
//! Select a completed invocation from PID1 history, never by mtime or fallback.
use super::super::*;
const START: &str = "7d4958e842da4a758f6c1cdc7b36dcc5";
const SUCCESS: &str = "7ad2d189f7e94e70a38c781354912448";
const FINISHED: &str = "39f53479d3a045ac8e11786248231fbf";
pub(super) struct Selection {
    pub binding: BoundFile,
    pub receipt: Value,
    pub history: Value,
}
fn clock(r: &Value) -> Result<u64> {
    Ok(r["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("guard manager timestamp missing")?
        .parse()?)
}
fn iid(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn manager(r: &Value, name: &str) -> bool {
    r["_PID"] == "1" && r["_UID"] == "0" && r["UNIT"] == name
}
fn latest_completed<'a>(rows: &'a [Value], name: &str) -> Result<&'a Value> {
    let mut terminal = rows
        .iter()
        .filter(|r| {
            manager(r, name)
                && (r["MESSAGE_ID"] == FINISHED
                    || r.get("JOB_RESULT").is_some_and(|v| v != "done")
                    || r.get("RESULT").is_some_and(|v| v != "success")
                    || r.get("EXIT_CODE").is_some()
                    || r["MESSAGE"].as_str().is_some_and(|s| {
                        s.starts_with(&format!("{name}: Failed"))
                            || s.starts_with(&format!("Failed {name}"))
                    }))
        })
        .map(|r| Ok((clock(r)?, r)))
        .collect::<Result<Vec<_>>>()?;
    terminal.sort_by_key(|(t, _)| *t);
    let (last, row) = terminal
        .last()
        .context("guard has no completed manager invocation")?;
    ensure!(
        terminal.iter().filter(|(t, _)| t == last).count() == 1,
        "ambiguous guard terminal manager records"
    );
    ensure!(
        row["MESSAGE_ID"] == FINISHED
            && row["JOB_RESULT"] == "done"
            && row["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with(&format!("Finished {name} -"))),
        "latest guard invocation failed; do not fall back to an older success"
    );
    Ok(row)
}
fn terminal_history(
    rows: &[Value],
    name: &str,
    selected: &str,
    receipt: &Value,
    minimum: u64,
    now: u64,
    age: u64,
) -> Result<Value> {
    ensure!(
        iid(selected) && receipt["guard_invocation_id"] == selected,
        "guard receipt invocation differs"
    );
    let sample = receipt["recorded_unix_seconds"]
        .as_u64()
        .context("guard receipt clock")?;
    ensure!(
        sample >= minimum && sample <= now && now - sample <= age,
        "guard receipt is stale or backdated"
    );
    let own = rows
        .iter()
        .filter(|r| {
            (manager(r, name) && r["INVOCATION_ID"] == selected)
                || (r["_SYSTEMD_UNIT"] == name && r["_SYSTEMD_INVOCATION_ID"] == selected)
        })
        .collect::<Vec<_>>();
    let one = |pred: &dyn Fn(&Value) -> bool| -> Result<&Value> {
        let v = own.iter().copied().filter(|r| pred(r)).collect::<Vec<_>>();
        ensure!(
            v.len() == 1,
            "missing/duplicate guard invocation history event"
        );
        Ok(v[0])
    };
    let start = one(&|r| {
        manager(r, name)
            && r["MESSAGE_ID"] == START
            && r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with(&format!("Starting {name} -")))
    })?;
    let stdout = one(&|r| {
        r["_UID"] == "0"
            && r["_PID"] != "1"
            && r["_SYSTEMD_UNIT"] == name
            && r["_SYSTEMD_INVOCATION_ID"] == selected
            && r["MESSAGE"]
                .as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .is_some_and(|v| v == *receipt)
    })?;
    let done = one(&|r| {
        manager(r, name)
            && r["MESSAGE_ID"] == SUCCESS
            && r["MESSAGE"] == format!("{name}: Deactivated successfully.")
    })?;
    let finish = one(&|r| {
        manager(r, name)
            && r["MESSAGE_ID"] == FINISHED
            && r["JOB_RESULT"] == "done"
            && r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with(&format!("Finished {name} -")))
    })?;
    let (a, b, c, d) = (clock(start)?, clock(stdout)?, clock(done)?, clock(finish)?);
    ensure!(
        a <= b
            && b <= c
            && c <= d
            && d / 1_000_000 <= now
            && a / 1_000_000 <= sample
            && sample <= b / 1_000_000,
        "guard manager/receipt clocks out of order"
    );
    let boot = start["_BOOT_ID"]
        .as_str()
        .filter(|s| iid(s))
        .context("guard boot identity missing")?;
    ensure!(
        [stdout, done, finish].iter().all(|r| r["_BOOT_ID"] == boot),
        "guard history crosses boot identities"
    );
    // Very short oneshots can exit before journald reads /proc: _EXE and
    // _CMDLINE may be absent. PID1's full successful-job command plus the
    // independently checked current immutable ExecStart remains authoritative.
    let finished_command = finish["MESSAGE"]
        .as_str()
        .context("guard finish message")?
        .strip_prefix(&format!("Finished {name} - [systemd-run] "))
        .and_then(|s| s.strip_suffix('.'))
        .context("guard manager did not preserve the full command")?;
    let exe = finished_command
        .split_whitespace()
        .next()
        .context("guard manager executable")?;
    let expected = format!(
        "{exe} {} --plan-sha256 {} --self-sha256 {}",
        receipt["plan"].as_str().context("guard plan path")?,
        receipt["plan_sha256"].as_str().context("guard plan hash")?,
        receipt["guard_sha256"]
            .as_str()
            .context("guard executable hash")?
    );
    ensure!(
        finished_command == expected
            && stdout.get("_EXE").is_none_or(|v| v.as_str() == Some(exe))
            && stdout
                .get("_CMDLINE")
                .is_none_or(|v| v.as_str() == Some(expected.as_str())),
        "guard manager/kernel command does not bind its exact plan and executable"
    );
    let expected_exec_start = format!(
        "{{ path={exe} ; argv[]={expected} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
    );
    Ok(
        json!({"schema":"jetstreamer-completed-guard-history-v1","unit":name,"guard_invocation_id":selected,"minimum_sampled_seconds":minimum,"selected_unix_seconds":now,"maximum_age_seconds":age,"executable":exe,"expected_exec_start":expected_exec_start,"events":[start,stdout,done,finish]}),
    )
}
fn no_stop(root: &Path) -> Result<()> {
    for name in ["stop-intent.json", "stop-completion.json"] {
        ensure!(
            fs::symlink_metadata(root.join(name))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "guard has a stop intent or completion"
        );
    }
    Ok(())
}
pub(super) fn validate_history_events(history: &Value, receipt: &Value) -> Result<()> {
    ensure!(
        history["schema"] == "jetstreamer-completed-guard-history-v1",
        "guard history schema differs"
    );
    let name = history["unit"].as_str().context("guard history unit")?;
    let selected = history["guard_invocation_id"]
        .as_str()
        .context("guard history IID")?;
    let rows = history["events"]
        .as_array()
        .context("guard history events")?;
    let expected = terminal_history(
        rows,
        name,
        selected,
        receipt,
        history["minimum_sampled_seconds"]
            .as_u64()
            .context("guard history minimum")?,
        history["selected_unix_seconds"]
            .as_u64()
            .context("guard history time")?,
        history["maximum_age_seconds"]
            .as_u64()
            .context("guard history age")?,
    )?;
    ensure!(
        *history == expected,
        "guard history is not the exact selected invocation"
    );
    Ok(())
}
pub(super) fn validate_selected_events(
    history: &Value,
    receipt: &Value,
    rows: &[Value],
) -> Result<()> {
    validate_history_events(history, receipt)?;
    let name = history["unit"].as_str().context("guard history unit")?;
    let latest = latest_completed(rows, name)?;
    ensure!(
        history["events"]
            .as_array()
            .context("guard history events")?
            .last()
            == Some(latest),
        "guard history is not the latest completed manager fire"
    );
    Ok(())
}
pub(super) fn validate_history(history: &Value, receipt: &Value) -> Result<()> {
    validate_history_events(history, receipt)?;
    let exe = Path::new(
        history["executable"]
            .as_str()
            .context("guard history executable")?,
    );
    let meta = fs::symlink_metadata(exe)?;
    ensure!(
        exe.is_absolute()
            && exe.canonicalize()? == exe
            && meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o222 == 0,
        "guard executable is not immutable"
    );
    ensure!(
        private157::file_binding(exe)?["sha256"] == receipt["guard_sha256"],
        "guard history executable hash differs"
    );
    Ok(())
}
pub(super) fn select(
    name: &str,
    root: &Path,
    minimum: u64,
    now: u64,
    age: u64,
) -> Result<Selection> {
    ensure!(
        name.ends_with(".service")
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && age > 0
            && age <= 1800,
        "invalid guard history scope"
    );
    let m = fs::symlink_metadata(root)?;
    ensure!(
        root.is_absolute()
            && root.canonicalize()? == root
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0,
        "guard receipt directory is not root-private"
    );
    no_stop(root)?;
    let since = now.saturating_sub(age).saturating_sub(60);
    let output = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            name,
            "--output=json",
            "--no-pager",
            "--lines=4096",
            "--since",
            &format!("@{since}"),
            "--until",
            &format!("@{now}"),
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 16 << 20,
        "guard history unavailable or oversized"
    );
    let rows = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "guard history row bounds"
    );
    let finish = latest_completed(&rows, name)?;
    let selected = finish["INVOCATION_ID"]
        .as_str()
        .filter(|s| iid(s))
        .context("guard completed IID invalid")?;
    let path = root.join(format!("sample-{selected}.json"));
    let rm = fs::symlink_metadata(&path)?;
    ensure!(
        rm.is_file() && rm.uid() == 0 && rm.nlink() == 1 && rm.mode() & 0o077 == 0,
        "guard receipt privacy/ownership differs"
    );
    let binding: BoundFile = serde_json::from_value(private157::file_binding(&path)?)?;
    let receipt = bound_json(&binding)?;
    let history = terminal_history(&rows, name, selected, &receipt, minimum, now, age)?;
    validate_history(&history, &receipt)?;
    let current = unit(name)?;
    ensure!(
        current["Id"] == name
            && current["LoadState"] == "loaded"
            && current["ActiveState"] != "failed"
            && current["Result"] == "success"
            && current["NRestarts"] == "0"
            && pipeline_status::same_exec_start(
                history["expected_exec_start"]
                    .as_str()
                    .context("guard selected command")?,
                current["ExecStart"]
                    .as_str()
                    .context("guard current command")?
            ),
        "guard currently failed or command changed after history selection"
    );
    no_stop(root)?;
    ensure!(
        private157::file_binding(&path)? == private157::binding(&binding),
        "guard receipt changed after history selection"
    );
    Ok(Selection {
        binding,
        receipt,
        history,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root-only read-only check of the three exact host guard journals/receipts; no resource sample"]
    fn host_old_guards_have_completed_manager_bound_receipts() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (index, name, root) in [
            (
                0,
                "horizon-ownroot225-protective-v1.service",
                "/var/lib/jetstreamer/horizon-ownroot225-rebased-guard-receipts-v1",
            ),
            (
                1,
                "horizon-prefix205-protective-v1.service",
                "/var/lib/jetstreamer/horizon-prefix205-guard-receipts-v1",
            ),
            (
                2,
                "horizon-prefix204-protective-v1.service",
                "/var/lib/jetstreamer/horizon-prefix204-guard-receipts-v1",
            ),
        ] {
            let selected =
                select(name, Path::new(root), now.saturating_sub(120), now, 120).unwrap();
            publication203::guard(&selected.receipt, index, now.saturating_sub(120), now).unwrap();
            println!(
                "selected {} {}",
                name, selected.receipt["guard_invocation_id"]
            );
        }
    }
    fn fixture() -> (Vec<Value>, Value) {
        let n = "horizon-guard-test.service";
        let id = "a".repeat(32);
        let boot = "b".repeat(32);
        let receipt = json!({"guard_invocation_id":id,"recorded_unix_seconds":100,"plan":"/sealed/plan","plan_sha256":"c".repeat(64),"guard_sha256":"d".repeat(64)});
        let mgr = |mid: &str, time: &str, msg: String| json!({"_PID":"1","_UID":"0","UNIT":n,"INVOCATION_ID":id,"_BOOT_ID":boot,"MESSAGE_ID":mid,"__REALTIME_TIMESTAMP":time,"MESSAGE":msg});
        let start = mgr(START, "100000000", format!("Starting {n} - guard..."));
        let stdout = json!({"_PID":"42","_UID":"0","_SYSTEMD_UNIT":n,"_SYSTEMD_INVOCATION_ID":id,"_BOOT_ID":boot,"__REALTIME_TIMESTAMP":"101000000","MESSAGE":receipt.to_string(),"_EXE":"/sealed/guard","_CMDLINE":format!("/sealed/guard /sealed/plan --plan-sha256 {} --self-sha256 {}","c".repeat(64),"d".repeat(64))});
        let done = mgr(
            SUCCESS,
            "102000000",
            format!("{n}: Deactivated successfully."),
        );
        let mut finish = mgr(
            FINISHED,
            "103000000",
            format!(
                "Finished {n} - [systemd-run] /sealed/guard /sealed/plan --plan-sha256 {} --self-sha256 {}.",
                "c".repeat(64),
                "d".repeat(64)
            ),
        );
        finish["JOB_RESULT"] = json!("done");
        (vec![start, stdout, done, finish], receipt)
    }
    #[test]
    fn currently_starting_unwritten_iid_does_not_hide_last_completed_success() {
        let (mut rows, r) = fixture();
        let mut new = rows[0].clone();
        new["INVOCATION_ID"] = json!("e".repeat(32));
        new["__REALTIME_TIMESTAMP"] = json!("104000000");
        rows.push(new);
        let done = latest_completed(&rows, "horizon-guard-test.service").unwrap();
        assert_eq!(done["INVOCATION_ID"], "a".repeat(32));
        terminal_history(
            &rows,
            "horizon-guard-test.service",
            &"a".repeat(32),
            &r,
            99,
            105,
            120,
        )
        .unwrap();
    }
    #[test]
    fn later_failed_guard_never_falls_back_to_an_older_success() {
        let (mut rows, _) = fixture();
        let mut bad = rows[3].clone();
        bad["INVOCATION_ID"] = json!("e".repeat(32));
        bad["__REALTIME_TIMESTAMP"] = json!("104000000");
        bad["JOB_RESULT"] = json!("failed");
        rows.push(bad);
        assert!(latest_completed(&rows, "horizon-guard-test.service").is_err());
    }
    #[test]
    fn short_oneshot_metadata_loss_requires_complete_pid1_command_and_rejects_truncation() {
        let (mut rows, r) = fixture();
        rows[1].as_object_mut().unwrap().remove("_EXE");
        rows[1].as_object_mut().unwrap().remove("_CMDLINE");
        terminal_history(
            &rows,
            "horizon-guard-test.service",
            &"a".repeat(32),
            &r,
            99,
            105,
            120,
        )
        .unwrap();
        let mut bad = rows.clone();
        bad[3]["MESSAGE"] = json!("Finished horizon-guard-test.service - truncated.");
        assert!(
            terminal_history(
                &bad,
                "horizon-guard-test.service",
                &"a".repeat(32),
                &r,
                99,
                105,
                120
            )
            .is_err()
        );
        rows[1]["_EXE"] = json!("/foreign/guard");
        assert!(
            terminal_history(
                &rows,
                "horizon-guard-test.service",
                &"a".repeat(32),
                &r,
                99,
                105,
                120
            )
            .is_err()
        );
    }
    #[test]
    fn history_requires_exact_pid1_manager_success_stdout_iid_plan_and_freshness() {
        let (rows, r) = fixture();
        let call = |v: &[Value], p: &Value, min: u64, now: u64| {
            terminal_history(
                v,
                "horizon-guard-test.service",
                &"a".repeat(32),
                p,
                min,
                now,
                120,
            )
        };
        call(&rows, &r, 99, 105).unwrap();
        assert!(call(&rows, &r, 101, 105).is_err());
        assert!(call(&rows, &r, 99, 221).is_err());
        for index in 0..4 {
            let mut bad = rows.clone();
            bad.remove(index);
            assert!(call(&bad, &r, 99, 105).is_err());
            let mut bad = rows.clone();
            bad.push(rows[index].clone());
            assert!(call(&bad, &r, 99, 105).is_err());
        }
        for (index, key) in [
            (0, "_PID"),
            (0, "_UID"),
            (0, "INVOCATION_ID"),
            (1, "_UID"),
            (1, "_SYSTEMD_INVOCATION_ID"),
            (1, "_CMDLINE"),
            (2, "MESSAGE_ID"),
            (3, "JOB_RESULT"),
            (3, "_BOOT_ID"),
        ] {
            let mut bad = rows.clone();
            bad[index][key] = json!("wrong");
            assert!(call(&bad, &r, 99, 105).is_err(), "{index}:{key}");
        }
        let mut wrong = r;
        wrong["guard_invocation_id"] = json!("e".repeat(32));
        assert!(call(&rows, &wrong, 99, 105).is_err());
    }
}
