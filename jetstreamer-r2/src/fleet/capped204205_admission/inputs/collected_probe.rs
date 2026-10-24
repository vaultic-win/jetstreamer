//! Independent collected-probe authentication; retained v1 gates stay unchanged.
use super::*;
use sha2::{Digest, Sha256};
struct ProbeIdentity {
    probe_unit: String,
}
fn valid_invocation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn message_digest(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}
fn collected_terminal(
    v: &Value,
    p: &ProbeIdentity,
    executed: &BoundFile,
    b: &BoundFile,
) -> Result<()> {
    for (key, expected) in [
        ("Id", p.probe_unit.as_str()),
        ("LoadState", "loaded"),
        ("Type", "exec"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("ExecMainPID", "0"),
        ("ExecMainCode", "0"),
        ("ExecMainStatus", "0"),
        ("InvocationID", ""),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ControlGroup", ""),
        ("Triggers", ""),
        ("TriggeredBy", ""),
        ("Job", ""),
    ] {
        ensure!(
            v[key] == expected,
            "collected probe terminal differs: {key}"
        );
    }
    let command = format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
        executed.path.display(),
        executed.path.display(),
        b.path.display(),
        b.sha256,
        executed.sha256
    );
    ensure!(
        v["ExecStart"] == command,
        "collected probe command differs from exact executed executable and plan"
    );
    Ok(())
}

/// Collected display counters confer no execution identity. Require the complete
/// independent original journal proof, including the actual stdout executable.

fn collected_journal(
    v: &Value,
    p: &ProbeIdentity,
    executed: &BoundFile,
    result: &Value,
) -> Result<()> {
    journal(v, p, executed, result)?;
    let rows = v.as_array().context("collected probe journal array")?;
    let boot = rows[0]["_BOOT_ID"]
        .as_str()
        .context("original probe boot")?;
    ensure!(valid_invocation(boot), "original probe boot is invalid");
    let mut cursors = std::collections::BTreeSet::new();
    let mut previous = 0;
    let mut start = None;
    let mut success = None;
    let mut stdout = None;
    let pid = number(result, "probe_main_pid")?.to_string();
    for row in rows {
        let timestamp = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .context("original probe journal timestamp")?;
        let cursor = row["__CURSOR"]
            .as_str()
            .context("original probe journal cursor")?;
        ensure!(
            row["_BOOT_ID"] == boot
                && row["_MACHINE_ID"] == result["host_machine_id"]
                && row["_UID"] == "0"
                && timestamp > 0
                && timestamp >= previous
                && !cursor.is_empty()
                && cursors.insert(cursor),
            "original probe journal boot, host, clock or cursor differs"
        );
        previous = timestamp;
        if row["_PID"] == "1" {
            ensure!(
                row["UNIT"] == p.probe_unit
                    && row["INVOCATION_ID"] == result["probe_invocation_id"]
                    && row["_TRANSPORT"] == "journal",
                "original probe manager record has another owner"
            );
            let message = row["MESSAGE"].as_str().context("probe manager message")?;
            ensure!(
                !["Stopping ", "Stopped "]
                    .iter()
                    .any(|s| message.starts_with(s))
                    && !["Failed", "Main process exited", ": Killing"]
                        .iter()
                        .any(|s| message.contains(s))
                    && row.get("EXIT_STATUS").is_none_or(|s| s == "0"),
                "original probe manager indicates stop or failure"
            );
            if row["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf" {
                ensure!(
                    start.is_none() && message.starts_with(&format!("Started {} -", p.probe_unit)),
                    "original probe start is missing or duplicated"
                );
                start = Some(timestamp);
            }
            if row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448" {
                ensure!(
                    success.is_none()
                        && message == format!("{}: Deactivated successfully.", p.probe_unit),
                    "original probe success is missing or duplicated"
                );
                success = Some(timestamp);
            }
        } else {
            ensure!(
                row["_PID"].as_str() == Some(pid.as_str())
                    && row["_SYSTEMD_UNIT"] == p.probe_unit
                    && row["_SYSTEMD_INVOCATION_ID"] == result["probe_invocation_id"]
                    && row["_TRANSPORT"] == "stdout"
                    && row["_EXE"].as_str() == executed.path.to_str()
                    && row["MESSAGE"]
                        .as_str()
                        .and_then(|s| serde_json::from_str::<Value>(s).ok())
                        .as_ref()
                        == Some(result)
                    && stdout.is_none(),
                "original probe stdout identity is absent, changed or duplicated"
            );
            stdout = Some(timestamp);
        }
    }
    ensure!(
        start
            .zip(stdout)
            .zip(success)
            .is_some_and(|((a, b), c)| a < b && b < c),
        "original probe lacks ordered PID1 start, exact stdout and successful completion"
    );
    Ok(())
}

fn validate_ack(ack: &Value, records: &Value, executed: &BoundFile, result: &Value) -> Result<()> {
    ensure!(
        ack["schema"] == "jetstreamer-capped204205-native-stdout-ack-v1"
            && ack["complete_stdout_record_observed"] == true
            && ack["wait_limit_millis"] == 10000
            && (1..=32).contains(&number(ack, "observed_records")?)
            && ack["native_initialized"] == false
            && ack["archive_body_read"] == false
            && ack["r2_mutations"] == false,
        "native stdout acknowledgement scope differs"
    );
    let rows = records
        .as_array()
        .context("acknowledged stdout journal array")?;
    let matching = rows
        .iter()
        .filter(|row| row["__CURSOR"] == ack["cursor"])
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "native acknowledgement cursor is absent or duplicated"
    );
    let row = matching[0];
    for key in [
        "_PID",
        "_UID",
        "_SYSTEMD_UNIT",
        "_SYSTEMD_INVOCATION_ID",
        "_MACHINE_ID",
        "_BOOT_ID",
        "_TRANSPORT",
        "_EXE",
    ] {
        ensure!(
            row[key].is_string() && row[key] == ack["record_fields"][key],
            "native acknowledged identity differs: {key}"
        );
    }
    let pid = number(result, "probe_main_pid")?.to_string();
    let message = row["MESSAGE"]
        .as_str()
        .context("acknowledged complete message")?;
    ensure!(
        row["_EXE"].as_str() == executed.path.to_str()
            && row["_PID"].as_str() == Some(pid.as_str())
            && serde_json::from_str::<Value>(message)? == *result
            && ack["message_sha256"] == message_digest(message.as_bytes())
            && row["__REALTIME_TIMESTAMP"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == Some(number(ack, "realtime_usec")?),
        "native acknowledgement does not bind the complete original stdout"
    );
    Ok(())
}

fn journal(v: &Value, p: &ProbeIdentity, own: &BoundFile, result: &Value) -> Result<()> {
    let rows = v
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 8192)
        .context("bounded actual probe journal array")?;
    let machine = &result["host_machine_id"];
    let iid = &result["probe_invocation_id"];
    let pid = number(result, "probe_main_pid")?.to_string();
    let manager = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["_MACHINE_ID"] == *machine
                && r["UNIT"] == p.probe_unit
                && r["INVOCATION_ID"] == *iid
        })
        .collect::<Vec<_>>();
    let success = format!("{}: Deactivated successfully.", p.probe_unit);
    ensure!(
        manager.iter().filter(|r| r["MESSAGE"] == success).count() == 1
            && !manager.iter().any(|r| r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.contains("Failed") || s.contains("Main process exited"))),
        "actual probe journal lacks exactly one clean same-invocation PID1 success"
    );
    ensure!(
        rows.iter()
            .filter(|r| r["_UID"] == "0"
                && r["_MACHINE_ID"] == *machine
                && r["_PID"] == pid
                && r["_SYSTEMD_UNIT"] == p.probe_unit
                && r["_SYSTEMD_INVOCATION_ID"] == *iid
                && r["_EXE"].as_str() == own.path.to_str()
                && r["MESSAGE"]
                    .as_str()
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
                    .is_some_and(|v| v == *result))
            .count()
            == 1,
        "actual probe journal lacks one exact self-generated stdout result"
    );
    Ok(())
}

pub(super) fn validate(
    cap: &Value,
    probe: &BoundFile,
    plan: &BoundFile,
    probe_plan: &Value,
    terminal: &Value,
    result: &Value,
) -> Result<()> {
    ensure!(
        cap["capture_plan_schema"]
            == "jetstreamer-capped204205-resource-capability-capture-plan-v2"
            && cap["terminal_display_kind"] == "loaded-collected-zero"
            && result["journal_stdout_ack_required"] == true
            && result["probe_main_pid"] == cap["probe_main_pid"]
            && result["host_machine_id"] == cap["host_machine_id"],
        "collected capability requires the closed acknowledged writer/capture path"
    );
    let capture_tool = bound_member(&cap["capture_tool"])?;
    native209_admission::sealed_file(&capture_tool.path, &capture_tool.sha256, None)?;
    let capture_plan = native209::immutable_json(&bound_member(&cap["capture_plan"])?)?;
    let expected_output =
        Path::new(string(probe_plan, "probe_root")?).join("resource-capability.json");
    ensure!(
        capture_plan.as_object().is_some_and(|o| o.len() == 8)
            && capture_plan["schema"] == cap["capture_plan_schema"]
            && capture_plan["executed_probe"] == private157::binding(probe)
            && capture_plan["probe_plan"] == private157::binding(plan)
            && capture_plan["probe_receipt"] == cap["probe_receipt"]
            && capture_plan["terminal_properties"] == cap["terminal_properties"]
            && capture_plan["manager_journal"] == cap["manager_journal"]
            && capture_plan["stdout_ack"] == cap["stdout_ack"]
            && capture_plan["output"]
                .as_str()
                .is_some_and(|path| Path::new(path) == expected_output),
        "collected capability capture plan changed original identities or output"
    );
    let journal = native209::immutable_json(&bound_member(&cap["manager_journal"])?)?;
    let ack = native209::immutable_json(&bound_member(&cap["stdout_ack"])?)?;
    let identity = ProbeIdentity {
        probe_unit: string(cap, "probe_unit")?.into(),
    };
    collected_terminal(terminal, &identity, probe, plan)?;
    collected_journal(&journal, &identity, probe, result)?;
    validate_ack(&ack, &journal, probe, result)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (
        ProbeIdentity,
        BoundFile,
        BoundFile,
        Value,
        Value,
        Value,
        Value,
    ) {
        let p = ProbeIdentity {
            probe_unit: "horizon-capped204205-resource-probe-fixture.service".into(),
        };
        let probe = bound_member(&json!({"path":"/sealed/executed-probe","sha256":"a".repeat(64)}))
            .unwrap();
        let plan =
            bound_member(&json!({"path":"/sealed/original-plan","sha256":"b".repeat(64)})).unwrap();
        let result = json!({"probe_invocation_id":"1".repeat(32),"probe_main_pid":300,"host_machine_id":"2".repeat(32),"journal_stdout_ack_required":true});
        let command = format!(
            "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
            probe.path.display(),
            probe.path.display(),
            plan.path.display(),
            plan.sha256,
            probe.sha256
        );
        let terminal = json!({"Id":p.probe_unit,"LoadState":"loaded","Type":"exec","ActiveState":"inactive","SubState":"dead","MainPID":"0","ExecMainPID":"0","ExecMainCode":"0","ExecMainStatus":"0","InvocationID":"","NRestarts":"0","Restart":"no","Result":"success","ControlGroup":"","Triggers":"","TriggeredBy":"","Job":"","ExecStart":command});
        let start = json!({"_PID":"1","_UID":"0","_MACHINE_ID":result["host_machine_id"],"UNIT":p.probe_unit,"INVOCATION_ID":result["probe_invocation_id"],"_TRANSPORT":"journal","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":format!("Started {} - fixture.",p.probe_unit)});
        let stdout = json!({"_PID":"300","_UID":"0","_MACHINE_ID":result["host_machine_id"],"_SYSTEMD_UNIT":p.probe_unit,"_SYSTEMD_INVOCATION_ID":result["probe_invocation_id"],"_TRANSPORT":"stdout","_EXE":probe.path,"MESSAGE":serde_json::to_string(&result).unwrap()});
        let mut end = start.clone();
        end["MESSAGE_ID"] = json!("7ad2d189f7e94e70a38c781354912448");
        end["MESSAGE"] = json!(format!("{}: Deactivated successfully.", p.probe_unit));
        let mut rows = json!([start, stdout, end]);
        for (i, row) in rows.as_array_mut().unwrap().iter_mut().enumerate() {
            row["_BOOT_ID"] = json!("3".repeat(32));
            row["__CURSOR"] = json!(format!("cursor-{i}"));
            row["__REALTIME_TIMESTAMP"] = json!((100 + i).to_string());
        }
        let fields = [
            "_PID",
            "_UID",
            "_SYSTEMD_UNIT",
            "_SYSTEMD_INVOCATION_ID",
            "_MACHINE_ID",
            "_BOOT_ID",
            "_TRANSPORT",
            "_EXE",
        ]
        .into_iter()
        .map(|k| (k.to_string(), rows[1][k].clone()))
        .collect::<serde_json::Map<_, _>>();
        let ack = json!({"schema":"jetstreamer-capped204205-native-stdout-ack-v1","complete_stdout_record_observed":true,"record_fields":fields,"message_sha256":message_digest(rows[1]["MESSAGE"].as_str().unwrap().as_bytes()),"cursor":"cursor-1","realtime_usec":101,"wait_limit_millis":10000,"observed_records":1,"native_initialized":false,"archive_body_read":false,"r2_mutations":false});
        (p, probe, plan, result, terminal, rows, ack)
    }
    #[test]
    fn collected_terminal_requires_explicit_zero_shape_and_exact_executed_command() {
        let (p, probe, plan, _, terminal, _, _) = fixture();
        collected_terminal(&terminal, &p, &probe, &plan).unwrap();
        for key in terminal.as_object().unwrap().keys() {
            let mut bad = terminal.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(
                collected_terminal(&bad, &p, &probe, &plan).is_err(),
                "{key}"
            );
        }
        for (key, value) in [
            ("ExecMainPID", json!("300")),
            ("ExecMainCode", json!("1")),
            ("InvocationID", json!("1".repeat(32))),
            ("Job", json!("pending")),
            ("Result", json!("signal")),
            ("Triggers", json!("other.service")),
        ] {
            let mut bad = terminal.clone();
            bad[key] = value;
            assert!(
                collected_terminal(&bad, &p, &probe, &plan).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn collected_proof_rejects_absent_executable_wrong_boot_and_incomplete_lifecycle() {
        let (p, probe, _, result, _, rows, _) = fixture();
        collected_journal(&rows, &p, &probe, &result).unwrap();
        for (index, key, value) in [
            (1, "_EXE", Value::Null),
            (1, "_EXE", json!("/other/probe")),
            (1, "_BOOT_ID", json!("4".repeat(32))),
            (0, "INVOCATION_ID", json!("4".repeat(32))),
            (1, "__CURSOR", json!("cursor-0")),
            (1, "__REALTIME_TIMESTAMP", json!("99")),
            (2, "MESSAGE", json!("probe: Main process exited")),
        ] {
            let mut bad = rows.clone();
            bad[index][key] = value;
            assert!(
                collected_journal(&bad, &p, &probe, &result).is_err(),
                "{index} {key}"
            );
        }
        for index in 0..3 {
            let mut bad = rows.clone();
            bad.as_array_mut().unwrap().remove(index);
            assert!(collected_journal(&bad, &p, &probe, &result).is_err());
        }
    }
    #[test]
    fn native_acknowledgement_binds_exact_journal_cursor_payload_clock_and_executable() {
        let (_, probe, _, result, _, rows, ack) = fixture();
        validate_ack(&ack, &rows, &probe, &result).unwrap();
        for (key, value) in [
            ("cursor", json!("absent")),
            ("message_sha256", json!("f".repeat(64))),
            ("realtime_usec", json!(102)),
            ("wait_limit_millis", json!(0)),
            ("complete_stdout_record_observed", json!(false)),
            ("observed_records", json!(33)),
        ] {
            let mut bad = ack.clone();
            bad[key] = value;
            assert!(validate_ack(&bad, &rows, &probe, &result).is_err(), "{key}");
        }
        let mut bad = ack;
        bad["record_fields"]["_EXE"] = json!("/other/probe");
        assert!(validate_ack(&bad, &rows, &probe, &result).is_err());
    }
}
