use crate::{BOOT, INVOCATION, PID, UNIT, custody::digest};
use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};
use std::{fs, path::Path, process::Command};

pub const MAIN_EXIT: &str = "98e322203f7a4ed290d09fe03c09fe15";
const FAILED: &str = "d9b373ed55a64feb8242e02dbe79a49c";
const STARTED: &str = "39f53479d3a045ac8e11786248231fbf";
const DIGEST_OK: &str =
    "epoch 168 passed independent archive SHA-256, starting full PoH verification";
const FULL_OK: &str = "epoch 168 passed full PoH verification, starting local plugin playback";

fn program_state() -> Result<Value> {
    let result = Command::new("/usr/bin/systemctl").args(["show", "--all", UNIT, "--property",
        "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,Job,ExecMainPID,ExecMainCode,ExecMainStatus,NRestarts,Result"]).output()?;
    ensure!(
        matches!(result.status.code(), Some(0 | 4)) && result.stdout.len() < 16384,
        "original manager state unavailable"
    );
    let mut props = Map::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("malformed service state")?;
        ensure!(
            props.insert(key.into(), json!(value)).is_none(),
            "duplicate manager field"
        );
    }
    let state = Value::Object(props);
    ensure!(
        state["Id"] == UNIT
            && state["MainPID"] == "0"
            && state["ControlPID"] == "0"
            && state["ControlGroup"] == ""
            && state["Job"] == "",
        "original service has live work"
    );
    if state["LoadState"] == "not-found" {
        ensure!(
            state["ActiveState"] == "inactive"
                && state["SubState"] == "dead"
                && state["InvocationID"] == "",
            "different collected service"
        );
    } else {
        ensure!(
            state["LoadState"] == "loaded"
                && state["InvocationID"] == INVOCATION
                && state["ActiveState"] == "failed"
                && state["SubState"] == "failed"
                && state["Result"] == "exit-code"
                && state["ExecMainPID"] == PID
                && state["ExecMainCode"] == "1"
                && state["ExecMainStatus"] == "1"
                && state["NRestarts"] == "0",
            "original wrapper did not exit with status 1"
        );
    }
    Ok(state)
}

fn event(row: &Value) -> Result<Value> {
    let time = row["__MONOTONIC_TIMESTAMP"]
        .as_str()
        .context("journal clock")?
        .parse::<u64>()?;
    let realtime = row["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("journal wall clock")?
        .parse::<u64>()?;
    Ok(
        json!({"at_monotonic_usec":time, "at_realtime_usec":realtime, "message":row["MESSAGE"],
            "cursor":row["__CURSOR"].as_str().context("journal cursor")?}),
    )
}

fn journal(rows: &[Value], cmd: &str, binary: &Path) -> Result<Value> {
    let mut seen = Map::new();
    for row in rows {
        let message = row["MESSAGE"].as_str().context("journal message")?;
        ensure!(
            row["_BOOT_ID"] == BOOT && row["_UID"] == "0",
            "wrong journal owner or boot"
        );
        let key = if row["_PID"] == "1" {
            ensure!(
                row["UNIT"] == UNIT && row["INVOCATION_ID"] == INVOCATION,
                "wrong manager invocation"
            );
            match row["MESSAGE_ID"].as_str() {
                Some(STARTED) => Some("started"),
                Some(MAIN_EXIT) => {
                    ensure!(
                        row["EXIT_CODE"] == "exited"
                            && row["EXIT_STATUS"] == "1"
                            && row["COMMAND"] == "ExecStart"
                            && message
                                == format!(
                                    "{UNIT}: Main process exited, code=exited, status=1/FAILURE"
                                ),
                        "wrong wrapper exit cause"
                    );
                    Some("main_exit")
                }
                Some(FAILED) => {
                    ensure!(
                        row["UNIT_RESULT"] == "exit-code"
                            && message == format!("{UNIT}: Failed with result 'exit-code'."),
                        "wrong original unit result"
                    );
                    Some("failed")
                }
                Some("7ad2d189f7e94e70a38c781354912448") => {
                    anyhow::bail!("service recorded a clean exit")
                }
                _ => None,
            }
        } else {
            ensure!(
                row["_PID"] == PID
                    && row["_SYSTEMD_UNIT"] == UNIT
                    && row["_SYSTEMD_INVOCATION_ID"] == INVOCATION
                    && row["_EXE"] == json!(binary)
                    && row["_CMDLINE"] == cmd,
                "unbound original wrapper journal"
            );
            match message.trim_end() {
                DIGEST_OK => Some("archive_digest"),
                FULL_OK => Some("full_poh"),
                "Error: Git diff failed:" => Some("closing_diff"),
                m if m.starts_with("archive digest checked ")
                    || m.starts_with("full: [verify]")
                    || (m.starts_with("playback: ") && m.contains("horizon_tps ")) =>
                {
                    None
                }
                _ => anyhow::bail!("unexpected original wrapper diagnostic: {message}"),
            }
        };
        if let Some(k) = key {
            ensure!(
                seen.insert(k.into(), event(row)?).is_none(),
                "duplicate journal event {k}"
            );
        }
    }
    let mut previous = None;
    for key in [
        "started",
        "archive_digest",
        "full_poh",
        "closing_diff",
        "main_exit",
        "failed",
    ] {
        let time = seen
            .get(key)
            .and_then(|v| v["at_monotonic_usec"].as_u64())
            .with_context(|| format!("missing journal event {key}"))?;
        ensure!(
            previous.is_none_or(|p| time >= p),
            "out-of-order journal event {key}"
        );
        previous = Some(time);
    }
    Ok(Value::Object(seen))
}

pub fn failure(cmd: &str, binary: &Path) -> Result<Value> {
    let props = program_state()?;
    let current = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(
        current.trim().replace('-', "") == BOOT,
        "boot changed since original scan"
    );
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "-q",
            "-b",
            "--no-pager",
            "-o",
            "json",
            &format!("UNIT={UNIT}"),
            "_PID=1",
            "_UID=0",
            "+",
            &format!("_SYSTEMD_UNIT={UNIT}"),
            &format!("_SYSTEMD_INVOCATION_ID={INVOCATION}"),
            &format!("_PID={PID}"),
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty() && output.stdout.len() < 1024 * 1024,
        "original journal unavailable or exceeds its bounded output"
    );
    let rows = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let entries = journal(&rows, cmd, binary)?;
    ensure!(
        program_state()? == props,
        "native terminal changed during journal check"
    );
    Ok(
        json!({"manager":props, "journal":entries, "unit":UNIT, "invocation":INVOCATION,
        "boot":BOOT, "original_wrapper_exit":1, "journal_rows":rows.len(), "journal_sha256":digest(&output.stdout)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<Value> {
        let mut rows = vec![
            json!({"_PID":"1","MESSAGE_ID":STARTED,"MESSAGE":"started"}),
            json!({"_PID":PID,"MESSAGE":DIGEST_OK}),
            json!({"_PID":PID,"MESSAGE":FULL_OK}),
            json!({"_PID":PID,"MESSAGE":"Error: Git diff failed: "}),
            json!({"_PID":"1","MESSAGE_ID":MAIN_EXIT,"COMMAND":"ExecStart","EXIT_CODE":"exited","EXIT_STATUS":"1",
                    "MESSAGE":format!("{UNIT}: Main process exited, code=exited, status=1/FAILURE")}),
            json!({"_PID":"1","MESSAGE_ID":FAILED,"UNIT_RESULT":"exit-code","MESSAGE":format!("{UNIT}: Failed with result 'exit-code'.")}),
        ];
        for (index, r) in rows.iter_mut().enumerate() {
            r["_BOOT_ID"] = json!(BOOT);
            r["_UID"] = json!("0");
            r["__MONOTONIC_TIMESTAMP"] = json!(index.to_string());
            r["__REALTIME_TIMESTAMP"] = json!(index.to_string());
            r["__CURSOR"] = json!(index.to_string());
            if r["_PID"] == PID {
                r["_SYSTEMD_UNIT"] = json!(UNIT);
                r["_SYSTEMD_INVOCATION_ID"] = json!(INVOCATION);
                r["_EXE"] = json!("/original");
                r["_CMDLINE"] = json!("original run");
            } else {
                r["UNIT"] = json!(UNIT);
                r["INVOCATION_ID"] = json!(INVOCATION);
            }
        }
        rows
    }

    #[test]
    fn only_the_closing_diff_with_both_native_successes_qualifies() {
        let check = |v: &[Value]| journal(v, "original run", Path::new("/original"));
        let base = rows();
        assert!(check(&base).is_ok());
        for pos in 0..base.len() {
            let mut missing = base.clone();
            missing.remove(pos);
            assert!(check(&missing).is_err());
            let mut duplicate = base.clone();
            duplicate.push(base[pos].clone());
            assert!(check(&duplicate).is_err());
        }
        for (pos, field, v) in [
            (3, "MESSAGE", "Error: playback exited exit status: 1"),
            (3, "MESSAGE", "Error: Git diff failed: I/O error"),
            (3, "__MONOTONIC_TIMESTAMP", "1"),
            (3, "_PID", "1"),
            (3, "_CMDLINE", "wrong"),
            (3, "_EXE", "/copied"),
            (3, "_SYSTEMD_INVOCATION_ID", "another"),
            (1, "_BOOT_ID", "another"),
            (4, "EXIT_CODE", "killed"),
            (4, "EXIT_STATUS", "0"),
            (4, "COMMAND", "ExecStartPost"),
            (5, "UNIT_RESULT", "oom-kill"),
        ] {
            let mut rows = base.clone();
            rows[pos][field] = json!(v);
            assert!(check(&rows).is_err());
        }
    }
}
