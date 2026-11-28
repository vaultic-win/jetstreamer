//! Original executing identity and genuine manager completion are separate from
//! current unloaded-unit state. A not-found unit never supplies the original IID.
use super::*;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-retry2-scratch-retire-tools-20261113-v1/retire";
const IMAGE_SHA: &str = "2c934866f572ae162b86de059dbe31e42ca1028dbaa78d0d3cefbf4b75aa25d0";
fn current(v: &Value, unit: &str, iid: &str) -> Result<()> {
    ensure!(
        v["Id"] == unit
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"] == ""
            && (v["NRestarts"].is_null() || v["NRestarts"] == "0")
            && ((v["LoadState"] == "not-found"
                && v["InvocationID"] == ""
                && v["ActiveState"] == "inactive"
                && v["SubState"] == "dead")
                || (v["LoadState"] == "loaded"
                    && v["InvocationID"] == iid
                    && ((v["ActiveState"] == "inactive" && v["SubState"] == "dead")
                        || (v["ActiveState"] == "active" && v["SubState"] == "exited"))
                    && v["Result"] == "success"
                    && v["ExecMainStatus"] == "0")),
        "current retirement unit live, queued, reused or not wholly terminal"
    );
    Ok(())
}
fn decimal(v: &Value, k: &str) -> Result<u64> {
    let s = v[k].as_str().context("native journal clock")?;
    ensure!(
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
        "native clock malformed"
    );
    Ok(s.parse()?)
}
fn validate(
    epoch: u64,
    w: &Value,
    c: &Value,
    argv: &Value,
    execution: &Value,
    at: u64,
) -> Result<Value> {
    let unit = format!("horizon-retry2-scratch-retire-{epoch}-execute-20261113-v1.service");
    let original = &w["actual_original_native_execution"];
    let iid = original["InvocationID"]
        .as_str()
        .context("genuine original native IID")?;
    ensure!(
        lower_hex(iid, 32)
            && iid.bytes().any(|b| b != b'0')
            && original["Id"] == unit
            && original["LoadState"] == "loaded"
            && original["ActiveState"] == "active"
            && original["SubState"] == "running"
            && original["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|p| p > 0)
            && original["ControlPID"] == "0"
            && original["NRestarts"] == "0"
            && original["Job"] == ""
            && original["MemoryMax"] == "2147483648"
            && original["MemorySwapMax"] == "0"
            && c["basis"]["tool_sha256"] == IMAGE_SHA,
        "exact original qualified retirement execution identity required"
    );
    for key in ["first_gates", "pre_remove_gates", "final_gates"] {
        ensure!(
            c[key]["own"] == *original,
            "completion has different original native identity: {key}"
        );
    }
    let a: Vec<String> = serde_json::from_value(argv.clone())?;
    let pos = a
        .iter()
        .position(|v| v == IMAGE)
        .context("actual qualified retirement image argv")?;
    ensure!(
        a.len() == pos + 7
            && a.get(pos + 1)
                == Some(&format!(
                    "/usr/local/lib/jetstreamer/horizon-retry2-scratch-{epoch}-retire-plan-20261113-v1/plan.json"
                ))
            && a.get(pos + 2).is_some_and(|s| s == "--plan-sha256")
            && a.get(pos + 3).is_some_and(|s| lower_hex(s, 64))
            && a.get(pos + 4).is_some_and(|s| s == "--self-sha256")
            && a.get(pos + 5).is_some_and(|s| s == IMAGE_SHA)
            && a.get(pos + 6).is_some_and(|s| s == "--execute")
            && a.iter().any(|s| s == "--wait")
            && a.iter().any(|s| s == &format!("--unit={unit}"))
            && a.iter().any(|s| s == "RemainAfterExit=no"),
        "original exact wait/execute argv differs"
    );
    ensure!(
        execution["code"] == 0
            && execution["stderr"].as_str().is_some_and(|s| s
                .lines()
                .any(|line| line == format!("Running as unit: {unit}; invocation ID: {iid}"))
                && s.lines()
                    .any(|line| line == "Finished with result: success")
                && s.lines()
                    .any(|line| line == "Main processes terminated with: code=exited/status=0")),
        "genuine original systemd-run completion differs"
    );
    let rows = w["original_PID1_terminal_journal"]
        .as_array()
        .context("genuine original PID1 rows")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 128,
        "native journal bound"
    );
    let mut cursors = BTreeSet::new();
    let mut started = None;
    let mut success = None;
    for row in rows {
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["_COMM"] == "systemd"
                && row["_EXE"] == "/usr/lib/systemd/systemd"
                && row["UNIT"] == unit
                && row["INVOCATION_ID"] == iid
                && row["_MACHINE_ID"] == "59498204047045e4a428419acee7df19"
                && row["_BOOT_ID"] == "763ea84ca81f4dddad364b1ea2ba36dd",
            "foreign original PID1 identity"
        );
        let cursor = row["__CURSOR"].as_str().context("native cursor")?;
        ensure!(
            !cursor.is_empty() && cursors.insert(cursor),
            "missing/duplicate original native cursor"
        );
        let realtime = decimal(row, "__REALTIME_TIMESTAMP")?;
        let mono = decimal(row, "__MONOTONIC_TIMESTAMP")?;
        ensure!(
            realtime > 0 && mono > 0 && realtime / 1_000_000 <= at,
            "future/zero native completion clock"
        );
        if let Some(result) = row.get("UNIT_RESULT") {
            ensure!(result == "success", "native failed result");
        }
        if let Some(result) = row.get("JOB_RESULT") {
            ensure!(result == "done", "native failed job");
        }
        if row["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf" {
            ensure!(
                row["JOB_TYPE"] == "start" && started.replace((realtime, mono)).is_none(),
                "ambiguous started record"
            );
        }
        if row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448" {
            ensure!(
                row["MESSAGE"] == format!("{unit}: Deactivated successfully.")
                    && success.replace((realtime, mono)).is_none(),
                "ambiguous successful terminal record"
            );
        }
    }
    let start = started.context("original native start required")?;
    let end = success.context("original successful deactivation required")?;
    ensure!(
        start.0 <= end.0 && start.1 <= end.1,
        "native completion precedes original start"
    );
    current(&w["current_native"], &unit, iid)?;
    Ok(
        json!({"unit":unit,"original_invocation_id":iid,"original_success_realtime_microseconds":end.0,"original_execution":w["original_execution"],"original_argv":w["original_argv"],"current_native_is_distinct_from_original_execution":true}),
    )
}
pub(super) fn authenticate(epoch: u64, w: &Value, c: &Value) -> Result<Value> {
    let argv = bound(&serde_json::from_value::<Bound>(
        w["original_argv"].clone(),
    )?)?;
    let execution = bound(&serde_json::from_value::<Bound>(
        w["original_execution"].clone(),
    )?)?;
    let proof = validate(epoch, w, c, &argv, &execution, now()?)?;
    let a: Vec<String> = serde_json::from_value(argv)?;
    let pos = a.iter().position(|s| s == IMAGE).context("actual image")?;
    let mut plan = bound(&Bound {
        path: a[pos + 1].clone().into(),
        sha256: a[pos + 3].clone(),
    })?;
    for key in [
        "fleet",
        "dependency_review",
        "observer",
        "sample_unix_seconds",
    ] {
        plan.as_object_mut()
            .context("actual plan object")?
            .remove(key);
    }
    ensure!(
        digest(&serde_json::to_vec(&plan)?) == c["basis"]["scope_sha256"],
        "original actual plan does not bind completion scope"
    );
    fixed(IMAGE, IMAGE_SHA, 64 << 20)?;
    let unit = proof["unit"].as_str().context("retirement unit")?;
    let actual = serde_json::to_value(native(unit)?)?;
    current(
        &actual,
        unit,
        proof["original_invocation_id"]
            .as_str()
            .context("original IID")?,
    )?;
    Ok(json!({"original_completion":proof,"fresh_current_native":actual}))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixtures() -> Vec<Value> {
        serde_json::from_str(include_str!("actual-retirement-terminal-fixtures.json")).unwrap()
    }
    fn completion(f: &Value) -> Value {
        let mut c = f["completion_native_gates"].clone();
        c["basis"] = json!({"tool_sha256":f["tool_sha256"]});
        c
    }
    #[test]
    fn genuine_all_four_completed_unloaded_units_accept_without_invented_current_iid() {
        for f in fixtures() {
            let c = completion(&f);
            validate(
                f["epoch"].as_u64().unwrap(),
                &f["wrapper"],
                &c,
                &f["argv"],
                &f["execution"],
                2_000_000_000,
            )
            .unwrap();
            assert_eq!(f["wrapper"]["current_native"]["InvocationID"], "");
        }
    }
    #[test]
    fn original_completion_rejects_failed_foreign_journal_and_rebound_gate() {
        let f = fixtures().remove(0);
        let c = completion(&f);
        let mut execution = f["execution"].clone();
        execution["code"] = json!(1);
        assert!(
            validate(
                166,
                &f["wrapper"],
                &c,
                &f["argv"],
                &execution,
                2_000_000_000
            )
            .is_err()
        );
        for key in ["_PID", "UNIT", "INVOCATION_ID", "_BOOT_ID"] {
            let mut w = f["wrapper"].clone();
            w["original_PID1_terminal_journal"][2][key] = json!("foreign");
            assert!(
                validate(166, &w, &c, &f["argv"], &f["execution"], 2_000_000_000).is_err(),
                "{key}"
            );
        }
        let mut c = c;
        c["final_gates"]["own"]["InvocationID"] = json!("a".repeat(32));
        assert!(
            validate(
                166,
                &f["wrapper"],
                &c,
                &f["argv"],
                &f["execution"],
                2_000_000_000
            )
            .is_err()
        );
    }
    #[test]
    fn current_unloaded_unit_cannot_supply_foreign_or_fabricated_original_identity() {
        let f = fixtures().remove(0);
        let c = completion(&f);
        for (key, val) in [
            ("InvocationID", json!("a".repeat(32))),
            ("MainPID", json!("42")),
            ("Job", json!("123 queued")),
            ("ActiveState", json!("active")),
        ] {
            let mut w = f["wrapper"].clone();
            w["current_native"][key] = val;
            assert!(
                validate(166, &w, &c, &f["argv"], &f["execution"], 2_000_000_000).is_err(),
                "{key}"
            );
        }
        let mut w = f["wrapper"].clone();
        w["original_PID1_terminal_journal"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["MESSAGE_ID"] != "7ad2d189f7e94e70a38c781354912448");
        assert!(validate(166, &w, &c, &f["argv"], &f["execution"], 2_000_000_000).is_err());
    }
}
