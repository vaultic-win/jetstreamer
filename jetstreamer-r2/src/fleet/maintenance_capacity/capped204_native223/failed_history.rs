//! Only the original native 223 resource owner may use this modern failure form.
//! This does not extend generic capped success/stop or archive qualification.
use super::*;
pub(super) const FAILURE_ID: &str = "d9b373ed55a64feb8242e02dbe79a49c";
const START_ID: &str = "39f53479d3a045ac8e11786248231fbf";
const EXIT_ID: &str = "98e322203f7a4ed290d09fe03c09fe15";
fn decimal(v: &Value, key: &str) -> Result<u64> {
    let s = v[key]
        .as_str()
        .context("native 223 manager decimal field absent")?;
    let n = s.parse::<u64>()?;
    ensure!(
        n > 0 && n.to_string() == s,
        "native 223 manager decimal is noncanonical or zero"
    );
    Ok(n)
}
pub(super) fn authenticate(current: &Value, rows: &[Value]) -> Result<()> {
    ensure!(
        !rows.is_empty() && rows.len() <= 16384,
        "native 223 failed manager history size differs"
    );
    ensure!(
        current["Id"] == prefix223_native20::UNIT
            && current["Result"] == "exit-code"
            && current["ExecMainStatus"] == "1"
            && current["ActiveState"] == "failed"
            && current["SubState"] == "failed",
        "native 223 observed failure and actual manager state/exit disagree"
    );
    let mut last = 0;
    let mut cursors = BTreeSet::new();
    let mut start = None;
    let mut exit = None;
    let mut failed = None;
    let mut original_boot = None;
    let mut last_mono = 0;
    for row in rows {
        let at = decimal(row, "__REALTIME_TIMESTAMP")?;
        let cursor = row["__CURSOR"]
            .as_str()
            .filter(|s| !s.is_empty())
            .context("native 223 manager cursor absent")?;
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == prefix223_native20::UNIT
                && at >= last
                && cursors.insert(cursor),
            "native 223 failed manager identity/order/cursor differs"
        );
        last = at;
        let id = &row["MESSAGE_ID"];
        if id == START_ID && row["INVOCATION_ID"] == IID {
            ensure!(
                start.is_none()
                    && row["JOB_TYPE"] == "start"
                    && row["JOB_RESULT"] == "done"
                    && row["MESSAGE"].as_str().is_some_and(
                        |s| s.starts_with(&format!("Started {} - ", prefix223_native20::UNIT))
                    ),
                "native 223 exact original PID1 start is missing, duplicate or inconsistent"
            );
            let boot = row["_BOOT_ID"]
                .as_str()
                .filter(|s| private_prefix::iid(s))
                .context("native 223 original boot absent")?;
            original_boot = Some(boot);
            start = Some(at);
        }
        if start.is_none() {
            ensure!(
                row["INVOCATION_ID"] != IID || !matches!(id.as_str(), Some(EXIT_ID | FAILURE_ID)),
                "native 223 original exit/result precedes its authenticated start"
            );
            continue;
        }
        let mono = decimal(row, "__MONOTONIC_TIMESTAMP")?;
        ensure!(
            row["INVOCATION_ID"] == IID
                && row["_BOOT_ID"].as_str() == original_boot
                && mono >= last_mono,
            "native 223 replacement/foreign boot or backward monotonic history"
        );
        last_mono = mono;
        if id == EXIT_ID {
            ensure!(
                exit.is_none()
                    && failed.is_none()
                    && at > start.unwrap()
                    && row["EXIT_CODE"] == "exited"
                    && row["EXIT_STATUS"] == current["ExecMainStatus"]
                    && row["MESSAGE"]
                        == format!(
                            "{}: Main process exited, code=exited, status=1/FAILURE",
                            prefix223_native20::UNIT
                        ),
                "native 223 exact main exit is missing, duplicate or disagrees with actual status"
            );
            exit = Some((at, mono));
        }
        if id == FAILURE_ID {
            let (exited, exit_mono) =
                exit.context("native 223 failed result precedes actual main exit")?;
            ensure!(
                failed.is_none()
                    && at > exited
                    && mono > exit_mono
                    && row["MESSAGE"]
                        == format!(
                            "{}: Failed with result 'exit-code'.",
                            prefix223_native20::UNIT
                        ),
                "native 223 exact exit-code result is duplicated, backward or inconsistent"
            );
            failed = Some(at);
        }
        ensure!(
            !matches!(
                id.as_str(),
                Some(
                    "7ad2d189f7e94e70a38c781354912448"
                        | "9d1aaa27d60140bd96365438aad20286"
                        | "be02cf6855d2428ba40df7e9d022f03d"
                )
            ),
            "native 223 modern failed attempt has conflicting success/stop/failure evidence"
        );
    }
    ensure!(
        start.is_some() && exit.is_some() && failed.is_some(),
        "native 223 requires the exact original start, actual main exit and failed-result sequence"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rows() -> Vec<Value> {
        let row = |at: u64, mono: u64, id: &str, msg: String| {
            json!({"_PID":"1","_UID":"0","UNIT":prefix223_native20::UNIT,
            "INVOCATION_ID":IID,"_BOOT_ID":"a".repeat(32),"__CURSOR":at.to_string(),
            "__REALTIME_TIMESTAMP":at.to_string(),"__MONOTONIC_TIMESTAMP":mono.to_string(),"MESSAGE_ID":id,"MESSAGE":msg})
        };
        let mut start = row(
            1_000_000,
            10,
            START_ID,
            format!(
                "Started {} - Private qualification.",
                prefix223_native20::UNIT
            ),
        );
        start["JOB_TYPE"] = json!("start");
        start["JOB_RESULT"] = json!("done");
        let mut exit = row(
            2_000_000,
            20,
            EXIT_ID,
            format!(
                "{}: Main process exited, code=exited, status=1/FAILURE",
                prefix223_native20::UNIT
            ),
        );
        exit["EXIT_CODE"] = json!("exited");
        exit["EXIT_STATUS"] = json!("1");
        vec![
            start,
            exit,
            row(
                2_000_001,
                21,
                FAILURE_ID,
                format!(
                    "{}: Failed with result 'exit-code'.",
                    prefix223_native20::UNIT
                ),
            ),
            row(
                2_000_002,
                22,
                "ae8f7b866b0347b9af31fe1c80b127c0",
                format!("{}: Consumed CPU time.", prefix223_native20::UNIT),
            ),
        ]
    }
    fn state() -> Value {
        let mut s = super::super::tests::current();
        s["ActiveState"] = json!("failed");
        s["SubState"] = json!("failed");
        s["Result"] = json!("exit-code");
        s["ExecMainStatus"] = json!("1");
        s
    }
    fn encode(rows: &[Value]) -> Vec<u8> {
        rows.iter()
            .map(|v| format!("{v}\n"))
            .collect::<String>()
            .into_bytes()
    }
    #[test]
    fn exact_modern_failure_releases_only_native223_resources_and_not_generic_capped_gates() {
        let raw = encode(&rows());
        let s = state();
        assert!(
            capped204205_work::exact_terminal_manager(&raw, prefix223_native20::UNIT, IID).is_err()
        );
        assert_eq!(terminal_shape(&s, &raw).unwrap(), "failed-needs-repair");
        let mut proof = terminal_fixture();
        proof["outcome"] = json!("failed-needs-repair");
        proof["current_unit"] = s;
        proof["manager_journal_sha256"] = json!(hex_lower(&Sha256::digest(&raw)));
        proof["manager_journal"] = json!(String::from_utf8(raw).unwrap());
        validate_terminal_saved(&proof).unwrap();
        for (path, value) in [
            ("/cgroup/state", json!("populated")),
            ("/process_references/references", json!(["open"])),
            (
                "/pending_job_units",
                json!(["horizon-qualify-223-replacement.service"]),
            ),
            ("/failure_history_preserved", json!(false)),
            ("/archive_qualification_authorized", json!(true)),
            ("/publication_authorized", json!(true)),
            ("/r2_mutations", json!(true)),
        ] {
            let mut bad = proof.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(validate_terminal_saved(&bad).is_err(), "{path}");
        }
    }
    #[test]
    fn modern_failure_needs_exact_pid1_start_exit_result_and_the_same_original_lifetime() {
        let good = rows();
        let s = state();
        authenticate(&s, &good).unwrap();
        for (index, key, value) in [
            (0, "INVOCATION_ID", json!("b".repeat(32))),
            (0, "JOB_RESULT", json!("failed")),
            (0, "MESSAGE", json!("Started another unit")),
            (1, "_PID", json!("2")),
            (1, "_UID", json!("1000")),
            (1, "UNIT", json!("foreign.service")),
            (1, "EXIT_CODE", json!("killed")),
            (1, "EXIT_STATUS", json!("0")),
            (
                1,
                "MESSAGE",
                json!(format!(
                    "{}: Main process exited, code=exited, status=2/FAILURE",
                    prefix223_native20::UNIT
                )),
            ),
            (
                2,
                "MESSAGE",
                json!(format!(
                    "{}: Failed with result 'oom-kill'.",
                    prefix223_native20::UNIT
                )),
            ),
            (2, "_BOOT_ID", json!("b".repeat(32))),
            (2, "__MONOTONIC_TIMESTAMP", json!("19")),
            (2, "__REALTIME_TIMESTAMP", json!("1999999")),
            (3, "INVOCATION_ID", json!("b".repeat(32))),
        ] {
            let mut bad = good.clone();
            bad[index][key] = value;
            assert!(authenticate(&s, &bad).is_err(), "{index}/{key}");
        }
        for index in 0..3 {
            let mut bad = good.clone();
            bad.remove(index);
            assert!(
                terminal_shape(&s, &encode(&bad)).is_err(),
                "missing {index}"
            );
        }
        for index in 0..3 {
            let mut bad = good.clone();
            let mut duplicate = good[index].clone();
            duplicate["__CURSOR"] = json!(format!("duplicate-{index}"));
            bad.insert(index + 1, duplicate);
            assert!(authenticate(&s, &bad).is_err(), "duplicate {index}");
        }
        let mut bad = good.clone();
        bad[3]["MESSAGE_ID"] = json!("7ad2d189f7e94e70a38c781354912448");
        assert!(authenticate(&s, &bad).is_err());
        for (key, value) in [
            ("Result", json!("success")),
            ("Result", json!("oom-kill")),
            ("ExecMainStatus", json!("0")),
            ("ExecMainStatus", json!("2")),
            ("ActiveState", json!("active")),
            ("NRestarts", json!("1")),
            ("MainPID", json!("42")),
        ] {
            let mut bad = s.clone();
            bad[key] = value;
            assert!(terminal_shape(&bad, &encode(&good)).is_err(), "{key}");
        }
    }
    #[test]
    #[ignore = "root-only existing sealed native223 failure packet; metadata reads only, no service/resource/cloud/R2 actions"]
    fn actual_sealed_native223_failure_qualifies_resource_terminal_shape_only() {
        let base =
            Path::new("/var/lib/jetstreamer/horizon-native223-prefix-failure-e70a-20261025-v1");
        let raw = read_stable_bounded(
            &base.join("complete-pid1-journal.jsonl"),
            4 << 20,
            "actual native223 failure journal",
        )
        .unwrap();
        assert_eq!(
            hex_lower(&Sha256::digest(&raw)),
            "58e40c27ef840b8843b531d4ce372e955ae55c878638651979672904706c627f"
        );
        let text = fs::read_to_string(base.join("terminal-properties.txt")).unwrap();
        let properties = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let (k, v) = l.split_once('=').unwrap();
                (k.to_string(), json!(v))
            })
            .collect::<serde_json::Map<_, _>>();
        let s = Value::Object(properties);
        assert_eq!(terminal_shape(&s, &raw).unwrap(), "failed-needs-repair");
        assert!(
            capped204205_work::exact_terminal_manager(&raw, prefix223_native20::UNIT, IID).is_err()
        );
        assert_eq!(s["InvocationID"], IID);
        assert_eq!(s["Result"], "exit-code");
        assert_eq!(s["ExecMainStatus"], "1");
    }
}
