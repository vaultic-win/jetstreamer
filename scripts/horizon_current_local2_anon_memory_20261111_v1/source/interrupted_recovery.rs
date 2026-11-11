//! Exact epoch166 recovery of the interrupted V3 metadata writer. No service mutation.
use super::*;
const LEAF: &str = "/var/lib/jetstreamer/local2-data-guard-handoffs-20261110-v1/epoch166";
const OPERATOR: &str =
    "/usr/local/lib/jetstreamer/horizon-local2-data-guard-handoff-operator-20261110-v3/handoff";
const OPERATOR_SHA: &str = "a31fd31b6cf776128235c6a8e998380aeb0fa37a4079b7c2caaee3515d39d020";
const OPERATOR_SEAL_SHA: &str = "e47005df65cdf6974ed32d8c9ff4720a359c47f2b4572f3519b7142403705548";
const SOURCE_IID: &str = "a86193a9218a4dcf8933dda284db2201";
fn pinned(v: &Value, name: &str, hash: &str) -> R<()> {
    need(
        v["path"] == format!("{LEAF}/{name}") && v["sha256"] == hash,
        "exact interrupted166 evidence pin required",
    )
}
pub(super) fn terminal166(v: &Value, unit: &Value, service: bool) -> R<()> {
    if !service {
        return terminal(v, unit, false);
    }
    need(
        unit == "horizon-guard-replacement-166-local2-20261110-v1.service"
            && v["Id"] == *unit
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "failed"
            && v["SubState"] == "failed"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Job"] == ""
            && v["ControlGroup"] == ""
            && v["Result"] == "signal"
            && v["ExecMainStatus"] == "15",
        "exact drained SIGTERM166 service required",
    )
}
fn stop_history(rows: &[Value], original: &Value, last: u64, stop: u64) -> R<u64> {
    need(
        rows.len() == 3
            && original["timer_unit"] == "horizon-guard-replacement-166-local2-20261110-v1.timer"
            && original["timer_invocation_id"] == "8e205884319945f399c762928b10d260",
        "exact original166 timer history required",
    )?;
    let mut times = Vec::new();
    for r in rows {
        need(
            r["_PID"] == "1"
                && r["UNIT"] == original["timer_unit"]
                && r["INVOCATION_ID"] == original["timer_invocation_id"]
                && r["_BOOT_ID"] == "763ea84ca81f4dddad364b1ea2ba36dd",
            "genuine original timer PID1 IID required",
        )?;
        times.push(s(r, "__REALTIME_TIMESTAMP")?.parse::<u64>()?);
    }
    need(
        rows[0]["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
            && rows[0]["JOB_RESULT"] == "done"
            && rows[0]["JOB_TYPE"] == "start"
            && rows[1]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && rows[2]["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286"
            && rows[2]["JOB_RESULT"] == "done"
            && rows[2]["JOB_TYPE"] == "stop"
            && times[0] < times[1]
            && times[1] <= times[2]
            && times[1] >= last.checked_mul(1_000_000).ok_or("last clock overflow")?
            && times[2] / 1_000_000 == stop
            && stop == 1_794_352_200,
        "timer stop must follow three genuine successor completions",
    )?;
    Ok(times[1])
}
fn service_stop_history(rows: &Value, state: &Value, original: &Value, last: u64) -> R<()> {
    let rows = rows.as_array().ok_or("genuine oldservice stop journal")?;
    need(
        rows.len() <= 80 && hex(s(state, "InvocationID")?, 32),
        "bounded exact failed service IID required",
    )?;
    let matching = |r: &&Value| {
        r["_PID"] == "1"
            && r["UNIT"] == original["guard_unit"]
            && r["INVOCATION_ID"] == state["InvocationID"]
            && r["_BOOT_ID"] == "763ea84ca81f4dddad364b1ea2ba36dd"
    };
    let in_window = |r: &&Value| {
        r["__REALTIME_TIMESTAMP"]
            .as_str()
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|t| t >= last.saturating_mul(1_000_000) && t <= 1_794_352_201_000_000)
    };
    need(
        rows.iter().filter(matching).filter(in_window).any(|r| {
            r["MESSAGE_ID"] == "d9b373ed55a64feb8242e02dbe79a49c" && r["UNIT_RESULT"] == "signal"
        }),
        "genuine old166 service failed-by-signal PID1 event required",
    )
}
pub(super) fn validate(
    a: &Accepted,
    h: &Value,
    original: &Value,
    c: &Context<'_>,
    last: u64,
    clock: u64,
) -> R<()> {
    need(
        c.epoch == 166
            && c.iid == "3d0d0bb640684627ab370e314e6c116a"
            && h.get("old_timer_at_last_new_completion").is_none()
            && h.get("old_timer_overlap_recorded_unix_seconds").is_none()
            && h.get("old_guard_stop_started_unix_seconds").is_none(),
        "recovery166 must use genuine stop history, never invented overlap snapshots",
    )?;
    let r = bound(&h["interrupted_operator_recovery"])?;
    need(
        r["schema"] == "horizon-epoch166-interrupted-guard-handoff-recovery-v1"
            && r["owner"] == "/root"
            && r["epoch"] == 166
            && r["primary_thread"] == PRIMARY
            && r["actual_original_operator_invocation_id"] == SOURCE_IID
            && r["no_producer_control_operations"] == true
            && r["no_guard_control_operations"] == true
            && r["no_reset_failed"] == true
            && r["remote_mutations"] == false
            && r["resource_credit_bytes"] == 0
            && n(&r, "recorded_unix_seconds")? >= 1_794_352_200
            && n(&r, "recorded_unix_seconds")? <= n(h, "recorded_unix_seconds")?
            && r["old_timer_state"] == h["old_timer_state"]
            && r["old_service_terminal"] == h["old_service_terminal"]
            && r["producer"] == h["producer_after"]
            && r["new_timer"] == h["new_timer"],
        "complete narrow interrupted operator recovery required",
    )?;
    need(
        r["source_operator"]["path"] == OPERATOR
            && r["source_operator"]["sha256"] == OPERATOR_SHA
            && r["source_operator_deployment_seal"]["sha256"] == OPERATOR_SEAL_SHA,
        "exact original V3 operator required",
    )?;
    normal(
        &r["source_operator"],
        &r["source_operator_deployment_seal"],
        "handoff",
        "0555",
    )?;
    need(
        r["recovery_operator"]["path"]
            == "/usr/local/lib/jetstreamer/horizon-epoch166-interrupted-handoff-recovery-20261110-v2/recover"
            && hex(s(&r, "actual_recovery_operator_invocation_id")?, 32),
        "normally sealed exact recovery route required",
    )?;
    normal(
        &r["recovery_operator"],
        &r["recovery_operator_deployment_seal"],
        "recover",
        "0555",
    )?;
    service_stop_history(
        &r["old_service_stop_journal"],
        &h["old_service_terminal"],
        original,
        last,
    )?;
    let e = &r["retained_evidence"];
    for (name, hash) in [
        (
            "OLD_LAST_GUARD_PID1_TIMER.json",
            "c55220ae1480c18570c1495556686a2ec50ca228fb6dcf95c956f36a2eb832b7",
        ),
        (
            "NEW_TIMER_COMPLETION_1.json",
            "b0f1f7c68259f02e87b3a91b05839fdf4b4c301109401a0b35676d1efc3d6d98",
        ),
        (
            "NEW_TIMER_COMPLETION_2.json",
            "e02ccc4e24b5ab95917f08db612a30e60b3feb90a06f51a8e1d300ffc826a116",
        ),
        (
            "NEW_TIMER_COMPLETION_3.json",
            "d868aba905310ec63c15f6b7db30a7e12741e170ce785d98fe5c2a54c9847238",
        ),
        (
            "NEW_GUARD_PROTECTION.json",
            "2b016b0763012a7b5d2dc01cd7f5a79dd0bee8905d2070514df9013f6ffa78e9",
        ),
        (
            "OLD_GUARD_STOP-ORIGINAL-ARGV.json",
            "d781f1e72c06d72c82813366f449ceee6742684a3a8fc422d411ae29ceea2623",
        ),
        (
            "OLD_GUARD_STOP-ORIGINAL-EXECUTION.json",
            "26b2e5ef69f78ce7bd14198cabaa9ce0f198348eb20652c1fc331e9d069828a6",
        ),
        (
            "FAILED_HANDOFF_PRESERVED.json",
            "f9b0b89adbd61112fdbdc47aa88969019400a9565aaea9af05a70ee65a1d43d4",
        ),
        (
            "ROOT_SERIAL_NATIVE16_ALLOCATION.json",
            "33108d8c25d42a3f8aec19174ce38560400a45d05633a614f834bf2fb7c8f524",
        ),
        (
            "ROOT_ACTUAL_OLD_TIMER_STOP_JOURNAL.jsonl",
            "72a5b7c8bd86773c8c452908a92b7c9aa2f7ae4652bfbf7ddec61f6a6f99859d",
        ),
    ] {
        pinned(&e[name], name, hash)?;
    }
    need(
        h["old_last_guard_pid1_timer"] == e["OLD_LAST_GUARD_PID1_TIMER.json"]
            && h["new_protection"] == e["NEW_GUARD_PROTECTION.json"]
            && h["genuine_new_timer_completions"]
                == json!([
                    e["NEW_TIMER_COMPLETION_1.json"],
                    e["NEW_TIMER_COMPLETION_2.json"],
                    e["NEW_TIMER_COMPLETION_3.json"]
                ]),
        "recovered handoff must retain exact three original completions",
    )?;
    let argv = bound(&e["OLD_GUARD_STOP-ORIGINAL-ARGV.json"])?;
    need(
        argv == json!([
            "/usr/bin/systemctl",
            "stop",
            original["timer_unit"],
            original["guard_unit"]
        ]),
        "exact original guard-only stop argv required",
    )?;
    let stop = bound(&e["OLD_GUARD_STOP-ORIGINAL-EXECUTION.json"])?;
    need(
        stop["code"] == 0
            && stop["stdout"] == ""
            && stop["stderr"] == ""
            && stop["recorded_unix_seconds"] == 1_794_352_200u64,
        "successful original stop execution required",
    )?;
    let failure = bound(&e["FAILED_HANDOFF_PRESERVED.json"])?;
    need(
        failure["epoch"] == 166
            && failure["error"] == "old guard not drained"
            && failure["producer_never_signaled_by_operator"] == true
            && failure["recorded_unix_seconds"] == stop["recorded_unix_seconds"]
            && failure["original_protection"] == *c.original_protection,
        "exact interrupted writer failure required",
    )?;
    let funding = bound(&e["ROOT_SERIAL_NATIVE16_ALLOCATION.json"])?;
    need(
        funding["actual_operator_invocation_id"] == SOURCE_IID
            && funding["epoch"] == 166
            && funding["all_original_promises_and_producers_retained"] == true,
        "actual original operator IID provenance required",
    )?;
    let jb = &e["ROOT_ACTUAL_OLD_TIMER_STOP_JOURNAL.jsonl"];
    let raw = bytes(Path::new(s(jb, "path")?), false)?;
    need(
        sha(&raw) == s(jb, "sha256")?,
        "retained timer journal changed",
    )?;
    let rows = std::str::from_utf8(&raw)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    let deactivated = stop_history(&rows, original, last, n(&stop, "recorded_unix_seconds")?)?;
    need(
        r["old_timer_deactivated_realtime_microseconds"] == deactivated,
        "retained timer stop chronology differs",
    )?;
    terminal166(&h["old_timer_state"], &original["timer_unit"], false)?;
    terminal166(&h["old_service_terminal"], &original["guard_unit"], true)?;
    owner(&r["producer"], c)?;
    timer(&r["new_timer"], &a.protection)?;
    let fresh = bound(&r["current_new_guard_proof"])?;
    let g = bound(&fresh["receipt"])?;
    sample(a, &g, c, n(&r, "recorded_unix_seconds")?, true)?;
    proof(a, &fresh, &g, c)?;
    need(
        n(&g, "recorded_unix_seconds")? >= last && n(&r, "recorded_unix_seconds")? <= clock,
        "recovery requires later genuine healthy successor completion",
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn original() -> Value {
        json!({"timer_unit":"horizon-guard-replacement-166-local2-20261110-v1.timer","timer_invocation_id":"8e205884319945f399c762928b10d260"})
    }
    fn rows() -> Vec<Value> {
        let o = original();
        let mut rows = vec![
            json!({"MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","JOB_RESULT":"done","JOB_TYPE":"start","__REALTIME_TIMESTAMP":"1794339094320166"}),
            json!({"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","__REALTIME_TIMESTAMP":"1794352200575066"}),
            json!({"MESSAGE_ID":"9d1aaa27d60140bd96365438aad20286","JOB_RESULT":"done","JOB_TYPE":"stop","__REALTIME_TIMESTAMP":"1794352200575182"}),
        ];
        for r in &mut rows {
            r["_PID"] = json!("1");
            r["UNIT"] = o["timer_unit"].clone();
            r["INVOCATION_ID"] = o["timer_invocation_id"].clone();
            r["_BOOT_ID"] = json!("763ea84ca81f4dddad364b1ea2ba36dd");
        }
        rows
    }
    #[test]
    fn real_stop_after_third_success_is_overlap_evidence() {
        assert_eq!(
            stop_history(&rows(), &original(), 1_794_352_193, 1_794_352_200).unwrap(),
            1_794_352_200_575_066
        );
    }
    #[test]
    fn invented_or_early_stop_history_is_rejected() {
        for (k, v) in [
            ("_PID", json!("2")),
            ("INVOCATION_ID", json!("b".repeat(32))),
            ("JOB_RESULT", json!("failed")),
            ("JOB_TYPE", json!("restart")),
            ("__REALTIME_TIMESTAMP", json!("1794352190000000")),
        ] {
            let mut r = rows();
            r[2][k] = v;
            assert!(
                stop_history(&r, &original(), 1_794_352_193, 1_794_352_200).is_err(),
                "{k}"
            );
        }
        assert!(stop_history(&rows()[..2], &original(), 1_794_352_193, 1_794_352_200).is_err());
        assert!(stop_history(&rows(), &original(), 1_794_352_201, 1_794_352_200).is_err());
    }
    #[test]
    fn only_genuine_failed_original_service_iid_can_explain_sigterm() {
        let o = json!({"guard_unit":"old.service"});
        let state = json!({"InvocationID":"a".repeat(32)});
        let row = json!({"_PID":"1","UNIT":"old.service","INVOCATION_ID":"a".repeat(32),"_BOOT_ID":"763ea84ca81f4dddad364b1ea2ba36dd","MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c","UNIT_RESULT":"signal","__REALTIME_TIMESTAMP":"1794352200580000"});
        service_stop_history(&json!([row]), &state, &o, 1_794_352_193).unwrap();
        for (k, v) in [
            ("_PID", json!("2")),
            ("INVOCATION_ID", json!("b".repeat(32))),
            ("UNIT", json!("foreign.service")),
            ("UNIT_RESULT", json!("exit-code")),
            ("__REALTIME_TIMESTAMP", json!("1794352202000000")),
        ] {
            let mut changed = row.clone();
            changed[k] = v;
            assert!(
                service_stop_history(&json!([changed]), &state, &o, 1_794_352_193).is_err(),
                "{k}"
            );
        }
    }
    #[test]
    fn sigterm_terminal_exception_never_accepts_live_work_or_other_epoch() {
        let u = json!("horizon-guard-replacement-166-local2-20261110-v1.service");
        let v = json!({"Id":u,"LoadState":"loaded","ActiveState":"failed","SubState":"failed","MainPID":"0","ControlPID":"0","NRestarts":"0","Job":"","ControlGroup":"","Result":"signal","ExecMainStatus":"15"});
        terminal166(&v, &u, true).unwrap();
        for (k, x) in [
            ("MainPID", "12"),
            ("ControlPID", "13"),
            ("ControlGroup", "/live"),
            ("NRestarts", "1"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "9"),
            ("ActiveState", "active"),
        ] {
            let mut bad = v.clone();
            bad[k] = json!(x);
            assert!(terminal166(&bad, &u, true).is_err(), "{k}");
        }
        assert!(terminal166(&v, &json!("another.service"), true).is_err());
    }
}
