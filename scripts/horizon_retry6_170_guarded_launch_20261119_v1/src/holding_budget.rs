//! Preserve the actual old169 transfer allocation until its exact successful exit.
use super::*;
const UNIT: &str = "horizon-closed169-local2-park-20261119-v1.service";
const IID: &str = "3bc22adcd63a4b3fa2bcddad22260e4c";
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-holding-candidate-20261023-v1/jetstreamer-r2";
const MEMORY: u64 = 2 << 30;
const CPU: u64 = 2_000_000;

fn active(v: &Value) -> Result<bool> {
    ensure!(
        v["Id"] == UNIT
            && v["InvocationID"] == IID
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Job"] == ""
            && v["ControlPID"] == "0"
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && v["MemoryMax"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(MEMORY)
            && v["MemorySwapMax"] == "0"
            && v["CPUQuotaPerSecUSec"] == "2s",
        "holding identity, limits or result differ"
    );
    if v["ActiveState"] == "active" && v["SubState"] == "running" {
        ensure!(
            string(v, "MainPID")?.parse::<u64>()? > 0,
            "holding running without process"
        );
        Ok(true)
    } else {
        ensure!(
            v["MainPID"] == "0"
                && ((v["ActiveState"] == "inactive" && v["SubState"] == "dead")
                    || (v["ActiveState"] == "active" && v["SubState"] == "exited")),
            "holding is neither executing nor successfully terminal"
        );
        Ok(false)
    }
}
pub(super) fn observe() -> Result<Value> {
    let output=Command::new("/usr/bin/systemctl").args(["show",UNIT,
        "-pId,InvocationID,ActiveState,SubState,MainPID,ControlPID,NRestarts,Restart,Job,Result,ExecMainStatus,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec"]).output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty(),
        "holding native capture failed"
    );
    let mut fields = serde_json::Map::new();
    for line in String::from_utf8(output.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("holding property")?;
        ensure!(
            fields.insert(k.into(), json!(v)).is_none(),
            "duplicate holding property"
        );
    }
    let row = Value::Object(fields);
    let running = active(&row)?;
    let start = if running {
        let pid = string(&row, "MainPID")?.parse::<u64>()?;
        let start = process_start_ticks(pid)?;
        ensure!(
            fs::read_link(format!("/proc/{pid}/exe"))? == Path::new(IMAGE),
            "holding executable changed"
        );
        ensure!(process_start_ticks(pid)? == start, "holding PID reused");
        Some(start)
    } else {
        None
    };
    Ok(json!({"native":row,"start_ticks":start,"running":running}))
}
pub(super) fn requirements(
    audit: &Value,
    holding: &Value,
    total: u64,
    available: u64,
    cores: u64,
) -> Result<Value> {
    let running = active(&holding["native"])?;
    ensure!(holding["running"] == running, "holding state differs");
    let memory = if running { MEMORY } else { 0 };
    let cpu = if running { CPU } else { 0 };
    let required = number(audit, "required_available_memory_bytes")?
        .checked_add(memory)
        .context("holding memory overflow")?;
    let complete = number(audit, "complete_memory_plus_reserve_bytes")?
        .checked_add(memory)
        .context("holding total overflow")?;
    let complete_cpu = number(audit, "complete_cpu_quota_micros")?
        .checked_add(cpu)
        .context("holding CPU overflow")?;
    ensure!(
        total >= complete && available >= required,
        "holding memory does not fit"
    );
    ensure!(
        cores > 0 && complete_cpu <= cores.checked_mul(1_000_000).context("CPU overflow")?,
        "holding CPU does not fit"
    );
    Ok(
        json!({"required_available_memory_bytes":required,"complete_memory_plus_reserve_bytes":complete,
        "complete_cpu_quota_micros":complete_cpu,"additional_holding_memory_bytes":memory,
        "additional_holding_cpu_quota_micros":cpu,"holding_DATA_staging_bytes":0,
        "DATA_credit_bytes":0,"all_prepared_and_audit_promises_retained":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the exact native169 holding invocation"]
    fn actual_native_holding_invocation_is_accepted_without_data_credit() {
        let observed = observe().unwrap();
        let base = json!({"required_available_memory_bytes":600u64<<30,
            "complete_memory_plus_reserve_bytes":724u64<<30,"complete_cpu_quota_micros":47_000_000u64});
        let booked = requirements(&base, &observed, 726u64 << 30, 602u64 << 30, 49).unwrap();
        assert_eq!(booked["DATA_credit_bytes"], 0);
        assert_eq!(
            booked["additional_holding_memory_bytes"],
            if observed["running"] == true {
                MEMORY
            } else {
                0
            }
        );
    }
    fn native(running: bool) -> Value {
        json!({"Id":UNIT,"InvocationID":IID,"NRestarts":"0","Restart":"no","Job":"",
            "ControlPID":"0","Result":"success","ExecMainStatus":"0","MemoryMax":MEMORY.to_string(),
            "MemorySwapMax":"0","CPUQuotaPerSecUSec":"2s","ActiveState":"active",
            "SubState":if running {"running"} else {"exited"},"MainPID":if running {"123"} else {"0"}})
    }
    #[test]
    fn active_transfer_is_additive_and_requires_full_fit() {
        let base = json!({"required_available_memory_bytes":600u64<<30,"complete_memory_plus_reserve_bytes":724u64<<30,"complete_cpu_quota_micros":47_000_000u64});
        let held = json!({"native":native(true),"running":true});
        assert!(requirements(&base, &held, 726u64 << 30, 602u64 << 30, 49).is_ok());
        assert!(requirements(&base, &held, (726u64 << 30) - 1, 602u64 << 30, 49).is_err());
        assert!(requirements(&base, &held, 726u64 << 30, (602u64 << 30) - 1, 49).is_err());
        assert!(requirements(&base, &held, 726u64 << 30, 602u64 << 30, 48).is_err());
        let ended = json!({"native":native(false),"running":false});
        assert_eq!(
            requirements(&base, &ended, 724u64 << 30, 600u64 << 30, 47).unwrap()["additional_holding_memory_bytes"],
            0
        );
    }
    #[test]
    fn missing_failed_replaced_and_changed_limit_units_do_not_release_booking() {
        assert!(active(&Value::Null).is_err());
        for (k, v) in [
            ("InvocationID", "b".repeat(32)),
            ("Result", "exit-code".into()),
            ("ExecMainStatus", "1".into()),
            ("NRestarts", "1".into()),
            ("MemoryMax", "1".into()),
            ("CPUQuotaPerSecUSec", "3s".into()),
            ("Job", "1".into()),
        ] {
            let mut row = native(false);
            row[k] = json!(v);
            assert!(active(&row).is_err());
        }
        let mut row = native(false);
        row["SubState"] = json!("running");
        assert!(active(&row).is_err());
    }
}
