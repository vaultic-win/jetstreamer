//! Bind the second real peer; absent or forecast identities never qualify.
use super::*;
const UNIT167: &str = "horizon-qualify-167-replacement-local3retry7-20261110-v1.service";
const GUARD167: &str = "horizon-guard-replacement-167-local3retry7-20261110-v1";
pub(super) const ADMISSION: &str = "/var/lib/jetstreamer/retry7-single167-guarded-launch-20261119-v1/epoch167/ACTUAL_REPLACEMENT_ADMISSION.json";
pub(super) const PROTECTION: &str = "/var/lib/jetstreamer/retry7-single167-guarded-launch-20261119-v1/epoch167/ACTUAL_GUARD_PROTECTION.json";

fn shape(
    a: &Value,
    g: &Value,
    n: &Value,
    recorded: &Value,
    timer: &Value,
    start: u64,
    sha: &str,
) -> Result<()> {
    let pid = string(n, "MainPID")?.parse::<u64>()?;
    let iid = string(n, "InvocationID")?;
    ensure!(
        pid > 0 && start > 0 && iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
        "real epoch167 identity required"
    );
    ensure!(
        a["schema"] == "horizon-standard-replacement-admission-v1"
            && a["epoch"] == 167
            && a["owner"] == "/root"
            && a["primary_thread"] == THREAD
            && a["producer_unit"] == UNIT167
            && a["producer_invocation_id"] == iid
            && a["producer_pid"] == pid
            && a["fresh_admission_passed"] == true
            && a["all_prior_promises_retained"] == true
            && a["guard_minimum_free_bytes"] == FLOOR
            && a["candidate_root_cap_bytes"] == 512u64 << 30
            && a["resource_credit_bytes"] == 0
            && a["memory_or_DATA_promise_ending_bytes"] == 0,
        "epoch167 genuine admission differs"
    );
    ensure!(
        g["schema"] == "horizon-standard-live-peer-protection-v1"
            && g["epoch"] == 167
            && g["producer_unit"] == UNIT167
            && g["producer_invocation_id"] == iid
            && g["admission"] == json!({"path":ADMISSION,"sha256":sha})
            && g["guard_unit"] == format!("{GUARD167}.service")
            && g["timer_unit"] == format!("{GUARD167}.timer"),
        "epoch167 protection differs"
    );
    ensure!(
        n["Id"] == UNIT167
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["NRestarts"] == "0"
            && n["ControlPID"] == "0"
            && n["Job"] == ""
            && recorded["InvocationID"] == iid
            && recorded["MainPID"] == n["MainPID"]
            && recorded["MainStartTicks"] == start,
        "epoch167 producer changed"
    );
    ensure!(
        timer["Id"] == format!("{GUARD167}.timer")
            && timer["ActiveState"] == "active"
            && timer["Job"] == ""
            && timer["InvocationID"] == g["timer_invocation_id"],
        "epoch167 timer changed"
    );
    Ok(())
}
pub(super) fn observe167(prepared: &Value) -> Result<Value> {
    let ab = read_regular(Path::new(ADMISSION), 1 << 20, false)?;
    let gb = read_regular(Path::new(PROTECTION), 1 << 20, false)?;
    let a: Value = serde_json::from_slice(&ab)?;
    let g: Value = serde_json::from_slice(&gb)?;
    let n = native(UNIT167)?;
    let start = process_start_ticks(string(&n, "MainPID")?.parse()?)?;
    let recorded = bound(&a["actual_producer_native"], 1 << 20)?;
    let timer = native(&format!("{GUARD167}.timer"))?;
    shape(&a, &g, &n, &recorded, &timer, start, &digest(&ab))?;
    let fleet = bound(&prepared["fleet"], 16 << 20)?;
    let rows = fleet["actual_executing_replays"]
        .as_array()
        .context("fleet replays")?;
    let boot = fleet["actual_active_bootstraps"]
        .as_array()
        .context("fleet bootstrap")?;
    let selected: Vec<_> = rows
        .iter()
        .chain(boot)
        .filter(|r| r["epoch"] == 167)
        .collect();
    ensure!(
        rows.len() + boot.len() == 2 && selected.len() == 1,
        "exact two-peer fleet required"
    );
    let r = selected[0];
    ensure!(
        r["unit"]["Id"] == UNIT167
            && r["unit"]["InvocationID"] == n["InvocationID"]
            && r["admission"] == json!({"path":ADMISSION,"sha256":digest(&ab)})
            && r["guard_protection"] == json!({"path":PROTECTION,"sha256":digest(&gb)}),
        "fleet167 binding differs"
    );
    let p = bound(&prepared["plan"], 16 << 20)?;
    ensure!(
        p["retry170"]["protected167_admission"] == r["admission"]
            && p["retry170"]["protected167_guard"] == r["guard_protection"],
        "preparation must consume this actual peer"
    );
    Ok(
        json!({"native":n,"start_ticks":start,"admission_sha256":digest(&ab),"protection_sha256":digest(&gb),"timer":timer}),
    )
}
pub(super) fn unchanged(before: &Value, after: &Value) -> Result<()> {
    for epoch in ["166", "167"] {
        for field in ["admission_sha256", "protection_sha256"] {
            ensure!(
                string(&before[epoch], field)? == string(&after[epoch], field)?,
                "peer {epoch} custody changed"
            );
        }
        ensure!(
            number(&before[epoch], "start_ticks")? == number(&after[epoch], "start_ticks")?
                && string(&before[epoch]["native"], "InvocationID")?
                    == string(&after[epoch]["native"], "InvocationID")?,
            "peer {epoch} changed during launch"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn second_peer_rejects_missing_admission_reused_pid_and_changed_guard() {
        let iid = "a".repeat(32);
        let sha = "b".repeat(64);
        let a = json!({"schema":"horizon-standard-replacement-admission-v1","epoch":167,
            "owner":"/root","primary_thread":THREAD,"producer_unit":UNIT167,
            "producer_invocation_id":iid,"producer_pid":123,
            "fresh_admission_passed":true,"all_prior_promises_retained":true,
            "guard_minimum_free_bytes":FLOOR,"candidate_root_cap_bytes":512u64<<30,
            "resource_credit_bytes":0,"memory_or_DATA_promise_ending_bytes":0});
        let g = json!({"schema":"horizon-standard-live-peer-protection-v1","epoch":167,
            "producer_unit":UNIT167,"producer_invocation_id":iid,
            "admission":{"path":ADMISSION,"sha256":sha},
            "guard_unit":format!("{GUARD167}.service"),"timer_unit":format!("{GUARD167}.timer"),
            "timer_invocation_id":"c".repeat(32)});
        let n = json!({"Id":UNIT167,"MainPID":"123","InvocationID":iid,
            "ActiveState":"active","SubState":"running","NRestarts":"0","ControlPID":"0","Job":""});
        let r = json!({"InvocationID":iid,"MainPID":"123","MainStartTicks":456});
        let t = json!({"Id":format!("{GUARD167}.timer"),"ActiveState":"active","Job":"","InvocationID":"c".repeat(32)});
        shape(&a, &g, &n, &r, &t, 456, &sha).unwrap();
        let mut old = a.clone();
        old["producer_unit"] =
            json!("horizon-qualify-167-replacement-local3retry6-20261110-v1.service");
        assert!(shape(&old, &g, &n, &r, &t, 456, &sha).is_err());
        assert!(shape(&Value::Null, &g, &n, &r, &t, 456, &sha).is_err());
        assert!(shape(&a, &g, &n, &r, &t, 457, &sha).is_err());
        let mut bad = a.clone();
        bad["fresh_admission_passed"] = json!(false);
        assert!(shape(&bad, &g, &n, &r, &t, 456, &sha).is_err());
        bad = a.clone();
        bad["guard_minimum_free_bytes"] = json!(FLOOR - 1);
        assert!(shape(&bad, &g, &n, &r, &t, 456, &sha).is_err());
        bad = g.clone();
        bad["admission"]["sha256"] = json!("e".repeat(64));
        assert!(shape(&a, &bad, &n, &r, &t, 456, &sha).is_err());
        bad = n.clone();
        bad["InvocationID"] = json!("f".repeat(32));
        assert!(shape(&a, &g, &bad, &r, &t, 456, &sha).is_err());
        bad = t.clone();
        bad["ActiveState"] = json!("inactive");
        assert!(shape(&a, &g, &n, &r, &bad, 456, &sha).is_err());
        bad = t.clone();
        bad["InvocationID"] = json!("f".repeat(32));
        assert!(shape(&a, &g, &n, &r, &bad, 456, &sha).is_err());
    }
    #[test]
    fn both_peers_must_remain_real_and_stable() {
        let row = json!({"admission_sha256":"a","protection_sha256":"b","start_ticks":123,
            "native":{"InvocationID":"c".repeat(32)}});
        let good = json!({"166":row,"167":row});
        unchanged(&good, &good).unwrap();
        for epoch in ["166", "167"] {
            let mut bad = good.clone();
            bad[epoch] = Value::Null;
            assert!(unchanged(&good, &bad).is_err());
            bad = good.clone();
            bad[epoch]["start_ticks"] = json!(124);
            assert!(unchanged(&good, &bad).is_err());
            bad = good.clone();
            bad[epoch]["native"]["InvocationID"] = json!("d".repeat(32));
            assert!(unchanged(&good, &bad).is_err());
            bad = good.clone();
            bad[epoch]["admission_sha256"] = json!("e");
            assert!(unchanged(&good, &bad).is_err());
        }
    }
}
