//! Match the successful native guard sample to the still-held diagnostic.
use super::*;

pub(super) fn first_guard(actor: &Value, evidence: &Value) -> Result<Value> {
    let dir = runtime();
    let (first, first_ref) = live_document(&dir.join("FIRST_GUARD.json"))?;
    let (plan, plan_ref) = live_document(&dir.join("ACTUAL_GUARD_PLAN.json"))?;
    let iid = text(&first, "guard_invocation")?;
    ensure!(
        token(iid) && iid != text(actor, "invocation_id")?,
        "invalid guard invocation"
    );
    let expected_sample = dir
        .join("guard-receipts")
        .join(format!("sample-{iid}.json"));
    ensure!(
        first["receipt"]["path"] == json!(expected_sample),
        "different guard sample path"
    );
    let sample = bound(&first["receipt"])?;
    let service = TIMER.replace(".timer", ".service");
    let fields = "Id,ActiveState,SubState,Job,InvocationID,Triggers,Result";
    let timer = show(TIMER, fields)?;
    ensure!(
        timer["Id"] == TIMER
            && timer["ActiveState"] == "active"
            && timer["SubState"] == "waiting"
            && timer["Job"].is_empty()
            && timer["Result"] == "success"
            && timer["Triggers"] == service
            && token(&timer["InvocationID"])
            && first["timer"]["InvocationID"] == timer["InvocationID"]
            && first["timer"]["Id"] == TIMER,
        "different native guard timer"
    );
    let q = bound(&evidence["guard_qualification"])?;
    let template = bound(&q["static_controls"]["positive"])?;
    let mut expected = template;
    expected["invocation_id"] = actor["invocation_id"].clone();
    expected["minimum_free_bytes"] = actor["armed_floor"].clone();
    ensure!(plan == expected, "different actual guard plan");
    let floor = num(actor, "armed_floor")?;
    let age = now()?
        .checked_sub(num(&sample, "recorded_unix_seconds")?)
        .context("guard timestamp in future")?;
    let allocation = &sample["root_physical_observation"];
    let mut lower = CAP;
    let mut upper = 0;
    for side in ["first", "second"] {
        let bytes = num(&allocation[side], "physical_bytes")?;
        ensure!(
            bytes > 0 && bytes <= CAP && num(&allocation[side], "vanished_entries")? == 0,
            "incomplete held tree walk"
        );
        lower = lower.min(bytes);
        upper = upper.max(bytes);
    }
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && age <= 120
            && sample["guard_invocation_id"] == iid
            && sample["guard_sha256"] == evidence["guard"]["sha256"]
            && sample["plan"] == plan_ref["path"]
            && sample["plan_sha256"] == plan_ref["sha256"]
            && sample["producer"]["pid"] == actor["producer_pid"]
            && sample["producer"]["cgroup"] == actor["cgroup"]
            && sample["producer"]["invocation_id"] == actor["invocation_id"]
            && sample["producer_invocation_id"] == actor["invocation_id"]
            && sample["workers"] == json!([])
            && sample["producer_stop_enabled"] == true
            && sample["minimum_free_bytes"] == floor
            && sample["maximum_root_physical_bytes"] == CAP
            && allocation["maximum_physical_bytes"] == CAP
            && allocation["conservative_physical_bytes"] == upper
            && allocation["exceeds_budget"] == false
            && sample["maximum_worker_vmas"] == 3_500_000
            && sample["DATA_fulfillment"]["qualified_native_witness"] == q["witness"]
            && num(
                &sample["DATA_fulfillment"],
                "enforced_raw_minimum_free_bytes"
            )? >= floor
            && num(&sample, "available_bytes")? >= floor
            && sample["DATA_fulfillment"]["resource_credit_bytes"] == 0
            && [
                "trip_reason",
                "DATA_fulfillment_observation_error",
                "root_physical_observation_error",
                "worker_observation_error",
                "bounded_canary"
            ]
            .iter()
            .all(|k| sample.get(*k) == Some(&Value::Null))
            && [
                "remote_mutations",
                "r2_mutations",
                "scratch_deleted",
                "bounded_measurement"
            ]
            .iter()
            .all(|k| sample[*k] == false),
        "native first guard failed, stale, or observed another generation"
    );
    let journal = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            &format!("_BOOT_ID={}", text(actor, "boot_id")?.replace('-', "")),
            &format!("UNIT={service}"),
            &format!("INVOCATION_ID={iid}"),
        ])
        .output()?;
    ensure!(journal.status.success(), "missing PID 1 guard journal");
    let events = String::from_utf8(journal.stdout)?;
    let mut successes = 0;
    for line in events.lines() {
        let event: Value = serde_json::from_str(line)?;
        match event["MESSAGE_ID"].as_str() {
            Some("7ad2d189f7e94e70a38c781354912448") => {
                let ts = text(&event, "__REALTIME_TIMESTAMP")?.parse::<u64>()? / 1_000_000;
                ensure!(
                    ts >= num(&sample, "recorded_unix_seconds")?,
                    "PID 1 event predates guard sample"
                );
                successes += 1;
            }
            Some("d9b373ed55a64feb8242e02dbe79a49c" | "98e322203f7a4ed290d09fe03c09fe15") => {
                bail!("failed first guard")
            }
            _ => (),
        }
    }
    ensure!(
        successes == 1 && timer == show(TIMER, fields)?,
        "ambiguous native guard completion or timer turnover"
    );
    Ok(
        json!({"first_guard":first_ref,"actual_guard_plan":plan_ref,"sample":first["receipt"],"guard_invocation_id":iid,
        "timer_invocation_id":timer["InvocationID"],"physical_bytes":lower,"available_bytes":sample["available_bytes"],
        "recorded_unix_seconds":sample["recorded_unix_seconds"]}),
    )
}
