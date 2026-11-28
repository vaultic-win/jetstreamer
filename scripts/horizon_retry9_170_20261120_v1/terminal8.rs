//! Authenticate the collected retry8 transient unit, its first guard rejection and failed setup.
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const STOP: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry8-recovery-20261120-v1/preparation/epoch170/local3retry8/guard-state/receipts/stop-completion.json";
const INTENT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry8-recovery-20261120-v1/preparation/epoch170/local3retry8/guard-state/receipts/stop-intent.json";
const FAILED: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry8-recovery-20261120-v1/launch-state/epoch170/FAILED_SETUP.json";
const IID: &str = "c2459faf6493457f97aee03ba46ec6c5";
const PLAN: &str = "dc20ab2577fcdc3106e0cb962e1f50c532a16b7084315c860ee365ab79f2b8ef";
const UNIT: &str = "horizon-qualify-170-replacement-local3retry8-20261110-v1.service";
pub(crate) fn bindings() -> Value {
    json!({
        "stopped_retry8_170":{"path":STOP,"sha256":"69387c320047cfc86244df36f5b25c550ecc0a376bd7eb6dbda6ee0851ad685e"},
        "stop_intent_retry8_170":{"path":INTENT,"sha256":"d5a3d2c11bcced81410ebec758bd333b71783f974feaed7dae17598becafa6ed"},
        "failed_setup_retry8_170":{"path":FAILED,"sha256":"89ee89247480b725c8207249447cbed293e79f489cf6fdfd02ea524cfe9c7d9e"}
    })
}
fn read_member(binding: &Value) -> Result<Value> {
    let path = Path::new(binding["path"].as_str().unwrap());
    ensure!(path.canonicalize()? == path, "noncanonical retry8 receipt");
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= 64 << 10,
        "retry8 receipt custody"
    );
    let mut raw = Vec::new();
    file.by_ref().take((64 << 10) + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == meta.len()
            && binding["sha256"] == format!("{:x}", Sha256::digest(&raw)),
        "retry8 receipt changed"
    );
    Ok(serde_json::from_slice(&raw)?)
}
fn shape(stop: &Value, intent: &Value, failed: &Value) -> Result<()> {
    let sample = &intent["sample"];
    let old = &sample["producer"];
    let terminal = &stop["terminal"];
    ensure!(
        stop["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && stop["intent"] == INTENT
            && stop["plan_sha256"] == PLAN
            && stop["producer_invocation_id"] == IID
            && stop["r2_mutations"] == false
            && stop["remote_mutations"] == false
            && stop["scratch_deleted"] == false
            && terminal["load_state"] == "not-found"
            && terminal["invocation_id"] == ""
            && terminal["active"] == "inactive"
            && terminal["sub"] == "dead"
            && terminal["pid"] == 0
            && terminal["restarts"] == 0
            && terminal["result"] == "success"
            && terminal["restart_policy"] == "no"
            && terminal["kill_mode"] == "control-group"
            && terminal["delegated"] == false,
        "collected retry8 terminal unit differs"
    );
    ensure!(
        intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && intent["plan_sha256"] == PLAN
            && intent["producer_invocation_id"] == IID
            && intent["reason"] == "DATA-fulfillment-observation-failed"
            && sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["plan_sha256"] == PLAN
            && sample["producer_invocation_id"] == IID
            && old["invocation_id"] == IID
            && old["pid"] == 2605010
            && old["cgroup"] == format!("/system.slice/{UNIT}")
            && old["restarts"] == 0
            && old["active"] == "active"
            && old["sub"] == "running"
            && sample["guard_sha256"]
                == "47406f752751e730a809bfaa212a6cb8869e418d1d245240206225f7e2fff588"
            && sample["guard_invocation_id"] == "ed9e40728813419691f29dd256052424"
            && sample["DATA_fulfillment_observation_error"]
                == "exact admitted local2 or selected local3 unit required"
            && sample["fulfilled_existing_DATA_bytes"] == 0
            && sample["minimum_free_bytes"] == 6_829_053_656_882u64
            && sample["maximum_root_physical_bytes"] == 309_237_645_312u64,
        "wrong retry8 namespace rejection"
    );
    ensure!(
        failed["guard_timer_start_confirmed"] == true
            && failed["originals_preserved"] == true
            && failed["error"] == "missing fulfilled_existing_DATA_bytes"
            && failed["recorded_unix_seconds"] == 1795158322,
        "incorrect retry8 failed setup"
    );
    Ok(())
}
pub(crate) fn event() -> Value {
    json!({"path":"/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry8-recovery-20261120-v1/TERMINAL_RETRY8.json","sha256":"8caf45b9f9e6aa5c15333aa93b0fb69731a1cff0483c9acc00d25fb03092335e"})
}
pub(crate) fn authenticate(fleet_event: &Value) -> Result<Value> {
    ensure!(
        fleet_event == &event(),
        "current fleet missing genuine retry8 stop"
    );
    let e = read_member(fleet_event)?;
    let r = bindings();
    ensure!(
        e["epoch"] == 170
            && e["unit"] == UNIT
            && e["invocation"] == IID
            && e["state"]["MainPID"] == "0"
            && e["state"]["ActiveState"] == "inactive"
            && e["state"]["Job"] == ""
            && e["resource_credit_bytes"] == 0
            && e["readiness_claimed"] == false
            && e["stop_intent"] == r["stop_intent_retry8_170"]
            && e["stop_completion"] == r["stopped_retry8_170"]
            && e["failed_setup"] == r["failed_setup_retry8_170"],
        "terminal event differs"
    );
    shape(
        &read_member(&r["stopped_retry8_170"])?,
        &read_member(&r["stop_intent_retry8_170"])?,
        &read_member(&r["failed_setup_retry8_170"])?,
    )?;
    Ok(r)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn genuine_collected_unit_is_bound_to_the_guarded_producer() {
        let r = authenticate(&event()).unwrap();
        let s = read_member(&r["stopped_retry8_170"]).unwrap();
        let i = read_member(&r["stop_intent_retry8_170"]).unwrap();
        let f = read_member(&r["failed_setup_retry8_170"]).unwrap();
        let mut bad = s.clone();
        bad["producer_invocation_id"] = json!("");
        assert!(shape(&bad, &i, &f).is_err());
        let mut bad = i.clone();
        bad["sample"]["DATA_fulfillment_observation_error"] = Value::Null;
        assert!(shape(&s, &bad, &f).is_err());
        let mut bad = f;
        bad["originals_preserved"] = json!(false);
        assert!(shape(&s, &i, &bad).is_err());
    }
}
