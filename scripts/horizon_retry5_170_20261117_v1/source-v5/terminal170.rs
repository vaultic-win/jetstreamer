//! Exact stopped retry4 epoch170 lineage. Its reservation remains fully charged.
use super::*;

pub(super) const UNIT: &str = "horizon-qualify-170-replacement-local3retry4-20261110-v1.service";
pub(super) const IID: &str = "aabba5ff4c8e4c22ad18c80472713aa9";
const INTENT: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch170/local3retry4/guard-state/receipts/stop-intent.json";
const INTENT_SHA: &str = "ce1beb74263dee307a2999ad7680438f11cfc7ef17e2096f71e6376f9958dffd";
const COMPLETION: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch170/local3retry4/guard-state/receipts/stop-completion.json";
const COMPLETION_SHA: &str = "584fe719e362f4fcf3a34caa37d526b43fabcafb0255bd443592209c82c3167c";
const ADMISSION: &str = "/var/lib/jetstreamer/epoch170-retry4-live167-20261116-v1/launch-v1/epoch170/ACTUAL_REPLACEMENT_ADMISSION.json";
const ADMISSION_SHA: &str = "e45bb1a2dbcd422e430d9c435cef100a29b2feb91d04d6942e01b785afd43353";
const PROTECTION: &str = "/var/lib/jetstreamer/epoch170-retry4-live167-20261116-v1/launch-v1/epoch170/ACTUAL_GUARD_PROTECTION.json";
const PROTECTION_SHA: &str = "80ad2dc1d71a15d40540d261da68d22484f7b8a1ce171c820afcca9cd3e606c5";
const GUARD_PLAN_SHA: &str = "b1866173970ab0735242699936ccb8a4570d6fc6a6b2a11acbc88510b915af79";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub stop_intent: Bound,
    pub stop_completion: Bound,
}

fn exact_bound(path: &str, sha256: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha256.into(),
    }
}

pub(super) fn exact() -> Request {
    Request {
        stop_intent: exact_bound(INTENT, INTENT_SHA),
        stop_completion: exact_bound(COMPLETION, COMPLETION_SHA),
    }
}

fn validate_evidence(
    intent: &Value,
    complete: &Value,
    admission: &Value,
    protection: &Value,
) -> Result<()> {
    ensure!(
        intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && intent["producer_invocation_id"] == IID
            && intent["plan_sha256"] == GUARD_PLAN_SHA
            && intent["reason"] == "DATA-fulfillment-observation-failed"
            && intent["sample"]["producer"]["invocation_id"] == IID
            && intent["sample"]["producer"]["active"] == "active"
            && intent["sample"]["producer"]["restarts"] == 0
            && intent["sample"]["producer_stop_enabled"] == true
            && intent["sample"]["trip_reason"] == "DATA-fulfillment-observation-failed"
            && intent["sample"]["scratch_deleted"] == false
            && intent["sample"]["remote_mutations"] == false,
        "epoch170 exact DATA-guard stop intent changed"
    );
    let terminal = &complete["terminal"];
    ensure!(
        complete["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && complete["producer_invocation_id"] == IID
            && complete["plan_sha256"] == GUARD_PLAN_SHA
            && complete["intent"] == INTENT
            && complete["scratch_deleted"] == false
            && complete["remote_mutations"] == false
            && complete["r2_mutations"] == false
            && terminal["invocation_id"] == IID
            && terminal["pid"] == 0
            && terminal["restarts"] == 0
            && terminal["active"] == "inactive"
            && terminal["sub"] == "dead"
            && terminal["result"] == "success",
        "epoch170 original retry4 stop did not complete"
    );
    ensure!(
        admission["schema"] == "horizon-standard-replacement-admission-v1"
            && admission["epoch"] == 170
            && admission["producer_unit"] == UNIT
            && admission["producer_invocation_id"] == IID
            && admission["fresh_admission_passed"] == true
            && admission["all_prior_promises_retained"] == true
            && admission["candidate_hard_memory_bytes"] == 73_014_444_032u64
            && admission["resource_credit_bytes"] == 0
            && admission["memory_or_DATA_promise_ending_bytes"] == 0,
        "epoch170 original admission or retained promise differs"
    );
    ensure!(
        protection["schema"] == "horizon-standard-live-peer-protection-v1"
            && protection["epoch"] == 170
            && protection["producer_unit"] == UNIT
            && protection["producer_invocation_id"] == IID
            && protection["admission"]
                == serde_json::to_value(exact_bound(ADMISSION, ADMISSION_SHA))?
            && protection["plan"]["sha256"] == GUARD_PLAN_SHA,
        "epoch170 original guard protection differs"
    );
    Ok(())
}

fn native_closed() -> Result<Value> {
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", UNIT, "-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,NRestarts,Job,Result,ExecMainStatus"])
        .output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty() && output.stdout.len() <= 65_536,
        "epoch170 native terminal query failed"
    );
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("epoch170 native field")?;
        ensure!(
            fields.insert(key.to_owned(), value.to_owned()).is_none(),
            "duplicate epoch170 field"
        );
    }
    let value = serde_json::to_value(fields)?;
    ensure!(
        value["Id"] == UNIT
            && value["LoadState"] == "not-found"
            && value["ActiveState"] == "inactive"
            && value["SubState"] == "dead"
            && value["InvocationID"] == ""
            && value["MainPID"] == "0"
            && value["ControlPID"] == "0"
            && value["ControlGroup"] == ""
            && value["NRestarts"] == "0"
            && value["Job"] == ""
            && value["Result"] == "success"
            && value["ExecMainStatus"] == "0",
        "epoch170 retry4 unit is not collected and closed"
    );
    let cgroup = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    if cgroup.exists() {
        let procs = fs::read_to_string(cgroup.join("cgroup.procs"))?;
        ensure!(
            procs.trim().is_empty(),
            "epoch170 retry4 cgroup still has processes"
        );
    }
    Ok(value)
}

pub(super) fn authenticate(request: &Request) -> Result<Value> {
    ensure!(*request == exact(), "epoch170 exact stop bindings required");
    let intent = bound(&request.stop_intent)?;
    let completion = bound(&request.stop_completion)?;
    let admission = bound(&exact_bound(ADMISSION, ADMISSION_SHA))?;
    let protection = bound(&exact_bound(PROTECTION, PROTECTION_SHA))?;
    validate_evidence(&intent, &completion, &admission, &protection)?;
    native_closed()
}

pub(super) fn declaration(row: &Value, request: &Request) -> Result<()> {
    ensure!(
        *request == exact()
            && row["epoch"] == 170
            && row["state"] == "terminal-retained"
            && row["producer_unit"] == UNIT
            && row["invocation_id"] == IID
            && row["terminal_event"] == serde_json::to_value(&request.stop_completion)?
            && row["retained_memory_promise_bytes"] == 73_014_444_032u64
            && row["memory_resident_deduction_bytes"] == 0
            && row["promise_ending_bytes"] == 0,
        "epoch170 terminal declaration cannot release a resource promise"
    );
    authenticate(request)?;
    Ok(())
}

pub(super) fn endpoint(request: &Request) -> Result<Value> {
    let native = authenticate(request)?;
    Ok(
        json!({"stop_intent":request.stop_intent,"stop_completion":request.stop_completion,
        "admission":exact_bound(ADMISSION,ADMISSION_SHA),"guard_protection":exact_bound(PROTECTION,PROTECTION_SHA),
        "current_native":native,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_guard_stop_is_bound_and_not_a_credit() {
        let request = exact();
        let intent = bound(&request.stop_intent).unwrap();
        let complete = bound(&request.stop_completion).unwrap();
        let admission = bound(&exact_bound(ADMISSION, ADMISSION_SHA)).unwrap();
        let protection = bound(&exact_bound(PROTECTION, PROTECTION_SHA)).unwrap();
        validate_evidence(&intent, &complete, &admission, &protection).unwrap();
        let mut changed = complete.clone();
        changed["terminal"]["pid"] = json!(1);
        assert!(validate_evidence(&intent, &changed, &admission, &protection).is_err());
        let mut changed = intent.clone();
        changed["reason"] = json!("root-physical-budget");
        assert!(validate_evidence(&changed, &complete, &admission, &protection).is_err());
    }
}
