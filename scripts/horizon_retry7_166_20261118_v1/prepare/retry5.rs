//! Exact epoch 166 retry5 lineage. The failed retry4 output was retired; the
//! original DATA witnesses and all prior resource promises remain in force.
use super::*;

const TERMINAL: &str =
    "/var/lib/jetstreamer/root0348-oneowner-cycle-20261116-v1/TERMINAL166_EVENT.json";
const TERMINAL_SHA: &str = "0fb4f358747aefaaf5f34e93cfce8156a21cd0abc33138151456f258e2217231";
const PREPARATION: &str =
    "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch166/local3retry4/prepared.json";
const PREPARATION_SHA: &str = "9ef0e9a27edc1863de3b6a4a2cbd0f338fa9720259c62f17f0ba62f304810c8c";
const ADMISSION: &str = "/var/lib/jetstreamer/retry4-single166-guarded-launch-20261114-v5/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json";
const ADMISSION_SHA: &str = "3c02237052a6b25a28c9f5026714a1fa530da2283c647628f2136b3843d0d582";
const RETIREMENT: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/receipts/retire166-completion-v1.json";
const RETIREMENT_SHA: &str = "92dd1eeec86a8289bc7cc23a59e8dac2eb1e0814dd6623ff321095db3363992e";
const LOCAL2: &str =
    "/home/sol/horizon-disk-audit-20261116T2052Z/OLD166-LOCAL2-RETIREMENT-PROOF.json";
const LOCAL2_SHA: &str = "08d07989b1121674e63c79a330a27586431dd89ada83e93b6893bd9428f86514";
const OLD_UNIT: &str = "horizon-qualify-166-replacement-local3retry4-20261110-v1.service";
const OLD_IID: &str = "58778e77980e4a15828c3be837e447aa";
const FAILED_RETRY5: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch166/local3retry5/guard-state/receipts/sample-5b03cac176234482a2afd31bcbf3cdec.json";
const FAILED_RETRY5_SHA: &str = "04b669f00269fa7995e8fb8175fd4a8a226279f224a06bae16600ae8d6927b9e";
const FAILED_RETRY5_IID: &str = "4e97705db1b04ab3846a2857e0db158b";
const FAILED_RETRY5_STOP: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch166/local3retry5/guard-state/receipts/stop-completion.json";
const FAILED_RETRY5_STOP_SHA: &str =
    "7b08bb184942fd5f43274dbe25a0eb29e9514ff87e40456480013df4535f1bef";
const FAILED_RETRY5_SETUP: &str =
    "/var/lib/jetstreamer/retry5-single166-guarded-launch-20261117-v1/epoch166/FAILED_SETUP.json";
const FAILED_RETRY5_SETUP_SHA: &str =
    "246b64c2451b6e568b2d03cfadb1a5fe48a8e1f13699c80b6904f3ef75b3fccd";
const FAILED_RETRY6_STOP: &str = "/var/lib/jetstreamer/retry6-preparation-20261117-v1/epoch166/local3retry6/guard-state/receipts/stop-intent.json";
const FAILED_RETRY6_STOP_SHA: &str =
    "3901e732145152e22372c63c32c3744833cfc1c10f45d11e9e7a9c34fed25074";
const FAILED_RETRY6_COMPLETION: &str = "/var/lib/jetstreamer/retry6-preparation-20261117-v1/epoch166/local3retry6/guard-state/receipts/stop-completion.json";
const FAILED_RETRY6_COMPLETION_SHA: &str =
    "34a92966ddb3007db7f1a06bfb0668f48856ebaa725937eacd9088df0a050f01";
const FAILED_RETRY6_IID: &str = "b3992e492e1a4d49a9e4e4a01a13c815";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub terminal_event: Bound,
    pub prior_preparation: Bound,
    pub prior_admission: Bound,
    pub retired_retry4: Bound,
    pub retired_local2_partial: Bound,
    #[serde(default)]
    pub failed_retry5: Option<Bound>,
    #[serde(default)]
    pub failed_retry6: Option<Bound>,
}

fn exact(path: &str, sha256: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha256.into(),
    }
}

pub(super) fn selected(p: &Plan) -> bool {
    p.epoch == 166 && ["local3retry5", "local3retry6", "local3retry7"].contains(&p.attempt.as_str())
}

pub(super) fn shape(p: &Plan) -> Result<()> {
    if !selected(p) {
        ensure!(
            !["local3retry5", "local3retry6", "local3retry7"].contains(&p.attempt.as_str())
                && p.retry5.is_none(),
            "retry5 lineage is exact166 only"
        );
        return Ok(());
    }
    let r = p
        .retry5
        .as_ref()
        .context("retry5 exact terminal and retirement bindings required")?;
    ensure!(
        r.terminal_event == exact(TERMINAL, TERMINAL_SHA)
            && r.prior_preparation == exact(PREPARATION, PREPARATION_SHA)
            && r.prior_admission == exact(ADMISSION, ADMISSION_SHA)
            && r.retired_retry4 == exact(RETIREMENT, RETIREMENT_SHA)
            && r.retired_local2_partial == exact(LOCAL2, LOCAL2_SHA),
        "retry5 exact predecessor or retirement binding differs"
    );
    ensure!(
        if ["local3retry6", "local3retry7"].contains(&p.attempt.as_str()) {
            r.failed_retry5 == Some(exact(FAILED_RETRY5, FAILED_RETRY5_SHA))
        } else {
            r.failed_retry5.is_none()
        },
        "retry6 requires exact failed retry5 guard sample"
    );
    ensure!(
        if p.attempt == "local3retry7" {
            r.failed_retry6 == Some(exact(FAILED_RETRY6_STOP, FAILED_RETRY6_STOP_SHA))
        } else {
            r.failed_retry6.is_none()
        },
        "retry7 requires exact stopped retry6 guard intent"
    );
    ensure!(
        p.existing_preparation.is_none()
            && p.retry4.is_none()
            && p.fresh_subtree
                == Path::new(&format!(
                    "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-{}-20261110-v1",
                    p.attempt
                )),
        "retry5/retry6 requires a fresh disjoint root"
    );
    for unit in [
        OLD_UNIT,
        "horizon-guard-replacement-166-local3retry4-20261110-v1.service",
        "horizon-guard-replacement-166-local3retry4-20261110-v1.timer",
        "horizon-qualify-166-replacement-local2-20261110-v1.service",
    ] {
        ensure!(
            p.closed_units.iter().any(|u| u == unit),
            "retired producer or guard omitted"
        );
    }
    if ["local3retry6", "local3retry7"].contains(&p.attempt.as_str()) {
        for unit in [
            "horizon-qualify-166-replacement-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry5-20261110-v1.timer",
        ] {
            ensure!(
                p.closed_units.iter().any(|candidate| candidate == unit),
                "failed retry5 owner omitted"
            );
        }
    }
    if p.attempt == "local3retry7" {
        for unit in [
            "horizon-qualify-166-replacement-local3retry6-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry6-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry6-20261110-v1.timer",
        ] {
            ensure!(
                p.closed_units.iter().any(|candidate| candidate == unit),
                "stopped retry6 owner omitted"
            );
        }
    }
    let required_guard = if p.attempt == "local3retry7" {
        prelaunch_data::RETRY7_RUNTIME
    } else if p.attempt == "local3retry6" {
        prelaunch_data::RETRY6_RUNTIME
    } else {
        prelaunch_data::RETRY5_RUNTIME
    };
    ensure!(
        p.data_fulfillment
            .as_ref()
            .is_some_and(|r| r.runtime.path == Path::new(required_guard)),
        "retry5/retry6 requires its exact qualified successor DATA guard"
    );
    Ok(())
}

pub(super) fn authenticate(p: &Plan) -> Result<Value> {
    shape(p)?;
    if !selected(p) {
        return Ok(Value::Null);
    }
    let r = p.retry5.as_ref().context("retry5 binding")?;
    let terminal = bound(&r.terminal_event)?;
    let preparation = bound(&r.prior_preparation)?;
    let admission = bound(&r.prior_admission)?;
    let retired = bound(&r.retired_retry4)?;
    let local2 = bound(&r.retired_local2_partial)?;
    ensure!(
        terminal["epoch"] == 166
            && terminal["owner"] == "/root"
            && terminal["primary_thread"] == THREAD
            && terminal["original_invocation_id"] == OLD_IID
            && terminal["active_replay_epochs"] == json!([])
            && terminal["resource_credit_bytes"] == 0
            && terminal["reason"].as_str().is_some_and(
                |s| s.contains("root physical allocation309894897664 exceeding309237645312")
            ),
        "retry4 terminal evidence differs"
    );
    ensure!(
        preparation["schema"] == "horizon-standard-replacement-recipe-preparation-v1"
            && preparation["epoch"] == 166
            && preparation["attempt"] == "local3retry4"
            && admission["schema"] == "horizon-standard-replacement-admission-v1"
            && admission["epoch"] == 166
            && admission["owner"] == "/root"
            && admission["primary_thread"] == THREAD
            && admission["producer_unit"] == OLD_UNIT
            && admission["producer_invocation_id"] == OLD_IID
            && admission["fresh_native_Rust_preparation"]
                == serde_json::to_value(&r.prior_preparation)?
            && admission["fresh_admission_passed"] == true
            && admission["resource_credit_bytes"] == 0,
        "prior retry4 admission and preparation differ"
    );
    ensure!(
        retired["schema"] == "jetstreamer-holding-retire166-completion-v1"
            && retired["members_retired"] == 7
            && retired["remote_mutations"] == false
            && retired["replay_launch_authorized"] == false
            && retired["observer_log_and_scratch_preserved"] == true
            && local2["schema"] == "horizon-old166-local2-partial-retirement-evidence-v1"
            && local2["epoch"] == 166
            && local2["phase"] == "retired"
            && local2["archive_allocated_bytes"] == 65_280_708_608u64
            && local2["active_DATA_witness_member"] == false
            && local2["remote_mutations"] == false,
        "exact local retirements differ"
    );
    let old_retry4 = retired["intent"]["members"][0]["path"]
        .as_str()
        .context("old retry4 archive path")?;
    let old_local2 = local2["archive_path"]
        .as_str()
        .context("old local2 archive path")?;
    for old in [old_retry4, old_local2] {
        ensure!(
            fs::symlink_metadata(old).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "retired partial archive reappeared or is inaccessible"
        );
    }
    let receipt: Bound = serde_json::from_value(local2["cleanup_receipt"].clone())?;
    ensure!(
        digest(&raw(&receipt.path, 1 << 20, false)?) == receipt.sha256,
        "local2 cleanup receipt differs"
    );
    let failed_retry5 = if ["local3retry6", "local3retry7"].contains(&p.attempt.as_str()) {
        let sample_binding = r.failed_retry5.as_ref().context("failed retry5 binding")?;
        let sample = bound(sample_binding)?;
        let stop_binding = exact(FAILED_RETRY5_STOP, FAILED_RETRY5_STOP_SHA);
        let stop = bound(&stop_binding)?;
        let setup_binding = exact(FAILED_RETRY5_SETUP, FAILED_RETRY5_SETUP_SHA);
        let setup = bound(&setup_binding)?;
        ensure!(
            sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                && sample["producer_invocation_id"] == FAILED_RETRY5_IID
                && sample["trip_reason"] == "DATA-fulfillment-observation-failed"
                && sample["DATA_fulfillment_observation_error"]
                    == "exact admitted local2 or selected local3 unit required"
                && stop["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
                && stop["producer_invocation_id"] == FAILED_RETRY5_IID
                && stop["plan_sha256"] == sample["plan_sha256"]
                && stop["scratch_deleted"] == false
                && setup["error"] == "guard sample DATA or identity proof invalid"
                && setup["guard_timer_start_confirmed"] == true
                && setup["originals_preserved"] == true,
            "retry5 failed guard and stop evidence differs"
        );
        Some(
            json!({"sample":sample_binding,"stop":stop_binding,"setup":setup_binding,
            "producer_invocation_id":FAILED_RETRY5_IID,"partial_reuse":false}),
        )
    } else {
        None
    };
    let failed_retry6 = if p.attempt == "local3retry7" {
        let stop_binding = r
            .failed_retry6
            .as_ref()
            .context("failed retry6 intent binding")?;
        let stop = bound(stop_binding)?;
        let completion_binding = exact(FAILED_RETRY6_COMPLETION, FAILED_RETRY6_COMPLETION_SHA);
        let completion = bound(&completion_binding)?;
        ensure!(
            stop["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
                && stop["producer_invocation_id"] == FAILED_RETRY6_IID
                && stop["reason"] == "DATA-fulfillment-observation-failed"
                && stop["sample"]["DATA_fulfillment_observation_error"]
                    == "anchored no-follow open failed: No such file or directory (os error 2)"
                && completion["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
                && completion["producer_invocation_id"] == FAILED_RETRY6_IID
                && completion["plan_sha256"] == stop["plan_sha256"]
                && completion["scratch_deleted"] == false,
            "retry6 guard stop evidence differs"
        );
        Some(
            json!({"stop_intent":stop_binding,"stop_completion":completion_binding,"producer_invocation_id":FAILED_RETRY6_IID,"scratch_preserved":true,"partial_reuse":false}),
        )
    } else {
        None
    };
    Ok(
        json!({"terminal_event":r.terminal_event,"prior_preparation":r.prior_preparation,"prior_admission":r.prior_admission,"retired_retry4":r.retired_retry4,"retired_local2_partial":r.retired_local2_partial,"old_retry4_invocation_id":OLD_IID,"failed_retry5":failed_retry5,"failed_retry6":failed_retry6,"old_partial_reuse":false,"resource_credit_bytes":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        let mut p: Plan = serde_json::from_str(include_str!(
            "../emitter/epoch166.RETRY4_PLAN.SOURCE_TEMPLATE.json"
        ))
        .unwrap();
        p.attempt = "local3retry5".into();
        p.retry4 = None;
        p.retry5 = Some(Request {
            terminal_event: exact(TERMINAL, TERMINAL_SHA),
            prior_preparation: exact(PREPARATION, PREPARATION_SHA),
            prior_admission: exact(ADMISSION, ADMISSION_SHA),
            retired_retry4: exact(RETIREMENT, RETIREMENT_SHA),
            retired_local2_partial: exact(LOCAL2, LOCAL2_SHA),
            failed_retry5: None,
            failed_retry6: None,
        });
        p.fresh_subtree = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry5-20261110-v1".into();
        p.closed_units.extend([
            OLD_UNIT.into(),
            "horizon-guard-replacement-166-local3retry4-20261110-v1.service".into(),
            "horizon-guard-replacement-166-local3retry4-20261110-v1.timer".into(),
            "horizon-qualify-166-replacement-local2-20261110-v1.service".into(),
        ]);
        p.data_fulfillment = Some(crate::prelaunch_data::tests::request());
        p.data_fulfillment.as_mut().unwrap().runtime.path = prelaunch_data::RETRY5_RUNTIME.into();
        p.data_fulfillment.as_mut().unwrap().runtime_seal.path =
            Path::new(prelaunch_data::RETRY5_RUNTIME)
                .parent()
                .unwrap()
                .join("deployment-seal-receipt.json");
        p
    }

    fn retry6_plan() -> Plan {
        let mut p = plan();
        p.attempt = "local3retry6".into();
        p.retry5.as_mut().unwrap().failed_retry5 = Some(exact(FAILED_RETRY5, FAILED_RETRY5_SHA));
        p.fresh_subtree = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1".into();
        p.closed_units.extend([
            "horizon-qualify-166-replacement-local3retry5-20261110-v1.service".into(),
            "horizon-guard-replacement-166-local3retry5-20261110-v1.service".into(),
            "horizon-guard-replacement-166-local3retry5-20261110-v1.timer".into(),
        ]);
        let data = p.data_fulfillment.as_mut().unwrap();
        data.runtime.path = prelaunch_data::RETRY6_RUNTIME.into();
        data.runtime_seal.path = Path::new(prelaunch_data::RETRY6_RUNTIME)
            .parent()
            .unwrap()
            .join("deployment-seal-receipt.json");
        p
    }

    fn retry7_plan() -> Plan {
        let mut p = retry6_plan();
        p.attempt = "local3retry7".into();
        p.retry5.as_mut().unwrap().failed_retry6 =
            Some(exact(FAILED_RETRY6_STOP, FAILED_RETRY6_STOP_SHA));
        p.fresh_subtree = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1".into();
        p.closed_units.extend([
            "horizon-qualify-166-replacement-local3retry6-20261110-v1.service".into(),
            "horizon-guard-replacement-166-local3retry6-20261110-v1.service".into(),
            "horizon-guard-replacement-166-local3retry6-20261110-v1.timer".into(),
        ]);
        let data = p.data_fulfillment.as_mut().unwrap();
        data.runtime.path = prelaunch_data::RETRY7_RUNTIME.into();
        data.runtime_seal.path = Path::new(prelaunch_data::RETRY7_RUNTIME)
            .parent()
            .unwrap()
            .join("deployment-seal-receipt.json");
        p
    }

    #[test]
    fn retry5_requires_exact_terminal_and_both_retirements() {
        let mut p = plan();
        shape(&p).unwrap();
        p.retry5.as_mut().unwrap().retired_local2_partial.sha256 = "0".repeat(64);
        assert!(shape(&p).is_err());
    }

    #[test]
    fn retry5_rejects_foreign_epoch_and_in_place_reuse() {
        let mut p = plan();
        p.epoch = 167;
        assert!(shape(&p).is_err());
        let mut p = plan();
        p.fresh_subtree = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry4-20261110-v1".into();
        assert!(shape(&p).is_err());
    }

    #[test]
    fn actual_predecessor_and_retirement_evidence_is_authenticated() {
        let result = authenticate(&plan()).unwrap();
        assert_eq!(result["old_retry4_invocation_id"], OLD_IID);
        assert_eq!(result["old_partial_reuse"], false);
    }

    #[test]
    fn retry6_requires_failed_retry5_lineage_and_closed_units() {
        let mut p = retry6_plan();
        shape(&p).unwrap();
        p.retry5.as_mut().unwrap().failed_retry5 = None;
        assert!(shape(&p).is_err());
        let mut p = retry6_plan();
        p.closed_units.pop();
        assert!(shape(&p).is_err());
        let mut p = retry6_plan();
        p.data_fulfillment.as_mut().unwrap().runtime.path = prelaunch_data::RETRY5_RUNTIME.into();
        assert!(shape(&p).is_err());
    }

    #[test]
    fn retry6_authenticates_actual_failed_guard_and_stop() {
        let result = authenticate(&retry6_plan()).unwrap();
        assert_eq!(
            result["failed_retry5"]["producer_invocation_id"],
            FAILED_RETRY5_IID
        );
        assert_eq!(result["failed_retry5"]["partial_reuse"], false);
    }

    #[test]
    fn retry7_requires_stopped_retry6_and_exact_new_guard() {
        let mut p = retry7_plan();
        shape(&p).unwrap();
        p.retry5.as_mut().unwrap().failed_retry6 = None;
        assert!(shape(&p).is_err());
        let mut p = retry7_plan();
        p.closed_units.pop();
        assert!(shape(&p).is_err());
        let mut p = retry7_plan();
        p.data_fulfillment.as_mut().unwrap().runtime.path = prelaunch_data::RETRY6_RUNTIME.into();
        assert!(shape(&p).is_err());
        let result = authenticate(&retry7_plan()).unwrap();
        assert_eq!(
            result["failed_retry6"]["producer_invocation_id"],
            FAILED_RETRY6_IID
        );
        assert_eq!(result["failed_retry6"]["scratch_preserved"], true);
    }
}
