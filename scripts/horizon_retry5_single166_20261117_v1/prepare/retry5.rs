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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub terminal_event: Bound,
    pub prior_preparation: Bound,
    pub prior_admission: Bound,
    pub retired_retry4: Bound,
    pub retired_local2_partial: Bound,
}

fn exact(path: &str, sha256: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha256.into(),
    }
}

pub(super) fn selected(p: &Plan) -> bool {
    p.epoch == 166 && p.attempt == "local3retry5"
}

pub(super) fn shape(p: &Plan) -> Result<()> {
    if !selected(p) {
        ensure!(
            p.attempt != "local3retry5" && p.retry5.is_none(),
            "retry5 is exact166 only"
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
        p.existing_preparation.is_none()
            && p.retry4.is_none()
            && p.fresh_subtree
                == Path::new(
                    "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry5-20261110-v1"
                ),
        "retry5 requires a fresh disjoint root"
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
    ensure!(
        p.data_fulfillment
            .as_ref()
            .is_some_and(|r| r.runtime.path == Path::new(prelaunch_data::RETRY5_RUNTIME)),
        "retry5 requires its own qualified successor DATA guard"
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
    Ok(
        json!({"terminal_event":r.terminal_event,"prior_preparation":r.prior_preparation,"prior_admission":r.prior_admission,"retired_retry4":r.retired_retry4,"retired_local2_partial":r.retired_local2_partial,"old_retry4_invocation_id":OLD_IID,"old_partial_reuse":false,"resource_credit_bytes":0}),
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
}
