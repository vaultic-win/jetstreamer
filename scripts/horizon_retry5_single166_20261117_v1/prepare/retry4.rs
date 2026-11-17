//! Exact166 retry4 continuation. Original retry2 lineage remains independently
//! validated; these additional immutable receipts bind the intervening retry3.
use super::*;
const IID: &str = "7fa1849bd3a74fd78d5e3322e2e57016";
const OLD_UNIT: &str = "horizon-qualify-166-replacement-local3retry3-20261110-v1.service";
const STOP: &str = "/var/lib/jetstreamer/retry3-scratch166-retirement-qualification-20261113-v1/ORIGINAL_EPOCH166_STOP_EVIDENCE.json";
const STOP_SHA: &str = "afc574421f324d5895627709b1cfa8bfa4dbfb724264236eb18879d40b13a544";
const RETIRED: &str = "/var/lib/jetstreamer/retry3-scratch166-native-retirement-20261113-v1/ROOT_ACTUAL_CONTENTS_RETIREMENT_COMPLETE.json";
const RETIRED_SHA: &str = "9d6e31490155f349ef07e19504a86db67f8b70f414c249f634bd7ac8a38f9d0d";
const COMPLETION: &str =
    "/var/lib/jetstreamer/retry3-scratch166-retirement-20261113-v1/epoch166/completion.json";
const COMPLETION_SHA: &str = "47f50739d2e674b924e800991ebdfc19017a4847034b0d85f67e9f685d271205";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub stopped_event: Bound,
    pub retired_scratch: Bound,
}
pub(super) fn selected(p: &Plan) -> bool {
    p.epoch == 166 && p.attempt == "local3retry4"
}
fn exact(path: &str, hash: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: hash.into(),
    }
}
pub(super) fn shape(p: &Plan) -> Result<()> {
    if !selected(p) {
        ensure!(
            p.attempt != "local3retry4" && p.retry4.is_none(),
            "retry4 is exact166 only"
        );
        return Ok(());
    }
    let r = p
        .retry4
        .as_ref()
        .context("retry4 original stop/retirement required")?;
    ensure!(
        r.stopped_event == exact(STOP, STOP_SHA)
            && r.retired_scratch == exact(RETIRED, RETIRED_SHA),
        "retry4 exact historical binding differs"
    );
    ensure!(
        p.existing_preparation.is_none()
            && p.fresh_subtree
                == Path::new(
                    "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry4-20261110-v1"
                ),
        "retry4 requires precreated disjoint empty root"
    );
    for unit in [
        OLD_UNIT,
        "horizon-guard-replacement-166-local3retry3-20261110-v1.service",
        "horizon-guard-replacement-166-local3retry3-20261110-v1.timer",
    ] {
        ensure!(
            p.closed_units.iter().any(|u| u == unit),
            "old retry3 owner/guard omitted"
        );
    }
    ensure!(
        p.data_fulfillment
            .as_ref()
            .is_some_and(|r| r.runtime.path == Path::new(prelaunch_data::RUNTIME)),
        "retry4 requires own-image successor guard"
    );
    Ok(())
}
fn validate(stop: &Value, retired: &Value, done: &Value) -> Result<()> {
    ensure!(
        stop["epoch"] == 166
            && stop["reason"] == "DATA-fulfillment-observation-failed"
            && stop["original_claim"]["producer_unit"] == OLD_UNIT
            && stop["original_claim"]["expected_producer_invocation_id"] == IID
            && stop["original_claim"]["expected_controller_invocation_id"] == IID
            && stop["original_invocation_children"] == json!([])
            && stop["all_original_promises_retained"] == true
            && stop["resource_credit_bytes"] == 0,
        "exact retry3 stopped lineage differs"
    );
    let rows = stop["original_PID1"]
        .as_array()
        .context("original PID1 records")?;
    ensure!(
        rows.iter().any(|r| r["_PID"] == "1"
            && r["_UID"] == "0"
            && r["UNIT"] == OLD_UNIT
            && r["INVOCATION_ID"] == IID
            && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"),
        "original retry3 PID1 completion missing"
    );
    ensure!(
        retired["owner"] == "/root"
            && retired["completion"] == serde_json::to_value(exact(COMPLETION, COMPLETION_SHA))?
            && retired["scratch_before_physical_bytes"] == 36_101_939_200u64
            && retired["scratch_after_physical_bytes"] == 4096
            && retired["retired_physical_bytes"] == 36_101_935_104u64
            && retired["scratch_inode_preserved"] == true
            && retired["archives_inputs_original_witnesses_preserved"] == true
            && retired["new_admission_required"] == true
            && retired["no_resource_promise_release"] == true,
        "exact retry3 scratch retirement differs"
    );
    ensure!(
        done["schema"] == "jetstreamer-retry3-scratch166-complete-v1"
            && done["basis"]["source"]["original_retry3_stop_event"]
                == serde_json::to_value(exact(STOP, STOP_SHA))?
            && done["basis"]["scratch_identity"]["device"] == 64512
            && done["basis"]["scratch_identity"]["inode"] == 103284833
            && done["scratch_empty"] == true
            && done["scratch_root_preserved"] == true
            && done["partial_archive_and_all_inputs_preserved"] == true
            && done["archive_deletion_authorized"] == false
            && done["replay_launch_authorized"] == false
            && done["resource_promise_ending_authorized"] == false
            && done["resource_credit_bytes"] == 0
            && done["remote_mutations"] == false
            && done["r2_mutations"] == false,
        "retry4 cannot consume old output or release promises"
    );
    Ok(())
}
pub(super) fn authenticate(p: &Plan) -> Result<Value> {
    shape(p)?;
    if !selected(p) {
        return Ok(Value::Null);
    }
    let r = p.retry4.as_ref().context("retry4 bindings")?;
    let stop = bound(&r.stopped_event)?;
    let retired = bound(&r.retired_scratch)?;
    let completion = exact(COMPLETION, COMPLETION_SHA);
    let done = bound(&completion)?;
    validate(&stop, &retired, &done)?;
    Ok(
        json!({"original_stop":r.stopped_event,"original_failed_invocation_id":IID,"actual_scratch_retirement":r.retired_scratch,"completion":completion,"retirement_bytes_already_in_current_free_not_new_credit":true,"resource_credit_bytes":0,"old_partial_and_inputs_preserved":true}),
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
        p.data_fulfillment = Some(crate::prelaunch_data::tests::request());
        p
    }
    #[test]
    fn exact_retry4_selects_only166_and_keeps_current_budget() {
        let mut p = plan();
        shape(&p).unwrap();
        crate::shapes(&p).unwrap();
        assert!(current_budget::selected(&p));
        for e in [167, 168, 169, 170, 171, 172] {
            p.epoch = e;
            assert!(shape(&p).is_err());
        }
    }
    #[test]
    fn stale_binding_old_root_and_omitted_owner_reject() {
        let mut p = plan();
        p.retry4.as_mut().unwrap().stopped_event.sha256 = "0".repeat(64);
        assert!(shape(&p).is_err());
        let mut p = plan();
        p.fresh_subtree="/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry3-20261110-v1".into();
        assert!(shape(&p).is_err());
        let mut p = plan();
        p.closed_units.retain(|u| u != OLD_UNIT);
        assert!(shape(&p).is_err());
    }
    #[test]
    fn retained_legacy_plan_needs_no_retry4_receipt() {
        let p = crate::tests::plan();
        shape(&p).unwrap();
        assert!(!selected(&p));
    }
    #[test]
    fn exact_retained_lineage_and_changed_iid_or_released_promise() {
        let f: Value = serde_json::from_str(include_str!("retry4-lineage-fixture.json")).unwrap();
        validate(&f["stop"], &f["retired"], &f["completion"]).unwrap();
        let mut bad = f.clone();
        bad["stop"]["original_claim"]["expected_producer_invocation_id"] =
            json!("00000000000000000000000000000000");
        assert!(validate(&bad["stop"], &bad["retired"], &bad["completion"]).is_err());
        let mut bad = f.clone();
        bad["completion"]["resource_credit_bytes"] = json!(1);
        assert!(validate(&bad["stop"], &bad["retired"], &bad["completion"]).is_err());
        let mut bad = f;
        bad["completion"]["partial_archive_and_all_inputs_preserved"] = json!(false);
        assert!(validate(&bad["stop"], &bad["retired"], &bad["completion"]).is_err());
    }
}
