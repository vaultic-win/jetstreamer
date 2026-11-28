//! Exact epoch167 retry5 proposal. Qualification, capacity booking and launch are separate gates.
use super::*;

pub(super) const ATTEMPT: &str = "local3retry5";
pub(super) const CANDIDATE_CAP: u64 = 512 << 30;
pub(super) const CAP_DELTA: u64 = CANDIDATE_CAP - ROOT_CAP;
pub(super) const COMPLETE_DATA: u64 = completed167::COMPLETE_DATA + CAP_DELTA;
pub(super) const RAW_FLOOR: u64 = completed167::RAW_FLOOR + CAP_DELTA;
pub(super) const SCHEMA: &str = "horizon-epoch167-retry5-native-allocation-v1";
pub(super) const WORKING_SET_SCHEMA: &str = "horizon-epoch167-retry5-cap512-working-set-v1";
const STOP: &str = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-controls-v7/peer170-terminal169-build-v4/terminal167-event-v1/EVENT.json";
const STOP_SHA: &str = "e9a1f5047280ff29b5579ee6fee4516ae90a19b43c015cc69072ab48376ecd97";
const COMPLETION: &str = "/home/sol/.jetstreamer-private/retry3-scratch167-retirement-20261115-v2/epoch167/completion.json";
const COMPLETION_SHA: &str = "dedf9ba9081847bc2ac4e7ac8aad946fbe1b9f19018de9b2db7314f14aa5d683";
const ACCEPTANCE: &str = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-controls-v7/scratch167-build-v3/operation-v1/execute/ROOT_ACTUAL_ACCEPTANCE.json";
const ACCEPTANCE_SHA: &str = "7178a935813abe5f162cc719f08110379a25a7b5b097125fd3ecd99f3fc00f75";
const TERMINAL: &str = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-controls-v7/scratch167-build-v3/operation-v1/execute/ORIGINAL_TERMINAL.json";
const TERMINAL_SHA: &str = "69f97842ba4f3ac15414c6028621b7deb2a8bd8b71f346101386b31471185c47";
const SEQUENCE: &str = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-controls-v7/scratch167-build-v3/operation-v1/ROOT_SEQUENCE_COMPLETED.json";
const SEQUENCE_SHA: &str = "d7a3a2a93439ae501439aa96a1473474148bf313556c00551a305bbd172c9a7b";
const OLD_IID: &str = "7ce90d0ec8114cf3a6be73eb9cf75ae8";
const OLD_UNIT: &str = "horizon-qualify-167-replacement-local3retry3-20261110-v1.service";
const RETIRE_IID: &str = "ca95481b36a3417ca3e7b3721551f025";
const RETIRE_UNIT: &str = "horizon-retry3-scratch167-retire-167-execute-20261115-v2.service";
const SCRATCH: &str = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry3-20261110-v1/private/destination-86634fd7a4241d45f1595fc598908bb3b6c7c9bccdecae2837b8420c0d050d78/work/root-cohort-167-167/run-3120563-1794606106965328489/scratch";
const BOOKING_DIRECTORY: &str = "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1";
#[cfg(test)]
const TEST_BOOKING: &str = "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING-20261117T1825Z.json";
const PEER_UNIT: &str = "horizon-qualify-166-replacement-local3retry6-20261110-v1.service";
const PEER_IID: &str = "b3992e492e1a4d49a9e4e4a01a13c815";
const PEER_ADMISSION: &str = "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json";
const PEER_ADMISSION_SHA: &str = "24033084033ab661720ea714cce584fdee4464a14e845563bb43de200ca0eb81";
const PEER_PROTECTION: &str = "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_GUARD_PROTECTION.json";
const PEER_PROTECTION_SHA: &str =
    "21cb4ced79b12be21c3f5011f7de183909078afa3f4826ef3c0e509bed0afa5d";
const STOP_RETRY4_167: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry4/guard-state/receipts/stop-completion.json";
const STOP_RETRY4_167_SHA: &str =
    "2b45af4f5d058e51f291cf1c80d0c23b05a171b2e646d7d72b117d8e7bf6ea8d";
const INTENT_RETRY4_167: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry4/guard-state/receipts/stop-intent.json";
const INTENT_RETRY4_167_SHA: &str =
    "a1a17d316becfc970aa39de16fb0d8e6db4b73595af8977e5887eefea3ea4657";
const IID_RETRY4_167: &str = "3eaae9a18cc64bdd89ca1d14fe9e9819";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub stopped_event: Bound,
    pub retirement: Bound,
    pub native_acceptance: Bound,
    pub completed_sequence: Bound,
    pub additive_data_booking: Bound,
    pub stopped_retry4_167: Bound,
    pub stopped_retry4_170: terminal170::Request,
}
fn exact(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn booking_path(path: &Path) -> bool {
    path.parent() == Some(Path::new(BOOKING_DIRECTORY))
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.strip_prefix("ROOT_DATA_BOOKING-")
                    .and_then(|suffix| suffix.strip_suffix(".json"))
                    .is_some_and(|stamp| {
                        stamp.len() == 14
                            && stamp.as_bytes()[..8].iter().all(u8::is_ascii_digit)
                            && stamp.as_bytes()[8] == b'T'
                            && stamp.as_bytes()[9..13].iter().all(u8::is_ascii_digit)
                            && stamp.as_bytes()[13] == b'Z'
                    })
            })
}
pub(super) fn selected(p: &Plan) -> bool {
    p.epoch == 167 && p.attempt == ATTEMPT
}
pub(super) fn candidate_cap(p: &Plan) -> u64 {
    if selected(p) { CANDIDATE_CAP } else { ROOT_CAP }
}
pub(super) fn root_cap(p: &Plan, epoch: u64) -> u64 {
    if selected(p) && epoch == 167 {
        CANDIDATE_CAP
    } else {
        ROOT_CAP
    }
}
pub(super) fn is_protected166(epoch: u64, unit: &str, iid: &str) -> bool {
    epoch == 166 && unit == PEER_UNIT && iid == PEER_IID
}
fn peer_rows(v: &Value) -> Result<()> {
    let rows = v.as_array().context("exact166 resident owner array")?;
    ensure!(rows.len() == 1, "one exact protected166 peer is required");
    let r = &rows[0];
    ensure!(
        r["epoch"] == 166
            && r["unit"] == PEER_UNIT
            && r["invocation_id"] == PEER_IID
            && r["main_pid"] == 689067
            && r["main_start_ticks"] == 326476185u64
            && r["admission"] == serde_json::to_value(exact(PEER_ADMISSION, PEER_ADMISSION_SHA))?
            && r["guard_protection"]
                == serde_json::to_value(exact(PEER_PROTECTION, PEER_PROTECTION_SHA))?,
        "protected166 process, admission or guard identity differs"
    );
    Ok(())
}
pub(super) fn memory_scope(r: &resident_memory::Request) -> Result<u64> {
    ensure!(
        r.admission_only_capture
            && r.host_kernel_same_resident_basis
            && r.terminal166.is_none()
            && r.terminal167.as_ref() == Some(&terminal167::exact())
            && r.terminal169.as_ref() == Some(&terminal169::exact())
            && r.terminal170.as_ref() == Some(&terminal170::exact()),
        "candidate167 requires exact live166 and stopped167/169/170 lineage"
    );
    terminal170::authenticate(r.terminal170.as_ref().context("stopped170 evidence")?)?;
    peer_rows(&serde_json::to_value(&r.owners)?)?;
    Ok(COMPLETE_DATA)
}
pub(super) fn shape(p: &Plan) -> Result<()> {
    if !selected(p) {
        ensure!(
            p.retry167.is_none(),
            "epoch167 successor evidence on another route"
        );
        return Ok(());
    }
    let r = p
        .retry167
        .as_ref()
        .context("exact167 successor proof required")?;
    ensure!(
        r.stopped_event == exact(STOP, STOP_SHA)
            && r.retirement == exact(COMPLETION, COMPLETION_SHA)
            && r.native_acceptance == exact(ACCEPTANCE, ACCEPTANCE_SHA)
            && r.completed_sequence == exact(SEQUENCE, SEQUENCE_SHA)
            && booking_path(&r.additive_data_booking.path)
            && lower_hex(&r.additive_data_booking.sha256, 64)
            && r.stopped_retry4_167 == exact(STOP_RETRY4_167, STOP_RETRY4_167_SHA)
            && r.stopped_retry4_170 == terminal170::exact()
            && p.retry4.is_none()
            && p.retry3.is_some()
            && p.existing_preparation.is_none()
            && p.fresh_subtree
                == Path::new(
                    "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry5-20261110-v1"
                )
            && p.current_allocation
                .as_ref()
                .is_some_and(|v| v.schema == SCHEMA)
            && p.data_fulfillment
                .as_ref()
                .is_some_and(|v| v.runtime.path == Path::new(retry167_native_guard::RUNTIME)),
        "exact fresh167 route, lineage, additive reservation and successor guard required"
    );
    for u in [
        OLD_UNIT,
        "horizon-guard-replacement-167-local3retry3-20261110-v1.service",
        "horizon-guard-replacement-167-local3retry3-20261110-v1.timer",
        "horizon-qualify-167-replacement-local3retry4-20261110-v1.service",
        "horizon-guard-replacement-167-local3retry4-20261110-v1.service",
        "horizon-guard-replacement-167-local3retry4-20261110-v1.timer",
        "horizon-qualify-170-replacement-local3retry4-20261110-v1.service",
    ] {
        ensure!(
            p.closed_units.iter().any(|x| x == u),
            "old167 owner or guard omitted"
        );
    }
    memory_scope(
        p.resident_memory
            .as_ref()
            .context("protected166 resident request")?,
    )?;
    Ok(())
}
fn validate_retirement(
    stop: &Value,
    done: &Value,
    acceptance: &Value,
    sequence: &Value,
    native: &Value,
) -> Result<()> {
    ensure!(
        stop["epoch"] == 167
            && stop["owner"] == "/root"
            && stop["primary_thread"] == THREAD
            && stop["original_invocation_id"] == OLD_IID
            && stop["resource_credit_bytes"] == 0,
        "original167 stop identity differs"
    );
    ensure!(
        done["schema"] == "jetstreamer-retry3-scratch167-complete-v1"
            && done["basis"]["source"]["original_retry3_stop_event"]
                == serde_json::to_value(exact(STOP, STOP_SHA))?
            && done["basis"]["scratch_identity"]["device"] == 64512
            && done["basis"]["scratch_identity"]["inode"] == 104136881u64
            && done["scratch_empty"] == true
            && done["scratch_root_preserved"] == true
            && done["partial_archive_and_all_inputs_preserved"] == true
            && done["archive_deletion_authorized"] == false
            && done["replay_launch_authorized"] == false
            && done["resource_promise_ending_authorized"] == false
            && done["resource_credit_bytes"] == 0
            && done["remote_mutations"] == false
            && done["r2_mutations"] == false,
        "actual167 retirement identity, preservation or authority differs"
    );
    ensure!(
        acceptance["owner"] == "/root"
            && acceptance["phase"] == "execute"
            && acceptance["receipt"] == serde_json::to_value(exact(COMPLETION, COMPLETION_SHA))?
            && acceptance["terminal"] == serde_json::to_value(exact(TERMINAL, TERMINAL_SHA))?
            && acceptance["invocation_id"] == RETIRE_IID
            && acceptance["replay_launch_authorized"] == false
            && sequence["owner"] == "/root"
            && sequence["execute"] == serde_json::to_value(exact(ACCEPTANCE, ACCEPTANCE_SHA))?
            && sequence["no_resource_promise_ending"] == true
            && sequence["separate_physical_reclamation_and_fresh_admission_required"] == true,
        "genuine167 native retirement completion chain differs"
    );
    ensure!(
        native["Id"] == RETIRE_UNIT
            && native["InvocationID"] == RETIRE_IID
            && native["MainPID"] == "0"
            && native["ControlPID"] == "0"
            && native["Result"] == "success"
            && native["ExecMainStatus"] == "0"
            && native["NRestarts"] == "0"
            && native["SubState"] == "exited"
            && native["Job"] == "",
        "retirement launch is not native successful completion"
    );
    Ok(())
}
fn booking(v: &Value, p: &Plan) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-epoch167-retry5-additive-root-cap-booking-v1"
            && v["owner"] == "/root"
            && v["primary_thread"] == THREAD
            && v["epoch"] == 167
            && v["attempt"] == ATTEMPT
            && v["source_fleet"] == serde_json::to_value(&p.fleet)?
            && v["reservation_booked"] == true
            && v["previous_complete_DATA_bytes"] == completed167::COMPLETE_DATA
            && v["additional_DATA_bytes"] == CAP_DELTA
            && v["complete_DATA_bytes"] == COMPLETE_DATA
            && v["historical_root_cap_bytes"] == ROOT_CAP
            && v["candidate_root_cap_bytes"] == CANDIDATE_CAP
            && v["previous_raw_floor_bytes"] == completed167::RAW_FLOOR
            && v["raw_floor_bytes"] == RAW_FLOOR
            && v["complete_projected_memory_bytes_unchanged"] == current_budget::CURRENT_MEMORY
            && v["protected166_admission"]
                == serde_json::to_value(exact(PEER_ADMISSION, PEER_ADMISSION_SHA))?
            && v["protected166_guard"]
                == serde_json::to_value(exact(PEER_PROTECTION, PEER_PROTECTION_SHA))?
            && v["protected166_root_cap_bytes_unchanged"] == ROOT_CAP
            && v["stopped170"] == serde_json::to_value(terminal170::exact())?
            && v["stopped170_root_cap_bytes_unchanged"] == ROOT_CAP
            && v["stopped_retry4_167"]
                == serde_json::to_value(exact(STOP_RETRY4_167, STOP_RETRY4_167_SHA))?
            && v["completed167_retained_output_cap_bytes_unchanged"]
                == completed_output_report::RETAINED_CAP
            && v["all_prior_promises_retained"] == true
            && v["resource_credit_bytes"] == 0
            && v["resource_promise_ending_bytes"] == 0
            && v["new_memory_promise_bytes"] == 0
            && v["replay_launch_authorized"] == false
            && v["remote_mutations"] == false,
        "explicit additive167 reservation or retained166/170 protection differs"
    );
    Ok(())
}
pub(super) fn declaration(v: &Value, p: &Plan) -> Result<()> {
    if !selected(p) {
        return Ok(());
    }
    let request = p.retry167.as_ref().context("retry167 request")?;
    ensure!(
        v["candidate_root_cap_booking"] == serde_json::to_value(&request.additive_data_booking)?
            && v["candidate_root_cap_bytes"] == CANDIDATE_CAP
            && v["additive_root_cap_reservation_bytes"] == CAP_DELTA
            && v["protected166_root_cap_bytes"] == ROOT_CAP
            && v["stopped170_root_cap_bytes"] == ROOT_CAP,
        "working-set declaration must expose exact167 cap increment and retained166/170 caps"
    );
    booking(&bound(&request.additive_data_booking)?, p)
}
pub(super) fn authenticate(p: &Plan) -> Result<Value> {
    shape(p)?;
    if !selected(p) {
        return Ok(Value::Null);
    }
    let r = p.retry167.as_ref().context("retry167 request")?;
    terminal167::authenticate(&terminal167::exact(), now()?)?;
    terminal170::authenticate(&r.stopped_retry4_170)?;
    let stopped = bound(&r.stopped_retry4_167)?;
    let intent = bound(&exact(INTENT_RETRY4_167, INTENT_RETRY4_167_SHA))?;
    ensure!(
        intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && intent["producer_invocation_id"] == IID_RETRY4_167
            && intent["reason"] == "DATA-fulfillment-observation-failed"
            && intent["sample"]["scratch_deleted"] == false
            && stopped["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && stopped["producer_invocation_id"] == IID_RETRY4_167
            && stopped["intent"] == INTENT_RETRY4_167
            && stopped["scratch_deleted"] == false
            && stopped["terminal"]["pid"] == 0
            && stopped["terminal"]["restarts"] == 0
            && stopped["terminal"]["active"] == "inactive"
            && stopped["terminal"]["sub"] == "dead"
            && stopped["remote_mutations"] == false
            && stopped["r2_mutations"] == false,
        "stopped retry4 epoch167 must retain its partial and claim no credit"
    );
    let stop = bound(&r.stopped_event)?;
    let done = bound(&r.retirement)?;
    let acceptance = bound(&r.native_acceptance)?;
    let sequence = bound(&r.completed_sequence)?;
    let terminal = bound(&exact(TERMINAL, TERMINAL_SHA))?;
    validate_retirement(&stop, &done, &acceptance, &sequence, &terminal)?;
    booking(&bound(&r.additive_data_booking)?, p)?;
    let path = Path::new(SCRATCH);
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_dir()
            && m.dev() == 64512
            && m.ino() == 104136881
            && fs::read_dir(path)?.next().is_none(),
        "retired167 scratch inode or emptiness changed"
    );
    Ok(
        json!({"stop":r.stopped_event,"retirement":r.retirement,"native_acceptance":r.native_acceptance,
        "completed_sequence":r.completed_sequence,"additive_data_booking":r.additive_data_booking,
        "stopped_retry4_167":r.stopped_retry4_167,"stopped_retry4_170":r.stopped_retry4_170,
        "fresh_attempt":ATTEMPT,"historical_root_cap_bytes":ROOT_CAP,"candidate_root_cap_bytes":CANDIDATE_CAP,
        "additional_DATA_bytes":CAP_DELTA,"resource_credit_bytes":0,"resource_promise_ending_bytes":0,
        "partial_reuse":false,"protected166_unchanged":true,"stopped170_promise_retained":true,"replay_launch_authorized":false}),
    )
}
pub(super) fn slot_budget(r: &Review) -> Result<()> {
    ensure!(
        r.epoch == 167
            && r.attempt == ATTEMPT
            && r.retained_lane_physical_bytes > 0
            && r.retained_lane_physical_bytes < ROOT_CAP
            && r.proposed_fresh_working_maximum_bytes
                == CANDIDATE_CAP - r.retained_lane_physical_bytes
            && r.candidate_remaining_growth_bytes == r.proposed_fresh_working_maximum_bytes
            && r.existing_original_slot_future_growth_bytes
                == ROOT_CAP - r.retained_lane_physical_bytes
            && r.additional_growth_not_covered_by_existing_promise_bytes == CAP_DELTA,
        "candidate167 must retain the old whole-root promise and explicitly book exactly the cap increment"
    );
    Ok(())
}
pub(super) fn unbooked_growth(p: &Plan, r: &Review) -> Result<u64> {
    if selected(p) {
        slot_budget(r)?;
        // The exact delta is reserved in RAW_FLOOR; counting it again here would double-charge it.
        r.additional_growth_not_covered_by_existing_promise_bytes
            .checked_sub(CAP_DELTA)
            .context("cap booking underflow")
    } else {
        Ok(r.additional_growth_not_covered_by_existing_promise_bytes)
    }
}
pub(super) fn fit(
    raw: u64,
    fulfilled: u64,
    totals: &BTreeMap<u64, u64>,
    staging: u64,
    extra: u64,
) -> Result<Value> {
    ensure!(
        totals.keys().copied().collect::<BTreeSet<_>>() == BTreeSet::from([166, 167, 169, 170])
            && totals.values().all(|n| *n > 0 && *n < ROOT_CAP)
            && fulfilled > 0
            && fulfilled <= 241_482_399_744
            && staging >= 64 << 20
            && extra == CAP_DELTA,
        "complete native roots and exact additive reservation required"
    );
    let total_growth = totals.iter().try_fold(0u64, |sum, (epoch, n)| {
        sum.checked_add(
            (if *epoch == 167 {
                CANDIDATE_CAP
            } else {
                ROOT_CAP
            }) - n,
        )
        .context("growth overflow")
    })?;
    let outside_raised_floor = total_growth
        .checked_sub(CAP_DELTA)
        .context("reserved cap delta exceeds growth")?;
    let floor = RAW_FLOOR
        .checked_sub(fulfilled)
        .context("floor underflow")?;
    let required = floor
        .checked_add(outside_raised_floor)
        .and_then(|n| n.checked_add(staging))
        .and_then(|n| n.checked_add(10 << 30))
        .context("native fit overflow")?;
    ensure!(
        raw >= required,
        "complete166/167/169/170 growth does not fit: free={raw}, required={required}"
    );
    Ok(
        json!({"conservative_raw_available_bytes":raw,"fulfilled_existing_DATA_bytes":fulfilled,
        "immutable_effective_guard_floor_bytes":floor,"complete_concurrent_remaining_growth_bytes":total_growth,
        "candidate_root_cap_bytes":CANDIDATE_CAP,"protected166_root_cap_bytes":ROOT_CAP,
        "stopped170_root_cap_bytes":ROOT_CAP,
        "booked_root_cap_increment_inside_floor_bytes":CAP_DELTA,
        "remaining_growth_outside_raised_floor_bytes":outside_raised_floor,
        "additional_growth_not_covered_by_existing_promise_bytes":extra,
        "additional_growth_not_already_booked_bytes":0,"fresh_subtree_overlap_bytes":staging,
        "unrelated_growth_margin_bytes":10u64<<30,"required_raw_available_bytes":required,
        "headroom_after_full_growth_bytes":raw-required,"forecast_offloads_credited_bytes":0,
        "resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn actual(path: &str, sha: &str) -> Value {
        let bytes = fs::read(path).expect("root native test must read hash-bound genuine evidence");
        assert_eq!(digest(&bytes), sha);
        serde_json::from_slice(&bytes).unwrap()
    }
    fn evidence() -> [Value; 5] {
        [
            actual(STOP, STOP_SHA),
            actual(COMPLETION, COMPLETION_SHA),
            actual(ACCEPTANCE, ACCEPTANCE_SHA),
            actual(SEQUENCE, SEQUENCE_SHA),
            actual(TERMINAL, TERMINAL_SHA),
        ]
    }
    fn validate(v: &[Value; 5]) -> Result<()> {
        validate_retirement(&v[0], &v[1], &v[2], &v[3], &v[4])
    }
    #[test]
    fn genuine167_native_retirement_is_required() {
        let v = evidence();
        validate(&v).unwrap();
        for key in ["InvocationID", "Id", "Result", "ExecMainStatus", "MainPID"] {
            let mut bad = v.clone();
            bad[4][key] = json!("changed");
            assert!(validate(&bad).is_err());
        }
        let mut bad = v.clone();
        bad[0]["original_invocation_id"] = json!(PEER_IID);
        assert!(validate(&bad).is_err());
        let mut bad = v.clone();
        bad[1]["basis"]["scratch_identity"]["inode"] = json!(104136882);
        assert!(validate(&bad).is_err());
        let mut bad = v.clone();
        bad[1]["resource_credit_bytes"] = json!(1);
        assert!(validate(&bad).is_err());
        let mut bad = v.clone();
        bad[2]["receipt"]["sha256"] = json!("0".repeat(64));
        assert!(validate(&bad).is_err());
    }
    fn peer() -> Value {
        json!([{"epoch":166,"unit":PEER_UNIT,"invocation_id":PEER_IID,
        "main_pid":689067,"main_start_ticks":326476185u64,
        "admission":exact(PEER_ADMISSION,PEER_ADMISSION_SHA),"guard_protection":exact(PEER_PROTECTION,PEER_PROTECTION_SHA)}])
    }
    #[test]
    fn omitted_crossed_or_duplicate_peer_cannot_pass() {
        let good = peer();
        peer_rows(&good).unwrap();
        assert!(peer_rows(&json!([])).is_err());
        assert!(peer_rows(&json!([good[0], good[0]])).is_err());
        for key in [
            "epoch",
            "unit",
            "invocation_id",
            "main_pid",
            "main_start_ticks",
            "admission",
            "guard_protection",
        ] {
            let mut bad = good.clone();
            bad[0][key] = Value::Null;
            assert!(peer_rows(&bad).is_err(), "{key}");
        }
    }
    #[test]
    fn additive_cap_is_charged_exactly_once_at_byte_boundary() {
        let totals = BTreeMap::from([
            (166, 232814460928),
            (167, 226745851904),
            (169, 185928404992),
            (170, 57792991232),
        ]);
        let fulfilled = 241482399744;
        let staging = 64 << 20;
        let p = fit(u64::MAX, fulfilled, &totals, staging, CAP_DELTA).unwrap();
        let need = p["required_raw_available_bytes"].as_u64().unwrap();
        let old_growth = totals.values().map(|n| ROOT_CAP - n).sum::<u64>();
        assert_eq!(
            need,
            completed167::RAW_FLOOR - fulfilled + old_growth + CAP_DELTA + staging + (10 << 30)
        );
        fit(need, fulfilled, &totals, staging, CAP_DELTA).unwrap();
        assert!(fit(need - 1, fulfilled, &totals, staging, CAP_DELTA).is_err());
        assert!(fit(need, fulfilled, &totals, staging, CAP_DELTA - 1).is_err());
        let mut omitted = totals.clone();
        omitted.remove(&170);
        assert!(fit(u64::MAX, fulfilled, &omitted, staging, CAP_DELTA).is_err());
    }
    #[test]
    fn historical_caps_and_healthy166_never_change() {
        assert_eq!(ROOT_CAP, 288u64 << 30);
        assert_eq!(CANDIDATE_CAP, 512u64 << 30);
        assert_eq!(CAP_DELTA, 224u64 << 30);
        let mut p = crate::tests::plan();
        assert_eq!(candidate_cap(&p), ROOT_CAP);
        p.epoch = 167;
        p.attempt = ATTEMPT.into();
        assert_eq!(candidate_cap(&p), CANDIDATE_CAP);
        for e in [166, 169, 170] {
            assert_eq!(root_cap(&p, e), ROOT_CAP);
        }
        p.epoch = 170;
        assert_eq!(candidate_cap(&p), ROOT_CAP);
    }
    fn successor_plan() -> Plan {
        let mut p: Plan = serde_json::from_value(actual(
            "/usr/local/lib/jetstreamer/horizon-retry3-167-prepare-plan-20261113-v1/plan.json",
            "31a4b1921039aee2466852c34ead27ef7584b00aab4b8429f7ab6c980fbb2d73",
        ))
        .unwrap();
        p.attempt = ATTEMPT.into();
        p.producer_unit = "horizon-qualify-167-replacement-local3retry5-20261110-v1.service".into();
        p.guard_base = "horizon-guard-replacement-167-local3retry5-20261110-v1".into();
        p.fresh_subtree =
            Path::new(profile(167).unwrap().lane).join("replacement-local3retry5-20261110-v1");
        p.existing_preparation = None;
        p.retry4 = None;
        for u in [
            p.producer_unit.clone(),
            format!("{}.timer", p.guard_base),
            format!("{}.service", p.guard_base),
        ] {
            if !p.closed_units.contains(&u) {
                p.closed_units.push(u);
            }
        }
        for u in [
            "horizon-qualify-167-replacement-local3retry4-20261110-v1.service",
            "horizon-guard-replacement-167-local3retry4-20261110-v1.timer",
            "horizon-guard-replacement-167-local3retry4-20261110-v1.service",
            "horizon-qualify-170-replacement-local3retry4-20261110-v1.service",
        ] {
            if !p.closed_units.iter().any(|entry| entry == u) {
                p.closed_units.push(u.into());
            }
        }
        p.retry167 = Some(Request {
            stopped_event: exact(STOP, STOP_SHA),
            retirement: exact(COMPLETION, COMPLETION_SHA),
            native_acceptance: exact(ACCEPTANCE, ACCEPTANCE_SHA),
            completed_sequence: exact(SEQUENCE, SEQUENCE_SHA),
            additive_data_booking: exact(TEST_BOOKING, &"a".repeat(64)),
            stopped_retry4_167: exact(STOP_RETRY4_167, STOP_RETRY4_167_SHA),
            stopped_retry4_170: terminal170::exact(),
        });
        p.current_allocation = Some(current_allocation::Request {
            schema: SCHEMA.into(),
        });
        p.resident_memory = Some(
            serde_json::from_value(json!({"observer":p.fleet,
            "owners":peer(),"host_kernel_same_resident_basis":true,"admission_only_capture":true,
            "terminal167":terminal167::exact(),"terminal169":terminal169::exact(),
            "terminal170":terminal170::exact()}))
            .unwrap(),
        );
        let mut guard = crate::prelaunch_data::tests::request();
        guard.runtime = exact(retry167_native_guard::RUNTIME, &"a".repeat(64));
        guard.runtime_seal = serde_json::from_value(retry167_native_guard::seal_binding()).unwrap();
        guard.qualification =
            serde_json::from_value(retry167_native_guard::qualification_binding()).unwrap();
        p.data_fulfillment = Some(guard);
        p
    }
    #[test]
    fn complete_outer_shape_accepts_exact167_and_rejects_crossed_route() {
        let p = successor_plan();
        crate::shapes(&p).unwrap();
        assert!(current_budget::selected(&p));
        let g = guard_template(&p, profile(167).unwrap());
        assert_eq!(g["maximum_root_physical_bytes"], CANDIDATE_CAP);
        assert_eq!(g["minimum_free_bytes"], RAW_FLOOR);
        assert_eq!(g["worker_root"], profile(167).unwrap().lane);
        for key in [
            "retirement",
            "stopped_event",
            "native_acceptance",
            "completed_sequence",
            "stopped_retry4_167",
        ] {
            let mut raw = serde_json::to_value(successor_plan()).unwrap();
            raw["retry167"][key]["sha256"] = json!("0".repeat(64));
            let bad: Plan = serde_json::from_value(raw).unwrap();
            assert!(crate::shapes(&bad).is_err());
        }
        let mut p = successor_plan();
        p.resident_memory.as_mut().unwrap().owners.clear();
        assert!(crate::shapes(&p).is_err());
        let mut p = successor_plan();
        p.closed_units.retain(|u| u != OLD_UNIT);
        assert!(crate::shapes(&p).is_err());
        let mut p = successor_plan();
        p.fresh_subtree =
            Path::new(profile(167).unwrap().lane).join("replacement-local3retry4-20261110-v1");
        assert!(crate::shapes(&p).is_err());
        let mut p = successor_plan();
        p.epoch = 170;
        assert!(crate::shapes(&p).is_err());
    }
    #[test]
    fn booking_follows_fresh_fleet_only_inside_exact_private_root() {
        assert!(booking_path(Path::new(TEST_BOOKING)));
        for bad in [
            "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING.json",
            "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING-20261117T1825Z.json/extra",
            "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING-20261117T1825Z.json.old",
            "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING-20261117T18ZZZ.json",
            "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/../ROOT_DATA_BOOKING-20261117T1825Z.json",
        ] {
            assert!(!booking_path(Path::new(bad)), "{bad}");
        }
        let mut p = successor_plan();
        p.retry167.as_mut().unwrap().additive_data_booking.path =
            Path::new("/tmp/ROOT_DATA_BOOKING-20261117T1825Z.json").into();
        assert!(crate::shapes(&p).is_err());
    }
    #[test]
    fn full_review_separates_cap_booking_from_historical_slot() {
        let p = successor_plan();
        let mut r = crate::tests::review(&p);
        r.epoch = 167;
        r.current_budget = Some(current_budget::exact());
        r.data_fulfillment = p.data_fulfillment.clone();
        r.retained_lane_physical_bytes = 226745851904;
        r.proposed_fresh_working_maximum_bytes = CANDIDATE_CAP - r.retained_lane_physical_bytes;
        r.candidate_remaining_growth_bytes = r.proposed_fresh_working_maximum_bytes;
        r.existing_original_slot_future_growth_bytes = ROOT_CAP - r.retained_lane_physical_bytes;
        r.additional_growth_not_covered_by_existing_promise_bytes = CAP_DELTA;
        r.minimum_initial_available_data_bytes = RAW_FLOOR + (64 << 20);
        crate::review_shape(&p, &r, 1000).unwrap();
        assert_eq!(unbooked_growth(&p, &r).unwrap(), 0);
        r.additional_growth_not_covered_by_existing_promise_bytes -= 1;
        assert!(crate::review_shape(&p, &r, 1000).is_err());
    }
}
