//! Exact epoch167 successor proposals. Qualification, capacity booking and launch are separate gates.
use super::*;

pub(super) const ATTEMPT: &str = "local3retry5";
pub(super) const RETRY6: &str = "local3retry6";
pub(super) const CANDIDATE_CAP: u64 = 512 << 30;
pub(super) const CAP_DELTA: u64 = CANDIDATE_CAP - ROOT_CAP;
pub(super) const COMPLETE_DATA: u64 = completed167::COMPLETE_DATA + CAP_DELTA;
pub(super) const RAW_FLOOR: u64 = completed167::RAW_FLOOR + CAP_DELTA;
pub(super) const SCHEMA: &str = "horizon-epoch167-retry5-native-allocation-v1";
pub(super) const WORKING_SET_SCHEMA: &str = "horizon-epoch167-retry5-cap512-working-set-v1";
pub(super) const RETRY6_SCHEMA: &str = "horizon-epoch167-retry6-native-allocation-v1";
pub(super) const RETRY6_WORKING_SET_SCHEMA: &str = "horizon-epoch167-retry6-cap512-working-set-v1";
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
const RETRY6_BOOKING_DIRECTORY: &str = "/var/lib/jetstreamer/epoch167-retry6-zeropeer-20261118-v1";
#[cfg(test)]
const TEST_BOOKING: &str = "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING-20261117T1825Z.json";
const PEER_UNIT: &str = "horizon-qualify-166-replacement-local3retry6-20261110-v1.service";
const PEER_IID: &str = "b3992e492e1a4d49a9e4e4a01a13c815";
const PEER_ADMISSION: &str = "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json";
const PEER_ADMISSION_SHA: &str = "24033084033ab661720ea714cce584fdee4464a14e845563bb43de200ca0eb81";
const PEER_PROTECTION: &str = "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_GUARD_PROTECTION.json";
const PEER_PROTECTION_SHA: &str = "21cb4ced79b12be21c3f5011f7de183909078afa3f4826ef3c0e509bed0afa5d";
const NEW_PEER_UNIT: &str = "horizon-qualify-166-replacement-local3retry7-20261110-v1.service";
const NEW_PEER_IID: &str = "03fa3ce80d8c4769a1e9dec548cdbeca";
const NEW_PEER_ADMISSION: &str = "/var/lib/jetstreamer/retry7-single166-guarded-launch-20261118-v2/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json";
const NEW_PEER_ADMISSION_SHA: &str = "13c8ac3ea9b9525b2f757acccffc3ea7fb4eaf3b1080fb0c3de946c9dd422489";
const NEW_PEER_PROTECTION: &str = "/var/lib/jetstreamer/retry7-single166-guarded-launch-20261118-v2/epoch166/ACTUAL_GUARD_PROTECTION.json";
const NEW_PEER_PROTECTION_SHA: &str = "99bb9656fc859e2a89134a140288697fdbe4289a044ca333edec40f12e2e851a";
const STOP_RETRY4_167: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry4/guard-state/receipts/stop-completion.json";
const STOP_RETRY4_167_SHA: &str = "2b45af4f5d058e51f291cf1c80d0c23b05a171b2e646d7d72b117d8e7bf6ea8d";
const INTENT_RETRY4_167: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry4/guard-state/receipts/stop-intent.json";
const INTENT_RETRY4_167_SHA: &str = "a1a17d316becfc970aa39de16fb0d8e6db4b73595af8977e5887eefea3ea4657";
const IID_RETRY4_167: &str = "3eaae9a18cc64bdd89ca1d14fe9e9819";
const STOP_RETRY6_166: &str = "/var/lib/jetstreamer/retry6-preparation-20261117-v1/epoch166/local3retry6/guard-state/receipts/stop-completion.json";
const STOP_RETRY6_166_SHA: &str = "34a92966ddb3007db7f1a06bfb0668f48856ebaa725937eacd9088df0a050f01";
const INTENT_RETRY6_166: &str = "/var/lib/jetstreamer/retry6-preparation-20261117-v1/epoch166/local3retry6/guard-state/receipts/stop-intent.json";
const INTENT_RETRY6_166_SHA: &str = "3901e732145152e22372c63c32c3744833cfc1c10f45d11e9e7a9c34fed25074";
const STOP_RETRY5_167: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry5/guard-state/receipts/stop-completion.json";
const STOP_RETRY5_167_SHA: &str = "65a1a0f574e0f5f776ca1540cf5498300aa0a87016055f4ab8de0a8327900062";
const INTENT_RETRY5_167: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry5/guard-state/receipts/stop-intent.json";
const INTENT_RETRY5_167_SHA: &str = "f98f19b72fedbe9e2e73bef057bb259b6d9ea670c4d306bb7f419fe71bb593f9";
const STOP_RETRY5_170: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch170/local3retry5/guard-state/receipts/stop-completion.json";
const STOP_RETRY5_170_SHA: &str = "1751d0ad7c16e58b7dec251908120275f8ea0bb1fc6fe85073e3d812a1618168";
const INTENT_RETRY5_170: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch170/local3retry5/guard-state/receipts/stop-intent.json";
const INTENT_RETRY5_170_SHA: &str = "3fadd006f888a072f4743031e0413375210f9bd4ad4b1b986682289b43d1400d";

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
    Bound { path: path.into(), sha256: sha.into() }
}
fn booking_path(path: &Path, retry6_route: bool) -> bool {
    path.parent() == Some(Path::new(if retry6_route { RETRY6_BOOKING_DIRECTORY } else { BOOKING_DIRECTORY }))
        && path.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
            name.strip_prefix("ROOT_DATA_BOOKING-")
                .and_then(|suffix| suffix.strip_suffix(".json"))
                .is_some_and(|stamp| stamp.len() == 14
                    && stamp.as_bytes()[..8].iter().all(u8::is_ascii_digit)
                    && stamp.as_bytes()[8] == b'T'
                    && stamp.as_bytes()[9..13].iter().all(u8::is_ascii_digit)
                    && stamp.as_bytes()[13] == b'Z')
        })
}
pub(super) fn selected(p: &Plan) -> bool { p.epoch == 167 && [ATTEMPT, RETRY6].contains(&p.attempt.as_str()) }
pub(super) fn retry6(p: &Plan) -> bool { p.epoch == 167 && p.attempt == RETRY6 }
// The retry7 guard retains the stopped retry6 root in addition to the historical
// fleet. This obligation is additive to epoch167's 512 GiB cap increment.
fn has_retry7_peer(r: &resident_memory::Request) -> bool {
    serde_json::to_value(&r.owners).is_ok_and(|v| v[0]["unit"] == NEW_PEER_UNIT)
}
pub(super) fn retained_peer_data(p: &Plan) -> u64 {
    if retry6(p) && p.resident_memory.as_ref().is_some_and(has_retry7_peer) { ROOT_CAP } else { 0 }
}
pub(super) fn complete_data(p: &Plan) -> u64 { COMPLETE_DATA + retained_peer_data(p) }
pub(super) fn raw_floor(p: &Plan) -> u64 { RAW_FLOOR + retained_peer_data(p) }
pub(super) fn candidate_cap(p: &Plan) -> u64 {
    if selected(p) { CANDIDATE_CAP } else { ROOT_CAP }
}
pub(super) fn root_cap(p: &Plan, epoch: u64) -> u64 {
    if selected(p) && epoch == 167 { CANDIDATE_CAP } else { ROOT_CAP }
}
pub(super) fn is_protected166(epoch: u64, unit: &str, iid: &str) -> bool {
    epoch == 166 && ((unit == PEER_UNIT && iid == PEER_IID)
        || (unit == NEW_PEER_UNIT && iid == NEW_PEER_IID))
}
pub(super) fn protected166_guard_floor(epoch: u64, unit: &str, iid: &str) -> Option<u64> {
    if !is_protected166(epoch, unit, iid) { return None; }
    Some(current_budget::CURRENT_FLOOR + if unit == NEW_PEER_UNIT { ROOT_CAP } else { 0 })
}
fn peer_rows(v: &Value) -> Result<()> {
    let rows = v.as_array().context("exact166 resident owner array")?;
    ensure!(rows.len() == 1, "one exact protected166 peer is required");
    let r = &rows[0];
    if r["unit"] == NEW_PEER_UNIT {
        ensure!(r["epoch"] == 166 && r["invocation_id"] == NEW_PEER_IID
            && r["main_pid"] == 1450368 && r["main_start_ticks"] == 337513170u64
            && r["admission"] == serde_json::to_value(exact(NEW_PEER_ADMISSION, NEW_PEER_ADMISSION_SHA))?
            && r["guard_protection"] == serde_json::to_value(exact(NEW_PEER_PROTECTION, NEW_PEER_PROTECTION_SHA))?,
            "retry7 peer identity or protection differs");
        return Ok(());
    }
    ensure!(
        r["epoch"] == 166 && r["unit"] == PEER_UNIT && r["invocation_id"] == PEER_IID
        && r["main_pid"] == 689067 && r["main_start_ticks"] == 326476185u64
        && r["admission"] == serde_json::to_value(exact(PEER_ADMISSION, PEER_ADMISSION_SHA))?
        && r["guard_protection"] == serde_json::to_value(exact(PEER_PROTECTION, PEER_PROTECTION_SHA))?,
        "protected166 process, admission or guard identity differs"
    );
    Ok(())
}
pub(super) fn memory_scope(r: &resident_memory::Request) -> Result<u64> {
    ensure!(
        r.admission_only_capture && r.host_kernel_same_resident_basis
        && r.terminal166.is_none()
        && r.terminal167.as_ref() == Some(&terminal167::exact())
        && r.terminal169.as_ref() == Some(&terminal169::exact())
        && r.terminal170.as_ref() == Some(&terminal170::exact()),
        "candidate167 requires exact stopped167/169/170 lineage"
    );
    terminal170::authenticate(r.terminal170.as_ref().context("stopped170 evidence")?)?;
    if r.owners.is_empty() {
        authenticate_stop(STOP_RETRY6_166, STOP_RETRY6_166_SHA, INTENT_RETRY6_166, INTENT_RETRY6_166_SHA, 166, "b3992e492e1a4d49a9e4e4a01a13c815")?;
        authenticate_stop(STOP_RETRY5_167, STOP_RETRY5_167_SHA, INTENT_RETRY5_167, INTENT_RETRY5_167_SHA, 167, "c6f69b8bb668428ea560b12736a53b6b")?;
        authenticate_stop(STOP_RETRY5_170, STOP_RETRY5_170_SHA, INTENT_RETRY5_170, INTENT_RETRY5_170_SHA, 170, "aab865eb4cee44d69f536944e4c5f722")?;
    } else {
        peer_rows(&serde_json::to_value(&r.owners)?)?;
    }
    Ok(COMPLETE_DATA + if has_retry7_peer(r) { ROOT_CAP } else { 0 })
}
fn authenticate_stop(stop_path: &str, stop_sha: &str, intent_path: &str, intent_sha: &str, epoch: u64, iid: &str) -> Result<()> {
    let stop = bound(&exact(stop_path, stop_sha))?;
    let intent = bound(&exact(intent_path, intent_sha))?;
    ensure!(stop["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
        && stop["producer_invocation_id"] == iid
        && stop["intent"] == intent_path
        && stop["scratch_deleted"] == false
        && stop["remote_mutations"] == false && stop["r2_mutations"] == false
        && stop["terminal"]["invocation_id"] == iid
        && stop["terminal"]["pid"] == 0
        && stop["terminal"]["restarts"] == 0
        && stop["terminal"]["active"] == "inactive"
        && stop["terminal"]["sub"] == "dead"
        && intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
        && intent["producer_invocation_id"] == iid
        && intent["reason"] == "DATA-fulfillment-observation-failed"
        && intent["sample"]["scratch_deleted"] == false
        && intent["sample"]["producer_stop_enabled"] == true
        && intent["sample"]["trip_reason"] == "DATA-fulfillment-observation-failed",
        "stopped epoch {epoch} has no exact guard trip and terminal completion");
    Ok(())
}
pub(super) fn stopped166_declaration(row: &Value) -> Result<()> {
    authenticate_stop(STOP_RETRY6_166, STOP_RETRY6_166_SHA, INTENT_RETRY6_166, INTENT_RETRY6_166_SHA, 166, "b3992e492e1a4d49a9e4e4a01a13c815")?;
    ensure!(row["epoch"] == 166
        && row["state"] == "terminal-retained"
        && row["producer_unit"] == "horizon-qualify-166-replacement-local3retry6-20261110-v1.service"
        && row["invocation_id"] == "b3992e492e1a4d49a9e4e4a01a13c815"
        && row["stop_completion"] == serde_json::to_value(exact(STOP_RETRY6_166, STOP_RETRY6_166_SHA))?
        && row["retained_lane_physical_bytes"].as_u64().is_some_and(|n| n > 0 && n < ROOT_CAP)
        && row["remaining_growth_bytes"] == ROOT_CAP - row["retained_lane_physical_bytes"].as_u64().unwrap(),
        "stopped166 retained root declaration differs");
    Ok(())
}
pub(super) fn shape(p: &Plan) -> Result<()> {
    if !selected(p) {
        ensure!(p.retry167.is_none(), "epoch167 successor evidence on another route");
        return Ok(());
    }
    let r = p.retry167.as_ref().context("exact167 successor proof required")?;
    ensure!(
        r.stopped_event == exact(STOP, STOP_SHA)
        && r.retirement == exact(COMPLETION, COMPLETION_SHA)
        && r.native_acceptance == exact(ACCEPTANCE, ACCEPTANCE_SHA)
        && r.completed_sequence == exact(SEQUENCE, SEQUENCE_SHA)
        && booking_path(&r.additive_data_booking.path, retry6(p))
        && lower_hex(&r.additive_data_booking.sha256, 64)
        && r.stopped_retry4_167 == exact(STOP_RETRY4_167, STOP_RETRY4_167_SHA)
        && r.stopped_retry4_170 == terminal170::exact()
        && p.retry4.is_none() && p.retry3.is_some()
        && p.existing_preparation.is_none()
        && p.fresh_subtree == Path::new(if retry6(p) {
            "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1"
        } else {
            "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry5-20261110-v1"
        })
        && p.current_allocation.as_ref().is_some_and(|v| v.schema == if retry6(p) { RETRY6_SCHEMA } else { SCHEMA })
        && p.data_fulfillment.as_ref().is_some_and(|v| v.runtime.path == Path::new(if retained_peer_data(p) > 0 {
            prelaunch_data::RETRY6_LIVE166_RUNTIME
        } else if retry6(p) {
            prelaunch_data::RETRY6_167_RUNTIME
        } else {
            retry167_native_guard::RUNTIME
        })),
        "exact fresh167 route, lineage, additive reservation and successor guard required"
    );
    for u in [OLD_UNIT, "horizon-guard-replacement-167-local3retry3-20261110-v1.service",
        "horizon-guard-replacement-167-local3retry3-20261110-v1.timer",
        "horizon-qualify-167-replacement-local3retry4-20261110-v1.service",
        "horizon-guard-replacement-167-local3retry4-20261110-v1.service",
        "horizon-guard-replacement-167-local3retry4-20261110-v1.timer",
        "horizon-qualify-170-replacement-local3retry4-20261110-v1.service"] {
        ensure!(p.closed_units.iter().any(|x| x == u), "old167 owner or guard omitted");
    }
    if retry6(p) {
        ensure!(p.producer_unit == "horizon-qualify-167-replacement-local3retry6-20261110-v1.service"
            && p.guard_base == "horizon-guard-replacement-167-local3retry6-20261110-v1"
            && p.resident_memory.as_ref().is_some_and(|m| m.owners.is_empty()
                || (m.owners.len() == 1 && serde_json::to_value(&m.owners).is_ok_and(|v|
                    v[0]["unit"] == NEW_PEER_UNIT && peer_rows(&v).is_ok()))),
            "retry6 requires a fresh producer and an exact zero-owner or protected retry7 peer capture");
        for u in [
            "horizon-qualify-166-replacement-local3retry6-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry6-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry6-20261110-v1.timer",
            "horizon-qualify-167-replacement-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-167-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-167-local3retry5-20261110-v1.timer",
            "horizon-qualify-170-replacement-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-170-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-170-local3retry5-20261110-v1.timer",
        ] {
            ensure!(p.closed_units.iter().any(|x| x == u), "stopped retry5/6 owner or guard omitted");
        }
    } else {
        ensure!(p.resident_memory.as_ref().is_some_and(|m| m.owners.len() == 1),
            "retry5 requires its exact live166 peer");
    }
    memory_scope(p.resident_memory.as_ref().context("protected166 resident request")?)?;
    Ok(())
}
fn validate_retirement(stop: &Value, done: &Value, acceptance: &Value, sequence: &Value, native: &Value) -> Result<()> {
    ensure!(
        stop["epoch"] == 167 && stop["owner"] == "/root" && stop["primary_thread"] == THREAD
        && stop["original_invocation_id"] == OLD_IID && stop["resource_credit_bytes"] == 0,
        "original167 stop identity differs"
    );
    ensure!(
        done["schema"] == "jetstreamer-retry3-scratch167-complete-v1"
        && done["basis"]["source"]["original_retry3_stop_event"] == serde_json::to_value(exact(STOP, STOP_SHA))?
        && done["basis"]["scratch_identity"]["device"] == 64512
        && done["basis"]["scratch_identity"]["inode"] == 104136881u64
        && done["scratch_empty"] == true && done["scratch_root_preserved"] == true
        && done["partial_archive_and_all_inputs_preserved"] == true
        && done["archive_deletion_authorized"] == false && done["replay_launch_authorized"] == false
        && done["resource_promise_ending_authorized"] == false && done["resource_credit_bytes"] == 0
        && done["remote_mutations"] == false && done["r2_mutations"] == false,
        "actual167 retirement identity, preservation or authority differs"
    );
    ensure!(
        acceptance["owner"] == "/root" && acceptance["phase"] == "execute"
        && acceptance["receipt"] == serde_json::to_value(exact(COMPLETION, COMPLETION_SHA))?
        && acceptance["terminal"] == serde_json::to_value(exact(TERMINAL, TERMINAL_SHA))?
        && acceptance["invocation_id"] == RETIRE_IID && acceptance["replay_launch_authorized"] == false
        && sequence["owner"] == "/root"
        && sequence["execute"] == serde_json::to_value(exact(ACCEPTANCE, ACCEPTANCE_SHA))?
        && sequence["no_resource_promise_ending"] == true
        && sequence["separate_physical_reclamation_and_fresh_admission_required"] == true,
        "genuine167 native retirement completion chain differs"
    );
    ensure!(
        native["Id"] == RETIRE_UNIT && native["InvocationID"] == RETIRE_IID
        && native["MainPID"] == "0" && native["ControlPID"] == "0"
        && native["Result"] == "success" && native["ExecMainStatus"] == "0"
        && native["NRestarts"] == "0" && native["SubState"] == "exited" && native["Job"] == "",
        "retirement launch is not native successful completion"
    );
    Ok(())
}
fn booking(v: &Value, p: &Plan) -> Result<()> {
    ensure!(
        v["schema"] == (if retry6(p) {
            "horizon-epoch167-retry6-additive-root-cap-booking-v1"
        } else {
            "horizon-epoch167-retry5-additive-root-cap-booking-v1"
        })
        && v["owner"] == "/root" && v["primary_thread"] == THREAD && v["epoch"] == 167
        && v["attempt"] == p.attempt && v["source_fleet"] == serde_json::to_value(&p.fleet)?
        && v["reservation_booked"] == true
        && v["previous_complete_DATA_bytes"] == completed167::COMPLETE_DATA
        && v["additional_DATA_bytes"] == CAP_DELTA && v["complete_DATA_bytes"] == complete_data(p)
        && v["historical_root_cap_bytes"] == ROOT_CAP && v["candidate_root_cap_bytes"] == CANDIDATE_CAP
        && v["previous_raw_floor_bytes"] == completed167::RAW_FLOOR && v["raw_floor_bytes"] == raw_floor(p)
        && v["complete_projected_memory_bytes_unchanged"] == current_budget::CURRENT_MEMORY
        && (retry6(p) || (v["protected166_admission"] == serde_json::to_value(exact(PEER_ADMISSION, PEER_ADMISSION_SHA))?
        && v["protected166_guard"] == serde_json::to_value(exact(PEER_PROTECTION, PEER_PROTECTION_SHA))?))
        && v["protected166_root_cap_bytes_unchanged"] == ROOT_CAP
        && v["stopped170"] == serde_json::to_value(terminal170::exact())?
        && v["stopped170_root_cap_bytes_unchanged"] == ROOT_CAP
        && v["stopped_retry4_167"] == serde_json::to_value(exact(STOP_RETRY4_167, STOP_RETRY4_167_SHA))?
        && v["completed167_retained_output_cap_bytes_unchanged"] == completed_output_report::RETAINED_CAP
        && v["all_prior_promises_retained"] == true && v["resource_credit_bytes"] == 0
        && v["resource_promise_ending_bytes"] == 0 && v["new_memory_promise_bytes"] == 0
        && v["replay_launch_authorized"] == false && v["remote_mutations"] == false
        && (!retry6(p) || (v["stopped_retry6_166"] == serde_json::to_value(exact(STOP_RETRY6_166, STOP_RETRY6_166_SHA))?
            && v["stopped_retry5_167"] == serde_json::to_value(exact(STOP_RETRY5_167, STOP_RETRY5_167_SHA))?
            && v["stopped_retry5_170"] == serde_json::to_value(exact(STOP_RETRY5_170, STOP_RETRY5_170_SHA))?
            && (if retained_peer_data(p) > 0 {
                v["protected166_admission"] == serde_json::to_value(exact(NEW_PEER_ADMISSION, NEW_PEER_ADMISSION_SHA))?
                    && v["protected166_guard"] == serde_json::to_value(exact(NEW_PEER_PROTECTION, NEW_PEER_PROTECTION_SHA))?
                    && v["retained_retry6_166_DATA_bytes"] == ROOT_CAP
            } else {
                v["protected166_admission"].is_null() && v["protected166_guard"].is_null()
            }))),
        "explicit additive167 reservation or retained166/170 protection differs"
    );
    Ok(())
}
pub(super) fn declaration(v: &Value, p: &Plan) -> Result<()> {
    if !selected(p) { return Ok(()); }
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
    if !selected(p) { return Ok(Value::Null); }
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
    ensure!(path.canonicalize()? == path && m.is_dir() && m.dev() == 64512
        && m.ino() == 104136881 && fs::read_dir(path)?.next().is_none(),
        "retired167 scratch inode or emptiness changed");
    Ok(json!({"stop":r.stopped_event,"retirement":r.retirement,"native_acceptance":r.native_acceptance,
        "completed_sequence":r.completed_sequence,"additive_data_booking":r.additive_data_booking,
        "stopped_retry4_167":r.stopped_retry4_167,"stopped_retry4_170":r.stopped_retry4_170,
        "fresh_attempt":p.attempt,"historical_root_cap_bytes":ROOT_CAP,"candidate_root_cap_bytes":CANDIDATE_CAP,
        "additional_DATA_bytes":CAP_DELTA,"resource_credit_bytes":0,"resource_promise_ending_bytes":0,
        "partial_reuse":false,"protected166_unchanged":true,"stopped170_promise_retained":true,"replay_launch_authorized":false}))
}
pub(super) fn slot_budget(r: &Review) -> Result<()> {
    ensure!(r.epoch == 167 && [ATTEMPT, RETRY6].contains(&r.attempt.as_str()) && r.retained_lane_physical_bytes > 0
        && r.retained_lane_physical_bytes < ROOT_CAP
        && r.proposed_fresh_working_maximum_bytes == CANDIDATE_CAP - r.retained_lane_physical_bytes
        && r.candidate_remaining_growth_bytes == r.proposed_fresh_working_maximum_bytes
        && r.existing_original_slot_future_growth_bytes == ROOT_CAP - r.retained_lane_physical_bytes
        && r.additional_growth_not_covered_by_existing_promise_bytes == CAP_DELTA,
        "candidate167 must retain the old whole-root promise and explicitly book exactly the cap increment");
    Ok(())
}
pub(super) fn unbooked_growth(p: &Plan, r: &Review) -> Result<u64> {
    if selected(p) {
        slot_budget(r)?;
        // The exact delta is reserved in RAW_FLOOR; counting it again here would double-charge it.
        r.additional_growth_not_covered_by_existing_promise_bytes.checked_sub(CAP_DELTA).context("cap booking underflow")
    } else { Ok(r.additional_growth_not_covered_by_existing_promise_bytes) }
}
pub(super) fn fit_with_retained_peer(retained_peer: u64, raw: u64, fulfilled: u64, totals: &BTreeMap<u64,u64>, staging: u64, extra: u64) -> Result<Value> {
    ensure!([0, ROOT_CAP].contains(&retained_peer), "unqualified retained peer DATA increment");
    ensure!(totals.keys().copied().collect::<BTreeSet<_>>() == BTreeSet::from([166,167,169,170])
        && totals.values().all(|n| *n > 0 && *n < ROOT_CAP)
        && fulfilled > 0 && fulfilled <= 241_482_399_744 && staging >= 64 << 20
        && extra == CAP_DELTA, "complete native roots and exact additive reservation required");
    let total_growth = totals.iter().try_fold(0u64, |sum,(epoch,n)| {
        sum.checked_add((if *epoch == 167 {CANDIDATE_CAP} else {ROOT_CAP}) - n).context("growth overflow")
    })?;
    let outside_raised_floor = total_growth.checked_sub(CAP_DELTA).context("reserved cap delta exceeds growth")?;
    let floor = (RAW_FLOOR + retained_peer).checked_sub(fulfilled).context("floor underflow")?;
    let required = floor.checked_add(outside_raised_floor).and_then(|n|n.checked_add(staging))
        .and_then(|n|n.checked_add(10 << 30)).context("native fit overflow")?;
    ensure!(raw >= required, "complete166/167/169/170 growth does not fit: free={raw}, required={required}");
    Ok(json!({"conservative_raw_available_bytes":raw,"fulfilled_existing_DATA_bytes":fulfilled,
        "immutable_effective_guard_floor_bytes":floor,"retained_retry6_166_DATA_bytes":retained_peer,"complete_concurrent_remaining_growth_bytes":total_growth,
        "candidate_root_cap_bytes":CANDIDATE_CAP,"protected166_root_cap_bytes":ROOT_CAP,
        "stopped170_root_cap_bytes":ROOT_CAP,
        "booked_root_cap_increment_inside_floor_bytes":CAP_DELTA,
        "remaining_growth_outside_raised_floor_bytes":outside_raised_floor,
        "additional_growth_not_covered_by_existing_promise_bytes":extra,
        "additional_growth_not_already_booked_bytes":0,"fresh_subtree_overlap_bytes":staging,
        "unrelated_growth_margin_bytes":10u64<<30,"required_raw_available_bytes":required,
        "headroom_after_full_growth_bytes":raw-required,"forecast_offloads_credited_bytes":0,
        "resource_credit_bytes":0,"promise_ending_bytes":0}))
}
#[cfg(test)]
fn fit(raw: u64, fulfilled: u64, totals: &BTreeMap<u64,u64>, staging: u64, extra: u64) -> Result<Value> {
    fit_with_retained_peer(0, raw, fulfilled, totals, staging, extra)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn actual(path:&str, sha:&str)->Value {
        let bytes=fs::read(path).expect("root native test must read hash-bound genuine evidence");
        assert_eq!(digest(&bytes),sha);
        serde_json::from_slice(&bytes).unwrap()
    }
    fn evidence()->[Value;5] {
        [actual(STOP,STOP_SHA),actual(COMPLETION,COMPLETION_SHA),actual(ACCEPTANCE,ACCEPTANCE_SHA),
            actual(SEQUENCE,SEQUENCE_SHA),actual(TERMINAL,TERMINAL_SHA)]
    }
    fn validate(v:&[Value;5])->Result<()> {validate_retirement(&v[0],&v[1],&v[2],&v[3],&v[4])}
    #[test] fn genuine167_native_retirement_is_required() {
        let v=evidence();validate(&v).unwrap();
        for key in ["InvocationID","Id","Result","ExecMainStatus","MainPID"] {
            let mut bad=v.clone();bad[4][key]=json!("changed");assert!(validate(&bad).is_err());
        }
        let mut bad=v.clone();bad[0]["original_invocation_id"]=json!(PEER_IID);assert!(validate(&bad).is_err());
        let mut bad=v.clone();bad[1]["basis"]["scratch_identity"]["inode"]=json!(104136882);assert!(validate(&bad).is_err());
        let mut bad=v.clone();bad[1]["resource_credit_bytes"]=json!(1);assert!(validate(&bad).is_err());
        let mut bad=v.clone();bad[2]["receipt"]["sha256"]=json!("0".repeat(64));assert!(validate(&bad).is_err());
    }
    fn peer()->Value {json!([{"epoch":166,"unit":PEER_UNIT,"invocation_id":PEER_IID,
        "main_pid":689067,"main_start_ticks":326476185u64,
        "admission":exact(PEER_ADMISSION,PEER_ADMISSION_SHA),"guard_protection":exact(PEER_PROTECTION,PEER_PROTECTION_SHA)}])}
    #[test] fn omitted_crossed_or_duplicate_peer_cannot_pass() {
        let good=peer();peer_rows(&good).unwrap();assert!(peer_rows(&json!([])).is_err());
        assert!(peer_rows(&json!([good[0],good[0]])).is_err());
        for key in ["epoch","unit","invocation_id","main_pid","main_start_ticks","admission","guard_protection"] {
            let mut bad=good.clone();bad[0][key]=Value::Null;assert!(peer_rows(&bad).is_err(),"{key}");
        }
    }
    #[test] fn retry7_peer_requires_actual_admission_and_unchanged_identity() {
        let admission = actual(NEW_PEER_ADMISSION, NEW_PEER_ADMISSION_SHA);
        let protection = actual(NEW_PEER_PROTECTION, NEW_PEER_PROTECTION_SHA);
        assert_eq!(admission["producer_invocation_id"], NEW_PEER_IID);
        assert_eq!(protection["admission"], serde_json::to_value(exact(NEW_PEER_ADMISSION, NEW_PEER_ADMISSION_SHA)).unwrap());
        let good = json!([{"epoch":166,"unit":NEW_PEER_UNIT,"invocation_id":NEW_PEER_IID,
            "main_pid":1450368,"main_start_ticks":337513170u64,
            "admission":exact(NEW_PEER_ADMISSION,NEW_PEER_ADMISSION_SHA),
            "guard_protection":exact(NEW_PEER_PROTECTION,NEW_PEER_PROTECTION_SHA)}]);
        peer_rows(&good).unwrap();
        for key in ["epoch","unit","invocation_id","main_pid","main_start_ticks","admission","guard_protection"] {
            let mut bad = good.clone(); bad[0][key] = Value::Null;
            assert!(peer_rows(&bad).is_err(), "{key}");
        }
        assert!(peer_rows(&json!([good[0],good[0]])).is_err());
    }
    #[test] fn additive_cap_is_charged_exactly_once_at_byte_boundary() {
        let totals=BTreeMap::from([(166,232814460928),(167,226745851904),(169,185928404992),(170,57792991232)]);
        let fulfilled=241482399744;let staging=64<<20;
        let p=fit(u64::MAX,fulfilled,&totals,staging,CAP_DELTA).unwrap();
        let need=p["required_raw_available_bytes"].as_u64().unwrap();
        let old_growth=totals.values().map(|n|ROOT_CAP-n).sum::<u64>();
        assert_eq!(need,completed167::RAW_FLOOR-fulfilled+old_growth+CAP_DELTA+staging+(10<<30));
        fit(need,fulfilled,&totals,staging,CAP_DELTA).unwrap();
        assert!(fit(need-1,fulfilled,&totals,staging,CAP_DELTA).is_err());
        assert!(fit(need,fulfilled,&totals,staging,CAP_DELTA-1).is_err());
        let mut omitted=totals.clone();omitted.remove(&170);
        assert!(fit(u64::MAX,fulfilled,&omitted,staging,CAP_DELTA).is_err());
    }
    #[test] fn historical_caps_and_healthy166_never_change() {
        assert_eq!(ROOT_CAP,288u64<<30);assert_eq!(CANDIDATE_CAP,512u64<<30);
        assert_eq!(CAP_DELTA,224u64<<30);
        let mut p=crate::tests::plan();assert_eq!(candidate_cap(&p),ROOT_CAP);
        p.epoch=167;p.attempt=ATTEMPT.into();assert_eq!(candidate_cap(&p),CANDIDATE_CAP);
        for e in [166,169,170] {assert_eq!(root_cap(&p,e),ROOT_CAP);}
        p.epoch=170;assert_eq!(candidate_cap(&p),ROOT_CAP);
    }
    fn successor_plan()->Plan {
        let mut p:Plan=serde_json::from_value(actual(
            "/usr/local/lib/jetstreamer/horizon-retry3-167-prepare-plan-20261113-v1/plan.json",
            "31a4b1921039aee2466852c34ead27ef7584b00aab4b8429f7ab6c980fbb2d73")).unwrap();
        p.attempt=ATTEMPT.into();
        p.producer_unit="horizon-qualify-167-replacement-local3retry5-20261110-v1.service".into();
        p.guard_base="horizon-guard-replacement-167-local3retry5-20261110-v1".into();
        p.fresh_subtree=Path::new(profile(167).unwrap().lane).join("replacement-local3retry5-20261110-v1");
        p.existing_preparation=None;p.retry4=None;
        for u in [p.producer_unit.clone(),format!("{}.timer",p.guard_base),format!("{}.service",p.guard_base)] {
            if !p.closed_units.contains(&u) {p.closed_units.push(u);}
        }
        for u in [
            "horizon-qualify-167-replacement-local3retry4-20261110-v1.service",
            "horizon-guard-replacement-167-local3retry4-20261110-v1.timer",
            "horizon-guard-replacement-167-local3retry4-20261110-v1.service",
            "horizon-qualify-170-replacement-local3retry4-20261110-v1.service",
        ] {
            if !p.closed_units.iter().any(|entry| entry == u) {p.closed_units.push(u.into());}
        }
        p.retry167=Some(Request{stopped_event:exact(STOP,STOP_SHA),retirement:exact(COMPLETION,COMPLETION_SHA),
            native_acceptance:exact(ACCEPTANCE,ACCEPTANCE_SHA),completed_sequence:exact(SEQUENCE,SEQUENCE_SHA),
            additive_data_booking:exact(TEST_BOOKING,&"a".repeat(64)),
            stopped_retry4_167:exact(STOP_RETRY4_167,STOP_RETRY4_167_SHA),
            stopped_retry4_170:terminal170::exact()});
        p.current_allocation=Some(current_allocation::Request{schema:SCHEMA.into()});
        p.resident_memory=Some(serde_json::from_value(json!({"observer":p.fleet,
            "owners":peer(),"host_kernel_same_resident_basis":true,"admission_only_capture":true,
            "terminal167":terminal167::exact(),"terminal169":terminal169::exact(),
            "terminal170":terminal170::exact()})).unwrap());
        let mut guard=crate::prelaunch_data::tests::request();
        guard.runtime=exact(retry167_native_guard::RUNTIME,&"a".repeat(64));
        guard.runtime_seal=serde_json::from_value(retry167_native_guard::seal_binding()).unwrap();
        guard.qualification=serde_json::from_value(retry167_native_guard::qualification_binding()).unwrap();
        p.data_fulfillment=Some(guard);
        p
    }
    fn retry6_plan() -> Plan {
        let mut p = successor_plan();
        p.attempt = RETRY6.into();
        p.producer_unit = "horizon-qualify-167-replacement-local3retry6-20261110-v1.service".into();
        p.guard_base = "horizon-guard-replacement-167-local3retry6-20261110-v1".into();
        p.fresh_subtree = Path::new(profile(167).unwrap().lane).join("replacement-local3retry6-20261110-v1");
        p.retry167.as_mut().unwrap().additive_data_booking.path = Path::new(RETRY6_BOOKING_DIRECTORY)
            .join("ROOT_DATA_BOOKING-20261118T1720Z.json");
        p.current_allocation.as_mut().unwrap().schema = RETRY6_SCHEMA.into();
        p.resident_memory.as_mut().unwrap().owners.clear();
        p.data_fulfillment.as_mut().unwrap().runtime = exact(prelaunch_data::RETRY6_167_RUNTIME,
            "46de4a2461fba0d807ebc581809285ca3f2c67098db0f0824ce47fdd0a0620f3");
        p.data_fulfillment.as_mut().unwrap().runtime_seal = exact(
            "/usr/local/lib/jetstreamer/horizon-epoch167-retry6-original-slot-guard-20261118-v1/deployment-seal-receipt.json",
            "9a9816783ce496d784baee9e4535e2165628af993b63ea277c42af6104d312cb");
        p.data_fulfillment.as_mut().unwrap().qualification = exact(
            "/usr/local/lib/jetstreamer/horizon-epoch167-retry6-original-slot-guard-20261118-v1/artifact-proof.json",
            "1ae7fdcc48ce72f6dac78139d8510ebf580b73afec63357c89c829d53cc89218");
        for unit in [
            "horizon-qualify-167-replacement-local3retry6-20261110-v1.service",
            "horizon-guard-replacement-167-local3retry6-20261110-v1.service",
            "horizon-guard-replacement-167-local3retry6-20261110-v1.timer",
            "horizon-qualify-166-replacement-local3retry6-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry6-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry6-20261110-v1.timer",
            "horizon-qualify-167-replacement-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-167-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-167-local3retry5-20261110-v1.timer",
            "horizon-qualify-170-replacement-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-170-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-170-local3retry5-20261110-v1.timer",
        ] {
            if !p.closed_units.iter().any(|u| u == unit) { p.closed_units.push(unit.into()); }
        }
        p
    }
    #[test]
    fn live_retry7_peer_preserves_additive_data_in_every_admission_layer() {
        let mut p = retry6_plan();
        p.resident_memory.as_mut().unwrap().owners = serde_json::from_value(json!([{
            "epoch":166,"unit":NEW_PEER_UNIT,"invocation_id":NEW_PEER_IID,
            "main_pid":1450368,"main_start_ticks":337513170u64,
            "admission":exact(NEW_PEER_ADMISSION,NEW_PEER_ADMISSION_SHA),
            "guard_protection":exact(NEW_PEER_PROTECTION,NEW_PEER_PROTECTION_SHA)
        }])).unwrap();
        assert!(crate::shapes(&p).is_err(), "old lower-floor guard must fail for a live retry7 peer");
        let d = p.data_fulfillment.as_mut().unwrap();
        d.runtime = exact(prelaunch_data::RETRY6_LIVE166_RUNTIME,
            "2d6c455e385045e554ad08de8f0b1909e52fb7aa700c006d12817449e74a8f14");
        d.runtime_seal = exact("/usr/local/lib/jetstreamer/horizon-epoch167-retry6-live166retry7-guard-20261118-v1/deployment-seal-receipt.json",
            "a51da067e2428462f5ae8d2753cb3765d9b08da1be4b61843151bd4b2ce7cf8b");
        d.qualification = exact("/usr/local/lib/jetstreamer/horizon-epoch167-retry6-live166retry7-guard-20261118-v1/artifact-proof.json",
            "4ef203ce7537301ddb56f750c42372ec9c1624aa323d6d42fc2e51b96886d69a");
        d.contract = data_fulfillment::Binding {
            contract: data_fulfillment::Bound { path: "/usr/local/lib/jetstreamer/horizon-epoch167-retry6-live166retry7-data-contract-20261118-v1/contract.json".into(), sha256: "6096d816cbe2bc1b15e37268d736785be018da0dfd05deca03d40551d307902c".into() },
            deployment_seal: data_fulfillment::Bound { path: "/usr/local/lib/jetstreamer/horizon-epoch167-retry6-live166retry7-data-contract-20261118-v1/deployment-seal-receipt.json".into(), sha256: "22fa7d9c94214c1584d2ce03eade50d1ed961f788419aba1c632b38262de1eca".into() },
        };
        prelaunch_data::authenticate(d).unwrap();
        let mut crossed: prelaunch_data::Request = serde_json::from_value(serde_json::to_value(&d).unwrap()).unwrap();
        crossed.runtime.sha256 = "0".repeat(64);
        assert!(prelaunch_data::authenticate(&crossed).is_err());
        crate::shapes(&p).unwrap();
        resident_memory::peer_admissions(p.resident_memory.as_ref().unwrap()).unwrap();
        assert_eq!(protected166_guard_floor(166, NEW_PEER_UNIT, NEW_PEER_IID), Some(6_584_106_303_282));
        assert_eq!(protected166_guard_floor(166, NEW_PEER_UNIT, PEER_IID), None);
        let actual_prep = actual("/var/lib/jetstreamer/retry7-preparation-20261118-v1/epoch166/local3retry7/prepared.json",
            "778d8569453e451849570cab7a6927c697b8c4065f22c6341bf7b4ba73bc2499");
        let baseline = actual_prep["actual_full_lane_ledger"]["physical_bytes"].as_u64().unwrap();
        let row = json!({"producer_unit":NEW_PEER_UNIT});
        retry3::peer_preparation(166, &row, &actual_prep, baseline).unwrap();
        assert!(retry3::peer_preparation(166, &row, &actual_prep, baseline + 1).is_err());
        assert_eq!(complete_data(&p), 6_794_761_027_378);
        assert_eq!(raw_floor(&p), 6_829_053_656_882);
        assert_eq!(terminal169::data(&p), complete_data(&p));
        assert_eq!(terminal169::floor(&p), raw_floor(&p));
        assert_eq!(memory_scope(p.resident_memory.as_ref().unwrap()).unwrap(), complete_data(&p));
        assert_eq!(guard_template(&p, profile(167).unwrap())["minimum_free_bytes"], raw_floor(&p));

        let mut booked: Value = serde_json::from_slice(&fs::read(
            "/var/lib/jetstreamer/epoch167-retry6-zeropeer-20261118-v1/ROOT_DATA_BOOKING-20261118T1819Z.json"
        ).unwrap()).unwrap();
        booked["source_fleet"] = serde_json::to_value(&p.fleet).unwrap();
        assert!(booking(&booked, &p).is_err());
        booked["complete_DATA_bytes"] = json!(complete_data(&p));
        booked["raw_floor_bytes"] = json!(raw_floor(&p));
        booked["protected166_admission"] = serde_json::to_value(exact(NEW_PEER_ADMISSION,NEW_PEER_ADMISSION_SHA)).unwrap();
        booked["protected166_guard"] = serde_json::to_value(exact(NEW_PEER_PROTECTION,NEW_PEER_PROTECTION_SHA)).unwrap();
        booked["retained_retry6_166_DATA_bytes"] = json!(ROOT_CAP);
        booking(&booked, &p).unwrap();
        for key in ["complete_DATA_bytes", "raw_floor_bytes", "retained_retry6_166_DATA_bytes",
            "protected166_admission", "protected166_guard"] {
            let mut bad = booked.clone(); bad[key] = Value::Null;
            assert!(booking(&bad, &p).is_err(), "{key}");
        }
        let totals=BTreeMap::from([(166,232814460928),(167,226745851904),(169,185928404992),(170,57792991232)]);
        let old = fit(u64::MAX,241482399744,&totals,64<<20,CAP_DELTA).unwrap();
        let old_need = old["required_raw_available_bytes"].as_u64().unwrap();
        assert!(fit_with_retained_peer(ROOT_CAP,old_need,241482399744,&totals,64<<20,CAP_DELTA).is_err());
        let need = old_need + ROOT_CAP;
        fit_with_retained_peer(ROOT_CAP,need,241482399744,&totals,64<<20,CAP_DELTA).unwrap();
        assert!(fit_with_retained_peer(ROOT_CAP,need-1,241482399744,&totals,64<<20,CAP_DELTA).is_err());
    }
    #[test]
    fn retry6_zero_peer_shape_requires_three_exact_stops_and_fresh_scope() {
        let p = retry6_plan();
        crate::shapes(&p).unwrap();
        assert!(booking_path(&p.retry167.as_ref().unwrap().additive_data_booking.path, true));
        let g = guard_template(&p, profile(167).unwrap());
        assert_eq!(g["maximum_root_physical_bytes"], CANDIDATE_CAP);
        assert_eq!(g["minimum_free_bytes"], RAW_FLOOR);
        assert_eq!(g["data_fulfillment"], serde_json::to_value(&p.data_fulfillment.as_ref().unwrap().contract).unwrap());
        let mut crossed = retry6_plan();
        crossed.resident_memory.as_mut().unwrap().owners = successor_plan().resident_memory.unwrap().owners;
        assert!(crate::shapes(&crossed).is_err());
        let mut crossed = retry6_plan();
        crossed.data_fulfillment.as_mut().unwrap().runtime.path = retry167_native_guard::RUNTIME.into();
        assert!(crate::shapes(&crossed).is_err());
        let mut crossed = retry6_plan();
        crossed.closed_units.retain(|u| u != "horizon-guard-replacement-166-local3retry6-20261110-v1.timer");
        assert!(crate::shapes(&crossed).is_err());
    }
    #[test] fn complete_outer_shape_accepts_exact167_and_rejects_crossed_route() {
        let p=successor_plan();crate::shapes(&p).unwrap();
        assert!(current_budget::selected(&p));
        let g=guard_template(&p,profile(167).unwrap());
        assert_eq!(g["maximum_root_physical_bytes"],CANDIDATE_CAP);
        assert_eq!(g["minimum_free_bytes"],RAW_FLOOR);
        assert_eq!(g["worker_root"],profile(167).unwrap().lane);
        for key in ["retirement","stopped_event","native_acceptance","completed_sequence","stopped_retry4_167"] {
            let mut raw=serde_json::to_value(successor_plan()).unwrap();
            raw["retry167"][key]["sha256"]=json!("0".repeat(64));
            let bad:Plan=serde_json::from_value(raw).unwrap();assert!(crate::shapes(&bad).is_err());
        }
        let mut p=successor_plan();p.resident_memory.as_mut().unwrap().owners.clear();
        assert!(crate::shapes(&p).is_err());
        let mut p=successor_plan();p.closed_units.retain(|u|u!=OLD_UNIT);
        assert!(crate::shapes(&p).is_err());
        let mut p=successor_plan();p.fresh_subtree=Path::new(profile(167).unwrap().lane).join("replacement-local3retry4-20261110-v1");
        assert!(crate::shapes(&p).is_err());
        let mut p=successor_plan();p.epoch=170;assert!(crate::shapes(&p).is_err());
    }
    #[test] fn booking_follows_fresh_fleet_only_inside_exact_private_root() {
        assert!(booking_path(Path::new(TEST_BOOKING), false));
        for bad in [
            "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING.json",
            "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING-20261117T1825Z.json/extra",
            "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING-20261117T1825Z.json.old",
            "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING-20261117T18ZZZ.json",
            "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/../ROOT_DATA_BOOKING-20261117T1825Z.json",
        ] {
            assert!(!booking_path(Path::new(bad), false), "{bad}");
        }
        let mut p=successor_plan();
        p.retry167.as_mut().unwrap().additive_data_booking.path=Path::new("/tmp/ROOT_DATA_BOOKING-20261117T1825Z.json").into();
        assert!(crate::shapes(&p).is_err());
    }
    #[test] fn full_review_separates_cap_booking_from_historical_slot() {
        let p=successor_plan();let mut r=crate::tests::review(&p);
        r.epoch=167;r.current_budget=Some(current_budget::exact());r.data_fulfillment=p.data_fulfillment.clone();
        r.retained_lane_physical_bytes=226745851904;
        r.proposed_fresh_working_maximum_bytes=CANDIDATE_CAP-r.retained_lane_physical_bytes;
        r.candidate_remaining_growth_bytes=r.proposed_fresh_working_maximum_bytes;
        r.existing_original_slot_future_growth_bytes=ROOT_CAP-r.retained_lane_physical_bytes;
        r.additional_growth_not_covered_by_existing_promise_bytes=CAP_DELTA;
        r.minimum_initial_available_data_bytes=RAW_FLOOR+(64<<20);
        crate::review_shape(&p,&r,1000).unwrap();
        assert_eq!(unbooked_growth(&p,&r).unwrap(),0);
        r.additional_growth_not_covered_by_existing_promise_bytes-=1;
        assert!(crate::review_shape(&p,&r,1000).is_err());
    }

}
