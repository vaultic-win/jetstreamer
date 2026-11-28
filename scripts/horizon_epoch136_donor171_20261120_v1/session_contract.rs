//! Pure validators for the parent-owned handoff. None grants Initialize.
use super::*;

pub(super) fn denial(plan: &Value, pass: &Value) -> Result<()> {
    ensure!(
        pass["schema"] == "horizon-epoch136-native-preinit-result-v1"
            && pass["genuine_cli_snapshot_binding_and_hello_reached"] == true
            && pass["denial_returned_nonzero"] == true
            && pass["worker_reaped"] == true
            && pass["initialize_release_sent"] == false
            && pass["snapshot_restored"] == false
            && pass["actual_worker_guard_qualified"] == false
            && pass["slots_replayed"] == 0
            && pass["publication_authorized"] == false
            && pass["node_sha256"] == plan["node"]["sha256"]
            && pass["worker_sha256"] == plan["worker"]["sha256"],
        "native denial does not qualify these images or affirmative worker release"
    );
    Ok(())
}
pub(super) fn ready(
    plan: &Value,
    admission: &Value,
    ready: &Value,
    launch: &Value,
    clock: u64,
) -> Result<()> {
    let iid = text(ready, "invocation_id")?;
    let recorded = n(ready, "recorded_unix_seconds")?;
    ensure!(
        ready["schema"] == "horizon-epoch136-actual-ready-v1"
            && ready["unit"] == UNIT
            && guard168::iid(iid)
            && ready["helper"] == plan["helper"]
            && ready["node"] == plan["node"]
            && ready["worker"] == plan["worker"]
            && ready["node_spawned"] == false
            && ready["worker_spawned"] == false
            && ready["publication_authorized"] == false
            && recorded >= n(admission, "recorded_unix_seconds")?
            && recorded <= clock
            && clock - recorded < 180
            && clock < n(admission, "launch_expires_unix_seconds")?
            && launch["schema"] == "jetstreamer-epoch136-actual-20261120-launch-v1"
            && launch["unit"] == UNIT
            && launch["invocation_id"] == iid
            && launch["pid"] == ready["pid"]
            && launch["start_ticks"] == ready["start_ticks"]
            && launch["plan"] == admission["plan"]
            && launch["publication_authorized"] == false,
        "wrong, expired or already executing payload ready/launch"
    );
    prefire(&ready["guard_prefire"]["sample"], ready, admission, clock)
}
pub(super) fn prefire(sample: &Value, ready: &Value, admission: &Value, clock: u64) -> Result<()> {
    let stamp = n(sample, "recorded_unix_seconds")?;
    let floor = n(admission, "protected_existing_free_bytes")?;
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["producer_invocation_id"] == ready["invocation_id"]
            && sample["producer"]["invocation_id"] == ready["invocation_id"]
            && sample["producer"]["pid"] == ready["pid"]
            && sample["producer"]["restarts"] == 0
            && sample["producer"]["active"] == "active"
            && sample["producer"]["sub"] == "running"
            && sample["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && sample["guard_sha256"] == scope::GUARD_SHA
            && sample["plan_sha256"] == ready["guard_plan_sha256"]
            && sample["producer_stop_enabled"] == true
            && sample["minimum_free_bytes"] == floor
            && sample["maximum_root_physical_bytes"] == scope::ROOT_STOP
            && sample["maximum_worker_vmas"] == scope::VMA
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && sample["root_physical_observation"]["exceeds_budget"] == false
            && n(
                &sample["root_physical_observation"],
                "conservative_physical_bytes"
            )? <= scope::ROOT_STOP
            && n(sample, "available_bytes")? >= floor
            && stamp >= n(admission, "recorded_unix_seconds")?
            && stamp <= clock
            && clock - stamp <= 120
            && sample["bounded_measurement"] == false
            && sample["bounded_canary"].is_null()
            && sample["native_main"].is_null()
            && sample["workers"].as_array().is_some_and(Vec::is_empty),
        "prefire must be a fresh complete zero-worker protective sample"
    );
    Ok(())
}
pub(super) fn pending_owner(
    plan: &Value,
    ready: &Value,
    ready_ref: &Value,
    request: &Value,
) -> Value {
    json!({"unit":UNIT,"invocation_id":ready["invocation_id"],"helper":plan["helper"],
        "ready_recorded_unix_seconds":ready["recorded_unix_seconds"],
        "ready":ready_ref,"parent_request":request,"node_spawned":false,"worker_spawned":false,
        "repair_open":true,"ordinary_replay_claim":false})
}
pub(super) fn registration(
    registration: &Value,
    owner: &Value,
    status: &Value,
    fleet: &Value,
    initial_fleet: &Value,
    clock: u64,
) -> Result<()> {
    let stamp = n(registration, "recorded_unix_seconds")?;
    ensure!(
        registration["schema"] == "horizon-epoch136-current-owner-registration-v1"
            && registration["epoch"] == 136
            && registration["unit"] == UNIT
            && registration["invocation_id"] == owner["invocation_id"]
            && registration["helper"] == owner["helper"]
            && registration["request"] == owner["parent_request"]
            && registration["repair_open"] == true
            && registration["ordinary_replay_claim"] == false
            && registration["authenticated_readback"] == true
            && stamp >= n(owner, "ready_recorded_unix_seconds")?
            && stamp <= clock
            && clock - stamp <= 120
            && status["epoch"] == 136
            && status["key"] == "epoch-136.epoch-status.json"
            && status["authenticated_readback"] == true
            && status["producer_invocation_id"] == owner["invocation_id"]
            && status["current_repair_owner"] == "/root"
            && status["epoch136_pending_owner"] == *owner
            && status["epoch136_registration_unix_seconds"] == stamp
            && status["after_status"]["epoch"] == 136
            && status["after_status"]["phase"] == "verification"
            && status["after_etag"].as_str().is_some_and(|s| !s.is_empty())
            && digest(text(status, "after_sha256")?, 64)
            && fleet["epoch136_pending_owner"] == *owner
            && fleet["epoch136_registration_unix_seconds"] == stamp
            && fleet["effective_status_receipts"]["136"] == registration["status_receipt"]
            && fleet["all_active_status_reports_authenticated_readback"] == true,
        "parent status/fleet receipts do not register this waiting owner"
    );
    for key in [
        "complete_DATA_bytes",
        "complete_projected_memory_bytes",
        "all_reservation_ending_bytes",
        "actual_executing_replays",
        "actual_active_bootstraps",
        "actual_active_private_diagnostics",
        "terminal172_closure",
    ] {
        ensure!(
            !initial_fleet[key].is_null() && fleet[key] == initial_fleet[key],
            "status registration changed complete fleet/resource field {key}"
        );
    }
    Ok(())
}
