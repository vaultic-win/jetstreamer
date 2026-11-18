//! Fresh epoch 170 retry5 scope. The stopped retry4 promise is retained.
use super::*;

pub(super) const ATTEMPT: &str = "local3retry5";
pub(super) const SCHEMA: &str = "horizon-epoch170-retry5-native-allocation-v1";
pub(super) const WORKING_SET_SCHEMA: &str = "horizon-epoch170-retry5-current-fleet-working-set-v1";
pub(super) const GUARD_RUNTIME: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch170-retry5-data-guard-20261117-v1/guard";
const FRESH_SUBTREE: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry5-20261110-v1";
const CONTRACT: &str =
    "/var/lib/jetstreamer/epoch170-retry5-recovery-20261117-v1/contract-sealed-v2/contract.json";
const CONTRACT_SEAL: &str = "/var/lib/jetstreamer/epoch170-retry5-recovery-20261117-v1/contract-sealed-v2/deployment-seal-receipt.json";
const RETAINED167_BOOKING: &str = "/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/ROOT_DATA_BOOKING-20261117T2012Z.json";
const RETAINED167_BOOKING_SHA: &str =
    "cd6c57cb8d81842fefef6dda432b14502a38ecbc556dbae0d8641b28064131fb";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub stopped_retry4_170: terminal170::Request,
}

pub(super) fn selected(p: &Plan) -> bool {
    p.epoch == 170 && p.attempt == ATTEMPT
}

pub(super) fn root_cap(p: &Plan, epoch: u64) -> u64 {
    if selected(p) && epoch == 167 {
        retry167::CANDIDATE_CAP
    } else {
        ROOT_CAP
    }
}

pub(super) fn declaration(v: &Value, p: &Plan) -> Result<()> {
    if !selected(p) {
        return Ok(());
    }
    let binding = Bound {
        path: RETAINED167_BOOKING.into(),
        sha256: RETAINED167_BOOKING_SHA.into(),
    };
    let booking = bound(&binding)?;
    ensure!(
        v["retained_epoch167_cap_booking"] == serde_json::to_value(&binding)?
            && v["candidate_root_cap_bytes"] == ROOT_CAP
            && v["protected167_root_cap_bytes"] == retry167::CANDIDATE_CAP
            && booking["schema"] == "horizon-epoch167-retry5-additive-root-cap-booking-v1"
            && booking["reservation_booked"] == true
            && booking["complete_DATA_bytes"] == retry167::COMPLETE_DATA
            && booking["raw_floor_bytes"] == retry167::RAW_FLOOR
            && booking["all_prior_promises_retained"] == true
            && booking["resource_credit_bytes"] == 0,
        "retained 167 cap and current 170 candidate cap must be declared"
    );
    Ok(())
}

fn peer_rows(rows: &[resident_memory::Owner]) -> Result<()> {
    let rows = serde_json::to_value(rows)?;
    let rows = rows.as_array().context("exact live166/live167 peer rows")?;
    ensure!(
        rows.len() == 2,
        "both live peers required for retry5 epoch170"
    );
    for (epoch, unit, iid, admission, admission_sha, guard, guard_sha) in [
        (
            166,
            "horizon-qualify-166-replacement-local3retry6-20261110-v1.service",
            "b3992e492e1a4d49a9e4e4a01a13c815",
            "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json",
            "24033084033ab661720ea714cce584fdee4464a14e845563bb43de200ca0eb81",
            "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_GUARD_PROTECTION.json",
            "21cb4ced79b12be21c3f5011f7de183909078afa3f4826ef3c0e509bed0afa5d",
        ),
        (
            167,
            "horizon-qualify-167-replacement-local3retry5-20261110-v1.service",
            "c6f69b8bb668428ea560b12736a53b6b",
            "/var/lib/jetstreamer/retry5-single167-guarded-launch-20261117-v1/epoch167/ACTUAL_REPLACEMENT_ADMISSION.json",
            "e4332cdc5f6163748bbaa8197ae200e5da407362d688ec78290fa127c81fc1e1",
            "/var/lib/jetstreamer/retry5-single167-guarded-launch-20261117-v1/epoch167/ACTUAL_GUARD_PROTECTION.json",
            "faac89575a00a973d4ff83e6b63d4155d12ca9436d3125db7ed8b3ae6d5c4e0a",
        ),
    ] {
        let matching: Vec<_> = rows.iter().filter(|r| r["epoch"] == epoch).collect();
        ensure!(matching.len() == 1, "missing or duplicate live peer");
        let peer = matching[0];
        ensure!(
            peer["unit"] == unit
                && peer["invocation_id"] == iid
                && peer["admission"] == json!({"path":admission,"sha256":admission_sha})
                && peer["guard_protection"] == json!({"path":guard,"sha256":guard_sha}),
            "live peer identity or protection changed"
        );
    }
    Ok(())
}

pub(super) fn memory_scope(request: &resident_memory::Request) -> Result<u64> {
    ensure!(
        request.admission_only_capture
            && request.host_kernel_same_resident_basis
            && request.terminal166.is_none()
            && request.terminal167.is_none()
            && request.terminal169.as_ref() == Some(&terminal169::exact())
            && request.terminal170.as_ref() == Some(&terminal170::exact()),
        "retry5 epoch170 must retain exact terminal169/170 and both live peers"
    );
    terminal170::authenticate(request.terminal170.as_ref().context("stopped170")?)?;
    peer_rows(&request.owners)?;
    Ok(retry167::COMPLETE_DATA)
}

pub(super) fn shape(p: &Plan) -> Result<()> {
    if !selected(p) {
        ensure!(
            p.retry170.is_none(),
            "epoch170 retry5 proof on a foreign route"
        );
        return Ok(());
    }
    let r = p
        .retry170
        .as_ref()
        .context("retry5 epoch170 lineage required")?;
    ensure!(
        r.stopped_retry4_170 == terminal170::exact()
            && p.fresh_subtree == Path::new(FRESH_SUBTREE)
            && p.current_allocation
                .as_ref()
                .is_some_and(|v| v.schema == SCHEMA)
            && p.retry3.is_some()
            && p.retry4.is_none()
            && p.retry167.is_none()
            && p.existing_preparation.is_none(),
        "exact fresh epoch170 retry5 route required"
    );
    for unit in [
        terminal170::UNIT,
        "horizon-guard-replacement-170-local3retry4-20261110-v1.service",
        "horizon-guard-replacement-170-local3retry4-20261110-v1.timer",
    ] {
        ensure!(
            p.closed_units.iter().any(|x| x == unit),
            "stopped retry4 owner or guard omitted"
        );
    }
    let data = p
        .data_fulfillment
        .as_ref()
        .context("fresh DATA binding required")?;
    ensure!(
        data.contract.contract.path == Path::new(CONTRACT)
            && lower_hex(&data.contract.contract.sha256, 64)
            && data.contract.deployment_seal.path == Path::new(CONTRACT_SEAL)
            && lower_hex(&data.contract.deployment_seal.sha256, 64)
            && data.runtime.path == Path::new(GUARD_RUNTIME),
        "fresh epoch170 witness contract and successor guard required"
    );
    memory_scope(
        p.resident_memory
            .as_ref()
            .context("current peer capture required")?,
    )?;
    Ok(())
}

pub(super) fn authenticate(p: &Plan) -> Result<Value> {
    shape(p)?;
    if !selected(p) {
        return Ok(Value::Null);
    }
    let request = p.retry170.as_ref().context("retry5 epoch170 request")?;
    let stop = terminal170::authenticate(&request.stopped_retry4_170)?;
    let booking = Bound {
        path: RETAINED167_BOOKING.into(),
        sha256: RETAINED167_BOOKING_SHA.into(),
    };
    declaration(
        &json!({
            "retained_epoch167_cap_booking": booking,
            "candidate_root_cap_bytes": ROOT_CAP,
            "protected167_root_cap_bytes": retry167::CANDIDATE_CAP,
        }),
        p,
    )?;
    Ok(json!({
        "stopped_retry4_170": stop,
        "retained_epoch167_cap_booking": booking,
        "fresh_attempt": ATTEMPT,
        "candidate_root_cap_bytes": ROOT_CAP,
        "protected167_root_cap_bytes": retry167::CANDIDATE_CAP,
        "all_prior_promises_retained": true,
        "resource_credit_bytes": 0,
        "replay_launch_authorized": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_set_rejects_missing_duplicate_and_foreign_generation() {
        let mut rows: Vec<resident_memory::Owner> = serde_json::from_value(json!([
            {
                "epoch": 166,
                "unit": "horizon-qualify-166-replacement-local3retry6-20261110-v1.service",
                "invocation_id": "b3992e492e1a4d49a9e4e4a01a13c815",
                "main_pid": 689067,
                "main_start_ticks": 1,
                "admission": {"path": "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json", "sha256": "24033084033ab661720ea714cce584fdee4464a14e845563bb43de200ca0eb81"},
                "guard_protection": {"path": "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_GUARD_PROTECTION.json", "sha256": "21cb4ced79b12be21c3f5011f7de183909078afa3f4826ef3c0e509bed0afa5d"}
            },
            {
                "epoch": 167,
                "unit": "horizon-qualify-167-replacement-local3retry5-20261110-v1.service",
                "invocation_id": "c6f69b8bb668428ea560b12736a53b6b",
                "main_pid": 872689,
                "main_start_ticks": 1,
                "admission": {"path": "/var/lib/jetstreamer/retry5-single167-guarded-launch-20261117-v1/epoch167/ACTUAL_REPLACEMENT_ADMISSION.json", "sha256": "e4332cdc5f6163748bbaa8197ae200e5da407362d688ec78290fa127c81fc1e1"},
                "guard_protection": {"path": "/var/lib/jetstreamer/retry5-single167-guarded-launch-20261117-v1/epoch167/ACTUAL_GUARD_PROTECTION.json", "sha256": "faac89575a00a973d4ff83e6b63d4155d12ca9436d3125db7ed8b3ae6d5c4e0a"}
            }
        ])).unwrap();
        peer_rows(&rows).unwrap();
        let absent = rows.pop().unwrap();
        assert!(peer_rows(&rows).is_err());
        rows.push(absent);
        let mut duplicate: Vec<resident_memory::Owner> =
            serde_json::from_value(serde_json::to_value(&rows).unwrap()).unwrap();
        duplicate[1] = serde_json::from_value(serde_json::to_value(&rows[0]).unwrap()).unwrap();
        assert!(peer_rows(&duplicate).is_err());
        let mut foreign: Value = serde_json::to_value(&rows).unwrap();
        foreign[1]["invocation_id"] = json!("f".repeat(32));
        let foreign: Vec<resident_memory::Owner> = serde_json::from_value(foreign).unwrap();
        assert!(peer_rows(&foreign).is_err());
    }
}
