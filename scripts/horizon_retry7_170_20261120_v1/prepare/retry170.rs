//! Exact retry7 candidate170 with protected166 retry8 and genuinely admitted167 retry7.
//! Future167 identity comes only from authenticated admission and protection, never a forecast.
use super::*;
pub(super) const ATTEMPT: &str = "local3retry7";
pub(super) const SCHEMA: &str = "horizon-epoch170-retry7-native-allocation-v1";
pub(super) const WORKING_SET_SCHEMA: &str = "horizon-epoch170-retry7-current-fleet-working-set-v1";
pub(super) const COMPLETE_DATA: u64 = retry167::COMPLETE_DATA + ROOT_CAP;
pub(super) const RAW_FLOOR: u64 = retry167::RAW_FLOOR + ROOT_CAP;
pub(super) const GUARD_RUNTIME: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1/guard-v1/guard";
pub(super) const GUARD_SHA: &str =
    "6b9b398287815ca9581ed3fbd5e15e772eceef3eacd31a7463822288b5641c6a";
pub(super) const PEER166_UNIT: &str =
    "horizon-qualify-166-replacement-local3retry8-20261110-v1.service";
pub(super) const PEER166_IID: &str = "4f09db5f45074244a45b06aeef932d1d";
pub(super) const PEER167_UNIT: &str =
    "horizon-qualify-167-replacement-local3retry7-20261110-v1.service";
const PEER166_ADMISSION: &str = "/var/lib/jetstreamer/retry8-single166-guarded-launch-20261119-v1/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json";
const PEER166_ADMISSION_SHA: &str =
    "3cb6ab13fab607414111c2e027ff36b9716b1050de008e631e5475df5d857273";
const PEER166_PROTECTION: &str = "/var/lib/jetstreamer/retry8-single166-guarded-launch-20261119-v1/epoch166/ACTUAL_GUARD_PROTECTION.json";
const PEER166_PROTECTION_SHA: &str =
    "c50f120993c44bd899a81deb260dd1c2e68505020457af793611525534061918";
const STOP: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch170/local3retry5/guard-state/receipts/stop-completion.json";
const STOP_SHA: &str = "1751d0ad7c16e58b7dec251908120275f8ea0bb1fc6fe85073e3d812a1618168";
const INTENT: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch170/local3retry5/guard-state/receipts/stop-intent.json";
const INTENT_SHA: &str = "3fadd006f888a072f4743031e0413375210f9bd4ad4b1b986682289b43d1400d";
const STOP_IID: &str = "aab865eb4cee44d69f536944e4c5f722";
const STOP_PLAN_SHA: &str = "d348dc434adc78b0924d008fede3fea40d46624605c59d414c2b4f8004ac2178";
const STOP6: &str = "/var/lib/jetstreamer/retry6-170-preparation-20261118-v1/epoch170/local3retry6/guard-state/receipts/stop-completion.json";
const STOP6_SHA: &str = "3601e2dabb55f7c3ca9ed8f91c253588f301b51a87c42ba9ece18f73fab48264";
const INTENT6: &str = "/var/lib/jetstreamer/retry6-170-preparation-20261118-v1/epoch170/local3retry6/guard-state/receipts/stop-intent.json";
const INTENT6_SHA: &str = "22344407c7f7f034eae858791636fc0275c7b12c2bee1a5326e18dd1560700fb";
const STOP6_IID: &str = "ebd212d2045145259449d1d5c3d65353";
const STOP6_PLAN_SHA: &str = "6f689ea9a9ab92bf0ab4b3d6fe1a0a585282f0bad7be7bbb975f583dccea217f";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub stopped_retry4_170: terminal170::Request,
    pub stopped_retry5_170: Bound,
    pub stopped_retry6_170: Bound,
    pub retained_epoch167_booking: Bound,
    pub protected167_admission: Bound,
    pub protected167_guard: Bound,
}
fn exact(path: &str, sha256: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha256.into(),
    }
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
fn stop_chain_shape(
    stop: &Value,
    intent: &Value,
    invocation: &str,
    intent_path: &str,
    plan_sha: &str,
) -> Result<()> {
    let sample = &intent["sample"];
    ensure!(
        stop["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && stop["producer_invocation_id"] == invocation
            && stop["intent"] == intent_path
            && stop["plan_sha256"] == plan_sha
            && stop["terminal"]["invocation_id"] == invocation
            && stop["terminal"]["pid"] == 0
            && stop["terminal"]["restarts"] == 0
            && stop["terminal"]["active"] == "inactive"
            && stop["terminal"]["sub"] == "dead"
            && stop["terminal"]["result"] == "success"
            && stop["terminal"]["restart_policy"] == "no"
            && stop["terminal"]["kill_mode"] == "control-group"
            && stop["terminal"]["delegated"] == false
            && stop["scratch_deleted"] == false
            && stop["remote_mutations"] == false
            && stop["r2_mutations"] == false
            && intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && intent["producer_invocation_id"] == invocation
            && intent["plan_sha256"] == plan_sha
            && intent["reason"] == "DATA-fulfillment-observation-failed"
            && sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["plan_sha256"] == plan_sha
            && sample["producer_invocation_id"] == invocation
            && sample["producer"]["invocation_id"] == invocation
            && sample["producer"]["active"] == "active"
            && sample["producer"]["sub"] == "running"
            && sample["producer"]["pid"]
                .as_u64()
                .is_some_and(|pid| pid > 0)
            && sample["producer"]["restarts"] == 0
            && sample["producer"]["restart_policy"] == "no"
            && sample["producer"]["kill_mode"] == "control-group"
            && sample["producer"]["delegated"] == false
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"] == "DATA-fulfillment-observation-failed"
            && sample["scratch_deleted"] == false
            && sample["remote_mutations"] == false
            && sample["r2_mutations"] == false,
        "exact terminal producer, stop intent and sampled plan must agree"
    );
    Ok(())
}
fn stop_shape(stop: &Value, intent: &Value) -> Result<()> {
    stop_chain_shape(stop, intent, STOP_IID, INTENT, STOP_PLAN_SHA)
        .context("exact terminal retry5 epoch170 is required")
}
fn authenticate_stop() -> Result<Value> {
    let stop = bound(&exact(STOP, STOP_SHA))?;
    stop_shape(&stop, &bound(&exact(INTENT, INTENT_SHA))?)?;
    Ok(stop)
}
fn stop6_shape(stop: &Value, intent: &Value) -> Result<()> {
    stop_chain_shape(stop, intent, STOP6_IID, INTENT6, STOP6_PLAN_SHA)?;
    ensure!(
        intent["sample"]["DATA_fulfillment_observation_error"] == "bounded writer query"
            && intent["sample"]["guard_sha256"]
                == "2572c20c10b1473a9438e8d08d4aaf6ccb06fa9aa47e3508fe90e6bcaddddc6b"
            && intent["sample"]["guard_invocation_id"] == "29f2f649118e4828b36c934f4e71aa20"
            && intent["sample"]["minimum_free_bytes"] == RAW_FLOOR
            && intent["sample"]["maximum_root_physical_bytes"] == ROOT_CAP
            && intent["sample"]["fulfilled_existing_DATA_bytes"] == 0,
        "exact retry6 terminal and failed-query evidence required"
    );
    Ok(())
}
fn authenticate_stop6() -> Result<Value> {
    let stop = bound(&exact(STOP6, STOP6_SHA))?;
    stop6_shape(&stop, &bound(&exact(INTENT6, INTENT6_SHA))?)?;
    Ok(stop)
}
fn peer_rows_shape(rows: &Value, a: &Value, g: &Value) -> Result<()> {
    let rows = rows.as_array().context("exact166/167 owners")?;
    ensure!(rows.len() == 2, "both genuinely live166/167 peers required");
    let row = |epoch| -> Result<&Value> {
        let selected: Vec<_> = rows.iter().filter(|v| v["epoch"] == epoch).collect();
        ensure!(selected.len() == 1, "missing or duplicate live peer");
        Ok(selected[0])
    };
    let r = row(166)?;
    ensure!(
        r["unit"] == PEER166_UNIT
            && r["invocation_id"] == PEER166_IID
            && r["main_pid"] == 1746683
            && r["main_start_ticks"] == 339966412u64
            && r["admission"]
                == serde_json::to_value(exact(PEER166_ADMISSION, PEER166_ADMISSION_SHA))?
            && r["guard_protection"]
                == serde_json::to_value(exact(PEER166_PROTECTION, PEER166_PROTECTION_SHA))?,
        "protected166 retry8 identity changed"
    );
    let r = row(167)?;
    ensure!(
        r["unit"] == PEER167_UNIT
            && r["invocation_id"]
                .as_str()
                .is_some_and(|v| lower_hex(v, 32))
            && r["main_pid"].as_u64().is_some_and(|v| v > 0)
            && r["main_start_ticks"].as_u64().is_some_and(|v| v > 0)
            && a["schema"] == "horizon-standard-replacement-admission-v1"
            && a["owner"] == "/root"
            && a["primary_thread"] == THREAD
            && a["epoch"] == 167
            && a["producer_unit"] == PEER167_UNIT
            && a["producer_invocation_id"] == r["invocation_id"]
            && a["producer_pid"] == r["main_pid"]
            && a["fresh_admission_passed"] == true
            && a["all_prior_promises_retained"] == true
            && a["guard_minimum_free_bytes"] == RAW_FLOOR
            && a["memory_or_DATA_promise_ending_bytes"] == 0
            && a["resource_credit_bytes"] == 0
            && g["schema"] == "horizon-standard-live-peer-protection-v1"
            && g["epoch"] == 167
            && g["producer_unit"] == PEER167_UNIT
            && g["producer_invocation_id"] == r["invocation_id"]
            && g["admission"] == r["admission"],
        "future167 must have actual matching admission, guard, PID and retained floor"
    );
    Ok(())
}
fn peer_rows(rows: &[resident_memory::Owner]) -> Result<()> {
    let rows = serde_json::to_value(rows)?;
    let peer = rows
        .as_array()
        .context("owners")?
        .iter()
        .find(|r| r["epoch"] == 167)
        .context("live167")?;
    let a: Bound = serde_json::from_value(peer["admission"].clone())?;
    let g: Bound = serde_json::from_value(peer["guard_protection"].clone())?;
    peer_rows_shape(&rows, &bound(&a)?, &bound(&g)?)
}
pub(super) fn memory_scope(request: &resident_memory::Request) -> Result<u64> {
    ensure!(
        request.admission_only_capture
            && request.host_kernel_same_resident_basis
            && request.terminal166.is_none()
            && request.terminal167.is_none()
            && request.terminal169.as_ref() == Some(&terminal169::exact())
            && request.terminal170.as_ref() == Some(&terminal170::exact()),
        "retry7 epoch170 requires exact terminal169/170, retry6 stop, and two protected peers"
    );
    terminal170::authenticate(request.terminal170.as_ref().context("stopped170")?)?;
    authenticate_stop()?;
    authenticate_stop6()?;
    peer_rows(&request.owners)?;
    Ok(COMPLETE_DATA)
}
pub(super) fn declaration(v: &Value, p: &Plan) -> Result<()> {
    if !selected(p) {
        return Ok(());
    }
    let r = p.retry170.as_ref().context("retry170 request")?;
    let booking = bound(&r.retained_epoch167_booking)?;
    ensure!(
        v["retained_epoch167_cap_booking"] == serde_json::to_value(&r.retained_epoch167_booking)?
            && v["candidate_root_cap_bytes"] == ROOT_CAP
            && v["protected167_root_cap_bytes"] == retry167::CANDIDATE_CAP
            && v["retained_retry6_166_DATA_bytes"] == ROOT_CAP
            && booking["schema"] == "horizon-epoch167-retry6-additive-root-cap-booking-v1"
            && booking["owner"] == "/root"
            && booking["primary_thread"] == THREAD
            && booking["epoch"] == 167
            && booking["attempt"] == "local3retry7"
            && booking["reservation_booked"] == true
            && booking["all_prior_promises_retained"] == true
            && booking["complete_DATA_bytes"] == COMPLETE_DATA
            && booking["raw_floor_bytes"] == RAW_FLOOR
            && booking["candidate_root_cap_bytes"] == retry167::CANDIDATE_CAP
            && booking["retained_retry6_166_DATA_bytes"] == ROOT_CAP
            && booking["protected166_admission"]
                == serde_json::to_value(exact(PEER166_ADMISSION, PEER166_ADMISSION_SHA))?
            && booking["protected166_guard"]
                == serde_json::to_value(exact(PEER166_PROTECTION, PEER166_PROTECTION_SHA))?
            && booking["resource_credit_bytes"] == 0
            && booking["resource_promise_ending_bytes"] == 0,
        "full retained166/167 DATA booking required"
    );
    let prep = bound(&serde_json::from_value::<Bound>(
        bound(&r.protected167_admission)?["fresh_native_Rust_preparation"].clone(),
    )?)?;
    let plan = bound(&serde_json::from_value::<Bound>(prep["plan"].clone())?)?;
    ensure!(
        prep["epoch"] == 167
            && prep["attempt"] == "local3retry7"
            && plan["retry167"]["additive_data_booking"]
                == serde_json::to_value(&r.retained_epoch167_booking)?,
        "retained booking is not the genuinely admitted167 preparation booking"
    );
    Ok(())
}
pub(super) fn shape(p: &Plan) -> Result<()> {
    if !selected(p) {
        ensure!(p.retry170.is_none(), "retry170 evidence on foreign route");
        return Ok(());
    }
    let r = p.retry170.as_ref().context("retry7 epoch170 lineage")?;
    ensure!(
        r.stopped_retry4_170 == terminal170::exact()
            && r.stopped_retry5_170 == exact(STOP, STOP_SHA)
            && r.stopped_retry6_170 == exact(STOP6, STOP6_SHA)
            && p.producer_unit
                == "horizon-qualify-170-replacement-local3retry7-20261110-v1.service"
            && p.guard_base == "horizon-guard-replacement-170-local3retry7-20261110-v1"
            && p.fresh_subtree
                == Path::new(
                    "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1"
                )
            && p.current_allocation
                .as_ref()
                .is_some_and(|v| v.schema == SCHEMA)
            && p.retry3.is_some()
            && p.retry4.is_none()
            && p.retry167.is_none()
            && p.existing_preparation.is_none(),
        "exact fresh170 retry7 route required"
    );
    for unit in [
        terminal170::UNIT,
        "horizon-guard-replacement-170-local3retry4-20261110-v1.service",
        "horizon-guard-replacement-170-local3retry4-20261110-v1.timer",
        "horizon-qualify-170-replacement-local3retry5-20261110-v1.service",
        "horizon-guard-replacement-170-local3retry5-20261110-v1.service",
        "horizon-guard-replacement-170-local3retry5-20261110-v1.timer",
        "horizon-qualify-170-replacement-local3retry6-20261110-v1.service",
        "horizon-guard-replacement-170-local3retry6-20261110-v1.service",
        "horizon-guard-replacement-170-local3retry6-20261110-v1.timer",
    ] {
        ensure!(
            p.closed_units.iter().any(|u| u == unit),
            "stopped170 generation omitted"
        );
    }
    for b in [
        &r.retained_epoch167_booking,
        &r.protected167_admission,
        &r.protected167_guard,
    ] {
        ensure!(
            b.path.starts_with("/var/lib/jetstreamer") && lower_hex(&b.sha256, 64),
            "private hash-bound actual evidence required"
        );
    }
    let data = p
        .data_fulfillment
        .as_ref()
        .context("fresh guard contract")?;
    guard_contract_shape(data)?;
    let m = p.resident_memory.as_ref().context("current peers")?;
    memory_scope(m)?;
    let rows = serde_json::to_value(&m.owners)?;
    let peer = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["epoch"] == 167)
        .context("peer167")?;
    ensure!(
        peer["admission"] == serde_json::to_value(&r.protected167_admission)?
            && peer["guard_protection"] == serde_json::to_value(&r.protected167_guard)?,
        "plan and native peer proof differ"
    );
    Ok(())
}
fn guard_contract_shape(data: &prelaunch_data::Request) -> Result<()> {
    prelaunch_data::shape(data)?;
    ensure!(
        data.runtime.path == Path::new(GUARD_RUNTIME)
            && data.runtime.sha256 == GUARD_SHA
            && contract_path(&data.contract.contract.path)
            && data.contract.deployment_seal.path
                == data
                    .contract
                    .contract
                    .path
                    .parent()
                    .unwrap()
                    .join("deployment-seal-receipt.json"),
        "successor170 guard and own-image native contract required"
    );
    Ok(())
}
pub(super) fn authenticate(p: &Plan) -> Result<Value> {
    shape(p)?;
    if !selected(p) {
        return Ok(Value::Null);
    }
    let r = p.retry170.as_ref().context("retry170 request")?;
    let stop = authenticate_stop()?;
    declaration(
        &json!({"retained_epoch167_cap_booking":r.retained_epoch167_booking,
        "candidate_root_cap_bytes":ROOT_CAP,"protected167_root_cap_bytes":retry167::CANDIDATE_CAP,
        "retained_retry6_166_DATA_bytes":ROOT_CAP}),
        p,
    )?;
    Ok(
        json!({"stopped_retry6_170":authenticate_stop6()?,"stopped_retry5_170":stop,"stopped_retry4_170":terminal170::authenticate(&r.stopped_retry4_170)?,
        "retained_epoch167_cap_booking":r.retained_epoch167_booking,"protected167_admission":r.protected167_admission,
        "protected167_guard":r.protected167_guard,"fresh_attempt":ATTEMPT,"complete_DATA_bytes":COMPLETE_DATA,
        "raw_floor_bytes":RAW_FLOOR,"resource_credit_bytes":0,"replay_launch_authorized":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    // Byte-for-byte retained receipts, not fabricated successful native evidence.
    // Production still authenticates the original root-owned, hash-bound files.
    fn stop_fixtures(retry: u8) -> (Value, Value) {
        let (stop, intent, stop_sha, intent_sha) = match retry {
            5 => (
                include_bytes!("fixtures/retry5-stop-completion.json").as_slice(),
                include_bytes!("fixtures/retry5-stop-intent.json").as_slice(),
                STOP_SHA,
                INTENT_SHA,
            ),
            6 => (
                include_bytes!("fixtures/retry6-stop-completion.json").as_slice(),
                include_bytes!("fixtures/retry6-stop-intent.json").as_slice(),
                STOP6_SHA,
                INTENT6_SHA,
            ),
            _ => panic!("unknown retained generation"),
        };
        assert_eq!(digest(stop), stop_sha);
        assert_eq!(digest(intent), intent_sha);
        (
            serde_json::from_slice(stop).unwrap(),
            serde_json::from_slice(intent).unwrap(),
        )
    }
    #[test]
    fn genuine_retry6_stop_retains_exact_owner_and_failure() {
        let (stop, intent) = stop_fixtures(6);
        stop6_shape(&stop, &intent).unwrap();
        for key in [
            "producer_invocation_id",
            "scratch_deleted",
            "intent",
            "plan_sha256",
        ] {
            let mut changed = stop.clone();
            changed[key] = Value::Null;
            assert!(stop6_shape(&changed, &intent).is_err());
        }
        let mut changed = intent.clone();
        changed["sample"]["DATA_fulfillment_observation_error"] = json!("unrelated failure");
        assert!(stop6_shape(&stop, &changed).is_err());
        assert_ne!(STOP6_IID, STOP_IID);
        assert_eq!(ATTEMPT, "local3retry7");
    }
    fn reject_changed_stop_chain(
        stop: &Value,
        intent: &Value,
        check: fn(&Value, &Value) -> Result<()>,
    ) {
        check(stop, intent).unwrap();
        for pointer in [
            "/schema",
            "/producer_invocation_id",
            "/intent",
            "/plan_sha256",
            "/terminal/invocation_id",
            "/terminal/pid",
            "/terminal/restarts",
            "/terminal/active",
            "/terminal/sub",
            "/terminal/result",
            "/terminal/restart_policy",
            "/terminal/kill_mode",
            "/terminal/delegated",
            "/scratch_deleted",
            "/remote_mutations",
            "/r2_mutations",
        ] {
            let mut changed = stop.clone();
            *changed.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(check(&changed, intent).is_err(), "stop {pointer}");
        }
        for pointer in [
            "/schema",
            "/producer_invocation_id",
            "/plan_sha256",
            "/reason",
            "/sample/schema",
            "/sample/plan_sha256",
            "/sample/producer_invocation_id",
            "/sample/producer/invocation_id",
            "/sample/producer/active",
            "/sample/producer/sub",
            "/sample/producer/pid",
            "/sample/producer/restarts",
            "/sample/producer/restart_policy",
            "/sample/producer/kill_mode",
            "/sample/producer/delegated",
            "/sample/producer_stop_enabled",
            "/sample/trip_reason",
            "/sample/scratch_deleted",
            "/sample/remote_mutations",
            "/sample/r2_mutations",
        ] {
            let mut changed = intent.clone();
            *changed.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(check(stop, &changed).is_err(), "intent {pointer}");
        }
        // Equal missing or forged hashes must not satisfy the linked-plan gate.
        for replacement in [Value::Null, json!("f".repeat(64))] {
            let mut changed_stop = stop.clone();
            let mut changed_intent = intent.clone();
            changed_stop["plan_sha256"] = replacement.clone();
            changed_intent["plan_sha256"] = replacement.clone();
            changed_intent["sample"]["plan_sha256"] = replacement;
            assert!(check(&changed_stop, &changed_intent).is_err());
        }
    }
    #[test]
    fn both_retained_stops_reject_broken_terminal_and_sample_bindings() {
        let (stop5, intent5) = stop_fixtures(5);
        let (stop6, intent6) = stop_fixtures(6);
        reject_changed_stop_chain(&stop5, &intent5, stop_shape);
        reject_changed_stop_chain(&stop6, &intent6, stop6_shape);
        assert!(stop6_shape(&stop5, &intent6).is_err());
        assert!(stop6_shape(&stop6, &intent5).is_err());
        assert!(stop_shape(&stop6, &intent6).is_err());
        for pointer in [
            "/sample/guard_sha256",
            "/sample/guard_invocation_id",
            "/sample/minimum_free_bytes",
            "/sample/maximum_root_physical_bytes",
            "/sample/fulfilled_existing_DATA_bytes",
        ] {
            let mut changed = intent6.clone();
            *changed.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(stop6_shape(&stop6, &changed).is_err(), "{pointer}");
        }
    }
    #[test]
    fn retry7_contract_requires_exact_new_guard_and_seal_locations() {
        // Parser-only request: it cannot supply native witness or admission authority.
        let mut request = prelaunch_data::tests::request();
        request.runtime = exact(GUARD_RUNTIME, GUARD_SHA);
        request.runtime_seal.path = Path::new(GUARD_RUNTIME)
            .parent()
            .unwrap()
            .join("deployment-seal-receipt.json");
        request.contract.contract.path = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1/data-contract-v1/contract.json".into();
        request.contract.deployment_seal.path = request
            .contract
            .contract
            .path
            .parent()
            .unwrap()
            .join("deployment-seal-receipt.json");
        guard_contract_shape(&request).unwrap();
        let mut changed = request.clone();
        changed.runtime.sha256 =
            "2572c20c10b1473a9438e8d08d4aaf6ccb06fa9aa47e3508fe90e6bcaddddc6b".into();
        assert!(guard_contract_shape(&changed).is_err());
        changed = request.clone();
        changed.runtime.path = "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry7-data-guard-20261118-v1/guard".into();
        assert!(guard_contract_shape(&changed).is_err());
        changed = request.clone();
        changed.runtime_seal.path = "/tmp/deployment-seal-receipt.json".into();
        assert!(guard_contract_shape(&changed).is_err());
        changed = request.clone();
        changed.contract.deployment_seal.path = "/tmp/deployment-seal-receipt.json".into();
        assert!(guard_contract_shape(&changed).is_err());
        changed = request;
        changed.contract.contract.path = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/data-contract-2315-v1/contract.json".into();
        changed.contract.deployment_seal.path = changed
            .contract
            .contract
            .path
            .parent()
            .unwrap()
            .join("deployment-seal-receipt.json");
        assert!(guard_contract_shape(&changed).is_err());
    }
    #[test]
    fn genuine166retry8_protection_retains_current_complete_floor() {
        let a = bound(&exact(PEER166_ADMISSION, PEER166_ADMISSION_SHA)).unwrap();
        let g = bound(&exact(PEER166_PROTECTION, PEER166_PROTECTION_SHA)).unwrap();
        assert_eq!(a["producer_unit"], PEER166_UNIT);
        assert_eq!(a["producer_invocation_id"], PEER166_IID);
        assert_eq!(a["producer_pid"], 1746683);
        assert_eq!(a["guard_minimum_free_bytes"], RAW_FLOOR);
        assert_eq!(
            g["admission"],
            serde_json::to_value(exact(PEER166_ADMISSION, PEER166_ADMISSION_SHA)).unwrap()
        );
        let plan = bound(&serde_json::from_value(g["plan"].clone()).unwrap()).unwrap();
        assert_eq!(plan["minimum_free_bytes"], RAW_FLOOR);
        assert_eq!(plan["maximum_root_physical_bytes"], ROOT_CAP);
    }
    #[test]
    fn genuine170_retry5_terminal_is_required() {
        let (stop, intent) = stop_fixtures(5);
        stop_shape(&stop, &intent).unwrap();
        for key in ["producer_invocation_id", "scratch_deleted", "intent"] {
            let mut bad = stop.clone();
            bad[key] = Value::Null;
            assert!(stop_shape(&bad, &intent).is_err());
        }
        assert_eq!(COMPLETE_DATA, 6_794_761_027_378);
        assert_eq!(RAW_FLOOR, 6_829_053_656_882);
    }
    #[test]
    fn no_future_peer_is_accepted_without_admission() {
        assert!(peer_rows_shape(&json!([]), &Value::Null, &Value::Null).is_err());
        assert!(
            peer_rows_shape(
                &json!([{"epoch":166},{"epoch":167,"unit":PEER167_UNIT}]),
                &Value::Null,
                &Value::Null
            )
            .is_err()
        );
    }
    #[test]
    fn matching_future_peer_requires_every_admission_binding() {
        // Synthetic parser fixture only; operational peer_rows always hash-reads genuine receipts.
        let ab = json!({"path":"/var/lib/jetstreamer/test/ACTUAL_REPLACEMENT_ADMISSION.json","sha256":"a".repeat(64)});
        let rows = json!([
            {"epoch":166,"unit":PEER166_UNIT,"invocation_id":PEER166_IID,"main_pid":1746683,"main_start_ticks":339966412u64,
             "admission":exact(PEER166_ADMISSION,PEER166_ADMISSION_SHA),"guard_protection":exact(PEER166_PROTECTION,PEER166_PROTECTION_SHA)},
            {"epoch":167,"unit":PEER167_UNIT,"invocation_id":"b".repeat(32),"main_pid":123,"main_start_ticks":456,"admission":ab}
        ]);
        let a = json!({"schema":"horizon-standard-replacement-admission-v1","owner":"/root","primary_thread":THREAD,
            "epoch":167,"producer_unit":PEER167_UNIT,"producer_invocation_id":"b".repeat(32),"producer_pid":123,
            "fresh_admission_passed":true,"all_prior_promises_retained":true,"guard_minimum_free_bytes":RAW_FLOOR,
            "memory_or_DATA_promise_ending_bytes":0,"resource_credit_bytes":0});
        let g = json!({"schema":"horizon-standard-live-peer-protection-v1","epoch":167,"producer_unit":PEER167_UNIT,
            "producer_invocation_id":"b".repeat(32),"admission":ab});
        peer_rows_shape(&rows, &a, &g).unwrap();
        let mut stopped_peer = rows.clone();
        stopped_peer[1]["unit"] =
            json!("horizon-qualify-167-replacement-local3retry6-20261110-v1.service");
        assert!(peer_rows_shape(&stopped_peer, &a, &g).is_err());
        for key in [
            "producer_unit",
            "producer_invocation_id",
            "producer_pid",
            "guard_minimum_free_bytes",
            "fresh_admission_passed",
            "all_prior_promises_retained",
            "resource_credit_bytes",
            "memory_or_DATA_promise_ending_bytes",
        ] {
            let mut bad = a.clone();
            bad[key] = Value::Null;
            assert!(peer_rows_shape(&rows, &bad, &g).is_err(), "{key}");
        }
        let mut bad = g.clone();
        bad["admission"]["sha256"] = json!("c".repeat(64));
        assert!(peer_rows_shape(&rows, &a, &bad).is_err());
        assert!(peer_rows_shape(&json!([rows[0], rows[0]]), &a, &g).is_err());
    }
}

fn contract_path(path: &Path) -> bool {
    if path.file_name().and_then(|name| name.to_str()) != Some("contract.json") {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    // Retain the qualified legacy contracts used for measurement. Fresh HOME
    // contracts have their own exact parent and the stage tool's generation tag.
    // This path selector grants no seal, witness, freshness or resource credit.
    let prefix = match parent.parent() {
        Some(root) if root == Path::new("/usr/local/lib/jetstreamer") => {
            "horizon-epoch170-retry6-live166retry8-data-contract-"
        }
        Some(root)
            if root
                == Path::new(
                    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1",
                ) =>
        {
            "data-contract-"
        }
        _ => return false,
    };
    parent
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(prefix))
        .is_some_and(|tag| {
            (1..=32).contains(&tag.len())
                && tag
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}
#[cfg(test)]
mod contract_generation_tests {
    use super::*;
    const HOME: &str =
        "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1";

    #[test]
    fn contract_generations_never_escape_exact_namespace() {
        for tag in ["20261119-v1", "retry2"] {
            assert!(contract_path(Path::new(&format!(
                "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-data-contract-{tag}/contract.json"
            ))));
        }
        for path in [
            "/tmp/contract.json",
            "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-data-contract-/contract.json",
            "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-data-contract-v2/other.json",
            "/usr/local/lib/jetstreamer/horizon-epoch167-retry6-live166retry8-data-contract-v2/contract.json",
            "/usr/local/lib/jetstreamer/data-contract-v2/contract.json",
        ] {
            assert!(!contract_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn home_contracts_accept_exact_stage_generations_and_preserve_legacy_measurements() {
        let longest = "a".repeat(32);
        for tag in ["v1", "v2", "20261119-v1", "retry2", longest.as_str()] {
            let home = format!("{HOME}/data-contract-{tag}/contract.json");
            let legacy = format!(
                "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-data-contract-{tag}/contract.json"
            );
            assert!(contract_path(Path::new(&home)), "{home}");
            assert!(contract_path(Path::new(&legacy)), "{legacy}");
        }
        let too_long = "a".repeat(33);
        for tag in [
            "",
            "V2",
            "v_2",
            "v.2",
            "v2/child",
            "../v2",
            too_long.as_str(),
        ] {
            let path = format!("{HOME}/data-contract-{tag}/contract.json");
            assert!(!contract_path(Path::new(&path)), "{path}");
        }
        for path in [
            format!("{HOME}/data-contract-v2/other.json"),
            format!("{HOME}/data-contract-v2/child/contract.json"),
            format!("{HOME}/data-contract-v2/../contract.json"),
            format!("{HOME}/../data-contract-v2/contract.json"),
            format!("{HOME}-other/data-contract-v2/contract.json"),
            format!("{HOME}/horizon-epoch170-retry6-live166retry8-data-contract-v2/contract.json"),
            format!(
                "{}/data-contract-v2/contract.json",
                HOME.replace("epoch170", "epoch169")
            ),
            format!(
                "{}/data-contract-v2/contract.json",
                HOME.replace("retry7-recovery", "retry8-recovery")
            ),
        ] {
            assert!(!contract_path(Path::new(&path)), "{path}");
        }
    }
}
