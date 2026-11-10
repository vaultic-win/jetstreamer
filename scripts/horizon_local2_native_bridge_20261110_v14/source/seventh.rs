//! Exact epoch172 original birth. Source pins come from genuine retained native evidence.
use super::*;
pub(super) const BATCH172: &str = "/var/lib/jetstreamer/cached-standard-input-qualification-20261110-v1/actual-next172-local2-launch-v1";
const UNIT: &str = "horizon-qualify-172-replacement-local2-20261110-v1.service";
const PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-independent172-singleton-package-20261110-v1";
fn profile() -> R<Value> {
    let p: Value = serde_json::from_str(include_str!("epoch172-pins.json"))?;
    validate_registration(&p)?;
    Ok(p)
}
fn validate_registration(p: &Value) -> R<()> {
    need(
        p["schema"] == "horizon-local2-exact172-native-registration-v1"
            && p["genuine_native_birth_registered"] == true,
        "epoch172 awaits genuine native birth registration; no identity inferred",
    )
}
fn exact(p: &Value, birth: &Value) -> R<Value> {
    let native = &birth["native"];
    let run = Path::new(s(p, "run_directory")?);
    let start = n(p, "original_start_unix_seconds")?;
    need(p["epoch"]==172 && p["unit"]==UNIT && p["invocation_id"].as_str().is_some_and(|s|s.len()==32 && s.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) && n(p,"main_pid")?>1 && start>0 && native["Id"]==UNIT && native["InvocationID"]==p["invocation_id"] && s(native,"MainPID")?.parse::<u64>()?==n(p,"main_pid")? && native["ExecMainStartTimestamp"]==p["original_start_native"] && native["WorkingDirectory"]==PACKAGE && native["ControlGroup"]==format!("/system.slice/{UNIT}") && birth["run_directory"]==p["run_directory"] && birth["scratch_path"]==json!(run.join("scratch")) && birth["no_transaction_replay_claimed"]==true && birth["launch"]==p["launch"] && run.is_absolute() && run.starts_with("/home/sol/.jetstreamer-private/epoch172-standard-lane-20261110-v1/replacement-local2-20261110-v1/private") && Path::new(s(p,"worker_executable")?).starts_with(run.join("scratch/.historical-runtime")) && Path::new(s(p,"worker_executable")?).file_name().is_some_and(|n|n=="historical-worker"),"exact172 registered birth/run/copied worker differs")?;
    owner(native, native)?;
    Ok(
        json!({"producer_invocation_id":p["invocation_id"],"run_directory":run,"scratch_path":run.join("scratch"),"archive_path":run.join("archives/epoch-172.jet"),"worker_executable":p["worker_executable"],"birth_binding":p["birth"]}),
    )
}
pub(super) fn paths172() -> R<Value> {
    let p = profile()?;
    exact(&p, &hash_bound(&p["birth"])?)
}
pub(super) fn bootstrap_start172() -> R<u64> {
    n(&profile()?, "original_start_unix_seconds")
}
pub(super) fn validate172_original(original: &Value, paths: &Value, start: u64) -> R<()> {
    let p = profile()?;
    let birth = hash_bound(&p["birth"])?;
    need(
        hash_bound(&p["original_native"])? == birth["native"],
        "172 birth/native envelope changed",
    )?;
    identity172(&p, original, paths, &birth, start)?;
    let first = hash_bound(&p["first_guard"])?;
    let sample = hash_bound(&first["receipt"])?;
    let protection = hash_bound(&p["protection"])?;
    first172(&p, &birth["native"], &first, &sample, &protection)?;
    let result = hash_bound(&p["launch"])?;
    launch172(&p, &result)?;
    let batch = Path::new(BATCH172).join("epoch172");
    need(
        p["admission"] == bound(&batch.join("ACTUAL_REPLACEMENT_ADMISSION.json"))?
            && p["protection"] == bound(&batch.join("ACTUAL_GUARD_PROTECTION.json"))?,
        "172 original admission/protection namespace changed",
    )
}
fn identity172(p: &Value, original: &Value, paths: &Value, birth: &Value, start: u64) -> R<()> {
    owner(original, &birth["native"])?;
    need(
        start == n(p, "original_start_unix_seconds")? && *paths == exact(p, birth)?,
        "original172 identity/clock/copied worker changed",
    )
}
fn first172(
    p: &Value,
    original: &Value,
    first: &Value,
    sample: &Value,
    protection: &Value,
) -> R<()> {
    let start = n(p, "original_start_unix_seconds")?;
    owner(&first["actual_producer"], original)?;
    need(
        sample["producer_invocation_id"] == p["invocation_id"]
            && sample["guard_sha256"] == GUARD
            && sample["guard_invocation_id"] == first["guard_service"]["InvocationID"]
            && sample["plan_sha256"] == protection["plan"]["sha256"]
            && first["receipt"] == protection["first_guard_sample"]
            && sample["producer_stop_enabled"] == true
            && sample.get("trip_reason") == Some(&Value::Null)
            && sample.get("worker_observation_error") == Some(&Value::Null)
            && sample.get("root_physical_observation_error") == Some(&Value::Null)
            && n(sample, "recorded_unix_seconds")? >= start
            && n(sample, "recorded_unix_seconds")?
                <= start
                    .checked_add(25)
                    .ok_or("172 first guard clock overflow")?
            && first["guard_service"]["Result"] == "success"
            && first["guard_service"]["ExecMainStatus"] == "0"
            && first["guard_service"]["MainPID"] == "0"
            && first["guard_service"]["ControlPID"] == "0"
            && first["guard_service"]["ActiveState"] == "inactive"
            && first["guard_service"]["Job"] == ""
            && first["guard_service"]["Id"] == protection["guard_unit"]
            && first["guard_service"]["TriggeredBy"] == protection["timer_unit"]
            && first["timer"]["Id"] == protection["timer_unit"]
            && first["timer"]["Triggers"] == protection["guard_unit"]
            && first["timer"]["InvocationID"] == protection["timer_invocation_id"]
            && first["timer"]["ActiveState"] == "active"
            && first["genuine_first_timer_driven_success"] == true,
        "original172 first25s timer guard differs",
    )?;
    need(
        first["journal"].as_array().is_some_and(|rows| {
            rows.iter().any(|r| {
                r["_PID"] == "1"
                    && r["UNIT"] == protection["guard_unit"]
                    && r["INVOCATION_ID"] == first["guard_service"]["InvocationID"]
                    && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            })
        }),
        "172 first guard genuine PID1 completion required",
    )
}
fn launch172(p: &Value, result: &Value) -> R<()> {
    let rows = result["protected"]
        .as_array()
        .ok_or("172 protected launch rows")?;
    need(
        rows.len() == 1
            && rows[0]["epoch"] == 172
            && rows[0]["invocation_id"] == p["invocation_id"]
            && rows[0]["pid"] == p["main_pid"]
            && rows[0]["transaction_replay_claimed"] == false
            && rows[0]["first_guard"] == p["first_guard"]
            && rows[0]["admission"] == p["admission"]
            && rows[0]["protection"] == p["protection"]
            && result["failed"].as_array().is_some_and(Vec::is_empty),
        "original172 genuine guarded launch result differs",
    )
}
pub(super) fn package172_worker() -> R<Value> {
    let p = profile()?;
    let package = Path::new(PACKAGE);
    need(
        bound(&package.join("deployment-seal-receipt.json"))? == p["package_deployment_seal"],
        "172 original package seal differs",
    )?;
    let mut proof = package_worker_image(
        &package.join("jetstreamer-historical-worker-v1-5-6"),
        WORKER,
    )?;
    proof["package_deployment_seal"] = p["package_deployment_seal"].clone();
    Ok(proof)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn birth(p: &Value) -> Value {
        json!({"native":{"Id":UNIT,"InvocationID":p["invocation_id"],"MainPID":"1213582","ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running","Job":"","ExecMainStartTimestamp":p["original_start_native"],"WorkingDirectory":PACKAGE,"ControlGroup":format!("/system.slice/{UNIT}")},"run_directory":p["run_directory"],"scratch_path":Path::new(s(p,"run_directory").unwrap()).join("scratch"),"launch":p["launch"],"no_transaction_replay_claimed":true})
    }
    fn first_fixture(p: &Value) -> (Value, Value, Value) {
        let guard = "horizon-guard-replacement-172-local2-20261110-v1.service";
        let timer = "horizon-guard-replacement-172-local2-20261110-v1.timer";
        let iid = "f".repeat(32);
        let receipt = json!({"path":"/retained/synthetic-sample.json","sha256":"c".repeat(64)});
        let protection = json!({"guard_unit":guard,"timer_unit":timer,"timer_invocation_id":"e".repeat(32),"first_guard_sample":receipt,"plan":{"sha256":"d".repeat(64)}});
        let sample = json!({"producer_invocation_id":p["invocation_id"],"guard_sha256":GUARD,"guard_invocation_id":iid,"plan_sha256":protection["plan"]["sha256"],"producer_stop_enabled":true,"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"recorded_unix_seconds":1794350308});
        let first = json!({"receipt":receipt,"actual_producer":birth(p)["native"],"guard_service":{"Id":guard,"InvocationID":iid,"Result":"success","ExecMainStatus":"0","MainPID":"0","ControlPID":"0","ActiveState":"inactive","Job":"","TriggeredBy":timer},"timer":{"Id":timer,"Triggers":guard,"InvocationID":protection["timer_invocation_id"],"ActiveState":"active"},"genuine_first_timer_driven_success":true,"journal":[{"_PID":"1","UNIT":guard,"INVOCATION_ID":iid,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"}]});
        (first, sample, protection)
    }
    #[test]
    fn first172_needs_original_sha_real_timer_and_original25second_clock() {
        let p = profile().unwrap();
        let b = birth(&p);
        let (first, sample, protection) = first_fixture(&p);
        first172(&p, &b["native"], &first, &sample, &protection).unwrap();
        for (key, value) in [
            ("guard_sha256", json!("b".repeat(64))),
            ("recorded_unix_seconds", json!(1794350309)),
            ("producer_stop_enabled", json!(false)),
            ("trip_reason", json!("trip")),
            ("worker_observation_error", json!("error")),
            ("root_physical_observation_error", json!("error")),
        ] {
            let mut changed = sample.clone();
            changed[key] = value;
            assert!(
                first172(&p, &b["native"], &first, &changed, &protection).is_err(),
                "{key}"
            );
        }
        let mut changed = sample.clone();
        changed.as_object_mut().unwrap().remove("trip_reason");
        assert!(first172(&p, &b["native"], &first, &changed, &protection).is_err());
    }
    #[test]
    fn first172_cannot_substitute_pid1_timer_plan_or_same_owner_proof() {
        let p = profile().unwrap();
        let b = birth(&p);
        let (first, sample, protection) = first_fixture(&p);
        for pointer in [
            "/guard_service/TriggeredBy",
            "/guard_service/InvocationID",
            "/timer/InvocationID",
            "/actual_producer/InvocationID",
            "/receipt/sha256",
            "/journal/0/_PID",
        ] {
            let mut changed = first.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(
                first172(&p, &b["native"], &changed, &sample, &protection).is_err(),
                "{pointer}"
            );
        }
        let mut changed = sample.clone();
        changed["plan_sha256"] = json!("a".repeat(64));
        assert!(first172(&p, &b["native"], &first, &changed, &protection).is_err());
    }
    #[test]
    fn actual172_birth_registers_original_clock_path_and_aluirm_worker() {
        let p = profile().unwrap();
        let b = birth(&p);
        let paths = exact(&p, &b).unwrap();
        identity172(&p, &b["native"], &paths, &b, 1794350283).unwrap();
        assert!(s(&paths,"worker_executable").unwrap().ends_with("/scratch/.historical-runtime/jetstreamer-historical-parent-aluIrm/bound-worker/historical-worker"));
        assert_eq!(
            paths["birth_binding"]["sha256"],
            "3a8bcfa2890c788124a24aac9b5d8c9403e8bbd67061892d2ceb54c93b81682e"
        );
    }
    #[test]
    fn mutated172_original_identity_date_run_or_launch_is_rejected() {
        let p = profile().unwrap();
        let b = birth(&p);
        for pointer in [
            "/native/InvocationID",
            "/native/MainPID",
            "/native/ExecMainStartTimestamp",
            "/native/WorkingDirectory",
            "/native/ControlGroup",
            "/native/NRestarts",
            "/run_directory",
            "/scratch_path",
            "/launch/sha256",
        ] {
            let mut changed = b.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(exact(&p, &changed).is_err(), "{pointer}");
        }
    }
    #[test]
    fn actual172_paths_and_bootstrap_clock_cannot_be_substituted() {
        let p = profile().unwrap();
        let b = birth(&p);
        let paths = exact(&p, &b).unwrap();
        for key in [
            "worker_executable",
            "scratch_path",
            "archive_path",
            "run_directory",
            "birth_binding",
        ] {
            let mut changed = paths.clone();
            changed[key] = json!("substitute");
            assert!(
                identity172(&p, &b["native"], &changed, &b, 1794350283).is_err(),
                "{key}"
            );
        }
        assert!(identity172(&p, &b["native"], &paths, &b, 1794350284).is_err());
        assert_eq!(
            classify(172, None, false, 1794350283, 1794353883).unwrap(),
            "bootstrap"
        );
        assert!(classify(172, None, false, 1794350283, 1794353884).is_err());
    }
    #[test]
    fn actual172_launch_proof_keeps_first_guard_admission_and_protection() {
        let p = profile().unwrap();
        let result = json!({"protected":[{"epoch":172,"invocation_id":p["invocation_id"],"pid":p["main_pid"],"transaction_replay_claimed":false,"first_guard":p["first_guard"],"admission":p["admission"],"protection":p["protection"]}],"failed":[]});
        launch172(&p, &result).unwrap();
        for key in [
            "epoch",
            "invocation_id",
            "pid",
            "first_guard",
            "admission",
            "protection",
            "transaction_replay_claimed",
        ] {
            let mut changed = result.clone();
            changed["protected"][0][key] = Value::Null;
            assert!(launch172(&p, &changed).is_err(), "{key}");
        }
    }
    #[test]
    fn empty172_registration_cannot_invent_a_birth_clock_or_path() {
        let pending = json!({"schema":"horizon-local2-exact172-native-registration-v1","genuine_native_birth_registered":false});
        assert!(validate_registration(&pending).is_err());
        assert!(exact(&pending, &json!({})).is_err());
    }
    #[test]
    fn seventh_modes_include_actual_owner_set_and_no_duplicate() {
        assert_eq!(epochs_for_mode("capture172").unwrap(), vec![172]);
        assert_eq!(epochs_for_mode("guards172").unwrap(), vec![172]);
        assert_eq!(
            epochs_for_mode("capture7").unwrap(),
            vec![166, 167, 168, 169, 170, 171, 172]
        );
        assert_eq!(
            epochs_for_mode("guards7").unwrap(),
            vec![166, 167, 168, 169, 170, 171, 172]
        );
    }
}
