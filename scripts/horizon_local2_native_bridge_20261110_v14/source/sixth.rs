//! Exact epoch171 original birth; all identities come from retained native evidence.
use super::*;
pub(super) const BATCH171: &str = "/var/lib/jetstreamer/cached-standard-input-qualification-20261110-v1/actual-next171-local2-launch-v1";
pub(super) const START171: u64 = 1794348592;
const IID171: &str = "9b33770ea58a4622b55a5e6e5165eaa5";
const PID171: u64 = 1177103;
const UNIT171: &str = "horizon-qualify-171-replacement-local2-20261110-v1.service";
const NATIVE_START171: &str = "Tue 2026-11-10 22:09:52 UTC";
const BIRTH171: &str = "/home/sol/.jetstreamer-private/visible-primary-next-observer-223022-six-local2-20261110-v1/NEW171_BIRTH_BINDING.json";
const BIRTH171_SHA: &str = "7745ae0822498f3959f50f5304ea378ccb9323a103f1908d37821b4ae9134394";
const FIRST171_SHA: &str = "e2c524922d8df995ed1fde501515986e3ab04e46b69a9b644d954e07c392181d";
const ADMISSION171_SHA: &str = "5df2e07c93cb2df7c05b473dcf20d5c80280f6dd324176fc991d97528460a8d1";
const PROTECTION171_SHA: &str = "79689f69bd789c1addc8fecc6202b61daf56de4a06f21d95f95b1b7ba881f167";
const PACKAGE171: &str =
    "/usr/local/lib/jetstreamer/horizon-independent171-singleton-package-20261110-v1";
const PACKAGE171_SEAL_SHA: &str =
    "a0b39e58bb539d03bcbbfd4835f926219f59186809b2106658836128410cc7e4";
const RUN171: &str = "/home/sol/.jetstreamer-private/epoch171-standard-lane-20261110-v1/replacement-local2-20261110-v1/private/destination-821b340b1d732f265a638485ca2929d52a5db49f9619afa26f52525047dc2ccf/work/root-cohort-171-171/run-1177103-1794348596212437206";
const WORKER_REL171: &str = "scratch/.historical-runtime/jetstreamer-historical-parent-CjASLa/bound-worker/historical-worker";

fn birth171() -> R<Value> {
    hash_bound(&json!({"path":BIRTH171,"sha256":BIRTH171_SHA}))
}
fn paths_from_birth(birth: &Value) -> R<Value> {
    let native = &birth["native"];
    let run = Path::new(RUN171);
    need(
        native["Id"] == UNIT171
            && native["InvocationID"] == IID171
            && native["MainPID"] == "1177103"
            && native["ExecMainStartTimestamp"] == NATIVE_START171
            && native["WorkingDirectory"] == PACKAGE171
            && native["ControlGroup"] == format!("/system.slice/{UNIT171}")
            && birth["run_directory"] == RUN171
            && birth["scratch_path"] == json!(run.join("scratch"))
            && birth["no_transaction_replay_claimed"] == true,
        "exact171 original birth identity/path/date required",
    )?;
    owner(native, native)?;
    Ok(json!({
        "producer_invocation_id":IID171,
        "run_directory":run,
        "scratch_path":run.join("scratch"),
        "archive_path":run.join("archives/epoch-171.jet"),
        "worker_executable":run.join(WORKER_REL171),
        "birth_binding":{"path":BIRTH171,"sha256":BIRTH171_SHA}
    }))
}
pub(super) fn paths171() -> R<Value> {
    paths_from_birth(&birth171()?)
}
fn validate_identity(original: &Value, paths: &Value, birth: &Value, start: u64) -> R<()> {
    let expected = paths_from_birth(birth)?;
    owner(original, &birth["native"])?;
    need(
        start == START171 && *paths == expected,
        "exact171 native/path/copied-worker/start binding",
    )
}
fn first171(first: &Value, sample: &Value) -> R<()> {
    let guard_unit = "horizon-guard-replacement-171-local2-20261110-v1.service";
    let timer_unit = "horizon-guard-replacement-171-local2-20261110-v1.timer";
    need(
        sample["producer_invocation_id"] == IID171
            && sample["guard_sha256"] == GUARD
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && n(sample, "recorded_unix_seconds")? >= START171
            && n(sample, "recorded_unix_seconds")? <= START171 + 25
            && first["guard_service"]["Id"] == guard_unit
            && first["guard_service"]["Result"] == "success"
            && first["guard_service"]["ExecMainStatus"] == "0"
            && first["guard_service"]["TriggeredBy"] == timer_unit
            && first["timer"]["Id"] == timer_unit
            && first["timer"]["Triggers"] == guard_unit
            && first["genuine_first_timer_driven_success"] == true,
        "genuine original171 first timer guard within25seconds required",
    )
}
fn launch_result(result: &Value, first: &Value, admission: &Value, protection: &Value) -> R<()> {
    let rows = result["protected"]
        .as_array()
        .ok_or("171 protected launch rows")?;
    need(
        rows.len() == 1
            && rows[0]["epoch"] == 171
            && rows[0]["invocation_id"] == IID171
            && rows[0]["pid"] == PID171
            && rows[0]["transaction_replay_claimed"] == false
            && rows[0]["first_guard"] == *first
            && rows[0]["admission"] == *admission
            && rows[0]["protection"] == *protection
            && admission["sha256"] == ADMISSION171_SHA
            && protection["sha256"] == PROTECTION171_SHA
            && result["failed"].as_array().is_some_and(Vec::is_empty),
        "original genuine171 guarded launch result",
    )
}
pub(super) fn validate171_original(original: &Value, paths: &Value, start: u64) -> R<()> {
    let birth = birth171()?;
    validate_identity(original, paths, &birth, start)?;
    let batch = Path::new(BATCH171).join("epoch171");
    let first = bound(&batch.join("GENUINE_FIRST_GUARD_PID1_TIMER_PROOF.json"))?;
    need(
        first["sha256"] == FIRST171_SHA,
        "original171 first proof changed",
    )?;
    let proof = hash_bound(&first)?;
    first171(&proof, &hash_bound(&proof["receipt"])?)?;
    launch_result(
        &hash_bound(&birth["launch"])?,
        &first,
        &bound(&batch.join("ACTUAL_REPLACEMENT_ADMISSION.json"))?,
        &bound(&batch.join("ACTUAL_GUARD_PROTECTION.json"))?,
    )
}
pub(super) fn package171_worker(e: u64) -> R<Value> {
    need(e == 171, "only bootstrap171 package-worker route")?;
    let package = Path::new(PACKAGE171);
    let seal = bound(&package.join("deployment-seal-receipt.json"))?;
    need(
        seal["sha256"] == PACKAGE171_SEAL_SHA,
        "original171 package seal changed",
    )?;
    let mut proof = package_worker_image(
        &package.join("jetstreamer-historical-worker-v1-5-6"),
        WORKER,
    )?;
    proof["package_deployment_seal"] = seal;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn birth() -> Value {
        json!({"native":{"Id":UNIT171,"InvocationID":IID171,"MainPID":PID171.to_string(),"ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running","ExecMainStartTimestamp":NATIVE_START171,"ControlGroup":format!("/system.slice/{UNIT171}"),"Job":"","WorkingDirectory":PACKAGE171},"run_directory":RUN171,"scratch_path":Path::new(RUN171).join("scratch"),"no_transaction_replay_claimed":true})
    }
    fn first() -> (Value, Value) {
        (
            json!({"guard_service":{"Id":"horizon-guard-replacement-171-local2-20261110-v1.service","Result":"success","ExecMainStatus":"0","TriggeredBy":"horizon-guard-replacement-171-local2-20261110-v1.timer"},"timer":{"Id":"horizon-guard-replacement-171-local2-20261110-v1.timer","Triggers":"horizon-guard-replacement-171-local2-20261110-v1.service"},"genuine_first_timer_driven_success":true}),
            json!({"producer_invocation_id":IID171,"guard_sha256":GUARD,"producer_stop_enabled":true,"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"recorded_unix_seconds":START171+25}),
        )
    }
    #[test]
    fn original171_birth_and_copied_worker_are_bound_to_actual_nov10_run() {
        let birth = birth();
        let paths = paths_from_birth(&birth).unwrap();
        validate_identity(&birth["native"], &paths, &birth, START171).unwrap();
        assert_eq!(
            paths["worker_executable"],
            json!(Path::new(RUN171).join(WORKER_REL171))
        );
        assert_eq!(
            paths["archive_path"],
            json!(Path::new(RUN171).join("archives/epoch-171.jet"))
        );
        assert_eq!(paths["birth_binding"]["sha256"], BIRTH171_SHA);
    }
    #[test]
    fn mutated171_birth_identity_and_old_package_date_fail() {
        for (key, value) in [
            ("InvocationID", json!(IID170)),
            ("MainPID", json!("1177104")),
            (
                "ExecMainStartTimestamp",
                json!("Tue 2026-11-10 22:10:52 UTC"),
            ),
            (
                "WorkingDirectory",
                json!(
                    "/usr/local/lib/jetstreamer/horizon-independent171-singleton-package-20261109-v1"
                ),
            ),
            ("ControlGroup", json!("/system.slice/other.service")),
            ("NRestarts", json!("1")),
        ] {
            let mut b = birth();
            b["native"][key] = value;
            assert!(paths_from_birth(&b).is_err());
        }
        let mut b = birth();
        b["run_directory"] = json!(format!("{RUN171}-substitute"));
        assert!(paths_from_birth(&b).is_err());
    }
    #[test]
    fn wrong171_scratch_archive_or_worker_cannot_use_birth_binding() {
        let b = birth();
        let original = &b["native"];
        for key in [
            "scratch_path",
            "archive_path",
            "worker_executable",
            "birth_binding",
        ] {
            let mut paths = paths_from_birth(&b).unwrap();
            paths[key] = json!("substitute");
            assert!(validate_identity(original, &paths, &b, START171).is_err());
        }
        let paths = paths_from_birth(&b).unwrap();
        assert!(validate_identity(original, &paths, &b, START171 + 1).is_err());
    }
    #[test]
    fn absent171_worker_and_null_progress_only_use_original_bootstrap_hour() {
        assert_eq!(
            classify(171, None, false, START171, START171 + 3600).unwrap(),
            "bootstrap"
        );
        assert!(classify(171, None, false, START171, START171 + 3601).is_err());
        assert!(classify(171, None, false, START171 + 1, START171 + 2).is_err());
        assert!(classify(171, None, false, START171, START171 - 1).is_err());
    }
    #[test]
    fn replay171_requires_real_worker_positive_target_and_current_clock() {
        let p = json!({"epoch":171,"transactions":1,"recorded_unix_seconds":START171+5});
        assert_eq!(
            classify(171, Some(&p), true, START171, START171 + 6).unwrap(),
            "replay"
        );
        assert!(classify(171, Some(&p), false, START171, START171 + 6).is_err());
        for (key, value) in [
            ("epoch", json!(170)),
            ("transactions", json!(0)),
            ("recorded_unix_seconds", json!(START171 - 1)),
            ("recorded_unix_seconds", json!(START171 + 7)),
        ] {
            let mut bad = p.clone();
            bad[key] = value;
            assert!(classify(171, Some(&bad), true, START171, START171 + 6).is_err());
        }
    }
    #[test]
    fn exact171_terminal_range_is_required_for_progress() {
        let good =
            "[2026-11-10T22:10:02Z INFO x] progress slot 73872001/74303999 (0%) txs=2 accounts=3";
        assert_eq!(progress(good, 171).unwrap().unwrap()["transactions"], 2);
        assert!(progress(&good.replace("74303999", "74304000"), 171).is_err());
        assert!(progress(&good.replace("73872001", "73871999"), 171).is_err());
        assert!(
            progress(&good.replace("progress slot", "warmup slot"), 171)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn first171_guard_keeps_original_25second_boundary_and_timer() {
        let (f, s) = first();
        first171(&f, &s).unwrap();
        for at in [START171 - 1, START171 + 26] {
            let mut bad = s.clone();
            bad["recorded_unix_seconds"] = json!(at);
            assert!(first171(&f, &bad).is_err());
        }
        for (key, value) in [
            ("producer_invocation_id", json!(IID170)),
            ("producer_stop_enabled", json!(false)),
            ("trip_reason", json!("floor")),
            ("worker_observation_error", json!("error")),
            ("root_physical_observation_error", json!("error")),
        ] {
            let mut bad = s.clone();
            bad[key] = value;
            assert!(first171(&f, &bad).is_err());
        }
        let mut bad = f.clone();
        bad["timer"]["Id"] = json!("foreign.timer");
        assert!(first171(&bad, &s).is_err());
    }
    #[test]
    fn exact171_launch_result_rejects_rebound_proofs_and_replay_claims() {
        let first = json!({"path":"first","sha256":FIRST171_SHA});
        let admission = json!({"path":"admission","sha256":ADMISSION171_SHA});
        let protection = json!({"path":"protection","sha256":PROTECTION171_SHA});
        let result = json!({"protected":[{"epoch":171,"invocation_id":IID171,"pid":PID171,"transaction_replay_claimed":false,"first_guard":first,"admission":admission,"protection":protection}],"failed":[]});
        launch_result(&result, &first, &admission, &protection).unwrap();
        for (key, value) in [
            ("epoch", json!(170)),
            ("invocation_id", json!(IID170)),
            ("pid", json!(PID171 + 1)),
            ("transaction_replay_claimed", json!(true)),
            ("first_guard", json!({"path":"other","sha256":FIRST171_SHA})),
        ] {
            let mut bad = result.clone();
            bad["protected"][0][key] = value;
            assert!(launch_result(&bad, &first, &admission, &protection).is_err());
        }
        let mut bad = result.clone();
        bad["failed"] = json!([{"epoch":171}]);
        assert!(launch_result(&bad, &first, &admission, &protection).is_err());
    }
    #[test]
    fn all_old_modes_and_exact_six_owner_modes_remain_supported() {
        for (mode, expected) in [
            ("capture", vec![166, 167, 168]),
            ("guards", vec![166, 167, 168]),
            ("capture169", vec![169]),
            ("guards169", vec![169]),
            ("capture170", vec![170]),
            ("guards170", vec![170]),
            ("capture4", vec![166, 167, 168, 169]),
            ("guards4", vec![166, 167, 168, 169]),
            ("capture5", vec![166, 167, 168, 169, 170]),
            ("guards5", vec![166, 167, 168, 169, 170]),
            ("capture171", vec![171]),
            ("guards171", vec![171]),
            ("capture6", vec![166, 167, 168, 169, 170, 171]),
            ("guards6", vec![166, 167, 168, 169, 170, 171]),
        ] {
            assert_eq!(epochs_for_mode(mode).unwrap(), expected);
        }
        assert!(epochs_for_mode("capture8").is_err());
        assert!(epochs_for_mode("guards173").is_err());
    }
    #[test]
    fn epoch171_dates_do_not_rewrite_original_five_paths() {
        for e in 166..=170 {
            assert!(
                manifest_for(e)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains("20261109-v1")
            );
            assert!(
                log_for(e)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains("standard-lane-20261109-v1")
            );
        }
        assert_eq!(
            manifest_for(171).unwrap(),
            Path::new(PACKAGE171).join("preflight-171-v4.json")
        );
        assert_eq!(
            log_for(171).unwrap(),
            Path::new(
                "/home/sol/.jetstreamer-private/epoch171-standard-lane-20261110-v1/replacement-local2-20261110-v1/producer.log"
            )
        );
        assert!(manifest_for(173).is_err());
        assert!(log_for(173).is_err());
    }
}
