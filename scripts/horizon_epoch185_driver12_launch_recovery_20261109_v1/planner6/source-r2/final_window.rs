//! Pure finite-sequence contract, not an executor or native acceptance producer.
//! Root's real native/helper receipts remain mandatory; no generic command runner.
use crate::storage::Bound;
use anyhow::{Result, ensure};
use serde_json::{Value,json};

/// Validate the ORIGINAL release clocks, including actual main entry. Moving
/// evidence or sealing a new view never renews a receipt's original sample.
pub fn release_window(ready:u64,deadline:u64,receipts:[u64;4],guard:u64,
    issued:u64,expires:u64,main_entry:u64)->Result<()>{
    ensure!(deadline.checked_sub(ready)==Some(600),"positive setup must be original600seconds");
    ensure!(ready<=guard&&guard<=issued&&issued<=main_entry&&main_entry<expires&&expires<=deadline,
        "positive first-fire/token/main-entry chronology or original deadline");
    ensure!(main_entry-guard<=30,"genuine guard proof stale at original main entry");
    for sampled in receipts{
        ensure!(ready<=sampled&&sampled<=issued&&main_entry-sampled<=30,
            "original task/status/fleet/reader receipt stale or future at main entry");
    }
    Ok(())
}
pub fn source_sequence(prelaunch_reader:&Bound,native_capture:&Bound,postreader:&Bound)->Value{
    let sealer="/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
    let helper=|route:&str| json!({"program":postreader,"route":route,
        "argv_tail":["<exact-normally-sealed-spec>","--spec-sha256","<exact-spec-sha>","--self-sha256",postreader.sha256],
        "caller_booleans_not_accepted_as_native_proof":true});
    json!({"schema":"epoch185-positive-original600s-finite-sequence-contract-v1",
        "metadata_only":true,"executor_implemented":false,"native_calls_performed":0,
        "raw_execution_outcomes_copied":false,"original_setup_seconds":600,
        "prelaunch_reader":prelaunch_reader,"native_capture":native_capture,"post_enrollment_reader":postreader,
        "late_bindings_before_activation":["fresh Root resource/admission acceptance","distinct absent positive namespace",
            "original admission issue/expiry","normal evidence/envelope/unit seals",
            "current full reader and exact closedQA/normal6GiB ledger","complete final execution/capture recipe"],
        "stages":[
            {"stage":"actual_ready_and_task","program":native_capture,
                "route":"capture-cold185-startpre-task","requires":"actual original ready event,IID,ControlPID,start_ticks; no reset"},
            {"stage":"enrollment","operation":helper("enroll-cold185-startpre")},
            {"stage":"actual_enrolled_fleet","operation":{"program":postreader,"route":"fleet-reconcile",
                "argv_tail":["<exact-fleet-plan>","--plan-sha256","<exact-plan-sha>"]}},
            {"stage":"full_original_reader","operation":helper("read-failed4-current-accounting"),
                "requires":"same new qualified image, exact enrolled tuple and disjoint observer-IID output namespace"},
            {"stage":"original_reader_drain_and_normal_completion_seal",
                "requires":"real PID1 success, original outer reaped,cgroup/descriptors drained,four emitted original families",
                "sealer":sealer,"no_synthetic_completion":true},
            {"stage":"fresh_fleet_acceptance_after_long_reader","operation":helper("prove-cold185-fleet")},
            {"stage":"fresh_current_reader_acceptance","operation":helper("prove-cold185-current-reader")},
            {"stage":"fresh_task_acknowledgment","operation":helper("prove-cold185-task-status"),"spec_kind":"task_acknowledgment"},
            {"stage":"fresh_status_bridge","operation":helper("prove-cold185-task-status"),"spec_kind":"status_readback"},
            {"stage":"normally_seal_exact_four_underlying_originals","sealer":sealer,
                "requires":"each exact original source path/hash/length,0444 copy; retained original untouched"},
            {"stage":"four_readable_evidence_validations","operation":helper("prove-cold185-readable-evidence"),
                "count":4,"original_receipt_sample_clocks_unchanged":true},
            {"stage":"normally_seal_four_readable_views","sealer":sealer},
            {"stage":"real_sol_capability","requires":"actual actor sandbox reads final four views and every underlying proof"},
            {"stage":"first_genuine_timer_driven_guard","requires":"actual timer fire and actual successful matching guard,no trip; never manual-success substitute"},
            {"stage":"normal_actual_IID_token_seal","sealer":sealer,
                "requires":"exact four final views,real first guard,original ready/IID/admission,expiry within original setup"},
            {"stage":"original_main_entry","requires":"natural existing prestart/main continuation; all four ORIGINAL receipts and guard <=30s"}
        ],
        "ready_IID_task_paths_and_all_member_hashes_require_genuine_late_binding":true,
        "all_publication_full_epoch_and_runtime_successor_gates_remain_independent":true,
        "admission_issued":false,"replay_launch_authorized":false,"publication_authorized":false})
}

/// Post-release metadata clock audit only. Existing native lifecycle producer
/// owns native authentication; this route never promotes its own clock check to
/// native/launch authority and never runs a service or updates a token.
pub fn inspect(request:&Bound,program:&Bound)->Result<Value>{
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request{schema:String,original_task:Bound,retained_lifecycle:Bound}
    let s:Request=serde_json::from_value(crate::storage::json(request)?)?;
    ensure!(s.schema=="horizon-epoch185-original-release-clock-inspection-v1","clock inspection scope");
    let task=crate::storage::json(&s.original_task)?;
    let life=crate::storage::json(&s.retained_lifecycle)?;
    ensure!(task["schema"]=="horizon-epoch185-genuine-native-startpre-task-v1"
        && life["schema"]=="horizon-epoch185-native-retained-lifecycle-v2"
        && life["task"]==json!(s.original_task)&&life["actor_invocation_id"]==task["actor_invocation_id"],
        "clock inspection crossed original task/lifecycle");
    let release=&life["release"];let token=&release["token_value"];
    let mut stamps=[0;4];
    for (i,key) in ["task_acknowledgment","status_readback","fleet_enrollment","current_reader_native_acceptance"].iter().enumerate(){
        let binding=crate::storage::bound(&token[*key])?;
        let receipt=crate::storage::json(&binding)?;
        ensure!(receipt["kind"]==*key&&receipt["actor_invocation_id"]==task["actor_invocation_id"],
            "clock inspection crossed receipt kind/IID");
        stamps[i]=crate::storage::n(&receipt,"sampled_at")?;
    }
    release_window(crate::storage::n(&task["ready"],"started_at")?,
        crate::storage::n(&task,"original_setup_deadline_unix_seconds")?,stamps,
        crate::storage::n(&release["first_guard_value"],"sampled_at")?,
        crate::storage::n(token,"issued_at")?,crate::storage::n(token,"expires_at")?,
        crate::storage::n(release,"released_at")?)?;
    Ok(json!({"schema":"horizon-epoch185-original-release-clock-inspection-result-v1",
        "request":request,"program":program,"original_task":s.original_task,"retained_lifecycle":s.retained_lifecycle,
        "original_clocks_consistent":true,"native_authentication_performed":false,
        "replay_launch_authorized":false,"publication_authorized":false}))
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn long_reader_then_fresh_acceptances_can_fit_original600s(){
        release_window(1000,1600,[1120,1121,1118,1119],1123,1124,1150,1126).unwrap();
    }
    #[test] fn acceptance_before96second_reader_is_not_freshened_by_copy_or_seal(){
        assert!(release_window(1000,1600,[1120,1121,1010,1119],1123,1124,1150,1126).is_err());
    }
    #[test] fn token_issued_in_time_but_main_entry_after_freshness_is_rejected(){
        assert!(release_window(1000,1600,[1120;4],1123,1124,1200,1151).is_err());
    }
    #[test] fn neither_expired_token_nor_extended_original_setup_is_accepted(){
        assert!(release_window(1000,1600,[1120;4],1123,1124,1126,1126).is_err());
        assert!(release_window(1000,1601,[1120;4],1123,1124,1150,1126).is_err());
    }
}

#[cfg(test)]
mod helper34_sequence_role_regression {
    use super::*;
    #[test]
    fn sequence_keeps_prelaunch13_separate_and_uses_selected_helper_for_every_downstream_stage() {
        let prelaunch = Bound { path: "/usr/local/lib/jetstreamer/horizon-first-lane-combined-witness-terminal145-helper-tools-20261107-v13/jetstreamer-r2".into(), sha256: "d00ee6ad4076c32b90a416efc9236208cd7ee8b64e572d5ad830c9a709eac470".into() };
        let helper = Bound { path: crate::lineage::DRIVER11_NATIVE_PATH.into(), sha256: crate::lineage::DRIVER11_NATIVE_SHA.into() };
        let contract = source_sequence(&prelaunch, &helper, &helper);
        assert_eq!(contract["prelaunch_reader"], json!(prelaunch));
        assert_eq!(contract["post_enrollment_reader"], json!(helper));
        assert_eq!(contract["native_capture"], json!(helper));
        assert_eq!(contract["stages"][0]["program"], json!(helper));
        for stage in contract["stages"].as_array().unwrap() {
            if let Some(operation) = stage.get("operation") {
                assert_eq!(operation["program"], json!(helper), "{}", stage["stage"]);
                assert_ne!(operation["program"], json!(prelaunch));
            }
        }
        assert_eq!(contract["executor_implemented"], false);
        assert_eq!(contract["native_calls_performed"], 0);
        assert_eq!(contract["admission_issued"], false);
        assert_eq!(contract["replay_launch_authorized"], false);
        assert_eq!(contract["publication_authorized"], false);
        assert!(!contract.to_string().contains("0f1d171bc9fee7a1d06186e62b03e601d575bdcacfa30545cf0c084850f0934c"));
    }
}

#[cfg(test)] mod helper35_current_sequence_regression {
 use super::*;
 #[test] fn actual_helper35_is_used_for_all_downstream_stages_prelaunch13_remains_separate() {
  let prelaunch=Bound{path:"/usr/local/lib/jetstreamer/horizon-first-lane-combined-witness-terminal145-helper-tools-20261107-v13/jetstreamer-r2".into(),sha256:"d00ee6ad4076c32b90a416efc9236208cd7ee8b64e572d5ad830c9a709eac470".into()};
  let current=Bound{path:crate::lineage::DRIVER12_NATIVE_PATH.into(),sha256:crate::lineage::DRIVER12_NATIVE_SHA.into()};
  let sequence=source_sequence(&prelaunch,&current,&current);
  assert_eq!(sequence["prelaunch_reader"],json!(prelaunch));assert_eq!(sequence["native_capture"],json!(current));assert_eq!(sequence["post_enrollment_reader"],json!(current));
  for stage in sequence["stages"].as_array().unwrap(){if let Some(operation)=stage.get("operation"){assert_eq!(operation["program"],json!(current));assert_ne!(operation["program"],json!(prelaunch));}}
  assert_eq!(sequence["stages"][0]["program"],json!(current));
  for flag in ["executor_implemented","admission_issued","replay_launch_authorized","publication_authorized"]{assert_eq!(sequence[flag],false);}
  assert_eq!(sequence["native_calls_performed"],0);
 }
}
