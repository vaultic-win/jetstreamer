//! Native admission is deliberately insufficient: follow the actual finalized
//! outcome, original restore completion and the finalizer's outer lifecycle.
use super::*;
pub(super) const FINALIZER: &str = "horizon-epoch163-native-input-finalize-20261107-v1.service";
const FINALIZER_IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-native163-finalizer-retained-exec-tools-20261108-v2/native-input-finalize";
const FINALIZER_SHA: &str = "fdf4b9a93e5522e6a1dc34ed91f0612197d49970679cd7e8240511b5d603ba03";
const NATIVE_IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-epoch163-native-input-tools-20261106-v7/native-input";
const NATIVE_SHA: &str = "9e9de6bdcb149d08d17cc53ce4322577e4a1aab164a1ac848b04ae8426205850";
const DOWNLOAD_IID: &str = "7e01ca99b80f4f629ff315a19f10b4a1";
/// Created only after original lineage and actual native/finalizer terminal
/// identities pass. Draining does not release either reservation.
pub(super) struct Retained { evidence: Value }
impl Retained {
    pub(super) fn evidence(&self) -> &Value { &self.evidence }
}
fn lineage(inputs: &Value, completion: &Value, outcome: &Value, admission: &Value, finalizer: &Value, acceptance: &Bound) -> Result<()> {
    let iid = completion["invocation_id"].as_str().context("native completion IID")?;
    ensure!(storage::hex(iid, 32)
        && completion["schema"] == "epoch163-native-input-original-completion-v1"
        && completion["unit"] == super::super::native_restore::ACTOR
        && completion["worker_shutdown_and_reap_passed"] == true
        && completion["original_worker_identity_retired"] == true
        && completion["original_capability_actor_drained"] == true
        && completion["original_cgroup_empty"] == true
        && completion["native_outcome"] == inputs["native_outcome"]
        && outcome["schema"] == "epoch163-native-input-outcome-v3"
        && outcome["actor_invocation_id"] == iid
        && outcome["snapshot_integrity_verified"] == true
        && outcome["mapped_worker_image_verified"] == true
        && outcome["source_mounts_read_only"] == true
        && outcome["vma_guards_enforced"] == true
        && outcome["worker_shutdown_acknowledged"] == true
        && outcome["mapped_worker_sha256"] == inputs["mapped_worker_sha256"]
        && outcome["replay_entries_sent"] == 0
        && admission["schema"] == "epoch163-native-input-admission-v2"
        && admission["actor_invocation_id"] == iid
        && admission["program"] == json!({"path":NATIVE_IMAGE,"sha256":NATIVE_SHA})
        && completion["original_program"] == admission["program"]
        && completion["original_admission"] == outcome["admission"]
        && admission["native_restore_only"] == true
        && admission["replay_launch_authorized"] == false
        && admission["publication_authorized"] == false,
        "first128 requires original successful finalized native restore lineage");
    ensure!(finalizer["schema"] == "epoch163-native-input-finalizer-original-lifecycle-v1"
        && finalizer["unit"] == FINALIZER
        && finalizer["program"] == json!({"path":FINALIZER_IMAGE,"sha256":FINALIZER_SHA})
        && finalizer["acceptance"] == json!(acceptance)
        && finalizer["original_completion"] == inputs["original_completion"]
        && finalizer["native_outcome"] == inputs["native_outcome"]
        && finalizer["original_outer_reaped"] == true
        && finalizer["original_cgroup_empty"] == true
        && finalizer["original_descriptors_drained"] == true
        && finalizer["result"] == "success" && finalizer["exec_main_status"] == 0,
        "native finalizer must itself finish, reap and drain before replay capability");
    let j = &finalizer["original_PID1_success_event"];
    ensure!(j["_PID"] == "1" && j["_UID"] == "0" && j["UNIT"] == FINALIZER
        && j["INVOCATION_ID"] == finalizer["invocation_id"]
        && storage::hex(finalizer["invocation_id"].as_str().unwrap_or(""),32)
        && j["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
        && j["MESSAGE"] == format!("{FINALIZER}: Deactivated successfully."),
        "native finalizer original PID1 success");
    Ok(())
}
pub(super) fn validate(acceptance: &Bound, inputs: &Value, finalizer_bound: &Bound) -> Result<Retained> {
    let completion = protected(&to_bound(&inputs["original_completion"])?)?;
    let outcome = protected(&to_bound(&inputs["native_outcome"])?)?;
    let admission = immutable(&to_bound(&outcome["admission"])?)?;
    let finalizer = immutable(finalizer_bound)?;
    lineage(inputs, &completion, &outcome, &admission, &finalizer, acceptance)?;
    ensure!(inputs["schema"] == "epoch163-first-output128-input-capability-v1"
        && inputs["bootstrap_generation"] == 1634787272998262u64
        && inputs["bootstrap_slot"] == 70415741
        && inputs["snapshot_integrity_verified"] == true
        && inputs["original_capability_actor_drained"] == true
        && inputs["mapped_worker_sha256"] == "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819"
        && admission["actor_memory_bytes"] == 128u64<<30
        && admission["candidate_incremental_DATA_bytes"] == 40u64<<30
        && admission["no_raw_memory_or_DATA_release_credit"] == true,
        "first128 retained native charge requires actual fixed128GiB/40GiB admission");
    // Original immutable issuer metadata only; no snapshot/ledger body is read.
    let native_plan = to_bound(&admission["plan"])?;
    let native_phase = to_bound(&admission["resource_phase_ledger"])?;
    ensure!(outcome["plan"] == json!(native_plan), "retained native original plan crossed");
    immutable(&native_plan)?;
    immutable(&native_phase)?;

    artifact(FINALIZER_IMAGE, FINALIZER_SHA)?;
    let download = protected(&to_bound(&admission["download"])?)?;
    ensure!(download["invocation_id"] == DOWNLOAD_IID, "first128 original current downloader IID");
    for (name, iid, substate) in [
        (super::super::native_restore::ACTOR, &completion["invocation_id"], "exited"),
        (FINALIZER, &finalizer["invocation_id"], "dead"),
    ] {
        let native = unit(name)?;
        ensure!(native["Id"] == name && native["InvocationID"] == *iid
            && native["MainPID"] == "0" && native["ControlPID"] == "0"
            && native["ControlGroup"] == "" && native["Job"] == ""
            && native["NRestarts"] == "0" && native["Result"] == "success"
            && native["ExecMainStatus"] == "0" && native["SubState"] == substate,
            "original native/finalizer actor replaced, unfinished or undrained");
    }
    let pid = n(&completion,"original_worker_pid")?;
    let ticks = n(&completion,"original_worker_start_ticks")?;
    ensure!(pid > 1 && ticks > 0, "native original worker identity");
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => ensure!(stat.rsplit_once(") ").context("retired worker stat")?.1.split_whitespace().nth(19).context("retired worker ticks")?.parse::<u64>()? != ticks, "native worker is still live"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(Retained { evidence: json!({"schema":"epoch163-native128-retained-first128-charge-v1",
        "actor_unit":super::super::native_restore::ACTOR,"actor_invocation_id":completion["invocation_id"],
        "input_capability":acceptance,"native_plan":native_plan,"native_phase_ledger":native_phase,
        "native_admission":outcome["admission"],"native_outcome":inputs["native_outcome"],
        "original_completion":inputs["original_completion"],"finalizer_completion":finalizer_bound,
        "memory_bytes":128u64<<30,"DATA_bytes":40u64<<30,
        "charging_scope":"first128-point-of-use-additive-to-unchanged-typed-baseline",
        "memory_credit_bytes":0,"DATA_credit_bytes":0,"physical_credit_bytes":0,"release_authorized":false}) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_admission_and_shutdown_ack_cannot_substitute_for_completed_capability() {
        let b=Bound{path:"/sealed/capability".into(),sha256:"a".repeat(64)};
        let admission=json!({"schema":"epoch163-native-input-admission-v2","admitted":true,"native_restore_only":true});
        assert!(lineage(&admission,&json!({}),&json!({"worker_shutdown_acknowledged":true}),&admission,&json!({}),&b).is_err());
        assert_eq!(DOWNLOAD_IID.len(),32);
    }
}
#[cfg(test)]
mod finalized_lineage_regressions {
    use super::*;
    #[test]
    fn real_capability_requires_matching_outcome_completion_and_finalizer_drains() {
        let acceptance=Bound{path:"/sealed/acceptance".into(),sha256:"a".repeat(64)};
        let cb=json!({"path":"/private/completion","sha256":"b".repeat(64)});
        let ob=json!({"path":"/private/outcome","sha256":"c".repeat(64)});
        let ab=json!({"path":"/private/admission","sha256":"d".repeat(64)});
        let iid="e".repeat(32);
        let fiid="f".repeat(32);
        let program=json!({"path":NATIVE_IMAGE,"sha256":NATIVE_SHA});
        let inputs=json!({"original_completion":cb,"native_outcome":ob,"mapped_worker_sha256":"worker"});
        let completion=json!({"schema":"epoch163-native-input-original-completion-v1","unit":super::super::super::native_restore::ACTOR,"invocation_id":iid,
            "worker_shutdown_and_reap_passed":true,"original_worker_identity_retired":true,"original_capability_actor_drained":true,"original_cgroup_empty":true,
            "native_outcome":ob,"original_program":program,"original_admission":ab});
        let outcome=json!({"schema":"epoch163-native-input-outcome-v3","actor_invocation_id":iid,"snapshot_integrity_verified":true,"mapped_worker_image_verified":true,
            "source_mounts_read_only":true,"vma_guards_enforced":true,"worker_shutdown_acknowledged":true,"mapped_worker_sha256":"worker","replay_entries_sent":0,"admission":ab});
        let admission=json!({"schema":"epoch163-native-input-admission-v2","actor_invocation_id":iid,"program":program,"native_restore_only":true,"replay_launch_authorized":false,"publication_authorized":false});
        let finalizer=json!({"schema":"epoch163-native-input-finalizer-original-lifecycle-v1","unit":FINALIZER,"invocation_id":fiid,"program":{"path":FINALIZER_IMAGE,"sha256":FINALIZER_SHA},
            "acceptance":acceptance,"original_completion":cb,"native_outcome":ob,"original_outer_reaped":true,"original_cgroup_empty":true,"original_descriptors_drained":true,"result":"success","exec_main_status":0,
            "original_PID1_success_event":{"_PID":"1","_UID":"0","UNIT":FINALIZER,"INVOCATION_ID":fiid,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{FINALIZER}: Deactivated successfully.")}});
        lineage(&inputs,&completion,&outcome,&admission,&finalizer,&acceptance).unwrap();
        for field in ["original_outer_reaped","original_cgroup_empty","original_descriptors_drained"] {
            let mut bad=finalizer.clone();bad[field]=json!(false);
            assert!(lineage(&inputs,&completion,&outcome,&admission,&bad,&acceptance).is_err(),"{field}");
        }
        let mut bad=completion.clone();bad["worker_shutdown_and_reap_passed"]=json!(false);
        assert!(lineage(&inputs,&bad,&outcome,&admission,&finalizer,&acceptance).is_err());
        let mut bad=outcome.clone();bad["actor_invocation_id"]=json!("0".repeat(32));
        assert!(lineage(&inputs,&completion,&bad,&admission,&finalizer,&acceptance).is_err());
    }
}
