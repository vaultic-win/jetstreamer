//! Historical successful verifier proof; never a replacement live admission.
use super::*;
fn terminal(current: &Value, launched: &Value) -> Result<()> {
    ensure!(
        current["Id"] == UNIT
            && current["ActiveState"] == "active"
            && current["SubState"] == "exited"
            && current["MainPID"] == "0"
            && current["InvocationID"] == launched["invocation_id"]
            && current["NRestarts"] == "0"
            && current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && current["ExecStart"]
                .as_str()
                .and_then(|s| s.split_once(" ; ignore_errors="))
                .is_some_and(|(s, _)| s == command()),
        "144 verifier is not the exact clean terminal invocation"
    );
    Ok(())
}
fn validation(r: &Value) -> Result<()> {
    ensure!(
        r["schema"] == "jetstreamer-focused-qualification-artifact-validation-v1"
            && r["validation"] == "pass"
            && r["epoch"] == 144
            && r["archive"] == ARCHIVE
            && r["archive_bytes"] == 109159726722u64
            && r["archive_sha256"] == ARCHIVE_SHA
            && r["bootstrap_slot"] == 62207522
            && r["output_slot_start"] == 62208000
            && r["output_slot_count"] == 431491
            && r["terminal_slot"] == 62639490
            && r["runtime_profile"] == "solana-v1.4.25"
            && r["worker_executable_sha256"]
                == "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"
            && r["canonical_checksum_sidecar_absent"] == true,
        "144 independent prefix validation differs"
    );
    Ok(())
}
pub(super) fn capture(s: &Spec, lb: &BoundFile, r: &Value, c: &DiagnosticClaim) -> Result<()> {
    launch(r, c)?;
    let current = unit(UNIT)?;
    terminal(&current, r)?;
    let vb = BoundFile {
        path: Path::new(ROOT).join("epoch-144-prefix.validation.json"),
        sha256: "35b52ea28979dc8bc360afde41b1b71059a8451c801b71e65ebeac458c59f044".into(),
    };
    validation(&bound_json(&vb)?)?;
    // Admission history is retained as history, not refreshed or relabeled.
    let ab: BoundFile = serde_json::from_value(r["admission_evidence"].clone())?;
    let a = bound_json(&ab)?;
    ensure!(
        a["schema"] == "jetstreamer-private-prefix144-admission-v1"
            && a["decision"] == "pass"
            && a["observer"] == r["observer"]
            && a["previous_fleet"] == r["previous_fleet"]
            && a["replay_launch_authorized"] == false
            && a["publication_authorized"] == false,
        "144 historical admission differs"
    );
    ensure!(
        unit(UNIT)? == current,
        "144 terminal owner changed during capture"
    );
    let path = Path::new(ROOT).join("completed.json");
    immutable_receipt(
        &path,
        &json!({"schema":"jetstreamer-private-epoch144-completed-prefix-proof-v1","epoch":144,"unit":UNIT,"launch":binding(lb),"validation":binding(&vb),"terminal_unit":current,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"new_resource_samples":0,"archive_rehash_performed":false,"prior_admission_event_accepted":false,"ordinary_replay_claim":false,"full_epoch_verified":false,"replay_launch_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let spec = s.stage.join("completed-routine-spec.json");
    persist(
        &spec,
        &json!({"schema":"jetstreamer-horizon-private-completed144-routine-spec-v1","proof":file_binding(&path)?,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let sb = file_binding(&spec)?;
    let seal = s.stage.join("completed-spec-seal-plan.json");
    persist(
        &seal,
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":"/usr/local/lib/jetstreamer/horizon-prefix144-completed-inputs-20261021-v1","members":[{"source":spec,"name":"spec.json","sha256":sb["sha256"],"mode":256}]}),
    )?;
    println!(
        "{}",
        json!({"proof":file_binding(&path)?,"routine_spec":sb,"seal_plan":file_binding(&seal)?})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_proof_rejects_live_restarted_or_different_command() {
        let r = json!({"invocation_id":"a".repeat(32)});
        let good = json!({"Id":UNIT,"ActiveState":"active","SubState":"exited","MainPID":"0","InvocationID":"a".repeat(32),"NRestarts":"0","Result":"success","ExecMainStatus":"0","ExecStart":format!("{} ; ignore_errors=no",command())});
        terminal(&good, &r).unwrap();
        for key in [
            "Id",
            "ActiveState",
            "SubState",
            "MainPID",
            "InvocationID",
            "NRestarts",
            "Result",
            "ExecMainStatus",
            "ExecStart",
        ] {
            let mut bad = good.clone();
            bad[key] = json!("different");
            assert!(terminal(&bad, &r).is_err(), "accepted{key}");
        }
    }
}
