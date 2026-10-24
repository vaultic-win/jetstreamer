//! Add only the actual guarded canary to an accepted fleet, without a resource poll.
use super::canary227 as c;
use super::*;
fn same_claim(a: &DiagnosticClaim, b: &DiagnosticClaim) -> bool {
    a.epoch == b.epoch
        && a.unit == b.unit
        && a.invocation_id == b.invocation_id
        && a.scratch_path == b.scratch_path
        && a.launch_receipt == b.launch_receipt
}
fn origin_binding(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    ensure!(p.first_epoch==201 && p.last_epoch==300 && p.admission_transition_guard.is_none()
        && previous["schema"]==SCHEMA && previous["sampled_at_utc"]==sampled
        && previous["observer_receipt"].as_str()==p.observer.path.to_str() && previous["observer_sha256"]==p.observer.sha256
        && proof["schema"]==c::SCHEMA && proof["launched"]==true
        && proof["observer"]==private157::binding(&p.observer)
        && p.previous_fleet.as_ref().is_some_and(|f|proof["fleet"]==private157::binding(f))
        && proof["resource_samples_taken"]==0 && proof["bounded_replay_authorized"]==true
        && proof["repair_gate_state"]=="failed-needs-repair" && proof["preserve_original_failed227_history"]==true
        && proof["original_failed_invocation_id"]==c::ORIGINAL_IID
        && ["ordinary_replay_authorized","replay_launch_authorized","full_epoch_qualified","full_cold_epoch_peak_qualified",
            "canonical_prefix_qualified","full_verification_qualified","current_plugin_qualified","runtime_promotion_authorized",
            "canonical_sidecar_authorized","publication_authorized","remote_mutations","r2_mutations"].iter().all(|k|proof[*k]==false),
        "227 canary event cannot replace resource observation, original failure, or qualification gates");
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("227 canary event clock")?;
    ensure!(
        clock
            == utc_seconds(
                proof["sampled_at_utc"]
                    .as_str()
                    .context("227 canary event UTC")?
            )?
            && clock > utc_seconds(sampled)?
            && clock <= now
            && now - clock <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < clock),
        "227 canary event stale/backdated"
    );
    Ok(())
}
fn claim_addition(old: &[DiagnosticClaim], new: &[DiagnosticClaim]) -> Result<()> {
    ensure!(!old.iter().any(c::namespace) && new.len()==old.len()+1
        && new.iter().filter(|d|c::namespace(d)).count()==1
        && old.iter().all(|d|new.iter().filter(|n|same_claim(d,n)).count()==1),
        "227 canary event must add exactly one new diagnostic without changing any historical claim");
    Ok(())
}
fn gate(g: &Gate, n: &Gate, epoch: u64, claim: &DiagnosticClaim) -> Result<()> {
    ensure!(
        g.state == n.state
            && serde_json::to_value(&g.reserve_stop)? == serde_json::to_value(&n.reserve_stop)?
            && g.evidence.iter().all(|e| n.evidence.contains(e)),
        "227 canary event changed preserved gate"
    );
    if epoch == 227 {
        ensure!(g.state=="failed-needs-repair" && n.evidence.contains(&claim.launch_receipt)
            && n.evidence.iter().all(|e|g.evidence.contains(e) || *e==claim.launch_receipt),
            "227 canary event must preserve original failed repair gate and add only captured launch");
    } else {
        ensure!(
            g.next_action == n.next_action && g.evidence == n.evidence,
            "227 canary event changed unrelated gate"
        );
    }
    Ok(())
}
pub(super) fn event_predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    origin_binding(previous, p, proof, sampled, now)?;
    let a = bound_json(&serde_json::from_value(
        proof["fresh_resource_admission"].clone(),
    )?)?;
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("227 event clock")?;
    ensure!(
        a["schema"] == "jetstreamer-private-epoch227-v1625-canary-admission-v1"
            && a["mode"] == "bounded-canary"
            && a["admitted"] == true
            && a["unit"] == c::UNIT
            && a["private_run_root"] == c::ROOT
            && a["candidate_incremental_peak_bytes"] == c::CANDIDATE
            && a["maximum_memory_bytes"] == c::MEMORY
            && a["canary_plan"] == proof["resource_plan"]
            && a["input_capability"] == proof["input_capability"]
            && a["observer"] == proof["observer"]
            && a["fleet"] == proof["fleet"]
            && a["fresh_complete_census_passed"] == true
            && a["older_producers_and_guards_preserved"] == true
            && a["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= clock && clock - n <= 900),
        "227 event lacks exact fresh canary admission"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"]
            .as_str()
            .context("227 previous plan")?
            .into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("227 previous plan SHA")?
            .into(),
    })?)?;
    claim_addition(&old.diagnostics, &p.diagnostics)?;
    let claim = p
        .diagnostics
        .iter()
        .find(|d| c::namespace(d))
        .context("227 new diagnostic absent")?;
    validate_diagnostic_launch(proof, claim)?;
    ensure!(
        c::launch_matches(claim, proof)
            && p.metadata_event.as_ref() == Some(&claim.launch_receipt)
            && bound_json(&claim.launch_receipt)? == *proof,
        "227 metadata event differs from exact actual launch"
    );
    let mut tracked = old.tracked_units.iter().cloned().collect::<BTreeSet<_>>();
    tracked.insert(c::UNIT.into());
    ensure!(
        tracked == p.tracked_units.iter().cloned().collect()
            && p.tracked_units.len() == tracked.len()
            && p.schema == old.schema
            && p.first_epoch == old.first_epoch
            && p.last_epoch == old.last_epoch
            && p.observer == old.observer
            && p.status_receipt_directory == old.status_receipt_directory
            && p.runtime_handoff157 == old.runtime_handoff157
            && p.continuation203_runtime_extension == old.continuation203_runtime_extension
            && p.epoch203_ram_auxiliary.is_none()
            && old.epoch203_ram_auxiliary.is_none()
            && p.pipeline_claims == old.pipeline_claims
            && p.gates.len() == old.gates.len(),
        "227 canary event changed unrelated history/configuration"
    );
    ensure!(
        old.gates.contains_key(&227),
        "227 original failed gate absent"
    );
    for (epoch, g) in &old.gates {
        gate(
            g,
            p.gates.get(epoch).context("227 prior gate omitted")?,
            *epoch,
            claim,
        )?;
    }
    Ok(())
}
pub(super) fn event_census(
    previous: &Value,
    current: &BTreeMap<String, Value>,
    claim: &DiagnosticClaim,
) -> Result<()> {
    ensure!(
        c::namespace(claim)
            && !previous["active"]
                .as_array()
                .context("227 old active census")?
                .iter()
                .any(|r| r["epoch"] == 227),
        "227 canary event overlaps an existing owner"
    );
    let proof = bound_json(&claim.launch_receipt)?;
    validate_diagnostic_launch(&proof, claim)?;
    native210_peer_history::current(previous, current)?;
    prefix223_live_peer::current(previous, current)?;
    let mut view = current.clone();
    let actual = view.remove(c::UNIT).context("227 new canary absent")?;
    singleton227_admission::owners(previous, &view)?;
    let pid = actual["MainPID"]
        .as_str()
        .and_then(|n| n.parse::<u64>().ok());
    ensure!(
        diagnostic_stage_running(&actual)
            && actual["InvocationID"] == claim.invocation_id
            && actual["NRestarts"] == "0"
            && actual["ControlGroup"] == format!("/system.slice/{}", c::UNIT)
            && pid.is_some_and(|n| n > 1)
            && pid == proof["main_pid"].as_u64()
            && c::same_command(&actual["ExecStart"], &proof["expected_exec_start"]),
        "227 actual canary identity changed"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn diagnostic(unit: &str) -> DiagnosticClaim {
        DiagnosticClaim {
            epoch: 227,
            unit: unit.into(),
            invocation_id: "a".repeat(32),
            scratch_path: c::ROOT.into(),
            launch_receipt: BoundFile {
                path: "/captured.json".into(),
                sha256: "b".repeat(64),
            },
        }
    }
    #[test]
    fn addition_preserves_all_historical_diagnostics_including_the_failed_original() {
        let old = vec![diagnostic("original-failed227.service")];
        let new = vec![
            diagnostic("original-failed227.service"),
            diagnostic(c::UNIT),
        ];
        claim_addition(&old, &new).unwrap();
        assert!(claim_addition(&old, &new[1..]).is_err());
        let mut bad = new;
        bad[0].invocation_id = "c".repeat(32);
        assert!(claim_addition(&old, &bad).is_err());
        let old = vec![diagnostic(c::UNIT)];
        let new = vec![diagnostic(c::UNIT), diagnostic(c::UNIT)];
        assert!(claim_addition(&old, &new).is_err());
    }
    #[test]
    fn canary_must_leave_failed_gate_open_with_its_original_evidence() {
        let claim = diagnostic(c::UNIT);
        let binding = BoundFile {
            path: "/original-failure.json".into(),
            sha256: "c".repeat(64),
        };
        let old = Gate {
            state: "failed-needs-repair".into(),
            next_action: "repair".into(),
            evidence: vec![binding.clone()],
            reserve_stop: None,
        };
        let mut new = Gate {
            state: old.state.clone(),
            next_action: "bounded comparison".into(),
            evidence: vec![binding, claim.launch_receipt.clone()],
            reserve_stop: None,
        };
        gate(&old, &new, 227, &claim).unwrap();
        for state in ["blocked-qualification", "live-replay", "remote-ready"] {
            new.state = state.into();
            assert!(gate(&old, &new, 227, &claim).is_err());
        }
        new.state = old.state.clone();
        new.evidence.remove(0);
        assert!(gate(&old, &new, 227, &claim).is_err());
    }
    #[test]
    fn event_does_not_create_new_resource_sample_or_promotion_authority() {
        let observer = json!({"path":"/observer.json","sha256":"a".repeat(64)});
        let predecessor = json!({"path":"/previous.json","sha256":"b".repeat(64)});
        let p:Plan=serde_json::from_value(json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,
            "observer":observer,"previous_fleet":predecessor,"output":"/output.json","status_receipt_directory":"/receipts","gates":{},"tracked_units":[]})).unwrap();
        let sampled = "2026-10-23T18:00:00Z";
        let previous = json!({"schema":SCHEMA,"sampled_at_utc":sampled,"observer_receipt":"/observer.json","observer_sha256":"a".repeat(64),"recorded_unix_seconds":1792778400u64});
        let mut proof = json!({"schema":c::SCHEMA,"launched":true,"observer":observer,"fleet":predecessor,"resource_samples_taken":0,
            "bounded_replay_authorized":true,"repair_gate_state":"failed-needs-repair","preserve_original_failed227_history":true,
            "original_failed_invocation_id":c::ORIGINAL_IID,"recorded_unix_seconds":1792778460u64,"sampled_at_utc":"2026-10-23T18:01:00Z"});
        for k in [
            "ordinary_replay_authorized",
            "replay_launch_authorized",
            "full_epoch_qualified",
            "full_cold_epoch_peak_qualified",
            "canonical_prefix_qualified",
            "full_verification_qualified",
            "current_plugin_qualified",
            "runtime_promotion_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            proof[k] = json!(false);
        }
        origin_binding(&previous, &p, &proof, sampled, 1792778500).unwrap();
        for (key, value) in [
            ("resource_samples_taken", json!(1)),
            ("full_epoch_qualified", json!(true)),
            ("repair_gate_state", json!("repaired")),
            ("recorded_unix_seconds", json!(1792778400u64)),
            ("observer", json!({"path":"/other","sha256":"a".repeat(64)})),
        ] {
            let mut bad = proof.clone();
            bad[key] = value;
            assert!(
                origin_binding(&previous, &p, &bad, sampled, 1792778500).is_err(),
                "{key}"
            );
        }
        assert!(origin_binding(&previous, &p, &proof, sampled, 1792779000).is_err());
    }
}
