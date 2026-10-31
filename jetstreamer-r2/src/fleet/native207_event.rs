//! One guarded native 207 owner may join an accepted sample without a new poll.
use super::native207 as c;
use super::*;
fn origin_binding(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    ensure!(
        p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && previous["schema"] == SCHEMA
            && previous["sampled_at_utc"] == sampled
            && previous["observer_receipt"].as_str() == p.observer.path.to_str()
            && previous["observer_sha256"] == p.observer.sha256
            && proof["schema"] == "jetstreamer-private-epoch207-native-input-running-v1"
            && proof["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|f| proof["fleet"] == private157::binding(f))
            && proof["resource_samples_taken"] == 0
            && proof["entry_replay"] == false
            && proof["publication_authorized"] == false
            && proof["remote_mutations"] == false
            && proof["r2_mutations"] == false,
        "207 event cannot replace its accepted resource/fleet observation"
    );
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("207 event clock")?;
    ensure!(
        clock == utc_seconds(proof["sampled_at_utc"].as_str().context("207 event UTC")?)?
            && clock > utc_seconds(sampled)?
            && clock <= now
            && now - clock <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < clock),
        "207 event stale/backdated"
    );
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
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("207 event clock")?;
    let a = bound_json(&serde_json::from_value(proof["admission"].clone())?)?;
    ensure!(
        a["schema"] == "jetstreamer-private-epoch207-native-admission-v1"
            && a["mode"] == "native-cold"
            && a["admitted"] == true
            && a["unit"] == c::UNIT
            && a["private_run_root"] == c::ROOT
            && a["candidate_incremental_peak_bytes"] == c::SCRATCH
            && a["observer"] == proof["observer"]
            && a["fleet"] == proof["fleet"]
            && a["fresh_complete_census_passed"] == true
            && a["older_producers_and_guards_preserved"] == true
            && a["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= clock && clock - n <= 900),
        "207 event lacks exact fresh native admission"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"]
            .as_str()
            .context("207 predecessor plan")?
            .into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("207 predecessor plan SHA")?
            .into(),
    })?)?;
    let claims = p
        .pipeline_claims
        .iter()
        .filter(|s| s.unit == c::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1
            && p.pipeline_claims.len() == old.pipeline_claims.len() + 1
            && !old.pipeline_claims.iter().any(|s| s.unit == c::UNIT)
            && old
                .pipeline_claims
                .iter()
                .all(|s| p.pipeline_claims.contains(s)),
        "207 event changed pipeline history"
    );
    let claim = claims[0];
    c::claim(claim)?;
    ensure!(
        p.metadata_event.as_ref() == claim.evidence.first()
            && bound_json(&claim.evidence[0])? == *proof,
        "207 event origin differs from its registered owner"
    );
    let mut tracked = old.tracked_units.iter().cloned().collect::<BTreeSet<_>>();
    tracked.insert(c::UNIT.into());
    ensure!(
        tracked == p.tracked_units.iter().cloned().collect()
            && p.schema == old.schema
            && p.observer == old.observer
            && p.status_receipt_directory == old.status_receipt_directory
            && p.runtime_handoff157 == old.runtime_handoff157
            && p.continuation203_runtime_extension == old.continuation203_runtime_extension
            && p.epoch203_ram_auxiliary.is_none()
            && old.epoch203_ram_auxiliary.is_none()
            && p.diagnostics.len() == old.diagnostics.len()
            && old
                .diagnostics
                .iter()
                .all(|d| p.diagnostics.iter().any(|n| n.epoch == d.epoch
                    && n.unit == d.unit
                    && n.invocation_id == d.invocation_id
                    && n.scratch_path == d.scratch_path
                    && n.launch_receipt == d.launch_receipt)),
        "207 event changed historical owners or unrelated configuration"
    );
    ensure!(
        p.gates.len() == old.gates.len(),
        "207 event changed gate census"
    );
    for (epoch, gate) in &old.gates {
        let new = p
            .gates
            .get(epoch)
            .context("207 event omitted a prior gate")?;
        ensure!(
            new.state == gate.state
                && serde_json::to_value(&new.reserve_stop)?
                    == serde_json::to_value(&gate.reserve_stop)?
                && gate.evidence.iter().all(|e| new.evidence.contains(e))
                && (*epoch == 207
                    || (new.next_action == gate.next_action && new.evidence == gate.evidence)),
            "207 event changed an unrelated or completion gate"
        );
        if *epoch == 207 {
            ensure!(
                new.evidence
                    .iter()
                    .all(|e| gate.evidence.contains(e) || claim.evidence.contains(e)),
                "207 event added unrelated epoch evidence"
            );
        }
    }
    Ok(())
}

pub(super) fn event_census(
    previous: &Value,
    current: &BTreeMap<String, Value>,
    claim: &PipelineClaim,
) -> Result<()> {
    c::claim(claim)?;
    ensure!(
        !previous["active"]
            .as_array()
            .context("207 old active census")?
            .iter()
            .any(|r| r["epoch"] == 207),
        "207 event overlaps an existing owner"
    );
    let mut view = current.clone();
    let native = view
        .remove(c::UNIT)
        .context("207 new native owner missing")?;
    singleton227_admission::owners(previous, &view)?;
    c::live(claim, &native)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_event_cannot_replace_its_resource_observer_or_prior_fleet() {
        let observer = json!({"path":"/observer.json","sha256":"a".repeat(64)});
        let previous_bound = json!({"path":"/previous.json","sha256":"b".repeat(64)});
        let p:Plan=serde_json::from_value(json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,"observer":observer,"previous_fleet":previous_bound,"output":"/output.json","status_receipt_directory":"/receipts","gates":{},"tracked_units":[]})).unwrap();
        let sampled = "2026-10-23T18:00:00Z";
        let previous = json!({"schema":SCHEMA,"sampled_at_utc":sampled,"observer_receipt":"/observer.json","observer_sha256":"a".repeat(64),"recorded_unix_seconds":1792778400u64});
        let proof = json!({"schema":c::SCHEMA,"observer":observer,"fleet":previous_bound,"resource_samples_taken":0,"entry_replay":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"recorded_unix_seconds":1792778460u64,"sampled_at_utc":"2026-10-23T18:01:00Z"});
        origin_binding(&previous, &p, &proof, sampled, 1792778500).unwrap();
        for (key, value) in [
            (
                "observer",
                json!({"path":"/another.json","sha256":"a".repeat(64)}),
            ),
            (
                "fleet",
                json!({"path":"/previous.json","sha256":"c".repeat(64)}),
            ),
            (
                "schema",
                json!("jetstreamer-private-epoch227-native-input-running-v1"),
            ),
            ("resource_samples_taken", json!(1)),
            ("entry_replay", json!(true)),
            ("recorded_unix_seconds", json!(1792778400u64)),
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
