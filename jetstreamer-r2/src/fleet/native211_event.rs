//! One guarded native 211 owner may join an accepted sample without a new poll.
use super::native211 as c;
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
            && proof["schema"] == "jetstreamer-private-epoch211-native-input-running-v1"
            && proof["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|f| proof["fleet"] == private157::binding(f))
            && proof["resource_samples_taken"] == 0
            && proof["entry_replay"] == false
            && proof["publication_authorized"] == false
            && proof["remote_mutations"] == false
            && proof["r2_mutations"] == false,
        "211 event cannot replace its accepted resource/fleet observation"
    );
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("211 event clock")?;
    ensure!(
        clock == utc_seconds(proof["sampled_at_utc"].as_str().context("211 event UTC")?)?
            && clock > utc_seconds(sampled)?
            && clock <= now
            && now - clock <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < clock),
        "211 event stale/backdated"
    );
    Ok(())
}
// Called only after the exact immutable admitted/captured native claim validates.
fn gate_state(epoch: u64, old: &str, new: &str) -> bool {
    old == new
        || (epoch == 211
            && matches!(old, "not-yet-staged" | "staged-admissible")
            && new == "blocked-qualification")
}
pub(super) fn event_predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    event_predecessor_read(previous, p, proof, sampled, now, &c::FsEvidence)
}
pub(super) fn event_predecessor_read(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
    reader: &impl c::EvidenceReader,
) -> Result<()> {
    origin_binding(previous, p, proof, sampled, now)?;
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("211 event clock")?;
    let a = reader.json(&serde_json::from_value(proof["admission"].clone())?, true)?;
    ensure!(
        a["schema"] == "horizon-native211-current-fleet-admission-v1"
            && a["mode"] == "native-cold"
            && a["admitted"] == true
            && a["unit"] == c::UNIT
            && a["private_run_root"] == c::ROOT
            && a["candidate_incremental_peak_bytes"] == c::SCRATCH
            && a["observer"] == proof["observer"]
            && a["fleet"] == proof["fleet"]
            && a["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= clock && clock - n <= 300),
        "211 event lacks exact fresh native admission"
    );
    let old: Plan = serde_json::from_value(
        reader.json(
            &BoundFile {
                path: previous["plan"]
                    .as_str()
                    .context("211 predecessor plan")?
                    .into(),
                sha256: previous["plan_sha256"]
                    .as_str()
                    .context("211 predecessor plan SHA")?
                    .into(),
            },
            false,
        )?,
    )?;
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
        "211 event changed pipeline history"
    );
    let claim = claims[0];
    c::claim_read(claim, reader)?;
    ensure!(
        p.metadata_event.as_ref() == claim.evidence.first()
            && reader.json(&claim.evidence[0], true)? == *proof,
        "211 event origin differs from its registered owner"
    );
    let mut tracked = old.tracked_units.iter().cloned().collect::<BTreeSet<_>>();
    tracked.insert(c::UNIT.into());
    ensure!(
        tracked == p.tracked_units.iter().cloned().collect()
            && p.first_epoch == old.first_epoch
            && p.last_epoch == old.last_epoch
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
        "211 event changed historical owners or unrelated configuration"
    );
    ensure!(
        p.gates.len() == old.gates.len(),
        "211 event changed gate census"
    );
    for (epoch, gate) in &old.gates {
        let new = p
            .gates
            .get(epoch)
            .context("211 event omitted a prior gate")?;
        ensure!(
            same_operator_status(&gate.operator_status, &new.operator_status)
                && gate_state(*epoch, &gate.state, &new.state)
                && serde_json::to_value(&new.reserve_stop)?
                    == serde_json::to_value(&gate.reserve_stop)?
                && gate.evidence.iter().all(|e| new.evidence.contains(e))
                && (*epoch == 211
                    || (new.next_action == gate.next_action && new.evidence == gate.evidence)),
            "211 event changed an unrelated or completion gate"
        );
        if *epoch == 211 {
            ensure!(
                new.evidence.iter().any(|e| claim.evidence.contains(e)),
                "211 blocked gate lacks its genuine captured origin"
            );
            ensure!(
                new.evidence
                    .iter()
                    .all(|e| gate.evidence.contains(e) || claim.evidence.contains(e)),
                "211 event added unrelated epoch evidence"
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
    for row in previous["active"].as_array().context("211 prior active")? {
        let overlaps = if let Some(epoch) = row["epoch"].as_u64() {
            epoch == 211
        } else {
            parse_observer_claim_range(row["range"].as_str().context("211 prior owner scope")?)?
                .contains(&211)
        };
        ensure!(!overlaps, "211 admission overlaps a prior range owner");
    }
    ensure!(
        !previous["active"]
            .as_array()
            .context("211 old active census")?
            .iter()
            .any(|r| r["epoch"] == 211),
        "211 event overlaps an existing owner"
    );
    let mut view = current.clone();
    let native = view
        .remove(c::UNIT)
        .context("211 new native owner missing")?;
    native211_capture::peers(previous, &view, c::UNIT)?;
    c::live(claim, &native)?;
    Ok(())
}

pub(super) fn same_operator_status(
    a: &Option<OperatorStatusEvidence>,
    b: &Option<OperatorStatusEvidence>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.basis == b.basis && a.completion == b.completion && a.raw_status == b.raw_status
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admitted_native_gate_only_enters_blocked_qualification_for_211() {
        for old in ["not-yet-staged", "staged-admissible"] {
            assert!(gate_state(211, old, "blocked-qualification"));
            assert!(!gate_state(227, old, "blocked-qualification"));
            assert!(!gate_state(229, old, "blocked-qualification"));
            for authority in ["ready", "complete", "post-replay-pipeline", "live-replay"] {
                assert!(!gate_state(211, old, authority));
            }
        }
        for old in [
            "ready",
            "complete",
            "failed-needs-repair",
            "post-replay-pipeline",
        ] {
            assert!(!gate_state(211, old, "blocked-qualification"));
            assert!(gate_state(211, old, old));
        }
    }
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
