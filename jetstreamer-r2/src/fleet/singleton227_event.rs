//! One guarded native227 owner may join an accepted sample without a new poll.
use super::*;
use super::{singleton227 as c, singleton227_admission as admission};
pub(super) fn event_predecessor(
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
            && proof["schema"] == "jetstreamer-private-epoch227-native-input-running-v1"
            && proof["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|f| proof["fleet"] == private157::binding(f))
            && proof["resource_samples_taken"] == 0
            && proof["entry_replay"] == false
            && proof["publication_authorized"] == false
            && proof["remote_mutations"] == false
            && proof["r2_mutations"] == false,
        "227 event cannot replace its accepted resource/fleet observation"
    );
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("227 event clock")?;
    ensure!(
        clock == utc_seconds(proof["sampled_at_utc"].as_str().context("227 event UTC")?)?
            && clock > utc_seconds(sampled)?
            && clock <= now
            && now - clock <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < clock),
        "227 event stale/backdated"
    );
    let a = bound_json(&serde_json::from_value(proof["admission"].clone())?)?;
    ensure!(
        a["schema"] == "jetstreamer-private-epoch227-singleton-admission-v1"
            && a["mode"] == "native-cold"
            && a["admitted"] == true
            && a["unit"] == admission::NATIVE_UNIT
            && a["private_run_root"] == admission::NATIVE_ROOT
            && a["candidate_incremental_peak_bytes"] == c::SCRATCH
            && a["observer"] == proof["observer"]
            && a["fleet"] == proof["fleet"]
            && a["fresh_complete_census_passed"] == true
            && a["older_producers_and_guards_preserved"] == true
            && a["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= clock && clock - n <= 900),
        "227 event lacks exact fresh native admission"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"]
            .as_str()
            .context("227 predecessor plan")?
            .into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("227 predecessor plan SHA")?
            .into(),
    })?)?;
    let claims = p
        .pipeline_claims
        .iter()
        .filter(|s| s.unit == admission::NATIVE_UNIT)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1
            && p.pipeline_claims.len() == old.pipeline_claims.len() + 1
            && !old
                .pipeline_claims
                .iter()
                .any(|s| s.unit == admission::NATIVE_UNIT)
            && old
                .pipeline_claims
                .iter()
                .all(|s| p.pipeline_claims.contains(s)),
        "227 event changed pipeline history"
    );
    let claim = claims[0];
    c::native_claim(claim)?;
    ensure!(
        p.metadata_event.as_ref() == claim.evidence.first()
            && bound_json(&claim.evidence[0])? == *proof,
        "227 event origin differs from its registered owner"
    );
    let mut tracked = old.tracked_units.iter().cloned().collect::<BTreeSet<_>>();
    tracked.insert(admission::NATIVE_UNIT.into());
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
        "227 event changed historical owners or unrelated configuration"
    );
    ensure!(
        p.gates.len() == old.gates.len(),
        "227 event changed gate census"
    );
    for (epoch, gate) in &old.gates {
        let new = p
            .gates
            .get(epoch)
            .context("227 event omitted a prior gate")?;
        ensure!(
            new.state == gate.state
                && gate.evidence.iter().all(|e| new.evidence.contains(e))
                && (*epoch == 227
                    || (new.next_action == gate.next_action && new.evidence == gate.evidence)),
            "227 event changed an unrelated or completion gate"
        );
        if *epoch == 227 {
            ensure!(
                new.evidence
                    .iter()
                    .all(|e| gate.evidence.contains(e) || claim.evidence.contains(e)),
                "227 event added unrelated epoch evidence"
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
    c::native_claim(claim)?;
    ensure!(
        !previous["active"]
            .as_array()
            .context("227 old active census")?
            .iter()
            .any(|r| r["epoch"] == 227),
        "227 event overlaps an existing owner"
    );
    let mut view = current.clone();
    let native = view
        .remove(admission::NATIVE_UNIT)
        .context("227 new native owner missing")?;
    admission::owners(previous, &view)?;
    c::native_live(claim, &native)?;
    Ok(())
}
