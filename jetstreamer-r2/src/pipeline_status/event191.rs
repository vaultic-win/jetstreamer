//! First real recovered191 queue event; resource timestamp remains unchanged.
use super::*;
pub(super) fn sample(p: &Plan, observer: &Value, proof: &Value, now: u64) -> Result<String> {
    ensure!(
        p.schema == "jetstreamer-cohort191-native-handoff-status-plan-v2"
            && (191..=194).contains(&p.epoch)
            && p.binding.claim_phase == "cohort191-delivery"
            && p.binding.unit == "horizon-cohort191-delivery-queue-20261023-v1.service"
            && p.binding.invocation_id == "0defba8ed0844040a2601c68d79060b2"
            && p.phase == "verification"
            && proof["observer"] == json!({"path":p.observer.path,"sha256":p.observer.sha256})
            && proof["native_event_clock"].is_object()
            && p.phase_handoff_event.as_ref().is_some_and(|b| p
                .estimate_evidence
                .iter()
                .any(|x| x.path == b.path && x.sha256 == b.sha256)),
        "191 event status lost recovered queue, phase or evidence"
    );
    let sample = proof["sampled_at_utc"]
        .as_str()
        .context("191 event sample")?;
    let event = fleet::utc_seconds(sample)?;
    let resource = fleet::utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("191 retained resource sample")?,
    )?;
    ensure!(
        resource < event && event - resource <= 1800 && event <= now && now - event <= 300,
        "191 event status requires fresh distinct native metadata clock"
    );
    super::super::cohort191_delivery::validate_event(proof, event)?;
    Ok(sample.into())
}
