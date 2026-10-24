//! First real recovered epoch 191 queue event; resource timestamp remains unchanged.
use super::*;
pub(super) fn sample(p: &Plan, observer: &Value, proof: &Value, now: u64) -> Result<String> {
    let row = proof["queue_observation"]["epochs"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["epoch"] == p.epoch))
        .context("191 exact event stage")?;
    let phase = match row["stage"].as_str() {
        Some("upload") => "upload",
        Some("readback" | "source-revalidation") => "readback",
        Some(
            "queued-full"
            | "full-verification"
            | "queued-plugin"
            | "plugin-verification"
            | "queued-upload",
        ) => "verification",
        _ => bail!("191 event has no active stage"),
    };
    ensure!(
        p.schema == "jetstreamer-cohort191-native-handoff-status-plan-v2"
            && (191..=194).contains(&p.epoch)
            && p.binding.claim_phase == "cohort191-delivery"
            && p.binding.unit == "horizon-cohort191-delivery-queue-20261023-v1.service"
            && p.binding.invocation_id == "0defba8ed0844040a2601c68d79060b2"
            && p.phase == phase
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

pub(super) async fn publish(
    s3: &Client,
    r2: &R2Config,
    status: &EpochStatus,
    p: &Plan,
) -> Result<(String, Option<String>)> {
    let observer = bound_json(&p.observer)?;
    let resource = fleet::utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("191 resource time")?,
    )?;
    let previous = get_mutable_object(
        s3,
        &r2.bucket,
        &format!("epoch-{}.epoch-status.json", p.epoch),
    )
    .await?;
    if let Some(object) = &previous {
        let old: EpochStatus = serde_json::from_slice(&object.bytes)?;
        ensure!(
            old.epoch == status.epoch
                && (epoch_status_bytes(&old)? == epoch_status_bytes(status)?
                    || (old.phase == "verification"
                        && fleet::utc_seconds(&old.sampled_at_utc)? <= resource)),
            "191 native event cannot repeatedly refresh an existing later event/countdown"
        );
    }
    publish_epoch_status_bound_previous(s3, r2, status, previous.as_ref().map(|o| o.etag.as_str()))
        .await
}
