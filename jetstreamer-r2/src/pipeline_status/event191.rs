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
    if let Some(config) = readback_config(proof)? {
        ensure!(
            p.epoch == config.epoch
                && p.phase == "readback"
                && config.accepted_fleet.path == p.fleet.path
                && config.accepted_fleet.sha256 == p.fleet.sha256,
            "same-owner event is not this accepted epoch's readback handoff"
        );
    }
    Ok(sample.into())
}

fn readback_config(
    proof: &Value,
) -> Result<Option<super::super::cohort191_delivery::readback_handoff::Config>> {
    let clock: Bound = serde_json::from_value(proof["native_event_clock"].clone())?;
    super::super::cohort191_delivery::readback_handoff::config(&bound_json(&clock)?)
}

fn same_previous_or_exact_retry(
    object_bytes: &[u8],
    object_etag: &str,
    prior: &StatusPublicationReceipt,
    status: &EpochStatus,
) -> Result<()> {
    ensure!(
        object_bytes == epoch_status_bytes(status)?
            || (object_bytes == epoch_status_bytes(&prior.status)?
                && object_etag == prior.object_etag),
        "readback handoff would replace a newer or foreign status version"
    );
    Ok(())
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
    let event = bound_json(
        p.phase_handoff_event
            .as_ref()
            .context("missing native handoff event")?,
    )?;
    if let Some(config) = readback_config(&event)? {
        ensure!(
            p.epoch == config.epoch
                && p.phase == "readback"
                && status.phase == "readback"
                && config.accepted_fleet.path == p.fleet.path
                && config.accepted_fleet.sha256 == p.fleet.sha256,
            "same-owner publisher is not the accepted readback epoch"
        );
        let value =
            super::super::cohort191_delivery::bound(&config.previous_status_publication, false)?;
        super::super::cohort191_delivery::readback_handoff::previous_shape(
            &value,
            &config,
            &observer,
            &json!({"path":p.observer.path,"sha256":p.observer.sha256}),
        )?;
        let prior = validate_status_publication_receipt_bytes(
            Path::new("/home/sol/.jetstreamer-private/r2-status-receipts"),
            &config.previous_status_publication.path,
            &serde_json::to_vec(&value)?,
            &r2.bucket,
            p.epoch,
        )?;
        let object = previous
            .as_ref()
            .context("same-owner readback cannot create a missing upload status")?;
        same_previous_or_exact_retry(&object.bytes, &object.etag, &prior, status)?;
        return publish_epoch_status_bound_previous(s3, r2, status, Some(&object.etag)).await;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_owner_handoff_preserves_exact_etag_and_idempotent_receipt_recovery() {
        let upload = EpochStatus {
            epoch: 191,
            jet_size_bytes: 1000,
            elapsed_execution_millis: 9000,
            estimated_remaining_millis: 2000,
            sampled_at_utc: "2026-10-24T09:16:00Z".into(),
            phase: "upload".into(),
        };
        let mut readback = upload.clone();
        readback.phase = "readback".into();
        readback.sampled_at_utc = "2026-10-24T09:20:00Z".into();
        readback.estimated_remaining_millis = 1500;
        let prior = StatusPublicationReceipt {
            schema: PIPELINE_STATUS_RECEIPT_SCHEMA.into(),
            bucket: "bucket".into(),
            epoch: 191,
            key: "epoch-191.epoch-status.json".into(),
            status: upload.clone(),
            object_etag: "authenticated-upload-etag".into(),
            previous_object_etag: None,
            observer_receipt: "/observer.json".into(),
            observer_receipt_sha256: "a".repeat(64),
            controller_invocation_id: String::new(),
            producer_invocation_id: String::new(),
            authenticated_readback: true,
            verified_unix_seconds: 100,
            pipeline_binding: None,
        };
        let upload_bytes = epoch_status_bytes(&upload).unwrap();
        let readback_bytes = epoch_status_bytes(&readback).unwrap();
        same_previous_or_exact_retry(&upload_bytes, &prior.object_etag, &prior, &readback).unwrap();
        assert!(
            same_previous_or_exact_retry(&upload_bytes, "replacement-etag", &prior, &readback)
                .is_err()
        );
        // A retry after remote publication and before local receipt durability
        // reads back the identical event payload without another mutation.
        same_previous_or_exact_retry(&readback_bytes, "new-readback-etag", &prior, &readback)
            .unwrap();
        let mut newer = readback.clone();
        newer.sampled_at_utc = "2026-10-24T09:46:00Z".into();
        assert!(same_previous_or_exact_retry(
            &epoch_status_bytes(&newer).unwrap(),
            "newer-etag",
            &prior,
            &readback
        )
        .is_err());
        let mut changed_eta = readback.clone();
        changed_eta.estimated_remaining_millis += 1;
        assert!(same_previous_or_exact_retry(
            &epoch_status_bytes(&changed_eta).unwrap(),
            "changed-etag",
            &prior,
            &readback
        )
        .is_err());
    }
}
