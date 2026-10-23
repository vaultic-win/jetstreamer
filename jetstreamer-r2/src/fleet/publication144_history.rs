//! Exact real144 publication may retain completed private diagnostic history.
//! This is not a general exception for overlapping private/public owners.
use super::*;
const PUB: &str = "horizon-publish-144-v4-20261022-v1.service";
const UPLOAD: &str = "horizon-upload-144-v4-20261022-v1.service";
const IID: &str = "0f5bfa27bcfb4af3b16233f46ae38ab4";
const ORIGIN: &str = "/var/lib/jetstreamer/horizon-publication144-owner-20261022-v1/launch.json";
const ORIGIN_SHA: &str = "dd5e002e2cfee2ae1b554a13b7559ebb67329cec5fe936ea719a4b90127dd3bd";
pub(super) fn namespace(c: &PipelineClaim) -> bool {
    c.epoch == 144
        && matches!(
            (c.unit.as_str(), c.phase.as_str()),
            (PUB, "local-publication") | (UPLOAD, "upload-readback")
        )
}
fn checked_publisher(c: &PipelineClaim, v: &Value) -> Result<()> {
    ensure!(
        namespace(c)
            && c.unit == PUB
            && c.invocation_id == IID
            && c.evidence.len() == 1
            && c.evidence[0].path == Path::new(ORIGIN)
            && c.evidence[0].sha256 == ORIGIN_SHA
            && v["schema"] == "jetstreamer-exact144-publication-launch-v1"
            && v["epoch"] == 144
            && v["launched"] == true
            && v["claim"]["unit"] == PUB
            && v["claim"]["phase"] == "local-publication"
            && v["claim"]["invocation_id"] == IID
            && v["claim"]["expected_exec_start"] == c.expected_exec_start
            && v["publisher_sha256"]
                == "4274f83c6d84a2bc2014b30122a38406b6498045f543ba170598baa8369a7efa"
            && v["tracker_sha256"]
                == "b85dc978377f20036ecd40cb4495729f27c2e8dc906c3cb2576463d9adf1dc75"
            && v["publisher_plan"]["sha256"]
                == "640b33757e7bece8fb68bcb727db5edb47814ee43a30b7aa6ffb2e3bb1b2ad21"
            && v["ordinary_replay_claim"] == false
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false,
        "private144 history cannot borrow a different public publisher/origin"
    );
    Ok(())
}
pub(super) fn validate(p: &Plan, census: &BTreeMap<String, Value>) -> Result<bool> {
    let public: Vec<_> = p.pipeline_claims.iter().filter(|c| namespace(c)).collect();
    if public.is_empty() {
        return Ok(false);
    }
    let pubs: Vec<_> = public.iter().copied().filter(|c| c.unit == PUB).collect();
    ensure!(
        pubs.len() == 1 && public.len() <= 2,
        "duplicated or missing144 publisher history"
    );
    let original = bound_json(pubs[0].evidence.first().context("144 origin evidence")?)?;
    checked_publisher(pubs[0], &original)?;
    for d in p
        .diagnostics
        .iter()
        .filter(|d| diagnostic_scope(d).contains(&144))
    {
        let v = census
            .get(&d.unit)
            .context("144 private history missing from census")?;
        ensure!(
            v["MainPID"] == "0"
                && matches!(
                    v["ActiveState"].as_str(),
                    Some("active" | "inactive" | "failed")
                )
                && matches!(v["SubState"].as_str(), Some("exited" | "dead" | "failed")),
            "public144 cannot overlap a live private diagnostic"
        );
    }
    for upload in public.iter().filter(|c| c.unit == UPLOAD) {
        ensure!(
            upload.evidence.len() == 2
                && upload.evidence[0].path == Path::new(ORIGIN)
                && upload.evidence[0].sha256 == ORIGIN_SHA,
            "144 upload lost publisher lineage"
        );
        let l = bound_json(&upload.evidence[1])?;
        ensure!(
            upload.evidence[1].path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-epoch144-delivery-20261023-v7/launch.json"
                )
                && l["schema"] == "jetstreamer-exact144-delivery-launch-v1"
                && l["epoch"] == 144
                && l["self_sha256"]
                    == "9fdca9475356c3f8c82c8dbdd55d57476116771be2e3ca6b8914c40c8f41e08e"
                && l["claim"]["unit"] == UPLOAD
                && l["claim"]["phase"] == "upload-readback"
                && l["claim"]["origin_unit"] == PUB
                && l["claim"]["origin_invocation_id"] == IID
                && l["claim"]["invocation_id"] == upload.invocation_id
                && l["claim"]["expected_exec_start"] == upload.expected_exec_start,
            "144 upload is not the authenticated actual handoff"
        );
    }
    Ok(true)
}
pub(super) fn event_predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sample: &str,
    now: u64,
) -> Result<()> {
    let event = proof["sampled_at_utc"]
        .as_str()
        .context("metadata event clock")?;
    let seconds = utc_seconds(event)?;
    let upload: Vec<_> = p
        .pipeline_claims
        .iter()
        .filter(|c| namespace(c) && c.unit == UPLOAD)
        .collect();
    ensure!(
        p.first_epoch == 101
            && p.last_epoch == 200
            && upload.len() == 1
            && previous["schema"] == SCHEMA
            && previous["first_epoch"] == 101
            && previous["last_epoch"] == 200
            && previous["sampled_at_utc"] == sample
            && previous["observer_receipt"].as_str() == p.observer.path.to_str()
            && previous["observer_sha256"] == p.observer.sha256
            && previous["assigned_range"].is_null()
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < seconds)
            && previous["active"].as_array().is_some_and(|a| !a
                .iter()
                .any(|v| v["epoch"] == 144 && v["phase"] == "upload-readback")),
        "event must advance actual owner after the same accepted resource sample,not repeat an upload refresh"
    );
    let u = upload[0];
    let b = p.metadata_event.as_ref().context("event binding")?;
    ensure!(
        is_canonical_utc(event)
            && seconds > utc_seconds(sample)?
            && seconds <= now
            && now - seconds <= 300
            && b.path
                == Path::new("/var/lib/jetstreamer/horizon-epoch144-progress-20261022-v1")
                    .join(format!("event-progress-{}.json", seconds * 1000))
            && proof["schema"] == "jetstreamer-exact144-authenticated-child-progress-v2"
            && proof["phase_handoff_event"] == true
            && proof["epoch"] == 144
            && proof["self_sha256"]
                == "3133c3bea1a6c18bd9cfef9fe3c12f8a4d156c655eb130859f39ec04c858f0aa"
            && proof["observer"]["path"].as_str() == p.observer.path.to_str()
            && proof["observer"]["sha256"] == p.observer.sha256
            && proof["owner"]["Id"] == UPLOAD
            && proof["owner"]["InvocationID"] == u.invocation_id
            && u.evidence.len() == 2
            && proof["delivery_launch"]["path"].as_str() == u.evidence[1].path.to_str()
            && proof["delivery_launch"]["sha256"] == u.evidence[1].sha256
            && proof["forecast"]["sampled_at_millis"] == seconds * 1000
            && proof["resource_samples_taken"] == 0
            && proof["remote_mutations"] == false
            && proof["r2_mutations"] == false,
        "metadata event lost authentic fresh child,forecast or original resource evidence"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_handoff_advances_event_clock_without_faking_resource_sample() {
        let time = utc_seconds("2026-10-23T00:49:14Z").unwrap();
        let p:Plan=serde_json::from_value(json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":101,"last_epoch":200,
            "observer":{"path":"/observer","sha256":"a".repeat(64)},"output":"/out","status_receipt_directory":"/receipts","gates":{},"tracked_units":[],
            "metadata_event":{"path":format!("/var/lib/jetstreamer/horizon-epoch144-progress-20261022-v1/event-progress-{}.json",time*1000),"sha256":"c".repeat(64)},
            "pipeline_claims":[{"epoch":144,"unit":UPLOAD,"phase":"upload-readback","invocation_id":"d".repeat(32),"expected_exec_start":"exact",
                "evidence":[{"path":ORIGIN,"sha256":ORIGIN_SHA},{"path":"/upload","sha256":"b".repeat(64)}]}]})).unwrap();
        let before = json!({"schema":SCHEMA,"first_epoch":101,"last_epoch":200,"sampled_at_utc":"2026-10-23T00:28:00Z",
            "observer_receipt":"/observer","observer_sha256":"a".repeat(64),"recorded_unix_seconds":time-60,"active":[]});
        let proof = json!({"schema":"jetstreamer-exact144-authenticated-child-progress-v2","epoch":144,"phase_handoff_event":true,
            "self_sha256":"3133c3bea1a6c18bd9cfef9fe3c12f8a4d156c655eb130859f39ec04c858f0aa","sampled_at_utc":"2026-10-23T00:49:14Z",
            "observer":{"path":"/observer","sha256":"a".repeat(64)},"owner":{"Id":UPLOAD,"InvocationID":"d".repeat(32)},
            "delivery_launch":{"path":"/upload","sha256":"b".repeat(64)},"forecast":{"sampled_at_millis":time*1000},
            "resource_samples_taken":0,"remote_mutations":false,"r2_mutations":false});
        event_predecessor(&before, &p, &proof, "2026-10-23T00:28:00Z", time + 1).unwrap();
        for key in ["observer_sha256", "sampled_at_utc", "recorded_unix_seconds"] {
            let mut bad = before.clone();
            bad[key] = json!("foreign");
            assert!(
                event_predecessor(&bad, &p, &proof, "2026-10-23T00:28:00Z", time + 1).is_err(),
                "{key}"
            );
        }
        let mut repeated = before.clone();
        repeated["active"] = json!([{"epoch":144,"phase":"upload-readback"}]);
        assert!(
            event_predecessor(&repeated, &p, &proof, "2026-10-23T00:28:00Z", time + 1).is_err()
        );
        assert!(
            event_predecessor(&before, &p, &proof, "2026-10-23T00:28:00Z", time + 301).is_err()
        );
        let mut counterfeit = proof.clone();
        counterfeit["resource_samples_taken"] = json!(1);
        assert!(
            event_predecessor(&before, &p, &counterfeit, "2026-10-23T00:28:00Z", time + 1).is_err()
        );
    }
    #[test]
    fn exact_real_publisher_is_distinct_from_private_scan_or_foreign_publication() {
        let c: PipelineClaim = serde_json::from_value(
            json!({"epoch":144,"phase":"local-publication","unit":PUB,"invocation_id":IID,
            "expected_exec_start":"exact","evidence":[{"path":ORIGIN,"sha256":ORIGIN_SHA}]}),
        )
        .unwrap();
        let v = json!({"schema":"jetstreamer-exact144-publication-launch-v1","epoch":144,"launched":true,
            "claim":{"unit":PUB,"phase":"local-publication","invocation_id":IID,"expected_exec_start":"exact"},
            "publisher_sha256":"4274f83c6d84a2bc2014b30122a38406b6498045f543ba170598baa8369a7efa",
            "tracker_sha256":"b85dc978377f20036ecd40cb4495729f27c2e8dc906c3cb2576463d9adf1dc75",
            "publisher_plan":{"sha256":"640b33757e7bece8fb68bcb727db5edb47814ee43a30b7aa6ffb2e3bb1b2ad21"},
            "ordinary_replay_claim":false,"publication_authorized":false,"r2_mutations":false});
        checked_publisher(&c, &v).unwrap();
        for pointer in [
            "/claim/invocation_id",
            "/publisher_plan/sha256",
            "/publisher_sha256",
            "/r2_mutations",
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(checked_publisher(&c, &bad).is_err(), "{pointer}");
        }
    }
}
