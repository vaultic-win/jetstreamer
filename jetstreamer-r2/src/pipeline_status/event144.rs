//! Initial publisher->upload metadata event. Retains the last real resource
//! observer; cannot refresh an existing upload/readback countdown autonomously.
use super::*;
const READER_SHA: &str = "3133c3bea1a6c18bd9cfef9fe3c12f8a4d156c655eb130859f39ec04c858f0aa";
pub(super) fn sample(p: &Plan, observer: &Value, proof: &Value, now: u64) -> Result<String> {
    let (sample, event_ms, resource_ms) = checked(p, observer, proof, now)?;
    let child: Bound = serde_json::from_value(proof["child_launch"].clone())?;
    let launch: Bound = serde_json::from_value(proof["delivery_launch"].clone())?;
    let root = launch.path.parent().context("delivery capture parent")?;
    ensure!(
        root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-epoch144-delivery-"))
            && launch.path == root.join("launch.json")
            && child.path == root.join("upload-child-launch.json"),
        "foreign handoff capture paths"
    );
    let c = bound_json(&child)?;
    let l = bound_json(&launch)?;
    validate_child(p, proof, &c, &l, event_ms, resource_ms)?;
    Ok(sample)
}
fn checked(p: &Plan, observer: &Value, proof: &Value, now: u64) -> Result<(String, u64, u64)> {
    let b = p
        .phase_handoff_event
        .as_ref()
        .context("handoff progress binding")?;
    let sample = proof["sampled_at_utc"]
        .as_str()
        .context("handoff sample time")?;
    let event = fleet::utc_seconds(sample)?;
    let resource = fleet::utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("resource sample")?,
    )?;
    let event_ms = event.checked_mul(1000).context("event clock overflow")?;
    ensure!(
        exact144_binding(p)
            && p.phase == "upload"
            && p.binding.unit == UPLOAD144
            && p.expected_jet_size_bytes == 109177480876
            && p.jet_path == Path::new("/home/sol/horizon/epoch-144.jet")
            && b.path.parent()
                == Some(Path::new(
                    "/var/lib/jetstreamer/horizon-epoch144-progress-20261022-v1"
                ))
            && b.path.file_name().and_then(|n| n.to_str())
                == Some(format!("event-progress-{event_ms}.json").as_str())
            && p.estimate_evidence
                .iter()
                .any(|e| e.path == b.path && e.sha256 == b.sha256),
        "event profile is not exact 144 initial upload handoff"
    );
    ensure!(
        proof["schema"] == "jetstreamer-exact144-authenticated-child-progress-v2"
            && proof["self_sha256"] == READER_SHA
            && proof["epoch"] == 144
            && proof["phase_handoff_event"] == true
            && proof["observer"]["path"].as_str() == p.observer.path.to_str()
            && proof["observer"]["sha256"] == p.observer.sha256
            && proof["owner"]["Id"] == p.binding.unit
            && proof["owner"]["InvocationID"] == p.binding.invocation_id
            && proof["owner"]["NRestarts"] == "0"
            && proof["forecast"]["schema"] == "jetstreamer-exact144-child-sidecar-forecast-v1"
            && proof["forecast"]["sampled_at_millis"] == event_ms
            && proof["forecast"]["estimated_remaining_millis"] == p.estimated_remaining_millis
            && matches!(
                proof["forecast"]["phase"].as_str(),
                Some("pre-upload-source-hash" | "upload" | "awaiting-readback")
            )
            && proof["resource_samples_taken"] == 0
            && proof["remote_mutations"] == false
            && proof["r2_mutations"] == false,
        "event proof lost actual owner, forecast or unchanged resource evidence"
    );
    ensure!(
        resource < event && event - resource <= 1800 && event <= now && now - event <= 300,
        "handoff event must use a fresh distinct metadata clock"
    );
    Ok((
        sample.into(),
        event_ms,
        resource
            .checked_mul(1000)
            .context("resource clock overflow")?,
    ))
}
fn validate_child(
    p: &Plan,
    proof: &Value,
    c: &Value,
    l: &Value,
    event: u64,
    resource: u64,
) -> Result<()> {
    let spawned = c["spawned_millis"].as_u64().context("child spawn event")?;
    let child_plan: Bound = serde_json::from_value(c["plan"].clone())?;
    ensure!(
        c["schema"] == "horizon-exact144-delivery-child-launch-v1"
            && c["owner"]["InvocationID"] == p.binding.invocation_id
            && c["owner"] == l["owner"]
            && c["plan"] == l["plan"]
            && c["archive_sync"] == true
            && c["archive_ready"] == false
            && child_plan.path.is_absolute()
            && hex_id(&child_plan.sha256, 64)
            && c["client"]["path"]
                == "/usr/local/lib/jetstreamer/horizon-publication144-progress-client-20261022-v1/jetstreamer-r2"
            && c["client"]["sha256"]
                == "c91b5ab379e876c6426be82adb381644927e7b5a199e3709dc9ce59dc2a6d96a"
            && c["child_pid"].as_u64().is_some_and(|p| p > 0)
            && proof["child_identity"]["pid"] == c["child_pid"]
            && proof["child_identity"]["uid"] == 1001
            && proof["child_identity"]["gid"] == 1003
            && proof["child_identity"]["capabilities_empty"] == true
            && spawned > resource
            && spawned <= event
            && event - spawned <= 300000
            && l["schema"] == "jetstreamer-exact144-delivery-launch-v1"
            && l["self_sha256"]
                == "9fdca9475356c3f8c82c8dbdd55d57476116771be2e3ca6b8914c40c8f41e08e"
            && l["initial_delivery_phase"] == "upload-readback"
            && l["claim"]["origin_unit"] == PUB144
            && l["claim"]["origin_invocation_id"] == p.binding.origin_invocation_id
            && l["owner"]["InvocationID"] == p.binding.invocation_id
            && proof["owner"]["MainPID"] == l["owner"]["MainPID"],
        "event is not a fresh actual nonqueued child of the original publisher"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn event_clock_keeps_resource_evidence_and_rejects_foreign_or_stale_progress() {
        let mut p = super::super::tests::directory_plan();
        p.epoch = 144;
        p.phase = "upload".into();
        p.binding.unit = UPLOAD144.into();
        p.binding.origin_unit = PUB144.into();
        p.binding.claim_phase = "upload-readback".into();
        p.origin_launch.path = ORIGIN144.into();
        p.jet_path = "/home/sol/horizon/epoch-144.jet".into();
        p.expected_jet_size_bytes = 109177480876;
        let sample = "2026-10-22T23:58:02Z";
        let t = fleet::utc_seconds(sample).unwrap();
        let b = Bound {
            path: format!(
                "/var/lib/jetstreamer/horizon-epoch144-progress-20261022-v1/event-progress-{}.json",
                t * 1000
            )
            .into(),
            sha256: "b".repeat(64),
        };
        p.estimate_evidence = vec![Bound {
            path: b.path.clone(),
            sha256: b.sha256.clone(),
        }];
        p.phase_handoff_event = Some(b);
        let o = json!({"recorded_at_utc":"2026-10-22T23:58:00Z"});
        let proof = json!({"schema":"jetstreamer-exact144-authenticated-child-progress-v2","epoch":144,"self_sha256":READER_SHA,
            "phase_handoff_event":true,"sampled_at_utc":sample,"observer":{"path":p.observer.path,"sha256":p.observer.sha256},
            "owner":{"Id":UPLOAD144,"InvocationID":p.binding.invocation_id,"NRestarts":"0"},
            "forecast":{"schema":"jetstreamer-exact144-child-sidecar-forecast-v1","sampled_at_millis":t*1000,
                "estimated_remaining_millis":p.estimated_remaining_millis,"phase":"pre-upload-source-hash"},
            "resource_samples_taken":0,"remote_mutations":false,"r2_mutations":false});
        assert_eq!(checked(&p, &o, &proof, t + 1).unwrap().0, sample);
        for pointer in [
            "/epoch",
            "/phase_handoff_event",
            "/observer/sha256",
            "/owner/InvocationID",
            "/owner/Id",
            "/forecast/phase",
            "/forecast/estimated_remaining_millis",
            "/resource_samples_taken",
            "/r2_mutations",
        ] {
            let mut bad = proof.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(checked(&p, &o, &bad, t + 1).is_err(), "{pointer}");
        }
        assert!(checked(&p, &o, &proof, t - 1).is_err());
        assert!(checked(&p, &o, &proof, t + 301).is_err());
        assert!(checked(&p, &json!({"recorded_at_utc":sample}), &proof, t + 1).is_err());
        assert!(
            checked(
                &p,
                &json!({"recorded_at_utc":"2026-10-22T22:58:00Z"}),
                &proof,
                t + 1
            )
            .is_err()
        );
        p.phase = "readback".into();
        assert!(checked(&p, &o, &proof, t + 1).is_err());
    }
    #[test]
    fn conditional_mutation_allows_one_phase_change_or_identical_receipt_recovery_only() {
        let status = EpochStatus {
            epoch: 144,
            jet_size_bytes: 109177480876,
            elapsed_execution_millis: 1234,
            estimated_remaining_millis: 1234,
            sampled_at_utc: "2026-10-22T23:58:02Z".into(),
            phase: "upload".into(),
        };
        validate_initial144_handoff(None, &status).unwrap();
        validate_initial144_handoff(Some(&status), &status).unwrap();
        let mut prior = status.clone();
        prior.phase = "publication".into();
        validate_initial144_handoff(Some(&prior), &status).unwrap();
        prior.phase = "readback".into();
        assert!(validate_initial144_handoff(Some(&prior), &status).is_err());
        prior.phase = "upload".into();
        prior.estimated_remaining_millis += 1;
        assert!(validate_initial144_handoff(Some(&prior), &status).is_err());
        prior.phase = "replay".into();
        assert!(validate_initial144_handoff(Some(&prior), &status).is_err());
        prior.epoch = 143;
        prior.phase = "publication".into();
        assert!(validate_initial144_handoff(Some(&prior), &status).is_err());
    }
    #[test]
    fn handoff_requires_new_actual_child_and_original_publisher_lineage() {
        let mut p = super::super::tests::directory_plan();
        p.binding.origin_unit = PUB144.into();
        let owner = json!({"InvocationID":p.binding.invocation_id,"MainPID":"123"});
        let c = json!({"schema":"horizon-exact144-delivery-child-launch-v1","owner":owner,
            "plan":{"path":"/sealed/delivery.json","sha256":"a".repeat(64)},
            "client":{"path":"/usr/local/lib/jetstreamer/horizon-publication144-progress-client-20261022-v1/jetstreamer-r2",
                "sha256":"c91b5ab379e876c6426be82adb381644927e7b5a199e3709dc9ce59dc2a6d96a"},
            "child_pid":456,"spawned_millis":2000,"archive_sync":true,"archive_ready":false});
        let l = json!({"schema":"jetstreamer-exact144-delivery-launch-v1","self_sha256":"9fdca9475356c3f8c82c8dbdd55d57476116771be2e3ca6b8914c40c8f41e08e",
            "owner":owner,"plan":c["plan"],"initial_delivery_phase":"upload-readback",
            "claim":{"origin_unit":PUB144,"origin_invocation_id":p.binding.origin_invocation_id}});
        let proof = json!({"owner":owner,"child_identity":{"pid":456,"uid":1001,"gid":1003,"capabilities_empty":true}});
        validate_child(&p, &proof, &c, &l, 3000, 1000).unwrap();
        for (which, pointer) in [
            (0, "/plan/sha256"),
            (0, "/client/sha256"),
            (0, "/child_pid"),
            (0, "/archive_ready"),
            (0, "/spawned_millis"),
            (1, "/self_sha256"),
            (1, "/claim/origin_invocation_id"),
            (1, "/owner/InvocationID"),
            (2, "/child_identity/capabilities_empty"),
            (2, "/child_identity/pid"),
        ] {
            let mut values = [c.clone(), l.clone(), proof.clone()];
            *values[which].pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(
                validate_child(&p, &values[2], &values[0], &values[1], 3000, 1000).is_err(),
                "{which}:{pointer}"
            );
        }
        assert!(validate_child(&p, &proof, &c, &l, 1000, 0).is_err());
        assert!(validate_child(&p, &proof, &c, &l, 400000, 1000).is_err());
        assert!(validate_child(&p, &proof, &c, &l, 3000, 2500).is_err());
    }
}
