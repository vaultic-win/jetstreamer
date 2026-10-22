//! Exact160 terminal handoff. Metadata only; no replay or archive authority.
use super::*;

pub(super) const UNIT: &str =
    "jetstreamer-root-sweep-e160-s1-20261020-v1-r2-e160-160-lane-a-1.service";
const IID: &str = "f3ec98a134d544e78cb2083f502ed292";
const CONTROLLER: &str = "f07e4e26c28642b8826b13d625edf89c";
const ORIGINAL_ARCHIVE: &str = "/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1/lane-a/private/destination-586105dbe82bb0446e1b4c9295bfb7f16e3fc6f70ff439cab2672ef48275f8db/work/root-cohort-160-160/run-1237930-1792459999139141808/archives/epoch-160.jet";
const ARCHIVE: &str =
    "/home/sol/.jetstreamer-private/epoch160-singleton-20261020-v1/lane-a/output/epoch-160.jet";
const OWNER: &str = "jetstreamer-epoch160-singleton-20261020-controller-v1-r2.service";
const HANDOFF: &str =
    "/var/lib/jetstreamer/horizon-epoch160-delivery-observations-20261022-v1/handoff.json";
const LENGTH: u64 = 148095631232;
const PROOF: &str =
    "/var/lib/jetstreamer/horizon-epoch160-delivery-observations-20261022-v1/proof.json";
const PROOF_SHA: &str = "032dfc226e2c831ba82cdeaf84892dd49659952ff28a0062743adf49a1c1f564";
const STATUS: &str = "/home/sol/.jetstreamer-private/r2-status-receipts";
pub(super) const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch160-delivery-fleet-reader-20261022-v2/jetstreamer-r2";
pub(super) const READER_SHA: &str =
    "05fc78377ee6cf76f2d6d71f3ec7fa97f90facaf31bf67bb1db517c699432699";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    pub(super) proof: Bound,
    handoff: Bound,
    pub(super) origin_publication: Bound,
    origin_observer: Bound,
    delayed_recovery: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) public_observation: Option<Bound>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) timed_upload: bool,
}
pub(super) fn reader(p: &Plan) -> bool {
    p.epoch160_delivery.is_some()
        && native141::acquisition_enabled(p)
        && p.assembly144_scans.is_some()
        && p.public198_delivery.is_some()
        && ((p.tools.r2.path == Path::new(READER) && p.tools.r2.sha256 == READER_SHA)
            || public160::reader(p))
}
fn range(r: &Value) -> Result<()> {
    ensure!(
        r["range"] == "160"
            && r["epochs"] == json!([160])
            && r["expected_producer_invocation_id"] == IID
            && r["expected_controller_invocation_id"] == CONTROLLER
            && r["terminal_slot"] == 69551999u64
            && r["epoch_additional_replay_slots"] == json!({"160":0})
            && r["epoch_downstream_allowance_seconds"] == json!({"160":43200})
            && r["archive_directory"].as_str()
                == Path::new(ORIGINAL_ARCHIVE).parent().and_then(Path::to_str)
            && r.get("elapsed_execution_millis").is_none(),
        "160 predecessor scope/budget changed"
    );
    Ok(())
}
fn checked_proof(v: &Value, target: u64) -> Result<()> {
    let e = &v["evidence"];
    let events = &e["events"];
    ensure!(
        v["schema"] == "jetstreamer-epoch160-delivery-proof-v1"
            && v["observer_sha256"]
                == "16883ab31a8dba5eac787b523d9723390ea183472797bf9a4553589aebe4cb42"
            && v["observed_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t > 0 && t < target)
            && v["resource_samples"] == 0
            && v["publication_authorized"] == false
            && v["replay_launch_authorized"] == false
            && v["r2_mutations"] == false
            && e["schema"] == "jetstreamer-epoch160-finalization-observation-v1"
            && e["owner"]["Id"] == UNIT
            && e["owner"]["InvocationID"] == IID
            && e["owner"]["MainPID"] == "1237930"
            && e["owner"]["NRestarts"] == "0"
            && e["owner"]["ActiveState"] == "active"
            && e["owner"]["SubState"] == "running"
            && e["archive"]["path"] == ORIGINAL_ARCHIVE
            && e["archive"]["bytes"] == LENGTH
            && events["schema"] == "jetstreamer-epoch160-finalization-events-v1"
            && events["unit"] == UNIT
            && events["invocation_id"] == IID
            && events["terminal_slot"] == 69551999u64
            && events["trusted_root_slot"] == 69551776u64
            && events["archive_close_bytes"] == LENGTH
            && events["independent_full_verification_passed"] == false
            && events["publication_authorized"] == false
            && events["r2_mutations"] == false,
        "160 proof owner/terminal/authority differs"
    );
    Ok(())
}
fn proof(p: &Plan) -> Result<Value> {
    let s = p
        .epoch160_delivery
        .as_ref()
        .context("160 profile missing")?;
    ensure!(
        is_101(p)?
            && reader(p)
            && !p.expected_epochs.contains(&160)
            && s.proof.path == Path::new(PROOF)
            && s.proof.sha256 == PROOF_SHA,
        "160 profile reader/census/proof differs"
    );
    let mut v = bound_json(&s.proof, false)?;
    checked_proof(&v, utc_seconds(&p.sample_target_utc)?)?;
    let origin = bound_json(&s.origin_publication, false)?;
    ensure!(
        s.origin_publication.path.parent() == Some(Path::new(STATUS))
            && origin["schema"]
                == "jetstreamer-horizon-r2-status-authenticated-publication-receipt-v1"
            && origin["bucket"] == BUCKET
            && origin["epoch"] == 160
            && origin["status"]["epoch"] == 160
            && origin["status"]["phase"] == "replay"
            && origin["authenticated_readback"] == true
            && origin["producer_invocation_id"] == IID
            && origin["controller_invocation_id"] == CONTROLLER
            && origin["observer_receipt"].as_str() == s.origin_observer.path.to_str()
            && origin["observer_receipt_sha256"] == s.origin_observer.sha256,
        "160 authenticated original clock differs"
    );
    let o = bound_json(&s.origin_observer, false)?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["recorded_at_utc"] == origin["status"]["sampled_at_utc"]
            && o["replays"]
                .as_array()
                .context("160 origin census")?
                .iter()
                .filter(|r| r["range"] == "160"
                    && r["invocation_binding_stable"] == true
                    && r["producer_after"]["unit"] == UNIT
                    && r["producer_after"]["invocation_id"] == IID
                    && r["controller_after"]["invocation_id"] == CONTROLLER)
                .count()
                == 1,
        "160 original observer differs"
    );
    // This is retained terminal/clock history, not current custody. The actual
    //fleet reader and status publisher independently revalidate a live owner
    //and its current archive; an ended handoff must not freeze healthy ranges.
    ensure!(
        s.handoff.path == Path::new(HANDOFF),
        "foreign160 controller handoff path"
    );
    let h = bound_json(&s.handoff, false)?;
    ensure!(
        h["schema"] == "jetstreamer-epoch160-delivery-proof-v1"
            && h["observer_sha256"] == READER_SHA
            && h["resource_samples"] == 0
            && h["observed_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t < utc_seconds(&p.sample_target_utc).unwrap_or(0))
            && h["publication_authorized"] == false
            && h["r2_mutations"] == false
            && h["evidence"]["schema"] == "jetstreamer-epoch160-controller-import-handoff-v1"
            && h["evidence"]["controller"]["Id"] == OWNER
            && h["evidence"]["controller"]["InvocationID"] == CONTROLLER
            && h["evidence"]["terminal_evidence"] == v["evidence"]["events"]
            && h["evidence"]["archive_path"] == ARCHIVE
            && h["evidence"]["archive_bytes"] == LENGTH
            && h["evidence"]["source_receipt_sha256"]
                == "92c949f845d3c554cd2c6026b5ef970ece11425bdfe8ffc28eba39bf5d2bc237",
        "160 controller handoff differs"
    );
    v["controller_handoff"] = h["evidence"].clone();
    Ok(v)
}
pub(super) fn effective_model(p: &Plan, model: &Value) -> Result<Value> {
    if p.epoch160_delivery.is_none() {
        return Ok(model.clone());
    }
    proof(p)?;
    apply_model(model, &p.epoch160_delivery.as_ref().unwrap().proof)
}
fn apply_model(model: &Value, proof: &Bound) -> Result<Value> {
    let mut out = model.clone();
    let rows = out["ranges"].as_array_mut().context("160 model ranges")?;
    ensure!(
        rows.iter().filter(|r| r["range"] == "160").count() <= 1,
        "duplicate160 range"
    );
    for r in rows.iter() {
        if r["range"] == "160" {
            range(r)?;
        } else {
            ensure!(
                !r["epochs"]
                    .as_array()
                    .is_some_and(|a| a.contains(&json!(160))),
                "160 mixed cohort"
            );
        }
    }
    rows.retain(|r| r["range"] != "160");
    out["expected_observer_ranges"]
        .as_array_mut()
        .context("160 observer census")?
        .retain(|r| r != "160");
    let b = serde_json::to_value(proof)?;
    let evidence = out["evidence"]
        .as_array_mut()
        .context("160 model evidence")?;
    if !evidence.contains(&b) {
        evidence.push(b);
    }
    Ok(out)
}
pub(super) fn interval(p: &Plan) -> Result<Option<u64>> {
    if !p
        .epoch160_delivery
        .as_ref()
        .is_some_and(|s| s.delayed_recovery)
    {
        return Ok(None);
    }
    ensure!(
        p.sample_target_utc == "2026-10-22T15:58:00Z"
            && p.previous_observer.sha256
                == "50ac2a4f84f258c709b8cff4d333488e6a2cf483f85edc4dc2901dba2fb53c21"
            && p.previous_observer
                .path
                .ends_with("sample-20261022T145800Z.json"),
        "160 delayed cadence differs"
    );
    Ok(Some(3600))
}
pub(super) fn consume(p: &mut Plan) -> Result<()> {
    if p.epoch160_delivery
        .as_ref()
        .is_some_and(|s| s.delayed_recovery)
    {
        ensure!(
            p.sample_target_utc == "2026-10-22T16:28:00Z"
                && p.previous_observer
                    .path
                    .ends_with("sample-20261022T155800Z.json"),
            "160 successor cadence differs"
        );
        p.epoch160_delivery.as_mut().unwrap().delayed_recovery = false;
    }
    Ok(())
}
pub(super) fn enable(
    p: &mut Plan,
    config: &mut Value,
    model: &Value,
    completion: &Value,
) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.epoch160_delivery.is_none()
            && p.expected_epochs.contains(&160)
            && native141::acquisition_reader(p)
            && p.publication144.is_none()
            && p.sample_target_utc == "2026-10-22T15:28:00Z"
            && p.previous_observer.sha256
                == "50ac2a4f84f258c709b8cff4d333488e6a2cf483f85edc4dc2901dba2fb53c21",
        "160 handoff is not exact accepted1458 successor"
    );
    range(
        model["ranges"]
            .as_array()
            .context("160 predecessor ranges")?
            .iter()
            .find(|r| r["range"] == "160")
            .context("160 range absent")?,
    )?;
    let mut origins = Vec::new();
    for b in completion["status_publications"]
        .as_array()
        .context("160 origin status census")?
    {
        let b: Bound = serde_json::from_value(b.clone())?;
        if bound_json(&b, false)?["epoch"] == 160 {
            origins.push(b);
        }
    }
    ensure!(origins.len() == 1, "160 origin status missing/duplicate");
    let prior = bound_json(&p.previous_fleet, false)?;
    ensure!(
        prior["epochs"]
            .as_array()
            .context("160 prior fleet")?
            .iter()
            .filter(|r| r["epoch"] == 160 && r["state"] == "live-replay")
            .count()
            == 1,
        "160 predecessor not live replay"
    );
    p.epoch160_delivery = Some(Profile {
        proof: Bound {
            path: PROOF.into(),
            sha256: PROOF_SHA.into(),
        },
        handoff: bound(PathBuf::from(HANDOFF), false)?,
        origin_publication: origins.remove(0),
        origin_observer: p.previous_observer.clone(),
        delayed_recovery: true,
        public_observation: None,
        timed_upload: false,
    });
    p.expected_epochs.retain(|e| *e != 160);
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    for path in [&mut p.observer, &mut p.estimate_output, &mut p.fleet_output] {
        *path = PathBuf::from(
            path.to_str()
                .context("160 retime path")?
                .replace("20261022T152800Z", "20261022T155800Z"),
        );
    }
    p.sample_target_utc = "2026-10-22T15:58:00Z".into();
    let rows = config["replays"]
        .as_array_mut()
        .context("160 observer rows")?;
    ensure!(
        rows.iter().filter(|r| r["range"] == "160").count() == 1,
        "160 replay config missing/duplicate"
    );
    rows.retain(|r| r["range"] != "160");
    config["not_before_utc"] = json!(p.sample_target_utc);
    config["output"] = json!(p.observer);
    p.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
    interval(p)?;
    proof(p)?;
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, fleet: &mut Value) -> Result<()> {
    if public160::enabled(p) {
        return public160::derive_fleet(p, fleet);
    }
    let Some(s) = &p.epoch160_delivery else {
        return Ok(());
    };
    let v = proof(p)?;
    if let Some(importer) = v["controller_handoff"]["importer"]["Id"].as_str() {
        let tracked = fleet["tracked_units"]
            .as_array_mut()
            .context("160 importer census")?;
        let unit = json!(importer);
        if !tracked.contains(&unit) {
            tracked.push(unit);
        }
    }
    let claim = json!({"epoch":160,"phase":"controller-import-handoff","unit":OWNER,"invocation_id":CONTROLLER,
        "expected_exec_start":v["controller_handoff"]["controller"]["ExecStart"],"evidence":[s.proof,s.handoff,s.origin_publication]});
    let claims = fleet["pipeline_claims"]
        .as_array_mut()
        .context("160 pipeline census")?;
    let current: Vec<_> = claims.iter().filter(|c| c["epoch"] == 160).collect();
    if current.is_empty() {
        claims.push(claim);
    } else {
        ensure!(
            current.len() == 1 && *current[0] == claim,
            "160 pipeline replaced/duplicated"
        );
    }
    let gate = &mut fleet["gates"]["160"];
    ensure!(
        matches!(
            gate["state"].as_str(),
            Some("live-replay" | "staged-admissible" | "post-replay-pipeline")
        ),
        "160 cannot weaken qualification/failure gate"
    );
    gate["state"] = json!("post-replay-pipeline");
    gate["next_action"] = json!(
        "Track160 controller-owned staged/importing handoff with original producer clock. On terminal controller/canonical import, promptly authenticate existing160 verifier/upload children and repair status; do not present the old owner projection as fresh, restart replay, or infer remote readiness. Preserve independent gates."
    );
    for b in [&s.proof, &s.handoff, &s.origin_publication] {
        let b = serde_json::to_value(b)?;
        let a = gate["evidence"]
            .as_array_mut()
            .context("160 gate evidence")?;
        if !a.contains(&b) {
            a.push(b);
        }
    }
    Ok(())
}
pub(super) fn remaining(v: &Value, target: &str) -> Result<u64> {
    let close = v["evidence"]["events"]["events"][3]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("160 close timestamp")?
        .parse::<u64>()?
        / 1000;
    let sample = utc_seconds(target)?
        .checked_mul(1000)
        .context("160 sample overflow")?;
    ensure!(close <= sample, "160 close after sample");
    close
        .checked_add(43200000)
        .and_then(|end| end.checked_sub(sample))
        .filter(|n| *n > 0)
        .context("160 downstream budget exhausted; qualify revised estimate, no zero clamp")
}
pub(super) fn publish(p: &Plan, pipeline: &Value, observer: &Bound) -> Result<Value> {
    if public160::enabled(p) {
        return public160::publish(p, pipeline, observer);
    }
    let Some(s) = &p.epoch160_delivery else {
        return Ok(Value::Null);
    };
    let v = proof(p)?;
    let fleet: Bound = serde_json::from_value(pipeline["provisional_fleet"].clone())?;
    let f = bound_json(&fleet, false)?;
    let matching = f["active"]
        .as_array()
        .context("160 active census")?
        .iter()
        .filter(|r| {
            r["epoch"] == 160
                && r["phase"] == "controller-import-handoff"
                && r["unit"]["Id"] == OWNER
                && r["unit"]["InvocationID"] == CONTROLLER
        })
        .count();
    if matching == 0 {
        return Ok(
            json!({"provisional_fleet":fleet,"publication_skipped":true,"reason":"Original160 controller handoff ended; exact downstream child qualification/status repair is open. Other healthy replay publications continue; old160 projection is not current."}),
        );
    }
    ensure!(
        f["sampled_at_utc"] == p.sample_target_utc
            && f["observer_sha256"] == observer.sha256
            && f["inventory"]["anomalies"] == 0
            && f["active"]
                .as_array()
                .context("160 active census")?
                .iter()
                .filter(|r| r["epoch"] == 160
                    && r["phase"] == "controller-import-handoff"
                    && r["unit"]["Id"] == OWNER
                    && r["unit"]["InvocationID"] == CONTROLLER)
                .count()
                == 1,
        "160 needs exact active owner in coordinated fleet"
    );
    let target = p
        .cycle_directory
        .join("delivery160-status/sealed/pipeline-plan.json");
    let eta = remaining(&v, &p.sample_target_utc)?;
    let value = json!({"schema":"jetstreamer-horizon-pipeline-status-plan-v1","epoch":160,"phase":"publication",
        "binding":{"unit":OWNER,"invocation_id":CONTROLLER,"expected_exec_start":v["controller_handoff"]["controller"]["ExecStart"],"claim_phase":"controller-import-handoff","origin_unit":UNIT,"origin_invocation_id":IID,"model_path":target,"model_sha256":"","fleet_path":fleet.path,"fleet_sha256":fleet.sha256},
        "observer":observer,"fleet":fleet,"origin_launch":s.origin_publication,"estimate_evidence":[s.proof,s.handoff],
        "estimate_basis":"Exact160 clean producer terminal, committed lane archive and independently reauthenticated controller-owned staged/importing handoff; retained43200second downstream budget anchored to real archive close, including source rehash/import, independent full/plugin checks, uploader/readback/source revalidation/sidecar; original producer elapsed clock retained.",
        "estimated_remaining_millis":eta,"jet_path":ARCHIVE,"expected_jet_size_bytes":LENGTH,"peer_units":[],"receipt_directory":STATUS,"receipt_directory_uid":1001});
    let sealed =
        delivery198::seal_values(p, "delivery160-status", &[("pipeline-plan.json", value)])?;
    let model = bound(sealed.join("pipeline-plan.json"), true)?;
    for (suffix, check) in [("check", true), ("publish", false)] {
        let mut args = vec![
            "status-publish-pipeline".into(),
            model.path.display().to_string(),
            "--plan-sha256".into(),
            model.sha256.clone(),
        ];
        if check {
            args.push("--check-only".into());
        }
        child(
            &p.tools.r2,
            &args,
            !check,
            &p.cycle_directory
                .join(format!("child-delivery160-{suffix}.json")),
        )?;
    }
    let digits: String = p
        .sample_target_utc
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let publication = bound(
        Path::new(STATUS).join(format!("epoch-160.status-{digits}.json")),
        false,
    )?;
    validate_publication(p, observer, &model, &bound_json(&publication, false)?)?;
    Ok(json!({"provisional_fleet":fleet,"pipeline_plan":model,"publication":publication}))
}
fn bound(path: PathBuf, immutable: bool) -> Result<Bound> {
    let b = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&b),
    })
}
fn validate_publication(p: &Plan, o: &Bound, m: &Bound, r: &Value) -> Result<()> {
    let v = bound_json(m, true)?;
    ensure!(
        r["schema"]
            == "jetstreamer-horizon-r2-status-authenticated-pipeline-publication-receipt-v1"
            && r["bucket"] == BUCKET
            && r["epoch"] == 160
            && r["key"] == "epoch-160.epoch-status.json"
            && r["authenticated_readback"] == true
            && r["status"]["epoch"] == 160
            && r["status"]["phase"] == "publication"
            && r["status"]["sampled_at_utc"] == p.sample_target_utc
            && r["status"]["jet_size_bytes"] == LENGTH
            && r["status"]["estimated_remaining_millis"] == v["estimated_remaining_millis"]
            && r["status"]["elapsed_execution_millis"].as_u64().is_some()
            && r["observer_receipt"].as_str() == o.path.to_str()
            && r["observer_receipt_sha256"] == o.sha256
            && r["pipeline_binding"]["unit"] == OWNER
            && r["pipeline_binding"]["invocation_id"] == CONTROLLER
            && r["pipeline_binding"]["origin_unit"] == UNIT
            && r["pipeline_binding"]["origin_invocation_id"] == IID
            && r["pipeline_binding"]["claim_phase"] == "controller-import-handoff"
            && r["pipeline_binding"]["model_path"].as_str() == m.path.to_str()
            && r["pipeline_binding"]["model_sha256"] == m.sha256
            && r["pipeline_binding"]["fleet_path"] == v["fleet"]["path"]
            && r["pipeline_binding"]["fleet_sha256"] == v["fleet"]["sha256"],
        "160 status receipt differs"
    );
    Ok(())
}
pub(super) fn validate_completed(p: &Plan, c: &Value) -> Result<()> {
    if public160::enabled(p) {
        return public160::validate_completed(p, c);
    }
    if p.epoch160_delivery.is_none() {
        ensure!(c["epoch160_delivery"].is_null(), "unexpected160 completion");
        return Ok(());
    }
    let d = &c["epoch160_delivery"];
    ensure!(
        d["provisional_fleet"] == c["epoch198_delivery"]["provisional_fleet"],
        "160 used another fleet sample"
    );
    if d["publication_skipped"] == true {
        let fleet: Bound = serde_json::from_value(d["provisional_fleet"].clone())?;
        let f = bound_json(&fleet, false)?;
        ensure!(
            d["publication"].is_null()
                && f["sampled_at_utc"] == p.sample_target_utc
                && !f["active"]
                    .as_array()
                    .context("160 skipped active census")?
                    .iter()
                    .any(|r| r["epoch"] == 160),
            "live160 cannot be skipped"
        );
        return Ok(());
    }
    let m: Bound = serde_json::from_value(d["pipeline_plan"].clone())?;
    let r: Bound = serde_json::from_value(d["publication"].clone())?;
    let o: Bound = serde_json::from_value(c["observer"].clone())?;
    ensure!(
        m.path
            == p.cycle_directory
                .join("delivery160-status/sealed/pipeline-plan.json"),
        "foreign160 model"
    );
    validate_publication(p, &o, &m, &bound_json(&r, false)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Bound {
        Bound {
            path: PROOF.into(),
            sha256: PROOF_SHA.into(),
        }
    }
    fn model() -> Value {
        json!({"ranges":[{"range":"152-153","epochs":[152,153],"keep":u64::MAX},
            {"range":"160","epochs":[160],"expected_producer_invocation_id":IID,
             "expected_controller_invocation_id":CONTROLLER,"terminal_slot":69551999,
             "epoch_additional_replay_slots":{"160":0},"epoch_downstream_allowance_seconds":{"160":43200},
             "archive_directory":Path::new(ORIGINAL_ARCHIVE).parent()},
            {"range":"191-194","epochs":[191,192,193,194],"keep":u64::MAX}],
            "expected_observer_ranges":["152-153","160","191-194"],"evidence":[]})
    }
    #[test]
    fn singleton_handoff_preserves_every_other_range_and_is_idempotent() {
        let m = model();
        let out = apply_model(&m, &binding()).unwrap();
        assert_eq!(out["ranges"], json!([m["ranges"][0], m["ranges"][2]]));
        assert_eq!(
            out["expected_observer_ranges"],
            json!(["152-153", "191-194"])
        );
        assert_eq!(out["evidence"], json!([binding()]));
        assert_eq!(apply_model(&out, &binding()).unwrap(), out);
        for key in [
            "expected_producer_invocation_id",
            "expected_controller_invocation_id",
            "terminal_slot",
            "archive_directory",
            "epochs",
            "epoch_downstream_allowance_seconds",
            "epoch_additional_replay_slots",
        ] {
            let mut bad = m.clone();
            bad["ranges"][1][key] = json!("foreign");
            assert!(apply_model(&bad, &binding()).is_err(), "{key}");
        }
        let mut bad = m.clone();
        bad["ranges"][0]["epochs"] = json!([152, 160]);
        assert!(apply_model(&bad, &binding()).is_err());
        let mut bad = m;
        let duplicate = bad["ranges"][1].clone();
        bad["ranges"].as_array_mut().unwrap().push(duplicate);
        assert!(apply_model(&bad, &binding()).is_err());
    }
    #[test]
    fn downstream_budget_is_close_anchored_and_never_zero_clamped() {
        let v = json!({"evidence":{"events":{"events":[{}, {}, {}, {"__REALTIME_TIMESTAMP":"1792681958830997"}]}}});
        assert_eq!(remaining(&v, "2026-10-22T15:58:00Z").unwrap(), 40478830);
        assert!(remaining(&v, "2026-10-22T15:12:00Z").is_err());
        assert!(remaining(&v, "2026-10-23T03:13:00Z").is_err());
    }
    fn plan() -> Plan {
        let mut p = super::super::tests::fixture101().0;
        p.epoch160_delivery = Some(Profile {
            proof: binding(),
            handoff: binding(),
            origin_publication: binding(),
            origin_observer: binding(),
            delayed_recovery: true,
            public_observation: None,
            timed_upload: false,
        });
        p.sample_target_utc = "2026-10-22T15:58:00Z".into();
        p.previous_observer=Bound{path:"/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261022T145800Z.json".into(),sha256:"50ac2a4f84f258c709b8cff4d333488e6a2cf483f85edc4dc2901dba2fb53c21".into()};
        p
    }
    #[test]
    fn delayed_cadence_is_exact_and_consumed_only_by_genuine_successor() {
        let mut p = plan();
        assert_eq!(interval(&p).unwrap(), Some(3600));
        p.sample_target_utc = "2026-10-22T16:28:00Z".into();
        assert!(interval(&p).is_err());
        assert!(consume(&mut p).is_err());
        p.previous_observer.path="/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261022T155800Z.json".into();
        consume(&mut p).unwrap();
        assert_eq!(interval(&p).unwrap(), None);
    }
    #[test]
    fn source_wires_real_runtime_model_fleet_publication_and_completion() {
        let s = include_str!("routine_cycle.rs");
        for call in [
            "delivery160::effective_model(",
            "delivery160::derive_fleet(p, &mut fleet)?",
            "delivery160::publish(p, &pipeline, &observer)?",
            "\"epoch160_delivery\":delivery160_status",
        ] {
            assert!(s.contains(call), "{call}");
        }
        let s = include_str!("routine_next.rs");
        assert!(s.contains("delivery160::validate_completed(p, &completion)?"));
        assert!(s.contains("delivery160::consume(&mut next)?"));
    }
}
