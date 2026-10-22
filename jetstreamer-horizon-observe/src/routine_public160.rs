//! Canonical160 delivery through authenticated existing watcher children.
use super::*;
const PROOF: &str =
    "/var/lib/jetstreamer/horizon-epoch160-public-observation-20261022-v1/proof.json";
pub(super) const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch160-public-fleet-reader-20261022-v3/jetstreamer-r2";
pub(super) const READER_SHA: &str =
    "a820019c733f9afb87754ad52deffad07b6d843bdf29069f8c17d6c2d18ae019";
const STATUS: &str = "/home/sol/.jetstreamer-private/r2-status-receipts";
const ORIGIN: &str = "jetstreamer-root-sweep-e160-s1-20261020-v1-r2-e160-160-lane-a-1.service";
const ORIGIN_IID: &str = "f3ec98a134d544e78cb2083f502ed292";
const ARCHIVE: &str = "/home/sol/horizon/epoch-160.jet";
pub(super) fn enabled(p: &Plan) -> bool {
    p.epoch160_delivery
        .as_ref()
        .is_some_and(|s| s.public_observation.is_some())
}
pub(super) fn reader(p: &Plan) -> bool {
    enabled(p) && p.tools.r2.path == Path::new(READER) && p.tools.r2.sha256 == READER_SHA
}
fn read(p: &Plan) -> Result<Value> {
    let b = p
        .epoch160_delivery
        .as_ref()
        .and_then(|s| s.public_observation.as_ref())
        .context("160 public proof absent")?;
    ensure!(
        b.path == Path::new(PROOF) && reader(p),
        "foreign160 public reader/proof"
    );
    let v = bound_json(b, false)?;
    validate_capture(&v, utc_seconds(&p.sample_target_utc)?)?;
    Ok(v)
}
fn validate_capture(v: &Value, target: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-epoch160-public-observation-v1"
            && v["observer_sha256"] == READER_SHA
            && v["observed_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t > 0 && t < target)
            && v["import_receipt_sha256"]
                == "628e3525ec55ecaf7bcbade1c5a26d4afe6fe948a203f73de28a571a6bf40815"
            && v["archive_path"] == ARCHIVE
            && v["archive_bytes"] == 148095631232u64
            && v["archive_inode"] == 99942496u64
            && v["new_resource_samples"] == 0
            && v["archive_hash_performed"] == false
            && v["replay_launch_authorized"] == false
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false
            && v["owners"].as_array().is_some_and(|a| a.len() == 3),
        "160 public proof differs"
    );
    let expected = [
        (
            "full-verification",
            "jetstreamer-horizon-audit-epochs101-181-v4.service",
            "2612e3bb8fe4415b804532ee87d46ea3",
        ),
        (
            "plugin-verification",
            "jetstreamer-horizon-plugin-receipt-watcher-shard-c-v4-fsync.service",
            "89b072dea9cd4167881d060c571be6cf",
        ),
        (
            "upload-readback",
            "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service",
            "e4e455fbd455483282107652ca37b83d",
        ),
    ];
    for (r, (phase, unit, iid)) in v["owners"].as_array().unwrap().iter().zip(expected) {
        ensure!(
            r["phase"] == phase
                && r["unit"]["Id"] == unit
                && r["unit"]["InvocationID"] == iid
                && r["unit"]["NRestarts"] == "0"
                && r["unit"]["ExecStart"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()),
            "160 public watcher differs"
        );
    }
    ensure!(
        v["owners"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["actual_child_start_millis"]
                .as_u64()
                .is_some_and(|t| t > 0)),
        "160 proof has no actual child"
    );
    Ok(())
}
pub(super) fn enable(p: &mut Plan) -> Result<()> {
    ensure!(
        is_101(p)?
            && ((p.sample_target_utc == "2026-10-22T16:28:00Z"
                && p.previous_observer.sha256
                    == "1f5d74eafe10ef5897f137b61e2f8cf403c717c4238348f92bec5830e69908e4")
                || (p.sample_target_utc == "2026-10-22T16:58:00Z"
                    && p.previous_observer
                        .path
                        .ends_with("sample-20261022T162800Z.json")))
            && p.epoch160_delivery.is_some()
            && !enabled(p),
        "160 public handoff must follow accepted1558 cycle"
    );
    let bytes = read_checked(Path::new(PROOF), LIMIT, 0, false)?;
    p.epoch160_delivery.as_mut().unwrap().public_observation = Some(Bound {
        path: PROOF.into(),
        sha256: sha(&bytes),
    });
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    read(p)?;
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    let v = read(p)?;
    let profile = p.epoch160_delivery.as_ref().unwrap();
    let rows = f["pipeline_claims"]
        .as_array_mut()
        .context("160 pipeline census")?;
    // The exact original controller claim is superseded by the canonical-import
    // proof; unrelated history and every other epoch are left untouched.
    for r in rows.iter().filter(|r| r["epoch"] == 160) {
        ensure!(
            (r["phase"] == "controller-import-handoff"
                && r["unit"] == "jetstreamer-epoch160-singleton-20261020-controller-v1-r2.service"
                && r["invocation_id"] == "f07e4e26c28642b8826b13d625edf89c")
                || v["owners"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|o| r["phase"] == o["phase"]
                        && r["unit"] == o["unit"]["Id"]
                        && r["invocation_id"] == o["unit"]["InvocationID"]),
            "160 foreign pipeline cannot be replaced"
        );
    }
    rows.retain(|r| r["epoch"] != 160);
    for o in v["owners"].as_array().unwrap() {
        rows.push(json!({"epoch":160,"phase":o["phase"],"unit":o["unit"]["Id"],"invocation_id":o["unit"]["InvocationID"],"expected_exec_start":o["unit"]["ExecStart"],"evidence":[profile.public_observation,profile.origin_publication]}));
    }
    for o in v["owners"].as_array().unwrap() {
        let units = f["tracked_units"]
            .as_array_mut()
            .context("160 tracked census")?;
        if !units.contains(&o["unit"]["Id"]) {
            units.push(o["unit"]["Id"].clone());
        }
    }
    let gate = &mut f["gates"]["160"];
    ensure!(
        gate["state"] == "post-replay-pipeline",
        "160 public transition cannot weaken another gate"
    );
    gate["next_action"] = json!(
        "Canonical160 import is committed. Authenticate actual160 full/plugin/upload children at each coordinated sample; preserve independent digest-matching receipts and sole global uploader. Matching verified R2sidecar is completion, not a local import or idle watcher. Repair missing downstream ownership/status promptly."
    );
    let b = serde_json::to_value(profile.public_observation.as_ref().unwrap())?;
    let evidence = gate["evidence"]
        .as_array_mut()
        .context("160 gate evidence")?;
    if !evidence.contains(&b) {
        evidence.push(b);
    }
    Ok(())
}
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let b = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&b),
    })
}
pub(super) fn publish(p: &Plan, pipeline: &Value, observer: &Bound) -> Result<Value> {
    let v = read(p)?;
    let profile = p.epoch160_delivery.as_ref().unwrap();
    let fleet: Bound = serde_json::from_value(pipeline["provisional_fleet"].clone())?;
    let ledger = bound_json(&fleet, false)?;
    ensure!(
        ledger["sampled_at_utc"] == p.sample_target_utc
            && ledger["observer_sha256"] == observer.sha256
            && ledger["inventory"]["anomalies"] == 0,
        "160 coordinated fleet differs"
    );
    let ready = ledger["epochs"]
        .as_array()
        .context("160 epoch ledger")?
        .iter()
        .any(|r| r["epoch"] == 160 && r["state"] == "remote-ready");
    if ready {
        child(
            &p.tools.r2,
            &[
                "status-delete".into(),
                "/home/sol/horizon".into(),
                "--epochs".into(),
                "160-160".into(),
                "--receipt-directory".into(),
                STATUS.into(),
                "--archive-receipt-directory".into(),
                "/home/sol/.jetstreamer-private/r2-receipts".into(),
                "--latest-status-publication-receipt".into(),
            ],
            true,
            &p.cycle_directory.join("child-public160-status-delete.json"),
        )?;
        return Ok(
            json!({"provisional_fleet":fleet,"publication_skipped":true,"ready_pair_verified_cleanup":true}),
        );
    }
    let active = ledger["active"].as_array().context("160 active census")?;
    let owner = [
        "upload-readback",
        "plugin-verification",
        "full-verification",
    ]
    .iter()
    .find_map(|phase| {
        active
            .iter()
            .find(|r| r["epoch"] == 160 && r["phase"] == *phase)
    });
    let Some(owner) = owner else {
        return Ok(
            json!({"provisional_fleet":fleet,"publication_skipped":true,"reason":"No authenticated actual160 child; repair downstream/status promptly, never invent a watcher claim"}),
        );
    };
    ensure!(
        v["owners"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["phase"] == owner["phase"]
                && o["unit"]["Id"] == owner["unit"]["Id"]
                && o["unit"]["InvocationID"] == owner["unit"]["InvocationID"]),
        "160 active owner differs"
    );
    let phase = if owner["phase"] == "upload-readback" {
        "upload"
    } else {
        "verification"
    };
    let old = bound_json(&profile.proof, false)?;
    let eta = delivery160::remaining(&old, &p.sample_target_utc)?;
    let target = p
        .cycle_directory
        .join("delivery160-status/sealed/pipeline-plan.json");
    let model = json!({"schema":"jetstreamer-horizon-pipeline-status-plan-v1","epoch":160,"phase":phase,
        "binding":{"unit":owner["unit"]["Id"],"invocation_id":owner["unit"]["InvocationID"],"expected_exec_start":owner["unit"]["ExecStart"],"claim_phase":owner["phase"],"origin_unit":ORIGIN,"origin_invocation_id":ORIGIN_IID,"model_path":target,"model_sha256":"","fleet_path":fleet.path,"fleet_sha256":fleet.sha256},
        "observer":observer,"fleet":fleet,"origin_launch":profile.origin_publication,"estimate_evidence":[profile.proof,profile.public_observation],"estimate_basis":"Canonical160 committed import and actual epoch-specific watcher child; retained43200second downstream deadline anchored to original archive close, no clock reset or watcher-as-child substitution; independent full/plugin/R2readback/sidecar gates remain separate.","estimated_remaining_millis":eta,"jet_path":ARCHIVE,"expected_jet_size_bytes":148095631232u64,"peer_units":[],"receipt_directory":STATUS,"receipt_directory_uid":1001});
    let package =
        delivery198::seal_values(p, "delivery160-status", &[("pipeline-plan.json", model)])?;
    let model = file(package.join("pipeline-plan.json"), true)?;
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
                .join(format!("child-public160-{suffix}.json")),
        )?;
    }
    let digits: String = p
        .sample_target_utc
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let publication = file(
        Path::new(STATUS).join(format!("epoch-160.status-{digits}.json")),
        false,
    )?;
    validate(p, observer, &model, &bound_json(&publication, false)?)?;
    Ok(json!({"provisional_fleet":fleet,"pipeline_plan":model,"publication":publication}))
}
fn validate(p: &Plan, observer: &Bound, model: &Bound, r: &Value) -> Result<()> {
    let m = bound_json(model, true)?;
    let v = read(p)?;
    ensure!(
        m["epoch"] == 160
            && v["owners"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["phase"] == m["binding"]["claim_phase"]
                    && o["unit"]["Id"] == m["binding"]["unit"]
                    && o["unit"]["InvocationID"] == m["binding"]["invocation_id"])
            && r["schema"]
                == "jetstreamer-horizon-r2-status-authenticated-pipeline-publication-receipt-v1"
            && r["bucket"] == BUCKET
            && r["epoch"] == 160
            && r["key"] == "epoch-160.epoch-status.json"
            && r["authenticated_readback"] == true
            && r["status"]["sampled_at_utc"] == p.sample_target_utc
            && r["status"]["phase"] == m["phase"]
            && r["status"]["jet_size_bytes"] == 148095631232u64
            && r["status"]["estimated_remaining_millis"] == m["estimated_remaining_millis"]
            && r["observer_receipt"].as_str() == observer.path.to_str()
            && r["observer_receipt_sha256"] == observer.sha256
            && r["pipeline_binding"]["unit"] == m["binding"]["unit"]
            && r["pipeline_binding"]["invocation_id"] == m["binding"]["invocation_id"]
            && r["pipeline_binding"]["origin_unit"] == ORIGIN
            && r["pipeline_binding"]["origin_invocation_id"] == ORIGIN_IID
            && r["pipeline_binding"]["model_path"].as_str() == model.path.to_str()
            && r["pipeline_binding"]["model_sha256"] == model.sha256,
        "160 public status differs"
    );
    Ok(())
}
pub(super) fn validate_completed(p: &Plan, c: &Value) -> Result<()> {
    let d = &c["epoch160_delivery"];
    let fleet: Bound = serde_json::from_value(d["provisional_fleet"].clone())?;
    ensure!(
        d["provisional_fleet"] == c["epoch198_delivery"]["provisional_fleet"],
        "160 used another coordinated fleet"
    );
    if d["publication_skipped"] == true {
        let f = bound_json(&fleet, false)?;
        ensure!(
            d["publication"].is_null()
                && (d["ready_pair_verified_cleanup"] == true
                    || !f["active"]
                        .as_array()
                        .context("160 skipped active census")?
                        .iter()
                        .any(|r| r["epoch"] == 160)),
            "160 active work skipped without repair"
        );
        return Ok(());
    }
    let o: Bound = serde_json::from_value(c["observer"].clone())?;
    let m: Bound = serde_json::from_value(d["pipeline_plan"].clone())?;
    let r: Bound = serde_json::from_value(d["publication"].clone())?;
    ensure!(
        m.path
            == p.cycle_directory
                .join("delivery160-status/sealed/pipeline-plan.json"),
        "foreign160 public model"
    );
    validate(p, &o, &m, &bound_json(&r, false)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn capture() -> Value {
        let rows=[("full-verification","jetstreamer-horizon-audit-epochs101-181-v4.service","2612e3bb8fe4415b804532ee87d46ea3"),("plugin-verification","jetstreamer-horizon-plugin-receipt-watcher-shard-c-v4-fsync.service","89b072dea9cd4167881d060c571be6cf"),("upload-readback","horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service","e4e455fbd455483282107652ca37b83d")].map(|(phase,unit,iid)|json!({"phase":phase,"unit":{"Id":unit,"InvocationID":iid,"NRestarts":"0","ExecStart":"exact sealed command"},"actual_child_start_millis":1}));
        json!({"schema":"jetstreamer-epoch160-public-observation-v1","observer_sha256":READER_SHA,"observed_unix_seconds":1,"import_receipt_sha256":"628e3525ec55ecaf7bcbade1c5a26d4afe6fe948a203f73de28a571a6bf40815","archive_path":ARCHIVE,"archive_bytes":148095631232u64,"archive_inode":99942496,"new_resource_samples":0,"archive_hash_performed":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,"owners":rows})
    }
    #[test]
    fn public_handoff_is_exact_non_authorizing_and_never_backdated() {
        let v = capture();
        validate_capture(&v, 2).unwrap();
        assert!(validate_capture(&v, 1).is_err());
        for key in [
            "schema",
            "observer_sha256",
            "import_receipt_sha256",
            "archive_path",
            "archive_bytes",
            "archive_inode",
            "new_resource_samples",
            "archive_hash_performed",
            "publication_authorized",
            "r2_mutations",
            "replay_launch_authorized",
        ] {
            let mut bad = v.clone();
            bad[key] = json!("foreign");
            assert!(validate_capture(&bad, 2).is_err(), "{key}");
        }
        let mut bad = v.clone();
        for o in bad["owners"].as_array_mut().unwrap() {
            o["actual_child_start_millis"] = Value::Null;
        }
        assert!(validate_capture(&bad, 2).is_err());
        for key in ["Id", "InvocationID", "NRestarts", "ExecStart"] {
            let mut bad = v.clone();
            bad["owners"][0]["unit"][key] = json!("");
            assert!(validate_capture(&bad, 2).is_err(), "{key}");
        }
        let mut bad = v;
        bad["owners"].as_array_mut().unwrap().swap(0, 1);
        assert!(validate_capture(&bad, 2).is_err());
    }
}
