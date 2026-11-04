//! Coordinated publication ETA; never samples resources or changes archives.
use super::*;
const CALIBRATION: &str =
    "/var/lib/jetstreamer/horizon-publication144-calibration-20261022-v1/eta.json";
const CALIBRATION_SHA: &str = "bc2c99fc95e795424cfa9a1f383765d37d34dcc35b35945d7e9cb2943b135dd7";
const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch144-assembly-only-20261022-v2/epoch-144-assembly-only-v4.jet";
const LENGTH: u64 = 109177480876;
fn bound(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn calibration() -> Result<(Bound, u64)> {
    let b = Bound {
        path: CALIBRATION.into(),
        sha256: CALIBRATION_SHA.into(),
    };
    let v = bound_json(&b, false)?;
    ensure!(
        v["schema"] == "jetstreamer-exact144-delivery-timing-calibration-v1"
            && v["tool_sha256"]
                == "91ff592e5bd6579c80c5890aa2cb44a70eaf3180bbbf9512d8f3375ddf993438"
            && v["source_epoch"] == 198
            && v["estimate"]["target_archive_bytes"] == LENGTH
            && v["estimate"]["publication_to_sidecar_millis"] == 4979863
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false,
        "publication 144 calibration changed"
    );
    Ok((b, 4979863))
}
fn start(events: &[Value], iid: &str) -> Result<u64> {
    let matches: Vec<_> = events
        .iter()
        .filter(|e| {
            e["UNIT"] == UNIT
                && e["INVOCATION_ID"] == iid
                && e["_PID"] == "1"
                && e["_UID"] == "0"
                && e["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("Starting "))
        })
        .collect();
    ensure!(
        matches.len() == 1,
        "publisher manager start is missing/ambiguous"
    );
    Ok(matches[0]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("publisher manager timestamp")?
        .parse::<u64>()?
        / 1000)
}
fn manager_start(iid: &str) -> Result<u64> {
    let o = Command::new("/usr/bin/journalctl")
        .args([
            "_PID=1",
            "_UID=0",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={iid}"),
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 1 << 20,
        "publisher manager journal unreadable/oversized"
    );
    let events: Vec<Value> = std::str::from_utf8(&o.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    start(&events, iid)
}
fn remaining(start: u64, sample: u64, budget: u64) -> Result<u64> {
    ensure!(start <= sample, "publisher starts after coordinated sample");
    let n = start
        .checked_add(budget)
        .and_then(|n| n.checked_sub(sample))
        .context(
            "publication ETA overdue or overflow; diagnose slowdown, do not reset countdown",
        )?;
    ensure!(
        n > 0,
        "publication ETA overdue; diagnose before replacing status"
    );
    Ok(n)
}
pub(crate) fn publish(p: &Plan, prior_pipeline: &Value, observer: &Bound) -> Result<Value> {
    publish_using(p, prior_pipeline, observer, &p.tools.r2)
}
pub(crate) fn publish_using(
    p: &Plan,
    prior_pipeline: &Value,
    observer: &Bound,
    writer: &Bound,
) -> Result<Value> {
    let Some(profile) = &p.publication144 else {
        return Ok(json!({"enabled":false}));
    };
    validate(p)?;
    if uploading(p) {
        return upload::publish(p, prior_pipeline, observer);
    }
    let provisional: Bound = serde_json::from_value(prior_pipeline["provisional_fleet"].clone())?;
    let ledger = bound_json(&provisional, false)?;
    ensure!(
        ledger["sampled_at_utc"] == p.sample_target_utc
            && ledger["observer_sha256"] == observer.sha256,
        "publication status needs exact coordinated fleet"
    );
    let found: Vec<_> = ledger["active"]
        .as_array()
        .context("pipeline active census")?
        .iter()
        .filter(|e| e["epoch"] == 144 && e["phase"] == "local-publication")
        .collect();
    if found.is_empty() {
        return Ok(
            json!({"provisional_fleet":provisional,"publication_skipped":true,"reason":"No active exact 144 local publisher; reconcile terminal/upload stage promptly, no replay ETA invented"}),
        );
    }
    ensure!(
        found.len() == 1 && found[0]["unit"]["Id"] == UNIT,
        "unexpected or overlapping 144publisher"
    );
    let u = &found[0]["unit"];
    let launch = bound_json(&profile.launch, true)?;
    ensure!(
        u["InvocationID"] == launch["claim"]["invocation_id"],
        "publication status owner changed"
    );
    let (calibration, budget) = calibration()?;
    let stamp = utc_seconds(&p.sample_target_utc)?
        .checked_mul(1000)
        .context("sample overflow")?;
    let eta = remaining(
        manager_start(u["InvocationID"].as_str().context("publisher IID")?)?,
        stamp,
        budget,
    )?;
    let target = p
        .cycle_directory
        .join("publication144-status/sealed/pipeline-plan.json");
    let model = json!({"schema":"jetstreamer-horizon-pipeline-status-plan-v1","epoch":144,"phase":"publication",
        "binding":{"unit":UNIT,"invocation_id":u["InvocationID"],"expected_exec_start":u["ExecStart"],"claim_phase":"local-publication","origin_unit":UNIT,"origin_invocation_id":u["InvocationID"],"model_path":target,"model_sha256":"","fleet_path":provisional.path,"fleet_sha256":provisional.sha256},
        "observer":observer,"fleet":provisional,"origin_launch":profile.launch,"estimate_evidence":[calibration,profile.launch],
        "estimate_basis":"Exact 198 hash/upload/readback calibration scaled by complete 144/198 bytes, three independent import pass allowances plus separate R2 hash/upload/readback/source-revalidation/sidecar and 10min dispatch. Deadline anchored once to the exact 144 canonical-artifact publisher manager start, no countdown reset.",
        "estimated_remaining_millis":eta,"jet_path":SOURCE,"expected_jet_size_bytes":LENGTH,"peer_units":[],
        "receipt_directory":"/home/sol/.jetstreamer-private/r2-status-receipts","receipt_directory_uid":1001});
    let package =
        delivery198::seal_values(p, "publication144-status", &[("pipeline-plan.json", model)])?;
    let model = bound(package.join("pipeline-plan.json"), true)?;
    for (name, check) in [("check", true), ("publish", false)] {
        let mut args = vec![
            "status-publish-pipeline".into(),
            model.path.display().to_string(),
            "--plan-sha256".into(),
            model.sha256.clone(),
        ];
        if check {
            args.push("--check-only".into());
        }
        let capture = p
            .cycle_directory
            .join(format!("child-publication144-{name}.json"));
        if let Err(e) = child(writer, &args, !check, &capture) {
            return Ok(
                json!({"provisional_fleet":provisional,"publication_skipped":true,"failed_child":bound(capture,false)?,"reason":format!("Exact 144 status needs prompt repair: {e:#}"),"archive_mutations":false}),
            );
        }
    }
    let digits: String = p
        .sample_target_utc
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let publication = bound(
        PathBuf::from(format!(
            "/home/sol/.jetstreamer-private/r2-status-receipts/epoch-144.status-{digits}.json"
        )),
        false,
    )?;
    validate_publication(
        &p.sample_target_utc,
        &model,
        &bound_json(&model, true)?,
        &bound_json(&publication, false)?,
    )?;
    Ok(json!({"provisional_fleet":provisional,"pipeline_plan":model,"publication":publication}))
}
fn validate_publication(sample: &str, model: &Bound, v: &Value, r: &Value) -> Result<()> {
    ensure!(
        v["epoch"] == 144
            && v["phase"] == "publication"
            && v["binding"]["unit"] == UNIT
            && r["schema"]
                == "jetstreamer-horizon-r2-status-authenticated-pipeline-publication-receipt-v1"
            && r["epoch"] == 144
            && r["bucket"] == BUCKET
            && r["key"] == "epoch-144.epoch-status.json"
            && r["status"]["epoch"] == 144
            && r["status"]["phase"] == "publication"
            && r["status"]["sampled_at_utc"] == sample
            && r["status"]["jet_size_bytes"] == LENGTH
            && r["status"]["elapsed_execution_millis"].as_u64().is_some()
            && r["status"]["estimated_remaining_millis"] == v["estimated_remaining_millis"]
            && v["estimated_remaining_millis"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && r["observer_receipt"] == v["observer"]["path"]
            && r["observer_receipt_sha256"] == v["observer"]["sha256"]
            && r["pipeline_binding"]["unit"] == UNIT
            && r["pipeline_binding"]["invocation_id"] == v["binding"]["invocation_id"]
            && r["pipeline_binding"]["claim_phase"] == "local-publication"
            && r["pipeline_binding"]["origin_unit"] == UNIT
            && r["pipeline_binding"]["origin_invocation_id"]
                == v["binding"]["origin_invocation_id"]
            && r["pipeline_binding"]["fleet_path"] == v["binding"]["fleet_path"]
            && r["pipeline_binding"]["fleet_sha256"] == v["binding"]["fleet_sha256"]
            && r["pipeline_binding"]["model_path"].as_str() == model.path.to_str()
            && r["pipeline_binding"]["model_sha256"] == model.sha256
            && r["authenticated_readback"] == true,
        "publication 144 status receipt differs from exact model"
    );
    Ok(())
}
pub(crate) fn validate_completed(p: &Plan, c: &Value) -> Result<()> {
    if p.publication144.is_none() {
        return Ok(());
    }
    if uploading(p) {
        return upload::validate_completed(p, c);
    }
    let d = &c["epoch144_delivery"];
    ensure!(
        d["provisional_fleet"] == c["epoch198_delivery"]["provisional_fleet"],
        "144 status used another fleet sample"
    );
    if d["publication_skipped"] == true {
        ensure!(
            d["publication"].is_null() && d["reason"].as_str().is_some_and(|s| !s.is_empty()),
            "skipped 144status invented publication"
        );
        return Ok(());
    }
    let model: Bound = serde_json::from_value(d["pipeline_plan"].clone())?;
    let publication: Bound = serde_json::from_value(d["publication"].clone())?;
    validate_publication(
        &p.sample_target_utc,
        &model,
        &bound_json(&model, true)?,
        &bound_json(&publication, false)?,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dashboard_receipt_is_exact_pipeline_schema_key_owner_model_and_sample() {
        let model = Bound {
            path: "/sealed/model.json".into(),
            sha256: "a".repeat(64),
        };
        let sample = "2026-10-22T16:00:00Z";
        let v = json!({"epoch":144,"phase":"publication","estimated_remaining_millis":1234,
            "observer":{"path":"/sample","sha256":"b".repeat(64)},
            "binding":{"unit":UNIT,"invocation_id":"c".repeat(32),"origin_invocation_id":"c".repeat(32),"fleet_path":"/fleet","fleet_sha256":"d".repeat(64)}});
        let r = json!({"schema":"jetstreamer-horizon-r2-status-authenticated-pipeline-publication-receipt-v1","epoch":144,"bucket":BUCKET,"key":"epoch-144.epoch-status.json",
            "status":{"epoch":144,"phase":"publication","sampled_at_utc":sample,"jet_size_bytes":LENGTH,"elapsed_execution_millis":10,"estimated_remaining_millis":1234},
            "observer_receipt":"/sample","observer_receipt_sha256":"b".repeat(64),
            "pipeline_binding":{"unit":UNIT,"invocation_id":"c".repeat(32),"claim_phase":"local-publication","origin_unit":UNIT,"origin_invocation_id":"c".repeat(32),"model_path":model.path,"model_sha256":model.sha256,"fleet_path":"/fleet","fleet_sha256":"d".repeat(64)},"authenticated_readback":true});
        validate_publication(sample, &model, &v, &r).unwrap();
        for (pointer, value) in [
            ("/schema", json!("replay-receipt")),
            ("/epoch", json!(198)),
            ("/key", json!("epoch-144.jet")),
            ("/bucket", json!("wrong")),
            ("/status/phase", json!("replay")),
            ("/status/estimated_remaining_millis", json!(0)),
            ("/pipeline_binding/invocation_id", json!("d".repeat(32))),
            ("/pipeline_binding/model_sha256", json!("b".repeat(64))),
            ("/observer_receipt_sha256", json!("d".repeat(64))),
            ("/authenticated_readback", json!(false)),
        ] {
            let mut wrong = r.clone();
            *wrong.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_publication(sample, &model, &v, &wrong).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn original_deadline_is_not_reset_or_clamped() {
        assert_eq!(remaining(1000, 2000, 5000).unwrap(), 4000);
        assert_eq!(remaining(1000, 4000, 5000).unwrap(), 2000);
        assert!(remaining(1000, 6000, 5000).is_err());
        assert!(remaining(2000, 1000, 5000).is_err());
        assert!(remaining(u64::MAX, u64::MAX, 1).is_err());
    }
    #[test]
    fn original_manager_start_requires_one_exact_root_event() {
        let iid = "a".repeat(32);
        let e = json!({"UNIT":UNIT,"INVOCATION_ID":iid,"_PID":"1","_UID":"0","MESSAGE":"Starting exact publisher...","__REALTIME_TIMESTAMP":"1792620000000000"});
        assert_eq!(
            start(std::slice::from_ref(&e), &iid).unwrap(),
            1792620000000
        );
        for key in ["UNIT", "INVOCATION_ID", "_PID", "_UID", "MESSAGE"] {
            let mut wrong = e.clone();
            wrong[key] = json!("foreign");
            assert!(start(&[wrong], &iid).is_err());
        }
        assert!(start(&[e.clone(), e], &iid).is_err());
    }
}
