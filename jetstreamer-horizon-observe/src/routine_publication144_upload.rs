//! Exact nonqueued publisher -> upload history and coordinated metadata.
use super::*;
const UPLOAD: &str = "horizon-upload-144-v4-20261022-v1.service";
const WORKER: &str = "/usr/local/lib/jetstreamer/horizon-publication144-single-delivery-20261022-v7/jetstreamer-publication144-deliver";
const WORKER_SHA: &str = "9fdca9475356c3f8c82c8dbdd55d57476116771be2e3ca6b8914c40c8f41e08e";
const PROGRESS: &str = "/usr/local/lib/jetstreamer/horizon-publication144-child-progress-reader-20261022-v3/jetstreamer-publication144-progress";
const PROGRESS_SHA: &str = "d0f084a53c3b1eed735f826f2139cf459eb4b1a85558fc02ab8c030ca8168231";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch144-progress-20261022-v1";
const LENGTH: u64 = 109177480876;
const DIGEST: &str = "153d3e5e5b7cbdc31bb4229315786000b84442a75b3b83cf4a50184b20b84a33";
const ACTIVE_UPLOAD: &str = "Track exact144 nonqueued upload/readback using authenticated child progress and original publisher clock;preserve canonical and private assembly. Capture terminal event promptly;ready requires authenticated matching sidecar,not service success.";
const SUCCESS_UPLOAD: &str = "Exact144 upload worker is terminal-success;reconcile authenticated ready pair and owned-status cleanup receipts immediately. Preserve canonical/private artifacts until ordinary boundary retirement gates pass.";
const FAILED_UPLOAD: &str = "Exact144 upload worker is positively terminal unsuccessful;capture terminal evidence,remove owned stale status through qualified inactive lifecycle,and repair idempotently from preserved canonical/staged artifacts. Keep repair open;never overwrite R2 or retry over occupied attempt state.";
fn id(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
pub(super) fn checked(s: &Profile) -> Result<(Value, Value)> {
    let b = s.upload.as_ref().context("missing144 upload capture")?;
    let l = bound_json(b, true)?;
    let original = bound_json(&s.launch, true)?;
    let pb: Bound = serde_json::from_value(l["plan"].clone())?;
    let d = bound_json(&pb, true)?;
    let ib: Bound = serde_json::from_value(l["worker_intent"].clone())?;
    let kb: Bound = serde_json::from_value(l["lock_acquisition"].clone())?;
    let i = bound_json(&ib, false)?;
    let k = bound_json(&kb, false)?;
    let claim = lineage(s, &l, &original, &pb, &d, &i, &k)?;
    Ok((claim, l))
}
fn lineage(
    s: &Profile,
    l: &Value,
    original: &Value,
    pb: &Bound,
    d: &Value,
    i: &Value,
    k: &Value,
) -> Result<Value> {
    let b = s.upload.as_ref().context("missing144 upload capture")?;
    let root = Path::new(d["output_directory"].as_str().context("delivery root")?);
    ensure!(
        root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-epoch144-delivery-"))
            && b.path == root.join("launch.json")
            && d["schema"] == "jetstreamer-exact144-single-delivery-plan-v1"
            && d["publisher_plan"] == original["publisher_plan"]
            && d["tracker_plan"] == original["tracker_plan"]
            && d["client"]["path"] == COMPOSITE_READER
            && d["client"]["sha256"] == COMPOSITE_READER_SHA
            && d["r2_create_missing_pair_authorized"] == true
            && d["r2_overwrite_authorized"] == false
            && d["local_retirement_authorized"] == false,
        "foreign144 upload plan or origin"
    );
    ensure!(
        l["schema"] == "jetstreamer-exact144-delivery-launch-v1"
            && l["epoch"] == 144
            && l["self_sha256"] == WORKER_SHA
            && l["initial_delivery_phase"] == "upload-readback"
            && l["claim"]["unit"] == UPLOAD
            && l["claim"]["phase"] == "upload-readback"
            && id(&l["claim"]["invocation_id"])
            && l["claim"]["invocation_id"] == l["owner"]["InvocationID"]
            && l["claim"]["origin_unit"] == UNIT
            && l["claim"]["origin_invocation_id"] == original["claim"]["invocation_id"],
        "foreign or queued144 upload capture"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(l[flag] == false, "upload capture grants authority:{flag}");
    }
    let expected = format!(
        "{{ path={WORKER} ; argv[]={WORKER} {} --plan-sha256 {} --self-sha256 {WORKER_SHA} --run",
        pb.path.display(),
        pb.sha256
    );
    ensure!(
        l["claim"]["expected_exec_start"] == l["owner"]["ExecStart"]
            && l["owner"]["ExecStart"]
                .as_str()
                .and_then(|s| s.split_once(" ; ignore_errors="))
                .is_some_and(|(a, b)| a == expected && b.starts_with("no ;"))
            && l["owner"]["Id"] == UPLOAD
            && l["owner"]["NRestarts"] == "0"
            && l["owner"]["Restart"] == "no"
            && l["owner"]["Type"] == "oneshot"
            && l["owner"]["RemainAfterExit"] == "yes"
            && l["owner"]["ActiveState"] == "activating"
            && l["owner"]["SubState"] == "start"
            && l["owner"]["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|n| n > 0),
        "upload capture lacks exact live worker"
    );
    let ib: Bound = serde_json::from_value(l["worker_intent"].clone())?;
    let kb: Bound = serde_json::from_value(l["lock_acquisition"].clone())?;
    ensure!(
        ib.path == root.join("intent.json") && kb.path == root.join("lock-acquired.json"),
        "foreign upload intent/lock path"
    );
    ensure!(
        i["schema"] == "horizon-exact144-delivery-intent-v1"
            && i["plan"] == l["plan"]
            && i["self_sha256"] == WORKER_SHA
            && i["owner"] == l["owner"]
            && i["lock_acquisition_mode"] == "nonblocking-no-queue"
            && i["publisher"]["origin_sha256"] == s.launch.sha256
            && i["publisher"]["publisher"]["InvocationID"] == original["claim"]["invocation_id"]
            && i["publisher"]["publisher"]["MainPID"] == "0"
            && i["publisher"]["publisher"]["Result"] == "success"
            && i["publisher"]["publisher"]["ExecMainStatus"] == "0"
            && i["publisher"]["publication"]["committed"] == true
            && i["publisher"]["publication"]["archive_sha256"] == DIGEST
            && i["publisher"]["publication"]["archive_bytes"] == LENGTH
            && k["schema"] == "horizon-exact144-delivery-lock-v1"
            && k["plan"] == l["plan"]
            && k["owner"] == l["owner"]
            && k["shared_mutation_lock"]
                == "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock"
            && k["acquired_millis"]
                .as_u64()
                .zip(i["lock_wait_started_millis"].as_u64())
                .is_some_and(|(a, b)| a >= b),
        "upload lacks authentic original publication and exclusive lock lineage"
    );
    let claim = json!({"epoch":144,"phase":"upload-readback","unit":UPLOAD,"invocation_id":l["claim"]["invocation_id"],
        "expected_exec_start":l["claim"]["expected_exec_start"],"evidence":[s.launch,b]});
    Ok(claim)
}
fn state(u: &Value, l: &Value) -> Result<(&'static str, &'static str)> {
    ensure!(
        u["Id"] == UPLOAD
            && u["LoadState"] == "loaded"
            && u["InvocationID"] == l["claim"]["invocation_id"]
            && u["NRestarts"] == "0"
            && u["ExecStart"]
                .as_str()
                .zip(l["claim"]["expected_exec_start"].as_str())
                .is_some_and(|(a, b)| {
                    a.split_once(" ; ignore_errors=")
                        .zip(b.split_once(" ; ignore_errors="))
                        .is_some_and(|((left, lmeta), (right, rmeta))| {
                            left == right && lmeta.starts_with("no ;") && rmeta.starts_with("no ;")
                        })
                }),
        "144 upload owner/command changed"
    );
    if u["ActiveState"] == "activating"
        && u["SubState"] == "start"
        && u["MainPID"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|n| n > 0)
    {
        return Ok(("post-replay-pipeline", ACTIVE_UPLOAD));
    }
    ensure!(
        u["MainPID"] == "0"
            && matches!(
                (u["ActiveState"].as_str(), u["SubState"].as_str()),
                (Some("active"), Some("exited"))
                    | (Some("failed"), Some("failed"))
                    | (Some("inactive"), Some("dead"))
            ),
        "144 upload is not positively live or terminal"
    );
    if u["ActiveState"] == "active" && u["Result"] == "success" && u["ExecMainStatus"] == "0" {
        Ok(("post-replay-pipeline", SUCCESS_UPLOAD))
    } else {
        Ok(("failed-needs-repair", FAILED_UPLOAD))
    }
}
pub(super) fn retained(s: &Profile, f: &Value, origin: &Value) -> Result<Option<(Value, Value)>> {
    let (claim, _) = checked(s)?;
    let rows = f["pipeline_claims"].as_array().context("upload history")?;
    if !rows.iter().any(|r| r["unit"] == UPLOAD) {
        return retained_gate_from(f, origin, &s.launch);
    }
    let g = &f["gates"]["144"];
    ensure!(
        rows.iter().filter(|r| r["unit"] == UPLOAD).count() == 1
            && rows.contains(&claim)
            && rows.contains(origin)
            && g["evidence"]
                .as_array()
                .is_some_and(|a| a.contains(&serde_json::to_value(&s.launch).unwrap())
                    && a.contains(&serde_json::to_value(s.upload.as_ref().unwrap()).unwrap()))
            && matches!(
                (g["state"].as_str(), g["next_action"].as_str()),
                (
                    Some("post-replay-pipeline"),
                    Some(ACTIVE_UPLOAD | SUCCESS_UPLOAD)
                ) | (Some("failed-needs-repair"), Some(FAILED_UPLOAD))
            ),
        "upload history/gate changed"
    );
    Ok(Some((g["state"].clone(), g["next_action"].clone())))
}
pub(super) fn derive(s: &Profile, f: &mut Value) -> Result<()> {
    let (claim, l) = checked(s)?;
    let rows = f["pipeline_claims"]
        .as_array_mut()
        .context("upload claims")?;
    let found: Vec<_> = rows.iter().filter(|r| r["unit"] == UPLOAD).collect();
    ensure!(
        found.is_empty() || (found.len() == 1 && found[0] == &claim),
        "upload history cannot be replaced"
    );
    if found.is_empty() {
        rows.push(claim);
    }
    let units = f["tracked_units"]
        .as_array_mut()
        .context("tracked upload")?;
    if !units.contains(&json!(UPLOAD)) {
        units.push(json!(UPLOAD));
    }
    let o=Command::new("/usr/bin/systemctl").args(["show",UPLOAD,"--property=Id,LoadState,InvocationID,NRestarts,ActiveState,SubState,MainPID,Result,ExecMainStatus,ExecStart"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 32768,
        "upload identity unavailable"
    );
    let u = serde_json::to_value(
        std::str::from_utf8(&o.stdout)?
            .lines()
            .map(|s| s.split_once('=').context("upload property"))
            .collect::<Result<BTreeMap<_, _>>>()?,
    )?;
    let (operational, action) = state(&u, &l)?;
    let g = &mut f["gates"]["144"];
    g["state"] = json!(operational);
    g["next_action"] = json!(action);
    let evidence = g["evidence"]
        .as_array_mut()
        .context("upload gate evidence")?;
    let b = serde_json::to_value(s.upload.as_ref().unwrap())?;
    if !evidence.contains(&b) {
        evidence.push(b);
    }
    Ok(())
}
fn bound(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn phase(v: &Value) -> Result<&'static str> {
    match v["phase"].as_str() {
        Some("pre-upload-source-hash" | "upload" | "awaiting-readback") => Ok("upload"),
        Some("readback" | "source-revalidation-sidecar" | "sidecar-commit") => Ok("readback"),
        _ => anyhow::bail!("unsupported144 child phase;never invent queued progress"),
    }
}
pub(super) fn publish(p: &Plan, pipeline: &Value, observer: &Bound) -> Result<Value> {
    // Operational failure in one delivery must remain explicit without losing
    // the other ranges' already authenticated metadata or inventing an ETA.
    let provisional: Bound = serde_json::from_value(pipeline["provisional_fleet"].clone())?;
    match publish_inner(p, pipeline, observer) {
        Ok(v) => Ok(v),
        Err(e) => Ok(
            json!({"provisional_fleet":provisional,"publication_skipped":true,
            "reason":format!("Exact144 upload progress/status incident;repair promptly without restarting healthy work:{e:#}"),"delivery_kind":"upload144"}),
        ),
    }
}
fn publish_inner(p: &Plan, pipeline: &Value, observer: &Bound) -> Result<Value> {
    let s = p.publication144.as_ref().context("upload profile")?;
    let (_, l) = checked(s)?;
    let provisional: Bound = serde_json::from_value(pipeline["provisional_fleet"].clone())?;
    let f = bound_json(&provisional, false)?;
    ensure!(
        f["sampled_at_utc"] == p.sample_target_utc && f["observer_sha256"] == observer.sha256,
        "upload status requires coordinated fleet"
    );
    let active: Vec<_> = f["active"]
        .as_array()
        .context("active census")?
        .iter()
        .filter(|r| r["epoch"] == 144)
        .collect();
    if active.is_empty() {
        return Ok(
            json!({"provisional_fleet":provisional,"publication_skipped":true,"reason":"Exact144 upload is not active;capture terminal event and reconcile ready/failure status lifecycle promptly","delivery_kind":"upload144"}),
        );
    }
    ensure!(
        active.len() == 1
            && active[0]["phase"] == "upload-readback"
            && state(&active[0]["unit"], &l)?.1 == ACTIVE_UPLOAD,
        "overlapping144 upload owner"
    );
    let pb: Bound = serde_json::from_value(l["plan"].clone())?;
    let d = bound_json(&pb, true)?;
    let child_path = Path::new(d["output_directory"].as_str().context("delivery output")?)
        .join("upload-child-launch.json");
    let child_bound = bound(child_path, false)?;
    let sample = utc_seconds(&p.sample_target_utc)?
        .checked_mul(1000)
        .context("sample overflow")?;
    private_dir(Path::new(ROOT))?;
    let progress_plan = json!({"schema":"jetstreamer-exact144-child-progress-plan-v1","delivery_plan":pb,"delivery_launch":s.upload,
        "child_launch":child_bound,"observer":observer,"sample_unix_millis":sample,"output_receipt":format!("{ROOT}/progress-{sample}.json")});
    let package =
        delivery198::seal_values(p, "upload144-progress", &[("plan.json", progress_plan)])?;
    let input = bound(package.join("plan.json"), true)?;
    let tool = Bound {
        path: PROGRESS.into(),
        sha256: PROGRESS_SHA.into(),
    };
    tool_ok(&tool)?;
    let capture = p.cycle_directory.join("child-upload144-progress.json");
    child(
        &tool,
        &[
            input.path.display().to_string(),
            "--plan-sha256".into(),
            input.sha256.clone(),
            "--self-sha256".into(),
            PROGRESS_SHA.into(),
        ],
        false,
        &capture,
    )?;
    let progress = bound(
        PathBuf::from(format!("{ROOT}/progress-{sample}.json")),
        false,
    )?;
    let proof = bound_json(&progress, false)?;
    let forecast = &proof["forecast"];
    ensure!(
        proof["schema"] == "jetstreamer-exact144-authenticated-child-progress-v2"
            && proof["self_sha256"] == PROGRESS_SHA
            && proof["plan"]["path"] == input.path.to_str().context("progress plan path")?
            && proof["plan"]["sha256"] == input.sha256
            && proof["observer"] == serde_json::to_value(observer)?
            && proof["delivery_launch"] == serde_json::to_value(s.upload.as_ref().unwrap())?
            && forecast["schema"] == "jetstreamer-exact144-child-sidecar-forecast-v1"
            && forecast["sampled_at_millis"] == sample
            && forecast["estimated_remaining_millis"]
                .as_u64()
                .is_some_and(|n| n > 0),
        "upload forecast differs from authenticated child/sample"
    );
    let status_phase = phase(forecast)?;
    let u = &active[0]["unit"];
    let target = p
        .cycle_directory
        .join("upload144-status/sealed/pipeline-plan.json");
    let model = json!({"schema":"jetstreamer-horizon-pipeline-status-plan-v1","epoch":144,"phase":status_phase,
        "binding":{"unit":UPLOAD,"invocation_id":u["InvocationID"],"expected_exec_start":u["ExecStart"],"claim_phase":"upload-readback",
            "origin_unit":UNIT,"origin_invocation_id":l["claim"]["origin_invocation_id"],"model_path":target,"model_sha256":"","fleet_path":provisional.path,"fleet_sha256":provisional.sha256},
        "observer":observer,"fleet":provisional,"origin_launch":s.launch,"estimate_evidence":[progress,s.upload,s.launch],
        "estimate_basis":"Authenticated exact live144 child progress/forecast;original publisher invocation clock retained;no queued time or replay ETA fabricated",
        "estimated_remaining_millis":forecast["estimated_remaining_millis"],"jet_path":"/home/sol/horizon/epoch-144.jet","expected_jet_size_bytes":LENGTH,
        "peer_units":[],"receipt_directory":"/home/sol/.jetstreamer-private/r2-status-receipts","receipt_directory_uid":1001});
    let package =
        delivery198::seal_values(p, "upload144-status", &[("pipeline-plan.json", model)])?;
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
            .join(format!("child-upload144-status-{name}.json"));
        if let Err(e) = child(&p.tools.r2, &args, !check, &capture) {
            return Ok(
                json!({"provisional_fleet":provisional,"publication_skipped":true,"failed_child":bound(capture,false)?,"reason":format!("Exact144 upload status requires prompt repair:{e:#}"),"delivery_kind":"upload144"}),
            );
        }
    }
    let digits: String = p
        .sample_target_utc
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let publication = bound(
        format!("/home/sol/.jetstreamer-private/r2-status-receipts/epoch-144.status-{digits}.json")
            .into(),
        false,
    )?;
    validate_result(
        &p.sample_target_utc,
        &model,
        &bound_json(&model, true)?,
        &bound_json(&publication, false)?,
    )?;
    Ok(
        json!({"provisional_fleet":provisional,"pipeline_plan":model,"publication":publication,"progress":progress,"delivery_kind":"upload144"}),
    )
}
fn validate_result(sample: &str, model: &Bound, m: &Value, r: &Value) -> Result<()> {
    ensure!(
        matches!(m["phase"].as_str(), Some("upload" | "readback"))
            && m["epoch"] == 144
            && m["binding"]["unit"] == UPLOAD
            && m["binding"]["claim_phase"] == "upload-readback"
            && m["binding"]["origin_unit"] == UNIT
            && r["schema"]
                == "jetstreamer-horizon-r2-status-authenticated-pipeline-publication-receipt-v1"
            && r["epoch"] == 144
            && r["bucket"] == BUCKET
            && r["key"] == "epoch-144.epoch-status.json"
            && r["authenticated_readback"] == true
            && r["status"]["epoch"] == 144
            && r["status"]["phase"] == m["phase"]
            && r["status"]["sampled_at_utc"] == sample
            && r["status"]["jet_size_bytes"] == LENGTH
            && r["status"]["elapsed_execution_millis"].as_u64().is_some()
            && r["status"]["estimated_remaining_millis"] == m["estimated_remaining_millis"]
            && m["estimated_remaining_millis"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && r["observer_receipt"] == m["observer"]["path"]
            && r["observer_receipt_sha256"] == m["observer"]["sha256"]
            && r["pipeline_binding"]["model_path"] == model.path.to_str().context("model path")?
            && r["pipeline_binding"]["model_sha256"] == model.sha256,
        "144 upload status does not reproduce exact model"
    );
    for key in [
        "unit",
        "invocation_id",
        "claim_phase",
        "origin_unit",
        "origin_invocation_id",
        "fleet_path",
        "fleet_sha256",
    ] {
        ensure!(
            r["pipeline_binding"][key] == m["binding"][key],
            "144 upload status binding changed:{key}"
        );
    }
    Ok(())
}
pub(super) fn validate_completed(p: &Plan, c: &Value) -> Result<()> {
    let d = &c["epoch144_delivery"];
    ensure!(
        d["delivery_kind"] == "upload144"
            && d["provisional_fleet"] == c["epoch198_delivery"]["provisional_fleet"],
        "upload completion used another fleet"
    );
    if d["publication_skipped"] == true {
        ensure!(
            d["publication"].is_null() && d["reason"].as_str().is_some_and(|s| !s.is_empty()),
            "skipped upload invented publication"
        );
        return Ok(());
    }
    let model: Bound = serde_json::from_value(d["pipeline_plan"].clone())?;
    let publication: Bound = serde_json::from_value(d["publication"].clone())?;
    validate_result(
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
    fn upload_lineage_rejects_changed_origin_plan_lock_client_and_authority() {
        let root = "/var/lib/jetstreamer/horizon-epoch144-delivery-test";
        let bound = |path: &str| Bound {
            path: path.into(),
            sha256: "a".repeat(64),
        };
        let s = Profile {
            launch: bound(LAUNCH),
            upload: Some(bound(&format!("{root}/launch.json"))),
        };
        let pb = bound("/sealed/delivery.json");
        let publisher = json!({"path":"/sealed/publisher.json","sha256":"b".repeat(64)});
        let tracker = json!({"path":"/sealed/tracker.json","sha256":"c".repeat(64)});
        let original = json!({"publisher_plan":publisher,"tracker_plan":tracker,
            "claim":{"invocation_id":"d".repeat(32)}});
        let d = json!({"output_directory":root,"schema":"jetstreamer-exact144-single-delivery-plan-v1",
            "publisher_plan":publisher,"tracker_plan":tracker,"client":{"path":COMPOSITE_READER,"sha256":COMPOSITE_READER_SHA},
            "r2_create_missing_pair_authorized":true,"r2_overwrite_authorized":false,"local_retirement_authorized":false});
        let command = format!(
            "{{ path={WORKER} ; argv[]={WORKER} {} --plan-sha256 {} --self-sha256 {WORKER_SHA} --run ; ignore_errors=no ; start_time=[n/a] }}",
            pb.path.display(),
            pb.sha256
        );
        let owner = json!({"Id":UPLOAD,"InvocationID":"e".repeat(32),"NRestarts":"0","Restart":"no","Type":"oneshot",
            "RemainAfterExit":"yes","ActiveState":"activating","SubState":"start","MainPID":"123","ExecStart":command});
        let l = json!({"schema":"jetstreamer-exact144-delivery-launch-v1","epoch":144,"self_sha256":WORKER_SHA,
            "initial_delivery_phase":"upload-readback","plan":pb,"owner":owner,
            "claim":{"unit":UPLOAD,"phase":"upload-readback","invocation_id":"e".repeat(32),"origin_unit":UNIT,
                "origin_invocation_id":"d".repeat(32),"expected_exec_start":command},
            "worker_intent":bound(&format!("{root}/intent.json")),"lock_acquisition":bound(&format!("{root}/lock-acquired.json")),
            "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"publication_authorized":false,
            "retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let i = json!({"schema":"horizon-exact144-delivery-intent-v1","plan":pb,"self_sha256":WORKER_SHA,"owner":owner,
            "lock_acquisition_mode":"nonblocking-no-queue","lock_wait_started_millis":100,
            "publisher":{"origin_sha256":s.launch.sha256,
                "publisher":{"InvocationID":"d".repeat(32),"MainPID":"0","Result":"success","ExecMainStatus":"0"},
                "publication":{"committed":true,"archive_sha256":DIGEST,"archive_bytes":LENGTH}}});
        let k = json!({"schema":"horizon-exact144-delivery-lock-v1","plan":pb,"owner":owner,
            "shared_mutation_lock":"/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock","acquired_millis":101});
        let good = lineage(&s, &l, &original, &pb, &d, &i, &k).unwrap();
        assert!(
            good.get("origin_unit").is_none(),
            "fleet claim must use its strict schema"
        );
        for (which, pointer) in [
            (0, "/claim/origin_invocation_id"),
            (0, "/owner/InvocationID"),
            (0, "/initial_delivery_phase"),
            (0, "/worker_intent/path"),
            (0, "/lock_acquisition/path"),
            (0, "/r2_mutations"),
            (1, "/client/sha256"),
            (1, "/publisher_plan/sha256"),
            (1, "/tracker_plan/sha256"),
            (1, "/r2_overwrite_authorized"),
            (2, "/publisher/origin_sha256"),
            (2, "/publisher/publication/archive_sha256"),
            (2, "/publisher/publication/archive_bytes"),
            (2, "/lock_acquisition_mode"),
            (3, "/plan/sha256"),
            (3, "/shared_mutation_lock"),
            (3, "/owner/InvocationID"),
        ] {
            let mut values = [l.clone(), d.clone(), i.clone(), k.clone()];
            *values[which].pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(
                lineage(
                    &s, &values[0], &original, &pb, &values[1], &values[2], &values[3]
                )
                .is_err(),
                "{which}:{pointer}"
            );
        }
        let mut early = k.clone();
        early["acquired_millis"] = json!(99);
        assert!(lineage(&s, &l, &original, &pb, &d, &i, &early).is_err());
    }
    #[test]
    fn detailed_child_phases_map_only_to_supported_nonqueued_dashboard_phases() {
        for name in ["pre-upload-source-hash", "upload", "awaiting-readback"] {
            assert_eq!(phase(&json!({"phase":name})).unwrap(), "upload");
        }
        for name in ["readback", "source-revalidation-sidecar", "sidecar-commit"] {
            assert_eq!(phase(&json!({"phase":name})).unwrap(), "readback");
        }
        assert!(phase(&json!({"phase":"queued-upload"})).is_err());
        assert!(phase(&Value::Null).is_err());
    }
    #[test]
    fn live_terminal_failed_and_replaced_workers_remain_distinct() {
        let command =
            "{ path=/worker ; argv[]=/worker --run ; ignore_errors=no ; start_time=[n/a] }";
        let l = json!({"claim":{"invocation_id":"a".repeat(32),"expected_exec_start":command}});
        let mut u = json!({"Id":UPLOAD,"LoadState":"loaded","InvocationID":"a".repeat(32),"NRestarts":"0","ExecStart":command,"ActiveState":"activating","SubState":"start","MainPID":"123"});
        assert_eq!(state(&u, &l).unwrap().1, ACTIVE_UPLOAD);
        u["MainPID"] = json!("0");
        assert!(state(&u, &l).is_err());
        u["ActiveState"] = json!("failed");
        u["SubState"] = json!("failed");
        assert_eq!(state(&u, &l).unwrap().1, FAILED_UPLOAD);
        u["ActiveState"] = json!("active");
        u["SubState"] = json!("exited");
        u["Result"] = json!("success");
        u["ExecMainStatus"] = json!("0");
        assert_eq!(state(&u, &l).unwrap().1, SUCCESS_UPLOAD);
        for k in ["InvocationID", "NRestarts", "ExecStart"] {
            let mut bad = u.clone();
            bad[k] = json!("foreign");
            assert!(state(&bad, &l).is_err(), "{k}");
        }
    }
    #[test]
    fn status_receipt_keeps_original_publisher_clock_and_exact_upload_model() {
        let model = Bound {
            path: "/sealed/model.json".into(),
            sha256: "a".repeat(64),
        };
        let binding = json!({"unit":UPLOAD,"invocation_id":"b".repeat(32),"claim_phase":"upload-readback","origin_unit":UNIT,
            "origin_invocation_id":"c".repeat(32),"fleet_path":"/fleet.json","fleet_sha256":"d".repeat(64)});
        let m = json!({"epoch":144,"phase":"upload","binding":binding,"observer":{"path":"/observer.json","sha256":"e".repeat(64)},"estimated_remaining_millis":1234});
        let mut actual_binding = binding;
        actual_binding["model_path"] = json!(model.path);
        actual_binding["model_sha256"] = json!(model.sha256);
        let r = json!({"schema":"jetstreamer-horizon-r2-status-authenticated-pipeline-publication-receipt-v1","epoch":144,"bucket":BUCKET,
            "key":"epoch-144.epoch-status.json","authenticated_readback":true,
            "status":{"epoch":144,"phase":"upload","sampled_at_utc":"2026-10-22T23:58:00Z","jet_size_bytes":LENGTH,"elapsed_execution_millis":1000,"estimated_remaining_millis":1234},
            "observer_receipt":"/observer.json","observer_receipt_sha256":"e".repeat(64),"pipeline_binding":actual_binding});
        validate_result("2026-10-22T23:58:00Z", &model, &m, &r).unwrap();
        for pointer in [
            "/pipeline_binding/origin_invocation_id",
            "/pipeline_binding/invocation_id",
            "/pipeline_binding/model_sha256",
            "/pipeline_binding/fleet_sha256",
            "/status/estimated_remaining_millis",
            "/status/phase",
            "/status/sampled_at_utc",
            "/observer_receipt_sha256",
            "/authenticated_readback",
        ] {
            let mut bad = r.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                validate_result("2026-10-22T23:58:00Z", &model, &m, &bad).is_err(),
                "{pointer}"
            );
        }
    }
}
