//! Optional closed191 native delivery metadata. Ordinary lanes keep their old
//! publisher pins; only the fleet reader and these four publications use the
//! newly sealed reader. Missing current custody is a durable isolated incident.
use super::*;
const UNIT: &str = "jetstreamer-root-sweep-e191-194-t5-20261016-v2-r2-e191-194-lane-a-1.service";
const IID: &str = "ea93199ed2fa470d99de248c2a10b246";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    pub publisher: Bound,
    pub terminal_event: Bound,
    pub event_directory: PathBuf,
}
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn event_path(p: &Plan) -> Option<PathBuf> {
    p.cohort191_delivery.as_ref().map(|s| {
        s.event_directory
            .join(format!("event-{}.json", stamp(&p.sample_target_utc)))
    })
}
fn terminal(v: &Value, target: u64) -> Result<()> {
    jetstreamer_horizon_observe::cohort191_delivery_model::validate_native_terminal(
        &v["native_events"],
        target,
    )?;
    ensure!(
        v["schema"] == "jetstreamer-cohort191-delivery-event-v2"
            && v["first_epoch"] == 191
            && v["last_epoch"] == 194
            && v["sample_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= target)
            && v["native_events"]["trusted_root_slot"] == 84239250u64
            && v["native_events"]["archive_terminal_slot"] == 84239999u64
            && v["native_events"]["root"]["_SYSTEMD_UNIT"] == UNIT
            && v["native_events"]["root"]["_SYSTEMD_INVOCATION_ID"] == IID
            && v["native_events"]["root"]["_PID"] == "2189644"
            && v["native_events"]["closes"]
                .as_array()
                .is_some_and(|a| a.len() == 4)
            && v["resource_samples"] == 0,
        "191 transition is not the exact final-root/four-close native event"
    );
    for flag in [
        "publication_authorized",
        "replay_launch_authorized",
        "r2_mutations",
        "archive_readiness_claimed",
    ] {
        ensure!(v[flag] == false, "191 terminal event acquired authority");
    }
    Ok(())
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    let Some(s) = &p.cohort191_delivery else {
        return Ok(());
    };
    ensure!(
        is_101(p)?
            && !(191..=194).any(|e| p.expected_epochs.contains(&e))
            && s.publisher.path.parent().and_then(Path::parent)
                == Some(Path::new("/usr/local/lib/jetstreamer"))
            && s.publisher.path.file_name().and_then(|s| s.to_str()) == Some("jetstreamer-r2")
            && s.event_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && s.event_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-cohort191-delivery-events-")),
        "foreign191 publisher, event namespace or duplicate ordinary claim"
    );
    tool_ok(&s.publisher)?;
    let v = bound_json(&s.terminal_event, false)?;
    terminal(&v, utc_seconds(&p.sample_target_utc)?)?;
    ensure!(
        v["capture_self_sha256"] == s.publisher.sha256
            && v["capture_program"].as_str() == s.publisher.path.to_str(),
        "191 transition producer differs from sealed publisher"
    );
    // Bind immutable capture provenance before removing the replay model. This
    // does not reuse a mutable controller state as historical terminal proof.
    let capture: Bound = serde_json::from_value(v["capture_plan"].clone())?;
    let c = bound_json(&capture, true)?;
    ensure!(
        c["schema"] == "jetstreamer-cohort191-delivery-capture-plan-v2"
            && c["claims"] == v["claims"]
            && c["observer"] == v["observer"]
            && c["origins"] == v["origins"]
            && c["forecast"] == v["forecast"],
        "191 transition/capture provenance differs"
    );
    Ok(())
}
pub(super) fn effective_model(p: &Plan, model: &Value) -> Result<Value> {
    if p.cohort191_delivery.is_none() {
        return Ok(model.clone());
    }
    validate(p)?;
    let mut next = model.clone();
    let ranges = next["ranges"]
        .as_array_mut()
        .context("191 ordinary ranges")?;
    let old: Vec<_> = ranges.iter().filter(|r| r["range"] == "191-194").collect();
    ensure!(
        old.len() <= 1
            && old
                .iter()
                .all(|r| r["epochs"] == json!([191, 192, 193, 194])
                    && r["expected_producer_invocation_id"] == IID),
        "191 ordinary source scope differs"
    );
    ranges.retain(|r| r["range"] != "191-194");
    if let Some(expected) = next["expected_observer_ranges"].as_array_mut() {
        expected.retain(|r| r != "191-194");
    }
    Ok(next)
}
pub(super) fn fleet_reader(p: &Plan) -> &Bound {
    p.cohort191_delivery
        .as_ref()
        .map(|s| &s.publisher)
        .unwrap_or_else(|| qualification141_status::fleet_reader(p))
}
fn accepted(p: &Plan) -> Result<Option<(Bound, Value)>> {
    if p.cohort191_delivery.is_none() {
        return Ok(None);
    }
    let path = p.cycle_directory.join("cohort191-accepted.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let receipt = file(path, false)?;
    let receipt = bound_json(&receipt, false)?;
    ensure!(
        receipt["schema"] == "jetstreamer-cohort191-routine-acceptance-v2"
            && receipt["sampled_at_utc"] == p.sample_target_utc,
        "191 accepted event belongs to another cycle"
    );
    let event: Bound = serde_json::from_value(receipt["event"].clone())?;
    Ok(Some((event.clone(), bound_json(&event, false)?)))
}
pub(super) fn prepare(p: &Plan, observer: &Bound) -> Result<()> {
    let Some(s) = &p.cohort191_delivery else {
        return Ok(());
    };
    let result = (|| -> Result<Bound> {
        let b = file(event_path(p).context("191 current event path")?, false)?;
        let v = bound_json(&b, false)?;
        terminal(&v, utc_seconds(&p.sample_target_utc)?)?;
        ensure!(
            v["sampled_at_utc"] == p.sample_target_utc
                && v["observer"] == serde_json::to_value(observer)?
                && v["capture_self_sha256"] == s.publisher.sha256
                && v["capture_program"].as_str() == s.publisher.path.to_str(),
            "191 current custody is stale, backdated or produced by another reader"
        );
        child(
            &s.publisher,
            &[
                "check-delivery-191".into(),
                b.path.display().to_string(),
                "--event-sha256".into(),
                b.sha256.clone(),
            ],
            false,
            &p.cycle_directory.join("child-cohort191-custody.json"),
        )?;
        Ok(b)
    })();
    match result {
        Ok(event) => {
            write_new(
                &p.cycle_directory.join("cohort191-accepted.json"),
                &json!({"schema":"jetstreamer-cohort191-routine-acceptance-v2","sampled_at_utc":p.sample_target_utc,"event":event,"new_resource_samples":0}),
            )?;
        }
        Err(error) => {
            write_new(
                &p.cycle_directory.join("cohort191-incident.json"),
                &json!({"schema":"jetstreamer-cohort191-status-incident-v2","epochs":[191,192,193,194],
            "sampled_at_utc":p.sample_target_utc,"error":format!("{error:#}"),"publication_skipped":true,
            "repair_priority":"Restore exact current native custody/forecast before publishing these four statuses",
            "other_lanes_continue":true,"new_resource_samples":0,"r2_mutations":false}),
            )?;
        }
    }
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, fleet: &mut Value) -> Result<()> {
    let Some(s) = &p.cohort191_delivery else {
        return Ok(());
    };
    let accepted = accepted(p)?;
    let claims = fleet["pipeline_claims"]
        .as_array_mut()
        .context("191 pipeline claims")?;
    claims.retain(|c| {
        !c["epoch"]
            .as_u64()
            .is_some_and(|e| (191..=194).contains(&e))
    });
    for epoch in 191..=194 {
        let key = epoch.to_string();
        let entries = fleet["gates"][&key]["evidence"]
            .as_array_mut()
            .context("191 gate evidence")?;
        let b = serde_json::to_value(&s.terminal_event)?;
        if !entries.contains(&b) {
            entries.push(b);
        }
        fleet["gates"][&key]["state"] = json!("blocked-qualification");
        fleet["gates"][&key]["next_action"] = json!(
            "191 cohort replay terminal; repair/refresh native delivery custody and exact stage estimate; independent full/plugin and authenticated sync gates remain required"
        );
    }
    if let Some((event, v)) = accepted {
        for c in v["claims"].as_array().context("191 accepted claims")? {
            let mut claim = c.clone();
            claim
                .as_object_mut()
                .context("191 native claim")?
                .remove("program");
            claim["evidence"] = json!([event]);
            fleet["pipeline_claims"].as_array_mut().unwrap().push(claim);
        }
    }
    Ok(())
}
pub(super) fn publish(p: &Plan, provisional: &Value, observer: &Bound) -> Result<Value> {
    if p.cohort191_delivery.is_none() {
        return Ok(json!({"enabled":false}));
    }
    let attempt = (|| -> Result<Value> {
        let (event, v) = accepted(p)?.context("191 current custody was not accepted")?;
        let s = p.cohort191_delivery.as_ref().unwrap();
        let fleet: Bound = serde_json::from_value(provisional["provisional_fleet"].clone())?;
        let mut publications = Vec::new();
        for c in v["claims"].as_array().context("191 current claims")? {
            let epoch = c["epoch"].as_u64().context("191 current epoch")?;
            let phase = match c["phase"].as_str().context("191 phase")? {
                "cohort191-delivery" => {
                    let row = v["queue_observation"]["epochs"]
                        .as_array()
                        .context("191 queue cutoff rows")?
                        .iter()
                        .find(|r| r["epoch"] == epoch)
                        .context("191 queue cutoff member")?;
                    match row["stage"].as_str() {
                        Some("upload") => "upload",
                        Some("readback" | "source-revalidation") => "readback",
                        _ => "verification",
                    }
                }
                "upload-readback" => {
                    let f: Bound = serde_json::from_value(v["forecast"].clone())?;
                    let f = bound_json(&f, true)?;
                    let row = f["epochs"]
                        .as_array()
                        .context("191 forecast epochs")?
                        .iter()
                        .find(|r| r["epoch"] == epoch)
                        .context("191 forecast row")?;
                    if row["readback"]["state"] == "active" {
                        "readback"
                    } else {
                        "upload"
                    }
                }
                _ => "verification",
            };
            let root = p
                .cycle_directory
                .join(format!("cohort191-status-{epoch}/sealed"));
            let path = root.join("pipeline-plan.json");
            let model = json!({"schema":"jetstreamer-horizon-pipeline-status-plan-v1","epoch":epoch,"phase":phase,
                "binding":{"unit":c["unit"],"invocation_id":c["invocation_id"],"expected_exec_start":c["expected_exec_start"],
                "claim_phase":c["phase"],"origin_unit":UNIT,"origin_invocation_id":IID,"model_path":path,"model_sha256":"",
                "fleet_path":fleet.path,"fleet_sha256":fleet.sha256},"observer":observer,"fleet":fleet,
                "origin_launch":v["origins"][epoch.to_string()],"estimate_evidence":[event],
                "estimate_basis":"Exact native custody and stage forecast through serial authenticated sidecar commit",
                "estimated_remaining_millis":v["estimated_remaining_millis"][epoch.to_string()],
                "jet_path":v["archives"][epoch.to_string()]["path"],
                "expected_jet_size_bytes":v["archives"][epoch.to_string()]["length"],"peer_units":[],
                "receipt_directory":"/home/sol/.jetstreamer-private/r2-status-receipts","receipt_directory_uid":1001});
            // The canonical sealer, rather than a writable generated model,
            // owns every per-epoch publication plan.
            let package = delivery198::seal_values(
                p,
                &format!("cohort191-status-{epoch}"),
                &[("pipeline-plan.json", model)],
            )?;
            ensure!(package == root, "191 publication package namespace differs");
            let b = file(path, true)?;
            child(
                &s.publisher,
                &[
                    "status-publish-pipeline".into(),
                    b.path.display().to_string(),
                    "--plan-sha256".into(),
                    b.sha256,
                ],
                true,
                &p.cycle_directory
                    .join(format!("child-cohort191-status-{epoch}.json")),
            )?;
            let digits: String = p
                .sample_target_utc
                .chars()
                .filter(char::is_ascii_digit)
                .collect();
            let receipt = file(
                Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
                    .join(format!("epoch-{epoch}.status-{digits}.json")),
                false,
            )?;
            let r = bound_json(&receipt, false)?;
            ensure!(
                r["authenticated_readback"] == true
                    && r["epoch"] == epoch
                    && r["status"]["sampled_at_utc"] == p.sample_target_utc
                    && r["status"]["estimated_remaining_millis"]
                        == v["estimated_remaining_millis"][epoch.to_string()],
                "191 publication readback receipt differs"
            );
            publications.push(receipt);
        }
        Ok(
            json!({"enabled":true,"event":event,"status_publications":publications,"new_resource_samples":0}),
        )
    })();
    match attempt {
        Ok(v) => Ok(v),
        Err(e) => {
            let b = write_new(
                &p.cycle_directory
                    .join("cohort191-publication-incident.json"),
                &json!({"schema":"jetstreamer-cohort191-status-incident-v2","sampled_at_utc":p.sample_target_utc,
                "error":format!("{e:#}"),"other_lanes_continue":true,"new_resource_samples":0}),
            )?;
            Ok(
                json!({"enabled":true,"publication_skipped":true,"incident":b,"new_resource_samples":0}),
            )
        }
    }
}
pub(super) fn completion(p: &Plan, c: &Value) -> Result<()> {
    if p.cohort191_delivery.is_none() {
        return Ok(());
    }
    let s = &c["cohort191_delivery"];
    ensure!(
        s["enabled"] == true
            && s["new_resource_samples"] == 0
            && (s["status_publications"].is_array() || s["publication_skipped"] == true),
        "191 completion omitted publications or durable incident"
    );
    Ok(())
}
