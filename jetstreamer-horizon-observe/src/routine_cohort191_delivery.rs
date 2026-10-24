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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffSpec {
    schema: String,
    profile: Profile,
    publication_authorized: bool,
    replay_launch_authorized: bool,
    r2_mutations: bool,
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
    if v["schema"] == "jetstreamer-cohort191-terminal-transition-v1" {
        jetstreamer_horizon_observe::cohort191_delivery_model::validate_terminal_transition(
            &v,
            utc_seconds(&p.sample_target_utc)?,
        )?;
    } else {
        terminal(&v, utc_seconds(&p.sample_target_utc)?)?;
    }
    ensure!(
        v["capture_self_sha256"] == s.publisher.sha256
            && v["capture_program"].as_str() == s.publisher.path.to_str(),
        "191 transition producer differs from sealed publisher"
    );
    // Bind immutable capture provenance before removing the replay model. This
    // does not reuse a mutable controller state as historical terminal proof.
    let capture: Bound = serde_json::from_value(v["capture_plan"].clone())?;
    let c = bound_json(&capture, true)?;
    if v["schema"] == "jetstreamer-cohort191-terminal-transition-v1" {
        ensure!(
            c["schema"] == "jetstreamer-cohort191-terminal-collection-plan-v1"
                && c["program"] == serde_json::to_value(&s.publisher)?
                && c["source_batch"] == v["source_batch"]
                && c["public_batch"] == v["public_batch"]
                && c["output"].as_str() == s.terminal_event.path.to_str()
                && c.get("observer").is_none(),
            "191 terminal-only collector plan/program/import differs"
        );
    } else {
        ensure!(
            c["schema"] == "jetstreamer-cohort191-delivery-capture-plan-v2"
                && c["claims"] == v["claims"]
                && c["observer"] == v["observer"]
                && c["origins"] == v["origins"]
                && c["forecast"] == v["forecast"],
            "191 transition/capture provenance differs"
        );
    }
    Ok(())
}
const RANGES: [&str; 5] = ["152-153", "155-156", "191-194", "183-184", "185-185"];
const CID: &str = "c741f57764384e07a08484e6451f8f0c";
fn range_set(v: &Value, field: &str) -> Result<BTreeSet<String>> {
    let rows = v[field].as_array().context("191 closed replay census")?;
    let names = rows
        .iter()
        .map(|r| {
            r["range"]
                .as_str()
                .map(str::to_owned)
                .context("191 range name")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(names.len() == rows.len(), "191 duplicate replay range");
    Ok(names)
}
/// Pure bounded edit shared by the first offline preparation and its tests.
/// Only the terminal original cohort is removed; all remaining JSON is retained.
fn remove_replay(
    model: &Value,
    config: &Value,
    epochs: &[u64],
) -> Result<(Value, Value, Vec<u64>)> {
    let expected: BTreeSet<String> = RANGES.into_iter().map(str::to_owned).collect();
    ensure!(
        range_set(model, "ranges")? == expected && range_set(config, "replays")? == expected,
        "191 first transition requires exact five-owner predecessor"
    );
    let ranges = model["ranges"].as_array().unwrap();
    let target = ranges.iter().find(|r| r["range"] == "191-194").unwrap();
    ensure!(
        target["epochs"] == json!([191, 192, 193, 194])
            && target["expected_producer_invocation_id"] == IID
            && target["expected_controller_invocation_id"] == CID
            && target["terminal_slot"] == 84239999u64,
        "191 predecessor geometry/original binding differs"
    );
    for row in config["replays"].as_array().unwrap() {
        let m = ranges.iter().find(|m| m["range"] == row["range"]).unwrap();
        for key in [
            "expected_controller_invocation_id",
            "expected_producer_invocation_id",
        ] {
            ensure!(
                row[key] == m[key],
                "191 transition cannot change another current owner"
            );
        }
    }
    ensure!(
        epochs.iter().copied().collect::<BTreeSet<_>>().len() == epochs.len()
            && (191..=194).all(|e| epochs.contains(&e)),
        "191 predecessor must still own each exact epoch once"
    );
    let mut m = model.clone();
    m["ranges"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["range"] != "191-194");
    if let Some(names) = m["expected_observer_ranges"].as_array_mut() {
        names.retain(|r| r != "191-194");
    }
    let mut c = config.clone();
    c["replays"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["range"] != "191-194");
    Ok((
        m,
        c,
        epochs
            .iter()
            .copied()
            .filter(|e| !(191..=194).contains(e))
            .collect(),
    ))
}
pub(super) fn next_config(p: &Plan, config: &mut Value) -> Result<()> {
    if p.cohort191_delivery.is_none() {
        return Ok(());
    }
    validate(p)?;
    ensure!(
        range_set(config, "replays")?
            == RANGES
                .into_iter()
                .filter(|s| *s != "191-194")
                .map(str::to_owned)
                .collect(),
        "191 successor must retain exactly the other four observer owners"
    );
    Ok(())
}
/// Consumes only a real already-written root-only terminal proof and sealed
/// handoff spec. It takes no new observation and writes no operational receipt.
pub(super) fn enable(
    next: &mut Plan,
    config: &mut Value,
    model: &Value,
    spec: &Bound,
) -> Result<()> {
    ensure!(
        is_101(next)? && next.cohort191_delivery.is_none(),
        "191 transition is already enabled/foreign"
    );
    let value: HandoffSpec = serde_json::from_value(bound_json(spec, true)?)?;
    ensure!(
        value.schema == "jetstreamer-cohort191-routine-handoff-spec-v1"
            && !value.publication_authorized
            && !value.replay_launch_authorized
            && !value.r2_mutations,
        "191 handoff spec acquired authority"
    );
    let profile = value.profile;
    let proof = bound_json(&profile.terminal_event, false)?;
    ensure!(
        proof["schema"] == "jetstreamer-cohort191-terminal-transition-v1",
        "191 first transition requires observer-independent native terminal proof"
    );
    let (_model, edited, epochs) = remove_replay(model, config, &next.expected_epochs)?;
    next.cohort191_delivery = Some(profile);
    next.expected_epochs = epochs;
    validate(next)?;
    *config = edited;
    next.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
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
    ensure!(
        range_set(&next, "ranges")?
            == RANGES
                .into_iter()
                .filter(|s| *s != "191-194")
                .map(str::to_owned)
                .collect(),
        "191 effective model lost another original replay"
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    fn predecessor() -> (Value, Value, Vec<u64>) {
        let rows=RANGES.iter().enumerate().map(|(i,name)| {
            let (controller,producer,epochs)=if *name=="191-194" {(CID.into(),IID.into(),vec![191,192,193,194])} else {(format!("{:032x}",i+1),format!("{:032x}",i+16),vec![152+i as u64])};
            json!({"range":name,"epochs":epochs,"terminal_slot":84239999,"expected_controller_invocation_id":controller,"expected_producer_invocation_id":producer,"preserved_large_counter":u64::MAX})
        }).collect::<Vec<_>>();
        let model = json!({"ranges":rows,"expected_observer_ranges":RANGES,"evidence":[{"historical":"unchanged"}]});
        let config = json!({"replays":rows,"diagnostic_replays":[{"range":"141","owner":"unchanged"}],"minimum_interval_seconds":1800});
        (
            model,
            config,
            vec![152, 153, 155, 156, 183, 184, 185, 191, 192, 193, 194],
        )
    }
    #[test]
    fn exact_first_transition_preserves_all_survivors_diagnostics_and_large_counters() {
        let (m, c, e) = predecessor();
        let (next, config, epochs) = remove_replay(&m, &c, &e).unwrap();
        assert_eq!(
            next["ranges"],
            json!(
                m["ranges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["range"] != "191-194")
                    .collect::<Vec<_>>()
            )
        );
        assert_eq!(config["replays"], next["ranges"]);
        assert_eq!(config["diagnostic_replays"], c["diagnostic_replays"]);
        assert_eq!(config["minimum_interval_seconds"], 1800);
        assert_eq!(next["evidence"], m["evidence"]);
        assert_eq!(epochs, vec![152, 153, 155, 156, 183, 184, 185]);
        assert!(remove_replay(&next, &config, &epochs).is_err());
    }
    #[test]
    fn first_transition_rejects_missing_duplicate_foreign_or_rebound_owners() {
        let (m, c, e) = predecessor();
        for key in [
            "expected_controller_invocation_id",
            "expected_producer_invocation_id",
        ] {
            let mut bad = c.clone();
            bad["replays"][0][key] = json!("f".repeat(32));
            assert!(remove_replay(&m, &bad, &e).is_err());
        }
        let mut missing = c.clone();
        missing["replays"].as_array_mut().unwrap().pop();
        assert!(remove_replay(&m, &missing, &e).is_err());
        let mut duplicate = c.clone();
        duplicate["replays"][0] = duplicate["replays"][1].clone();
        assert!(remove_replay(&m, &duplicate, &e).is_err());
        let mut bad = m.clone();
        bad["ranges"][2]["epochs"] = json!([191, 192, 193]);
        assert!(remove_replay(&bad, &c, &e).is_err());
        let mut missing_epoch = e.clone();
        missing_epoch.pop();
        assert!(remove_replay(&m, &c, &missing_epoch).is_err());
        let mut duplicated_epoch = e;
        duplicated_epoch.push(191);
        assert!(remove_replay(&m, &c, &duplicated_epoch).is_err());
    }
    #[test]
    fn corrected_four_owner_config_passes_actual_gate_while_unmodified_five_owner_config_fails() {
        let (p, _, _, _, _, _, mut config, _) = super::super::tests::fixture();
        let (model, mut predecessor, epochs) = predecessor();
        predecessor["schema"] = config["schema"].clone();
        for key in [
            "output",
            "not_before_utc",
            "minimum_interval_seconds",
            "previous_sample",
        ] {
            predecessor[key] = config[key].clone();
        }
        // This fixture is an ordinary host profile; diagnostics are validated
        // separately and are deliberately not promoted to ordinary owners.
        predecessor
            .as_object_mut()
            .unwrap()
            .remove("diagnostic_replays");
        validate_observer_config(&p, &model, &predecessor).unwrap();
        let (four, corrected, _) = remove_replay(&model, &predecessor, &epochs).unwrap();
        assert!(validate_observer_config(&p, &four, &predecessor).is_err());
        validate_observer_config(&p, &four, &corrected).unwrap();
        config["replays"] = corrected["replays"].clone();
        assert_eq!(range_set(&config, "replays").unwrap().len(), 4);
    }
}
