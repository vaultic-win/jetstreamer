//! Exact 03:16 native importer gate-contract continuation after six status writes.
//! Preserve failed artifacts and original sample; never repeat replay statuses.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261024T031600Z-guard-stopped185-import-pending191-repair141-v2";
const PLAN_SHA: &str = "a3520473cf2ae7d0d6066b84116b5e0bc9e75240bc1f4d4faa442d576ed07ae0";
const ORIGINAL_IID: &str = "af569030e39d4e5ea1e7a2b4efc59bd6";
const UNIT: &str = "horizon-cohort191-gate-recovery-20261024-v1.service";
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn successful(v: &Value, tool: &Bound) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && v["success"] == true
            && v["exit_code"] == 0
            && v["signal"].is_null()
            && v["tool"] == serde_json::to_value(tool)?,
        "original metadata child not successful"
    );
    Ok(())
}
fn exact(p: &Plan, pb: &Bound, i: &Value, f: &Value) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.cycle_directory == Path::new(ROOT)
            && p.sample_target_utc == "2026-10-24T03:16:00Z"
            && pb.sha256 == PLAN_SHA
            && p.publication144.is_some()
            && cohort191_import::enabled(p)
            && terminal185::enabled(p)
            && repair141_status::enabled(p)
            && i["plan"] == serde_json::to_value(pb)?
            && i["invocation_id"] == ORIGINAL_IID
            && i["self_sha256"]
                == "4870d485bfcb486940e6ba19f99e7c7baab4f2847647af98cfcef6d3ea1ef85c"
            && f["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && f["success"] == false
            && f["exit_code"] == 1
            && f["signal"].is_null()
            && f["tool"] == serde_json::to_value(cohort191_delivery::fleet_reader(p))?
            && f["stderr"]["text"]
                == "Error: live pipeline requires an independently evidenced post-replay gate\n",
        "not the exact 03:16 original 191 gate contract failure"
    );
    Ok(())
}
pub(super) fn run(p: &Plan, pb: &Bound, self_sha: &str, check: bool) -> Result<()> {
    let intent = file(p.cycle_directory.join("intent.json"), false)?;
    let failed = Bound {
        path: p.cycle_directory.join("child-public198-fleet.json"),
        sha256: "01c0cc48510d43998ab46505b42d8d1d403d220fd02e746daeb4bdd72d195fa2".into(),
    };
    let i = bound_json(&intent, false)?;
    exact(p, pb, &i, &bound_json(&failed, false)?)?;
    let o = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            &p.cycle_unit,
            "--property=InvocationID,NRestarts,MainPID,ActiveState,SubState,Result,ExecMainStatus",
        ])
        .output()?;
    ensure!(o.status.success(), "original cycle unavailable");
    let fields: BTreeMap<_, _> = std::str::from_utf8(&o.stdout)?
        .lines()
        .filter_map(|s| s.split_once('='))
        .collect();
    for (k, v) in [
        ("InvocationID", ORIGINAL_IID),
        ("NRestarts", "0"),
        ("MainPID", "0"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
        ("ExecMainStatus", "1"),
    ] {
        ensure!(
            fields.get(k) == Some(&v),
            "original failed cycle changed:{k}"
        );
    }
    let observer = Bound {
        path: p.observer.clone(),
        sha256: "d84a0c4a8459eef580736daebeb2a551c3e28548bf37a8c0339c7fdb07fdf929".into(),
    };
    ensure!(
        i["observer"] == serde_json::to_value(&observer)?,
        "original observer changed"
    );
    bound_json(&observer, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sample = utc_seconds(&p.sample_target_utc)?;
    ensure!(
        sample <= now && now - sample <= 1800,
        "history recovery needs original fresh resource sample, not a replacement observation"
    );
    let model = file(p.cycle_directory.join("sealed/eta-model.json"), true)?;
    let mv = bound_json(&model, true)?;
    let estimates = file(p.estimate_output.clone(), false)?;
    let ev = bound_json(&estimates, false)?;
    ensure!(
        ev["model_sha256"] == model.sha256 && ev["estimator_sha256"] == p.tools.estimator.sha256,
        "original estimate lineage changed"
    );
    successful(
        &bound_json(
            &file(p.cycle_directory.join("child-estimator.json"), false)?,
            false,
        )?,
        &p.tools.estimator,
    )?;
    let mut statuses = Vec::new();
    ensure!(
        p.expected_epochs == [152, 153, 155, 156, 183, 184],
        "191 recovery ordinary status census changed"
    );
    for e in verify_estimates(p, &mv, &observer, &ev)? {
        let epoch = e["epoch"].as_u64().context("epoch")?;
        successful(
            &bound_json(
                &file(
                    p.cycle_directory.join(format!("child-status-{epoch}.json")),
                    false,
                )?,
                false,
            )?,
            &p.tools.r2,
        )?;
        let b = file(
            Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
                .join(format!("epoch-{epoch}.status-20261024031600.json")),
            false,
        )?;
        next_preparation::validate_status(&bound_json(&b, false)?, p, &observer, &e)?;
        statuses.push(b);
    }
    let original = file(p.cycle_directory.join("sealed/fleet-plan.json"), true)?;
    let original_value = bound_json(&original, true)?;
    ensure!(
        original_value["observer"] == serde_json::to_value(&observer)?
            && original_value["previous_fleet"] == serde_json::to_value(&p.previous_fleet)?
            && original_value["output"].as_str() == p.fleet_output.to_str(),
        "191 original final fleet provenance changed"
    );
    let mut corrected = original_value.clone();
    cohort191_delivery::derive_fleet(p, &mut corrected)?;
    correction_scope(&original_value, &corrected)?;
    let accepted = file(p.cycle_directory.join("cohort191-accepted.json"), false)?;
    let acceptance = bound_json(&accepted, false)?;
    let event: Bound = serde_json::from_value(acceptance["event"].clone())?;
    let native = bound_json(&event, false)?;
    ensure!(
        event.sha256 == "d986ae11f06377cb742eb78f9412b1cd398683ec9604ede6e347bee0518dc588"
            && native["observer"] == serde_json::to_value(&observer)?
            && native["capture_self_sha256"]
                == "9ff8bd9896da179d67ba030153e31917177fc706af0a79ec2d5aa68f90ccfa96",
        "191 accepted actual importer evidence changed"
    );
    let writer = cohort191_delivery::fleet_reader(p);
    tool_ok(writer)?;
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    absent(&p.fleet_output)?;
    absent(&p.cycle_directory.join("completion.json"))?;
    absent(&p.cycle_directory.join("public198-provisional-fleet.json"))?;
    let root = p.cycle_directory.join("cohort191-gate-recovery-v1");
    absent(&root)?;
    ensure!(
        sha(env::var("HORIZON_S3_ENDPOINT")?.as_bytes()) == p.endpoint_sha256,
        "191 recovery endpoint differs"
    );
    if check {
        println!(
            "exact 191 gate continuation preflight passed; no observation, remote request or status rewrite"
        );
        return Ok(());
    }
    let iid = authenticate_named_service(UNIT)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    File::open(&p.cycle_directory)?.sync_all()?;
    let recovery = write_new(
        &root.join("intent.json"),
        &json!({
        "schema":"jetstreamer-exact191-gate-recovery-v1","original_intent":intent,
        "failed_child":failed,"original_fleet_plan":original,"accepted_native_event":event,
        "writer":writer,"observer":observer,"recovery_invocation_id":iid,
        "new_resource_samples":0,"replay_status_republications":0,"archive_mutations":false}),
    )?;
    let mut provisional_value = corrected.clone();
    provisional_value["output"] = json!(p.cycle_directory.join("public198-provisional-fleet.json"));
    let package = delivery198::seal_values(
        p,
        "cohort191-gate-recovery-plans",
        &[
            ("fleet-plan.json", corrected),
            ("provisional-plan.json", provisional_value),
        ],
    )?;
    let fleet_plan = file(package.join("fleet-plan.json"), true)?;
    let provisional_plan = file(package.join("provisional-plan.json"), true)?;
    let pipeline = public198::publish_sealed(
        p,
        &observer,
        &provisional_plan,
        &root.join("child-provisional-fleet.json"),
    )?;
    let d144 = publication144::publish(p, &pipeline, &observer)?;
    let d160 = delivery160::publish(p, &pipeline, &observer)?;
    let d141 = qualification141_status::publish(p, &pipeline, &observer)?;
    let d191 = cohort191_delivery::publish(p, &pipeline, &observer)?;
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    child(
        writer,
        &[
            "fleet-reconcile".into(),
            fleet_plan.path.display().to_string(),
            "--plan-sha256".into(),
            fleet_plan.sha256.clone(),
        ],
        true,
        &root.join("child-final-fleet.json"),
    )?;
    let fleet = file(p.fleet_output.clone(), false)?;
    let ledger = bound_json(&fleet, false)?;
    ensure!(
        ledger["observer_sha256"] == observer.sha256
            && ledger["plan_sha256"] == fleet_plan.sha256
            && ledger["sampled_at_utc"] == p.sample_target_utc
            && ledger["inventory"]["anomalies"] == 0,
        "191 recovered fleet differs"
    );
    let observed = bound_json(&observer, false)?;
    let capacity = capacity::decision(p, &observed, &ledger)?;
    let c = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","plan":pb,
        "self_sha256":self_sha,"sampled_at_utc":p.sample_target_utc,"observer":observer,
        "model":model,"estimates":estimates,"invocation_id":iid,"fleet_plan":fleet_plan,
        "fleet":fleet,"status_publications":statuses,"inventory":ledger["inventory"],
        "epoch198_delivery":pipeline,"epoch160_delivery":d160,"epoch144_delivery":d144,
        "qualification141_status":d141,"cohort191_delivery":d191,"capacity_decision":capacity,
        "cohort191_gate_recovery":recovery,"new_resource_samples":0,
        "replay_status_republications":0,"archive_mutations":false,"sidecar_mutations":false,
        "replay_launch_authorized":false,"deletions":false});
    next_preparation::completion_bindings(p, pb, &c)?;
    public198::validate_completed(p, &c)?;
    delivery160::validate_completed(p, &c)?;
    publication144::validate_completed(p, &c)?;
    write_new(&root.join("completion.json"), &c)?;
    write_new(&p.cycle_directory.join("completion.json"), &c)?;
    Ok(())
}
fn correction_scope(original: &Value, corrected: &Value) -> Result<()> {
    let mut expected = original.clone();
    for epoch in 191..=194 {
        let key = epoch.to_string();
        ensure!(
            original["gates"][&key]["state"] == "blocked-qualification"
                && corrected["gates"][&key]["state"] == "post-replay-pipeline",
            "191 gate correction scope/state differs"
        );
        expected["gates"][&key] = corrected["gates"][&key].clone();
    }
    ensure!(
        expected == *corrected,
        "191 gate correction changed another field"
    );
    Ok(())
}
pub(super) fn completed(p: &Plan, c: &Value) -> Result<bool> {
    if c["cohort191_gate_recovery"].is_null() {
        return Ok(false);
    }
    ensure!(
        p.cycle_directory == Path::new(ROOT) && p.sample_target_utc == "2026-10-24T03:16:00Z",
        "191 recovery completion belongs to another cycle"
    );
    let intent: Bound = serde_json::from_value(c["cohort191_gate_recovery"].clone())?;
    let v = bound_json(&intent, false)?;
    ensure!(
        intent.path
            == p.cycle_directory
                .join("cohort191-gate-recovery-v1/intent.json")
            && v["schema"] == "jetstreamer-exact191-gate-recovery-v1"
            && v["new_resource_samples"] == 0
            && v["replay_status_republications"] == 0,
        "191 recovery completion lost exact original intent"
    );
    let original: Bound = serde_json::from_value(v["original_fleet_plan"].clone())?;
    let corrected: Bound = serde_json::from_value(c["fleet_plan"].clone())?;
    ensure!(
        original.path == p.cycle_directory.join("sealed/fleet-plan.json")
            && corrected.path
                == p.cycle_directory
                    .join("cohort191-gate-recovery-plans/sealed/fleet-plan.json"),
        "191 recovery fleet package differs"
    );
    correction_scope(
        &bound_json(&original, true)?,
        &bound_json(&corrected, true)?,
    )?;
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn correction_cannot_change_other_gates_owners_or_provenance() {
        let original = json!({"gates":(190..=195).map(|e|(e.to_string(),json!({"state":"blocked-qualification","evidence":[]}))).collect::<BTreeMap<_,_>>(),"observer":"original","pipeline_claims":["native"]});
        let mut corrected = original.clone();
        for e in 191..=194 {
            corrected["gates"][e.to_string()]["state"] = json!("post-replay-pipeline");
        }
        correction_scope(&original, &corrected).unwrap();
        for key in ["observer", "pipeline_claims"] {
            let mut bad = corrected.clone();
            bad[key] = json!("substituted");
            assert!(correction_scope(&original, &bad).is_err());
        }
        let mut bad = corrected;
        bad["gates"]["190"]["state"] = json!("post-replay-pipeline");
        assert!(correction_scope(&original, &bad).is_err());
    }
}
