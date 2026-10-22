//! Finish only the exact failed10:28 metadata transaction, without resampling.
use super::*;
const UNIT: &str = "horizon-routine-recover-assembly144-scans-1028-20261022-v1.service";
const OLD: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261022T102800Z-native141-rejection-assembly144-upload198-refresh-completed144-v1";
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let b = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&b),
    })
}
fn scope(p: &Plan, pb: &Bound) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.sample_target_utc == "2026-10-22T10:28:00Z"
            && p.assembly144_scans.is_some()
            && pb.sha256 == "fbd6a7d2a18e4cf753f45f3fbaea062fba54344c894aa6d650288dcdcc681940"
            && p.cycle_directory
                == Path::new(
                    "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261022T102800Z-native141-rejection-assembly144-scans-upload198-refresh-completed144-v1"
                ),
        "foreign assembly144 metadata recovery"
    );
    Ok(())
}
fn failed(name: &str, iid: &str) -> Result<()> {
    let o = Command::new("systemctl")
        .args([
            "show",
            name,
            "--property=MainPID,InvocationID,Result,ExecMainStatus,ActiveState,SubState,NRestarts",
        ])
        .output()?;
    ensure!(o.status.success(), "failed metadata owner unreadable");
    let t = std::str::from_utf8(&o.stdout)?;
    let f: BTreeMap<_, _> = t.lines().filter_map(|s| s.split_once('=')).collect();
    for (k, v) in [
        ("MainPID", "0"),
        ("InvocationID", iid),
        ("Result", "exit-code"),
        ("ExecMainStatus", "1"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("NRestarts", "0"),
    ] {
        ensure!(f.get(k) == Some(&v), "metadata owner differs:{k}");
    }
    Ok(())
}
fn unchanged_model(expected: &Value, original: &[u8]) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(expected)?;
    bytes.push(b'\n');
    ensure!(
        bytes == original,
        "recovery changes original ETA model bytes"
    );
    Ok(())
}
fn successful_child(value: &Value) -> Result<()> {
    ensure!(
        value["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && value["success"] == true
            && value["exit_code"] == 0
            && value["signal"].is_null(),
        "original metadata child did not succeed"
    );
    Ok(())
}
pub(super) fn run(p: &Plan, pb: &Bound, self_sha: &str, check: bool) -> Result<()> {
    scope(p, pb)?;
    let check_unit = format!("{}-check.service", UNIT.strip_suffix(".service").unwrap());
    let invocation = authenticate_named_service(if check { &check_unit } else { UNIT })?;
    failed(
        "horizon-routine-cycle-101-200-20261022T102800Z-native141-rejection-assembly144-upload198-refresh-completed144-v1.service",
        "c8ea97c1295149c8a4d8eaf5fe42d80d",
    )?;
    failed(&p.cycle_unit, "5699853378bd403ba44d6e99f2b09e8b")?;
    absent(&p.cycle_directory)?;
    absent(&p.fleet_output)?;
    let old = Path::new(OLD);
    let failure = file(old.join("failure.json"), false)?;
    let rejected = file(old.join("child-public198-fleet.json"), false)?;
    ensure!(
        failure.sha256 == "39ea532a50036303db52cc3daab710759a746319b6011b307e29dbb56bce5931"
            && rejected.sha256
                == "1ef52f815c56fa6e44c3ce2ef2c2620bc59dbe7ae40f97e5c1a9dc2501f2508d",
        "metadata failure evidence differs"
    );
    let intent = bound_json(&file(old.join("intent.json"), false)?, false)?;
    ensure!(
        intent["invocation_id"] == "c8ea97c1295149c8a4d8eaf5fe42d80d"
            && intent["plan"]["sha256"]
                == "b741f1aea4f5bc907b6ff6b9ceb7f7bd84ab3ee4b6a3f11afc733eb9f354cec5",
        "original transaction identity differs"
    );
    let observer = file(p.observer.clone(), false)?;
    ensure!(
        observer.sha256 == "fbb4b77a655d7594025c6672af374e103a43e4bf09a7cf8ba48fcdc2d4bbf735"
            && intent["observer"] == serde_json::to_value(&observer)?,
        "original observer changed"
    );
    let model = bound_json(&p.model_template, true)?;
    let fleet = bound_json(&p.fleet_template, true)?;
    let previous = bound_json(&p.previous_fleet, false)?;
    validate_templates(
        p,
        &model,
        &fleet,
        &previous,
        &bound_json(&p.previous_estimates, false)?,
        &bound_json(&p.previous_observer, false)?,
    )?;
    latest_fleet_unchanged(p, &previous)?;
    let effective = private144::effective_model(
        p,
        &delivery198::effective_model(p, &controller_recovery::model(p, &model)?)?,
    )?;
    validate_observer_config(p, &effective, &bound_json(&p.observer_config, true)?)?;
    terminal_handoff::preflight(p, &effective)?;
    let observed = bound_json(&observer, false)?;
    let effective = terminal_handoff::for_observation(p, &effective, &observed)?;
    let effective = cohort191::for_observation(p, &effective, &observed)?;
    validate_observation(
        p,
        &effective,
        &observed,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let (expected_model, expected_fleet) = derive(p, &effective, &fleet, &observer)?;
    let original_model = file(old.join("sealed/eta-model.json"), true)?;
    unchanged_model(&expected_model, &bound_bytes(&original_model, true)?)?;
    let estimates = file(p.estimate_output.clone(), false)?;
    let ev = bound_json(&estimates, false)?;
    ensure!(
        ev["model_sha256"] == original_model.sha256
            && ev["model_path"].as_str() == original_model.path.to_str()
            && ev["estimator_sha256"] == p.tools.estimator.sha256,
        "original estimate provenance differs"
    );
    successful_child(&bound_json(
        &file(old.join("child-estimator.json"), false)?,
        false,
    )?)?;
    let entries = verify_estimates(p, &expected_model, &observer, &ev)?;
    let mut statuses = Vec::new();
    for e in entries {
        let epoch = e["epoch"].as_u64().context("status epoch")?;
        let b = file(
            Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
                .join(format!("epoch-{epoch}.status-20261022102800.json")),
            false,
        )?;
        next_preparation::validate_status(&bound_json(&b, false)?, p, &observer, &e)?;
        successful_child(&bound_json(
            &file(old.join(format!("child-status-{epoch}.json")), false)?,
            false,
        )?)?;
        statuses.push(b);
    }
    for tool in [&p.tools.r2, &p.tools.sealer, &p.tools.estimator] {
        tool_ok(tool)?;
    }
    ensure!(
        sha(env::var("HORIZON_S3_ENDPOINT")
            .context("endpoint missing")?
            .as_bytes())
            == p.endpoint_sha256,
        "recovery endpoint differs"
    );
    if check {
        println!(
            "exact10:28 recovery evidence passed; no sampling, writes, status publication or remote access"
        );
        return Ok(());
    }
    fs::create_dir(&p.cycle_directory)?;
    fs::set_permissions(&p.cycle_directory, fs::Permissions::from_mode(0o700))?;
    File::open(p.cycle_directory.parent().unwrap())?.sync_all()?;
    let recovery = write_new(
        &p.cycle_directory.join("intent.json"),
        &json!({"schema":"jetstreamer-assembly144-scans-metadata-recovery-intent-v1",
        "plan":pb,"failure":failure,"failed_child":rejected,"observer":observer,"original_model":original_model,
        "estimates":estimates,"status_publications":statuses,"invocation_id":invocation,"self_sha256":self_sha,
        "new_resource_samples":0,"status_republication":false,"archive_mutations":false,"replay_launch_authorized":false}),
    )?;
    // Copy only the independently reproduced model bytes into the normal
    // completion namespace. Preserve the estimate's original source-model path.
    let model_source = write_new(
        &p.cycle_directory.join("model-source.json"),
        &expected_model,
    )?;
    let fleet_source = write_new(
        &p.cycle_directory.join("fleet-source.json"),
        &expected_fleet,
    )?;
    let package = p.cycle_directory.join("sealed");
    let seal_plan = write_new(
        &p.cycle_directory.join("seal-plan.json"),
        &json!({
        "schema":"jetstreamer-sealed-deployment-plan-v1","destination":package,"members":[
        {"source":model_source.path,"name":"eta-model.json","sha256":model_source.sha256,"mode":292},
        {"source":fleet_source.path,"name":"fleet-plan.json","sha256":fleet_source.sha256,"mode":292}]}),
    )?;
    child(
        &p.tools.sealer,
        &[
            seal_plan.path.display().to_string(),
            "--plan-sha256".into(),
            seal_plan.sha256,
            "--self-sha256".into(),
            p.tools.sealer.sha256.clone(),
        ],
        false,
        &p.cycle_directory.join("child-sealer.json"),
    )?;
    let model = file(package.join("eta-model.json"), true)?;
    let fleet_plan = file(package.join("fleet-plan.json"), true)?;
    ensure!(
        model.sha256 == original_model.sha256,
        "copied model bytes differ"
    );
    let pipeline = public198::publish(p, &expected_fleet, &observer)?;
    latest_fleet_unchanged(p, &previous)?;
    child(
        &p.tools.r2,
        &[
            "fleet-reconcile".into(),
            fleet_plan.path.display().to_string(),
            "--plan-sha256".into(),
            fleet_plan.sha256.clone(),
        ],
        true,
        &p.cycle_directory.join("child-fleet.json"),
    )?;
    let ledger = file(p.fleet_output.clone(), false)?;
    let lv = bound_json(&ledger, false)?;
    ensure!(
        lv["plan_sha256"] == fleet_plan.sha256
            && lv["observer_sha256"] == observer.sha256
            && lv["sampled_at_utc"] == p.sample_target_utc
            && lv["inventory"]["anomalies"] == 0,
        "recovered fleet differs"
    );
    write_new(
        &p.cycle_directory.join("completion.json"),
        &json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1",
        "plan":pb,"self_sha256":self_sha,"invocation_id":invocation,"sampled_at_utc":p.sample_target_utc,
        "observer":observer,"model":model,"estimates":estimates,"fleet_plan":fleet_plan,"fleet":ledger,"inventory":lv["inventory"],
        "status_publications":statuses,"epoch198_delivery":pipeline,"assembly144_metadata_recovery":recovery,
        "new_resource_samples":0,"archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false,"deletions":false}),
    )?;
    println!(
        "exact10:28 fleet recovered; original sample, estimate, nine statuses and failures preserved"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_model_requires_exact_bytes_not_just_equivalent_json() {
        let value = json!({"n":9007199254740993u64});
        let mut bytes = serde_json::to_vec_pretty(&value).unwrap();
        bytes.push(b'\n');
        unchanged_model(&value, &bytes).unwrap();
        assert!(unchanged_model(&value, &serde_json::to_vec(&value).unwrap()).is_err());
        assert!(unchanged_model(&json!({"n":9007199254740992u64}), &bytes).is_err());
    }
    #[test]
    fn successful_child_rejects_partial_failed_or_signaled_results() {
        let good = json!({"schema":"jetstreamer-horizon-routine-child-result-v1","success":true,"exit_code":0,"signal":null});
        successful_child(&good).unwrap();
        for (field, replacement) in [
            ("schema", json!("foreign")),
            ("success", json!(false)),
            ("exit_code", json!(1)),
            ("signal", json!(9)),
        ] {
            let mut bad = good.clone();
            bad[field] = replacement;
            assert!(successful_child(&bad).is_err());
        }
        assert!(successful_child(&json!({"success":true})).is_err());
    }
    #[test]
    fn scope_rejects_foreign_plan_or_sample() {
        let (p, ..) = crate::tests::fixture101();
        let mut v = serde_json::to_value(p).unwrap();
        v["assembly144_scans"] = json!({"full":{"path":"/proof/full","sha256":"a".repeat(64)},"plugin":{"path":"/proof/plugin","sha256":"b".repeat(64)}});
        let mut p: Plan = serde_json::from_value(v).unwrap();
        p.sample_target_utc = "2026-10-22T10:28:00Z".into();
        p.cycle_directory="/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261022T102800Z-native141-rejection-assembly144-scans-upload198-refresh-completed144-v1".into();
        let mut b = Bound {
            path: "/plan".into(),
            sha256: "fbd6a7d2a18e4cf753f45f3fbaea062fba54344c894aa6d650288dcdcc681940".into(),
        };
        scope(&p, &b).unwrap();
        b.sha256 = "c".repeat(64);
        assert!(scope(&p, &b).is_err());
        b.sha256 = "fbd6a7d2a18e4cf753f45f3fbaea062fba54344c894aa6d650288dcdcc681940".into();
        p.sample_target_utc = "2026-10-22T10:58:00Z".into();
        assert!(scope(&p, &b).is_err());
    }
}
