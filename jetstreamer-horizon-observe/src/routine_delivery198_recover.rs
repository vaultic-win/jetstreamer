//! Finish only the failed20:18 metadata transaction; never resample or replay.
use super::*;
const UNIT: &str = "horizon-routine-recover-delivery198-2018-20261021-v1.service";
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn scope(p: &Plan, pb: &Bound) -> Result<()> {
    ensure!(
        pb.sha256 == "5820b69150677bd27c3a2dc18d8d101332c556b3e3078bd37281d409ee7e4014"
            && p.sample_target_utc == "2026-10-21T20:18:00Z"
            && is_101(p)?
            && p.cycle_directory
                == Path::new(
                    "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261021T201800Z-delivery198-completed144-v1"
                ),
        "foreign198 failed-cycle recovery"
    );
    Ok(())
}
pub(super) fn run(p: &Plan, pb: &Bound, self_sha: &str) -> Result<()> {
    scope(p, pb)?;
    let invocation = authenticate_named_service(UNIT)?;
    let root = &p.cycle_directory;
    absent(&root.join("completion.json"))?;
    let failure = file(root.join("failure.json"), false)?;
    let check = file(root.join("child-delivery198-check.json"), false)?;
    ensure!(
        failure.sha256 == "afc84dc94ebf5b8a6267a4ebf3232cdc8f36100be9cb69fe933c05eeded7f99b"
            && check.sha256 == "af890856c1566551962c8c4fe13f890e3cfc89215b0e2d61c09345c30693aa14",
        "198 recovery failure evidence differs"
    );
    let intent = bound_json(&file(root.join("intent.json"), false)?, false)?;
    ensure!(
        intent["plan"] == serde_json::to_value(pb)?
            && intent["invocation_id"] == "5d23eac5bdc04ba28dbc29f95c62786d",
        "198 recovery intent differs"
    );
    let output = Command::new("systemctl")
        .args([
            "show",
            &p.cycle_unit,
            "--property=MainPID,InvocationID,Result,ExecMainStatus,ActiveState,SubState",
        ])
        .output()?;
    ensure!(output.status.success(), "198 failed unit unreadable");
    let fields: BTreeMap<_, _> = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(|l| l.split_once('=').context("198 unit property"))
        .collect::<Result<_>>()?;
    for (k, v) in [
        ("MainPID", "0"),
        ("InvocationID", "5d23eac5bdc04ba28dbc29f95c62786d"),
        ("Result", "exit-code"),
        ("ExecMainStatus", "1"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
    ] {
        ensure!(fields.get(k) == Some(&v), "198 failed owner differs:{k}");
    }
    let observer = file(p.observer.clone(), false)?;
    ensure!(
        observer.sha256 == "a875e052381e1fdf0aee6e1e847649a0c99b808f77a27e20937e895a303f3e03"
            && intent["observer"] == serde_json::to_value(&observer)?,
        "198 original sample changed"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        now.checked_sub(utc_seconds(&p.sample_target_utc)?)
            .is_some_and(|n| n <= 1800),
        "198 metadata recovery sample stale"
    );
    let model = file(root.join("sealed/eta-model.json"), true)?;
    let fleet_plan = file(root.join("sealed/fleet-plan.json"), true)?;
    let old_model = bound_json(&p.model_template, true)?;
    let old_fleet = bound_json(&p.fleet_template, true)?;
    let old_ledger = bound_json(&p.previous_fleet, false)?;
    validate_templates(
        p,
        &old_model,
        &old_fleet,
        &old_ledger,
        &bound_json(&p.previous_estimates, false)?,
        &bound_json(&p.previous_observer, false)?,
    )?;
    let effective = private144::effective_model(
        p,
        &delivery198::effective_model(p, &controller_recovery::model(p, &old_model)?)?,
    )?;
    let observed = bound_json(&observer, false)?;
    let effective = terminal_handoff::for_observation(p, &effective, &observed)?;
    validate_observation(p, &effective, &observed, now)?;
    let (expected_model, expected_fleet) = derive(p, &effective, &old_fleet, &observer)?;
    ensure!(
        bound_json(&model, true)? == expected_model
            && bound_json(&fleet_plan, true)? == expected_fleet,
        "198 sealed transaction does not reproduce original derivation"
    );
    let estimates = file(p.estimate_output.clone(), false)?;
    let estimate_value = bound_json(&estimates, false)?;
    ensure!(
        estimate_value["model_sha256"] == model.sha256,
        "198 recovered estimate/model mismatch"
    );
    let entries = verify_estimates(p, &bound_json(&model, true)?, &observer, &estimate_value)?;
    let mut statuses = Vec::new();
    for entry in entries {
        let epoch = entry["epoch"].as_u64().context("198 peer epoch")?;
        let publication = file(
            Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
                .join(format!("epoch-{epoch}.status-20261021201800.json")),
            false,
        )?;
        next_preparation::validate_status(&bound_json(&publication, false)?, p, &observer, &entry)?;
        let result = bound_json(
            &file(root.join(format!("child-status-{epoch}.json")), false)?,
            false,
        )?;
        ensure!(result["success"] == true, "198 peer status child failed");
        statuses.push(publication);
    }
    let previous = bound_json(&p.previous_fleet, false)?;
    latest_fleet_unchanged(p, &previous)?;
    let tool = Bound {
        path: prefix144::RECOVERY_WRITER.into(),
        sha256: prefix144::RECOVERY_WRITER_SHA.into(),
    };
    tool_ok(&tool)?;
    ensure!(
        sha(env::var("HORIZON_S3_ENDPOINT")
            .context("198 recovery endpoint missing")?
            .as_bytes())
            == p.endpoint_sha256,
        "198 recovery endpoint changed"
    );
    let recovery = root.join("metadata-recovery-v1");
    absent(&recovery)?;
    fs::create_dir(&recovery)?;
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700))?;
    File::open(root)?.sync_all()?;
    write_new(
        &recovery.join("intent.json"),
        &json!({"schema":"jetstreamer-epoch198-metadata-recovery-intent-v1","plan":pb,"failure":failure,"failed_child":check,"observer":observer,"tool":tool,"invocation_id":invocation,"self_sha256":self_sha,"new_resource_samples":0,"replay_launch_authorized":false,"archive_mutations":false}),
    )?;
    let pipeline_plan = file(
        root.join("delivery198-status/sealed/pipeline-plan.json"),
        true,
    )?;
    for (name, check) in [("check", true), ("publish", false)] {
        let mut args = vec![
            "status-publish-pipeline".into(),
            pipeline_plan.path.display().to_string(),
            "--plan-sha256".into(),
            pipeline_plan.sha256.clone(),
        ];
        if check {
            args.push("--check-only".into());
        }
        child(
            &tool,
            &args,
            !check,
            &recovery.join(format!("child-{name}.json")),
        )?;
    }
    let publication = file(
        PathBuf::from(
            "/home/sol/.jetstreamer-private/r2-status-receipts/epoch-198.status-20261021201800.json",
        ),
        false,
    )?;
    let provisional = file(root.join("delivery198-provisional-fleet.json"), false)?;
    let pipeline = json!({"pipeline_plan":pipeline_plan,"provisional_fleet":provisional,"publication":publication});
    let mut completion = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","plan":pb,"self_sha256":self_sha,"invocation_id":invocation,"sampled_at_utc":p.sample_target_utc,"observer":observer,"model":model,"estimates":estimates,"fleet_plan":fleet_plan,"status_publications":statuses,"epoch198_delivery":pipeline,"recovery_intent":file(recovery.join("intent.json"),false)?,"new_resource_samples":0,"replay_launch_authorized":false,"archive_mutations":false,"sidecar_mutations":false,"deletions":false});
    delivery198::validate_completed(p, &completion)?;
    latest_fleet_unchanged(p, &previous)?;
    child(
        &tool,
        &[
            "fleet-reconcile".into(),
            fleet_plan.path.display().to_string(),
            "--plan-sha256".into(),
            fleet_plan.sha256.clone(),
        ],
        true,
        &recovery.join("child-fleet.json"),
    )?;
    let fleet = file(p.fleet_output.clone(), false)?;
    let ledger = bound_json(&fleet, false)?;
    ensure!(
        ledger["plan_sha256"] == fleet_plan.sha256
            && ledger["observer_sha256"] == observer.sha256
            && ledger["sampled_at_utc"] == p.sample_target_utc
            && ledger["inventory"]["anomalies"] == 0,
        "198 recovered fleet differs"
    );
    completion["fleet"] = serde_json::to_value(fleet)?;
    completion["inventory"] = ledger["inventory"].clone();
    write_new(&root.join("completion.json"), &completion)?;
    println!("198 metadata cycle recovered; original failure preserved, zero new resource samples");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_cannot_target_another_cycle_or_plan() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let mut b = Bound {
            path: "/plan".into(),
            sha256: "5820b69150677bd27c3a2dc18d8d101332c556b3e3078bd37281d409ee7e4014".into(),
        };
        p.sample_target_utc = "2026-10-21T20:18:00Z".into();
        p.cycle_directory="/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261021T201800Z-delivery198-completed144-v1".into();
        scope(&p, &b).unwrap();
        b.sha256 = "a".repeat(64);
        assert!(scope(&p, &b).is_err());
        b.sha256 = "5820b69150677bd27c3a2dc18d8d101332c556b3e3078bd37281d409ee7e4014".into();
        p.sample_target_utc = "2026-10-21T20:48:00Z".into();
        assert!(scope(&p, &b).is_err());
    }
}
