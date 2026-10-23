//! Exact early fleet-contract recovery, after eight original status writes.
//! Preserve failed artifacts and original sample; never repeat replay statuses.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261023T002800Z-publication144-census141-boundaries-native141-all-retry-public160-timed-scans-upload198-v1";
const PLAN_SHA: &str = "c4efec9ee89cb1bcd2386135b788724a04eaa4f82450ea56ae0d2058c9454807";
const ORIGINAL_IID: &str = "42ca2ec3426e4ab28272e9eece47cac9";
const UNIT: &str = "horizon-publication144-history-recovery-20261023-v1.service";
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
            && p.sample_target_utc == "2026-10-23T00:28:00Z"
            && pb.sha256 == PLAN_SHA
            && p.publication144.is_some()
            && !publication144::uploading(p)
            && i["plan"] == serde_json::to_value(pb)?
            && i["invocation_id"] == ORIGINAL_IID
            && i["self_sha256"]
                == "b1e3882377f060b506e15695d110b944a29b74f0393c39789db0f827ddb7e13f"
            && f["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && f["success"] == false
            && f["exit_code"] == 1
            && f["signal"].is_null()
            && f["tool"] == serde_json::to_value(&p.tools.r2)?
            && f["stderr"]["text"]
                == "Error: private144 fleet scope, gate, tracking or overlapping owner differs\n",
        "not the exact original144 private/public contract failure"
    );
    Ok(())
}
pub(super) fn run(p: &Plan, pb: &Bound, self_sha: &str, check: bool) -> Result<()> {
    let intent = file(p.cycle_directory.join("intent.json"), false)?;
    let failed = Bound {
        path: p.cycle_directory.join("child-public198-fleet.json"),
        sha256: "05a2a11e2262b45e4248f155967987968a7329c6f39e397af211d227f721ff17".into(),
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
        sha256: "e7bf36cf9b1622f6c5febdd45db52ac782d24f2a72dee50652e08ee7136d8735".into(),
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
        "history recovery needs original fresh resource sample,not a replacement observation"
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
                .join(format!("epoch-{epoch}.status-20261023002800.json")),
            false,
        )?;
        next_preparation::validate_status(&bound_json(&b, false)?, p, &observer, &e)?;
        statuses.push(b);
    }
    let provisional_plan = Bound {
        path: p
            .cycle_directory
            .join("public198-stage/sealed/fleet-plan.json"),
        sha256: "76c237192426062c4b8a30661bed7e2ab773dd960ff6b0686576a1df9dade123".into(),
    };
    bound_json(&provisional_plan, true)?;
    let fleet_plan = file(p.cycle_directory.join("sealed/fleet-plan.json"), true)?;
    let fv = bound_json(&fleet_plan, true)?;
    ensure!(
        fv["observer"] == serde_json::to_value(&observer)?
            && fv["previous_fleet"] == serde_json::to_value(&p.previous_fleet)?
            && fv["output"].as_str() == p.fleet_output.to_str(),
        "final fleet source changed"
    );
    let writer = Bound {
        path: publication144::HISTORY_READER.into(),
        sha256: publication144::HISTORY_READER_SHA.into(),
    };
    tool_ok(&writer)?;
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    absent(&p.fleet_output)?;
    absent(&p.cycle_directory.join("completion.json"))?;
    let root = p.cycle_directory.join("private-public-history-recovery-v1");
    absent(&root)?;
    ensure!(
        sha(env::var("HORIZON_S3_ENDPOINT")?.as_bytes()) == p.endpoint_sha256,
        "recovery endpoint differs"
    );
    if check {
        println!(
            "exact144 history recovery qualified; no resource sample,status write or remote request"
        );
        return Ok(());
    }
    let iid = authenticate_named_service(UNIT)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    File::open(&p.cycle_directory)?.sync_all()?;
    let recovery = write_new(
        &root.join("intent.json"),
        &json!({"schema":"jetstreamer-exact144-private-public-history-recovery-v1","original_intent":intent,"failed_child":failed,"writer":writer,"observer":observer,"recovery_invocation_id":iid,"new_resource_samples":0,"replay_status_republications":0,"archive_mutations":false}),
    )?;
    child(
        &writer,
        &[
            "fleet-reconcile".into(),
            provisional_plan.path.display().to_string(),
            "--plan-sha256".into(),
            provisional_plan.sha256.clone(),
        ],
        true,
        &root.join("child-provisional-fleet.json"),
    )?;
    let provisional = file(
        p.cycle_directory.join("public198-provisional-fleet.json"),
        false,
    )?;
    let pf = bound_json(&provisional, false)?;
    ensure!(
        pf["observer_sha256"] == observer.sha256
            && pf["plan_sha256"] == provisional_plan.sha256
            && pf["inventory"]["anomalies"] == 0,
        "recovered provisional fleet differs"
    );
    for epoch in [160, 198] {
        ensure!(
            pf["epochs"]
                .as_array()
                .context("epochs")?
                .iter()
                .any(|e| e["epoch"] == epoch
                    && e["state"] == "remote-ready"
                    && e["status"].is_null()),
            "downstream readiness changed"
        );
    }
    let pipeline = json!({"provisional_fleet":provisional,"publication_skipped":true,"reason":"No authenticated current198 verifier child; stage transition/status cleanup requires prompt reconciliation"});
    let d144 = publication144::publish_using(p, &pipeline, &observer, &writer)?;
    let d160 = delivery160::publish(p, &pipeline, &observer)?;
    child(
        &writer,
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
        "recovered final fleet differs"
    );
    let c = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","plan":pb,"self_sha256":self_sha,"sampled_at_utc":p.sample_target_utc,"observer":observer,"model":model,"estimates":estimates,"invocation_id":iid,"fleet_plan":fleet_plan,"fleet":fleet,"status_publications":statuses,"inventory":ledger["inventory"],"epoch198_delivery":pipeline,"epoch160_delivery":d160,"epoch144_delivery":d144,"private_public_history_recovery":recovery,"new_resource_samples":0,"replay_status_republications":0,"archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false,"deletions":false});
    next_preparation::completion_bindings(p, pb, &c)?;
    public198::validate_completed(p, &c)?;
    delivery160::validate_completed(p, &c)?;
    publication144::validate_completed(p, &c)?;
    write_new(&root.join("completion.json"), &c)?;
    write_new(&p.cycle_directory.join("completion.json"), &c)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_recovery_is_not_a_generic_status_retry_or_owner_substitution() {
        let (mut p, ..) = crate::tests::fixture101();
        p.sample_target_utc = "2026-10-23T00:28:00Z".into();
        p.cycle_directory = ROOT.into();
        p.publication144 = Some(
            serde_json::from_value(json!({"launch":{"path":"/capture","sha256":"a".repeat(64)}}))
                .unwrap(),
        );
        let pb = Bound {
            path: "/plan".into(),
            sha256: PLAN_SHA.into(),
        };
        let i = json!({"plan":pb,"invocation_id":ORIGINAL_IID,"self_sha256":"b1e3882377f060b506e15695d110b944a29b74f0393c39789db0f827ddb7e13f"});
        let f = json!({"schema":"jetstreamer-horizon-routine-child-result-v1","success":false,"exit_code":1,"signal":null,"tool":p.tools.r2,
            "stderr":{"text":"Error: private144 fleet scope, gate, tracking or overlapping owner differs\n"}});
        exact(&p, &pb, &i, &f).unwrap();
        for field in ["success", "exit_code", "signal", "tool", "stderr"] {
            let mut bad = f.clone();
            bad[field] = json!("foreign");
            assert!(exact(&p, &pb, &i, &bad).is_err(), "{field}");
        }
        let mut bad = i.clone();
        bad["invocation_id"] = json!("foreign");
        assert!(exact(&p, &pb, &bad, &f).is_err());
        p.publication144 = None;
        assert!(exact(&p, &pb, &i, &f).is_err());
    }
}
