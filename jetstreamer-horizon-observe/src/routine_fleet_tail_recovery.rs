//! One exact final-fleet read failure; never repeat samples or status writes.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261022T202800Z-native141-all-retry-public160-timed-scans-upload198-v1";
const PLAN_SHA: &str = "9bba35ef4f99d79127f348ea8f99f7a4279f61d4a1360f84a825c8c1bc960046";
const IID: &str = "ff971af797604a5da583e247bc4f0779";
const UNIT: &str = "horizon-final-fleet-recovery-20261022T202800Z-v1.service";
const FAILURE_SHA: &str = "0bf835db23990ba62a3eaefbaf563bd7b215b1cfb3c90dde105d09011572b4b8";
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
        "original child not successful"
    );
    Ok(())
}
fn exact(p: &Plan, pb: &Bound, i: &Value, f: &Value) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.sample_target_utc == "2026-10-22T20:28:00Z"
            && p.cycle_directory == Path::new(ROOT)
            && pb.sha256 == PLAN_SHA
            && native141::all_retry_enabled(p)
            && p.publication144.is_none()
            && i["plan"] == serde_json::to_value(pb)?
            && i["invocation_id"] == IID
            && i["self_sha256"]
                == "db62a44643c8501d497fad1d94ef5f1d26b4da93b5a3e7e3e498a49b0aef211b"
            && f["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && f["success"] == false
            && f["exit_code"] == 1
            && f["signal"].is_null()
            && f["tool"] == serde_json::to_value(&p.tools.r2)?
            && f["stderr"]["text"]
                == "Error: failed to fetch remote sidecar\n\nCaused by:\n    0: service error\n    1: unhandled error\n    2: Error\n",
        "not the exact2028 final read-only inventory failure"
    );
    Ok(())
}
pub(super) fn run(p: &Plan, pb: &Bound, self_sha: &str, check: bool) -> Result<()> {
    let intent = file(p.cycle_directory.join("intent.json"), false)?;
    let rejected = Bound {
        path: p.cycle_directory.join("child-fleet.json"),
        sha256: FAILURE_SHA.into(),
    };
    let i = bound_json(&intent, false)?;
    exact(p, pb, &i, &bound_json(&rejected, false)?)?;
    let o = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            &p.cycle_unit,
            "--property=InvocationID,NRestarts,MainPID,ActiveState,SubState,Result,ExecMainStatus",
        ])
        .output()?;
    ensure!(o.status.success(), "failed cycle owner unreadable");
    let text = std::str::from_utf8(&o.stdout)?;
    let fields: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
    for (k, v) in [
        ("InvocationID", IID),
        ("NRestarts", "0"),
        ("MainPID", "0"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
        ("ExecMainStatus", "1"),
    ] {
        ensure!(fields.get(k) == Some(&v), "failed cycle changed:{k}");
    }
    let observer = Bound {
        path: p.observer.clone(),
        sha256: "a8774a03053f603a61e3078b5a6a2fb6e8f123f7c4444701b84c50196958d1a1".into(),
    };
    ensure!(
        i["observer"] == serde_json::to_value(&observer)?,
        "original observer differs"
    );
    let observed = bound_json(&observer, false)?;
    let model = file(p.cycle_directory.join("sealed/eta-model.json"), true)?;
    let mv = bound_json(&model, true)?;
    validate_observation(
        p,
        &mv,
        &observed,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let fleet_plan = file(p.cycle_directory.join("sealed/fleet-plan.json"), true)?;
    let fv = bound_json(&fleet_plan, true)?;
    ensure!(
        fv["observer"] == serde_json::to_value(&observer)?
            && fv["previous_fleet"] == serde_json::to_value(&p.previous_fleet)?
            && fv["output"].as_str() == p.fleet_output.to_str(),
        "original final fleet plan changed"
    );
    let estimates = file(p.estimate_output.clone(), false)?;
    let ev = bound_json(&estimates, false)?;
    ensure!(
        ev["model_sha256"] == model.sha256
            && ev["model_path"].as_str() == model.path.to_str()
            && ev["estimator_sha256"] == p.tools.estimator.sha256,
        "original estimates changed"
    );
    successful(
        &bound_json(
            &file(p.cycle_directory.join("child-estimator.json"), false)?,
            false,
        )?,
        &p.tools.estimator,
    )?;
    let entries = verify_estimates(p, &mv, &observer, &ev)?;
    let mut statuses = Vec::new();
    for e in entries {
        let epoch = e["epoch"].as_u64().context("status epoch")?;
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
                .join(format!("epoch-{epoch}.status-20261022202800.json")),
            false,
        )?;
        next_preparation::validate_status(&bound_json(&b, false)?, p, &observer, &e)?;
        statuses.push(b);
    }
    successful(
        &bound_json(
            &file(p.cycle_directory.join("child-public198-fleet.json"), false)?,
            false,
        )?,
        &p.tools.r2,
    )?;
    successful(
        &bound_json(
            &file(
                p.cycle_directory.join("child-public160-status-delete.json"),
                false,
            )?,
            false,
        )?,
        &p.tools.r2,
    )?;
    let provisional = file(
        p.cycle_directory.join("public198-provisional-fleet.json"),
        false,
    )?;
    let pf = bound_json(&provisional, false)?;
    for epoch in [160, 198] {
        ensure!(
            pf["epochs"]
                .as_array()
                .context("provisional epochs")?
                .iter()
                .any(|e| e["epoch"] == epoch
                    && e["state"] == "remote-ready"
                    && e["status"].is_null()),
            "ready downstream evidence changed"
        );
    }
    ensure!(
        pf["observer_sha256"] == observer.sha256
            && pf["sampled_at_utc"] == p.sample_target_utc
            && pf["inventory"]["anomalies"] == 0,
        "original provisional fleet differs"
    );
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    absent(&p.fleet_output)?;
    absent(&p.cycle_directory.join("completion.json"))?;
    let root = p.cycle_directory.join("final-fleet-recovery-v1");
    absent(&root)?;
    ensure!(
        sha(env::var("HORIZON_S3_ENDPOINT")?.as_bytes()) == p.endpoint_sha256,
        "recovery endpoint differs"
    );
    tool_ok(&p.tools.r2)?;
    if check {
        println!(
            "exact final-fleet recovery qualified; no resource sample,status write or remote request"
        );
        return Ok(());
    }
    let iid = authenticate_named_service(UNIT)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    File::open(&p.cycle_directory)?.sync_all()?;
    let recovery = write_new(
        &root.join("intent.json"),
        &json!({"schema":"horizon-exact2028-final-fleet-recovery-v1","original_intent":intent,"failed_child":rejected,"original_invocation_id":IID,"recovery_invocation_id":iid,"observer":observer,"new_resource_samples":0,"status_writes":0,"archive_mutations":false,"sidecar_mutations":false,"r2_mutations":false}),
    )?;
    child(
        &p.tools.r2,
        &[
            "fleet-reconcile".into(),
            fleet_plan.path.display().to_string(),
            "--plan-sha256".into(),
            fleet_plan.sha256.clone(),
        ],
        true,
        &root.join("child-fleet.json"),
    )?;
    let fleet = file(p.fleet_output.clone(), false)?;
    let ledger = bound_json(&fleet, false)?;
    ensure!(
        ledger["observer_sha256"] == observer.sha256
            && ledger["plan_sha256"] == fleet_plan.sha256
            && ledger["sampled_at_utc"] == p.sample_target_utc
            && ledger["inventory"]["anomalies"] == 0,
        "recovered fleet differs"
    );
    let pipeline = json!({"provisional_fleet":provisional,"publication_skipped":true,"reason":"No authenticated current198 verifier child; stage transition/status cleanup requires prompt reconciliation"});
    let d160 = json!({"provisional_fleet":provisional,"publication_skipped":true,"ready_pair_verified_cleanup":true});
    let c = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","plan":pb,"self_sha256":self_sha,"sampled_at_utc":p.sample_target_utc,"observer":observer,"model":model,"estimates":estimates,"invocation_id":iid,"fleet_plan":fleet_plan,"fleet":fleet,"status_publications":statuses,"inventory":ledger["inventory"],"epoch198_delivery":pipeline,"epoch160_delivery":d160,"epoch144_delivery":{"enabled":false},"final_fleet_recovery":recovery,"new_resource_samples":0,"replay_status_republications":0,"archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false,"deletions":false});
    next_preparation::completion_bindings(p, pb, &c)?;
    public198::validate_completed(p, &c)?;
    public160::validate_completed(p, &c)?;
    write_new(&root.join("completion.json"), &c)?;
    write_new(&p.cycle_directory.join("completion.json"), &c)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_rejects_another_cycle_attempt_success_or_failure_cause() {
        let (mut p, ..) = crate::tests::fixture101();
        p.sample_target_utc = "2026-10-22T20:28:00Z".into();
        p.cycle_directory = ROOT.into();
        let b = json!({"path":"/proof","sha256":"a".repeat(64)});
        p.native141_audit =
            Some(serde_json::from_value(json!({"first_guard":b,"all_retry":b})).unwrap());
        let pb = Bound {
            path: "/plan".into(),
            sha256: PLAN_SHA.into(),
        };
        let i = json!({"plan":pb,"invocation_id":IID,"self_sha256":"db62a44643c8501d497fad1d94ef5f1d26b4da93b5a3e7e3e498a49b0aef211b"});
        let f = json!({"schema":"jetstreamer-horizon-routine-child-result-v1","success":false,"exit_code":1,"signal":null,"tool":p.tools.r2,"stderr":{"text":"Error: failed to fetch remote sidecar\n\nCaused by:\n    0: service error\n    1: unhandled error\n    2: Error\n"}});
        exact(&p, &pb, &i, &f).unwrap();
        for (key, value) in [
            ("success", json!(true)),
            ("exit_code", json!(0)),
            ("signal", json!(9)),
            ("stderr", json!({"text":"different failure"})),
        ] {
            let mut bad = f.clone();
            bad[key] = value;
            assert!(exact(&p, &pb, &i, &bad).is_err());
        }
        let mut bad = i.clone();
        bad["invocation_id"] = json!("foreign");
        assert!(exact(&p, &pb, &bad, &f).is_err());
        p.sample_target_utc = "2026-10-22T20:58:00Z".into();
        assert!(exact(&p, &pb, &i, &f).is_err());
    }
    #[test]
    fn tail_recovery_cannot_borrow_successful_or_foreign_child() {
        let t = Bound {
            path: "/tool".into(),
            sha256: "a".repeat(64),
        };
        let v = json!({"schema":"jetstreamer-horizon-routine-child-result-v1","success":true,"exit_code":0,"signal":null,"tool":t});
        successful(&v, &t).unwrap();
        for key in ["success", "exit_code", "signal", "tool"] {
            let mut bad = v.clone();
            bad[key] = json!("foreign");
            assert!(successful(&bad, &t).is_err());
        }
    }
}
