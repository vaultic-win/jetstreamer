//! One exact final-fleet read failure; never repeat samples or status writes.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261022T202800Z-native141-all-retry-public160-timed-scans-upload198-v1";
const PLAN_SHA: &str = "9bba35ef4f99d79127f348ea8f99f7a4279f61d4a1360f84a825c8c1bc960046";
const IID: &str = "ff971af797604a5da583e247bc4f0779";
const UNIT: &str = "horizon-final-fleet-recovery-20261022T202800Z-v1.service";
const FAILURE_SHA: &str = "0bf835db23990ba62a3eaefbaf563bd7b215b1cfb3c90dde105d09011572b4b8";
struct Profile {
    root: &'static str,
    plan_sha: &'static str,
    iid: &'static str,
    unit: &'static str,
    failure_sha: &'static str,
    observer_sha: &'static str,
    original_helper_sha: &'static str,
    failed_operation: &'static str,
    sample: &'static str,
}
const OLD: Profile = Profile {
    root: ROOT,
    plan_sha: PLAN_SHA,
    iid: IID,
    unit: UNIT,
    failure_sha: FAILURE_SHA,
    observer_sha: "a8774a03053f603a61e3078b5a6a2fb6e8f123f7c4444701b84c50196958d1a1",
    original_helper_sha: "db62a44643c8501d497fad1d94ef5f1d26b4da93b5a3e7e3e498a49b0aef211b",
    failed_operation: "fetch remote sidecar",
    sample: "2026-10-22T20:28:00Z",
};
const LATE: Profile = Profile {
    root: "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261022T235800Z-census141-boundaries-native141-all-retry-public160-timed-scans-upload198-v1",
    plan_sha: "c07f8ad094386a5a3ee9853b183e5380651df4ba1cb9066884fc985c7675ad15",
    iid: "aa7553e84fe8403faa1c6585388b6361",
    unit: "horizon-final-fleet-recovery-20261022T235800Z-v1.service",
    failure_sha: "2eebb70f6307d99373f4826f8b75a88994806afa25665cb2555b1c8e8fee504c",
    observer_sha: "3400fdf69e95e399230759361d6dcc457a75c77091d4ec08ca91ce46b7946dc7",
    original_helper_sha: "deff1dae86d86f80754ff602d181c3363c3aeb6ac1ad0988f3452b30fdfb5bfc",
    failed_operation: "stat remote archive",
    sample: "2026-10-22T23:58:00Z",
};
fn profile(p: &Plan, pb: &Bound) -> Result<&'static Profile> {
    [&OLD, &LATE]
        .into_iter()
        .find(|s| {
            p.sample_target_utc == s.sample
                && p.cycle_directory == Path::new(s.root)
                && pb.sha256 == s.plan_sha
        })
        .context("not an exact reviewed final-fleet read failure profile")
}
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
    let s = profile(p, pb)?;
    ensure!(
        is_101(p)?
            && native141::all_retry_enabled(p)
            && p.publication144.is_none()
            && i["plan"] == serde_json::to_value(pb)?
            && i["invocation_id"] == s.iid
            && i["self_sha256"] == s.original_helper_sha
            && f["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && f["success"] == false
            && f["exit_code"] == 1
            && f["signal"].is_null()
            && f["tool"] == serde_json::to_value(&p.tools.r2)?
            && f["stderr"]["text"]
                == format!(
                    "Error: failed to {}\n\nCaused by:\n    0: service error\n    1: unhandled error\n    2: Error\n",
                    s.failed_operation
                ),
        "not the exact reviewed final read-only inventory failure"
    );
    Ok(())
}
pub(super) fn run(p: &Plan, pb: &Bound, self_sha: &str, check: bool) -> Result<()> {
    let s = profile(p, pb)?;
    let intent = file(p.cycle_directory.join("intent.json"), false)?;
    let rejected = Bound {
        path: p.cycle_directory.join("child-fleet.json"),
        sha256: s.failure_sha.into(),
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
        ("InvocationID", s.iid),
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
        sha256: s.observer_sha.into(),
    };
    ensure!(
        i["observer"] == serde_json::to_value(&observer)?,
        "original observer differs"
    );
    let observed = bound_json(&observer, false)?;
    let model = file(p.cycle_directory.join("sealed/eta-model.json"), true)?;
    let mv = bound_json(&model, true)?;
    // Cadence validation consumes the genuine predecessor model, not the
    // already-derived model whose timestamp is the current sample.
    let prior_model = bound_json(&p.model_template, true)?;
    let prior_model = private144::effective_model(
        p,
        &delivery160::effective_model(
            p,
            &delivery198::effective_model(p, &controller_recovery::model(p, &prior_model)?)?,
        )?,
    )?;
    let prior_model = terminal_handoff::for_observation(p, &prior_model, &observed)?;
    let prior_model = cohort191::for_observation(p, &prior_model, &observed)?;
    validate_observation(
        p,
        &prior_model,
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
            Path::new("/home/sol/.jetstreamer-private/r2-status-receipts").join(format!(
                "epoch-{epoch}.status-{}.json",
                p.sample_target_utc
                    .chars()
                    .filter(char::is_ascii_digit)
                    .collect::<String>()
            )),
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
    let iid = authenticate_named_service(s.unit)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    File::open(&p.cycle_directory)?.sync_all()?;
    let recovery = write_new(
        &root.join("intent.json"),
        &json!({"schema":"horizon-exact-final-fleet-recovery-v2","original_intent":intent,"failed_child":rejected,"original_invocation_id":s.iid,"recovery_invocation_id":iid,"observer":observer,"new_resource_samples":0,"status_writes":0,"archive_mutations":false,"sidecar_mutations":false,"r2_mutations":false}),
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
    let pipeline = json!({"provisional_fleet":provisional,"publication_skipped":true,"reason":"No authenticated current 198 verifier child; stage transition/status cleanup requires prompt reconciliation"});
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
    fn late_head_failure_is_a_separate_exact_profile_not_a_generic_retry() {
        let (mut p, ..) = crate::tests::fixture101();
        p.sample_target_utc = LATE.sample.into();
        p.cycle_directory = LATE.root.into();
        let b = json!({"path":"/proof","sha256":"a".repeat(64)});
        p.native141_audit =
            Some(serde_json::from_value(json!({"first_guard":b,"all_retry":b})).unwrap());
        let mut pb = Bound {
            path: "/plan".into(),
            sha256: LATE.plan_sha.into(),
        };
        let i = json!({"plan":pb,"invocation_id":LATE.iid,"self_sha256":LATE.original_helper_sha});
        let f = json!({"schema":"jetstreamer-horizon-routine-child-result-v1","success":false,"exit_code":1,"signal":null,"tool":p.tools.r2,
            "stderr":{"text":format!("Error: failed to {}\n\nCaused by:\n    0: service error\n    1: unhandled error\n    2: Error\n",LATE.failed_operation)}});
        exact(&p, &pb, &i, &f).unwrap();
        for key in ["invocation_id", "self_sha256"] {
            let mut bad = i.clone();
            bad[key] = json!("foreign");
            assert!(exact(&p, &pb, &bad, &f).is_err());
        }
        let mut old_error = f.clone();
        old_error["stderr"]["text"] = json!(format!(
            "Error: failed to {}\n\nCaused by:\n    0: service error\n    1: unhandled error\n    2: Error\n",
            OLD.failed_operation
        ));
        assert!(exact(&p, &pb, &i, &old_error).is_err());
        pb.sha256 = OLD.plan_sha.into();
        assert!(exact(&p, &pb, &i, &f).is_err());
        p.sample_target_utc = "2026-10-23T00:28:00Z".into();
        assert!(profile(&p, &pb).is_err());
    }
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
