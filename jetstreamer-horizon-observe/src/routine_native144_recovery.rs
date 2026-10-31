//! Finish the exact failed 23:28 metadata cycle without resampling or rewriting statuses.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261021T232800Z-native144-upload198-refresh-completed144-v1";
const PLAN_SHA: &str = "f38c2225b477868d6a5acba3cdea2059d9a6bc8a50b3a4c18a06bc3c7f9b6d8b";
const OLD_IID: &str = "567d4735efee4bacb638faf2684c268a";
const OLD_HELPER_SHA: &str = "c82ed0098202419c1b461707b6aebbb2149a5729dbb1cc1893acf4adc78521d6";
const FAILED_SHA: &str = "63733a8aaaedd0e5403418dfc573ec47397b53fd08547907c22e3c9abdc57622";
const PROVISIONAL_SHA: &str = "10424be36b3a6edab8520811f20dc586cb8716926654022b06df646261597421";
const FLEET_SHA: &str = "943772688fc24b1e01fd7abdbdcf56359d4582f73a51b83ceea09371d91b15bb";
const UNIT: &str = "horizon-native144-observer-cycle-recovery-20261021-v1.service";
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn exact(p: &Plan, pb: &Bound, intent: &Value, failed: &Value) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.sample_target_utc == "2026-10-21T23:28:00Z"
            && p.cycle_directory == Path::new(ROOT)
            && pb.sha256 == PLAN_SHA
            && p.native144_restore.is_some()
            && public198::upload(p)
            && intent["plan"] == serde_json::to_value(pb)?
            && intent["invocation_id"] == OLD_IID
            && intent["self_sha256"] == OLD_HELPER_SHA
            && failed["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && failed["success"] == false
            && failed["exit_code"] == 1
            && failed["signal"].is_null()
            && failed["tool"]["sha256"]
                == "48699f87596d93f319476d2af0c0b90e14a7ca672ed5a326c7af1a4f25ebae85"
            && failed["stderr"]["text"] == "Error: private144 observer envelope owner differs\n",
        "not the exact recoverable native 144 observer failure"
    );
    Ok(())
}
pub(super) fn run(p: &Plan, pb: &Bound, self_sha: &str, check: bool) -> Result<()> {
    let intent = file(p.cycle_directory.join("intent.json"), false)?;
    let failed = Bound {
        path: p.cycle_directory.join("child-public198-fleet.json"),
        sha256: FAILED_SHA.into(),
    };
    let iv = bound_json(&intent, false)?;
    let fv = bound_json(&failed, false)?;
    exact(p, pb, &iv, &fv)?;
    let observed: Bound = serde_json::from_value(iv["observer"].clone())?;
    ensure!(
        observed.path == p.observer
            && observed.sha256
                == "2addb94b258266c1941f51d38b457ef6f034388a475238613d80b4c9c442a7f8",
        "native 144 recovery observer differs"
    );
    let o = bound_json(&observed, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let model_template = bound_json(&p.model_template, true)?;
    let model_template = terminal_handoff::for_observation(p, &model_template, &o)?;
    validate_observation(p, &model_template, &o, now)?;
    let (expected_model, expected_fleet) = derive(
        p,
        &model_template,
        &bound_json(&p.fleet_template, true)?,
        &observed,
    )?;
    let model = file(p.cycle_directory.join("sealed/eta-model.json"), true)?;
    let fleet = Bound {
        path: p.cycle_directory.join("sealed/fleet-plan.json"),
        sha256: FLEET_SHA.into(),
    };
    ensure!(
        bound_json(&model, true)? == expected_model && bound_json(&fleet, true)? == expected_fleet,
        "native 144 recovery would change accepted formula or fleet scope"
    );
    let estimates = file(p.estimate_output.clone(), false)?;
    let ev = bound_json(&estimates, false)?;
    let entries = verify_estimates(p, &expected_model, &observed, &ev)?;
    let status_root = Path::new(
        expected_model["status_receipt_directory"]
            .as_str()
            .context("status root")?,
    );
    let digits: String = p
        .sample_target_utc
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let mut statuses = Vec::new();
    for entry in entries {
        let epoch = entry["epoch"].as_u64().context("recovery epoch")?;
        let c = bound_json(
            &file(
                p.cycle_directory.join(format!("child-status-{epoch}.json")),
                false,
            )?,
            false,
        )?;
        ensure!(
            c["success"] == true
                && c["exit_code"] == 0
                && c["signal"].is_null()
                && c["tool"] == serde_json::to_value(&p.tools.r2)?,
            "status child did not already succeed"
        );
        let b = file(
            status_root.join(format!("epoch-{epoch}.status-{digits}.json")),
            false,
        )?;
        next_preparation::validate_status(&bound_json(&b, false)?, p, &observed, &entry)?;
        statuses.push(b);
    }
    let source_failure = bound_json(&file(p.cycle_directory.join("failure.json"), false)?, false)?;
    ensure!(
        source_failure["plan"] == serde_json::to_value(pb)?
            && source_failure["automatic_retry_authorized"] == false,
        "original cycle failure differs"
    );
    let output = Command::new("systemctl")
        .args([
            "show",
            &p.cycle_unit,
            "--property=InvocationID,MainPID,NRestarts,ActiveState,SubState,Result,ExecMainStatus",
        ])
        .output()?;
    ensure!(output.status.success(), "original failed owner unreadable");
    let mut fields = BTreeMap::new();
    for l in std::str::from_utf8(&output.stdout)?.lines() {
        let (k, v) = l.split_once('=').context("failed owner field")?;
        ensure!(
            fields.insert(k, v).is_none(),
            "duplicate failed owner field"
        );
    }
    for (k, v) in [
        ("InvocationID", OLD_IID),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
        ("ExecMainStatus", "1"),
    ] {
        ensure!(
            fields.get(k) == Some(&v),
            "original cycle is not exact terminal failure:{k}"
        );
    }
    let reader = native144::reader();
    tool_ok(&reader)?;
    let provisional_plan = Bound {
        path: p
            .cycle_directory
            .join("public198-stage/sealed/fleet-plan.json"),
        sha256: PROVISIONAL_SHA.into(),
    };
    let pv = bound_json(&provisional_plan, true)?;
    let mut expected = expected_fleet.clone();
    let provisional_path = p.cycle_directory.join("public198-provisional-fleet.json");
    expected["output"] = json!(provisional_path);
    ensure!(
        pv == expected,
        "provisional fleet changed more than its private output"
    );
    absent(&provisional_path)?;
    absent(&p.fleet_output)?;
    absent(&p.cycle_directory.join("completion.json"))?;
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    let endpoint = env::var("HORIZON_S3_ENDPOINT").context("recovery endpoint missing")?;
    ensure!(
        sha(endpoint.as_bytes()) == p.endpoint_sha256 && p.bucket == BUCKET,
        "foreign recovery endpoint"
    );
    if check {
        println!(
            "native144 cycle recovery preflight passed; no sampling, status writes or remote access"
        );
        return Ok(());
    }
    let iid = authenticate_named_service(UNIT)?;
    let root = p.cycle_directory.join("native144-observer-recovery-v1");
    absent(&root)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    File::open(&p.cycle_directory)?.sync_all()?;
    write_new(
        &root.join("intent.json"),
        &json!({"schema":"horizon-native144-cycle-recovery-intent-v1","source_plan":pb,
        "source_intent":intent,"failed_child":failed,"reader":reader,"self_sha256":self_sha,"invocation_id":iid,
        "new_resource_samples":0,"status_republications":0,"archive_mutations":false,"sidecar_mutations":false}),
    )?;
    for (name, plan) in [("provisional", &provisional_plan), ("canonical", &fleet)] {
        child(
            &reader,
            &[
                "fleet-reconcile".into(),
                plan.path.display().to_string(),
                "--plan-sha256".into(),
                plan.sha256.clone(),
            ],
            true,
            &root.join(format!("child-{name}.json")),
        )?;
        let ledger_path = if name == "provisional" {
            &provisional_path
        } else {
            &p.fleet_output
        };
        let value = bound_json(&file(ledger_path.clone(), false)?, false)?;
        let epoch = value["epochs"]
            .as_array()
            .context("recovery epochs")?
            .iter()
            .find(|e| e["epoch"] == 198)
            .context("recovery198")?;
        ensure!(
            value["inventory"]["anomalies"] == 0
                && epoch["state"] == "remote-ready"
                && epoch["status"].is_null(),
            "198 ready/absent-status gate differs during recovery"
        );
    }
    let canonical = file(p.fleet_output.clone(), false)?;
    let ledger = bound_json(&canonical, false)?;
    let provisional = file(provisional_path, false)?;
    let recovery = json!({"schema":"horizon-native144-cycle-recovery-v1","reader":reader,"failed_child":failed,
        "original_cycle_unit":p.cycle_unit,"original_invocation_id":OLD_IID,"original_exit_status":1,
        "recovery_unit":UNIT,"recovery_invocation_id":iid,"new_resource_samples":0,"status_republications":0});
    let receipt = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","plan":pb,"self_sha256":self_sha,
        "sampled_at_utc":p.sample_target_utc,"observer":observed,"model":model,"estimates":estimates,"invocation_id":iid,
        "fleet_plan":fleet,"fleet":canonical,"status_publications":statuses,"inventory":ledger["inventory"],
        "epoch198_delivery":{"provisional_fleet":provisional,"publication_skipped":true,"reason":"Authenticated 198 ready pair; status already conditionally deleted"},
        "native144_observer_recovery":recovery,"replay_launch_authorized":false,"archive_mutations":false,
        "sidecar_mutations":false,"deletions":false,"new_resource_samples":0});
    write_new(&root.join("completion.json"), &receipt)?;
    write_new(&p.cycle_directory.join("completion.json"), &receipt)?;
    println!("{}", p.cycle_directory.join("completion.json").display());
    Ok(())
}
pub(super) fn consume(p: &mut Plan, c: &Value) -> Result<()> {
    let Some(r) = c.get("native144_observer_recovery") else {
        return Ok(());
    };
    ensure!(
        r["schema"] == "horizon-native144-cycle-recovery-v1"
            && r["reader"] == serde_json::to_value(native144::reader())?
            && r["original_invocation_id"] == OLD_IID
            && r["original_exit_status"] == 1
            && r["recovery_unit"] == UNIT
            && r["failed_child"]["sha256"] == FAILED_SHA
            && r["failed_child"]["path"] == format!("{ROOT}/child-public198-fleet.json")
            && r["new_resource_samples"] == 0
            && r["status_republications"] == 0
            && c["plan"]["sha256"] == PLAN_SHA
            && c["sampled_at_utc"] == "2026-10-21T23:28:00Z"
            && p.native144_restore.is_some()
            && public198::upload(p),
        "foreign native 144 recovery consumption"
    );
    p.tools.r2 = native144::reader();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Plan, Bound, Value, Value) {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        p.sample_target_utc = "2026-10-21T23:28:00Z".into();
        p.cycle_directory = ROOT.into();
        p.native144_restore=Some(serde_json::from_value(json!({"launch":{"path":"/launch","sha256":"a".repeat(64)},
            "event_fleet":{"path":"/event","sha256":"a".repeat(64)},"event_plan":{"path":"/event-plan","sha256":"a".repeat(64)},"invocation_id":"b".repeat(32)})).unwrap());
        let d = &mut p.scope_101_200.as_mut().unwrap().diagnostic_ranges[0];
        d.controller_unit = native144::UNIT.into();
        d.producer_unit = native144::UNIT.into();
        d.expected_controller_invocation_id = "b".repeat(32);
        d.expected_producer_invocation_id = "b".repeat(32);
        p.public198_delivery=Some(serde_json::from_value(json!({"promotion":{"path":"/promotion","sha256":"a".repeat(64)},
            "origin":{"path":"/origin","sha256":"a".repeat(64)},"claims":[],"progressive_upload":true})).unwrap());
        let b = Bound {
            path: "/source-plan".into(),
            sha256: PLAN_SHA.into(),
        };
        let i = json!({"plan":b,"invocation_id":OLD_IID,"self_sha256":OLD_HELPER_SHA});
        let f = json!({"schema":"jetstreamer-horizon-routine-child-result-v1","success":false,"exit_code":1,"signal":null,
            "tool":{"sha256":"48699f87596d93f319476d2af0c0b90e14a7ca672ed5a326c7af1a4f25ebae85"},
            "stderr":{"text":"Error: private144 observer envelope owner differs\n"}});
        (p, b, i, f)
    }
    #[test]
    fn recovery_is_exact_failure_only_never_a_generic_cycle_or_status_retry() {
        let (p, b, i, f) = fixture();
        exact(&p, &b, &i, &f).unwrap();
        let mut bad = i.clone();
        bad["invocation_id"] = json!("c".repeat(32));
        assert!(exact(&p, &b, &bad, &f).is_err());
        for (key, v) in [
            ("success", json!(true)),
            ("exit_code", json!(0)),
            ("signal", json!(9)),
        ] {
            let mut bad = f.clone();
            bad[key] = v;
            assert!(exact(&p, &b, &i, &bad).is_err());
        }
        let mut bad = f;
        bad["stderr"]["text"] = json!("unrelated failure");
        assert!(exact(&p, &b, &i, &bad).is_err());
    }
    #[test]
    fn successor_pins_qualified_reader_without_changing_other_tools_or_consensus_evidence() {
        let (mut p, b, _, _) = fixture();
        let old_estimator = serde_json::to_value(&p.tools.estimator).unwrap();
        let c = json!({"plan":b,"sampled_at_utc":"2026-10-21T23:28:00Z","native144_observer_recovery":{
            "schema":"horizon-native144-cycle-recovery-v1","reader":native144::reader(),"original_invocation_id":OLD_IID,
            "original_exit_status":1,"recovery_unit":UNIT,"failed_child":{"path":format!("{ROOT}/child-public198-fleet.json"),"sha256":FAILED_SHA},
            "new_resource_samples":0,"status_republications":0}});
        consume(&mut p, &c).unwrap();
        assert_eq!(
            serde_json::to_value(&p.tools.r2).unwrap(),
            serde_json::to_value(native144::reader()).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&p.tools.estimator).unwrap(),
            old_estimator
        );
        let mut bad = c;
        bad["native144_observer_recovery"]["status_republications"] = json!(1);
        assert!(consume(&mut p, &bad).is_err());
    }
}
