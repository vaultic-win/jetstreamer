//! Recover only the exact02:29 bootstrap fleet-tail transaction; never repeat replay statuses.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261023T032958Z-repair185-repair183-upload144-census141-boundaries-native141-all-retry-public160-timed-scans-upload198-v1";
const PLAN_SHA: &str = "b94636002204d78307b8e5e8bcc47bce042c1717536eb5541fb02cc0d7557224";
const OLD_IID: &str = "4952ea50313146808ac188b74a11af81";
const FAILED_SHA: &str = "55dc96199bf956cff1b05530e0e03da839dcaf976b8d3c71f3afa2ca8d97e225";
const UNIT: &str = "horizon-repair185-fleet-recovery-20261023-v1.service";
pub(super) const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-publication144-fleet-reader-20261023-v4/jetstreamer-r2";
pub(super) const READER_SHA: &str =
    "0ac98fef0a7397ba2f5cb879ff829dfc1a4a33a2b3d7c0cf1789764e04cd2e70";
pub(super) fn reader() -> Bound {
    Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    }
}
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn corrected_fleet(original: &Value) -> Result<Value> {
    let mut corrected = original.clone();
    repair185::replacement_gate(&mut corrected["gates"]["185"])?;
    Ok(corrected)
}

fn exact(p: &Plan, pb: &Bound, i: &Value, f: &Value) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.sample_target_utc == "2026-10-23T03:29:58Z"
            && p.cycle_directory == Path::new(ROOT)
            && pb.sha256 == PLAN_SHA
            && p.repair185_handoff.is_some()
            && public198::upload(p)
            && i["plan"] == serde_json::to_value(pb)?
            && i["invocation_id"] == OLD_IID
            && i["self_sha256"]
                == "597fbd87095b5d15a454dc62434263a8a4bb29cf2ea897dc098fd574e0d875d3"
            && f["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && f["success"] == false
            && f["exit_code"] == 1
            && f["signal"].is_null()
            && f["tool"] == serde_json::to_value(&p.tools.r2)?
            && f["stderr"]["text"] == "Error: reserve stop cannot discard another observer claim\n",
        "not the exact epoch185 guard-timer metadata failure"
    );
    Ok(())
}
pub(super) fn run(p: &Plan, pb: &Bound, self_sha: &str, check: bool) -> Result<()> {
    let intent = file(p.cycle_directory.join("intent.json"), false)?;
    let rejected = Bound {
        path: p.cycle_directory.join("child-public198-fleet.json"),
        sha256: FAILED_SHA.into(),
    };
    let iv = bound_json(&intent, false)?;
    exact(p, pb, &iv, &bound_json(&rejected, false)?)?;
    let terminal = Command::new("systemctl")
        .args([
            "show",
            &p.cycle_unit,
            "--property=InvocationID,MainPID,NRestarts,ActiveState,SubState,Result,ExecMainStatus",
        ])
        .output()?;
    ensure!(
        terminal.status.success(),
        "original failed cycle unreadable"
    );
    let t = std::str::from_utf8(&terminal.stdout)?;
    let fields: BTreeMap<_, _> = t.lines().filter_map(|s| s.split_once('=')).collect();
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
            "original failed cycle changed:{k}"
        );
    }
    let observer = Bound {
        path: p.observer.clone(),
        sha256: "3eddc4f438804791f45ccb4ba73b4f76687ffed154c08a5e77edea50df9ff0d8".into(),
    };
    ensure!(
        iv["observer"] == serde_json::to_value(&observer)?,
        "original observer differs"
    );
    bound_json(&observer, false)?;
    let model = Bound {
        path: p.cycle_directory.join("sealed/eta-model.json"),
        sha256: "ccf2a2face4c6d341af71a2d852e58ea3324a93b3494a780a7c29ad5885dacb1".into(),
    };
    let fleet_plan = Bound {
        path: p.cycle_directory.join("sealed/fleet-plan.json"),
        sha256: "f4a20b872fd5d99fcd7333d5e9be6a478082519ed4015b58487b2b9d7064c2ff".into(),
    };
    let mv = bound_json(&model, true)?;
    let fv = bound_json(&fleet_plan, true)?;
    corrected_fleet(&fv)?;
    repair183::validate_live(p)?;
    repair185::validate_live(p)?;
    repair185::effective_model(p, &bound_json(&p.model_template, true)?)?;
    let provisional_plan = Bound {
        path: p
            .cycle_directory
            .join("public198-stage/sealed/fleet-plan.json"),
        sha256: "8f63e02b86abdc8e53fac3da63c7eebc1364862d9adc8c567251c6fbeed622a4".into(),
    };
    let provisional_path = p.cycle_directory.join("public198-provisional-fleet.json");
    let mut expected = fv.clone();
    expected["output"] = json!(provisional_path);
    ensure!(
        bound_json(&provisional_plan, true)? == expected,
        "provisional fleet differs"
    );
    let estimates = file(p.estimate_output.clone(), false)?;
    let ev = bound_json(&estimates, false)?;
    ensure!(
        ev["model_sha256"] == model.sha256
            && ev["model_path"].as_str() == model.path.to_str()
            && ev["estimator_sha256"] == p.tools.estimator.sha256,
        "original estimate provenance differs"
    );
    let entries = verify_estimates(p, &mv, &observer, &ev)?;
    let mut statuses = Vec::new();
    for e in entries {
        let epoch = e["epoch"].as_u64().context("recovery epoch")?;
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
            "original replay status child did not succeed"
        );
        let b = file(
            Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
                .join(format!("epoch-{epoch}.status-20261023032958.json")),
            false,
        )?;
        next_preparation::validate_status(&bound_json(&b, false)?, p, &observer, &e)?;
        statuses.push(b);
    }
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    absent(&provisional_path)?;
    absent(&p.fleet_output)?;
    absent(&p.cycle_directory.join("completion.json"))?;
    let reader = reader();
    tool_ok(&reader)?;
    ensure!(
        sha(env::var("HORIZON_S3_ENDPOINT")?.as_bytes()) == p.endpoint_sha256,
        "recovery endpoint differs"
    );
    if check {
        println!("epoch185 fleet recovery preflight passed; no resource sample or remote access");
        return Ok(());
    }
    let iid = authenticate_named_service(UNIT)?;
    let root = p.cycle_directory.join("repair185-fleet-recovery-v1");
    absent(&root)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    File::open(&p.cycle_directory)?.sync_all()?;
    let recovery = write_new(
        &root.join("intent.json"),
        &json!({"schema":"horizon-repair185-fleet-recovery-v1",
        "source_plan":pb,"source_intent":intent,"rejected_child":rejected,"reader":reader,"original_invocation_id":OLD_IID,
        "recovery_unit":UNIT,"recovery_invocation_id":iid,"new_resource_samples":0,"replay_status_republications":0,
        "archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false}),
    )?;
    let corrected = corrected_fleet(&fv)?;
    let mut provisional_value = corrected.clone();
    provisional_value["output"] = json!(provisional_path);
    let mut staging: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
    staging.cycle_directory = root.clone();
    let package = delivery198::seal_values(
        &staging,
        "stop-history-correction",
        &[
            ("fleet-plan.json", corrected),
            ("provisional-plan.json", provisional_value),
        ],
    )?;
    let fleet_plan = file(package.join("fleet-plan.json"), true)?;
    let provisional_plan = file(package.join("provisional-plan.json"), true)?;
    child(
        &reader,
        &[
            "fleet-reconcile".into(),
            provisional_plan.path.display().to_string(),
            "--plan-sha256".into(),
            provisional_plan.sha256,
        ],
        true,
        &root.join("child-provisional.json"),
    )?;
    let provisional = file(provisional_path, false)?;
    let pipeline = json!({"provisional_fleet":provisional,"publication_skipped":true,"reason":"Previously completed198; recovery repairs guard-timer fleet census without replay status republication"});
    let ledger = bound_json(&provisional, false)?;
    ensure!(
        ledger["inventory"]["anomalies"] == 0
            && ledger["epochs"]
                .as_array()
                .context("epochs")?
                .iter()
                .any(|e| e["epoch"] == 198
                    && e["state"] == "remote-ready"
                    && e["status"].is_null()),
        "198 ready/absent-status evidence changed"
    );
    let mut current: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
    current.tools.r2 = reader.clone();
    let d144 = publication144::publish(&current, &pipeline, &observer)?;
    let d160 = delivery160::publish(&current, &pipeline, &observer)?;
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    child(
        &reader,
        &[
            "fleet-reconcile".into(),
            fleet_plan.path.display().to_string(),
            "--plan-sha256".into(),
            fleet_plan.sha256.clone(),
        ],
        true,
        &root.join("child-canonical.json"),
    )?;
    let fleet = file(p.fleet_output.clone(), false)?;
    let ledger = bound_json(&fleet, false)?;
    ensure!(
        ledger["inventory"]["anomalies"] == 0
            && ledger["observer_sha256"] == observer.sha256
            && ledger["plan_sha256"] == fleet_plan.sha256,
        "recovered fleet binding differs"
    );
    let completion = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","plan":pb,"self_sha256":self_sha,
        "sampled_at_utc":p.sample_target_utc,"observer":observer,"model":model,"estimates":estimates,"invocation_id":iid,
        "fleet_plan":fleet_plan,"fleet":fleet,"status_publications":statuses,"inventory":ledger["inventory"],
        "epoch198_delivery":pipeline,"epoch160_delivery":d160,"epoch144_delivery":d144,"unestimated_bootstrap_epochs":[185],"repair185_fleet_recovery":recovery,
        "new_resource_samples":0,"replay_status_republications":0,"archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false,"deletions":false});
    next_preparation::completion_bindings(p, pb, &completion)?;
    publication144::validate_completed(p, &completion)?;
    delivery160::validate_completed(p, &completion)?;
    write_new(&root.join("completion.json"), &completion)?;
    write_new(&p.cycle_directory.join("completion.json"), &completion)?;
    Ok(())
}
pub(super) fn consume(p: &mut Plan, c: &Value) -> Result<()> {
    let Some(b) = c.get("repair185_fleet_recovery") else {
        return Ok(());
    };
    let b: Bound = serde_json::from_value(b.clone())?;
    ensure!(
        b.path == Path::new(ROOT).join("repair185-fleet-recovery-v1/intent.json"),
        "foreign183 fleet recovery intent"
    );
    let v = bound_json(&b, false)?;
    ensure!(
        v["schema"] == "horizon-repair185-fleet-recovery-v1"
            && v["reader"] == serde_json::to_value(reader())?
            && v["original_invocation_id"] == OLD_IID
            && v["source_plan"]["sha256"] == PLAN_SHA
            && v["recovery_unit"] == UNIT
            && v["recovery_invocation_id"] == c["invocation_id"]
            && v["new_resource_samples"] == 0
            && v["replay_status_republications"] == 0
            && v["archive_mutations"] == false
            && v["sidecar_mutations"] == false
            && v["replay_launch_authorized"] == false,
        "foreign183 fleet recovery receipt"
    );
    p.tools.r2 = reader();
    Ok(())
}

pub(super) fn completed_plan(p: &Plan, c: &Value) -> Result<bool> {
    if c.get("repair185_fleet_recovery").is_none() {
        return Ok(false);
    }
    let mut checked: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
    consume(&mut checked, c)?;
    let corrected: Bound = serde_json::from_value(c["fleet_plan"].clone())?;
    ensure!(
        corrected.path
            == Path::new(ROOT)
                .join("repair185-fleet-recovery-v1/stop-history-correction/sealed/fleet-plan.json"),
        "foreign epoch185 corrected plan"
    );
    let original = Bound {
        path: Path::new(ROOT).join("sealed/fleet-plan.json"),
        sha256: "f4a20b872fd5d99fcd7333d5e9be6a478082519ed4015b58487b2b9d7064c2ff".into(),
    };
    ensure!(
        bound_json(&corrected, true)? == corrected_fleet(&bound_json(&original, true)?)?,
        "epoch185 correction changed more than the two non-replay guard observations"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_plan_or_nonmatching_failure_cannot_resume() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        p.sample_target_utc = "2026-10-23T03:29:58Z".into();
        p.cycle_directory = ROOT.into();
        p.repair185_handoff = Some(Bound {
            path: "/handoff".into(),
            sha256: "a".repeat(64),
        });
        p.public198_delivery = Some(
            serde_json::from_value(
                json!({"promotion":{"path":"/promotion","sha256":"a".repeat(64)},
       "origin":{"path":"/origin","sha256":"a".repeat(64)},"claims":[],"progressive_upload":true}),
            )
            .unwrap(),
        );
        let b = Bound {
            path: "/plan".into(),
            sha256: PLAN_SHA.into(),
        };
        let i = json!({"plan":b,"invocation_id":OLD_IID,"self_sha256":"597fbd87095b5d15a454dc62434263a8a4bb29cf2ea897dc098fd574e0d875d3"});
        let f = json!({"schema":"jetstreamer-horizon-routine-child-result-v1","success":false,"exit_code":1,"signal":null,
       "tool":p.tools.r2,"stderr":{"text":"Error: reserve stop cannot discard another observer claim\n"}});
        exact(&p, &b, &i, &f).unwrap();
        for (key, value) in [
            ("success", json!(true)),
            ("exit_code", json!(0)),
            ("signal", json!(9)),
            ("stderr", json!({"text":"another failure"})),
        ] {
            let mut bad = f.clone();
            bad[key] = value;
            assert!(exact(&p, &b, &i, &bad).is_err());
        }
        p.repair185_handoff = None;
        assert!(exact(&p, &b, &i, &f).is_err());
    }
}
