//! Recover only the interrupted16:58 metadata transaction; never repeat replay statuses.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261022T165800Z-public160-native141-acquisition-scans-upload198-v1";
const PLAN_SHA: &str = "9ce0eb518223931865a774f882adaaac1eb06682d03b9b5a8b178760a9b0ac0c";
const OLD_IID: &str = "85eb5b6d7a2e4c908fc00901aa6b5ce5";
const FAILED_SHA: &str = "2eececdf2d61090e0f4aaebb4bbcb509109752fa016798bebfb23e4d57d24927";
const UNIT: &str = "horizon-public160-cycle-recovery-20261022-v1.service";
pub(super) const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch160-public-fleet-reader-20261022-v4/jetstreamer-r2";
pub(super) const READER_SHA: &str =
    "5ecf8a5e48267aafc9a0fddbc870b12d92d72d6c9c453d56bff196d7731a52be";
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
fn exact(p: &Plan, pb: &Bound, i: &Value, f: &Value) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.sample_target_utc == "2026-10-22T16:58:00Z"
            && p.cycle_directory == Path::new(ROOT)
            && pb.sha256 == PLAN_SHA
            && public160::enabled(p)
            && public198::upload(p)
            && i["plan"] == serde_json::to_value(pb)?
            && i["invocation_id"] == OLD_IID
            && i["self_sha256"]
                == "6346cdecdc707a2f8423157bf89dd9a39ba4879bc23455709133e35ba32219bf"
            && f["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && f["success"] == false
            && f["exit_code"] == 1
            && f["signal"].is_null()
            && f["tool"] == serde_json::to_value(&p.tools.r2)?
            && f["stderr"]["text"] == "Error: duplicate or inconsistent cohort pipeline claim\n",
        "not the exact public160 shared-uploader metadata failure"
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
        sha256: "194f92c146bb754c6117956b038eb815cf0388b3b5d373949fba338a36ef507d".into(),
    };
    ensure!(
        iv["observer"] == serde_json::to_value(&observer)?,
        "original observer differs"
    );
    bound_json(&observer, false)?;
    let model = Bound {
        path: p.cycle_directory.join("sealed/eta-model.json"),
        sha256: "3a48ae4fc0bb63d07452a469b8221eb343fdaeb24518c2df1631c8aac75bc411".into(),
    };
    let fleet_plan = Bound {
        path: p.cycle_directory.join("sealed/fleet-plan.json"),
        sha256: "2d4b25805bd8f9aa421d34fe09e5e4edd9b263ca00e5b45f8993ecff18b265af".into(),
    };
    let mv = bound_json(&model, true)?;
    let fv = bound_json(&fleet_plan, true)?;
    let provisional_plan = Bound {
        path: p
            .cycle_directory
            .join("public198-stage/sealed/fleet-plan.json"),
        sha256: "c38d06f4c87a05ccb0e6e612c016fd14940badb4924e018cdfb5e17e876498c1".into(),
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
                .join(format!("epoch-{epoch}.status-20261022165800.json")),
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
        println!("public160 recovery preflight passed; no resource sample or remote access");
        return Ok(());
    }
    let iid = authenticate_named_service(UNIT)?;
    let root = p.cycle_directory.join("public160-recovery-v1");
    absent(&root)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    File::open(&p.cycle_directory)?.sync_all()?;
    let recovery = write_new(
        &root.join("intent.json"),
        &json!({"schema":"horizon-public160-cycle-recovery-v1",
        "source_plan":pb,"source_intent":intent,"rejected_child":rejected,"reader":reader,"original_invocation_id":OLD_IID,
        "recovery_unit":UNIT,"recovery_invocation_id":iid,"new_resource_samples":0,"replay_status_republications":0,
        "archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false}),
    )?;
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
    let pipeline = json!({"provisional_fleet":provisional,"publication_skipped":true,"reason":"Previously completed198; recovery only restores160 downstream status"});
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
    let d160 = public160::publish(&current, &pipeline, &observer)?;
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
        "epoch198_delivery":pipeline,"epoch160_delivery":d160,"epoch144_delivery":null,"public160_recovery":recovery,
        "new_resource_samples":0,"replay_status_republications":0,"archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false,"deletions":false});
    next_preparation::completion_bindings(p, pb, &completion)?;
    public160::validate_completed(p, &completion)?;
    write_new(&root.join("completion.json"), &completion)?;
    write_new(&p.cycle_directory.join("completion.json"), &completion)?;
    Ok(())
}
pub(super) fn consume(p: &mut Plan, c: &Value) -> Result<()> {
    let Some(b) = c.get("public160_recovery") else {
        return Ok(());
    };
    let b: Bound = serde_json::from_value(b.clone())?;
    ensure!(
        b.path == Path::new(ROOT).join("public160-recovery-v1/intent.json"),
        "foreign160 recovery intent"
    );
    let v = bound_json(&b, false)?;
    ensure!(
        v["schema"] == "horizon-public160-cycle-recovery-v1"
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
        "foreign160 recovery receipt"
    );
    p.tools.r2 = reader();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_recovery_cannot_retry_another_cycle_or_successful_child() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        p.sample_target_utc = "2026-10-22T16:58:00Z".into();
        p.cycle_directory = ROOT.into();
        p.epoch160_delivery=Some(serde_json::from_value(json!({
            "proof":{"path":"/proof","sha256":"a".repeat(64)},"handoff":{"path":"/handoff","sha256":"a".repeat(64)},
            "origin_publication":{"path":"/origin","sha256":"a".repeat(64)},"origin_observer":{"path":"/observer","sha256":"a".repeat(64)},
            "delayed_recovery":false,"public_observation":{"path":"/public","sha256":"a".repeat(64)}})).unwrap());
        p.public198_delivery=Some(serde_json::from_value(json!({"promotion":{"path":"/promotion","sha256":"a".repeat(64)},
            "origin":{"path":"/origin","sha256":"a".repeat(64)},"claims":[],"progressive_upload":true})).unwrap());
        let pb = Bound {
            path: "/plan".into(),
            sha256: PLAN_SHA.into(),
        };
        let i = json!({"plan":pb,"invocation_id":OLD_IID,"self_sha256":"6346cdecdc707a2f8423157bf89dd9a39ba4879bc23455709133e35ba32219bf"});
        let f = json!({"schema":"jetstreamer-horizon-routine-child-result-v1","success":false,"exit_code":1,"signal":null,
            "tool":p.tools.r2,"stderr":{"text":"Error: duplicate or inconsistent cohort pipeline claim\n"}});
        exact(&p, &pb, &i, &f).unwrap();
        for (key, value) in [
            ("success", json!(true)),
            ("exit_code", json!(0)),
            ("signal", json!(9)),
            ("stderr", json!({"text":"other failure"})),
        ] {
            let mut bad = f.clone();
            bad[key] = value;
            assert!(exact(&p, &pb, &i, &bad).is_err(), "{key}");
        }
        let mut bad = i.clone();
        bad["invocation_id"] = json!("f".repeat(32));
        assert!(exact(&p, &pb, &bad, &f).is_err());
        p.sample_target_utc = "2026-10-22T17:28:00Z".into();
        assert!(exact(&p, &pb, &i, &f).is_err());
    }
}
