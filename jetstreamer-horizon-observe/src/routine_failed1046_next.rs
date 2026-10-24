//! Exact offline successor of an incomplete cycle; never a synthetic completion.
use super::*;
const OLD: &str = "2026-10-24T10:46:00Z";
const NEXT: &str = "2026-10-24T11:16:00Z";
const GEN: &str = "memory152-rebind-terminal191-repair141-v1";
const PLAN_SHA: &str = "bce61136607a15dc147de668420722581e060f84d05076c9b6fc1d38e6967f49";
const OBS_SHA: &str = "48b2d228c2d34d70a7905bf21c5732ffefd5fbdf5f1a91c5d26e90e1dd3d97a2";
const MODEL_SHA: &str = "07415757ac536bdb5204b820bacf31f734d695b16421c7bcf3e734760abbd1b5";
const EST_SHA: &str = "54be8774943b53bb8cf47bfa8db7fd34e27fbd44951b8d6362a87d2112053a87";
const FP_SHA: &str = "f02210b0c1c73cd3e2ada0306dc95c51b3cbeba624dd72a17d560aba5aee5019";
const FLEET_SHA: &str = "e80b1c3c42bafc53dc0540e0135f86f0271807568fe440512f4b3a1d2429567d";
const CONFIG_SHA: &str = "37bcc4258de9791b8bdb300a5759bad3ce6c944862f10d0aa085a464c59a3728";
const SIX: [u64; 6] = [152, 153, 155, 156, 183, 184];
const STATUS_SHAS: [&str; 6] = [
    "fd6f010d02d2914b0cf6c966655d994a54f034509fb6904b60e8f36462ea7a97",
    "c610c4b5baa6b458555b824fef32973505b48ace9b16dfacdf04720f8716797b",
    "33427b5235743c0213c8b457a7fcd51131d90783156989d0e4e8130b92e91b9d",
    "defeae72326df9716cef9858b76c76da2e4a449d0f5015f93df8f0f99362e5b9",
    "eca4966f456cc1218483137bab3cb26ff439f2ffa615c2ec855bd236cef6d271",
    "6e001b68f1c3fb04b292fde52c3508d38bf1a770df0146813aa44195aec67f1f",
];

fn b(path: PathBuf, sha256: &str) -> Bound {
    Bound {
        path,
        sha256: sha256.into(),
    }
}
fn observer() -> Bound {
    b("/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261024T104600Z.json".into(), OBS_SHA)
}
fn model(p: &Plan) -> Bound {
    b(p.cycle_directory.join("sealed/eta-model.json"), MODEL_SHA)
}
fn fleet_plan(p: &Plan) -> Bound {
    b(p.cycle_directory.join("sealed/fleet-plan.json"), FP_SHA)
}
fn profile(p: &Plan, pb: &Bound) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.sample_target_utc == OLD
            && p.delayed_schedule_utc.is_none()
            && generation_101(p) == GEN
            && p.expected_epochs == SIX
            && pb.sha256 == PLAN_SHA
            && pb.path
                == Path::new("/var/lib/jetstreamer").join(format!(
                    "horizon-routine-plan-101-200-20261024T104600Z-{GEN}/cycle-plan.json"
                ))
            && p.observer == observer().path
            && p.cycle_directory
                == Path::new("/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2")
                    .join(format!("20261024T104600Z-{GEN}")),
        "foreign failed 10:46 preparation"
    );
    Ok(())
}
fn failure_proof(pb: &Bound, intent: &Value, failure: &Value, child: &Value) -> Result<()> {
    ensure!(
        intent["schema"] == "jetstreamer-horizon-routine-cycle-intent-v1"
            && intent["plan"] == serde_json::to_value(pb)?
            && intent["observer"] == serde_json::to_value(observer())?
            && intent["sampled_at_utc"] == OLD
            && intent["invocation_id"] == "6933a1a03292411e907f54ae222cd8a1"
            && intent["archive_mutations"] == false
            && intent["replay_launch_authorized"] == false
            && failure["schema"] == "jetstreamer-horizon-routine-cycle-failure-v1"
            && failure["plan"] == intent["plan"]
            && failure["observer"] == intent["observer"]
            && failure["archive_mutations"] == false
            && failure["replay_launch_authorized"] == false
            && failure["automatic_retry_authorized"] == false
            && failure["error"]
                .as_str()
                .is_some_and(|e| e.ends_with("/child-public198-fleet.json"))
            && child["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && child["success"] == false
            && child["exit_code"] == 1
            && child["signal"].is_null()
            && child["stderr"]["truncated"] == false
            && child["stderr"]["text"]
                == "Error: fleet unit identities or commands changed during reconciliation\n"
            && child["archive_mutations_authorized"] == false
            && child["replay_launch_authorized"] == false,
        "not the exact failed census before cycle completion"
    );
    Ok(())
}
fn recovered(p: &Plan, fleet: &Value) -> Result<()> {
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["sampled_at_utc"] == OLD
            && fleet["observer_sha256"] == OBS_SHA
            && fleet["plan_sha256"] == FP_SHA
            && fleet["plan"].as_str() == fleet_plan(p).path.to_str()
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet["inventory"]["anomalies"] == 0
            && fleet["inventory"]["ready_pairs"] == 60
            && fleet["inventory"]["missing"] == 40
            && fleet["remote_mutations"] == false
            && fleet["producer_mutations"] == false
            && fleet["publication_authorized"] == false,
        "recovered fleet is not the exact canonical 10:46 reconciliation"
    );
    Ok(())
}
fn derive(p: &Plan, config: &Value) -> Result<(Plan, Value, PathBuf)> {
    ensure!(
        config["schema"] == "jetstreamer-horizon-live-resource-sample-config-v2"
            && config["output"].as_str() == p.observer.to_str()
            && config["not_before_utc"] == OLD
            && config["minimum_interval_seconds"] == 1800
            && config
                .get("observation_reason")
                .is_none_or(|v| v == "routine"),
        "foreign observer cadence"
    );
    let mut c = config.clone();
    c["previous_sample"] = json!(p.observer);
    c["output"] = json!(
        "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261024T111600Z.json"
    );
    c["not_before_utc"] = json!(NEXT);
    ensure!(
        sha(&next_preparation::encoded(&c)?) == CONFIG_SHA,
        "11:16 observer differs from root's sealed config"
    );
    let mut n: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
    n.sample_target_utc = NEXT.into();
    n.delayed_schedule_utc = None;
    n.previous_observer = observer();
    n.model_template = model(p);
    n.fleet_template = fleet_plan(p);
    n.previous_estimates = b(p.estimate_output.clone(), EST_SHA);
    n.previous_fleet = b(p.fleet_output.clone(), FLEET_SHA);
    n.observer = serde_json::from_value(c["output"].clone())?;
    n.observer_config = b(
        Path::new("/var/lib/jetstreamer").join(format!(
            "horizon-next-observer-101-200-20261024T111600Z-{GEN}/observer.json"
        )),
        CONFIG_SHA,
    );
    n.cycle_unit = cycle_unit(&n)?;
    n.cycle_directory = Path::new("/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2")
        .join(format!("20261024T111600Z-{GEN}"));
    n.estimate_output = p
        .estimate_output
        .parent()
        .context("estimate parent")?
        .join("horizon-r2-status-estimates-20261024T111600Z-cohort-gated-v5.json");
    n.fleet_output = Path::new(FLEET_ROOT_101).join("fleet-20261024T111600Z.json");
    if let Some(scope) = &mut n.scope_101_200 {
        scope.additional_tracked_units = vec![n.cycle_unit.clone()];
    }
    let package = Path::new("/var/lib/jetstreamer").join(format!(
        "horizon-routine-plan-101-200-20261024T111600Z-{GEN}"
    ));
    Ok((n, c, package))
}
pub(super) fn prepare(p: &Plan, pb: &Bound, self_sha: &str) -> Result<()> {
    profile(p, pb)?;
    absent(&p.cycle_directory.join("completion.json"))?;
    let intent_b = b(
        p.cycle_directory.join("intent.json"),
        "b2907c081a3cf929862399d2446a42b802767297b9d29b52f68442bbad6636b6",
    );
    let failure_b = b(
        p.cycle_directory.join("failure.json"),
        "a62e56bb0fdc8d53e8bbfad9910b4b01d95f4f4b4effc0254bef5e5dc19f10c3",
    );
    let child_b = b(
        p.cycle_directory.join("child-public198-fleet.json"),
        "224b80a30c28741b3535b07e15f903b947fd045270f9e2c19b3ce5281ff97c64",
    );
    failure_proof(
        pb,
        &bound_json(&intent_b, false)?,
        &bound_json(&failure_b, false)?,
        &bound_json(&child_b, false)?,
    )?;
    let observed = bound_json(&observer(), false)?;
    ensure!(
        observed["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observed["recorded_at_utc"] == OLD,
        "wrong retained observer"
    );
    let m = bound_json(&model(p), true)?;
    let fp = bound_json(&fleet_plan(p), true)?;
    let estimates = bound_json(&b(p.estimate_output.clone(), EST_SHA), false)?;
    let entries = verify_estimates(p, &m, &observer(), &estimates)?;
    ensure!(entries.len() == 6, "six genuine estimates required");
    for (epoch, digest) in SIX.into_iter().zip(STATUS_SHAS) {
        let bytes = read_checked(
            &p.cycle_directory.join(format!("child-status-{epoch}.json")),
            LIMIT,
            0,
            false,
        )?;
        let child: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            child["success"] == true
                && child["exit_code"] == 0
                && child["signal"].is_null()
                && child["tool"] == serde_json::to_value(&p.tools.r2)?,
            "status child failed or changed"
        );
        let path = Path::new(
            m["status_receipt_directory"]
                .as_str()
                .context("status receipt directory")?,
        )
        .join(format!("epoch-{epoch}.status-20261024104600.json"));
        let bytes = bound_bytes(&b(path, digest), false)?;
        next_preparation::validate_status(
            &serde_json::from_slice(&bytes)?,
            p,
            &observer(),
            entries
                .iter()
                .find(|e| e["epoch"] == epoch)
                .context("estimate missing")?,
        )?;
    }
    let fleet = bound_json(&b(p.fleet_output.clone(), FLEET_SHA), false)?;
    recovered(p, &fleet)?;
    let config = bound_json(&p.observer_config, true)?;
    let (next, next_config, package) = derive(p, &config)?;
    ensure!(
        bound_json(&next.observer_config, true)? == next_config,
        "root's sealed observer changed"
    );
    next_preparation::validate_folded_scope(p, &fp)?;
    validate_templates(&next, &m, &fp, &fleet, &estimates, &observed)?;
    latest_fleet_unchanged(&next, &fleet)?;
    let root = Path::new("/var/lib/jetstreamer/horizon-next-preparations-101-200-v2");
    private_dir(root)?;
    let stage = root.join("20261024T111600Z-after-failed1046-v1");
    absent(&stage)?;
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    File::open(root)?.sync_all()?;
    let source = write_new(
        &stage.join("cycle-plan.json"),
        &serde_json::to_value(&next)?,
    )?;
    let seal = write_new(
        &stage.join("cycle-seal-plan.json"),
        &next_preparation::seal_plan(
            &stage,
            "cycle-plan.json",
            &package,
            "cycle-plan.json",
            &source.sha256,
        ),
    )?;
    let result = write_new(
        &stage.join("preparation.json"),
        &json!({"schema":"jetstreamer-after-failed1046-next-preparation-v1","current_plan":pb,"self_sha256":self_sha,"original_intent":intent_b,"original_failure":failure_b,"failed_child":child_b,"observer":observer(),"recovered_fleet":next.previous_fleet,"model":next.model_template,"estimates":next.previous_estimates,"fleet_plan":next.fleet_template,"next_sample_target_utc":NEXT,"cycle_source":source,"cycle_seal_plan":seal,"observer_reused":next.observer_config,"cycle_destination":package,"current_cycle_completion_created":false,"new_resource_samples":0,"status_publications_repeated":false,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false,"deployment_authorized":false,"preflight_required":true}),
    )?;
    println!("{}", result.path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Plan, Bound, Value) {
        let bytes = include_str!("fixtures/failed1046-plan.json");
        assert_eq!(sha(bytes.as_bytes()), PLAN_SHA);
        let p: Plan = serde_json::from_str(bytes).unwrap();
        let pb = b(
            Path::new("/var/lib/jetstreamer").join(format!(
                "horizon-routine-plan-101-200-20261024T104600Z-{GEN}/cycle-plan.json"
            )),
            PLAN_SHA,
        );
        (
            p,
            pb,
            serde_json::from_str(include_str!("fixtures/failed1046-observer-config.json")).unwrap(),
        )
    }
    #[test]
    fn derives_exact_successor_without_completion_or_scope_changes() {
        let (p, pb, c) = fixture();
        profile(&p, &pb).unwrap();
        let (n, nc, _) = derive(&p, &c).unwrap();
        assert_eq!(n.sample_target_utc, NEXT);
        assert_eq!(n.previous_observer.sha256, OBS_SHA);
        assert_eq!(n.previous_fleet.sha256, FLEET_SHA);
        assert_eq!(n.fleet_template.sha256, FP_SHA);
        assert_eq!(n.model_template.sha256, MODEL_SHA);
        assert_eq!(n.previous_estimates.sha256, EST_SHA);
        assert_eq!(n.expected_epochs, SIX);
        assert_eq!(
            n.cycle_unit,
            format!("horizon-routine-cycle-101-200-20261024T111600Z-{GEN}.service")
        );
        let mut expected = c;
        expected["previous_sample"] = json!(p.observer);
        expected["output"] = json!(n.observer);
        expected["not_before_utc"] = json!(NEXT);
        assert_eq!(nc, expected);
        assert_eq!(sha(&next_preparation::encoded(&nc).unwrap()), CONFIG_SHA);
        let old = serde_json::to_value(&p).unwrap();
        let new = serde_json::to_value(&n).unwrap();
        for (key, value) in old.as_object().unwrap() {
            if ![
                "sample_target_utc",
                "observer",
                "observer_config",
                "previous_observer",
                "model_template",
                "fleet_template",
                "previous_estimates",
                "previous_fleet",
                "cycle_unit",
                "cycle_directory",
                "estimate_output",
                "fleet_output",
                "scope_101_200",
            ]
            .contains(&key.as_str())
            {
                assert_eq!(&new[key], value, "{key}");
            }
        }
        let mut old_scope = old["scope_101_200"].clone();
        old_scope["additional_tracked_units"] =
            new["scope_101_200"]["additional_tracked_units"].clone();
        assert_eq!(old_scope, new["scope_101_200"]);
    }
    #[test]
    fn rejects_foreign_profile_and_cadence_relaxation() {
        let (mut p, mut pb, c) = fixture();
        pb.sha256 = "0".repeat(64);
        assert!(profile(&p, &pb).is_err());
        pb.sha256 = PLAN_SHA.into();
        p.expected_epochs.push(141);
        assert!(profile(&p, &pb).is_err());
        for (key, value) in [
            ("minimum_interval_seconds", json!(0)),
            ("observation_reason", json!("user-requested-status")),
            ("not_before_utc", json!(NEXT)),
            ("output", json!("/foreign")),
        ] {
            let mut changed = c.clone();
            changed[key] = value;
            assert!(derive(&fixture().0, &changed).is_err());
        }
    }
    #[test]
    fn rejects_wrong_failure_and_unbound_or_mutating_fleet() {
        let (p, pb, _) = fixture();
        let mut fleet = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","sampled_at_utc":OLD,"observer_sha256":OBS_SHA,"plan_sha256":FP_SHA,"plan":fleet_plan(&p).path,"first_epoch":101,"last_epoch":200,"inventory":{"anomalies":0,"ready_pairs":60,"missing":40},"remote_mutations":false,"producer_mutations":false,"publication_authorized":false});
        recovered(&p, &fleet).unwrap();
        fleet["plan_sha256"] = json!(PLAN_SHA);
        assert!(recovered(&p, &fleet).is_err());
        let intent = json!({"schema":"jetstreamer-horizon-routine-cycle-intent-v1","plan":pb,"observer":observer(),"sampled_at_utc":OLD,"invocation_id":"6933a1a03292411e907f54ae222cd8a1","archive_mutations":false,"replay_launch_authorized":false});
        let failure = json!({"schema":"jetstreamer-horizon-routine-cycle-failure-v1","plan":pb,"observer":observer(),"archive_mutations":false,"replay_launch_authorized":false,"automatic_retry_authorized":false,"error":"retained/child-public198-fleet.json"});
        let child = json!({"schema":"jetstreamer-horizon-routine-child-result-v1","success":false,"exit_code":1,"signal":null,"stderr":{"truncated":false,"text":"Error: fleet unit identities or commands changed during reconciliation\n"},"archive_mutations_authorized":false,"replay_launch_authorized":false});
        failure_proof(&pb, &intent, &failure, &child).unwrap();
        for (pointer, value) in [
            ("/success", json!(true)),
            ("/exit_code", json!(0)),
            ("/signal", json!(15)),
            ("/stderr/text", json!("another failure")),
            ("/stderr/truncated", json!(true)),
        ] {
            let mut bad = child.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(failure_proof(&pb, &intent, &failure, &bad).is_err());
        }
    }
}
