//! Offline recovery after a missed ordinary interval, authenticated by a real completion.
use super::*;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    schema: String,
    previous_plan: Bound,
    completion: Bound,
    observer_config: Bound,
    target_utc: String,
}
fn derive(
    p: &Plan,
    pb: &Bound,
    c: &Value,
    old_config: &Value,
    proof: &Proof,
    proof_bound: &Bound,
) -> Result<Plan> {
    ensure!(
        is_101(p)?
            && proof.schema == "jetstreamer-horizon-missed-cadence-proof-v1"
            && serde_json::to_value(&proof.previous_plan)? == serde_json::to_value(pb)?
            && proof.completion.path == p.cycle_directory.join("completion.json")
            && utc_seconds(&proof.target_utc)?
                .checked_sub(utc_seconds(&p.sample_target_utc)?)
                .is_some_and(|interval| interval > 1800),
        "foreign or non-missed cadence proof"
    );
    next_preparation::completion_bindings(p, pb, c)?;
    ensure!(
        old_config["schema"] == "jetstreamer-horizon-live-resource-sample-config-v2"
            && old_config["not_before_utc"] == scheduled_target(p)?
            && old_config["output"].as_str() == p.observer.to_str()
            && old_config["minimum_interval_seconds"] == 1800
            && old_config
                .get("observation_reason")
                .is_none_or(|v| v == "routine"),
        "foreign predecessor config"
    );
    let mark = stamp(&proof.target_utc);
    let mut config = old_config.clone();
    let observer = Path::new("/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1")
        .join(format!("sample-{mark}.json"));
    config["not_before_utc"] = json!(proof.target_utc);
    config["output"] = json!(observer);
    config["previous_sample"] = json!(p.observer);
    ensure!(
        sha(&next_preparation::encoded(&config)?) == proof.observer_config.sha256,
        "observer changes exceed exact retime"
    );
    let mut n: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
    n.sample_target_utc = proof.target_utc.clone();
    n.delayed_schedule_utc = None;
    n.missed_cadence = Some(proof_bound.clone());
    n.observer = observer;
    n.observer_config = proof.observer_config.clone();
    n.previous_observer = serde_json::from_value(c["observer"].clone())?;
    n.model_template = serde_json::from_value(c["model"].clone())?;
    n.fleet_template = serde_json::from_value(c["fleet_plan"].clone())?;
    n.previous_estimates = serde_json::from_value(c["estimates"].clone())?;
    n.previous_fleet = serde_json::from_value(c["fleet"].clone())?;
    n.cycle_unit = cycle_unit(&n)?;
    n.cycle_directory = Path::new("/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2")
        .join(format!("{mark}-{}", generation_101(p)));
    n.estimate_output = p
        .estimate_output
        .parent()
        .context("estimate parent")?
        .join(format!(
            "horizon-r2-status-estimates-{mark}-cohort-gated-v5.json"
        ));
    n.fleet_output = Path::new(FLEET_ROOT_101).join(format!("fleet-{mark}.json"));
    if let Some(scope) = &mut n.scope_101_200 {
        scope.additional_tracked_units = vec![n.cycle_unit.clone()];
    }
    Ok(n)
}
fn load(proof_bound: &Bound) -> Result<(Proof, Plan, Value, Value)> {
    let proof: Proof = serde_json::from_value(bound_json(proof_bound, true)?)?;
    let previous: Plan = serde_json::from_value(bound_json(&proof.previous_plan, true)?)?;
    let completion = bound_json(&proof.completion, false)?;
    let config = bound_json(&previous.observer_config, true)?;
    bound_bytes(&proof.observer_config, true)?;
    Ok((proof, previous, completion, config))
}
pub(super) fn active(p: &Plan) -> Result<bool> {
    let Some(binding) = &p.missed_cadence else {
        return Ok(false);
    };
    let (_, previous, _, _) = load(binding)?;
    Ok(interval(p, &previous.sample_target_utc)?.is_some())
}
pub(super) fn interval(p: &Plan, old_time: &str) -> Result<Option<u64>> {
    let Some(binding) = &p.missed_cadence else {
        return Ok(None);
    };
    ensure!(
        p.delayed_schedule_utc.is_none(),
        "missed cadence cannot use delayed schedule"
    );
    let (proof, previous, completion, config) = load(binding)?;
    let expected = derive(
        &previous,
        &proof.previous_plan,
        &completion,
        &config,
        &proof,
        binding,
    )?;
    ensure!(
        serde_json::to_value(p)? == serde_json::to_value(expected)?
            && old_time == previous.sample_target_utc,
        "missed cadence changed bound policy or predecessor"
    );
    Ok(Some(
        utc_seconds(&p.sample_target_utc)?
            .checked_sub(utc_seconds(old_time)?)
            .context("interval underflow")?,
    ))
}

pub(super) fn prepare(p: &Plan, pb: &Bound, proof_bound: &Bound, self_sha: &str) -> Result<()> {
    let (proof, previous, completion, config) = load(proof_bound)?;
    ensure!(
        serde_json::to_value(p)? == serde_json::to_value(&previous)?,
        "proof uses another predecessor"
    );
    let next = derive(p, pb, &completion, &config, &proof, proof_bound)?;
    let model = bound_json(&next.model_template, true)?;
    let fleet_plan = bound_json(&next.fleet_template, true)?;
    let fleet = bound_json(&next.previous_fleet, false)?;
    let estimates = bound_json(&next.previous_estimates, false)?;
    let observed = bound_json(&next.previous_observer, false)?;
    next_preparation::validate_folded_scope(p, &fleet_plan)?;
    validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observed)?;
    validate_observer_config(&next, &model, &bound_json(&next.observer_config, true)?)?;
    latest_fleet_unchanged(&next, &fleet)?;
    let mark = stamp(&next.sample_target_utc);
    let root = Path::new("/var/lib/jetstreamer/horizon-next-preparations-101-200-v2");
    private_dir(root)?;
    let stage = root.join(format!("{mark}-missed-cadence-v1"));
    absent(&stage)?;
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    File::open(root)?.sync_all()?;
    let source = write_new(
        &stage.join("cycle-plan.json"),
        &serde_json::to_value(&next)?,
    )?;
    let destination = Path::new("/var/lib/jetstreamer").join(format!(
        "horizon-routine-plan-101-200-{mark}-{}",
        generation_101(p)
    ));
    let seal = write_new(
        &stage.join("cycle-seal-plan.json"),
        &next_preparation::seal_plan(
            &stage,
            "cycle-plan.json",
            &destination,
            "cycle-plan.json",
            &source.sha256,
        ),
    )?;
    let receipt = write_new(
        &stage.join("preparation.json"),
        &json!({"schema":"jetstreamer-horizon-missed-cadence-preparation-v1","previous_plan":pb,"proof":proof_bound,"self_sha256":self_sha,"cycle_source":source,"cycle_seal_plan":seal,"cycle_destination":destination,"new_resource_samples":0,"completion_fabricated":false,"status_publications_repeated":false,"service_state_changed":false,"r2_mutations":false,"deployment_authorized":false,"preflight_required":true}),
    )?;
    println!("{}", receipt.path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Plan, Bound, Value, Value, Proof, Bound) {
        let p: Plan =
            serde_json::from_str(include_str!("fixtures/missed-cadence-plan.json")).unwrap();
        let pb=Bound{path:"/var/lib/jetstreamer/horizon-routine-notes-plan-101-200-20261024T114600Z-v1/cycle-plan.json".into(),sha256:"519a016047742f0709328c1a5807e2b66ff9e91bfdcf92cabb57fa548f95b6bc".into()};
        let c: Value =
            serde_json::from_str(include_str!("fixtures/missed-cadence-completion.json")).unwrap();
        let cfg =
            serde_json::from_str(include_str!("fixtures/missed-cadence-config.json")).unwrap();
        let proof=Proof{schema:"jetstreamer-horizon-missed-cadence-proof-v1".into(),previous_plan:pb.clone(),completion:Bound{path:p.cycle_directory.join("completion.json"),sha256:sha(include_bytes!("fixtures/missed-cadence-completion.json"))},observer_config:Bound{path:"/var/lib/jetstreamer/horizon-observer-capacity-recovery-20261024T143400Z-v1/observer.json".into(),sha256:"6380173bf6ee9ad7e3a29763e070667fb403959e5e000e071c5836d886f9b42e".into()},target_utc:"2026-10-24T14:34:00Z".into()};
        (
            p,
            pb,
            c,
            cfg,
            proof,
            Bound {
                path: "/sealed/proof.json".into(),
                sha256: "0".repeat(64),
            },
        )
    }
    #[test]
    fn genuine_completion_derives_only_actual_successor_and_preserves_policy() {
        let (p, pb, c, cfg, proof, binding) = fixture();
        let n = derive(&p, &pb, &c, &cfg, &proof, &binding).unwrap();
        assert_eq!(n.sample_target_utc, "2026-10-24T14:34:00Z");
        assert!(n.delayed_schedule_utc.is_none());
        assert_eq!(
            utc_seconds(&n.sample_target_utc).unwrap() - utc_seconds(&p.sample_target_utc).unwrap(),
            10080
        );
        assert_eq!(
            serde_json::to_value(&n.previous_observer).unwrap(),
            c["observer"]
        );
        let old = serde_json::to_value(&p).unwrap();
        let new = serde_json::to_value(&n).unwrap();
        for (key, value) in old.as_object().unwrap() {
            if ![
                "sample_target_utc",
                "delayed_schedule_utc",
                "missed_cadence",
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
        let mut scope = old["scope_101_200"].clone();
        scope["additional_tracked_units"] =
            new["scope_101_200"]["additional_tracked_units"].clone();
        assert_eq!(scope, new["scope_101_200"]);
    }
    #[test]
    fn rejects_fabricated_completion_foreign_predecessor_and_non_missed_interval() {
        let (p, pb, c, cfg, mut proof, binding) = fixture();
        let mut bad = c.clone();
        bad["sampled_at_utc"] = json!(proof.target_utc);
        assert!(derive(&p, &pb, &bad, &cfg, &proof, &binding).is_err());
        proof.previous_plan.sha256 = "f".repeat(64);
        assert!(derive(&p, &pb, &c, &cfg, &proof, &binding).is_err());
        proof.previous_plan = pb.clone();
        for time in ["2026-10-24T11:45:00Z", "2026-10-24T12:16:00Z", "bad"] {
            proof.target_utc = time.into();
            assert!(derive(&p, &pb, &c, &cfg, &proof, &binding).is_err());
        }
    }
    #[test]
    fn rejects_cadence_relaxation_and_any_extra_observer_change() {
        let (p, pb, c, cfg, proof, binding) = fixture();
        for (key, value) in [
            ("minimum_interval_seconds", json!(0)),
            ("observation_reason", json!("user-requested-status")),
            ("replays", json!([])),
            ("extra_permission", json!(true)),
        ] {
            let mut bad = cfg.clone();
            bad[key] = value;
            assert!(
                derive(&p, &pb, &c, &bad, &proof, &binding).is_err(),
                "{key}"
            );
        }
        let mut proof = proof;
        proof.completion.path = "/foreign/completion.json".into();
        assert!(derive(&p, &pb, &c, &cfg, &proof, &binding).is_err());
    }
}
