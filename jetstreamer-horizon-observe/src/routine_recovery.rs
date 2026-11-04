//! One exact missed-cycle/controller adoption, not an arbitrary interval/owner override.
use super::*;
const PROOF: &str =
    "/usr/local/lib/jetstreamer/horizon-package-controller-first-fire-20261021-v1/first-fire.json";
const PROOF_SHA: &str = "baad8fedb7ae8ab271da2c34850b54f626b907424eeb6c9669947b7d6dce3444";
const BINDINGS: &str =
    "/usr/local/lib/jetstreamer/horizon-package-controller-rebind-20261021-v1/guard-bindings.json";
const BINDINGS_SHA: &str = "b86c4d36b47ba1556ef47630eff12774ab980a30805e66999fd6947f84df1b47";
const OLD: &str = "2026-10-21T14:08:00Z";
const NEXT: &str = "2026-10-21T15:08:00Z";
pub(super) const CONTROLLER198: &str = "02c5ac25b42f47c99776ba5b65b6f4a9";

pub(super) fn epoch198_controller(binding: &Bound) -> Result<&'static str> {
    let rows = evidence(binding)?;
    let matches: Vec<_> = rows["bindings"]
        .as_array()
        .context("198recovery bindings")?
        .iter()
        .filter(|r| r["range"] == "198")
        .collect();
    ensure!(
        matches.len() == 1
            && matches[0]["controller_iid"] == CONTROLLER198
            && matches[0]["producer_iid"] == "e5612ef00a5b4fcab04df2c13a6b35b0",
        "198controller recovery cannot change original producer"
    );
    Ok(CONTROLLER198)
}

pub(super) fn epoch198_origin(model: &Value) -> Result<Option<Bound>> {
    let rows = model["evidence"]
        .as_array()
        .context("198origin model evidence")?;
    let matches: Vec<_> = rows
        .iter()
        .filter(|e| e["path"] == PROOF || e["sha256"] == PROOF_SHA)
        .collect();
    if matches.is_empty() {
        return Ok(None);
    }
    ensure!(
        matches.len() == 1,
        "duplicate 198controller recovery origin"
    );
    let binding: Bound = serde_json::from_value(matches[0].clone())?;
    ensure!(
        utc_seconds(
            model["sample_target_utc"]
                .as_str()
                .context("origin model time")?
        )? >= utc_seconds(NEXT)?,
        "198controller origin predates accepted adoption"
    );
    epoch198_controller(&binding)?;
    Ok(Some(binding))
}

fn evidence(binding: &Bound) -> Result<Value> {
    ensure!(
        binding.path == Path::new(PROOF) && binding.sha256 == PROOF_SHA,
        "unsupported controller recovery evidence"
    );
    let proof = bound_json(binding, true)?;
    ensure!(
        proof["schema"] == "jetstreamer-package-controller-guard-first-fire-v1"
            && proof["last_accepted_sample"] == OLD
            && proof["next_sample"] == NEXT
            && proof["missed_sample"] == "2026-10-21T14:38:00Z"
            && proof["failed_observer"]["sample_absent"] == true
            && proof["failed_cycle"]["cycle_directory_absent"] == true
            && proof["failed_cycle"]["status_publications"] == 0,
        "controller recovery does not prove the exact missed cycle"
    );
    for flag in [
        "replay_launch_authorized",
        "publication_authorized",
        "local_retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(
            proof[flag] == false,
            "recovery proof grants authority: {flag}"
        );
    }
    let b: Bound = serde_json::from_value(proof["bindings"].clone())?;
    ensure!(
        b.path == Path::new(BINDINGS) && b.sha256 == BINDINGS_SHA,
        "foreign controller recovery bindings"
    );
    let bindings = bound_json(&b, true)?;
    let rows = bindings["bindings"]
        .as_array()
        .context("recovery bindings missing")?;
    let fires = proof["first_fires"]
        .as_array()
        .context("recovery first fires missing")?;
    ensure!(
        rows.len() == 6 && fires.len() == 6,
        "incomplete recovery census"
    );
    ensure!(
        proof["all_first_fires"]["armed"] == true
            && proof["all_first_fires"]["trip"] == false
            && proof["all_first_fires"]["exit_status"] == 0
            && proof["all_first_fires"]["restarts"] == 0
            && proof["all_first_fires"]["maximum_worker_vmas"] == 800000,
        "recovery guards not qualified"
    );
    for row in rows {
        let matches: Vec<_> = fires
            .iter()
            .filter(|f| f["range"] == row["range"])
            .collect();
        ensure!(
            matches.len() == 1
                && matches[0]["minimum_free_bytes"] == row["floor"]
                && matches[0]["available_bytes"].as_u64() > row["floor"].as_u64()
                && matches[0]["worker_vmas"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n <= 800000),
            "recovery first-fire proof differs"
        );
    }
    Ok(bindings)
}

pub(super) fn interval(p: &Plan) -> Result<u64> {
    if p.controller_rebind.is_some() {
        return controller_rebind::interval(p);
    }
    if let Some(interval) = delivery160::interval(p)? {
        return Ok(interval);
    }
    if let Some(interval) = public198::interval(p)? {
        return Ok(interval);
    }
    if let Some(interval) = delivery198::recovery_interval(p)? {
        return Ok(interval);
    }
    if p.runtime_handoff157.is_some() {
        return runtime157::interval(p);
    }
    let Some(binding) = &p.package_controller_recovery else {
        return Ok(1800);
    };
    ensure!(
        is_101(p)?
            && p.sample_target_utc == NEXT
            && p.previous_observer.path
                == Path::new(
                    "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261021T140800Z.json"
                )
            && p.previous_observer.sha256
                == "e32f3173d8cbd13dbe7ceb598d0ba11eff99702c34e4a92260daab26ca1f3d97"
            && p.epoch198_delivery.is_none(),
        "controller recovery target or predecessor differs"
    );
    evidence(binding)?;
    Ok(3600)
}

fn transform(model: &Value, bindings: &Value, adopt: bool) -> Result<Value> {
    let mut model = model.clone();
    let rows = model["ranges"].as_array_mut().context("model ranges")?;
    let bindings = bindings["bindings"]
        .as_array()
        .context("controller bindings")?;
    ensure!(
        rows.len() == 6 && bindings.len() == 6,
        "controller model census changed"
    );
    for binding in bindings {
        let found: Vec<_> = rows
            .iter_mut()
            .filter(|r| r["range"] == binding["range"])
            .collect();
        ensure!(
            found.len() == 1,
            "controller recovery model range missing/duplicate"
        );
        let row = found.into_iter().next().unwrap();
        ensure!(
            row["expected_producer_invocation_id"] == binding["producer_iid"]
                && row["expected_controller_invocation_id"]
                    == binding[if adopt {
                        "old_controller_iid"
                    } else {
                        "controller_iid"
                    }],
            "controller recovery cannot change producer or borrow another controller"
        );
        if adopt {
            row["expected_controller_invocation_id"] = binding["controller_iid"].clone();
        }
    }
    Ok(model)
}

pub(super) fn model(p: &Plan, model: &Value) -> Result<Value> {
    let Some(binding) = &p.package_controller_recovery else {
        return Ok(model.clone());
    };
    interval(p)?;
    ensure!(
        model["sample_target_utc"] == OLD,
        "recovery requires actual old model clock"
    );
    let mut next = transform(model, &evidence(binding)?, true)?;
    let evidence = next["evidence"].as_array_mut().context("model evidence")?;
    let binding = serde_json::to_value(binding)?;
    if !evidence.contains(&binding) {
        evidence.push(binding);
    }
    Ok(next)
}

pub(super) fn consume(next: &mut Plan, model: &Value) -> Result<()> {
    if let Some(binding) = &next.package_controller_recovery {
        ensure!(
            model["sample_target_utc"] == NEXT,
            "unconsumed recovery cannot advance"
        );
        transform(model, &evidence(binding)?, false)?;
        next.package_controller_recovery = None;
    }
    Ok(())
}

pub(super) fn enable(
    next: &mut Plan,
    config: &mut Value,
    observer_package: &mut PathBuf,
    cycle_package: &mut PathBuf,
    old_model: &Value,
) -> Result<()> {
    ensure!(
        is_101(next)?
            && next.package_controller_recovery.is_none()
            && next.sample_target_utc == "2026-10-21T14:38:00Z"
            && old_model["sample_target_utc"] == OLD,
        "package recovery must consume genuine 14:08completion"
    );
    absent(&next.observer)?;
    absent(&next.cycle_directory)?;
    absent(&next.estimate_output)?;
    absent(&next.fleet_output)?;
    let binding = Bound {
        path: PROOF.into(),
        sha256: PROOF_SHA.into(),
    };
    let bindings = evidence(&binding)?;
    transform(old_model, &bindings, true)?;
    let rows = config["replays"]
        .as_array_mut()
        .context("configured recovery census")?;
    for binding in bindings["bindings"].as_array().unwrap() {
        let found: Vec<_> = rows
            .iter_mut()
            .filter(|r| r["range"] == binding["range"])
            .collect();
        ensure!(
            found.len() == 1,
            "configured recovery owner missing/duplicate"
        );
        let row = found.into_iter().next().unwrap();
        ensure!(
            row["controller_unit"] == binding["controller"]
                && row["producer_unit"] == binding["producer"]
                && row["expected_producer_invocation_id"] == binding["producer_iid"]
                && row["expected_controller_invocation_id"] == binding["old_controller_iid"],
            "configured recovery owner changed"
        );
        row["expected_controller_invocation_id"] = binding["controller_iid"].clone();
    }
    let advance = |path: &Path| -> Result<PathBuf> {
        let s = path.to_str().context("recovery path UTF8")?;
        ensure!(
            s.matches("20261021T143800Z").count() == 1,
            "recovery path namespace differs"
        );
        Ok(s.replace("20261021T143800Z", "20261021T150800Z").into())
    };
    *observer_package = advance(observer_package)?;
    *cycle_package = advance(cycle_package)?;
    next.observer = advance(&next.observer)?;
    next.observer_config.path = observer_package.join("observer.json");
    next.cycle_directory = advance(&next.cycle_directory)?;
    next.estimate_output = advance(&next.estimate_output)?;
    next.fleet_output = advance(&next.fleet_output)?;
    next.sample_target_utc = NEXT.into();
    next.package_controller_recovery = Some(binding);
    next.cycle_unit = cycle_unit(next)?;
    next.scope_101_200
        .as_mut()
        .unwrap()
        .additional_tracked_units = vec![next.cycle_unit.clone()];
    config["not_before_utc"] = json!(NEXT);
    config["output"] = json!(next.observer);
    // Preserve every predecessor hash, producer clock and pending 157 handoff.
    // Isolate the already-private 144 claim before its expected terminal event.
    private144::enable(next, config, old_model)?;
    interval(next)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value) {
        let bindings = json!({"bindings":(0..6).map(|n| json!({"range":n.to_string(),"producer_iid":format!("p{n}"),"old_controller_iid":format!("old{n}"),"controller_iid":format!("new{n}")})).collect::<Vec<_>>()});
        let model = json!({"sample_target_utc":OLD,"opaque_u64":u64::MAX,"ranges":(0..6).map(|n| json!({"range":n.to_string(),"expected_producer_invocation_id":format!("p{n}"),"expected_controller_invocation_id":format!("old{n}"),"allowance":43200,"terminal":u64::MAX-n})).collect::<Vec<_>>()});
        (model, bindings)
    }
    #[test]
    fn adoption_changes_only_the_six_exact_controller_ids() {
        let (model, bindings) = fixture();
        let actual = transform(&model, &bindings, true).unwrap();
        let mut expected = model.clone();
        for n in 0..6 {
            expected["ranges"][n]["expected_controller_invocation_id"] = json!(format!("new{n}"));
        }
        assert_eq!(actual, expected);
        assert_eq!(transform(&actual, &bindings, false).unwrap(), actual);
        assert!(transform(&actual, &bindings, true).is_err());
    }
    #[test]
    fn producer_change_or_incomplete_census_cannot_be_adopted() {
        let (mut model, bindings) = fixture();
        model["ranges"][0]["expected_producer_invocation_id"] = json!("replacement");
        assert!(transform(&model, &bindings, true).is_err());
        let (mut model, bindings) = fixture();
        model["ranges"].as_array_mut().unwrap().pop();
        assert!(transform(&model, &bindings, true).is_err());
    }
    #[test]
    fn changed198controller_cannot_borrow_a_missing_or_pre_adoption_origin() {
        assert!(
            epoch198_origin(&json!({"evidence":[],"sample_target_utc":NEXT}))
                .unwrap()
                .is_none()
        );
        assert!(
            epoch198_origin(
                &json!({"evidence":[{"path":PROOF,"sha256":PROOF_SHA}],"sample_target_utc":OLD})
            )
            .is_err()
        );
        assert!(epoch198_origin(&json!({"evidence":[{"path":PROOF,"sha256":"f".repeat(64)}],"sample_target_utc":NEXT})).is_err());
    }
    #[test]
    #[ignore = "requires root and exact immutable package-recovery evidence; no 198 event or adoption claimed"]
    fn exact198controller_binding_keeps_original_producer_and_legacy_origin() {
        let binding = Bound {
            path: PROOF.into(),
            sha256: PROOF_SHA.into(),
        };
        assert_eq!(epoch198_controller(&binding).unwrap(), CONTROLLER198);
        let model = json!({"evidence":[binding],"sample_target_utc":NEXT});
        let accepted = epoch198_origin(&model).unwrap().unwrap();
        assert_eq!(accepted.path, Path::new(PROOF));
        assert_eq!(accepted.sha256, PROOF_SHA);
        assert!(
            epoch198_origin(&json!({"evidence":[],"sample_target_utc":OLD}))
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn ordinary_plans_keep_the_hard_thirty_minute_interval() {
        let (p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        assert_eq!(interval(&p).unwrap(), 1800);
    }
    #[test]
    fn recovery_does_not_authorize_other_targets_or_an_arbitrary_binding() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        p.package_controller_recovery = Some(Bound {
            path: PROOF.into(),
            sha256: PROOF_SHA.into(),
        });
        assert!(interval(&p).is_err());
        p.sample_target_utc = NEXT.into();
        assert!(interval(&p).is_err());
        assert!(
            evidence(&Bound {
                path: "/foreign/proof.json".into(),
                sha256: PROOF_SHA.into()
            })
            .is_err()
        );
    }
}
