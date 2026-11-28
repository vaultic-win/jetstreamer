//! Exact no-rate runtime verification pause, not inactivity or launch authority.
use super::*;
const PROOF: &str = "/usr/local/lib/jetstreamer/horizon-epoch157-verification-pause-evidence-20261021-v1/pause.json";
const SHA: &str = "7551fdeafd0c5773dfb52a1b0df8b867f09e1dc1b2939569568bf5ede99789c2";
pub(super) const WRITER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch157-runtime-reader-20261021-v1/jetstreamer-r2";
pub(super) const WRITER_SHA: &str =
    "357d30f9d88bfe87758d256d5b1d98139311364e0ba3c1469ebea14db1c07b30";
const OLD: &str = "2026-10-21T15:08:00Z";
const NEXT: &str = "2026-10-21T16:08:00Z";
pub(super) fn writer(p: &Plan) -> bool {
    (p.tools.r2.path == Path::new(WRITER) && p.tools.r2.sha256 == WRITER_SHA)
        || prefix157::writer(p)
}
pub(super) fn validate(p: &Plan) -> Result<Value> {
    let b = p.runtime_handoff157.as_ref().context("157pause missing")?;
    ensure!(
        is_101(p)?
            && b.path == Path::new(PROOF)
            && b.sha256 == SHA
            && p.package_controller_recovery.is_none()
            && p.epoch157_terminal_handoff.is_none()
            && !p.expected_epochs.contains(&157)
            && writer(p),
        "foreign 157pause profile"
    );
    let proof = bound_json(b, true)?;
    ensure!(
        proof["schema"] == "jetstreamer-epoch157-runtime-verification-pause-v1"
            && proof["last_accepted_sample"] == OLD
            && proof["next_sample"] == NEXT
            && proof["epoch157_eta_unavailable"] == true,
        "157pause proof differs"
    );
    for flag in [
        "replay_launch_authorized",
        "publication_authorized",
        "local_retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(proof[flag] == false, "157pause grants authority");
    }
    Ok(proof)
}
pub(super) fn interval(p: &Plan) -> Result<u64> {
    validate(p)?;
    if p.sample_target_utc == NEXT {
        ensure!(
            p.previous_observer.sha256
                == "46429902fde6a991e50ee391a8c7e4ce97cb6996ef48adf01e6dd083dfd42e02"
                && p.previous_observer.path
                    == Path::new(
                        "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261021T150800Z.json"
                    ),
            "157pause predecessor differs"
        );
        Ok(3600)
    } else {
        ensure!(
            utc_seconds(&p.sample_target_utc)? > utc_seconds(NEXT)?,
            "157pause before recovery"
        );
        Ok(1800)
    }
}
fn exclude(model: &Value) -> Result<Value> {
    let mut out = model.clone();
    let rows = out["ranges"].as_array_mut().context("157model ranges")?;
    ensure!(
        rows.iter().filter(|r| r["range"] == "157").count() <= 1,
        "duplicate157range"
    );
    rows.retain(|r| r["range"] != "157");
    out["expected_observer_ranges"]
        .as_array_mut()
        .context("157 observer ranges")?
        .retain(|r| r != "157");
    Ok(out)
}
pub(super) fn effective_model(p: &Plan, model: &Value) -> Result<Value> {
    if p.runtime_handoff157.is_none() {
        return Ok(model.clone());
    }
    let proof = validate(p)?;
    let original: Bound = serde_json::from_value(proof["original_model"].clone())?;
    let original = bound_json(&original, true)?;
    let r = original["ranges"]
        .as_array()
        .context("original157ranges")?
        .iter()
        .find(|r| r["range"] == "157")
        .context("original157missing")?;
    ensure!(
        r["terminal_slot"] == 68140176
            && r["epochs"] == json!([157])
            && r["epoch_additional_replay_slots"] == json!({"157":115823})
            && r["epoch_downstream_allowance_seconds"] == json!({"157":43200}),
        "original 157queue changed"
    );
    let mut out = exclude(model)?;
    let evidence = out["evidence"]
        .as_array_mut()
        .context("157model evidence")?;
    let binding = serde_json::to_value(p.runtime_handoff157.as_ref().unwrap())?;
    if !evidence.contains(&binding) {
        evidence.push(binding);
    }
    Ok(out)
}
pub(super) fn derive_fleet(p: &Plan, fleet: &mut Value) -> Result<()> {
    if let Some(binding) = &p.runtime_handoff157 {
        validate(p)?;
        fleet["runtime_handoff157"] = serde_json::to_value(binding)?;
    }
    Ok(())
}
pub(super) fn enable(
    p: &mut Plan,
    config: &mut Value,
    observer_package: &mut PathBuf,
    cycle_package: &mut PathBuf,
    model: &Value,
) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.runtime_handoff157.is_none()
            && p.sample_target_utc == "2026-10-21T15:38:00Z"
            && model["sample_target_utc"] == OLD
            && p.epoch157_terminal_handoff.is_some(),
        "157pause requires genuine 15:08completion"
    );
    for path in [
        &p.observer,
        &p.cycle_directory,
        &p.estimate_output,
        &p.fleet_output,
    ] {
        absent(path)?;
    }
    let rows = config["replays"]
        .as_array_mut()
        .context("157config census")?;
    let found: Vec<_> = rows.iter().filter(|r| r["range"] == "157").collect();
    ensure!(
        found.len() == 1
            && found[0]["expected_producer_invocation_id"] == "d66eddeac8304adfbd17e4ebe1c6c1f9"
            && found[0]["expected_controller_invocation_id"] == "fcba4ece12fa462faf9062a3ad607879",
        "157config owner differs"
    );
    rows.retain(|r| r["range"] != "157");
    let advance = |path: &Path| -> Result<PathBuf> {
        let s = path.to_str().context("157path UTF8")?;
        ensure!(
            s.matches("20261021T153800Z").count() == 1,
            "157recovery namespace differs"
        );
        Ok(s.replace("20261021T153800Z", "20261021T160800Z").into())
    };
    *observer_package = advance(observer_package)?;
    *cycle_package = advance(cycle_package)?;
    p.observer = advance(&p.observer)?;
    p.observer_config.path = observer_package.join("observer.json");
    p.cycle_directory = advance(&p.cycle_directory)?;
    p.estimate_output = advance(&p.estimate_output)?;
    p.fleet_output = advance(&p.fleet_output)?;
    p.sample_target_utc = NEXT.into();
    p.epoch157_terminal_handoff = None;
    p.runtime_handoff157 = Some(Bound {
        path: PROOF.into(),
        sha256: SHA.into(),
    });
    p.expected_epochs.retain(|e| *e != 157);
    p.tools.r2 = Bound {
        path: WRITER.into(),
        sha256: WRITER_SHA.into(),
    };
    p.cycle_unit = cycle_unit(p)?;
    p.scope_101_200.as_mut().unwrap().additional_tracked_units = vec![p.cycle_unit.clone()];
    p.additional_gate_evidence
        .entry("157".into())
        .or_default()
        .push(Bound {
            path: PROOF.into(),
            sha256: SHA.into(),
        });
    config["not_before_utc"] = json!(NEXT);
    config["output"] = json!(p.observer);
    p.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
    effective_model(p, model)?;
    interval(p)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_plans_cannot_borrow_pause_interval_or_writer() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        assert!(!writer(&p));
        p.runtime_handoff157 = Some(Bound {
            path: PROOF.into(),
            sha256: SHA.into(),
        });
        assert!(validate(&p).is_err());
        assert!(interval(&p).is_err());
    }
    #[test]
    #[ignore = "root-only sealed production evidence; offline no service observation or remote mutation"]
    fn exact_pause_retains_real_predecessor_and_other_ten_epochs() {
        let p: Plan = serde_json::from_slice(&fs::read("/var/lib/jetstreamer/horizon-routine-plan-101-200-20261021T150800Z-v2/cycle-plan.json").unwrap()).unwrap();
        let c: Value =
            serde_json::from_slice(&fs::read(p.cycle_directory.join("completion.json")).unwrap())
                .unwrap();
        let b = Bound {path: "/var/lib/jetstreamer/horizon-routine-plan-101-200-20261021T150800Z-v2/cycle-plan.json".into(), sha256: "87fc86351a0ef74111d729c1492b865f914e21454e1605f9809dc34875c58ef5".into()};
        let config = bound_json(&p.observer_config, true).unwrap();
        let (mut next, mut config, mut op, mut cp) =
            next_preparation::derive_next(&p, &b, &c, &config).unwrap();
        let model = bound_json(&next.model_template, true).unwrap();
        controller_recovery::consume(&mut next, &model).unwrap();
        enable(&mut next, &mut config, &mut op, &mut cp, &model).unwrap();
        assert_eq!(next.expected_epochs.len(), 10);
        assert_eq!(interval(&next).unwrap(), 3600);
        assert_eq!(config["previous_sample"], json!(p.observer));
        let effective = private144::effective_model(&next, &model).unwrap();
        validate_observer_config(&next, &effective, &config).unwrap();
        assert_eq!(effective["ranges"].as_array().unwrap().len(), 5);
        assert_eq!(model["ranges"].as_array().unwrap().len(), 6);
        next.sample_target_utc = "2026-10-21T16:38:00Z".into();
        assert_eq!(interval(&next).unwrap(), 1800);
        next.sample_target_utc = "2026-10-21T15:38:00Z".into();
        assert!(interval(&next).is_err());
    }
    #[test]
    fn pause_removes_only157_and_preserves_all_other_bytes_and_u64s() {
        let original = json!({"ranges":[{"range":"157","epochs":[157],"offset":115823},{"range":"198","epochs":[198],"clock":u64::MAX}],"expected_observer_ranges":["157","198"],"opaque":u64::MAX});
        let out = exclude(&original).unwrap();
        assert_eq!(out["ranges"], json!([original["ranges"][1]]));
        assert_eq!(out["opaque"], u64::MAX);
        assert_eq!(out["expected_observer_ranges"], json!(["198"]));
        assert_eq!(exclude(&out).unwrap(), out);
    }
}
