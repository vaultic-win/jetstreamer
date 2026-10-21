//! Exact private diagnostic isolation; never completion, inactivity or cleanup proof.
use super::*;

pub(super) const INVOCATION: &str = "ea4a806906ba493e9af49e2a9c71c9e7";
pub(super) const WRITER: &str =
    "/usr/local/lib/jetstreamer/horizon-private144-observer-20261021-v1/jetstreamer-r2";
pub(super) const WRITER_SHA: &str =
    "41d92da399e7c0a20f90599ff1d2dd6d21b7c143f197fbe3df381de58bd83932";
const UNIT: &str = "horizon-qualify-epoch144-loader-focus-20261016-v1.service";
const SCRATCH: &str =
    "/home/sol/.jetstreamer-private/epoch144-upgradeable-loader-focus-20261016-v1/scratch";

fn enabled(p: &Plan) -> bool {
    p.scope_101_200
        .as_ref()
        .is_some_and(|s| s.private144_observer)
}

pub(super) fn effective_model(p: &Plan, model: &Value) -> Result<Value> {
    is_101(p)?;
    let mut model = runtime157::effective_model(p, model)?;
    if enabled(p) {
        ensure!(
            (p.tools.r2.path == Path::new(WRITER) && p.tools.r2.sha256 == WRITER_SHA)
                || (p.runtime_handoff157.is_some() && runtime157::writer(p))
                || (delivery198::pending(p)
                    && p.tools.r2.path == Path::new(delivery198::HANDOFF_WRITER)
                    && p.tools.r2.sha256 == delivery198::HANDOFF_WRITER_SHA),
            "private144 requires its qualified fleet/status writer"
        );
        ensure!(
            !p.expected_epochs.contains(&144)
                && !model["ranges"]
                    .as_array()
                    .context("model ranges")?
                    .iter()
                    .any(|r| r["range"] == "144"
                        || r["epochs"]
                            .as_array()
                            .is_some_and(|a| a.contains(&json!(144)))),
            "private144 must never have a production estimate"
        );
        let ranges = model["expected_observer_ranges"]
            .as_array_mut()
            .context("expected observer census")?;
        ensure!(
            ranges.iter().filter(|r| **r == "144").count() <= 1,
            "duplicate private144 census"
        );
        ranges.retain(|r| r != "144");
    }
    Ok(model)
}

fn config_owner(row: &Value) -> Result<()> {
    ensure!(
        row["range"] == "144"
            && row["controller_unit"] == UNIT
            && row["producer_unit"] == UNIT
            && row["expected_controller_invocation_id"] == INVOCATION
            && row["expected_producer_invocation_id"] == INVOCATION
            && row["scratch_path"] == SCRATCH
            && row["worker_executable_basename"] == "historical-worker",
        "private144 config owner or tree differs"
    );
    Ok(())
}

pub(super) fn enable(p: &mut Plan, config: &mut Value, model: &Value) -> Result<()> {
    ensure!(
        is_101(p)? && !enabled(p),
        "private144 migration requires unmigrated101 profile"
    );
    let scope = p
        .scope_101_200
        .as_mut()
        .context("private144 scope missing")?;
    ensure!(
        scope.diagnostic_ranges.len() == 1
            && scope.diagnostic_ranges[0].expected_producer_invocation_id == INVOCATION,
        "private144 migration requires exact original owner"
    );
    ensure!(
        config["diagnostic_replays"].is_null()
            || config["diagnostic_replays"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "private144 migration cannot replace existing private diagnostics"
    );
    let rows = config["replays"]
        .as_array_mut()
        .context("replay census missing")?;
    let indices: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r["range"] == "144")
        .map(|(i, _)| i)
        .collect();
    ensure!(indices.len() == 1, "private144 source missing or duplicate");
    config_owner(&rows[indices[0]])?;
    let row = rows.remove(indices[0]);
    config["diagnostic_replays"] = json!([row]);
    scope.private144_observer = true;
    p.tools.r2 = Bound {
        path: WRITER.into(),
        sha256: WRITER_SHA.into(),
    };
    effective_model(p, model)?;
    p.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
    Ok(())
}

pub(super) fn validate(p: &Plan, model: &Value, value: &Value, observed: bool) -> Result<()> {
    ensure!(is_101(p)? && enabled(p), "private144 profile missing");
    effective_model(p, model)?;
    if p.native144_restore.is_some() {
        return native144::observer(p, value, observed);
    }
    ensure!(
        !value["replays"]
            .as_array()
            .context("ordinary census")?
            .iter()
            .any(|r| r["range"] == "144"),
        "private144 cannot remain an ordinary claim"
    );
    let rows = value["diagnostic_replays"]
        .as_array()
        .context("private144 diagnostic census missing")?;
    ensure!(rows.len() == 1, "private144 diagnostic census differs");
    let row = &rows[0];
    if !observed {
        return config_owner(row);
    }
    ensure!(
        row["range"] == "144"
            && row["producer_unit"] == UNIT
            && row["expected_producer_invocation_id"] == INVOCATION
            && row["scratch_path"] == SCRATCH,
        "private144 envelope owner differs"
    );
    for field in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            row[field] == false,
            "private144 envelope grants authority: {field}"
        );
    }
    match row["status"].as_str() {
        Some("unavailable") => {
            ensure!(
                row["observation"].is_null()
                    && row["error"].as_str().is_some_and(|s| !s.trim().is_empty()),
                "unavailable144 requires explicit unresolved evidence"
            );
            // This is deliberately not terminal or inactivity evidence. The
            // independent full fleet census and open repair remain mandatory.
        }
        Some("observed") => {
            let sample = &row["observation"];
            ensure!(
                row["error"].is_null()
                    && sample["range"] == "144"
                    && sample["scratch_path"] == SCRATCH
                    && sample["invocation_binding_stable"] == true,
                "private144 observation differs"
            );
            for kind in ["controller", "producer"] {
                for point in ["before", "after"] {
                    let owner = &sample[format!("{kind}_{point}")];
                    ensure!(
                        owner["invocation_id"] == INVOCATION
                            && owner["restarts"] == 0
                            && matches!(
                                owner["active_state"].as_str(),
                                Some("active" | "activating")
                            ),
                        "private144 observed owner changed"
                    );
                }
            }
        }
        _ => anyhow::bail!("unknown private144 observation outcome"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires root and exact sealed14:38 host plan; no sampling, processes or writes"]
    fn host_configuration_migration_is_exact_and_non_mutating() {
        let plan = Bound {
            path: "/var/lib/jetstreamer/horizon-routine-plan-101-200-20261021T143800Z-v2/cycle-plan.json".into(),
            sha256: "393630f927aa3048b0808433f83d12d9792e4717fefe469a4e6b7df843f45093".into(),
        };
        let mut p: Plan = serde_json::from_slice(&bound_bytes(&plan, true).unwrap()).unwrap();
        let mut config = bound_json(&p.observer_config, true).unwrap();
        let old_config = config.clone();
        let model = bound_json(&p.model_template, true).unwrap();
        let old_model = model.clone();
        enable(&mut p, &mut config, &model).unwrap();
        let effective = effective_model(&p, &model).unwrap();
        validate_observer_config(&p, &effective, &config).unwrap();
        assert_eq!(model, old_model);
        assert_eq!(effective["ranges"], model["ranges"]);
        assert_eq!(effective["evidence"], model["evidence"]);
        let mut expected = old_config;
        let rows = expected["replays"].as_array_mut().unwrap();
        let i = rows.iter().position(|r| r["range"] == "144").unwrap();
        let row = rows.remove(i);
        expected["diagnostic_replays"] = json!([row]);
        assert_eq!(config, expected);
        assert_eq!(
            p.observer_config.sha256,
            sha(&next_preparation::encoded(&config).unwrap())
        );
    }
    fn fixture() -> (Plan, Value, Value) {
        let (mut p, mut model, _, _, _, _, mut config, _) = crate::tests::fixture101();
        let d = &mut p.scope_101_200.as_mut().unwrap().diagnostic_ranges[0];
        d.expected_controller_invocation_id = INVOCATION.into();
        d.expected_producer_invocation_id = INVOCATION.into();
        config["replays"][1] = json!({"range":"144","controller_unit":UNIT,"producer_unit":UNIT,
            "expected_controller_invocation_id":INVOCATION,"expected_producer_invocation_id":INVOCATION,
            "scratch_path":SCRATCH,"worker_executable_basename":"historical-worker",
            "append_log":{"path":"/exact/log","device":u64::MAX,"inode":u64::MAX-1}});
        model["expected_observer_ranges"] = json!(["198", "144"]);
        (p, model, config)
    }
    fn envelope() -> Value {
        json!({"range":"144","producer_unit":UNIT,"expected_producer_invocation_id":INVOCATION,
            "scratch_path":SCRATCH,"status":"unavailable","observation":null,"error":"no worker",
            "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false})
    }
    #[test]
    fn migration_preserves_every_other_field_and_lossless_log_identity() {
        let (mut p, model, mut config) = fixture();
        let original = config.clone();
        let old_model = model.clone();
        enable(&mut p, &mut config, &model).unwrap();
        let effective = effective_model(&p, &model).unwrap();
        assert_eq!(model, old_model);
        let mut expected = old_model;
        expected["expected_observer_ranges"] = json!(["198"]);
        assert_eq!(effective, expected);
        assert_eq!(config["replays"], json!([original["replays"][0]]));
        assert_eq!(
            config["diagnostic_replays"],
            json!([original["replays"][1]])
        );
        assert_eq!(
            config["diagnostic_replays"][0]["append_log"]["device"].as_u64(),
            Some(u64::MAX)
        );
        validate(&p, &effective, &config, false).unwrap();
        assert!(enable(&mut p, &mut config, &model).is_err());
        assert_eq!(effective_model(&p, &effective).unwrap(), effective);
    }
    #[test]
    fn unavailable_is_explicit_not_activity_completion_or_authority() {
        let (mut p, model, mut config) = fixture();
        enable(&mut p, &mut config, &model).unwrap();
        let value = json!({"replays":[],"diagnostic_replays":[envelope()]});
        validate(&p, &model, &value, true).unwrap();
        for (key, bad) in [
            ("expected_producer_invocation_id", json!("f".repeat(32))),
            ("status", json!("complete")),
            ("error", json!("")),
            ("observation", json!({"range":"144"})),
            ("r2_mutations", json!(true)),
            ("current_sidecar_eta_valid", json!(true)),
        ] {
            let mut v = value.clone();
            v["diagnostic_replays"][0][key] = bad;
            assert!(validate(&p, &model, &v, true).is_err(), "{key}");
        }
    }
    #[test]
    fn actual_cycle_accepts_unavailable_diagnostic_but_still_rejects_bad_production_owner() {
        let (mut p, model, mut config) = fixture();
        let (_, _, _, _, _, _, _, mut observation) = crate::tests::fixture101();
        enable(&mut p, &mut config, &model).unwrap();
        let model = effective_model(&p, &model).unwrap();
        validate_observer_config(&p, &model, &config).unwrap();
        observation["replays"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["range"] != "144");
        observation["diagnostic_replays"] = json!([envelope()]);
        let now = utc_seconds(&p.sample_target_utc).unwrap() + 60;
        validate_observation(&p, &model, &observation, now).unwrap();
        observation["replays"][0]["producer_after"]["restarts"] = json!(1);
        assert!(validate_observation(&p, &model, &observation, now).is_err());
    }
    #[test]
    fn observed_diagnostic_requires_exact_stable_owner_and_never_borrows_a_new_one() {
        let (mut p, model, mut config) = fixture();
        enable(&mut p, &mut config, &model).unwrap();
        let owner = json!({"invocation_id":INVOCATION,"restarts":0,"active_state":"active"});
        let sample = json!({"range":"144","scratch_path":SCRATCH,"invocation_binding_stable":true,
            "controller_before":owner,"controller_after":owner,"producer_before":owner,"producer_after":owner});
        let mut entry = envelope();
        entry["status"] = json!("observed");
        entry["error"] = Value::Null;
        entry["observation"] = sample;
        let mut value = json!({"replays":[],"diagnostic_replays":[entry]});
        validate(&p, &model, &value, true).unwrap();
        value["diagnostic_replays"][0]["observation"]["producer_after"]["invocation_id"] =
            json!("f".repeat(32));
        assert!(validate(&p, &model, &value, true).is_err());
    }
    #[test]
    fn migration_rejects_foreign_scope_tree_duplicate_or_production_status() {
        for mutation in 0..5 {
            let (mut p, mut model, mut config) = fixture();
            match mutation {
                0 => config["replays"][1]["scratch_path"] = json!("/foreign"),
                1 => {
                    p.expected_epochs.push(144);
                }
                2 => {
                    let r = config["replays"][1].clone();
                    config["replays"].as_array_mut().unwrap().push(r);
                }
                3 => model["ranges"][0]["epochs"] = json!([144]),
                _ => {
                    p.scope_101_200.as_mut().unwrap().diagnostic_ranges[0]
                        .expected_producer_invocation_id = "f".repeat(32)
                }
            }
            assert!(enable(&mut p, &mut config, &model).is_err(), "{mutation}");
        }
    }
}
