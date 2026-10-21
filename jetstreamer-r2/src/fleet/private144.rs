//! Keep the exact retained private144 owner in the full fleet after observer isolation.
use super::*;
const UNIT: &str = "horizon-qualify-epoch144-loader-focus-20261016-v1.service";
const IID: &str = "ea4a806906ba493e9af49e2a9c71c9e7";
const SCRATCH: &str =
    "/home/sol/.jetstreamer-private/epoch144-upgradeable-loader-focus-20261016-v1/scratch";

fn classify(row: &Value, current: &Value, sample: &str) -> Result<Value> {
    ensure!(
        row["producer_unit"] == UNIT
            && row["expected_producer_invocation_id"] == IID
            && row["scratch_path"] == SCRATCH,
        "private144 observer envelope owner differs"
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
        Some("unavailable") => ensure!(
            row["observation"].is_null()
                && row["error"].as_str().is_some_and(|s| !s.trim().is_empty()),
            "private144 unavailable outcome lacks explicit uncertainty"
        ),
        Some("observed") => {
            ensure!(
                row["error"].is_null()
                    && row["observation"]["range"] == "144"
                    && row["observation"]["scratch_path"] == SCRATCH
                    && row["observation"]["invocation_binding_stable"] == true,
                "private144 observation unstable"
            );
            for kind in ["controller", "producer"] {
                for point in ["before", "after"] {
                    let owner = &row["observation"][format!("{kind}_{point}")];
                    ensure!(
                        owner["invocation_id"] == IID
                            && owner["restarts"] == 0
                            && matches!(
                                owner["active_state"].as_str(),
                                Some("active" | "activating")
                            ),
                        "private144 observed owner differs"
                    );
                }
            }
        }
        _ => anyhow::bail!("unknown private144 observation outcome"),
    }
    let live = matches!(
        current["ActiveState"].as_str(),
        Some("active" | "activating")
    ) && current["SubState"] != "exited";
    if live {
        ensure!(
            current["InvocationID"] == IID && current["NRestarts"] == "0",
            "private144 live owner replaced or restarted"
        );
    }
    Ok(
        json!({"epoch":144,"phase":"diagnostic-qualification","producer":current,
        "expected_invocation_id":IID,"scratch_path":SCRATCH,"live":live,
        "sampled_at_utc":sample,"resource_observation":row,
        "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,
        "terminal_outcome_requires_canary_receipt":true,"inactivity_or_cleanup_proven":false,
        "publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false}),
    )
}

pub(super) fn observe(
    plan: &Plan,
    observer: &Value,
    census: &BTreeMap<String, Value>,
    sample: &str,
) -> Result<Option<Value>> {
    let rows: Vec<_> = observer["diagnostic_replays"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["range"] == "144")
        .collect();
    if rows.is_empty() {
        return Ok(None);
    }
    let overlaps: Vec<_> = plan
        .diagnostics
        .iter()
        .filter(|d| diagnostic_scope(d).contains(&144))
        .collect();
    if !overlaps.is_empty() {
        ensure!(
            overlaps.len() <= 2
                && overlaps
                    .iter()
                    .all(|c| prefix144::namespace(c) || native144::namespace(c))
                && overlaps.iter().filter(|c| prefix144::namespace(c)).count() <= 1
                && overlaps.iter().filter(|c| native144::namespace(c)).count() <= 1,
            "private144 overlapping diagnostic is not its exact independent verifier"
        );
        // Preserve the old observation as terminal history, never as another
        // live claim. Cleared IDs alone are not sufficient: authenticate PID1.
        crate::inactive_status::private144_terminal_manager_proof(
            census.get(UNIT).context("private144 old owner absent")?,
        )?;
        for claim in &overlaps {
            checked_diagnostic_launch(claim)?;
        }
    }
    ensure!(
        rows.len() == 1
            && plan.first_epoch == 101
            && plan.last_epoch == 200
            && plan.tracked_units.iter().any(|u| u == UNIT)
            && plan.gates.get(&144).is_some_and(|g| matches!(
                g.state.as_str(),
                "blocked-qualification" | "failed-needs-repair"
            ))
            && !plan.pipeline_claims.iter().any(|c| c.epoch == 144)
            && !observer["replays"]
                .as_array()
                .context("ordinary replay census")?
                .iter()
                .any(|r| r["range"] == "144"),
        "private144 fleet scope, gate, tracking or overlapping owner differs"
    );
    Ok(Some(classify(
        rows[0],
        census
            .get(UNIT)
            .context("private144 tracked unit missing from census")?,
        sample,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root-only exact retained144 verifier plan and real terminal manager journal; no remote access"]
    fn exact_completed_old144_can_coexist_only_with_its_private_verifier() {
        let p:Plan=serde_json::from_value(bound_json(&BoundFile{path:"/usr/local/lib/jetstreamer/horizon-prefix144-admission-plan-20261021-v1/fleet-plan.json".into(),sha256:"1a070f224017cb3364173bee353c71cdcd6f053a27e6a72068a88640ab18e8af".into()}).unwrap()).unwrap();
        let o = bound_json(&p.observer).unwrap();
        let c = BTreeMap::from([(UNIT.into(), unit(UNIT).unwrap())]);
        let v = observe(&p, &o, &c, "2026-10-21T17:38:00Z")
            .unwrap()
            .unwrap();
        assert_eq!(v["live"], false);
        let mut active = c.clone();
        active.get_mut(UNIT).unwrap()["ActiveState"] = json!("active");
        active.get_mut(UNIT).unwrap()["SubState"] = json!("running");
        assert!(observe(&p, &o, &active, "sample").is_err());
        let mut foreign = p;
        foreign
            .diagnostics
            .iter_mut()
            .find(|d| d.epoch == 144)
            .unwrap()
            .unit = "horizon-qualify-144-unbound.service".into();
        assert!(observe(&foreign, &o, &c, "sample").is_err());
    }
    fn row() -> Value {
        json!({"range":"144","producer_unit":UNIT,"expected_producer_invocation_id":IID,"scratch_path":SCRATCH,
            "status":"unavailable","error":"no worker","observation":null,
            "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"replay_launch_authorized":false,
            "publication_authorized":false,"r2_mutations":false})
    }
    #[test]
    fn unavailable_resource_sample_does_not_erase_actual_live_owner() {
        let current =
            json!({"ActiveState":"active","SubState":"running","InvocationID":IID,"NRestarts":"0"});
        let result = classify(&row(), &current, "2026-10-21T15:08:00Z").unwrap();
        assert_eq!(result["live"], true);
        assert_eq!(result["current_sidecar_eta_valid"], false);
        assert_eq!(result["inactivity_or_cleanup_proven"], false);
        let mut replaced = current.clone();
        replaced["InvocationID"] = json!("f".repeat(32));
        assert!(classify(&row(), &replaced, "sample").is_err());
    }
    #[test]
    fn terminal_owner_is_not_an_active_claim_or_cleanup_authority() {
        let current =
            json!({"ActiveState":"inactive","SubState":"dead","InvocationID":IID,"NRestarts":"0"});
        let result = classify(&row(), &current, "sample").unwrap();
        assert_eq!(result["live"], false);
        assert_eq!(result["terminal_outcome_requires_canary_receipt"], true);
        assert_eq!(result["inactivity_or_cleanup_proven"], false);
        let mut forged = row();
        forged["publication_authorized"] = json!(true);
        assert!(classify(&forged, &current, "sample").is_err());
    }
}
