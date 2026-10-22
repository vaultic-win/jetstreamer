//! Keep the exact retained private144 owner in the full fleet after observer isolation.
use super::*;
const UNIT: &str = "horizon-qualify-epoch144-loader-focus-20261016-v1.service";
const IID: &str = "ea4a806906ba493e9af49e2a9c71c9e7";
const SCRATCH: &str =
    "/home/sol/.jetstreamer-private/epoch144-upgradeable-loader-focus-20261016-v1/scratch";

fn classify(row: &Value, current: &Value, sample: &str) -> Result<Value> {
    classify_owner(
        row,
        current,
        sample,
        UNIT,
        IID,
        SCRATCH,
        "diagnostic-qualification",
    )
}
fn classify_owner(
    row: &Value,
    current: &Value,
    sample: &str,
    unit: &str,
    iid: &str,
    scratch: &str,
    phase: &str,
) -> Result<Value> {
    ensure!(
        row["producer_unit"] == unit
            && row["expected_producer_invocation_id"] == iid
            && row["scratch_path"] == scratch,
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
                    && row["observation"]["scratch_path"] == scratch
                    && row["observation"]["invocation_binding_stable"] == true,
                "private144 observation unstable"
            );
            for kind in ["controller", "producer"] {
                for point in ["before", "after"] {
                    let owner = &row["observation"][format!("{kind}_{point}")];
                    ensure!(
                        owner["invocation_id"] == iid
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
            current["InvocationID"] == iid && current["NRestarts"] == "0",
            "private144 live owner replaced or restarted"
        );
    }
    Ok(json!({"epoch":144,"phase":phase,"producer":current,
        "expected_invocation_id":iid,"scratch_path":scratch,"live":live,
        "sampled_at_utc":sample,"resource_observation":row,
        "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,
        "terminal_outcome_requires_canary_receipt":phase!="native-restore-only"&&phase!="private-checkpoint-continuation",
        "terminal_outcome_requires_continuation_receipt":phase=="private-checkpoint-continuation",
        "terminal_outcome_requires_native_receipt":phase=="native-restore-only","inactivity_or_cleanup_proven":false,
        "publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false}))
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
            overlaps.len() <= 3
                && overlaps.iter().all(|c| prefix144::namespace(c)
                    || native144::namespace(c)
                    || continuation144::namespace(c))
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
        ensure!(
            overlaps
                .iter()
                .filter(|c| continuation144::namespace(c))
                .count()
                <= 1,
            "duplicated144 continuation"
        );
        if overlaps.iter().any(|c| continuation144::namespace(c)) {
            let native = census
                .get(native144::UNIT)
                .context("native144 history absent")?;
            ensure!(
                native["InvocationID"] == "1219f5b93e0a40639db09f6996746243"
                    && native["ActiveState"] == "active"
                    && native["SubState"] == "exited"
                    && native["MainPID"] == "0"
                    && native["Result"] == "success"
                    && native["ExecMainStatus"] == "0",
                "continuation144 cannot overlap native comparison"
            );
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
    if rows[0]["producer_unit"] == continuation144::UNIT {
        let claim = overlaps
            .iter()
            .find(|c| continuation144::namespace(c))
            .context("continuation144 observer has no bound launch")?;
        ensure!(
            rows[0]["expected_producer_invocation_id"] == claim.invocation_id
                && rows[0]["scratch_path"].as_str() == claim.scratch_path.to_str(),
            "continuation144 observer differs from launch"
        );
        return Ok(Some(classify_owner(
            rows[0],
            census
                .get(continuation144::UNIT)
                .context("continuation144 owner absent")?,
            sample,
            continuation144::UNIT,
            &claim.invocation_id,
            continuation144::SCRATCH,
            "private-checkpoint-continuation",
        )?));
    }
    if rows[0]["producer_unit"] == native144::UNIT {
        let claim = overlaps
            .iter()
            .find(|c| native144::namespace(c))
            .context("native144 observer has no exact diagnostic claim")?;
        ensure!(
            rows[0]["expected_producer_invocation_id"] == claim.invocation_id
                && rows[0]["scratch_path"].as_str() == claim.scratch_path.to_str(),
            "native144 observer differs from bound launch"
        );
        let current = census
            .get(native144::UNIT)
            .context("native144 census missing")?;
        return Ok(Some(classify_owner(
            rows[0],
            current,
            sample,
            native144::UNIT,
            &claim.invocation_id,
            claim.scratch_path.to_str().context("native144 scratch")?,
            "native-restore-only",
        )?));
    }
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
    fn continuation_envelope_is_private_and_requires_its_own_terminal_receipt() {
        let iid = "d".repeat(32);
        let mut r = row();
        r["producer_unit"] = json!(continuation144::UNIT);
        r["expected_producer_invocation_id"] = json!(iid);
        r["scratch_path"] = json!(continuation144::SCRATCH);
        let current =
            json!({"ActiveState":"active","SubState":"running","InvocationID":iid,"NRestarts":"0"});
        let v = classify_owner(
            &r,
            &current,
            "sample",
            continuation144::UNIT,
            &iid,
            continuation144::SCRATCH,
            "private-checkpoint-continuation",
        )
        .unwrap();
        assert_eq!(v["live"], true);
        assert_eq!(v["current_sidecar_eta_valid"], false);
        assert_eq!(v["terminal_outcome_requires_continuation_receipt"], true);
        assert_eq!(v["terminal_outcome_requires_native_receipt"], false);
        assert_eq!(v["terminal_outcome_requires_canary_receipt"], false);
        assert_eq!(v["inactivity_or_cleanup_proven"], false);
        assert!(classify(&r, &current, "sample").is_err());
        let mut bad = r.clone();
        bad["expected_producer_invocation_id"] = json!("e".repeat(32));
        assert!(
            classify_owner(
                &bad,
                &current,
                "sample",
                continuation144::UNIT,
                &iid,
                continuation144::SCRATCH,
                "private-checkpoint-continuation"
            )
            .is_err()
        );
    }
    #[test]
    fn native_observer_is_exact_diagnostic_history_not_a_live_eta_or_cleanup_proof() {
        let iid = "b".repeat(32);
        let scratch = "/native/scratch";
        let mut r = row();
        r["producer_unit"] = json!(native144::UNIT);
        r["expected_producer_invocation_id"] = json!(iid);
        r["scratch_path"] = json!(scratch);
        let current =
            json!({"ActiveState":"active","SubState":"exited","InvocationID":iid,"NRestarts":"0"});
        let result = classify_owner(
            &r,
            &current,
            "sample",
            native144::UNIT,
            &iid,
            scratch,
            "native-restore-only",
        )
        .unwrap();
        assert_eq!(result["live"], false);
        assert_eq!(result["current_sidecar_eta_valid"], false);
        assert_eq!(result["terminal_outcome_requires_native_receipt"], true);
        assert_eq!(result["inactivity_or_cleanup_proven"], false);
        assert!(
            classify(&r, &current, "sample").is_err(),
            "native cannot masquerade as old producer"
        );
        for (key, value) in [
            ("expected_producer_invocation_id", json!("c".repeat(32))),
            ("scratch_path", json!("/foreign")),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(
                classify_owner(
                    &bad,
                    &current,
                    "sample",
                    native144::UNIT,
                    &iid,
                    scratch,
                    "native-restore-only"
                )
                .is_err()
            );
        }
    }
    #[test]
    #[ignore = "root exact failed23:28native observer regression; no resource sampling, writes or network"]
    fn actual_native_observer_requires_exact_bound_native_claim_and_preserves_old_owner_proof() {
        let b=BoundFile {path:"/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261021T232800Z-native144-upload198-refresh-completed144-v1/public198-stage/sealed/fleet-plan.json".into(),sha256:"10424be36b3a6edab8520811f20dc586cb8716926654022b06df646261597421".into()};
        let p: Plan = serde_json::from_value(bound_json(&b).unwrap()).unwrap();
        let o = bound_json(&p.observer).unwrap();
        let names = p.tracked_units.iter().cloned().collect();
        let c = census(&names, 101, 200).unwrap();
        let value = observe(&p, &o, &c, "2026-10-21T23:28:00Z")
            .unwrap()
            .unwrap();
        assert_eq!(
            value["expected_invocation_id"],
            "1219f5b93e0a40639db09f6996746243"
        );
        assert_eq!(value["live"], false);
        let mut bad = p;
        bad.diagnostics.retain(|c| !native144::namespace(c));
        assert!(observe(&bad, &o, &c, "sample").is_err());
    }
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
