//! Refresh private141's operational replay ETA in the existing control cycle.
//! The new reader is only metadata tooling; no replay or archive gate changes.
use super::*;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    publisher: Bound,
    delivery_policy: Bound,
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    let Some(s) = &p.qualification141_status else {
        return Ok(());
    };
    ensure!(
        is_101(p)?
            && original141::capped_enabled(p)
            && p.public198_delivery.is_some()
            && original141::invocation(p) == Some("e639f007d482464f8a251455659d2ede")
            && matches!(
                s.publisher.path.to_str(),
                Some(
                    "/usr/local/lib/jetstreamer/horizon-epoch141-status-tools-20261023-v1/jetstreamer-r2"
                        | "/usr/local/lib/jetstreamer/horizon-epoch141-lifecycle-tools-20261023-v2/jetstreamer-r2"
                )
            )
            && !p.expected_epochs.contains(&141),
        "foreign141 status profile or duplicate estimate"
    );
    tool_ok(&s.publisher)?;
    policy(s)?;
    Ok(())
}
fn policy(s: &Profile) -> Result<(Value, u64)> {
    let v = bound_json(&s.delivery_policy, true)?;
    ensure!(
        v["schema"] == "jetstreamer-epoch141-sidecar-planning-v2"
            && v["epoch"] == 141
            && v["live_execution_terminal_slot"] == 61328765
            && v["epoch_terminal_slot"] == 61343999
            && v["separate_suffix_slots"] == 15234
            && v["root_invocation_continues_through_suffix"] == false
            && v["runtime_checkpoint_resume_qualified"] == false
            && v["publication_authorized"] == false
            && v["replay_launch_authorized"] == false
            && v["estimate_basis"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty())
            && v["estimate_uncertainty"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty())
            && v["planning_evidence"]
                .as_array()
                .is_some_and(|a| a.len() >= 2 && a.len() <= 16),
        "141 status policy cannot turn root qualification into a sidecar"
    );
    let stages = v["stage_allowance_millis"]
        .as_object()
        .context("141 stage allowances missing")?;
    ensure!(
        stages.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from([
                "suffix_input_restore_and_qualification",
                "assembly_close_import",
                "independent_full_verification",
                "current_plugin_verification",
                "required_boundary_checks",
                "upload_readback_source_revalidation_sidecar"
            ]),
        "141 stage allowance census differs"
    );
    let total = stages.values().try_fold(0u64, |total, n| {
        total
            .checked_add(
                n.as_u64()
                    .filter(|n| *n > 0)
                    .context("141 stage allowance invalid")?,
            )
            .context("141 stage allowance overflow")
    })?;
    ensure!(total > 0, "141 downstream allowance missing");
    Ok((v, total))
}
pub(super) fn fleet_reader(p: &Plan) -> &Bound {
    p.qualification141_status
        .as_ref()
        .map(|s| &s.publisher)
        .unwrap_or(&p.tools.r2)
}
pub(super) fn publish(p: &Plan, prior_pipeline: &Value, observer: &Bound) -> Result<Value> {
    publish_with(
        p,
        observer,
        || publish_current(p, prior_pipeline, observer),
        write_new,
    )
}
fn publish_with(
    p: &Plan,
    observer: &Bound,
    attempt: impl FnOnce() -> Result<Value>,
    persist: impl FnOnce(&Path, &Value) -> Result<Bound>,
) -> Result<Value> {
    if p.qualification141_status.is_none() {
        return Ok(json!({"enabled":false}));
    }
    // Structural validation remains fatal in validate_plan. An operational
    // failure in this private lane must not suppress the other eleven statuses,
    // final fleet reconciliation or the single successor cadence. In particular,
    // failure here is never evidence of terminality or permission to delete.
    match attempt() {
        Ok(value) => Ok(value),
        Err(error) => {
            let incident = persist(
                &p.cycle_directory
                    .join("qualification141-status-incident.json"),
                &json!({"schema":"jetstreamer-qualification141-status-incident-v2",
                    "epoch":141,"sampled_at_utc":p.sample_target_utc,"observer":observer,
                    "invocation_id":"e639f007d482464f8a251455659d2ede",
                    "error":format!("{error:#}"),"status_refresh_succeeded":false,
                    "previous_status_must_not_be_presented_as_current":true,
                    "terminality_established":false,"inactive_cleanup_authorized":false,
                    "remaining_growth_released":false,"repair_must_remain_open":true,
                    "next_action":"Inspect the preserved child failure and current owner. Repair an active owner's estimate; for positive capped141 termination, capture native manager evidence and reconcile the complete replacement/downstream claim census before conditional inactive cleanup. Preserve prefix/checkpoint bytes; root61328765 still leaves15234 suffix slots. No unavailable sample, missing rate or timeout proves inactivity.",
                    "replay_launch_authorized":false,"publication_authorized":false}),
            )?;
            Ok(
                json!({"enabled":true,"refresh_outcome":"incident","incident":incident,
                "new_resource_samples":0,"publication_authorized":false}),
            )
        }
    }
}
fn publish_current(p: &Plan, prior_pipeline: &Value, observer: &Bound) -> Result<Value> {
    let Some(s) = &p.qualification141_status else {
        return Ok(json!({"enabled":false}));
    };
    validate(p)?;
    let provisional: Bound = serde_json::from_value(prior_pipeline["provisional_fleet"].clone())?;
    let f = bound_json(&provisional, false)?;
    ensure!(
        f["sampled_at_utc"] == p.sample_target_utc
            && f["observer_sha256"] == observer.sha256
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200,
        "141 status requires same-sample accepted fleet"
    );
    let (policy, allowance) = policy(s)?;
    let directory = p.cycle_directory.join("qualification141-sealed");
    let source = write_new(
        &p.cycle_directory.join("qualification141-plan-source.json"),
        &json!({"schema":"jetstreamer-qualification141-status-plan-v2","observer":observer,"fleet":provisional,
            "receipt_directory":"/home/sol/.jetstreamer-private/r2-status-receipts",
            "estimate_receipt":p.cycle_directory.join("qualification141-estimate.json"),
            "downstream_allowance_millis":{"141":allowance},"epoch141_delivery_policy":s.delivery_policy,
            "estimate_basis":policy["estimate_basis"]}),
    )?;
    let seal = write_new(
        &p.cycle_directory.join("qualification141-seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":directory,
            "members":[{"source":source.path,"name":"plan.json","sha256":source.sha256,"mode":292}]}),
    )?;
    child(
        &p.tools.sealer,
        &[
            seal.path.display().to_string(),
            "--plan-sha256".into(),
            seal.sha256,
            "--self-sha256".into(),
            p.tools.sealer.sha256.clone(),
        ],
        false,
        &p.cycle_directory.join("child-qualification141-seal.json"),
    )?;
    child(
        &s.publisher,
        &[
            "status-publish-qualification".into(),
            directory.join("plan.json").display().to_string(),
            "--plan-sha256".into(),
            source.sha256,
            "--self-sha256".into(),
            s.publisher.sha256.clone(),
        ],
        true,
        &p.cycle_directory.join("child-qualification141-status.json"),
    )?;
    let digits: String = p
        .sample_target_utc
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let path = Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
        .join(format!("epoch-141.status-{digits}.json"));
    let bytes = read_checked(&path, LIMIT, 0, false)?;
    let receipt: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        receipt["epoch"] == 141
            && receipt["status"]["epoch"] == 141
            && receipt["status"]["phase"] == "replay"
            && receipt["status"]["sampled_at_utc"] == p.sample_target_utc
            && receipt["observer_receipt_sha256"] == observer.sha256
            && receipt["controller_invocation_id"] == "e639f007d482464f8a251455659d2ede"
            && receipt["producer_invocation_id"] == "e639f007d482464f8a251455659d2ede"
            && receipt["authenticated_readback"] == true,
        "141 status publication differs from cycle"
    );
    Ok(
        json!({"enabled":true,"publication":{"path":path,"sha256":sha(&bytes)},
        "delivery_policy":s.delivery_policy,"new_resource_samples":0,"publication_authorized":false}),
    )
}
pub(super) fn completion(p: &Plan, c: &Value) -> Result<()> {
    if p.qualification141_status.is_some() {
        ensure!(
            c["qualification141_status"]["enabled"] == true
                && c["qualification141_status"]["new_resource_samples"] == 0
                && c["qualification141_status"]["publication_authorized"] == false,
            "completion omits current141 operational status"
        );
        if c["qualification141_status"]["refresh_outcome"] == "incident" {
            let b: Bound =
                serde_json::from_value(c["qualification141_status"]["incident"].clone())?;
            let r = bound_json(&b, false)?;
            validate_incident(p, &r)?;
            ensure!(
                r["observer"] == c["observer"],
                "141 incident is not bound to the cycle observer"
            );
            return Ok(());
        }
        let b: Bound = serde_json::from_value(c["qualification141_status"]["publication"].clone())?;
        let r = bound_json(&b, false)?;
        ensure!(
            r["status"]["epoch"] == 141
                && r["status"]["phase"] == "replay"
                && r["status"]["sampled_at_utc"] == p.sample_target_utc
                && r["authenticated_readback"] == true,
            "141 completion publication is not current and authenticated"
        );
    }
    Ok(())
}
fn validate_incident(p: &Plan, r: &Value) -> Result<()> {
    ensure!(
        r["schema"] == "jetstreamer-qualification141-status-incident-v2"
            && r["epoch"] == 141
            && r["sampled_at_utc"] == p.sample_target_utc
            && r["invocation_id"] == "e639f007d482464f8a251455659d2ede"
            && r["error"].as_str().is_some_and(|s| !s.trim().is_empty())
            && r["status_refresh_succeeded"] == false
            && r["previous_status_must_not_be_presented_as_current"] == true
            && r["terminality_established"] == false
            && r["inactive_cleanup_authorized"] == false
            && r["remaining_growth_released"] == false
            && r["repair_must_remain_open"] == true
            && r["replay_launch_authorized"] == false
            && r["publication_authorized"] == false,
        "141 operational incident cannot establish terminality, release growth or authorize cleanup"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_private_eta_records_incident_without_failing_other_cycle_work() {
        let (mut p, ..) = super::super::tests::fixture101();
        let dummy = Bound {
            path: "/sealed/dummy".into(),
            sha256: "a".repeat(64),
        };
        p.qualification141_status = Some(Profile {
            publisher: dummy.clone(),
            delivery_policy: dummy.clone(),
        });
        let result = publish_with(
            &p,
            &dummy,
            || anyhow::bail!("private owner stopped or rate unavailable"),
            |path, incident| {
                assert_eq!(
                    path,
                    p.cycle_directory
                        .join("qualification141-status-incident.json")
                );
                validate_incident(&p, incident)?;
                assert_eq!(incident["observer"], serde_json::to_value(&dummy)?);
                Ok(Bound {
                    path: path.into(),
                    sha256: sha(&serde_json::to_vec(incident)?),
                })
            },
        )
        .unwrap();
        assert_eq!(result["refresh_outcome"], "incident");
        assert_eq!(result["new_resource_samples"], 0);
        assert!(result["publication"].is_null());
        assert_eq!(result["publication_authorized"], false);
        // If durable incident writing itself fails, reporting success would hide
        // the dashboard accuracy incident and remains forbidden.
        assert!(
            publish_with(
                &p,
                &dummy,
                || anyhow::bail!("no rate"),
                |_, _| anyhow::bail!("disk failure")
            )
            .is_err()
        );
    }
    #[test]
    fn status_failure_is_a_same_sample_incident_never_terminal_or_cleanup_authority() {
        let (p, ..) = super::super::tests::fixture101();
        let incident = json!({"schema":"jetstreamer-qualification141-status-incident-v2",
            "epoch":141,"sampled_at_utc":p.sample_target_utc,
            "invocation_id":"e639f007d482464f8a251455659d2ede","error":"no sufficient rate",
            "status_refresh_succeeded":false,"previous_status_must_not_be_presented_as_current":true,
            "terminality_established":false,"inactive_cleanup_authorized":false,
            "remaining_growth_released":false,"repair_must_remain_open":true,
            "replay_launch_authorized":false,"publication_authorized":false});
        validate_incident(&p, &incident).unwrap();
        for key in [
            "status_refresh_succeeded",
            "terminality_established",
            "inactive_cleanup_authorized",
            "remaining_growth_released",
            "replay_launch_authorized",
            "publication_authorized",
        ] {
            let mut bad = incident.clone();
            bad[key] = json!(true);
            assert!(validate_incident(&p, &bad).is_err(), "accepted{key}");
        }
        for (key, value) in [
            ("epoch", json!(144)),
            ("sampled_at_utc", json!("2026-01-01T00:00:00Z")),
            ("invocation_id", json!("replacement")),
            ("error", json!("")),
            ("repair_must_remain_open", json!(false)),
            (
                "previous_status_must_not_be_presented_as_current",
                json!(false),
            ),
        ] {
            let mut bad = incident.clone();
            bad[key] = value;
            assert!(validate_incident(&p, &bad).is_err(), "accepted{key}");
        }
    }
}
