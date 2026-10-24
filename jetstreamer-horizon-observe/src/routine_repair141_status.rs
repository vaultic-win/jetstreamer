//! Adopt and refresh the real 141 repair owner inside the existing observation.
//! No extra observer, producer restart, task launch or resource admission.
use super::*;
const UNIT: &str = "horizon-repair-141-floor-20261024-v1.service";
const PROGRAM: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch141-repair-status-tools-20261024-v1/jetstreamer-r2";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch141-active-repair-20261024-v1";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    queue_plan: Bound,
    owner_capture: Bound,
    planning_policy: Bound,
    invocation_id: String,
}
fn profile(p: &Plan) -> Option<&Profile> {
    p.qualification141_status.as_ref()?.active_repair.as_ref()
}
pub(super) fn enabled(p: &Plan) -> bool {
    profile(p).is_some()
}
pub(super) fn invocation(p: &Plan) -> Option<&str> {
    Some(&profile(p)?.invocation_id)
}
fn file(path: PathBuf) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, false)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn sample_digits(sample: &str) -> Result<String> {
    utc_seconds(sample)?;
    Ok(sample.chars().filter(char::is_ascii_digit).collect())
}
fn publication_path(sample: &str) -> Result<PathBuf> {
    Ok(
        Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
            .join(format!("epoch-141.status-{}.json", sample_digits(sample)?)),
    )
}
fn estimate_path(sample: &str) -> Result<PathBuf> {
    Ok(Path::new(ROOT).join(format!("estimate-{}.json", sample_digits(sample)?)))
}
fn capture(s: &Profile) -> Result<Value> {
    let c = bound_json(&s.owner_capture, false)?;
    ensure!(
        c["schema"] == "jetstreamer-epoch141-repair-owner-capture-v2"
            && c["epoch"] == 141
            && c["unit"] == UNIT
            && c["invocation_id"] == s.invocation_id
            && c["queue_plan"] == serde_json::to_value(&s.queue_plan)?
            && s.invocation_id.len() == 32
            && s.invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "141 repair profile is not an actual native queue capture"
    );
    let q = bound_json(&s.queue_plan, true)?;
    ensure!(
        q["schema"] == "jetstreamer-epoch141-repair-queue-plan-v2" && q["epoch"] == 141,
        "foreign 141 repair queue plan"
    );
    Ok(c)
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    let Some(s) = profile(p) else { return Ok(()) };
    let status = p.qualification141_status.as_ref().unwrap();
    ensure!(
        is_101(p)?
            && original141::capped_enabled(p)
            && p.public198_delivery.is_some()
            && !p.expected_epochs.contains(&141)
            && status.publisher.path == Path::new(PROGRAM),
        "141 repair profile changed ordinary claims or publisher"
    );
    tool_ok(&status.publisher)?;
    let c = capture(s)?;
    ensure!(
        c["program"] == serde_json::to_value(&status.publisher)?
            && c["manager_start_unix_millis"]
                .as_u64()
                .is_some_and(|start| start
                    <= utc_seconds(&p.sample_target_utc)
                        .unwrap_or(0)
                        .saturating_mul(1000)),
        "141 repair cannot backdate its first sample or use another program"
    );
    let v = bound_json(&s.planning_policy, true)?;
    ensure!(
        v["schema"] == "jetstreamer-epoch141-recovery-planning-v2"
            && v["epoch"] == 141
            && v["planning_assumptions_reviewed"] == true,
        "141 repair lacks reviewed recovery allowances"
    );
    Ok(())
}
pub(super) fn enable(p: &mut Plan, b: &Bound) -> Result<()> {
    let v = bound_json(b, true)?;
    ensure!(
        v["schema"] == "jetstreamer-epoch141-repair-routine-handoff-v2"
            && v["replay_launch_authorized"] == false
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false,
        "foreign 141 repair cadence handoff"
    );
    let s: Profile = serde_json::from_value(v["active_repair"].clone())?;
    let publisher: Bound = serde_json::from_value(v["publisher"].clone())?;
    let old = p
        .qualification141_status
        .as_mut()
        .context("141 repair preserves the existing qualification profile/history")?;
    ensure!(
        old.active_repair.is_none(),
        "141 repair cadence already adopted"
    );
    old.publisher = publisher;
    old.active_repair = Some(s);
    validate(p)
}
fn fold(fleet: &mut Value, claim: Value) -> Result<()> {
    let rows = fleet["pipeline_claims"]
        .as_array_mut()
        .context("141 fleet pipeline claims")?;
    let existing: Vec<_> = rows.iter().filter(|r| r["epoch"] == 141).collect();
    ensure!(
        existing.is_empty() || existing.len() == 1 && *existing[0] == claim,
        "141 repair cannot replace another pipeline handoff"
    );
    if existing.is_empty() {
        rows.push(claim);
    }
    let tracked = fleet["tracked_units"]
        .as_array_mut()
        .context("141 fleet tracked units")?;
    if !tracked.contains(&json!(UNIT)) {
        tracked.push(json!(UNIT));
    }
    ensure!(
        fleet["gates"]["141"]["state"] == "failed-needs-repair",
        "141 active repair must preserve the open failed epoch"
    );
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, fleet: &mut Value) -> Result<()> {
    let Some(s) = profile(p) else { return Ok(()) };
    validate(p)?;
    let c = capture(s)?;
    fold(
        fleet,
        json!({"epoch":141,"phase":"epoch141-active-repair","unit":UNIT,
        "invocation_id":s.invocation_id,"expected_exec_start":c["manager"]["ExecStart"],"evidence":[s.owner_capture]}),
    )
}
pub(super) fn publish(p: &Plan, prior: &Value, observer: &Bound) -> Result<Value> {
    let s = profile(p).context("141 active repair disabled")?;
    validate(p)?;
    let profile = p.qualification141_status.as_ref().unwrap();
    let provisional: Bound = serde_json::from_value(prior["provisional_fleet"].clone())?;
    let f = bound_json(&provisional, false)?;
    ensure!(
        f["sampled_at_utc"] == p.sample_target_utc && f["observer_sha256"] == observer.sha256,
        "141 repair requires this cycle's accepted fleet"
    );
    let state = file(Path::new(ROOT).join("state.json"))?;
    let current = bound_json(&state, false)?;
    ensure!(
        current["status"] == "managing-repair"
            && current["invocation_id"] == s.invocation_id
            && current["checkpoint_beyond_bootstrap_proven"] == false
            && current["remaining_growth_released"] == false,
        "141 repair lost its real queue or qualified a handoff; reconcile the next phase"
    );
    let mut assessment = bound_json(&s.planning_policy, true)?;
    assessment["estimate_observer"] = serde_json::to_value(observer)?;
    assessment["estimate_owner_invocation_id"] = json!(s.invocation_id);
    assessment["repair_state"] = serde_json::to_value(&state)?;
    assessment["assessment_method"] =
        json!("retain-unqualified-stage-budgets-from-authenticated-current-queue-v2");
    assessment["assessment_basis"] = json!(
        "Current authenticated queue proves no qualified checkpoint, export/restore or replay admission. Recompute the complete cold recovery forecast from the measured historical rate and all still-unqualified reviewed allowances. Successful engineering subprocess exit is not stage qualification. Revise the reviewed policy when qualified milestones or overrun evidence justify it; no fabricated partial replay credit."
    );
    let source = write_new(
        &p.cycle_directory.join("repair141-assessment-source.json"),
        &assessment,
    )?;
    let latest = f["epochs"]
        .as_array()
        .context("141 fleet entries")?
        .iter()
        .find(|r| r["epoch"] == 141)
        .context("141 fleet entry")?;
    let previous = if latest["status"].is_null() {
        None
    } else {
        let sample = latest["status"]["payload"]["sampled_at_utc"]
            .as_str()
            .context("141 previous status sample")?;
        Some(file(publication_path(sample)?)?)
    };
    let directory = p.cycle_directory.join("repair141-sealed");
    let plan = json!({"schema":"jetstreamer-epoch141-repair-status-plan-v2","epoch":141,"observer":observer,"fleet":provisional,
        "queue_plan":s.queue_plan,"owner_capture":s.owner_capture,"policy":{"path":directory.join("assessment.json"),"sha256":source.sha256},
        "estimate_receipt":estimate_path(&p.sample_target_utc)?,
        "receipt_directory":"/home/sol/.jetstreamer-private/r2-status-receipts","previous_publication":previous,
        "exclusive_local_epoch_ownership":true,"authenticated_other_host_handoffs":[]});
    let plan_source = write_new(&p.cycle_directory.join("repair141-plan-source.json"), &plan)?;
    let seal = write_new(
        &p.cycle_directory.join("repair141-seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":directory,
        "members":[{"source":source.path,"name":"assessment.json","sha256":source.sha256,"mode":292},
            {"source":plan_source.path,"name":"plan.json","sha256":plan_source.sha256,"mode":292}]}),
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
        &p.cycle_directory.join("child-repair141-seal.json"),
    )?;
    child(
        &profile.publisher,
        &[
            "status-publish-repair141".into(),
            directory.join("plan.json").display().to_string(),
            "--plan-sha256".into(),
            plan_source.sha256,
            "--self-sha256".into(),
            profile.publisher.sha256.clone(),
        ],
        true,
        &p.cycle_directory.join("child-repair141-publish.json"),
    )?;
    let receipt = file(publication_path(&p.sample_target_utc)?)?;
    validate_publication(p, &bound_json(&receipt, false)?, observer)?;
    Ok(
        json!({"enabled":true,"active_repair":true,"publication":receipt,"new_resource_samples":0,"publication_authorized":false}),
    )
}
fn validate_publication(p: &Plan, r: &Value, observer: &Bound) -> Result<()> {
    let s = profile(p).context("141 active repair disabled")?;
    ensure!(
        r["epoch"] == 141
            && r["status"]["epoch"] == 141
            && r["status"]["phase"] == "verification"
            && r["status"]["sampled_at_utc"] == p.sample_target_utc
            && r["status"]["estimated_remaining_millis"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && r["observer_receipt_sha256"] == observer.sha256
            && r["pipeline_binding"]["unit"] == UNIT
            && r["pipeline_binding"]["invocation_id"] == s.invocation_id
            && r["authenticated_readback"] == true,
        "141 repair receipt is not this sample's authenticated real owner"
    );
    Ok(())
}
pub(super) fn completion(p: &Plan, c: &Value) -> Result<()> {
    let b: Bound = serde_json::from_value(c["qualification141_status"]["publication"].clone())?;
    let observer: Bound = serde_json::from_value(c["observer"].clone())?;
    validate_publication(p, &bound_json(&b, false)?, &observer)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repair_receipts_use_the_publishers_canonical_numeric_sample_names() {
        assert_eq!(
            publication_path("2026-10-23T22:56:00Z").unwrap(),
            Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
                .join("epoch-141.status-20261023225600.json")
        );
        assert_eq!(
            estimate_path("2026-10-24T00:26:00Z").unwrap(),
            Path::new(ROOT).join("estimate-20261024002600.json")
        );
        assert!(publication_path("../2026-10-23T22:56:00Z").is_err());
        assert!(estimate_path("2026-10-24T00:26:00Z/other").is_err());
    }
    #[test]
    fn repair_fold_preserves_history_and_other_claims_and_rejects_owner_replacement() {
        let mut f = json!({"diagnostics":[{"epoch":141,"old":"preserve"}],"pipeline_claims":[{"epoch":198,"counter":u64::MAX}],"tracked_units":["other"],"gates":{"141":{"state":"failed-needs-repair","evidence":["old"]}}});
        let old = f.clone();
        let claim = json!({"epoch":141,"unit":UNIT,"invocation_id":"a".repeat(32)});
        fold(&mut f, claim.clone()).unwrap();
        fold(&mut f, claim.clone()).unwrap();
        assert_eq!(f["diagnostics"], old["diagnostics"]);
        assert_eq!(f["gates"], old["gates"]);
        assert_eq!(f["pipeline_claims"][0], old["pipeline_claims"][0]);
        assert_eq!(f["pipeline_claims"].as_array().unwrap().len(), 2);
        let mut replacement = claim;
        replacement["invocation_id"] = json!("b".repeat(32));
        assert!(fold(&mut f, replacement).is_err());
    }
}
