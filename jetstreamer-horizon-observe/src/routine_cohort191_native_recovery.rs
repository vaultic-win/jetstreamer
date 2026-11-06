//! Exact 05:16 failed fleet tail. Reuses six authenticated publications and the
//! original resource observer; new epoch 191 metadata has its own genuine event clock.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261024T051600Z-memory152-rebind-guard-stopped185-import-pending191-repair141-v2";
const PLAN_SHA: &str = "61d0de19d0e401d692565dcb32edc414fcacf9d261f23d0702016470faf3504b";
const FAILED_SHA: &str = "32a6f4f0fb82198ea13901b583b3716a23822e4f9df83261dbac0e1df600606c";
const OBSERVER_SHA: &str = "0db9966d4b29d38984e8a2d9d0938d61dfb005356195a29e63362ea7ca4e70f1";
const OLD_IID: &str = "4116fa9b09124b56906ede24e25cbc2c";
const UNIT: &str = "horizon-cohort191-native-event-tail-recovery-20261024-v2.service";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    profile: cohort191_delivery::Profile,
    publication_authorized: bool,
    replay_launch_authorized: bool,
    r2_mutations: bool,
}
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn success(v: &Value, tool: &Bound) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-routine-child-result-v1"
            && v["success"] == true
            && v["exit_code"] == 0
            && v["signal"].is_null()
            && v["tool"] == serde_json::to_value(tool)?,
        "0516 original child unsuccessful"
    );
    Ok(())
}
fn exact(p: &Plan, pb: &Bound, intent: &Value, failure: &Value) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.cycle_directory == Path::new(ROOT)
            && pb.sha256 == PLAN_SHA
            && p.sample_target_utc == "2026-10-24T05:16:00Z"
            && p.expected_epochs == [152, 153, 155, 156, 183, 184]
            && intent["plan"] == serde_json::to_value(pb)?
            && intent["invocation_id"] == OLD_IID
            && intent["self_sha256"]
                == "5c6f27076a93c963e462313b311ef6c201f4e5b8286982d894ff7898790844ed"
            && failure["success"] == false
            && failure["exit_code"] == 1
            && failure["signal"].is_null()
            && failure["stderr"]["text"]
                == "Error: unbound live producer horizon-full-verify-191-native191-20261023-v1.service; rebuild fleet plan and observer census\n",
        "not exact0516 retained native191 census failure"
    );
    Ok(())
}
fn correction(original: &Value, corrected: &Value) -> Result<()> {
    let mut expected = original.clone();
    for epoch in 191..=194 {
        expected["gates"][epoch.to_string()] = corrected["gates"][epoch.to_string()].clone();
    }
    let old = original["pipeline_claims"]
        .as_array()
        .context("0516 prior claims")?;
    let new = corrected["pipeline_claims"]
        .as_array()
        .context("0516 corrected claims")?;
    ensure!(
        old.iter()
            .filter(|c| !c["epoch"]
                .as_u64()
                .is_some_and(|n| (191..=194).contains(&n)))
            .eq(new.iter().filter(|c| !c["epoch"]
                .as_u64()
                .is_some_and(|n| (191..=194).contains(&n))))
            && new
                .iter()
                .filter(|c| c["epoch"]
                    .as_u64()
                    .is_some_and(|n| (191..=194).contains(&n)))
                .count()
                == 4,
        "0516 recovery changed another owner or lost191members"
    );
    expected["pipeline_claims"] = corrected["pipeline_claims"].clone();
    ensure!(
        expected == *corrected,
        "0516 recovery changed non191 fleet fields"
    );
    Ok(())
}
pub(super) fn run(p: &Plan, pb: &Bound, self_sha: &str, spec: &Bound, check: bool) -> Result<()> {
    let intent = file(p.cycle_directory.join("intent.json"), false)?;
    let failed = Bound {
        path: p.cycle_directory.join("child-public198-fleet.json"),
        sha256: FAILED_SHA.into(),
    };
    let i = bound_json(&intent, false)?;
    exact(p, pb, &i, &bound_json(&failed, false)?)?;
    let saved = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            &p.cycle_unit,
            "--property=InvocationID,MainPID,NRestarts,ActiveState,SubState,Result,ExecMainStatus",
        ])
        .output()?;
    ensure!(saved.status.success(), "0516 failed owner unreadable");
    let text = std::str::from_utf8(&saved.stdout)?;
    let properties: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
    for (key, value) in [
        ("InvocationID", OLD_IID),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
        ("ExecMainStatus", "1"),
    ] {
        ensure!(
            properties.get(key) == Some(&value),
            "0516 failed native owner changed:{key}"
        );
    }
    let observer = Bound {
        path: p.observer.clone(),
        sha256: OBSERVER_SHA.into(),
    };
    ensure!(
        i["observer"] == serde_json::to_value(&observer)?,
        "0516 original observer changed"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sampled = utc_seconds(&p.sample_target_utc)?;
    ensure!(
        now >= sampled && now - sampled <= 1800,
        "0516 retained sample is stale/future"
    );
    bound_json(&observer, false)?;
    let model = file(p.cycle_directory.join("sealed/eta-model.json"), true)?;
    let mv = bound_json(&model, true)?;
    let estimates = file(p.estimate_output.clone(), false)?;
    let ev = bound_json(&estimates, false)?;
    ensure!(
        estimates.sha256 == "f89eb7c15232fc22672fa98cc02a1709c837f5db02d3bbcb2441ae2bbefd8859"
            && ev["model_sha256"] == model.sha256
            && ev["estimator_sha256"] == p.tools.estimator.sha256,
        "0516 estimate lineage changed"
    );
    success(
        &bound_json(
            &file(p.cycle_directory.join("child-estimator.json"), false)?,
            false,
        )?,
        &p.tools.estimator,
    )?;
    let mut statuses = vec![];
    for e in verify_estimates(p, &mv, &observer, &ev)? {
        let epoch = e["epoch"].as_u64().context("0516 epoch")?;
        success(
            &bound_json(
                &file(
                    p.cycle_directory.join(format!("child-status-{epoch}.json")),
                    false,
                )?,
                false,
            )?,
            &p.tools.r2,
        )?;
        let receipt = file(
            Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
                .join(format!("epoch-{epoch}.status-20261024051600.json")),
            false,
        )?;
        next_preparation::validate_status(&bound_json(&receipt, false)?, p, &observer, &e)?;
        statuses.push(receipt);
    }
    let spec_value: Spec = serde_json::from_value(bound_json(spec, true)?)?;
    ensure!(
        spec_value.schema == "jetstreamer-cohort191-native-tail-recovery-spec-v2"
            && !spec_value.publication_authorized
            && !spec_value.replay_launch_authorized
            && !spec_value.r2_mutations
            && spec_value.profile.native_handoff_event
            && !spec_value.profile.import_pending,
        "0516 recovery spec changed phase/authority"
    );
    let mut effective: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
    effective.cohort191_delivery = Some(spec_value.profile);
    cohort191_delivery::validate(&effective)?;
    let original = file(p.cycle_directory.join("sealed/fleet-plan.json"), true)?;
    let original_value = bound_json(&original, true)?;
    ensure!(
        original_value["observer"] == serde_json::to_value(&observer)?
            && original_value["previous_fleet"] == serde_json::to_value(&p.previous_fleet)?
            && original_value["output"].as_str() == p.fleet_output.to_str(),
        "0516 original fleet provenance changed"
    );
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    absent(&p.fleet_output)?;
    absent(&p.cycle_directory.join("completion.json"))?;
    let root = p.cycle_directory.join("cohort191-native-event-recovery-v3");
    absent(&root)?;
    ensure!(
        sha(env::var("HORIZON_S3_ENDPOINT")?.as_bytes()) == p.endpoint_sha256,
        "0516 recovery endpoint differs"
    );
    if check {
        println!(
            "exact0516 native event recovery preflight passed; no new observation or status republication"
        );
        return Ok(());
    }
    let iid = authenticate_named_service(UNIT)?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    File::open(&p.cycle_directory)?.sync_all()?;
    let recovery = write_new(
        &root.join("intent.json"),
        &json!({"schema":"jetstreamer-cohort191-native-tail-recovery-v2","original_intent":intent,"failed_child":failed,"original_fleet_plan":original,"spec":spec,"observer":observer,"recovery_invocation_id":iid,"new_resource_samples":0,"replay_status_republications":0,"archive_mutations":false}),
    )?;
    cohort191_delivery::prepare(&effective, &observer)?;
    let mut corrected = original_value.clone();
    cohort191_delivery::derive_fleet(&effective, &mut corrected)?;
    correction(&original_value, &corrected)?;
    let mut provisional = corrected.clone();
    provisional["output"] = json!(p.cycle_directory.join("public198-provisional-fleet.json"));
    let package = delivery198::seal_values(
        p,
        "cohort191-native-event-recovery-plans",
        &[
            ("fleet-plan.json", corrected),
            ("provisional-plan.json", provisional),
            ("effective-plan.json", serde_json::to_value(&effective)?),
        ],
    )?;
    let effective_plan = file(package.join("effective-plan.json"), true)?;
    let fleet_plan = file(package.join("fleet-plan.json"), true)?;
    let provisional_plan = file(package.join("provisional-plan.json"), true)?;
    let pipeline = public198::publish_sealed(
        &effective,
        &observer,
        &provisional_plan,
        &root.join("child-provisional-fleet.json"),
    )?;
    let d144 = publication144::publish(&effective, &pipeline, &observer)?;
    let d160 = delivery160::publish(&effective, &pipeline, &observer)?;
    let d141 = qualification141_status::publish(&effective, &pipeline, &observer)?;
    let d191 = cohort191_delivery::publish(&effective, &pipeline, &observer)?;
    ensure!(
        d191["status_publications"]
            .as_array()
            .is_some_and(|rows| rows.len() == 4),
        "0516 native event status publication incomplete; preserve repair artifacts"
    );
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    child(
        cohort191_delivery::fleet_reader(&effective),
        &[
            "fleet-reconcile".into(),
            fleet_plan.path.display().to_string(),
            "--plan-sha256".into(),
            fleet_plan.sha256.clone(),
        ],
        true,
        &root.join("child-final-fleet.json"),
    )?;
    let fleet = file(p.fleet_output.clone(), false)?;
    let ledger = bound_json(&fleet, false)?;
    ensure!(
        ledger["observer_sha256"] == OBSERVER_SHA
            && ledger["plan_sha256"] == fleet_plan.sha256
            && ledger["sampled_at_utc"] == p.sample_target_utc
            && ledger["inventory"]["anomalies"] == 0,
        "0516 recovered fleet differs"
    );
    let capacity = capacity::decision(&effective, &bound_json(&observer, false)?, &ledger)?;
    let c = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","plan":pb,"self_sha256":self_sha,"sampled_at_utc":p.sample_target_utc,"observer":observer,"model":model,"estimates":estimates,"invocation_id":iid,"fleet_plan":fleet_plan,"fleet":fleet,"status_publications":statuses,"inventory":ledger["inventory"],"epoch198_delivery":pipeline,"epoch160_delivery":d160,"epoch144_delivery":d144,"qualification141_status":d141,"cohort191_delivery":d191,"capacity_decision":capacity,"cohort191_native_recovery":recovery,"cohort191_effective_plan":effective_plan,"new_resource_samples":0,"replay_status_republications":0,"archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false,"deletions":false});
    next_preparation::completion_bindings(p, pb, &c)?;
    public198::validate_completed(p, &c)?;
    delivery160::validate_completed(p, &c)?;
    publication144::validate_completed(p, &c)?;
    write_new(&root.join("completion.json"), &c)?;
    write_new(&p.cycle_directory.join("completion.json"), &c)?;
    Ok(())
}
pub(super) fn completed(p: &Plan, c: &Value) -> Result<bool> {
    if c["cohort191_native_recovery"].is_null() {
        return Ok(false);
    }
    ensure!(
        p.cycle_directory == Path::new(ROOT) && c["observer"]["sha256"] == OBSERVER_SHA,
        "0516 recovery completion foreign"
    );
    let intent: Bound = serde_json::from_value(c["cohort191_native_recovery"].clone())?;
    let proof = bound_json(&intent, false)?;
    ensure!(
        intent.path
            == p.cycle_directory
                .join("cohort191-native-event-recovery-v3/intent.json")
            && proof["schema"] == "jetstreamer-cohort191-native-tail-recovery-v2"
            && proof["failed_child"]["sha256"] == FAILED_SHA
            && proof["new_resource_samples"] == 0
            && proof["replay_status_republications"] == 0,
        "0516 recovery history changed"
    );
    let original: Bound = serde_json::from_value(proof["original_fleet_plan"].clone())?;
    let corrected: Bound = serde_json::from_value(c["fleet_plan"].clone())?;
    ensure!(
        original.path == p.cycle_directory.join("sealed/fleet-plan.json")
            && corrected.path
                == p.cycle_directory
                    .join("cohort191-native-event-recovery-plans/sealed/fleet-plan.json"),
        "0516 recovery fleet namespace changed"
    );
    correction(
        &bound_json(&original, true)?,
        &bound_json(&corrected, true)?,
    )?;
    Ok(true)
}
pub(super) fn successor(p: &Plan, c: &Value, next: &mut Plan) -> Result<()> {
    if !completed(p, c)? {
        return Ok(());
    }
    let binding: Bound = serde_json::from_value(c["cohort191_effective_plan"].clone())?;
    ensure!(
        binding.path
            == p.cycle_directory
                .join("cohort191-native-event-recovery-plans/sealed/effective-plan.json"),
        "0516 effective plan namespace changed"
    );
    let effective: Plan = serde_json::from_value(bound_json(&binding, true)?)?;
    next.cohort191_delivery = effective.cohort191_delivery;
    if let Some(profile) = &mut next.cohort191_delivery {
        profile.native_handoff_event = false;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn correction_preserves_every_other_owner_and_gate() {
        let original = json!({"gates":(190..=195).map(|e|(e.to_string(),json!({"state":"blocked-qualification"}))).collect::<BTreeMap<_,_>>(),"pipeline_claims":[{"epoch":190,"owner":"keep"}],"observer":"keep"});
        let mut changed = original.clone();
        for e in 191..=194 {
            changed["gates"][e.to_string()] = json!({"state":"post-replay-pipeline"});
            changed["pipeline_claims"]
                .as_array_mut()
                .unwrap()
                .push(json!({"epoch":e,"owner":"actualqueue"}));
        }
        correction(&original, &changed).unwrap();
        for key in ["observer", "gates"] {
            let mut bad = changed.clone();
            bad[key] = json!({});
            assert!(correction(&original, &bad).is_err());
        }
        changed["pipeline_claims"][0]["owner"] = json!("changed");
        assert!(correction(&original, &changed).is_err());
    }
}
