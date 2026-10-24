//! Exact same-sample guarded verification event; writes a plan for native sealing.
use super::verification223 as c;
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    previous_fleet: BoundFile,
    original_plan: BoundFile,
    guard_sample: BoundFile,
    guard_plan: BoundFile,
    output: PathBuf,
    preparation_directory: PathBuf,
    deployment_directory: PathBuf,
}
fn delta(plan: &mut Value, s: &Spec, launch: &BoundFile, claim: &DiagnosticClaim) -> Result<()> {
    ensure!(
        plan["admission_transition_guard"].is_null(),
        "verification 223 cannot replace another pending admission"
    );
    let rows = plan["diagnostics"]
        .as_array_mut()
        .context("verification 223 preserved diagnostic history")?;
    ensure!(
        !rows.iter().any(|r| r["unit"] == c::UNIT),
        "verification 223 owner already recorded"
    );
    rows.push(json!({"epoch":223,"unit":claim.unit,"invocation_id":claim.invocation_id,"scratch_path":claim.scratch_path,
        "launch_receipt":private157::binding(launch)}));
    let units = plan["tracked_units"]
        .as_array_mut()
        .context("verification 223 tracked census")?;
    ensure!(
        !units.contains(&json!(c::UNIT)),
        "verification 223 already tracked"
    );
    units.push(json!(c::UNIT));
    plan["gates"]["223"]["evidence"]
        .as_array_mut()
        .context("verification 223 blocked repair gate")?
        .extend([
            private157::binding(launch),
            private157::binding(&s.guard_sample),
        ]);
    plan["previous_fleet"] = private157::binding(&s.previous_fleet);
    plan["output"] = json!(s.output);
    plan["admission_transition_guard"] = private157::binding(&s.guard_sample);
    Ok(())
}
fn owners(f: &Value) -> Result<BTreeMap<String, Value>> {
    let mut names = f["unit_census"]
        .as_object()
        .context("verification 223 whole owner census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c::UNIT.into());
    let current = census(&names, 201, 300)?;
    let mut old = current.clone();
    old.remove(c::UNIT);
    maintenance_capacity::current_owners(f, &old)?;
    Ok(current)
}
pub(super) fn run() -> Result<()> {
    let (sb, self_sha) = publication203::parsed_args("prepare-verification223-fleet")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&sb)?)?;
    ensure!(
        s.schema == "jetstreamer-private223-verification-fleet-spec-v1"
            && s.preparation_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && s.deployment_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-campaign-fleet-201-300-verification223-"))
            && [&s.output, &s.preparation_directory, &s.deployment_directory]
                .iter()
                .all(|p| p.is_absolute() && p.starts_with("/var/lib/jetstreamer"))
            && s.preparation_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-223-verification-fleet-preparation-"))
            && s.deployment_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-223-verification-fleet-plan-"))
            && s.output
                .file_name()
                .is_some_and(|n| n == "fleet-ledger.json"),
        "verification 223 preparation scope differs"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.previous_fleet)?;
    let mut p = bound_json(&s.original_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sampled = o["recorded_at_utc"]
        .as_str()
        .context("verification 223 observer timestamp")?;
    let t = utc_seconds(sampled)?;
    ensure!(
        t <= now
            && now - t <= 1800
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["sampled_at_utc"] == sampled
            && f["observer_sha256"] == s.observer.sha256
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && p["observer"] == private157::binding(&s.observer)
            && f["plan"].as_str() == s.original_plan.path.to_str()
            && f["plan_sha256"] == s.original_plan.sha256
            && f["admission_transition_guard"].is_null()
            && f["inventory"]["anomalies"] == 0
            && !f["active"]
                .as_array()
                .context("verification 223 active census")?
                .iter()
                .any(|r| r["epoch"] == 223),
        "verification 223 event lost accepted sample, original plan or source ownership"
    );
    let launch: BoundFile = serde_json::from_value(private157::file_binding(
        &Path::new(c::STATE).join("launch.json"),
    )?)?;
    let r = bound_json(&launch)?;
    let claim = DiagnosticClaim {
        epoch: 223,
        unit: c::UNIT.into(),
        invocation_id: r["invocation_id"]
            .as_str()
            .context("verification 223 actual iid")?
            .into(),
        scratch_path: r["private_directory"]
            .as_str()
            .context("verification 223 private root")?
            .into(),
        launch_receipt: launch,
    };
    c::launch(&r, &claim)?;
    ensure!(
        r["previous_fleet"] == private157::binding(&s.previous_fleet)
            && r["observer"] == private157::binding(&s.observer),
        "verification 223 launch predecessor differs"
    );
    let selected =
        warmup223::completed_guard_binding(c::GUARD_UNIT, Path::new(c::GUARD_RECEIPTS), t, now)?;
    ensure!(
        selected["binding"] == private157::binding(&s.guard_sample),
        "verification 223 guard is not the latest successful fire"
    );
    let timer = singleton227_capture::properties(
        &c::GUARD_UNIT.replace(".service", ".timer"),
        "ActiveState",
    )?;
    ensure!(
        timer.get("ActiveState").is_some_and(|s| s == "active"),
        "verification 223 protective timer is inactive"
    );
    let g = bound_json(&s.guard_sample)?;
    let gp = bound_json(&s.guard_plan)?;
    ensure!(
        c::guard_matches(&claim, &r, &gp),
        "verification 223 guard plan differs"
    );
    delta(&mut p, &s, &claim.launch_receipt, &claim)?;
    let typed: Plan = serde_json::from_value(p.clone())?;
    validate_same_sample_admission(&f, &typed, sampled, &g, &gp, now)?;
    let before = owners(&f)?;
    c::validate_live(&claim, &before[c::UNIT])?;
    let caps = c::live_limits(&claim.scratch_path)?;
    let after = owners(&f)?;
    ensure!(
        before == after && caps == c::live_limits(&claim.scratch_path)?,
        "verification 223 event owners/caps changed"
    );
    let source = s.preparation_directory.join("fleet-plan.json");
    persist(&source, &p)?;
    let b = private157::file_binding(&source)?;
    persist(
        &s.preparation_directory.join("seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1",
        "destination":s.deployment_directory,"members":[{"source":source,"name":"fleet-plan.json","sha256":b["sha256"],"mode":256}]}),
    )?;
    persist(
        &s.preparation_directory.join("preparation.json"),
        &json!({"schema":"jetstreamer-private223-verification-fleet-preparation-v1",
        "spec":private157::binding(&sb),"self_sha256":self_sha,"accepted_observer":private157::binding(&s.observer),
        "preserved_fleet":private157::binding(&s.previous_fleet),"launch":private157::binding(&claim.launch_receipt),
        "guard_sample":private157::binding(&s.guard_sample),"guard_plan":private157::binding(&s.guard_plan),
        "resource_samples_taken":0,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}
