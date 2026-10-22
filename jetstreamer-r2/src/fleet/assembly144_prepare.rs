//! Append-only same-sample assembly owner event. No launch/resource poll/R2 writes.
use super::*;
use private157::{binding, file_binding};
pub(super) const GUARD_UNIT: &str = "horizon-assembly144-guard-20261022-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-assembly144-fleet-preparation-20261022-v1";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-assembly144-fleet-plan-20261022-v1";
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
}
fn delta(plan: &mut Value, s: &Spec, launch: &BoundFile, claim: &DiagnosticClaim) -> Result<()> {
    ensure!(
        plan["admission_transition_guard"].is_null(),
        "assembly event cannot replace another admission"
    );
    let rows = plan["diagnostics"]
        .as_array_mut()
        .context("assembly diagnostic history")?;
    ensure!(
        rows.iter()
            .filter(|r| r["unit"] == continuation144::UNIT
                && r["invocation_id"] == "8fddd3ef045c4fe5b12c7d25f43a4b73")
            .count()
            == 1
            && !rows.iter().any(|r| r["unit"] == assembly144::UNIT),
        "assembly lost original/duplicated recovery history"
    );
    rows.push(
        json!({"epoch":144,"unit":claim.unit,"invocation_id":claim.invocation_id,
        "scratch_path":claim.scratch_path,"launch_receipt":binding(launch)}),
    );
    let tracked = plan["tracked_units"]
        .as_array_mut()
        .context("assembly tracked census")?;
    ensure!(
        !tracked.contains(&json!(assembly144::UNIT)),
        "assembly unexpectedly already tracked"
    );
    tracked.push(json!(assembly144::UNIT));
    plan["gates"]["144"]["evidence"]
        .as_array_mut()
        .context("assembly144 gate")?
        .extend([binding(launch), binding(&s.guard_sample)]);
    plan["previous_fleet"] = binding(&s.previous_fleet);
    plan["output"] = json!(s.output);
    plan["admission_transition_guard"] = binding(&s.guard_sample);
    Ok(())
}
fn guard_sandbox() -> Result<()> {
    let out = ProcessCommand::new("systemctl").args(["show",GUARD_UNIT,
        "--property=ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "assembly guard sandbox unreadable"
    );
    let text = std::str::from_utf8(&out.stdout)?;
    let fields: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
    for (k, v) in [
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", "cap_dac_override cap_sys_ptrace"),
        ("AmbientCapabilities", "cap_dac_override cap_sys_ptrace"),
    ] {
        ensure!(
            fields.get(k) == Some(&v),
            "assembly guard sandbox differs:{k}"
        );
    }
    Ok(())
}
fn owners(previous: &Value) -> Result<BTreeMap<String, Value>> {
    let mut names: BTreeSet<_> = previous["unit_census"]
        .as_object()
        .context("previous census")?
        .keys()
        .cloned()
        .collect();
    names.insert(assembly144::UNIT.into());
    let current = census(&names, 101, 200)?;
    // Only this separately authenticated new assembler may be absent from the
    // prior census. Original timeout and every older owner remain protected.
    let mut older = current.clone();
    older.remove(assembly144::UNIT);
    assembly144_admission::timeout_properties()?;
    assembly144_admission::protected_owners(previous, &older)?;
    Ok(current)
}
pub(super) fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 8
            && a[3] == "--spec-sha256"
            && a[5] == "--self-sha256"
            && matches!(a[7].as_str(), "--fleet" | "--routine-spec"),
        "usage: prepare-assembly-only144-fleet SPEC --spec-sha256 SHA --self-sha256 SHA MODE"
    );
    continuation144::sealed_self(&a[6])?;
    let sm = fs::symlink_metadata(&a[2])?;
    ensure!(
        sm.is_file() && sm.uid() == 0 && sm.nlink() == 1 && sm.mode() & 0o222 == 0,
        "unsealed assembly fleet spec"
    );
    let s: Spec = serde_json::from_value(bound_json(&BoundFile {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    })?)?;
    ensure!(
        s.schema == "jetstreamer-assembly144-fleet-spec-v1"
            && s.output.parent()
                == Some(Path::new(
                    "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1"
                ))
            && s.output
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("fleet-")
                    && s.ends_with("-assembly144-admitted.json")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))),
        "foreign assembly fleet event scope"
    );
    let previous = bound_json(&s.previous_fleet)?;
    let observer = bound_json(&s.observer)?;
    let mut plan = bound_json(&s.original_plan)?;
    let lb: BoundFile = serde_json::from_value(file_binding(
        &Path::new(assembly144::STATE).join("launch.json"),
    )?)?;
    let r = bound_json(&lb)?;
    let c = DiagnosticClaim {
        epoch: 144,
        unit: assembly144::UNIT.into(),
        invocation_id: r["invocation_id"].as_str().context("assembly iid")?.into(),
        scratch_path: assembly144::ROOT.into(),
        launch_receipt: lb,
    };
    assembly144::launch(&r, &c)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sample = utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("assembly observer time")?,
    )?;
    ensure!(
        sample <= now
            && now - sample <= 1800
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && previous["schema"] == SCHEMA
            && previous["first_epoch"] == 101
            && previous["last_epoch"] == 200
            && previous["observer_sha256"] == s.observer.sha256
            && previous["sampled_at_utc"] == observer["recorded_at_utc"]
            && previous["plan"].as_str() == s.original_plan.path.to_str()
            && previous["plan_sha256"] == s.original_plan.sha256
            && plan["observer"] == binding(&s.observer)
            && previous["admission_transition_guard"].is_null()
            && r["observer"] == binding(&s.observer)
            && r["previous_fleet"] == binding(&s.previous_fleet),
        "assembly event stale/foreign predecessor"
    );
    let guard = bound_json(&s.guard_sample)?;
    let gp = bound_json(&s.guard_plan)?;
    delta(&mut plan, &s, &c.launch_receipt, &c)?;
    let typed: Plan = serde_json::from_value(plan.clone())?;
    validate_same_sample_admission(
        &previous,
        &typed,
        observer["recorded_at_utc"].as_str().unwrap(),
        &guard,
        &gp,
        now,
    )?;
    if a[7] == "--routine-spec" {
        let event: BoundFile = serde_json::from_value(file_binding(&s.output)?)?;
        let ep: BoundFile =
            serde_json::from_value(file_binding(&Path::new(DEST).join("fleet-plan.json"))?)?;
        let e = bound_json(&event)?;
        ensure!(
            bound_json(&ep)? == plan
                && e["previous_fleet"] == binding(&s.previous_fleet)
                && e["observer_sha256"] == s.observer.sha256
                && e["plan"].as_str() == ep.path.to_str()
                && e["plan_sha256"] == ep.sha256
                && e["admission_transition_guard"] == binding(&s.guard_sample)
                && e["inventory"]["anomalies"] == 0,
            "assembly event not accepted"
        );
        persist(
            &Path::new(ROOT).join("routine-spec.json"),
            &json!({"schema":"jetstreamer-assembly144-routine-spec-v1",
            "launch":binding(&c.launch_receipt),"event_fleet":binding(&event),"event_plan":binding(&ep),
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        )?;
        return Ok(());
    }
    continuation144_prepare::assembly_first_fire(
        &unit(GUARD_UNIT)?,
        &guard,
        &s.guard_plan,
        &r,
        now,
    )?;
    guard_sandbox()?;
    let before = owners(&previous)?;
    assembly144::validate_live(&c, &before[&c.unit])?;
    let after = owners(&previous)?;
    ensure!(
        before[&c.unit] == after[&c.unit],
        "assembly owner changed during event preparation"
    );
    let source = Path::new(ROOT).join("fleet-plan.json");
    persist(&source, &plan)?;
    let b = file_binding(&source)?;
    persist(
        &Path::new(ROOT).join("seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,
        "members":[{"source":source,"name":"fleet-plan.json","sha256":b["sha256"],"mode":256}]}),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_delta_is_append_only_and_preserves_original_u64_history() {
        let b = || BoundFile {
            path: "/evidence".into(),
            sha256: "a".repeat(64),
        };
        let s = Spec {
            schema: "jetstreamer-assembly144-fleet-spec-v1".into(),
            observer: b(),
            previous_fleet: b(),
            original_plan: b(),
            guard_sample: b(),
            guard_plan: b(),
            output: "/fleet".into(),
        };
        let c = DiagnosticClaim {
            epoch: 144,
            unit: assembly144::UNIT.into(),
            invocation_id: "b".repeat(32),
            scratch_path: assembly144::ROOT.into(),
            launch_receipt: b(),
        };
        let mut p = json!({"diagnostics":[{"epoch":144,"unit":continuation144::UNIT,"invocation_id":"8fddd3ef045c4fe5b12c7d25f43a4b73","counter":u64::MAX}],
            "tracked_units":[continuation144::UNIT],"gates":{"144":{"state":"blocked-qualification","next_action":"keep","evidence":[]}},
            "pipelines":{"counter":u64::MAX-1},"admission_transition_guard":null});
        let old = p.clone();
        delta(&mut p, &s, &c.launch_receipt, &c).unwrap();
        assert_eq!(p["diagnostics"][0], old["diagnostics"][0]);
        assert_eq!(p["pipelines"], old["pipelines"]);
        assert_eq!(p["gates"]["144"]["state"], old["gates"]["144"]["state"]);
        assert_eq!(p["gates"]["144"]["next_action"], "keep");
        assert!(delta(&mut p, &s, &c.launch_receipt, &c).is_err());
    }
}
