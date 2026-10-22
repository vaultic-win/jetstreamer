//! Exact same-sample private144 fleet handoff, never a launcher or resource poll.
use super::*;
use continuation144::{SCHEMA, SCRATCH, UNIT};
use private157::{binding, file_binding};
const ROOT: &str = "/var/lib/jetstreamer/horizon-continuation144-fleet-preparation-20261022-v1";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-continuation144-fleet-plan-20261022-v1";
const LAUNCH: &str = "/var/lib/jetstreamer/horizon-continuation144-launch-20261022-v1/launch.json";
const GUARD_UNIT: &str = "horizon-continuation144-guard-20261022-v1.service";
const GUARD: &str = "/usr/local/lib/jetstreamer/horizon-standalone-guard-target-handoff-20261019-v2/jetstreamer-horizon-standalone-guard";
const GUARD_SHA: &str = "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194";

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
fn scope(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == "jetstreamer-continuation144-fleet-spec-v2"
            && s.output.parent()
                == Some(Path::new(
                    "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1"
                ))
            && s.output
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(
                    |s| s.starts_with("fleet-") && s.ends_with("-continuation144-admitted.json")
                ),
        "foreign private144 event scope"
    );
    Ok(())
}
fn owners(previous: &Value) -> Result<()> {
    let mut names: BTreeSet<_> = previous["unit_census"]
        .as_object()
        .context("previous census")?
        .keys()
        .cloned()
        .collect();
    names.insert(UNIT.into());
    let current = census(&names, 101, 200)?;
    snapshot144::check_owners(previous, &current)?;
    Ok(())
}
fn first_fire(gu: &Value, g: &Value, gp: &BoundFile, r: &Value, now: u64) -> Result<()> {
    first_fire_for(gu, g, gp, r, now, false)
}
pub(super) fn assembly_first_fire(
    gu: &Value,
    g: &Value,
    gp: &BoundFile,
    r: &Value,
    now: u64,
) -> Result<()> {
    ensure!(
        r["schema"] == assembly144::SCHEMA
            && r["unit"] == assembly144::UNIT
            && r["assembly_only_no_replay"] == true,
        "zero-worker first fire requires exact no-replay launch"
    );
    first_fire_for(gu, g, gp, r, now, true)
}
fn first_fire_for(
    gu: &Value,
    g: &Value,
    gp: &BoundFile,
    r: &Value,
    now: u64,
    assembly: bool,
) -> Result<()> {
    let expected = format!(
        "{{ path={GUARD} ; argv[]={GUARD} {} --plan-sha256 {} --self-sha256 {GUARD_SHA}",
        gp.path.display(),
        gp.sha256
    );
    ensure!(
        gu["Id"]
            == if assembly {
                assembly144_prepare::GUARD_UNIT
            } else {
                GUARD_UNIT
            }
            && gu["LoadState"] == "loaded"
            && gu["InvocationID"] == g["guard_invocation_id"]
            && gu["NRestarts"] == "0"
            && gu["MainPID"] == "0"
            && gu["Result"] == "success"
            && gu["ExecMainStatus"] == "0"
            && matches!(gu["ActiveState"].as_str(), Some("inactive" | "active"))
            && gu["ExecStart"]
                .as_str()
                .and_then(|s| s.split_once(" ; ignore_errors=").map(|(p, _)| p))
                == Some(expected.as_str())
            && g["plan_sha256"] == gp.sha256
            && g["guard_sha256"] == GUARD_SHA
            && g["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= now && now - n <= 120)
            && g["producer_invocation_id"] == r["invocation_id"]
            && g["trip_reason"].is_null()
            && g["worker_observation_error"].is_null()
            && g["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && g["workers"].as_array().is_some_and(|w| if assembly {
                w.is_empty()
            } else {
                w.len() == 1
                    && w[0][0].as_u64().is_some_and(|n| n > 0)
                    && w[0][1].as_u64().is_some_and(|n| n > 0 && n <= 3500000)
            }),
        "private144 requires actual clean exact-worker sandboxed first fire"
    );
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 8
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && matches!(args[7].as_str(), "--fleet" | "--routine-spec")
            && unsafe { libc::geteuid() } == 0,
        "usage: prepare-continuation144-fleet SPEC --spec-sha256 SHA --self-sha256 SHA MODE"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(&exe)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read(&exe)?)) == args[6],
        "unsealed private144 fleet preparer"
    );
    let s: Spec = serde_json::from_value(bound_json(&BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    })?)?;
    scope(&s)?;
    let previous = bound_json(&s.previous_fleet)?;
    let observer = bound_json(&s.observer)?;
    let mut plan = bound_json(&s.original_plan)?;
    let lb: BoundFile = serde_json::from_value(file_binding(Path::new(LAUNCH))?)?;
    let r = bound_json(&lb)?;
    let c = DiagnosticClaim {
        epoch: 144,
        unit: UNIT.into(),
        invocation_id: r["invocation_id"]
            .as_str()
            .context("private144 invocation")?
            .into(),
        scratch_path: SCRATCH.into(),
        launch_receipt: lb,
    };
    continuation144::launch(&r, &c)?;
    ensure!(
        r["schema"] == SCHEMA
            && previous["schema"] == super::SCHEMA
            && previous["first_epoch"] == 101
            && previous["last_epoch"] == 200
            && previous["plan"].as_str() == s.original_plan.path.to_str()
            && previous["plan_sha256"] == s.original_plan.sha256
            && previous["observer_sha256"] == s.observer.sha256
            && previous["sampled_at_utc"] == observer["recorded_at_utc"]
            && plan["observer"] == binding(&s.observer)
            && r["previous_fleet"] == binding(&s.previous_fleet)
            && r["observer"] == binding(&s.observer)
            && previous["admission_transition_guard"].is_null()
            && plan["admission_transition_guard"].is_null(),
        "private144 event predecessor differs"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sample = utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("observer time")?,
    )?;
    ensure!(
        sample <= now && now - sample <= 1800,
        "private144 event sample stale"
    );
    if args[7] == "--routine-spec" {
        let event: BoundFile = serde_json::from_value(file_binding(&s.output)?)?;
        let ev = bound_json(&event)?;
        let ep: BoundFile =
            serde_json::from_value(file_binding(&Path::new(DEST).join("fleet-plan.json"))?)?;
        ensure!(
            ev["plan"].as_str() == ep.path.to_str()
                && ev["plan_sha256"] == ep.sha256
                && ev["previous_fleet"] == binding(&s.previous_fleet)
                && ev["observer_sha256"] == s.observer.sha256
                && ev["admission_transition_guard"] == binding(&s.guard_sample),
            "private144 event not accepted"
        );
        persist(
            &Path::new(ROOT).join("routine-spec.json"),
            &json!({"schema":"jetstreamer-continuation144-routine-spec-v2",
            "launch":binding(&c.launch_receipt),"event_fleet":binding(&event),"event_plan":binding(&ep),
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        )?;
        return Ok(());
    }
    let guard = bound_json(&s.guard_sample)?;
    let guard_plan = bound_json(&s.guard_plan)?;
    first_fire(&unit(GUARD_UNIT)?, &guard, &s.guard_plan, &r, now)?;
    let limits=ProcessCommand::new("systemctl").args(["show",GUARD_UNIT,"--property=ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities"]).output()?;
    ensure!(
        limits.status.success(),
        "private144 guard sandbox unreadable"
    );
    let text = std::str::from_utf8(&limits.stdout)?;
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
            "private144 guard sandbox differs:{k}"
        );
    }
    owners(&previous)?;
    continuation144::validate_live(&c, &unit(UNIT)?)?;
    plan["previous_fleet"] = binding(&s.previous_fleet);
    plan["output"] = json!(s.output);
    plan["admission_transition_guard"] = binding(&s.guard_sample);
    let ds = plan["diagnostics"]
        .as_array_mut()
        .context("diagnostic history")?;
    ensure!(
        !ds.iter().any(|v| v["unit"] == UNIT),
        "duplicated private144 continuation history"
    );
    ds.push(json!({"epoch":144,"unit":UNIT,"invocation_id":c.invocation_id,"scratch_path":SCRATCH,"launch_receipt":binding(&c.launch_receipt)}));
    let names = plan["tracked_units"]
        .as_array_mut()
        .context("tracked units")?;
    if !names.contains(&json!(UNIT)) {
        names.push(json!(UNIT));
    }
    plan["gates"]["144"]["evidence"]
        .as_array_mut()
        .context("144 gate evidence")?
        .extend([binding(&c.launch_receipt), binding(&s.guard_sample)]);
    let typed: Plan = serde_json::from_value(plan.clone())?;
    validate_same_sample_admission(
        &previous,
        &typed,
        observer["recorded_at_utc"].as_str().unwrap(),
        &guard,
        &guard_plan,
        now,
    )?;
    let output = Path::new(ROOT).join("fleet-plan.json");
    persist(&output, &plan)?;
    let pb = file_binding(&output)?;
    persist(
        &Path::new(ROOT).join("seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,
        "members":[{"source":output,"name":"fleet-plan.json","sha256":pb["sha256"],"mode":256}]}),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_fire_rejects_workerless_native_budgets_or_unbound_services() {
        let p = BoundFile {
            path: "/guard.json".into(),
            sha256: "a".repeat(64),
        };
        let r = json!({"invocation_id":"b".repeat(32),"required_guard_minimum_free_bytes":4_500_000_000_000u64});
        let command = format!(
            "{{ path={GUARD} ; argv[]={GUARD} {} --plan-sha256 {} --self-sha256 {GUARD_SHA} ; ignore_errors=no }}",
            p.path.display(),
            p.sha256
        );
        let gu = json!({"Id":GUARD_UNIT,"LoadState":"loaded","InvocationID":"c".repeat(32),"NRestarts":"0","MainPID":"0",
            "Result":"success","ExecMainStatus":"0","ActiveState":"inactive","ExecStart":command});
        let g = json!({"plan_sha256":p.sha256,"guard_sha256":GUARD_SHA,"guard_invocation_id":"c".repeat(32),"recorded_unix_seconds":1000,
            "producer_invocation_id":r["invocation_id"],"trip_reason":null,"worker_observation_error":null,
            "minimum_free_bytes":r["required_guard_minimum_free_bytes"],"workers":[[123,400000]]});
        first_fire(&gu, &g, &p, &r, 1120).unwrap();
        assert!(first_fire(&gu, &g, &p, &r, 1121).is_err());
        let mut bad = g.clone();
        bad["workers"] = json!([]);
        assert!(first_fire(&gu, &bad, &p, &r, 1000).is_err());
        let mut bad = g.clone();
        bad["minimum_free_bytes"] = json!(3916063202758u64);
        assert!(first_fire(&gu, &bad, &p, &r, 1000).is_err());
        let mut bad = gu.clone();
        bad["InvocationID"] = json!("d".repeat(32));
        assert!(first_fire(&bad, &g, &p, &r, 1000).is_err());
        let mut ar = r.clone();
        ar["schema"] = json!(assembly144::SCHEMA);
        ar["unit"] = json!(assembly144::UNIT);
        ar["assembly_only_no_replay"] = json!(true);
        let mut ag = g.clone();
        ag["workers"] = json!([]);
        let mut au = gu.clone();
        au["Id"] = json!(assembly144_prepare::GUARD_UNIT);
        assembly_first_fire(&au, &ag, &p, &ar, 1000).unwrap();
        assert!(assembly_first_fire(&au, &g, &p, &ar, 1000).is_err());
        assert!(assembly_first_fire(&gu, &ag, &p, &ar, 1000).is_err());
        ar["unit"] = json!(UNIT);
        assert!(assembly_first_fire(&au, &ag, &p, &ar, 1000).is_err());
    }
}
