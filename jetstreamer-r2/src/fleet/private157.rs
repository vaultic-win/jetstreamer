//! One exact read-only retained-prefix verifier, never a full epoch gate.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch157-prefix-verification-launch-v1";
pub(super) const UNIT: &str = "horizon-qualify-157-private-verification-20261021-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch157-retained-prefix-audit-20261021-v1";
const VERIFIER: &str = "/usr/local/lib/jetstreamer/horizon-epoch157-retained-prefix-validator-20261021-v1/jetstreamer-qualification-verify";
const SHA: &str = "b075d4548224cd3ca01f6f7bb441d835b7db4dd769136065d0b516fdeceac582";
const ARCHIVE: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j/output/.epoch-157.jet.runtime-segments/epoch-157.segment-00-67824000-68140177.jet";
fn command() -> String {
    format!(
        "{{ path={VERIFIER} ; argv[]={VERIFIER} {ARCHIVE} --private-root=/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j/output/.epoch-157.jet.runtime-segments --expected-epoch=157 --expected-output-start-slot=67824000 --expected-bootstrap-slot=67823809 --expected-terminal-slot=68140176 --expected-runtime-profile=solana-v1.5.6 --expected-worker-sha256=cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819 --receipt={ROOT}/epoch-157-prefix.validation.json"
    )
}
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 157 && c.unit == UNIT
}
pub(super) fn live_limits() -> Result<()> {
    let out=ProcessCommand::new("/usr/bin/systemctl").args(["show",UNIT,"--no-pager","--property=Type,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,User,UMask"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "157verifier sandbox unreadable"
    );
    let mut limits = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("157limit field")?;
        ensure!(limits.insert(k, v).is_none(), "duplicate157limit");
    }
    validate_limits(&limits)
}
fn validate_limits(l: &BTreeMap<&str, &str>) -> Result<()> {
    for (k, v) in [
        ("Type", "exec"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "4294967296"),
        ("MemoryMax", "8589934592"),
        ("MemorySwapMax", "0"),
        ("RuntimeMaxUSec", "6h"),
        ("CPUQuotaPerSecUSec", "4s"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("ReadWritePaths", ROOT),
        ("User", "root"),
        ("UMask", "0077"),
    ] {
        ensure!(l.get(k) == Some(&v), "157verifier hard sandbox differs:{k}");
    }
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    ensure!(
        namespace(c)
            && r["schema"] == SCHEMA
            && r["epoch"] == 157
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && r["launched"] == true
            && c.invocation_id.len() == 32
            && c.scratch_path == Path::new(ROOT)
            && r["private_run_root"] == ROOT
            && r["verifier_sha256"] == SHA
            && r["archive_path"] == ARCHIVE
            && r["archive_sha256"]
                == "4a4d4403a4fe92bd24c8406cebb93eccbc614e8cb746dda9dcbf8b17eeeddadf"
            && r["manifest_sha256"]
                == "a1fff20066a4e7267a161912d3611ec98c2aa267865fe4f6d36a3f28a78ab528"
            && r["output_slot_start"] == 67824000
            && r["terminal_slot"] == 68140176
            && r["output_slot_count"] == 316177
            && r["expected_exec_start"]
                .as_str()
                .and_then(|s| s.split_once(" ; ignore_errors="))
                .is_some_and(|(s, _)| s == command())
            && r["plan"]
                == "/usr/local/lib/jetstreamer/horizon-epoch157-retained-prefix-validator-20261021-v1/prefix-audit-plan.json"
            && r["plan_sha256"]
                == "c4c6190e36addb38d5b14ff672378e336b0031f4d183ba8e599ed952ceebeec4"
            && r["maximum_memory_bytes"] == 8u64 << 30
            && r["maximum_cpu_percent"] == 400
            && r["maximum_new_disk_bytes"] == 1u64 << 20
            && r["maximum_runtime_seconds"] == 21600,
        "157prefix verifier launch scope/identity differs"
    );
    for flag in [
        "replay_entries_authorized",
        "full_epoch_verified",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(r[flag] == false, "157prefix launch grants authority:{flag}");
    }
    Ok(())
}
pub(super) fn admission(
    previous: &Value,
    p: &Plan,
    c: &DiagnosticClaim,
    r: &Value,
    planning: &Value,
    now: u64,
) -> Result<()> {
    launch(r, c)?;
    ensure!(
        p.first_epoch == 101
            && p.last_epoch == 200
            && planning["schema"] == "jetstreamer-epoch157-retained-prefix-audit-planning-v1"
            && planning["validator_sha256"] == SHA
            && planning["archive"] == ARCHIVE
            && planning["archive_sha256"] == r["archive_sha256"]
            && planning["expected_terminal_slot"] == 68140176
            && planning["replay_launch_authorized"] == false
            && planning["publication_authorized"] == false
            && r["observer"]["path"].as_str() == p.observer.path.to_str()
            && r["observer"]["sha256"] == p.observer.sha256
            && p.admission_transition_guard.as_ref() == Some(&c.launch_receipt)
            && r["previous_fleet"]["path"].as_str()
                == p.previous_fleet.as_ref().and_then(|b| b.path.to_str())
            && r["previous_fleet"]["sha256"].as_str()
                == p.previous_fleet.as_ref().map(|b| b.sha256.as_str()),
        "157verifier admission lineage differs"
    );
    let stamp = r["recorded_unix_seconds"]
        .as_u64()
        .context("157launch time missing")?;
    let sample = utc_seconds(
        previous["sampled_at_utc"]
            .as_str()
            .context("157sample time")?,
    )?;
    ensure!(
        stamp >= sample
            && stamp <= now
            && now - stamp <= 1800
            && now - sample <= 1800
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= stamp)
            && !previous["active"]
                .as_array()
                .context("157active census")?
                .iter()
                .any(|a| a["epoch"] == 157),
        "157admission stale or overlaps active work"
    );
    let observer = bound_json(&p.observer)?;
    resources(&observer)?;
    let protected = 4_740_696_923_590u64;
    ensure!(
        r["protected_existing_floor_bytes"] == protected,
        "157protected floor differs"
    );
    let ab: BoundFile = serde_json::from_value(r["admission_evidence"].clone())?;
    let a = bound_json(&ab)?;
    ensure!(
        a["schema"] == "jetstreamer-private-prefix157-admission-v1"
            && a["decision"] == "pass"
            && a["observer"] == r["observer"]
            && a["previous_fleet"] == r["previous_fleet"]
            && a["protected_producers"] == r["protected_producers"]
            && a["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n >= sample && n <= stamp)
            && a["replay_launch_authorized"] == false
            && a["publication_authorized"] == false
            && a["r2_mutations"] == false,
        "157verifier lacks real pre-launch admission"
    );
    for (name, before) in previous["unit_census"]
        .as_object()
        .context("157prior units")?
    {
        if name.starts_with("jetstreamer-root-sweep-") && before["ActiveState"] == "active" {
            ensure!(
                r["protected_producers"][name] == before["InvocationID"],
                "157admission dropped old producer:{name}"
            );
        }
    }
    Ok(())
}
fn resources(observer: &Value) -> Result<()> {
    let protected = 4_740_696_923_590u64;
    ensure!(
        observer["filesystem"]["conservative_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= protected + (1 << 20))
            && observer["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= (128 + 8) * 1024 * 1024),
        "157read-only verifier does not fit unchanged protected envelope"
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    schema: String,
    original_plan: BoundFile,
    previous_fleet: BoundFile,
    observer: BoundFile,
    launch: BoundFile,
    output: PathBuf,
    stage: PathBuf,
    destination: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionSpec {
    schema: String,
    observer: BoundFile,
    previous_fleet: BoundFile,
    planning: BoundFile,
    output: PathBuf,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
fn admit(value: Value) -> Result<()> {
    let s: AdmissionSpec = serde_json::from_value(value)?;
    ensure!(
        s.schema == "jetstreamer-private-prefix157-admission-spec-v1"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.r2_mutations
            && s.output == Path::new(ROOT).join("admission.json"),
        "foreign157admission spec"
    );
    let previous = bound_json(&s.previous_fleet)?;
    let observer = bound_json(&s.observer)?;
    let planning = bound_json(&s.planning)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sample = utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("157admission time")?,
    )?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && sample <= now
            && now - sample <= 1800
            && previous["schema"] == SCHEMA_FLEET
            && previous["first_epoch"] == 101
            && previous["last_epoch"] == 200
            && previous["observer_sha256"] == s.observer.sha256
            && previous["sampled_at_utc"] == observer["recorded_at_utc"]
            && planning["schema"] == "jetstreamer-epoch157-retained-prefix-audit-planning-v1"
            && planning["validator_sha256"] == SHA
            && planning["replay_launch_authorized"] == false
            && planning["publication_authorized"] == false,
        "157admission inputs stale or foreign"
    );
    resources(&observer)?;
    ensure!(
        !previous["active"]
            .as_array()
            .context("157active")?
            .iter()
            .any(|r| r["epoch"] == 157),
        "157already active"
    );
    let names = previous["unit_census"]
        .as_object()
        .context("157census")?
        .keys()
        .cloned()
        .collect();
    let current = census(&names, 101, 200)?;
    let mut protected = serde_json::Map::new();
    for (name, row) in &current {
        if name.starts_with("jetstreamer-root-sweep-") && row["ActiveState"] == "active" {
            let old = &previous["unit_census"][name];
            ensure!(
                old["ActiveState"] == "active"
                    && old["InvocationID"] == row["InvocationID"]
                    && row["NRestarts"] == "0",
                "157admission producer changed:{name}"
            );
            protected.insert(name.clone(), row["InvocationID"].clone());
        }
    }
    for (name, row) in previous["unit_census"].as_object().unwrap() {
        if name.starts_with("jetstreamer-root-sweep-") && row["ActiveState"] == "active" {
            ensure!(
                protected.get(name) == Some(&row["InvocationID"]),
                "157producer disappeared before admission"
            );
        }
    }
    let future = unit(UNIT)?;
    ensure!(
        matches!(future["ActiveState"].as_str(), Some("inactive" | "failed"))
            && future["MainPID"] == "0",
        "157verifier already running"
    );
    let record = json!({"schema":"jetstreamer-private-prefix157-admission-v1","decision":"pass","recorded_unix_seconds":now,
        "observer":binding(&s.observer),"previous_fleet":binding(&s.previous_fleet),"planning":binding(&s.planning),
        "protected_producers":protected,"protected_existing_floor_bytes":4740696923590u64,
        "maximum_new_disk_bytes":1u64<<20,"maximum_memory_bytes":8u64<<30,"maximum_cpu_percent":400,
        "new_resource_samples":0,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    persist(&s.output, &record)?;
    println!("{}", file_binding(&s.output)?);
    Ok(())
}
fn immutable_receipt(path: &Path, value: &Value) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = validate_output_destination(path)?;
    let mut t = tempfile::NamedTempFile::new_in(parent)?;
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(t.as_file_mut(), value)?;
    t.write_all(b"\n")?;
    t.as_file().sync_all()?;
    t.persist_noclobber(path)
        .map_err(|e| anyhow!("prefix157 receipt occupied:{e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn capture_launch(value: Value) -> Result<()> {
    let s: AdmissionSpec = serde_json::from_value(value)?;
    ensure!(
        s.schema == "jetstreamer-private-prefix157-admission-spec-v1"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.r2_mutations
            && s.output == Path::new(ROOT).join("admission.json"),
        "foreign157capture spec"
    );
    let a = bound_json(&BoundFile {
        path: s.output.clone(),
        sha256: file_binding(&s.output)?["sha256"].as_str().unwrap().into(),
    })?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        a["schema"] == "jetstreamer-private-prefix157-admission-v1"
            && a["decision"] == "pass"
            && a["observer"] == binding(&s.observer)
            && a["previous_fleet"] == binding(&s.previous_fleet)
            && a["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= now && now - n <= 1800),
        "157launch admission stale or foreign"
    );
    let current = unit(UNIT)?;
    ensure!(
        current["Id"] == UNIT
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["NRestarts"] == "0"
            && current["MainPID"]
                .as_str()
                .is_some_and(|p| p.parse::<u32>().is_ok_and(|n| n > 0)),
        "157verifier not newly live"
    );
    live_limits()?;
    let r = json!({"schema":SCHEMA,"epoch":157,"unit":UNIT,"invocation_id":current["InvocationID"],"launched":true,"recorded_unix_seconds":now,
        "private_run_root":ROOT,"expected_exec_start":current["ExecStart"],"verifier_sha256":SHA,"archive_path":ARCHIVE,
        "archive_sha256":"4a4d4403a4fe92bd24c8406cebb93eccbc614e8cb746dda9dcbf8b17eeeddadf","manifest_sha256":"a1fff20066a4e7267a161912d3611ec98c2aa267865fe4f6d36a3f28a78ab528",
        "output_slot_start":67824000,"terminal_slot":68140176,"output_slot_count":316177,
        "plan":"/usr/local/lib/jetstreamer/horizon-epoch157-retained-prefix-validator-20261021-v1/prefix-audit-plan.json","plan_sha256":"c4c6190e36addb38d5b14ff672378e336b0031f4d183ba8e599ed952ceebeec4",
        "observer":binding(&s.observer),"previous_fleet":binding(&s.previous_fleet),"admission_evidence":file_binding(&s.output)?,"protected_producers":a["protected_producers"],"protected_existing_floor_bytes":4740696923590u64,
        "maximum_memory_bytes":8u64<<30,"maximum_cpu_percent":400,"maximum_new_disk_bytes":1u64<<20,"maximum_runtime_seconds":21600,
        "replay_entries_authorized":false,"full_epoch_verified":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let c = DiagnosticClaim {
        epoch: 157,
        unit: UNIT.into(),
        invocation_id: current["InvocationID"]
            .as_str()
            .context("157capture IID")?
            .into(),
        scratch_path: ROOT.into(),
        launch_receipt: BoundFile {
            path: Path::new(ROOT).join("launch.json"),
            sha256: "0".repeat(64),
        },
    };
    launch(&r, &c)?;
    ensure!(unit(UNIT)? == current, "157verifier changed during capture");
    let path = Path::new(ROOT).join("launch.json");
    immutable_receipt(&path, &r)?;
    println!("{}", file_binding(&path)?);
    Ok(())
}
const SCHEMA_FLEET: &str = "jetstreamer-horizon-campaign-fleet-v1";
fn binding(b: &BoundFile) -> Value {
    json!({"path":b.path,"sha256":b.sha256})
}
fn file_binding(path: &Path) -> Result<Value> {
    Ok(
        json!({"path":path,"sha256":hex_lower(&Sha256::digest(read_stable_bounded(path,16<<20,"prefix157 prepared file")?))}),
    )
}
pub(super) fn prepare() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        (a.len() == 7
            || (a.len() == 8
                && matches!(a[7].as_str(), "--routine-spec" | "--admit" | "--launch")))
            && a[3] == "--spec-sha256"
            && a[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: prepare-private-prefix157 SPEC --spec-sha256 HEX --self-sha256 HEX [--routine-spec]"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let em = fs::symlink_metadata(&exe)?;
    ensure!(
        em.uid() == 0
            && em.nlink() == 1
            && em.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == a[6],
        "unsealed prefix157 preparer"
    );
    let input = BoundFile {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    if a.get(7).is_some_and(|s| s == "--admit") {
        return admit(bound_json(&input)?);
    }
    if a.get(7).is_some_and(|s| s == "--launch") {
        return capture_launch(bound_json(&input)?);
    }
    let s: Preparation = serde_json::from_value(bound_json(&input)?)?;
    ensure!(s.schema=="jetstreamer-private-prefix157-fleet-preparation-v1"
        && s.stage==Path::new("/var/lib/jetstreamer/horizon-prefix157-fleet-preparation-20261021-v1")
        && s.destination==Path::new("/usr/local/lib/jetstreamer/horizon-prefix157-admission-plan-20261021-v1")
        && s.output.parent()==Some(Path::new("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1"))
        && s.output.file_name().and_then(|n|n.to_str()).is_some_and(|n|n.starts_with("fleet-") && n.ends_with("-prefix157-admitted.json")),"foreign prefix157 preparation scope");
    let sm = fs::symlink_metadata(&s.stage)?;
    ensure!(
        s.stage.canonicalize()? == s.stage
            && sm.is_dir()
            && sm.uid() == 0
            && sm.mode() & 0o077 == 0,
        "unsafe prefix157 preparation directory"
    );
    let previous = bound_json(&s.previous_fleet)?;
    let r = bound_json(&s.launch)?;
    let original = bound_json(&s.original_plan)?;
    ensure!(
        previous["plan"].as_str() == s.original_plan.path.to_str()
            && previous["plan_sha256"] == s.original_plan.sha256
            && previous["observer_sha256"] == s.observer.sha256
            && original["observer"] == binding(&s.observer)
            && previous["admission_transition_guard"].is_null()
            && original["admission_transition_guard"].is_null(),
        "prefix157 preparation does not consume accepted fullfleet"
    );
    let plan_path = s.destination.join("fleet-plan.json");
    if a.len() == 8 {
        let event = bound_json(&BoundFile {
            path: s.output.clone(),
            sha256: file_binding(&s.output)?["sha256"].as_str().unwrap().into(),
        })?;
        let pb = file_binding(&plan_path)?;
        ensure!(
            event["plan"].as_str() == plan_path.to_str()
                && event["plan_sha256"] == pb["sha256"]
                && event["previous_fleet"] == binding(&s.previous_fleet)
                && event["observer_sha256"] == s.observer.sha256
                && event["admission_transition_guard"] == binding(&s.launch),
            "prefix157 event proof differs"
        );
        let spec = json!({"schema":"jetstreamer-horizon-private-prefix157-routine-spec-v1","launch":binding(&s.launch),
            "event_fleet":file_binding(&s.output)?,"event_plan":pb,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
        let path = s.stage.join("routine-spec.json");
        persist(&path, &spec)?;
        println!("{}", file_binding(&path)?);
        return Ok(());
    }
    let c = DiagnosticClaim {
        epoch: 157,
        unit: UNIT.into(),
        invocation_id: r["invocation_id"].as_str().context("157launch IID")?.into(),
        scratch_path: ROOT.into(),
        launch_receipt: BoundFile {
            path: s.launch.path.clone(),
            sha256: s.launch.sha256.clone(),
        },
    };
    launch(&r, &c)?;
    let mut plan = original;
    plan["previous_fleet"] = binding(&s.previous_fleet);
    plan["output"] = json!(s.output);
    plan["admission_transition_guard"] = binding(&s.launch);
    let ds = plan["diagnostics"]
        .as_array_mut()
        .context("157prior diagnostics")?;
    ensure!(
        !ds.iter().any(|d| d["epoch"] == 157),
        "157already has diagnostic owner"
    );
    ds.push(json!({"epoch":157,"unit":UNIT,"invocation_id":c.invocation_id,"scratch_path":ROOT,"launch_receipt":binding(&s.launch)}));
    let units = plan["tracked_units"]
        .as_array_mut()
        .context("157tracked units")?;
    if !units.contains(&json!(UNIT)) {
        units.push(json!(UNIT));
    }
    reconcile_blocked_gate(&mut plan, &previous)?;
    let gate = &mut plan["gates"]["157"];
    gate["state"] = json!("blocked-qualification");
    gate["next_action"] = json!(
        "Complete private independent retained-prefix reread under exact157 verifier; preserve source and snapshot. Full epoch, native v1.5.8 restart, remaining suffix/assembly and publication are not yet qualified."
    );
    gate["evidence"]
        .as_array_mut()
        .context("157gate evidence")?
        .push(binding(&s.launch));
    let typed: Plan = serde_json::from_value(plan.clone())?;
    let planning = bound_json(&BoundFile {
        path: r["plan"].as_str().context("157planning path")?.into(),
        sha256: r["plan_sha256"].as_str().context("157planning SHA")?.into(),
    })?;
    validate_same_sample_admission(
        &previous,
        &typed,
        previous["sampled_at_utc"].as_str().context("157sample")?,
        &r,
        &planning,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let source = s.stage.join("fleet-plan.json");
    persist(&source, &plan)?;
    let b = file_binding(&source)?;
    let seal = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":s.destination,
        "members":[{"source":source,"name":"fleet-plan.json","sha256":b["sha256"],"mode":256}]});
    let seal_path = s.stage.join("seal-plan.json");
    persist(&seal_path, &seal)?;
    println!(
        "{}",
        json!({"plan":b,"seal_plan":file_binding(&seal_path)?,"resource_samples":0,"service_mutations":false,"r2_mutations":false})
    );
    Ok(())
}
fn reconcile_blocked_gate(plan: &mut Value, previous: &Value) -> Result<()> {
    ensure!(
        previous["epochs"]
            .as_array()
            .context("157prior epochs")?
            .iter()
            .filter(|e| e["epoch"] == 157
                && matches!(
                    e["state"].as_str(),
                    Some("blocked-qualification" | "failed-needs-repair")
                ))
            .count()
            == 1
            && previous["runtime_handoff157"]["live"] == false
            && previous["runtime_handoff157"]["ordinary_replay_restored"] == false
            && previous["runtime_handoff157"]["evidence"] == plan["runtime_handoff157"]
            && plan["runtime_handoff157"]["sha256"]
                == "7551fdeafd0c5773dfb52a1b0df8b867f09e1dc1b2939569568bf5ede99789c2"
            && matches!(
                plan["gates"]["157"]["state"].as_str(),
                Some(
                    "not-yet-staged"
                        | "staged-admissible"
                        | "blocked-qualification"
                        | "failed-needs-repair"
                )
            ),
        "157computed inactive repair is not bound to the original paused owner"
    );
    // Templates describe base gates; the complete reader derives live/terminal
    // ownership separately. Fold the accepted computed repair, never the old
    // template's not-yet-staged placeholder, into this private verifier gate.
    plan["gates"]["157"]["state"] = json!("blocked-qualification");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 157,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: "/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let r = json!({"schema":SCHEMA,"epoch":157,"unit":UNIT,"invocation_id":c.invocation_id,"launched":true,
            "private_run_root":ROOT,"verifier_sha256":SHA,"archive_path":ARCHIVE,"archive_sha256":"4a4d4403a4fe92bd24c8406cebb93eccbc614e8cb746dda9dcbf8b17eeeddadf",
            "manifest_sha256":"a1fff20066a4e7267a161912d3611ec98c2aa267865fe4f6d36a3f28a78ab528","output_slot_start":67824000,"terminal_slot":68140176,"output_slot_count":316177,
            "expected_exec_start":format!("{} ; ignore_errors=no ; start_time=[fixture]",command()),
            "plan":"/usr/local/lib/jetstreamer/horizon-epoch157-retained-prefix-validator-20261021-v1/prefix-audit-plan.json","plan_sha256":"c4c6190e36addb38d5b14ff672378e336b0031f4d183ba8e599ed952ceebeec4",
            "maximum_memory_bytes":8u64<<30,"maximum_cpu_percent":400,"maximum_new_disk_bytes":1u64<<20,"maximum_runtime_seconds":21600,
            "replay_entries_authorized":false,"full_epoch_verified":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        (c, r)
    }
    #[test]
    fn private_prefix_never_borrows_full_epoch_or_other_invocation() {
        let (c, r) = fixture();
        launch(&r, &c).unwrap();
        for (key, v) in [
            ("full_epoch_verified", json!(true)),
            ("terminal_slot", json!(68255999)),
            ("archive_path", json!("/other")),
            ("invocation_id", json!("f".repeat(32))),
            ("maximum_memory_bytes", json!(16u64 << 30)),
        ] {
            let mut bad = r.clone();
            bad[key] = v;
            assert!(launch(&bad, &c).is_err(), "accepted{key}");
        }
    }
    #[test]
    fn no_extra_writable_path_or_unbounded_runtime_is_allowed() {
        let mut l = BTreeMap::from([
            ("Type", "exec"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryHigh", "4294967296"),
            ("MemoryMax", "8589934592"),
            ("MemorySwapMax", "0"),
            ("RuntimeMaxUSec", "6h"),
            ("CPUQuotaPerSecUSec", "4s"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("ReadWritePaths", ROOT),
            ("User", "root"),
            ("UMask", "0077"),
        ]);
        validate_limits(&l).unwrap();
        l.insert("ReadWritePaths", "/home/sol");
        assert!(validate_limits(&l).is_err());
        l.insert("ReadWritePaths", ROOT);
        l.insert("RuntimeMaxUSec", "infinity");
        assert!(validate_limits(&l).is_err());
    }
    #[test]
    fn readonly_admission_preserves_protected_disk_and_memory_exactly() {
        let mut o = json!({"filesystem":{"conservative_available_bytes":4740696923590u64+(1<<20)},"host_memory":{"conservative_available_kib":(128+8)*1024*1024u64}});
        resources(&o).unwrap();
        o["filesystem"]["conservative_available_bytes"] = json!(4740696923590u64 + (1 << 20) - 1);
        assert!(resources(&o).is_err());
        o["filesystem"]["conservative_available_bytes"] = json!(4740696923590u64 + (1 << 20));
        o["host_memory"]["conservative_available_kib"] = json!((128 + 8) * 1024 * 1024u64 - 1);
        assert!(resources(&o).is_err());
    }
    #[test]
    fn accepted_computed_failure_can_replace_only_its_bound_placeholder_gate() {
        let proof = json!({"path":"/pause.json","sha256":"7551fdeafd0c5773dfb52a1b0df8b867f09e1dc1b2939569568bf5ede99789c2"});
        let mut plan = json!({"runtime_handoff157":proof,"gates":{"157":{"state":"not-yet-staged"},"140":{"keep":u64::MAX}}});
        let previous = json!({"epochs":[{"epoch":157,"state":"blocked-qualification"}],"runtime_handoff157":{"live":false,"ordinary_replay_restored":false,"evidence":proof}});
        reconcile_blocked_gate(&mut plan, &previous).unwrap();
        assert_eq!(plan["gates"]["157"]["state"], "blocked-qualification");
        assert_eq!(plan["gates"]["140"]["keep"], u64::MAX);
        let mut bad = previous.clone();
        bad["runtime_handoff157"]["live"] = json!(true);
        assert!(reconcile_blocked_gate(&mut plan, &bad).is_err());
        let mut bad = previous;
        bad["epochs"][0]["state"] = json!("remote-ready");
        assert!(reconcile_blocked_gate(&mut plan, &bad).is_err());
    }
}
