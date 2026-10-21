//! One exact private144 independent reread. Never a full epoch or replay claim.
use super::*;
use private157::{binding, file_binding, immutable_receipt};
mod completed;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch144-prefix-verification-launch-v1";
const UNIT: &str = "horizon-qualify-144-private-verification-20261021-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch144-retained-prefix-audit-20261021-v1";
const VERIFIER: &str = "/usr/local/lib/jetstreamer/horizon-epoch157-retained-prefix-validator-20261021-v1/jetstreamer-qualification-verify";
const SHA: &str = "b075d4548224cd3ca01f6f7bb441d835b7db4dd769136065d0b516fdeceac582";
const ARCHIVE: &str = "/home/sol/.jetstreamer-private/epoch144-upgradeable-loader-focus-20261016-v1/output/epoch-144-through-62639490.jet";
const ARCHIVE_SHA: &str = "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273";
const MANIFEST_SHA: &str = "691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a";
const PROTECTED: u64 = 4_740_696_923_590;
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 144 && c.unit == UNIT
}
pub(super) fn live_limits() -> Result<()> {
    private157::live_limits_for(UNIT, ROOT)
}
fn command() -> String {
    format!(
        "{{ path={VERIFIER} ; argv[]={VERIFIER} {ARCHIVE} --private-root=/home/sol/.jetstreamer-private/epoch144-upgradeable-loader-focus-20261016-v1 --expected-epoch=144 --expected-output-start-slot=62208000 --expected-bootstrap-slot=62207522 --expected-terminal-slot=62639490 --expected-runtime-profile=solana-v1.4.25 --expected-worker-sha256=2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8 --receipt={ROOT}/epoch-144-prefix.validation.json"
    )
}
fn denied(r: &Value) -> Result<()> {
    for flag in [
        "replay_entries_authorized",
        "full_epoch_verified",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(r[flag] == false, "144 prefix proof grants authority:{flag}");
    }
    Ok(())
}
fn planning(r: &Value) -> Result<()> {
    ensure!(
        r["schema"] == "jetstreamer-epoch144-retained-prefix-audit-planning-v1"
            && r["validator_sha256"] == SHA
            && r["archive"] == ARCHIVE
            && r["archive_sha256"] == ARCHIVE_SHA
            && r["manifest_sha256"] == MANIFEST_SHA
            && r["expected_output_start_slot"] == 62208000
            && r["expected_bootstrap_slot"] == 62207522
            && r["expected_terminal_slot"] == 62639490
            && r["output_slot_count"] == 431491,
        "144 prefix planning differs"
    );
    denied(r)?;
    let manifest = read_stable_bounded(
        &PathBuf::from(format!("{ARCHIVE}.segment.json")),
        16 << 10,
        "144 original prefix manifest",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest)) == MANIFEST_SHA,
        "144 original prefix manifest changed"
    );
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    ensure!(
        namespace(c)
            && r["schema"] == SCHEMA
            && r["epoch"] == 144
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && c.invocation_id.len() == 32
            && r["launched"] == true
            && c.scratch_path == Path::new(ROOT)
            && r["private_run_root"] == ROOT
            && r["verifier_sha256"] == SHA
            && r["archive_path"] == ARCHIVE
            && r["archive_sha256"] == ARCHIVE_SHA
            && r["manifest_sha256"] == MANIFEST_SHA
            && r["output_slot_start"] == 62208000
            && r["terminal_slot"] == 62639490
            && r["output_slot_count"] == 431491
            && r["expected_exec_start"]
                .as_str()
                .and_then(|s| s.split_once(" ; ignore_errors="))
                .is_some_and(|(s, _)| s == command())
            && r["maximum_memory_bytes"] == 8u64 << 30
            && r["maximum_cpu_percent"] == 400
            && r["maximum_new_disk_bytes"] == 1u64 << 20
            && r["maximum_runtime_seconds"] == 21600,
        "144 private prefix launch differs"
    );
    denied(r)
}
pub(super) fn admission(
    previous: &Value,
    p: &Plan,
    c: &DiagnosticClaim,
    r: &Value,
    proposal: &Value,
    now: u64,
) -> Result<()> {
    launch(r, c)?;
    planning(proposal)?;
    let sample = utc_seconds(previous["sampled_at_utc"].as_str().context("144 sample")?)?;
    let launched = r["recorded_unix_seconds"]
        .as_u64()
        .context("144 launch time")?;
    ensure!(
        p.first_epoch == 101
            && p.last_epoch == 200
            && sample <= launched
            && launched <= now
            && now - sample <= 1800
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= launched)
            && r["observer"] == binding(&p.observer)
            && r["previous_fleet"]
                == binding(p.previous_fleet.as_ref().context("144 prior fleet")?)
            && p.admission_transition_guard.as_ref() == Some(&c.launch_receipt)
            && r["protected_existing_floor_bytes"] == PROTECTED
            && !previous["active"]
                .as_array()
                .context("144 prior active")?
                .iter()
                .any(|a| a["epoch"] == 144),
        "144 admission lineage stale, foreign or overlapping"
    );
    private157::resources(&bound_json(&p.observer)?)?;
    let b: BoundFile = serde_json::from_value(r["admission_evidence"].clone())?;
    let a = bound_json(&b)?;
    ensure!(
        a["schema"] == "jetstreamer-private-prefix144-admission-v1"
            && a["decision"] == "pass"
            && a["observer"] == r["observer"]
            && a["previous_fleet"] == r["previous_fleet"]
            && a["protected_producers"] == r["protected_producers"]
            && a["protected_existing_floor_bytes"] == PROTECTED
            && a["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n >= sample && n <= launched)
            && a["replay_launch_authorized"] == false
            && a["publication_authorized"] == false
            && a["r2_mutations"] == false,
        "144 prefix has no bound prelaunch admission"
    );
    for (name, row) in previous["unit_census"]
        .as_object()
        .context("144 prior census")?
    {
        if name.starts_with("jetstreamer-root-sweep-") && row["ActiveState"] == "active" {
            ensure!(
                r["protected_producers"][name] == row["InvocationID"],
                "144 admission dropped older producer"
            );
        }
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    previous_fleet: BoundFile,
    original_plan: BoundFile,
    planning: BoundFile,
    launch: Option<BoundFile>,
    stage: PathBuf,
    destination: PathBuf,
    output: PathBuf,
}
fn protected(previous: &Value) -> Result<Value> {
    let names = protected_census_names(previous)?;
    let current = census(&names, 101, 200)?;
    let mut result = serde_json::Map::new();
    for (name, row) in &current {
        if name.starts_with("jetstreamer-root-sweep-") && row["ActiveState"] == "active" {
            let old = &previous["unit_census"][name];
            ensure!(
                old["ActiveState"] == "active"
                    && old["InvocationID"] == row["InvocationID"]
                    && row["NRestarts"] == "0",
                "144 old producer changed"
            );
            result.insert(name.clone(), row["InvocationID"].clone());
        }
    }
    for (name, row) in previous["unit_census"].as_object().unwrap() {
        if name.starts_with("jetstreamer-root-sweep-") && row["ActiveState"] == "active" {
            ensure!(
                result.get(name) == Some(&row["InvocationID"]),
                "144 old producer disappeared"
            );
        }
    }
    Ok(Value::Object(result))
}
fn protected_census_names(previous: &Value) -> Result<BTreeSet<String>> {
    let mut names: BTreeSet<String> = previous["unit_census"]
        .as_object()
        .context("144 old census")?
        .keys()
        .cloned()
        .collect();
    // The launch-capture census must explicitly name its own just-started,
    // exact verifier; otherwise generic census correctly rejects it as unbound.
    // Old claims remain in the set and every old producer is reauthenticated.
    names.insert(UNIT.into());
    Ok(names)
}
fn claim(r: &Value, b: &BoundFile) -> Result<DiagnosticClaim> {
    Ok(DiagnosticClaim {
        epoch: 144,
        unit: UNIT.into(),
        invocation_id: r["invocation_id"].as_str().context("144 IID")?.into(),
        scratch_path: ROOT.into(),
        launch_receipt: BoundFile {
            path: b.path.clone(),
            sha256: b.sha256.clone(),
        },
    })
}
pub(super) fn prepare() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 8
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0
            && matches!(
                args[7].as_str(),
                "--admit" | "--launch" | "--fleet" | "--routine-spec" | "--completed-proof"
            ),
        "usage: prepare-private-prefix144 SPEC --spec-sha256 HEX --self-sha256 HEX MODE"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(exe)?;
    ensure!(
        m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "144 preparer not sealed"
    );
    let s: Spec = serde_json::from_value(bound_json(&BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    })?)?;
    ensure!(s.schema=="jetstreamer-private-prefix144-preparation-spec-v1"
        && s.stage==Path::new("/var/lib/jetstreamer/horizon-prefix144-fleet-preparation-20261021-v1")
        && s.destination==Path::new("/usr/local/lib/jetstreamer/horizon-prefix144-admission-plan-20261021-v1")
        && s.output.parent()==Some(Path::new("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1"))
        && s.output.file_name().and_then(|n|n.to_str()).is_some_and(|n|n.starts_with("fleet-") && n.ends_with("-prefix144-admitted.json")),"144 preparation namespace differs");
    let previous = bound_json(&s.previous_fleet)?;
    let observer = bound_json(&s.observer)?;
    let proposal = bound_json(&s.planning)?;
    planning(&proposal)?;
    let mut plan = bound_json(&s.original_plan)?;
    ensure!(
        previous["schema"] == SCHEMA_FLEET
            && previous["first_epoch"] == 101
            && previous["last_epoch"] == 200
            && previous["plan"].as_str() == s.original_plan.path.to_str()
            && previous["plan_sha256"] == s.original_plan.sha256
            && previous["observer_sha256"] == s.observer.sha256
            && plan["observer"] == binding(&s.observer)
            && previous["admission_transition_guard"].is_null()
            && plan["admission_transition_guard"].is_null(),
        "144 inputs not accepted ordinary fleet"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sample = utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("144 sample time")?,
    )?;
    let admission_path = Path::new(ROOT).join("admission.json");
    if args[7] == "--admit" {
        ensure!(
            observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                && sample <= now
                && now - sample <= 1800
                && previous["sampled_at_utc"] == observer["recorded_at_utc"],
            "144 admission sample stale"
        );
        ensure!(
            !previous["active"]
                .as_array()
                .context("144 active")?
                .iter()
                .any(|r| r["epoch"] == 144),
            "144 active claim exists"
        );
        private157::resources(&observer)?;
        let protected = protected(&previous)?;
        let future = unit(UNIT)?;
        ensure!(
            matches!(future["ActiveState"].as_str(), Some("inactive" | "failed"))
                && future["MainPID"] == "0",
            "144 verifier already live"
        );
        immutable_receipt(
            &admission_path,
            &json!({"schema":"jetstreamer-private-prefix144-admission-v1","decision":"pass","recorded_unix_seconds":now,"observer":binding(&s.observer),"previous_fleet":binding(&s.previous_fleet),"planning":binding(&s.planning),"protected_producers":protected,"protected_existing_floor_bytes":PROTECTED,"maximum_new_disk_bytes":1u64<<20,"maximum_memory_bytes":8u64<<30,"maximum_cpu_percent":400,"new_resource_samples":0,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        )?;
        println!("{}", file_binding(&admission_path)?);
        return Ok(());
    }
    if args[7] == "--launch" {
        let ab: BoundFile = serde_json::from_value(file_binding(&admission_path)?)?;
        let a = bound_json(&ab)?;
        ensure!(
            a["schema"] == "jetstreamer-private-prefix144-admission-v1"
                && a["decision"] == "pass"
                && a["observer"] == binding(&s.observer)
                && a["previous_fleet"] == binding(&s.previous_fleet)
                && a["planning"] == binding(&s.planning)
                && a["recorded_unix_seconds"]
                    .as_u64()
                    .is_some_and(|n| n >= sample && n <= now && now - n <= 1800),
            "144 missing fresh admission"
        );
        ensure!(
            protected(&previous)? == a["protected_producers"],
            "144 older claims changed before capture"
        );
        let current = unit(UNIT)?;
        ensure!(
            current["ActiveState"] == "active"
                && current["SubState"] == "running"
                && current["NRestarts"] == "0"
                && current["MainPID"]
                    .as_str()
                    .is_some_and(|s| s.parse::<u32>().is_ok_and(|n| n > 0)),
            "144 verifier not newly live"
        );
        live_limits()?;
        let r = json!({"schema":SCHEMA,"epoch":144,"unit":UNIT,"invocation_id":current["InvocationID"],"launched":true,"recorded_unix_seconds":now,"private_run_root":ROOT,"expected_exec_start":current["ExecStart"],"verifier_sha256":SHA,"archive_path":ARCHIVE,"archive_sha256":ARCHIVE_SHA,"manifest_sha256":MANIFEST_SHA,"output_slot_start":62208000,"terminal_slot":62639490,"output_slot_count":431491,"plan":s.planning.path,"plan_sha256":s.planning.sha256,"observer":binding(&s.observer),"previous_fleet":binding(&s.previous_fleet),"admission_evidence":binding(&ab),"protected_producers":a["protected_producers"],"protected_existing_floor_bytes":PROTECTED,"maximum_memory_bytes":8u64<<30,"maximum_cpu_percent":400,"maximum_new_disk_bytes":1u64<<20,"maximum_runtime_seconds":21600,"replay_entries_authorized":false,"full_epoch_verified":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let b = BoundFile {
            path: Path::new(ROOT).join("launch.json"),
            sha256: "0".repeat(64),
        };
        launch(&r, &claim(&r, &b)?)?;
        ensure!(
            unit(UNIT)? == current,
            "144 verifier changed during capture"
        );
        immutable_receipt(&b.path, &r)?;
        println!("{}", file_binding(&b.path)?);
        return Ok(());
    }
    let lb = s.launch.as_ref().context("144 launch binding required")?;
    let r = bound_json(lb)?;
    let c = claim(&r, lb)?;
    launch(&r, &c)?;
    if args[7] == "--completed-proof" {
        return completed::capture(&s, lb, &r, &c);
    }
    let plan_path = s.destination.join("fleet-plan.json");
    if args[7] == "--routine-spec" {
        let event_binding: BoundFile = serde_json::from_value(file_binding(&s.output)?)?;
        let event = bound_json(&event_binding)?;
        let pb = file_binding(&plan_path)?;
        ensure!(
            event["plan"].as_str() == plan_path.to_str()
                && event["plan_sha256"] == pb["sha256"]
                && event["previous_fleet"] == binding(&s.previous_fleet)
                && event["observer_sha256"] == s.observer.sha256
                && event["admission_transition_guard"] == binding(lb),
            "144 event binding differs"
        );
        let path = s.stage.join("routine-spec.json");
        persist(
            &path,
            &json!({"schema":"jetstreamer-horizon-private-prefix144-routine-spec-v1","launch":binding(lb),"event_fleet":binding(&event_binding),"event_plan":pb,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        )?;
        println!("{}", file_binding(&path)?);
        return Ok(());
    }
    plan["previous_fleet"] = binding(&s.previous_fleet);
    plan["output"] = json!(s.output);
    plan["admission_transition_guard"] = binding(lb);
    let ds = plan["diagnostics"]
        .as_array_mut()
        .context("144 diagnostics")?;
    ensure!(
        !ds.iter().any(|d| d["epoch"] == 144),
        "144 duplicate diagnostic"
    );
    ds.push(json!({"epoch":144,"unit":UNIT,"invocation_id":c.invocation_id,"scratch_path":ROOT,"launch_receipt":binding(lb)}));
    let units = plan["tracked_units"]
        .as_array_mut()
        .context("144 tracked units")?;
    if !units.contains(&json!(UNIT)) {
        units.push(json!(UNIT));
    }
    ensure!(
        previous["epochs"]
            .as_array()
            .context("144 prior epochs")?
            .iter()
            .filter(|e| e["epoch"] == 144 && e["state"] == "blocked-qualification")
            .count()
            == 1,
        "144 prior repair gate differs"
    );
    plan["gates"]["144"]["state"] = json!("blocked-qualification");
    plan["gates"]["144"]["next_action"] = json!(
        "Complete private independent retained144 prefix reread; original diagnostic ended cleanly and stale status was conditionally removed. Preserve archive. Final509slots, restart/assembly, full epoch/plugin and R2 remain unqualified."
    );
    plan["gates"]["144"]["evidence"]
        .as_array_mut()
        .context("144 evidence")?
        .push(binding(lb));
    let typed: Plan = serde_json::from_value(plan.clone())?;
    validate_same_sample_admission(
        &previous,
        &typed,
        previous["sampled_at_utc"].as_str().context("144 sample")?,
        &r,
        &proposal,
        now,
    )?;
    let path = s.stage.join("fleet-plan.json");
    persist(&path, &plan)?;
    let pb = file_binding(&path)?;
    let seal = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":s.destination,"members":[{"source":path,"name":"fleet-plan.json","sha256":pb["sha256"],"mode":256}]});
    let path = s.stage.join("seal-plan.json");
    persist(&path, &seal)?;
    println!("{}", json!({"plan":pb,"seal_plan":file_binding(&path)?}));
    Ok(())
}
const SCHEMA_FLEET: &str = "jetstreamer-horizon-campaign-fleet-v1";

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 144,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: Path::new(ROOT).join("launch.json"),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"epoch":144,"unit":UNIT,"invocation_id":c.invocation_id,"launched":true,"private_run_root":ROOT,"expected_exec_start":format!("{} ; ignore_errors=no ; pid=123",command()),"verifier_sha256":SHA,"archive_path":ARCHIVE,"archive_sha256":ARCHIVE_SHA,"manifest_sha256":MANIFEST_SHA,"output_slot_start":62208000,"terminal_slot":62639490,"output_slot_count":431491,"maximum_memory_bytes":8u64<<30,"maximum_cpu_percent":400,"maximum_new_disk_bytes":1u64<<20,"maximum_runtime_seconds":21600,"untouched_consensus_integer":u64::MAX});
        for flag in [
            "replay_entries_authorized",
            "full_epoch_verified",
            "runtime_promotion_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[flag] = json!(false);
        }
        (c, r)
    }
    #[test]
    fn exact144_verifier_cannot_be_replay_full_epoch_or_another_owner() {
        let (c, r) = fixture();
        launch(&r, &c).unwrap();
        for key in [
            "epoch",
            "unit",
            "invocation_id",
            "private_run_root",
            "verifier_sha256",
            "archive_path",
            "archive_sha256",
            "manifest_sha256",
            "output_slot_start",
            "terminal_slot",
            "output_slot_count",
            "maximum_memory_bytes",
            "maximum_cpu_percent",
            "maximum_new_disk_bytes",
            "maximum_runtime_seconds",
            "expected_exec_start",
            "full_epoch_verified",
            "replay_entries_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            let mut bad = r.clone();
            bad[key] = json!("different");
            assert!(launch(&bad, &c).is_err(), "accepted{key}");
        }
        assert_eq!(r["untouched_consensus_integer"], u64::MAX);
        let mut wrong = c;
        wrong.epoch = 157;
        assert!(launch(&r, &wrong).is_err());
    }
    #[test]
    fn unchanged_old_growth_reserve_is_required_for_readonly144() {
        let mut o = json!({"filesystem":{"conservative_available_bytes":PROTECTED+(1u64<<20)},"host_memory":{"conservative_available_kib":136u64*1024*1024}});
        private157::resources(&o).unwrap();
        o["filesystem"]["conservative_available_bytes"] = json!(PROTECTED);
        assert!(private157::resources(&o).is_err());
    }
    #[test]
    fn capture_census_adds_only_its_exact_verifier_and_preserves_all_old_names() {
        let p = json!({"unit_census":{"old-producer.service":{},"old-diagnostic.service":{}}});
        assert_eq!(
            protected_census_names(&p).unwrap(),
            BTreeSet::from([
                "old-producer.service".into(),
                "old-diagnostic.service".into(),
                UNIT.into()
            ])
        );
    }
}
