//! Capture only the exact admitted native probe and its real guard transition.
use super::*;
use private157::{binding, file_binding, immutable_receipt};
const ROOT: &str = "/var/lib/jetstreamer/horizon-native144-fleet-preparation-20261021-v1";
const LAUNCH: &str = "/var/lib/jetstreamer/horizon-epoch144-native-restore-20261021-v1/launch.json";
const DESTINATION: &str = "/usr/local/lib/jetstreamer/horizon-native144-admission-plan-20261021-v1";
const GUARD: &str = "/usr/local/lib/jetstreamer/horizon-standalone-guard-target-handoff-20261019-v2/jetstreamer-horizon-standalone-guard";
const GUARD_SHA: &str = "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194";
const GUARD_DESTINATION: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch144-native-guard-20261021-v1";
const GUARD_RECEIPTS: &str = "/var/lib/jetstreamer/horizon-epoch144-native-guard-20261021-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    previous_fleet: BoundFile,
    original_plan: BoundFile,
    native_plan: BoundFile,
    admission: BoundFile,
    guard_sample: Option<BoundFile>,
    guard_plan: Option<BoundFile>,
    output: PathBuf,
}
fn scope(s: &Spec) -> Result<()> {
    ensure!(s.schema == "jetstreamer-native144-fleet-preparation-spec-v1"
        && s.native_plan.path == Path::new(PLAN)
        && s.output.parent() == Some(Path::new("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1"))
        && s.output.file_name().and_then(|n|n.to_str()).is_some_and(|n| n.starts_with("fleet-") && n.ends_with("-native144-admitted.json")),
        "foreign native 144 preparation scope");
    Ok(())
}
fn claim(r: &Value, b: &BoundFile) -> Result<DiagnosticClaim> {
    Ok(DiagnosticClaim {
        epoch: 144,
        unit: UNIT.into(),
        invocation_id: r["invocation_id"]
            .as_str()
            .context("native 144 invocation")?
            .into(),
        scratch_path: SCRATCH.into(),
        launch_receipt: BoundFile {
            path: b.path.clone(),
            sha256: b.sha256.clone(),
        },
    })
}
fn owners(previous: &Value) -> Result<Value> {
    let mut names: BTreeSet<_> = previous["unit_census"]
        .as_object()
        .context("native 144 census")?
        .keys()
        .cloned()
        .collect();
    names.insert(UNIT.into());
    let current = census(&names, 101, 200)?;
    snapshot144::check_owners(previous, &current)?;
    Ok(serde_json::to_value(current)?)
}
fn guard_first_fire(current: &Value, sample: &Value, plan: &BoundFile, now: u64) -> Result<()> {
    let name = format!("{}-guard.service", UNIT.trim_end_matches(".service"));
    let command = format!(
        "{{ path={GUARD} ; argv[]={GUARD} {} --plan-sha256 {} --self-sha256 {GUARD_SHA}",
        plan.path.display(),
        plan.sha256
    );
    ensure!(
        sample["plan_sha256"] == plan.sha256
            && sample["guard_sha256"] == GUARD_SHA
            && sample["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 120)
            && current["Id"] == name
            && current["LoadState"] == "loaded"
            && current["InvocationID"]
                .as_str()
                .is_some_and(|id| id.len() == 32
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && current["InvocationID"] == sample["guard_invocation_id"]
            && current["NRestarts"] == "0"
            && current["MainPID"] == "0"
            && current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && ((current["ActiveState"] == "inactive" && current["SubState"] == "dead")
                || (current["ActiveState"] == "active" && current["SubState"] == "exited"))
            && command_part(&current["ExecStart"]) == Some(command.as_str())
            && current["ExecStart"]
                .as_str()
                .is_some_and(|s| s.contains(" ; ignore_errors=no ;")),
        "native 144 requires exact fresh successful guard first fire"
    );
    Ok(())
}
fn guard_sandbox(limits: &str) -> Result<()> {
    let mut fields = BTreeMap::new();
    for line in limits.lines() {
        let (key, value) = line
            .split_once('=')
            .context("native 144 guard sandbox field")?;
        ensure!(
            fields.insert(key, value).is_none(),
            "duplicate guard sandbox field"
        );
    }
    for (key, value) in [
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", "cap_dac_override cap_sys_ptrace"),
        ("AmbientCapabilities", "cap_dac_override cap_sys_ptrace"),
    ] {
        ensure!(
            fields.get(key) == Some(&value),
            "native 144 guard sandbox differs:{key}"
        );
    }
    Ok(())
}
fn guard_configuration(iid: &str) -> Result<Value> {
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "native 144 guard requires exact invocation"
    );
    Ok(
        json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1",
        "unit":UNIT,"invocation_id":iid,"filesystem":"/home/sol",
        "minimum_free_bytes":4740696923590u64,"worker_root":SCRATCH,
        "maximum_worker_vmas":3500000,"receipt_directory":GUARD_RECEIPTS,"bounded_measurement":null}),
    )
}
pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 8
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && matches!(args[7].as_str(), "--capture" | "--fleet" | "--routine-spec")
            && unsafe { libc::geteuid() } == 0,
        "usage: prepare-native144 SPEC --spec-sha256 HEX --self-sha256 HEX MODE"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(&exe)?;
    ensure!(
        m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read(&exe)?)) == args[6],
        "native 144 preparer must be sealed"
    );
    let s: Spec = serde_json::from_value(bound_json(&BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    })?)?;
    scope(&s)?;
    let previous = bound_json(&s.previous_fleet)?;
    let observer = bound_json(&s.observer)?;
    let mut plan = bound_json(&s.original_plan)?;
    let native = bound_json(&s.native_plan)?;
    let admission = bound_json(&s.admission)?;
    ensure!(
        previous["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && previous["first_epoch"] == 101
            && previous["last_epoch"] == 200
            && previous["plan"].as_str() == s.original_plan.path.to_str()
            && previous["plan_sha256"] == s.original_plan.sha256
            && previous["observer_sha256"] == s.observer.sha256
            && plan["observer"] == binding(&s.observer)
            && previous["sampled_at_utc"] == observer["recorded_at_utc"]
            && previous["admission_transition_guard"].is_null()
            && plan["admission_transition_guard"].is_null()
            && native["schema"] == "jetstreamer-private-epoch144-native-restore-probe-plan-v2"
            && native["admission_receipt"] == binding(&s.admission)
            && native["inputs"]["sha256"] == INPUTS_SHA
            && admission["schema"] == "jetstreamer-epoch144-native-admission-receipt-v2"
            && admission["admitted"] == true
            && admission["restore_only"] == true
            && admission["observer"] == binding(&s.observer)
            && admission["fleet"] == binding(&s.previous_fleet),
        "native 144 preparation does not bind admitted canonical predecessor"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sample = utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("native 144 sample")?,
    )?;
    ensure!(
        sample <= now && now - sample <= 1800,
        "native 144 fleet transition sample stale"
    );
    if args[7] == "--capture" {
        ensure!(
            admission["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= now && now - n <= 900)
                && !previous["active"]
                    .as_array()
                    .context("native 144 active census")?
                    .iter()
                    .any(|r| r["epoch"] == 144),
            "native 144 admission stale or overlapping"
        );
        let protected = owners(&previous)?;
        let current = unit(UNIT)?;
        ensure!(
            current["ActiveState"] == "active"
                && current["SubState"] == "running"
                && current["NRestarts"] == "0"
                && current["MainPID"]
                    .as_str()
                    .is_some_and(|p| p.parse::<u32>().is_ok_and(|n| n > 0)),
            "native 144 not newly live"
        );
        live_limits(UNIT)?;
        let r = json!({"schema":SCHEMA,"epoch":144,"unit":UNIT,"invocation_id":current["InvocationID"],"launched":true,"recorded_unix_seconds":now,
            "native_probe_sha256":PROBE_SHA,"input_policy_sha256":INPUTS_SHA,"worker_sha256":"2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8",
            "snapshot_sha256":"f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae","snapshot_slot":62639490,
            "maximum_runtime_seconds":1800,"maximum_memory_bytes":64u64<<30,"maximum_cpu_percent":400,"experimental_envelope_bytes":40u64<<30,
            "protected_existing_floor_bytes":4740696923590u64,"native_plan":binding(&s.native_plan),"admission":binding(&s.admission),
            "observer":binding(&s.observer),"previous_fleet":binding(&s.previous_fleet),"expected_exec_start":current["ExecStart"],"protected_unit_census":protected,
            "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"full_epoch_verified":false,"local_retirement_authorized":false,
            "replay_entries_authorized":false,"suffix_execution_authorized":false,"assembly_authorized":false,"canonical_sidecar_authorized":false,
            "runtime_promotion_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let b = BoundFile {
            path: LAUNCH.into(),
            sha256: "0".repeat(64),
        };
        launch(&r, &claim(&r, &b)?)?;
        ensure!(unit(UNIT)? == current, "native 144 changed during capture");
        owners(&previous)?;
        immutable_receipt(Path::new(LAUNCH), &r)?;
        // Emit the invocation-bound guard configuration in the same observed
        // capture, avoiding a manual identity transcription while the short
        // restore is starting. Deployment and actual sandbox first fire remain
        // independent mandatory gates; this writes no service or timer.
        let guard_source = Path::new(ROOT).join("guard-plan.json");
        persist(
            &guard_source,
            &guard_configuration(
                r["invocation_id"]
                    .as_str()
                    .context("native 144 capture invocation")?,
            )?,
        )?;
        let guard_binding = file_binding(&guard_source)?;
        persist(
            &Path::new(ROOT).join("guard-seal-plan.json"),
            &json!({
            "schema":"jetstreamer-sealed-deployment-plan-v1","destination":GUARD_DESTINATION,
            "members":[{"source":guard_source,"name":"guard-plan.json","sha256":guard_binding["sha256"],"mode":256}]}),
        )?;
        println!("{}", file_binding(Path::new(LAUNCH))?);
        return Ok(());
    }
    let lb: BoundFile = serde_json::from_value(file_binding(Path::new(LAUNCH))?)?;
    let r = bound_json(&lb)?;
    let c = claim(&r, &lb)?;
    launch(&r, &c)?;
    if args[7] == "--routine-spec" {
        let event: BoundFile = serde_json::from_value(file_binding(&s.output)?)?;
        let value = bound_json(&event)?;
        let pb = file_binding(&Path::new(DESTINATION).join("fleet-plan.json"))?;
        ensure!(
            value["previous_fleet"] == binding(&s.previous_fleet)
                && value["observer_sha256"] == s.observer.sha256
                && value["plan"] == pb["path"]
                && value["plan_sha256"] == pb["sha256"]
                && value["admission_transition_guard"]
                    == binding(s.guard_sample.as_ref().context("native 144 guard")?),
            "native 144 event differs"
        );
        let output = Path::new(ROOT).join("routine-spec.json");
        persist(
            &output,
            &json!({"schema":"jetstreamer-horizon-native144-routine-spec-v1","launch":binding(&lb),"event_fleet":binding(&event),"event_plan":pb,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        )?;
        println!("{}", file_binding(&output)?);
        return Ok(());
    }
    let gb = s
        .guard_sample
        .as_ref()
        .context("native 144 requires actual guard first fire")?;
    let gp = s.guard_plan.as_ref().context("native 144 guard plan")?;
    let guard = bound_json(gb)?;
    let guard_plan = bound_json(gp)?;
    let guard_unit = format!("{}-guard.service", UNIT.trim_end_matches(".service"));
    let gu = unit(&guard_unit)?;
    guard_first_fire(&gu, &guard, gp, now)?;
    let limits = ProcessCommand::new("systemctl").args(["show",&guard_unit,"--property=ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities"]).output()?;
    ensure!(
        limits.status.success(),
        "native 144 guard sandbox unreadable"
    );
    guard_sandbox(std::str::from_utf8(&limits.stdout)?)?;
    owners(&previous)?;
    validate_live(&c, &unit(UNIT)?)?;
    plan["previous_fleet"] = binding(&s.previous_fleet);
    plan["output"] = json!(s.output);
    plan["admission_transition_guard"] = binding(gb);
    let ds = plan["diagnostics"]
        .as_array_mut()
        .context("native 144 diagnostic history")?;
    ensure!(
        !ds.iter().any(|d| d["unit"] == UNIT),
        "duplicate native 144 diagnostic"
    );
    ds.push(json!({"epoch":144,"unit":UNIT,"invocation_id":c.invocation_id,"scratch_path":SCRATCH,"launch_receipt":binding(&lb)}));
    let units = plan["tracked_units"]
        .as_array_mut()
        .context("native 144 tracked units")?;
    if !units.contains(&json!(UNIT)) {
        units.push(json!(UNIT));
    }
    plan["gates"]["144"]["evidence"]
        .as_array_mut()
        .context("native 144 gate evidence")?
        .extend([binding(&lb), binding(gb)]);
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
    let seal = Path::new(ROOT).join("seal-plan.json");
    persist(
        &seal,
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DESTINATION,"members":[{"source":output,"name":"fleet-plan.json","sha256":pb["sha256"],"mode":256}]}),
    )?;
    println!("{}", file_binding(&seal)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_guard_protects_older_claims_and_has_no_canary_or_replay_authority() {
        let iid = "b".repeat(32);
        let p = guard_configuration(&iid).unwrap();
        assert_eq!(p["unit"], UNIT);
        assert_eq!(p["invocation_id"], iid);
        assert_eq!(p["worker_root"], SCRATCH);
        assert_eq!(p["minimum_free_bytes"], 4740696923590u64);
        assert_eq!(p["maximum_worker_vmas"], 3500000);
        assert_eq!(p["receipt_directory"], GUARD_RECEIPTS);
        assert!(p.get("bounded_canary").is_none());
        assert!(p["bounded_measurement"].is_null());
        assert!(guard_configuration("wrong").is_err());
        assert!(guard_configuration(&"G".repeat(32)).is_err());
    }

    fn bound(path: &str) -> BoundFile {
        BoundFile {
            path: path.into(),
            sha256: "a".repeat(64),
        }
    }

    #[test]
    fn preparation_is_restricted_to_exact_private_native144_scope() {
        let mut s = Spec {
            schema: "jetstreamer-native144-fleet-preparation-spec-v1".into(),
            observer: bound("/observer"), previous_fleet: bound("/fleet"),
            original_plan: bound("/plan"), native_plan: bound(PLAN), admission: bound("/admission"),
            guard_sample: None, guard_plan: None,
            output: "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-test-native144-admitted.json".into(),
        };
        scope(&s).unwrap();
        s.native_plan.path = "/foreign/plan.json".into();
        assert!(scope(&s).is_err());
        s.native_plan.path = PLAN.into();
        for output in [
            "/tmp/fleet-test-native144-admitted.json",
            "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-test.json",
        ] {
            s.output = output.into();
            assert!(scope(&s).is_err(), "{output}");
        }
    }

    #[test]
    fn first_fire_binds_exact_guard_command_invocation_plan_and_time() {
        let plan = bound("/usr/local/lib/jetstreamer/native144-test/guard-plan.json");
        let sample = json!({"guard_invocation_id":"b".repeat(32),"guard_sha256":GUARD_SHA,
            "recorded_unix_seconds":1000,"plan_sha256":plan.sha256});
        let current = json!({"Id":format!("{}-guard.service", UNIT.trim_end_matches(".service")),
            "LoadState":"loaded","InvocationID":"b".repeat(32),"NRestarts":"0", "MainPID":"0",
            "Result":"success","ExecMainStatus":"0","ActiveState":"inactive","SubState":"dead",
            "ExecStart":format!("{{ path={GUARD} ; argv[]={GUARD} {} --plan-sha256 {} --self-sha256 {GUARD_SHA} ; ignore_errors=no ; start_time=[n/a] }}",plan.path.display(),plan.sha256)});
        guard_first_fire(&current, &sample, &plan, 1120).unwrap();
        assert!(guard_first_fire(&current, &sample, &plan, 1121).is_err());
        assert!(guard_first_fire(&current, &sample, &plan, 999).is_err());
        for (key, value) in [
            ("Id", json!("other-guard.service")),
            ("LoadState", json!("not-found")),
            ("InvocationID", json!("c".repeat(32))),
            ("MainPID", json!("42")),
            ("NRestarts", json!("1")),
            ("Result", json!("exit-code")),
            ("ExecMainStatus", json!("1")),
            ("ActiveState", json!("failed")),
            ("SubState", json!("running")),
            ("ExecStart", json!("/bin/true")),
        ] {
            let mut bad = current.clone();
            bad[key] = value;
            assert!(
                guard_first_fire(&bad, &sample, &plan, 1000).is_err(),
                "{key}"
            );
        }
        for needle in [GUARD_SHA, &plan.sha256, "ignore_errors=no"] {
            let mut bad = current.clone();
            bad["ExecStart"] = json!(
                current["ExecStart"]
                    .as_str()
                    .unwrap()
                    .replace(needle, "wrong")
            );
            assert!(
                guard_first_fire(&bad, &sample, &plan, 1000).is_err(),
                "{needle}"
            );
        }
        for key in ["plan_sha256", "guard_sha256", "guard_invocation_id"] {
            let mut bad = sample.clone();
            bad[key] = json!("c".repeat(64));
            assert!(
                guard_first_fire(&current, &bad, &plan, 1000).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn first_fire_requires_least_privilege_sandbox_without_duplicate_properties() {
        let limits = "ProtectSystem=strict\nProtectHome=read-only\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=cap_dac_override cap_sys_ptrace\nAmbientCapabilities=cap_dac_override cap_sys_ptrace\n";
        guard_sandbox(limits).unwrap();
        for line in limits.lines() {
            assert!(guard_sandbox(&limits.replace(line, "")).is_err(), "{line}");
            assert!(
                guard_sandbox(&format!("{limits}{line}\n")).is_err(),
                "{line}"
            );
        }
        assert!(guard_sandbox(&limits.replace("cap_sys_ptrace", "cap_sys_admin")).is_err());
    }
}
