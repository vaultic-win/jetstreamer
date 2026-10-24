//! Capture an actually started, freshly admitted and guarded canary. Never launch it.
use super::canary227 as c;
use super::singleton227_capture::{journal, properties, require};
use super::*;
const OUTPUT: &str = "/var/lib/jetstreamer/horizon-227-v1625-canary-capture-v1/launch.json";
const UNIT_FILE: &str =
    "/etc/systemd/system/horizon-qualify-227-v1625-bounded-resource-d01adb19-v1.service";
const PROTECTIVE: &str = "horizon-canary227-v1625-protective-v1.service";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    fresh_resource_admission: BoundFile,
    input_capability: BoundFile,
    guard: BoundFile,
    guard_plan: BoundFile,
    resource_plan: BoundFile,
    resource_proposal: BoundFile,
    unit_file: BoundFile,
    output: PathBuf,
}
fn sandbox(p: &BTreeMap<String, String>, command: &str) -> Result<()> {
    // systemd stores the decimal caps rounded down to whole pages.
    require(
        p,
        &[
            ("Type", "exec"),
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryHigh", "149999996928"),
            ("MemoryMax", "224999997440"),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("TasksMax", "512"),
            ("RuntimeMaxUSec", "6h"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("PrivateNetwork", "no"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            ("ReadWritePaths", c::ROOT),
            ("Transient", "no"),
            ("FragmentPath", UNIT_FILE),
            ("RemainAfterExit", "no"),
            ("Result", "success"),
            ("NRestarts", "0"),
            ("ActiveState", "active"),
            ("SubState", "running"),
        ],
    )?;
    ensure!(
        c::same_command(
            &json!(p.get("ExecStart").context("227 command absent")?),
            &json!(command)
        ),
        "227 sandbox command differs"
    );
    Ok(())
}
fn protection(
    a: &Value,
    g: &Value,
    p: &Value,
    r: &Value,
    claim: &DiagnosticClaim,
    now: u64,
) -> Result<()> {
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("227 admission clock")?;
    let guarded = g["recorded_unix_seconds"]
        .as_u64()
        .context("227 guard clock")?;
    ensure!(
        a["schema"] == "jetstreamer-private-epoch227-v1625-canary-admission-v1"
            && a["admitted"] == true
            && a["epoch"] == 227
            && a["mode"] == "bounded-canary"
            && a["unit"] == c::UNIT
            && a["private_run_root"] == c::ROOT
            && a["candidate_incremental_peak_bytes"] == c::CANDIDATE
            && a["maximum_scratch_bytes"] == c::SCRATCH
            && a["maximum_memory_bytes"] == c::MEMORY
            && a["canary_plan"] == r["resource_plan"]
            && a["input_capability"] == r["input_capability"]
            && a["resource_proposal"] == r["resource_proposal"]
            && a["fresh_complete_census_passed"] == true
            && a["older_producers_and_guards_preserved"] == true
            && a["all_immutable_inputs_rehashed"] == true
            && a["producer_started"] == false
            && a["resource_samples_taken"] == 0
            && a["bounded_replay_resource_admitted"] == true
            && a["protected_existing_floor_bytes"] == r["guard_minimum_free_bytes"]
            && a["required_initial_free_bytes"] == r["required_initial_free_bytes"]
            && guarded >= admitted
            && guarded - admitted <= 900
            && guarded <= now
            && now - admitted <= 900
            && c::guard_matches(claim, r, p)
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == c::GUARD_SHA
            && g["producer_invocation_id"] == claim.invocation_id
            && g["producer"]["invocation_id"] == claim.invocation_id
            && g["producer"]["cgroup"] == format!("/system.slice/{}", c::UNIT)
            && g["producer"]["pid"].as_u64().is_some_and(|n| n > 1)
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer_stop_enabled"] == true
            && g["bounded_canary"] == p["bounded_canary"]
            && g["bounded_measurement"] == false
            && g.get("native_main").is_some_and(Value::is_null)
            && g.get("target_handoff_error").is_some_and(Value::is_null)
            && g["maximum_worker_vmas"] == 3_500_000
            && g["maximum_root_physical_bytes"] == c::SCRATCH
            && g["root_physical_observation"]["maximum_physical_bytes"] == c::SCRATCH
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= c::SCRATCH)
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(p["minimum_free_bytes"].as_u64())
                .is_some_and(|(x, y)| x >= y)
            && g["workers"].as_array().is_some_and(|v| v.len() == 1)
            && g["workers"][0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 3_500_000)
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "227 canary admission/actual guard identity or budget differs"
    );
    native227_v1625::no_authority(a)
}
fn manager(g: &Value, plan: &BoundFile, now: u64) -> Result<Value> {
    let p=properties(PROTECTIVE,"Type,User,Restart,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec,ExecStart,Result,ExecMainStatus,ActiveState,SubState")?;
    require(
        &p,
        &[
            ("Type", "oneshot"),
            ("User", "root"),
            ("Restart", "no"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("MemoryMax", "1073741824"),
            ("TasksMax", "256"),
            ("CPUQuotaPerSecUSec", "1s"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
        ],
    )?;
    let gp = bound_json(plan)?;
    ensure!(
        p.get("ReadWritePaths").map(String::as_str) == gp["receipt_directory"].as_str(),
        "227 guard write scope differs"
    );
    let command = format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {}",
        c::GUARD,
        c::GUARD,
        plan.path.display(),
        plan.sha256,
        c::GUARD_SHA
    );
    ensure!(
        c::same_command(
            &json!(p["ExecStart"]),
            &json!(format!("{command} ; ignore_errors=no }}"))
        ),
        "227 guard command differs"
    );
    let timer = properties(
        &PROTECTIVE.replace(".service", ".timer"),
        "ActiveState,SubState",
    )?;
    require(
        &timer,
        &[("ActiveState", "active"), ("SubState", "waiting")],
    )?;
    let (rows, sha) = journal(PROTECTIVE)?;
    let successful = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == PROTECTIVE
                && r["INVOCATION_ID"] == g["guard_invocation_id"]
                && r["MESSAGE"] == format!("{PROTECTIVE}: Deactivated successfully.")
        })
        .collect::<Vec<_>>();
    ensure!(successful.len() == 1, "227 exact guard PID1 success absent");
    let completed = warmup223::completed_guard_binding(
        PROTECTIVE,
        Path::new(
            gp["receipt_directory"]
                .as_str()
                .context("227 guard receipts")?,
        ),
        g["recorded_unix_seconds"]
            .as_u64()
            .context("227 guard clock")?,
        now,
    )?;
    ensure!(
        bound_json(&serde_json::from_value(completed["binding"].clone())?)? == *g,
        "227 latest completed guard differs"
    );
    Ok(
        json!({"properties":p,"timer":timer,"manager_completion":successful[0],"journal_sha256":sha,"completed_guard":completed}),
    )
}
fn peers(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    native210_peer_history::current(f, current)?;
    prefix223_live_peer::current(f, current)?;
    let mut protected = current.clone();
    protected.remove(c::UNIT);
    singleton227_admission::owners(f, &protected)
}
fn bindings(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == "jetstreamer-private-epoch227-v1625-canary-capture-spec-v1"
            && s.output == Path::new(OUTPUT)
            && s.unit_file.path == Path::new(UNIT_FILE),
        "227 capture destination/unit differs"
    );
    native209_admission::sealed_file(&s.unit_file.path, &s.unit_file.sha256, None)?;
    let m = fs::symlink_metadata(&s.unit_file.path)?;
    ensure!(m.mode() & 0o7777 == 0o444, "227 unit must be root0444");
    for b in [
        &s.resource_plan,
        &s.resource_proposal,
        &s.input_capability,
        &s.fresh_resource_admission,
        &s.guard_plan,
    ] {
        bound_json(b)?;
    }
    Ok(())
}
fn launch(s: &Spec, a: &Value, u: &Value, now: u64) -> Result<(DiagnosticClaim, Value)> {
    let iid = u["InvocationID"].as_str().context("227 actual IID")?;
    let pid = u["MainPID"]
        .as_str()
        .context("227 actual PID")?
        .parse::<u64>()?;
    ensure!(pid > 1, "227 missing actual PID");
    let claim = DiagnosticClaim {
        epoch: 227,
        unit: c::UNIT.into(),
        invocation_id: iid.into(),
        scratch_path: c::ROOT.into(),
        launch_receipt: BoundFile {
            path: s.output.clone(),
            sha256: "0".repeat(64),
        },
    };
    let mut r = json!({"schema":c::SCHEMA,"epoch":227,"unit":c::UNIT,"private_run_root":c::ROOT,"launched":true,
        "invocation_id":iid,"main_pid":pid,"recorded_unix_seconds":now,"sampled_at_utc":publication203::utc(now)?,
        "node_sha256":c::NODE_SHA,"worker_sha256":c::WORKER_SHA,"runner_sha256":c::RUNNER_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,
        "original_failed_invocation_id":c::ORIGINAL_IID,"preserve_original_failed227_history":true,"repair_gate_state":"failed-needs-repair",
        "fresh_complete_resource_admission_passed":true,"input_capability_passed":true,"native_input_qualified":true,
        "runtime":"solana-v1.6.25","runtime_revision":"7de8a55b54d3e11058b82f9483bb405d143b455c",
        "snapshot_slot":c::BOOTSTRAP,"snapshot_accounts_hash":c::ACCOUNTS,"worker_entry_start":c::BOOTSTRAP+1,
        "worker_entry_end_exclusive":c::TARGET+1,"output_slot_start":98_064_000u64,"target_slot":c::TARGET,
        "terminal_root_slot":c::TERMINAL,"canonical_checkpoint_slots":[c::BOOTSTRAP,c::TERMINAL],"controlled_target_is_checkpoint":false,
        "target_stop_protocol":"cooperative-resume-only","maximum_scratch_bytes":c::SCRATCH,"maximum_root_physical_bytes":c::SCRATCH,
        "control_metadata_bytes":c::CONTROL_METADATA,"candidate_incremental_peak_bytes":c::CANDIDATE,"experimental_envelope_bytes":c::CANDIDATE,
        "maximum_memory_bytes":c::MEMORY,"memory_high_bytes":c::HIGH,"cpu_quota_cores":8,"solana_rayon_threads":8,"historical_poh_threads":2,
        "rust_min_stack_bytes":67_108_864u64,"maximum_runtime_seconds":c::RUNTIME_MAX,"bounded_replay_authorized":true,
        "guard_minimum_free_bytes":a["protected_existing_floor_bytes"],"required_initial_free_bytes":a["required_initial_free_bytes"],
        "observer":a["observer"],"fleet":a["fleet"],"resource_samples_taken":0,"expected_exec_start":u["ExecStart"],
        "evidence":{"units":[{"unit":c::UNIT,"invocation_id":iid,"restarts":0,"load_state":u["LoadState"],"result":u["Result"],
            "main_pid":pid,"active_state":u["ActiveState"],"sub_state":u["SubState"]}]}});
    for (k, path, sha) in [
        ("node", c::NODE, c::NODE_SHA),
        ("worker", c::WORKER, c::WORKER_SHA),
        ("runner", c::RUNNER, c::RUNNER_SHA),
        ("guard", c::GUARD, c::GUARD_SHA),
        ("snapshot", c::SNAPSHOT, c::SNAPSHOT_SHA),
        ("native_input_proof", c::NATIVE, c::NATIVE_SHA),
        (
            "readonly_native_input_proof",
            c::NATIVE_READONLY,
            c::NATIVE_SHA,
        ),
        (
            "native_running_origin",
            c::NATIVE_ORIGIN,
            c::NATIVE_ORIGIN_SHA,
        ),
        (
            "original_failed_launch",
            c::ORIGINAL_LAUNCH,
            c::ORIGINAL_LAUNCH_SHA,
        ),
        (
            "original_failure_journal",
            c::ORIGINAL_JOURNAL,
            c::ORIGINAL_JOURNAL_SHA,
        ),
    ] {
        r[k] = json!({"path":path,"sha256":sha});
    }
    for (k, b) in [
        ("fresh_resource_admission", &s.fresh_resource_admission),
        ("input_capability", &s.input_capability),
        ("resource_plan", &s.resource_plan),
        ("resource_proposal", &s.resource_proposal),
        ("unit_file", &s.unit_file),
    ] {
        r[k] = private157::binding(b);
    }
    for k in [
        "ordinary_replay_authorized",
        "replay_launch_authorized",
        "full_epoch_qualified",
        "full_cold_epoch_peak_qualified",
        "canonical_prefix_qualified",
        "full_verification_qualified",
        "current_plugin_qualified",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        r[k] = json!(false);
    }
    validate_diagnostic_launch(&r, &claim)?;
    ensure!(
        c::launch_matches(&claim, &r),
        "227 capture exact launch scope differs"
    );
    Ok((claim, r))
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-canary227-v1625")?;
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    bindings(&s)?;
    if s.output.try_exists()? {
        let old = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["capture_spec"] == private157::binding(&binding)
                && old["capture_helper_sha256"] == self_sha
                && old["schema"] == c::SCHEMA
                && old["launched"] == true,
            "227 capture retry conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let a = bound_json(&s.fresh_resource_admission)?;
    let g = bound_json(&s.guard)?;
    let gp = bound_json(&s.guard_plan)?;
    let f = bound_json(&serde_json::from_value(a["fleet"].clone())?)?;
    let mut names = f["unit_census"]
        .as_object()
        .context("227 accepted census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c::UNIT.into());
    let before = census(&names, 201, 300)?;
    peers(&f, &before)?;
    let u = before.get(c::UNIT).context("227 actual producer absent")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (claim, mut r) = launch(&s, &a, u, now)?;
    protection(&a, &g, &gp, &r, &claim, now)?;
    ensure!(
        g["plan_sha256"] == s.guard_plan.sha256
            && g["producer"]["pid"] == r["main_pid"]
            && u["NRestarts"] == "0",
        "227 actual guarded PID/restarts differ"
    );
    let p=properties(c::UNIT,"Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,ProtectHome,ProtectSystem,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,ReadWritePaths,ExecMainPID,ExecMainStartTimestampMonotonic,Result,ActiveState,SubState,NRestarts,ExecStart,Transient,FragmentPath,RemainAfterExit")?;
    sandbox(
        &p,
        r["expected_exec_start"]
            .as_str()
            .context("227 expected command")?,
    )?;
    ensure!(
        p["ExecMainPID"].parse::<u64>()? == r["main_pid"].as_u64().context("227 PID")?,
        "227 PID changed"
    );
    let start = p["ExecMainStartTimestampMonotonic"].parse::<u64>()?;
    ensure!(start > 0, "227 missing actual start");
    let mut mono = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, mono.as_mut_ptr()) } == 0,
        "227 monotonic clock"
    );
    let mono = unsafe { mono.assume_init() };
    let micros = u64::try_from(mono.tv_sec)?
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_add(u64::try_from(mono.tv_nsec).ok()? / 1000))
        .context("227 clock overflow")?;
    let elapsed = micros.checked_sub(start).context("227 future start")? / 1000;
    let wall: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    r["producer_start_monotonic_microseconds"] = json!(start);
    r["producer_started_unix_millis"] =
        json!(wall.checked_sub(elapsed).context("227 start underflow")?);
    r["elapsed_execution_millis_at_capture"] = json!(elapsed);
    r["actual_guard_timer_proof"] = manager(&g, &s.guard_plan, now)?;
    r["guard_sample"] = private157::binding(&s.guard);
    r["guard_plan"] = private157::binding(&s.guard_plan);
    r["capture_spec"] = private157::binding(&binding);
    r["capture_helper_sha256"] = json!(self_sha);
    r["actual_sandbox"] = json!(p);
    let after = census(&names, 201, 300)?;
    peers(&f, &after)?;
    ensure!(before == after, "227 capture census changed");
    bindings(&s)?;
    private157::immutable_receipt(&s.output, &r)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn effective_sandbox_is_exact_and_missing_properties_fail_closed() {
        let command = "{ path=/runner ; argv[]=/runner plan ; ignore_errors=no }";
        let mut p = BTreeMap::new();
        for (k, v) in [
            ("Type", "exec"),
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryHigh", "149999996928"),
            ("MemoryMax", "224999997440"),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("TasksMax", "512"),
            ("RuntimeMaxUSec", "6h"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("PrivateNetwork", "no"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            ("ReadWritePaths", c::ROOT),
            ("Transient", "no"),
            ("FragmentPath", UNIT_FILE),
            ("RemainAfterExit", "no"),
            ("Result", "success"),
            ("NRestarts", "0"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("ExecStart", command),
        ] {
            p.insert(k.into(), v.into());
        }
        sandbox(&p, command).unwrap();
        for key in p.keys() {
            let mut bad = p.clone();
            bad.remove(key);
            assert!(sandbox(&bad, command).is_err(), "{key}");
        }
        for (key, value) in [
            ("Type", "simple"),
            ("User", "root"),
            ("MemoryMax", "225000000000"),
            ("ReadWritePaths", "/home/ubuntu"),
            ("NRestarts", "1"),
            ("Transient", "yes"),
            ("ExecStart", "different"),
        ] {
            let mut bad = p.clone();
            bad.insert(key.into(), value.into());
            assert!(sandbox(&bad, command).is_err(), "{key}");
        }
    }
    #[test]
    fn actual_guard_cannot_borrow_admission_identity_budget_or_checkpoint_authority() {
        let b = |path: &str| json!({"path":path,"sha256":"c".repeat(64)});
        let s:Spec=serde_json::from_value(json!({"schema":"jetstreamer-private-epoch227-v1625-canary-capture-spec-v1",
            "fresh_resource_admission":b("/var/lib/jetstreamer/horizon-227-v1625-canary-admission-test/admission.json"),
            "input_capability":b("/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-capability-test/receipts/capability.json"),
            "guard":b("/guard.json"),"guard_plan":b("/guard-plan.json"),
            "resource_plan":b("/var/lib/jetstreamer/horizon-227-v1625-canary-resource-test/resource-plan.json"),
            "resource_proposal":b("/proposal.json"),"unit_file":b(UNIT_FILE),"output":OUTPUT})).unwrap();
        let iid = "a".repeat(32);
        let mut a = json!({"schema":"jetstreamer-private-epoch227-v1625-canary-admission-v1","admitted":true,"epoch":227,
            "mode":"bounded-canary","unit":c::UNIT,"private_run_root":c::ROOT,"recorded_unix_seconds":100,
            "candidate_incremental_peak_bytes":c::CANDIDATE,"maximum_scratch_bytes":c::SCRATCH,"maximum_memory_bytes":c::MEMORY,
            "canary_plan":private157::binding(&s.resource_plan),"input_capability":private157::binding(&s.input_capability),
            "resource_proposal":private157::binding(&s.resource_proposal),"fresh_complete_census_passed":true,
            "older_producers_and_guards_preserved":true,"all_immutable_inputs_rehashed":true,"producer_started":false,
            "resource_samples_taken":0,"bounded_replay_resource_admitted":true,"protected_existing_floor_bytes":c::FLOOR_LOWER_BOUND,
            "required_initial_free_bytes":c::FLOOR_LOWER_BOUND+c::CANDIDATE});
        for k in [
            "entry_replay",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            a[k] = json!(false);
        }
        let command =
            c::expected_command(&json!({"resource_plan":private157::binding(&s.resource_plan)}))
                .unwrap();
        let u = json!({"InvocationID":iid,"MainPID":"42","NRestarts":"0","LoadState":"loaded","Result":"success",
            "ActiveState":"active","SubState":"running","ExecStart":format!("{command} ; ignore_errors=no ; pid=42 }}")});
        let (claim, r) = launch(&s, &a, &u, 102).unwrap();
        let p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":c::UNIT,"invocation_id":iid,
            "filesystem":"/","worker_root":c::ROOT,"minimum_free_bytes":c::FLOOR_LOWER_BOUND,"maximum_root_physical_bytes":c::SCRATCH,
            "maximum_worker_vmas":3_500_000,"bounded_canary":{"expected_uid":1000,"maximum_drainage_seconds":120,
            "target_stop_intent":Path::new(c::ROOT).join("receipts/target-stop.json")}});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","recorded_unix_seconds":101,
            "guard_sha256":c::GUARD_SHA,"producer_invocation_id":iid,"producer":{"invocation_id":iid,
            "cgroup":format!("/system.slice/{}",c::UNIT),"pid":42,"restarts":0,"active":"active","sub":"running"},
            "producer_stop_enabled":true,"bounded_canary":p["bounded_canary"],"bounded_measurement":false,"native_main":null,
            "target_handoff_error":null,"maximum_worker_vmas":3_500_000,"maximum_root_physical_bytes":c::SCRATCH,
            "root_physical_observation":{"maximum_physical_bytes":c::SCRATCH,"exceeds_budget":false,"conservative_physical_bytes":4096},
            "minimum_free_bytes":c::FLOOR_LOWER_BOUND,"available_bytes":c::FLOOR_LOWER_BOUND+1,"workers":[[43,100]],
            "trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"canary_target_error":null,
            "remote_mutations":false,"r2_mutations":false});
        protection(&a, &g, &p, &r, &claim, 102).unwrap();
        for (key, value) in [
            ("producer_invocation_id", json!("b".repeat(32))),
            ("available_bytes", json!(1)),
            ("bounded_measurement", json!(true)),
            ("trip_reason", json!("disk")),
            ("recorded_unix_seconds", json!(99)),
        ] {
            let mut bad = g.clone();
            bad[key] = value;
            assert!(protection(&a, &bad, &p, &r, &claim, 102).is_err(), "{key}");
        }
        let mut bad = a.clone();
        bad["canary_plan"]["sha256"] = json!("d".repeat(64));
        assert!(protection(&bad, &g, &p, &r, &claim, 102).is_err());
        let mut bad = p.clone();
        bad["bounded_canary"]["maximum_drainage_seconds"] = json!(180);
        assert!(protection(&a, &g, &bad, &r, &claim, 102).is_err());
        assert!(protection(&a, &g, &p, &r, &claim, 1001).is_err());
    }
}
