//! Bind the actually admitted full210 job and its first real protective fire.
use super::{singleton210 as c, *};
use singleton227_capture::{journal, properties, require};
const PROTECTIVE: &str = "horizon-singleton210-protective-v1.service";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    admission: BoundFile,
    guard: BoundFile,
    guard_plan: BoundFile,
    output: PathBuf,
}

pub(super) fn protection(
    a: &Value,
    g: &Value,
    p: &Value,
    now: u64,
    plan_sha: &str,
) -> Result<String> {
    maintenance_capacity::singleton210_memory_proven(&a["capacity"])?;
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("210 full admission clock")?;
    let guarded = g["recorded_unix_seconds"]
        .as_u64()
        .context("210 full guard clock")?;
    let iid = g["producer_invocation_id"]
        .as_str()
        .context("210 full guard IID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && a["schema"] == "jetstreamer-private-epoch210-singleton-admission-v1"
            && a["epoch"] == 210
            && a["mode"] == "replay"
            && a["admitted"] == true
            && a["unit"] == c::UNIT
            && a["private_run_root"] == c::ROOT
            && a["candidate_incremental_peak_bytes"] == c::PEAK
            && a["maximum_memory_bytes"] == c::MEMORY
            && a["fresh_complete_census_passed"] == true
            && a["older_producers_and_guards_preserved"] == true
            && guarded >= admitted
            && guarded - admitted <= 900
            && guarded <= now
            && now - admitted <= 900
            && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && p["unit"] == c::UNIT
            && p["invocation_id"] == iid
            && p["filesystem"] == "/"
            && p["worker_root"] == c::ROOT
            && p["minimum_free_bytes"] == a["protected_existing_floor_bytes"]
            && p["maximum_root_physical_bytes"] == c::PEAK
            && p["maximum_worker_vmas"] == 3500000
            && p.get("native_main").is_none_or(Value::is_null)
            && p.get("bounded_canary").is_none_or(Value::is_null)
            && p.get("bounded_measurement").is_none_or(Value::is_null)
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == c::GUARD_SHA
            && g["plan_sha256"] == plan_sha
            && g["producer"]["invocation_id"] == iid
            && g["producer"]["cgroup"] == format!("/system.slice/{}", c::UNIT)
            && g["producer"]["pid"].as_u64().is_some_and(|n| n > 1)
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer_stop_enabled"] == true
            && g["maximum_root_physical_bytes"] == c::PEAK
            && g["maximum_worker_vmas"] == 3500000
            && g["root_physical_observation"]["maximum_physical_bytes"] == c::PEAK
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= c::PEAK)
            && g["workers"].as_array().is_some_and(|v| v.len() == 1)
            && g["workers"][0][0].as_u64().is_some_and(|n| n > 1)
            && g["workers"][0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3500000)
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(p["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "210 full actual guard/admission scope, owner or budget differs"
    );
    c::no_publication(a)?;
    Ok(iid.into())
}
fn guard_manager(g: &Value, plan: &BoundFile) -> Result<Value> {
    let p = properties(
        PROTECTIVE,
        "Type,User,Restart,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec,ExecStart,Result,ExecMainStatus,ActiveState,SubState",
    )?;
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
        "210 full guard write scope differs"
    );
    let cmd = format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {}",
        c::GUARD,
        c::GUARD,
        plan.path.display(),
        plan.sha256,
        c::GUARD_SHA
    );
    ensure!(
        p["ExecStart"]
            .split_once(" ; ignore_errors=")
            .map(|(s, _)| s)
            == Some(cmd.as_str()),
        "210 full guard command differs"
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
    let success = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["UNIT"] == PROTECTIVE
                && r["INVOCATION_ID"] == g["guard_invocation_id"]
                && r["MESSAGE"] == format!("{PROTECTIVE}: Deactivated successfully.")
        })
        .collect::<Vec<_>>();
    ensure!(
        success.len() == 1,
        "210 full guard lacks one exact PID1 success"
    );
    Ok(json!({"properties":p,"timer":timer,"manager_completion":success[0],"journal_sha256":sha}))
}
pub(super) fn sandbox(p: &BTreeMap<String, String>) -> Result<()> {
    require(
        p,
        &[
            ("Type", "exec"),
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryHigh", "150000000000"),
            ("MemoryMax", "225000000000"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "512"),
            ("RuntimeMaxUSec", "3d"),
            ("CPUQuotaPerSecUSec", "16s"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            ("ReadWritePaths", c::ROOT),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Result", "success"),
            ("NRestarts", "0"),
        ],
    )?;
    let expected = [
        "RUST_MIN_STACK=134217728".into(),
        "SOLANA_RAYON_THREADS=16".into(),
        "JETSTREAMER_HISTORICAL_POH_THREADS=8".into(),
        "TOKIO_WORKER_THREADS=8".into(),
        "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1".into(),
        format!("JETSTREAMER_PRIVATE_RUN_ROOT={}/private", c::ROOT),
        format!("JETSTREAMER_HISTORICAL_WORKER_V1_6_16={}", c::WORKER),
    ]
    .into_iter()
    .collect::<BTreeSet<String>>();
    ensure!(
        p.get("Environment")
            .context("210 full environment")?
            .split_whitespace()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            == expected,
        "210 full environment differs"
    );
    ensure!(
        p.get("ExecStart")
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .map(|(s, _)| s)
            == Some(c::command().as_str()),
        "210 full command differs"
    );
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-singleton210")?;
    let s: Spec = serde_json::from_value(native210::immutable_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch210-singleton-capture-spec-v1"
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-210-singleton-capture-"))
            && s.output.file_name().is_some_and(|n| n == "launch.json"),
        "210 full capture spec/output differs"
    );
    if s.output.try_exists()? {
        let old = native210::immutable_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["capture_spec"] == private157::binding(&binding)
                && old["capture_helper_sha256"] == self_sha,
            "210 full capture retry conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let a = native210::immutable_json(&s.admission)?;
    let g = bound_json(&s.guard)?;
    let gp = native210::immutable_json(&s.guard_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let iid = protection(&a, &g, &gp, now, &s.guard_plan.sha256)?;
    c::native(&serde_json::from_value(a["native_input"].clone())?)?;
    let manager = guard_manager(&g, &s.guard_plan)?;
    let f = bound_json(&serde_json::from_value(a["fleet"].clone())?)?;
    let observer: BoundFile = serde_json::from_value(a["observer"].clone())?;
    let fleet: BoundFile = serde_json::from_value(a["fleet"].clone())?;
    ensure!(
        bound_json(&observer)?["recorded_at_utc"] == f["sampled_at_utc"]
            && fleet.sha256 == a["fleet"]["sha256"],
        "210 admission observer/fleet changed"
    );
    let mut names = f["unit_census"]
        .as_object()
        .context("210 full prior unit census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c::UNIT.into());
    let before = census(&names, 201, 300)?;
    let mut prior = before.clone();
    prior.remove(c::UNIT);
    singleton210_admission::owners(&f, &prior, &a["resource_basis"])?;
    let u = before.get(c::UNIT).context("210 full producer omitted")?;
    ensure!(
        u["InvocationID"] == iid
            && u["MainPID"].as_str().and_then(|n| n.parse::<u64>().ok())
                == g["producer"]["pid"].as_u64(),
        "210 full producer changed after first guard"
    );
    let props = properties(
        c::UNIT,
        "Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,ProtectHome,ProtectSystem,NoNewPrivileges,CapabilityBoundingSet,ReadWritePaths,Environment,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainStatus,Result,ActiveState,SubState,NRestarts,ExecStart",
    )?;
    sandbox(&props)?;
    let mut v = json!({"schema":c::SCHEMA,"epoch":210,"private_run_root":c::ROOT,"launched":true,
        "node_sha256":c::NODE_SHA,"worker_sha256":c::WORKER_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,"manifest_fingerprint":c::FINGERPRINT,
        "bootstrap_slot":90719638u64,"canonical_root_slot":91151575u64,"post_root_slot_count":424,"terminal_slot":91151999u64,
        "output_slot_start":90720000u64,"output_slot_count":432000,"runtime":"solana-v1.6.16",
        "maximum_scratch_bytes":c::SCRATCH,"experimental_envelope_bytes":c::PEAK,"maximum_runtime_seconds":259200,
        "phase_metadata_reservation_bytes":c::METADATA_RESERVE,
        "upstream_shrink_budget_cap":true,"guard_minimum_free_bytes":a["protected_existing_floor_bytes"],"required_initial_free_bytes":a["required_initial_free_bytes"],
        "expected_exec_start":u["ExecStart"]});
    let evidence = json!({"capability":a["capability"],"native_input":a["native_input"],"resource_plan":a["resource_plan"],
        "admission":private157::binding(&s.admission),"guard":private157::binding(&s.guard),"guard_plan":private157::binding(&s.guard_plan),
        "guard_manager":manager,"sandbox":props,"observer":a["observer"],"fleet":a["fleet"],
        "capacity":a["capacity"],
        "recorded_unix_seconds":now,"sampled_at_utc":publication203::utc(now)?,"resource_samples_taken":0,
        "capture_spec":private157::binding(&binding),"capture_helper_sha256":self_sha,
        "evidence":{"units":[{"unit":c::UNIT,"invocation_id":iid,"restarts":0,"load_state":"loaded","active_state":"active","sub_state":"running",
            "main_pid":g["producer"]["pid"],"result":"success"}]}});
    for (key, value) in evidence.as_object().context("210 full capture evidence")? {
        ensure!(v.get(key).is_none(), "210 capture field collision");
        v[key] = value.clone();
    }
    for key in [
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        v[key] = json!(false);
    }
    let d = DiagnosticClaim {
        epoch: 210,
        unit: c::UNIT.into(),
        invocation_id: iid,
        scratch_path: c::ROOT.into(),
        launch_receipt: BoundFile {
            path: s.output.clone(),
            sha256: "0".repeat(64),
        },
    };
    c::bindings(&d, &v)?;
    ensure!(
        before == census(&names, 201, 300)?,
        "210 full capture owner census changed"
    );
    singleton210_admission::owners(&f, &prior, &a["resource_basis"])?;
    private157::immutable_receipt(&s.output, &v)
}
