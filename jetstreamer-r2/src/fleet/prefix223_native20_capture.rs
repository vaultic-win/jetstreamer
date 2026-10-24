//! Capture only an actually admitted full native 20 prefix and real guarded IID.
use super::{prefix223_native20 as c, *};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    admission: BoundFile,
    guard: BoundFile,
    guard_plan: BoundFile,
    output: PathBuf,
}
pub(super) fn guard_valid(
    a: &Value,
    g: &Value,
    p: &Value,
    plan_sha: &str,
    now: u64,
) -> Result<String> {
    super::prefix223_native20_admission::validate_saved(a)?;
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("prefix admission clock")?;
    let guarded = g["recorded_unix_seconds"]
        .as_u64()
        .context("prefix guard clock")?;
    let iid = g["producer_invocation_id"]
        .as_str()
        .context("prefix guarded IID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && admitted <= guarded
            && guarded <= now
            && now - admitted <= 900
            && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && p["unit"] == c::UNIT
            && p["invocation_id"] == iid
            && p["filesystem"] == "/"
            && p["worker_root"] == c::ROOT
            && p["receipt_directory"] == c::GUARD_RECEIPTS
            && p["minimum_free_bytes"] == c::FLOOR
            && p["maximum_root_physical_bytes"] == c::PEAK
            && p["maximum_worker_vmas"] == 3500000
            && p.get("native_main").is_none_or(Value::is_null)
            && p.get("bounded_measurement").is_none_or(Value::is_null)
            && p.get("bounded_canary").is_none_or(Value::is_null)
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
            && g["root_physical_observation"]["maximum_physical_bytes"] == c::PEAK
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= c::PEAK)
            && g["maximum_worker_vmas"] == 3500000
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
            && g["minimum_free_bytes"] == c::FLOOR
            && g["available_bytes"].as_u64().is_some_and(|n| n >= c::FLOOR)
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "prefix actual guard/admission tuple differs"
    );
    Ok(iid.into())
}
pub(super) fn sandbox(p: &BTreeMap<String, String>) -> Result<()> {
    singleton227_capture::require(
        p,
        &[
            ("Type", "simple"),
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryHigh", "150000000000"),
            ("MemoryMax", "225000000000"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "512"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("ProtectControlGroups", "yes"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", "cap_dac_override"),
            ("AmbientCapabilities", "cap_dac_override"),
            ("ReadWritePaths", c::ROOT),
            ("OOMPolicy", "kill"),
            ("OOMScoreAdjust", "1000"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Result", "success"),
            ("NRestarts", "0"),
        ],
    )?;
    ensure!(
        p.get("ExecStart")
            .is_some_and(|s| c::same_command(&json!(s))),
        "prefix current command differs"
    );
    ensure!(
        p.get("Environment").is_some_and(String::is_empty),
        "prefix wrapper must own its environment configuration"
    );
    Ok(())
}
fn manager(plan: &BoundFile, g: &BoundFile, sample: u64, now: u64) -> Result<Value> {
    let selected = warmup223::completed_guard_binding(
        c::PROTECTIVE,
        Path::new(c::GUARD_RECEIPTS),
        sample,
        now,
    )?;
    ensure!(
        selected["binding"] == private157::binding(g),
        "prefix first guard is not latest completed invocation"
    );
    let p = singleton227_capture::properties(
        c::PROTECTIVE,
        "Type,User,Restart,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec,ExecStart",
    )?;
    singleton227_capture::require(
        &p,
        &[
            ("Type", "oneshot"),
            ("User", "root"),
            ("Restart", "no"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("ReadWritePaths", c::GUARD_RECEIPTS),
            ("MemoryMax", "1073741824"),
            ("TasksMax", "256"),
            ("CPUQuotaPerSecUSec", "1s"),
        ],
    )?;
    let command = format!(
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
            == Some(command.as_str()),
        "prefix guard executable/plan differs"
    );
    let timer = singleton227_capture::properties(
        &c::PROTECTIVE.replace(".service", ".timer"),
        "ActiveState,SubState",
    )?;
    ensure!(
        timer.get("ActiveState").is_some_and(|s| s == "active"),
        "prefix timer not active"
    );
    Ok(json!({"completed_selection":selected,"properties":p,"timer":timer}))
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-prefix223-native20")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch223-native20-prefix-capture-spec-v1"
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-native223-prefix-capture-"))
            && s.output.file_name().is_some_and(|s| s == "launch.json"),
        "prefix capture scope differs"
    );
    if s.output.try_exists()? {
        let old = native209::immutable_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["capture_spec"] == private157::binding(&binding)
                && old["capture_helper_sha256"] == self_sha,
            "prefix capture retry conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    c::prerequisites()?;
    let a = native209::immutable_json(&s.admission)?;
    let g = bound_json(&s.guard)?;
    let p = native209::immutable_json(&s.guard_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let iid = guard_valid(&a, &g, &p, &s.guard_plan.sha256, now)?;
    let completed = manager(
        &s.guard_plan,
        &s.guard,
        a["recorded_unix_seconds"]
            .as_u64()
            .context("prefix admission time")?,
        now,
    )?;
    let f = bound_json(&serde_json::from_value(a["fleet"].clone())?)?;
    let mut names = f["unit_census"]
        .as_object()
        .context("prefix capture full census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c::UNIT.into());
    let before = census(&names, 201, 300)?;
    prefix223_native20_admission::owners(&f, &before, true)?;
    let own = &before[c::UNIT];
    ensure!(
        own["InvocationID"] == iid
            && own["MainPID"].as_str().and_then(|n| n.parse::<u64>().ok())
                == g["producer"]["pid"].as_u64(),
        "prefix owner changed since guard"
    );
    let props = singleton227_capture::properties(
        c::UNIT,
        "Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,ProtectHome,ProtectSystem,ProtectControlGroups,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,Environment,OOMPolicy,OOMScoreAdjust,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainStatus,Result,ActiveState,SubState,NRestarts,ExecStart",
    )?;
    sandbox(&props)?;
    let mut v = json!({"schema":c::SCHEMA,"epoch":223,"private_run_root":c::ROOT,"launched":true,"runner_sha256":c::RUNNER_SHA,
        "node_sha256":c::NODE_SHA,"worker_sha256":c::WORKER_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,"runtime":"solana-v1.6.20",
        "bootstrap_slot":96335538u64,"terminal_root_slot":96767522u64,"output_slot_start":96336000u64,"output_slot_count":431523,"uncovered_suffix_slots":477,
        "natural_parent_completion_required":true,"maximum_scratch_bytes":300_000_000_000u64,"experimental_envelope_bytes":c::PEAK,"maximum_memory_bytes":c::MEMORY,"maximum_runtime_seconds":259200,
        "guard_minimum_free_bytes":c::FLOOR,"required_initial_free_bytes":c::INITIAL,"expected_exec_start":own["ExecStart"]});
    let provenance = json!({"capability":a["capability"],"resource_plan":a["resource_plan"],"warmup_terminal":a["warmup_terminal"],"admission":private157::binding(&s.admission),
        "guard":private157::binding(&s.guard),"guard_plan":private157::binding(&s.guard_plan),"guard_manager":completed,"sandbox":props,
        "observer":a["observer"],"fleet":a["fleet"],"recorded_unix_seconds":now,"sampled_at_utc":publication203::utc(now)?,"resource_samples_taken":0,"entry_replay":true,"ordinary_replay_claim":false,"public_sidecar_countdown_authorized":true,
        "capture_spec":private157::binding(&binding),"capture_helper_sha256":self_sha,
        "evidence":{"units":[{"unit":c::UNIT,"invocation_id":iid,"restarts":0,"load_state":"loaded","active_state":"active","sub_state":"running","main_pid":g["producer"]["pid"],"result":"success"}]}});
    for (key, field) in provenance
        .as_object()
        .context("prefix capture provenance")?
    {
        ensure!(v.get(key).is_none(), "duplicate prefix capture field:{key}");
        v[key] = field.clone();
    }
    for key in [
        "ordinary_replay_authorized",
        "full_cold_epoch_peak_qualified",
        "repair_closed",
        "canonical_prefix_independently_qualified",
        "native_restart_qualified",
        "suffix_qualified",
        "assembly_qualified",
        "full_epoch_qualified",
        "full_plugin_qualified",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        v[key] = json!(false);
    }
    let d = DiagnosticClaim {
        epoch: 223,
        unit: c::UNIT.into(),
        invocation_id: iid,
        scratch_path: c::ROOT.into(),
        launch_receipt: BoundFile {
            path: s.output.clone(),
            sha256: "0".repeat(64),
        },
    };
    c::bindings(&d, &v)?;
    let after = census(&names, 201, 300)?;
    prefix223_native20_admission::owners(&f, &after, true)?;
    ensure!(before == after, "prefix capture census changed");
    private157::immutable_receipt(&s.output, &v)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_prefix_sandbox_rejects_a_warmup_cap_or_lost_private_scope() {
        let mut p = [
            ("Type", "simple"),
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryHigh", "150000000000"),
            ("MemoryMax", "225000000000"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "512"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("ProtectControlGroups", "yes"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", "cap_dac_override"),
            ("AmbientCapabilities", "cap_dac_override"),
            ("ReadWritePaths", c::ROOT),
            ("OOMPolicy", "kill"),
            ("OOMScoreAdjust", "1000"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Result", "success"),
            ("NRestarts", "0"),
            ("Environment", ""),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect::<BTreeMap<String, String>>();
        p.insert(
            "ExecStart".into(),
            format!("{} ; ignore_errors=no", c::command()),
        );
        sandbox(&p).unwrap();
        for (k, v) in [
            ("MemoryMax", "137438953472"),
            ("MemoryHigh", "149999996928"),
            ("CapabilityBoundingSet", ""),
            ("ReadWritePaths", "/other"),
            ("Environment", "UNREVIEWED=1"),
        ] {
            let mut bad = p.clone();
            bad.insert(k.into(), v.into());
            assert!(sandbox(&bad).is_err(), "{k}");
        }
    }
}
