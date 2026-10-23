//! Capture exact capped204 launch only after its real protective timer succeeds.
use super::*;
const UNIT: &str = "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1";
const GUARD_UNIT: &str = "horizon-prefix204-protective-v1.service";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon-prefix204-guard-receipts-v1";
const GUARD_BIN: &str = "/var/lib/jetstreamer/horizon-ownroot203-capability-8623b37c-v1/jetstreamer-horizon-standalone-guard";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    admission: BoundFile,
    guard: BoundFile,
    guard_plan: BoundFile,
    output: PathBuf,
}
fn properties(name: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args(["show", name, "--no-pager", &format!("--property={fields}")])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 32768,
        "204 launch properties unavailable"
    );
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("204 property syntax")?;
        ensure!(
            result.insert(k.into(), v.into()).is_none(),
            "duplicate204 property"
        );
    }
    Ok(result)
}
fn required(p: &BTreeMap<String, String>, pairs: &[(&str, &str)]) -> Result<()> {
    for (k, v) in pairs {
        ensure!(
            p.get(*k).map(String::as_str) == Some(*v),
            "204 sandbox property differs:{k}"
        );
    }
    Ok(())
}
fn manager(g: &Value, plan: &BoundFile) -> Result<Value> {
    let p = properties(
        GUARD_UNIT,
        "Type,User,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,MemoryMax,CPUQuotaPerSecUSec,TasksMax,ExecStart,Result,ExecMainStatus,ActiveState,SubState",
    )?;
    required(
        &p,
        &[
            ("Type", "oneshot"),
            ("User", "root"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("ReadWritePaths", RECEIPTS),
            ("MemoryMax", "1073741824"),
            ("CPUQuotaPerSecUSec", "1s"),
            ("TasksMax", "256"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
        ],
    )?;
    let command = format!(
        "{{ path={GUARD_BIN} ; argv[]={GUARD_BIN} {} --plan-sha256 {} --self-sha256 {}",
        plan.path.display(),
        plan.sha256,
        prefix204::GUARD_SHA
    );
    ensure!(
        p["ExecStart"]
            .split_once(" ; ignore_errors=")
            .map(|(s, _)| s)
            == Some(command.as_str()),
        "204 protective command differs"
    );
    let timer = properties(
        "horizon-prefix204-protective-v1.timer",
        "ActiveState,SubState",
    )?;
    required(
        &timer,
        &[("ActiveState", "active"), ("SubState", "waiting")],
    )?;
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            GUARD_UNIT,
            "--output=json",
            "--no-pager",
            "--lines=128",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 8 << 20,
        "204 guard completion journal unavailable"
    );
    let mut found = None;
    for line in out.stdout.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let v: Value = serde_json::from_slice(line)?;
        if v["UNIT"] == GUARD_UNIT
            && v["_PID"] == "1"
            && v["INVOCATION_ID"] == g["guard_invocation_id"]
            && v["MESSAGE"] == format!("{GUARD_UNIT}: Deactivated successfully.")
        {
            ensure!(
                found.replace(v).is_none(),
                "duplicate204 guard manager completion"
            );
        }
    }
    Ok(
        json!({"properties":p,"timer":timer,"manager_completion":found.context("204 first real timer fire has no PID1 success")?,
        "journal_sha256":hex_lower(&Sha256::digest(&out.stdout))}),
    )
}
pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: capture-prefix204 SPEC --spec-sha256 SHA --self-sha256 SHA (root)"
    );
    let m = fs::symlink_metadata(fs::read_link("/proc/self/exe")?)?;
    ensure!(
        m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "204 launch helper unsealed"
    );
    let b = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let s: Spec = serde_json::from_value(bound_json(&b)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch204-capped-prefix-capture-spec-v1"
            && s.output
                == Path::new(
                    "/var/lib/jetstreamer/horizon-prefix204-launch-fcbf3992-v1/launch.json"
                ),
        "204 launch capture scope differs"
    );
    if s.output.try_exists()? {
        let old = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["schema"] == prefix204::SCHEMA
                && old["launched"] == true
                && old["capture_spec"]["sha256"] == b.sha256
                && old["capture_helper_sha256"] == args[6],
            "204 existing capture conflicts with this exact operation"
        );
        println!("Exact capped204 capture already committed; no repeated launch or mutation");
        return Ok(());
    }
    let a = bound_json(&s.admission)?;
    let g = bound_json(&s.guard)?;
    let p = bound_json(&s.guard_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("204 admission time")?;
    ensure!(
        a["schema"] == "jetstreamer-private-epoch204-capped-prefix-admission-v1"
            && a["admitted"] == true
            && admitted <= now
            && now - admitted <= 900,
        "204 missing/stale admission"
    );
    let f = bound_json(&serde_json::from_value(a["fleet"].clone())?)?;
    let mut names = f["unit_census"]
        .as_object()
        .context("204 protected census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(UNIT.into());
    let before = census(&names, 201, 300)?;
    snapshot144::check_owners(&f, &before)?;
    let u = before.get(UNIT).context("204 producer absent")?;
    let iid = u["InvocationID"].as_str().context("204 producer IID")?;
    let claim = DiagnosticClaim {
        epoch: 204,
        unit: UNIT.into(),
        invocation_id: iid.into(),
        scratch_path: ROOT.into(),
        launch_receipt: BoundFile {
            path: s.output.clone(),
            sha256: "0".repeat(64),
        },
    };
    let mut r = json!({"schema":prefix204::SCHEMA,"epoch":204,"private_run_root":ROOT,"launched":true,"recorded_unix_seconds":now,
        "node_sha256":"025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d",
        "worker_sha256":"4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc",
        "runner_sha256":"1cd9bfe3418616add2319802adc4caf66b86e3f6fdf6c903c4be2648b10c0baa",
        "snapshot_sha256":"d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6",
        "bootstrap_slot":88127580,"terminal_root_slot":88559361,"output_slot_start":88128000,"output_slot_count":431362,
        "uncovered_suffix_slots":638,"runtime":"solana-v1.6.16","solana_rayon_threads":16,"maximum_runtime_seconds":259200,
        "maximum_scratch_bytes":300_000_000_000u64,"experimental_envelope_bytes":300_000_000_000u64+(160u64<<30),
        "natural_parent_completion_required":true,"upstream_shrink_budget_cap":true,"root_prefix_resource_attempt_authorized":true,
        "plan_path":"/var/lib/jetstreamer/horizon-prefix204-resource-fcbf3992-v1/resource-plan.json","plan_sha256":a["plan_sha256"],
        "guard_minimum_free_bytes":a["protected_existing_floor_bytes"],"required_initial_free_bytes":a["required_initial_free_bytes"],
        "expected_exec_start":u["ExecStart"],"admission":private157::binding(&s.admission),
        "capability":{"path":"/var/lib/jetstreamer/horizon-prefix204-input-capability-result-v1/capability.json",
            "sha256":"9b2c12e561660f1c7e3c0af3708fddb3240e51a83bd7ed272bc96750f9caeb85"},
        "evidence":{"units":[{"unit":UNIT,"invocation_id":iid,"restarts":0,"load_state":u["LoadState"],"result":u["Result"],
            "main_pid":u["MainPID"].as_str().context("204 PID")?.parse::<u64>()?,"active_state":u["ActiveState"],"sub_state":u["SubState"]}]}});
    for k in [
        "ordinary_replay_authorized",
        "canonical_prefix_independently_qualified",
        "native_restart_qualified",
        "assembly_qualified",
        "full_cold_epoch_peak_qualified",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        r[k] = json!(false);
    }
    validate_diagnostic_launch(&r, &claim)?;
    prefix204::bindings(&claim, &r)?;
    ensure!(
        u["NRestarts"] == "0"
            && g["guard_sha256"] == prefix204::GUARD_SHA
            && g["plan_sha256"] == s.guard_plan.sha256
            && g["producer_invocation_id"] == iid
            && g["producer"]["pid"].as_u64()
                == u["MainPID"].as_str().and_then(|s| s.parse::<u64>().ok())
            && g["producer_stop_enabled"] == true
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["maximum_worker_vmas"] == 3500000
            && g["maximum_root_physical_bytes"] == 300_000_000_000u64
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(p["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false
            && g["workers"].as_array().is_some_and(|v| v.len() == 1)
            && g["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t >= admitted && t <= now && now - t <= 1800)
            && p["unit"] == UNIT
            && p["invocation_id"] == iid
            && p["worker_root"] == format!("{ROOT}/scratch")
            && prefix204::guard_matches(&claim, &r, &p),
        "204 actual guard is not a clean protected worker fire"
    );
    let sandbox = properties(
        UNIT,
        "User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,ProtectHome,ProtectSystem,NoNewPrivileges,ReadWritePaths",
    )?;
    required(
        &sandbox,
        &[
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryHigh", "206158430208"),
            ("MemoryMax", "240518168576"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "4096"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("NoNewPrivileges", "yes"),
            ("ReadWritePaths", ROOT),
        ],
    )?;
    let proof = manager(&g, &s.guard_plan)?;
    let after = census(&names, 201, 300)?;
    snapshot144::check_owners(&f, &after)?;
    ensure!(before == after, "204 owner census changed during capture");
    r["guard"] = private157::binding(&s.guard);
    r["guard_plan"] = private157::binding(&s.guard_plan);
    r["actual_guard_timer_proof"] = proof;
    r["actual_sandbox"] = json!(sandbox);
    r["capture_spec"] = private157::binding(&b);
    r["capture_helper_sha256"] = json!(args[6]);
    validate_output_destination(&s.output)?;
    private157::immutable_receipt(&s.output, &r)?;
    println!(
        "Exact capped204 launch and first protective timer captured; publication remains closed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sandbox_requires_every_exact_property_without_weakening_absent_values() {
        let mut p = BTreeMap::from([
            ("User".into(), "ubuntu".into()),
            ("Restart".into(), "no".into()),
        ]);
        required(&p, &[("User", "ubuntu"), ("Restart", "no")]).unwrap();
        assert!(required(&p, &[("MemoryMax", "240518168576")]).is_err());
        p.insert("Restart".into(), "on-failure".into());
        assert!(required(&p, &[("Restart", "no")]).is_err());
    }
}
