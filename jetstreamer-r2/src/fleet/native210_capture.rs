//! Capture the exact protected 210 native job; no replay or launch operation.
use super::native210 as c;
use super::singleton227_capture::{journal, require};
use super::*;
const PROTECTIVE: &str = "horizon-native210-protective-v1.service";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mode: String,
    admission: BoundFile,
    guard: BoundFile,
    guard_plan: BoundFile,
    output: PathBuf,
}
pub(super) fn properties(unit: &str) -> Result<BTreeMap<String, String>> {
    singleton227_capture::properties(
        unit,
        "Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,CPUAffinity,TasksMax,RuntimeMaxUSec,ProtectHome,ProtectSystem,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,ReadWritePaths,Environment,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainStatus,Result,ActiveState,SubState,NRestarts,ExecStart,Transient,FragmentPath,RemainAfterExit",
    )
}
fn native_affinity(value: &str) -> bool {
    matches!(value, "0-7" | "0 1 2 3 4 5 6 7")
}
fn persistent(p: &BTreeMap<String, String>) -> Result<()> {
    require(
        p,
        &[
            ("Transient", "no"),
            ("FragmentPath", c::UNIT_FILE),
            ("RemainAfterExit", "no"),
        ],
    )
}
pub(super) fn sandbox(p: &BTreeMap<String, String>) -> Result<()> {
    persistent(p)?;
    require(
        p,
        &[
            ("Type", "exec"),
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryHigh", "120259084288"),
            ("MemoryMax", "137438953472"),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("TasksMax", "512"),
            ("RuntimeMaxUSec", "45min"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            ("ReadWritePaths", c::ROOT),
            ("Result", "success"),
            ("NRestarts", "0"),
        ],
    )?;
    ensure!(
        p.get("CPUAffinity").is_some_and(|v| native_affinity(v)),
        "210 native CPU affinity differs"
    );
    let expected = [
        "RUST_MIN_STACK=134217728".into(),
        "SOLANA_RAYON_THREADS=8".into(),
        "JETSTREAMER_HISTORICAL_POH_THREADS=2".into(),
        format!(
            "JETSTREAMER_EPOCH210_V1616_TEST_SCRATCH={}/scratch",
            c::ROOT
        ),
    ]
    .into_iter()
    .collect::<BTreeSet<String>>();
    ensure!(
        p.get("Environment")
            .context("210 environment")?
            .split_whitespace()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            == expected,
        "210 native environment differs"
    );
    ensure!(
        p.get("ExecStart")
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .map(|(s, _)| s)
            == Some(c::command().as_str()),
        "210 native command differs"
    );
    Ok(())
}
pub(super) fn protection(a: &Value, g: &Value, p: &Value, now: u64) -> Result<()> {
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("210 admission clock")?;
    let guarded = g["recorded_unix_seconds"]
        .as_u64()
        .context("210 guard clock")?;
    let iid = g["producer_invocation_id"]
        .as_str()
        .context("210 guarded invocation")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && a["schema"] == "jetstreamer-private-epoch210-native-admission-v1"
            && a["admitted"] == true
            && a["epoch"] == 210
            && a["mode"] == "native-cold"
            && a["unit"] == c::UNIT
            && a["private_run_root"] == c::ROOT
            && a["candidate_incremental_peak_bytes"] == c::SCRATCH
            && a["maximum_memory_bytes"] == c::MEMORY
            && a["cold_plan"] == json!({"path":c::PLAN,"sha256":c::PLAN_SHA})
            && a["all_immutable_inputs_rehashed"] == true
            && a["snapshot_restored"] == false
            && a["producer_started"] == false
            && a["resource_samples_taken"] == 0
            && guarded >= admitted
            && guarded - admitted <= 900
            && guarded <= now
            && now - admitted <= 3600
            && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && p["unit"] == c::UNIT
            && p["invocation_id"] == iid
            && p["filesystem"] == "/"
            && p["worker_root"] == c::ROOT
            && p["minimum_free_bytes"] == a["protected_existing_floor_bytes"]
            && p["maximum_root_physical_bytes"] == c::SCRATCH
            && p["maximum_worker_vmas"] == 3500000
            && p.get("bounded_canary").is_none_or(Value::is_null)
            && p.get("bounded_measurement").is_none_or(Value::is_null)
            && p["native_main"]["executable"] == c::TEST
            && p["native_main"]["sha256"] == c::TEST_SHA
            && p["native_main"]["main_pid"] == g["producer"]["pid"]
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == c::GUARD_SHA
            && g["producer"]["invocation_id"] == iid
            && g["producer"]["cgroup"] == format!("/system.slice/{}", c::UNIT)
            && g["producer"]["pid"].as_u64().is_some_and(|n| n > 1)
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer_stop_enabled"] == true
            && g["native_main"] == p["native_main"]
            && g["maximum_worker_vmas"] == 3500000
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
            && g["workers"][0][0] == g["producer"]["pid"]
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
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "210 native admission/guard scope, identity or budget differs"
    );
    c::no_authority(a)?;
    Ok(())
}
fn manager(g: &Value, plan: &BoundFile) -> Result<Value> {
    let p = singleton227_capture::properties(
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
        "210 guard write scope differs"
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
        "210 guard command differs"
    );
    let timer = singleton227_capture::properties(
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
                && r["UNIT"] == PROTECTIVE
                && r["INVOCATION_ID"] == g["guard_invocation_id"]
                && r["MESSAGE"] == format!("{PROTECTIVE}: Deactivated successfully.")
        })
        .collect::<Vec<_>>();
    ensure!(successful.len() == 1, "210 exact PID1 guard success absent");
    Ok(
        json!({"properties":p,"timer":timer,"manager_completion":successful[0],"journal_sha256":sha}),
    )
}
pub(super) fn marker(rows: &[Value], iid: &str) -> Result<Value> {
    let mut found = None;
    let mut success = None;
    let mut terminal = None;
    let mut last = 0u64;
    for (index, r) in rows.iter().enumerate() {
        let clock = r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("210 journal clock")?
            .parse::<u64>()?;
        ensure!(clock >= last, "210 journal clock rollback");
        last = clock;
        let msg = r["MESSAGE"].as_str().context("210 journal message")?;
        if r["_PID"] == "1" {
            ensure!(
                r["UNIT"] == c::UNIT && r["INVOCATION_ID"] == iid,
                "210 foreign manager row"
            );
            if msg == format!("{}: Deactivated successfully.", c::UNIT) {
                ensure!(
                    terminal.replace(index).is_none(),
                    "210 duplicate manager completion"
                );
            }
        } else {
            ensure!(
                r["_SYSTEMD_UNIT"] == c::UNIT && r["_SYSTEMD_INVOCATION_ID"] == iid,
                "210 foreign child row"
            );
            if let Some((_, fields)) = msg.split_once("epoch210-v1616-native-input ") {
                let mut parsed = BTreeMap::new();
                for field in fields.split_whitespace() {
                    let (k, v) = field.split_once('=').context("210 marker field")?;
                    ensure!(
                        parsed.insert(k.to_owned(), v.to_owned()).is_none(),
                        "210 duplicate marker field"
                    );
                }
                for (k, v) in [
                    ("slot", "90719638"),
                    ("accounts_hash", c::ACCOUNTS_HASH),
                    ("replay_entries", "0"),
                    ("bootstrap_writes", "0"),
                ] {
                    ensure!(
                        parsed.get(k).map(String::as_str) == Some(v),
                        "210 canonical marker differs:{k}"
                    );
                }
                for k in [
                    "capitalization",
                    "transaction_count",
                    "tick_height",
                    "next_write_version",
                ] {
                    parsed
                        .get(k)
                        .context("210 missing integer")?
                        .parse::<u64>()?;
                }
                ensure!(
                    parsed.len() == 10
                        && parsed.get("bank_hash").is_some_and(|s| !s.is_empty())
                        && parsed.get("last_blockhash").is_some_and(|s| !s.is_empty()),
                    "210 marker census differs"
                );
                ensure!(
                    found.replace((index, json!(parsed))).is_none(),
                    "210 duplicate marker"
                );
            } else if msg.starts_with("test result:") {
                ensure!(
                    msg.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
                        && success.replace(index).is_none(),
                    "210 test outcome differs"
                );
            }
        }
    }
    let (i, v) = found.context("210 marker absent")?;
    ensure!(
        success.zip(terminal).is_some_and(|(s, t)| i < s && s < t),
        "210 ordered test/terminal proof absent"
    );
    Ok(v)
}
fn mode(mode: &str) -> Result<bool> {
    match mode {
        "running" => Ok(true),
        _ => bail!("210 requires running capture followed by its independent terminal proof"),
    }
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-native210-input")?;
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    let running = mode(&s.mode)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch210-native-capture-spec-v1"
            && s.output == Path::new(c::ORIGIN)
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-210-native-capture-"))
            && s.output.file_name().is_some_and(|n| n
                == if running {
                    "intent.json"
                } else {
                    "native.json"
                }),
        "210 capture destination differs"
    );
    if s.output.try_exists()? {
        let old = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["capture_spec"] == private157::binding(&binding)
                && old["capture_helper_sha256"] == self_sha,
            "210 capture conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    native209_admission::sealed_file(Path::new(c::UNIT_FILE), c::UNIT_FILE_SHA, None)?;
    let a = bound_json(&s.admission)?;
    let g = bound_json(&s.guard)?;
    let gp = bound_json(&s.guard_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    protection(&a, &g, &gp, now)?;
    ensure!(
        g["plan_sha256"] == s.guard_plan.sha256,
        "210 guard plan digest differs"
    );
    let manager = manager(&g, &s.guard_plan)?;
    let iid = g["producer_invocation_id"].as_str().context("210 IID")?;
    let f = bound_json(&serde_json::from_value(a["fleet"].clone())?)?;
    let mut names = f["unit_census"]
        .as_object()
        .context("210 accepted census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c::UNIT.into());
    let before = census(&names, 201, 300)?;
    native210_peer_history::current(&f, &before)?;
    let mut protected = before.clone();
    protected.remove(c::UNIT);
    singleton227_admission::owners(&f, &protected)?;
    let p = properties(c::UNIT)?;
    sandbox(&p)?;
    ensure!(
        p["ExecMainPID"].parse::<u64>()?
            == g["producer"]["pid"].as_u64().context("210 guarded PID")?,
        "210 producer PID differs"
    );
    let mut r = if running {
        require(&p, &[("ActiveState", "active"), ("SubState", "running")])?;
        let u = before.get(c::UNIT).context("210 live owner absent")?;
        ensure!(
            u["InvocationID"] == iid
                && u["MainPID"].as_str().and_then(|n| n.parse::<u64>().ok())
                    == g["producer"]["pid"].as_u64(),
            "210 owner changed"
        );
        let start = p["ExecMainStartTimestampMonotonic"].parse::<u64>()?;
        ensure!(start > 0, "210 producer clock absent");
        let mut mono = std::mem::MaybeUninit::<libc::timespec>::uninit();
        ensure!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, mono.as_mut_ptr()) } == 0,
            "210 monotonic clock"
        );
        let mono = unsafe { mono.assume_init() };
        let micros = u64::try_from(mono.tv_sec)?
            .checked_mul(1_000_000)
            .and_then(|n| n.checked_add(u64::try_from(mono.tv_nsec).ok()? / 1000))
            .context("210 clock overflow")?;
        let elapsed = micros
            .checked_sub(start)
            .context("210 start future dated")?
            / 1000;
        let wall: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        json!({"schema":c::SCHEMA,"epoch":210,"unit":c::UNIT,"private_run_root":c::ROOT,"invocation_id":iid,"main_pid":g["producer"]["pid"],"test_sha256":c::TEST_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,"genesis_sha256":c::GENESIS_SHA,
            "bootstrap_slot":90719638u64,"accounts_hash":c::ACCOUNTS_HASH,"expected_exec_start":u["ExecStart"],"maximum_memory_bytes":c::MEMORY,"maximum_scratch_bytes":c::SCRATCH,"cold_plan":{"path":c::PLAN,"sha256":c::PLAN_SHA},"unit_file":{"path":c::UNIT_FILE,"sha256":c::UNIT_FILE_SHA},
            "observer":a["observer"],"fleet":a["fleet"],"resource_samples_taken":0,"ordinary_replay_claim":false,"replay_entries":0,"native_input_qualified":false,
            "producer_start_monotonic_microseconds":start,"producer_started_unix_millis":wall.checked_sub(elapsed).context("210 start underflow")?,"elapsed_execution_millis_at_capture":elapsed})
    } else {
        require(
            &p,
            &[
                ("ActiveState", "inactive"),
                ("SubState", "dead"),
                ("ExecMainStatus", "0"),
            ],
        )?;
        let (rows, sha) = journal(c::UNIT)?;
        let rows = rows
            .into_iter()
            .filter(|r| {
                r["_SYSTEMD_INVOCATION_ID"] == iid
                    || (r["_PID"] == "1" && r["INVOCATION_ID"] == iid)
            })
            .collect::<Vec<_>>();
        let checkpoint = marker(&rows, iid)?;
        json!({"schema":"jetstreamer-private-epoch210-native-input-qualified-v1","epoch":210,"unit":c::UNIT,"invocation_id":iid,"test_sha256":c::TEST_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,"genesis_sha256":c::GENESIS_SHA,"bootstrap_slot":90719638u64,"accounts_hash":c::ACCOUNTS_HASH,
            "native_marker":checkpoint,"journal_sha256":sha,"journal_rows":rows,"child_success":true,"child_exit_code":0,"producer_terminal_and_zero_restarts":true,"replay_entries":0,"bootstrap_writes":0,"native_input_qualified":true,"resource_samples_taken":0})
    };
    for flag in [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        r[flag] = json!(false);
    }
    r["recorded_unix_seconds"] = json!(now);
    r["public_sidecar_countdown_authorized"] = json!(running);
    r["sampled_at_utc"] = json!(publication203::utc(now)?);
    r["admission"] = private157::binding(&s.admission);
    r["guard"] = private157::binding(&s.guard);
    r["guard_plan"] = private157::binding(&s.guard_plan);
    r["capture_spec"] = private157::binding(&binding);
    r["capture_helper_sha256"] = json!(self_sha);
    r["sandbox"] = json!(p);
    r["guard_manager"] = manager;
    let after = census(&names, 201, 300)?;
    native210_peer_history::current(&f, &after)?;
    ensure!(before == after, "210 capture owner census changed");
    private157::immutable_receipt(&s.output, &r)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transient_collected_or_remain_after_exit_units_cannot_be_captured() {
        let good = BTreeMap::from([
            ("Transient".into(), "no".into()),
            ("FragmentPath".into(), c::UNIT_FILE.into()),
            ("RemainAfterExit".into(), "no".into()),
        ]);
        persistent(&good).unwrap();
        for (key, value) in [
            ("Transient", "yes"),
            ("FragmentPath", "/run/systemd/transient/native.service"),
            ("RemainAfterExit", "yes"),
        ] {
            let mut bad = good.clone();
            bad.insert(key.into(), value.into());
            assert!(persistent(&bad).is_err());
            bad.remove(key);
            assert!(persistent(&bad).is_err());
        }
        assert!(mode("running").unwrap());
        assert!(mode("qualified").is_err());
    }
    #[test]
    fn systemd_cpu_affinity_renderings_are_equivalent_only_for_the_exact_eight_cpu_set() {
        assert!(native_affinity("0-7"));
        assert!(native_affinity("0 1 2 3 4 5 6 7"));
        for wrong in [
            "",
            "0-8",
            "1-8",
            "0 1 2 3 4 5 6",
            "0 1 2 3 4 5 6 7 7",
            "0 1 2 3 4 5 6 7 8",
        ] {
            assert!(!native_affinity(wrong), "{wrong}");
        }
    }
    #[test]
    fn protection_cannot_mix_owners_admissions_guards_or_budget_exceptions() {
        let iid = "a".repeat(32);
        let mut a = json!({"schema":"jetstreamer-private-epoch210-native-admission-v1","admitted":true,"epoch":210,"mode":"native-cold","unit":c::UNIT,"private_run_root":c::ROOT,
            "candidate_incremental_peak_bytes":c::SCRATCH,"maximum_memory_bytes":c::MEMORY,"cold_plan":{"path":c::PLAN,"sha256":c::PLAN_SHA},"all_immutable_inputs_rehashed":true,
            "snapshot_restored":false,"producer_started":false,"resource_samples_taken":0,"recorded_unix_seconds":100,"protected_existing_floor_bytes":1000});
        for flag in [
            "entry_replay",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            a[flag] = json!(false);
        }
        let p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":c::UNIT,"invocation_id":iid,"filesystem":"/","worker_root":c::ROOT,
            "minimum_free_bytes":1000,"maximum_root_physical_bytes":c::SCRATCH,"maximum_worker_vmas":3500000,"native_main":{"executable":c::TEST,"sha256":c::TEST_SHA,"main_pid":42}});
        let g = json!({"recorded_unix_seconds":101,"producer_invocation_id":iid,"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_sha256":c::GUARD_SHA,
            "producer":{"invocation_id":iid,"cgroup":format!("/system.slice/{}",c::UNIT),"pid":42,"restarts":0,"active":"active","sub":"running"},
            "producer_stop_enabled":true,"native_main":p["native_main"],"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":c::SCRATCH,
            "root_physical_observation":{"maximum_physical_bytes":c::SCRATCH,"exceeds_budget":false,"conservative_physical_bytes":4096},
            "minimum_free_bytes":1000,"available_bytes":2000,"workers":[[42,100]],"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"canary_target_error":null,"remote_mutations":false,"r2_mutations":false});
        protection(&a, &g, &p, 102).unwrap();
        for pointer in [
            "/native_main/main_pid",
            "/native_main/sha256",
            "/worker_root",
            "/maximum_root_physical_bytes",
            "/unit",
        ] {
            let mut bad = p.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(protection(&a, &g, &bad, 102).is_err(), "{pointer}");
        }
        for (pointer, value) in [
            ("/producer/pid", json!(1)),
            ("/producer/invocation_id", json!("b".repeat(32))),
            ("/guard_sha256", json!(singleton227::NATIVE_GUARD_SHA)),
            ("/trip_reason", json!("disk")),
            ("/available_bytes", json!(999)),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(protection(&a, &bad, &p, 102).is_err(), "{pointer}");
        }
        let mut bad = a.clone();
        bad["mode"] = json!("replay");
        assert!(protection(&bad, &g, &p, 102).is_err());
        assert!(protection(&a, &g, &p, 4000).is_err());
    }
    #[test]
    fn marker_requires_exact_ordered_native_commitment_and_manager_identity() {
        let iid = "a".repeat(32);
        let child = |m: &str, t: &str| json!({"_PID":"42","_SYSTEMD_UNIT":c::UNIT,"_SYSTEMD_INVOCATION_ID":iid,"MESSAGE":m,"__REALTIME_TIMESTAMP":t});
        let text = format!(
            "epoch210-v1616-native-input slot=90719638 bank_hash=known accounts_hash={} last_blockhash=known capitalization=18446744073709551614 transaction_count=1 tick_height=1 next_write_version=1 replay_entries=0 bootstrap_writes=0",
            c::ACCOUNTS_HASH
        );
        let rows = vec![
            child(&text, "1"),
            child(
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 60 filtered out; finished in 1s",
                "2",
            ),
            json!({"_PID":"1","UNIT":c::UNIT,"INVOCATION_ID":iid,"MESSAGE":format!("{}: Deactivated successfully.",c::UNIT),"__REALTIME_TIMESTAMP":"3"}),
        ];
        assert_eq!(
            marker(&rows, &iid).unwrap()["capitalization"],
            "18446744073709551614"
        );
        for i in 0..rows.len() {
            let mut bad = rows.clone();
            bad.remove(i);
            assert!(marker(&bad, &iid).is_err());
        }
        let mut bad = rows.clone();
        bad[2]["INVOCATION_ID"] = json!("b".repeat(32));
        assert!(marker(&bad, &iid).is_err());
        let mut bad = rows.clone();
        bad[0]["MESSAGE"] = json!(text.replace("slot=90719638", "slot=89423445"));
        assert!(marker(&bad, &iid).is_err());
        let mut bad = rows.clone();
        bad.swap(0, 1);
        assert!(marker(&bad, &iid).is_err());
        assert!(mode("replay").is_err());
        assert!(mode("native-cold").is_err());
    }
}
