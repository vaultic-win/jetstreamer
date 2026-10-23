//! Capture only real native qualification or an exactly guarded singleton.
use super::*;
use super::{singleton227 as c, singleton227_admission as admission};
const GUARD_BIN: &str = "/var/lib/jetstreamer/horizon-ownroot203-capability-8623b37c-v1/jetstreamer-horizon-standalone-guard";
const NATIVE_GUARD_BIN: &str = "/var/lib/jetstreamer/horizon-native227-main-guard-e53a03e5-v2/jetstreamer-horizon-standalone-guard";
const TEST: &str = "/var/lib/jetstreamer/horizon-227-native-test-optimized-v1/native-input-test";
const TEST_SHA: &str = "1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mode: String,
    admission: BoundFile,
    guard: BoundFile,
    guard_plan: BoundFile,
    output: PathBuf,
    #[serde(default)]
    native_running: bool,
}
fn properties(unit: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args(["show", unit, "--no-pager", &format!("--property={fields}")])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 65536,
        "227 unit properties unavailable"
    );
    let mut p = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("227 property syntax")?;
        ensure!(
            p.insert(k.into(), v.into()).is_none(),
            "227 duplicate property"
        );
    }
    Ok(p)
}
fn require(p: &BTreeMap<String, String>, values: &[(&str, &str)]) -> Result<()> {
    for (k, v) in values {
        ensure!(
            p.get(*k).map(String::as_str) == Some(*v),
            "227 sandbox differs:{k}"
        );
    }
    Ok(())
}
fn journal(unit: &str) -> Result<(Vec<Value>, String)> {
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            unit,
            "--output=json",
            "--no-pager",
            "--lines=2048",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16 << 20,
        "227 journal unavailable/oversize"
    );
    let rows = out
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    Ok((rows, hex_lower(&Sha256::digest(&out.stdout))))
}
fn manager(mode: &str, guard: &Value, plan: &BoundFile) -> Result<Value> {
    let unit = if mode == "native-cold" {
        "horizon-native227-protective-v1.service"
    } else {
        "horizon-singleton227-protective-v1.service"
    };
    let p = properties(
        unit,
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
    let guard_plan = bound_json(plan)?;
    ensure!(
        p.get("ReadWritePaths").map(String::as_str) == guard_plan["receipt_directory"].as_str(),
        "227 protective write scope differs"
    );
    let (guard_bin, guard_sha) = if mode == "native-cold" {
        (NATIVE_GUARD_BIN, c::NATIVE_GUARD_SHA)
    } else {
        (GUARD_BIN, c::GUARD_SHA)
    };
    let command = format!(
        "{{ path={guard_bin} ; argv[]={guard_bin} {} --plan-sha256 {} --self-sha256 {}",
        plan.path.display(),
        plan.sha256,
        guard_sha
    );
    ensure!(
        p["ExecStart"]
            .split_once(" ; ignore_errors=")
            .map(|(s, _)| s)
            == Some(command.as_str()),
        "227 protective command differs"
    );
    let timer = properties(&unit.replace(".service", ".timer"), "ActiveState,SubState")?;
    require(
        &timer,
        &[("ActiveState", "active"), ("SubState", "waiting")],
    )?;
    let (rows, sha) = journal(unit)?;
    let success = rows
        .iter()
        .filter(|v| {
            v["_PID"] == "1"
                && v["UNIT"] == unit
                && v["INVOCATION_ID"] == guard["guard_invocation_id"]
                && v["MESSAGE"] == format!("{unit}: Deactivated successfully.")
        })
        .collect::<Vec<_>>();
    ensure!(
        success.len() == 1,
        "227 guard has no unique PID1 completion"
    );
    Ok(json!({"properties":p,"timer":timer,"manager_completion":success[0],"journal_sha256":sha}))
}
pub(super) fn native_command() -> String {
    format!(
        "{{ path={TEST} ; argv[]={TEST} runtime::tests::native_epoch227_cold_input_matches_canonical_accounts_commitment --exact --ignored --test-threads=1 --nocapture"
    )
}
fn environment(p: &BTreeMap<String, String>, mode: &str) -> Result<()> {
    let expected = if mode == "native-cold" {
        vec![
            "RUST_MIN_STACK=67108864".into(),
            "SOLANA_RAYON_THREADS=8".into(),
            "JETSTREAMER_HISTORICAL_POH_THREADS=2".into(),
            format!(
                "JETSTREAMER_EPOCH227_V1620_TEST_SCRATCH={}/scratch",
                admission::NATIVE_ROOT
            ),
        ]
    } else {
        vec![
            "RUST_MIN_STACK=67108864".into(),
            "SOLANA_RAYON_THREADS=16".into(),
            "JETSTREAMER_HISTORICAL_POH_THREADS=8".into(),
            "TOKIO_WORKER_THREADS=8".into(),
            "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1".into(),
            format!("JETSTREAMER_PRIVATE_RUN_ROOT={}/private", c::ROOT),
            format!("JETSTREAMER_HISTORICAL_WORKER_V1_6_20={}", c::WORKER),
        ]
    };
    let expected = expected.into_iter().collect::<BTreeSet<String>>();
    let actual = p
        .get("Environment")
        .context("227 environment missing")?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    ensure!(
        actual == expected,
        "227 environment differs from the exact worker/input profile"
    );
    Ok(())
}
fn marker(rows: &[Value], iid: &str) -> Result<Value> {
    let mut markers = Vec::new();
    let mut success = 0;
    for row in rows.iter().filter(|r| r["_SYSTEMD_INVOCATION_ID"] == iid) {
        let Some(message) = row["MESSAGE"].as_str() else {
            continue;
        };
        if message.contains("test result: ok. 1 passed; 0 failed; 0 ignored;") {
            success += 1;
        }
        if let Some((_, fields)) = message.split_once("epoch227-v1620-native-input ") {
            let mut parsed = BTreeMap::new();
            for field in fields.split_whitespace() {
                let (k, v) = field.split_once('=').context("227 native field")?;
                ensure!(
                    parsed.insert(k.to_owned(), v.to_owned()).is_none(),
                    "227 duplicate native field"
                );
            }
            for (k, v) in [
                ("slot", "98063464"),
                (
                    "accounts_hash",
                    "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR",
                ),
                ("replay_entries", "0"),
                ("bootstrap_writes", "0"),
            ] {
                ensure!(
                    parsed.get(k).map(String::as_str) == Some(v),
                    "227 native commitment differs:{k}"
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
                    .context("227 missing native integer")?
                    .parse::<u64>()?;
            }
            ensure!(
                parsed.len() == 10
                    && parsed.contains_key("bank_hash")
                    && parsed.contains_key("last_blockhash"),
                "227 native marker census differs"
            );
            markers.push(json!(parsed));
        }
    }
    ensure!(
        markers.len() == 1 && success == 1,
        "227 native result lacks exact successful test/commitment census"
    );
    Ok(markers.remove(0))
}
pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: capture-singleton227 SPEC --spec-sha256 SHA --self-sha256 SHA (root)"
    );
    let own = fs::symlink_metadata(fs::read_link("/proc/self/exe")?)?;
    ensure!(
        own.uid() == 0
            && own.nlink() == 1
            && own.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "227 capture helper unsealed"
    );
    let b = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let s: Spec = serde_json::from_value(bound_json(&b)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch227-singleton-capture-spec-v1"
            && matches!(s.mode.as_str(), "native-cold" | "replay")
            && (!s.native_running || s.mode == "native-cold"),
        "227 capture scope differs"
    );
    ensure!(
        s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-227-capture-"))
            && s.output.file_name().is_some_and(|n| n == "launch.json"
                || n == "native.json"
                || (s.native_running && n == "intent.json")),
        "227 capture destination differs"
    );
    if s.output.try_exists()? {
        let old = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["capture_spec"] == private157::binding(&b)
                && old["capture_helper_sha256"] == args[6],
            "227 existing capture conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let a = bound_json(&s.admission)?;
    let g = bound_json(&s.guard)?;
    let p = bound_json(&s.guard_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("227 admission clock")?;
    let guarded = g["recorded_unix_seconds"]
        .as_u64()
        .context("227 guard clock")?;
    ensure!(
        a["schema"] == "jetstreamer-private-epoch227-singleton-admission-v1"
            && a["mode"] == s.mode
            && a["admitted"] == true
            && guarded >= admitted
            && guarded - admitted <= 900
            && guarded <= now
            && now - admitted
                <= if s.mode == "native-cold" && !s.native_running {
                    3600
                } else {
                    900
                },
        "227 missing/stale launch admission"
    );
    let (unit, root, peak) = if s.mode == "native-cold" {
        (admission::NATIVE_UNIT, admission::NATIVE_ROOT, c::SCRATCH)
    } else {
        (c::UNIT, c::ROOT, c::PEAK)
    };
    let iid = g["producer_invocation_id"]
        .as_str()
        .context("227 guarded invocation")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && p["unit"] == unit
            && p["invocation_id"] == iid
            && p["worker_root"] == root
            && p["filesystem"] == "/"
            && p["minimum_free_bytes"] == a["protected_existing_floor_bytes"]
            && p["maximum_root_physical_bytes"] == peak
            && p["maximum_worker_vmas"] == 3500000
            && p.get("bounded_canary").is_none_or(Value::is_null)
            && p.get("bounded_measurement").is_none_or(Value::is_null)
            && g["guard_sha256"]
                == if s.mode == "native-cold" {
                    c::NATIVE_GUARD_SHA
                } else {
                    c::GUARD_SHA
                }
            && g["plan_sha256"] == s.guard_plan.sha256
            && g["producer"]["invocation_id"] == iid
            && g["producer"]["cgroup"] == format!("/system.slice/{unit}")
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer_stop_enabled"] == true
            && g["maximum_root_physical_bytes"] == peak
            && g["root_physical_observation"]["maximum_physical_bytes"] == peak
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= peak)
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(p["minimum_free_bytes"].as_u64())
                .is_some_and(|(x, y)| x >= y)
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
        "227 actual protection differs"
    );
    let manager = manager(&s.mode, &g, &s.guard_plan)?;
    let f = bound_json(&serde_json::from_value(a["fleet"].clone())?)?;
    let mut names = f["unit_census"]
        .as_object()
        .context("227 prior census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(unit.into());
    let before = census(&names, 201, 300)?;
    let mut protected = before.clone();
    protected.remove(unit);
    admission::owners(&f, &protected)?;
    let u = before.get(unit).context("227 producer absent")?;
    let sandbox = properties(
        unit,
        "Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,RuntimeMaxUSec,ProtectHome,ProtectSystem,NoNewPrivileges,ReadWritePaths,Environment,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainStatus,Result,ActiveState,SubState,NRestarts,ExecStart",
    )?;
    if s.mode == "native-cold" {
        ensure!(
            p["native_main"]["executable"] == TEST
                && p["native_main"]["sha256"] == TEST_SHA
                && p["native_main"]["main_pid"] == g["producer"]["pid"]
                && g["native_main"] == p["native_main"],
            "227 native MainPID executable binding differs"
        );
    } else {
        ensure!(
            p.get("native_main").is_none_or(Value::is_null),
            "227 replay cannot borrow native process semantics"
        );
    }
    require(
        &sandbox,
        &[
            ("Type", "exec"),
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemorySwapMax", "0"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("NoNewPrivileges", "yes"),
            ("ReadWritePaths", root),
            ("Result", "success"),
            ("NRestarts", "0"),
        ],
    )?;
    environment(&sandbox, &s.mode)?;
    let mut result = if s.mode == "native-cold" {
        require(
            &sandbox,
            &[
                ("MemoryHigh", "120259084288"),
                ("MemoryMax", "137438953472"),
                ("TasksMax", "512"),
                ("RuntimeMaxUSec", "45min"),
            ],
        )?;
        if s.native_running {
            require(
                &sandbox,
                &[("ActiveState", "active"), ("SubState", "running")],
            )?;
            ensure!(
                u["InvocationID"] == iid
                    && u["MainPID"].as_str().and_then(|p| p.parse::<u64>().ok())
                        == g["producer"]["pid"].as_u64(),
                "227 native running identity changed"
            );
        } else {
            require(
                &sandbox,
                &[
                    ("ActiveState", "inactive"),
                    ("SubState", "dead"),
                    ("ExecMainStatus", "0"),
                ],
            )?;
        }
        ensure!(
            sandbox["ExecStart"]
                .split_once(" ; ignore_errors=")
                .map(|(s, _)| s)
                == Some(native_command().as_str())
                && sandbox["ExecMainPID"].parse::<u64>()?
                    == g["producer"]["pid"]
                        .as_u64()
                        .context("227 native guarded PID")?
                && g["workers"].as_array().is_some_and(|w| w.len() == 1)
                && g["workers"][0][0] == g["producer"]["pid"]
                && g["workers"][0][1]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 3500000),
            "227 native command/PID differs"
        );
        if s.native_running {
            json!({"schema":"jetstreamer-private-epoch227-native-input-running-v1","epoch":227,"unit":unit,"private_run_root":root,
                "invocation_id":iid,"main_pid":g["producer"]["pid"],"test_sha256":TEST_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,
                "expected_exec_start":u["ExecStart"],"maximum_memory_bytes":128u64<<30,"maximum_scratch_bytes":c::SCRATCH,
                "observer":a["observer"],"fleet":a["fleet"],"resource_samples_taken":0,"ordinary_replay_claim":false,
                "verification_status":{"phase":"native-input-verification","active":true,"epoch":227,"entry_replay":false,"native_input_qualified":false},
                "replay_entries":0,"native_input_qualified":false,"public_sidecar_countdown_authorized":false})
        } else {
            let (rows, journal_sha) = journal(unit)?;
            let native = marker(&rows, iid)?;
            json!({"schema":"jetstreamer-private-epoch227-native-input-qualified-v1","epoch":227,"test_sha256":TEST_SHA,
            "snapshot_sha256":c::SNAPSHOT_SHA,"bootstrap_slot":98063464u64,"accounts_hash":"4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR",
            "native_marker":native,"journal_sha256":journal_sha,"child_success":true,"child_exit_code":0,"producer_terminal_and_zero_restarts":true,"replay_entries":0,"bootstrap_writes":0})
        }
    } else {
        require(
            &sandbox,
            &[
                ("MemoryHigh", "150000000000"),
                ("MemoryMax", "225000000000"),
                ("TasksMax", "512"),
                ("RuntimeMaxUSec", "3d"),
                ("ActiveState", "active"),
                ("SubState", "running"),
            ],
        )?;
        ensure!(
            u["InvocationID"] == iid
                && c::same_command(&u["ExecStart"], &Value::Null)
                && u["MainPID"].as_str().and_then(|p| p.parse::<u64>().ok())
                    == g["producer"]["pid"].as_u64()
                && g["workers"].as_array().is_some_and(|v| v.len() == 1)
                && g["workers"][0][1]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 3500000),
            "227 actual replay identity/worker differs"
        );
        json!({"schema":c::SCHEMA,"epoch":227,"private_run_root":c::ROOT,"launched":true,"node_sha256":c::NODE_SHA,
            "worker_sha256":c::WORKER_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,"manifest_fingerprint":c::FINGERPRINT,"bootstrap_slot":98063464u64,
            "canonical_root_slot":98495291u64,"terminal_slot":98495999u64,"output_slot_start":98064000u64,"output_slot_count":432000,
            "runtime":"solana-v1.6.20","maximum_scratch_bytes":c::SCRATCH,"experimental_envelope_bytes":c::PEAK,
            "maximum_runtime_seconds":259200,"upstream_shrink_budget_cap":true,"guard_minimum_free_bytes":a["protected_existing_floor_bytes"],
            "required_initial_free_bytes":a["required_initial_free_bytes"],"expected_exec_start":u["ExecStart"],"resource_plan":a["resource_plan"],"native_input":a["native_input"],
            "capability":{"path":c::CAPABILITY,"sha256":c::CAPABILITY_SHA},"evidence":{"units":[{"unit":unit,"invocation_id":iid,"restarts":0,"load_state":u["LoadState"],"result":u["Result"],
            "main_pid":u["MainPID"].as_str().context("227 PID")?.parse::<u64>()?,"active_state":u["ActiveState"],"sub_state":u["SubState"]}]}})
    };
    for k in [
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        result[k] = json!(false);
    }
    result["recorded_unix_seconds"] = json!(now);
    result["sampled_at_utc"] = json!(publication203::utc(now)?);
    if s.mode == "native-cold" {
        result["entry_replay"] = json!(false);
        let start = sandbox["ExecMainStartTimestampMonotonic"].parse::<u64>()?;
        let mut mono = std::mem::MaybeUninit::<libc::timespec>::uninit();
        ensure!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, mono.as_mut_ptr()) } == 0,
            "227 monotonic clock unavailable"
        );
        let mono = unsafe { mono.assume_init() };
        let micros = u64::try_from(mono.tv_sec)?
            .checked_mul(1_000_000)
            .and_then(|s| s.checked_add(u64::try_from(mono.tv_nsec).ok()? / 1000))
            .context("227 monotonic clock overflow")?;
        let elapsed = micros
            .checked_sub(start)
            .context("227 producer start is future-dated")?
            / 1000;
        let wall: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        result["producer_start_monotonic_microseconds"] = json!(start);
        result["producer_started_unix_millis"] = json!(
            wall.checked_sub(elapsed)
                .context("227 execution start underflow")?
        );
        result["elapsed_execution_millis_at_capture"] = json!(elapsed);
    }
    result["admission"] = private157::binding(&s.admission);
    result["guard"] = private157::binding(&s.guard);
    result["guard_plan"] = private157::binding(&s.guard_plan);
    result["capture_spec"] = private157::binding(&b);
    result["capture_helper_sha256"] = json!(args[6]);
    result["sandbox"] = json!(sandbox);
    result["guard_manager"] = manager;
    let after = census(&names, 201, 300)?;
    ensure!(before == after, "227 owner census changed during capture");
    if s.mode == "native-cold" && !s.native_running {
        c::native_valid(&result)?;
    } else if s.mode == "replay" {
        let claim = DiagnosticClaim {
            epoch: 227,
            unit: unit.into(),
            invocation_id: iid.into(),
            scratch_path: root.into(),
            launch_receipt: BoundFile {
                path: s.output.clone(),
                sha256: "0".repeat(64),
            },
        };
        c::bindings(&claim, &result)?;
    }
    private157::immutable_receipt(&s.output, &result)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rows() -> Vec<Value> {
        vec![
            json!({"_SYSTEMD_INVOCATION_ID":"a".repeat(32),"MESSAGE":"epoch227-v1620-native-input slot=98063464 bank_hash=known accounts_hash=4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR last_blockhash=known capitalization=18446744073709551614 transaction_count=1 tick_height=1 next_write_version=1 replay_entries=0 bootstrap_writes=0"}),
            json!({"_SYSTEMD_INVOCATION_ID":"a".repeat(32),"MESSAGE":"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured"}),
        ]
    }
    #[test]
    fn native_marker_requires_exact_invocation_root_and_success_without_numeric_roundtrip() {
        let r = rows();
        let v = marker(&r, &"a".repeat(32)).unwrap();
        assert_eq!(v["capitalization"], "18446744073709551614");
        assert!(marker(&r, &"b".repeat(32)).is_err());
        let mut missing = r.clone();
        missing.pop();
        assert!(marker(&missing, &"a".repeat(32)).is_err());
        let mut wrong = r.clone();
        wrong[0]["MESSAGE"] = json!(
            r[0]["MESSAGE"]
                .as_str()
                .unwrap()
                .replace("slot=98063464", "slot=98063465")
        );
        assert!(marker(&wrong, &"a".repeat(32)).is_err());
        let mut duplicated = r.clone();
        duplicated.push(r[0].clone());
        assert!(marker(&duplicated, &"a".repeat(32)).is_err());
    }
}
