use super::*;
use std::os::fd::AsRawFd;

#[cfg(not(feature = "epoch171"))]
const TEMPLATE: &str = include_str!("producer.service");
#[cfg(feature = "epoch171")]
const TEMPLATE: &str = include_str!("producer171.service");
const OLD_EXE: &str = PAYLOAD;
fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}
fn producer_argv(token: &str) -> Result<Vec<String>> {
    let mut args = vec![format!("--unit={UNIT}"), format!("--description={token}")];
    let mut start = false;
    for prop in TEMPLATE
        .split_once("[Service]\n")
        .context("missing service")?
        .1
        .lines()
        .filter(|l| !l.is_empty())
    {
        let (k, v) = prop.split_once('=').context("service property")?;
        if k == "ExecStart" {
            ensure!(v == format!("{OLD_EXE} run"), "payload arg changed");
            start = true;
            continue;
        }
        if k == "Type" {
            ensure!(v == "exec", "unexpected service type");
            args.push("--service-type=exec".into());
            continue;
        }
        let value = if k == "ExecPaths" {
            ensure!(v.starts_with(OLD_EXE), "unrecognized payload exec paths");
            v.replacen(OLD_EXE, &format!("{GATE_ALIAS} {PAYLOAD_ALIAS}"), 1)
        } else if k == "BindReadOnlyPaths" {
            format!(
                "{v} {PACKAGE}/{GATE}:{GATE_ALIAS} {PAYLOAD}:{PAYLOAD_ALIAS} {BASE}/barrier:{BARRIER_ALIAS}"
            )
        } else {
            v.to_owned()
        };
        args.push(format!("--property={k}={value}"));
    }
    ensure!(
        start
            && args.contains(&format!("--property=ReadWritePaths={DEST}"))
            && args.contains(&"--property=MemoryMax=73014444032".to_owned())
            && args.contains(&"--property=CPUQuota=300%".to_owned()),
        "producer contract"
    );
    // systemd-run resolves the command on the host before PID 1 mounts the private gate.
    args.extend(strings(&["/usr/bin/env", GATE_ALIAS]));
    Ok(args)
}
fn guard_argv(plan: &Path, sha: &str) -> Vec<String> {
    let mut a = strings(&[
        "--on-active=1s",
        "--on-unit-inactive=5s",
        "--timer-property=AccuracySec=1s",
        "--service-type=oneshot",
        "--property=User=root",
        "--property=Group=root",
        "--property=UMask=0077",
        "--property=Restart=no",
        "--property=MemoryMax=1G",
        "--property=MemorySwapMax=0",
        "--property=CPUQuota=100%",
        "--property=TasksMax=256",
        "--property=TimeoutStartSec=120",
        "--property=TimeoutStopSec=15",
        "--property=PrivateNetwork=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=read-only",
        "--property=PrivateTmp=yes",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
        "--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
    ]);
    a.extend([
        format!("--unit={}", GUARD_SERVICE.trim_end_matches(".service")),
        format!("--timer-property=Requisite={UNIT}"),
        format!("--timer-property=After={UNIT}"),
        format!("--timer-property=StopPropagatedFrom={UNIT}"),
        format!("--property=ReadWritePaths={RECEIPTS}"),
        format!("--property=StandardOutput=append:{BASE}/guard.stdout"),
        format!("--property=StandardError=append:{BASE}/guard.stderr"),
        GUARD.into(),
        plan.display().to_string(),
        "--plan-sha256".into(),
        sha.into(),
        "--self-sha256".into(),
        GUARD_SHA.into(),
    ]);
    a
}
fn mkdir(path: &Path, mode: u32) -> Result<()> {
    fs::DirBuilder::new().mode(mode).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    custody(path, 0, 0, None, mode)?;
    File::open(path.parent().context("dir parent")?)?.sync_all()?;
    Ok(())
}
fn sample(dir: &Path, producer: &Value, floor: u64, sha: &str, deadline: Instant) -> Result<Value> {
    let id = at(producer, "InvocationID")?;
    let pid = at(producer, "MainPID")?.parse::<u64>()?;
    while Instant::now() < deadline {
        for e in fs::read_dir(dir)? {
            let path = e?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            ensure!(!name.starts_with("stop-"), "guard recorded stop");
            if !name.starts_with("sample-") || !name.ends_with(".json") {
                continue;
            }
            let raw = read_root(&path)?;
            let s: Value = serde_json::from_slice(&raw)?;
            first_sample(&s, id, pid, sha, floor)?;
            let sid = at(&s, "guard_invocation_id")?;
            ensure!(
                iid(sid) && name == format!("sample-{sid}.json"),
                "guard receipt filename"
            );
            let unit = show(GUARD_SERVICE)?;
            let timer = show(TIMER)?;
            if unit["InvocationID"] != sid || unit["ActiveState"] != "inactive" {
                continue;
            }
            ensure!(
                unit["Result"] == "success"
                    && unit["ExecMainStatus"] == "0"
                    && unit["MainPID"] == "0"
                    && unit["ControlPID"] == "0"
                    && timer["ActiveState"] == "active"
                    && timer["Triggers"] == GUARD_SERVICE
                    && unit["TriggeredBy"] == TIMER
                    && timer["Job"] == ""
                    && iid(at(&timer, "InvocationID")?),
                "genuine first timer guard"
            );
            let native = show(UNIT)?;
            ensure!(
                native["InvocationID"] == id
                    && native["MainPID"] == producer["MainPID"]
                    && native["ActiveState"] == "active"
                    && native["NRestarts"] == "0",
                "gated producer changed"
            );
            // Query only the matching PID1 record, and emit only its two non-sensitive fields.
            let journal = run(
                "/usr/bin/journalctl",
                &[
                    String::from("--no-pager"),
                    String::from("-ojson"),
                    String::from("--output-fields=_PID,INVOCATION_ID"),
                    String::from("_PID=1"),
                    format!("UNIT={GUARD_SERVICE}"),
                    format!("INVOCATION_ID={sid}"),
                    String::from("-n1"),
                ],
                deadline,
            )?;
            ensure!(
                journal
                    .lines()
                    .filter_map(|s| serde_json::from_str::<Value>(s).ok())
                    .any(|r| r["_PID"] == "1" && r["INVOCATION_ID"] == sid),
                "PID1 guard start missing"
            );
            return Ok(
                json!({"receipt":binding(&path,&digest(&raw)),"raw_floor_bytes":floor,"producer":native,"timer":timer,"guard":unit,"genuine_first_timer_driven_success":true}),
            );
        }
        thread::sleep(Duration::from_millis(120));
    }
    bail!("first guard deadline expired")
}
fn sealed_plan(
    root: &Path,
    actual: &Value,
    sha: &str,
    id: &str,
    deadline: Instant,
) -> Result<PathBuf> {
    let dest = root.join(format!("guard-plan-{id}"));
    let src = root.join("ACTUAL_GUARD_PLAN.json");
    let p = record(
        root,
        "GUARD_SEAL_PLAN.json",
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":[{"source":src,"name":"guard-plan.json","sha256":sha,"mode":292}]}),
    )?;
    run(
        SEALER,
        &strings(&[
            at(&p, "path")?,
            "--plan-sha256",
            at(&p, "sha256")?,
            "--self-sha256",
            SEALER_SHA,
        ]),
        deadline,
    )?;
    let final_path = dest.join("guard-plan.json");
    ensure!(
        json_pin(&final_path, sha)? == *actual,
        "sealed guard plan differs"
    );
    Ok(final_path)
}
fn check_fit(v: &Value) -> Result<u64> {
    let floor = v["protected_raw_floor_bytes"]
        .as_u64()
        .context("raw floor")?;
    ensure!(
        floor >= ORIGINAL_GUARD_FLOOR
            && v["root_cap_bytes"] == CAP
            && v["remaining_standard_root_bytes"]
                .as_u64()
                .is_some_and(|n| n >= SNAP_BYTES + 20_144)
            && v["standard_root_allocated_bytes"]
                .as_u64()
                .and_then(|n| n.checked_add(v["remaining_standard_root_bytes"].as_u64()?))
                == Some(CAP)
            && v["total_memory_bytes"]
                .as_u64()
                .zip(v["complete_memory_plus_reserve_bytes"].as_u64())
                .is_some_and(|(t, c)| t >= c && c > 0),
        "full fit or snapshot staging headroom invalid"
    );
    Ok(floor)
}
fn description(unit: &str) -> Result<String> {
    run(
        "/usr/bin/systemctl",
        &strings(&["show", unit, "-pDescription", "--value"]),
        bounded(),
    )
    .map(|s| s.trim_end().to_owned())
}
fn rollback(token: &str, timer_owned: Option<&str>) -> Result<()> {
    let n = show(UNIT)?;
    if n["ActiveState"] != "inactive" && n["LoadState"] != "not-found" {
        ensure!(description(UNIT)? == token, "foreign unit during rollback");
        run(
            "/usr/bin/systemctl",
            &strings(&["stop", UNIT]),
            Instant::now() + Duration::from_secs(130),
        )?;
        let n = show(UNIT)?;
        ensure!(
            n["MainPID"] == "0" && n["ActiveState"] != "active",
            "rollback did not stop producer"
        );
    }
    if let Some(id) = timer_owned {
        let t = show(TIMER)?;
        if t["ActiveState"] == "active" {
            ensure!(t["InvocationID"] == id, "foreign guard timer");
            run("/usr/bin/systemctl", &strings(&["stop", TIMER]), bounded())?;
        }
    }
    Ok(())
}
pub(super) fn launch(fleet: &Path, sha: &str, provenance: Value, pre: Value) -> Result<()> {
    let root = Path::new(BASE);
    custody(root, 0, 0, None, 0o700)?;
    let lock = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join("admission.lock"))?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "concurrent admission"
    );
    for unit in [UNIT, GUARD_SERVICE, TIMER] {
        unused(unit)?;
    }
    check_fit(&pre)?;
    let token = format!(
        "epoch{EPOCH}-trace-{}",
        fs::read_to_string("/proc/sys/kernel/random/uuid")?.trim()
    );
    let actor = producer_argv(&token)?;
    record(
        root,
        "PREFLIGHT.json",
        &json!({"fleet":binding(fleet,sha),"provenance":provenance,"measurement":pre,"producer_argv":actor}),
    )?;
    mkdir(Path::new(RECEIPTS), 0o700)?;
    mkdir(&root.join("barrier"), 0o755)?;
    for name in ["guard.stdout", "guard.stderr"] {
        exclusive(&root.join(name), &[], 0o600)?;
    }
    child_stage()?;
    let fresh = fit::inspect(fleet, sha, None)?;
    check_fit(&fresh)?;
    let selection = guard_floor::select(&fresh)?;
    let floor = selection["armed_floor_bytes"]
        .as_u64()
        .context("armed floor")?;
    record(root, "FINAL_PRELAUNCH_FIT.json", &fresh)?;
    let selection_ref = record(root, "GUARD_FLOOR_RESERVATION.json", &selection)?;
    let static_plan = record(
        root,
        "STATIC_PLAN.json",
        &plan("11111111111111111111111111111111", floor)?,
    )?;
    let validation: Value = serde_json::from_str(&run(
        GUARD,
        &strings(&[
            at(&static_plan, "path")?,
            "--plan-sha256",
            at(&static_plan, "sha256")?,
            "--self-sha256",
            GUARD_SHA,
            "--validate-plan-only",
        ]),
        bounded(),
    )?)?;
    ensure!(
        validation["validated"] == true
            && validation["plan_sha256"] == static_plan["sha256"]
            && validation["self_sha256"] == GUARD_SHA
            && validation["unit"] == UNIT
            && validation["resource_samples_taken"] == 0,
        "guard static preflight failed"
    );
    record(root, "STATIC_SCOPE.json", &validation)?;
    for unit in [UNIT, GUARD_SERVICE, TIMER] {
        unused(unit)?;
    }
    let mut owned_timer = None;
    let attempt = (|| -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(25);
        run("/usr/bin/systemd-run", &actor, deadline)?;
        let producer = show(UNIT)?;
        let id = at(&producer, "InvocationID")?;
        ensure!(
            iid(id)
                && producer["MainPID"]
                    .as_str()
                    .and_then(|p| p.parse::<u64>().ok())
                    .is_some_and(|p| p > 1)
                && producer["ActiveState"] == "active"
                && producer["SubState"] == "running"
                && producer["NRestarts"] == "0"
                && description(UNIT)? == token,
            "new producer identity"
        );
        let native = record(root, "PRODUCER_NATIVE.json", &producer)?;
        let actual = plan(id, floor)?;
        let p = record(root, "ACTUAL_GUARD_PLAN.json", &actual)?;
        let plan_sha = at(&p, "sha256")?;
        let sealed = sealed_plan(root, &actual, plan_sha, id, deadline)?;
        let argv = guard_argv(&sealed, plan_sha);
        record(root, "GUARD_ARGV.json", &json!(argv))?;
        run("/usr/bin/systemd-run", &argv, deadline)?;
        let native_timer = show(TIMER)?;
        ensure!(
            iid(at(&native_timer, "InvocationID")?) && native_timer["Triggers"] == GUARD_SERVICE,
            "guard timer did not start"
        );
        owned_timer = Some(at(&native_timer, "InvocationID")?.to_owned());
        let first = sample(Path::new(RECEIPTS), &producer, floor, plan_sha, deadline)?;
        let first_ref = record(root, "FIRST_GUARD.json", &first)?;
        let mut after = fit::inspect(fleet, sha, Some(id))?;
        let post_fit = record(root, "POST_GUARD_FIT.json", &after)?;
        check_fit(&after)?;
        let floor_check = guard_floor::post(&after, &selection)?;
        let floor_proof = record(root, "POST_GUARD_FLOOR.json", &floor_check)?;
        after["guard_floor_selection"] = selection_ref.clone();
        after["post_guard_fit"] = post_fit;
        after["post_guard_floor_proof"] = floor_proof;
        after["armed_guard_floor_bytes"] = json!(floor);
        after["complete_required_DATA_with_guard_margin_bytes"] =
            floor_check["complete_required_DATA_with_guard_margin_bytes"].clone();
        let cap = record(root, "POST_GUARD_CAPACITY.json", &after)?;
        let n = show(UNIT)?;
        ensure!(
            n["MainPID"] == producer["MainPID"]
                && n["InvocationID"] == id
                && n["ActiveState"] == "active"
                && n["NRestarts"] == "0"
                && show(TIMER)?["InvocationID"] == native_timer["InvocationID"]
                && show(TIMER)?["ActiveState"] == "active",
            "guard or producer changed"
        );
        ensure!(
            !Path::new(RECEIPTS).join("stop-intent.json").try_exists()?,
            "guard stop pending"
        );
        let entry = record(
            root,
            "AUTHORIZED_GATED_PAYLOAD.json",
            &json!({"schema":format!("epoch{EPOCH}-trace-private-guarded-payload-release-v1"),"epoch":EPOCH,"producer_unit":UNIT,"producer_invocation_id":id,"actual_native":native,"fleet":binding(fleet,sha),"protected_timer":native_timer,"guard_sample":first_ref,"actual_guard_plan":binding(&sealed,plan_sha),"capacity":cap,"actor_memory_max_bytes":68u64<<30,"entire_root_cap":CAP,"retained_original_booking_bytes":288u64<<30,"diagnostic_remaining_HOME_growth_charged_bytes":after["remaining_standard_root_bytes"],"additional_historical_DATA_booking_bytes":0,"additional_actor_memory_bytes":0,"archive_publication_authorized":false,"transaction_replay_claimed":false,"private_payload_release_authorized":true,"recorded_at":now()?}),
        )?;
        // This final atomic action releases the waiting producer; all post-guard proofs already exist.
        let barrier = root.join("barrier");
        exclusive(&barrier.join(".ready"), id.as_bytes(), 0o444)?;
        fs::rename(barrier.join(".ready"), barrier.join("allow"))?;
        File::open(&barrier)?.sync_all()?;
        let staged = staged::capture(
            id,
            at(&producer, "MainPID")?.parse()?,
            at(&native_timer, "InvocationID")?,
        )?;
        let staged_ref = record(root, "VERIFIED_STAGING.json", &staged)?;
        record(
            root,
            "ACTUAL_ADMISSION_AND_PROTECTION.json",
            &json!({"schema":format!("epoch{EPOCH}-trace-private-guarded-admission-v1"),"epoch":EPOCH,"producer_unit":UNIT,"producer_invocation_id":id,"producer_pid":at(&producer,"MainPID")?.parse::<u64>()?,"gate_release":entry,"first_guard":first_ref,"post_guard_capacity":cap,"snapshot_staging":staged_ref,"bootstrap_only":true,"bank_restoration_proven":false,"transaction_replay_claimed":false,"archive_publication_authorized":false,"recorded_at":now()?}),
        )
    })();
    match attempt {
        Ok(b) => {
            println!("{b}");
            Ok(())
        }
        Err(failure) => {
            let rolled = rollback(&token, owned_timer.as_deref());
            record(
                root,
                "FAILED_SETUP.json",
                &json!({"error":failure.to_string(),"rollback_error":rolled.as_ref().err().map(ToString::to_string),"rolled_back":rolled.is_ok(),"recorded_at":now()?,"remote_mutations":false}),
            )?;
            rolled?;
            Err(failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn producer_uses_only_the_nested_home_tree_and_sealed_payload() {
        let argv = producer_argv("metered-trace-test").unwrap();
        assert!(argv.ends_with(&strings(&["/usr/bin/env", GATE_ALIAS])));
        let mounts = argv
            .iter()
            .find_map(|a| a.strip_prefix("--property=BindReadOnlyPaths="))
            .unwrap();
        assert!(
            mounts
                .split_whitespace()
                .any(|b| b.ends_with(&format!("/{SNAP}:{SNAP_ALIAS}")))
        );
        assert!(mounts.split_whitespace().any(|b|b==format!("/var/lib/jetstreamer/horizon_runtime_data/epoch172-metered-admission-20261120-g2/inputs-v1/jetstreamer-historical-worker-v1-5-6:{NODE_PACKAGE}/jetstreamer-historical-worker-v1-5-6")));
        let writable: Vec<_> = argv
            .iter()
            .filter_map(|a| a.strip_prefix("--property=ReadWritePaths="))
            .collect();
        assert_eq!(writable, vec![DEST]);
        assert!(
            argv.iter()
                .any(|a| a.contains(&format!("{PAYLOAD}:{PAYLOAD_ALIAS}")))
        );
        assert!(
            argv.iter()
                .any(|a| a.contains(&format!("{PACKAGE}/{GATE}:{GATE_ALIAS}")))
        );
    }
    #[test]
    fn timer_requires_the_live_producer_without_starting_it() {
        let argv = guard_argv(Path::new("/sealed/guard-plan.json"), &"a".repeat(64));
        assert!(argv.contains(&format!("--timer-property=Requisite={UNIT}")));
        assert!(
            !argv
                .iter()
                .any(|a| a.contains("BindsTo=") || a.contains("Requires="))
        );
        assert!(argv.contains(&"--on-unit-inactive=5s".to_string()));
        assert!(argv.contains(&format!("--property=ReadWritePaths={RECEIPTS}")));
    }
    #[test]
    fn consumed_bootstrap_bytes_must_fit_existing_root() {
        let v = json!({"protected_raw_floor_bytes":ORIGINAL_GUARD_FLOOR,"root_cap_bytes":CAP,"remaining_standard_root_bytes":3u64<<30,"standard_root_allocated_bytes":CAP-(3u64<<30),"total_memory_bytes":810902843392u64,"complete_memory_plus_reserve_bytes":810658050048u64});
        assert_eq!(check_fit(&v).unwrap(), ORIGINAL_GUARD_FLOOR);
        let mut v = v;
        v["remaining_standard_root_bytes"] = json!(1);
        assert!(check_fit(&v).is_err());
    }
}
