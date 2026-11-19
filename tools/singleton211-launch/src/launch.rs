//! Persistent held gate, real timer first fire, then same-PID exec of the pinned full211 node.
use super::*;
// Admission sealing consumes the original wall-clock lease. Never renew it
// when converting to the single monotonic gate deadline.
fn startup_window(issued: u64, wall_us: u64, expires_s: u64) -> Result<(u64, u64)> {
    let remaining = expires_s
        .checked_mul(1_000_000)
        .and_then(|end| end.checked_sub(wall_us))
        .context("original admission expired before startup")?;
    ensure!(remaining > 0, "original admission expired before startup");
    let gate = issued
        .checked_add(remaining.min(60_000_000))
        .context("gate deadline overflow")?;
    let operator = issued
        .checked_add(remaining.min(50_000_000))
        .context("operator deadline overflow")?;
    Ok((gate, operator))
}
pub(super) fn package(attempt: &str, kind: &str) -> PathBuf {
    PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-singleton211-{kind}-{attempt}"
    ))
}
pub(super) fn safe_attempt(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub(super) fn cpus(review: &Value) -> Result<String> {
    let a = review["cpu_affinity"].as_array().context("CPU affinity")?;
    ensure!(a.len() == 16, "exactly sixteen replay CPUs required");
    let mut seen = BTreeSet::new();
    for c in a {
        let c = c.as_u64().context("CPU integer")?;
        ensure!(c < 4096 && seen.insert(c), "duplicate/invalid CPU");
    }
    Ok(seen
        .into_iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" "))
}
pub(super) fn node_args() -> Vec<String> {
    vec![
        "211".into(),
        format!("{ROOT}/output"),
        "--verify".into(),
        "--root-checkpoint-cohort".into(),
        format!("--cohort-manifest={PREFLIGHT}"),
        format!("--cohort-manifest-fingerprint={FINGERPRINT}"),
        format!("--snapshot-archive={INPUT}/{SNAPSHOT}"),
    ]
}
pub(super) fn environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("RUST_MIN_STACK".into(), "134217728".into()),
        ("SOLANA_RAYON_THREADS".into(), "16".into()),
        ("JETSTREAMER_HISTORICAL_POH_THREADS".into(), "8".into()),
        ("TOKIO_WORKER_THREADS".into(), "8".into()),
        ("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME".into(), "1".into()),
        (
            "JETSTREAMER_PRIVATE_RUN_ROOT".into(),
            format!("{ROOT}/private"),
        ),
        (
            "JETSTREAMER_HISTORICAL_WORKER_V1_6_16".into(),
            WORKER.into(),
        ),
    ])
}
pub(super) fn gate_command(plan: &Bound, self_sha: &str) -> String {
    format!(
        "{GATE} gate {} {} {self_sha}",
        plan.path.display(),
        plan.sha256
    )
}
pub(super) fn producer_template(plan: &Bound, affinity: &str, self_sha: &str) -> String {
    let env = environment()
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "[Unit]\nDescription=Epoch 211 guarded full singleton replay\n[Service]\nType=exec\nRemainAfterExit=no\nUser=ubuntu\nGroup=ubuntu\nRestart=no\nKillMode=control-group\nDelegate=no\nMemoryHigh=150000000000\nMemoryMax={MEMORY}\nMemorySwapMax=0\nTasksMax=512\nCPUQuota=1600%\nCPUAffinity={affinity}\nRuntimeMaxSec=259200\nTimeoutStopSec=30\nProtectHome=read-only\nProtectSystem=strict\nPrivateNetwork=no\nPrivateTmp=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nReadWritePaths={ROOT}\nBindReadOnlyPaths={INPUT}/genesis.tar.bz2:{ROOT}/output/genesis.tar.bz2\nUMask=0077\nEnvironment={env}\nExecStart={}\n",
        gate_command(plan, self_sha)
    )
}
pub(super) fn guard_template(guard: &Bound, plan: &Bound, receipts: &Path) -> String {
    format!(
        "[Unit]\nDescription=Epoch 211 singleton protective guard\nStartLimitIntervalSec=0\n[Service]\nType=oneshot\nUser=root\nRestart=no\nKillMode=control-group\nDelegate=no\nMemoryMax=268435456\nMemorySwapMax=0\nTasksMax=64\nCPUQuota=100%\nTimeoutStartSec=15\nProtectSystem=strict\nProtectHome=read-only\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE\nAmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE\nReadWritePaths={}\nUMask=0077\nExecStart={} {} --plan-sha256 {} --self-sha256 {}\n",
        receipts.display(),
        guard.path.display(),
        plan.path.display(),
        plan.sha256,
        guard.sha256
    )
}
pub(super) fn timer_template() -> String {
    format!(
        "[Unit]\nDescription=Epoch 211 singleton guard cadence\n[Timer]\nOnActiveSec=1s\nOnUnitActiveSec=30s\nAccuracySec=1s\nRandomizedDelaySec=0\nUnit={GUARD_UNIT}\n"
    )
}
pub(super) fn retention_template() -> String {
    format!(
        "[Unit]\nDescription=Retain epoch 211 singleton terminal evidence\nDefaultDependencies=no\nAfter={UNIT}\nIgnoreOnIsolate=yes\n"
    )
}
pub(super) fn retention(n: &mut Native, package: &Path) -> Result<Value> {
    let v = n.show(RETENTION)?;
    ensure!(
        v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "active"
            && v["After"] == UNIT
            && v["IgnoreOnIsolate"] == "yes"
            && v["DefaultDependencies"] == "no"
            && v["DropInPaths"] == ""
            && v["Job"] == ""
            && fs::canonicalize(text(&v, "FragmentPath")?)? == package.join(RETENTION),
        "terminal retention not armed"
    );
    for key in ["Wants", "Requires", "BindsTo", "Upholds"] {
        ensure!(v[key] == "", "retention has activation dependency {key}");
    }
    Ok(v)
}
pub(super) fn pristine() -> Result<()> {
    for path in [PathBuf::from(ROOT), Path::new(ROOT).join("output")] {
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            path.canonicalize()? == path
                && m.is_dir()
                && m.uid() == 1000
                && m.gid() == 1000
                && m.mode() & 0o777 == 0o700,
            "singleton directory custody"
        );
    }
    let leaves = |p: &Path| -> Result<BTreeSet<std::ffi::OsString>> {
        Ok(fs::read_dir(p)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<_>>()?)
    };
    ensure!(
        leaves(Path::new(ROOT))? == BTreeSet::from(["output".into()])
            && leaves(&Path::new(ROOT).join("output"))?
                == BTreeSet::from(["genesis.tar.bz2".into()]),
        "singleton root is not pristine"
    );
    let id = identity(&Path::new(ROOT).join("output/genesis.tar.bz2"))?;
    ensure!(
        id.2 == 0 && id.3 == 1000 && id.4 & 0o777 == 0o400,
        "genesis read-only mount placeholder differs"
    );
    Ok(())
}
fn install(from: &Path, unit: &str) -> Result<()> {
    let to = Path::new("/etc/systemd/system").join(unit);
    absent(&to)?;
    symlink(from, &to)?;
    File::open("/etc/systemd/system")?.sync_all()?;
    Ok(())
}
pub(super) fn producer(
    n: &mut Native,
    iid: Option<&str>,
    plan: &Bound,
    affinity: &str,
    self_sha: &str,
    node: bool,
) -> Result<Value> {
    let v = n.show(UNIT)?;
    producer_properties(&v, plan, affinity, self_sha)?;
    let attempt = plan
        .path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("horizon-singleton211-startup-plan-"))
        .context("producer plan namespace")?;
    ensure!(
        fs::canonicalize(text(&v, "FragmentPath")?)? == package(attempt, "producer").join(UNIT),
        "live producer fragment changed"
    );
    if let Some(iid) = iid {
        live::finite_owner(&v, UNIT, iid, MEMORY)?;
        let pid = text(&v, "MainPID")?.parse::<u64>()?;
        let mapped = PathBuf::from(format!("/proc/{pid}/exe"));
        ensure!(
            fs::read_link(&mapped)? == Path::new(if node { NODE } else { GATE })
                && metadata_identity(&fs::metadata(&mapped)?)
                    == identity(Path::new(if node { NODE } else { GATE }))?,
            "native mapped image differs"
        );
    } else {
        ensure!(
            v["ActiveState"] == "inactive"
                && v["SubState"] == "dead"
                && v["MainPID"] == "0"
                && v["ControlPID"] == "0"
                && v["Job"] == ""
                && v["InvocationID"] == "",
            "candidate started before admission"
        );
    }
    Ok(v)
}
pub(super) fn producer_properties(
    v: &Value,
    plan: &Bound,
    affinity: &str,
    self_sha: &str,
) -> Result<()> {
    let attempt = plan
        .path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("horizon-singleton211-startup-plan-"))
        .context("producer plan namespace")?;
    let expected = package(attempt, "producer").join(UNIT);
    ensure!(
        v["FragmentPath"] == json!(expected)
            || v["FragmentPath"] == format!("/etc/systemd/system/{UNIT}"),
        "producer fragment changed"
    );
    Bound::new(
        expected,
        digest(producer_template(plan, affinity, self_sha).as_bytes()),
    )
    .artifact()?;
    for (key, want) in [
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
        ("CPUQuotaPerSecUSec", "16s"),
        ("RuntimeMaxUSec", "3d"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("PrivateNetwork", "no"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("ReadWritePaths", ROOT),
        ("NRestarts", "0"),
        ("LoadState", "loaded"),
        ("DropInPaths", ""),
        ("Transient", "no"),
        ("RemainAfterExit", "no"),
    ] {
        ensure!(v[key] == want, "native sandbox changed {key}");
    }
    let actual_cpus = text(v, "CPUAffinity")?;
    // systemd may compress consecutive CPU identifiers into ranges.
    let mut actual = BTreeSet::new();
    for s in actual_cpus.split_whitespace() {
        if let Some((a, b)) = s.split_once('-') {
            let a = a.parse::<u64>()?;
            let b = b.parse::<u64>()?;
            ensure!(a <= b && b - a < 4096, "CPU range");
            actual.extend(a..=b);
        } else {
            actual.insert(s.parse::<u64>()?);
        }
    }
    let expected: BTreeSet<u64> = affinity
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(actual == expected, "CPU set changed");
    let command = format!("{{ path={GATE} ; argv[]={}", gate_command(plan, self_sha));
    ensure!(
        text(v, "ExecStart")?.split(" ; ignore_errors=").next() == Some(command.as_str()),
        "gate command changed"
    );
    let expected: BTreeSet<_> = environment()
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    ensure!(
        text(v, "Environment")?
            .split_whitespace()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            == expected,
        "replay environment differs"
    );
    ensure!(
        v["BindReadOnlyPaths"] == format!("{INPUT}/genesis.tar.bz2:{ROOT}/output/genesis.tar.bz2"),
        "genesis mount differs"
    );
    Ok(())
}
pub(super) fn first_guard(
    p: &Value,
    t: &Value,
    gp: &Value,
    g: &Value,
    j: &Value,
    clock: u64,
) -> Result<()> {
    let iid = text(t, "invocation_id")?;
    let gid = text(t, "guard_invocation_id")?;
    let pid = num(t, "main_pid")?;
    ensure!(
        hex(iid, 32) && hex(gid, 32) && iid != gid && pid > 1,
        "token identities"
    );
    let issued = num(p, "issued_monotonic_us")?;
    let expires = num(p, "expires_monotonic_us")?;
    ensure!(
        expires > issued
            && expires - issued <= 60_000_000
            && num(t, "recorded_monotonic_us")? >= issued,
        "first guard reset or lengthened original window"
    );
    ensure!(
        gp["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && gp["unit"] == UNIT
            && gp["invocation_id"] == iid
            && gp["filesystem"] == "/"
            && gp["worker_root"] == ROOT
            && gp["minimum_free_bytes"] == p["minimum_free_bytes"]
            && gp["maximum_root_physical_bytes"] == SCRATCH
            && gp["maximum_worker_vmas"] == 3500000
            && gp.get("native_main").is_none_or(Value::is_null)
            && gp.get("bounded_measurement").is_none_or(Value::is_null)
            && gp.get("bounded_canary").is_none_or(Value::is_null),
        "first native guard plan differs"
    );
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["plan"] == t["guard_plan"]["path"]
            && g["plan_sha256"] == t["guard_plan"]["sha256"]
            && g["guard_sha256"] == p["guard"]["sha256"]
            && g["guard_invocation_id"] == gid
            && g["producer_invocation_id"] == iid
            && g["producer"]["invocation_id"] == iid
            && g["producer"]["pid"] == pid
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["result"] == "success"
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer"]["restarts"] == 0
            && g["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && g["producer_stop_enabled"] == true
            && g.get("native_main") == Some(&Value::Null)
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && num(g, "available_bytes")? >= num(p, "minimum_free_bytes")?
            && g["maximum_worker_vmas"] == 3_500_000
            && g["maximum_root_physical_bytes"] == SCRATCH
            && g["root_physical_observation"]["maximum_physical_bytes"] == SCRATCH
            && g["root_physical_observation"]["exceeds_budget"] == false
            && num(
                &g["root_physical_observation"],
                "conservative_physical_bytes"
            )? <= SCRATCH
            && g["workers"].as_array().is_some_and(Vec::is_empty)
            && g["bounded_measurement"] == false
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "first guard did not protect held singleton root"
    );
    for key in [
        "trip_reason",
        "worker_observation_error",
        "root_physical_observation_error",
        "canary_target_error",
        "target_handoff_error",
        "bounded_canary",
        "target_handoff",
    ] {
        ensure!(
            g.get(key) == Some(&Value::Null),
            "guard error or missing null {key}"
        );
    }
    fresh(num(g, "recorded_unix_seconds")?, clock, 60)?;
    let rows = j.as_array().context("PID1 array")?;
    ensure!(!rows.is_empty() && rows.len() <= 64, "journal bound");
    let rows: Vec<_> = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == GUARD_UNIT
                && r["INVOCATION_ID"] == gid
                && r["_BOOT_ID"] == text(p, "boot_id").unwrap_or("").replace('-', "")
        })
        .collect();
    let start: Vec<_> = rows
        .iter()
        .filter(|r| {
            r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with(&format!("Starting {GUARD_UNIT} -")))
        })
        .collect();
    let end: Vec<_> = rows
        .iter()
        .filter(|r| r["MESSAGE"] == format!("{GUARD_UNIT}: Deactivated successfully."))
        .collect();
    ensure!(
        start.len() == 1 && end.len() == 1,
        "genuine unique PID1 first fire missing"
    );
    let start = text(start[0], "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
    let end = text(end[0], "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
    ensure!(
        start >= num(p, "issued_monotonic_us")?
            && end > start
            && end <= num(t, "recorded_monotonic_us")?
            && num(t, "recorded_monotonic_us")? < num(p, "expires_monotonic_us")?,
        "guard outside original startup window"
    );
    Ok(())
}
pub(super) fn run(
    n: &mut Native,
    review: &Value,
    review_ref: &Bound,
    self_sha: &str,
    a: &Value,
) -> Result<()> {
    let qualification = qualification::operation(review)?;
    let attempt = text(review, "attempt")?;
    ensure!(safe_attempt(attempt), "attempt namespace");
    let affinity = cpus(review)?;
    pristine()?;
    Bound::new(GATE, self_sha).artifact()?;
    inputs::validate(&binding(&review["input_capability"])?.sealed()?)?;
    let guard = binding(&review["guard"])?;
    guard.artifact()?;
    for unit in [UNIT, GUARD_UNIT, TIMER, RETENTION] {
        ensure!(
            n.show(unit)?["LoadState"] == "not-found",
            "unit name already consumed"
        );
        for dir in ["/etc/systemd/system", "/run/systemd/system"] {
            absent(&Path::new(dir).join(unit))?;
            absent(&Path::new(dir).join(format!("{unit}.d")))?;
        }
    }
    let admitted = package(attempt, "admission");
    let startup = package(attempt, "startup-plan");
    let producer_package = package(attempt, "producer");
    let guard_package = package(attempt, "guard-binding");
    let proof_package = package(attempt, "first-fire");
    let receipts = package(attempt, "guard-receipts");
    for path in [
        &admitted,
        &startup,
        &producer_package,
        &guard_package,
        &proof_package,
        &receipts,
    ] {
        absent(path)?;
    }
    let ar = save_json(&n.root, "admission.json", a)?;
    n.seal(&admitted, &[("admission.json", ar.clone())])?;
    let ar = Bound::new(admitted.join("admission.json"), ar.sha256);
    fs::create_dir(&receipts)?;
    fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700))?;
    File::open(receipts.parent().unwrap())?.sync_all()?;
    let token_root = Path::new(TOKENS);
    let m = fs::symlink_metadata(token_root)?;
    ensure!(
        token_root.canonicalize()? == token_root
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o022 == 0,
        "unsafe startup token root"
    );
    trusted_parents(&token_root.join("future"))?;
    // One original 60s gate window includes plan sealing and all manager work.
    let issued = mono()?;
    let wall_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_micros()
        .try_into()?;
    let (expires, deadline) = startup_window(issued, wall_us, num(a, "expires_unix_seconds")?)?;
    n.deadline = Some(deadline);
    let p = json!({"schema":"horizon-singleton211-startup-plan-v1","operation":review["operation"],"epoch":211,"unit":UNIT,"guard_unit":GUARD_UNIT,"worker_root":ROOT,"bootstrap_slot":91_151_575u64,
        "snapshot_sha256":SNAPSHOT_SHA,"maximum_root_physical_bytes":SCRATCH,"maximum_memory_bytes":MEMORY,"token_root":TOKENS,"boot_id":a["boot_id"],
        "gate":Bound::new(GATE,self_sha),"node":Bound::new(NODE,NODE_SHA),"worker":Bound::new(WORKER,WORKER_SHA),"input_capability":review["input_capability"],"native_input":Bound::new(NATIVE_PROOF,NATIVE_PROOF_SHA),"guard":guard,"admission":ar,"minimum_free_bytes":a["protected_existing_floor_bytes"],"issued_monotonic_us":issued,"expires_monotonic_us":expires});
    let pr = save_json(&n.root, "plan.json", &p)?;
    n.seal(&startup, &[("plan.json", pr.clone())])?;
    let pr = Bound::new(startup.join("plan.json"), pr.sha256);
    let unit = save(
        &n.root,
        UNIT,
        producer_template(&pr, &affinity, self_sha).as_bytes(),
    )?;
    let retain = save(&n.root, RETENTION, retention_template().as_bytes())?;
    n.seal(&producer_package, &[(UNIT, unit), (RETENTION, retain)])?;
    install(&producer_package.join(UNIT), UNIT)?;
    install(&producer_package.join(RETENTION), RETENTION)?;
    n.run("/usr/bin/systemctl", &["daemon-reload"])?;
    producer(n, None, &pr, &affinity, self_sha, false)?;
    n.run("/usr/bin/systemctl", &["start", RETENTION])?;
    retention(n, &producer_package)?;
    producer(n, None, &pr, &affinity, self_sha, false)?;
    // Recheck fresh capacity immediately before the first activation, without
    // rerunning Git/source hashing within the short first-fire clock.
    let latest = admission::validate(n, review, review_ref, self_sha, true)?;
    ensure!(
        latest["protected_existing_floor_bytes"] == a["protected_existing_floor_bytes"],
        "floor changed before start"
    );
    producer(n, None, &pr, &affinity, self_sha, false)?;
    n.run("/usr/bin/systemctl", &["start", "--no-block", UNIT])?;
    let first = loop {
        n.check()?;
        let v = n.show(UNIT)?;
        if v["ActiveState"] == "active" && v["SubState"] == "running" {
            break v;
        }
        ensure!(
            v["ActiveState"] == "activating" || v["Job"] != "",
            "native failed before first guard"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let iid = text(&first, "InvocationID")?.to_owned();
    ensure!(hex(&iid, 32), "native invocation missing");
    // No retry: failure retains all sealed evidence and only this exact attempt is stopped.
    let result = (|| -> Result<()> {
        let v = producer(n, Some(&iid), &pr, &affinity, self_sha, false)?;
        let pid = text(&v, "MainPID")?.parse::<u64>()?;
        let token_dest = token_root.join(&iid);
        absent(&token_dest)?;
        let guard_floor = if qualification {
            u64::MAX
        } else {
            num(a, "protected_existing_floor_bytes")?
        };
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,"filesystem":"/","minimum_free_bytes":guard_floor,"worker_root":ROOT,"maximum_root_physical_bytes":SCRATCH,"maximum_worker_vmas":3500000,"receipt_directory":receipts});
        let gr = save_json(&n.root, "guard-plan.json", &gp)?;
        let deployed_gr = Bound::new(guard_package.join("guard-plan.json"), &gr.sha256);
        let gu = save(
            &n.root,
            GUARD_UNIT,
            guard_template(&guard, &deployed_gr, &receipts).as_bytes(),
        )?;
        let tu = save(&n.root, TIMER, timer_template().as_bytes())?;
        n.seal(
            &guard_package,
            &[("guard-plan.json", gr), (GUARD_UNIT, gu), (TIMER, tu)],
        )?;
        install(&guard_package.join(GUARD_UNIT), GUARD_UNIT)?;
        install(&guard_package.join(TIMER), TIMER)?;
        n.run("/usr/bin/systemctl", &["daemon-reload"])?;
        n.run(
            guard.path.to_str().context("guard path")?,
            &[
                deployed_gr.path.to_str().context("guard plan path")?,
                "--plan-sha256",
                &deployed_gr.sha256,
                "--self-sha256",
                &guard.sha256,
                "--validate-plan-only",
            ],
        )?;
        let held = producer(n, Some(&iid), &pr, &affinity, self_sha, false)?;
        let held = if qualification {
            Some(qualification::held_capture(&held, &pr, &p)?)
        } else {
            None
        };
        n.run("/usr/bin/systemctl", &["start", TIMER])?;
        if let Some(held) = held {
            return qualification::capture_stop(
                n,
                &held,
                &pr,
                &deployed_gr,
                &producer_package,
                &guard_package,
                &receipts,
            );
        }
        let g = loop {
            n.check()?;
            let g = n.show(GUARD_UNIT)?;
            if g["ActiveState"] == "inactive"
                && g["SubState"] == "dead"
                && g["Result"] == "success"
                && g["ExecMainStatus"] == "0"
                && g["MainPID"] == "0"
                && g["ControlPID"] == "0"
                && g["Job"] == ""
                && g["InvocationID"].as_str().is_some_and(|s| hex(s, 32))
            {
                break g;
            }
            ensure!(g["ActiveState"] != "failed", "first guard failed");
            std::thread::sleep(Duration::from_millis(100));
        };
        ensure!(
            g["StartLimitIntervalUSec"] == "0" && g["DropInPaths"] == "",
            "guard rate limit/drop-ins differ"
        );
        let gid = text(&g, "InvocationID")?;
        let timer = n.show(TIMER)?;
        ensure!(
            timer["LoadState"] == "loaded"
                && timer["ActiveState"] == "active"
                && timer["SubState"] == "waiting"
                && timer["Unit"] == GUARD_UNIT
                && timer["Job"] == ""
                && timer["DropInPaths"] == "",
            "timer not armed"
        );
        let object = format!(
            "/org/freedesktop/systemd1/unit/{}",
            TIMER
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() {
                    c.to_string()
                } else {
                    format!("_{:02x}", c as u32)
                })
                .collect::<String>()
        );
        let typed = n.run(
            "/usr/bin/busctl",
            &[
                "get-property",
                "org.freedesktop.systemd1",
                &object,
                "org.freedesktop.systemd1.Timer",
                "NextElapseUSecMonotonic",
            ],
        )?;
        let words: Vec<_> = std::str::from_utf8(&typed)?.split_whitespace().collect();
        ensure!(words.len() == 2 && words[0] == "t", "typed timer deadline");
        let next = words[1].parse::<u64>()?;
        let clock = mono()?;
        ensure!(
            next > clock && next - clock <= 35_000_000,
            "timer next fire missing/late"
        );
        let sample_path = receipts.join(format!("sample-{gid}.json"));
        let sample = Bound::new(&sample_path, hash(&sample_path)?).json()?;
        for stop in ["stop-intent.json", "stop-completion.json"] {
            absent(&receipts.join(stop))?;
        }
        let raw = n.run(
            "/usr/bin/journalctl",
            &[
                "--all",
                "--no-pager",
                "--output=json",
                "--boot=0",
                "_PID=1",
                &format!("UNIT={GUARD_UNIT}"),
                &format!("INVOCATION_ID={gid}"),
            ],
        )?;
        let rows = serde_json::Deserializer::from_slice(&raw)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let journal = json!(rows);
        let sr = save_json(&n.root, "actual-first-guard-sample.json", &sample)?;
        let jr = save_json(&n.root, "actual-first-guard-PID1.json", &journal)?;
        n.seal(
            &proof_package,
            &[
                ("guard-sample.json", sr.clone()),
                ("guard-PID1.json", jr.clone()),
            ],
        )?;
        let mut token = json!({"schema":"horizon-singleton211-first-guard-token-v1","startup_plan_sha256":pr.sha256,"unit":UNIT,"invocation_id":iid,"main_pid":pid,"gate":p["gate"],"node":p["node"],"worker":p["worker"],"guard":guard,"boot_id":p["boot_id"],"admission":ar,"guard_invocation_id":gid,"guard_plan":deployed_gr,
            "guard_sample":Bound::new(proof_package.join("guard-sample.json"),sr.sha256),"guard_pid1_journal":Bound::new(proof_package.join("guard-PID1.json"),jr.sha256),"recorded_monotonic_us":mono()?});
        deny_authority(&mut token);
        token["replay_launch_authorized"] = json!(true);
        first_guard(&p, &token, &gp, &sample, &journal, now()?)?;
        let latest = admission::validate(n, review, review_ref, self_sha, true)?;
        ensure!(
            latest["protected_existing_floor_bytes"] == a["protected_existing_floor_bytes"],
            "changed floor before token"
        );
        producer(n, Some(&iid), &pr, &affinity, self_sha, false)?;
        gate::held(pid, &iid)?;
        let tr = save_json(&n.root, "guard-admission.json", &token)?;
        let ts = save(
            &n.root,
            "guard-admission.sha256",
            format!("{}\n", tr.sha256).as_bytes(),
        )?;
        n.seal(
            &token_dest,
            &[
                ("guard-admission.json", tr.clone()),
                ("guard-admission.sha256", ts),
            ],
        )?;
        n.check()?;
        let producer = loop {
            n.check()?;
            let mapped = fs::read_link(format!("/proc/{pid}/exe"))?;
            if mapped == Path::new(NODE) {
                break producer(n, Some(&iid), &pr, &affinity, self_sha, true)?;
            }
            ensure!(mapped == Path::new(GATE), "unexpected transition image");
            std::thread::sleep(Duration::from_millis(20));
        };
        let retain = retention(n, &producer_package)?;
        let unit_file = Bound::new(
            producer_package.join(UNIT),
            hash(&producer_package.join(UNIT))?,
        );
        let mut handoff = json!({"schema":"horizon-singleton211-guarded-startup-v1","unit":UNIT,"invocation_id":iid,"main_pid":pid,"producer":producer,"unit_file":unit_file,"retention":retain,"startup_plan":pr,"admission":ar,"guard_plan":deployed_gr,"first_guard_sample":token["guard_sample"],"first_guard_pid1_journal":token["guard_pid1_journal"],"first_guard_token":Bound::new(token_dest.join("guard-admission.json"),tr.sha256),"recorded_monotonic_us":mono()?,"recorded_unix_seconds":now()?,"native_input_qualified":true,"entry_replay_observed":false,"native_input":Bound::new(NATIVE_PROOF,NATIVE_PROOF_SHA),"node":p["node"],"worker":p["worker"],"input_capability":p["input_capability"],"epoch":211,"output_slot_start":91152000u64,"terminal_slot":91583999u64,"canonical_root_slot":91583512u64,"post_root_slot_count":487,"output_slot_count":432000});
        ensure!(
            num(&handoff, "recorded_unix_seconds")? <= num(a, "expires_unix_seconds")?
                && num(&handoff, "recorded_monotonic_us")? < expires,
            "original admission expired before handoff"
        );
        deny_authority(&mut handoff);
        handoff["replay_launch_authorized"] = json!(true);
        handoff["launched"] = json!(true);
        handoff["private_run_root"] = json!(ROOT);
        handoff["launcher_sha256"] = json!(self_sha);
        handoff["guard_sha256"] = json!(guard.sha256);
        handoff["same_pid_exec_observed"] = json!(true);
        lifecycle::validate_handoff(&handoff)?;
        let h = save_json(&n.root, "guarded-startup-handoff.json", &handoff)?;
        println!("{}", serde_json::to_string(&h)?);
        Ok(())
    })();
    if result.is_err() {
        n.deadline = None;
        if let Ok(v) = n.show(UNIT)
            && v["InvocationID"] == iid
            && matches!(v["ActiveState"].as_str(), Some("active" | "activating"))
        {
            let _ = n.run("/usr/bin/systemctl", &["stop", "--no-block", UNIT]);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_guard_requires_real_held_gate_sample_and_original_pid1_window() {
        let p = json!({"boot_id":"00000000-0000-0000-0000-000000000001","guard":{"sha256":"d".repeat(64)},"minimum_free_bytes":100,"issued_monotonic_us":1000,"expires_monotonic_us":60_001_000});
        let t = json!({"invocation_id":"a".repeat(32),"guard_invocation_id":"b".repeat(32),"main_pid":42,"guard_plan":{"path":"/var/lib/jetstreamer/guard/plan.json","sha256":"c".repeat(64)},"recorded_monotonic_us":3000});
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":t["invocation_id"],"filesystem":"/","worker_root":ROOT,"minimum_free_bytes":100,"maximum_root_physical_bytes":SCRATCH,"maximum_worker_vmas":3500000});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","plan":t["guard_plan"]["path"],"plan_sha256":t["guard_plan"]["sha256"],"guard_sha256":"d".repeat(64),"guard_invocation_id":t["guard_invocation_id"],"producer_invocation_id":t["invocation_id"],
            "producer":{"invocation_id":t["invocation_id"],"pid":42,"active":"active","sub":"running","load_state":"loaded","result":"success","restart_policy":"no","kill_mode":"control-group","delegated":false,"restarts":0,"cgroup":format!("/system.slice/{UNIT}")},"producer_stop_enabled":true,"native_main":gp["native_main"],"minimum_free_bytes":100,"available_bytes":101,"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":SCRATCH,"root_physical_observation":{"maximum_physical_bytes":SCRATCH,"exceeds_budget":false,"conservative_physical_bytes":1},"workers":[],"bounded_measurement":false,"remote_mutations":false,"r2_mutations":false,"recorded_unix_seconds":100,
            "trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"canary_target_error":null,"target_handoff_error":null,"bounded_canary":null,"target_handoff":null});
        let row = |message: String, clock: &str| json!({"_PID":"1","_UID":"0","UNIT":GUARD_UNIT,"INVOCATION_ID":t["guard_invocation_id"],"_BOOT_ID":"00000000000000000000000000000001","MESSAGE":message,"__MONOTONIC_TIMESTAMP":clock});
        let j = json!([
            row(format!("Starting {GUARD_UNIT} - guard..."), "1001"),
            row(format!("{GUARD_UNIT}: Deactivated successfully."), "2000")
        ]);
        first_guard(&p, &t, &gp, &g, &j, 100).unwrap();
        for (pointer, value) in [
            ("/producer_stop_enabled", json!(false)),
            ("/producer/pid", json!(43)),
            ("/producer/restarts", json!(1)),
            ("/workers", json!([[43, 10]])),
            ("/native_main", json!({"main_pid":42})),
            ("/bounded_measurement", json!(true)),
            ("/trip_reason", json!("floor")),
            ("/recorded_unix_seconds", json!(39)),
            ("/recorded_unix_seconds", json!(101)),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                first_guard(&p, &t, &gp, &bad, &j, 100).is_err(),
                "{pointer}"
            );
        }
        for (pointer, value) in [
            ("/0/_PID", json!("42")),
            ("/1/INVOCATION_ID", json!("c".repeat(32))),
            ("/0/__MONOTONIC_TIMESTAMP", json!("999")),
            ("/1/__MONOTONIC_TIMESTAMP", json!("3001")),
            ("/1/_BOOT_ID", json!("0".repeat(32))),
        ] {
            let mut bad = j.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                first_guard(&p, &t, &gp, &g, &bad, 100).is_err(),
                "{pointer}"
            );
        }
        assert!(first_guard(&p, &t, &gp, &g, &json!([j[0], j[0], j[1]]), 100).is_err());
        let mut missing = g.clone();
        missing.as_object_mut().unwrap().remove("trip_reason");
        assert!(first_guard(&p, &t, &gp, &missing, &j, 100).is_err());
        for key in gp.as_object().unwrap().keys() {
            let mut bad = gp.clone();
            bad[key] = Value::Null;
            assert!(
                first_guard(&p, &t, &bad, &g, &j, 100).is_err(),
                "plan {key}"
            );
        }
        for (key, value) in [
            ("issued_monotonic_us", json!(2001)),
            ("expires_monotonic_us", json!(60_001_001)),
            ("expires_monotonic_us", json!(3000)),
        ] {
            let mut bad = p.clone();
            bad[key] = value;
            assert!(
                first_guard(&bad, &t, &gp, &g, &j, 100).is_err(),
                "clock {key}"
            );
        }
        let retention = retention_template();
        assert!(retention.contains(&format!("After={UNIT}\n")));
        for forbidden in ["Wants=", "Requires=", "BindsTo=", "Upholds=", "[Install]"] {
            assert!(!retention.contains(forbidden));
        }
    }
}
