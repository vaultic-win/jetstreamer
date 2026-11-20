//! Persistent native unit, real timer first fire, and one invocation-bound token.
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
fn package(attempt: &str, kind: &str) -> PathBuf {
    PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-native265-{kind}-{attempt}"
    ))
}
fn safe_attempt(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn cpus(review: &Value) -> Result<String> {
    let a = review["cpu_affinity"].as_array().context("CPU affinity")?;
    ensure!(a.len() == 8, "exactly eight native CPUs required");
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
fn native_template(plan: &Bound, affinity: &str) -> String {
    format!(
        "[Unit]\nDescription=Epoch 265 gated native cold input qualification\n[Service]\nType=exec\nRemainAfterExit=no\nUser=ubuntu\nGroup=ubuntu\nRestart=no\nKillMode=control-group\nDelegate=no\nMemoryHigh=100000000000\nMemoryMax={MEMORY}\nMemorySwapMax=0\nTasksMax=512\nCPUQuota=800%\nCPUAffinity={affinity}\nRuntimeMaxSec=2700\nTimeoutStopSec=30\nProtectHome=read-only\nProtectSystem=strict\nPrivateNetwork=yes\nPrivateTmp=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nReadWritePaths={ROOT}\nUMask=0077\nEnvironment=RUST_MIN_STACK=134217728 SOLANA_RAYON_THREADS=8 JETSTREAMER_HISTORICAL_POH_THREADS=2 JETSTREAMER_EPOCH265_STARTUP_PLAN={} JETSTREAMER_EPOCH265_STARTUP_PLAN_SHA256={}\nExecStart={HARNESS}\n",
        plan.path.display(),
        plan.sha256
    )
}
fn guard_template(guard: &Bound, plan: &Bound, receipts: &Path) -> String {
    format!(
        "[Unit]\nDescription=Epoch 265 native protective guard\nStartLimitIntervalSec=0\n[Service]\nType=oneshot\nUser=root\nRestart=no\nKillMode=control-group\nDelegate=no\nMemoryMax=268435456\nMemorySwapMax=0\nTasksMax=64\nCPUQuota=100%\nTimeoutStartSec=60\nProtectSystem=strict\nProtectHome=read-only\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE\nAmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE\nReadWritePaths={}\nUMask=0077\nExecStart={} {} --plan-sha256 {} --self-sha256 {}\n",
        receipts.display(),
        guard.path.display(),
        plan.path.display(),
        plan.sha256,
        guard.sha256
    )
}
fn timer_template() -> String {
    format!(
        "[Unit]\nDescription=Epoch 265 native guard cadence\n[Timer]\nOnActiveSec=1s\nOnUnitActiveSec=30s\nAccuracySec=1s\nRandomizedDelaySec=0\nUnit={GUARD_UNIT}\n"
    )
}
fn retention_template() -> String {
    format!(
        "[Unit]\nDescription=Retain epoch 265 native terminal evidence\nDefaultDependencies=no\nAfter={UNIT}\nIgnoreOnIsolate=yes\n"
    )
}
fn retention(n: &mut Native, package: &Path) -> Result<Value> {
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
fn pristine() -> Result<()> {
    let root = Path::new(ROOT);
    let m = fs::symlink_metadata(root)?;
    ensure!(
        root.canonicalize()? == root
            && m.is_dir()
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o777 == 0o700,
        "native root custody"
    );
    ensure!(
        fs::read_dir(root)?.next().is_none(),
        "native265 root must remain empty before first gate"
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
fn producer(n: &mut Native, iid: Option<&str>, plan: &Bound, affinity: &str) -> Result<Value> {
    let v = n.show(UNIT)?;
    let attempt = plan
        .path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("horizon-native265-startup-plan-"))
        .context("producer plan namespace")?;
    let expected = package(attempt, "producer").join(UNIT);
    ensure!(
        fs::canonicalize(text(&v, "FragmentPath")?)? == expected,
        "producer fragment changed"
    );
    Bound::new(expected, digest(native_template(plan, affinity).as_bytes())).artifact()?;
    for (key, want) in [
        ("Type", "exec"),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "100000000000"),
        ("MemoryMax", "128000000000"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("RuntimeMaxUSec", "45min"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("PrivateNetwork", "yes"),
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
    let actual_cpus = text(&v, "CPUAffinity")?;
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
    let command = format!("{{ path={HARNESS} ; argv[]={HARNESS}");
    ensure!(
        periodic::stable_command(text(&v, "ExecStart")?)?
            == format!("{command} ; ignore_errors=no"),
        "native command changed"
    );
    let expected: BTreeSet<_> = [
        "RUST_MIN_STACK=134217728".into(),
        "SOLANA_RAYON_THREADS=8".into(),
        "JETSTREAMER_HISTORICAL_POH_THREADS=2".into(),
        format!("JETSTREAMER_EPOCH265_STARTUP_PLAN={}", plan.path.display()),
        format!("JETSTREAMER_EPOCH265_STARTUP_PLAN_SHA256={}", plan.sha256),
    ]
    .into_iter()
    .collect();
    ensure!(
        text(&v, "Environment")?
            .split_whitespace()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            == expected,
        "native environment differs"
    );
    if let Some(iid) = iid {
        live::finite_owner(&v, UNIT, iid, MEMORY)?;
        let pid = text(&v, "MainPID")?.parse::<u64>()?;
        let mapped = PathBuf::from(format!("/proc/{pid}/exe"));
        ensure!(
            fs::read_link(&mapped)? == Path::new(HARNESS)
                && metadata_identity(&fs::metadata(&mapped)?) == identity(Path::new(HARNESS))?,
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
use crate::first_guard::first_guard;
pub(super) fn run(
    n: &mut Native,
    review: &Value,
    review_ref: &Bound,
    self_sha: &str,
    a: &Value,
) -> Result<()> {
    let attempt = text(review, "attempt")?;
    ensure!(safe_attempt(attempt), "attempt namespace");
    let affinity = cpus(review)?;
    pristine()?;
    Bound::new(HARNESS, HARNESS_SHA).artifact()?;
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

    for path in [
        &admitted,
        &startup,
        &producer_package,
        &guard_package,
        &proof_package,
    ] {
        absent(path)?;
    }
    let ar = save_json(&n.root, "admission.json", a)?;
    n.seal(&admitted, &[("admission.json", ar.clone())])?;
    let ar = Bound::new(admitted.join("admission.json"), ar.sha256);
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
    let p = json!({"schema":"horizon-native265-startup-plan-v1","epoch":265,"unit":UNIT,"guard_unit":GUARD_UNIT,"worker_root":ROOT,"bootstrap_slot":114_479_281u64,
        "snapshot_sha256":SNAPSHOT_SHA,"maximum_root_physical_bytes":SCRATCH,"maximum_memory_bytes":MEMORY,"token_root":TOKENS,"boot_id":a["boot_id"],
        "harness":Bound::new(HARNESS,HARNESS_SHA),"worker":Bound::new(WORKER,WORKER_SHA),"input_packet":Bound::new(PACKET,PACKET_SHA),"genesis_sha256":GENESIS_SHA,"guard":guard,"admission":ar,"minimum_free_bytes":a["protected_existing_floor_bytes"],"issued_monotonic_us":issued,"expires_monotonic_us":expires});
    let pr = save_json(&n.root, "plan.json", &p)?;
    n.seal(&startup, &[("plan.json", pr.clone())])?;
    let pr = Bound::new(startup.join("plan.json"), pr.sha256);
    let unit = save(&n.root, UNIT, native_template(&pr, &affinity).as_bytes())?;
    let retain = save(&n.root, RETENTION, retention_template().as_bytes())?;
    n.seal(&producer_package, &[(UNIT, unit), (RETENTION, retain)])?;
    install(&producer_package.join(UNIT), UNIT)?;
    install(&producer_package.join(RETENTION), RETENTION)?;
    n.run("/usr/bin/systemctl", &["daemon-reload"])?;
    producer(n, None, &pr, &affinity)?;
    n.run("/usr/bin/systemctl", &["start", RETENTION])?;
    retention(n, &producer_package)?;
    producer(n, None, &pr, &affinity)?;
    // Recheck fresh capacity immediately before the first activation, without
    // rerunning Git/source hashing within the short first-fire clock.
    let latest = admission::validate(n, review, review_ref, self_sha, true)?;
    ensure!(
        latest["protected_existing_floor_bytes"] == a["protected_existing_floor_bytes"],
        "floor changed before start"
    );
    producer(n, None, &pr, &affinity)?;
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
        let v = producer(n, Some(&iid), &pr, &affinity)?;
        let pid = text(&v, "MainPID")?.parse::<u64>()?;
        let receipts = PathBuf::from(format!(
            "/var/lib/jetstreamer/horizon-native265-guard-receipts-{iid}"
        ));
        absent(&receipts)?;
        fs::create_dir(&receipts)?;
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700))?;
        File::open(receipts.parent().unwrap())?.sync_all()?;
        let main_stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let start_ticks = main_stat
            .rsplit_once(')')
            .context("main stat")?
            .1
            .split_whitespace()
            .nth(19)
            .context("main ticks")?
            .parse::<u64>()?;
        let guard_floor = if review["operation"] == "qualify-guard" {
            u64::MAX
        } else {
            num(a, "protected_existing_floor_bytes")?
        };
        let token_dest = token_root.join(&iid);
        absent(&token_dest)?;
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,"filesystem":"/","minimum_free_bytes":guard_floor,"boot_id":a["boot_id"],"main_start_ticks":start_ticks,"worker_root":ROOT,"maximum_root_physical_bytes":SCRATCH,"maximum_worker_vmas":3500000,"receipt_directory":receipts,"native_main":{"main_pid":pid,"executable":HARNESS,"sha256":HARNESS_SHA}});
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
        producer(n, Some(&iid), &pr, &affinity)?;
        n.run("/usr/bin/systemctl", &["start", TIMER])?;
        if review["operation"] == "qualify-guard" {
            return qualification::capture_stop(
                n,
                &iid,
                pid,
                &receipts,
                &deployed_gr,
                &pr,
                &producer_package,
                &guard_package,
                &p,
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
        let mut token = json!({"schema":"horizon-native265-first-guard-token-v1","startup_plan_sha256":pr.sha256,"unit":UNIT,"invocation_id":iid,"main_pid":pid,"harness":p["harness"],"guard":guard,"boot_id":p["boot_id"],"admission":ar,"guard_invocation_id":gid,"guard_plan":deployed_gr,
            "guard_sample":Bound::new(proof_package.join("guard-sample.json"),sr.sha256),"guard_pid1_journal":Bound::new(proof_package.join("guard-PID1.json"),jr.sha256),"recorded_monotonic_us":mono()?});
        deny_authority(&mut token);
        first_guard(&p, &token, &gp, &sample, &journal, now()?)?;
        let latest = admission::validate(n, review, review_ref, self_sha, true)?;
        ensure!(
            latest["protected_existing_floor_bytes"] == a["protected_existing_floor_bytes"],
            "changed floor before token"
        );
        producer(n, Some(&iid), &pr, &affinity)?;
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
        let producer = producer(n, Some(&iid), &pr, &affinity)?;
        let retain = retention(n, &producer_package)?;
        let unit_file = Bound::new(
            producer_package.join(UNIT),
            hash(&producer_package.join(UNIT))?,
        );
        let mut handoff = json!({"schema":"horizon-native265-guarded-startup-v1","unit":UNIT,"invocation_id":iid,"main_pid":pid,"producer":producer,"unit_file":unit_file,"retention":retain,"startup_plan":pr,"admission":ar,"guard_plan":deployed_gr,"first_guard_sample":token["guard_sample"],"first_guard_pid1_journal":token["guard_pid1_journal"],"first_guard_token":Bound::new(token_dest.join("guard-admission.json"),tr.sha256),"recorded_monotonic_us":mono()?,"recorded_unix_seconds":now()?,"native_input_qualified":false});
        ensure!(
            num(&handoff, "recorded_unix_seconds")? <= num(a, "expires_unix_seconds")?
                && num(&handoff, "recorded_monotonic_us")? < expires,
            "original admission expired before handoff"
        );
        deny_authority(&mut handoff);
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
    fn sealing_delay_consumes_original_admission_lease() {
        assert_eq!(
            startup_window(10, 100_000_000, 160).unwrap(),
            (60_000_010, 50_000_010)
        );
        assert_eq!(
            startup_window(10, 152_500_000, 160).unwrap(),
            (7_500_010, 7_500_010)
        );
        assert!(startup_window(10, 160_000_000, 160).is_err());
        assert!(startup_window(10, 161_000_000, 160).is_err());
        assert!(startup_window(u64::MAX, 100_000_000, 160).is_err());
    }
    #[test]
    fn native_template_uses_internal_gate_and_exact_harness() {
        let p = Bound::new(
            "/var/lib/jetstreamer/horizon-native265-startup-plan-test/plan.json",
            "a".repeat(64),
        );
        let unit = native_template(&p, "0 1 2 3 4 5 6 7");
        assert!(!unit.contains("ExecStartPre"));
        assert!(unit.contains("JETSTREAMER_EPOCH265_STARTUP_PLAN="));
        assert!(unit.contains(&format!("ExecStart={HARNESS}")));
        assert!(unit.contains("MemorySwapMax=0\n"));
        assert!(unit.contains("PrivateNetwork=yes\n"));
    }
    #[test]
    fn attempts_and_affinity_reject_template_injection() {
        for s in ["", "../bad", "attempt\nExecStart=bad", "a b"] {
            assert!(!safe_attempt(s));
        }
        assert!(safe_attempt("20261119-v1"));
        assert!(cpus(&json!({"cpu_affinity":[0,1,2,3,4,5,6,7]})).is_ok());
        assert!(cpus(&json!({"cpu_affinity":[0,1,2,3,4,5,6,6]})).is_err());
        assert!(cpus(&json!({"cpu_affinity":[0,1,2,3,4,5,6,"7\n"]})).is_err());
    }
    #[test]
    fn retention_orders_without_activation_edges() {
        let retention = retention_template();
        assert!(retention.contains(&format!("After={UNIT}\n")));
        for forbidden in ["Wants=", "Requires=", "BindsTo=", "Upholds=", "[Install]"] {
            assert!(!retention.contains(forbidden));
        }
    }
}
