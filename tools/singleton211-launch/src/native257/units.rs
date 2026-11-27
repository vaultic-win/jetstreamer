// Load inert definitions and a mandatory future EnvironmentFile before the admission clock.
use super::*;
use crate::prepare::{Argument, env_properties, seal_pair, verify_pair};

pub(super) const STARTUP: Argument = Argument {
    variable: PLAN_SHA_ENV,
    env: "startup.env",
    plan: "plan.json",
};
pub(super) const GUARD_ARG: Argument = Argument {
    variable: GUARD_SHA_ENV,
    env: "guard.env",
    plan: "guard-plan.json",
};
pub(super) fn parse_cpu_list(raw: &str) -> Result<BTreeSet<u64>> {
    let mut values = BTreeSet::new();
    for token in raw.trim().split(',') {
        let (left, right) = token.split_once('-').unwrap_or((token, token));
        let (lo, hi) = (left.parse::<u64>()?, right.parse::<u64>()?);
        ensure!(lo <= hi && hi < 4096, "invalid CPU extent");
        for cpu in lo..=hi {
            ensure!(values.insert(cpu), "repeated CPU");
        }
    }
    Ok(values)
}
pub(super) fn affinity(review: &Value) -> Result<String> {
    affinity_width(review, 8)
}

pub(super) fn affinity_width(review: &Value, count: usize) -> Result<String> {
    let a = review["cpu_affinity"].as_array().context("CPU affinity")?;
    ensure!(a.len() == count, "exactly {count} native CPUs required");
    let mut seen = BTreeSet::new();
    for c in a {
        let c = c.as_u64().context("CPU integer")?;
        ensure!(c < 4096 && seen.insert(c), "duplicate/invalid CPU");
    }
    let online = parse_cpu_list(&fs::read_to_string("/sys/devices/system/cpu/online")?)?;
    let cpuset = parse_cpu_list(&fs::read_to_string(
        "/sys/fs/cgroup/system.slice/cpuset.cpus.effective",
    )?)?;
    ensure!(
        seen.is_subset(&online) && seen.is_subset(&cpuset),
        "selected CPU outside online system slice"
    );
    Ok(seen
        .into_iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" "))
}
fn native_template(plan: &Bound, affinity: &str) -> String {
    let timeout = if EPOCH == 266 { 7200 } else { 2700 };
    format!(
        "[Unit]\nDescription=Epoch {EPOCH} gated native cold input qualification\n[Service]\nType=exec\nRemainAfterExit=no\nUser=ubuntu\nGroup=ubuntu\nRestart=no\nKillMode=control-group\nDelegate=no\nMemoryHigh=100000000000\nMemoryMax={MEMORY}\nMemorySwapMax=0\nTasksMax=512\nCPUQuota=800%\nCPUAffinity={affinity}\nRuntimeMaxSec={timeout}\nTimeoutStopSec=30\nProtectHome=read-only\nProtectSystem=strict\nPrivateNetwork=yes\n{PRODUCER_SANDBOX}NoNewPrivileges=yes\nCapabilityBoundingSet=\nReadWritePaths={ROOT}\nUMask=0077\nEnvironment=RUST_MIN_STACK=134217728 SOLANA_RAYON_THREADS=8 JETSTREAMER_HISTORICAL_POH_THREADS=2 {PLAN_ENV}={}\nEnvironmentFile={}\nExecStart={HARNESS}\n",
        plan.path.display(),
        plan.path.with_file_name("startup.env").display()
    )
}
fn guard_template(guard: &Bound, plan: &Path, receipts: &Path) -> String {
    let guard_sandbox = if matches!(EPOCH, 212 | 266) {
        "ProtectControlGroups=yes\nPrivateTmp=yes\n"
    } else {
        ""
    };
    format!(
        "[Unit]\nDescription=Epoch {EPOCH} native protective guard\nStartLimitIntervalSec=0\n[Service]\nType=oneshot\nUser=root\nRestart=no\nKillMode=control-group\nDelegate=no\nMemoryMax=268435456\nMemorySwapMax=0\nTasksMax=64\nCPUQuota=100%\nTimeoutStartSec=60\nProtectSystem=strict\nProtectHome=read-only\nPrivateNetwork=yes\n{guard_sandbox}NoNewPrivileges=yes\nCapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE\nAmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE\nReadWritePaths={}\nUMask=0077\nEnvironmentFile={}\nExecStart={} {} --plan-sha256 ${{{GUARD_SHA_ENV}}} --self-sha256 {}\n",
        receipts.display(),
        plan.with_file_name("guard.env").display(),
        guard.path.display(),
        plan.display(),
        guard.sha256
    )
}
fn timer_template() -> String {
    format!(
        "[Unit]\nDescription=Epoch {EPOCH} native guard cadence\n[Timer]\nOnActiveSec=1s\nOnUnitActiveSec=30s\nAccuracySec=1s\nRandomizedDelaySec=0\nUnit={GUARD_UNIT}\n"
    )
}
fn retention_template() -> String {
    format!(
        "[Unit]\nDescription=Retain epoch {RETENTION_DESCRIPTION_EPOCH} native terminal evidence\nDefaultDependencies=no\nAfter={UNIT} {GUARD_UNIT} {TIMER}\nIgnoreOnIsolate=yes\n"
    )
}
pub(super) fn retention(n: &mut Native, package: &Path) -> Result<Value> {
    let v = n.show(RETENTION)?;
    ensure!(
        v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "active"
            && retains_all(&v)?
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
        "native root must remain empty before first gate"
    );
    Ok(())
}
fn kernel_cpus(pid: u64) -> Result<BTreeSet<u64>> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    parse_cpu_list(
        status
            .lines()
            .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
            .context("missing kernel CPU mask")?
            .trim(),
    )
}
pub(crate) fn cpu_sharing(n: &mut Native, r: &Value) -> Result<Value> {
    let selected = affinity(r)?
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    let fleet = binding(&r["fleet"])?.json()?;
    let mut shared = BTreeMap::new();
    let mut rows = Vec::new();
    for row in fleet["active"].as_array().context("active fleet")? {
        let Some(peer) = peer_window::protected_owner(EPOCH, row) else {
            continue;
        };
        let name = text(peer, "Id")?;
        let current = n.show(name)?;
        live::same_owner(peer, &current)?;
        let pid = text(&current, "MainPID")?.parse()?;
        let cpus = kernel_cpus(pid)?;
        let cross: Vec<_> = selected.intersection(&cpus).copied().collect();
        if !cross.is_empty() {
            shared.insert(name.to_owned(), cross.clone());
        }
        live::same_owner(&current, &n.show(name)?)?;
        rows.push(json!({"unit":name,"invocation_id":current["InvocationID"],"pid":pid,"cpus":cpus,"shared_with_candidate":cross}));
    }
    ensure!(
        r["reviewed_cpu_overlap"] == json!(shared),
        "CPU sharing differs from Main's allocation"
    );
    Ok(json!({"selected":selected,"reviewed_cpu_overlap":shared,"observed_peers":rows}))
}
pub(super) fn producer(
    n: &mut Native,
    iid: Option<&str>,
    plan: &Bound,
    affinity: &str,
) -> Result<Value> {
    let v = n.show(UNIT)?;
    let attempt = plan
        .path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix(PLAN_PREFIX))
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
        ("MemoryMax", MEMORY.to_string().as_str()),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("RuntimeMaxUSec", if EPOCH == 266 { "2h" } else { "45min" }),
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
    check_sandbox(&v)?;
    verify_pair(plan, STARTUP)?;
    super::super::prepare::env_properties(&v, &plan.path.with_file_name("startup.env"))?;
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
        format!("{PLAN_ENV}={}", plan.path.display()),
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
        ensure!(
            kernel_cpus(pid)?
                == affinity
                    .split_whitespace()
                    .map(str::parse)
                    .collect::<std::result::Result<BTreeSet<_>, _>>()?,
            "kernel CPU set changed"
        );
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

pub(super) fn bind_plan(
    n: &mut Native,
    dest: &Path,
    value: &Bound,
    arg: Argument,
) -> Result<Bound> {
    seal_pair(n, dest, value, arg)
}
fn retains_all(v: &Value) -> Result<bool> {
    let parts: Vec<_> = text(v, "After")?.split_whitespace().collect();
    Ok(parts.len() == 3
        && parts.into_iter().collect::<BTreeSet<_>>() == BTreeSet::from([UNIT, GUARD_UNIT, TIMER]))
}
pub(super) fn guard_properties(v: &Value, guard: &Bound, plan: &Path, alias: &Path) -> Result<()> {
    env_properties(v, &plan.with_file_name(GUARD_ARG.env))?;
    ensure!(
        v["Environment"] == ""
            && v["Id"] == GUARD_UNIT
            && v["User"] == "root"
            && v["Type"] == "oneshot"
            && v["Restart"] == "no"
            && v["MemoryMax"] == "268435456"
            && v["MemorySwapMax"] == "0"
            && v["TasksMax"] == "64"
            && v["ReadWritePaths"].as_str() == alias.to_str()
            && v["StartLimitIntervalUSec"] == "0"
            && periodic::stable_command(text(v, "ExecStart")?)?
                == format!(
                    "{{ path={} ; argv[]={} {} --plan-sha256 ${{{GUARD_SHA_ENV}}} --self-sha256 {} ; ignore_errors=no",
                    guard.path.display(),
                    guard.path.display(),
                    plan.display(),
                    guard.sha256
                ),
        "prepared guard resources or command differs"
    );
    Ok(())
}
fn definitions(r: &Value) -> Result<Vec<(&'static str, PathBuf, String)>> {
    let attempt = text(r, "attempt")?;
    ensure!(crate::launch::safe_attempt(attempt), "attempt");
    let producer = package(attempt, "producer");
    let guards = package(attempt, "guard-units");
    let startup = Bound::new(package(attempt, "startup-plan").join("plan.json"), "");
    let gp = package(attempt, "guard-binding").join("guard-plan.json");
    let alias = package(attempt, "receipt-mount");
    Ok(vec![
        (
            UNIT,
            producer.join(UNIT),
            native_template(&startup, &affinity(r)?),
        ),
        (RETENTION, producer.join(RETENTION), retention_template()),
        (
            GUARD_UNIT,
            guards.join(GUARD_UNIT),
            guard_template(&Bound::new(GUARD, GUARD_SHA), &gp, &alias),
        ),
        (TIMER, guards.join(TIMER), timer_template()),
    ])
}
fn loaded(n: &mut Native, review: &Value) -> Result<Value> {
    let attempt = text(review, "attempt")?;
    let mut owned = BTreeMap::new();
    for (unit, path, template) in definitions(review)? {
        let link = Path::new("/etc/systemd/system").join(unit);
        let m = fs::symlink_metadata(&link)?;
        ensure!(
            m.file_type().is_symlink() && m.uid() == 0 && fs::read_link(&link)? == path,
            "candidate unit link changed"
        );
        for root in ["/etc/systemd/system", "/run/systemd/system"] {
            absent(&Path::new(root).join(format!("{unit}.d")))?;
        }
        absent(&Path::new("/run/systemd/system").join(unit))?;
        let b = Bound::new(&path, digest(template.as_bytes()));
        trusted_parents(&path)?;
        ensure!(
            b.bytes(true)? == template.as_bytes(),
            "candidate template changed"
        );
        let v = n.show(unit)?;
        ensure!(
            v["Id"] == unit
                && v["LoadState"] == "loaded"
                && v["ActiveState"] == "inactive"
                && v["SubState"] == "dead"
                && v["Job"] == ""
                && v["InvocationID"] == ""
                && v["DropInPaths"] == ""
                && fs::canonicalize(text(&v, "FragmentPath")?)? == path,
            "candidate unit is stale or consumed"
        );
        match unit {
            UNIT => {
                let pr = package(attempt, "startup-plan").join(STARTUP.plan);
                env_properties(&v, &pr.with_file_name(STARTUP.env))?;
                let cmd = format!("{{ path={HARNESS} ; argv[]={HARNESS} ; ignore_errors=no");
                ensure!(
                    periodic::stable_command(text(&v, "ExecStart")?)? == cmd,
                    "prepared producer command differs"
                );
            }
            GUARD_UNIT => guard_properties(
                &v,
                &binding(&review["guard"])?,
                &package(attempt, "guard-binding").join(GUARD_ARG.plan),
                &package(attempt, "receipt-mount"),
            )?,
            TIMER => ensure!(v["Unit"] == GUARD_UNIT, "prepared timer target differs"),
            RETENTION => {
                ensure!(
                    retains_all(&v)?
                        && ["Requires", "Wants", "BindsTo", "Upholds"]
                            .iter()
                            .all(|k| v[*k] == ""),
                    "prepared retention has activation edges"
                );
            }
            _ => unreachable!(),
        }
        owned.insert(unit, b);
    }
    Ok(json!(owned))
}
pub(super) fn prepare(
    n: &mut Native,
    review: &Value,
    review_ref: &Bound,
    self_sha: &str,
) -> Result<()> {
    let attempt = text(review, "attempt")?;
    ensure!(crate::launch::safe_attempt(attempt), "attempt namespace");
    pristine()?;
    for kind in [
        "admission",
        "startup-plan",
        "producer",
        "guard-units",
        "guard-binding",
        "receipt-mount",
        "first-fire",
        "prepared",
    ] {
        absent(&package(attempt, kind))?;
    }
    let definitions = definitions(review)?;
    for (unit, _, _) in &definitions {
        for root in ["/etc/systemd/system", "/run/systemd/system"] {
            absent(&Path::new(root).join(unit))?;
            absent(&Path::new(root).join(format!("{unit}.d")))?;
        }
        ensure!(
            n.show(unit)?["LoadState"] == "not-found",
            "candidate name already loaded"
        );
    }
    let (pairs, remainder) = definitions.as_chunks::<2>();
    ensure!(remainder.is_empty(), "incomplete unit package");
    for pair in pairs {
        let dest = pair[0].1.parent().context("unit package")?;
        let mut members = Vec::new();
        for (unit, path, template) in pair {
            ensure!(path.parent() == Some(dest), "mixed unit package");
            members.push((*unit, save(&n.root, unit, template.as_bytes())?));
        }
        n.seal(dest, &members)?;
    }
    for (unit, path, _) in &definitions {
        let link = Path::new("/etc/systemd/system").join(unit);
        symlink(path, &link)?;
    }
    File::open("/etc/systemd/system")?.sync_all()?;
    let units = loaded(n, review)?;
    let mut proof = json!({"schema":PREPARED_SCHEMA,"review":review_ref,
        "attempt":attempt,"operation":review["operation"],"cpu_affinity":review["cpu_affinity"],"gate":Bound::new(LAUNCHER,self_sha),
        "guard":review["guard"],"boot_id":review["boot_id"],"source_publication":review["source_publication"],
        "units":units,"recorded_unix_seconds":now()?,"recorded_monotonic_us":mono()?});
    deny_authority(&mut proof);
    let b = save_json(&n.root, "prepared.json", &proof)?;
    let dest = package(attempt, "prepared");
    n.seal(&dest, &[("prepared.json", b.clone())])?;
    println!(
        "{}",
        serde_json::to_string(&Bound::new(dest.join("prepared.json"), b.sha256))?
    );
    Ok(())
}
pub(super) fn accepted(n: &mut Native, review: &Value, self_sha: &str, a: &Value) -> Result<Bound> {
    let attempt = text(review, "attempt")?;
    ensure!(crate::launch::safe_attempt(attempt), "attempt namespace");
    let reference = binding(&review["preparation"])?;
    ensure!(
        reference.path == package(attempt, "prepared").join("prepared.json"),
        "preparation namespace"
    );
    let p = reference.sealed()?;
    no_authority(&p)?;
    let old = binding(&p["review"])?.sealed()?;
    ensure!(
        p["schema"] == PREPARED_SCHEMA
            && p["review"] != a["review"]
            && p["units"] == loaded(n, review)?
            && num(&p, "recorded_monotonic_us")? < mono()?
            && num(&p, "recorded_unix_seconds")? < num(review, "recorded_unix_seconds")?
            && num(review, "recorded_unix_seconds")? <= num(a, "issued_unix_seconds")?,
        "preparation must precede a fresh review and admission"
    );
    for k in ["operation", "attempt", "boot_id", "cpu_affinity", "guard"] {
        ensure!(old[k] == p[k] && p[k] == review[k], "prepared {k} changed");
    }
    ensure!(
        old["source_publication"] == p["source_publication"],
        "original prepared publication changed"
    );
    let old_source = binding(&p["source_publication"])?.sealed()?;
    let current_source = binding(&review["source_publication"])?.sealed()?;
    let gate = binding(&p["gate"])?;
    gate.artifact()?;
    prepared_transition(
        &reference,
        &gate,
        &Bound::new(LAUNCHER, self_sha),
        &old_source,
        &current_source,
    )?;
    Ok(reference)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires systemd-analyze and the deployed epoch257 artifact paths"]
    fn deployed_command_paths_pass_offline_unit_syntax_verification() {
        let dir = tempfile::tempdir().unwrap();
        let online = fs::read_to_string("/sys/devices/system/cpu/online").unwrap();
        let cpus: Vec<_> = parse_cpu_list(&online)
            .unwrap()
            .into_iter()
            .take(8)
            .collect();
        let review = json!({"attempt":"offline-syntax","cpu_affinity":cpus});
        let mut paths = Vec::new();
        for (name, _, body) in definitions(&review).unwrap() {
            let p = dir.path().join(name);
            fs::write(&p, body).unwrap();
            paths.push(p);
        }
        let result = Command::new("/usr/bin/systemd-analyze")
            .args([
                "--generators=no",
                "--recursive-errors=no",
                "--man=no",
                "verify",
            ])
            .args(&paths)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    #[test]
    fn static_environment_holds_no_future_iid_or_digest() {
        let p = Bound::new("/tmp/test/plan.json", "f".repeat(64));
        let u = native_template(&p, "48 49 50 51 52 53 54 55");
        assert!(u.contains("EnvironmentFile=/tmp/test/startup.env\n"));
        assert!(!u.contains(&p.sha256));
        assert!(u.contains(&format!("MemoryMax={MEMORY}\n")));
        let g = guard_template(
            &Bound::new(GUARD, GUARD_SHA),
            Path::new("/tmp/guard/guard-plan.json"),
            Path::new("/tmp/receipt-mount"),
        );
        assert!(g.contains("EnvironmentFile=/tmp/guard/guard.env\n"));
        assert!(g.contains(&format!("${{{GUARD_SHA_ENV}}}")));
        assert!(g.contains("ReadWritePaths=/tmp/receipt-mount\n"));
        // Preserve the four epoch 257 definitions already sealed by the v3 launcher.
        if EPOCH == 257 {
            let (old_path, old_sha) = crate::native257::saved_guard(&json!({})).unwrap();
            let original = guard_template(
                &Bound::new(old_path, old_sha),
                Path::new("/tmp/guard/guard-plan.json"),
                Path::new("/tmp/receipt-mount"),
            );
            assert_eq!(g, original.replace(old_path, GUARD).replace(old_sha, GUARD_SHA));
            assert_eq!(
                [u, original, timer_template(), retention_template()].map(|text| digest(text.as_bytes())),
                [
                    "1fa3f168082793e306b98b91e95cad23cdedae3fb707dbe1d2eec05bb3f64130",
                    "c8e3dd87247b9c9151a86a9f9d0dac094a60c55013bcbe2bee70cadcccf5b034",
                    "1c9315b967275f8d674f83afb54b9b3af8704482b2bd54b5b20684aa95046457",
                    "dc0d217f3918de4a79e0a5c7f8cf01e09b411f09299a1d608e01ea6b8d9ec821"
                ]
            );
        }
        assert_eq!(
            parse_cpu_list("2,4-6").unwrap(),
            BTreeSet::from([2, 4, 5, 6])
        );
        for v in ["", "4-2", "2,2", "4096", "a"] {
            assert!(parse_cpu_list(v).is_err());
        }
    }
}
