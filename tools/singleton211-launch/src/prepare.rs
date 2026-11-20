//! Link and load inert definitions before the actual fleet review and admission.
//! The real gate and guard receive their own sealed digest only when their plan exists.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Argument {
    pub(super) variable: &'static str,
    pub(super) env: &'static str,
    pub(super) plan: &'static str,
}
pub(super) const STARTUP: Argument = Argument {
    variable: "HORIZON211_STARTUP_PLAN_SHA256",
    env: "startup.env",
    plan: "plan.json",
};
pub(super) const GUARD_ARG: Argument = Argument {
    variable: "HORIZON211_GUARD_PLAN_SHA256",
    env: "guard.env",
    plan: "guard-plan.json",
};
impl Argument {
    fn bytes(self, sha: &str) -> Result<Vec<u8>> {
        ensure!(hex(sha, 64), "expected exactly one lowercase plan digest");
        Ok(format!("{}={sha}\n", self.variable).into_bytes())
    }
}

pub(super) fn env_properties(v: &Value, env: &Path) -> Result<()> {
    ensure!(
        v["EnvironmentFiles"] == format!("{} (ignore_errors=no)", env.display())
            && v["PassEnvironment"] == ""
            && v["UnsetEnvironment"] == ""
            && v["DropInPaths"] == "",
        "plan argument environment changed"
    );
    Ok(())
}

pub(super) fn guard_properties(v: &Value, guard: &Bound, plan: &Path) -> Result<()> {
    env_properties(v, &plan.with_file_name(GUARD_ARG.env))?;
    let command = format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 ${{HORIZON211_GUARD_PLAN_SHA256}} --self-sha256 {} ; ignore_errors=no",
        guard.path.display(),
        guard.path.display(),
        plan.display(),
        guard.sha256
    );
    ensure!(
        v["Environment"] == ""
            && v["Id"] == GUARD_UNIT
            && v["User"] == "root"
            && v["Type"] == "oneshot"
            && v["Restart"] == "no"
            && v["MemoryMax"] == "268435456"
            && v["TasksMax"] == "64"
            && periodic::stable_command(text(v, "ExecStart")?)? == command,
        "guard command or resource contract changed"
    );
    Ok(())
}
pub(super) fn seal_pair(
    n: &mut Native,
    destination: &Path,
    source: &Bound,
    arg: Argument,
) -> Result<Bound> {
    let env = save(&n.root, arg.env, &arg.bytes(&source.sha256)?)?;
    n.seal(destination, &[(arg.plan, source.clone()), (arg.env, env)])?;
    let plan = Bound::new(destination.join(arg.plan), &source.sha256);
    verify_pair(&plan, arg)?;
    Ok(plan)
}
pub(super) fn verify_pair(plan: &Bound, arg: Argument) -> Result<()> {
    ensure!(
        plan.path.file_name().and_then(|s| s.to_str()) == Some(arg.plan),
        "wrong plan basename"
    );
    let env = plan.path.with_file_name(arg.env);
    for path in [&plan.path, &env] {
        trusted_parents(path)?;
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == *path
                && m.is_file()
                && m.nlink() == 1
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o7777 == 0o444,
            "plan argument custody"
        );
    }
    let bytes = arg.bytes(&plan.sha256)?;
    plan.bytes(true)?;
    ensure!(
        Bound::new(env, digest(&bytes)).bytes(true)? == bytes,
        "plan digest argument differs"
    );
    Ok(())
}
fn definitions(
    attempt: &str,
    review: &Value,
    self_sha: &str,
) -> Result<Vec<(&'static str, PathBuf, String)>> {
    ensure!(launch::safe_attempt(attempt), "attempt namespace");
    let producer = launch::package(attempt, "producer");
    let guards = launch::package(attempt, "guard-units");
    let startup = launch::package(attempt, "startup-plan").join(STARTUP.plan);
    let guard_plan = launch::package(attempt, "guard-binding").join(GUARD_ARG.plan);
    let receipts = launch::package(attempt, "guard-receipts");
    Ok(vec![
        (
            UNIT,
            producer.join(UNIT),
            launch::producer_template(&startup, &launch::cpus(review)?, self_sha),
        ),
        (
            RETENTION,
            producer.join(RETENTION),
            launch::retention_template(),
        ),
        (
            GUARD_UNIT,
            guards.join(GUARD_UNIT),
            launch::guard_template(&binding(&review["guard"])?, &guard_plan, &receipts),
        ),
        (TIMER, guards.join(TIMER), launch::timer_template()),
    ])
}

fn loaded(n: &mut Native, review: &Value, self_sha: &str) -> Result<Value> {
    let attempt = text(review, "attempt")?;
    let mut owned = BTreeMap::new();
    for (unit, path, template) in definitions(attempt, review, self_sha)? {
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
                let pr = launch::package(attempt, "startup-plan").join(STARTUP.plan);
                env_properties(&v, &pr.with_file_name(STARTUP.env))?;
                let cmd = format!(
                    "{{ path={GATE} ; argv[]={} ; ignore_errors=no",
                    launch::gate_command(&pr, self_sha)
                );
                ensure!(
                    periodic::stable_command(text(&v, "ExecStart")?)? == cmd,
                    "prepared producer command differs"
                );
            }
            GUARD_UNIT => guard_properties(
                &v,
                &binding(&review["guard"])?,
                &launch::package(attempt, "guard-binding").join(GUARD_ARG.plan),
            )?,
            TIMER => ensure!(v["Unit"] == GUARD_UNIT, "prepared timer target differs"),
            RETENTION => {
                ensure!(
                    launch::retains_all(&v)?
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
pub(super) fn run(
    n: &mut Native,
    review: &Value,
    review_ref: &Bound,
    self_sha: &str,
) -> Result<()> {
    let attempt = text(review, "attempt")?;
    ensure!(launch::safe_attempt(attempt), "attempt namespace");
    launch::pristine()?;
    for kind in [
        "admission",
        "startup-plan",
        "producer",
        "guard-units",
        "guard-binding",
        "guard-receipts",
        "first-fire",
        "prepared",
    ] {
        absent(&launch::package(attempt, kind))?;
    }
    let definitions = definitions(attempt, review, self_sha)?;
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
    let units = loaded(n, review, self_sha)?;
    let mut proof = json!({"schema":"horizon-singleton211-prepared-units-v1","review":review_ref,
        "attempt":attempt,"operation":review["operation"],"cpu_affinity":review["cpu_affinity"],"gate":Bound::new(GATE,self_sha),
        "guard":review["guard"],"boot_id":review["boot_id"],"source_publication":review["source_publication"],
        "units":units,"recorded_unix_seconds":now()?,"recorded_monotonic_us":mono()?});
    deny_authority(&mut proof);
    let b = save_json(&n.root, "prepared.json", &proof)?;
    let dest = launch::package(attempt, "prepared");
    n.seal(&dest, &[("prepared.json", b.clone())])?;
    println!(
        "{}",
        serde_json::to_string(&Bound::new(dest.join("prepared.json"), b.sha256))?
    );
    Ok(())
}
pub(super) fn accepted(n: &mut Native, review: &Value, self_sha: &str, a: &Value) -> Result<Bound> {
    let attempt = text(review, "attempt")?;
    ensure!(launch::safe_attempt(attempt), "attempt namespace");
    let reference = binding(&review["preparation"])?;
    ensure!(
        reference.path == launch::package(attempt, "prepared").join("prepared.json"),
        "preparation namespace"
    );
    let p = reference.sealed()?;
    no_authority(&p)?;
    let old = binding(&p["review"])?.sealed()?;
    ensure!(
        p["schema"] == "horizon-singleton211-prepared-units-v1"
            && p["gate"] == json!(Bound::new(GATE, self_sha))
            && p["review"] != a["review"]
            && p["units"] == loaded(n, review, self_sha)?
            && num(&p, "recorded_monotonic_us")? < mono()?
            && num(&p, "recorded_unix_seconds")? < num(review, "recorded_unix_seconds")?
            && num(review, "recorded_unix_seconds")? <= num(a, "recorded_unix_seconds")?,
        "preparation must precede a fresh review and admission"
    );
    for k in [
        "operation",
        "attempt",
        "boot_id",
        "cpu_affinity",
        "guard",
        "source_publication",
    ] {
        ensure!(old[k] == p[k] && p[k] == review[k], "prepared {k} changed");
    }
    Ok(reference)
}

/// Replay the immutable preparation and original peer deadline binding offline,
/// including from the held gate before it can exec the native worker.
pub(super) fn historical(review: &Value, plan: &Value, a: &Value) -> Result<()> {
    let attempt = text(review, "attempt")?;
    ensure!(launch::safe_attempt(attempt), "attempt namespace");
    let preparation = binding(&review["preparation"])?;
    let receipt = binding(&plan["peer_window"])?;
    ensure!(
        plan["preparation"] == json!(preparation)
            && preparation.path == launch::package(attempt, "prepared").join("prepared.json")
            && receipt.path == launch::package(attempt, "admission").join("peer-window.json"),
        "startup refers to a foreign preloaded graph or peer window"
    );
    let p = preparation.sealed()?;
    let w = receipt.sealed()?;
    no_authority(&p)?;
    ensure!(
        p["schema"] == "horizon-singleton211-prepared-units-v1"
            && p["review"] != a["review"]
            && p["operation"] == plan["operation"]
            && p["attempt"] == review["attempt"]
            && p["gate"] == plan["gate"]
            && p["guard"] == plan["guard"]
            && p["cpu_affinity"] == review["cpu_affinity"]
            && p["source_publication"] == a["source_publication"]
            && p["boot_id"] == plan["boot_id"]
            && w["boot_id"] == p["boot_id"]
            && w["review"] == a["review"]
            && w["schema"] == "horizon-singleton211-original-peer-window-v1"
            && num(&p, "recorded_unix_seconds")? < num(review, "recorded_unix_seconds")?
            && num(review, "recorded_unix_seconds")? <= num(a, "recorded_unix_seconds")?
            && num(&p, "recorded_monotonic_us")? <= num(&w, "recorded_monotonic_us")?
            && num(&w, "recorded_monotonic_us")? <= num(plan, "issued_monotonic_us")?
            && num(plan, "expires_monotonic_us")? <= num(&w, "deadline_with_margin_monotonic_us")?,
        "historical preparation or original peer window changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_unit_templates_hold_separate_mandatory_single_arguments() {
        let startup = Path::new("/var/lib/jetstreamer/startup/plan.json");
        let gp = Path::new("/var/lib/jetstreamer/binding/guard-plan.json");
        let gate = launch::producer_template(startup, "0-15", &"a".repeat(64));
        let guard = launch::guard_template(
            &Bound::new(GUARD, "b".repeat(64)),
            gp,
            Path::new("/var/lib/jetstreamer/receipts"),
        );
        assert!(gate.contains("EnvironmentFile=/var/lib/jetstreamer/startup/startup.env\n"));
        assert!(gate.contains(" ${HORIZON211_STARTUP_PLAN_SHA256} "));
        assert!(!gate.contains(GUARD_ARG.variable));
        assert!(guard.contains("EnvironmentFile=/var/lib/jetstreamer/binding/guard.env\n"));
        assert!(guard.contains(" --plan-sha256 ${HORIZON211_GUARD_PLAN_SHA256} --self-sha256 "));
        assert!(!guard.contains(STARTUP.variable));
    }
    #[test]
    fn neither_qualification_nor_real_start_nor_retirement_can_reload_pid1() {
        let launch = include_str!("launch.rs");
        let retire = include_str!("qualification.rs");
        for source in [launch, retire] {
            assert!(!source.contains("daemon-reload"));
        }
        assert!(launch.contains("qualification::capture_stop("));
        assert!(launch.contains("first_guard(&p, &token,"));
        assert!(launch.contains("peers.verify(n)?;"));
    }
    #[test]
    fn strict_digest_and_single_mandatory_environment_source() {
        let sha = "a".repeat(64);
        for arg in [STARTUP, GUARD_ARG] {
            assert_eq!(
                arg.bytes(&sha).unwrap(),
                format!("{}={sha}\n", arg.variable).as_bytes()
            );
            for bad in ["A".repeat(64), "a".repeat(63), format!("{sha}\nX=1")] {
                assert!(arg.bytes(&bad).is_err());
            }
        }
        let env = Path::new("/some/guard.env");
        let good = json!({"EnvironmentFiles":"/some/guard.env (ignore_errors=no)","PassEnvironment":"","UnsetEnvironment":"","DropInPaths":""});
        env_properties(&good, env).unwrap();
        for (key, value) in [
            ("EnvironmentFiles", "/some/guard.env (ignore_errors=yes)"),
            (
                "EnvironmentFiles",
                "/some/guard.env (ignore_errors=no) /other (ignore_errors=no)",
            ),
            ("PassEnvironment", "X"),
            ("UnsetEnvironment", "X"),
            ("DropInPaths", "/override.conf"),
        ] {
            let mut bad = good.clone();
            bad[key] = json!(value);
            assert!(env_properties(&bad, env).is_err());
        }
    }
}
