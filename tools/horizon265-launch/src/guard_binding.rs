//! Preloaded static guard graph, with one late immutable digest argument.
//! No unit links, reloads, service starts, clock renewal or admission occur here.
use super::*;
const VARIABLE: &str = "HORIZON265_GUARD_PLAN_SHA256";
const PROPERTIES: &str = "ExecStart,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment,Type,User,Group,MemoryMax,MemorySwapMax,TasksMax";
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn environment(sha: &str) -> Result<Vec<u8>> {
    ensure!(digest(sha), "guard argument is not one lowercase SHA256");
    Ok(format!("{VARIABLE}={sha}\n").into_bytes())
}
fn expected_exec() -> String {
    format!(
        "{{ path={GUARD} ; argv[]={GUARD} {BOUND}/guard-plan.json --plan-sha256 ${{{VARIABLE}}} --self-sha256 {GUARD_SHA} ; ignore_errors=no"
    )
}
fn command_identity(value: &str) -> Result<&str> {
    let (command, metadata) = value
        .split_once(" ; start_time=")
        .context("guard manager argv framing")?;
    ensure!(
        value.matches("{ path=").count() == 1
            && value.matches(" ; start_time=").count() == 1
            && metadata.ends_with(" }"),
        "multiple or malformed guard commands"
    );
    Ok(command)
}
fn loaded_properties(
    g: &BTreeMap<String, String>,
    t: &BTreeMap<String, String>,
    pristine: bool,
) -> Result<()> {
    ensure!(
        row(g, "Id")? == GUARD_UNIT
            && row(t, "Id")? == TIMER
            && row(g, "LoadState")? == "loaded"
            && row(t, "LoadState")? == "loaded"
            && row(g, "DropInPaths")?.is_empty()
            && row(t, "DropInPaths")?.is_empty()
            && row(t, "Unit")? == GUARD_UNIT
            && command_identity(row(g, "ExecStart")?)? == expected_exec()
            && row(g, "EnvironmentFiles")? == format!("{BOUND}/guard.env (ignore_errors=no)")
            && row(g, "Environment")?.is_empty()
            && row(g, "PassEnvironment")?.is_empty()
            && row(g, "UnsetEnvironment")?.is_empty()
            && row(g, "Type")? == "oneshot"
            && row(g, "User")? == "root"
            && row(g, "Group")?.is_empty()
            && row(g, "Restart")? == "no"
            && row(g, "MemoryMax")? == "1073741824"
            && row(g, "MemorySwapMax")? == "0"
            && row(g, "TasksMax")? == "256",
        "preloaded guard graph/argument contract differs"
    );
    if pristine {
        for v in [g, t] {
            closed(v)?;
            ensure!(
                row(v, "ActiveState")? == "inactive"
                    && row(v, "SubState")? == "dead"
                    && row(v, "InvocationID")?.is_empty(),
                "preloaded guard/timer namespace was consumed"
            );
        }
    }
    Ok(())
}
pub(super) fn loaded(n: &mut Native, pristine: bool) -> Result<()> {
    inputs::check_static()?;
    for unit in [GUARD_UNIT, TIMER] {
        let link = Path::new("/run/systemd/system").join(unit);
        ensure!(
            link.read_link()? == Path::new(STATIC).join(unit),
            "preloaded graph link changed"
        );
    }
    let (g, _) = n.show(GUARD_UNIT, PROPERTIES)?;
    let (t, _) = n.show(TIMER, "Unit,NextElapseUSecMonotonic")?;
    loaded_properties(&g, &t, pristine)
}
fn immutable(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o444,
        "mutable/foreign guard binding file"
    );
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "mutable guard binding ancestor"
        );
    }
    Ok(())
}
pub(super) fn verify(plan: &Value) -> Result<()> {
    let plan_path = Path::new(BOUND).join("guard-plan.json");
    let env_path = Path::new(BOUND).join("guard.env");
    immutable(&plan_path)?;
    immutable(&env_path)?;
    let expected = text(plan, "sha256")?;
    ensure!(
        hash(&plan_path)? == expected && small(&env_path)? == environment(expected)?,
        "immutable guard plan/argument pair differs"
    );
    Ok(())
}
pub(super) fn seal(n: &mut Native, plan: &Value) -> Result<Value> {
    let expected = text(plan, "sha256")?;
    ensure!(
        hash(Path::new(text(plan, "path")?))? == expected,
        "unsealed guard plan changed"
    );
    let env = save_at(&n.root, "guard.env", &environment(expected)?)?;
    let seal=n.seal(BOUND,vec![
        json!({"source":plan["path"],"name":"guard-plan.json","sha256":plan["sha256"],"mode":292}),
        json!({"source":env["path"],"name":"guard.env","sha256":env["sha256"],"mode":292}),
    ],"guard-seal-plan.json")?;
    verify(plan)?;
    Ok(
        json!({"schema":"horizon265-preloaded-guard-argument-binding-v1",
        "guard_plan":{"path":format!("{BOUND}/guard-plan.json"),"sha256":expected},
        "environment":{"path":format!("{BOUND}/guard.env"),"sha256":env["sha256"]},
        "deployment_seal":seal,"unit":GUARD_UNIT,"timer":TIMER,
        "unit_files_preloaded_before_fresh_admission":true,
        "daemon_reload_after_fresh_admission":false,"guard_started":false,
        "first_guard_evidence_still_required":true,"replay_launch_authorized":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn environment_is_exactly_one_nonexpanding_digest_assignment() {
        let sha = "a".repeat(64);
        assert_eq!(
            environment(&sha).unwrap(),
            format!("{VARIABLE}={sha}\n").as_bytes()
        );
        for bad in [
            "A".repeat(64),
            "a".repeat(63),
            format!("{}\nOTHER=x", "a".repeat(64)),
            "$TOKEN".into(),
            "$(id)".into(),
            "a b".into(),
        ] {
            assert!(environment(&bad).is_err());
        }
    }
    fn fixture() -> (BTreeMap<String, String>, BTreeMap<String, String>) {
        let common = [
            ("LoadState", "loaded"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("InvocationID", ""),
            ("DropInPaths", ""),
            ("Job", ""),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("ControlGroup", ""),
            ("NRestarts", "0"),
        ];
        let mut g = common
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>();
        let mut t = g.clone();
        g.insert("Id".into(), GUARD_UNIT.into());
        t.insert("Id".into(), TIMER.into());
        t.insert("Unit".into(), GUARD_UNIT.into());
        for (k, v) in [
            ("Environment", ""),
            ("PassEnvironment", ""),
            ("UnsetEnvironment", ""),
            ("Type", "oneshot"),
            ("User", "root"),
            ("Group", ""),
            ("Restart", "no"),
            ("MemoryMax", "1073741824"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "256"),
        ] {
            g.insert(k.into(), v.into());
        }
        g.insert(
            "EnvironmentFiles".into(),
            format!("{BOUND}/guard.env (ignore_errors=no)"),
        );
        g.insert(
            "ExecStart".into(),
            format!(
                "{} ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
                expected_exec()
            ),
        );
        (g, t)
    }
    #[test]
    fn preloaded_graph_rejects_optional_or_additional_argument_sources() {
        let (g, t) = fixture();
        loaded_properties(&g, &t, true).unwrap();
        for (key, bad) in [
            (
                "EnvironmentFiles",
                format!("{BOUND}/guard.env (ignore_errors=yes)"),
            ),
            (
                "EnvironmentFiles",
                format!("{BOUND}/guard.env (ignore_errors=no) /other (ignore_errors=no)"),
            ),
            ("Environment", format!("{VARIABLE}={}", "0".repeat(64))),
            ("PassEnvironment", VARIABLE.into()),
            ("UnsetEnvironment", VARIABLE.into()),
            ("DropInPaths", "/tmp/override.conf".into()),
            ("InvocationID", "a".repeat(32)),
        ] {
            let mut changed = g.clone();
            changed.insert(key.into(), bad);
            assert!(loaded_properties(&changed, &t, true).is_err(), "{key}");
        }
        let mut changed = t;
        changed.insert("InvocationID".into(), "b".repeat(32));
        assert!(loaded_properties(&g, &changed, true).is_err());
    }
    #[test]
    fn manager_command_must_keep_direct_guard_and_braced_single_argument() {
        let (g, t) = fixture();
        for value in [
            g["ExecStart"].replace(
                "${HORIZON265_GUARD_PLAN_SHA256}",
                "$HORIZON265_GUARD_PLAN_SHA256",
            ),
            g["ExecStart"].replace("--plan-sha256", "--different-flag"),
            g["ExecStart"].replace("--self-sha256", "extra --self-sha256"),
        ] {
            let mut changed = g.clone();
            changed.insert("ExecStart".into(), value);
            assert!(loaded_properties(&changed, &t, true).is_err());
        }
    }
    #[test]
    fn launch_has_no_unit_graph_mutation_after_fresh_window() {
        let source = include_str!("main.rs");
        let launch = source
            .split("fn launch(")
            .nth(1)
            .unwrap()
            .split("fn run()")
            .next()
            .unwrap();
        for forbidden in ["daemon-reload", "symlink(", "guard.service", "guard.timer"] {
            assert!(!launch.contains(forbidden), "{forbidden}");
        }
        assert!(launch.contains("current::guard_start_window"));
        assert!(launch.contains("validate_first_sample"));
        assert!(launch.contains("current::census(n, a, true)"));
        assert!(launch.contains("pre(&n.show(UNIT"));
        assert!(
            source
                .split("fn prepare(")
                .nth(1)
                .unwrap()
                .split("fn ")
                .next()
                .unwrap()
                .contains("daemon-reload")
        );
    }
}
