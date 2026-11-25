// The retirement reviews identified these exact retired generations in the published
// graph. Their service names, command lines, fragment digests and terminal IDs
// are compiled inputs, never values supplied by a retirement request.
use super::*;
use std::{ffi::OsStr, io::ErrorKind, process::Command};

const RETRY10_PARK: &str = "horizon-closed166-retry10-park-20261122-v1.service";
const RETRY7_PARK: &str = "horizon-closed166-retry7-park-20261120-v1.service";
const RETRY8_PARK: &str = "horizon-closed166-retry8-park-20261120-v1.service";
const RETRY8_SHELL_CENSUS: &str = "horizon-closed166-prefix-consumer-census-20261124-v1.service";
const METERED168_PARK: &str = "horizon-closed168-full-metered-park-20261122-v1.service";
const METERED168_DROPIN_OWNERS: [&str; 9] = [
    "horizon-observer-root144959-live166167170-20261121-v1.service",
    "horizon-observer-root154959-live166167170-20261121-v1.service",
    "horizon-observer-root165022-live166167170-20261121-v1.service",
    "horizon-observer-root172022-live166167170-20261121-v1.service",
    "horizon-observer-root221010-live166167170-20261121-v1.service",
    "horizon-observer-root224010-live166167170-20261121-v1.service",
    "horizon-observer-root231010-live166167170-20261121-v1.service",
    "horizon-observer-root234010-live166167170-20261121-v1.service",
    "horizon-observer-root004010-live166167170-20261122-v1.service",
];
const METERED168_FAILED_OBSERVER: &str =
    "horizon-observer-root174010-live166167170-20261122-v1.service";
const REGISTRY: &str = include_str!("holding_epoch166_reviewed_managers.json");
const PROPERTIES: &str = "Id,Names,Job,NeedDaemonReload,Transient,LoadState,ActiveState,SubState,CanStart,UnitFileState,FragmentPath,DropInPaths,InvocationID,ExecMainPID,ExecMainExitTimestampMonotonic,ExecMainCode,ExecMainStatus,MainPID,ControlPID,ControlGroup,NRestarts,Result,Restart,RequiredBy,Requisite,RequisiteOf,WantedBy,BoundBy,UpheldBy,ConsistsOf,OnSuccessOf,OnFailureOf,TriggeredBy,Triggers";
const BACKLINKS: [&str; 9] = [
    "RequiredBy",
    "WantedBy",
    "BoundBy",
    "UpheldBy",
    "ConsistsOf",
    "OnSuccessOf",
    "OnFailureOf",
    "TriggeredBy",
    "Triggers",
];

#[derive(Deserialize)]
struct Terminal {
    fragment: PathBuf,
    sha256: String,
    invocation: String,
    pid: String,
    exit_us: String,
    state: String,
    substate: String,
    result: String,
    code: Option<String>,
    status: String,
    argv: String,
    requisite: Vec<String>,
    requisite_of: Vec<String>,
}

fn terminal_command_matches(unit: &str, terminal: &Terminal, command: &str) -> bool {
    if command.matches("argv[]=").count() != 1 {
        return false;
    }
    if command.contains(&format!("argv[]={0} ;", terminal.argv)) {
        return true;
    }
    // Reloading the unchanged transient fragment re-escapes shell dollars in
    // this one census command and clears its formatted attempt accounting.
    // The caller still binds the fragment, native invocation and main result.
    unit == RETRY8_SHELL_CENSUS
        && terminal.invocation == "03a02108b42a4126852e7d74d686bd46"
        && command
            == format!(
                "{{ path=/bin/bash ; argv[]={} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
                terminal.argv.replace('$', "$$"),
            )
}

#[derive(Default, Deserialize)]
pub(super) struct Registered {
    dropins: BTreeMap<String, BTreeMap<PathBuf, String>>,
    terminals: BTreeMap<String, Terminal>,
}

impl Registered {
    pub(super) fn profile(park_name: &str) -> Result<Self> {
        match park_name {
            RETRY10_PARK => Ok(serde_json::from_str(REGISTRY)?),
            RETRY7_PARK => {
                let mut registry = Self::profile(RETRY8_PARK)?;
                registry.dropins.clear();
                registry.terminals.retain(|unit, _| matches!(
                    unit.as_str(),
                    "horizon-custody166-terminal-census-20261120-v1.service"
                        | "horizon-observer-live166retry8-first-20261119-v1.service"
                ));
                let observers: BTreeMap<String, Terminal> = serde_json::from_str(include_str!(
                    "holding_epoch166_retry7_observers.json"
                ))?;
                registry.terminals.extend(observers);
                Ok(registry)
            }
            RETRY8_PARK => Ok(serde_json::from_str(include_str!(
                "holding_epoch166_retry8_reviewed_managers.json"
            ))?),
            METERED168_PARK => {
                // These same retired observers also reference the old 168 run.
                // Keep retry10's own terminal/census units out of the 168 registry.
                let mut registry: Self = serde_json::from_str(REGISTRY)?;
                registry
                    .dropins
                    .retain(|owner, _| METERED168_DROPIN_OWNERS.contains(&owner.as_str()));
                registry
                    .terminals
                    .retain(|owner, _| owner == METERED168_FAILED_OBSERVER);
                // This immutable registry binds the successful PID1 start jobs and stored
                // receipt writers of the original epoch 168 capture and census.
                let completed: BTreeMap<String, Terminal> = serde_json::from_str(include_str!(
                    "holding_epoch168_completed_followers.json"
                ))?;
                registry.terminals.extend(completed);
                Ok(registry)
            }
            _ => Ok(Self::default()),
        }
    }

    pub(super) fn terminal(&self, name: &str) -> bool {
        self.terminals.contains_key(name)
    }

    pub(super) fn dropin(&self, node: &Node) -> bool {
        let [owner] = node.owner_units.as_slice() else {
            return false;
        };
        self.dropins
            .get(owner)
            .and_then(|files| files.get(&node.file.path))
            == Some(&node.file.sha256)
    }

    fn targets(&self) -> BTreeSet<String> {
        self.dropins
            .keys()
            .chain(self.terminals.keys())
            .flat_map(|unit| {
                let stem = unit.strip_suffix(".service").expect("fixed service name");
                ["service", "timer", "path", "socket"].map(|ext| format!("{stem}.{ext}"))
            })
            .collect()
    }

    fn definition_files(&self) -> BTreeMap<&Path, &str> {
        self.dropins
            .values()
            .flat_map(|files| files.iter().map(|(p, h)| (p.as_path(), h.as_str())))
            .chain(
                self.terminals
                    .values()
                    .map(|t| (t.fragment.as_path(), t.sha256.as_str())),
            )
            .collect()
    }

    // Requisite= only accepts an already-active dependency, without starting
    // it. Both census invocations required the retained terminal capture,
    // and the capture required the authenticated park. Pin both directions.
    fn relation(row: &Value, key: &str, expected: &[String]) -> bool {
        let Some(value) = row[key].as_str() else {
            return false;
        };
        let mut words: Vec<_> = value.split_whitespace().collect();
        words.sort_unstable();
        words == expected
    }

    fn state(&self, unit: &str, row: &Value) -> Result<()> {
        ensure!(
            row["Id"] == unit
                && row["Names"] == unit
                && row["Job"] == ""
                && row["NeedDaemonReload"] == "no"
                && row["DropInPaths"] == ""
                && BACKLINKS.iter().all(|k| row[k] == ""),
            "reviewed manager acquires an alias, job, trigger, dependency or override: {unit}"
        );
        if let Some(t) = self.terminals.get(unit) {
            ensure!(
                Self::relation(row, "Requisite", &t.requisite)
                    && Self::relation(row, "RequisiteOf", &t.requisite_of),
                "original nonactivating dependencies changed: {unit}"
            );
            let command = row["ExecStart"].as_str().context("terminal ExecStart")?;
            ensure!(
                row["LoadState"] == "loaded"
                    && row["Transient"] == "yes"
                    && row["ActiveState"] == t.state
                    && row["SubState"] == t.substate
                    && row["UnitFileState"] == "transient"
                    && row["FragmentPath"] == json!(t.fragment)
                    && row["InvocationID"] == t.invocation
                    && row["ExecMainExitTimestampMonotonic"] == t.exit_us
                    && row["ExecMainPID"] == t.pid
                    && row["ExecMainCode"] == t.code.as_deref().unwrap_or("1")
                    && row["Result"] == t.result
                    && row["ExecMainStatus"] == t.status
                    && row["MainPID"] == "0"
                    && row["ControlPID"] == "0"
                    && row["NRestarts"] == "0"
                    && row["ControlGroup"] == ""
                    && row["Restart"] == "no"
                    && terminal_command_matches(unit, t, command),
                "historical terminal invocation, command or result changed: {unit}"
            );
        } else {
            ensure!(
                row["Requisite"] == ""
                    && row["RequisiteOf"] == ""
                    && row["LoadState"] == "not-found"
                    && row["CanStart"] == "no"
                    && row["ActiveState"] == "inactive"
                    && row["SubState"] == "dead"
                    && row["Transient"] == "no"
                    && row["FragmentPath"] == ""
                    && row["UnitFileState"] == ""
                    && ["MainPID", "ControlPID"]
                        .iter()
                        .all(|k| row[k].is_null() || row[k] == "0")
                    && ["InvocationID", "ControlGroup", "ExecStart"]
                        .iter()
                        .all(|k| row[k].is_null() || row[k] == ""),
                "an obsolete unit or activation companion can run: {unit}"
            );
        }
        Ok(())
    }

    fn disk(&self, roots: &[PathBuf], targets: &BTreeSet<String>) -> Result<()> {
        let expected = self.definition_files();
        let mut found = BTreeSet::new();
        for root in roots {
            let items = match fs::read_dir(root) {
                Ok(items) => items,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("inspect manager unit path {}", root.display()));
                }
            };
            for item in items {
                let item = item?;
                let path = item.path();
                let name = item.file_name();
                let Some(name) = name.to_str() else { continue };
                if targets.contains(name) {
                    checked_file(&path, &expected, &mut found)?;
                } else if item.file_type()?.is_symlink() {
                    reject_activation_link(&path, targets)?;
                }
                if let Some(owner) = name
                    .strip_suffix(".d")
                    .filter(|owner| targets.contains(*owner))
                {
                    ensure!(
                        self.dropins.contains_key(owner) && item.file_type()?.is_dir(),
                        "new or linked unit override directory: {}",
                        path.display()
                    );
                    for entry in fs::read_dir(&path)? {
                        let p = entry?.path();
                        if p.extension() == Some(OsStr::new("conf")) {
                            checked_file(&p, &expected, &mut found)?;
                        }
                    }
                }
                if [".wants", ".requires", ".upholds"]
                    .iter()
                    .any(|s| name.ends_with(s))
                {
                    for entry in fs::read_dir(&path).with_context(|| {
                        format!("inspect activation directory {}", path.display())
                    })? {
                        let entry = entry?;
                        ensure!(
                            !entry
                                .file_name()
                                .to_str()
                                .is_some_and(|n| targets.contains(n)),
                            "reviewed manager has a dependency link: {}",
                            entry.path().display()
                        );
                        if entry.file_type()?.is_symlink() {
                            reject_activation_link(&entry.path(), targets)?;
                        }
                    }
                }
            }
        }
        ensure!(
            found.len() == expected.len(),
            "a reviewed manager definition disappeared"
        );
        Ok(())
    }

    pub(super) fn verify(&self) -> Result<()> {
        if self.terminals.is_empty() {
            return Ok(());
        }
        let targets = self.targets();
        let raw =
            output(Command::new("/usr/bin/systemctl").args(["show", "-pUnitPath", "--value"]))?;
        let roots: Vec<PathBuf> = raw.split_whitespace().map(PathBuf::from).collect();
        ensure!(
            !roots.is_empty()
                && roots.len() <= 64
                && roots.iter().all(|p| p.is_absolute())
                && [
                    "/etc/systemd/system",
                    "/run/systemd/system",
                    "/run/systemd/transient",
                    "/usr/lib/systemd/system"
                ]
                .iter()
                .all(|p| roots.contains(&PathBuf::from(p))),
            "unexpected systemd load path"
        );
        self.disk(&roots, &targets)?;
        let raw = output(
            Command::new("/usr/bin/systemctl")
                .args(["show", "--all", "-p", PROPERTIES])
                .args(&targets),
        )?;
        let mut seen = BTreeSet::new();
        let cgroups = Path::new("/sys/fs/cgroup/system.slice");
        ensure!(cgroups.is_dir(), "manager cgroup root unavailable");
        for block in raw.trim_end().split("\n\n") {
            let mut fields = serde_json::Map::new();
            for line in block.lines() {
                let (k, v) = line.split_once('=').context("invalid manager property")?;
                ensure!(
                    fields.insert(k.to_owned(), json!(v)).is_none(),
                    "duplicate manager property"
                );
            }
            let mut row = Value::Object(fields);
            let name = row["Id"].as_str().context("missing manager identity")?;
            ensure!(
                targets.contains(name) && seen.insert(name.to_owned()),
                "unknown or duplicate manager"
            );
            let name = name.to_owned();
            if self.terminal(&name) {
                // Shell commands in older transient units may contain literal
                // newlines. Read this property independently of the scalar fields.
                let exec = output(Command::new("/usr/bin/systemctl").args([
                    "show",
                    &name,
                    "-pExecStart",
                    "--value",
                ]))?;
                row["ExecStart"] = json!(exec.trim_end_matches('\n'));
            }
            self.state(&name, &row)?;
            group_empty(&cgroups.join(&name))?;
            group_empty(&Path::new("/sys/fs/cgroup/horizonaudit.slice").join(&name))?;
        }
        ensure!(seen == targets, "incomplete manager readback");
        Ok(())
    }
}

fn checked_file(
    path: &Path,
    expected: &BTreeMap<&Path, &str>,
    found: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let sha = expected
        .get(path)
        .with_context(|| format!("new activatable fragment/drop-in: {}", path.display()))?;
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.nlink() == 1
            && md.mode() & 0o022 == 0
            && path.canonicalize()? == path,
        "untrusted manager definition: {}",
        path.display()
    );
    let bytes = read_stable_bounded(path, 1 << 20, "reviewed terminal/observer definition")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == *sha && found.insert(path.to_owned()),
        "changed/duplicate historical definition: {}",
        path.display()
    );
    Ok(())
}

fn reject_activation_link(path: &Path, targets: &BTreeSet<String>) -> Result<()> {
    // A dangling alias to a missing observer matters too. Follow the raw path
    // at every hop; canonicalize alone would hide that case.
    let mut p = path.to_owned();
    for _ in 0..40 {
        let target = match fs::read_link(&p) {
            Ok(q) => q,
            Err(e) if matches!(e.kind(), ErrorKind::InvalidInput | ErrorKind::NotFound) => {
                return Ok(());
            }
            Err(e) => {
                return Err(e).with_context(|| format!("inspect activation link {}", p.display()));
            }
        };
        ensure!(
            !target
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|s| targets.contains(s)),
            "activation alias targets historical unit: {}",
            p.display()
        );
        p = p.parent().context("manager link parent")?.join(target);
    }
    bail!("activation alias loop: {}", path.display());
}

fn group_empty(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(md) => {
            ensure!(
                md.is_dir()
                    && fs::read_to_string(path.join("cgroup.events"))?
                        .lines()
                        .any(|line| line == "populated 0"),
                "reviewed manager has active processes: {}",
                path.display()
            );
            Ok(())
        }
    }
}

fn output(command: &mut Command) -> Result<String> {
    let result = command.output()?;
    ensure!(
        result.status.success() && result.stderr.is_empty() && result.stdout.len() <= 1 << 20,
        "reviewed manager query failed"
    );
    Ok(String::from_utf8(result.stdout)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn actual() -> Registered {
        Registered::profile(RETRY10_PARK).unwrap()
    }

    #[test]
    fn retry8_shell_census_accepts_only_its_exact_reloaded_command() {
        let registry = Registered::profile(RETRY8_PARK).unwrap();
        let terminal = &registry.terminals[RETRY8_SHELL_CENSUS];
        let reset = format!(
            "{{ path=/bin/bash ; argv[]={} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
            terminal.argv.replace('$', "$$"),
        );
        assert!(terminal_command_matches(
            RETRY8_SHELL_CENSUS,
            terminal,
            &reset
        ));
        assert!(!terminal_command_matches(
            "foreign.service",
            terminal,
            &reset
        ));
        assert!(!terminal_command_matches(
            RETRY8_SHELL_CENSUS,
            terminal,
            &reset.replace("r8=$$?", "r8=0"),
        ));
    }

    #[test]
    fn retry7_uses_only_its_four_historical_consumer_units() {
        let registry = Registered::profile(RETRY7_PARK).unwrap();
        assert!(registry.dropins.is_empty());
        let owners: Vec<_> = registry.terminals.keys().map(String::as_str).collect();
        assert_eq!(owners, [
            "horizon-custody166-terminal-census-20261120-v1.service",
            "horizon-observer-live166retry8-first-20261119-v1.service",
            "horizon-observer-root0119-live166167-20261119-v1.service",
            "horizon-observer-root0121-stopped166167-20261119-v1.service",
        ]);
    }

    #[test]
    fn metered168_inherits_only_the_exact_shared_observer_definitions() {
        let all = actual();
        let metered = Registered::profile(METERED168_PARK).unwrap();
        assert_eq!(metered.dropins.len(), 9);
        assert_eq!(
            metered.dropins.values().map(BTreeMap::len).sum::<usize>(),
            11
        );
        assert_eq!(metered.terminals.len(), 3);
        for follower in [
            "horizon-closed168-full-metered-park-terminal-20261123-v2.service",
            "horizon-closed168-full-metered-consumer-census-20261123-v2.service",
        ] {
            assert!(metered.terminal(follower));
            assert!(!all.terminal(follower));
        }
        assert!(metered.terminal(METERED168_FAILED_OBSERVER));
        for owner in METERED168_DROPIN_OWNERS {
            assert_eq!(metered.dropins[owner], all.dropins[owner]);
        }
        assert!(!metered.terminal("horizon-closed166-retry10-park-terminal-20261122-v1.service"));
    }

    fn absent(unit: &str) -> Value {
        let mut row = json!({"Id":unit,"Names":unit,"Job":"","NeedDaemonReload":"no","DropInPaths":"","LoadState":"not-found","ActiveState":"inactive","SubState":"dead","Transient":"no","CanStart":"no","FragmentPath":"","UnitFileState":""});
        for key in BACKLINKS.into_iter().chain(["Requisite", "RequisiteOf"]) {
            row[key] = json!("");
        }
        row
    }

    #[test]
    fn retired_dropin_requires_its_exact_path_owner_digest_and_profile() {
        let registry = actual();
        assert_eq!(
            registry.dropins.values().map(BTreeMap::len).sum::<usize>(),
            12
        );
        for (owner, files) in &registry.dropins {
            for (path, digest) in files {
                let mut node = Node {
                    file: Bound {
                        path: path.clone(),
                        sha256: digest.clone(),
                    },
                    edges: vec![],
                    disposition: "retired-observer-drop-in".into(),
                    owner_units: vec![owner.clone()],
                    semantic_evidence: vec![],
                };
                assert!(registry.dropin(&node));
                assert!(
                    !Registered::profile("different profile")
                        .unwrap()
                        .dropin(&node)
                );
                node.owner_units.push("foreign.service".into());
                assert!(!registry.dropin(&node));
                node.owner_units.pop();
                node.file.sha256 = "0".repeat(64);
                assert!(!registry.dropin(&node));
                node.file.sha256 = digest.clone();
                node.file.path.set_extension("other");
                assert!(!registry.dropin(&node));
            }
        }
    }

    #[test]
    fn orphan_rejects_reload_alias_reenable_process_queue_and_triggers() {
        let registry = actual();
        let name = registry.dropins.keys().next().unwrap();
        for unit in [name.clone(), name.replace(".service", ".timer")] {
            let row = absent(&unit);
            registry.state(&unit, &row).unwrap();
            for (key, value) in [
                ("Id", "other.service"),
                ("Names", "alias.service"),
                ("Job", "779"),
                ("NeedDaemonReload", "yes"),
                ("DropInPaths", "/new.conf"),
                ("CanStart", "yes"),
                ("UnitFileState", "enabled"),
                ("FragmentPath", "/replacement.service"),
                ("LoadState", "loaded"),
                ("ActiveState", "activating"),
                ("SubState", "running"),
                ("MainPID", "125"),
                ("ControlPID", "125"),
                ("InvocationID", "changed"),
                ("ExecStart", "/foreign"),
                ("ControlGroup", "/live"),
                ("Transient", "yes"),
            ] {
                let mut changed = row.clone();
                changed[key] = json!(value);
                assert!(
                    registry.state(&unit, &changed).is_err(),
                    "accepted {unit} {key}"
                );
            }
            for key in BACKLINKS.into_iter().chain(["Requisite", "RequisiteOf"]) {
                let mut changed = row.clone();
                changed[key] = json!("activator.timer");
                assert!(
                    registry.state(&unit, &changed).is_err(),
                    "accepted {unit} {key}"
                );
            }
        }
    }

    #[test]
    fn terminal_requires_original_exit_result_invocation_command_and_no_pending_work() {
        let registry = actual();
        assert_eq!(registry.terminals.len(), 4);
        for (name, t) in &registry.terminals {
            let mut row = absent(name);
            for (k, v) in [
                ("LoadState", "loaded"),
                ("ActiveState", &t.state),
                ("SubState", &t.substate),
                ("Transient", "yes"),
                ("UnitFileState", "transient"),
                ("InvocationID", &t.invocation),
                ("ExecMainPID", &t.pid),
                ("ExecMainExitTimestampMonotonic", &t.exit_us),
                ("ExecMainStatus", &t.status),
                ("ExecMainCode", "1"),
                ("Result", &t.result),
                ("MainPID", "0"),
                ("ControlPID", "0"),
                ("NRestarts", "0"),
                ("ControlGroup", ""),
                ("Restart", "no"),
            ] {
                row[k] = json!(v);
            }
            row["ExecStart"] = json!(format!("{{ argv[]={0} ; }}", t.argv));
            row["FragmentPath"] = json!(t.fragment);
            row["Requisite"] = json!(t.requisite.join(" "));
            row["RequisiteOf"] = json!(
                t.requisite_of
                    .iter()
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            registry.state(name, &row).unwrap();
            for key in ["Requisite", "RequisiteOf"] {
                let expected = row[key].as_str().unwrap();
                for changed in [
                    format!("{expected} extra.service"),
                    format!("{expected} {expected}"),
                    String::new(),
                ] {
                    if changed.split_whitespace().count() == expected.split_whitespace().count() {
                        continue;
                    }
                    let mut r = row.clone();
                    r[key] = json!(changed);
                    assert!(
                        registry.state(name, &r).is_err(),
                        "changed historical prerequisite: {name} {key}"
                    );
                }
            }
            for key in [
                "LoadState",
                "Transient",
                "ActiveState",
                "SubState",
                "UnitFileState",
                "FragmentPath",
                "InvocationID",
                "ExecMainExitTimestampMonotonic",
                "ExecMainPID",
                "ExecMainCode",
                "Result",
                "ExecMainStatus",
                "MainPID",
                "ControlPID",
                "NRestarts",
                "ControlGroup",
                "Restart",
                "ExecStart",
                "TriggeredBy",
                "WantedBy",
                "Job",
                "DropInPaths",
            ] {
                let mut changed = row.clone();
                changed[key] = json!("changed");
                assert!(
                    registry.state(name, &changed).is_err(),
                    "accepted {name} {key}"
                );
            }
            row["ExecStart"] = json!(format!("argv[]={0} ; argv[]=/other ;", t.argv));
            assert!(registry.state(name, &row).is_err());
        }
    }

    #[test]
    fn hidden_activation_links_and_populated_descendants_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let name = "retired.service";
        let targets = BTreeSet::from([String::from(name)]);
        let want = t.join("sample.target.wants");
        fs::create_dir(&want).unwrap();
        let registry = Registered::default();
        registry.disk(&[t.into()], &targets).unwrap();
        symlink("../retired.service", want.join("alias.service")).unwrap();
        assert!(registry.disk(&[t.into()], &targets).is_err());
        fs::remove_file(want.join("alias.service")).unwrap();
        symlink("retired.service", t.join("middle.service")).unwrap();
        symlink("../middle.service", want.join("alias.service")).unwrap();
        assert!(reject_activation_link(&want.join("alias.service"), &targets).is_err());
        fs::remove_file(t.join("middle.service")).unwrap();
        symlink("/dev/null", want.join(name)).unwrap();
        assert!(registry.disk(&[t.into()], &targets).is_err());
        fs::remove_file(want.join(name)).unwrap();
        fs::write(t.join(name), "new fragment").unwrap();
        assert!(registry.disk(&[t.into()], &targets).is_err());
        let cg = t.join("group");
        group_empty(&cg).unwrap();
        fs::create_dir(&cg).unwrap();
        assert!(group_empty(&cg).is_err());
        fs::write(cg.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        assert!(group_empty(&cg).is_err());
        fs::write(cg.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
        group_empty(&cg).unwrap();
    }

    #[test]
    #[ignore = "read-only proof against the selected dev-samjohnson historical service registry"]
    fn actual_retired_managers_and_activation_namespace() {
        assert!(matches!(PARK, RETRY7_PARK | RETRY8_PARK | RETRY10_PARK | METERED168_PARK));
        Registered::profile(PARK).unwrap().verify().unwrap();
    }
}
