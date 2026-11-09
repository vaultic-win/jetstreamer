//! Exact reviewed, condition-blocked consumer envelopes. No legacy program is run.
//! Potential program/loader inputs remain distinct from currently admitted reads.
use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    unit: String,
    kind: String,
    fragment_path: PathBuf,
    fragment_sha256: String,
    program_path: PathBuf,
    program_sha256: String,
    argv: Vec<String>,
}
fn registrations() -> Result<Vec<Registration>> {
    Ok(serde_json::from_str(include_str!(
        "snapshot92447542_consumer_registry.json"
    ))?)
}
pub(super) fn registered_units() -> Result<BTreeSet<String>> {
    Ok(registrations()?.into_iter().map(|r| r.unit).collect())
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Parent {
    path: PathBuf,
    identity: DirectoryIdentity,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct InstalledFragment {
    path: PathBuf,
    raw_target: PathBuf,
    identity: Identity,
    parents: Vec<Parent>,
}
fn link_snapshot(path: &Path) -> Result<(PathBuf, Identity)> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.file_type().is_symlink(),
        "installed fragment is not a symlink"
    );
    let target = fs::read_link(path)?;
    ensure!(
        Identity::of(&before) == Identity::of(&fs::symlink_metadata(path)?)
            && target == fs::read_link(path)?,
        "installed fragment link changed"
    );
    Ok((target, Identity::of(&before)))
}
pub(super) fn installed(c: &Consumer, properties: &BTreeMap<String, String>) -> Result<Value> {
    let actual = PathBuf::from(
        properties
            .get("FragmentPath")
            .context("native fragment path missing")?,
    );
    ensure!(
        [
            Path::new("/etc/systemd/system").join(&c.unit),
            Path::new("/run/systemd/system").join(&c.unit)
        ]
        .contains(&actual),
        "unknown installed fragment namespace"
    );
    let mut current_parents = Vec::new();
    for path in actual
        .parent()
        .context("installed parent missing")?
        .ancestors()
    {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_dir() && path.canonicalize()? == path && m.uid() == 0 && m.mode() & 0o022 == 0,
            "installed fragment parent is unprotected"
        );
        current_parents.push(Parent {
            path: path.into(),
            identity: DirectoryIdentity::of(&m),
        });
    }
    if actual == c.fragment.path {
        ensure!(
            c.installed_fragment.is_none(),
            "unexpected installed alias binding"
        );
        return Ok(
            json!({"path":actual,"regular_canonical_fragment":true,"parents":current_parents}),
        );
    }
    let b = c
        .installed_fragment
        .as_ref()
        .context("separate installed alias binding required")?;
    ensure!(
        actual == b.path
            && [
                Path::new("/etc/systemd/system").join(&c.unit),
                Path::new("/run/systemd/system").join(&c.unit)
            ]
            .contains(&actual),
        "unknown installed fragment namespace"
    );
    let (target, id) = link_snapshot(&actual)?;
    ensure!(
        id == b.identity
            && id.uid == 0
            && id.gid == 0
            && target == b.raw_target
            && target == c.fragment.path
            && target.is_absolute()
            && actual.canonicalize()? == c.fragment.path,
        "installed alias custody/target changed"
    );
    let expected: Vec<_> = actual
        .parent()
        .context("alias parent missing")?
        .ancestors()
        .map(Path::to_path_buf)
        .collect();
    ensure!(
        b.parents.iter().map(|p| p.path.clone()).collect::<Vec<_>>() == expected,
        "incomplete alias parent custody chain"
    );
    for p in &b.parents {
        let m = fs::symlink_metadata(&p.path)?;
        ensure!(
            m.is_dir()
                && p.path.canonicalize()? == p.path
                && m.uid() == 0
                && m.mode() & 0o022 == 0
                && DirectoryIdentity::of(&m) == p.identity,
            "installed alias parent is replaced or writable"
        );
    }
    Ok(serde_json::to_value(b)?)
}
fn bus(unit: &str, property: &str) -> Result<(Value, Vec<u8>)> {
    bus_interface(unit, "org.freedesktop.systemd1.Service", property)
}
fn bus_interface(unit: &str, interface: &str, property: &str) -> Result<(Value, Vec<u8>)> {
    ensure!(safe_unit(unit), "unsafe native consumer unit");
    let object = format!(
        "/org/freedesktop/systemd1/unit/{}",
        unit.bytes()
            .map(|b| if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("_{b:02x}")
            })
            .collect::<String>()
    );
    let output = Command::new("/usr/bin/busctl")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "--json=short",
            "--timeout=3s",
            "get-property",
            "org.freedesktop.systemd1",
            &object,
            interface,
            property,
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 1 << 20,
        "native consumer D-Bus property failed"
    );
    Ok((serde_json::from_slice(&output.stdout)?, output.stdout))
}
const HOOKS: &[&str] = &[
    "ExecCondition",
    "ExecReload",
    "ExecStart",
    "ExecStartPost",
    "ExecStartPre",
    "ExecStop",
    "ExecStopPost",
];
const ENVIRONMENT: &[&str] = &[
    "Environment",
    "EnvironmentFiles",
    "PassEnvironment",
    "UnsetEnvironment",
    "ExecSearchPath",
    "WorkingDirectory",
    "RootDirectory",
    "RootImage",
];
fn command_argv(commands: &Value) -> Result<Vec<String>> {
    let map = commands.as_object().context("typed command map missing")?;
    ensure!(
        map.keys().map(String::as_str).collect::<BTreeSet<_>>() == HOOKS.iter().copied().collect(),
        "incomplete/unknown command hook set"
    );
    for key in HOOKS {
        let v = &map[*key];
        ensure!(v["type"] == "a(sasbttttuii)", "wrong typed command array");
        let rows = v["data"].as_array().context("typed command data missing")?;
        ensure!(
            if *key == "ExecStart" {
                rows.len() == 1
            } else {
                rows.is_empty()
            },
            "unexpected command hook or command count"
        );
    }
    let row = map["ExecStart"]["data"][0]
        .as_array()
        .context("ExecStart tuple missing")?;
    ensure!(
        row.len() == 10 && row[2] == false,
        "changed/ignored-error ExecStart tuple"
    );
    let argv: Vec<String> = serde_json::from_value(row[1].clone())?;
    ensure!(
        !argv.is_empty() && row[0] == argv[0],
        "ExecStart path/argv mismatch"
    );
    Ok(argv)
}
pub(super) fn native(c: &Consumer) -> Result<(Value, Vec<String>)> {
    let expected = evidence::bound_json(&c.native_commands)?;
    ensure!(
        expected["unit"] == c.unit,
        "typed command evidence belongs to another unit"
    );
    let expected = &expected["raw_typed_properties"];
    let argv = command_argv(expected)?;
    let (conditions, _) = bus_interface(&c.unit, "org.freedesktop.systemd1.Unit", "Conditions")?;
    ensure!(
        conditions["type"] == "a(sbbsi)"
            && conditions["data"]
                .as_array()
                .context("native condition array missing")?
                .iter()
                .any(|row| row.as_array().is_some_and(|a| a.len() == 5)
                    && row[0] == "ConditionPathExists"
                    && row[1] == false
                    && row[2] == true
                    && row[3] == c.guard_marker.path.to_str().unwrap_or("")),
        "exact non-trigger negative guard condition is not loaded by the manager"
    );
    let mut commands = BTreeMap::new();
    for key in HOOKS {
        let (value, _) = bus(&c.unit, key)?;
        ensure!(
            value == expected[*key],
            "effective consumer command changed"
        );
        commands.insert(*key, value);
    }
    let env = evidence::bound_json(&c.declared_environment)?;
    ensure!(
        env["unit"] == c.unit,
        "declared environment evidence belongs to another unit"
    );
    let digests = env["property_digests"]
        .as_object()
        .context("declared environment digest map missing")?;
    ensure!(
        digests.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == ENVIRONMENT.iter().copied().collect(),
        "incomplete declared environment envelope"
    );
    for key in ENVIRONMENT {
        let (value, bytes) = bus(&c.unit, key)?;
        ensure!(
            digests[*key]["type"] == value["type"] && digests[*key]["sha256"] == sha(&bytes),
            "declared consumer environment changed"
        );
    }
    Ok((
        json!({"typed_commands":commands,"actual_loaded_conditions":conditions,"declared_environment_sha256":c.declared_environment.sha256,"historical_loader_execution_not_asserted":true}),
        argv,
    ))
}
fn registration(c: &Consumer) -> Result<Registration> {
    let r = registrations()?
        .into_iter()
        .find(|r| r.unit == c.unit)
        .context("unregistered exact consumer unit")?;
    ensure!(
        r.kind == c.kind
            && r.fragment_path == c.fragment.path
            && r.fragment_sha256 == c.fragment.sha256
            && r.program_path == c.program.path
            && r.program_sha256 == c.program.sha256,
        "consumer differs from exact reviewed source envelope"
    );
    Ok(r)
}
pub(super) fn program(c: &Consumer, argv: &[String], sources: &[Value]) -> Result<()> {
    let r = registration(c)?;
    ensure!(
        argv == r.argv,
        "consumer mode, arguments or selected inputs changed"
    );
    root_bound_file(&c.program, 256 << 20, true)?;
    match c.kind.as_str() {
        "retired-importer" => {
            let image = c
                .importer
                .as_ref()
                .context("importer image binding missing")?;
            ensure!(
                image.path == c.program.path
                    && image.sha256 == IMPORTER_SHA
                    && image.sha256 == c.program.sha256
                    && sources.iter().any(|s| s["sha256"] == IMPORTER_MAIN_SHA)
                    && c.interpreter.is_none(),
                "unrecognized frozen importer/readset"
            );
            ensure!(
                argv.iter().any(|x| x == "--recover-staged-cohort-only"),
                "unreviewed importer mode"
            );
        }
        "retired-namespace-probe" => {
            ensure!(
                c.importer.is_none()
                    && argv.len() == 2
                    && argv[0] == "/bin/sh"
                    && Path::new(&argv[1]) == c.program.path,
                "probe is not the exact reviewed script invocation"
            );
            let interpreter = c
                .interpreter
                .as_ref()
                .context("probe interpreter missing")?;
            ensure!(
                Path::new("/bin/sh").canonicalize()? == interpreter.path,
                "probe interpreter changed"
            );
            root_bound_file(interpreter, 16 << 20, false)?;
        }
        "retired-other-slot-downloader" => {
            ensure!(
                c.importer.is_none()
                    && c.interpreter.is_none()
                    && !argv.iter().any(|x| x.contains("92447542")),
                "wrong downloader scope"
            );
        }
        "acquisition" => ensure!(
            c.unit == ACQUISITION_UNIT && c.importer.is_none() && c.interpreter.is_none(),
            "unknown acquisition scope"
        ),
        _ => bail!("unknown exact consumer kind"),
    }
    Ok(())
}
pub(super) fn readset(c: &Consumer, rs: &Value, sources: &[Value], argv: &[String]) -> Result<()> {
    ensure!(
        rs["schema"] == "jetstreamer-snapshot92447542-source-readset-v2"
            && rs["unit"] == c.unit
            && rs["fragment_sha256"] == c.fragment.sha256
            && rs["source_evidence"] == serde_json::to_value(sources)?
            && rs["effective_argv"] == serde_json::to_value(argv)?
            && rs["expanded_inputs_reviewed"] == true,
        "unreviewed consumer source/argument expansion"
    );
    ensure!(
        rs["scope"] == "potential-program-inputs-separate-from-condition-blocked-admitted-reads"
            && rs["currently_admitted_compressed_cache_reads"] == json!([])
            && rs["guard_sha256"] == c.guard.sha256
            && rs["guard_marker_sha256"] == c.guard_marker.sha256
            && rs["historical_loader_execution_qualified"] == false,
        "missing exact condition-blocked readset scope"
    );
    let potential: Vec<Bound> =
        serde_json::from_value(rs["potential_program_readset_evidence"].clone())?;
    ensure!(
        !potential.is_empty(),
        "potential program/loader input review missing"
    );
    for b in potential {
        root_bound_file(&b, 16 << 20, true)?;
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewAdmission {
    schema: String,
    issued_unix_seconds: u64,
    expires_unix_seconds: u64,
    self_binary: Bound,
    consumer_review: Bound,
    unit: String,
    invocation_id: String,
    expected_exec_start: String,
    output: PathBuf,
}
/// Independent metadata-only reader, sharing the production consumer proof.
/// No production Plan or lifecycle qualification is fabricated or bypassed.
pub(super) fn run_review(path: &str, admission_sha: &str, self_sha: &str) -> Result<()> {
    let bound = Bound {
        path: path.into(),
        sha256: admission_sha.into(),
    };
    let a: ReviewAdmission = serde_json::from_value(evidence::bound_json(&bound)?)?;
    ensure!(
        a.schema == "jetstreamer-snapshot92447542-consumer-review-admission-v1"
            && a.issued_unix_seconds <= now()?
            && now()? <= a.expires_unix_seconds
            && a.expires_unix_seconds > a.issued_unix_seconds
            && a.expires_unix_seconds - a.issued_unix_seconds <= 180,
        "consumer review admission expired/wrong route"
    );
    let self_path = fs::canonicalize("/proc/self/exe")?;
    let (actual, m) = evidence::hash_file(&self_path, 256 << 20)?;
    ensure!(
        self_path == a.self_binary.path
            && actual == a.self_binary.sha256
            && actual == self_sha
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && Identity::of(&m) == Identity::of(&fs::metadata("/proc/self/exe")?),
        "consumer reader self binding changed"
    );
    let parent = a.output.parent().context("review output parent missing")?;
    private_dir(parent)?;
    ensure!(
        a.output
            .file_name()
            .is_some_and(|x| x == "consumer-review.json")
            && absent(&a.output)?,
        "consumer review output occupied/unsafe"
    );
    let before = crate::snapshot92447542_census::native_owner(
        &a.unit,
        &a.invocation_id,
        &a.expected_exec_start,
        parent,
    )?;
    let target = Path::new(CACHE_ROOT).join(NAME);
    let original = Identity::of(&fs::symlink_metadata(&target)?);
    validate_original(&original)?;
    let proof = consumer_proof_core(&a.consumer_review, &original)?;
    ensure!(
        Identity::of(&fs::symlink_metadata(&target)?) == original
            && now()? <= a.expires_unix_seconds,
        "consumer reader original identity/clock changed"
    );
    let after = crate::snapshot92447542_census::native_owner(
        &a.unit,
        &a.invocation_id,
        &a.expected_exec_start,
        parent,
    )?;
    ensure!(before == after, "consumer reader owner changed");
    persist(
        &a.output,
        &json!({"schema":"jetstreamer-snapshot92447542-native-consumer-review-v1","admission":{"path":bound.path,"sha256":bound.sha256},"self_sha256":actual,"consumer_review_sha256":a.consumer_review.sha256,"before":before,"after":after,"original_identity":original,"proof":proof,"completed_unix_seconds":now()?,"cache_body_read":false,"lifecycle_qualification":false,"eviction_authorized":false,"restore_authorized":false,"replay_authorized":false,"remote_mutations":false}),
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn typed() -> Value {
        let mut m = serde_json::Map::new();
        for k in HOOKS {
            m.insert((*k).into(),json!({"type":"a(sasbttttuii)","data":if *k=="ExecStart"{json!([["/fixture",["/fixture"],false,0,0,0,0,0,0,0]])}else{json!([])}}));
        }
        Value::Object(m)
    }
    #[test]
    fn exact_registry_covers_all_eighteen_and_no_prefix_substitutes() {
        let rows = registrations().unwrap();
        assert_eq!(rows.len(), 18);
        assert_eq!(registered_units().unwrap().len(), 18);
        assert!(
            rows.iter()
                .any(|r| r.unit == "horizon-import-233-committed-v1.service")
        );
        assert!(
            rows.iter()
                .any(|r| r.unit == "horizon-publish-241-postcommit986-v1.service")
        );
        assert!(
            !rows
                .iter()
                .any(|r| r.unit == "horizon-import-233-unreviewed.service")
        );
        assert_eq!(
            rows.iter()
                .filter(|r| r.kind == "retired-namespace-probe")
                .count(),
            4
        );
        assert_eq!(
            rows.iter()
                .filter(|r| r.kind == "retired-other-slot-downloader")
                .count(),
            8
        );
    }
    #[test]
    fn all_eighteen_actual_native_arrays_match_their_registered_argv() {
        let fixture:Value=serde_json::from_str(include_str!("../../scripts/horizon_snapshot92447542_cache_v1/fixtures/actual18-typed-commands1042.json")).unwrap();
        let rows = registrations().unwrap();
        assert_eq!(fixture.as_object().unwrap().len(), rows.len());
        for r in rows {
            assert_eq!(command_argv(&fixture[&r.unit]).unwrap(), r.argv);
        }
    }
    #[test]
    fn typed_hook_inventory_cannot_hide_a_reload_or_prestart() {
        let good = typed();
        assert_eq!(command_argv(&good).unwrap(), vec!["/fixture"]);
        for key in HOOKS.iter().filter(|k| **k != "ExecStart") {
            let mut bad = good.clone();
            bad[*key]["data"] = good["ExecStart"]["data"].clone();
            assert!(command_argv(&bad).is_err());
        }
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("ExecStop");
        assert!(command_argv(&missing).is_err());
    }
    #[test]
    fn changed_argv_path_ignore_errors_or_extra_start_rejects() {
        let good = typed();
        let mut bad = good.clone();
        bad["ExecStart"]["data"][0][0] = json!("/other");
        assert!(command_argv(&bad).is_err());
        let mut bad = good.clone();
        bad["ExecStart"]["data"][0][2] = json!(true);
        assert!(command_argv(&bad).is_err());
        let mut bad = good.clone();
        bad["ExecStart"]["data"]
            .as_array_mut()
            .unwrap()
            .push(good["ExecStart"]["data"][0].clone());
        assert!(command_argv(&bad).is_err());
    }
    #[test]
    fn installed_link_retarget_or_recreation_changes_custody_even_with_same_bytes() {
        let t = tempfile::tempdir().unwrap();
        let a = t.path().join("a");
        let b = t.path().join("b");
        fs::write(&a, b"same").unwrap();
        fs::write(&b, b"same").unwrap();
        let link = t.path().join("installed.service");
        std::os::unix::fs::symlink(&a, &link).unwrap();
        let before = link_snapshot(&link).unwrap();
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&b, &link).unwrap();
        assert_ne!(link_snapshot(&link).unwrap(), before);
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&a, &link).unwrap();
        assert_ne!(link_snapshot(&link).unwrap(), before);
    }
}
