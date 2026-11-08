//! Child of persistent_reader: retire only the preserved0900 failed reader or
//! this executable's harmless failed-control unit. No payload/artifact removal.
use super::*;
const FAILED_IID: &str = "98d15a7a9691437da370d800125937b4";
const FAILED_PID: u64 = 3242681;
const FAILED_GENERATION: &str = "positive-8eef046c3ead415d9ad03ce6ee76e95c";
const FAILED_CAPTURE: &str = "/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0900-original-20261108-v19/1388-persistent-reader-native-original-outcome.json";
const FAILED_CAPTURE_SHA: &str = "ebbff7db86a4420b933f1dc4e790c2ac644d329bf81d7709e5e003dfd558b2da";
const SPEC: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-positive-enrolled-reader-8eef046c3ead415d9ad03ce6ee76e95c/spec.json";
const SPEC_SHA: &str = "547ac7a813b8108227730756c5f547882605df97c7454d9bfa483a94a7e412f0";
const CONTROL_PREFIX: &str = "horizon-positive185-reader-retirement-control-";

fn failed_shape(n: &Value, unit: &str, iid: &str, pid: u64) -> Result<()> {
    ensure!(
        storage::hex(iid, 32) && pid > 1 && pid <= i32::MAX as u64,
        "exact failed reader owner shape"
    );
    let pid_text = pid.to_string();
    ensure!(
        n["Id"] == unit && n["InvocationID"] == iid && n["ExecMainPID"] == pid_text.as_str(),
        "failed reader original owner/PID differs"
    );
    for (key, expected) in [
        ("LoadState", "loaded"),
        ("Transient", "no"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("ControlGroup", ""),
        ("Job", ""),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "exit-code"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", "1"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Type", "exec"),
        ("User", "root"),
        ("Group", "root"),
        ("RemainAfterExit", "no"),
    ] {
        ensure!(n[key] == expected, "failed reader terminal property: {key}");
    }
    let start = text(n, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?;
    let end = text(n, "ExecMainExitTimestampMonotonic")?.parse::<u64>()?;
    ensure!(
        start > 0 && end >= start,
        "failed reader original exit clock"
    );
    Ok(())
}
fn unchanged_failure(expected: &Value, actual: &Value) -> Result<()> {
    // Reload may clear display-only ExecStart timestamps/PID, while the
    // independent command_matches/profile checks retain the exact command.
    for field in FIELDS
        .split(',')
        .filter(|f| *f != "ExecStart" && *f != "FragmentPath")
    {
        ensure!(
            actual[field] == expected[field],
            "failed original changed: {field}"
        );
    }
    Ok(())
}
fn permitted(i: &Installed) -> Result<()> {
    ensure!(
        i.package.parent() == Some(Path::new("/usr/local/lib/jetstreamer"))
            && i.package
                .file_name()
                .and_then(|x| x.to_str())
                .is_some_and(|s| s.starts_with("horizon-positive185-persistent-reader-")),
        "fixed retired reader package namespace"
    );
    ensure!(
        unit_name(&i.unit) && unit_name(&i.keeper) && i.keeper.ends_with("-retain.target"),
        "retired reader/keeper names"
    );
    match i.kind {
        Kind::Production => ensure!(
            i.unit == READER_UNIT && i.argv.first().map(String::as_str) == Some(HELPER),
            "only exact failed production reader role"
        ),
        Kind::Control => ensure!(
            i.unit.starts_with(CONTROL_PREFIX) && i.unit.ends_with(".service"),
            "only harmless retirement control role"
        ),
    }
    Ok(())
}
fn package(i: &Installed) -> Result<()> {
    permitted(i)?;
    storage::bytes(&i.seal, 4 << 20, true)?;
    let seal = storage::json(&i.seal)?;
    ensure!(
        i.seal.path == i.package.join("deployment-seal-receipt.json")
            && seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["sealer_sha256"] == process::SEALER_SHA
            && seal["destination"] == i.package.to_string_lossy().as_ref(),
        "retired reader package normal seal crossed"
    );
    let rows = seal["members"]
        .as_array()
        .context("normal reader package members")?;
    ensure!(rows.len() == 2, "exact two reader package members");
    for (name, expected) in [
        (&i.unit, source(i.kind, &i.argv)?),
        (&i.keeper, keeper_source(&i.unit)?),
    ] {
        let matches = rows
            .iter()
            .filter(|x| x["name"] == *name && x["mode"] == "0444")
            .collect::<Vec<_>>();
        ensure!(matches.len() == 1, "exact normally sealed member");
        let member = Bound {
            path: i.package.join(name),
            sha256: text(matches[0], "sha256")?.into(),
        };
        ensure!(
            storage::bytes(&member, 1 << 20, true)? == expected.as_bytes(),
            "retired reader source differs"
        );
    }
    Ok(())
}
fn link_shape(uid: u32, gid: u32, symlink: bool, actual: &Path, expected: &Path) -> Result<()> {
    ensure!(
        uid == 0 && gid == 0 && symlink && actual == expected,
        "foreign or changed reader manager link"
    );
    Ok(())
}
fn link(i: &Installed, name: &str) -> Result<Value> {
    ensure!(
        name == i.unit || name == i.keeper,
        "only declared two manager aliases"
    );
    let parent = Path::new("/etc/systemd/system");
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        pm.is_dir()
            && !pm.file_type().is_symlink()
            && pm.uid() == 0
            && pm.gid() == 0
            && pm.mode() & 0o022 == 0,
        "Root manager directory custody"
    );
    ensure!(
        fs::symlink_metadata(Path::new("/run/systemd/system").join(name))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "foreign runtime reader alias"
    );
    let path = parent.join(name);
    let m = fs::symlink_metadata(&path)?;
    let target = fs::read_link(&path)?;
    link_shape(
        m.uid(),
        m.gid(),
        m.file_type().is_symlink(),
        &target,
        &i.package.join(name),
    )?;
    Ok(
        json!({"path":path,"target":target,"dev":m.dev(),"ino":m.ino(),"uid":m.uid(),
        "gid":m.gid(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()}),
    )
}
fn original_journal(r: &mut process::Runner<'_>, n: &Value) -> Result<Bound> {
    let unit = text(n, "Id")?;
    let iid = text(n, "InvocationID")?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let mut c = Command::new("/usr/bin/journalctl");
    c.args([
        "--all",
        "--no-pager",
        "-ojson",
        "-n",
        "64",
        "_PID=1",
        "_UID=0",
        &format!("UNIT={unit}"),
        &format!("INVOCATION_ID={iid}"),
    ]);
    let out = r.run("failed-reader-original-PID1", c, Duration::from_secs(5))?;
    let raw: Vec<u8> = serde_json::from_value(out["stdout_bytes"].clone())?;
    let rows = std::str::from_utf8(&raw)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let exit = text(n, "ExecMainExitTimestampMonotonic")?.parse::<u64>()?;
    ensure!(
        rows.iter().any(|x| x["_PID"] == "1"
            && x["_UID"] == "0"
            && x["UNIT"] == unit
            && x["INVOCATION_ID"] == iid
            && x["_BOOT_ID"] == boot
            && x["MESSAGE"] == format!("{unit}: Failed with result 'exit-code'.")
            && x["__MONOTONIC_TIMESTAMP"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|at| at >= exit)),
        "actual same-boot original PID1 failure absent"
    );
    storage::save(
        r.root,
        "failed-reader-original-PID1.json",
        &json!({"unit":unit,"iid":iid,"rows":rows}),
    )
}
fn inactive(n: &Value) -> Result<()> {
    ensure!(
        n["ActiveState"] == "inactive"
            && n["Job"] == ""
            && n.get("MainPID").is_none_or(|p| p == "0")
            && n.get("ControlPID").is_none_or(|p| p == "0"),
        "retired role not dormant"
    );
    Ok(())
}
fn cleanup(r: &mut process::Runner<'_>, i: &Installed, original: &Value) -> Result<Bound> {
    package(i)?;
    let iid = text(original, "InvocationID")?;
    let pid = text(original, "ExecMainPID")?.parse::<u64>()?;
    failed_shape(original, &i.unit, iid, pid)?;
    let current = query(r, &i.unit)?;
    profile(&current, i)?;
    failed_shape(&current, &i.unit, iid, pid)?;
    unchanged_failure(original, &current)?;
    ensure!(
        !Path::new(&format!("/proc/{pid}")).try_exists()?,
        "original failed reader PID still exists"
    );
    control_group_empty(&i.unit)?;
    let keeper = r.native(&i.keeper)?;
    ensure!(
        keeper["LoadState"] == "loaded"
            && keeper["ActiveState"] == "active"
            && keeper["SubState"] == "active"
            && keeper["Job"] == ""
            && storage::hex(text(&keeper, "InvocationID")?, 32),
        "exact original keeper not active"
    );
    let keeper_cgroup = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{}", i.keeper));
    ensure!(!keeper_cgroup.try_exists()?, "keeper owns process cgroup");
    let service_link = link(i, &i.unit)?;
    let keeper_link = link(i, &i.keeper)?;
    let journal = original_journal(r, &current)?;
    let intent = storage::save(
        r.root,
        "failed-reader-retirement-intent.json",
        &json!({"original_failed_native":current,"original_PID1_journal":journal,"package_seal":i.seal,
        "keeper_native":keeper,"service_link":service_link,"keeper_link":keeper_link,
        "original_PID_absent":true,"original_cgroup_empty":true,"only_empty_keeper_stop_authorized":true,
        "only_two_exact_manager_links_authorized":true,"all_original_payloads_and_failed_output_preserved":true}),
    )?;
    let mut c = Command::new("/usr/bin/systemctl");
    c.args(["stop", &i.keeper]);
    r.run("stop-only-empty-reader-keeper", c, Duration::from_secs(5))?;
    inactive(&r.native(&i.keeper)?)?;
    ensure!(
        !keeper_cgroup.try_exists()?,
        "stopped keeper owns process cgroup"
    );
    let last = query(r, &i.unit)?;
    profile(&last, i)?;
    failed_shape(&last, &i.unit, iid, pid)?;
    unchanged_failure(original, &last)?;
    control_group_empty(&i.unit)?;
    // Reset while the exact sealed alias still exists, after the immutable
    // failure evidence above. This avoids reset racing manager GC after unlink.
    let mut c = Command::new("/usr/bin/systemctl");
    c.args(["reset-failed", &i.unit]);
    r.run(
        "reset-only-preserved-failed-reader",
        c,
        Duration::from_secs(5),
    )?;
    inactive(&r.native(&i.unit)?)?;
    let timers_before = crate::timers::capture(r, "retire-reader-before")?;
    ensure!(
        link(i, &i.unit)? == service_link && link(i, &i.keeper)? == keeper_link,
        "manager alias changed before unlink"
    );
    for name in [&i.unit, &i.keeper] {
        fs::remove_file(Path::new("/etc/systemd/system").join(name))?;
    }
    fs::File::open("/etc/systemd/system")?.sync_all()?;
    let mut c = Command::new("/usr/bin/systemctl");
    c.arg("daemon-reload");
    r.run(
        "retire-reader-one-audited-reload",
        c,
        Duration::from_secs(15),
    )?;
    let timers_after = crate::timers::capture_after(r, "retire-reader-after", &timers_before)?;
    let audit = crate::timers::validate(&timers_before, &timers_after)?;
    let timer_proof = storage::save(
        r.root,
        "failed-reader-retirement-timer-audit.json",
        &json!({"before":timers_before,"after":timers_after,"audit":audit}),
    )?;
    for name in [&i.unit, &i.keeper] {
        for dir in ["/etc/systemd/system", "/run/systemd/system"] {
            ensure!(
                fs::symlink_metadata(Path::new(dir).join(name))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "reader manager alias remains"
            );
        }
        inactive(&r.native(name)?)?;
        control_group_empty(name)?;
    }
    let final_reader = r.native(&i.unit)?;
    let final_keeper = r.native(&i.keeper)?;
    storage::save(
        r.root,
        "failed-reader-retirement-completion.json",
        &json!({"schema":"horizon-positive185-failed-reader-manager-retirement-v1","intent":intent,
        "original_PID1_journal":journal,"timer_audit":timer_proof,"final_reader_native":final_reader,
        "final_keeper_native":final_keeper,"actual_two_owned_manager_aliases_removed":true,
        "actual_same_shared_retirement_primitive_exercised":true,"only_failed_reader_reset":true,
        "only_zero_process_keeper_stopped":true,"sealed_packages_and_failed_namespaces_preserved":true,
        "input_body_reads":0,"resource_credit_bytes":0,"replay_launch_authorized":false,
        "publication_authorized":false,"program":r.self_image}),
    )
}
fn control_proof(r: &process::Runner<'_>, b: &Bound) -> Result<()> {
    ensure!(
        b.path.file_name().and_then(|x| x.to_str()) == Some("completion.json")
            && b.path.parent().and_then(Path::parent)
                == Some(Path::new("/usr/local/lib/jetstreamer")),
        "normally sealed retirement control required"
    );
    let seal = process::bind_file(
        &b.path
            .parent()
            .context("control parent")?
            .join("deployment-seal-receipt.json"),
        4 << 20,
    )?;
    storage::bytes(b, 4 << 20, true)?;
    storage::bytes(&seal, 4 << 20, true)?;
    let s = storage::json(&seal)?;
    ensure!(
        s["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && s["sealer_sha256"] == process::SEALER_SHA
            && s["destination"]
                == b.path
                    .parent()
                    .context("control parent")?
                    .to_string_lossy()
                    .as_ref()
            && s["members"]
                .as_array()
                .context("control seal members")?
                .iter()
                .filter(|x| x["name"] == "completion.json"
                    && x["sha256"] == b.sha256
                    && x["mode"] == "0444")
                .count()
                == 1,
        "retirement control normal seal differs"
    );
    let p = storage::json(b)?;
    ensure!(
        p["schema"] == "horizon-positive185-failed-reader-retirement-native-control-v1"
            && p["program"]["sha256"] == r.self_image.sha256
            && p["actual_two_owned_manager_aliases_removed"] == true
            && p["actual_same_shared_retirement_primitive_exercised"] == true
            && p["input_body_reads"] == 0
            && p["replay_launch_authorized"] == false,
        "actual same-image retirement control missing"
    );
    ensure!(
        p["actual_failed_original_pidfd_wait"]["actual_original_pidfd_exit_event"] == true,
        "native retirement control did not exercise actual failed pidfd exit"
    );
    let own = role(
        r.self_image.path.to_str().context("self image UTF8")?,
        &r.self_image.sha256,
    )?;
    ensure!(
        storage::json(&binding(&own["artifact"])?)?["all_required_tests_passed"] == true,
        "final qualified image required before production retirement"
    );
    Ok(())
}
pub(crate) fn execute(v: &Value, r: &mut process::Runner<'_>) -> Result<()> {
    ensure!(
        v["schema"] == "positive185-retire-exact0630-failed-reader-v1",
        "exact0630 retirement request"
    );
    control_proof(r, &binding(&v["native_retirement_control"])?)?;
    let capture = fixed(FAILED_CAPTURE, FAILED_CAPTURE_SHA);
    let raw = storage::json(&capture)?;
    let expected_argv = [
        "show",
        READER_UNIT,
        "--no-pager",
        &format!("--property={FIELDS}"),
    ];
    ensure!(
        raw["program"] == "/usr/bin/systemctl"
            && raw["argv"] == json!(expected_argv)
            && raw["exit_code"] == 0
            && raw["wait_error"].is_null()
            && raw["stdout_overflow"] == false
            && raw["stdout_read_error"].is_null(),
        "exact original failed reader metadata capture"
    );
    let bytes: Vec<u8> = serde_json::from_value(raw["stdout_bytes"].clone())?;
    let original = parse(&bytes)?;
    failed_shape(&original, READER_UNIT, FAILED_IID, FAILED_PID)?;
    let package = Path::new("/usr/local/lib/jetstreamer").join(format!(
        "horizon-positive185-persistent-reader-{FAILED_GENERATION}"
    ));
    let i = Installed {
        unit: READER_UNIT.into(),
        keeper: format!("horizon-positive185-reader-{FAILED_GENERATION}-retain.target"),
        argv: vec![
            HELPER.into(),
            "read-failed4-current-accounting".into(),
            SPEC.into(),
            "--spec-sha256".into(),
            SPEC_SHA.into(),
            "--self-sha256".into(),
            HELPER_SHA.into(),
        ],
        kind: Kind::Production,
        seal: process::bind_file(&package.join("deployment-seal-receipt.json"), 4 << 20)?,
        package,
    };
    let done = cleanup(r, &i, &original)?;
    println!(
        "{}",
        json!({"actual_failed_reader_retirement":done,"no_replay_or_archive_authority":true})
    );
    Ok(())
}
pub(crate) fn harmless_fail(spec: &Bound, own: &Bound) -> Result<()> {
    super::harmless_exec(spec, own)?;
    std::thread::sleep(Duration::from_secs(2));
    anyhow::bail!("intentional metadata-only failed reader retirement control")
}
pub(crate) fn qualify(r: &mut process::Runner<'_>) -> Result<()> {
    let generation = format!("retire-{}", r.iid);
    generation_check(&generation)?;
    let declaration = storage::save(
        r.root,
        "harmless-failed-reader-control-spec.json",
        &json!({"schema":"horizon-positive185-reader-lifecycle-harmless-child-v1","generation":generation}),
    )?;
    let published = seal(
        r,
        "harmless-failed-reader-control-spec",
        &Path::new("/usr/local/lib/jetstreamer").join(format!(
            "horizon-positive185-retirement-control-spec-{generation}"
        )),
        &[("spec.json", declaration)],
    )?;
    let spec = binding(&published["members"]["spec.json"])?;
    let argv = vec![
        r.self_image.path.display().to_string(),
        "reader-lifecycle-harmless-fail".into(),
        spec.path.display().to_string(),
        "--request-sha256".into(),
        spec.sha256,
        "--self-sha256".into(),
        r.self_image.sha256.clone(),
    ];
    let unit = format!("{CONTROL_PREFIX}{}.service", r.iid);
    let i = install(r, &generation, unit, argv, Kind::Control)?;
    let mut c = Command::new("/usr/bin/systemctl");
    c.args(["start", &i.keeper]);
    r.run(
        "start-only-harmless-failed-reader-control",
        c,
        Duration::from_secs(5),
    )?;
    let observed = query(r, &i.unit)?;
    profile(&observed, &i)?;
    ensure!(
        observed["ActiveState"] == "active" && observed["SubState"] == "running",
        "actual harmless control running PID required"
    );
    let wait = wait_original_pid(r, &observed, Instant::now() + Duration::from_secs(8))?;
    ensure!(
        wait["actual_original_pidfd_exit_event"] == true,
        "actual failed control pidfd path required"
    );
    let original = query(r, &i.unit)?;
    profile(&original, &i)?;
    let done = cleanup(r, &i, &original)?;
    let mut proof = storage::json(&done)?;
    proof["schema"] = json!("horizon-positive185-failed-reader-retirement-native-control-v1");
    proof["actual_failed_original_pidfd_wait"] = wait;
    let bound = storage::save(
        r.root,
        "actual-failed-reader-retirement-native-control.json",
        &proof,
    )?;
    let published = seal(
        r,
        "failed-reader-retirement-control-completion",
        &Path::new("/usr/local/lib/jetstreamer").join(format!(
            "horizon-positive185-failed-reader-retirement-control-{}",
            r.iid
        )),
        &[("completion.json", bound)],
    )?;
    println!("{}", published);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn failed() -> Value {
        json!({"Id":"test.service","InvocationID":"a".repeat(32),"ExecMainPID":"321", "LoadState":"loaded","Transient":"no",
        "MainPID":"0","ControlPID":"0","ControlGroup":"","Job":"","NRestarts":"0","Restart":"no","Result":"exit-code",
        "ExecMainCode":"1","ExecMainStatus":"1","ActiveState":"failed","SubState":"failed","Type":"exec","User":"root","Group":"root",
        "RemainAfterExit":"no","ExecMainStartTimestampMonotonic":"1000","ExecMainExitTimestampMonotonic":"2000"})
    }
    #[test]
    fn failed_reader_rejects_live_jobs_restarts_success_and_crossed_owner() {
        let a = failed();
        failed_shape(&a, "test.service", &"a".repeat(32), 321).unwrap();
        for (key, value) in [
            ("MainPID", "2"),
            ("ControlPID", "3"),
            ("Job", "queued"),
            ("NRestarts", "1"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("InvocationID", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ("ExecMainPID", "322"),
        ] {
            let mut b = a.clone();
            b[key] = json!(value);
            assert!(
                failed_shape(&b, "test.service", &"a".repeat(32), 321).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn foreign_manager_link_custody_or_target_never_authorizes_unlink() {
        let p = Path::new("/usr/local/lib/jetstreamer/qualified/member.service");
        link_shape(0, 0, true, p, p).unwrap();
        assert!(link_shape(1001, 0, true, p, p).is_err());
        assert!(link_shape(0, 1001, true, p, p).is_err());
        assert!(link_shape(0, 0, false, p, p).is_err());
        assert!(link_shape(0, 0, true, Path::new("/etc/foreign"), p).is_err());
    }
    #[test]
    fn authoritative_native_fields_never_borrow_display_only_reload_exception() {
        let a = failed();
        let mut b = a.clone();
        b["ExecStart"] = json!("cleared-display-only");
        unchanged_failure(&a, &b).unwrap();
        b["ExecMainPID"] = json!("322");
        assert!(unchanged_failure(&a, &b).is_err());
        b = a.clone();
        b["InvocationID"] = json!("b".repeat(32));
        assert!(unchanged_failure(&a, &b).is_err());
    }
    #[test]
    fn crossed_package_or_production_role_cannot_enter_retirement() {
        let mut i = Installed {
            unit: READER_UNIT.into(),
            keeper: "horizon-positive185-reader-test-retain.target".into(),
            argv: vec![HELPER.into()],
            kind: Kind::Production,
            package: "/usr/local/lib/jetstreamer/horizon-positive185-persistent-reader-test".into(),
            seal: fixed("/test/seal.json", &"a".repeat(64)),
        };
        permitted(&i).unwrap();
        i.package = "/etc/systemd/system".into();
        assert!(permitted(&i).is_err());
        i.package = "/usr/local/lib/jetstreamer/foreign".into();
        assert!(permitted(&i).is_err());
        i.package = "/usr/local/lib/jetstreamer/horizon-positive185-persistent-reader-test".into();
        i.unit = "healthy-replay.service".into();
        assert!(permitted(&i).is_err());
        i.unit = READER_UNIT.into();
        i.argv[0] = "/bin/false".into();
        assert!(permitted(&i).is_err());
    }
    #[test]
    fn dormant_role_cannot_hide_active_jobs_or_processes() {
        let a = json!({"ActiveState":"inactive","Job":"","MainPID":"0","ControlPID":"0"});
        inactive(&a).unwrap();
        for key in ["Job", "MainPID", "ControlPID"] {
            let mut b = a.clone();
            b[key] = json!("1");
            assert!(inactive(&b).is_err());
        }
    }
}
