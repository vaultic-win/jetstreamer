//! Child of persistent_reader: retire only exact preserved successful readers or
//! this executable's harmless successful-control unit. No payload/artifact removal.
use super::*;
const SUCCESSFUL_HELPER: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-ready-custody-postreader-tools-20261108-v30/jetstreamer-r2";
const SUCCESSFUL_HELPER_SHA: &str =
    "51381649ca4a4b353c738d37435bbfc594a36077a01f5d3a510504e8341a670f";
const SUCCESSFUL_IID: &str = "43dca2b7a35c42e6a67ed1c197be7cc4";
const SUCCESSFUL_PID: u64 = 3497331;
const SUCCESSFUL_GENERATION: &str = "positive-56e8732c576449908e19e099c954a61a";
const SUCCESSFUL_CAPTURE: &str = "/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual1630-original-r3-20261108-next/1953-persistent-reader-native-original-outcome.json";
const SUCCESSFUL_CAPTURE_SHA: &str =
    "2182398f49d9ef31bea47781d0f7eb297281f5096999d6d3dc3d7b7f324f9747";
const SPEC: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-positive-enrolled-reader-56e8732c576449908e19e099c954a61a/spec.json";
const SPEC_SHA: &str = "db945e093c756ee965d565f744e7be3db336598ecb7c665f20c9ab4007f34fa9";
const CONTROL_PREFIX: &str = "horizon-positive185-reader-retirement-control-";
const HELPER1800: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-typed-peer-postreader-tools-20261108-v31/jetstreamer-r2";
const HELPER1800_SHA: &str = "25b0c4114639d74f5cc7136857b61437e77085cca190c5533d48a3734723bd0b";
const ACTOR1800: &str =
    "horizon-qualify-185-capped-cold-positive-positive-1800-20261108-next.service";
const ACTOR1800_IID: &str = "c03a3715825a41cc9ae16c6c361bc302";
const READER1800_IID: &str = "4654538cd74f412ba5a1108bb11c0ece";
const READER1800_PID: u64 = 3557772;
const ROOT1800: &str = "/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual1800-original-r3-20261108-next";

// Exact newly observed0100 successful reader; historical1630/1800 routes stay separate.
const ACTOR0100: &str = "horizon-qualify-185-capped-cold-positive-positive-0100-20261109-next.service";
const ACTOR0100_IID: &str = "9568cb52af154f7d8fbd48e7571770fa";
const READER0100_IID: &str = "d7392886345a460996fa632037bb5a2c";
const READER0100_PID: u64 = 3825939;
const ROOT0100: &str = "/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0100-original-r3-20261109-next";
const HELPER0100: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-inherited-census-postreader-tools-20261108-v34/jetstreamer-r2";
const HELPER0100_SHA: &str = "dda7f44b24b7d9475c654efea20e2230f8374df9640b3e0bf724e7edac44c389";
fn installed0100() -> Installed {
 let package=PathBuf::from("/usr/local/lib/jetstreamer/horizon-positive185-persistent-reader-positive-9568cb52af154f7d8fbd48e7571770fa");
 Installed {unit:READER_UNIT.into(),keeper:"horizon-positive185-reader-positive-9568cb52af154f7d8fbd48e7571770fa-retain.target".into(),
 argv:vec![HELPER0100.into(),"read-failed4-current-accounting".into(),"/usr/local/lib/jetstreamer/horizon-epoch185-positive-enrolled-reader-9568cb52af154f7d8fbd48e7571770fa/spec.json".into(),"--spec-sha256".into(),"39ca0f00c63908887eee3fcaf8a4b1898f49aa192a056919bbc0b38d8ee805dd".into(),"--self-sha256".into(),HELPER0100_SHA.into()],kind:Kind::Production,
 seal:fixed("/usr/local/lib/jetstreamer/horizon-positive185-persistent-reader-positive-9568cb52af154f7d8fbd48e7571770fa/deployment-seal-receipt.json","41f49ddf825001c2db6662ea7afd60152fce93c5013e4bfa41b4e291351d2237"),package}
}
fn exact0100_installed(i: &Installed) -> bool {
 let expected=installed0100();
 matches!(i.kind,Kind::Production) && i.unit==expected.unit && i.keeper==expected.keeper && i.argv==expected.argv && i.package==expected.package && i.seal==expected.seal
}

fn successful_shape(n: &Value, unit: &str, iid: &str, pid: u64) -> Result<()> {
    ensure!(
        storage::hex(iid, 32) && pid > 1 && pid <= i32::MAX as u64,
        "exact successful reader owner shape"
    );
    let pid_text = pid.to_string();
    ensure!(
        n["Id"] == unit && n["InvocationID"] == iid && n["ExecMainPID"] == pid_text.as_str(),
        "successful reader original owner/PID differs"
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
        ("Result", "success"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", "0"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("Type", "exec"),
        ("User", "root"),
        ("Group", "root"),
        ("RemainAfterExit", "no"),
    ] {
        ensure!(
            n[key] == expected,
            "successful reader terminal property: {key}"
        );
    }
    let start = text(n, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?;
    let end = text(n, "ExecMainExitTimestampMonotonic")?.parse::<u64>()?;
    ensure!(
        start > 0 && end >= start,
        "successful reader original exit clock"
    );
    Ok(())
}
fn unchanged_successful(expected: &Value, actual: &Value) -> Result<()> {
    // Reload may clear display-only ExecStart timestamps/PID, while the
    // independent command_matches/profile checks retain the exact command.
    for field in FIELDS
        .split(',')
        .filter(|f| *f != "ExecStart" && *f != "FragmentPath")
    {
        ensure!(
            actual[field] == expected[field],
            "successful original changed: {field}"
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
            (i.unit == READER_UNIT
                && [SUCCESSFUL_HELPER, HELPER1800]
                    .contains(&i.argv.first().context("retired reader image")?.as_str())) || exact0100_installed(i),
            "only exact successful production reader role"
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
    let out = r.run("successful-reader-original-PID1", c, Duration::from_secs(5))?;
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
            && x["MESSAGE"] == format!("{unit}: Deactivated successfully.")
            && x["__MONOTONIC_TIMESTAMP"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|at| at >= exit)),
        "actual same-boot original PID1 success absent"
    );
    storage::save(
        r.root,
        "successful-reader-original-PID1.json",
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
    successful_shape(original, &i.unit, iid, pid)?;
    let current = query(r, &i.unit)?;
    profile(&current, i)?;
    successful_shape(&current, &i.unit, iid, pid)?;
    unchanged_successful(original, &current)?;
    ensure!(
        !Path::new(&format!("/proc/{pid}")).try_exists()?,
        "original successful reader PID still exists"
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
        "successful-reader-retirement-intent.json",
        &json!({"original_successful_native":current,"original_PID1_journal":journal,"package_seal":i.seal,
        "keeper_native":keeper,"service_link":service_link,"keeper_link":keeper_link,
        "original_PID_absent":true,"original_cgroup_empty":true,"only_empty_keeper_stop_authorized":true,
        "only_two_exact_manager_links_authorized":true,"all_original_payloads_and_successful_output_preserved":true}),
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
    inactive(&last)?;
    ensure!(
        last["NRestarts"] == "0"
            && last["ControlGroup"] == ""
            && last["Result"] == "success"
            && last["ExecMainStatus"] == "0",
        "successful original no-new-claim after keeper stop"
    );
    if last["InvocationID"] == iid {
        successful_shape(&last, &i.unit, iid, pid)?;
        unchanged_successful(original, &last)?;
    } else {
        ensure!(
            last["InvocationID"] == ""
                && last["ExecMainPID"] == "0"
                && last["ExecMainStartTimestampMonotonic"] == "0"
                && last["ExecMainExitTimestampMonotonic"] == "0",
            "only genuine cleared inactive success display after GC"
        );
    }
    control_group_empty(&i.unit)?;
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
        "successful-reader-retirement-timer-audit.json",
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
        "successful-reader-retirement-completion.json",
        &json!({"schema":"horizon-positive185-successful-reader-manager-retirement-v1","intent":intent,
        "original_PID1_journal":journal,"timer_audit":timer_proof,"final_reader_native":final_reader,
        "final_keeper_native":final_keeper,"actual_two_owned_manager_aliases_removed":true,
        "actual_same_shared_retirement_primitive_exercised":true,"only_successfully_completed_reader_retired":true,"reset_failed_called":false,
        "only_zero_process_keeper_stopped":true,"sealed_packages_and_successful_namespaces_preserved":true,
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
        p["schema"] == "horizon-positive185-successful-reader-retirement-native-control-v1"
            && p["program"]["sha256"] == r.self_image.sha256
            && p["actual_two_owned_manager_aliases_removed"] == true
            && p["actual_same_shared_retirement_primitive_exercised"] == true
            && p["input_body_reads"] == 0
            && p["replay_launch_authorized"] == false,
        "actual same-image retirement control missing"
    );
    ensure!(
        p["actual_successful_original_pidfd_wait"]["actual_original_pidfd_exit_event"] == true,
        "native retirement control did not exercise actual successful pidfd exit"
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
fn execute1630(v: &Value, r: &mut process::Runner<'_>) -> Result<()> {
    ensure!(
        v["schema"] == "positive185-retire-exact1630-successful-reader-v1",
        "exact1630 successful retirement request"
    );
    let expiry = fixed(
        "/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual1630-original-r3-20261108-next/ROOT_ACTUAL1630_ORIGINAL_SETUP_EXPIRED_AND_DRAINED.json",
        "19b8a02bd3aa2f4a11be822c4d23d71d90a9e53a75739548b9df67e88c6500f2",
    );
    let ended = storage::json(&expiry)?;
    ensure!(
        ended["original_invocation_id"] == "56e8732c576449908e19e099c954a61a"
            && ended["original_setup_deadline"] == 1794156381u64
            && ended["main_never_started"] == true
            && ended["token_destination_absent"] == true
            && ended["original_process_absent"] == true
            && ended["original_cgroup_empty"] == true
            && ended["no_second_final_attempt"] == true
            && now()? > 1794156381,
        "exact successful1630reader no-final-consumer expiry"
    );
    let final_outcome = storage::json(&binding(&ended["final_original_outcome"])?)?;
    ensure!(
        final_outcome["exit_code"] == 1
            && final_outcome["wait_error"].is_null()
            && final_outcome["program"] == FINAL
            && ended["final_control_root_empty"] == false
            && ended["actual_postreader_context_never_written"] == false,
        "actual failed original final consumer preserved and reaped"
    );
    control_proof(r, &binding(&v["native_retirement_control"])?)?;
    let capture = fixed(SUCCESSFUL_CAPTURE, SUCCESSFUL_CAPTURE_SHA);
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
        "exact original successful reader metadata capture"
    );
    let bytes: Vec<u8> = serde_json::from_value(raw["stdout_bytes"].clone())?;
    let original = parse(&bytes)?;
    successful_shape(&original, READER_UNIT, SUCCESSFUL_IID, SUCCESSFUL_PID)?;
    let package = Path::new("/usr/local/lib/jetstreamer").join(format!(
        "horizon-positive185-persistent-reader-{SUCCESSFUL_GENERATION}"
    ));
    let i = Installed {
        unit: READER_UNIT.into(),
        keeper: format!("horizon-positive185-reader-{SUCCESSFUL_GENERATION}-retain.target"),
        argv: vec![
            SUCCESSFUL_HELPER.into(),
            "read-failed4-current-accounting".into(),
            SPEC.into(),
            "--spec-sha256".into(),
            SPEC_SHA.into(),
            "--self-sha256".into(),
            SUCCESSFUL_HELPER_SHA.into(),
        ],
        kind: Kind::Production,
        seal: process::bind_file(&package.join("deployment-seal-receipt.json"), 4 << 20)?,
        package,
    };
    let done = cleanup(r, &i, &original)?;
    println!(
        "{}",
        json!({"actual_successful_reader_retirement":done,"no_replay_or_archive_authority":true})
    );
    Ok(())
}
fn expiry1800_shape(ended: &Value, at: u64) -> Result<()> {
    ensure!(
        ended["schema"]
            == "horizon-positive185-original1800-expiry-and-failed-guard-timer-retirement-event-v1"
            && ended["original_actor"]["Id"] == ACTOR1800
            && ended["original_actor"]["InvocationID"] == ACTOR1800_IID
            && ended["original_actor"]["MainPID"] == "0"
            && ended["original_actor"]["ControlPID"] == "0"
            && ended["original_actor"]["Job"] == ""
            && ended["original_actor"]["NRestarts"] == "0"
            && ended["original_setup_deadline"] == 1794161757u64
            && at > 1794161757
            && ended["original_control_PID_absent"] == true
            && ended["token_absent"] == true
            && ended["original_actor_unchanged"] == true
            && ended["no_retry_or_clock_reset_or_actor_restart"] == true
            && ended["only_new_failed_guard_timer_stopped"] == true
            && ended["reset_failed_called"] == false
            && ended["raw_memory_and_DATA_promises_preserved"] == true
            && ended["resource_credit_bytes"] == 0
            && ended["final_timer"]["ActiveState"] == "inactive"
            && ended["final_timer"]["SubState"] == "dead"
            && ended["final_timer"]["Job"] == "",
        "exact1800 actor/failed-guard expiry without resource credit"
    );
    Ok(())
}
fn execute1800(v: &Value, r: &mut process::Runner<'_>) -> Result<()> {
    let expiry = fixed(
        &format!(
            "{ROOT1800}/ROOT_ACTUAL1800_ORIGINAL_EXPIRED_FAILED_GUARD_TIMER_RETIRED_NO_CREDIT.json"
        ),
        "24e8285bf579d852693fbf5dd54fc003fdaac171bfd0bce4741b17bf8900a9c1",
    );
    let ended = storage::json(&expiry)?;
    expiry1800_shape(&ended, now()?)?;
    let actor = r.native(ACTOR1800)?;
    ensure!(
        actor["InvocationID"] == ACTOR1800_IID
            && actor["MainPID"] == "0"
            && actor["ControlPID"] == "0"
            && actor["Job"] == ""
            && actor["NRestarts"] == "0"
            && actor["ActiveState"] == "failed",
        "exact1800 expired actor changed or is active"
    );
    let failed = storage::json(&binding(&ended["original_final_failure"])?)?;
    ensure!(
        failed["original_setup_deadline"] == 1794161757u64
            && failed["no_retry_clock_reset_fake_success_or_actor_restart"] == true,
        "actual1800 final failure source crossed"
    );
    let outer = storage::json(&fixed(
        &format!("{ROOT1800}/3310-actual-c71-one-original-final-original-outcome.json"),
        "f993e51686d714eb5855be8afa8e706382f27faf4aec611775f88490b4984a2c",
    ))?;
    ensure!(
        outer["program"] == FINAL
            && outer["exit_code"] == 1
            && outer["wait_error"].is_null()
            && outer["no_retry_or_clock_reset"] == true,
        "actual1800 original Final2 was not terminal and reaped"
    );
    let completion = storage::json(&fixed(
        &format!("{ROOT1800}/original-enrolled-reader-completion.json"),
        "0c42ccd7e806402662aa5d303c2ac4e1f2fc6fe0b20ddb08b4c40346c6d426a4",
    ))?;
    ensure!(
        completion["invocation_id"] == READER1800_IID
            && completion["program"] == json!(fixed(HELPER1800, HELPER1800_SHA))
            && completion["original_outer_reaped"] == true
            && completion["original_cgroup_empty"] == true
            && completion["original_descriptors_drained"] == true,
        "actual1800 successful reader lifecycle incomplete"
    );
    control_proof(r, &binding(&v["native_retirement_control"])?)?;
    let capture = fixed(
        &format!("{ROOT1800}/2020-persistent-reader-native-original-outcome.json"),
        "9eaae6e4cf74c81e11fe05694919906a7312ecbcb0c4c7884fe3285164dcf179",
    );
    let raw = storage::json(&capture)?;
    ensure!(
        raw["program"] == "/usr/bin/systemctl"
            && raw["exit_code"] == 0
            && raw["wait_error"].is_null()
            && raw["stdout_overflow"] == false
            && raw["stdout_read_error"].is_null()
            && raw["argv"]
                == json!([
                    "show",
                    READER_UNIT,
                    "--no-pager",
                    format!("--property={FIELDS}")
                ]),
        "exact1800 successful original native capture changed"
    );
    let original = parse(&serde_json::from_value::<Vec<u8>>(
        raw["stdout_bytes"].clone(),
    )?)?;
    successful_shape(&original, READER_UNIT, READER1800_IID, READER1800_PID)?;
    ensure!(
        completion["original_native"] == original,
        "actual1800 native completion/capture crossed"
    );
    let generation = format!("positive-{ACTOR1800_IID}");
    let package = Path::new("/usr/local/lib/jetstreamer").join(format!(
        "horizon-positive185-persistent-reader-{generation}"
    ));
    let i = Installed {
        unit: READER_UNIT.into(),
        keeper: format!("horizon-positive185-reader-{generation}-retain.target"),
        argv: vec![
            HELPER1800.into(),
            "read-failed4-current-accounting".into(),
            format!(
                "/usr/local/lib/jetstreamer/horizon-epoch185-positive-enrolled-reader-{ACTOR1800_IID}/spec.json"
            ),
            "--spec-sha256".into(),
            "138a0e70b69ec3cbc0e89b390283e636233d290c61e1c3aa8dc47a0f112ea0dc".into(),
            "--self-sha256".into(),
            HELPER1800_SHA.into(),
        ],
        kind: Kind::Production,
        seal: process::bind_file(&package.join("deployment-seal-receipt.json"), 4 << 20)?,
        package,
    };
    let done = cleanup(r, &i, &original)?;
    println!(
        "{}",
        json!({"actual_successful_reader_retirement":done,"exact1800_original":true,"no_replay_or_archive_authority":true})
    );
    Ok(())
}
pub(crate) fn execute(v: &Value, r: &mut process::Runner<'_>) -> Result<()> {
    match text(v, "schema")? {
        "positive185-retire-exact1630-successful-reader-v1" => execute1630(v, r),
        "positive185-retire-exact1800-successful-reader-v1" => execute1800(v, r),
        "positive185-retire-exact0100-successful-reader-v1" => execute0100(v, r),
        _ => anyhow::bail!("unknown successful-reader retirement target"),
    }
}
pub(crate) fn qualify(r: &mut process::Runner<'_>) -> Result<()> {
    let generation = format!("retire-{}", r.iid);
    generation_check(&generation)?;
    let declaration = storage::save(
        r.root,
        "harmless-successful-reader-control-spec.json",
        &json!({"schema":"horizon-positive185-reader-lifecycle-harmless-child-v1","generation":generation}),
    )?;
    let published = seal(
        r,
        "harmless-successful-reader-control-spec",
        &Path::new("/usr/local/lib/jetstreamer").join(format!(
            "horizon-positive185-retirement-control-spec-{generation}"
        )),
        &[("spec.json", declaration)],
    )?;
    let spec = binding(&published["members"]["spec.json"])?;
    let argv = vec![
        r.self_image.path.display().to_string(),
        "reader-lifecycle-harmless-exec".into(),
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
        "start-only-harmless-successful-reader-control",
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
        "actual successful control pidfd path required"
    );
    let original = query(r, &i.unit)?;
    profile(&original, &i)?;
    let done = cleanup(r, &i, &original)?;
    let mut proof = storage::json(&done)?;
    proof["schema"] = json!("horizon-positive185-successful-reader-retirement-native-control-v1");
    proof["actual_successful_original_pidfd_wait"] = wait;
    let bound = storage::save(
        r.root,
        "actual-successful-reader-retirement-native-control.json",
        &proof,
    )?;
    let published = seal(
        r,
        "successful-reader-retirement-control-completion",
        &Path::new("/usr/local/lib/jetstreamer").join(format!(
            "horizon-positive185-successful-reader-retirement-control-{}",
            r.iid
        )),
        &[("completion.json", bound)],
    )?;
    println!("{}", published);
    Ok(())
}
fn terminal0100_shape(intent: &Value, stopped: &Value, guard: &Value) -> Result<()> {
 let actor=&intent["actor"]; let before=&intent["timer"];let after=&stopped["timer_after"];
 ensure!(actor["Id"]==ACTOR0100 && actor["InvocationID"]==ACTOR0100_IID && actor["MainPID"]=="0" && actor["ExecMainPID"]=="0" && actor["ControlPID"]=="0" && actor["ControlGroup"]=="" && actor["Job"]=="" && actor["NRestarts"]=="0" && actor["Result"]=="signal" && actor["ActiveState"]=="failed","exact0100 original terminal without Main");
 ensure!(stopped["original_actor_unchanged"]==*actor && stopped["only_new_failed_guard_timer_stopped"]==true && stopped["all_originals_and_promises_preserved"]==true && stopped["no_retry_reset_unlink_restart_or_credit"]==true,"exact owned0100 timer stop completion");
 ensure!(before["Id"]=="horizon-guard-185-capped-cold-positive-positive-0100-20261109-next.timer" && before["InvocationID"]=="0785b9a4f1084b24b81a85dc7d8bb5b6" && before["Unit"]=="horizon-guard-185-capped-cold-positive-positive-0100-20261109-next.service" && after["Id"]==before["Id"] && after["Unit"]==before["Unit"] && after["ActiveState"]=="inactive" && after["Job"]=="","exact owned0100 timer identity and stopped state");
 ensure!(intent["original_receipt"]==*guard && guard["schema"]=="horizon-epoch185-native-guard-result-v4" && guard["actor_unit"]==ACTOR0100 && guard["actor_invocation_id"]==ACTOR0100_IID && guard["guard_invocation_id"]=="50a0f038091f4c578791c3720a85a72e" && guard["timer_driven"]==true && guard["success"]==false && guard["failure"]=="No such file or directory (os error 2)" && guard["capacity_credit_bytes"]==0,"exact actual first guard failure; never success");
 Ok(())
}
fn execute0100(v: &Value,r: &mut process::Runner<'_>) -> Result<()> {
 let intent_binding=fixed("/home/sol/.jetstreamer-private/current0100-original-failure-and-owned-timer-stop-20261109-v1/STOP_ONLY_NEW_FAILED0100_TIMER_INTENT.json","7beb96e85a3926f91640c53e6574903777db194039fa31dc0815d80b24f0d6ef");let stopped_binding=fixed("/home/sol/.jetstreamer-private/current0100-original-failure-and-owned-timer-stop-20261109-v1/EXACT_OWNED_TIMER_STOP_COMPLETION.json","f402f674baa2a5474065cc6ff370f5bc971c78062e7a7942691e112892f8b138");let guard_binding=fixed("/var/lib/jetstreamer/epoch185-cold-guard-v4/guard-50a0f038091f4c578791c3720a85a72e.json","430cddfe3fc6968557eba5d9469448e860d25027d9b15dc3e2d87ba5558f37ac");
 let intent=storage::json(&intent_binding)?;let stopped=storage::json(&stopped_binding)?;let guard=storage::json(&guard_binding)?;
 terminal0100_shape(&intent,&stopped,&guard)?;
 ensure!(intent["first_guard_failure"]==json!(guard_binding),"exact0100 guard failure source digest");
 let actor=query(r,ACTOR0100)?;
 ensure!(intent["actor"].as_object().context("recorded terminal0100 actor")?.iter().all(|(k,value)|actor[k]==*value) && actor["ExecMainStartTimestampMonotonic"]=="0","original0100 remains terminal/noMain");
 let timer=r.native(text(&intent["timer"],"Id")?)?;
 ensure!(stopped["timer_after"].as_object().context("recorded stopped0100 timer")?.iter().all(|(k,value)|timer[k]==*value),"only original owned0100 timer remains stopped");
 let failed=storage::json(&fixed("/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0100-original-r3-20261109-next/3688-actual-c71-one-original-final-original-outcome.json","3d26a8bfa7abcd2d398acc6f78489689d83f633424aa563b6f1bd6f66fd57933"))?;
 ensure!(failed["program"]=="/usr/local/lib/jetstreamer/horizon-positive185-final-transaction-tools-20261108-v3/horizon-positive185-final" && failed["exit_code"]==1 && failed["exit_signal"].is_null() && failed["wait_error"].is_null() && failed["no_retry_or_clock_reset"]==true,"actual original Final3 ended; no current final consumer");
 let completion_binding=fixed("/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0100-original-r3-20261109-next/original-enrolled-reader-completion.json","518e3459830e841f089e9e768f759e2e67af5647343b6f0621728643ffff189d");let completion=storage::json(&completion_binding)?;
 ensure!(completion_binding.path.parent()==Some(Path::new(ROOT0100)) && completion["schema"]=="terminal199-parent-memory-original-reader-completion-v1" && completion["unit"]==READER_UNIT && completion["original_process_wait"]["actual_original_pidfd_exit_event"]==true && completion["original_process_wait"]["original_iid"]==READER0100_IID && completion["original_process_wait"]["original_pid"]==READER0100_PID,"exact0100 genuine completion and original pidfd path");
 ensure!(completion["invocation_id"]==READER0100_IID && completion["program"]==json!(fixed(HELPER0100,HELPER0100_SHA)) && completion["original_outer_reaped"]==true && completion["original_cgroup_empty"]==true && completion["original_descriptors_drained"]==true,"actual0100 successful reader completion");
 let record_binding=fixed("/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0100-original-r3-20261109-next/genuine-original-persistent-reader.json","f80f1eda5ddeeedc01356bd7fd009a0bf5e089b32e97bf541e69b5beeeef8724");let record=storage::json(&record_binding)?;
 ensure!(completion["actual_original_native_execution_record"]==json!(record_binding) && record["lifecycle"]["original_native"]==completion["original_native"] && record["reader_proof"]==completion["reader_proof"] && record["original_unit_package_seal"]==completion["normal_unit_package_seal"],"genuine0100 persistent-reader install/completion linkage");
 let original=&completion["original_native"];successful_shape(original,READER_UNIT,READER0100_IID,READER0100_PID)?;
 let i=installed0100();
 ensure!(completion["normal_unit_package_seal"]==json!(i.seal) && completion["original_ExecStart_argv"]==json!(i.argv),"exact0100 sealed argv/keeper/package");
 let proof=storage::json(&fixed("/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1/877f2be4fed85ee236d5bcecadb512d0034335e3e851eedd9d2add2c57c49846-cold185-9568cb52af154f7d8fbd48e7571770fa/proof.json","1636ad546e4817917196b7eec0f9474c98adb5d912c1ed3fa16b072948500531"))?;
 ensure!(proof["image"]==completion["program"] && proof["invocation_id"]==READER0100_IID && proof["unit"]==READER_UNIT && completion["reader_proof"]==json!(fixed("/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1/877f2be4fed85ee236d5bcecadb512d0034335e3e851eedd9d2add2c57c49846-cold185-9568cb52af154f7d8fbd48e7571770fa/proof.json","1636ad546e4817917196b7eec0f9474c98adb5d912c1ed3fa16b072948500531")),"exact0100 successful reader payload proof");
 let pid1=storage::json(&fixed("/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0100-original-r3-20261109-next/original-enrolled-reader-PID1.json","d28e339c3f2bc9392cc7f73c11b7b3a0e725951fcbc4fee72d711209ac6c19f8"))?;ensure!(pid1["unit"]==READER_UNIT && pid1["invocation_id"]==READER0100_IID && pid1["original_rows"].as_array().context("original0100 PID1 rows")?.contains(&completion["original_PID1_success_event"]),"exact0100 original PID1 journal event membership");
 ensure!(completion["original_PID1_journal"]==json!(fixed("/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0100-original-r3-20261109-next/original-enrolled-reader-PID1.json","d28e339c3f2bc9392cc7f73c11b7b3a0e725951fcbc4fee72d711209ac6c19f8")) && completion["original_PID1_success_event"]["_PID"]=="1" && completion["original_PID1_success_event"]["INVOCATION_ID"]==READER0100_IID,"exact0100 successful original PID1 source");
 let outer=storage::json(&fixed("/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0100-original-r3-20261109-next/original-reader-keeper-start-outer.json","58081bf1e25b31837d2ccda0c3bdd3a3e8a54f9a6d08321576bce55978a56316"))?;
 ensure!(completion["actual_original_outer_execution"]==json!(fixed("/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0100-original-r3-20261109-next/original-reader-keeper-start-outer.json","58081bf1e25b31837d2ccda0c3bdd3a3e8a54f9a6d08321576bce55978a56316")) && completion["actual_keeper_native"]["Id"]==i.keeper && outer["program"]=="/usr/bin/systemctl" && outer["argv"]==json!(["start",i.keeper]) && outer["exit_code"]==0 && outer["wait_error"].is_null() && outer["no_retry_or_clock_reset"]==true,"exact0100 original keeper invocation completed");
 control_proof(r,&binding(&v["native_retirement_control"])?)?;
 let context=storage::save(r.root,"exact0100-successful-reader-retirement-context.json",&json!({"completion":completion_binding,"record":record_binding,"first_guard_failure":guard_binding,"owned_timer_stop":stopped_binding,"actor_terminal_noMain":actor,"all_raw_promises_preserved":true,"resource_credit_bytes":0}))?;
 let done=cleanup(r,&i,original)?;
 println!("{}",json!({"actual_successful_reader_retirement":done,"exact0100_original":true,"context":context,"no_replay_or_archive_authority":true}));
 Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact1800_retirement_rejects_active_changed_or_unexpired_original() {
        let e = json!({"schema":"horizon-positive185-original1800-expiry-and-failed-guard-timer-retirement-event-v1",
            "original_actor":{"Id":ACTOR1800,"InvocationID":ACTOR1800_IID,"MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0"},
            "original_setup_deadline":1794161757u64,"original_control_PID_absent":true,"token_absent":true,
            "original_actor_unchanged":true,"no_retry_or_clock_reset_or_actor_restart":true,"only_new_failed_guard_timer_stopped":true,
            "reset_failed_called":false,"raw_memory_and_DATA_promises_preserved":true,"resource_credit_bytes":0,
            "final_timer":{"ActiveState":"inactive","SubState":"dead","Job":""}});
        expiry1800_shape(&e, 1794161758).unwrap();
        assert!(expiry1800_shape(&e, 1794161757).is_err());
        for pointer in [
            "/original_actor/MainPID",
            "/original_actor/ControlPID",
            "/original_actor/Job",
            "/original_actor/InvocationID",
        ] {
            let mut changed = e.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("foreign-or-active");
            assert!(expiry1800_shape(&changed, 1794161758).is_err());
        }
        for key in [
            "token_absent",
            "original_control_PID_absent",
            "raw_memory_and_DATA_promises_preserved",
        ] {
            let mut changed = e.clone();
            changed[key] = json!(false);
            assert!(expiry1800_shape(&changed, 1794161758).is_err());
        }
    }
    fn successful() -> Value {
        json!({"Id":"test.service","InvocationID":"a".repeat(32),"ExecMainPID":"321", "LoadState":"loaded","Transient":"no",
        "MainPID":"0","ControlPID":"0","ControlGroup":"","Job":"","NRestarts":"0","Restart":"no","Result":"success",
        "ExecMainCode":"1","ExecMainStatus":"0","ActiveState":"inactive","SubState":"dead","Type":"exec","User":"root","Group":"root",
        "RemainAfterExit":"no","ExecMainStartTimestampMonotonic":"1000","ExecMainExitTimestampMonotonic":"2000"})
    }
    #[test]
    fn successful_reader_rejects_live_jobs_restarts_failure_and_crossed_owner() {
        let a = successful();
        successful_shape(&a, "test.service", &"a".repeat(32), 321).unwrap();
        for (key, value) in [
            ("MainPID", "2"),
            ("ControlPID", "3"),
            ("Job", "queued"),
            ("NRestarts", "1"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("InvocationID", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ("ExecMainPID", "322"),
        ] {
            let mut b = a.clone();
            b[key] = json!(value);
            assert!(
                successful_shape(&b, "test.service", &"a".repeat(32), 321).is_err(),
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
        let a = successful();
        let mut b = a.clone();
        b["ExecStart"] = json!("cleared-display-only");
        unchanged_successful(&a, &b).unwrap();
        b["ExecMainPID"] = json!("322");
        assert!(unchanged_successful(&a, &b).is_err());
        b = a.clone();
        b["InvocationID"] = json!("b".repeat(32));
        assert!(unchanged_successful(&a, &b).is_err());
    }
    #[test]
    fn crossed_package_or_production_role_cannot_enter_retirement() {
        let mut i = Installed {
            unit: READER_UNIT.into(),
            keeper: "horizon-positive185-reader-test-retain.target".into(),
            argv: vec![SUCCESSFUL_HELPER.into()],
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

 // Exact0100 source regressions over preserved genuine metadata fixtures.

 #[test] fn actual0100_successful_reader_fixture_preserves_native_argv_and_package() {
  let completion:Value=serde_json::from_str(include_str!("fixtures/original0100-reader-completion.json")).unwrap();
  successful_shape(&completion["original_native"],READER_UNIT,READER0100_IID,READER0100_PID).unwrap();
  let i=installed0100();
  assert_eq!(completion["original_ExecStart_argv"],json!(i.argv));
  assert_eq!(completion["normal_unit_package_seal"],json!(i.seal));
  assert_eq!(completion["program"],json!(fixed(HELPER0100,HELPER0100_SHA)));
  assert_eq!(completion["original_process_wait"]["actual_original_pidfd_exit_event"],true);
  assert_eq!(completion["original_outer_reaped"],true);
  assert_eq!(completion["original_cgroup_empty"],true);
  assert_eq!(completion["original_descriptors_drained"],true);
 }

 #[test] fn recorded_terminal_guard_failure_stop_is_distinct_from_success_or_another_original() {
  let intent:Value=serde_json::from_str(include_str!("fixtures/original0100-timer-stop-intent.json")).unwrap();
  let stop:Value=serde_json::from_str(include_str!("fixtures/original0100-timer-stop-completion.json")).unwrap();
  let guard=intent["original_receipt"].clone();terminal0100_shape(&intent,&stop,&guard).unwrap();
  for pointer in ["/actor/InvocationID","/actor/MainPID","/actor/ExecMainPID"] {let mut bad=intent.clone();*bad.pointer_mut(pointer).unwrap()=json!("changed");assert!(terminal0100_shape(&bad,&stop,&guard).is_err());}
  let mut bad=guard.clone();bad["success"]=json!(true);assert!(terminal0100_shape(&intent,&stop,&bad).is_err());
  let mut bad=stop;bad["timer_after"]["ActiveState"]=json!("active");assert!(terminal0100_shape(&intent,&bad,&guard).is_err());
 }
 #[test] fn exact0100_permit_rejects_crossed_argv_package_keeper_and_seal() {
  assert!(exact0100_installed(&installed0100()));permitted(&installed0100()).unwrap();
  let mut i=installed0100();i.argv[2]="/crossed/spec.json".into();assert!(!exact0100_installed(&i));assert!(permitted(&i).is_err());
  let mut i=installed0100();i.keeper="foreign-retain.target".into();assert!(!exact0100_installed(&i));assert!(permitted(&i).is_err());
  let mut i=installed0100();i.seal.sha256="0".repeat(64);assert!(!exact0100_installed(&i));assert!(permitted(&i).is_err());
  let mut i=installed0100();i.package=PathBuf::from("/usr/local/lib/jetstreamer/foreign");assert!(!exact0100_installed(&i));assert!(permitted(&i).is_err());
 }
}
