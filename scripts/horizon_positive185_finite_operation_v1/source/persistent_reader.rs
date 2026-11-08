//! Retain genuine inactive/dead original reader identity through an active,
//! zero-process target. Production and metadata-native QA use this same path.
use crate::*;
#[path = "failed_reader_retirement.rs"]
pub(crate) mod failed_retirement;
pub const READER_UNIT: &str = "horizon-failed4-current-accounting-reader-20261104-v1.service";
const FIELDS: &str = "Id,LoadState,FragmentPath,DropInPaths,Transient,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,ControlGroup,Job,NRestarts,Restart,Result,ActiveState,SubState,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,ExecStart,Type,User,Group,RemainAfterExit,KillMode,MemoryAccounting,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,PrivateMounts,PrivateTmp,ProtectSystem,ProtectHome,PrivateNetwork,EnvironmentFiles,AppArmorProfile";
#[derive(Clone, Copy)]
enum Kind {
    Production,
    Control,
}
struct Installed {
    unit: String,
    keeper: String,
    argv: Vec<String>,
    kind: Kind,
    package: PathBuf,
    seal: Bound,
}
fn tokens(argv: &[String]) -> Result<()> {
    ensure!(
        !argv.is_empty()
            && argv.iter().all(|s| !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-=:\\".contains(&b))
                && !s.contains('\\')),
        "exact unambiguous native ExecStart tokens"
    );
    Ok(())
}
fn source(kind: Kind, argv: &[String]) -> Result<String> {
    tokens(argv)?;
    let profile = match kind {
        Kind::Production => {
            "MemoryHigh=2G\nMemoryMax=2G\nTasksMax=512\nRuntimeMaxSec=600s\nPrivateMounts=no\nPrivateTmp=no\nProtectSystem=no\nProtectHome=no\nPrivateNetwork=no\nEnvironmentFile=/etc/jetstreamer/horizon-r2.env\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nAmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\n"
        }
        Kind::Control => {
            "MemoryHigh=64M\nMemoryMax=64M\nTasksMax=16\nRuntimeMaxSec=10s\nPrivateNetwork=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=read-only\nCapabilityBoundingSet=\nAmbientCapabilities=\n"
        }
    };
    Ok(format!(
        "[Unit]\nDescription=Original positive185 reader retained native lifecycle\n[Service]\nType=exec\nUser=root\nGroup=root\nRestart=no\nRemainAfterExit=no\nKillMode=control-group\nMemoryAccounting=yes\nMemorySwapMax=0\nCPUQuota=100%\nTimeoutStopSec=15s\nUMask=0077\nNoNewPrivileges=yes\nAppArmorProfile=horizon-witness-test-deny199-20261107-v1\nStandardOutput=journal\nStandardError=journal\n{profile}ExecStart={}\n",
        argv.join(" ")
    ))
}
fn keeper_source(unit: &str) -> Result<String> {
    ensure!(
        unit_name(unit) && unit.ends_with(".service"),
        "exact retained service"
    );
    Ok(format!(
        "[Unit]\nDescription=Retain one genuine original positive185 reader invocation\nWants={unit}\nAfter={unit}\n"
    ))
}
fn parse(raw: &[u8]) -> Result<Value> {
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(raw)?.lines() {
        let (k, v) = line
            .split_once('=')
            .context("persistent reader native framing")?;
        ensure!(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate persistent reader native field"
        );
    }
    Ok(Value::Object(map))
}
fn query(r: &mut process::Runner<'_>, unit: &str) -> Result<Value> {
    ensure!(unit_name(unit), "native reader unit syntax");
    let mut c = Command::new("/usr/bin/systemctl");
    c.args(["show", unit, "--no-pager", &format!("--property={FIELDS}")]);
    let out = r.run("persistent-reader-native", c, Duration::from_secs(5))?;
    let bytes: Vec<u8> = serde_json::from_value(out["stdout_bytes"].clone())?;
    let mut n = parse(&bytes)?;
    ensure!(n["Id"] == unit, "actual reader native unit");
    if n.get("EnvironmentFiles").is_none() {
        let mut object = String::from("/org/freedesktop/systemd1/unit/");
        for byte in unit.bytes() {
            if byte.is_ascii_alphanumeric() {
                object.push(char::from(byte));
            } else {
                use std::fmt::Write as _;
                write!(object, "_{byte:02x}")?;
            }
        }
        let mut c = Command::new("/usr/bin/busctl");
        c.args([
            "get-property",
            "org.freedesktop.systemd1",
            &object,
            "org.freedesktop.systemd1.Service",
            "EnvironmentFiles",
        ]);
        let actual = r.run(
            "persistent-reader-empty-environment-files",
            c,
            Duration::from_secs(5),
        )?;
        let raw: Vec<u8> = serde_json::from_value(actual["stdout_bytes"].clone())?;
        ensure!(
            std::str::from_utf8(&raw)?.trim() == "a(sb) 0",
            "missing environment array is not an authenticated empty native property"
        );
        n["EnvironmentFiles"] = json!("");
    }
    Ok(n)
}
fn control_group_empty(unit: &str) -> Result<()> {
    let root = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}"));
    if root.try_exists()? {
        let mut queue = vec![root];
        let mut count = 0;
        while let Some(p) = queue.pop() {
            count += 1;
            ensure!(count <= 1024, "original reader cgroup bound");
            ensure!(
                fs::read_to_string(p.join("cgroup.procs"))?
                    .trim()
                    .is_empty(),
                "original reader cgroup remains populated"
            );
            for e in fs::read_dir(p)? {
                let e = e?;
                if e.file_type()?.is_dir() {
                    queue.push(e.path());
                }
            }
        }
    }
    Ok(())
}
fn terminal(n: &Value, unit: &str, iid: &str) -> Result<()> {
    ensure!(
        storage::hex(iid, 32)
            && n["Id"] == unit
            && n["LoadState"] == "loaded"
            && n["Transient"] == "no"
            && n["InvocationID"] == iid,
        "retained reader original native identity"
    );
    for (k, want) in [
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
        ensure!(n[k] == want, "original reader terminal property: {k}");
    }
    let pid = text(n, "ExecMainPID")?.parse::<u64>()?;
    ensure!(
        pid > 1 && pid <= i32::MAX as u64 && !Path::new(&format!("/proc/{pid}")).try_exists()?,
        "original reader PID still present"
    );
    let start = text(n, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?;
    let end = text(n, "ExecMainExitTimestampMonotonic")?.parse::<u64>()?;
    ensure!(
        start > 0 && end >= start,
        "original reader real start/exit clocks"
    );
    control_group_empty(unit)
}
fn command_matches(n: &Value, argv: &[String]) -> Result<()> {
    tokens(argv)?;
    let raw = text(n, "ExecStart")?;
    let (prefix, suffix) = raw
        .split_once(" ; ignore_errors=")
        .context("exact native ExecStart framing")?;
    ensure!(
        prefix == format!("{{ path={} ; argv[]={}", argv[0], argv.join(" "))
            && suffix.starts_with("no ; "),
        "original reader image/argv/error policy changed"
    );
    Ok(())
}
fn profile(n: &Value, i: &Installed) -> Result<()> {
    let expected_fragment = i.package.join(&i.unit);
    let native_fragment = PathBuf::from(text(n, "FragmentPath")?);
    ensure!(
        (native_fragment == expected_fragment
            || native_fragment == Path::new("/etc/systemd/system").join(&i.unit))
            && native_fragment.canonicalize()? == expected_fragment,
        "exact normally sealed reader FragmentPath/manager alias"
    );
    let manager_link = Path::new("/etc/systemd/system").join(&i.unit);
    let lm = fs::symlink_metadata(&manager_link)?;
    ensure!(
        lm.file_type().is_symlink()
            && lm.uid() == 0
            && lm.gid() == 0
            && fs::read_link(&manager_link)? == expected_fragment,
        "exact original reader manager link drift"
    );
    ensure!(
        n["LoadState"] == "loaded" && n["Transient"] == "no" && n["DropInPaths"] == "",
        "normally sealed persistent reader source changed"
    );
    command_matches(n, &i.argv)?;
    for (k, want) in [
        ("Type", "exec"),
        ("RemainAfterExit", "no"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("MemoryAccounting", "yes"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "1s"),
        ("NoNewPrivileges", "yes"),
        (
            "AppArmorProfile",
            "horizon-witness-test-deny199-20261107-v1",
        ),
    ] {
        ensure!(n[k] == want, "exact persistent reader profile {k}");
    }
    let expected: Vec<(&str, &str)> = match i.kind {
        Kind::Production => vec![
            ("MemoryHigh", "2147483648"),
            ("MemoryMax", "2147483648"),
            ("TasksMax", "512"),
            ("RuntimeMaxUSec", "10min"),
            ("PrivateMounts", "no"),
            ("PrivateTmp", "no"),
            ("ProtectSystem", "no"),
            ("ProtectHome", "no"),
            ("PrivateNetwork", "no"),
            (
                "EnvironmentFiles",
                "/etc/jetstreamer/horizon-r2.env (ignore_errors=no)",
            ),
            ("CapabilityBoundingSet", "cap_dac_override cap_sys_ptrace"),
            ("AmbientCapabilities", "cap_dac_override cap_sys_ptrace"),
        ],
        Kind::Control => vec![
            ("MemoryHigh", "67108864"),
            ("MemoryMax", "67108864"),
            ("TasksMax", "16"),
            ("RuntimeMaxUSec", "10s"),
            ("PrivateNetwork", "yes"),
            ("PrivateTmp", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("EnvironmentFiles", ""),
            ("CapabilityBoundingSet", ""),
            ("AmbientCapabilities", ""),
        ],
    };
    for (k, want) in expected {
        ensure!(n[k] == want, "persistent reader exact native envelope {k}");
    }
    Ok(())
}
fn install(
    r: &mut process::Runner<'_>,
    generation: &str,
    unit: String,
    argv: Vec<String>,
    kind: Kind,
) -> Result<Installed> {
    generation_check(generation)?;
    ensure!(
        unit_name(&unit) && unit.ends_with(".service"),
        "exact reader role"
    );
    let keeper = format!("horizon-positive185-reader-{generation}-retain.target");
    // A previous completed transient may still be loaded. Preserve its untouched
    // state; accept only natural terminal drain and never reset/stop/restart it.
    let old = r.native(&unit)?;
    ensure!(
        old["ActiveState"] == "inactive"
            && old["MainPID"] == "0"
            && old["ControlPID"] == "0"
            && old["NRestarts"] == "0"
            && old["Job"] == "",
        "previous reader not dormant/drained"
    );
    control_group_empty(&unit)?;
    let reference = r.native(&keeper)?;
    ensure!(
        reference["LoadState"] == "not-found"
            && reference["InvocationID"] == ""
            && reference["ActiveState"] == "inactive"
            && reference["Job"] == "",
        "fresh reader keeper required"
    );
    for name in [&unit, &keeper] {
        for dir in ["/etc/systemd/system", "/run/systemd/system"] {
            ensure!(
                fs::symlink_metadata(Path::new(dir).join(name))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "reader/reference manager link already exists; preserve it"
            );
        }
    }
    storage::save(
        r.root,
        "persistent-reader-predecessor.json",
        &json!({"exact_old_native":old,"old_original_untouched":true,"new_service":unit,"new_keeper":keeper,"no_reset_stop_or_restart":true}),
    )?;
    let service = write_bytes(r.root, &unit, source(kind, &argv)?.as_bytes())?;
    let target = write_bytes(r.root, &keeper, keeper_source(&unit)?.as_bytes())?;
    let package = Path::new("/usr/local/lib/jetstreamer").join(format!(
        "horizon-positive185-persistent-reader-{generation}"
    ));
    let sealed = seal(
        r,
        "persistent-reader-units",
        &package,
        &[(&unit, service), (&keeper, target)],
    )?;
    let receipt = binding(&sealed["normal_seal"])?;
    let timers_before = crate::timers::capture(r, "reader-before")?;
    for name in [&unit, &keeper] {
        std::os::unix::fs::symlink(
            package.join(name),
            Path::new("/etc/systemd/system").join(name),
        )?;
    }
    let mut c = Command::new("/usr/bin/systemctl");
    c.arg("daemon-reload");
    r.run("reader-one-reload", c, Duration::from_secs(15))?;
    let timers_after = crate::timers::capture_after(r, "reader-after", &timers_before)?;
    let audit = crate::timers::validate(&timers_before, &timers_after)?;
    storage::save(r.root, "reader-reload-original-before.json", &timers_before)?;
    storage::save(r.root, "reader-reload-original-after.json", &timers_after)?;
    storage::save(r.root, "reader-reload-original-timer-audit.json", &audit)?;
    let installed = Installed {
        unit,
        keeper,
        argv,
        kind,
        package,
        seal: receipt,
    };
    let native = query(r, &installed.unit)?;
    profile(&native, &installed)?;
    ensure!(
        native["ActiveState"] == "inactive"
            && native["MainPID"] == "0"
            && native["ControlPID"] == "0"
            && native["Job"] == "",
        "persistent exact reader must remain dormant"
    );
    let keeper_native = r.native(&installed.keeper)?;
    ensure!(
        keeper_native["ActiveState"] == "inactive"
            && keeper_native["InvocationID"] == ""
            && keeper_native["Job"] == "",
        "exact new keeper dormant"
    );
    Ok(installed)
}
fn generation_check(s: &str) -> Result<()> {
    ensure!(
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "reader unique safe generation"
    );
    Ok(())
}
fn wait_original_pid(r: &mut process::Runner<'_>, n: &Value, end: Instant) -> Result<Value> {
    let pid = text(n, "MainPID")?.parse::<u64>()?;
    ensure!(
        pid > 1 && pid <= i32::MAX as u64,
        "genuine original live reader PID"
    );
    let iid = text(n, "InvocationID")?;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as i32, 0) as i32 };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        ensure!(
            e.raw_os_error() == Some(libc::ESRCH),
            "original reader pidfd acquisition failed: {e}"
        );
        return Ok(
            json!({"original_pid":pid,"original_iid":iid,"pidfd_open_ESRCH_race":true,"terminal_and_PID1_authentication_still_required":true}),
        );
    }
    struct Descriptor(i32);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let fd = Descriptor(fd);
    loop {
        let left = end
            .checked_duration_since(Instant::now())
            .context("original reader finite completion wait expired")?;
        let mut p = libc::pollfd {
            fd: fd.0,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe {
            libc::poll(
                &mut p,
                1,
                left.as_millis().clamp(1, i32::MAX as u128) as i32,
            )
        };
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        ensure!(
            result > 0 && p.revents & libc::POLLIN != 0,
            "original reader pidfd completion deadline/error"
        );
        break;
    }
    let receipt = json!({"original_pid":pid,"original_iid":iid,"actual_original_pidfd_exit_event":true,"not_a_new_resource_observation":true});
    storage::save(r.root, "original-reader-pidfd-wait.json", &receipt)?;
    Ok(receipt)
}
fn success(r: &mut process::Runner<'_>, unit: &str, iid: &str, boot: &str) -> Result<Value> {
    let mut c = Command::new("/usr/bin/journalctl");
    c.args([
        "--all",
        "--no-pager",
        "-ojson",
        "-n",
        "2",
        "_PID=1",
        "_UID=0",
        &format!("UNIT={unit}"),
        &format!("INVOCATION_ID={iid}"),
        "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
    ]);
    let v = r.run("persistent-reader-original-PID1", c, Duration::from_secs(5))?;
    let bytes: Vec<u8> = serde_json::from_value(v["stdout_bytes"].clone())?;
    let rows = std::str::from_utf8(&bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.len() == 1
            && rows[0]["_PID"] == "1"
            && rows[0]["_UID"] == "0"
            && rows[0]["UNIT"] == unit
            && rows[0]["INVOCATION_ID"] == iid
            && rows[0]["_BOOT_ID"] == boot
            && rows[0]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && rows[0]["MESSAGE"] == format!("{unit}: Deactivated successfully."),
        "genuine unique same-boot original reader PID1 success"
    );
    Ok(rows[0].clone())
}
fn payload_rows(
    r: &mut process::Runner<'_>,
    unit: &str,
    iid: &str,
    image: &Path,
    original_pid: &str,
) -> Result<Vec<Value>> {
    let mut c = Command::new("/usr/bin/journalctl");
    c.args([
        "--all",
        "--no-pager",
        "-ojson",
        "-n",
        "128",
        &format!("_SYSTEMD_UNIT={unit}"),
        &format!("_SYSTEMD_INVOCATION_ID={iid}"),
        "_TRANSPORT=stdout",
    ]);
    let v = r.run(
        "persistent-reader-original-stdout",
        c,
        Duration::from_secs(5),
    )?;
    let bytes: Vec<u8> = serde_json::from_value(v["stdout_bytes"].clone())?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    Ok(std::str::from_utf8(&bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|x| {
            x["_UID"] == "0"
                && x["_SYSTEMD_UNIT"] == unit
                && x["_SYSTEMD_INVOCATION_ID"] == iid
                && x["_EXE"] == image.to_string_lossy().as_ref()
                && x["_PID"] == original_pid
                && x["_BOOT_ID"] == boot
        })
        .collect())
}
fn original(
    r: &mut process::Runner<'_>,
    i: &Installed,
    limit: Duration,
    start_phase: (&Value, u64),
) -> Result<Value> {
    let end = (Instant::now() + limit)
        .min(r.deadline)
        .min(r.pool_deadline);
    let outer_deadline = r.deadline;
    r.deadline = end;
    let result = (|| {
        let before = query(r, &i.unit)?;
        profile(&before, i)?;
        ensure!(
            before["ActiveState"] == "inactive"
                && before["MainPID"] == "0"
                && before["ControlPID"] == "0"
                && before["Job"] == "",
            "reader original not dormant"
        );
        let boot_raw = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let boot = boot_raw.trim().replace('-', "");
        crate::reader_phase::validate_persistent_start(r, start_phase.0, start_phase.1)?;
        let mut c = Command::new("/usr/bin/systemctl");
        c.args(["start", &i.keeper]);
        let outer = r.run("start-original-reader-keeper", c, Duration::from_secs(5))?;
        let outer_bound = storage::save(r.root, "original-reader-keeper-start-outer.json", &outer)?;
        let observed = query(r, &i.unit)?;
        profile(&observed, i)?;
        let observed_iid = text(&observed, "InvocationID")?.to_owned();
        ensure!(
            storage::hex(&observed_iid, 32) && observed["InvocationID"] != before["InvocationID"],
            "one actual new original reader invocation"
        );
        let waited = if observed["ActiveState"] == "active" && observed["SubState"] == "running" {
            wait_original_pid(r, &observed, end)?
        } else {
            json!({"original_already_terminal_before_pidfd_capture":true,"real_terminal_manager_and_PID1_authentication_required":true})
        };
        let terminal_native = query(r, &i.unit)?;
        profile(&terminal_native, i)?;
        terminal(&terminal_native, &i.unit, &observed_iid)?;
        let event = success(r, &i.unit, &observed_iid, &boot)?;
        let event_at = text(&event, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        let exit_at = text(&terminal_native, "ExecMainExitTimestampMonotonic")?.parse::<u64>()?;
        ensure!(
            event_at >= exit_at,
            "original reader PID1 completion precedes actual exit"
        );
        let keeper = r.native(&i.keeper)?;
        ensure!(
            keeper["LoadState"] == "loaded"
                && keeper["ActiveState"] == "active"
                && keeper["SubState"] == "active"
                && keeper["Job"] == "",
            "original zero-process reader reference absent"
        );
        let keeper_cgroup = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{}", i.keeper));
        ensure!(
            !keeper_cgroup.try_exists()?,
            "keeper target unexpectedly owns a process cgroup"
        );
        ensure!(
            query(r, &i.unit)? == terminal_native
                && fs::read_to_string("/proc/sys/kernel/random/boot_id")? == boot_raw,
            "original retained reader manager/boot changed"
        );
        control_group_empty(&i.unit)?;
        Ok(
            json!({"schema":"horizon-positive185-genuine-persistent-reader-original-lifecycle-v1","unit":i.unit,"invocation_id":observed_iid,"original_native":terminal_native,"original_PID1_success_event":event,"original_outer_reaped":true,"original_cgroup_empty":true,"original_descriptors_drained":true,"actual_original_outer_execution":outer_bound,"original_process_wait":waited,"actual_keeper_native":keeper,"normal_unit_package_seal":i.seal,"original_ExecStart_argv":i.argv,"before_native_preserved":before,"actual_advisory_start_phase":start_phase.0,"original_setup_deadline_checked_without_renewal":start_phase.1,"no_IID_reconstruction_or_deadline_renewal":true}),
        )
    })();
    r.deadline = outer_deadline;
    result
}
pub fn read(
    r: &mut process::Runner<'_>,
    spec: &Bound,
    generation: &str,
    original_setup_deadline: u64,
) -> Result<Value> {
    let declaration = storage::json(spec)?;
    let expected = PathBuf::from(text(&declaration, "output_directory")?).join("proof.json");
    let selected_role = crate::postreader::role()?;
    let selected_image = crate::postreader::image()?;
    let argv = crate::postreader::reader_argv(spec)?;
    let installed = install(r, generation, READER_UNIT.into(), argv, Kind::Production)?;
    let phase = crate::reader_phase::prepare_persistent_start(r, original_setup_deadline)?;
    let lifecycle = original(
        r,
        &installed,
        Duration::from_secs(180),
        (&phase, original_setup_deadline),
    )?;
    let iid = text(&lifecycle, "invocation_id")?;
    let rows = payload_rows(
        r,
        READER_UNIT,
        iid,
        &selected_image.path,
        text(&lifecycle["original_native"], "ExecMainPID")?,
    )?;
    let mut found = Vec::new();
    for row in rows {
        if let Some(message) = row["MESSAGE"].as_str()
            && let Ok(b) = serde_json::from_str::<Bound>(message)
            && b.path == expected
            && storage::hex(&b.sha256, 64)
        {
            found.push((b, row));
        }
    }
    ensure!(
        found.len() == 1,
        "one genuine same-IID reader stdout Bound to its exact output namespace"
    );
    let (reader_bound, row) = found.pop().context("original reader bound")?;
    let reader = storage::json(&reader_bound)?;
    crate::postreader::require_reader_image(&reader["image"])?;
    ensure!(
        reader["unit"] == READER_UNIT
            && reader["invocation_id"] == iid
            && reader["native"]["MainPID"] == lifecycle["original_native"]["ExecMainPID"],
        "actual reader payload/proof/native PID lineage crossed"
    );
    let record = storage::save(
        r.root,
        "genuine-original-persistent-reader.json",
        &json!({"lifecycle":lifecycle,"actual_original_stdout_payload":row,"reader_proof":reader_bound,"original_unit_package_seal":installed.seal,"actual_postreader_role":selected_role}),
    )?;
    Ok(
        json!({"reader_proof":reader_bound,"lifecycle":lifecycle,"original_native_execution_record":record}),
    )
}
pub fn harmless_exec(spec: &Bound, self_image: &Bound) -> Result<()> {
    let v = storage::json(spec)?;
    ensure!(
        unsafe { libc::geteuid() } == 0
            && v["schema"] == "horizon-positive185-reader-lifecycle-harmless-child-v1"
            && v.as_object().is_some_and(|x| x.len() == 2),
        "exact metadata-only child scope"
    );
    let token = text(&v, "generation")?;
    generation_check(token)?;
    let iid = env::var("INVOCATION_ID")?;
    ensure!(storage::hex(&iid, 32), "actual harmless child invocation");
    println!(
        "{}",
        json!({"schema":"horizon-positive185-reader-lifecycle-harmless-exec-v1","generation":token,"program":self_image,"invocation_id":iid,"original_pid":std::process::id(),"input_body_reads":0,"resource_observations":0,"campaign_mutations":false})
    );
    std::io::stdout().flush()?;
    std::thread::sleep(Duration::from_millis(1000));
    Ok(())
}
pub fn qualify(r: &mut process::Runner<'_>) -> Result<()> {
    let selected_postreader_role = crate::postreader::role()?;
    r.deadline = Instant::now() + Duration::from_secs(90);
    r.pool_deadline = r.deadline;
    let generation = format!("control-{}", r.iid);
    generation_check(&generation)?;
    let source = storage::save(
        r.root,
        "harmless-reader-control-source.json",
        &json!({"schema":"horizon-positive185-reader-lifecycle-harmless-child-v1","generation":generation}),
    )?;
    let dest = Path::new("/usr/local/lib/jetstreamer").join(format!(
        "horizon-positive185-reader-control-spec-{generation}"
    ));
    let published = seal(
        r,
        "harmless-reader-control-spec",
        &dest,
        &[("spec.json", source)],
    )?;
    let spec = binding(&published["members"]["spec.json"])?;
    let unit = format!("horizon-positive185-reader-control-{generation}.service");
    let argv = vec![
        r.self_image.path.display().to_string(),
        "reader-lifecycle-harmless-exec".into(),
        spec.path.display().to_string(),
        "--request-sha256".into(),
        spec.sha256.clone(),
        "--self-sha256".into(),
        r.self_image.sha256.clone(),
    ];
    let installed = install(r, &generation, unit, argv, Kind::Control)?;
    // The harmless metadata control exercises the same phase/start primitive.
    // This synthetic control budget grants no admission or replay authority.
    let control_deadline = now()?.checked_add(600).context("control phase deadline")?;
    let phase = crate::reader_phase::prepare_persistent_start(r, control_deadline)?;
    let lifecycle = original(
        r,
        &installed,
        Duration::from_secs(15),
        (&phase, control_deadline),
    )?;
    ensure!(
        lifecycle["original_process_wait"]["actual_original_pidfd_exit_event"] == true,
        "actual native control must exercise the original running-process pidfd wait path"
    );
    let iid = text(&lifecycle, "invocation_id")?;
    let payload_image = r.self_image.path.clone();
    let rows = payload_rows(
        r,
        &installed.unit,
        iid,
        &payload_image,
        text(&lifecycle["original_native"], "ExecMainPID")?,
    )?;
    let mut actual = Vec::new();
    for row in rows {
        if let Some(message) = row["MESSAGE"].as_str()
            && let Ok(v) = serde_json::from_str::<Value>(message)
            && v["schema"] == "horizon-positive185-reader-lifecycle-harmless-exec-v1"
            && v["generation"] == generation
            && v["program"] == json!(r.self_image)
            && v["invocation_id"] == iid
            && n(&v, "original_pid")?.to_string()
                == text(&lifecycle["original_native"], "ExecMainPID")?
            && v["input_body_reads"] == 0
            && v["resource_observations"] == 0
            && v["campaign_mutations"] == false
        {
            actual.push(row);
        }
    }
    ensure!(
        actual.len() == 1,
        "unique genuine harmless child native journal payload"
    );
    let proof = storage::save(
        r.root,
        "actual-reader-lifecycle-kernel-control.json",
        &json!({"schema":"horizon-positive185-actual-persistent-reader-kernel-control-v1","program":r.self_image,"candidate_normal_role":role(r.self_image.path.to_str().context("self image UTF8")?,&r.self_image.sha256)?,"actual_postreader_role":selected_postreader_role,"prelaunch_reader_image":fixed(HELPER,HELPER_SHA),"actual_original_lifecycle":lifecycle,"actual_harmless_payload":actual[0],"production_persistent_original_primitive_exercised":true,"actual_original_pidfd_wait_exercised":true,"input_body_reads":0,"resource_observations":0,"campaign_mutations":false,"replay_launch_authorized":false,"publication_authorized":false}),
    )?;
    let dest = Path::new("/usr/local/lib/jetstreamer").join(format!(
        "horizon-positive185-reader-lifecycle-kernel-control-{generation}"
    ));
    let published = seal(
        r,
        "reader-lifecycle-kernel-control",
        &dest,
        &[("completion.json", proof)],
    )?;
    println!("{}", published);
    Ok(())
}
pub fn validate_control(r: &mut process::Runner<'_>, bound: &Bound) -> Result<()> {
    storage::bytes(bound, 4 << 20, true)?;
    ensure!(
        bound.path.parent().and_then(Path::parent) == Some(Path::new("/usr/local/lib/jetstreamer")),
        "normally sealed reader-control completion required"
    );
    let directory = bound.path.parent().context("control completion parent")?;
    let seal = storage::json(&process::bind_file(
        &directory.join("deployment-seal-receipt.json"),
        4 << 20,
    )?)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["sealer_sha256"] == process::SEALER_SHA
            && seal["destination"] == directory.to_string_lossy().as_ref()
            && seal["members"]
                .as_array()
                .context("control seal members")?
                .iter()
                .filter(|m| m["name"]
                    == bound
                        .path
                        .file_name()
                        .and_then(|x| x.to_str())
                        .unwrap_or("")
                    && m["sha256"] == bound.sha256
                    && m["mode"] == "0444")
                .count()
                == 1,
        "actual original reader control normal member seal"
    );
    let proof = storage::json(bound)?;
    ensure!(
        proof["actual_postreader_role"] == crate::postreader::role()?
            && proof["prelaunch_reader_image"] == json!(fixed(HELPER, HELPER_SHA)),
        "same-image reader control crossed split prelaunch/postreader roles"
    );
    ensure!(
        proof["schema"] == "horizon-positive185-actual-persistent-reader-kernel-control-v1"
            && proof["program"]["sha256"] == r.self_image.sha256
            && proof["production_persistent_original_primitive_exercised"] == true
            && proof["actual_original_pidfd_wait_exercised"] == true
            && proof["input_body_reads"] == 0
            && proof["resource_observations"] == 0
            && proof["campaign_mutations"] == false,
        "actual same-image persistent-reader native control required before any185 hold"
    );
    let role = &proof["candidate_normal_role"];
    let candidate = binding(&proof["program"])?;
    let accepted = crate::role(
        candidate.path.to_str().context("candidate image UTF8")?,
        &candidate.sha256,
    )?;
    ensure!(
        accepted == *role,
        "native control original normal image metadata changed"
    );
    let lifecycle = &proof["actual_original_lifecycle"];
    let unit = text(lifecycle, "unit")?;
    ensure!(
        unit.starts_with("horizon-positive185-reader-control-control-positive-")
            && unit.ends_with(".service"),
        "exact harmless control namespace"
    );
    let native = query(r, unit)?;
    let package_seal = binding(&lifecycle["normal_unit_package_seal"])?;
    let package = storage::json(&package_seal)?;
    let directory = PathBuf::from(text(&package, "destination")?);
    let original_argv: Vec<String> =
        serde_json::from_value(lifecycle["original_ExecStart_argv"].clone())?;
    let keeper_name = text(&lifecycle["actual_keeper_native"], "Id")?.to_owned();
    let installed = Installed {
        unit: unit.into(),
        keeper: keeper_name,
        argv: original_argv.clone(),
        kind: Kind::Control,
        package: directory,
        seal: package_seal,
    };
    profile(&native, &installed)?;
    for field in FIELDS
        .split(',')
        .filter(|field| *field != "ExecStart" && *field != "FragmentPath")
    {
        ensure!(
            native[field] == lifecycle["original_native"][field],
            "original actual keeper control changed: {field}"
        );
    }
    command_matches(&native, &original_argv)?;
    terminal(&native, unit, text(lifecycle, "invocation_id")?)?;
    let keeper = text(&lifecycle["actual_keeper_native"], "Id")?;
    let current = r.native(keeper)?;
    ensure!(
        current == lifecycle["actual_keeper_native"],
        "original control keeper identity changed"
    );
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(
        success(r, unit, text(lifecycle, "invocation_id")?, &boot)?
            == lifecycle["original_PID1_success_event"],
        "original control PID1 success changed"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_reader_keeps_exact_profile_and_original_dead_lifecycle() {
        let argv = vec![
            crate::postreader::PATH.into(),
            "read-failed4-current-accounting".into(),
            "/usr/local/lib/jetstreamer/exact/spec.json".into(),
            "--spec-sha256".into(),
            "a".repeat(64),
            "--self-sha256".into(),
            "c".repeat(64), // Pure source-profile fixture, not a qualified pin.
        ];
        let s = source(Kind::Production, &argv).unwrap();
        for expected in [
            "Type=exec\n",
            "RemainAfterExit=no\n",
            "MemoryHigh=2G\n",
            "MemoryMax=2G\n",
            "RuntimeMaxSec=600s\n",
            "PrivateMounts=no\n",
            "ProtectSystem=no\n",
            "ProtectHome=no\n",
            "EnvironmentFile=/etc/jetstreamer/horizon-r2.env\n",
        ] {
            assert!(s.contains(expected), "{expected}");
        }
        assert!(!s.contains("--wait"));
        assert_eq!(
            keeper_source(READER_UNIT).unwrap(),
            format!(
                "[Unit]\nDescription=Retain one genuine original positive185 reader invocation\nWants={READER_UNIT}\nAfter={READER_UNIT}\n"
            )
        );
    }
    #[test]
    fn source_cannot_inject_commands_or_change_control_credential_profile() {
        for bad in [
            "bad path",
            "bad\nExecStart=/bad",
            "$BAD",
            "%i",
            "\\bad",
            "\"bad",
        ] {
            assert!(source(Kind::Control, &[bad.into()]).is_err());
        }
        let s = source(
            Kind::Control,
            &[
                "/usr/local/lib/jetstreamer/control/tool".into(),
                "reader-lifecycle-harmless-exec".into(),
            ],
        )
        .unwrap();
        assert!(!s.contains("EnvironmentFile="));
        assert!(
            s.contains("CapabilityBoundingSet=\n")
                && s.contains("MemoryMax=64M\n")
                && s.contains("PrivateNetwork=yes\n")
        );
    }
    #[test]
    fn original_native_scalar_framing_rejects_duplicates_and_empty_generation() {
        assert!(parse(b"Id=a\nId=b\n").is_err());
        assert!(generation_check("").is_err());
        assert!(generation_check("../bad").is_err());
        generation_check("control-positive-20261108-v4").unwrap();
    }
}
