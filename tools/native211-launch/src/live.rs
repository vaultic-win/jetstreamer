//! Fresh PID1/kernel census, twice, with strict owner and terminal drainage checks.
use super::*;
pub(super) const PROPS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainCode,ExecMainStatus,ExecStart,Job,Restart,KillMode,Delegate,ControlGroup,TriggeredBy,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,FragmentPath,DropInPaths,Type,User,Group,RuntimeMaxUSec,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,ReadWritePaths,Environment,CPUAffinity,CPUQuotaPerSecUSec,Unit,Transient,RemainAfterExit,StartLimitIntervalUSec,After,Wants,Requires,BindsTo,Upholds,IgnoreOnIsolate,DefaultDependencies";
fn scalar(v: &Value, key: &str) -> Result<u64> {
    Ok(text(v, key)?.parse()?)
}
fn kernel_memory_cap(configured: u64, page_size: i64) -> Result<u64> {
    let page = u64::try_from(page_size).context("invalid native page size")?;
    ensure!(
        page.is_power_of_two() && configured >= page,
        "invalid memory page/cap"
    );
    Ok(configured / page * page)
}
fn cg(unit: &str) -> String {
    format!("/system.slice/{unit}")
}
fn cgroup_path(unit: &str) -> PathBuf {
    Path::new("/sys/fs/cgroup/system.slice").join(unit)
}
pub(super) fn same_owner(a: &Value, b: &Value) -> Result<()> {
    for k in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ActiveState",
        "SubState",
        "Result",
        "ControlGroup",
    ] {
        ensure!(a[k] == b[k] && !a[k].is_null(), "owner changed {k}");
    }
    ensure!(
        command_identity(text(a, "ExecStart")?)? == command_identity(text(b, "ExecStart")?)?,
        "owner command changed"
    );
    Ok(())
}
pub(super) fn finite_owner(v: &Value, unit: &str, iid: &str, cap: u64) -> Result<u64> {
    ensure!(
        v["Id"] == unit
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["InvocationID"] == iid
            && hex(iid, 32)
            && v["NRestarts"] == "0"
            && v["Result"] == "success"
            && v["Job"] == ""
            && v["Restart"] == "no"
            && v["KillMode"] == "control-group"
            && v["Delegate"] == "no"
            && v["ControlGroup"] == cg(unit)
            && scalar(v, "MainPID")? > 1
            && scalar(v, "MemoryMax")? == cap
            && v["MemorySwapMax"] == "0",
        "live envelope changed {unit}"
    );
    let root = cgroup_path(unit);
    ensure!(root.canonicalize()? == root, "cgroup symlink");
    ensure!(
        fs::read_to_string(root.join("memory.max"))?
            .trim()
            .parse::<u64>()?
            == kernel_memory_cap(cap, unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?
            && fs::read_to_string(root.join("memory.swap.max"))?.trim() == "0",
        "kernel cap differs {unit}"
    );
    let members: BTreeSet<u64> = fs::read_to_string(root.join("cgroup.procs"))?
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        members.contains(&scalar(v, "MainPID")?),
        "main outside its cgroup"
    );
    let current = fs::read_to_string(root.join("memory.current"))?
        .trim()
        .parse()?;
    ensure!(current <= cap, "kernel memory exceeds cap");
    Ok(current)
}
pub(super) fn drained_tree(path: &Path, budget: &mut usize) -> Result<()> {
    ensure!(*budget > 0, "cgroup descendant bound");
    *budget -= 1;
    ensure!(
        fs::symlink_metadata(path)?.is_dir() && path.canonicalize()? == path,
        "unsafe cgroup"
    );
    for leaf in ["cgroup.procs", "cgroup.threads"] {
        ensure!(
            fs::read_to_string(path.join(leaf))?.trim().is_empty(),
            "terminal cgroup still populated"
        );
    }
    let events = fs::read_to_string(path.join("cgroup.events"))?;
    ensure!(
        events.lines().any(|l| l == "populated 0"),
        "terminal descendants populated"
    );
    for e in fs::read_dir(path)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            drained_tree(&e.path(), budget)?;
        }
    }
    Ok(())
}
// Preserve path/argv/ignore_errors byte identity; only PID1's display history
// may clear on daemon-reload. This follows pipeline_status::same_exec_start,
// without its equal-string shortcut for malformed command framing.
fn command_identity(value: &str) -> Result<&str> {
    let identity = periodic::stable_command(value)?;
    ensure!(
        value.matches(" ; start_time=").count() == 1 && identity.matches(" ; argv[]=").count() == 1,
        "ambiguous ExecStart framing"
    );
    let history = value
        .split_once(" ; start_time=")
        .context("command history")?
        .1;
    let fields: Vec<_> = history
        .strip_suffix(" }")
        .context("command history end")?
        .split(" ; ")
        .collect();
    ensure!(
        fields.len() == 5
            && fields[0].starts_with('[')
            && fields[0].ends_with(']')
            && fields[1].starts_with("stop_time=[")
            && fields[1].ends_with(']')
            && fields[2]
                .strip_prefix("pid=")
                .context("command PID")?
                .parse::<u32>()
                .is_ok(),
        "malformed ExecStart display history"
    );
    Ok(identity)
}
fn terminal_identity(current: &Value, receipt: &Value) -> Result<()> {
    let retained = &receipt["producer"]["unit"];
    ensure!(
        retained.is_object(),
        "drain receipt lacks nested producer unit"
    );
    for k in [
        "Id",
        "LoadState",
        "InvocationID",
        "ExecMainCode",
        "ExecMainStatus",
        "NRestarts",
        "Result",
        "ActiveState",
        "SubState",
        "MainPID",
    ] {
        ensure!(
            !retained[k].is_null() && current[k] == retained[k],
            "terminal identity changed {k}"
        );
    }
    ensure!(
        command_identity(text(current, "ExecStart")?)?
            == command_identity(text(retained, "ExecStart")?)?,
        "terminal command changed"
    );
    Ok(())
}
fn same_terminal_census(before: &Value, after: &Value) -> Result<()> {
    ensure!(
        command_identity(text(before, "ExecStart")?)?
            == command_identity(text(after, "ExecStart")?)?,
        "terminal command changed during census"
    );
    let mut normalized = after.clone();
    normalized["ExecStart"] = before["ExecStart"].clone();
    ensure!(*before == normalized, "terminal changed during census");
    Ok(())
}
pub(super) fn drain(n: &mut Native, r: &capacity::Reservation) -> Result<()> {
    let receipt = r.release.as_ref().context("release evidence")?.json()?;
    ensure!(
        receipt["schema"] == "horizon-singleton-terminal-drain-v1"
            && receipt["self_sha256"]
                == "74d264edbb2c198871d207814403aae317d6c41bb90baab73748438da3eec1e3"
            && receipt["producer_cgroup_drained"] == true
            && receipt["resource_release_authorized"] == false
            && receipt["fresh_complete_fleet_admission_required"] == true
            && receipt["recheck_terminal_and_drain_at_admission_required"] == true,
        "unqualified drain receipt"
    );
    let terminal = binding(&receipt["terminal_handoff"])?.json()?;
    let plan = binding(&receipt["plan"])?.json()?;
    ensure!(
        terminal["schema"] == "horizon-singleton-delivery-handoff-v1"
            && terminal["producer"] == receipt["producer"]
            && terminal["plan"] == receipt["plan"]
            && plan["producer_unit"] == r.unit
            && plan["producer_invocation_id"] == r.invocation_id,
        "drain owner changed"
    );
    let before = n.show(&r.unit)?;
    terminal_identity(&before, &receipt)?;
    ensure!(
        before["Id"] == r.unit
            && before["LoadState"] == "loaded"
            && before["ExecMainCode"] == "1"
            && before["InvocationID"] == r.invocation_id
            && before["MainPID"] == "0"
            && before["ControlPID"] == "0"
            && before["NRestarts"] == "0"
            && before["Result"] == "success"
            && before["ExecMainStatus"] == "0"
            && before["ActiveState"] == "inactive"
            && before["SubState"] == "dead"
            && before["Job"] == ""
            && before["Restart"] == "no"
            && before["Delegate"] == "no"
            && before["KillMode"] == "control-group"
            && before["TriggeredBy"] == ""
            && (before["ControlGroup"] == "" || before["ControlGroup"] == cg(&r.unit)),
        "terminal not drained/closed"
    );
    let path = cgroup_path(&r.unit);
    match fs::symlink_metadata(&path) {
        Ok(_) => drained_tree(&path, &mut 1024)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let group = cg(&r.unit);
    for e in fs::read_dir("/proc")? {
        let e = e?;
        if !e
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|c| c.is_ascii_digit())
        {
            continue;
        }
        match fs::read_to_string(e.path().join("cgroup")) {
            Ok(s) => ensure!(
                !s.lines()
                    .any(|l| l == format!("0::{group}") || l.starts_with(&format!("0::{group}/"))),
                "terminal still owns process"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    same_terminal_census(&before, &n.show(&r.unit)?)?;
    Ok(())
}
fn campaign(unit: &str) -> bool {
    unit.starts_with("horizon") || unit.starts_with("archive-") || unit.starts_with("jetstreamer")
}
pub(super) fn census(
    n: &mut Native,
    review: &Value,
    fleet: &Value,
    rows: &[capacity::Reservation],
    periodic: &[periodic::Control],
    candidate: bool,
) -> Result<BTreeMap<String, u64>> {
    let controls = review["control_units"]
        .as_array()
        .context("control units")?;
    let mut control_names = BTreeSet::new();
    // The candidate's new protective guard is not yet installed in the old fleet.
    let mut control_cap = 268_435_456;
    for c in controls {
        let unit = text(c, "unit")?;
        ensure!(
            control_names.insert(unit) && unit != UNIT,
            "duplicate/candidate control"
        );
        control_cap = capacity::add(control_cap, num(c, "maximum_memory_bytes")?)?;
    }
    ensure!(control_cap <= CONTROL, "controls exceed control reserve");
    let periodic_names: BTreeSet<_> = periodic.iter().map(|c| c.unit.as_str()).collect();
    ensure!(
        periodic_names.len() == periodic.len()
            && periodic_names.iter().all(|u| !control_names.contains(u)),
        "duplicate periodic/ordinary control"
    );
    for c in periodic {
        periodic::observe(n, c)?;
    }
    let current_units = n.run(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--all",
            "--type=service",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
    )?;
    let mut before = BTreeMap::new();
    let mut currents = BTreeMap::new();
    for r in rows {
        ensure!(
            r.unit.ends_with(".service")
                && !r.unit.contains('/')
                && r.unit != UNIT
                && !control_names.contains(r.unit.as_str())
                && !periodic_names.contains(r.unit.as_str()),
            "reservation unit scope"
        );
        if r.release.is_some() {
            drain(n, r)?;
            continue;
        }
        let v = n.show(&r.unit)?;
        if v["ActiveState"] == "active" || v["ActiveState"] == "activating" {
            let current = finite_owner(&v, &r.unit, &r.invocation_id, r.maximum_memory_bytes)?;
            let old = &fleet["unit_census"][&r.unit];
            ensure!(
                old.is_object(),
                "active reservation absent from complete fleet"
            );
            same_owner(old, &v)?;
            currents.insert(r.unit.clone(), current);
            before.insert(r.unit.clone(), v);
        } else {
            ensure!(
                v["MainPID"] == "0"
                    && v["ControlPID"] == "0"
                    && v["Job"] == ""
                    && matches!(v["ActiveState"].as_str(), Some("inactive" | "failed")),
                "ambiguous dormant reservation"
            );
            // Dormant reservations retain their complete hard cap and disk growth.
        }
    }
    for a in fleet["active"].as_array().context("fleet active")? {
        if a["phase"] == "producer-finalization" {
            let unit = text(&a["unit"], "Id")?;
            let v = before.get(unit).context("dropped finalization owner")?;
            same_owner(&a["unit"], v)?;
            continue;
        }
        for role in ["producer", "controller"] {
            let unit = text(&a[role], "Id")?;
            let v = before.get(unit).context("dropped active fleet owner")?;
            same_owner(&a[role], v)?;
        }
    }
    for line in std::str::from_utf8(&current_units)?.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        ensure!(parts.len() >= 4, "unit list framing");
        let unit = parts[0];
        if !campaign(unit) || !matches!(parts[2], "active" | "activating" | "deactivating") {
            continue;
        }
        if candidate && matches!(unit, UNIT | GUARD_UNIT) {
            continue;
        }
        if periodic_names.contains(unit) {
            continue;
        }
        if control_names.contains(unit) {
            let c = controls.iter().find(|c| c["unit"] == unit).unwrap();
            let v = n.show(unit)?;
            ensure!(
                scalar(&v, "MemoryMax")? == num(c, "maximum_memory_bytes")?
                    && v["MemorySwapMax"] == "0"
                    && periodic::stable_command(text(&v, "ExecStart")?)?
                        == periodic::stable_command(text(c, "expected_exec_start")?)?
                    && v["Restart"] == "no",
                "control service changed"
            );
        } else {
            ensure!(
                before.contains_key(unit),
                "unbooked campaign service {unit}"
            );
        }
    }
    let jobs = n.run(
        "/usr/bin/systemctl",
        &["list-jobs", "--no-legend", "--plain", "--no-pager"],
    )?;
    for line in std::str::from_utf8(&jobs)?.lines() {
        if line.trim() == "No jobs running." {
            continue;
        }
        let words: Vec<_> = line.split_whitespace().collect();
        ensure!(words.len() >= 4, "job census framing");
        let unit = words[1];
        if campaign(unit) {
            ensure!(
                control_names.contains(unit)
                    || periodic_names.contains(unit)
                    || (candidate && matches!(unit, UNIT | GUARD_UNIT | TIMER)),
                "unadmitted campaign job {unit}"
            );
        }
    }
    // Detect native workers outside the manager's accepted owner graph, including renamed services.
    let groups: BTreeSet<_> = before
        .keys()
        .map(|u| cg(u))
        .chain(control_names.iter().map(|u| cg(u)))
        .chain(periodic_names.iter().map(|u| cg(u)))
        .chain(candidate.then(|| cg(UNIT)))
        .chain(candidate.then(|| cg(GUARD_UNIT)))
        .collect();
    for e in fs::read_dir("/proc")? {
        let e = e?;
        let pid = e.file_name();
        if !pid.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let exe = match fs::read_link(e.path().join("exe")) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if exe.starts_with("/var/lib/jetstreamer")
            || exe.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
                s.starts_with("jetstreamer")
                    || s.starts_with("horizon")
                    || matches!(s, "native-input-test" | "test-runner" | "cargo" | "rustc")
            })
        {
            if pid.to_string_lossy() == std::process::id().to_string() {
                continue;
            }
            let record = match fs::read_to_string(e.path().join("cgroup")) {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            ensure!(record.lines().count() == 1, "nonunified cgroup");
            let group = record
                .trim()
                .strip_prefix("0::")
                .context("unified process group")?;
            ensure!(
                groups
                    .iter()
                    .any(|g| group == g || group.starts_with(&format!("{g}/"))),
                "unaccounted native process {}",
                pid.to_string_lossy()
            );
        }
    }
    for (unit, old) in before {
        let after = n.show(&unit)?;
        same_owner(&old, &after)?;
        let cap = rows
            .iter()
            .find(|r| r.unit == unit)
            .unwrap()
            .maximum_memory_bytes;
        let current = finite_owner(&after, &unit, text(&old, "InvocationID")?, cap)?;
        currents.entry(unit).and_modify(|v| *v = (*v).min(current));
    }
    for c in periodic {
        periodic::observe(n, c)?;
    }
    finalization::verify_inputs(fleet)?;
    Ok(currents)
}
pub(super) fn resources() -> Result<(u64, u64, u64)> {
    let mem = fs::read_to_string("/proc/meminfo")?;
    let value = |key: &str| -> Result<u64> {
        let row = mem
            .lines()
            .find(|l| l.starts_with(&format!("{key}:")))
            .context("meminfo key")?;
        row.split_whitespace()
            .nth(1)
            .context("meminfo value")?
            .parse::<u64>()?
            .checked_mul(1024)
            .context("memory overflow")
    };
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let path = std::ffi::CString::new("/")?;
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), &mut stat) } == 0,
        "statvfs"
    );
    let disk = (stat.f_bavail as u64)
        .checked_mul(stat.f_frsize as u64)
        .context("disk overflow")?;
    Ok((value("MemTotal")?, value("MemAvailable")?, disk))
}

#[cfg(test)]
mod drain_tests {
    use super::*;
    #[test]
    fn kernel_cap_matches_linux_page_rounding_without_reducing_booking() {
        assert_eq!(
            kernel_memory_cap(7_000_000_000, 4096).unwrap(),
            6_999_998_464
        );
        assert_eq!(
            kernel_memory_cap(128_000_000_000, 4096).unwrap(),
            128_000_000_000
        );
        assert!(kernel_memory_cap(7_000_000_000, -1).is_err());
        assert!(kernel_memory_cap(7_000_000_000, 0).is_err());
        assert!(kernel_memory_cap(7_000_000_000, 3000).is_err());
        assert!(kernel_memory_cap(1, 4096).is_err());
    }
    // Actual epoch247 terminal-drain v1 producer.unit, retained 2026-11-19.
    // Events and unrelated proof fields are omitted: this tests the identity reader,
    // not a substitute drain/admission receipt.
    fn fixture() -> Value {
        serde_json::from_str(r###"{
  "schema": "horizon-singleton-terminal-drain-v1",
  "producer": {
    "unit": {
      "ActiveState": "inactive",
      "ExecMainCode": "1",
      "ExecMainStatus": "0",
      "ExecStart": "{ path=/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node ; argv[]=/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 247 /home/ubuntu/.jetstreamer-private/qualification-247-reboot-20261117-v2/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon247-controls0345-v1/preflight-247-target1.json --cohort-manifest-fingerprint=sha256:12070bfb11a9153cd41b0d1179397947fd718e9891849d2e9a793d02dba098f3 --snapshot-archive=/var/lib/jetstreamer/horizon247-bootstrap-copy0347-work-v2/projection/bootstrap/snapshot-106703614-AtkJcCAEp3EfF4ymeeN9t3YvHuAq3aykuQ6vogtDYcf9.tar.zst ; ignore_errors=no ; start_time=[Tue 2026-11-17 02:31:12 UTC] ; stop_time=[Thu 2026-11-19 16:06:18 UTC] ; pid=50887 ; code=exited ; status=0 }",
      "Id": "horizon-qualify-247-reboot-20261117-v2.service",
      "InvocationID": "d091bb68ff2648159c76f690b3b7fee3",
      "LoadState": "loaded",
      "MainPID": "0",
      "NRestarts": "0",
      "Result": "success",
      "SubState": "dead"
    }
  }
}"###).unwrap()
    }
    fn cleared_history(unit: &Value) -> Value {
        let mut v = unit.clone();
        v["ExecStart"] = json!(format!(
            "{} ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
            command_identity(text(unit, "ExecStart").unwrap()).unwrap()
        ));
        v
    }
    #[test]
    fn actual_nested_terminal_receipt_survives_only_pid1_command_history_reset() {
        let receipt = fixture();
        let unit = &receipt["producer"]["unit"];
        terminal_identity(unit, &receipt).unwrap();
        let current = cleared_history(unit);
        terminal_identity(&current, &receipt).unwrap();
        same_terminal_census(unit, &current).unwrap();
        let mut owner = unit.clone();
        owner["ControlGroup"] = json!("");
        let reset = cleared_history(&owner);
        same_owner(&owner, &reset).unwrap();
        let mut unsafe_owner = reset;
        unsafe_owner["ExecStart"] = json!(
            text(&unsafe_owner, "ExecStart")
                .unwrap()
                .replace("ignore_errors=no", "ignore_errors=yes")
        );
        assert!(same_owner(&owner, &unsafe_owner).is_err());
        let flat = json!({"producer":unit});
        assert!(terminal_identity(unit, &flat).is_err());
        let absent = json!({"producer":{"unit":{}}});
        assert!(terminal_identity(&json!({}), &absent).is_err());
    }
    #[test]
    fn terminal_identity_rejects_changed_native_fields_and_missing_evidence() {
        let receipt = fixture();
        let original = &receipt["producer"]["unit"];
        for key in [
            "Id",
            "LoadState",
            "InvocationID",
            "ExecMainCode",
            "ExecMainStatus",
            "NRestarts",
            "Result",
            "ActiveState",
            "SubState",
            "MainPID",
        ] {
            let mut current = original.clone();
            current[key] = json!("changed");
            assert!(terminal_identity(&current, &receipt).is_err(), "{key}");
            assert!(same_terminal_census(original, &current).is_err(), "{key}");
            let mut missing = receipt.clone();
            missing["producer"]["unit"]
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(
                terminal_identity(original, &missing).is_err(),
                "missing {key}"
            );
        }
        let mut extra = original.clone();
        extra["ControlPID"] = json!("42");
        assert!(same_terminal_census(original, &extra).is_err());
    }
    #[test]
    fn command_identity_keeps_argv_ignore_errors_and_single_command_strict() {
        let receipt = fixture();
        let original = &receipt["producer"]["unit"];
        let current = cleared_history(original);
        let command = text(&current, "ExecStart").unwrap();
        for changed in [
            command.replace(" 247 ", " 248 "),
            command.replace("ignore_errors=no", "ignore_errors=yes"),
            command.replace("path=/var/lib/jetstreamer/", "path=/other/"),
            command.replace(" ; pid=0", " ; pid=invalid"),
            format!("{command} {command}"),
            command.replace("start_time=[n/a]", "start_time=n/a"),
        ] {
            let mut bad = current.clone();
            bad["ExecStart"] = json!(changed);
            assert!(terminal_identity(&bad, &receipt).is_err());
            assert!(same_terminal_census(original, &bad).is_err());
        }
        assert!(command_identity("opaque same string").is_err());
    }
}
