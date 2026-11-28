//! Scope-limited native proof before an exclusive standard-169 lease mutation.
//! This command authenticates closure. Deployment and a lease writer must
//! separately prove that future launches are fenced.
use super::*;
use crate::{
    standard169_cpu_lease::{
        COHORT_CONTROLLER, DEDICATED_PREFIXES, OPERATION_LOCK, REGISTRY_136, REGISTRY_171,
        STANDARD169_PLAN, dedicated_standard169, legacy_child_overlaps_169, require_unclaimed,
    },
    standard169_lineage::{MEASURE, focused_family, standard_names, standard_source},
    systemd_owned_mask::{HIGH, check_destinations, safe_dir},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::ErrorKind,
    os::fd::AsRawFd,
    process::ExitStatus,
};

const STATE: &str = "/var/lib/jetstreamer";
const SYSTEMD: &str = "/usr/bin/systemctl";
const CGROUPS: &str = "/sys/fs/cgroup/system.slice";
const LEGACY: &str = "jetstreamer-epochs159-173-target1-controller-v1-r2.service";
const LEGACY_LOCK: &str =
    "/var/lib/jetstreamer-root-sweep-epochs159-173-target1-20261016-v1/controller.lock";
const FOCUSED: &str = "horizon-qualify-169-focused-20261120-v4.service";
const FOCUSED_IID: &str = "0dfa0d36fbc246c28443a1c90a82c9cb";
const FOCUSED_GUARD: &str = "horizon-guard-169-focused-20261120-v4.service";
const FOCUSED_TIMER: &str = "horizon-guard-169-focused-20261120-v4.timer";
const FOCUSED_TIMER_IID: &str = "bca3b97b4b5c45e2a63496975378be20";
const FOCUSED_TERMINAL: (&str, &str) = (
    "/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-terminal-20261121-v1/TERMINAL.json",
    "218954bde25b9176b8063c1555dfcff29e91d5f42281198d3dbf5484ee98c6f5",
);
const FOCUSED_DRAIN: (&str, &str) = (
    "/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-terminal-20261121-v1/TERMINAL_GUARD_DRAINED.json",
    "113c410f773cfb565bbed3de95d1c9b7fc17b278010fcae14fa92728a90e1448",
);
const ADMISSION_136: &str =
    "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1/admission.json";
const OWNER_136: &[&str] = &[
    "horizon-qualify-136-actual-20261120-g1.service",
    "horizon-admit-136-actual-20261120-g1.service",
    "horizon-guard-136-actual-20261120-g1.service",
    "horizon-guard-136-actual-20261120-g1.timer",
];

#[derive(Debug, PartialEq, Eq)]
struct Scope {
    masks: BTreeSet<String>,
    legacy_children: BTreeSet<String>,
    watched: BTreeSet<String>,
}

fn unit_name(name: &str) -> bool {
    name.len() <= 255
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        && (name.ends_with(".service") || name.ends_with(".timer"))
}

fn inventory_names(raw: &str, key: &str) -> Result<BTreeSet<String>> {
    let rows: Vec<Value> = serde_json::from_str(raw)?;
    let mut units = BTreeSet::new();
    for row in rows {
        let unit = at(&row, key)?;
        ensure!(unit_name(unit), "invalid scoped PID1 name {unit}");
        ensure!(
            units.insert(unit.to_owned()),
            "duplicate scoped PID1 name {unit}"
        );
    }
    Ok(units)
}

fn inventory(
    patterns: &[String],
    call: &impl Fn(&str, &[String]) -> Result<(ExitStatus, String)>,
) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for (command, key) in [("list-units", "unit"), ("list-unit-files", "unit_file")] {
        let mut args = vec![
            command.to_owned(),
            "--no-pager".into(),
            "--no-legend".into(),
            "--output=json".into(),
        ];
        if command == "list-units" {
            args.push("--all".into());
        }
        args.extend_from_slice(patterns);
        let (status, output) = call(SYSTEMD, &args)?;
        ensure!(
            status.success(),
            "scoped systemctl {command} failed ({status})"
        );
        names.extend(inventory_names(&output, key)?);
    }
    Ok(names)
}

fn scope(route: &Value, discovered: &BTreeSet<String>) -> Result<Scope> {
    let mut legacy_children = BTreeSet::new();
    let mut dedicated = BTreeSet::new();
    for name in discovered {
        ensure!(unit_name(name), "invalid scoped unit name {name}");
        if dedicated_standard169(name) {
            dedicated.insert(name.clone());
        } else if legacy_child_overlaps_169(name)? {
            legacy_children.insert(name.clone());
        } else {
            ensure!(
                focused_family(name) || legacy_patterns().iter().any(|p| name.starts_with(p)),
                "unexpected scoped family {name}"
            );
        }
    }
    let mut masks = standard_names(route, &dedicated)?;
    ensure!(
        masks.remove(LEGACY),
        "missing legacy controller in original plan"
    );
    ensure!(
        masks.iter().all(|unit| dedicated_standard169(unit)),
        "original route contains a non-dedicated unit"
    );
    let watched = masks
        .iter()
        .chain(legacy_children.iter())
        .cloned()
        .chain(
            OWNER_136
                .iter()
                .copied()
                .chain([
                    LEGACY,
                    FOCUSED,
                    FOCUSED_GUARD,
                    FOCUSED_TIMER,
                    UNIT,
                    TIMER,
                    GUARD_SERVICE,
                ])
                .map(str::to_owned),
        )
        .collect();
    Ok(Scope {
        masks,
        legacy_children,
        watched,
    })
}

fn legacy_patterns() -> [String; 3] {
    ["sweep", "source-recovery", "import"]
        .map(|kind| format!("jetstreamer-root-{kind}-{COHORT_CONTROLLER}-"))
}

fn work_scope_patterns() -> Vec<String> {
    DEDICATED_PREFIXES
        .iter()
        .map(|p| format!("{p}*"))
        .chain(["horizon-retry*-peer169-*".to_owned()])
        .chain(legacy_patterns().map(|prefix| format!("{prefix}*")))
        .collect()
}

fn cgroup_names() -> Result<BTreeSet<String>> {
    let legacy = legacy_patterns();
    let mut groups = BTreeSet::new();
    for entry in fs::read_dir(CGROUPS)? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if DEDICATED_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
            || (name.starts_with("horizon-retry") && name.contains("-peer169-"))
            || legacy.iter().any(|prefix| name.starts_with(prefix))
        {
            ensure!(unit_name(&name), "malformed scoped cgroup name {name}");
            groups.insert(name.into_owned());
        }
    }
    Ok(groups)
}

fn relevant_jobs(raw: &str, scope: &Scope) -> Result<BTreeSet<String>> {
    let typed: Value = serde_json::from_str(raw)?;
    ensure!(
        typed["type"] == "a(usssoo)",
        "unexpected PID1 ListJobs signature"
    );
    let returns = typed["data"].as_array().context("ListJobs result")?;
    ensure!(returns.len() == 1, "unexpected ListJobs return arity");
    let jobs = returns[0].as_array().context("ListJobs job array")?;
    let mut ids = BTreeSet::new();
    let mut relevant = BTreeSet::new();
    for job in jobs {
        let row = job.as_array().context("ListJobs tuple")?;
        ensure!(row.len() == 6, "unexpected ListJobs tuple arity");
        let id = row[0]
            .as_u64()
            .filter(|id| *id > 0 && *id <= u32::MAX.into())
            .context("invalid ListJobs ID")?;
        let unit = row[1]
            .as_str()
            .filter(|s| {
                !s.is_empty()
                    && s.len() <= 255
                    && !s
                        .bytes()
                        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            })
            .context("invalid ListJobs unit")?;
        let mut object = String::from("/org/freedesktop/systemd1/unit/");
        for b in unit.bytes() {
            if b.is_ascii_alphanumeric() {
                object.push(char::from(b));
            } else {
                use std::fmt::Write as _;
                write!(object, "_{b:02x}")?;
            }
        }
        ensure!(
            ids.insert(id)
                && row[2].as_str().is_some_and(|s| !s.is_empty())
                && matches!(row[3].as_str(), Some("waiting" | "running"))
                && row[4] == format!("/org/freedesktop/systemd1/job/{id}")
                && row[5] == object,
            "invalid ListJobs identity for {unit}"
        );
        if scope.watched.contains(unit)
            || dedicated_standard169(unit)
            || legacy_child_overlaps_169(unit)?
        {
            relevant.insert(unit.to_owned());
        }
    }
    Ok(relevant)
}

fn parse_closed_units(
    scope: &Scope,
    status: ExitStatus,
    raw: &str,
) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
    ensure!(
        status.success() || status.code() == Some(4),
        "scoped systemctl show failed ({status})"
    );
    let mut units = BTreeMap::new();
    for section in raw.trim_end().split("\n\n") {
        let mut row = BTreeMap::new();
        for line in section.lines() {
            let (key, val) = line.split_once('=').context("scoped systemctl property")?;
            ensure!(
                row.insert(key.to_owned(), val.to_owned()).is_none(),
                "duplicate manager property {key}"
            );
        }
        let value = |key: &str| row.get(key).map(String::as_str);
        let unit = value("Id").context("missing manager Id")?;
        ensure!(scope.watched.contains(unit), "unexpected manager Id {unit}");
        let load = value("LoadState").context("missing manager LoadState")?;
        let allowed_names = match value("Names") {
            Some("") if load == "not-found" => true,
            Some(names) => names == unit,
            None => false,
        };
        ensure!(
            allowed_names
                && matches!(load, "loaded" | "not-found" | "masked")
                && (!scope.masks.contains(unit) || load != "masked")
                && matches!(value("ActiveState"), Some("inactive" | "failed"))
                && value("Job") == Some("")
                && [("MainPID", Some("0")), ("ControlPID", Some("0"))]
                    .into_iter()
                    .all(|(key, zero)| value(key) == zero
                        || (unit.ends_with(".timer") && value(key).is_none()))
                && (value("ControlGroup") == Some("")
                    || (unit.ends_with(".timer") && value("ControlGroup").is_none()))
                && matches!(value("Slice"), None | Some("" | "system.slice")),
            "live, aliased or ambiguous scoped unit {unit}"
        );
        let unit = unit.to_owned();
        ensure!(
            units.insert(unit.clone(), row).is_none(),
            "duplicate manager Id {unit}"
        );
    }
    ensure!(
        units.keys().eq(scope.watched.iter()),
        "incomplete scoped systemctl show"
    );
    ensure!(
        status.success() || units.values().any(|row| row["LoadState"] == "not-found"),
        "systemctl reported missing units without native evidence"
    );
    Ok(units)
}

fn is_cgroup_empty(raw: &str) -> bool {
    raw.lines()
        .filter(|line| line.starts_with("populated "))
        .eq(["populated 0"])
}

fn cgroup_empty(unit: &str) -> Result<&'static str> {
    // All scoped service definitions are in system.slice. A named alternate
    // slice or a nonempty ControlGroup fails the manager check before this read.
    let path = Path::new(CGROUPS).join(unit);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok("absent"),
        Err(e) => Err(e.into()),
        Ok(meta) => {
            ensure!(
                meta.is_dir() && path.canonicalize()? == path,
                "foreign cgroup {}",
                path.display()
            );
            ensure!(
                is_cgroup_empty(&fs::read_to_string(path.join("cgroup.events"))?),
                "scoped cgroup populated or unreadable at {unit}"
            );
            Ok("drained")
        }
    }
}

#[derive(PartialEq, Eq)]
struct Closure {
    scope: Scope,
    units: BTreeMap<String, BTreeMap<String, String>>,
    cgroups: BTreeMap<String, &'static str>,
}

fn capture(
    route: &Value,
    call: &impl Fn(&str, &[String]) -> Result<(ExitStatus, String)>,
    group_names: &impl Fn() -> Result<BTreeSet<String>>,
    drained: &impl Fn(&str) -> Result<&'static str>,
) -> Result<Closure> {
    let patterns = work_scope_patterns();
    let discovered = inventory(&patterns, call)?;
    let groups = group_names()?;
    let names = discovered.union(&groups).cloned().collect();
    let scope = scope(route, &names)?;
    let bus = [
        "--system",
        "--json=short",
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "ListJobs",
    ]
    .map(str::to_owned);
    let no_jobs = || -> Result<()> {
        let (status, output) = call("/usr/bin/busctl", &bus)?;
        ensure!(status.success(), "scoped PID1 ListJobs failed ({status})");
        let jobs = relevant_jobs(&output, &scope)?;
        ensure!(jobs.is_empty(), "queued scoped native jobs: {jobs:?}");
        Ok(())
    };
    no_jobs()?;
    let mut args = [
        "show", "--all", "--no-pager",
        "--property=Id,Names,LoadState,ActiveState,SubState,InvocationID,Job,MainPID,ControlPID,ControlGroup,Slice",
        "--",
    ].map(str::to_owned).to_vec();
    args.extend(scope.watched.iter().cloned());
    let (status, output) = call(SYSTEMD, &args)?;
    let units = parse_closed_units(&scope, status, &output)?;
    let cgroups = scope
        .watched
        .iter()
        .map(|unit| {
            let state = drained(unit)?;
            ensure!(
                matches!(state, "drained" | "absent"),
                "ambiguous cgroup at {unit}"
            );
            Ok((unit.clone(), state))
        })
        .collect::<Result<_>>()?;
    no_jobs()?;
    ensure!(
        inventory(&patterns, call)? == discovered && group_names()? == groups,
        "scoped unit or cgroup census changed"
    );
    Ok(Closure {
        scope,
        units,
        cgroups,
    })
}

fn focused_terminal(terminal: &Value, drain: &Value) -> Result<()> {
    let proof = &drain["binding"];
    ensure!(
        terminal["producer_unit"] == FOCUSED
            && terminal["producer_invocation_id"] == FOCUSED_IID
            && terminal["reservation_ending_bytes"] == 0
            && terminal["resource_credit_bytes"] == 0
            && proof["producer_invocation_id"] == FOCUSED_IID
            && proof["guard_unit"] == FOCUSED_GUARD
            && proof["timer_unit"] == FOCUSED_TIMER
            && proof["timer_invocation_id"] == FOCUSED_TIMER_IID
            && proof["resource_credit_bytes"] == 0
            && proof["terminal"] == binding(Path::new(FOCUSED_TERMINAL.0), FOCUSED_TERMINAL.1),
        "foreign focused 169 closure"
    );
    let retired = drain["after"]
        .as_array()
        .context("focused 169 guard drain")?;
    ensure!(
        retired.len() == 2
            && [FOCUSED_GUARD, FOCUSED_TIMER]
                .iter()
                .all(|unit| retired.iter().any(|row| {
                    row["Id"] == *unit
                        && row["ActiveState"] == "inactive"
                        && row["SubState"] == "dead"
                        && row["Job"] == ""
                })),
        "focused 169 guard did not drain"
    );
    Ok(())
}

fn expired_136(record: &Value, sampled_at: u64) -> Result<()> {
    let integer = |key: &str| {
        record[key]
            .as_u64()
            .with_context(|| format!("missing {key}"))
    };
    let expiry = integer("launch_expires_unix_seconds")?;
    let start = integer("recorded_unix_seconds")?;
    ensure!(
        record["schema"] == "horizon-epoch136-actual-admission-v1"
            && start > 0
            && start.checked_add(900) == Some(expiry)
            && sampled_at >= expiry,
        "live or ambiguous epoch 136 admission"
    );
    Ok(())
}

fn rival_136() -> Result<Value> {
    require_unclaimed(Path::new(REGISTRY_136))?;
    let path = Path::new(ADMISSION_136);
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Value::Null),
        Err(e) => Err(e.into()),
        Ok(_) => {
            let bytes = read_root(path)?;
            let record: Value = serde_json::from_slice(&bytes)?;
            expired_136(&record, now()?)?;
            Ok(binding(path, &digest(&bytes)))
        }
    }
}

pub(super) struct OperationLock(File);

impl OperationLock {
    pub(super) fn acquire() -> Result<Self> {
        Ok(Self(existing_lock(OPERATION_LOCK)?))
    }

    fn identity(&self) -> Result<(u64, u64)> {
        lock_identity(&self.0, OPERATION_LOCK)
    }
}

fn existing_lock(path: &str) -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let identity = lock_identity(&lock, path)?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "scoped native lock is held at {path}"
    );
    ensure!(
        lock_identity(&lock, path)? == identity,
        "native lock changed at {path}"
    );
    Ok(lock)
}

fn lock_identity(lock: &File, path: &str) -> Result<(u64, u64)> {
    let path = Path::new(path);
    let m = lock.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && path.canonicalize()? == path
            && (m.dev(), m.ino()) == (named.dev(), named.ino()),
        "foreign or replaced lock at {}",
        path.display()
    );
    Ok((m.dev(), m.ino()))
}

fn verify_cgroup_root() -> Result<()> {
    use std::{ffi::CString, mem::MaybeUninit};
    let dir = Path::new(CGROUPS);
    ensure!(
        dir.is_dir() && dir.canonicalize()? == dir,
        "missing native system.slice"
    );
    let path = CString::new(CGROUPS)?;
    let mut info = MaybeUninit::<libc::statfs>::uninit();
    ensure!(
        unsafe { libc::statfs(path.as_ptr(), info.as_mut_ptr()) } == 0
            && unsafe { info.assume_init() }.f_type == libc::CGROUP2_SUPER_MAGIC,
        "system.slice is outside cgroup v2"
    );
    let local = dir.metadata()?;
    let manager = fs::metadata(Path::new("/proc/1/root").join(dir.strip_prefix("/")?))?;
    ensure!(
        (local.dev(), local.ino()) == (manager.dev(), manager.ino())
            && fs::read_link("/proc/1/ns/cgroup")? == fs::read_link("/proc/self/ns/cgroup")?,
        "scoped closure reader is outside PID1's cgroup view"
    );
    Ok(())
}

pub(super) fn inspect(lock: &OperationLock) -> Result<Value> {
    let identity = lock.identity()?;
    let legacy = existing_lock(LEGACY_LOCK)?;
    let legacy_identity = lock_identity(&legacy, LEGACY_LOCK)?;
    verify_cgroup_root()?;
    require_unclaimed(Path::new(REGISTRY_171))?;
    let start = now()?;
    let boot = || fs::read_to_string("/proc/sys/kernel/random/boot_id");
    let boot_id = boot()?;
    let state = Path::new(STATE);
    let route = standard_source(state, json_pin)?;
    let measure = json_pin(&state.join(MEASURE.0), MEASURE.1)?;
    ensure!(
        measure["complete_booked_cpu_quota_micros"] == 43_000_000,
        "wrong historical CPU booking"
    );
    focused_terminal(
        &json_pin(Path::new(FOCUSED_TERMINAL.0), FOCUSED_TERMINAL.1)?,
        &json_pin(Path::new(FOCUSED_DRAIN.0), FOCUSED_DRAIN.1)?,
    )?;
    let rival = rival_136()?;
    let native = |program: &str, args: &[String]| {
        let (status, output) = run_status(program, args, bounded())?;
        Ok((status, String::from_utf8(output)?))
    };
    let proof = capture(&route, &native, &cgroup_names, &cgroup_empty)?;
    ensure!(
        capture(&route, &native, &cgroup_names, &cgroup_empty)? == proof,
        "scoped native closure changed"
    );
    let high = Path::new(HIGH);
    safe_dir(high)?;
    check_destinations(high, None, &proof.scope.masks)?;
    ensure!(
        rival == rival_136()? && boot()? == boot_id,
        "136 or boot identity changed"
    );
    require_unclaimed(Path::new(REGISTRY_171))?;
    let (device, inode) = lock.identity()?;
    ensure!((device, inode) == identity, "CPU operation lock changed");
    ensure!(
        lock_identity(&legacy, LEGACY_LOCK)? == legacy_identity,
        "legacy controller lock changed"
    );
    verify_cgroup_root()?;
    Ok(json!({
        "schema":"horizon-epoch171-standard169-native-closure-v1",
        "boot_id":boot_id.trim(),
        "started_unix_seconds":start,
        "completed_unix_seconds":now()?,
        "operation_lock":{"path":OPERATION_LOCK,"device":device,"inode":inode},
        "legacy_controller_lock":{"path":LEGACY_LOCK,"device":legacy_identity.0,"inode":legacy_identity.1},
        "standard_booking":binding(&state.join(MEASURE.0),MEASURE.1),
        "standard_plan":binding(&state.join(STANDARD169_PLAN.0),STANDARD169_PLAN.1),
        "focused_terminal":binding(Path::new(FOCUSED_TERMINAL.0),FOCUSED_TERMINAL.1),
        "focused_guard_drain":binding(Path::new(FOCUSED_DRAIN.0),FOCUSED_DRAIN.1),
        "expired_136_admission":rival,
        "dedicated_routes":proof.scope.masks,
        "overlapping_legacy_children":proof.scope.legacy_children,
        "native_units":proof.units,
        "cgroups":proof.cgroups,
        "mask_destination_directory":HIGH,
        "legacy_latch_qualified":false,
        "lease_established":false,
        "replay_launch_authorized":false,
        "resource_credit_bytes":0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, os::unix::process::ExitStatusExt};

    const DEDICATED: &str = "horizon-qualify-169-standard-20261109-v1.service";
    const HOURLY: &str = "horizon-qualify-169-focused-hourly-20261123-v1.service";
    const CHILD: &str =
        "jetstreamer-root-source-recovery-e159-173-t1-20261016-v1-r2-e167-170-lane-a-3.service";
    const OUTSIDE: &str = "jetstreamer-root-import-e159-173-t1-20261016-v1-r2-e171-173-2.service";

    fn original() -> Value {
        let closed = (0..25)
            .map(|idx| format!("horizon-guard-169-standard-{idx}.timer"))
            .chain([DEDICATED.to_owned(), LEGACY.to_owned()])
            .collect::<Vec<_>>();
        json!({"epoch":169,"producer_unit":DEDICATED,"closed_units":closed})
    }

    fn manager_row(unit: &str) -> String {
        format!(
            "Id={unit}\nNames={unit}\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nInvocationID=\nJob=\nMainPID=0\nControlPID=0\nControlGroup=\nSlice=system.slice"
        )
    }

    fn queue(unit: &str) -> String {
        use std::fmt::Write as _;
        let mut path = String::from("/org/freedesktop/systemd1/unit/");
        for b in unit.bytes() {
            if b.is_ascii_alphanumeric() {
                path.push(char::from(b));
            } else {
                write!(path, "_{b:02x}").unwrap();
            }
        }
        json!({"type":"a(usssoo)","data":[[[7,unit,"start","waiting","/org/freedesktop/systemd1/job/7",path]]]}).to_string()
    }

    #[derive(Clone, Copy, Default)]
    struct Fake {
        queued_at_end: Option<&'static str>,
        alias: bool,
        populated: bool,
        new_route: bool,
        foreign_mask: bool,
        orphaned: bool,
    }

    fn fixture(options: Fake) -> Result<Closure> {
        let jobs = Cell::new(0);
        let inventories = Cell::new(0);
        let call = |program: &str, args: &[String]| {
            let output = match (program, args[0].as_str()) {
                (SYSTEMD, "list-units") => {
                    assert!(args.iter().any(|arg| arg == "--all"));
                    assert!(
                        args.iter()
                            .any(|arg| arg.starts_with("jetstreamer-root-import-"))
                    );
                    inventories.set(inventories.get() + 1);
                    let mut rows = vec![json!({"unit":HOURLY})];
                    if !options.orphaned {
                        rows.push(json!({"unit":CHILD}));
                    }
                    if options.new_route && inventories.get() == 2 {
                        rows.push(json!({"unit":"horizon-qualify-169-new-generation.service"}));
                    }
                    json!(rows).to_string()
                }
                (SYSTEMD, "list-unit-files") => json!([{"unit_file":OUTSIDE}]).to_string(),
                (SYSTEMD, "show") => {
                    assert!(args.iter().all(|arg| arg != HOURLY && arg != OUTSIDE));
                    let first = args.iter().position(|arg| arg == "--").unwrap() + 1;
                    let mut rows = args[first..]
                        .iter()
                        .map(|unit| manager_row(unit))
                        .collect::<Vec<_>>();
                    if options.alias {
                        let row = rows
                            .iter_mut()
                            .find(|line| line.starts_with(&format!("Id={DEDICATED}\n")))
                            .unwrap();
                        *row = row.replace(
                            &format!("Names={DEDICATED}"),
                            &format!("Names={DEDICATED} alias.service"),
                        );
                    }
                    if options.foreign_mask {
                        let row = rows
                            .iter_mut()
                            .find(|line| line.starts_with(&format!("Id={DEDICATED}\n")))
                            .unwrap();
                        *row = row.replace("LoadState=loaded", "LoadState=masked");
                    }
                    rows.join("\n\n")
                }
                ("/usr/bin/busctl", "--system") => {
                    assert_eq!(args.last().unwrap(), "ListJobs");
                    jobs.set(jobs.get() + 1);
                    queue(if jobs.get() == 2 {
                        options.queued_at_end.unwrap_or(OUTSIDE)
                    } else {
                        OUTSIDE
                    })
                }
                _ => panic!("unexpected source command {program} {args:?}"),
            };
            Ok((ExitStatus::from_raw(0), output))
        };
        let drained = |unit: &str| {
            assert_ne!(unit, HOURLY);
            Ok(if unit == CHILD && options.populated {
                "populated"
            } else {
                "absent"
            })
        };
        let groups = || {
            Ok(if options.orphaned {
                BTreeSet::from([CHILD.to_owned()])
            } else {
                BTreeSet::new()
            })
        };
        capture(&original(), &call, &groups, &drained)
    }

    #[test]
    fn both_inventories_and_typed_jobs_preserve_other_cohorts_and_hourly_169() {
        let proof = fixture(Fake::default()).unwrap();
        assert_eq!(proof.scope.masks.len(), 33);
        assert_eq!(
            proof.scope.legacy_children,
            BTreeSet::from([CHILD.to_owned()])
        );
        assert!(proof.units.contains_key(LEGACY));
        assert!(proof.cgroups.contains_key(OWNER_136[0]));
        assert!(!proof.scope.masks.contains(LEGACY));
        assert!(!proof.scope.masks.contains(CHILD));
        assert!(!proof.units.contains_key(HOURLY));
        assert!(!proof.units.contains_key(OUTSIDE));
    }

    #[test]
    fn scope_refuses_queued_or_populated_children_aliases_and_crossing_inventory() {
        for options in [
            Fake {
                queued_at_end: Some(CHILD),
                ..Fake::default()
            },
            Fake {
                queued_at_end: Some(OWNER_136[1]),
                ..Fake::default()
            },
            Fake {
                populated: true,
                ..Fake::default()
            },
            Fake {
                populated: true,
                orphaned: true,
                ..Fake::default()
            },
            Fake {
                alias: true,
                ..Fake::default()
            },
            Fake {
                new_route: true,
                ..Fake::default()
            },
            Fake {
                foreign_mask: true,
                ..Fake::default()
            },
        ] {
            assert!(fixture(options).is_err());
        }
    }

    #[test]
    fn metadata_defaults_cannot_forge_native_closure() {
        let scope = scope(&original(), &BTreeSet::new()).unwrap();
        let output = scope
            .watched
            .iter()
            .map(|unit| manager_row(unit))
            .collect::<Vec<_>>()
            .join("\n\n");
        let ok = ExitStatus::from_raw(0);
        assert!(parse_closed_units(&scope, ok, &output.replace("Job=", "Job=42")).is_err());
        assert!(
            parse_closed_units(
                &scope,
                ok,
                &output.replace("Slice=system.slice", "Slice=other.slice")
            )
            .is_err()
        );
        assert!(parse_closed_units(&scope, ExitStatus::from_raw(4 << 8), &output).is_err());
        assert!(relevant_jobs(&queue(CHILD).replace("/job/7", "/job/8"), &scope).is_err());
        assert!(relevant_jobs(&queue(CHILD).replace("a(usssoo)", "a(uss)"), &scope).is_err());
        assert!(is_cgroup_empty("populated 0\nfrozen 0\n"));
        assert!(!is_cgroup_empty("frozen 0\n"));
        assert!(!is_cgroup_empty("populated 1\n"));
        assert!(!is_cgroup_empty("populated 1\npopulated 0\n"));
    }

    #[test]
    fn original_focused_drain_and_136_expiry_require_exact_identity() {
        let terminal = json!({"producer_unit":FOCUSED,"producer_invocation_id":FOCUSED_IID,
                              "reservation_ending_bytes":0,"resource_credit_bytes":0});
        let mut drain = json!({
            "binding":{"producer_invocation_id":FOCUSED_IID,"guard_unit":FOCUSED_GUARD,
                       "timer_unit":FOCUSED_TIMER,"timer_invocation_id":FOCUSED_TIMER_IID,
                       "resource_credit_bytes":0,"terminal":binding(Path::new(FOCUSED_TERMINAL.0),FOCUSED_TERMINAL.1)},
            "after":[{"Id":FOCUSED_GUARD,"ActiveState":"inactive","SubState":"dead","Job":""},
                     {"Id":FOCUSED_TIMER,"ActiveState":"inactive","SubState":"dead","Job":""}]
        });
        focused_terminal(&terminal, &drain).unwrap();
        drain["after"][1]["Job"] = json!("41");
        assert!(focused_terminal(&terminal, &drain).is_err());
        let mut admission = json!({"schema":"horizon-epoch136-actual-admission-v1",
                                  "recorded_unix_seconds":1000,"launch_expires_unix_seconds":1900});
        assert!(expired_136(&admission, 1899).is_err());
        expired_136(&admission, 1900).unwrap();
        admission["recorded_unix_seconds"] = json!(0);
        assert!(expired_136(&admission, 1900).is_err());
    }
}
