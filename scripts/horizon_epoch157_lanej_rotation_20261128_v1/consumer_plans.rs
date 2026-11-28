// PID1's text view omits empty command arrays and can put literal newlines and
// multiple ExecStart entries in a single unit. Keep the structured argument vectors.
const UNIT_PROJECTION: &str = r#"
def projection(kind, common, detail):
    parts = [common["FragmentPath"], *common["DropInPaths"], *common["Triggers"], *common["TriggeredBy"]]
    if kind == "Service" and "ExecStart" not in detail:
        raise ValueError("incomplete service properties")
    if kind in ("Path", "Timer"):
        parts.append(detail["Unit"])
    if kind == "Path":
        parts.extend(path for _, path in detail["Paths"])
    elif kind == "Socket":
        parts.extend(address for _, address in detail["Listen"])
    for field in ("ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStopPre", "ExecStop", "ExecStopPost"):
        for entry in detail.get(field, ()):
            parts.append(entry[0])
            parts.extend(entry[1])
    if "WorkingDirectory" in detail:
        parts.append(detail["WorkingDirectory"])
    return "\n".join(str(s) for s in parts)
"#;
const INERT_ACTIVATIONS: &str = r#"
import datetime, os
def expired_timer(common, timer, target):
    never = (1 << 64) - 1
    if not (common["Transient"] and common["UnitFileState"] == "transient"
            and common["ActiveState"] == "active" and common["SubState"] == "running"
            and not common["Job"][0] and not common["TriggeredBy"] and timer["Unit"] == target
            and timer["LastTriggerUSec"] > 0 and timer["LastTriggerUSecMonotonic"] > 0
            and timer["NextElapseUSecRealtime"] == timer["NextElapseUSecMonotonic"] == never):
        return None
    calendar, mono = timer["TimersCalendar"], timer["TimersMonotonic"]
    if len(calendar) + len(mono) != 1:
        return None
    if calendar:
        base, spec, next_time = calendar[0]
        try:
            scheduled = datetime.datetime.strptime(str(spec), "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return None
        if base != "OnCalendar" or next_time != 0 or scheduled.timestamp() > timer["LastTriggerUSec"] / 1e6 + 1:
            return None
        schedule = str(spec)
    else:
        base, duration, next_time = mono[0]
        if base not in ("OnActiveUSec","OnBootUSec") or next_time != 0 or duration <= 0:
            return None
        schedule = str(base) + "=" + str(duration)
    return {"timer":str(common["Id"]), "schedule":schedule,
            "last_trigger_usec":int(timer["LastTriggerUSec"]), "next_realtime_and_monotonic":"infinity"}

def exited_service(common, svc):
    if not (common["Transient"] and common["UnitFileState"] == "transient"
            and common["ActiveState"] == "active" and common["SubState"] == "exited"
            and not common["Job"][0] and svc["RemainAfterExit"] and svc["Restart"] == "no"
            and svc["Result"] == "success" and not svc["MainPID"] and not svc["ControlPID"]
            and not any(svc.get(k,()) for k in ("ExecStop", "ExecStopPost", "ExecReload"))):
        return False
    group = str(svc.get("ControlGroup",""))
    if group:
        events = "/sys/fs/cgroup" + group + "/cgroup.events"
        try:
            with open(events) as f:
                if "populated 0" not in f.read().splitlines():
                    return False
        except FileNotFoundError:
            return not os.path.lexists("/sys/fs/cgroup" + group)
    return True

def consumed_static_calendar(common, timer, fetch):
    never = (1 << 64) - 1
    target = str(timer["Unit"])
    if not (common["UnitFileState"] == "static" and not common["Transient"]
            and common["ActiveState"] == "active" and common["SubState"] == "elapsed"
            and not common["Job"][0] and not common["TriggeredBy"]
            and list(common["Triggers"]) == [target] and target.endswith(".service")
            and not common["OnSuccess"] and not common["OnFailure"] and timer["RemainAfterElapse"]
            and not timer["Persistent"] and not timer["OnClockChange"] and not timer["OnTimezoneChange"]
            and timer["LastTriggerUSec"] > 0 and timer["LastTriggerUSecMonotonic"] > 0
            and timer["NextElapseUSecRealtime"] == timer["NextElapseUSecMonotonic"] == never
            and not timer["TimersMonotonic"] and len(timer["TimersCalendar"]) == 1):
        return None
    base, spec, next_time = timer["TimersCalendar"][0]
    if base != "OnCalendar" or next_time != 0:
        return None
    try:
        time = datetime.datetime.strptime(str(spec), "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    if time.timestamp() > timer["LastTriggerUSec"] / 1e6 + 1:
        return None
    up, sp = fetch(target, "Service")
    if not (up["UnitFileState"] == "static" and up["ActiveState"] == "inactive" and up["SubState"] == "dead"
            and not up["Job"][0] and list(up["TriggeredBy"]) == [common["Id"]]
            and not sp["MainPID"] and not sp["ControlPID"] and not sp["ControlGroup"] and sp["Restart"] == "no"
            and sp["Result"] == "success" and sp["ExecMainStatus"] == 0
            and sp["ExecMainExitTimestampMonotonic"] >= timer["LastTriggerUSecMonotonic"]):
        return None
    return {"timer":str(common["Id"]),"service":target,"consumed_static_calendar":str(spec),
            "last_trigger_usec":int(timer["LastTriggerUSec"]),"exit_usec":int(sp["ExecMainExitTimestamp"])}

def closed_activation(kind, common, detail, fetch):
    if kind == "Service" and common["SubState"] == "exited":
        if not exited_service(common, detail):
            return None
        timers = []
        for source in common["TriggeredBy"]:
            if not source.endswith(".timer"):
                return None
            up, tp = fetch(source,"Timer")
            proof = expired_timer(up,tp,common["Id"])
            if proof is None:
                return None
            timers.append(proof)
        return {"service":str(common["Id"]), "invocation":bytes(common["InvocationID"]).hex(), "expired_triggers":timers}
    if kind == "Timer" and common["SubState"] == "running":
        target = detail["Unit"]
        proof = expired_timer(common,detail,target)
        if not proof or not target.endswith(".service"):
            return None
        up, sp = fetch(target,"Service")
        if not exited_service(up,sp) or list(up["TriggeredBy"]) != [common["Id"]]:
            return None
        return {"service":str(target), "invocation":bytes(up["InvocationID"]).hex(), "expired_triggers":[proof]}
    return None
"#;
const NATIVE_UNITS: &str = r#"
import dbus, json, sys
bus = dbus.SystemBus()
service = "org.freedesktop.systemd1"
manager = dbus.Interface(bus.get_object(service, "/org/freedesktop/systemd1", introspect=False), service + ".Manager")
rows = []
def fetch(name, kind):
    path = manager.GetUnit(str(name))
    p = dbus.Interface(bus.get_object(service, path, introspect=False), "org.freedesktop.DBus.Properties")
    return p.GetAll(service + ".Unit"), p.GetAll(service + "." + kind)
follow_armed_targets = sys.argv[1] == "1"
for unit in sys.argv[2:]:
    kind = unit.rsplit(".", 1)[1].capitalize()
    if kind not in ("Service", "Timer", "Path", "Socket"):
        raise ValueError("unrecognized systemd unit " + unit)
    try:
        path = manager.GetUnit(unit)
        props = dbus.Interface(bus.get_object(service, path, introspect=False), "org.freedesktop.DBus.Properties")
        common = props.GetAll(service + ".Unit")
        if common["Id"] != unit:
            raise ValueError("different native unit " + unit)
        row = {"unit":unit, "state":str(common["ActiveState"]), "sub":str(common["SubState"]), "projection":""}
        if follow_armed_targets and common["Job"][0] and row["state"] in ("inactive", "failed"):
            row["state"] = "queued"
        if row["state"] not in ("inactive", "failed"):
            detail = props.GetAll(service + "." + kind)
            row["projection"] = projection(kind, common, detail)
            try:
                row["closed"] = closed_activation(kind, common, detail, fetch)
                if follow_armed_targets and not row["closed"] and kind == "Timer":
                    row["closed"] = consumed_static_calendar(common, detail, fetch)
            except dbus.DBusException as exc:
                if exc.get_dbus_name() not in ("org.freedesktop.systemd1.NoSuchUnit", "org.freedesktop.DBus.Error.UnknownObject"):
                    raise
                row["closed"] = None
            if follow_armed_targets and not row.get("closed") and kind in ("Socket", "Timer", "Path"):
                targets = set(str(v) for v in common["Triggers"])
                if kind in ("Timer", "Path"):
                    targets.add(str(detail["Unit"]))
                for target in sorted(t for t in targets if t.endswith(".service")):
                    try:
                        up, sp = fetch(target, "Service")
                    except dbus.DBusException as exc:
                        raise ValueError("unresolved activation target " + target + " for " + unit) from exc
                    row["projection"] += "\n" + projection("Service", up, sp)
        rows.append(row)
    except dbus.DBusException as error:
        if error.get_dbus_name() not in ("org.freedesktop.systemd1.NoSuchUnit", "org.freedesktop.DBus.Error.UnknownObject"):
            raise
        rows.append({"unit":unit, "state":"gone", "sub":"", "projection":""})
print(json.dumps(rows))
"#;
#[derive(serde::Deserialize)]
struct NativePlan {
    unit: String,
    state: String,
    sub: String,
    projection: String,
    closed: Option<Value>,
}
fn native_plans(units: &[&str], follow_armed_targets: bool) -> Result<Vec<NativePlan>> {
    let program = format!("{UNIT_PROJECTION}\n{INERT_ACTIVATIONS}\n{NATIVE_UNITS}");
    let flag = if follow_armed_targets { "1" } else { "0" };
    let mut args = vec!["-IB", "-c", &program, flag];
    args.extend_from_slice(units);
    let rows: Vec<NativePlan> = serde_json::from_str(&command("/usr/bin/python3", &args)?)?;
    ensure!(
        rows.len() == units.len()
            && rows
                .iter()
                .zip(units)
                .all(|(row, expected)| row.unit == *expected),
        "incomplete native entry-point inventory"
    );
    Ok(rows)
}
fn tokens(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c.is_ascii_whitespace() || "\\\"'(){}[]=,;|:".contains(c))
        .filter(|n| n.starts_with('/'))
}
fn material(p: &Path) -> bool {
    let name = p.to_string_lossy();
    p.is_absolute()
        && [
            "/var/lib/jetstreamer",
            "/usr/local/lib/jetstreamer",
            "/home/sol/.jetstreamer-private",
            "/etc/systemd",
            "/run/systemd",
        ]
        .iter()
        .any(|root| name.starts_with(root))
        && p.extension().and_then(|x| x.to_str()).is_some_and(|x| {
            matches!(
                x,
                "json" | "py" | "sh" | "toml" | "service" | "timer" | "path" | "socket" | "conf"
            )
        })
        && ![
            "credential",
            "secret",
            "/logs/",
            "/.git/",
            "/receipts/sample-",
            "/guard-receipts/sample-",
        ]
        .iter()
        .any(|r| name.to_ascii_lowercase().contains(r))
}
fn follows(p: &Path) -> bool {
    if matches!(
        p.extension().and_then(|s| s.to_str()),
        Some("py" | "sh" | "service" | "timer" | "path" | "socket")
    ) {
        return true;
    }
    let name = p
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    [
        "plan",
        "config",
        "contract",
        "launch",
        "profile",
        "manifest",
        "settings",
        "observer",
        "authority",
        "dispatch",
    ]
    .iter()
    .any(|term| name.contains(term))
}
#[derive(Default)]
struct PlanCache {
    entries: BTreeMap<PathBuf, (Vec<&'static str>, Vec<PathBuf>)>,
    estimated_bytes: usize,
    examined: usize,
}
fn artifacts(s: &str, cache: &mut PlanCache) -> Result<Vec<(PathBuf, Vec<&'static str>)>> {
    let mut hits = Vec::new();
    let mut seen: BTreeSet<PathBuf> = tokens(s)
        .map(PathBuf::from)
        .filter(|p| material(p))
        .collect();
    let mut queue: VecDeque<PathBuf> = seen.iter().cloned().collect();
    while let Some(p) = queue.pop_front() {
        if !cache.entries.contains_key(&p) {
            let a = match fs::metadata(&p) {
                Ok(x) => x,
                Err(e)
                    if e.kind() == io::ErrorKind::NotFound
                        || e.raw_os_error() == Some(libc::ENOTDIR) =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            if !a.is_file() || a.len() > 2 << 20 {
                continue;
            }
            let raw = fs::read(&p)?;
            let text = String::from_utf8_lossy(&raw);
            // Evidence leaves still receive a complete text check. Their historical links are never executed.
            let children: Vec<PathBuf> = if follows(&p) {
                tokens(&text)
                    .map(PathBuf::from)
                    .filter(|p| material(p))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            };
            if cache.estimated_bytes >= 48 << 20 {
                cache.entries.clear();
                cache.estimated_bytes = 0;
            }
            cache.estimated_bytes += 320
                + p.as_os_str().len()
                + children
                    .iter()
                    .map(|c| 96 + c.as_os_str().len())
                    .sum::<usize>();
            cache.examined += 1;
            cache.entries.insert(p.clone(), (terms(&text), children));
        }
        let (terms, children) = &cache.entries[&p];
        if !terms.is_empty() {
            hits.push((p, terms.clone()));
        }
        for child in children {
            // Enqueue each unique path once. Many plans share the same underlying evidence.
            if !seen.contains(child) {
                seen.insert(child.clone());
                queue.push_back(child.clone());
            }
        }
    }
    Ok(hits)
}
