//! Original recurring guard commitments, additional to the ordinary control reserve.
use super::*;
const CAP: u64 = 1_073_741_824;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Control {
    pub unit: String,
    pub timer: String,
    pub maximum_memory_bytes: u64,
    pub service_source: Bound,
    pub timer_source: Bound,
    pub guard_plan: Bound,
    pub executable: Bound,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    controls: Vec<Control>,
}
fn pins() -> Vec<Control> {
    let values = [
        (
            248,
            "c7cd20e232e84f8058de9101444a574e12a033d3a530e039a20274259fac9fe6",
            "90b637b95289135efe99f0ee6d757e104c9badbb4982e320b5e7a7521b141024",
            "7f2209ef5e614df2b7d12b01070051c836e3c41d9040aca2db00e98fba9f16e3",
        ),
        (
            249,
            "03f078405c3025b3152a602ba1d1e9aee7d65668f5fd9a5ccc15c7b2073b7682",
            "82e08be6d57b66819d78fa3ba673454036e3a1c93e15207e98139035a25ca0cb",
            "dfbf507ae27d6a4b469ce59263f3c7825303b3cd9642d2ce675943ffc8638bea",
        ),
        (
            250,
            "5a605e17f9db1170865aa10c3ab4ff9c5c6941d1bca6664f3d9ea9a1065972f3",
            "8fd1463f68f37b1ca4f8e671bb526c8fcd73495c96df543eb29b6edcf41c54a6",
            "0e625edd5cf5a254baac67ae645244a2ca55e5500c9dc6fa8d2d8116528aa7fc",
        ),
        (
            251,
            "93b54fd11b87fc43f9195ff68e7a50c832198f380c2b4c9722457f36f0e61b1d",
            "7125309e78b87fe55dfc8dbf3d3f7208d472be7711a99f44bcb4fbe26ac1fe89",
            "814b3f178f8883e94b9ead62ff942c1674e7162a0bf82403e7937d7f94bd2dcc",
        ),
    ];
    values.into_iter().map(|(epoch, service, timer, plan)| {
        let generation = if epoch == 251 { "replacement-20261118" } else { "reboot-20261117" };
        let root = format!("/var/lib/jetstreamer/horizon{epoch}-{generation}-guard-v1");
        let stem = format!("horizon-{epoch}-{generation}-protective-v1");
        let executable = if epoch == 251 {
            Bound::new("/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard", "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d")
        } else {
            Bound::new("/var/lib/jetstreamer/horizon-native223-prefix-guard-044ccba7-v1/jetstreamer-horizon-standalone-guard", "044ccba70304c6d5690d2628c1ca08586462efdcc2d9f278903ee8bab0da6b3f")
        };
        Control { unit: format!("{stem}.service"), timer: format!("{stem}.timer"), maximum_memory_bytes: CAP,
            service_source: Bound::new(format!("{root}/guard.service"), service), timer_source: Bound::new(format!("{root}/guard.timer"), timer), guard_plan: Bound::new(format!("{root}/guard-plan.json"), plan), executable }
    }).collect()
}
fn envelope(ledger: &Value, previous: &Value) -> Result<Vec<Control>> {
    if ledger["schema"] != "horizon265-retained-reservations-v3" {
        ensure!(
            ledger.get("periodic_controls").is_none()
                && previous.get("periodic_controls").is_none(),
            "legacy booking cannot discard recurring controls"
        );
        return Ok(Vec::new());
    }
    ensure!(
        previous["schema"] == "horizon265-prior-host-booking-v3"
            && ledger["periodic_controls"] == previous["periodic_controls"],
        "original recurring control booking changed"
    );
    let e: Envelope = serde_json::from_value(ledger["periodic_controls"].clone())?;
    ensure!(
        e.schema == "horizon265-original-periodic-controls-v1",
        "periodic envelope schema"
    );
    let expected = pins();
    ensure!(
        e.controls.len() == expected.len(),
        "incomplete periodic obligations"
    );
    let mut seen = BTreeSet::new();
    for c in &e.controls {
        ensure!(seen.insert(&c.unit), "duplicate periodic control");
        let p = expected
            .iter()
            .find(|p| p.unit == c.unit)
            .context("unregistered periodic control")?;
        ensure!(
            serde_json::to_value(c)? == serde_json::to_value(p)?,
            "original periodic source or cap changed"
        );
    }
    Ok(e.controls)
}
pub(super) fn total(controls: &[Control]) -> Result<u64> {
    controls
        .iter()
        .try_fold(0, |sum, c| capacity::add(sum, c.maximum_memory_bytes))
}
fn directive<'a>(source: &'a str, key: &str) -> Result<&'a str> {
    let prefix = format!("{key}=");
    let entries: Vec<_> = source
        .lines()
        .filter_map(|l| l.strip_prefix(&prefix))
        .collect();
    ensure!(
        entries.len() == 1 && !entries[0].is_empty(),
        "missing/duplicate source directive {key}"
    );
    Ok(entries[0])
}
fn argv(c: &Control) -> String {
    format!(
        "{} {} --plan-sha256 {} --self-sha256 {}",
        c.executable.path.display(),
        c.guard_plan.path.display(),
        c.guard_plan.sha256,
        c.executable.sha256
    )
}
pub(super) fn booking(
    ledger: &Value,
    previous: &Value,
    rows: &[capacity::Reservation],
) -> Result<Vec<Control>> {
    let controls = envelope(ledger, previous)?;
    let original_producers = [
        "horizon-qualify-248-reboot-20261117-v1.service",
        "horizon-qualify-249-reboot-20261117-v1.service",
        "horizon-qualify-250-reboot-20261117-v1.service",
        "horizon-qualify-251-replacement-20261118-v1.service",
    ];
    ensure!(
        !rows
            .iter()
            .any(|r| original_producers.contains(&r.unit.as_str()))
            || controls.len() == 4,
        "original replay guards require complete v3 periodic booking even while inactive"
    );
    for c in &controls {
        ensure!(
            !rows.iter().any(|r| r.unit == c.unit),
            "periodic control also booked as producer"
        );
        c.service_source.artifact()?;
        c.timer_source.artifact()?;
        c.executable.artifact()?;
        let s = String::from_utf8(c.service_source.bytes(true)?)?;
        let t = String::from_utf8(c.timer_source.bytes(true)?)?;
        ensure!(
            directive(&s, "MemoryMax")?.parse::<u64>()? == c.maximum_memory_bytes
                && directive(&s, "MemorySwapMax")? == "0"
                && directive(&s, "Restart")? == "no"
                && directive(&s, "Type")? == "oneshot"
                && directive(&s, "ExecStart")? == argv(c)
                && directive(&t, "Unit")? == c.unit
                && directive(&t, "OnActiveSec")? == "1s"
                && directive(&t, "OnUnitInactiveSec")? == "60s"
                && directive(&t, "AccuracySec")? == "1s"
                && directive(&t, "RandomizedDelaySec")? == "0",
            "original periodic directives differ"
        );
        let p = c.guard_plan.sealed()?;
        let owner = rows
            .iter()
            .find(|r| p["unit"] == r.unit && p["invocation_id"] == r.invocation_id)
            .context("periodic guard producer not retained")?;
        ensure!(
            p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
                && p["filesystem"] == "/"
                && num(&p, "minimum_free_bytes")? == owner.minimum_free_bytes,
            "periodic original floor or owner differs"
        );
    }
    Ok(controls)
}
// Only PID1's execution history is volatile. ignore_errors remains part of identity.
pub(super) fn stable_command(value: &str) -> Result<&str> {
    let (command, trailer) = value
        .split_once(" ; start_time=")
        .context("ExecStart history delimiter")?;
    ensure!(
        command.starts_with("{ path=/")
            && command.contains(" ; argv[]=")
            && command.ends_with(" ; ignore_errors=no")
            && !command.contains(" }"),
        "unsafe ExecStart command framing"
    );
    let trailer = trailer
        .strip_suffix(" }")
        .context("ExecStart history end")?;
    let fields: Vec<_> = trailer.split(" ; ").collect();
    ensure!(
        fields.len() == 5
            && !trailer.contains('{')
            && !trailer.contains('}')
            && fields[1].starts_with("stop_time=")
            && fields[2].starts_with("pid=")
            && fields[3].starts_with("code=")
            && fields[4].starts_with("status="),
        "ExecStart history framing"
    );
    Ok(command)
}
fn service_values(c: &Control, s: &Value) -> Result<bool> {
    let expected = format!(
        "{{ path={} ; argv[]={} ; ignore_errors=no",
        c.executable.path.display(),
        argv(c)
    );
    ensure!(
        s["Id"] == c.unit
            && s["LoadState"] == "loaded"
            && s["DropInPaths"] == ""
            && s["Type"] == "oneshot"
            && s["User"] == "root"
            && s["NRestarts"] == "0"
            && s["Restart"] == "no"
            && s["KillMode"] == "control-group"
            && s["Delegate"] == "no"
            && text(s, "MemoryMax")?.parse::<u64>()? == c.maximum_memory_bytes
            && s["MemorySwapMax"] == "0"
            && s["TasksMax"] == "256"
            && s["CPUQuotaPerSecUSec"] == "1s"
            && s["TriggeredBy"] == c.timer
            && s["ControlPID"] == "0"
            && s["Result"] == "success"
            && stable_command(text(s, "ExecStart")?)? == expected,
        "periodic service contract changed"
    );
    let dormant = s["ActiveState"] == "inactive" && s["SubState"] == "dead";
    if dormant {
        ensure!(
            s["MainPID"] == "0"
                && s["Job"] == ""
                && s["ExecMainStatus"] == "0"
                && (s["ControlGroup"] == ""
                    || s["ControlGroup"] == format!("/system.slice/{}", c.unit)),
            "periodic dormant owner not drained"
        );
    } else {
        ensure!(
            ((s["ActiveState"] == "activating" && s["SubState"] == "start")
                || (s["ActiveState"] == "active" && s["SubState"] == "running"))
                && num_string(s, "MainPID")? > 1
                && hex(text(s, "InvocationID")?, 32)
                && s["ControlGroup"] == format!("/system.slice/{}", c.unit),
            "ambiguous periodic firing"
        );
    }
    Ok(dormant)
}
fn num_string(v: &Value, key: &str) -> Result<u64> {
    Ok(text(v, key)?.parse()?)
}
fn timer_values(c: &Control, t: &Value, dormant: bool) -> Result<()> {
    ensure!(
        t["Id"] == c.timer
            && t["LoadState"] == "loaded"
            && t["ActiveState"] == "active"
            && t["Unit"] == c.unit
            && t["Job"] == ""
            && t["DropInPaths"] == ""
            && (t["SubState"] == "waiting" || (!dormant && t["SubState"] == "running")),
        "periodic timer not armed"
    );
    Ok(())
}
fn fragment(v: &Value, source: &Bound, unit: &str) -> Result<()> {
    let path = Path::new(text(v, "FragmentPath")?);
    ensure!(
        path == Path::new("/run/systemd/system").join(unit),
        "periodic fragment path changed"
    );
    let m = fs::symlink_metadata(path)?;
    if m.file_type().is_symlink() {
        // This is an installed-unit adapter, not a relaxation of Bound::bytes.
        trusted_parents(path)?;
        let parents: Vec<_> = path
            .ancestors()
            .skip(1)
            .map(|p| Ok((p, metadata_identity(&fs::symlink_metadata(p)?))))
            .collect::<Result<_>>()?;
        installed_link(path, &source.path, 0, || {
            trusted_parents(&source.path)?;
            source.bytes(true)?;
            Ok(())
        })?;
        for (parent, before) in parents {
            ensure!(
                metadata_identity(&fs::symlink_metadata(parent)?) == before,
                "installed fragment ancestor changed"
            );
        }
        trusted_parents(path)?;
    } else {
        // Preserve the original regular-file path and its strict no-link reader.
        Bound::new(path, &source.sha256).bytes(false)?;
    }
    Ok(())
}
// The owner argument permits an unprivileged filesystem regression fixture.
// Production calls this only after all ancestors pass the root trust check.
fn installed_link(
    path: &Path,
    expected: &Path,
    owner: u32,
    verify_source: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let parent = path.parent().context("installed fragment parent")?;
    ensure!(
        path.is_absolute() && parent.canonicalize()? == parent,
        "noncanonical installed parent"
    );
    let parent_before = fs::symlink_metadata(parent)?;
    ensure!(
        parent_before.is_dir() && parent_before.uid() == owner && parent_before.mode() & 0o022 == 0,
        "untrusted installed fragment parent"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.file_type().is_symlink()
            && before.uid() == owner
            && before.nlink() == 1
            && expected.is_absolute()
            && fs::read_link(path)? == expected
            && expected.canonicalize()? == expected,
        "installed link owner/target differs or contains a chain"
    );
    let target = fs::symlink_metadata(expected)?;
    ensure!(
        target.is_file() && target.nlink() == 1,
        "installed source is not regular"
    );
    verify_source()?;
    ensure!(
        metadata_identity(&before) == metadata_identity(&fs::symlink_metadata(path)?)
            && fs::read_link(path)? == expected
            && expected.canonicalize()? == expected
            && metadata_identity(&target) == metadata_identity(&fs::symlink_metadata(expected)?)
            && metadata_identity(&parent_before)
                == metadata_identity(&fs::symlink_metadata(parent)?)
            && parent.canonicalize()? == parent,
        "installed fragment changed during verification"
    );
    Ok(())
}
fn process_census(c: &Control, s: &Value, dormant: bool) -> Result<()> {
    let group = format!("/system.slice/{}", c.unit);
    let main = num_string(s, "MainPID")?;
    let mut found = BTreeSet::new();
    for e in fs::read_dir("/proc")? {
        let e = e?;
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u64>() else {
            continue;
        };
        let record = match fs::read_to_string(e.path().join("cgroup")) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if !record
            .lines()
            .any(|l| l == format!("0::{group}") || l.starts_with(&format!("0::{group}/")))
        {
            continue;
        }
        ensure!(
            !dormant && record.trim() == format!("0::{group}"),
            "dormant/descendant periodic process"
        );
        let image = fs::read_link(e.path().join("exe"))?;
        if pid == main {
            ensure!(
                image == c.executable.path
                    && metadata_identity(&fs::metadata(e.path().join("exe"))?)
                        == identity(&c.executable.path)?,
                "periodic mapped main image changed"
            );
        } else {
            // The original guard's only external child is systemctl; do not allow
            // a native worker to hide inside a control cgroup.
            ensure!(
                image == Path::new("/usr/bin/systemctl"),
                "unexpected periodic child image"
            );
            let stat = fs::read_to_string(e.path().join("stat"))?;
            let tail = stat.rsplit_once(") ").context("child stat")?.1;
            ensure!(
                tail.split_whitespace()
                    .nth(1)
                    .context("child parent")?
                    .parse::<u64>()?
                    == main,
                "periodic child parent changed"
            );
        }
        found.insert(pid);
    }
    ensure!(
        dormant || found.contains(&main),
        "periodic main vanished during census"
    );
    Ok(())
}
pub(super) fn observe(n: &mut Native, c: &Control) -> Result<()> {
    let s = n.show(&c.unit)?;
    let dormant = service_values(c, &s)?;
    fragment(&s, &c.service_source, &c.unit)?;
    let t = n.show(&c.timer)?;
    timer_values(c, &t, dormant)?;
    fragment(&t, &c.timer_source, &c.timer)?;
    if dormant {
        let object = format!(
            "/org/freedesktop/systemd1/unit/{}",
            c.timer
                .chars()
                .map(|ch| if ch.is_ascii_alphanumeric() {
                    ch.to_string()
                } else {
                    format!("_{:02x}", ch as u32)
                })
                .collect::<String>()
        );
        let raw = n.run(
            "/usr/bin/busctl",
            &[
                "get-property",
                "org.freedesktop.systemd1",
                &object,
                "org.freedesktop.systemd1.Timer",
                "NextElapseUSecMonotonic",
            ],
        )?;
        let fields: Vec<_> = std::str::from_utf8(&raw)?.split_whitespace().collect();
        ensure!(
            fields.len() == 2 && fields[0] == "t",
            "periodic typed timer deadline"
        );
        let next = fields[1].parse::<u64>()?;
        let clock = mono()?;
        ensure!(
            next > clock && next - clock <= 65_000_000,
            "periodic next firing absent/late"
        );
    }
    let root = Path::new("/sys/fs/cgroup/system.slice").join(&c.unit);
    match fs::symlink_metadata(&root) {
        Ok(_) => {
            ensure!(root.canonicalize()? == root, "periodic cgroup symlink");
            ensure!(
                fs::read_to_string(root.join("memory.max"))?
                    .trim()
                    .parse::<u64>()?
                    == c.maximum_memory_bytes
                    && fs::read_to_string(root.join("memory.swap.max"))?.trim() == "0"
                    && fs::read_to_string(root.join("pids.max"))?.trim() == "256"
                    && fs::read_to_string(root.join("memory.current"))?
                        .trim()
                        .parse::<u64>()?
                        <= c.maximum_memory_bytes,
                "periodic kernel limits changed"
            );
            if dormant {
                live::drained_tree(&root, &mut 1024)?;
            } else {
                let members: BTreeSet<u64> = fs::read_to_string(root.join("cgroup.procs"))?
                    .split_whitespace()
                    .map(str::parse)
                    .collect::<std::result::Result<_, _>>()?;
                ensure!(
                    members.contains(&num_string(&s, "MainPID")?),
                    "periodic main outside kernel group"
                );
            }
        }
        Err(e) if dormant && e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    process_census(c, &s, dormant)?;
    let after = n.show(&c.unit)?;
    service_values(c, &after)?;
    live::same_owner(&s, &after)?;
    let timer_after = n.show(&c.timer)?;
    timer_values(c, &timer_after, dormant)?;
    fragment(&after, &c.service_source, &c.unit)?;
    fragment(&timer_after, &c.timer_source, &c.timer)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value) {
        let e = json!({"schema":"horizon265-original-periodic-controls-v1", "controls":pins()});
        (
            json!({"schema":"horizon265-retained-reservations-v3","periodic_controls":e}),
            json!({"schema":"horizon265-prior-host-booking-v3","periodic_controls":e}),
        )
    }
    #[test]
    fn original_periodic_booking_cannot_drop_shrink_rebind_or_duplicate_a_guard() {
        let (l, p) = fixture();
        assert_eq!(total(&envelope(&l, &p).unwrap()).unwrap(), 4_294_967_296);
        for pointer in [
            "/periodic_controls/controls/0/maximum_memory_bytes",
            "/periodic_controls/controls/0/guard_plan/sha256",
            "/periodic_controls/controls/0/service_source/sha256",
            "/periodic_controls/controls/0/timer_source/sha256",
            "/periodic_controls/controls/0/executable/sha256",
        ] {
            let mut a = l.clone();
            let mut b = p.clone();
            *a.pointer_mut(pointer).unwrap() = json!(0);
            *b.pointer_mut(pointer).unwrap() = json!(0);
            assert!(envelope(&a, &b).is_err(), "{pointer}");
        }
        let mut a = l.clone();
        a["periodic_controls"]["controls"]
            .as_array_mut()
            .unwrap()
            .pop();
        let mut b = p.clone();
        b["periodic_controls"] = a["periodic_controls"].clone();
        assert!(envelope(&a, &b).is_err());
        a = l.clone();
        a["periodic_controls"]["controls"][1] = a["periodic_controls"]["controls"][0].clone();
        b = p.clone();
        b["periodic_controls"] = a["periodic_controls"].clone();
        assert!(envelope(&a, &b).is_err());
        assert!(envelope(&l, &json!({"schema":"horizon265-prior-host-booking-v2"})).is_err());
        a = l.clone();
        a["schema"] = json!("horizon265-retained-reservations-v2");
        assert!(envelope(&a, &p).is_err());
    }
    #[test]
    fn command_ignores_only_pid1_execution_history() {
        let command = "{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no";
        let a = format!(
            "{command} ; start_time=[Thu] ; stop_time=[Thu] ; pid=1 ; code=exited ; status=0 }}"
        );
        let b = format!(
            "{command} ; start_time=[Fri] ; stop_time=[Fri] ; pid=2 ; code=exited ; status=0 }}"
        );
        assert_eq!(stable_command(&a).unwrap(), stable_command(&b).unwrap());
        assert!(stable_command(&a.replace("ignore_errors=no", "ignore_errors=yes")).is_err());
        assert_ne!(
            stable_command(&a.replace("argv[]=/usr/bin/true", "argv[]=/usr/bin/false")).unwrap(),
            stable_command(&a).unwrap()
        );
        assert!(stable_command(&(a.clone() + " ; another command")).is_err());
        assert!(stable_command(&a.replace(" ; pid=1", " ; unknown=1")).is_err());
        assert!(stable_command(&(a.clone() + &b)).is_err());
    }
    fn service(c: &Control) -> Value {
        json!({"Id":c.unit,"LoadState":"loaded","DropInPaths":"","Type":"oneshot","User":"root","NRestarts":"0","Restart":"no","KillMode":"control-group","Delegate":"no","MemoryMax":c.maximum_memory_bytes.to_string(),"MemorySwapMax":"0","TasksMax":"256","CPUQuotaPerSecUSec":"1s","TriggeredBy":c.timer,"ControlPID":"0","Result":"success","ExecStart":format!("{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=[Thu] ; stop_time=[Thu] ; pid=42 ; code=exited ; status=0 }}",c.executable.path.display(),argv(c)),"ActiveState":"inactive","SubState":"dead","MainPID":"0","Job":"","ExecMainStatus":"0","ControlGroup":""})
    }
    #[test]
    fn periodic_dead_and_firing_states_keep_same_full_commitment() {
        let c = &pins()[0];
        let s = service(c);
        assert!(service_values(c, &s).unwrap());
        let mut firing = s.clone();
        firing["ActiveState"] = json!("activating");
        firing["SubState"] = json!("start");
        firing["MainPID"] = json!("42");
        firing["InvocationID"] = json!("a".repeat(32));
        firing["ControlGroup"] = json!(format!("/system.slice/{}", c.unit));
        assert!(!service_values(c, &firing).unwrap());
        for (key, val) in [
            ("MemoryMax", "1"),
            ("MemorySwapMax", "max"),
            ("NRestarts", "1"),
            ("TriggeredBy", "other.timer"),
            ("DropInPaths", "override.conf"),
            ("Result", "exit-code"),
            ("ControlPID", "42"),
            ("MainPID", "42"),
        ] {
            let mut bad = s.clone();
            bad[key] = json!(val);
            assert!(service_values(c, &bad).is_err(), "{key}");
        }
        let t = json!({"Id":c.timer,"LoadState":"loaded","ActiveState":"active","SubState":"waiting","Unit":c.unit,"Job":"","DropInPaths":""});
        timer_values(c, &t, true).unwrap();
        let mut bad = t.clone();
        bad["SubState"] = json!("running");
        assert!(timer_values(c, &bad, true).is_err());
        timer_values(c, &bad, false).unwrap();
        bad["Unit"] = json!("unrelated.service");
        assert!(timer_values(c, &bad, false).is_err());
        assert_eq!(total(&pins()).unwrap(), 4 * CAP);
    }
}

#[cfg(test)]
mod installed_fragment_tests {
    use super::*;
    use std::os::unix::fs::symlink;
    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, u32) {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source = d.path().join("sealed.service");
        fs::write(&source, b"exact sealed source").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o444)).unwrap();
        let link = d.path().join("installed.service");
        symlink(&source, &link).unwrap();
        let uid = unsafe { libc::geteuid() };
        (d, source, link, uid)
    }
    #[test]
    fn exact_direct_installed_link_uses_original_sealed_source_without_loosening_reader() {
        let (_d, source, link, uid) = setup();
        let expected_digest = digest(&fs::read(&source).unwrap());
        installed_link(&link, &source, uid, || {
            ensure!(digest(&fs::read(&source)?) == expected_digest, "digest");
            Ok(())
        })
        .unwrap();
        // The normal bound reader must still reject the installed symlink.
        assert!(Bound::new(&link, &expected_digest).bytes(false).is_err());
        assert!(installed_link(&link, &source, uid + 1, || Ok(())).is_err());
    }
    #[test]
    fn wrong_target_chain_or_untrusted_link_parent_is_rejected() {
        let (d, source, link, uid) = setup();
        let other = d.path().join("other.service");
        fs::write(&other, b"exact sealed source").unwrap();
        assert!(installed_link(&link, &other, uid, || Ok(())).is_err());
        let chain = d.path().join("chain.service");
        symlink(&source, &chain).unwrap();
        fs::remove_file(&link).unwrap();
        symlink(&chain, &link).unwrap();
        assert!(installed_link(&link, &source, uid, || Ok(())).is_err());
        assert!(installed_link(&link, &chain, uid, || Ok(())).is_err());
        fs::remove_file(&link).unwrap();
        symlink(&source, &link).unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(installed_link(&link, &source, uid, || Ok(())).is_err());
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let alias = d.path().join("alias");
        symlink(d.path(), &alias).unwrap();
        assert!(installed_link(&alias.join("installed.service"), &source, uid, || Ok(())).is_err());
    }
    #[test]
    fn link_replacement_and_source_changes_during_verification_fail_closed() {
        let (d, source, link, uid) = setup();
        let replacement = d.path().join("replacement");
        symlink(&source, &replacement).unwrap();
        assert!(
            installed_link(&link, &source, uid, || {
                fs::rename(&replacement, &link)?;
                Ok(())
            })
            .is_err()
        );
        assert!(
            installed_link(&link, &source, uid, || {
                fs::set_permissions(&source, fs::Permissions::from_mode(0o644))?;
                fs::write(&source, b"different source bytes")?;
                Ok(())
            })
            .is_err()
        );
        assert!(installed_link(&link, &source, uid, || bail!("sealed digest mismatch")).is_err());
        assert!(
            installed_link(&link, &source, uid, || {
                fs::set_permissions(d.path(), fs::Permissions::from_mode(0o777))?;
                Ok(())
            })
            .is_err()
        );
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
}
