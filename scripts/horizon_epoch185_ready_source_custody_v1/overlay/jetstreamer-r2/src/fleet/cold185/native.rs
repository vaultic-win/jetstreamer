//! Strict native ownership for the exact qualified epoch 185 adapter.
//! Namespace recognition is not ownership authentication or resource authority.
use super::*;
mod retained;
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
const MIB: u64 = 1 << 20;
const GUARD_MEMORY: u64 = 256 << 20;
const PACKAGE_SEAL_SHA: &str = "834b63769108b5b6f073a5ea9cfb7246464ae7f078dbdc978bcaab381e8e865e";
const FIELDS: &str = "--property=Id,LoadState,InvocationID,MainPID,ControlPID,NRestarts,Restart,ActiveState,SubState,Result,ExecMainStatus,ExecMainCode,ControlGroup,MemoryAccounting,MemoryMax,MemoryHigh,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,User,Group,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ProtectSystem,ProtectHome,PrivateNetwork,KillMode,Delegate,Job,Type,RemainAfterExit,TimeoutStartUSec,RuntimeMaxUSec,TimeoutStopUSec,LimitFSIZE,ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,FragmentPath,DropInPaths,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment,Unit,Triggers,TriggeredBy,TimersMonotonic,LastTriggerUSecMonotonic,ExecMainStartTimestampMonotonic";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    actor_unit: String,
    expected_actor_invocation_id: String,
    envelope: BoundFile,
    admission: BoundFile,
    actor_source: BoundFile,
    guard_source: BoundFile,
    timer_source: BoundFile,
    ready: BoundFile,
    current_task_status: BoundFile,
    mode: String,
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("epoch 185 missing string {key}"))
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("epoch 185 missing integer {key}"))
}
fn binding(v: &Value) -> Result<BoundFile> {
    Ok(serde_json::from_value(v.clone())?)
}
fn digest(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn ancestors(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "epoch 185 noncanonical evidence path"
    );
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "epoch 185 evidence ancestor custody changed"
        );
    }
    Ok(())
}
pub(in crate::fleet) fn read_immutable(b: &BoundFile, maximum: u64) -> Result<Vec<u8>> {
    ensure!(
        is_lower_hex(&b.sha256, 64),
        "epoch 185 invalid source digest"
    );
    ancestors(&b.path)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o7222 == 0
            && before.len() <= maximum,
        "epoch 185 immutable source custody"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(&b.path)?)
            && digest(&bytes) == b.sha256,
        "epoch 185 immutable source drift"
    );
    Ok(bytes)
}
/// The original fleet writer publishes Root0600 bytes. Retain native ancestor,
/// bound and identity checks while allowing only that owner's writable metadata.
pub(in crate::fleet) fn read_generated_json(b: &BoundFile, maximum: u64) -> Result<Value> {
    ancestors(&b.path)?;
    let before = fs::symlink_metadata(&b.path)?;
    ensure!(
        maximum > 0
            && maximum <= 16 << 20
            && before.len() <= maximum
            && before.mode() & 0o7022 == 0,
        "epoch185 generated source bound or custody"
    );
    let value = crate::fleet::epoch186::accounting::protected_generated(b)?;
    ensure!(
        identity(&before) == identity(&fs::symlink_metadata(&b.path)?),
        "epoch185 original generated source drift"
    );
    Ok(value)
}
pub(in crate::fleet) fn read_json(b: &BoundFile, maximum: u64) -> Result<Value> {
    Ok(serde_json::from_slice(&read_immutable(b, maximum)?)?)
}
fn syntax(name: &str) -> bool {
    name.len() <= 180
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}
pub(in crate::fleet) fn query_namespace(name: &str) -> bool {
    syntax(name)
        && ((name.starts_with("horizon-qualify-185-capped-cold-") && name.ends_with(".service"))
            || (name.starts_with("horizon-guard-185-capped-cold-")
                && (name.ends_with(".service") || name.ends_with(".timer"))))
}
fn empty_hook_selectors(name: &str) -> &'static [&'static str] {
    if name.len() <= 180
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        && name.starts_with("horizon-guard-185-capped-cold-")
        && name.ends_with(".service")
    {
        &["ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost"]
    } else {
        &["ExecStartPost", "ExecStop", "ExecStopPost"]
    }
}
pub(in crate::fleet) fn unit(name: &str) -> Result<Value> {
    ensure!(
        query_namespace(name),
        "epoch 185 foreign native query target"
    );
    let result = ProcessCommand::new("/usr/bin/systemctl")
        .args(["show", name, "--no-pager", FIELDS])
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env_remove("SYSTEMD_HOST")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 128 << 10,
        "epoch 185 native query failed"
    );
    let mut value = property_map(name, std::str::from_utf8(&result.stdout)?)?;
    if name.ends_with(".service") {
        let observed = value
            .as_object_mut()
            .context("epoch 185 native service map")?;
        let mut strings = observed
            .iter()
            .map(|(key, entry)| {
                Ok((
                    key.clone(),
                    entry
                        .as_str()
                        .context("epoch 185 native string property")?
                        .to_owned(),
                ))
            })
            .collect::<Result<BTreeMap<String, String>>>()?;
        super::native_empty_hooks::complete_missing(
            name,
            empty_hook_selectors(name),
            &mut strings,
        )?;
        for (key, entry) in strings {
            observed.entry(key).or_insert_with(|| json!(entry));
        }
    }
    Ok(value)
}
fn property_map(name: &str, raw: &str) -> Result<Value> {
    let mut value = serde_json::Map::new();
    let mut timers = Vec::new();
    for line in raw.lines() {
        let (key, entry) = line
            .split_once('=')
            .context("epoch 185 native property framing")?;
        if key == "TimersMonotonic"
            && name.starts_with("horizon-guard-185-capped-cold-")
            && name.ends_with(".timer")
        {
            timers.push(entry);
        } else {
            ensure!(
                value.insert(key.into(), json!(entry)).is_none(),
                "epoch 185 duplicate native property"
            );
        }
    }
    if name.starts_with("horizon-guard-185-capped-cold-") && name.ends_with(".timer") {
        ensure!(
            timers.len() == 2
                && timers
                    .iter()
                    .filter(|v| v.starts_with("{ OnActiveUSec=1s ; next_elapse="))
                    .count()
                    == 1
                && timers
                    .iter()
                    .filter(|v| v.starts_with("{ OnUnitInactiveUSec=30s ; next_elapse="))
                    .count()
                    == 1,
            "epoch 185 timer has duplicate, missing or foreign monotonic bases"
        );
        // Preserve both actual values in original order; only this exact timer
        // property has the qualified repeated-key transport.
        value.insert("TimersMonotonic".into(), json!(timers.join("\n")));
    }
    Ok(Value::Object(value))
}
fn command(raw: &str, args: &[String]) -> Result<()> {
    let (prefix, _) = raw
        .split_once(" ; ignore_errors=")
        .context("epoch 185 native command framing")?;
    ensure!(
        !args.is_empty() && prefix == format!("{{ path={} ; argv[]={}", args[0], args.join(" ")),
        "epoch 185 native command identity changed"
    );
    Ok(())
}
fn args(spec: &Spec, guard: bool, prestart: bool) -> Vec<String> {
    let mut values = vec![DRIVER.to_owned()];
    if guard {
        values.push("guard".into());
    }
    if prestart {
        values.push("prestart".into());
    }
    values.extend([
        spec.envelope.path.to_string_lossy().into_owned(),
        "--plan-sha256".into(),
        spec.envelope.sha256.clone(),
        "--self-sha256".into(),
        DRIVER_SHA.into(),
    ]);
    values
}
fn source(native: &Value, selected: &BoundFile) -> Result<()> {
    read_immutable(selected, MIB)?;
    ensure!(
        Path::new(text(native, "FragmentPath")?).canonicalize()? == selected.path
            && text(native, "DropInPaths")?.is_empty(),
        "epoch 185 native source changed"
    );
    Ok(())
}
fn no_extra_hooks(native: &Value, has_prestart: bool) -> Result<()> {
    for key in ["ExecStartPost", "ExecStop", "ExecStopPost"] {
        ensure!(
            text(native, key)?.is_empty(),
            "epoch 185 unbound lifecycle hook"
        );
    }
    if !has_prestart {
        ensure!(
            text(native, "ExecStartPre")?.is_empty(),
            "epoch 185 extra pre-start hook"
        );
    }
    Ok(())
}
fn stage(native: &Value, expected_iid: &str) -> Result<(&'static str, u64)> {
    ensure!(
        native["InvocationID"] == expected_iid
            && native["LoadState"] == "loaded"
            && native["NRestarts"] == "0"
            && native["Restart"] == "no",
        "epoch 185 owner invocation or restart changed"
    );
    let main = text(native, "MainPID")?.parse::<u64>()?;
    let control = text(native, "ControlPID")?.parse::<u64>()?;
    match (
        text(native, "ActiveState")?,
        text(native, "SubState")?,
        main,
        control,
    ) {
        ("activating", "start-pre", 0, pid) if pid > 1 => Ok(("start-pre", pid)),
        ("active", "running", pid, 0) if pid > 1 => Ok(("running", pid)),
        ("inactive", "dead", 0, 0) | ("failed", "failed", 0, 0) | ("active", "exited", 0, 0)
            if text(native, "Job")?.is_empty() =>
        {
            Ok(("terminal", 0))
        }
        _ => anyhow::bail!("epoch 185 native owner is not exact start-pre, running or terminal"),
    }
}
fn actor_policy(spec: &Spec, envelope: &Value, native: &Value) -> Result<(&'static str, u64)> {
    let actual_stage = stage(native, &spec.expected_actor_invocation_id)?;
    ensure!(
        native["Id"] == spec.actor_unit
            && native["Type"] == "exec"
            && native["User"] == "sol"
            && native["Group"] == "horizon"
            && native["MemoryAccounting"] == "yes"
            && native["MemorySwapMax"] == "0"
            && text(native, "MemoryMax")?.parse::<u64>()? == number(&envelope["limits"], "memory")?
            && native["NoNewPrivileges"] == "yes"
            && text(native, "CapabilityBoundingSet")?.is_empty()
            && text(native, "AmbientCapabilities")?.is_empty()
            && native["KillMode"] == "control-group"
            && native["ProtectSystem"] == "strict"
            && native["ProtectHome"] == "read-only"
            && native["PrivateNetwork"] == "no"
            && native["TasksMax"] == "1024"
            && native["CPUQuotaPerSecUSec"] == "4s"
            && text(native, "LimitFSIZE")?.parse::<u64>()?
                == number(&envelope["limits"], "output")?
            && (native["ControlGroup"] == format!("/system.slice/{}", spec.actor_unit)
                || (actual_stage.0 == "terminal" && text(native, "ControlGroup")?.is_empty())),
        "epoch 185 actor native profile changed"
    );
    no_extra_hooks(native, true)?;
    command(text(native, "ExecStart")?, &args(spec, false, false))?;
    command(text(native, "ExecStartPre")?, &args(spec, false, true))?;
    source(native, &spec.actor_source)?;
    let environment = text(native, "Environment")?;
    ensure!(
        environment
            .split_whitespace()
            .any(|s| s.trim_matches('"') == "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1")
            && !environment
                .split_whitespace()
                .any(|s| s.starts_with("LD_") || s.starts_with("GLIBC_TUNABLES=")),
        "epoch 185 Candidate opt-in missing or loader override"
    );
    Ok(actual_stage)
}
fn guard_policy(
    spec: &Spec,
    envelope: &Value,
    native: &Value,
    terminal: bool,
    pending: bool,
) -> Result<()> {
    ensure!(
        native["Id"] == envelope["guard_unit"]
            && native["LoadState"] == "loaded"
            && native["Type"] == "oneshot"
            && native["User"] == "root"
            && native["Group"] == "root"
            && native["Restart"] == "no"
            && native["NRestarts"] == "0"
            && native["MemoryAccounting"] == "yes"
            && native["MemorySwapMax"] == "0"
            && text(native, "MemoryMax")?.parse::<u64>()? == GUARD_MEMORY
            && native["CPUQuotaPerSecUSec"] == "1s"
            && native["TasksMax"] == "256"
            && native["NoNewPrivileges"] == "yes"
            && native["KillMode"] == "control-group"
            && native["ProtectSystem"] == "strict"
            && native["ProtectHome"] == "read-only"
            && native["PrivateNetwork"] == "yes",
        "epoch 185 guard native profile changed"
    );
    no_extra_hooks(native, false)?;
    source(native, &spec.guard_source)?;
    command(text(native, "ExecStart")?, &args(spec, true, false))?;
    let capabilities = |key| -> Result<std::collections::BTreeSet<&str>> {
        Ok(text(native, key)?.split_whitespace().collect())
    };
    let expected = ["cap_dac_override", "cap_sys_ptrace"].into_iter().collect();
    ensure!(
        capabilities("CapabilityBoundingSet")? == expected
            && capabilities("AmbientCapabilities")? == expected,
        "epoch 185 guard capabilities changed"
    );
    if !terminal && !pending {
        ensure!(
            text(native, "InvocationID").is_ok_and(|s| is_lower_hex(s, 32))
                && native["Result"] == "success"
                && native["ExecMainStatus"] == "0"
                && native["MainPID"] == "0"
                && native["ControlPID"] == "0"
                && native["Job"] == ""
                && native["ActiveState"] == "inactive"
                && native["SubState"] == "dead"
                && text(native, "TriggeredBy")?
                    .split_whitespace()
                    .any(|s| s == envelope["timer_unit"]),
            "epoch 185 guard is not a completed genuine timer scope"
        );
    }
    Ok(())
}
fn timer_policy(
    spec: &Spec,
    envelope: &Value,
    native: &Value,
    terminal: bool,
    pending: bool,
) -> Result<()> {
    ensure!(
        native["Id"] == envelope["timer_unit"]
            && native["LoadState"] == "loaded"
            && native["Unit"] == envelope["guard_unit"],
        "epoch 185 timer scope changed"
    );
    source(native, &spec.timer_source)?;
    if !terminal && !pending {
        ensure!(
            native["ActiveState"] == "active"
                && native["SubState"] == "waiting"
                && native["Job"] == ""
                && is_lower_hex(text(native, "InvocationID")?, 32),
            "epoch 185 guard timer not armed"
        );
    }
    let lines = text(native, "TimersMonotonic")?.lines().collect::<Vec<_>>();
    ensure!(
        lines.len() == 2
            && lines
                .iter()
                .any(|s| s.starts_with("{ OnActiveUSec=1s ; next_elapse="))
            && lines
                .iter()
                .any(|s| s.starts_with("{ OnUnitInactiveUSec=30s ; next_elapse=")),
        "epoch 185 exact guard cadence changed"
    );
    Ok(())
}
fn pending_guard(
    envelope: &Value,
    actor_stage: &str,
    guard: &Value,
    timer: &Value,
    iid: &str,
) -> Result<bool> {
    if actor_stage != "start-pre"
        || guard["ActiveState"] != "inactive"
        || timer["ActiveState"] != "inactive"
    {
        return Ok(false);
    }
    ensure!(
        guard["SubState"] == "dead"
            && guard["MainPID"] == "0"
            && guard["ControlPID"] == "0"
            && text(guard, "InvocationID")?.is_empty()
            && timer["SubState"] == "dead"
            && text(timer, "InvocationID")?.is_empty(),
        "epoch 185 pending guard is not a pristine inactive promise"
    );
    let token = Path::new(text(envelope, "token_root")?)
        .join(iid)
        .join("token.json");
    ensure!(
        fs::symlink_metadata(&token).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "epoch 185 pending guard cannot coexist with any release token"
    );
    Ok(true)
}
fn ticks(pid: u64) -> Result<u64> {
    let value = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(value
        .rsplit_once(')')
        .context("epoch 185 process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("epoch 185 process start ticks")?
        .parse()?)
}
fn mapped(spec: &Spec, pid: u64, prestart: bool) -> Result<Value> {
    let image = BoundFile {
        path: PathBuf::from(DRIVER),
        sha256: DRIVER_SHA.into(),
    };
    read_immutable(&image, 8 << 20)?;
    let mapped = fs::File::open(format!("/proc/{pid}/exe"))?.metadata()?;
    let source = fs::metadata(DRIVER)?;
    ensure!(
        (mapped.dev(), mapped.ino()) == (source.dev(), source.ino()),
        "epoch 185 mapped driver changed"
    );
    let command = fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(
        !command.is_empty() && command.len() <= MIB as usize && command.last() == Some(&0),
        "epoch 185 process argument framing"
    );
    let actual = command[..command.len() - 1]
        .split(|c| *c == 0)
        .map(|s| Ok(std::str::from_utf8(s)?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        actual == args(spec, false, prestart),
        "epoch 185 mapped driver arguments changed"
    );
    let group = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    ensure!(
        group.trim() == format!("0::/system.slice/{}", spec.actor_unit),
        "epoch 185 process cgroup changed"
    );
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let uid = status
        .lines()
        .find_map(|s| s.strip_prefix("Uid:"))
        .context("epoch 185 process UID")?;
    ensure!(
        uid.split_whitespace().all(|s| s == "1001"),
        "epoch 185 driver effective UID changed"
    );
    Ok(
        json!({"path":DRIVER,"sha256":DRIVER_SHA,"pid":pid,"start_ticks":ticks(pid)?,
        "device":mapped.dev(),"inode":mapped.ino(),"actual_argv":actual,"cgroup":group.trim()}),
    )
}

/// Re-read a historical original readiness file through its exact worker-custody
/// contract. Live/terminal actor validation remains independently owned by enrollment.
pub(in crate::fleet) fn reread_original_ready(
    task: &BoundFile,
    expected: &BoundFile,
) -> Result<Value> {
    let original = read_json(task, 4 << 20)?;
    ensure!(
        original["schema"] == crate::fleet::cold185::TASK_SCHEMA
            && original["no_replay_or_publication_or_credit"] == true,
        "typed ready re-read requires the authenticated original task"
    );
    original_task(&original)?;
    let source: BoundFile = serde_json::from_value(original["spec"].clone())?;
    let declaration = read_json(&source, 4 << 20)?;
    ensure!(
        declaration["schema"] == "horizon-epoch185-native-startpre-task-capture-v1"
            && declaration["native_spec"] == original["native_spec"],
        "typed ready task declaration crossed"
    );
    let spec: Spec = serde_json::from_value(declaration["native_spec"].clone())?;
    ensure!(
        &spec.ready == expected && original["ready_binding"] == json!(expected),
        "typed ready source differs from original declared binding"
    );
    let envelope = read_json(&spec.envelope, 4 << 20)?;
    ready(&spec, &envelope)
}
#[cfg(test)]
mod typed_ready_original_control {
    use super::*;
    #[test]
    #[ignore = "Root genuine saved185 task/worker-custody control"]
    fn actual_original185_ready_source_uses_worker_custody_and_rejects_crossed_binding() {
        let task: BoundFile = serde_json::from_str(
            &std::env::var("JETSTREAMER_ACTUAL185_TYPED_READY_TASK_BINDING").unwrap(),
        )
        .unwrap();
        let original = read_json(&task, 4 << 20).unwrap();
        let ready: BoundFile = serde_json::from_value(original["ready_binding"].clone()).unwrap();
        let value = reread_original_ready(&task, &ready).unwrap();
        assert_eq!(
            value["actor_invocation_id"],
            original["actor_invocation_id"]
        );
        let crossed = BoundFile {
            path: ready.path.clone(),
            sha256: "f".repeat(64),
        };
        assert!(reread_original_ready(&task, &crossed).is_err());
        let foreign = BoundFile {
            path: Path::new("/tmp/foreign-ready.json").to_path_buf(),
            sha256: ready.sha256,
        };
        assert!(reread_original_ready(&task, &foreign).is_err());
    }
}
fn ready(spec: &Spec, envelope: &Value) -> Result<Value> {
    let expected = Path::new(text(envelope, "control_root")?)
        .join(format!("ready-{}.json", spec.expected_actor_invocation_id));
    ensure!(
        spec.ready.path == expected && expected.canonicalize()? == expected,
        "epoch 185 original readiness path changed"
    );
    let parent = fs::symlink_metadata(expected.parent().context("epoch 185 ready parent")?)?;
    ensure!(
        parent.is_dir() && parent.uid() == 1001 && parent.mode() & 0o7777 == 0o700,
        "epoch 185 readiness directory custody changed"
    );
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&expected)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 1001
            && before.nlink() == 1
            && before.mode() & 0o7777 == 0o600
            && before.len() <= MIB,
        "epoch 185 readiness file custody changed"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MIB + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(&expected)?)
            && bytes.len() as u64 == before.len()
            && digest(&bytes) == spec.ready.sha256,
        "epoch 185 original readiness drift"
    );
    let v: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        v["schema"] == "horizon-epoch185-worker-ready-v4"
            && v["epoch"] == 185
            && v["actor_unit"] == spec.actor_unit
            && v["actor_invocation_id"] == spec.expected_actor_invocation_id
            && v["admission_sha256"] == spec.admission.sha256
            && v["driver_sha256"] == DRIVER_SHA
            && v["metadata_and_prerequisites_validated"] == true,
        "epoch 185 original ready semantic binding"
    );
    Ok(v)
}
fn package() -> Result<Value> {
    let receipt = BoundFile {
        path: Path::new(PACKAGE).join("deployment-seal-receipt.json"),
        sha256: PACKAGE_SEAL_SHA.into(),
    };
    let seal = read_json(&receipt, 4 * MIB)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == PACKAGE,
        "epoch 185 exact package normal seal changed"
    );
    let members = seal["members"]
        .as_array()
        .context("epoch 185 package members")?;
    ensure!(
        members.len() == 8,
        "epoch 185 package member census changed"
    );
    for (name, bytes, sha) in [
        (
            "jetstreamer-node",
            48138328,
            "e987401354f0cddbd838b71439768d6ed84baddfe8c0c2b484addec553db1887",
        ),
        (
            "jetstreamer-historical-worker-v1-6-15",
            8962632,
            "6eef40863851927d0611fd90dd7c68528c8e1491a0fc18a28de492afa67316bd",
        ),
        (
            "snapshot-79919283-Hozk66F2tKQuhouHceuwU9xZzWaXksnBeU1JBysRBmmf.tar.zst",
            7250303600,
            "218173053f960ab1917adaae99b1680fdd75968d95f22aae6ffd41aef37f9ef2",
        ),
        (
            "genesis.tar.bz2",
            20144,
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        ),
        (
            "preflight-185-singleton-v4.json",
            11721,
            "01f3be9f86ccf2a39284b0faf11b7910532c2348e2a0801ef1e50a77548d3dc3",
        ),
        (
            "epoch-hashes-185.txt",
            142,
            "9ef0d882bf9b530abcd77f8aae199a0c2057c06b32a1d738c7443e3e431606fa",
        ),
    ] {
        let row = members
            .iter()
            .filter(|r| r["name"] == name)
            .collect::<Vec<_>>();
        ensure!(
            row.len() == 1 && row[0]["sha256"] == sha && row[0]["bytes"] == bytes,
            "epoch 185 package proof changed"
        );
        let path = Path::new(PACKAGE).join(name);
        ancestors(&path)?;
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7222 == 0
                && m.len() == bytes,
            "epoch 185 immutable package identity changed"
        );
    }
    Ok(json!(receipt))
}
fn limits(envelope: &Value) -> Result<(u64, u64)> {
    let l = &envelope["limits"];
    let memory = number(l, "memory")?;
    ensure!(
        memory > 0
            && memory <= 195084404736
            && number(l, "scratch")? > 0
            && number(l, "scratch")? <= 384 << 30
            && number(l, "output")? > 0
            && number(l, "output")? <= 128 << 30
            && (MIB..=64 * MIB).contains(&number(l, "metadata")?)
            && number(l, "log")? > 0
            && number(l, "log")? <= 64 * MIB
            && number(l, "vmas")? > 0
            && number(l, "vmas")? <= 4194304,
        "epoch 185 experimental limits widened"
    );
    let data = ["scratch", "output", "metadata", "log"]
        .iter()
        .try_fold(0u64, |sum, key| {
            sum.checked_add(number(l, key)?)
                .context("epoch 185 DATA promise overflow")
        })?;
    Ok((memory, data))
}
fn admission(spec: &Spec, envelope: &Value, now: u64, released: bool) -> Result<(Value, Value)> {
    let a = read_json(&spec.admission, 4 * MIB)?;
    ensure!(
        a["schema"] == "horizon-epoch185-root-accepted-native-admission-v1"
            && a["epoch"] == 185
            && a["unit"] == spec.actor_unit
            && a["phase"] == "verification"
            && !text(&a, "task_owner")?.is_empty()
            && a["full_reader_accepted"] == true
            && a["raw_obligations_preserved"] == true
            && a["prefix_only"] == true
            && a["ordinary_full_replay_authorized"] == false
            && a["publication_authorized"] == false
            && a["resource_credit_bytes"] == 0
            && a["minimum_free_bytes"] == envelope["plan"]["minimum_free_bytes"]
            && a["memory_max_bytes"] == envelope["limits"]["memory"],
        "epoch 185 Root admission scope changed"
    );
    let issued = number(&a, "issued_at")?;
    let expires = number(&a, "expires_at")?;
    ensure!(
        issued <= now
            && expires > issued
            && expires - issued <= 259800
            && (released || now < expires),
        "epoch 185 original admission expired"
    );
    let mut sources = json!({});
    for key in [
        "current_full_reader",
        "current_frame",
        "typed_memory",
        "typed_data",
        "fleet_owner",
        "status_readback",
        "root_acceptance",
    ] {
        let b = binding(&a[key])?;
        read_json(&b, 4 * MIB)?;
        sources[key] = json!(b);
    }
    Ok((a, sources))
}
fn current_task(spec: &Spec, now: u64, released: bool) -> Result<Value> {
    let task = read_json(&spec.current_task_status, 4 * MIB)?;
    ensure!(
        task["schema"] == "horizon-status-only-correction-v1"
            && task["epoch"] == 185
            && task["authenticated_readback"] == true
            && task["owner_evidence"]["current_operator"] == "/root"
            && task["after_status"]["epoch"] == 185
            && task["after_status"]["phase"] == "verification"
            && task["after_status"]["estimated_remaining_millis"]
                .as_u64()
                .is_some_and(|n| n > 0),
        "epoch 185 current task lacks authenticated Root numeric status"
    );
    let at = utc_seconds(text(&task["after_status"], "sampled_at_utc")?)?;
    ensure!(
        at <= now && (released || now - at <= 1800),
        "epoch 185 current task status stale"
    );
    Ok(json!(spec.current_task_status))
}
fn terminal_drained(actor: &str) -> Result<()> {
    let root = Path::new("/sys/fs/cgroup/system.slice").join(actor);
    if root.exists() {
        ensure!(
            fs::read_to_string(root.join("cgroup.procs"))?
                .trim()
                .is_empty()
                && fs::read_to_string(root.join("cgroup.events"))?
                    .lines()
                    .any(|s| s == "populated 0"),
            "epoch 185 terminal owner still has descendants"
        );
    }
    Ok(())
}
pub(in crate::fleet) fn original_task(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == TASK_SCHEMA
            && v["stage"] == "start-pre"
            && v["native_before"] == v["native_after"]
            && v["capacity_credit_bytes"] == 0,
        "epoch 185 original task is not a stable genuine start-pre proof"
    );
    let at = number(v, "recorded_unix_seconds")?;
    let started = number(&v["ready"], "started_at")?;
    ensure!(
        started <= at
            && at < number(v, "original_setup_deadline_unix_seconds")?
            && v["actor_invocation_id"] == v["ready"]["actor_invocation_id"]
            && v["mapped_driver"]["pid"] == v["ready"]["pid"]
            && v["mapped_driver"]["start_ticks"] == v["ready"]["start_ticks"],
        "epoch 185 original task readiness or clock differs"
    );
    Ok(())
}
pub(in crate::fleet) fn capture(value: &Value, now: u64) -> Result<Value> {
    let spec: Spec = serde_json::from_value(value.clone())?;
    ensure!(
        spec.schema == "horizon-epoch185-native-startpre-spec-v1"
            && query_namespace(&spec.actor_unit)
            && spec
                .actor_unit
                .starts_with("horizon-qualify-185-capped-cold-")
            && is_lower_hex(&spec.expected_actor_invocation_id, 32)
            && ["task-start-pre", "current-owner"].contains(&spec.mode.as_str()),
        "epoch 185 native spec scope"
    );
    let envelope = read_json(&spec.envelope, 4 * MIB)?;
    ensure!(
        envelope["schema"] == "horizon-epoch185-guarded-cold-envelope-v4"
            && envelope["plan"]["schema"] == "horizon-private-epoch185-capped-root-prefix-plan-v4"
            && envelope["plan"]["unit"] == spec.actor_unit
            && envelope["self_program"] == DRIVER
            && envelope["self_sha256"] == DRIVER_SHA
            && envelope["admission"] == json!(spec.admission)
            && envelope["actor_service_path"] == spec.actor_source.path.to_string_lossy().as_ref()
            && envelope["guard_service_path"] == spec.guard_source.path.to_string_lossy().as_ref()
            && envelope["timer_service"] == json!(spec.timer_source)
            && envelope["token_root"]
                == "/usr/local/lib/jetstreamer/horizon-epoch185-cold-gates-v4"
            && envelope["guard_receipt_root"] == "/var/lib/jetstreamer/epoch185-cold-guard-v4"
            && envelope["plan"]["node"]["path"] == format!("{PACKAGE}/jetstreamer-node")
            && envelope["plan"]["worker"]
                == format!("{PACKAGE}/jetstreamer-historical-worker-v1-6-15")
            && envelope["plan"]["target_slot"] == 80351283
            && envelope["plan"]["terminal_slot"] == 80351283,
        "epoch 185 exact native envelope binding changed"
    );
    let guard = text(&envelope, "guard_unit")?;
    let timer = text(&envelope, "timer_unit")?;
    ensure!(
        query_namespace(guard)
            && guard.starts_with("horizon-guard-185-capped-cold-")
            && timer == guard.replace(".service", ".timer"),
        "epoch 185 guard namespace changed"
    );
    let names = [spec.actor_unit.as_str(), guard, timer];
    let mut before = BTreeMap::new();
    for name in names {
        before.insert(name.to_owned(), unit(name)?);
    }
    let (owner_stage, pid) = actor_policy(&spec, &envelope, &before[&spec.actor_unit])?;
    ensure!(
        spec.mode != "task-start-pre" || owner_stage == "start-pre",
        "epoch 185 task capture requires start-pre"
    );
    let terminal = owner_stage == "terminal";
    let pending = pending_guard(
        &envelope,
        owner_stage,
        &before[guard],
        &before[timer],
        &spec.expected_actor_invocation_id,
    )?;
    guard_policy(&spec, &envelope, &before[guard], terminal, pending)?;
    timer_policy(&spec, &envelope, &before[timer], terminal, pending)?;
    let ready = ready(&spec, &envelope)?;
    let setup = number(&envelope, "setup_deadline_seconds")?;
    ensure!((30..=600).contains(&setup), "epoch 185 setup bound changed");
    let deadline = number(&ready, "started_at")?
        .checked_add(setup)
        .context("epoch 185 setup clock overflow")?;
    ensure!(
        number(&ready, "started_at")? <= now && (owner_stage != "start-pre" || now < deadline),
        "epoch 185 original pre-start deadline expired"
    );
    let mapped = if terminal {
        terminal_drained(&spec.actor_unit)?;
        Value::Null
    } else {
        mapped(&spec, pid, owner_stage == "start-pre")?
    };
    if owner_stage == "start-pre" {
        ensure!(
            mapped["pid"] == ready["pid"] && mapped["start_ticks"] == ready["start_ticks"],
            "epoch 185 mapped original ControlPID readiness changed"
        );
    }
    // Authenticate actual original release before permitting expired clocks as
    // retained history. This branch never creates or refreshes launch authority.
    let release = if owner_stage == "start-pre" {
        Value::Null
    } else {
        retained::release(&spec, &envelope, &ready, now)?
    };
    let released = !release.is_null();
    let (admission, admission_sources) = admission(&spec, &envelope, now, released)?;
    ensure!(
        admission["status_readback"] == json!(spec.current_task_status),
        "epoch 185 task status crossed the original Root admission"
    );
    let current_task = current_task(&spec, now, released)?;
    let guard_history = if owner_stage == "running" {
        retained::history(
            &spec,
            &envelope,
            &ready,
            &mapped,
            &before[guard],
            &before[timer],
            now,
        )?
    } else {
        Value::Null
    };
    let terminal_context = if terminal {
        retained::terminal_context(&spec, &envelope, &ready, &release, &before, now)?
    } else {
        Value::Null
    };
    let frame = read_json(&binding(&admission["current_frame"])?, 4 * MIB)?;
    let observer = frame["bindings"]["observer"].clone();
    binding(&observer)?;
    let (memory, data) = limits(&envelope)?;
    let package_seal = package()?;
    let mut after = BTreeMap::new();
    for name in names {
        after.insert(name.to_owned(), unit(name)?);
    }
    ensure!(
        before == after,
        "epoch 185 native capture raced owner or guard transition"
    );
    if !terminal {
        ensure!(
            ticks(pid)? == number(&mapped, "start_ticks")?,
            "epoch 185 process changed during capture"
        );
    }
    let mut sources = json!({"envelope":spec.envelope,"admission":spec.admission,
        "actor_source":spec.actor_source,"guard_source":spec.guard_source,"timer_source":spec.timer_source,
        "ready":spec.ready,"current_task":spec.current_task_status,"driver":{"path":DRIVER,"sha256":DRIVER_SHA},
        "package_seal":package_seal});
    for (key, item) in admission_sources
        .as_object()
        .context("epoch 185 admission sources")?
    {
        sources[key] = item.clone();
    }
    if released {
        for key in ["token", "seal"] {
            sources[format!("original_release_{key}")] = release[key].clone();
        }
    }
    Ok(
        json!({"schema":TASK_SCHEMA,"native_spec":value,"actor_unit":spec.actor_unit,
        "actor_invocation_id":spec.expected_actor_invocation_id,"guard_unit":guard,"timer_unit":timer,
        "envelope":spec.envelope,"envelope_value":envelope,"admission":spec.admission,"admission_value":admission,
        "actor_source":spec.actor_source,"guard_source":spec.guard_source,"timer_source":spec.timer_source,
        "current":admission_sources,"observer":observer,"current_task":current_task,"ready":ready,"ready_binding":spec.ready,
        "run_root":envelope["plan"]["run_root"],"limits":envelope["limits"],"minimum_free_bytes":admission["minimum_free_bytes"],
        "ready_sha256":spec.ready.sha256,"native_before":before,"native_after":after,"native":after,
        "stage":owner_stage,"guard_pending":pending,"actor_pid":pid,"actor_start_ticks":mapped["start_ticks"],"mapped_driver":mapped,
        "release":release,"guard_history":guard_history,"terminal_context":terminal_context,"recorded_unix_seconds":now,"current_capture_unix_seconds":now,
        "original_setup_deadline_unix_seconds":deadline,"setup_deadline_at":deadline,"memory_hard_bytes":memory,"candidate_DATA_bytes":data,
        "guard_memory_bytes":GUARD_MEMORY,"guard_floor_bytes":admission["minimum_free_bytes"],
        "source_bindings":sources,"capacity_credit_bytes":0,"no_replay_or_publication_or_credit":true}),
    )
}
/// Authenticate only the exact registered, genuinely in-flight protective
/// guard. The guard's memory remains charged by its existing actor peer.
pub(in crate::fleet) fn authenticate_guard_discovery(
    aggregate: &Value,
    name: &str,
    actual_native: &Value,
    clock: u64,
) -> Result<Option<Value>> {
    retained::discover(aggregate, name, actual_native, clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_names_and_nonservice_actor_are_not_recognized() {
        for name in [
            "horizon-qualify-186-capped-cold-a.service",
            "horizon-qualify-185-capped-cold-a.timer",
            "horizon-qualify-185-capped-cold-a.service/escape",
        ] {
            assert!(!query_namespace(name));
        }
        assert!(query_namespace("horizon-qualify-185-capped-cold-a.service"));
        assert!(query_namespace("horizon-guard-185-capped-cold-a.timer"));
    }
    #[test]
    fn native_stage_requires_exact_invocation_and_zero_restarts() {
        let mut v = json!({"InvocationID":"a".repeat(32),"LoadState":"loaded","NRestarts":"0","Restart":"no",
            "MainPID":"0","ControlPID":"123","ActiveState":"activating","SubState":"start-pre","Job":"123"});
        assert_eq!(stage(&v, &"a".repeat(32)).unwrap(), ("start-pre", 123));
        assert!(stage(&v, &"b".repeat(32)).is_err());
        v["NRestarts"] = json!("1");
        assert!(stage(&v, &"a".repeat(32)).is_err());
    }
    #[test]
    fn genuine_running_and_terminal_stages_do_not_alias_startpre() {
        let mut v = json!({"InvocationID":"a".repeat(32),"LoadState":"loaded","NRestarts":"0","Restart":"no",
            "MainPID":"123","ControlPID":"0","ActiveState":"active","SubState":"running","Job":""});
        assert_eq!(stage(&v, &"a".repeat(32)).unwrap(), ("running", 123));
        v["MainPID"] = json!("0");
        assert!(stage(&v, &"a".repeat(32)).is_err());
        v["ActiveState"] = json!("failed");
        v["SubState"] = json!("failed");
        assert_eq!(stage(&v, &"a".repeat(32)).unwrap(), ("terminal", 0));
    }
    #[test]
    fn native_command_compares_program_and_complete_argument_order() {
        let a = vec![
            "/sealed/driver".into(),
            "prestart".into(),
            "/sealed/plan".into(),
        ];
        assert!(command("{ path=/sealed/driver ; argv[]=/sealed/driver prestart /sealed/plan ; ignore_errors=no ; start_time=n/a ; }",&a).is_ok());
        assert!(command("{ path=/sealed/driver ; argv[]=/sealed/driver /sealed/plan prestart ; ignore_errors=no ; }",&a).is_err());
    }
    #[test]
    fn each_experimental_limit_and_data_sum_remains_bound() {
        let mut e = json!({"limits":{"memory":195084404736u64,"scratch":384u64<<30,"output":128u64<<30,"metadata":64*MIB,"log":64*MIB,"vmas":4194304}});
        let (memory, data) = limits(&e).unwrap();
        assert_eq!(memory, 195084404736);
        assert_eq!(data, (512u64 << 30) + 128 * MIB);
        for key in ["memory", "scratch", "output", "metadata", "log", "vmas"] {
            let old = e["limits"][key].as_u64().unwrap();
            e["limits"][key] = json!(old + 1);
            assert!(limits(&e).is_err(), "accepted {key}");
            e["limits"][key] = json!(old);
        }
    }
    #[test]
    fn original_task_preserves_real_ready_pid_ticks_and_deadline() {
        let mut v = json!({"schema":TASK_SCHEMA,"stage":"start-pre","native_before":{},"native_after":{},"capacity_credit_bytes":0,
            "actor_invocation_id":"a".repeat(32),"recorded_unix_seconds":1010,"original_setup_deadline_unix_seconds":1030,
            "ready":{"started_at":1000,"actor_invocation_id":"a".repeat(32),"pid":123,"start_ticks":456},
            "mapped_driver":{"pid":123,"start_ticks":456}});
        original_task(&v).unwrap();
        v["mapped_driver"]["start_ticks"] = json!(457);
        assert!(original_task(&v).is_err());
        v["mapped_driver"]["start_ticks"] = json!(456);
        v["recorded_unix_seconds"] = json!(1030);
        assert!(original_task(&v).is_err());
    }
    #[test]
    fn pending_guard_requires_real_empty_ids_and_absent_token() {
        let temp = tempfile::tempdir().unwrap();
        let iid = "a".repeat(32);
        let e = json!({"token_root":temp.path()});
        let guard = json!({"ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","InvocationID":""});
        // Timers have no service MainPID/ControlPID properties. Keep actual absence.
        let timer = json!({"ActiveState":"inactive","SubState":"dead","InvocationID":""});
        assert!(pending_guard(&e, "start-pre", &guard, &timer, &iid).unwrap());
        fs::create_dir(temp.path().join(&iid)).unwrap();
        fs::write(
            temp.path().join(&iid).join("token.json"),
            b"invalid negative fixture",
        )
        .unwrap();
        assert!(pending_guard(&e, "start-pre", &guard, &timer, &iid).is_err());
    }
    #[test]
    fn old_guard_invocation_is_not_a_pristine_pending_promise() {
        let guard = json!({"ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","InvocationID":"b".repeat(32)});
        let timer = json!({"ActiveState":"inactive","SubState":"dead","InvocationID":""});
        assert!(pending_guard(&json!({}), "start-pre", &guard, &timer, &"a".repeat(32)).is_err());
    }
    #[test]
    fn running_owner_cannot_borrow_pending_guard_authority() {
        assert!(
            !pending_guard(
                &json!({}),
                "running",
                &json!({}),
                &json!({}),
                &"a".repeat(32)
            )
            .unwrap()
        );
    }
    #[test]
    fn smaller_negative_scope_preserves_all_independent_limits() {
        let e = json!({"limits":{"memory":64*MIB,"scratch":MIB,"output":MIB,"metadata":MIB,"log":MIB,"vmas":10000}});
        assert_eq!(limits(&e).unwrap(), (64 * MIB, 4 * MIB));
    }
    #[test]
    fn exact_timer_repeated_property_keeps_both_original_bases() {
        let raw = "Id=horizon-guard-185-capped-cold-test.timer\nTimersMonotonic={ OnActiveUSec=1s ; next_elapse=1s }\nTimersMonotonic={ OnUnitInactiveUSec=30s ; next_elapse=30s }\n";
        let value = property_map("horizon-guard-185-capped-cold-test.timer", raw).unwrap();
        assert_eq!(
            value["TimersMonotonic"],
            "{ OnActiveUSec=1s ; next_elapse=1s }\n{ OnUnitInactiveUSec=30s ; next_elapse=30s }"
        );
        assert!(property_map("unrelated.service", raw).is_err());
    }
    #[test]
    fn timer_duplicate_or_foreign_base_and_other_duplicate_keys_reject() {
        let name = "horizon-guard-185-capped-cold-test.timer";
        for raw in [
            "TimersMonotonic={ OnActiveUSec=1s ; next_elapse=1s }\nTimersMonotonic={ OnActiveUSec=1s ; next_elapse=2s }\n",
            "TimersMonotonic={ OnActiveUSec=1s ; next_elapse=1s }\nTimersMonotonic={ OnBootUSec=30s ; next_elapse=30s }\n",
        ] {
            assert!(property_map(name, raw).is_err());
        }
        assert!(
            property_map(
                "horizon-qualify-185-capped-cold-test.service",
                "Id=a\nId=b\n"
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "Root read-only metadata QA for the installed epoch 185 v11 family; never activates units"]
    fn actual_installed_v11_service_hooks_and_timer_metadata() -> Result<()> {
        ensure!(unsafe { libc::geteuid() } == 0, "Root metadata QA required");
        let actor = "horizon-qualify-185-capped-cold-missing-token-20261105-v11.service";
        let guard = "horizon-guard-185-capped-cold-missing-token-20261105-v11.service";
        let timer = "horizon-guard-185-capped-cold-missing-token-20261105-v11.timer";
        for name in [actor, guard, timer] {
            let value = unit(name)?;
            ensure!(
                value["Id"] == name && value["LoadState"] == "loaded",
                "installed native identity changed"
            );
            ensure!(
                value["FragmentPath"] == format!("/etc/systemd/system/{name}")
                    && value["DropInPaths"] == "",
                "installed native source metadata changed"
            );
            if name.ends_with(".service") {
                for hook in ["ExecStartPost", "ExecStop", "ExecStopPost"] {
                    ensure!(
                        value[hook] == "",
                        "installed service hook is not attested empty"
                    );
                }
                ensure!(
                    value["ExecStart"].as_str().is_some_and(|v| !v.is_empty()),
                    "installed service lost its actual command"
                );
                // The original actor failed before readiness. Its real terminal
                // state and invocation must remain observable, never reset here.
                if name == guard {
                    ensure!(
                        value["ExecStartPre"] == "",
                        "guard prestart hook is not attested empty"
                    );
                    ensure!(
                        value["ActiveState"] == "inactive"
                            && value["SubState"] == "dead"
                            && value["InvocationID"] == "",
                        "unstarted guard metadata changed"
                    );
                } else {
                    ensure!(
                        value["ExecStartPre"]
                            .as_str()
                            .is_some_and(|v| !v.is_empty()),
                        "actor lost its actual nonempty prestart command"
                    );
                }
            } else {
                ensure!(
                    value["ActiveState"] == "inactive"
                        && value["SubState"] == "dead"
                        && value["InvocationID"] == "",
                    "unstarted timer metadata changed"
                );
                let rows = value["TimersMonotonic"]
                    .as_str()
                    .context("actual timer rows")?
                    .lines()
                    .collect::<Vec<_>>();
                ensure!(
                    rows.len() == 2
                        && rows
                            .iter()
                            .filter(|v| v.starts_with("{ OnActiveUSec=1s ; next_elapse="))
                            .count()
                            == 1
                        && rows
                            .iter()
                            .filter(|v| v.starts_with("{ OnUnitInactiveUSec=30s ; next_elapse="))
                            .count()
                            == 1,
                    "actual timer lost its exact two bases"
                );
                for service_only in [
                    "MainPID",
                    "ControlPID",
                    "ExecStartPost",
                    "ExecStop",
                    "ExecStopPost",
                ] {
                    ensure!(
                        value.get(service_only).is_none(),
                        "timer contains fabricated service metadata"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn only_exact_guard_service_selects_empty_prestart_attestation() {
        assert!(
            empty_hook_selectors("horizon-guard-185-capped-cold-test.service")
                .contains(&"ExecStartPre")
        );
        for name in [
            "horizon-qualify-185-capped-cold-test.service",
            "horizon-guard-185-capped-cold-test.timer",
            "horizon-guard-186-capped-cold-test.service",
            "horizon-guard-185-capped-cold-test.service/escape",
        ] {
            assert!(!empty_hook_selectors(name).contains(&"ExecStartPre"));
        }
    }
}
