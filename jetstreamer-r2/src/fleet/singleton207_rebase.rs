//! Closed, metadata-only migration of the existing 207 guard selector. Original
//! launch evidence is immutable. A separate old-floor bridge covers reconfiguration.
use super::*;
use std::os::unix::fs::MetadataExt;
const OLD_FLOOR: u64 = 2_034_359_738_368;
const OLD_PLAN_SHA: &str = "6b46b5ca40e1c1fde1aadf12b09c172e73a681c16c4646db54156e638b042c1c";
const LAUNCH_SHA: &str = "7712ae90f84c1e4870579893e9e184b28d1b644ea0099ab5c23110bc03165ec0";
const BUFFER: u64 = singleton227_admission::SHARED_GUARD_BUFFER;
const METADATA: u64 = 1 << 30;
const BRIDGE: &str = "horizon-singleton207-bridge-v1.service";
const BRIDGE_DIR: &str = "/var/lib/jetstreamer/horizon-singleton207-bridge-receipts-v1";
const PLAN_PREFIX: &str = "horizon-singleton207-rebase-";
const PREP: &str = "jetstreamer-singleton207-guard-rebase-preparation-v1";
const CAPTURE: &str = "jetstreamer-singleton207-guard-rebase-capture-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    schema: String,
    resource_basis: Value,
    original_launch: BoundFile,
    original_plan: BoundFile,
    plan_directory: PathBuf,
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    schema: String,
    preparation: BoundFile,
    previous: Option<BoundFile>,
    protected_guards: BTreeMap<String, BoundFile>,
    output: PathBuf,
}
fn read(b: &BoundFile) -> Result<Value> {
    native209::immutable_json(b)
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("207 rebase integer absent:{k}"))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("207 rebase string absent:{k}"))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn write(path: &Path, v: &Value) -> Result<()> {
    validate_output_destination(path)?;
    private157::immutable_receipt(path, v)
}
fn unit(name: &str) -> Result<Value> {
    Ok(json!(props(
        name,
        "Id,LoadState,InvocationID,MainPID,NRestarts,ActiveState,SubState,Result,ExecMainStatus,ControlGroup,ExecStart"
    )?))
}
fn props(name: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    singleton227_capture::properties(name, fields)
}
fn timer(name: &str, armed: bool) -> Result<Value> {
    let p = props(
        &name.replace(".service", ".timer"),
        "Id,InvocationID,ActiveState,SubState,Triggers,TimersMonotonic,DropInPaths,NeedDaemonReload",
    )?;
    timer_shape(&p, name, armed)?;
    Ok(json!(p))
}
fn timer_shape(p: &BTreeMap<String, String>, service: &str, armed: bool) -> Result<()> {
    ensure!(
        p.get("Id") == Some(&service.replace(".service", ".timer"))
            && p.get("DropInPaths").is_some_and(String::is_empty)
            && p.get("NeedDaemonReload").map(String::as_str) == Some("no"),
        "207 rebase timer namespace/config differs"
    );
    if armed {
        ensure!(
            p.get("ActiveState").map(String::as_str) == Some("active")
                && p.get("SubState").map(String::as_str) == Some("waiting")
                && p.get("Triggers").map(String::as_str) == Some(service)
                && p.get("InvocationID").is_some_and(|s| is_lower_hex(s, 32))
                && p.get("TimersMonotonic")
                    .is_some_and(|s| s.contains("OnUnitInactiveUSec=1min")
                        && !s.contains("OnActiveUSec")
                        && !s.contains("OnBootUSec")
                        && !s.contains("OnStartupUSec")
                        && !s.contains("OnUnitActiveUSec")),
            "207 rebase timer is not armed at the exact 60-second cadence"
        );
    } else {
        ensure!(
            p.get("ActiveState").map(String::as_str) == Some("inactive")
                && p.get("SubState").map(String::as_str) == Some("dead"),
            "207 bridge timer still armed"
        );
    }
    Ok(())
}
fn timer_journal(service: &str) -> Result<Vec<Value>> {
    let name = service.replace(".service", ".timer");
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "_PID=1",
            &format!("UNIT={name}"),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 4 << 20,
        "207 timer history unavailable/oversized"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !rows.is_empty() && rows.len() <= 16384,
        "207 timer history empty/oversized"
    );
    let mut last = 0;
    for row in &rows {
        let t = text(row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            row["_PID"] == "1" && row["_UID"] == "0" && row["UNIT"] == name && t >= last,
            "207 timer history identity/order differs"
        );
        last = t;
    }
    Ok(rows)
}
fn bridge_retired(before: &[Value], after: &[Value], since: u64) -> Result<()> {
    ensure!(
        after.starts_with(before) && after.len() > before.len(),
        "207 bridge retirement lost original timer history"
    );
    let name = BRIDGE.replace(".service", ".timer");
    ensure!(
        !before.is_empty() && after.len() <= 16384,
        "207 bridge timer history empty/oversized"
    );
    let mut last = 0u64;
    for row in after {
        let at = text(row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            row["_PID"] == "1" && row["_UID"] == "0" && row["UNIT"] == name && at >= last,
            "207 bridge retirement manager scope/order differs"
        );
        last = at;
    }
    let mut stopped = false;
    for row in &after[before.len()..] {
        let at = text(row, "__REALTIME_TIMESTAMP")?.parse::<u64>()? / 1_000_000;
        ensure!(
            at >= since
                && !text(row, "MESSAGE")?.starts_with("Started ")
                && !text(row, "MESSAGE")?.starts_with("Starting "),
            "207 bridge stopped/replaced before new coverage"
        );
        stopped |= row["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286"
            && row["JOB_TYPE"] == "stop"
            && row["JOB_RESULT"] == "done";
        stopped |= text(row, "MESSAGE")?.starts_with(&format!("Stopped {name}"));
    }
    ensure!(stopped, "207 bridge has no genuine terminal timer event");
    Ok(())
}
fn same_unit(left: &Value, right: &Value) -> bool {
    let (Some(a), Some(b)) = (left.as_object(), right.as_object()) else {
        return false;
    };
    a.len() == b.len()
        && a.iter().all(|(key, value)| {
            if key == "ExecStart" {
                value
                    .as_str()
                    .zip(b.get(key).and_then(Value::as_str))
                    .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b))
            } else {
                b.get(key) == Some(value)
            }
        })
}
fn same_census(left: &Value, right: &Value) -> bool {
    let (Some(a), Some(b)) = (left.as_object(), right.as_object()) else {
        return false;
    };
    a.len() == b.len()
        && a.iter()
            .all(|(name, u)| b.get(name).is_some_and(|v| same_unit(u, v)))
}
fn same_timer(left: &Value, right: &Value) -> bool {
    [
        "Id",
        "InvocationID",
        "ActiveState",
        "SubState",
        "Triggers",
        "DropInPaths",
        "NeedDaemonReload",
    ]
    .iter()
    .all(|k| left.get(*k).is_some() && left[*k] == right[*k])
}
fn owner(f: &Value, current: &BTreeMap<String, Value>) -> Result<DiagnosticClaim> {
    let plan: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: text(f, "plan")?.into(),
        sha256: text(f, "plan_sha256")?.into(),
    })?)?;
    let mut matching = plan
        .diagnostics
        .into_iter()
        .filter(|d| d.unit == singleton207::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "207 rebase lacks exact original diagnostic claim"
    );
    let d = matching.pop().unwrap();
    ensure!(
        d.launch_receipt.sha256 == LAUNCH_SHA,
        "207 rebase changed original launch"
    );
    checked_diagnostic_launch(&d)?;
    let u = current
        .get(singleton207::UNIT)
        .context("207 producer absent")?;
    singleton207::validate_live(&d, u)?;
    ensure!(
        same_unit(&f["unit_census"][singleton207::UNIT], u),
        "207 producer PID/IID/cgroup changed"
    );
    Ok(d)
}
fn release205(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    ensure!(
        !f["active"]
            .as_array()
            .context("207 rebase active roster missing")?
            .iter()
            .any(|r| r["epoch"] == 205),
        "workerless 205 assembly/downstream work is still live"
    );
    let rows = f["capped204205_work"]
        .as_array()
        .context("205 positive release row missing")?
        .iter()
        .filter(|r| r["epoch"] == 205)
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1
            && rows[0]["positive_inactivity_confirmed"] == true
            && rows[0]["live"] == false
            && rows[0]["ownership_unresolved"] != true,
        "205 lacks authenticated positive resource release"
    );
    let l = read(&serde_json::from_value(rows[0]["launch"].clone())?)?;
    let owners = [(text(&l, "unit")?.into(), text(&l, "invocation_id")?.into())];
    ensure!(
        capped204205_work::cleanup_current(f, 205, current, &owners)?,
        "205 release proof is not qualified"
    );
    Ok(())
}
fn plan_shape(p: &Value, original: &Value, floor: u64, bridge: bool) -> Result<()> {
    let mut expected = original.clone();
    expected["minimum_free_bytes"] = json!(if bridge { OLD_FLOOR } else { floor });
    if bridge {
        expected["receipt_directory"] = json!(BRIDGE_DIR);
    }
    ensure!(
        *p == expected
            && original["minimum_free_bytes"] == OLD_FLOOR
            && original["unit"] == singleton207::UNIT
            && original["worker_root"].as_str() == Some(singleton207::ROOT)
            && original["maximum_worker_vmas"] == 3500000
            && original["maximum_root_physical_bytes"] == 437_438_953_472u64,
        "207 rebase plan altered producer/root/VMA/guard scope"
    );
    Ok(())
}
fn budget(floor: u64, total_growth: u64, other_guard_floor: u64) -> Result<u64> {
    let other = total_growth
        .checked_sub(singleton207::DISK_RESERVATION)
        .context("207 full protected growth omitted")?;
    ensure!(
        other >= BUFFER,
        "207 protected growth lacks its inherited shared buffer"
    );
    // Common protected growth already contains its shared buffer once. Keep
    // that component when removing only 207's complete owner reservation.
    let stop = floor
        .checked_add(other)
        .and_then(|n| n.checked_add(METADATA))
        .context("207 rebase floor overflow")?
        .max(other_guard_floor);
    ensure!(
        stop < OLD_FLOOR && floor > 0,
        "207 rebase has no independently supported lower threshold"
    );
    Ok(stop)
}
fn guard_plan(prep: &Value, bridge: bool) -> Result<(BoundFile, Value)> {
    let b: BoundFile = serde_json::from_value(
        prep[if bridge {
            "bridge_plan"
        } else {
            "approved_plan"
        }]
        .clone(),
    )?;
    let p = read(&b)?;
    plan_shape(
        &p,
        &read(&serde_json::from_value(prep["original_plan"].clone())?)?,
        n(prep, "approved_floor_bytes")?,
        bridge,
    )?;
    Ok((b, p))
}
fn guard(service: &str, b: &BoundFile, p: &Value, current: &Value, minimum: u64) -> Result<Value> {
    let time = now()?;
    let selected = warmup223::completed_guard_binding(
        service,
        Path::new(text(p, "receipt_directory")?),
        minimum,
        time,
    )?;
    let sample = bound_json(&serde_json::from_value(selected["binding"].clone())?)?;
    guard_shape(&sample, p, b, current, time)?;
    let properties = props(
        service,
        "Id,Type,User,Restart,NRestarts,MemoryMax,TasksMax,CPUQuotaPerSecUSec,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,ExecStart,DropInPaths,NeedDaemonReload,ExecStartPre,ExecStartPost,ExecReload,ExecStop,ExecStopPost,OnSuccess,OnFailure,Environment,EnvironmentFiles,PassEnvironment,KillMode,Delegate,MemorySwapMax",
    )?;
    singleton227_capture::require(
        &properties,
        &[
            ("Id", service),
            ("Type", "oneshot"),
            ("User", "root"),
            ("Restart", "no"),
            ("NRestarts", "0"),
            ("MemoryMax", "1073741824"),
            ("TasksMax", "256"),
            ("CPUQuotaPerSecUSec", "1s"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("DropInPaths", ""),
            ("NeedDaemonReload", "no"),
        ],
    )?;
    for key in [
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
        "OnSuccess",
        "OnFailure",
        "Environment",
        "EnvironmentFiles",
        "PassEnvironment",
    ] {
        ensure!(
            properties.get(key).is_some_and(String::is_empty),
            "207 guard has an unqualified extra hook or environment source:{key}"
        );
    }
    ensure!(
        properties.get("KillMode").map(String::as_str) == Some("control-group")
            && properties.get("Delegate").map(String::as_str) == Some("no"),
        "207 guard cgroup ownership changed"
    );
    if service == BRIDGE || b.sha256 != OLD_PLAN_SHA {
        ensure!(
            properties.get("MemorySwapMax").map(String::as_str) == Some("0"),
            "207 replacement guard swap must be disabled"
        );
    }
    ensure!(
        properties["ReadWritePaths"] == text(p, "receipt_directory")?
            && private_prefix::same_command(
                &json!(properties["ExecStart"]),
                &selected["history"]["expected_exec_start"]
            )
            && selected["history"]["executable"].as_str() == Some(singleton207::GUARD),
        "207 guard effective executable/plan differs"
    );
    Ok(
        json!({"selected":selected,"sample":sample,"properties":properties,"timer":timer(service,true)?}),
    )
}
fn guard_shape(g: &Value, p: &Value, b: &BoundFile, u: &Value, time: u64) -> Result<()> {
    let t = n(g, "recorded_unix_seconds")?;
    ensure!(
        t <= time
            && time - t <= 90
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == singleton207::GUARD_SHA
            && g["plan_sha256"] == b.sha256
            && g["plan"].as_str() == b.path.to_str()
            && g["producer_invocation_id"] == u["InvocationID"]
            && g["producer"]["invocation_id"] == u["InvocationID"]
            && g["producer"]["pid"].as_u64().map(|v| v.to_string())
                == u["MainPID"].as_str().map(str::to_owned)
            && g["guard_invocation_id"]
                .as_str()
                .is_some_and(|v| is_lower_hex(v, 32))
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["result"] == "success"
            && g["producer"]["cgroup"] == format!("/system.slice/{}", singleton207::UNIT)
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer_stop_enabled"] == true
            && g["bounded_measurement"] == false
            && ["native_main", "bounded_canary", "target_handoff"]
                .iter()
                .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && n(g, "available_bytes")? >= n(p, "minimum_free_bytes")?
            && g["maximum_root_physical_bytes"] == 437_438_953_472u64
            && g["maximum_worker_vmas"] == 3500000
            && g["root_physical_observation"]["maximum_physical_bytes"] == 437_438_953_472u64
            && g["root_physical_observation"]["exceeds_budget"] == false
            && n(
                &g["root_physical_observation"],
                "conservative_physical_bytes"
            )? <= 437_438_953_472
            && g["workers"].as_array().is_some_and(|w| w.len() == 1
                && w[0][0].as_u64().is_some_and(|p| p > 1)
                && w[0][1].as_u64().is_some_and(|v| v > 0 && v < 3500000))
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error",
                "target_handoff_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "207 guard fresh native protection differs"
    );
    Ok(())
}
fn context(prep: &Value) -> Result<(Value, Value, BTreeMap<String, Value>)> {
    ensure!(
        prep["schema"] == PREP
            && n(prep, "recorded_unix_seconds")? <= now()?
            && now()? - n(prep, "recorded_unix_seconds")? <= 900,
        "207 preparation stale/future"
    );
    let f = assembly204_recovery::accepted_context(
        &serde_json::from_value(prep["resource_basis"]["fleet"].clone())?,
        &serde_json::from_value(prep["resource_basis"]["observer"].clone())?,
    )?;
    let o = bound_json(&serde_json::from_value(
        prep["resource_basis"]["observer"].clone(),
    )?)?;
    let t = utc_seconds(text(&o, "recorded_at_utc")?)?;
    ensure!(
        t <= now()? && now()? - t <= 1800,
        "207 rebase needs the genuine fresh scheduled observer"
    );
    let names = f["unit_census"]
        .as_object()
        .context("207 full census missing")?
        .keys()
        .cloned()
        .collect();
    let current = census(&names, 201, 300)?;
    maintenance_capacity::current_owners(&f, &current)?;
    owner(&f, &current)?;
    release205(&f, &current)?;
    ensure!(
        same_census(
            &serde_json::to_value(&current)?,
            &prep["capacity"]["unit_census_after_memory_and_guard_checks"]
        ),
        "207 rebase current peer roster or invocation changed"
    );
    Ok((f, o, current))
}
fn refresh(prep: &Value, guards: &BTreeMap<String, BoundFile>) -> Result<BTreeMap<String, Value>> {
    let (f, o, current) = context(prep)?;
    let mut view = f.clone();
    view["active"]
        .as_array_mut()
        .context("207 active roster absent")?
        .retain(|r| r["epoch"] != 207);
    let mut other = guards.clone();
    ensure!(
        other.remove(singleton207::UNIT).is_some(),
        "207 current guard key omitted"
    );
    let filtered =
        maintenance_capacity::legacy_observer(&o, &BTreeSet::from([singleton207::UNIT.into()]))?;
    let t = utc_seconds(text(&o, "recorded_at_utc")?)?;
    capped204205_admission::guards(&view, &other, &current, t, now()?)?;
    let (disk, _, memory, _) =
        capped204205_admission::combined_resources(&view, &filtered, &other, &current, t, now()?)?;
    let (other_floor, _) = native228_admission::protected_floor(0, disk, &other)?;
    let expected = budget(
        n(prep, "century_floor_bytes")?,
        disk.checked_add(singleton207::DISK_RESERVATION)
            .context("207 growth overflow")?,
        other_floor,
    )?;
    ensure!(
        expected <= n(prep, "approved_floor_bytes")?,
        "207 protected peer growth increased beyond approved floor"
    );
    let required = n(prep, "century_floor_bytes")?
        .checked_add(disk)
        .and_then(|n| n.checked_add(singleton207::DISK_RESERVATION))
        .context("207 refresh disk overflow")?
        .max(OLD_FLOOR)
        .checked_add(METADATA)
        .context("207 metadata disk overflow")?;
    ensure!(
        singleton227_admission::disk_free()? >= required,
        "207 rebase would consume current peer disk obligations"
    );
    let floor = n(
        &prep["capacity"]["memory_after"]["guard_rebase207_memory_policy"],
        "effective_available_memory_floor_bytes",
    )?;
    let required_memory = floor
        .checked_add(memory)
        .and_then(|n| n.checked_add(singleton207::MEMORY))
        .and_then(|n| n.checked_add(3u64 << 30))
        .context("207 refresh memory overflow")?;
    ensure!(
        native209_admission::actual_memory()? >= required_memory,
        "207 bridge/producer/peer native memory obligations no longer fit"
    );
    Ok(current)
}
fn issuer() -> Result<()> {
    let group = fs::read_to_string("/proc/self/cgroup")?;
    let relative = group
        .strip_prefix("0::")
        .context("207 issuer cgroup shape")?
        .trim();
    ensure!(
        relative.starts_with("/system.slice/"),
        "207 metadata issuer must have its own bounded systemd unit"
    );
    let path = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    let max = fs::read_to_string(path.join("memory.max"))?
        .trim()
        .parse::<u64>()?;
    ensure!(
        max > 0
            && max <= 1u64 << 30
            && fs::read_to_string(path.join("memory.swap.max"))?.trim() == "0",
        "207 issuer native memory/swap exceeds admitted allowance"
    );
    Ok(())
}
fn plan_directory(path: &Path) -> Result<()> {
    let leaf = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("207 plan directory name invalid")?;
    let suffix = leaf
        .strip_prefix(PLAN_PREFIX)
        .context("207 plan directory namespace differs")?;
    ensure!(
        path.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && !suffix.is_empty()
            && suffix.len() <= 96
            && suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "207 plan directory has an unsafe suffix"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "207 plan directory must be canonical root-private metadata"
    );
    Ok(())
}
fn prepare(binding: &BoundFile, self_sha: &str) -> Result<()> {
    let s: Prepare = serde_json::from_value(read(binding)?)?;
    ensure!(
        s.schema == "jetstreamer-singleton207-guard-rebase-spec-v1"
            && s.original_launch.sha256 == LAUNCH_SHA
            && s.original_plan.sha256 == OLD_PLAN_SHA,
        "207 rebase changed original admitted scope"
    );
    plan_directory(&s.plan_directory)?;
    ensure!(
        s.output == s.plan_directory.join("preparation.json")
            && fs::read_dir(&s.plan_directory)?.next().is_none(),
        "207 preparation needs a new empty metadata generation; preserve prior failed attempts"
    );
    let fb: BoundFile = serde_json::from_value(s.resource_basis["fleet"].clone())?;
    let ob: BoundFile = serde_json::from_value(s.resource_basis["observer"].clone())?;
    let f = assembly204_recovery::accepted_context(&fb, &ob)?;
    let names = f["unit_census"]
        .as_object()
        .context("207 accepted census missing")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 201, 300)?;
    let d = owner(&f, &before)?;
    ensure!(
        d.launch_receipt == s.original_launch,
        "207 source launch binding differs"
    );
    release205(&f, &before)?;
    let capacity = maintenance_capacity::check_guard_rebase207(&s.resource_basis)?;
    let floor = singleton227_admission::century_floor_for_maintenance(&f)?;
    let mut guards: BTreeMap<String, BoundFile> =
        serde_json::from_value(s.resource_basis["protected_guards"].clone())?;
    ensure!(
        guards.remove(singleton207::UNIT).is_some(),
        "207 old guard omitted"
    );
    let (_, other_floor) = native228_admission::protected_floor(0, 0, &guards)?;
    growth_census(&f, &capacity)?;
    let stop = budget(
        floor,
        n(&capacity, "protected_remaining_growth_bytes")?,
        other_floor,
    )?;
    ensure!(
        read(&s.original_launch)?["guard_plan"] == private157::binding(&s.original_plan),
        "207 original launch/guard plan binding differs"
    );
    let original = read(&s.original_plan)?;
    let mut approved = original.clone();
    approved["minimum_free_bytes"] = json!(stop);
    let mut bridge = original.clone();
    bridge["receipt_directory"] = json!(BRIDGE_DIR);
    plan_shape(&approved, &original, stop, false)?;
    plan_shape(&bridge, &original, stop, true)?;
    let current = census(&names, 201, 300)?;
    ensure!(before == current, "207 peer changed during preparation");
    let approved_path = s.plan_directory.join("guard-plan.json");
    let bridge_path = s.plan_directory.join("bridge-plan.json");
    write(&approved_path, &approved)?;
    write(&bridge_path, &bridge)?;
    let approved_binding: BoundFile =
        serde_json::from_value(private157::file_binding(&approved_path)?)?;
    let bridge_binding: BoundFile =
        serde_json::from_value(private157::file_binding(&bridge_path)?)?;
    let record = json!({"schema":PREP,"issuer_sha256":self_sha,"spec":binding,"resource_basis":s.resource_basis,"original_launch":s.original_launch,"original_plan":s.original_plan,"plan_directory":s.plan_directory,"approved_plan":approved_binding,"bridge_plan":bridge_binding,"century_floor_bytes":floor,"approved_floor_bytes":stop,"buffer_bytes":BUFFER,"transition_metadata_allowance_bytes":METADATA,"capacity":capacity,"producer":current[singleton207::UNIT],"recorded_unix_seconds":now()?,"replay_launch_authorized":false,"capacity_credit_authorized":false,"producer_mutations":false,"r2_mutations":false});
    write(&s.output, &record)
}
fn growth_census(f: &Value, capacity: &Value) -> Result<()> {
    let expected = f["active"]
        .as_array()
        .context("207 active census absent")?
        .iter()
        .map(|r| Ok(text(singleton227_admission::active_owner(r)?, "Id")?.to_owned()))
        .collect::<Result<BTreeSet<_>>>()?;
    let mut totals = Vec::new();
    for key in ["protected_growth_before", "protected_growth_after"] {
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for row in capacity[key]
            .as_array()
            .context("207 complete growth evidence absent")?
        {
            let name = text(row, "unit")?.to_owned();
            ensure!(
                expected.contains(&name) && seen.insert(name.clone()),
                "207 growth peer missing/foreign/duplicated"
            );
            let value = match (
                row["remaining_growth_bytes"].as_u64(),
                row["remaining_disk_growth_bytes"].as_u64(),
            ) {
                (Some(v), None) | (None, Some(v)) => v,
                _ => bail!("207 disk growth evidence absent/ambiguous"),
            };
            if name == singleton207::UNIT {
                ensure!(
                    value == singleton207::DISK_RESERVATION
                        && row["scratch_growth_credit_bytes"] == 0,
                    "207 full own-root reservation changed or credited"
                );
            }
            total = total
                .checked_add(value)
                .context("207 growth evidence overflow")?;
        }
        ensure!(seen == expected, "207 protected peer omitted");
        totals.push(total);
    }
    ensure!(
        singleton227_admission::with_shared_guard_buffer(
            totals
                .into_iter()
                .max()
                .context("207 growth brackets missing")?
        )? == n(capacity, "protected_remaining_growth_bytes")?,
        "207 protected growth sum understated"
    );
    Ok(())
}
fn saved_protection(
    v: &Value,
    binding: &BoundFile,
    plan: &Value,
    producer: &Value,
    time: u64,
    service: &str,
) -> Result<()> {
    guard_shape(&v["sample"], plan, binding, producer, time)?;
    let sample = bound_json(&serde_json::from_value(v["selected"]["binding"].clone())?)?;
    ensure!(
        sample == v["sample"] && v["selected"]["history"]["unit"] == service,
        "207 saved sample/history binding changed"
    );
    warmup223::validate_completed_guard_history(&v["selected"]["history"], &sample)?;
    let timer: BTreeMap<String, String> = serde_json::from_value(v["timer"].clone())?;
    timer_shape(&timer, service, true)?;
    Ok(())
}
fn validate_preparation(p: &Value) -> Result<()> {
    ensure!(
        p["schema"] == PREP
            && p["original_launch"]["sha256"] == LAUNCH_SHA
            && p["original_plan"]["sha256"] == OLD_PLAN_SHA
            && p["buffer_bytes"] == BUFFER
            && p["transition_metadata_allowance_bytes"] == METADATA
            && p["capacity"]["all_live_growth_and_century_floor_protected"] == true
            && p["capacity"]["additional_bytes"] == METADATA,
        "207 preparation authority or resource envelope differs"
    );
    let source: Prepare =
        serde_json::from_value(read(&serde_json::from_value(p["spec"].clone())?)?)?;
    plan_directory(&source.plan_directory)?;
    ensure!(
        source.schema == "jetstreamer-singleton207-guard-rebase-spec-v1"
            && source.output == source.plan_directory.join("preparation.json")
            && p["resource_basis"] == source.resource_basis
            && p["original_launch"] == private157::binding(&source.original_launch)
            && p["original_plan"] == private157::binding(&source.original_plan)
            && p["plan_directory"] == serde_json::to_value(&source.plan_directory)?
            && p["approved_plan"]["path"].as_str()
                == source.plan_directory.join("guard-plan.json").to_str()
            && p["bridge_plan"]["path"].as_str()
                == source.plan_directory.join("bridge-plan.json").to_str(),
        "207 preparation inputs/plans do not match its actual issuer spec"
    );
    let f = assembly204_recovery::accepted_context(
        &serde_json::from_value(p["resource_basis"]["fleet"].clone())?,
        &serde_json::from_value(p["resource_basis"]["observer"].clone())?,
    )?;
    growth_census(&f, &p["capacity"])?;
    ensure!(
        p["capacity"]["fleet"] == p["resource_basis"]["fleet"]
            && p["capacity"]["observer"] == p["resource_basis"]["observer"],
        "207 capacity source binding changed"
    );
    let floor = singleton227_admission::century_floor_for_maintenance(&f)?;
    let mut guards: BTreeMap<String, BoundFile> =
        serde_json::from_value(p["resource_basis"]["protected_guards"].clone())?;
    ensure!(
        guards.remove(singleton207::UNIT).is_some(),
        "207 preparation omitted own guard"
    );
    let (_, other_floor) = native228_admission::protected_floor(0, 0, &guards)?;
    ensure!(
        p["century_floor_bytes"] == floor
            && p["approved_floor_bytes"]
                == budget(
                    floor,
                    n(&p["capacity"], "protected_remaining_growth_bytes")?,
                    other_floor
                )?,
        "207 prepared floor cannot be independently rederived"
    );
    guard_plan(p, false)?;
    guard_plan(p, true)?;
    Ok(())
}
fn stage_census(v: &Value, p: &Value) -> Result<()> {
    ensure!(
        same_census(
            &v["unit_census_before"],
            &p["capacity"]["unit_census_after_memory_and_guard_checks"]
        ) && same_census(&v["unit_census_before"], &v["unit_census_after"])
            && same_unit(&v["producer"], &v["unit_census_before"][singleton207::UNIT]),
        "207 staged proof lost the complete unchanged peer census"
    );
    Ok(())
}
fn prior(c: &Capture, phase: &str, p: &Value, self_sha: &str) -> Result<Value> {
    let b = c.previous.as_ref().context("207 staged proof missing")?;
    let v = read(b)?;
    stage_census(&v, p)?;
    ensure!(
        v["schema"] == CAPTURE
            && v["phase"] == phase
            && v["preparation"] == private157::binding(&c.preparation)
            && v["issuer_sha256"] == self_sha
            && same_unit(&v["producer"], &p["producer"])
            && n(&v, "recorded_unix_seconds")? >= n(p, "recorded_unix_seconds")?,
        "207 staged proof belongs to another transaction or owner"
    );
    Ok(v)
}
fn capture(command: &str, binding: &BoundFile, self_sha: &str) -> Result<()> {
    let c: Capture = serde_json::from_value(read(binding)?)?;
    ensure!(
        c.schema == "jetstreamer-singleton207-guard-rebase-capture-spec-v1",
        "207 capture schema differs"
    );
    let p = read(&c.preparation)?;
    validate_preparation(&p)?;
    ensure!(
        p["issuer_sha256"] == self_sha,
        "207 rebase helper generation changed"
    );
    let current = refresh(&p, &c.protected_guards)?;
    let producer = &current[singleton207::UNIT];
    let start = n(&p, "recorded_unix_seconds")?;
    let (bridge_binding, bridge_plan) = guard_plan(&p, true)?;
    let (new_binding, new_plan) = guard_plan(&p, false)?;
    let phase = match command {
        "capture-singleton207-rebase-bridge" => "bridge",
        "capture-singleton207-rebase-switch" => "switch",
        "capture-singleton207-guard-rebase" => "complete",
        _ => bail!("unknown 207 rebase capture command"),
    };
    let mut proof = json!({"schema":CAPTURE,"phase":phase,"issuer_sha256":self_sha,"capture_spec":binding,"preparation":private157::binding(&c.preparation),"producer":producer,"recorded_unix_seconds":now()?,"capacity_credit_authorized":false,"producer_mutations":false,"replay_launch_authorized":false,"r2_mutations":false});
    if phase == "bridge" {
        ensure!(
            c.previous.is_none(),
            "207 initial bridge cannot borrow a prior stage"
        );
        let old_binding: BoundFile = serde_json::from_value(p["original_plan"].clone())?;
        let old_plan = read(&old_binding)?;
        proof["original_protection"] = guard(
            singleton207::PROTECTIVE,
            &old_binding,
            &old_plan,
            producer,
            start,
        )?;
        proof["bridge_protection"] = guard(BRIDGE, &bridge_binding, &bridge_plan, producer, start)?;
        proof["bridge_timer_journal"] = json!(timer_journal(BRIDGE)?);
    } else if phase == "switch" {
        let before = prior(&c, "bridge", &p, self_sha)?;
        proof["previous"] = json!(c.previous);
        let bridge = guard(BRIDGE, &bridge_binding, &bridge_plan, producer, start)?;
        ensure!(
            same_timer(&bridge["timer"], &before["bridge_protection"]["timer"])
                && json!(timer_journal(BRIDGE)?) == before["bridge_timer_journal"],
            "207 bridge was interrupted during original selector reconfiguration"
        );
        proof["bridge_protection"] = bridge;
        proof["bridge_timer_journal"] = before["bridge_timer_journal"].clone();
        proof["new_protection"] = guard(
            singleton207::PROTECTIVE,
            &new_binding,
            &new_plan,
            producer,
            n(&before, "recorded_unix_seconds")?,
        )?;
    } else {
        let before = prior(&c, "switch", &p, self_sha)?;
        proof["previous"] = json!(c.previous);
        proof["new_protection"] = guard(
            singleton207::PROTECTIVE,
            &new_binding,
            &new_plan,
            producer,
            n(&before, "recorded_unix_seconds")?,
        )?;
        proof["retired_bridge_timer"] = timer(BRIDGE, false)?;
        let old: Vec<Value> = serde_json::from_value(before["bridge_timer_journal"].clone())?;
        let after = timer_journal(BRIDGE)?;
        bridge_retired(&old, &after, n(&before, "recorded_unix_seconds")?)?;
        let u = unit(BRIDGE)?;
        ensure!(
            u["MainPID"] == "0"
                && u["NRestarts"] == "0"
                && matches!(u["ActiveState"].as_str(), Some("inactive" | "failed"))
                && matches!(u["SubState"].as_str(), Some("dead" | "failed")),
            "207 bridge service still active/restarting"
        );
        inactive_status::no_pending_owner_trigger(BRIDGE, u["LoadState"] == "not-found")?;
        proof["retired_bridge_cgroup"] = capped204205_work::empty_terminal_cgroup(BRIDGE)?;
        proof["retired_bridge_no_pending_owner_trigger"] = json!(true);
        proof["retired_bridge_service"] = u;
        proof["bridge_retirement_journal"] = json!(after);
        proof["completed_no_gap_transition"] = json!(true);
    }
    let after = refresh(&p, &c.protected_guards)?;
    ensure!(
        same_census(&json!(after), &json!(current)),
        "207 peers changed across handoff capture"
    );
    proof["unit_census_before"] = json!(current);
    proof["unit_census_after"] = json!(after);
    proof["recorded_unix_seconds"] = json!(now()?);
    write(&c.output, &proof)
}
/// Return a separate typed effective guard binding. Never alter original launch.
pub(super) fn effective(f: &Value, original: &Value) -> Result<Option<(BoundFile, Value)>> {
    let plan: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: text(f, "plan")?.into(),
        sha256: text(f, "plan_sha256")?.into(),
    })?)?;
    let Some(binding) = plan.singleton207_guard_handoff else {
        return Ok(None);
    };
    let done = read(&binding)?;
    ensure!(
        done["schema"] == CAPTURE
            && done["phase"] == "complete"
            && done["completed_no_gap_transition"] == true,
        "207 guard rebase is not completed"
    );
    let prep = read(&serde_json::from_value(done["preparation"].clone())?)?;
    validate_preparation(&prep)?;
    stage_census(&done, &prep)?;
    ensure!(
        read(&serde_json::from_value(prep["original_launch"].clone())?)? == *original
            && same_unit(&done["producer"], &prep["producer"])
            && done["issuer_sha256"] == prep["issuer_sha256"],
        "207 handoff substituted original launch/owner/helper"
    );
    let switched = read(&serde_json::from_value(done["previous"].clone())?)?;
    let bridge = read(&serde_json::from_value(switched["previous"].clone())?)?;
    for (v, phase) in [(&switched, "switch"), (&bridge, "bridge")] {
        stage_census(v, &prep)?;
        ensure!(
            v["schema"] == CAPTURE
                && v["phase"] == phase
                && v["preparation"] == done["preparation"]
                && v["issuer_sha256"] == done["issuer_sha256"]
                && same_unit(&v["producer"], &done["producer"]),
            "207 handoff staged proof foreign"
        );
    }
    let start = n(&prep, "recorded_unix_seconds")?;
    let a = n(&bridge, "recorded_unix_seconds")?;
    let b = n(&switched, "recorded_unix_seconds")?;
    let c = n(&done, "recorded_unix_seconds")?;
    ensure!(
        start <= a
            && a <= b
            && b <= c
            && c - start <= 900
            && bridge["bridge_timer_journal"] == switched["bridge_timer_journal"]
            && same_timer(
                &bridge["bridge_protection"]["timer"],
                &switched["bridge_protection"]["timer"]
            ),
        "207 no-gap stage sequence or bridge changed"
    );
    let before: Vec<Value> = serde_json::from_value(switched["bridge_timer_journal"].clone())?;
    let after: Vec<Value> = serde_json::from_value(done["bridge_retirement_journal"].clone())?;
    bridge_retired(&before, &after, b)?;
    let (bridge_binding, bridge_plan) = guard_plan(&prep, true)?;
    let original_binding: BoundFile = serde_json::from_value(prep["original_plan"].clone())?;
    saved_protection(
        &bridge["original_protection"],
        &original_binding,
        &read(&original_binding)?,
        &bridge["producer"],
        a,
        singleton207::PROTECTIVE,
    )?;
    saved_protection(
        &bridge["bridge_protection"],
        &bridge_binding,
        &bridge_plan,
        &bridge["producer"],
        a,
        BRIDGE,
    )?;
    saved_protection(
        &switched["bridge_protection"],
        &bridge_binding,
        &bridge_plan,
        &switched["producer"],
        b,
        BRIDGE,
    )?;
    let (approved, p) = guard_plan(&prep, false)?;
    saved_protection(
        &switched["new_protection"],
        &approved,
        &p,
        &switched["producer"],
        b,
        singleton207::PROTECTIVE,
    )?;
    saved_protection(
        &done["new_protection"],
        &approved,
        &p,
        &done["producer"],
        c,
        singleton207::PROTECTIVE,
    )?;
    let retired: BTreeMap<String, String> =
        serde_json::from_value(done["retired_bridge_timer"].clone())?;
    timer_shape(&retired, BRIDGE, false)?;
    ensure!(
        done["retired_bridge_service"]["MainPID"] == "0"
            && done["retired_bridge_service"]["NRestarts"] == "0"
            && done["retired_bridge_no_pending_owner_trigger"] == true
            && done["retired_bridge_cgroup"]["path"]
                == format!("/sys/fs/cgroup/system.slice/{BRIDGE}")
            && matches!(
                done["retired_bridge_cgroup"]["state"].as_str(),
                Some("absent" | "unpopulated")
            ),
        "207 saved bridge is not retired"
    );
    ensure!(
        done["new_protection"]["sample"]["plan_sha256"] == approved.sha256
            && done["new_protection"]["sample"]["plan"].as_str() == approved.path.to_str(),
        "207 completed handoff lost approved guard"
    );
    guard(
        singleton207::PROTECTIVE,
        &approved,
        &p,
        &f["unit_census"][singleton207::UNIT],
        utc_seconds(text(f, "sampled_at_utc")?)?,
    )?;
    Ok(Some((approved, p)))
}
pub(super) fn run(command: &str) -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args(command)?;
    issuer()?;
    if command == "prepare-singleton207-guard-rebase" {
        prepare(&binding, &self_sha)
    } else {
        capture(command, &binding, &self_sha)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn original() -> Value {
        json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":singleton207::UNIT,"invocation_id":"74eb420ca4574a50a35913d1417124f1","filesystem":"/","minimum_free_bytes":OLD_FLOOR,"worker_root":singleton207::ROOT,"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":437_438_953_472u64,"receipt_directory":singleton207::GUARD_RECEIPTS})
    }
    fn armed() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("Id".into(), BRIDGE.replace(".service", ".timer")),
            ("InvocationID".into(), "1".repeat(32)),
            ("ActiveState".into(), "active".into()),
            ("SubState".into(), "waiting".into()),
            ("Triggers".into(), BRIDGE.into()),
            (
                "TimersMonotonic".into(),
                "{ OnUnitInactiveUSec=1min ; next_elapse=100 }".into(),
            ),
            ("DropInPaths".into(), String::new()),
            ("NeedDaemonReload".into(), "no".into()),
        ])
    }
    #[test]
    fn rebase207_floor_keeps_every_peer_and_separate_transition_allowances() {
        let century = 245_383_154_903;
        let other = 640u64 << 30;
        let expected = century + other + BUFFER + METADATA;
        assert_eq!(
            budget(
                century,
                singleton227_admission::with_shared_guard_buffer(
                    singleton207::DISK_RESERVATION + other
                )
                .unwrap(),
                317_008_659_347
            )
            .unwrap(),
            expected
        );
        assert!(budget(century, singleton207::DISK_RESERVATION - 1, 0).is_err());
        assert!(budget(century, singleton207::DISK_RESERVATION + other, OLD_FLOOR).is_err());
        assert!(budget(u64::MAX, singleton207::DISK_RESERVATION + other, 0).is_err());
    }
    #[test]
    fn rebase207_growth_census_rejects_missing_duplicated_foreign_or_credited_peers() {
        let f = json!({"active":[{"epoch":207,"producer":{"Id":singleton207::UNIT}},{"epoch":225,"producer":{"Id":"peer225"}}]});
        let rows = json!([{"unit":singleton207::UNIT,"remaining_growth_bytes":singleton207::DISK_RESERVATION,"scratch_growth_credit_bytes":0},{"unit":"peer225","remaining_growth_bytes":640u64<<30}]);
        let good = json!({"protected_growth_before":rows,"protected_growth_after":rows,"protected_remaining_growth_bytes":singleton227_admission::with_shared_guard_buffer(singleton207::DISK_RESERVATION+(640u64<<30)).unwrap()});
        growth_census(&f, &good).unwrap();
        for key in ["protected_growth_before", "protected_growth_after"] {
            let mut bad = good.clone();
            bad[key].as_array_mut().unwrap().pop();
            assert!(growth_census(&f, &bad).is_err());
            let mut bad = good.clone();
            bad[key][1]["unit"] = json!(singleton207::UNIT);
            assert!(growth_census(&f, &bad).is_err());
            let mut bad = good.clone();
            bad[key][1]["unit"] = json!("foreign");
            assert!(growth_census(&f, &bad).is_err());
            let mut bad = good.clone();
            bad[key][0]["scratch_growth_credit_bytes"] = json!(1);
            assert!(growth_census(&f, &bad).is_err());
        }
    }
    #[test]
    fn rebase207_plan_preserves_root_vma_identity_and_original_receipt_namespace() {
        let old = original();
        let floor = 1_002_371_140_823u64;
        let mut new = old.clone();
        new["minimum_free_bytes"] = json!(floor);
        plan_shape(&new, &old, floor, false).unwrap();
        for (key, value) in [
            ("minimum_free_bytes", json!(floor - 1)),
            ("maximum_root_physical_bytes", json!(437_438_953_473u64)),
            ("maximum_worker_vmas", json!(3500001)),
            ("invocation_id", json!("2".repeat(32))),
            ("receipt_directory", json!("/other")),
        ] {
            let mut bad = new.clone();
            bad[key] = value;
            assert!(plan_shape(&bad, &old, floor, false).is_err(), "{key}");
        }
        let mut bridge = old.clone();
        bridge["receipt_directory"] = json!(BRIDGE_DIR);
        plan_shape(&bridge, &old, floor, true).unwrap();
        bridge["minimum_free_bytes"] = json!(floor);
        assert!(plan_shape(&bridge, &old, floor, true).is_err());
    }
    #[test]
    fn rebase207_timer_requires_live_exact_cadence_and_rejects_unarmed_transition() {
        let good = armed();
        timer_shape(&good, BRIDGE, true).unwrap();
        for (key, value) in [
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("InvocationID", ""),
            ("Triggers", "other.service"),
            ("TimersMonotonic", "{ OnUnitInactiveUSec=30min }"),
            ("DropInPaths", "/foreign.conf"),
        ] {
            let mut bad = good.clone();
            bad.insert(key.into(), value.into());
            assert!(timer_shape(&bad, BRIDGE, true).is_err(), "{key}");
        }
        let mut later = json!(good);
        later["TimersMonotonic"] = json!("{ OnUnitInactiveUSec=1min ; next_elapse=200 }");
        assert!(same_timer(&json!(good), &later));
        later["InvocationID"] = json!("2".repeat(32));
        assert!(!same_timer(&json!(good), &later));
    }
    #[test]
    fn rebase207_bridge_retirement_requires_new_coverage_and_same_pid1_history() {
        let name = BRIDGE.replace(".service", ".timer");
        let first = json!({"_PID":"1","_UID":"0","UNIT":name,"__REALTIME_TIMESTAMP":"100000000","MESSAGE":"Started bridge."});
        let stopped = json!({"_PID":"1","_UID":"0","UNIT":name,"__REALTIME_TIMESTAMP":"120000000","MESSAGE":format!("Stopped {name}"),"MESSAGE_ID":"9d1aaa27d60140bd96365438aad20286","JOB_TYPE":"stop","JOB_RESULT":"done"});
        let before = vec![first];
        let after = vec![before[0].clone(), stopped];
        bridge_retired(&before, &after, 110).unwrap();
        assert!(bridge_retired(&before, &after, 121).is_err());
        assert!(bridge_retired(&before, &before, 110).is_err());
        let mut bad = after.clone();
        bad[1]["_PID"] = json!("2");
        assert!(bridge_retired(&before, &bad, 110).is_err());
        let mut bad = after.clone();
        bad[1]["MESSAGE"] = json!("Started replacement timer.");
        assert!(bridge_retired(&before, &bad, 110).is_err());
        let mut bad = after.clone();
        bad[0]["MESSAGE"] = json!("foreign history");
        assert!(bridge_retired(&before, &bad, 110).is_err());
    }
    #[test]
    fn rebase207_guard_rejects_stale_foreign_tripped_or_changed_native_protection() {
        let g: Value =
            serde_json::from_str(include_str!("prefix223_live_peer/fixtures/guard207.json"))
                .unwrap();
        let old = original();
        let b = BoundFile {
            path: PathBuf::from(g["plan"].as_str().unwrap()),
            sha256: g["plan_sha256"].as_str().unwrap().into(),
        };
        let u = json!({"MainPID":g["producer"]["pid"].as_u64().unwrap().to_string(),"InvocationID":g["producer_invocation_id"]});
        let time = n(&g, "recorded_unix_seconds").unwrap();
        guard_shape(&g, &old, &b, &u, time + 1).unwrap();
        assert!(guard_shape(&g, &old, &b, &u, time + 91).is_err());
        for (pointer, value) in [
            ("/producer/restarts", json!(1)),
            ("/producer_invocation_id", json!("2".repeat(32))),
            ("/maximum_root_physical_bytes", json!(1)),
            ("/maximum_worker_vmas", json!(3500001)),
            ("/trip_reason", json!("disk")),
            ("/guard_sha256", json!("f".repeat(64))),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                guard_shape(&bad, &old, &b, &u, time + 1).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn rebase207_identity_allows_display_reload_only_and_never_changed_owner_or_command() {
        let a = json!({"Id":singleton207::UNIT,"InvocationID":"1".repeat(32),"MainPID":"42","NRestarts":"0","ExecStart":"{ path=/sealed/node ; argv[]=/sealed/node 207 ; ignore_errors=no ; start_time=[old] ; stop_time=[old] ; pid=42 ; code=(null) ; status=0/0 }"});
        let mut b = a.clone();
        b["ExecStart"] = json!(
            "{ path=/sealed/node ; argv[]=/sealed/node 207 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        );
        assert!(same_unit(&a, &b));
        for (key, value) in [
            ("MainPID", "43"),
            ("NRestarts", "1"),
            ("InvocationID", "different"),
            (
                "ExecStart",
                "{ path=/sealed/node ; argv[]=/sealed/node 208 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
            ),
        ] {
            let mut bad = b.clone();
            bad[key] = json!(value);
            assert!(!same_unit(&a, &bad), "{key}");
        }
    }
    #[test]
    fn rebase207_never_releases_workerless205_assembly_or_suffix_only_success() {
        let current = BTreeMap::new();
        let live =
            json!({"active":[{"epoch":205,"phase":"assembly","live":true}],"capped204205_work":[]});
        assert!(
            release205(&live, &current)
                .unwrap_err()
                .to_string()
                .contains("still live")
        );
        let suffix_only = json!({"active":[],"capped204205_work":[{"epoch":205,"positive_inactivity_confirmed":false,"live":false,"actual_suffix_native_barrier_passed":true}]});
        assert!(release205(&suffix_only, &current).is_err());
        let missing = json!({"active":[],"capped204205_work":[]});
        assert!(release205(&missing, &current).is_err());
    }
    #[test]
    fn rebase207_stage_proof_cannot_drop_or_change_an_unrelated_protected_peer() {
        let producer = json!({"Id":singleton207::UNIT,"InvocationID":"1".repeat(32),"MainPID":"42","NRestarts":"0"});
        let mut census = json!({"peer225":{"Id":"peer225","InvocationID":"2".repeat(32),"MainPID":"43","NRestarts":"0"}});
        census[singleton207::UNIT] = producer.clone();
        let p = json!({"capacity":{"unit_census_after_memory_and_guard_checks":census}});
        let good =
            json!({"producer":producer,"unit_census_before":census,"unit_census_after":census});
        stage_census(&good, &p).unwrap();
        let mut missing = good.clone();
        missing["unit_census_after"]
            .as_object_mut()
            .unwrap()
            .remove("peer225");
        assert!(stage_census(&missing, &p).is_err());
        let mut changed = good;
        changed["unit_census_after"]["peer225"]["InvocationID"] = json!("3".repeat(32));
        assert!(stage_census(&changed, &p).is_err());
    }
    #[test]
    fn rebase207_preparer_generates_plans_and_rejects_caller_floor_authority() {
        let bound = json!({"path":"/sealed/original.json","sha256":"a".repeat(64)});
        let good = json!({"schema":"jetstreamer-singleton207-guard-rebase-spec-v1","resource_basis":{},"original_launch":bound,"original_plan":bound,"plan_directory":"/var/lib/jetstreamer/horizon-singleton207-rebase-attempt1","output":"/var/lib/jetstreamer/horizon-singleton207-rebase-attempt1/preparation.json"});
        assert!(serde_json::from_value::<Prepare>(good.clone()).is_ok());
        for key in [
            "minimum_free_bytes",
            "approved_floor_bytes",
            "approved_plan",
            "skip205release",
        ] {
            let mut bad = good.clone();
            bad[key] = json!(1);
            assert!(serde_json::from_value::<Prepare>(bad).is_err(), "{key}");
        }
    }
    #[test]
    fn rebase207_common_accounting_retains_unowned_shared_buffer_exactly_once() {
        let own = singleton207::DISK_RESERVATION;
        let peer = 640u64 << 30;
        let before = json!([{"unit":singleton207::UNIT,"remaining_growth_bytes":own,"scratch_growth_credit_bytes":0},{"unit":"peer225","remaining_growth_bytes":peer}]);
        let mut after = before.clone();
        after[1]["remaining_growth_bytes"] = json!(peer + 123);
        let f = json!({"active":[{"epoch":207,"producer":{"Id":singleton207::UNIT}},{"epoch":225,"producer":{"Id":"peer225"}}]});
        // Invoke the exact helper used by singleton227 protected_growth. Its
        // shared 64 GiB is deliberately absent from the per-owner rows.
        let common = singleton227_admission::with_shared_guard_buffer(own + peer + 123).unwrap();
        let capacity = json!({"protected_growth_before":before,"protected_growth_after":after,"protected_remaining_growth_bytes":common});
        growth_census(&f, &capacity).unwrap();
        let century = 245_383_154_903;
        assert_eq!(
            budget(century, common, 317_008_659_347).unwrap(),
            century + peer + 123 + BUFFER + METADATA
        );
        for total in [own + peer + 123, common + BUFFER] {
            let mut bad = capacity.clone();
            bad["protected_remaining_growth_bytes"] = json!(total);
            assert!(growth_census(&f, &bad).is_err());
        }
        assert!(singleton227_admission::with_shared_guard_buffer(u64::MAX).is_err());
    }
}
