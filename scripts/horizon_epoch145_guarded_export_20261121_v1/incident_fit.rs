//! Reuse the registered fleet admission while a leased, read-only verifier runs.
//! A topology crossing stops the child until a new complete census succeeds.
use super::*;
use std::os::unix::{fs::OpenOptionsExt, process::ExitStatusExt};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
};
#[cfg(any(incident_focused145_only, incident_focused_post145_only))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v14/post-stop-fit";
#[cfg(all(incident_timeout_post145_only, not(incident_focused_post145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v11/post-stop-fit";
#[cfg(all(incident_post145_only, not(incident_timeout_post145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v7/post-stop-fit";
#[cfg(all(incident_timeout145_only, not(incident_focused145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v10/post-stop-fit";
#[cfg(all(incident_rejoin145_only, not(incident_timeout145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v6/post-stop-fit";
#[cfg(not(any(incident_post145_only, incident_rejoin145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v3/post-stop-fit";
const HOST_MEMORY: u64 = 810_658_050_048;
const GROUPS: &str = "/sys/fs/cgroup/system.slice";
type Process = (u32, u64, u64, u64);
type Population = BTreeMap<String, Vec<Process>>;

struct Capture {
    fleet: Bound,
    complete: Value,
    actors: Population,
    captured: Instant,
}

pub struct Fit {
    pub evidence: Value,
    capture: RefCell<Capture>,
}

fn original(path: &Path, limit: u64) -> Result<(Bound, Value)> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && before.is_file()
            && before.nlink() == 1
            && before.uid() == 0
            && before.gid() == 0
            && (before.mode() & 0o222 == 0 || before.mode() & 0o777 == 0o600)
            && before.len() > 0
            && before.len() <= limit,
        "untrusted original evidence {}",
        path.display()
    );
    let id = custody::identity(&before);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        custody::identity(&file.metadata()?) == id,
        "original descriptor changed"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == id.bytes
            && custody::identity(&file.metadata()?) == id
            && custody::identity(&fs::symlink_metadata(path)?) == id,
        "original receipt changed during read"
    );
    Ok((
        Bound {
            path: path.into(),
            sha256: custody::sha(&bytes),
        },
        serde_json::from_slice(&bytes)?,
    ))
}
fn head(start: &Bound) -> Result<Bound> {
    let mut b = start.clone();
    loop {
        ensure!(
            b.path
                .file_name()
                .is_some_and(|n| n == "ROOT_COMPLETE_OPERATIONAL_FLEET.json")
                && b.path.parent().and_then(Path::parent) == Some(Path::new(RUNTIME)),
            "foreign accepted fleet path"
        );
        let v: Value = serde_json::from_slice(&custody::bytes(&b, 32 << 20, false)?)?;
        ensure!(
            v["owner"] == "/root"
                && v["schema"] == "horizon-Root-complete-fleet-operational-review-v1",
            "invalid head of accepted fleet chain"
        );
        let timer = v["sole_next_timer"]
            .as_str()
            .or_else(|| v["sole_next_timer"]["unit"].as_str())
            .context("successor timer")?;
        let d = timer
            .strip_prefix("horizon-observer-")
            .and_then(|s| s.strip_suffix(".timer"))
            .context("observer timer")?;
        ensure!(
            d.starts_with("root")
                && d.len() < 128
                && d.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "unsafe timer name"
        );
        let p = Path::new(RUNTIME)
            .join(d)
            .join("ROOT_COMPLETE_OPERATIONAL_FLEET.json");
        if !p.try_exists()? {
            return Ok(b);
        }
        let (n, successor) = original(&p, 32 << 20)?;
        ensure!(
            capacity::n(&successor, "recorded_unix_seconds")?
                > capacity::n(&v, "recorded_unix_seconds")?,
            "fleet chain is not advancing"
        );
        b = n;
    }
}

fn active_population() -> Result<Population> {
    let mut population = BTreeMap::new();
    for entry in fs::read_dir(GROUPS)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("horizon-qualify") || !name.ends_with(".service") {
            continue;
        }
        let processes = entry.path().join("cgroup.procs");
        let ids = match fs::read_to_string(processes) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            other => other?,
        };
        let mut group = Vec::new();
        for line in ids.lines() {
            let p: u32 = line.parse()?;
            let t = native::ticks(p)?;
            let proc = Path::new("/proc").join(p.to_string());
            let e = fs::metadata(proc.join("exe"))?;
            ensure!(
                fs::read_to_string(proc.join("cgroup"))?.trim()
                    == format!("0::/system.slice/{name}")
                    && native::ticks(p)? == t,
                "unstable replay PID"
            );
            group.push((p, t, e.dev(), e.ino()));
        }
        if !group.is_empty() {
            group.sort();
            population.insert(name.to_owned(), group);
        }
    }
    Ok(population)
}

fn provider_identity() -> Result<Bound> {
    let path = Path::new(PROVIDER);
    let directory = path.parent().unwrap();
    let (r, seal) = original(&directory.join("deployment-seal-receipt.json"), 1 << 20)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(directory)
            && seal["sealer_sha256"]
                == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
            && seal["remote_mutations"] == false,
        "unknown provider deployment"
    );
    let member = seal["members"]
        .as_array()
        .context("provider members")?
        .iter()
        .find(|v| v["name"] == "post-stop-fit")
        .context("missing provider")?;
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o555
            && m.len() < 1 << 20
            && member["sha256"] == custody::sha(&fs::read(path)?),
        "changed provider"
    );
    Ok(r)
}

/// Recognize only the native held retry10 process while its guard is joining.
/// This result can defer a stopped verifier; only the full provider can resume it.
fn held_170() -> Result<Option<u64>> {
    let dir = Path::new(RUNTIME).join("epoch170-retry10-recovery-20261121-v1");
    let unit = "horizon-qualify-170-replacement-local3retry10-20261121-v1.service";
    if !dir.join("NATIVE_GATED.json").try_exists()?
        || dir
            .join("ACTUAL_ADMISSION_AND_PROTECTION.json")
            .try_exists()?
        || dir.join("START_FAILURE.json").try_exists()?
    {
        return Ok(None);
    }
    let (intent, v) = original(&dir.join("START_INTENT.json"), 8 << 20)?;
    let (gated, g) = original(&dir.join("NATIVE_GATED.json"), 2 << 20)?;
    ensure!(
        intent.sha256 == "762ecae29698c42a727b8ff0310a50f7219aa301420b473f4522cba27aa9fee7"
            && gated.sha256 == "8a9a80e813441ae0058f4cfda392e2e430cb9461ddb3c319dd62a194c2e3a8c4"
            && v["producer_unit"] == unit
            && v["epoch"] == 170
            && v["resource_credit_bytes"] == 0
            && g["producer_unit"] == unit
            && g["producer_invocation_id"] == "a456b826ce1c4634a2df66d66c5cc07f",
        "foreign pending 170 source"
    );
    let session: Bound = serde_json::from_value(v["actual_session"].clone())?;
    let controller: Bound = serde_json::from_value(v["controller"].clone())?;
    let package = custody::evidence(&controller)?;
    custody::evidence(&session)?;
    let (profile, pr) = original(&dir.join("profile.json"), 2 << 20)?;
    let gate = dir.join("controller/gate.py");
    ensure!(
        profile.sha256 == "1596f281f699b48f4e4c7e65adf1070e4961d604d38997a7747ffe60dc536782"
            && package["destination"] == json!(dir.join("controller"))
            && custody::sha(&fs::read(&gate)?)
                == "8e5f7c0d3a3118d2deaa2fc88a77e12044d8c7d93c3690644f4df7a45afdf1f9",
        "different pending 170 controller"
    );
    let pid: u32 = capacity::n(&g, "producer_pid")?.try_into()?;
    let proc = Path::new("/proc").join(pid.to_string());
    let m = capacity::native_values(unit)?;
    let projected = fs::metadata(proc.join("root/run/horizon-recovered170/gate.py"))?;
    let original_gate = fs::metadata(gate)?;
    let image = fs::metadata(proc.join("exe"))?;
    let python = fs::metadata("/usr/bin/python3")?;
    let mut argv = vec![
        "/usr/bin/python3",
        "-IB",
        "/run/horizon-recovered170/gate.py",
    ];
    for arg in pr["normal_argv"].as_array().context("held 170 argv")? {
        argv.push(arg.as_str().context("argument")?);
    }
    let command = fs::read(proc.join("cmdline"))?;
    let age = custody::now()?.checked_sub(capacity::n(&v, "recorded_unix_seconds")?);
    ensure!(
        age.is_some_and(|age| age <= 240)
            && m["ActiveState"] == "active"
            && m["SubState"] == "running"
            && m["MainPID"] == pid.to_string()
            && m["InvocationID"] == g["producer_invocation_id"]
            && m["Job"] == ""
            && m["NRestarts"] == "0"
            && m["MemoryMax"] == (68u64 << 30).to_string()
            && m["CPUQuotaPerSecUSec"] == "9s"
            && m["MemorySwapMax"] == "0"
            && fs::read_to_string(proc.join("cgroup"))?.trim()
                == format!("0::/system.slice/{unit}")
            && fs::read_to_string(Path::new(GROUPS).join(unit).join("cgroup.procs"))?.trim()
                == pid.to_string()
            && native::ticks(pid)? == capacity::n(&g, "start_ticks")?
            && (image.dev(), image.ino()) == (python.dev(), python.ino())
            && (projected.dev(), projected.ino()) == (original_gate.dev(), original_gate.ino())
            && command == [argv.join("\0").into_bytes(), vec![0]].concat(),
        "different pending 170 process"
    );
    Ok(Some(170))
}

fn pending_join(error: &str) -> Result<Option<u64>> {
    if cfg!(any(incident_rejoin145_only, incident_post145_only))
        && error
            .trim_end()
            .ends_with("ValueError: foreign pending 170")
    {
        return held_170();
    }
    for (epoch, unit, directory) in [
        (
            166,
            "horizon-qualify-166-independent-recovery-20261121-v1.service",
            "epoch166-independent-cold-recovery-20261121-v1",
        ),
        (
            167,
            "horizon-qualify-167-source-index-v1-20261121.service",
            "epoch167-source-index-recovery-20261121-v1",
        ),
        (
            168,
            "horizon-qualify-168-full-metered-20261121-v1.service",
            "epoch168-full-metered-20261121-v1",
        ),
        (
            170,
            "horizon-qualify-170-replacement-local3retry10-20261121-v1.service",
            "epoch170-retry10-recovery-20261121-v1",
        ),
    ] {
        let dir = Path::new(RUNTIME).join(directory);
        let known_missing = [
            "FIRST_GUARD.json",
            "ACTUAL_PRODUCER_NATIVE.json",
            "ACTUAL_GUARD_PLAN.json",
            "NATIVE_GATED.json",
        ]
        .iter()
        .any(|name| {
            error.lines().last().is_some_and(|l| {
                l.starts_with("FileNotFoundError:")
                    && l.contains(&dir.join(name).display().to_string())
            })
        });
        if !(known_missing
            || error
                .trim_end()
                .ends_with("ValueError: unadmitted peer or expired intent")
            || (epoch == 168
                && error
                    .trim_end()
                    .ends_with("ValueError: foreign pending normal 168")))
        {
            continue;
        }
        let intent = dir.join("START_INTENT.json");
        if !intent.try_exists()?
            || dir
                .join("ACTUAL_ADMISSION_AND_PROTECTION.json")
                .try_exists()?
            || dir.join("START_FAILURE.json").try_exists()?
            || !Path::new(GROUPS).join(unit).try_exists()?
        {
            continue;
        }
        let (_, v) = original(&intent, 8 << 20)?;
        let age = custody::now()?.checked_sub(intent.metadata()?.mtime().try_into()?);
        let m = capacity::native_values(unit)?;
        let pid = m["MainPID"]
            .as_str()
            .context("joining PID")?
            .parse::<u32>()?;
        let proc = Path::new("/proc").join(pid.to_string());
        if !age.is_some_and(|s| s <= 240)
            || v["producer_unit"] != unit
            || m["MemoryMax"] != (68u64 << 30).to_string()
            || m["CPUQuotaPerSecUSec"] != "9s"
            || fs::read_to_string(proc.join("cgroup"))?.trim() != format!("0::/system.slice/{unit}")
        {
            continue;
        }
        let native = dir.join(if epoch == 168 {
            "NATIVE_GATED.json"
        } else {
            "ACTUAL_PRODUCER_NATIVE.json"
        });
        if native.try_exists()? {
            let (_, actor) = original(&native, 2 << 20)?;
            ensure!(
                actor["producer_pid"] == pid
                    && actor["producer_invocation_id"] == m["InvocationID"]
                    && actor["start_ticks"] == native::ticks(pid)?,
                "different pending actor"
            );
        }
        // A pending result can only keep the already-stopped reader stopped. The
        // complete provider must establish the real guard before SIGCONT.
        return Ok(Some(epoch));
    }
    Ok(None)
}

/// Only the sealed fleet provider's exact, read-only PID1 probe can defer the child.
#[cfg(any(incident_timeout145_only, incident_timeout_post145_only))]
pub fn manager_timeout<'a>(stderr: &'a str, provider: &str) -> Option<&'a str> {
    let trace = stderr.trim_end();
    let entry = format!("Traceback (most recent call last):\n  File \"{provider}\", line ");
    if !trace.starts_with(&entry)
        || !trace.contains("  File \"/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1/session-v3/status168.py\", line 61, in show\n")
        || !trace.contains("  File \"/usr/lib/python3.12/subprocess.py\", line 1253, in _check_timeout\n    raise TimeoutExpired(") {
        return None;
    }
    let unit = trace.lines().next_back()?.strip_prefix("subprocess.TimeoutExpired: Command '['/usr/bin/systemctl', 'show', '-p', 'Id,LoadState,ActiveState,SubState,InvocationID,Description,MainPID,StartLimitAction,ControlPID,ControlGroup,Job,NRestarts,Triggers,TriggeredBy,Result,ExecMainStatus,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec', '")?.strip_suffix("']' timed out after 10 seconds")?;
    let registered = unit == UNIT
        || [
            "166-independent-recovery-20261121-v1",
            "167-source-index-v1-20261121",
            "168-full-metered-20261121-v1",
            "169-focused-20261120-v4",
            "170-replacement-local3retry10-20261121-v1",
            "172-full-half-core-20261120-v1",
        ]
        .iter()
        .any(|name| {
            unit.strip_prefix("horizon-qualify-")
                .and_then(|s| s.strip_suffix(".service"))
                == Some(*name)
                || unit.strip_prefix("horizon-guard-").and_then(|s| {
                    s.strip_suffix(".timer")
                        .or_else(|| s.strip_suffix(".service"))
                }) == Some(*name)
        });
    registered.then_some(unit)
}

#[cfg(any(incident_focused145_only, incident_focused_post145_only))]
pub fn missing_status_owner(trace: &str, provider: &str) -> bool {
    let first = format!("Traceback (most recent call last):\n  File \"{provider}\", line ");
    let frame = format!("  File \"{provider}\", line ");
    trace.starts_with(&first) && trace.lines().any(|l| l.starts_with(&frame) && l.ends_with(", in registered_status"))
        && trace.trim_end().ends_with("  File \"/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1/session-v3/status168.py\", line 34, in need\n    raise ValueError(message)\nValueError: cadence publisher absent")
}

fn refresh(previous: &Bound) -> Result<Capture> {
    let fleet = head(previous)?;
    let seal = provider_identity()?;
    // Direct execution lets the provider identify and exclude only its own PID
    // from its caller's cgroup without exempting another verifier or subprocess.
    let out = Command::new(PROVIDER)
        .arg("145")
        .arg(&fleet.path)
        .arg(&fleet.sha256)
        .output()?;
    let err = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        if cfg!(any(incident_rejoin145_only, incident_post145_only))
            && out.status.signal() == Some(libc::SIGALRM)
            && out.stdout.is_empty()
            && out.stderr.is_empty()
        {
            return Err(capacity::Reprice(
                "sealed complete provider exceeded its 142s alarm".into(),
            )
            .into());
        }
        #[cfg(any(incident_timeout145_only, incident_timeout_post145_only))]
        if out.status.code() == Some(1)
            && out.stdout.is_empty()
            && let Some(unit) = manager_timeout(&err, PROVIDER)
        {
            return Err(anyhow::Error::new(capacity::TopologyTimeout)
                .context(format!("sealed PID1 census timed out reading {unit}")));
        }
        #[cfg(any(incident_focused145_only, incident_focused_post145_only))]
        if out.status.code() == Some(1)
            && out.stdout.is_empty()
            && missing_status_owner(&err, PROVIDER)
        {
            return Err(anyhow::Error::new(capacity::TopologyTimeout)
                .context("registered status publisher is unavailable"));
        }
        if err.trim_end().ends_with("ValueError: superseded fleet") {
            let next = head(&fleet)?;
            if next != fleet {
                return refresh(&next);
            }
        }
        if let Some(epoch) = pending_join(&err)? {
            return Err(crate::peer_terminal::Pending(epoch).into());
        }
    }
    ensure!(
        out.status.success()
            || (out.status.code() == Some(1) && err.is_empty() && !out.stdout.is_empty()),
        "complete 145 capacity observation failed {}: {} {}",
        out.status,
        err,
        String::from_utf8_lossy(&out.stdout)
            .chars()
            .take(220)
            .collect::<String>()
    );
    let mut complete: Value = serde_json::from_slice(&out.stdout)?;
    ensure!(
        complete["epoch"] == 145
            && complete["schema"] == "horizon-incident-replay-fit-v1"
            && complete["fleet"] == json!(fleet)
            && complete["resource_credit_bytes"] == 0
            && complete["complete_cpu_quota_micros"] == 64_000_000
            && complete["complete_memory_plus_reserve_bytes"] == HOST_MEMORY
            && complete["phase145"]["invocation_id"] == verify_cgroup()?
            && complete["stopped_generation_resident_credit_bytes"] == 0
            && complete["replay_launch_authorized"] == false,
        "foreign incident capacity or 145 phase"
    );
    let actors = active_population()?;
    let expected: BTreeMap<_, _> = actors
        .iter()
        .map(|(unit, ps)| {
            (
                unit,
                ps.iter().map(|p| [u64::from(p.0), p.1]).collect::<Vec<_>>(),
            )
        })
        .collect();
    let recorded = capacity::n(&complete, "recorded_unix_seconds")?;
    let age = custody::now()?
        .checked_sub(recorded)
        .context("future provider capture")?;
    let (home, required_home) = (
        capacity::n(&complete, "available_HOME_bytes")?,
        capacity::n(&complete, "complete_required_HOME_bytes")?,
    );
    let (ram, required_ram) = (
        capacity::n(&complete, "available_memory_bytes")?,
        capacity::n(&complete, "required_available_memory_bytes")?,
    );
    let mut resident = 0u64;
    for row in complete["survivors"]
        .as_object()
        .context("survivors")?
        .values()
    {
        resident = resident
            .checked_add(capacity::n(row, "resident")?)
            .context("survivor resident total")?;
    }
    for n in complete["joined_resident_lower_bounds"]
        .as_object()
        .context("joined residents")?
        .values()
    {
        resident = resident
            .checked_add(n.as_u64().context("joined resident")?)
            .context("joined resident total")?;
    }
    ensure!(
        required_ram.checked_add(resident) == Some(HOST_MEMORY),
        "registered memory equation changed"
    );
    let fits = home >= required_home && ram >= required_ram;
    ensure!(
        required_home >= capacity::n(&complete, "protected_raw_floor_bytes")?
            && required_ram > 0
            && required_ram <= HOST_MEMORY
            && complete["fits"] == fits
            && fits == out.status.success(),
        "inconsistent provider result"
    );
    if complete["population"] != json!(expected) {
        return Err(capacity::Reprice(format!(
            "complete population crossing: captured={} actual={}",
            complete["population"],
            json!(expected)
        ))
        .into());
    }
    if age > 15 {
        return Err(
            capacity::Reprice(format!("provider capture at {recorded} is {age}s old")).into(),
        );
    }
    if !fits {
        return Err(capacity::Reprice(format!(
            "complete fit at {recorded}: HOME {home}/{required_home}; memory {ram}/{required_ram}"
        ))
        .into());
    }
    complete["provider_seal"] = json!(seal);
    Ok(Capture {
        fleet,
        complete,
        actors,
        captured: Instant::now(),
    })
}

fn current_guard(
    plan: &Value,
    original_sample: Option<&Value>,
    expected_remaining: u64,
    unit: &str,
) -> Result<(u64, u64)> {
    let b: Bound = serde_json::from_value(plan.clone())?;
    let p = custody::evidence(&b)?;
    let d = Path::new(
        p["receipt_directory"]
            .as_str()
            .context("guard receipt directory")?,
    );
    let mut file = File::open(d.parent().context("guard root")?.join("guard.stdout"))?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(2 << 20)))?;
    let mut tail = Vec::new();
    file.take(2 << 20).read_to_end(&mut tail)?;
    let latest = tail
        .split(|c| *c == b'\n')
        .rev()
        .find_map(|l| serde_json::from_slice::<Value>(l).ok())
        .context("latest native guard")?;
    let id = latest["guard_invocation_id"]
        .as_str()
        .context("guard IID")?;
    ensure!(custody::hex(id, 32), "invalid guard IID");
    let (sample_ref, observed) = original(&d.join(format!("sample-{id}.json")), 2 << 20)?;
    let scan = &observed["root_physical_observation"];
    let cap = capacity::n(&p, "maximum_root_physical_bytes")?;
    ensure!(
        observed == latest
            && observed["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && p["unit"] == unit
            && observed["producer_invocation_id"] == p["invocation_id"]
            && observed["plan_sha256"] == b.sha256
            && observed["trip_reason"].is_null()
            && observed["worker_observation_error"].is_null()
            && observed["root_physical_observation_error"].is_null()
            && observed["DATA_fulfillment_observation_error"].is_null()
            && observed["producer_stop_enabled"] == true
            && observed["producer"]["active"] == "active"
            && observed["producer"]["restarts"] == 0
            && scan["exceeds_budget"] == false
            && scan["maximum_physical_bytes"] == cap,
        "invalid current guard for {unit}"
    );
    let recorded = capacity::n(&observed, "recorded_unix_seconds")?;
    let age = custody::now()?
        .checked_sub(recorded)
        .context("future guard observation")?;
    if age > 90 {
        return Err(capacity::Reprice(format!("guard {unit} {sample_ref:?} is {age}s old")).into());
    }
    let floor = capacity::n(&p, "minimum_free_bytes")?;
    let remaining = if scan["first"]["vanished_entries"] == 0
        && scan["second"]["vanished_entries"] == 0
    {
        cap.checked_sub(
            capacity::n(&scan["first"], "physical_bytes")?
                .min(capacity::n(&scan["second"], "physical_bytes")?),
        )
        .context("guard cap exceeded")?
    } else if original_sample == Some(&json!(sample_ref)) {
        expected_remaining
    } else {
        // Keep exactly the earlier independently funded stable-subtree basis only through its original sample;
        // a changed unstable sample needs the provider's current measured lower-bound path.
        return Err(capacity::Reprice(format!(
                "guard {unit} measured remaining {expected_remaining} from {original_sample:?}; new {:?} has vanished counts {}/{}",
                sample_ref, scan["first"]["vanished_entries"], scan["second"]["vanished_entries"])).into());
    };
    Ok((floor, remaining.saturating_sub(expected_remaining)))
}

/// During initial admission and between independent passes there is no worker to stop.
/// Keep the lock, retrying just the authenticated transient probe before doing any work.
fn observe_idle<T>(mut observe: impl FnMut() -> Result<T>) -> Result<T> {
    loop {
        match observe() {
            Err(e)
                if cfg!(any(incident_timeout145_only, incident_timeout_post145_only))
                    && e.is::<capacity::TopologyTimeout>() =>
            {
                eprintln!("epoch145 waiting for a complete PID1 census: {e:#}");
                thread::sleep(if cfg!(test) {
                    Duration::from_millis(20)
                } else {
                    Duration::from_secs(10)
                });
            }
            result => return result,
        }
    }
}

impl Fit {
    pub fn capture(fleet: &Bound) -> Result<Self> {
        let initial = observe_idle(|| refresh(fleet))?;
        Ok(Self {
            evidence: initial.complete.clone(),
            capture: RefCell::new(initial),
        })
    }
    pub fn topology(&self) -> Result<()> {
        let previous = self.capture.borrow().fleet.clone();
        *self.capture.borrow_mut() = refresh(&previous)?;
        Ok(())
    }
    pub fn await_topology(&self) -> Result<()> {
        if self.capture.borrow().captured.elapsed() > Duration::from_secs(10) {
            observe_idle(|| self.topology())?;
        }
        Ok(())
    }
    pub fn await_current(&self, needed: u64) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            match self.current(needed) {
                Err(e)
                    if (e.is::<capacity::GuardInFlight>() || e.is::<capacity::Reprice>())
                        && Instant::now() < deadline =>
                {
                    observe_idle(|| self.topology())?
                }
                result => return result,
            }
        }
    }
    pub fn current(&self, needed: u64) -> Result<Value> {
        let last = self.capture.borrow();
        let s = &last.complete;
        ensure!(needed == 0, "frozen reader requested staging bytes");
        let age = last.captured.elapsed();
        if age > Duration::from_secs(45) {
            return Err(capacity::Reprice(format!("full capture age {age:?}")).into());
        }
        let actual = active_population()?;
        if actual != last.actors {
            return Err(capacity::Reprice(format!(
                "native population crossed: previous={:?} current={actual:?}",
                last.actors
            ))
            .into());
        }
        let mut required = capacity::n(s, "complete_required_HOME_bytes")?;
        let mut absolute = 0;
        for row in s["survivors"]
            .as_object()
            .context("incumbent guards")?
            .values()
        {
            let g = &row["guard"];
            let (floor, growth) = current_guard(
                &g["plan"],
                Some(&g["guard"]),
                capacity::n(g, "remaining")?,
                row["unit"].as_str().context("incumbent unit")?,
            )?;
            required = required.checked_add(growth).context("incumbent growth")?;
            absolute = absolute.max(floor);
        }
        for (epoch, row) in s["replacements"]
            .as_object()
            .context("replacement guards")?
        {
            let b = &s["bookings"][epoch];
            let (floor, growth) = current_guard(
                &row["plan"],
                Some(&row["guard"]),
                capacity::n(b, "remaining_bytes")?,
                row["producer_unit"].as_str().context("replacement unit")?,
            )?;
            // A new deficit can affect the original physical baseline and the independent new-generation spending calculation.
            required = required
                .checked_add(growth.checked_mul(2).context("baseline growth")?)
                .context("replacement growth")?;
            absolute = absolute.max(floor);
        }
        if !s["normal168"].is_null() || s["candidate136"]["occupied"] == true {
            // Both are admitted by the full provider. Check their exact current guard plan and remaining
            // allowance using the original rooted admission rather than letting a new peer bypass the check.
            for (epoch, plan, unit, remaining) in extra_guards(s)? {
                let sample =
                    if cfg!(any(incident_rejoin145_only, incident_post145_only)) && epoch == 168 {
                        Some(
                            s["bookings"]["168"]
                                .get("measured_guard")
                                .context("missing priced 168 native sample")?,
                        )
                    } else {
                        None
                    };
                let (floor, growth) = current_guard(&plan, sample, remaining, &unit)?;
                required = required.checked_add(growth).context("peer growth")?;
                absolute = absolute.max(floor);
                ensure!(matches!(epoch, 136 | 168), "foreign peer");
            }
        }
        required = required.max(absolute);
        let free = capacity::home()?.0;
        let mut resident = 0u64;
        let peers = s["survivors"]
            .as_object()
            .unwrap()
            .values()
            .map(|row| (&row["unit"], row, capacity::n(row, "resident")));
        let joined = s["replacements"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(e, row)| {
                (
                    &row["producer_unit"],
                    row,
                    capacity::n(&s["joined_resident_lower_bounds"], e),
                )
            });
        for (unit, row, baseline) in peers.chain(joined) {
            let p = Path::new(GROUPS).join(unit.as_str().context("resident unit")?);
            let values = fs::read_to_string(p.join("memory.stat"))?;
            let stat = |name: &str| -> Result<u64> {
                Ok(values
                    .lines()
                    .find_map(|l| l.strip_prefix(name))
                    .context("resident memory")?
                    .parse()?)
            };
            let mut pss = 0u64;
            for t in row["processes"].as_array().context("processes")? {
                let v = fs::read_to_string(format!("/proc/{}/smaps_rollup", t[0]))?;
                let kb: u64 = v
                    .lines()
                    .find_map(|l| l.strip_prefix("Pss:"))
                    .context("PSS")?
                    .split_whitespace()
                    .next()
                    .context("KiB")?
                    .parse()?;
                pss = pss.checked_add(kb * 1024).context("PSS sum")?;
            }
            resident = resident
                .checked_add(
                    pss.min(stat("anon ")? + stat("file_mapped ")?)
                        .min(baseline?)
                        .min(68 << 30),
                )
                .context("resident sum")?;
        }
        let memory = HOST_MEMORY.checked_sub(resident).context("memory budget")?;
        let available = capacity::meminfo("MemAvailable:")?;
        if free < required || available < memory {
            return Err(capacity::Reprice(format!(
                "live fit: HOME {free}/{required}; memory {available}/{memory}"
            ))
            .into());
        }
        Ok(
            json!({"free_bytes":free,"protected_bytes":required,"available_memory":available,"required_memory":memory,
            "fleet":last.fleet,"recorded_unix_seconds":s["recorded_unix_seconds"],"resource_credit_bytes":0}),
        )
    }
}

fn extra_guards(s: &Value) -> Result<Vec<(u64, Value, String, u64)>> {
    let mut result = Vec::new();
    if !s["normal168"].is_null() {
        let r = &s["normal168"];
        ensure!(r["ordinary_canonical"] == true, "unadmitted 168");
        let a = custody::evidence(&serde_json::from_value(r["admission"].clone())?)?;
        result.push((
            168,
            a["actual_guard_plan"].clone(),
            a["producer_unit"].as_str().context("168 unit")?.to_owned(),
            capacity::n(&s["bookings"]["168"], "remaining_bytes")?,
        ));
    }
    if s["candidate136"]["occupied"] == true {
        let r = &s["candidate136"];
        let identity = &r["identity"];
        let path = Path::new(
            "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1/reproduction/receipts/guard-plan.json",
        );
        let (plan, entry) = original(path, 2 << 20)?;
        ensure!(
            entry["invocation_id"] == identity["iid"]
                && entry["unit"] == identity["unit"]
                && entry["minimum_free_bytes"] == r["guard_floor"]
                && entry["maximum_root_physical_bytes"] == r["cap"],
            "foreign current 136 guard"
        );
        result.push((
            136,
            json!(plan),
            identity["unit"].as_str().context("136 unit")?.to_owned(),
            capacity::n(r, "remaining")?,
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root-owned accepted fleet and native production cgroups"]
    fn authenticates_the_actual_fleet_and_disallows_missing_members() {
        let p = PathBuf::from(std::env::var("INCIDENT_FLEET").unwrap());
        let (binding, _) = original(&p, 32 << 20).unwrap();
        let current = head(&binding).unwrap();
        let v: Value =
            serde_json::from_slice(&custody::bytes(&current, 32 << 20, false).unwrap()).unwrap();
        assert_eq!(v["owner"], "/root");
        let a = active_population().unwrap();
        for unit in [
            "horizon-qualify-172-full-half-core-20261120-v1.service",
            "horizon-qualify-166-independent-recovery-20261121-v1.service",
        ] {
            let ps = a.get(unit).unwrap();
            assert_eq!(ps.len(), 2);
            assert!(ps[0].0 != ps[1].0 && ps.iter().all(|p| p.1 > 0 && p.3 > 0));
        }
        assert!(
            current_guard(&json!({"path":p,"sha256":"f".repeat(64)}), None, 0, "bogus").is_err()
        );
    }
}
