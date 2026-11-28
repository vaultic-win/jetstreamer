//! Reuse the registered fleet admission while a leased, read-only verifier runs.
//! A topology crossing stops the child until a new complete census succeeds.
use super::*;
use std::os::unix::{fs::OpenOptionsExt, process::ExitStatusExt};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
};
#[cfg(incident_v9_census_recovery145_only)]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v9-census-recovery-v1/post-stop-fit";
#[cfg(all(incident_v8_census_recovery145_only, not(incident_v9_census_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v8-census-recovery-v1/post-stop-fit";
#[cfg(all(incident_v7_timeout_recovery145_only, not(incident_v8_census_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v7-timeout-recovery-v1/post-stop-fit";
#[cfg(all(incident_v6_stop_recovery145_only, not(incident_v7_timeout_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v6-stop-recovery-v2/post-stop-fit";
#[cfg(all(incident_v5z_guard_recovery145_only, not(incident_v6_stop_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v5z-guard-walk-recovery-v1/post-stop-fit";
#[cfg(all(incident_v5y_guard_recovery145_only, not(incident_v5z_guard_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v5y-custody-recovery-v1/post-stop-fit";
#[cfg(all(incident_v5x_guard_recovery145_only, not(incident_v5y_guard_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v5x-schema-recovery-v1/post-stop-fit";
#[cfg(all(incident_v5w_guard_recovery145_only, not(incident_v5x_guard_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v5w-donor-recovery-v1/post-stop-fit";
#[cfg(all(incident_v5v_guard_recovery145_only, not(incident_v5w_guard_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v5v-custody-recovery-v1/post-stop-fit";
#[cfg(all(incident_v5u_guard_recovery145_only, not(incident_v5v_guard_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v5u-guard-recovery-v1/post-stop-fit";
#[cfg(all(incident_v5t_guard_recovery145_only, not(incident_v5u_guard_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v5t-guard-recovery-v1/post-stop-fit";
#[cfg(all(incident_v5s_guard_recovery145_only, not(incident_v5t_guard_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v5s-guard-recovery-v1/post-stop-fit";
#[cfg(all(incident_v5r_guard_recovery145_only, not(incident_v5s_guard_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-v5r-guard-recovery-v1/post-stop-fit";
#[cfg(all(incident_encoded_prefix145_only, not(incident_v5r_guard_recovery145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-encoded-prefix-rejoin-v1/post-stop-fit";
#[cfg(all(incident_audit_turnover145_only, not(incident_encoded_prefix145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-audit-turnover-rejoin-v1/post-stop-fit";
#[cfg(all(incident_status_owner145_only, not(incident_audit_turnover145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-status-owner-rejoin-v1/post-stop-fit";
#[cfg(all(incident_donor_pressure145_only, not(incident_status_owner145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-donor-pressure-rejoin-v1/post-stop-fit";
#[cfg(all(incident_guard_walk145_only, not(incident_donor_pressure145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-guard-walk-rejoin-v1/post-stop-fit";
#[cfg(all(incident_missed_clock145_only, not(incident_guard_walk145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-missed-rejoin-v1/post-stop-fit";
#[cfg(all(incident_lease_start145_only, not(incident_missed_clock145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-lease-rejoin-v1/post-stop-fit";
#[cfg(all(incident_retry4_145_only, not(incident_lease_start145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-rejoin-v4/post-stop-fit";
#[cfg(all(incident_retry3_145_only, not(incident_retry4_145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-rejoin-v3/post-stop-fit";
#[cfg(all(incident_five_lane145_only, not(incident_retry3_145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-rejoin-v2/post-stop-fit";
#[cfg(all(incident_homefloor145_only, not(incident_five_lane145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-rejoin-v1/post-stop-fit";
#[cfg(all(incident_fixture145_only, not(incident_homefloor145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v20/post-stop-fit";
#[cfg(all(incident_timer145_only, not(incident_fixture145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v16/post-stop-fit";
#[cfg(incident_fixture_post145_only)]
const PROVIDER: &str = if cfg!(incident_v10_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v10-current-v1/post-stop-fit"
} else if cfg!(incident_v9_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v9-current-v1/post-stop-fit"
} else if cfg!(incident_v7_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v7-current-v1/post-stop-fit"
} else if cfg!(incident_v5z_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v6-current-v1/post-stop-fit"
} else if cfg!(incident_v5x_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5x-current-v1/post-stop-fit"
} else if cfg!(incident_v5w_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5w-current-v1/post-stop-fit"
} else if cfg!(incident_guard_v5u_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5u-guard-v1/post-stop-fit"
} else if cfg!(incident_v5u_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5u-v1/post-stop-fit"
} else if cfg!(incident_v5r_136_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5r-136-v1/post-stop-fit"
} else if cfg!(incident_v5q_136_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5q-136-v1/post-stop-fit"
} else if cfg!(incident_v5o_136_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5o-136-v1/post-stop-fit"
} else if cfg!(incident_v5n_136_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5n-136-v1/post-stop-fit"
} else if cfg!(incident_v5n_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5n-v1/post-stop-fit"
} else if cfg!(incident_v5m_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5m-v1/post-stop-fit"
} else if cfg!(incident_v5k_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5k-v1/post-stop-fit"
} else if cfg!(incident_v5j_retry1_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5j-v2/post-stop-fit"
} else if cfg!(incident_v5j_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5j-v1/post-stop-fit"
} else if cfg!(incident_v7c_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v23/post-stop-fit"
} else if cfg!(incident_v7b_post145_only) {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v21b/post-stop-fit"
} else {
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v21/post-stop-fit"
};
#[cfg(all(
    incident_registered136_post145_only,
    not(incident_fixture_post145_only)
))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v19/post-stop-fit";
#[cfg(all(incident_timer_post145_only, not(incident_registered136_post145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v17/post-stop-fit";
#[cfg(all(incident_retry_post145_only, not(incident_timer_post145_only)))]
const PROVIDER: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-v15/post-stop-fit";
#[cfg(all(
    any(incident_focused145_only, incident_focused_post145_only),
    not(any(incident_retry_post145_only, incident_timer145_only))
))]
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
#[cfg(incident_missed_clock145_only)]
#[path = "missed_clock.rs"]
pub(crate) mod missed_clock;
#[cfg(incident_guard_walk145_only)]
#[path = "guard_walk.rs"]
mod guard_walk;
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
            #[cfg(incident_missed_clock145_only)]
            if let Some(next) = missed_clock::replacement(&b, &v)? {
                let successor: Value = serde_json::from_slice(&custody::bytes(&next, 32 << 20, false)?)?;
                ensure!(capacity::n(&successor, "recorded_unix_seconds")? > capacity::n(&v, "recorded_unix_seconds")?,
                    "recovered fleet is not advancing");
                b = next;
                continue;
            }
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
        #[cfg(any(incident_homefloor145_only, incident_v5j_post145_only))]
        (
            166,
            "horizon-qualify-166-independent-retry11-20261122.service",
            "epoch166-retry11-rebook-20261122-v1",
        ),
        #[cfg(any(incident_homefloor145_only, incident_v5j_post145_only))]
        (
            170,
            "horizon-qualify-170-replacement-local3retry11-20261122.service",
            "epoch170-retry11-rebook-20261122-v1",
        ),
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
    let manager = [
        "  File \"/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1/session-v3/status168.py\", line 61, in show",
        "  File \"/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1/session-v4-registered136/status168.py\", line 61, in show",
    ];
    if !trace.starts_with(&entry)
        || !trace.lines().any(|line| manager.contains(&line))
        || !trace.contains("  File \"/usr/lib/python3.12/subprocess.py\", line 1253, in _check_timeout\n    raise TimeoutExpired(") {
        return None;
    }
    let unit = trace.lines().next_back()?.strip_prefix("subprocess.TimeoutExpired: Command '['/usr/bin/systemctl', 'show', '-p', 'Id,LoadState,ActiveState,SubState,InvocationID,Description,MainPID,StartLimitAction,ControlPID,ControlGroup,Job,NRestarts,Triggers,TriggeredBy,Result,ExecMainStatus,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec', '")?.strip_suffix("']' timed out after 10 seconds")?;
    let registered = unit == UNIT
        || [
            "166-independent-recovery-20261121-v1",
            "167-source-index-v1-20261121",
            "167-source-index-v3-20261122",
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

/// A bounded, read-only retirement inspection can time out while all paid files stay leased.
#[cfg(any(incident_timer145_only, incident_timer_post145_only))]
pub fn timer_inspection_timeout(stderr: &str, provider: &str) -> bool {
    let Some(directory) = Path::new(provider).parent() else {
        return false;
    };
    let probe = directory.join("retire-original-timers.py");
    let frame = format!("  File \"{provider}\", line ");
    let expected = format!(
        "subprocess.TimeoutExpired: Command '['/usr/bin/python3', '-IB', PosixPath('{}'), 'inspect']' timed out after 20 seconds",
        probe.display()
    );
    let mut lines = stderr.trim_end().lines();
    lines.next() == Some("Traceback (most recent call last):")
        && lines
            .next()
            .is_some_and(|line| line.starts_with(&frame) && line.ends_with(", in <module>"))
        && lines
            .clone()
            .any(|line| line.starts_with(&frame) && line.ends_with(", in proof_stops"))
        && lines.next_back() == Some(expected.as_str())
}

#[cfg(incident_guard_walk145_only)]
fn retained_donor_pressure<'a>(stderr: &'a str, provider: &str) -> Option<&'a str> {
    let directory = Path::new(provider).parent()?;
    let (detail, trace) = match stderr.strip_prefix("epoch145 donor capacity: ") {
        Some(with_detail) => {
            let (detail, trace) = with_detail.split_once('\n')?;
            let (home, memory) = detail
                .strip_prefix("home_shortfall_bytes=")?
                .split_once(" memory_shortfall_bytes=")?;
            let home = home.parse::<u64>().ok()?;
            let memory = memory.parse::<u64>().ok()?;
            if home == 0 && memory == 0 {
                return None;
            }
            (detail, trace)
        }
        None => ("", stderr),
    };
    let frame = format!("  File \"{provider}\", line ");
    let donor_frame = format!(
        "  File \"{}\", line ",
        directory.join("build_159_price.py").display()
    );
    let mut lines = trace.trim_end().lines();
    let recognized = lines.next() == Some("Traceback (most recent call last):")
        && lines
            .next()
            .is_some_and(|line| line.starts_with(&frame) && line.ends_with(", in <module>"))
        && lines.next_back() == Some("ValueError: insufficient HOME or general-slot memory")
        && lines
            .clone()
            .any(|line| line.starts_with(&frame) && line.ends_with(", in capture"))
        && lines.any(|line| line.starts_with(&donor_frame) && line.ends_with(", in cover"));
    recognized.then_some(detail)
}

#[cfg(incident_v5w_guard_recovery145_only)]
fn retained_donor_lock_busy(stderr: &str, provider: &str) -> bool {
    let Some(directory) = Path::new(provider).parent() else {
        return false;
    };
    let quote_frame = format!("  File \"{provider}\", line ");
    let donor_frame = format!("  File \"{}\", line ", directory.join("build_159_price.py").display());
    let mut rows = stderr.trim_end().lines();
    rows.next() == Some("Traceback (most recent call last):")
        && rows.next().is_some_and(|row| row.starts_with(&quote_frame) && row.ends_with(", in <module>"))
        && rows.next_back() == Some("ValueError: another actor holds the donor; requires its own enrollment")
        && rows.clone().any(|row| row.starts_with(&quote_frame) && row.ends_with(", in capture"))
        && rows.clone().any(|row| row.starts_with(&donor_frame) && row.ends_with(", in snapshot"))
        && rows.any(|row| row.starts_with(&donor_frame) && row.ends_with(", in donor_users"))
}

#[cfg(all(test, incident_v5w_guard_recovery145_only))]
#[test]
fn donor_lock_busy_requires_the_sealed_quote_and_snapshot_frames() {
    let provider = "/sealed/post-stop-fit";
    let trace = concat!(
        "Traceback (most recent call last):\n",
        "  File \"/sealed/post-stop-fit\", line 1692, in <module>\n",
        "  File \"/sealed/post-stop-fit\", line 1594, in capture\n",
        "  File \"/sealed/build_159_price.py\", line 133, in snapshot\n",
        "  File \"/sealed/build_159_price.py\", line 84, in donor_users\n",
        "  File \"/sealed/build_159_price.py\", line 32, in need\n",
        "ValueError: another actor holds the donor; requires its own enrollment\n",
    );
    assert!(retained_donor_lock_busy(trace, provider));
    assert!(!retained_donor_lock_busy(trace, "/foreign/post-stop-fit"));
    assert!(!retained_donor_lock_busy(&trace.replace("in donor_users", "in cover"), provider));
    assert!(!retained_donor_lock_busy(&trace.replace("another actor holds the donor", "donor lock replaced"), provider));
}

fn reserved_memory(_complete: &Value) -> Result<u64> {
    #[cfg(any(incident_homefloor145_only, incident_v5j_post145_only))]
    let qualification_memory = match &_complete["bounded_qualification"] {
        Value::Null => 0,
        q => {
            let valid_owner = if q["unit"]
                == "horizon-146-full-local-qualification-20261124-v1.service"
            {
                q["invocation_id"]
                    .as_str()
                    .is_some_and(|id| custody::hex(id, 32) && id.bytes().any(|b| b != b'0'))
                    && q["pid"]
                        .as_u64()
                        .is_some_and(|pid| (2..=i32::MAX as u64).contains(&pid))
                    && q["start_ticks"].as_u64().is_some_and(|ticks| ticks > 0)
                    && q["registration"]["path"]
                        == "/var/lib/jetstreamer/horizon_runtime_data/epoch146-singleton-20261122-v1/BOUNDED_ENTRY_LEASE.json"
                    && q["registration"]["sha256"]
                        .as_str()
                        .is_some_and(|sha| custody::hex(sha, 64))
            } else {
                q["unit"] == "horizon-142-full-local-qualification-20261122-v1.service"
                    && q["invocation_id"] == "42466cf599e7429889a778a68376c5ed"
                    && q["pid"] == 227497
            };
            ensure!(
                valid_owner
                    && q["memory_bytes"] == 192u64 << 20
                    && q["scratch_bytes"] == 8u64 << 20
                    && q["additional_cpu_quota_micros"] == 0,
                "foreign bounded native qualification"
            );
            capacity::n(q, "memory_bytes")?
        }
    };
    #[cfg(not(any(incident_homefloor145_only, incident_v5j_post145_only)))]
    let qualification_memory = 0;
    HOST_MEMORY
        .checked_add(qualification_memory)
        .context("qualified memory budget")
}

fn live_memory_budget(
    mut required: u64,
    credits: impl IntoIterator<Item = Result<u64>>,
    mut read_available: impl FnMut() -> Result<u64>,
) -> Result<(u64, u64)> {
    let mut available = read_available()?;
    let mut credits = credits.into_iter();
    while available < required {
        let Some(credit) = credits.next() else { break };
        required = required.checked_sub(credit?).context("memory budget")?;
        available = read_available()?;
    }
    Ok((available, required))
}

/// Reopen the holding tool's two completed retirements while this verifier holds
/// the same serial transition lock. Free space is measured by the provider.
#[cfg(any(incident_five_lane145_only, incident_v5j_post145_only))]
fn serial_handback(complete: &Value) -> Result<Vec<Bound>> {
    let state = Path::new(HOLDING_LOCK).parent().context("holding state")?;
    read_handback(complete, state, |path| match fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
        Ok(_) => anyhow::bail!("retired holding path reappeared: {}", path.display()),
    })
}

#[cfg(any(incident_five_lane145_only, incident_v5j_post145_only))]
fn read_handback(
    complete: &Value,
    state: &Path,
    absent: impl Fn(&Path) -> Result<()>,
) -> Result<Vec<Bound>> {
    let mut evidence = Vec::new();
    for (label, field, plan_sha) in [
        (
            "166-retry10",
            "registered_retry11_holding",
            "cee159c094d1d77778a24d7b563a6a6bdd295786652ff73745258bb086f33b04",
        ),
        (
            "168-full-metered",
            "registered_cold168_holding",
            "a8c1611f228a216d68b56f249e6b8c34c346b963f4675e6d7015ae22ae8c06c6",
        ),
    ] {
        let holding = &complete[field];
        ensure!(
            holding["stage"] == "completed-copy"
                && holding["additional_reservation_bytes"] == 0
                && holding["resource_credit_bytes"] == 0,
            "serial holding {label} has not drained"
        );
        let iid = holding["invocation_id"]
            .as_str()
            .context("holding invocation")?;
        ensure!(custody::hex(iid, 32), "invalid holding invocation");
        let terminal = state
            .join("receipts")
            .join(format!("epoch{label}-park-terminal-{iid}.json"));
        let (terminal_ref, proof) = original(&terminal, 1 << 20)?;
        let plan_path = Path::new(RUNTIME).join(format!(
            "epoch{label}-holding-20261122-v1/package/plan.json"
        ));
        let (plan_ref, plan) = original(&plan_path, 1 << 20)?;
        let path = state
            .join("retirements")
            .join(format!("epoch{label}-completion.json"));
        let (receipt, completed) = original(&path, 1 << 20)?;
        let intent = &completed["intent"];
        let quarantine = state.join("retirements").join(format!(
            "epoch{label}-{}.jet",
            plan["sha256"].as_str().context("holding SHA")?
        ));
        ensure!(
            plan_ref.sha256 == plan_sha
                && proof["park_plan"] == json!(plan_ref)
                && proof["invocation_id"] == iid
                && proof["unit"] == holding["unit"]
                && proof["start"] == holding["start"]
                && proof["schema"] == format!("horizon-closed{label}-park-terminal-v1")
                && completed["schema"]
                    == format!("jetstreamer-holding-retire{label}-completion-v1")
                && completed["authenticated_custody_revalidated"] == true
                && completed["resource_credit_bytes"] == 0
                && completed["actual_free_delta_claimed"] == false
                && completed["source_absent"] == true
                && completed["quarantine_absent"] == true
                && intent["park_terminal"] == json!(terminal_ref)
                && intent["custody"] == proof["custody"]
                && intent["sha256"] == plan["sha256"]
                && intent["length"] == plan["length"]
                && intent["source"] == plan["source"]
                && intent["quarantine"] == json!(quarantine)
                && intent["eligibility"] == plan["eligibility"]
                && plan["length"] == holding["restore_overlap_bytes"],
            "foreign {label} holding handback"
        );
        let source = Path::new(plan["source"].as_str().context("holding source")?);
        absent(source)?;
        absent(&quarantine)?;
        evidence.push(receipt);
    }
    Ok(evidence)
}

/// Check the actual handback before replacing the original failed unit identity.
#[cfg(incident_five_lane145_only)]
pub fn preflight(fleet: Bound, sha: &str) -> Result<()> {
    check_image(sha, Path::new(incident145::IMAGE))?;
    let _lock = lock()?;
    ensure!(head(&fleet)? == fleet, "a newer complete fleet exists");
    let seal = provider_identity()?;
    let response = Command::new(PROVIDER)
        .args([
            "145",
            fleet.path.to_str().context("fleet path")?,
            &fleet.sha256,
        ])
        .output()?;
    ensure!(
        response.status.success(),
        "145 preflight failed: {}",
        String::from_utf8_lossy(&response.stderr)
    );
    let v: Value = serde_json::from_slice(&response.stdout)?;
    ensure!(
        v["schema"] == "horizon-incident-replay-fit-v1"
            && v["epoch"] == 145
            && v["fits"] == true
            && v["fleet"] == json!(fleet)
            && v["candidate"].is_null()
            && v["resource_credit_bytes"] == 0
            && v["phase145"]["InvocationID"] == "afcf6cdd1ec0400ea2757f81472987b3"
            && v["phase145"]["failure"]["sha256"]
                == "5e001f59750a67f2cdce6aa43fb11b7d55e648a40d52e3fbee26ed3ead66a366"
            && v["phase145"]["source_checkpoint_exists"] == false
            && v["phase145"]["candidate"]["inode"] == 103237059
            && v["replay_launch_authorized"] == false
            && v["complete_cpu_quota_micros"] == 64_000_000
            && v["complete_memory_plus_reserve_bytes"] == HOST_MEMORY
            && capacity::n(&v, "available_HOME_bytes")?
                >= capacity::n(&v, "complete_required_HOME_bytes")?
            && capacity::n(&v, "available_memory_bytes")?
                >= capacity::n(&v, "required_available_memory_bytes")?,
        "unfunded or foreign 145 preflight"
    );
    let receipts = serial_handback(&v)?;
    ensure!(head(&fleet)? == fleet, "fleet changed during preflight");
    println!(
        "{}",
        json!({"fleet": fleet, "provider": seal, "serial_handback": receipts,
        "recorded_unix_seconds": v["recorded_unix_seconds"], "worker_started": false})
    );
    Ok(())
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
        #[cfg(incident_v5w_guard_recovery145_only)]
        if out.status.code() == Some(1)
            && out.stdout.is_empty()
            && retained_donor_lock_busy(&err, PROVIDER)
        {
            return Err(anyhow::Error::new(capacity::GuardInFlight)
                .context("retained donor operation lock is held during the fresh price"));
        }
        #[cfg(any(incident_homefloor145_only, incident_v5j_post145_only))]
        if out.status.code() == Some(75)
            && out.stdout.is_empty()
            && err == "public audit workers changed during capacity capture\n"
        {
            return Err(anyhow::Error::new(capacity::TopologyTimeout)
                .context("public audit worker roster changed while measuring capacity"));
        }
        #[cfg(incident_guard_walk145_only)]
        if out.status.code() == Some(1)
            && out.stdout.is_empty()
            && let Some(detail) = retained_donor_pressure(&err, PROVIDER)
        {
            // The original guarded stop window still applies. Only a new
            // complete fit can resume the worker, and no new worker is admitted.
            let err = anyhow::Error::new(capacity::GuardInFlight)
                .context("retained donor HOME or general-slot memory is temporarily insufficient");
            return Err(if detail.is_empty() {
                err
            } else {
                err.context(detail.to_owned())
            });
        }
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
        #[cfg(any(incident_timer145_only, incident_timer_post145_only))]
        if out.status.code() == Some(1)
            && out.stdout.is_empty()
            && timer_inspection_timeout(&err, PROVIDER)
        {
            return Err(anyhow::Error::new(capacity::TopologyTimeout)
                .context("sealed retirement inspection timed out"));
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
    #[cfg(incident_v5u_guard_recovery145_only)]
    {
        let observed: Bound = serde_json::from_value(
            complete["phase145"]["window"]["guard_terminal_predecessor"].clone(),
        )?;
        #[cfg(incident_v9_census_recovery145_only)]
        let pinned = incident145::v9_terminal()?;
        #[cfg(all(incident_v8_census_recovery145_only, not(incident_v9_census_recovery145_only)))]
        let pinned = incident145::v8_terminal()?;
        #[cfg(all(incident_v7_timeout_recovery145_only, not(incident_v8_census_recovery145_only)))]
        let pinned = incident145::v7_terminal()?;
        #[cfg(all(incident_v6_stop_recovery145_only, not(incident_v7_timeout_recovery145_only)))]
        let pinned = incident145::v6_terminal()?;
        #[cfg(all(incident_v5z_guard_recovery145_only, not(incident_v6_stop_recovery145_only)))]
        let pinned = incident145::v5z_terminal()?;
        #[cfg(all(incident_v5y_guard_recovery145_only, not(incident_v5z_guard_recovery145_only)))]
        let pinned = incident145::v5y_terminal()?;
        #[cfg(all(incident_v5x_guard_recovery145_only, not(incident_v5y_guard_recovery145_only)))]
        let pinned = incident145::v5x_terminal()?;
        #[cfg(all(incident_v5w_guard_recovery145_only, not(incident_v5x_guard_recovery145_only)))]
        let pinned = incident145::v5w_terminal()?;
        #[cfg(all(incident_v5v_guard_recovery145_only, not(incident_v5w_guard_recovery145_only)))]
        let pinned = incident145::v5v_terminal()?;
        #[cfg(not(incident_v5v_guard_recovery145_only))]
        let pinned = custody::binding(&Path::new(RUNTIME).join(
            "epoch145-semantic-continuity-20261121-v1/v5v-name-handoff/V5U_TERMINAL.json",
        ))?;
        ensure!(
            observed == pinned
                && complete["settled_hourly170"]["terminal"]["successful_exit"] == true
                && complete["settled_hourly170"]["terminal"]["reservation_ending_bytes"] == 0,
            "capacity provider changed the V5u terminal or epoch 170 settlement"
        );
    }
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
    #[cfg(any(incident_homefloor145_only, incident_v5j_post145_only))]
    {
        let holding = &complete["registered_retry11_holding"];
        let obligations = &complete["recovery_obligations"];
        ensure!(
            complete["candidate"].is_null()
                && holding["stage"] == "completed-copy"
                && holding["stage_bytes"] == 0
                && holding["resource_credit_bytes"] == 0
                && holding["additional_reservation_bytes"] == 0
                && holding["restore_overlap_bytes"] == 64922604512u64
                && obligations["public_storage"]["remaining_archive_growth_bytes"] == 0
                && obligations["public_storage"]["maximum_host_allocation_bytes"] == 256u64 << 20
                && obligations["prefix"]["maximum_HOME_allocation_bytes"] == 16u64 << 20
                && obligations["prefix"]["resource_credit_bytes"] == 0
                && complete["status_registration"]["consumer_seal"]["sha256"]
                    .as_str()
                    .is_some_and(|sha| custody::hex(sha, 64))
                && complete["candidate136"]["cap"] == 72u64 << 30,
            "145 requires the current paid HOME, holding and sole writer census"
        );
    }
    #[cfg(any(incident_five_lane145_only, incident_v5j_post145_only))]
    {
        let handback = serial_handback(&complete)?;
        complete["serial_145_holding_handback"] = json!(handback);
    }
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
    let reserved_ram = reserved_memory(&complete)?;
    ensure!(
        required_ram.checked_add(resident) == Some(reserved_ram),
        "registered memory equation changed"
    );
    let fits = home >= required_home && ram >= required_ram;
    ensure!(
        required_home >= capacity::n(&complete, "protected_raw_floor_bytes")?
            && required_ram > 0
            && required_ram <= reserved_ram
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

fn live_guard_sample(d: &Path, p: &Value, b: &Bound, unit: &str) -> Result<(Bound, Value)> {
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
    let cap = capacity::n(p, "maximum_root_physical_bytes")?;
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
            && observed["producer"]["invocation_id"] == p["invocation_id"]
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
    for pass in ["first", "second"] {
        capacity::n(&scan[pass], "vanished_entries")?;
        ensure!(capacity::n(&scan[pass], "physical_bytes")? <= cap, "native guard cap exceeded");
    }
    Ok((sample_ref, observed))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GuardCheck {
    Running,
    Stopped,
    RegisteredHold,
}

#[cfg(incident_guard_walk145_only)]
fn guard_walk_allocation(
    path: &Path,
    measured: Result<Option<u64>>,
    scan: &Value,
    latest: impl FnOnce() -> Result<Value>,
    check: GuardCheck,
) -> Result<u64> {
    let measured = measured?;
    let current = latest()?;
    let Some(mut paid) = measured else {
        let message = format!(
            "no pair of complete allocation walks for {}; awaiting a fresh guard sample",
            path.display()
        );
        if check == GuardCheck::RegisteredHold {
            // Keep the child stopped under the same registration. Charge the
            // full allocation cap until a complete new price is available.
            eprintln!("epoch145 registered hold: {message}");
            return Ok(0);
        }
        return Err(capacity::Reprice(message).into());
    };
    for observation in [scan, &current["root_physical_observation"]] {
        for pass in ["first", "second"] {
            paid = paid.min(capacity::n(&observation[pass], "physical_bytes")?);
        }
    }
    Ok(paid)
}

#[cfg(all(test, incident_guard_walk145_only))]
#[test]
fn registered_hold_charges_the_whole_cap_after_incomplete_walks() -> Result<()> {
    let path = Path::new("/fixture/guard-root");
    let scan = json!({"first": {"physical_bytes": 12}, "second": {"physical_bytes": 18}});
    let latest = || Ok(json!({"root_physical_observation": scan}));
    assert_eq!(
        guard_walk_allocation(path, Ok(None), &scan, latest, GuardCheck::RegisteredHold)?,
        0
    );
    assert!(
        guard_walk_allocation(path, Ok(None), &scan, latest, GuardCheck::Stopped)
            .unwrap_err()
            .is::<capacity::Reprice>()
    );
    assert_eq!(
        guard_walk_allocation(path, Ok(Some(21)), &scan, latest, GuardCheck::Stopped)?,
        12
    );

    let invalid_walk = Err(anyhow::anyhow!("charged directory was replaced"));
    let error = guard_walk_allocation(path, invalid_walk, &scan, latest, GuardCheck::RegisteredHold)
        .unwrap_err();
    assert_eq!(error.to_string(), "charged directory was replaced");
    let tripped = || anyhow::bail!("invalid current guard for epoch172");
    let error = guard_walk_allocation(path, Ok(None), &scan, tripped, GuardCheck::RegisteredHold)
        .unwrap_err();
    assert_eq!(error.to_string(), "invalid current guard for epoch172");
    Ok(())
}

fn current_guard(
    plan: &Value,
    original_sample: Option<&Value>,
    expected_remaining: u64,
    unit: &str,
    _check: GuardCheck,
) -> Result<(u64, u64)> {
    let b: Bound = serde_json::from_value(plan.clone())?;
    let p = custody::evidence(&b)?;
    let d = Path::new(
        p["receipt_directory"]
            .as_str()
            .context("guard receipt directory")?,
    );
    let (sample_ref, observed) = live_guard_sample(d, &p, &b, unit)?;
    let scan = &observed["root_physical_observation"];
    let cap = capacity::n(&p, "maximum_root_physical_bytes")?;
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
        #[cfg(incident_guard_walk145_only)]
        if _check != GuardCheck::Running {
            let path = Path::new(p["worker_root"].as_str().context("guard root path")?);
            ensure!(path.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
                && path.metadata()?.dev() == Path::new("/home/sol").metadata()?.dev(),
                "guard root differs from its HOME booking");
            // A trip, expired receipt or changed plan during measurement must
            // also be rejected when churn prevents a complete allocation walk.
            let paid = guard_walk_allocation(
                path,
                guard_walk::lower_bound(path, cap),
                scan,
                || Ok(live_guard_sample(d, &p, &b, unit)?.1),
                _check,
            )?;
            let remaining = cap.checked_sub(paid).context("guard cap exceeded")?;
            return Ok((floor, remaining.saturating_sub(expected_remaining)));
        }
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
                    && (e.is::<capacity::TopologyTimeout>()
                        || (cfg!(incident_homefloor145_only)
                            && e.is::<crate::peer_terminal::Pending>())) =>
            {
                eprintln!("epoch145 waiting for a complete census: {e:#}");
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
        let next = refresh(&previous);
        #[cfg(incident_missed_clock145_only)]
        if next.as_ref().is_err_and(|e| e.is::<missed_clock::Pending>()) {
            // Read live guards, population, memory and physical HOME against the last paid
            // topology. This check cannot yield a price or resume a stopped worker.
            self.limits(0, GuardCheck::RegisteredHold)
                .map_err(|e| anyhow::anyhow!("live guard refused the registered hold: {e:#}"))?;
        }
        *self.capture.borrow_mut() = next?;
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
        self.limits(needed, GuardCheck::Running)
    }
    pub fn current_stopped(&self, needed: u64) -> Result<Value> {
        let check = if cfg!(incident_v5r_guard_recovery145_only) {
            GuardCheck::Stopped
        } else {
            GuardCheck::Running
        };
        self.limits(needed, check)
    }
    fn limits(&self, needed: u64, check: GuardCheck) -> Result<Value> {
        let last = self.capture.borrow();
        let s = &last.complete;
        ensure!(needed == 0, "frozen reader requested staging bytes");
        let age = last.captured.elapsed();
        if check != GuardCheck::RegisteredHold && age > Duration::from_secs(45) {
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
        #[cfg(incident_missed_clock145_only)]
        {
            let cover = &s["epoch159_donor_cover"];
            ensure!(cover["fleet"] == s["fleet"] && cover["credited_retirement_bytes"] == 0
                && cover["diagnostic"]["invocation_id"] == "fd406b11e15040cb9039dd9fdc48f63d",
                "missing reserved donor resources");
            required = required.max(capacity::n(cover, "native_home_required")?);
        }
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
                check,
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
                check,
            )?;
            // A new deficit can affect the original physical baseline and the independent new-generation spending calculation.
            required = required
                .checked_add(growth.checked_mul(2).context("baseline growth")?)
                .context("replacement growth")?;
            absolute = absolute.max(floor);
        }
        if !s["normal168"].is_null() {
            let row = &s["normal168"];
            ensure!(row["ordinary_canonical"] == true, "unadmitted 168");
            let admitted = custody::evidence(&serde_json::from_value(row["admission"].clone())?)?;
            let booking = &s["bookings"]["168"];
            let sample = if cfg!(any(incident_rejoin145_only, incident_post145_only)) {
                Some(
                    booking
                        .get("measured_guard")
                        .context("missing priced 168 native sample")?,
                )
            } else {
                None
            };
            let (floor, growth) = current_guard(
                &admitted["actual_guard_plan"],
                sample,
                capacity::n(booking, "remaining_bytes")?,
                admitted["producer_unit"].as_str().context("168 unit")?,
                check,
            )?;
            required = required.checked_add(growth).context("168 growth")?;
            absolute = absolute.max(floor);
        }
        if s["candidate136"]["occupied"] == true {
            let (floor, growth) = current136(&s["candidate136"])?;
            required = required.checked_add(growth).context("136 growth")?;
            absolute = absolute.max(floor);
        }
        required = required.max(absolute);
        let free = capacity::home()?.0;
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
        let mut charged = peers
            .chain(joined)
            .map(|(unit, row, baseline)| Ok((baseline?, unit, row)))
            .collect::<Result<Vec<_>>>()?;
        charged.sort_unstable_by_key(|(baseline, ..)| std::cmp::Reverse(*baseline));
        // Walking the same large address spaces every guard tick contends with
        // the verifier for its core. Unmeasured peers get zero resident credit.
        let credits = charged.into_iter().map(|(baseline, unit, row)| {
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
            Ok(pss
                .min(stat("anon ")? + stat("file_mapped ")?)
                .min(baseline)
                .min(68 << 30))
        });
        let (available, memory) = live_memory_budget(reserved_memory(s)?, credits, || {
            capacity::meminfo("MemAvailable:")
        })?;
        if active_population()? != actual {
            return Err(capacity::Reprice(
                "native population changed during the live guard".into(),
            )
            .into());
        }
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

fn current136(priced: &Value) -> Result<(u64, u64)> {
    // This timer writes per-invocation receipts with StandardOutput=null.
    let unit = joint_candidate::UNIT;
    let identity = &priced["identity"];
    let iid = identity["iid"].as_str().context("136 invocation")?;
    let owner = capacity::native_values(unit)?;
    let pid = owner["MainPID"]
        .as_str()
        .context("136 PID")?
        .parse::<u32>()?;
    let ticks = native::ticks(pid)?;
    let plan: Bound = serde_json::from_value(priced["guard_plan"].clone())?;
    let root = Path::new(joint_candidate::BASE136).join("reproduction");
    let floor = capacity::n(priced, "guard_floor")?;
    ensure!(
        plan.path == root.join("receipts/guard-plan.json"),
        "foreign 136 guard plan"
    );
    let g = custody::evidence(&plan)?;
    ensure!(
        priced["cap"] == joint_candidate::LIMIT
            && identity["unit"] == unit
            && owner["InvocationID"] == iid
            && custody::hex(iid, 32)
            && identity["processes"]
                .as_array()
                .is_some_and(|ps| ps.contains(&json!([pid, ticks])))
            && g["unit"] == unit
            && g["invocation_id"] == iid
            && g["minimum_free_bytes"] == floor
            && g["maximum_root_physical_bytes"] == joint_candidate::ROOT_CAP
            && g["worker_root"] == json!(root)
            && g["receipt_directory"] == json!(root.join("receipts/guard")),
        "different protected 136 admission"
    );
    let fire = joint_candidate::guard_fire(&plan, iid, pid, floor, false)?;
    if !fire.is_current()?
        || capacity::native_values(unit)? != owner
        || native::ticks(pid)? != ticks
    {
        return Err(capacity::GuardInFlight.into());
    }
    let remaining = capacity::n(priced, "remaining")?;
    ensure!(
        (joint_candidate::LIMIT - joint_candidate::ROOT_CAP..=joint_candidate::LIMIT)
            .contains(&remaining),
        "136 booking outside its paid range"
    );
    Ok((floor, remaining136(&fire.sample)?.saturating_sub(remaining)))
}

fn remaining136(sample: &Value) -> Result<u64> {
    let scan = &sample["root_physical_observation"];
    let cap = joint_candidate::ROOT_CAP;
    ensure!(
        sample["maximum_root_physical_bytes"] == cap
            && scan["maximum_physical_bytes"] == cap
            && scan["exceeds_budget"] == false,
        "different 136 subtree guard"
    );
    let first = capacity::n(&scan["first"], "physical_bytes")?;
    let second = capacity::n(&scan["second"], "physical_bytes")?;
    ensure!(
        first <= cap && second <= cap,
        "invalid 136 physical measurement"
    );
    let stable_first = capacity::n(&scan["first"], "vanished_entries")? == 0;
    let stable_second = capacity::n(&scan["second"], "vanished_entries")? == 0;
    let realized = if stable_first && stable_second {
        first.min(second)
    } else {
        0
    };
    Ok(joint_candidate::LIMIT - realized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(incident_timeout145_only, incident_timeout_post145_only))]
    #[test]
    fn monitored_pid1_timeouts_accept_both_sealed_manager_frames() {
        let provider = "/sealed/provider/post-stop-fit";
        let unit = "horizon-qualify-172-full-half-core-20261120-v1.service";
        let trace = format!(
            "Traceback (most recent call last):\n  File \"{provider}\", line 2117, in <module>\n  File \"/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1/session-v4-registered136/status168.py\", line 61, in show\n  File \"/usr/lib/python3.12/subprocess.py\", line 1253, in _check_timeout\n    raise TimeoutExpired(\nsubprocess.TimeoutExpired: Command '['/usr/bin/systemctl', 'show', '-p', 'Id,LoadState,ActiveState,SubState,InvocationID,Description,MainPID,StartLimitAction,ControlPID,ControlGroup,Job,NRestarts,Triggers,TriggeredBy,Result,ExecMainStatus,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec', '{unit}']' timed out after 10 seconds\n"
        );
        assert_eq!(manager_timeout(&trace, provider), Some(unit));
        let original = trace.replace("session-v4-registered136", "session-v3");
        assert_eq!(manager_timeout(&original, provider), Some(unit));
        let current167 = "horizon-qualify-167-source-index-v3-20261122.service";
        let trace167 = trace.replace(unit, current167);
        assert_eq!(manager_timeout(&trace167, provider), Some(current167));
        for changed in [
            trace.replace("session-v4-registered136", "unsealed"),
            trace.replace(unit, "horizon-unregistered.service"),
            trace.replace("'show'", "'stop'"),
            trace.replace("after 10 seconds", "after 11 seconds"),
        ] {
            assert_eq!(manager_timeout(&changed, provider), None);
        }
        assert_eq!(manager_timeout(&trace, "/unsealed/post-stop-fit"), None);
    }

    #[cfg(incident_guard_walk145_only)]
    #[test]
    fn capacity_pressure_requires_the_exact_sealed_provider_and_donor_frames() {
        let provider = "/sealed/fit/post-stop-fit";
        let trace = format!(
            "Traceback (most recent call last):\n  File \"{provider}\", line 1320, in <module>\n  File \"{provider}\", line 1260, in capture\n  File \"/sealed/fit/build_159_price.py\", line 150, in cover\nValueError: insufficient HOME or general-slot memory\n"
        );
        assert_eq!(retained_donor_pressure(&trace, provider), Some(""));
        let detail = "home_shortfall_bytes=1 memory_shortfall_bytes=0";
        let with_detail = format!("epoch145 donor capacity: {detail}\n{trace}");
        assert_eq!(
            retained_donor_pressure(&with_detail, provider),
            Some(detail)
        );
        assert!(
            retained_donor_pressure(
                &with_detail.replace("memory_shortfall_bytes=0", "memory_shortfall_bytes=unknown"),
                provider
            )
            .is_none()
        );
        assert!(
            retained_donor_pressure(
                &trace.replace(
                    "/sealed/fit/build_159_price.py",
                    "/unsealed/build_159_price.py"
                ),
                provider
            )
            .is_none()
        );
        assert!(
            retained_donor_pressure(&trace.replace(", in cover", ", in snapshot"), provider)
                .is_none()
        );
        assert!(
            retained_donor_pressure(
                &trace.replace(
                    "insufficient HOME or general-slot memory",
                    "different donor or producer topology"
                ),
                provider
            )
            .is_none()
        );
    }
    #[cfg(incident_five_lane145_only)]
    #[test]
    #[ignore = "requires both root-owned production park plans"]
    fn both_exact_park_terminals_and_retirements_precede_handoff() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        fs::create_dir(state.join("retirements")).unwrap();
        fs::create_dir(state.join("receipts")).unwrap();
        let mut price = json!({});
        let mut finals = Vec::new();
        let iid = "1".repeat(32);
        let mut expected = Vec::new();
        for (label, field) in [
            ("166-retry10", "registered_retry11_holding"),
            ("168-full-metered", "registered_cold168_holding"),
        ] {
            let path = Path::new(RUNTIME).join(format!(
                "epoch{label}-holding-20261122-v1/package/plan.json"
            ));
            let (pr, plan) = original(&path, 1 << 20).unwrap();
            let unit = format!("horizon-closed{label}-park-20261122-v1.service");
            let start = json!({"path":"fixture-start","sha256":"3".repeat(64)});
            let custody = json!({"path":"fixture-custody","sha256":"4".repeat(64)});
            price[field] = json!({"stage":"completed-copy","unit":unit,"invocation_id":iid,"start":start,
                "restore_overlap_bytes":plan["length"],"additional_reservation_bytes":0,"resource_credit_bytes":0});
            let terminal = state
                .join("receipts")
                .join(format!("epoch{label}-park-terminal-{iid}.json"));
            let proof = json!({"schema":format!("horizon-closed{label}-park-terminal-v1"),"unit":unit,"start":start,"invocation_id":iid,"custody":custody,"park_plan":pr});
            let write = |file: &Path, v: &Value| {
                use std::os::unix::fs::PermissionsExt;
                fs::write(file, serde_json::to_vec(v).unwrap()).unwrap();
                fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
            };
            write(&terminal, &proof);
            let (terminal_ref, _) = original(&terminal, 1 << 20).unwrap();
            let quarantine = state.join("retirements").join(format!(
                "epoch{label}-{}.jet",
                plan["sha256"].as_str().unwrap()
            ));
            expected.extend([
                PathBuf::from(plan["source"].as_str().unwrap()),
                quarantine.clone(),
            ]);
            let receipt = state
                .join("retirements")
                .join(format!("epoch{label}-completion.json"));
            let completed = json!({"schema":format!("jetstreamer-holding-retire{label}-completion-v1"),
                "authenticated_custody_revalidated":true,"actual_free_delta_claimed":false,"resource_credit_bytes":0,
                "source_absent":true,"quarantine_absent":true,
                "intent":{"source":plan["source"],"length":plan["length"],"sha256":plan["sha256"],"quarantine":quarantine,
                    "park_terminal":terminal_ref,"eligibility":plan["eligibility"],"custody":custody}});
            write(&receipt, &completed);
            finals.push((receipt, completed));
        }
        let visited = RefCell::new(Vec::new());
        assert_eq!(
            read_handback(&price, state, |p| {
                visited.borrow_mut().push(p.to_owned());
                Ok(())
            })
            .unwrap()
            .len(),
            2
        );
        assert_eq!(visited.into_inner(), expected);
        assert!(read_handback(&price, state, |_| anyhow::bail!("reappeared")).is_err());
        for (key, bad) in [
            ("stage", json!("copy-only")),
            ("resource_credit_bytes", json!(1)),
            ("invocation_id", json!("2".repeat(32))),
        ] {
            let mut changed = price.clone();
            changed["registered_cold168_holding"][key] = bad;
            assert!(read_handback(&changed, state, |_| Ok(())).is_err());
        }
        let (path, good) = &finals[1];
        for key in [
            "source_absent",
            "quarantine_absent",
            "authenticated_custody_revalidated",
        ] {
            let mut bad = good.clone();
            bad[key] = false.into();
            fs::write(path, serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(read_handback(&price, state, |_| Ok(())).is_err());
        }
        fs::remove_file(path).unwrap();
        assert!(read_handback(&price, state, |_| Ok(())).is_err());
    }

    #[cfg(any(incident_homefloor145_only, incident_v5j_post145_only))]
    #[test]
    fn complete_and_live_prices_keep_the_bounded_qualification() {
        let mut observed = json!({"bounded_qualification":null});
        assert_eq!(reserved_memory(&observed).unwrap(), HOST_MEMORY);
        observed["bounded_qualification"] = json!({"unit":"horizon-142-full-local-qualification-20261122-v1.service",
            "invocation_id":"42466cf599e7429889a778a68376c5ed","pid":227497,"memory_bytes":192u64<<20,
            "scratch_bytes":8u64<<20,"additional_cpu_quota_micros":0});
        assert_eq!(
            reserved_memory(&observed).unwrap(),
            HOST_MEMORY + (192 << 20)
        );
        observed["bounded_qualification"]["pid"] = 42.into();
        assert!(reserved_memory(&observed).is_err());

        observed["bounded_qualification"] = json!({
            "unit": "horizon-146-full-local-qualification-20261124-v1.service",
            "invocation_id": "d1ac6c5e9ae14769801d74c299f5a599",
            "pid": 42, "start_ticks": 12345,
            "memory_bytes": 192u64 << 20, "scratch_bytes": 8u64 << 20,
            "additional_cpu_quota_micros": 0,
            "registration": {
                "path": "/var/lib/jetstreamer/horizon_runtime_data/epoch146-singleton-20261122-v1/BOUNDED_ENTRY_LEASE.json",
                "sha256": "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
            }
        });
        assert_eq!(
            reserved_memory(&observed).unwrap(),
            HOST_MEMORY + (192 << 20)
        );
        observed["bounded_qualification"]["registration"] = Value::Null;
        assert!(reserved_memory(&observed).is_err());
    }
    #[test]
    fn private_136_keeps_the_unspent_reservation_outside_its_guarded_subtree() {
        let cap = joint_candidate::ROOT_CAP;
        let mut sample = json!({"maximum_root_physical_bytes":cap, "root_physical_observation":{
            "maximum_physical_bytes":cap, "exceeds_budget":false,
            "first":{"physical_bytes":cap,"vanished_entries":0},
            "second":{"physical_bytes":cap-4096,"vanished_entries":0}}});
        assert_eq!(remaining136(&sample).unwrap(), (8u64 << 30) + 4096);
        sample["root_physical_observation"]["first"]["vanished_entries"] = 1.into();
        assert_eq!(remaining136(&sample).unwrap(), 72u64 << 30);
        sample["root_physical_observation"]["second"]["physical_bytes"] = (cap + 1).into();
        assert!(remaining136(&sample).is_err());
    }
    #[test]
    fn live_memory_fit_stops_after_sufficient_measured_credit() {
        let mut measured = 0;
        let credits = [28, 25, 20].into_iter().map(|credit| {
            measured += 1;
            Ok(credit)
        });
        assert_eq!(
            live_memory_budget(100, credits, || Ok(60)).unwrap(),
            (60, 47)
        );
        assert_eq!(measured, 2);
        let unused = std::iter::once_with(|| panic!("already fits without a credit"));
        assert_eq!(
            live_memory_budget(100, unused, || Ok(100)).unwrap(),
            (100, 100)
        );
    }

    #[test]
    fn live_memory_fit_checks_all_available_credit_under_pressure() {
        let mut observations = [60, 55, 37].into_iter();
        let quote =
            live_memory_budget(100, [Ok(20), Ok(40)], || Ok(observations.next().unwrap())).unwrap();
        assert_eq!(quote, (37, 40));
        assert!(
            live_memory_budget(100, [Err(anyhow::anyhow!("unavailable credit"))], || Ok(60))
                .is_err()
        );
    }
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
        #[cfg(not(any(incident_homefloor145_only, incident_v5j_post145_only)))]
        for unit in [
            "horizon-qualify-172-full-half-core-20261120-v1.service",
            "horizon-qualify-166-independent-recovery-20261121-v1.service",
        ] {
            let ps = a.get(unit).unwrap();
            assert_eq!(ps.len(), 2);
            assert!(ps[0].0 != ps[1].0 && ps.iter().all(|p| p.1 > 0 && p.3 > 0));
        }
        #[cfg(any(incident_homefloor145_only, incident_v5j_post145_only))]
        {
            // The last cadence can predate a just-admitted producer. The sealed
            // provider prices those replacements and fingerprints every native PID.
            let price = PathBuf::from(std::env::var("INCIDENT_HOMEFLOOR_PRICE").unwrap());
            let (_, before) = original(&price, 32 << 20).unwrap();
            assert_eq!(before["fleet"], json!(binding));
            if cfg!(incident_v5j_retry1_post145_only) {
                let (directory, predecessor) = if cfg!(incident_v5r_136_post145_only) {
                    ("v5r-name-handoff", "cbacb5a17e6347509640846eccb95cb0")
                } else if cfg!(incident_v5q_136_post145_only) {
                    ("v5q-name-handoff", "c01dc3ba08b74e3aa0d4b531601e9fda")
                } else if cfg!(incident_v5o_136_post145_only) {
                    ("v5o-name-handoff", "f86e7e61f4b34dc7aedc4e08a128e713")
                } else if cfg!(incident_v5n_post145_only) {
                    ("v5n-name-handoff", "dba04d40f1b046b4875d7e27e0ff224a")
                } else if cfg!(incident_v5m_post145_only) {
                    ("v5m-name-handoff", "ff597d64ad37400ea5c6836336fb6706")
                } else if cfg!(incident_v5k_post145_only) {
                    ("v5k-name-handoff", "f2afc696a63a4e6aa6812451cf3559e5")
                } else {
                    ("v5j-name-handoff-retry1", "48ad7b2234d74e74b0498e7110e0aee3")
                };
                let handoff = Path::new(RUNTIME)
                    .join("epoch145-semantic-continuity-20261121-v1")
                    .join(directory);
                let (_, started) =
                    original(&handoff.join("submission-result.json"), 1 << 20).unwrap();
                let (_, intent) =
                    original(&handoff.join("submission-intent.json"), 16 << 20).unwrap();
                let (original, argv) = if cfg!(incident_v5r_136_post145_only) {
                    (&intent["incumbent"], &intent["successor_argv"])
                } else {
                    (&intent["original"], &intent["argv"])
                };
                assert_eq!(
                    original["InvocationID"]
                        .as_str()
                        .or_else(|| original["INVOCATION_ID"].as_str()),
                    Some(predecessor)
                );
                assert_eq!(argv, &started["argv"]);
                assert_eq!(before["phase145"]["stage"], "leased-worker");
                assert_eq!(
                    before["phase145"]["invocation_id"],
                    started["invocation_id"]
                );
                assert_ne!(started["invocation_id"], predecessor);
            } else if cfg!(incident_status_owner145_only) {
                let phase = &before["phase145"];
                let (iid, failed, recovered, terminal_key, terminal) =
                    if cfg!(incident_audit_turnover145_only) {
                        ("c01dc3ba08b74e3aa0d4b531601e9fda",
                         "fa6fb641253e22525916d591a39589c75b4d01aeda7bc04f58da7c5bf2936a67",
                         "49b5c68ca1217ecd89af0a11f1ea96f9abe1dbec454b52783c7a541b9fa7e3fc",
                         "public_audit_terminal",
                         "abda107d59f55823a92d3609cbc142dec21e7e63337d9b495f6f070dfe04de24")
                    } else {
                        ("f3474dfad55f4a05a64431421881db29",
                         "8b5c1b7024fec2fadbfedc14b59bd80bad97d3f3e98ee30f405f78d8c1798d27",
                         "e4b9e72a6481ea4f38b8fe7b49986463e2f93d37bc1dcb7f2156049930fd744b",
                         "status_owner_terminal",
                         "95fc24c89db925ca86fa1f918a6f61e665d3c124a7e4687ecf8ee44816b01f6f")
                    };
                assert_eq!(phase["InvocationID"], iid);
                assert_eq!(phase["failure"]["sha256"], failed);
                assert_eq!(phase["recovery"]["sha256"], recovered);
                assert_eq!(phase[terminal_key]["sha256"], terminal);
                assert_eq!(phase["candidate"]["inode"], 103237059u64);
                assert_eq!(phase["candidate"]["bytes"], 105_610_995_833u64);
                assert_eq!(phase["source_checkpoint_exists"], false);
                assert!(phase["retry_worker"].is_null());
                assert_eq!(before["status_registration"]["invocation_id"], "d6d40746a4974ca186acd7f2d5a5cac4");
                assert_eq!(
                    before["status_registration"]["consumer_seal"]["sha256"],
                    "a608208cd09681d366f0994dfc43406b4f8430330e13919a88b3af031efaf160"
                );
            } else if cfg!(incident_donor_pressure145_only) {
                let phase = &before["phase145"];
                assert_eq!(phase["InvocationID"], "f86e7e61f4b34dc7aedc4e08a128e713");
                assert_eq!(phase["failure"]["sha256"], "553c2d9be55bf4688dd1c8b42bc497ba2f6ea985305e42b7fb7db951f400bd36");
                assert_eq!(phase["recovery"]["sha256"], "dad6a11f67b7717668c0189c607142ac89a64fc7fde8971b28b4e3c8622619ed");
                assert_eq!(phase["candidate"]["inode"], 103237059u64);
                assert_eq!(phase["candidate"]["bytes"], 105_610_995_833u64);
                assert_eq!(phase["source_checkpoint_exists"], false);
                assert!(phase["retry_worker"].is_null());
            } else if cfg!(incident_guard_walk145_only) {
                let phase = &before["phase145"];
                assert_eq!(phase["InvocationID"], "dba04d40f1b046b4875d7e27e0ff224a");
                assert_eq!(phase["failure"]["sha256"], "8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010");
                assert_eq!(phase["rejected_guard"]["sha256"], "6800d34a8bb71f468d2f06daf6a29cf9016d972f4cc1ef60d915600e8085ad1f");
                assert_eq!(phase["candidate"]["bytes"], 105_610_995_833u64);
                assert!(phase["retry_worker"].is_null());
            } else if cfg!(incident_missed_clock145_only) {
                assert_eq!(before["phase145"]["InvocationID"], "ff597d64ad37400ea5c6836336fb6706");
                assert_eq!(before["phase145"]["failure"]["sha256"], "04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6");
                assert!(before["phase145"]["retry_worker"].is_null());
            } else if cfg!(incident_lease_start145_only) {
                assert_eq!(before["phase145"]["InvocationID"], "f2afc696a63a4e6aa6812451cf3559e5");
                assert_eq!(before["phase145"]["failure"]["sha256"], "eff2c5c0da6cb103890f6ced5cb11920959f637234567d7fd2382a2fca2fbcc7");
                assert!(before["phase145"]["retry_worker"].is_null());
            } else {
                assert_eq!(
                    before["phase145"]["InvocationID"],
                    "afcf6cdd1ec0400ea2757f81472987b3"
                );
            }
            let observed: BTreeMap<_, _> = a
                .iter()
                .map(|(unit, members)| {
                    assert!(members.iter().all(|p| p.1 > 0 && p.3 > 0));
                    (
                        unit,
                        members
                            .iter()
                            .map(|p| [u64::from(p.0), p.1])
                            .collect::<Vec<_>>(),
                    )
                })
                .collect();
            assert_eq!(before["population"], json!(observed));
        }
        assert!(
            current_guard(&json!({"path":p,"sha256":"f".repeat(64)}), None, 0, "bogus", GuardCheck::Running).is_err()
        );
    }
}
