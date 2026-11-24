//! Release only a fleet-registered, capacity-checked held process.
use super::*;
use std::{
    ffi::OsString,
    fs::File,
    io::Write,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
};

const ORIGINAL_145: &str = "horizon-holding-export145-20261121-v1.service";
const HOLDING_LOCK: &str =
    "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock";
const HOLDING_LOCK_ID: (u64, u64) = (64512, 95818311);
const MAXIMUM_QUOTE_AGE: u64 = 120;

#[derive(Deserialize)]
struct Fleet {
    epoch146_bounded_entry_lease: Bound,
}

#[derive(Deserialize)]
struct Fit {
    schema: String,
    fleet: Bound,
    fits: bool,
    resource_credit_bytes: u64,
    recorded_unix_seconds: u64,
    bounded_qualification: Qualification,
    #[serde(rename = "available_HOME_bytes")]
    available_home_bytes: u64,
    #[serde(rename = "complete_required_HOME_bytes")]
    required_home_bytes: u64,
    available_memory_bytes: u64,
    required_available_memory_bytes: u64,
}

#[derive(Deserialize, PartialEq, Eq)]
struct Qualification {
    unit: String,
    invocation_id: String,
    pid: u32,
    start_ticks: u64,
    memory_bytes: u64,
    scratch_bytes: u64,
    additional_cpu_quota_micros: u64,
    registration: Bound,
}

fn check_capacity(
    fit: &Fit,
    fleet: &Bound,
    lease: &Lease,
    registration: &Bound,
    now: u64,
) -> Result<()> {
    let expected = Qualification {
        unit: lease.unit.clone(),
        invocation_id: lease.invocation_id.clone(),
        pid: lease.pid,
        start_ticks: lease.start_ticks,
        memory_bytes: 192 << 20,
        scratch_bytes: SCRATCH_LIMIT,
        additional_cpu_quota_micros: 0,
        registration: registration.clone(),
    };
    ensure!(
        fit.schema == "horizon-incident-replay-fit-v1"
            && &fit.fleet == fleet
            && fit.bounded_qualification == expected
            && fit.fits
            && fit.resource_credit_bytes == 0,
        "capacity quote does not register this held lease"
    );
    ensure!(
        now.checked_sub(fit.recorded_unix_seconds)
            .is_some_and(|age| age <= MAXIMUM_QUOTE_AGE)
            && fit.available_home_bytes >= fit.required_home_bytes
            && fit.available_memory_bytes >= fit.required_available_memory_bytes,
        "capacity quote expired or has insufficient headroom"
    );
    Ok(())
}

fn read_bound(reference: &Bound, maximum: u64, forbidden_mode: u32) -> Result<Vec<u8>> {
    let raw = read_root_file(&reference.path, maximum, forbidden_mode)?
        .with_context(|| format!("missing evidence {}", reference.path.display()))?;
    ensure!(
        digest(&raw) == reference.sha256,
        "changed bound evidence {}",
        reference.path.display()
    );
    Ok(raw)
}

fn manager(unit: &str) -> Result<BTreeMap<String, String>> {
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "-p",
               "InvocationID,MainPID,ExecMainPID,ExecMainStartTimestampMonotonic,ControlGroup,ControlPID,ActiveState,SubState,Job,NRestarts,Result"])
        .output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty(),
        "cannot observe {unit}"
    );
    String::from_utf8(output.stdout)?
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').context("invalid manager output")?;
            Ok((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn idle_original_verifier() -> Result<()> {
    let state = manager(ORIGINAL_145)?;
    ensure!(
        matches!(state["ActiveState"].as_str(), "inactive" | "failed")
            && state["MainPID"] == "0"
            && state["ControlPID"] == "0"
            && state["Job"].is_empty(),
        "the original epoch 145 verifier still owns its guard"
    );
    Ok(())
}

fn locked_holding() -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(HOLDING_LOCK)?;
    let meta = lock.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && (meta.dev(), meta.ino()) == HOLDING_LOCK_ID
            && meta.mode() & 0o777 == 0o600
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "the original holding transition is occupied"
    );
    Ok(lock)
}

fn monotonic_micros() -> Result<u64> {
    let mut now = MaybeUninit::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, now.as_mut_ptr()) } == 0,
        "read monotonic clock"
    );
    let now = unsafe { now.assume_init() };
    Ok(u64::try_from(now.tv_sec)? * 1_000_000 + u64::try_from(now.tv_nsec)? / 1_000)
}

fn start_ticks(path: &Path) -> Result<u64> {
    let stat = fs::read_to_string(path.join("stat"))?;
    Ok(stat
        .rsplit_once(')')
        .context("invalid held process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing held start ticks")?
        .parse()?)
}

fn check_held(lease: &Lease) -> Result<u64> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(
        lease.schema == LEASE_SCHEMA
            && lease.unit == UNIT
            && lease.boot == boot
            && lease.pid > 1
            && is_lower_hex(&lease.invocation_id, 32)
            && lease.preflight.path == Path::new(PREFLIGHT)
            && lease.preflight.sha256 == PREFLIGHT_SHA,
        "lease inputs or generation changed"
    );
    let state = manager(UNIT)?;
    let group = GROUP.strip_prefix("0::").context("invalid held cgroup")?;
    ensure!(
        state["InvocationID"] == lease.invocation_id
            && state["MainPID"] == lease.pid.to_string()
            && state["ExecMainPID"] == state["MainPID"]
            && state["ControlPID"] == "0"
            && state["ActiveState"] == "active"
            && state["SubState"] == "running"
            && state["Job"].is_empty()
            && state["NRestarts"] == "0"
            && state["ControlGroup"] == group,
        "held unit changed"
    );
    let proc = Path::new("/proc").join(lease.pid.to_string());
    let exe = fs::metadata(proc.join("exe"))?;
    let own = fs::metadata("/proc/self/exe")?;
    ensure!(
        (exe.dev(), exe.ino()) == (own.dev(), own.ino())
            && own.uid() == 0
            && own.mode() & 0o222 == 0
            && start_ticks(&proc)? == lease.start_ticks
            && fs::read_to_string(proc.join("cgroup"))?.trim() == GROUP,
        "held launcher image or process identity changed"
    );
    let started: u64 = state["ExecMainStartTimestampMonotonic"].parse()?;
    ensure!(
        started > 0
            && monotonic_micros()?
                .checked_sub(started)
                .is_some_and(|age| u128::from(age) + 1_000_000 < MAXIMUM_HOLD.as_micros()),
        "held launch window expired"
    );
    ensure!(
        manager(UNIT)? == state,
        "held manager changed during release validation"
    );
    Ok(started)
}

fn publish_permit(permit: &Permit, lease: &Lease) -> Result<File> {
    check_permit_directory()?;
    let dest = Path::new(PERMIT);
    let parent = dest.parent().context("release directory")?;
    let staged = parent.join(format!(".release-{}-{}", lease.pid, lease.start_ticks));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(&staged)?;
    let publication = (|| -> Result<File> {
        serde_json::to_writer(&mut file, permit)?;
        file.write_all(b"\n")?;
        file.set_permissions(fs::Permissions::from_mode(0o444))?;
        file.sync_all()?;
        let directory = File::open(parent)?;
        directory.sync_all()?;
        let a = CString::new(staged.as_os_str().as_bytes())?;
        let b = CString::new(dest.as_os_str().as_bytes())?;
        // Keep the release single-link and never replace an earlier permit.
        ensure!(
            unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    a.as_ptr(),
                    libc::AT_FDCWD,
                    b.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "publish bounded release: {}",
            io::Error::last_os_error()
        );
        Ok(directory)
    })();
    if publication.is_err() && staged.is_file() {
        fs::remove_file(staged)?;
    }
    publication
}

fn await_terminal(lease: &Lease, started: u64) -> Result<()> {
    let until = started + 485_000_000;
    let mut heartbeat = Instant::now() + Duration::from_secs(60);
    let group = Path::new("/sys/fs/cgroup").join(GROUP.trim_start_matches("0::/"));
    loop {
        let state = manager(UNIT)?;
        let proc = Path::new("/proc").join(lease.pid.to_string());
        let drained = match fs::read_to_string(group.join("cgroup.procs")) {
            Ok(members) => members.split_whitespace().next().is_none(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        };
        if matches!(state["ActiveState"].as_str(), "inactive" | "failed")
            && state["MainPID"] == "0"
            && state["ControlPID"] == "0"
            && state["Job"].is_empty()
            && !proc.exists()
            && drained
        {
            println!(
                "{}",
                json!({"phase": "terminal", "epoch": 146, "invocation_id":lease.invocation_id,
                                   "manager_result":state["Result"]})
            );
            return Ok(());
        }
        ensure!(
            state["InvocationID"] == lease.invocation_id && monotonic_micros()? < until,
            "released scope changed generation or has not drained"
        );
        if Instant::now() >= heartbeat {
            println!(
                "{}",
                json!({"phase":"waiting_for_terminal","epoch":146,
                                   "invocation_id":lease.invocation_id,
                                   "manager_state":state["ActiveState"]})
            );
            heartbeat += Duration::from_secs(60);
        }
        thread::sleep(Duration::from_millis(500));
    }
}

pub(super) fn issue(args: &[OsString]) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 3,
        "usage: --issue-release ACCEPTED_FLEET FLEET_SHA256 FIT_SHA256 (root)"
    );
    let fleet = Bound {
        path: PathBuf::from(&args[0]),
        sha256: args[1].to_str().context("fleet SHA")?.into(),
    };
    check_fleet_binding(&fleet)?;
    let accepted: Fleet = serde_json::from_slice(&read_bound(&fleet, 16 << 20, 0o022)?)?;
    let registration = accepted.epoch146_bounded_entry_lease;
    ensure!(
        registration.path == Path::new(LEASE),
        "foreign epoch 146 lease path"
    );
    let lease_json = String::from_utf8(read_bound(&registration, MAXIMUM_RECEIPT, 0o222)?)?;
    let lease: Lease = serde_json::from_str(&lease_json)?;
    let quote = Bound {
        path: fleet.path.with_file_name("ENTRY146_RELEASE_FIT.json"),
        sha256: args[2].to_str().context("fit SHA")?.into(),
    };
    let fit: Fit = serde_json::from_slice(&read_bound(&quote, 4 << 20, 0o022)?)?;
    let now = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_secs())
    };
    check_capacity(&fit, &fleet, &lease, &registration, now()?)?;
    let _transition = locked_holding()?;
    idle_original_verifier()?;
    let started = check_held(&lease)?;
    check_capacity(&fit, &fleet, &lease, &registration, now()?)?;
    idle_original_verifier()?;
    let permit = Permit {
        schema: PERMIT_SCHEMA.into(),
        lease_registration: registration,
        lease_json,
        accepted_fleet: fleet,
    };
    let release_directory = publish_permit(&permit, &lease)?;
    let durable = release_directory.sync_all();
    println!(
        "{}",
        json!({"phase":"permit_issued","epoch":146,"invocation_id":lease.invocation_id,
                        "accepted_fleet":permit.accepted_fleet,"capacity_quote":quote})
    );
    let terminal = await_terminal(&lease, started);
    durable?;
    terminal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_a_fresh_compatible_quote_from_the_same_fleet() {
        let fleet = Bound {
            path: "/fixture/fleet.json".into(),
            sha256: "a".repeat(64),
        };
        let registration = Bound {
            path: LEASE.into(),
            sha256: "b".repeat(64),
        };
        let lease = Lease {
            schema: LEASE_SCHEMA.into(),
            unit: UNIT.into(),
            preflight: Bound {
                path: PREFLIGHT.into(),
                sha256: PREFLIGHT_SHA.into(),
            },
            boot: "7".repeat(32),
            invocation_id: "9".repeat(32),
            pid: 42,
            start_ticks: 150,
        };
        let mut fit: Fit = serde_json::from_value(json!({
            "schema": "horizon-incident-replay-fit-v1", "fleet": fleet,
            "fits": true, "resource_credit_bytes": 0, "recorded_unix_seconds": 1000,
            "bounded_qualification": {
                "unit": UNIT, "invocation_id": lease.invocation_id, "pid": lease.pid,
                "start_ticks": lease.start_ticks, "memory_bytes": 192 << 20,
                "scratch_bytes": SCRATCH_LIMIT, "additional_cpu_quota_micros": 0,
                "registration": registration
            },
            "available_HOME_bytes": 100, "complete_required_HOME_bytes": 100,
            "available_memory_bytes": 100, "required_available_memory_bytes": 100
        }))
        .unwrap();
        assert!(check_capacity(&fit, &fleet, &lease, &registration, 1001).is_ok());
        assert!(check_capacity(&fit, &fleet, &lease, &registration, 999).is_err());
        assert!(check_capacity(&fit, &fleet, &lease, &registration, 1121).is_err());
        fit.required_home_bytes += 1;
        assert!(check_capacity(&fit, &fleet, &lease, &registration, 1001).is_err());
        fit.required_home_bytes -= 1;
        fit.bounded_qualification.start_ticks += 1;
        assert!(check_capacity(&fit, &fleet, &lease, &registration, 1001).is_err());
        fit.bounded_qualification.start_ticks -= 1;
        fit.fleet.sha256 = "c".repeat(64);
        assert!(check_capacity(&fit, &fleet, &lease, &registration, 1001).is_err());
    }
}
