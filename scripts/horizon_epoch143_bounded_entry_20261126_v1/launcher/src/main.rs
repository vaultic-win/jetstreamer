//! Keep one bounded epoch 143 process held until the sole fleet cadence registers it.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    ffi::CString,
    fs::{self, OpenOptions},
    io::{self, Read},
    mem::MaybeUninit,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{self, Command},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod release;

const UNIT: &str = "horizon-143-full-local-qualification-20261126-v1.service";
const GROUP: &str =
    "0::/horizonaudit.slice/horizon-143-full-local-qualification-20261126-v1.service";
const PREFLIGHT: &str = "/var/lib/jetstreamer/horizon-epoch143-bounded-entry-20261126-v1/static/STATIC_ENTRY_PREFLIGHT.json";
const PREFLIGHT_SHA: &str = env!("HORIZON_ENTRY143_PREFLIGHT_SHA");
const LEASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch143-bounded-entry-20261126-v1/BOUNDED_ENTRY_LEASE.json";
const PERMIT: &str =
    "/var/lib/jetstreamer/horizon-epoch143-bounded-entry-20261126-v1/state/RELEASE.json";
const FLEET: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const LEASE_SCHEMA: &str = "horizon-epoch143-bounded-entry-lease-v1";
const PERMIT_SCHEMA: &str = "horizon-epoch143-bounded-entry-release-v1";
const FILE_LIMIT: u64 = 2 << 20;
const SCRATCH_LIMIT: u64 = 8 << 20;
// Leave 160 seconds of the manager's eight-minute scope for the bounded probe.
const MAXIMUM_HOLD: Duration = Duration::from_secs(320);
const MAXIMUM_RECEIPT: u64 = 64 << 10;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    schema: String,
    unit: String,
    preflight: Bound,
    boot: String,
    invocation_id: String,
    pid: u32,
    start_ticks: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Permit {
    schema: String,
    lease_registration: Bound,
    lease_json: String,
    accepted_fleet: Bound,
}

#[derive(Deserialize)]
struct Mount {
    source: PathBuf,
    planned_target: PathBuf,
}

#[derive(Deserialize)]
struct Runtime {
    node: Bound,
    worker: Bound,
}

#[derive(Deserialize)]
struct Preflight {
    schema: String,
    planned_native_unit: String,
    planned_argv: Vec<String>,
    planned_environment: BTreeMap<String, String>,
    observed_mounts: Vec<Mount>,
    runtime: Runtime,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_lower_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && text.bytes().any(|c| c != b'0')
}

fn read_sealed(path: &Path) -> Result<Option<Vec<u8>>> {
    read_root_file(path, MAXIMUM_RECEIPT, 0o222)
}

fn read_root_file(path: &Path, maximum: u64, forbidden_mode: u32) -> Result<Option<Vec<u8>>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.mode() & forbidden_mode == 0
            && before.nlink() == 1
            && (1..=maximum).contains(&before.len()),
        "unsealed receipt {}",
        path.display()
    );
    let mut bytes = Vec::new();
    (&file).take(before.len() + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && (before.ctime(), before.ctime_nsec()) == (after.ctime(), after.ctime_nsec())
            && (named.dev(), named.ino(), named.ctime(), named.ctime_nsec())
                == (after.dev(), after.ino(), after.ctime(), after.ctime_nsec())
            && path.canonicalize()? == path,
        "receipt changed during read {}",
        path.display()
    );
    Ok(Some(bytes))
}

fn check_permit_directory() -> Result<()> {
    for directory in Path::new(PERMIT).ancestors().skip(1) {
        let metadata = fs::symlink_metadata(directory)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "untrusted release directory {}",
            directory.display()
        );
    }
    Ok(())
}

fn fs_state(path: &Path) -> Result<libc::statvfs> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    let mut state = MaybeUninit::uninit();
    // statvfs initializes all fields on success.
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), state.as_mut_ptr()) } == 0,
        "statvfs {}: {}",
        path.display(),
        io::Error::last_os_error()
    );
    Ok(unsafe { state.assume_init() })
}

fn identity() -> Result<Lease> {
    ensure!(
        unsafe { libc::geteuid() } == 1001 && unsafe { libc::getegid() } == 1003,
        "wrong bounded entry account"
    );
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == GROUP,
        "outside the bounded epoch 143 unit"
    );
    let invocation_id = env::var("INVOCATION_ID")?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(
        is_lower_hex(&invocation_id, 32) && is_lower_hex(&boot, 32),
        "missing bounded entry generation"
    );
    let proc_stat = fs::read_to_string("/proc/self/stat")?;
    let start_ticks = proc_stat
        .rsplit_once(')')
        .context("invalid process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing process start ticks")?
        .parse()?;
    ensure!(start_ticks > 0, "invalid process start ticks");
    Ok(Lease {
        schema: LEASE_SCHEMA.into(),
        unit: UNIT.into(),
        preflight: Bound {
            path: PREFLIGHT.into(),
            sha256: PREFLIGHT_SHA.into(),
        },
        pid: process::id(),
        start_ticks,
        invocation_id,
        boot,
    })
}

fn accept_permit(raw: &[u8], own: &Lease) -> Result<Bound> {
    let permit: Permit = serde_json::from_slice(raw)?;
    ensure!(
        permit.schema == PERMIT_SCHEMA
            && permit.lease_registration.path == Path::new(LEASE)
            && digest(permit.lease_json.as_bytes()) == permit.lease_registration.sha256,
        "different release or lease binding"
    );
    let lease: Lease = serde_json::from_str(&permit.lease_json)?;
    ensure!(&lease == own, "release names a different held invocation");
    check_fleet_binding(&permit.accepted_fleet)?;
    Ok(permit.accepted_fleet)
}

fn check_fleet_binding(fleet: &Bound) -> Result<()> {
    let directory = fleet.path.parent().context("no accepted fleet directory")?;
    ensure!(
        directory.parent() == Some(Path::new(FLEET))
            && directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|name| name.starts_with("root"))
            && fleet.path.file_name().and_then(|s| s.to_str())
                == Some("ROOT_COMPLETE_OPERATIONAL_FLEET.json")
            && is_lower_hex(&fleet.sha256, 64),
        "release lacks the accepted fleet binding"
    );
    Ok(())
}

fn verify_inputs(plan: &Preflight) -> Result<()> {
    let mut limit = MaybeUninit::uninit();
    ensure!(
        unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, limit.as_mut_ptr()) } == 0,
        "read bounded file limit"
    );
    let limit = unsafe { limit.assume_init() };
    ensure!(
        (limit.rlim_cur, limit.rlim_max) == (FILE_LIMIT, FILE_LIMIT),
        "wrong bounded file limit"
    );
    ensure!(
        plan.observed_mounts.len() == 3,
        "different bounded input roster"
    );
    for binding in &plan.observed_mounts {
        let source = fs::metadata(&binding.source)?;
        let target = fs::metadata(&binding.planned_target)?;
        ensure!(
            source.is_file()
                && target.is_file()
                && (target.dev(), target.ino()) == (source.dev(), source.ino())
                && fs_state(&binding.planned_target)?.f_flag & libc::ST_RDONLY != 0,
            "bounded input binding changed {}",
            binding.planned_target.display()
        );
    }
    let parent = Path::new(&plan.planned_argv[2])
        .parent()
        .context("no scratch parent")?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let scratch = fs_state(parent)?;
    ensure!(
        mounts.lines().any(|line| {
            line.split_once(" - ").is_some_and(|(before, after)| {
                before.split_whitespace().nth(4) == parent.to_str()
                    && after.split_whitespace().next() == Some("tmpfs")
            })
        }) && scratch.f_frsize.checked_mul(scratch.f_blocks) == Some(SCRATCH_LIMIT),
        "wrong bounded temporary filesystem"
    );
    ensure!(
        fs_state(&plan.runtime.worker.path)?.f_flag & libc::ST_NOEXEC != 0,
        "historical worker is executable in bounded entry"
    );
    Ok(())
}

fn verify_node(node: &Bound) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&node.path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.mode() & 0o222 == 0
            && (1..=128 << 20).contains(&before.len()),
        "unsealed bounded node"
    );
    let mut hash = Sha256::new();
    let read = io::copy(&mut (&mut file).take(before.len() + 1), &mut hash)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(&node.path)?;
    ensure!(
        read == before.len()
            && format!("{:x}", hash.finalize()) == node.sha256
            && (before.ctime(), before.ctime_nsec()) == (after.ctime(), after.ctime_nsec())
            && (named.dev(), named.ino(), named.ctime(), named.ctime_nsec())
                == (after.dev(), after.ino(), after.ctime(), after.ctime_nsec()),
        "bounded node image changed"
    );
    Ok(())
}

fn event(phase: &str, own: &Lease, started: Instant, detail: serde_json::Value) -> Result<()> {
    println!(
        "{}",
        json!({
            "phase": phase, "epoch": 143, "identity": own, "detail": detail,
            "unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "elapsed_seconds": started.elapsed().as_secs()
        })
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "--issue-release") {
        return release::issue(&args[1..]);
    }
    let started = Instant::now();
    ensure!(args.is_empty(), "unexpected bounded entry argument");
    let own = identity()?;
    let raw = read_sealed(Path::new(PREFLIGHT))?.context("missing bounded preflight")?;
    ensure!(digest(&raw) == PREFLIGHT_SHA, "different bounded preflight");
    let plan: Preflight = serde_json::from_slice(&raw)?;
    ensure!(
        plan.schema == "horizon-epoch143-bounded-static-entry-v1"
            && plan.planned_native_unit == UNIT
            && plan.planned_argv.len() == 8
            && plan.planned_argv[1] == "143"
            && plan.planned_argv[3] == "--verify"
            && plan.planned_argv[4] == "--root-checkpoint-cohort"
            && plan.planned_argv[6]
                == "--cohort-manifest-fingerprint=sha256:802ce7ae600d5942e1d7e73c66e845a550628a60bf5bdcb519cdeb57e8445fcf"
            && Path::new(&plan.planned_argv[0]) == plan.runtime.node.path,
        "different bounded entry route"
    );
    verify_inputs(&plan)?;
    verify_node(&plan.runtime.node)?;
    check_permit_directory()?;
    event(
        "held",
        &own,
        started,
        json!({"maximum_hold_seconds": MAXIMUM_HOLD.as_secs()}),
    )?;
    let mut heartbeat = started + Duration::from_secs(60);
    let deadline = started + MAXIMUM_HOLD;
    let fleet = loop {
        let now = Instant::now();
        ensure!(now < deadline, "bounded entry release expired");
        if let Some(permit) = read_sealed(Path::new(PERMIT))? {
            break accept_permit(&permit, &own)?;
        }
        if now >= heartbeat {
            event(
                "waiting_for_fleet_release",
                &own,
                started,
                json!({"remaining_seconds": (deadline - now).as_secs()}),
            )?;
            heartbeat += Duration::from_secs(60);
        }
        thread::sleep(Duration::from_millis(200));
    };
    verify_inputs(&plan)?;
    verify_node(&plan.runtime.node)?;
    ensure!(
        identity()? == own && Instant::now() < deadline,
        "bounded entry identity or release window changed"
    );
    event("released", &own, started, json!({"fleet": fleet}))?;
    let result = Command::new(&plan.runtime.node.path)
        .args(&plan.planned_argv[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("INVOCATION_ID", &own.invocation_id)
        .envs(&plan.planned_environment)
        .exec();
    Err(result).context("exec bounded epoch 143 node")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> Lease {
        Lease {
            schema: LEASE_SCHEMA.into(),
            unit: UNIT.into(),
            preflight: Bound {
                path: PREFLIGHT.into(),
                sha256: PREFLIGHT_SHA.into(),
            },
            boot: "7".repeat(32),
            invocation_id: "8".repeat(32),
            pid: 100,
            start_ticks: 10,
        }
    }

    fn permit(lease: &Lease) -> serde_json::Value {
        let lease_json = serde_json::to_string_pretty(lease).unwrap() + "\n";
        json!({
            "schema": PERMIT_SCHEMA,
            "lease_registration": {"path": LEASE, "sha256": digest(lease_json.as_bytes())},
            "lease_json": lease_json,
            "accepted_fleet": {
                "path": format!("{FLEET}/root-fixture/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                "sha256": "a".repeat(64)
            }
        })
    }

    #[test]
    fn accepts_the_exact_held_generation_and_accepted_fleet() {
        let own = lease();
        let release = permit(&own);
        let accepted = accept_permit(&serde_json::to_vec(&release).unwrap(), &own).unwrap();
        assert_eq!(accepted.sha256, "a".repeat(64));
    }

    #[test]
    fn rejects_crossed_leases_even_with_matching_lease_digests() {
        let own = lease();
        let mut wrong = lease();
        wrong.invocation_id = "9".repeat(32);
        assert!(accept_permit(&serde_json::to_vec(&permit(&wrong)).unwrap(), &own).is_err());
        let mut wrong = lease();
        wrong.start_ticks += 1;
        assert!(accept_permit(&serde_json::to_vec(&permit(&wrong)).unwrap(), &own).is_err());
    }

    #[test]
    fn rejects_altered_lease_bytes_and_foreign_fleet_paths() {
        let own = lease();
        let mut release = permit(&own);
        release["lease_registration"]["sha256"] = json!("b".repeat(64));
        assert!(accept_permit(&serde_json::to_vec(&release).unwrap(), &own).is_err());
        let mut release = permit(&own);
        release["accepted_fleet"]["path"] = json!("/tmp/ROOT_COMPLETE_OPERATIONAL_FLEET.json");
        assert!(accept_permit(&serde_json::to_vec(&release).unwrap(), &own).is_err());
    }
}
