use anyhow::{Context, Result, bail, ensure};
use profile::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const HIGH: u64 = 100_000_000_000;
const VMAS: u64 = 3_500_000;
const PROCS: &str = "/proc";
const CGROUPS: &str = "/sys/fs/cgroup";

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MainBinding {
    main_pid: u32,
    executable: PathBuf,
    sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    invocation_id: String,
    filesystem: PathBuf,
    minimum_free_bytes: u64,
    worker_root: PathBuf,
    maximum_worker_vmas: u64,
    maximum_root_physical_bytes: u64,
    receipt_directory: PathBuf,
    native_main: MainBinding,
    boot_id: String,
    main_start_ticks: u64,
    #[serde(default)]
    bounded_canary: Option<Value>,
    #[serde(default)]
    bounded_measurement: Option<Value>,
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn boot() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}
fn trusted_parents(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical path"
    );
    for p in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted evidence parent"
        );
    }
    Ok(())
}
fn metadata_id(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn sealed(path: &Path, digest: &str, limit: u64) -> Result<Vec<u8>> {
    trusted_parents(path)?;
    ensure!(hex(digest, 64), "invalid digest");
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= limit,
        "unsafe sealed evidence"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        metadata_id(&before) == metadata_id(&f.metadata()?),
        "sealed open race"
    );
    let mut bytes = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit
            && sha(&bytes) == digest
            && metadata_id(&before) == metadata_id(&f.metadata()?)
            && metadata_id(&before) == metadata_id(&fs::symlink_metadata(path)?),
        "sealed evidence changed"
    );
    Ok(bytes)
}
fn receipt_dir(p: &Path) -> Result<()> {
    trusted_parents(p)?;
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "receipt directory custody"
    );
    Ok(())
}
fn persist(path: &Path, v: &Value) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    receipt_dir(parent)?;
    let mut f = tempfile::NamedTempFile::new_in(parent)?;
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(f.as_file_mut(), v)?;
    f.write_all(b"\n")?;
    f.as_file().sync_all()?;
    f.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("no-clobber receipt: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn prior(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(m) => {
            receipt_dir(path.parent().context("private parent")?)?;
            ensure!(
                m.is_file()
                    && m.uid() == 0
                    && m.nlink() == 1
                    && m.mode() & 0o077 == 0
                    && m.len() <= 2 << 20
                    && path.canonicalize()? == path,
                "unsafe prior receipt"
            );
            let b = fs::read(path)?;
            ensure!(
                metadata_id(&m) == metadata_id(&fs::symlink_metadata(path)?),
                "prior receipt changed"
            );
            Ok(Some(serde_json::from_slice(&b)?))
        }
    }
}
fn validate(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-standalone-guard-plan-v1"
            && p.unit == UNIT
            && hex(&p.invocation_id, 32)
            && p.filesystem == Path::new(FILESYSTEM)
            && p.minimum_free_bytes > 0
            && p.worker_root == Path::new(ROOT)
            && p.maximum_worker_vmas == VMAS
            && p.maximum_root_physical_bytes == ROOT_CAP
            && p.native_main.main_pid > 1
            && p.native_main.executable == Path::new(HARNESS)
            && p.native_main.sha256 == HARNESS_SHA
            && p.main_start_ticks > 0
            && p.boot_id.len() == 36
            && p.bounded_canary.is_none()
            && p.bounded_measurement.is_none()
            && p.receipt_directory == Path::new(&format!("{}{}", RECEIPT_PREFIX, p.invocation_id)),
        "closed native guard profile differs"
    );
    Ok(())
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct Unit {
    load_state: String,
    invocation_id: String,
    active: String,
    sub: String,
    result: String,
    restarts: u64,
    restart_policy: String,
    kill_mode: String,
    delegated: bool,
    cgroup: String,
    pid: u32,
    control_pid: u32,
    exec_main_code: u32,
    exec_main_status: i32,
    memory_max: String,
    memory_high: String,
    memory_swap_max: String,
    tasks_max: String,
}
fn systemctl(args: &[&str]) -> Result<Vec<u8>> {
    let o = Command::new("/usr/bin/timeout")
        .args(["--signal=KILL", "5s", "/usr/bin/systemctl"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 64 << 10 && o.stderr.len() <= 64 << 10,
        "systemctl failed/bound exceeded"
    );
    Ok(o.stdout)
}
fn unit() -> Result<Unit> {
    let b = systemctl(&[
        "show",
        UNIT,
        "--property=Id,LoadState,InvocationID,ActiveState,SubState,Result,NRestarts,Restart,KillMode,Delegate,ControlGroup,MainPID,ControlPID,ExecMainCode,ExecMainStatus,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax",
    ])?;
    let mut rows = BTreeMap::new();
    for line in std::str::from_utf8(&b)?.lines() {
        let (k, v) = line.split_once('=').context("unit property")?;
        ensure!(rows.insert(k, v).is_none(), "duplicate property");
    }
    let get = |k| rows.get(k).copied().with_context(|| format!("missing {k}"));
    ensure!(get("Id")? == UNIT, "wrong unit");
    Ok(Unit {
        load_state: get("LoadState")?.into(),
        invocation_id: get("InvocationID")?.into(),
        active: get("ActiveState")?.into(),
        sub: get("SubState")?.into(),
        result: get("Result")?.into(),
        restarts: get("NRestarts")?.parse()?,
        restart_policy: get("Restart")?.into(),
        kill_mode: get("KillMode")?.into(),
        delegated: get("Delegate")? != "no",
        cgroup: get("ControlGroup")?.into(),
        pid: get("MainPID")?.parse()?,
        control_pid: get("ControlPID")?.parse()?,
        exec_main_code: get("ExecMainCode")?.parse()?,
        exec_main_status: get("ExecMainStatus")?.parse()?,
        memory_max: get("MemoryMax")?.into(),
        memory_high: get("MemoryHigh")?.into(),
        memory_swap_max: get("MemorySwapMax")?.into(),
        tasks_max: get("TasksMax")?.into(),
    })
}
fn bound_state(u: &Unit, p: &Plan, actual_boot: &str) -> Result<()> {
    ensure!(
        u.load_state == "loaded"
            && u.invocation_id == p.invocation_id
            && u.restarts == 0
            && u.restart_policy == "no"
            && u.kill_mode == "control-group"
            && !u.delegated
            && actual_boot == p.boot_id,
        "producer generation or boot changed; refuse to signal"
    );
    Ok(())
}
fn bound(u: &Unit, p: &Plan) -> Result<()> {
    bound_state(u, p, &boot()?)
}
fn active(u: &Unit) -> bool {
    matches!(u.active.as_str(), "active" | "activating" | "deactivating")
}
fn cgroup() -> PathBuf {
    Path::new(CGROUPS).join("system.slice").join(UNIT)
}
fn kernel_memory_cap(configured: u64, page_size: i64) -> Result<u64> {
    let page = u64::try_from(page_size).context("invalid native page size")?;
    ensure!(
        page.is_power_of_two() && configured >= page,
        "invalid memory page/cap"
    );
    Ok(configured / page * page)
}
fn memory(u: &Unit) -> Result<Value> {
    ensure!(
        u.memory_max == MEMORY.to_string()
            && u.memory_high == HIGH.to_string()
            && u.memory_swap_max == "0"
            && u.tasks_max == "512",
        "PID1 limits changed"
    );
    let c = cgroup();
    let read = |n: &str| -> Result<u64> { Ok(fs::read_to_string(c.join(n))?.trim().parse()?) };
    let max = read("memory.max")?;
    let high = read("memory.high")?;
    let swapmax = read("memory.swap.max")?;
    let current = read("memory.current")?;
    let swap = read("memory.swap.current")?;
    let tasks = read("pids.current")?;
    ensure!(
        max == kernel_memory_cap(MEMORY, unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?
            && high == kernel_memory_cap(HIGH, unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?
            && swapmax == 0
            && read("pids.max")? == 512
            && current <= MEMORY
            && swap == 0
            && tasks <= 512,
        "kernel resource bound differs/exceeded"
    );
    let events = fs::read_to_string(c.join("memory.events"))?;
    let mut parsed = BTreeMap::new();
    for line in events.lines() {
        let mut s = line.split_whitespace();
        let k = s.next().context("event key")?;
        let v = s.next().context("event count")?.parse::<u64>()?;
        ensure!(
            s.next().is_none() && parsed.insert(k, v).is_none(),
            "event syntax"
        );
    }
    for key in ["oom", "oom_kill", "oom_group_kill"] {
        ensure!(
            parsed.get(key) == Some(&0),
            "memory OOM event or missing counter"
        );
    }
    Ok(
        json!({"maximum_bytes":max,"high_bytes":high,"current_bytes":current,"swap_bytes":swap,"tasks":tasks,"events":parsed}),
    )
}
fn token(p: &Plan, plan_sha: &str) -> Result<bool> {
    let path = Path::new(TOKEN_ROOT)
        .join(&p.invocation_id)
        .join("guard-admission.json");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
        Ok(_) => (),
    }
    let d = path.with_file_name("guard-admission.sha256");
    trusted_parents(&d)?;
    let bytes = fs::read(&d)?;
    ensure!(bytes.len() == 65, "token digest length");
    sealed(&d, &sha(&bytes), 65)?;
    let t: Value =
        serde_json::from_slice(&sealed(&path, std::str::from_utf8(&bytes)?.trim(), 65536)?)?;
    ensure!(
        t["schema"] == TOKEN_SCHEMA
            && t["unit"] == UNIT
            && t["invocation_id"] == p.invocation_id
            && t["main_pid"] == p.native_main.main_pid
            && t["boot_id"] == p.boot_id
            && t["guard_plan"]["sha256"] == plan_sha
            && t["harness"]["path"] == HARNESS
            && t["harness"]["sha256"] == HARNESS_SHA,
        "foreign startup token"
    );
    Ok(true)
}
fn available() -> Result<u64> {
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(std::ffi::CString::new(FILESYSTEM)?.as_ptr(), &mut s) } == 0,
        "statvfs failed"
    );
    s.f_bavail
        .checked_mul(s.f_frsize)
        .context("free bytes overflow")
}
fn root_observe(p: &Plan, plan_sha: &str) -> Result<root_budget::Observation> {
    let m = fs::symlink_metadata(&p.worker_root)?;
    ensure!(
        m.is_dir()
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o777 == 0o700
            && p.worker_root.canonicalize()? == p.worker_root,
        "native root custody changed"
    );
    let v = json!({"schema":ROOT_PIN,"plan_sha256":plan_sha,
        "producer_invocation_id":p.invocation_id,"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode()});
    let path = p.receipt_directory.join("root-pin.json");
    match prior(&path)? {
        Some(old) => ensure!(old == v, "native root replaced"),
        None => persist(&path, &v)?,
    }
    root_budget::observe(&p.worker_root, ROOT_CAP)
}
fn run(args: &[String]) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        matches!(args.len(), 6 | 7)
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && (args.len() == 6 || args[6] == "--validate-plan-only"),
        "usage: guard PLAN --plan-sha256 SHA --self-sha256 SHA [--validate-plan-only]"
    );
    let exe = fs::canonicalize("/proc/self/exe")?;
    sealed(&exe, &args[5], 64 << 20)?;
    ensure!(
        metadata_id(&fs::metadata("/proc/self/exe")?) == metadata_id(&fs::symlink_metadata(&exe)?),
        "mapped guard changed"
    );
    let p: Plan = serde_json::from_slice(&sealed(Path::new(&args[1]), &args[3], 65536)?)?;
    validate(&p)?;
    if args.len() == 7 {
        println!(
            "{}",
            json!({"schema":STATIC,"validated":true,"plan_sha256":args[3],"resource_samples_taken":0,"protective_guard_proven":false,"replay_launch_authorized":false,"remote_mutations":false})
        );
        return Ok(());
    }
    receipt_dir(&p.receipt_directory)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p.receipt_directory.join("guard.lock"))?;
    let lm = lock.metadata()?;
    ensure!(
        lm.is_file() && lm.uid() == 0 && lm.nlink() == 1 && lm.mode() & 0o077 == 0,
        "unsafe guard lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "concurrent guard"
    );
    let gid = std::env::var("INVOCATION_ID")?;
    ensure!(
        hex(&gid, 32) && gid != p.invocation_id,
        "guard invocation differs"
    );
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{GUARD_UNIT}"),
        "guard cgroup differs"
    );
    let before = unit()?;
    bound(&before, &p)?;
    let recorded = now()?;
    let intent_path = p.receipt_directory.join("stop-intent.json");
    let intent = prior(&intent_path)?;
    if let Some(ref i) = intent {
        ensure!(
            i["plan_sha256"] == args[3] && i["producer_invocation_id"] == p.invocation_id,
            "foreign stop intent"
        );
    }
    if !active(&before) {
        ensure!(
            before.pid == 0
                && before.control_pid == 0
                && matches!(before.active.as_str(), "inactive" | "failed"),
            "unclassified terminal state"
        );
        let drain = processes::drain(&p, &args[3]);
        let drain_error = drain.as_ref().err().map(ToString::to_string);
        let drain = drain.ok();
        let after = unit()?;
        bound(&after, &p)?;
        ensure!(before == after, "terminal owner changed");
        let v = json!({"schema":TERMINAL,"recorded_unix_seconds":recorded,"plan_sha256":args[3],"guard_sha256":args[5],"guard_invocation_id":gid,"producer_invocation_id":p.invocation_id,"terminal":after,"drain":drain,"drain_error":drain_error,"prior_stop_intent":intent,"native_qualification_authorized":false,"resource_release_authorized":false,"remote_mutations":false,"r2_mutations":false,"scratch_deleted":false});
        persist(
            &p.receipt_directory.join(format!("terminal-{gid}.json")),
            &v,
        )?;
        println!("{v}");
        ensure!(
            drain_error.is_none(),
            "terminal drain failed; diagnostic retained"
        );
        return Ok(());
    }
    let observed = (|| -> Result<_> {
        ensure!(
            before.pid == p.native_main.main_pid
                && before.control_pid == 0
                && before.cgroup == format!("/system.slice/{UNIT}"),
            "actual owner differs"
        );
        let t = token(&p, &args[3])?;
        processes::observe(&p, &args[3], t)
    })();
    let worker_error = observed.as_ref().err().map(ToString::to_string);
    let process = observed.ok();
    let workers = process
        .as_ref()
        .map(|v| v["workers"].clone())
        .unwrap_or(json!([]));
    let resource = memory(&before);
    let memory_error = resource.as_ref().err().map(ToString::to_string);
    let resource = resource.ok();
    let free = available();
    let free_error = free.as_ref().err().map(ToString::to_string);
    let free = free.ok();
    let root = root_observe(&p, &args[3]);
    let root_error = root.as_ref().err().map(ToString::to_string);
    let root = root.ok();
    let reason = if intent.is_some() {
        Some("resume-stop-intent")
    } else if worker_error.is_some() {
        Some("worker-observation-failed")
    } else if memory_error.is_some() {
        Some("memory-envelope-failed")
    } else if free_error.is_some() {
        Some("filesystem-observation-failed")
    } else if free.is_some_and(|b| b < p.minimum_free_bytes) {
        Some("filesystem-floor")
    } else if root_error.is_some() {
        Some("root-observation-failed")
    } else if root.as_ref().is_some_and(|r| r.exceeds_budget) {
        Some("root-physical-budget")
    } else {
        None
    };
    let after = unit()?;
    bound(&after, &p)?;
    // A natural terminal transition is retained as a separate diagnostic; it is
    // never promoted to the first no-trip sample and never signals a new owner.
    if before != after {
        persist(
            &p.receipt_directory.join(format!("transition-{gid}.json")),
            &json!({"schema":TRANSITION,"plan_sha256":args[3],"producer_invocation_id":p.invocation_id,"guard_invocation_id":gid,"before":before,"after":after,"process_observation":process,"memory":resource,"root":root,"trip_reason":reason,"native_qualification_authorized":false,"remote_mutations":false}),
        )?;
        // A changed live envelope is a trip, not a harmless observation race.
        // A natural terminal needs no signal; a replacement fails bound() above.
        if active(&after) {
            if intent.is_none() {
                persist(
                    &intent_path,
                    &json!({"schema":STOP_INTENT,
                    "plan_sha256":args[3],"producer_invocation_id":p.invocation_id,"guard_invocation_id":gid,
                    "reason":"producer-state-changed-during-sample","transition":format!("transition-{gid}.json"),"remote_mutations":false}),
                )?;
            }
            let latest = unit()?;
            bound(&latest, &p)?;
            if active(&latest) {
                ensure!(
                    latest.pid == p.native_main.main_pid
                        && processes::stat(Path::new(PROCS), latest.pid)?.1 == p.main_start_ticks,
                    "refuse transition signal to reused MainPID"
                );
                systemctl(&["stop", "--no-block", UNIT])?;
            }
        }
        bail!("producer changed during sample; transition evidence retained");
    }
    let v = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","recorded_unix_seconds":recorded,
        "plan":args[1],"plan_sha256":args[3],"guard_sha256":args[5],"guard_invocation_id":gid,"producer":after,
        "producer_invocation_id":p.invocation_id,"available_bytes":free,"minimum_free_bytes":p.minimum_free_bytes,
        "maximum_worker_vmas":VMAS,"producer_stop_enabled":true,"maximum_root_physical_bytes":ROOT_CAP,
        "root_physical_observation":root,"root_physical_observation_error":root_error,"workers":workers,"worker_observation_error":worker_error,
        "trip_reason":reason,"bounded_measurement":false,"bounded_canary":null,"canary_target_error":null,
        "target_handoff":null,"target_handoff_error":null,"native_main":p.native_main,
        "process_observation":process,"memory_observation":resource,"memory_observation_error":memory_error,"filesystem_observation_error":free_error,
        "remote_mutations":false,"r2_mutations":false,"scratch_deleted":false});
    persist(&p.receipt_directory.join(format!("sample-{gid}.json")), &v)?;
    if let Some(reason) = reason {
        if intent.is_none() {
            persist(
                &intent_path,
                &json!({"schema":STOP_INTENT,"plan_sha256":args[3],"producer_invocation_id":p.invocation_id,"guard_invocation_id":gid,"reason":reason,"sample":v,"remote_mutations":false}),
            )?;
        }
        let latest = unit()?;
        bound(&latest, &p)?;
        if active(&latest) {
            ensure!(
                latest.pid == p.native_main.main_pid
                    && processes::stat(Path::new(PROCS), latest.pid)?.1 == p.main_start_ticks,
                "refuse signal reused MainPID"
            );
            systemctl(&["stop", "--no-block", UNIT])?;
        }
        persist(
            &p.receipt_directory.join(format!("stop-request-{gid}.json")),
            &json!({"schema":STOP_REQUEST,"plan_sha256":args[3],"producer_invocation_id":p.invocation_id,"guard_invocation_id":gid,"drain_proven":false,"remote_mutations":false}),
        )?;
        bail!("protective stop requested: {reason}");
    }
    println!("{v}");
    Ok(())
}
fn main() {
    if let Err(e) = run(&std::env::args().collect::<Vec<_>>()) {
        eprintln!("native guard failed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_high_threshold_retains_pid1_decimal_limit_and_accounts_for_page_rounding() {
        assert_eq!(
            kernel_memory_cap(100_000_000_000, 4096).unwrap(),
            99_999_997_952
        );
        assert_eq!(
            kernel_memory_cap(128_000_000_000, 4096).unwrap(),
            128_000_000_000
        );
        assert!(kernel_memory_cap(HIGH, -1).is_err());
        assert!(kernel_memory_cap(HIGH, 3000).is_err());
    }
    fn plan() -> Plan {
        serde_json::from_value(
            json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,
            "invocation_id":"a".repeat(32),"filesystem":FILESYSTEM,"minimum_free_bytes":1,
            "worker_root":ROOT,"maximum_worker_vmas":VMAS,"maximum_root_physical_bytes":ROOT_CAP,
            "receipt_directory":format!("{}{}",RECEIPT_PREFIX,"a".repeat(32)),
            "native_main":{"main_pid":42,"executable":HARNESS,"sha256":HARNESS_SHA},
            "boot_id":"12345678-1234-1234-1234-123456789abc","main_start_ticks":123}),
        )
        .unwrap()
    }
    #[test]
    fn only_closed265_image_root_budget_and_actual_owner_plan_are_accepted() {
        let p = plan();
        validate(&p).unwrap();
        let v = serde_json::to_value(p).unwrap();
        for (key, replacement) in [
            ("unit", json!("other.service")),
            ("maximum_root_physical_bytes", json!(ROOT_CAP + 1)),
            ("maximum_worker_vmas", json!(VMAS + 1)),
            ("worker_root", json!("/tmp")),
            ("main_start_ticks", json!(0)),
            ("minimum_free_bytes", json!(0)),
            ("bounded_canary", json!({})),
            ("receipt_directory", json!("/var/lib/jetstreamer/other")),
        ] {
            let mut bad = v.clone();
            bad[key] = replacement;
            assert!(
                validate(&serde_json::from_value(bad).unwrap()).is_err(),
                "{key}"
            );
        }
        let mut bad = plan();
        bad.native_main.sha256 = "0".repeat(64);
        assert!(validate(&bad).is_err());
        let mut bad = plan();
        bad.native_main.main_pid = 1;
        assert!(validate(&bad).is_err());
        let mut bad = v;
        bad["unknown_escape"] = json!(true);
        assert!(serde_json::from_value::<Plan>(bad).is_err());
    }
    #[test]
    fn generation_binding_refuses_new_boot_invocation_restart_or_delegation() {
        let p = plan();
        let u = Unit {
            load_state: "loaded".into(),
            invocation_id: p.invocation_id.clone(),
            active: "active".into(),
            sub: "running".into(),
            result: "success".into(),
            restarts: 0,
            restart_policy: "no".into(),
            kill_mode: "control-group".into(),
            delegated: false,
            cgroup: format!("/system.slice/{UNIT}"),
            pid: 42,
            control_pid: 0,
            exec_main_code: 0,
            exec_main_status: 0,
            memory_max: MEMORY.to_string(),
            memory_high: HIGH.to_string(),
            memory_swap_max: "0".into(),
            tasks_max: "512".into(),
        };
        bound_state(&u, &p, &p.boot_id).unwrap();
        assert!(bound_state(&u, &p, "other boot").is_err());
        let mut bad = u.clone();
        bad.invocation_id = "b".repeat(32);
        assert!(bound_state(&bad, &p, &p.boot_id).is_err());
        let mut bad = u.clone();
        bad.restarts = 1;
        assert!(bound_state(&bad, &p, &p.boot_id).is_err());
        let mut bad = u.clone();
        bad.delegated = true;
        assert!(bound_state(&bad, &p, &p.boot_id).is_err());
        let mut bad = u;
        bad.kill_mode = "process".into();
        assert!(bound_state(&bad, &p, &p.boot_id).is_err());
    }
}
