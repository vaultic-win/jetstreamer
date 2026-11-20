//! Exact epoch 166 retry 9 launch. The prepare receipt is an input, never launch authority.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
// The preparer rechecks the fleet, closed units, DATA and memory before writing its receipt.
// Allow its bounded measurement and preparation to finish within three minutes of the fleet.
const ORIGINAL_FLEET_PREPARATION_MAX_AGE_SECONDS: u64 = 180;
const UNIT: &str = "horizon-qualify-166-replacement-local3retry9-20261110-v1.service";
const GUARD: &str = "horizon-guard-replacement-166-local3retry9-20261110-v1";
const GUARD_STATE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry9-recovery-20261120-v1/preparation/epoch166/local3retry9/guard-state";
const GUARD_PLAN_PARENT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry9-live-state-20261120-v1/guard-plans";
const CAP: u64 = 309_237_645_312;
const FLOOR: u64 = 6_829_053_656_882;
const STOP_COMPLETION: &str = "/var/lib/jetstreamer/retry8-preparation-20261119-v1/epoch166/local3retry8/guard-state-recovery-v2/receipts/stop-completion.json";
const STOP_SHA: &str = "b99e26a6836609dc68b4c646eb19ce2b2c0edd0d7547c80b1e0b517be4875b08";
const PREPARED: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry9-recovery-20261120-v1/preparation/epoch166/local3retry9/prepared.json";
const OUTPUT_ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry9-recovery-20261120-v1/launch-state/epoch166";
const NODE: &str = "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-node";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const GUARD_IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry9-recovery-20261120-v1/guard-v1/guard";
const GUARD_SHA: &str = env!("HORIZON_RETRY9_GUARD_SHA256");
#[path = "../audit_budget.rs"]
mod audit_budget;
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("missing {key}"))
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().with_context(|| format!("missing {key}"))
}
fn read_regular(path: &Path, max: u64, immutable: bool) -> Result<Vec<u8>> {
    ensure!(path.is_absolute(), "absolute evidence path required");
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && before.uid() == 0 && before.nlink() == 1 && before.len() <= max,
        "unsafe evidence inode: {}",
        path.display()
    );
    ensure!(
        before.mode() & 0o022 == 0 && (!immutable || before.mode() & 0o222 == 0),
        "mutable evidence: {}",
        path.display()
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && after.ino() == path_after.ino()
            && bytes.len() as u64 == before.len(),
        "evidence changed during read"
    );
    Ok(bytes)
}
fn bound(binding: &Value, max: u64) -> Result<Value> {
    let path = Path::new(string(binding, "path")?);
    let expected = string(binding, "sha256")?;
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid evidence digest"
    );
    let bytes = read_regular(path, max, false)?;
    ensure!(
        digest(&bytes) == expected,
        "bound digest differs: {}",
        path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn fixed(path: &str, expected: &str, max: u64) -> Result<()> {
    let bytes = read_regular(Path::new(path), max, true)?;
    ensure!(digest(&bytes) == expected, "sealed image differs: {path}");
    Ok(())
}
fn inode_identity(meta: &fs::Metadata) -> Value {
    json!([
        meta.dev(),
        meta.ino(),
        meta.uid(),
        meta.gid(),
        meta.mode(),
        meta.nlink(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec()
    ])
}
fn staged_genesis(prepared: &Value) -> Result<()> {
    let stage = &prepared["genesis_stage"];
    let path = Path::new(string(stage, "path")?);
    ensure!(
        path == Path::new(
            "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry9-20261110-v1/output/genesis.tar.bz2"
        ) && stage["source"] == prepared["local_inputs"]["genesis"]
            && stage["no_clobber"] == true,
        "staged genesis route changed"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && before.nlink() == 1 && inode_identity(&before) == stage["identity"],
        "staged genesis identity differs"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(1 << 20)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == number(stage, "bytes")?
            && digest(&bytes) == string(stage, "sha256")?
            && inode_identity(&file.metadata()?) == stage["identity"]
            && inode_identity(&fs::symlink_metadata(path)?) == stage["identity"],
        "staged genesis changed"
    );
    Ok(())
}
fn fresh(recorded: u64, at: u64, maximum: u64, label: &str) -> Result<()> {
    ensure!(
        recorded <= at && at - recorded <= maximum,
        "stale or future {label}"
    );
    Ok(())
}
fn native(unit: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl").args([
        "show", unit, "-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Job,Result,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecStart,ControlGroup"
    ]).output()?;
    ensure!(out.status.success(), "systemctl show failed for {unit}");
    let body = String::from_utf8(out.stdout)?;
    let mut map = serde_json::Map::new();
    for row in body.lines() {
        let (key, value) = row.split_once('=').context("malformed native property")?;
        ensure!(!map.contains_key(key), "duplicate native property");
        map.insert(key.into(), json!(value));
    }
    Ok(Value::Object(map))
}
fn empty_target(row: &Value) -> Result<()> {
    ensure!(
        string(row, "Id")? == UNIT
            && matches!(string(row, "ActiveState")?, "inactive" | "failed")
            && string(row, "MainPID")? == "0"
            && string(row, "ControlPID")? == "0"
            && string(row, "Job")?.is_empty(),
        "target already claimed"
    );
    Ok(())
}
fn empty_guard_timer(row: &Value) -> Result<()> {
    ensure!(
        row["Id"] == format!("{GUARD}.timer")
            && matches!(string(row, "ActiveState")?, "inactive" | "failed")
            && row["Job"] == "",
        "guard timer already claimed"
    );
    Ok(())
}
fn closed_unit_unchanged(unit: &str, recorded: &Value, current: &Value) -> Result<()> {
    ensure!(
        unit.ends_with(".service") || unit.ends_with(".timer"),
        "prepared unit name invalid"
    );
    let no_processes = if unit.ends_with(".timer") {
        current["MainPID"].is_null() && current["ControlPID"].is_null()
    } else {
        current["MainPID"] == "0" && current["ControlPID"] == "0"
    };
    let recorded_fields = recorded
        .as_object()
        .context("prepared closed unit record missing")?;
    ensure!(
        current["Id"] == unit
            && matches!(string(current, "ActiveState")?, "inactive" | "failed")
            && current["Job"] == ""
            && no_processes
            && recorded_fields
                .iter()
                .all(|(key, value)| current[key] == *value),
        "closed unit changed after staging: {unit}"
    );
    Ok(())
}
fn revalidate_closed_units(prepared: &Value) -> Result<u64> {
    let previous = prepared["closed_units"]
        .as_object()
        .context("prepared closed unit census missing")?;
    ensure!(
        !previous.is_empty() && previous.len() <= 64,
        "prepared closed unit census size invalid"
    );
    for (unit, recorded) in previous {
        closed_unit_unchanged(unit, recorded, &native(unit)?)?;
    }
    Ok(previous.len() as u64)
}
fn zero_native_producers() -> Result<()> {
    let patterns = [
        "horizon-qualify-*-replacement-*.service",
        "horizon-qualify-*-standard-*.service",
    ];
    for args in [
        vec![
            "list-units",
            "--type=service",
            "--state=active,activating,deactivating,reloading",
        ],
        vec!["list-jobs"],
    ] {
        let out = Command::new("/usr/bin/systemctl")
            .args(&args)
            .args(["--no-legend", "--plain", "--no-pager"])
            .args(patterns)
            .output()?;
        ensure!(
            out.status.success() && out.stderr.is_empty() && out.stdout.len() <= (1 << 20),
            "could not inspect native replay units or jobs"
        );
        let text = std::str::from_utf8(&out.stdout)?;
        for row in text.lines().filter(|r| !r.trim().is_empty()) {
            let fields: Vec<_> = row.split_whitespace().collect();
            ensure!(
                args[0] == "list-units"
                    && fields.len() >= 4
                    && fields[2] == "active"
                    && fields[3] == "exited",
                "another replay producer or job is present: {row}"
            );
            let n = native(fields[0])?;
            ensure!(
                n["Id"] == fields[0]
                    && n["SubState"] == "exited"
                    && n["MainPID"] == "0"
                    && n["ControlPID"] == "0"
                    && n["Job"] == "",
                "replay producer changed during census"
            );
        }
    }
    Ok(())
}
fn process_start_ticks(pid: u64) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .context("process stat shape")?
        .1
        .split_whitespace()
        .collect();
    Ok(fields
        .get(19)
        .context("process start ticks missing")?
        .parse()?)
}
fn local_capacity(prepared: &Value) -> Result<Value> {
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let root = std::ffi::CString::new("/home/sol")?;
    ensure!(
        unsafe { libc::statvfs(root.as_ptr(), &mut stat) } == 0,
        "DATA statvfs failed"
    );
    let available = (stat.f_bavail as u64)
        .checked_mul(stat.f_frsize as u64)
        .context("DATA overflow")?;
    let required = number(
        &prepared["resource_checks"]["data_accounting"]["current_fit"],
        "raw_initial_demand_bytes",
    )?;
    ensure!(
        available >= required,
        "current DATA availability below admitted floor"
    );
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let free_kib: u64 = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .context("MemAvailable missing")?
        .split_whitespace()
        .next()
        .context("MemAvailable value")?
        .parse()?;
    let memory = free_kib.checked_mul(1024).context("memory overflow")?;
    let memory_required = number(
        &prepared["resource_checks"]["memory_accounting"],
        "required_available_bytes",
    )?;
    let total_required = number(
        &prepared["resource_checks"],
        "complete_memory_plus_reserve_bytes",
    )?;
    let total_kib: u64 = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .context("MemTotal missing")?
        .split_whitespace()
        .next()
        .context("MemTotal value")?
        .parse()?;
    ensure!(
        total_kib
            .checked_mul(1024)
            .context("total memory overflow")?
            >= total_required,
        "current total memory below complete promise and reserve"
    );
    ensure!(
        memory >= memory_required,
        "current memory below admitted demand"
    );
    Ok(
        json!({"available_DATA_bytes":available,"required_DATA_bytes":required,"available_memory_bytes":memory,"required_memory_bytes":memory_required}),
    )
}
fn exact_producer(argv: &[String]) -> Result<()> {
    ensure!(
        argv.first().map(String::as_str) == Some("/usr/bin/systemd-run"),
        "producer command changed"
    );
    ensure!(
        argv.iter().any(|v| v == &format!("--unit={UNIT}")),
        "producer unit changed"
    );
    let node = argv
        .iter()
        .position(|v| v == NODE)
        .context("node image missing")?;
    ensure!(
        argv.get(node + 1).map(String::as_str) == Some("166")
            && argv.iter().filter(|v| v.as_str() == NODE).count() == 1
            && argv.iter().any(|v| v == "--property=Restart=no"),
        "producer route changed"
    );
    Ok(())
}
fn exact_guard(argv: &[String], plan_path: &str, plan_sha: &str) -> Result<()> {
    ensure!(
        argv.first().map(String::as_str) == Some("/usr/bin/systemd-run")
            && argv.iter().any(|v| v == &format!("--unit={GUARD}"))
            && argv.iter().any(|v| v == "--on-active=1s")
            && argv.iter().any(|v| v == "--on-unit-inactive=5s")
            && argv.iter().any(|v| v == "--property=User=root")
            && argv.iter().any(|v| v == "--property=ProtectSystem=strict")
            && argv.iter().any(|v| v == "--property=Restart=no")
            && argv.iter().any(|v| v == GUARD_IMAGE),
        "guard timer route changed"
    );
    let guard = argv
        .iter()
        .position(|v| v == GUARD_IMAGE)
        .context("guard image missing")?;
    ensure!(
        argv.get(guard + 1).map(String::as_str) == Some(plan_path)
            && argv.get(guard + 2).map(String::as_str) == Some("--plan-sha256")
            && argv.get(guard + 3).map(String::as_str) == Some(plan_sha)
            && argv.get(guard + 4).map(String::as_str) == Some("--self-sha256")
            && argv.get(guard + 5).map(String::as_str) == Some(GUARD_SHA)
            && guard + 6 == argv.len(),
        "guard plan binding changed"
    );
    Ok(())
}
fn directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical state directory"
    );
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o7777 == 0o700
            && meta.dev() == fs::metadata("/home/sol")?.dev(),
        "unsafe state directory"
    );
    Ok(())
}
fn write_json(dir: &Path, name: &str, value: &Value) -> Result<Value> {
    directory(dir)?;
    ensure!(
        !name.contains('/') && !name.is_empty(),
        "unsafe receipt name"
    );
    let path = dir.join(name);
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(dir)?.sync_all()?;
    Ok(json!({"path":path,"sha256":digest(&fs::read(&path)?)}))
}
fn command(
    argv: &[String],
    dir: &Path,
    name: &str,
    limit: Duration,
    umask: Option<u32>,
) -> Result<()> {
    ensure!(!argv.is_empty(), "empty command");
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join(format!("{name}.stdout")))?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join(format!("{name}.stderr")))?;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(mask) = umask {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(move || {
                libc::umask(mask);
                Ok(())
            });
        }
    }
    let mut child = cmd.spawn()?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= limit {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{name} command exceeded bounded start window");
        }
        thread::sleep(Duration::from_millis(50));
    };
    ensure!(status.success(), "{name} command failed: {status}");
    Ok(())
}
fn monotonic_seconds() -> Result<f64> {
    let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) } == 0,
        "monotonic clock unavailable"
    );
    let ts = unsafe { ts.assume_init() };
    Ok(ts.tv_sec as f64 + ts.tv_nsec as f64 / 1_000_000_000.0)
}
fn actual_producer(previous: &Value) -> Result<Value> {
    let mut row = native(UNIT)?;
    let iid = string(&row, "InvocationID")?;
    ensure!(
        row["ActiveState"] == "active"
            && row["SubState"] == "running"
            && row["NRestarts"] == "0"
            && row["ControlPID"] == "0"
            && row["Job"] == ""
            && iid.len() == 32
            && iid.bytes().all(|v| v.is_ascii_hexdigit())
            && iid != string(previous, "InvocationID")?
            && string(&row, "MainPID")?.parse::<u64>()? > 0,
        "new producer identity not running or changed"
    );
    let pid = string(&row, "MainPID")?.parse::<u64>()?;
    row["MainStartTicks"] = json!(process_start_ticks(pid)?);
    Ok(row)
}
fn actual_guard_plan(prepared: &Value, producer: &Value) -> Result<Value> {
    let mut guard_plan = prepared["guard_plan_requires_actual_identity"].clone();
    ensure!(
        guard_plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && guard_plan["unit"] == UNIT
            && guard_plan["invocation_id"] == "REPLACE_ONLY_WITH_ACTUAL_NEW_NATIVE_PRODUCER_IID"
            && guard_plan["minimum_free_bytes"] == FLOOR
            && guard_plan["maximum_root_physical_bytes"] == CAP
            && guard_plan["receipt_directory"] == format!("{GUARD_STATE}/receipts"),
        "guard plan template differs"
    );
    guard_plan["invocation_id"] = json!(string(producer, "InvocationID")?);
    Ok(guard_plan)
}
fn guard_plan_destination(iid: &str) -> Result<String> {
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && iid.bytes().any(|byte| byte != b'0'),
        "actual lowercase native producer invocation required for guard destination"
    );
    Ok(format!("{GUARD_PLAN_PARENT}/guard-{iid}"))
}
fn guard_directory_identity(metadata: &fs::Metadata) -> Value {
    json!([
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode()
    ])
}
fn guard_plan_parent() -> Result<(File, Value)> {
    let path = Path::new(GUARD_PLAN_PARENT);
    directory(path)?;
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.dev() == fs::metadata("/home/sol")?.dev(),
        "guard plan parent is not on the home filesystem"
    );
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)?;
    let identity = guard_directory_identity(&before);
    ensure!(
        guard_directory_identity(&handle.metadata()?) == identity
            && guard_directory_identity(&fs::symlink_metadata(path)?) == identity,
        "guard plan parent changed while opening"
    );
    Ok((handle, identity))
}
fn guard_plan_parent_unchanged(handle: &File, identity: &Value) -> Result<()> {
    directory(Path::new(GUARD_PLAN_PARENT))?;
    let current = fs::symlink_metadata(GUARD_PLAN_PARENT)?;
    ensure!(
        current.dev() == fs::metadata("/home/sol")?.dev()
            && guard_directory_identity(&current) == *identity
            && guard_directory_identity(&handle.metadata()?) == *identity,
        "guard plan parent identity or home filesystem changed"
    );
    Ok(())
}
fn seal_guard(
    prepared: &Value,
    producer: &Value,
    dir: &Path,
) -> Result<(String, String, Vec<String>)> {
    let (parent_handle, parent_identity) = guard_plan_parent()?;
    let guard_plan = actual_guard_plan(prepared, producer)?;
    let guard_bound = write_json(dir, "ACTUAL_GUARD_PLAN.json", &guard_plan)?;
    let plan_sha = string(&guard_bound, "sha256")?.to_string();
    let iid = string(producer, "InvocationID")?;
    let destination = guard_plan_destination(iid)?;
    match fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("guard destination metadata"),
        Ok(_) => bail!("guard package destination already exists"),
    }
    let seal_plan = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,
        "members":[{"source":string(&guard_bound,"path")?,"name":"guard-plan.json","sha256":plan_sha,"mode":292}]});
    let seal_bound = write_json(dir, "GUARD_SEAL_PLAN.json", &seal_plan)?;
    let argv = vec![
        SEALER.to_string(),
        string(&seal_bound, "path")?.to_string(),
        "--plan-sha256".into(),
        string(&seal_bound, "sha256")?.to_string(),
        "--self-sha256".into(),
        SEALER_SHA.into(),
    ];
    guard_plan_parent_unchanged(&parent_handle, &parent_identity)?;
    command(
        &argv,
        dir,
        "GUARD_SEAL",
        Duration::from_secs(5),
        Some(0o022),
    )?;
    guard_plan_parent_unchanged(&parent_handle, &parent_identity)?;
    let destination_metadata = fs::symlink_metadata(&destination)?;
    ensure!(
        destination_metadata.is_dir()
            && destination_metadata.uid() == 0
            && destination_metadata.mode() & 0o022 == 0
            && destination_metadata.dev() == parent_handle.metadata()?.dev()
            && Path::new(&destination).canonicalize()? == Path::new(&destination),
        "sealed guard directory identity or home placement differs"
    );
    let sealed = format!("{destination}/guard-plan.json");
    ensure!(
        digest(&read_regular(Path::new(&sealed), 1 << 20, true)?) == plan_sha,
        "normally sealed guard plan differs"
    );
    let template: Vec<String> =
        serde_json::from_value(prepared["guard_argv_requires_sealed_actual_plan"].clone())?;
    let guard_argv: Vec<_> = template
        .iter()
        .map(|s| {
            s.replace(
                "REPLACE_WITH_NORMALLY_SEALED_ACTUAL_IID_BOUND_GUARD_PLAN_PATH",
                &sealed,
            )
            .replace("REPLACE_WITH_SEALED_ACTUAL_PLAN_SHA256", &plan_sha)
        })
        .collect();
    exact_guard(&guard_argv, &sealed, &plan_sha)?;
    Ok((sealed, plan_sha, guard_argv))
}
fn prepared_zero_peer_scope(prepared: &Value) -> Result<()> {
    let input = bound(&prepared["plan"], 32 << 20)?;
    ensure!(
        input["epoch"] == 166
            && input["attempt"] == "local3retry9"
            && input["resident_memory"]["owners"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && input["fleet"] == prepared["fleet"]
            && input["review"] == prepared["review"],
        "preparation does not bind the zero-peer retry9 inputs"
    );
    let closed = prepared["closed_units"]
        .as_object()
        .context("closed generation census")?;
    for (epoch, generation) in [(166, 7), (167, 6), (166, 8), (167, 7), (170, 6)] {
        let stem = format!("{epoch}-replacement-local3retry{generation}-20261110-v1");
        for name in [
            format!("horizon-qualify-{stem}.service"),
            format!(
                "horizon-guard-replacement-{epoch}-local3retry{generation}-20261110-v1.service"
            ),
            format!("horizon-guard-replacement-{epoch}-local3retry{generation}-20261110-v1.timer"),
        ] {
            ensure!(
                closed.contains_key(&name),
                "closed generation omitted: {name}"
            );
        }
    }
    let binding = &input["retry9_precreated_roots"];
    ensure!(
        binding["path"]
            == "/var/lib/jetstreamer/horizon_runtime_data/root-zero-166167-stop-20261120-v1/SUCCESSOR_ROOTS_BEFORE_WITNESS.json"
            && binding["sha256"]
                == "d9e8ae44c9726811b2104cac494b4ccc4a5ef3cb7bf56e5cadec6bf6f9b4be89",
        "precreated successor root receipt differs"
    );
    let proof = bound(binding, 1 << 20)?;
    let roots = proof["roots"].as_array().context("precreated roots")?;
    ensure!(
        roots.len() == 3,
        "expected three precreated successor roots"
    );
    for (row, (epoch, generation)) in roots.iter().zip([(166, 9), (167, 8), (170, 7)]) {
        let path = format!(
            "/home/sol/.jetstreamer-private/epoch{epoch}-standard-lane-20261109-v1/replacement-local3retry{generation}-20261110-v1"
        );
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            row["epoch"] == epoch
                && row["path"] == path
                && fs::canonicalize(&path)? == Path::new(&path)
                && m.is_dir()
                && m.dev() == fs::metadata("/home/sol")?.dev()
                && row["dev"] == m.dev()
                && row["ino"] == m.ino()
                && m.uid() == 1001
                && m.gid() == 1003
                && m.mode() & 0o7777 == 0o700,
            "precreated epoch {epoch} root changed"
        );
    }
    Ok(())
}
fn preflight(plan: &Value, at: u64) -> Result<(Value, Value)> {
    ensure!(
        plan["prior_stop_completion"]["path"] == STOP_COMPLETION
            && plan["prior_stop_completion"]["sha256"] == STOP_SHA,
        "exact retry8 stop required"
    );
    let stopped = bound(&plan["prior_stop_completion"], 1 << 20)?;
    ensure!(
        stopped["producer_invocation_id"] == "4f09db5f45074244a45b06aeef932d1d"
            && stopped["terminal"]["active"] == "inactive"
            && stopped["terminal"]["pid"] == 0
            && stopped["scratch_deleted"] == false,
        "retry8 stop must have preserved custody"
    );
    ensure!(
        plan["schema"] == "horizon-retry9-single166-launch-plan-v1"
            && plan["owner"] == "/root"
            && plan["primary_thread"] == THREAD
            && plan["launch_authorized"] == true,
        "foreign launch plan"
    );
    ensure!(
        string(plan, "output_root")? == OUTPUT_ROOT,
        "launch output root changed"
    );
    ensure!(
        string(&plan["prepared"], "path")? == PREPARED,
        "wrong preparation path"
    );
    let prepared = bound(&plan["prepared"], 8 << 20)?;
    ensure!(
        prepared["schema"] == "horizon-standard-replacement-recipe-preparation-v1"
            && prepared["owner"] == "/root"
            && prepared["primary_thread"] == THREAD
            && prepared["epoch"] == 166
            && prepared["attempt"] == "local3retry9"
            && prepared["replay_launched"] == false
            && prepared["replay_admission_receipt"] == false
            && prepared["guard_timer_started"] == false
            && prepared["remote_mutations"] == false,
        "preparation scope differs"
    );
    prepared_zero_peer_scope(&prepared)?;
    let prepared_at = number(&prepared, "recorded_unix_seconds")?;
    ensure!(prepared_at <= at, "future preparation");
    let review = bound(&prepared["review"], 1 << 20)?;
    fresh(
        number(&review, "recorded_unix_seconds")?,
        at,
        1800,
        "review",
    )?;
    fresh(
        number(&review, "recorded_unix_seconds")?,
        prepared_at,
        120,
        "original review",
    )?;
    let fleet = bound(&prepared["fleet"], 16 << 20)?;
    fresh(number(&fleet, "recorded_unix_seconds")?, at, 1800, "fleet")?;
    fresh(
        number(&fleet, "recorded_unix_seconds")?,
        prepared_at,
        ORIGINAL_FLEET_PREPARATION_MAX_AGE_SECONDS,
        "original fleet",
    )?;
    ensure!(
        fleet["actual_executing_replays"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && fleet["actual_active_bootstraps"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "zero-owner admission changed"
    );
    ensure!(
        prepared["data_fulfillment"]["contract"] == plan["data_fulfillment"],
        "DATA contract differs"
    );
    let _ = bound(&plan["data_fulfillment"]["contract"], 1 << 20)?;
    let _ = bound(&plan["data_fulfillment"]["deployment_seal"], 1 << 20)?;
    fixed(NODE, NODE_SHA, 64 << 20)?;
    fixed(GUARD_IMAGE, GUARD_SHA, 32 << 20)?;
    fixed(SEALER, SEALER_SHA, 32 << 20)?;
    staged_genesis(&prepared)?;
    let argv: Vec<String> = serde_json::from_value(prepared["producer_argv"].clone())?;
    exact_producer(&argv)?;
    let closed_units = revalidate_closed_units(&prepared)?;
    empty_target(&native(UNIT)?)?;
    let mut capacity = local_capacity(&prepared)?;
    capacity["revalidated_unix_seconds"] = json!(at);
    capacity["unchanged_closed_units"] = json!(closed_units);
    audit_budget::validate_fleet_obligation(&fleet["continuing_audit_obligation"])?;
    let checks = &prepared["resource_checks"];
    let audit = audit_budget::observe()?;
    ensure!(
        audit == checks["audit_native"],
        "HOME audit identity changed since preparation"
    );
    let mut audit_fit = checks["retry3_working_set"].clone();
    audit_fit["additional_growth_not_covered_by_existing_promise_bytes"] = json!(number(
        &review,
        "additional_growth_not_covered_by_existing_promise_bytes"
    )?);
    ensure!(
        audit_fit == checks["audit_fit"],
        "audit fit differs from prepared whole-fleet working set"
    );
    capacity["audit_home_DATA"] =
        audit_budget::data_requirements(&audit_fit, number(&capacity, "available_DATA_bytes")?)?;
    capacity["audit_budget_source_sha256"] = json!(audit_budget::compiled_source_sha256());
    let mem = fs::read_to_string("/proc/meminfo")?;
    let total = mem
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .context("MemTotal")?
        .split_whitespace()
        .next()
        .context("MemTotal bytes")?
        .parse::<u64>()?
        .checked_mul(1024)
        .context("memory overflow")?;
    let cores = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    ensure!(cores > 0, "online CPUs unknown");
    capacity["audit_additive_fit"] = audit_budget::requirements(
        &prepared,
        total,
        number(&capacity, "available_memory_bytes")?,
        cores as u64,
    )?;
    ensure!(
        capacity["audit_additive_fit"] == checks["audit_additive_resources"],
        "audit memory, CPU or native host limits changed since preparation"
    );
    capacity["audit_owner"] = audit;
    zero_native_producers()?;
    let _ = guard_plan_parent()?;
    ensure!(
        fleet["complete_DATA_bytes"] == 6_794_761_027_378u64,
        "retained166/167 DATA missing"
    );

    Ok((prepared, capacity))
}
fn guard_state(prepared: &Value) -> Result<PathBuf> {
    let original = PathBuf::from(string(
        &prepared["guard_plan_requires_actual_identity"],
        "receipt_directory",
    )?);
    ensure!(
        original == Path::new(&format!("{GUARD_STATE}/receipts")),
        "guard receipt directory changed"
    );
    let receipt = original;
    let parent = receipt.parent().context("guard state parent")?;
    ensure!(
        !parent.exists() && !receipt.exists(),
        "guard state was already used"
    );
    directory(parent.parent().context("preparation parent")?)?;
    fs::create_dir(parent)?;
    fs::set_permissions(parent, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    fs::create_dir(&receipt)?;
    fs::set_permissions(
        &receipt,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    File::open(parent)?.sync_all()?;
    File::open(parent.parent().context("preparation parent")?)?.sync_all()?;
    directory(parent)?;
    directory(&receipt)?;
    Ok(receipt)
}
fn journal_has_pid1(unit: &str, iid: &str) -> Result<bool> {
    let output = Command::new("/usr/bin/journalctl")
        .args(["--all", "--no-pager", "-ojson", "-u", unit])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() < (8 << 20),
        "guard journal unavailable"
    );
    for line in output.stdout.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let record: Value = serde_json::from_slice(line)?;
        if record["_PID"] == "1" && record["INVOCATION_ID"] == iid {
            return Ok(true);
        }
    }
    Ok(false)
}
fn guard_sample_shape(sample: &Value, iid: &str, plan_sha: &str, contract: &Value) -> Result<()> {
    let fulfilled = number(sample, "fulfilled_existing_DATA_bytes")?;
    let minimum = number(sample, "minimum_free_bytes")?;
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["producer_invocation_id"] == iid
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && sample["DATA_fulfillment_observation_error"].is_null()
            && sample["producer_stop_enabled"] == true
            && sample["guard_sha256"] == GUARD_SHA
            && sample["plan_sha256"] == plan_sha
            && sample["DATA_fulfillment"]["contract"] == *contract
            && sample["DATA_fulfillment"]["DATA_ending_bytes"] == 0
            && sample["DATA_fulfillment"]["resource_credit_bytes"] == 0
            && minimum == FLOOR
            && fulfilled > 0
            && fulfilled <= 100_000_000_000
            && number(sample, "effective_required_free_bytes")? == minimum - fulfilled
            && number(sample, "available_plus_fulfilled_bytes")? >= minimum,
        "guard sample DATA or identity proof invalid"
    );
    Ok(())
}
fn first_guard(
    prepared: &Value,
    producer: &Value,
    plan_sha: &str,
    receipt_dir: &Path,
    deadline: f64,
) -> Result<Value> {
    let iid = string(producer, "InvocationID")?;
    let guard_service = format!("{GUARD}.service");
    let guard_timer = format!("{GUARD}.timer");
    loop {
        ensure!(
            monotonic_seconds()? < deadline,
            "no genuine first guard completion within 25 seconds"
        );
        for entry in fs::read_dir(receipt_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let raw = read_regular(&path, 1 << 20, false)?;
            let sample: Value = serde_json::from_slice(&raw)?;
            if sample["producer_invocation_id"] != iid {
                continue;
            }
            guard_sample_shape(
                &sample,
                iid,
                plan_sha,
                &prepared["data_fulfillment"]["contract"],
            )?;
            let service = native(&guard_service)?;
            let timer = native(&guard_timer)?;
            if service["InvocationID"] != sample["guard_invocation_id"]
                || service["ActiveState"] != "inactive"
            {
                continue;
            }
            ensure!(
                service["Result"] == "success"
                    && service["ExecMainStatus"] == "0"
                    && service["MainPID"] == "0"
                    && service["ControlPID"] == "0"
                    && timer["ActiveState"] == "active"
                    && timer["Job"] == ""
                    && sample["fulfilled_existing_DATA_bytes"]
                        .as_u64()
                        .is_some_and(|n| n > 0 && n <= 100_000_000_000)
                    && sample["available_plus_fulfilled_bytes"]
                        .as_u64()
                        .is_some_and(|n| n >= FLOOR),
                "first guard completion or DATA protection invalid"
            );
            let current = native(UNIT)?;
            ensure!(
                current["InvocationID"] == producer["InvocationID"]
                    && current["MainPID"] == producer["MainPID"]
                    && current["ActiveState"] == "active"
                    && current["NRestarts"] == "0"
                    && process_start_ticks(string(&current, "MainPID")?.parse()?)?
                        == number(producer, "MainStartTicks")?,
                "producer changed before first guard completion"
            );
            ensure!(
                journal_has_pid1(&guard_service, string(&service, "InvocationID")?)?,
                "PID1 first timer invocation missing"
            );
            return Ok(json!({"receipt":{"path":path,"sha256":digest(&raw)},
                "guard_service":service,"timer":timer,"actual_producer":current,
                "genuine_first_timer_driven_success":true,"continuous_Root_supervision":true,
                "dynamic_DATA_fulfillment_proven":true,"recorded_unix_seconds":now()?}));
        }
        thread::sleep(Duration::from_millis(150));
    }
}
fn launch(plan: &Value, prepared: &Value, capacity: &Value) -> Result<Value> {
    let output_root = Path::new(string(plan, "output_root")?);
    directory(output_root)?;
    let before = native(UNIT)?;
    empty_target(&before)?;
    empty_guard_timer(&native(&format!("{GUARD}.timer"))?)?;
    let argv: Vec<String> = serde_json::from_value(prepared["producer_argv"].clone())?;
    let mut capacity = capacity.clone();
    let latest = local_capacity(prepared)?;
    let latest_memory = number(&latest, "available_memory_bytes")?;
    ensure!(
        latest_memory
            >= number(
                &capacity["audit_additive_fit"],
                "required_available_memory_bytes"
            )?,
        "final available memory does not cover the concurrent audit and replay"
    );
    capacity["available_memory_bytes"] = json!(latest_memory);
    capacity["available_DATA_bytes"] = latest["available_DATA_bytes"].clone();
    capacity["audit_home_DATA"] = audit_budget::data_requirements(
        &prepared["resource_checks"]["audit_fit"],
        number(&latest, "available_DATA_bytes")?,
    )?;
    ensure!(
        audit_budget::observe()? == capacity["audit_owner"],
        "audit owner changed at launch"
    );
    zero_native_producers()?;
    capacity["revalidated_unix_seconds"] = json!(now()?);
    let receipt_dir = guard_state(prepared)?;
    let _ = write_json(
        output_root,
        "ORIGINAL_PRODUCER_ARGV.json",
        &prepared["producer_argv"],
    )?;
    let _ = write_json(output_root, "PRELAUNCH_CAPACITY.json", &capacity)?;
    let launch_started = monotonic_seconds()?;
    let mut guard_timer_start_confirmed = false;
    let attempt = (|| -> Result<Value> {
        command(
            &argv,
            output_root,
            "PRODUCER_START",
            Duration::from_secs(12),
            None,
        )?;
        let producer = actual_producer(&before)?;
        let started: f64 = string(&producer, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?
            as f64
            / 1_000_000.0;
        let deadline = started + 25.0;
        ensure!(
            started >= launch_started && monotonic_seconds()? < deadline,
            "producer start clock or guard deadline invalid"
        );
        let producer_bound = write_json(output_root, "ACTUAL_PRODUCER_NATIVE.json", &producer)?;
        let (sealed_plan, plan_sha, guard_argv) = seal_guard(prepared, &producer, output_root)?;
        let _ = write_json(output_root, "ORIGINAL_GUARD_ARGV.json", &json!(guard_argv))?;
        command(
            &guard_argv,
            output_root,
            "GUARD_TIMER_START",
            Duration::from_secs(5),
            None,
        )?;
        guard_timer_start_confirmed = true;
        let first = first_guard(prepared, &producer, &plan_sha, &receipt_dir, deadline)?;
        let first_bound = write_json(
            output_root,
            "GENUINE_FIRST_GUARD_PID1_TIMER_PROOF.json",
            &first,
        )?;
        let admission = json!({"schema":"horizon-standard-replacement-admission-v1","owner":"/root",
            "primary_thread":THREAD,"epoch":166,"producer_unit":UNIT,
            "producer_invocation_id":string(&producer,"InvocationID")?,
            "producer_pid":string(&producer,"MainPID")?.parse::<u64>()?,
            "source_admission_evaluated_unix_seconds":number(&capacity,"revalidated_unix_seconds")?,
            "fresh_admission_passed":true,"all_existing_growth_and_floor_protected":true,
            "all_prior_promises_retained":true,"old_partial_and_inputs_preserved":true,
            "resource_credit_bytes":0,"memory_or_DATA_promise_ending_bytes":0,
            "candidate_hard_memory_bytes":73_014_444_032u64,
            "guard_minimum_free_bytes":FLOOR,
            "qualified_DATA_fulfillment_contract":prepared["data_fulfillment"]["contract"],
            "guard_sha256":GUARD_SHA,"genuine_dynamic_DATA_first_guard":first["receipt"],
            "fresh_native_Rust_preparation":plan["prepared"],
            "historical_preparation_recorded_unix_seconds":number(prepared,"recorded_unix_seconds")?,
            "current_closed_unit_revalidation":capacity,
            "actual_producer_native":producer_bound,"first_guard":first_bound,
            "recorded_unix_seconds":now()?,"remote_mutations":false,"r2_mutations":false});
        let admission_bound =
            write_json(output_root, "ACTUAL_REPLACEMENT_ADMISSION.json", &admission)?;
        let protection = json!({"schema":"horizon-standard-live-peer-protection-v1","owner":"/root",
            "epoch":166,"producer_unit":UNIT,"producer_invocation_id":string(&producer,"InvocationID")?,
            "admission":admission_bound,"plan":{"path":sealed_plan,"sha256":plan_sha},
            "first_guard_sample":first["receipt"],"guard_unit":format!("{GUARD}.service"),
            "timer_unit":format!("{GUARD}.timer"),"timer_invocation_id":first["timer"]["InvocationID"]});
        let protection_bound =
            write_json(output_root, "ACTUAL_GUARD_PROTECTION.json", &protection)?;
        Ok(
            json!({"epoch":166,"producer":producer,"admission":admission_bound,
            "guard_protection":protection_bound,"genuine_first_guard":first_bound,
            "bootstrap_only":true,"transaction_replay_claimed":false}),
        )
    })();
    if let Err(error) = &attempt {
        let current = native(UNIT).unwrap_or(Value::Null);
        if current["ActiveState"] == "active"
            && current["InvocationID"] != before["InvocationID"]
            && current["ExecMainStartTimestampMonotonic"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|v| v as f64 / 1_000_000.0 >= launch_started)
        {
            let _ = Command::new("/usr/bin/systemctl")
                .args(["stop", UNIT])
                .status();
        }
        // A failed or timed-out start has no proved ownership of the timer.
        // Leave that state for explicit inspection rather than stopping a
        // timer that another controller might have started concurrently.
        if guard_timer_start_confirmed {
            let _ = Command::new("/usr/bin/systemctl")
                .args(["stop", &format!("{GUARD}.timer")])
                .status();
        }
        let _ = write_json(
            output_root,
            "FAILED_SETUP.json",
            &json!({"error":error.to_string(),
            "originals_preserved":true,"guard_timer_start_confirmed":guard_timer_start_confirmed,
            "recorded_unix_seconds":now().unwrap_or(0)}),
        );
    }
    attempt
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 7
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && matches!(args[6].as_str(), "--check-only" | "--launch"),
        "usage: launch PLAN --plan-sha256 SHA --self-sha256 SHA (--check-only|--launch)"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "Root identity required");
    let exe = fs::read_link("/proc/self/exe")?;
    ensure!(
        exe == Path::new(
            "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry9-recovery-20261120-v1/launch-v1/launch"
        ),
        "sealed launch image required"
    );
    fixed(exe.to_str().context("executable UTF8")?, &args[5], 64 << 20)?;
    let plan_bytes = read_regular(Path::new(&args[1]), 1 << 20, true)?;
    ensure!(digest(&plan_bytes) == args[3], "launch plan digest differs");
    let plan: Value = serde_json::from_slice(&plan_bytes)?;
    let (prepared, capacity) = preflight(&plan, now()?)?;
    if args[6] == "--check-only" {
        println!(
            "{}",
            json!({"check_passed":true,"epoch":166,"no_launch":true,"current_capacity":capacity})
        );
        return Ok(());
    }
    let result = launch(&plan, &prepared, &capacity)?;
    println!("{result}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn producer_route_requires_exact_epoch_and_unit() {
        let good = vec![
            "/usr/bin/systemd-run".into(),
            format!("--unit={UNIT}"),
            "--property=Restart=no".into(),
            NODE.into(),
            "166".into(),
        ];
        exact_producer(&good).unwrap();
        let mut wrong = good.clone();
        wrong[4] = "167".into();
        assert!(exact_producer(&wrong).is_err());
        wrong = good;
        wrong[1] = "--unit=other.service".into();
        assert!(exact_producer(&wrong).is_err());
    }
    #[test]
    fn freshness_rejects_future_and_expired_evidence() {
        assert!(fresh(100, 190, 90, "receipt").is_ok());
        assert!(fresh(100, 191, 90, "receipt").is_err());
        assert!(fresh(101, 100, 90, "receipt").is_err());
        assert!(
            fresh(
                100,
                244,
                ORIGINAL_FLEET_PREPARATION_MAX_AGE_SECONDS,
                "original fleet"
            )
            .is_ok()
        );
        assert!(
            fresh(
                100,
                281,
                ORIGINAL_FLEET_PREPARATION_MAX_AGE_SECONDS,
                "original fleet"
            )
            .is_err()
        );
    }
    #[test]
    fn actual_guard_plan_binds_identity_without_changing_floor_or_cap() {
        let prepared = json!({"guard_plan_requires_actual_identity": {
            "schema": "jetstreamer-horizon-standalone-guard-plan-v1",
            "unit": UNIT,
            "invocation_id": "REPLACE_ONLY_WITH_ACTUAL_NEW_NATIVE_PRODUCER_IID",
            "minimum_free_bytes": FLOOR,
            "maximum_root_physical_bytes": CAP,
            "receipt_directory": format!("{GUARD_STATE}/receipts")
        }});
        let producer = json!({"InvocationID": "0123456789abcdef0123456789abcdef"});
        let result = actual_guard_plan(&prepared, &producer).unwrap();
        assert_eq!(result["minimum_free_bytes"], FLOOR);
        assert_eq!(result["maximum_root_physical_bytes"], CAP);
        assert_eq!(
            result["receipt_directory"],
            format!("{GUARD_STATE}/receipts")
        );
        assert_eq!(result["invocation_id"], producer["InvocationID"]);
        let mut changed = prepared;
        changed["guard_plan_requires_actual_identity"]["minimum_free_bytes"] = json!(FLOOR - 1);
        assert!(actual_guard_plan(&changed, &producer).is_err());
    }
    #[test]
    fn closed_unit_revalidation_rejects_restarts_and_claims() {
        let unit = "horizon-qualify-166-replacement-local3retry9-20261110-v1.service";
        let old = json!({"Id":unit,"ActiveState":"inactive","MainPID":"0",
            "ControlPID":"0","Job":"","InvocationID":""});
        let mut current = old.clone();
        current["ExecStart"] = json!("extra native property");
        closed_unit_unchanged(unit, &old, &current).unwrap();
        current["InvocationID"] = json!("foreign-launch");
        assert!(closed_unit_unchanged(unit, &old, &current).is_err());
        current = old.clone();
        current["ActiveState"] = json!("active");
        assert!(closed_unit_unchanged(unit, &old, &current).is_err());
        current = old.clone();
        current["MainPID"] = json!("1234");
        assert!(closed_unit_unchanged(unit, &old, &current).is_err());
    }
    #[test]
    fn first_guard_rejects_changed_contract_floor_and_trip() {
        let contract = json!({"contract":{"path":"/sealed/contract.json","sha256":"a".repeat(64)},
            "deployment_seal":{"path":"/sealed/seal.json","sha256":"b".repeat(64)}});
        let iid = "c".repeat(32);
        let sha = "d".repeat(64);
        let minimum = 6_829_053_656_882u64;
        let fulfilled = 100_000_000_000u64;
        let mut sample = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1",
            "producer_invocation_id":iid,"trip_reason":null,"worker_observation_error":null,
            "root_physical_observation_error":null,"DATA_fulfillment_observation_error":null,
            "producer_stop_enabled":true,"guard_sha256":GUARD_SHA,"plan_sha256":sha,
            "DATA_fulfillment":{"contract":contract,"DATA_ending_bytes":0,"resource_credit_bytes":0},
            "minimum_free_bytes":minimum,"fulfilled_existing_DATA_bytes":fulfilled,
            "effective_required_free_bytes":minimum-fulfilled,
            "available_plus_fulfilled_bytes":minimum});
        guard_sample_shape(&sample, &iid, &sha, &contract).unwrap();
        sample["trip_reason"] = json!("filesystem-floor");
        assert!(guard_sample_shape(&sample, &iid, &sha, &contract).is_err());
        sample["trip_reason"] = Value::Null;
        sample["effective_required_free_bytes"] = json!(minimum);
        assert!(guard_sample_shape(&sample, &iid, &sha, &contract).is_err());
        sample["effective_required_free_bytes"] = json!(minimum - fulfilled);
        sample["DATA_fulfillment"]["contract"] = json!({});
        assert!(guard_sample_shape(&sample, &iid, &sha, &contract).is_err());
    }
}
