use super::*;
use std::{os::fd::AsRawFd, path::PathBuf, process::Command};

const IMAGE_DIR: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/guard-v1";
const IMAGE_SHA: &str = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016";
const IMAGE_SEAL: &str = "cf0cc04561dd6f9c98e540b324a2352540ab48c0d13cd665280bc06ad18ee2eb";
const IMAGE_BYTES: u64 = 1_632_080;
const SAMPLE_MAX_AGE: u64 = 120;
const SOL: u32 = 1001;
const HORIZON: u32 = 1003;

pub fn verify_image() -> Result<Value> {
    let package = Path::new(IMAGE_DIR);
    seal_member(
        &seal(package, IMAGE_SEAL)?,
        "guard",
        IMAGE_SHA,
        IMAGE_BYTES,
        "0555",
    )?;
    let image = package.join("guard");
    verify_file(&image, IMAGE_SHA, IMAGE_BYTES, 0o555)?;
    Ok(binding(image, IMAGE_SHA))
}

pub fn plan(invocation: &str, floor: u64) -> Result<Value> {
    ensure!(
        iid(invocation) && floor >= price::PUBLICATION_COPY,
        "invalid guard invocation or HOME floor"
    );
    Ok(
        json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1",
        "unit":UNIT,"invocation_id":invocation,"filesystem":"/home/sol","minimum_free_bytes":floor,
        "worker_root":ROOT,"maximum_worker_vmas":VMAS,"maximum_root_physical_bytes":TREE_CAP,
        "receipt_directory":format!("{STATE}/guard-receipts")}),
    )
}

pub(crate) fn validate_sample(
    plan_ref: &Value,
    plan_value: &Value,
    sample: &Value,
    clock: u64,
    adopted: bool,
) -> Result<Option<u64>> {
    let invocation = text(plan_value, "invocation_id")?;
    let floor = number(plan_value, "minimum_free_bytes")?;
    ensure!(
        *plan_value == plan(invocation, floor)?,
        "different epoch 186 guard plan"
    );
    fresh(sample, "recorded_unix_seconds", clock, SAMPLE_MAX_AGE)?;
    let producer = &sample["producer"];
    let raw = &sample["root_physical_observation"];
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["plan"] == plan_ref["path"]
            && sample["plan_sha256"] == plan_ref["sha256"]
            && sample["guard_sha256"] == IMAGE_SHA
            && iid(text(sample, "guard_invocation_id")?)
            && sample["producer_invocation_id"] == invocation
            && producer["invocation_id"] == invocation
            && producer["cgroup"] == format!("/system.slice/{UNIT}")
            && number(producer, "pid")? > 1
            && producer["active"] == "active"
            && producer["sub"] == "running"
            && producer["restarts"] == 0
            && producer["restart_policy"] == "no"
            && producer["kill_mode"] == "control-group"
            && producer["delegated"] == false,
        "guard sample does not bind the exact epoch 186 producer"
    );
    let measured = number(raw, "conservative_physical_bytes")?;
    ensure!(
        sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && sample["bounded_measurement"] == false
            && sample["bounded_canary"].is_null()
            && sample["native_main"].is_null()
            && sample.get("DATA_fulfillment").is_none()
            && sample["scratch_deleted"] == false
            && sample["r2_mutations"] == false
            && sample["remote_mutations"] == false
            && sample["minimum_free_bytes"] == floor
            && number(sample, "available_bytes")? >= floor
            && sample["maximum_worker_vmas"] == VMAS
            && sample["maximum_root_physical_bytes"] == TREE_CAP
            && raw["maximum_physical_bytes"] == TREE_CAP
            && raw["exceeds_budget"] == false
            && measured > 0
            && measured <= TREE_CAP
            && number(&raw["first"], "physical_bytes")?
                .max(number(&raw["second"], "physical_bytes")?)
                == measured,
        "epoch 186 guard sample is not a normal successful protective sample"
    );
    let workers = sample["workers"]
        .as_array()
        .context("missing guard worker census")?;
    if adopted {
        ensure!(
            workers.len() == 1,
            "adoption requires exactly one worker in the guard sample"
        );
        let row = workers[0].as_array().context("invalid guard worker row")?;
        ensure!(row.len() == 2, "invalid guard worker row");
        let pid = row[0].as_u64().context("invalid guard worker PID")?;
        let vmas = row[1].as_u64().context("invalid guard worker VMA count")?;
        ensure!(
            pid > 1 && pid != number(producer, "pid")? && vmas > 0 && vmas <= VMAS,
            "invalid adopted worker"
        );
        return Ok(Some(pid));
    }
    ensure!(
        workers.is_empty(),
        "the first protective sample requires a held producer"
    );
    Ok(None)
}

pub fn properties(unit: &str) -> Result<Value> {
    let output = Command::new("/usr/bin/timeout").args([
        "10", "/usr/bin/systemctl", "show", "--all", "--no-pager",
        "--property=Id,ActiveState,SubState,LoadState,MainPID,ControlPID,Job,InvocationID,ControlGroup,NRestarts,Restart,Delegate,KillMode,User,Group,RuntimeMaxUSec,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,ExecStart,ExecMainPID,ExecMainStatus,ExecMainCode,Result,Triggers,TriggeredBy",
        unit,
    ]).env_clear().env("PATH","/usr/bin:/bin").env("LC_ALL", "C").output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty(),
        "cannot inspect native unit {unit}"
    );
    let stdout = String::from_utf8(output.stdout)?;
    let mut properties = serde_json::Map::new();
    for line in stdout.lines() {
        let (key, value) = line.split_once('=').context("invalid native property")?;
        ensure!(
            properties.insert(key.to_owned(), json!(value)).is_none(),
            "duplicate native property"
        );
    }
    ensure!(
        properties.get("Id") == Some(&json!(unit)),
        "different native unit {unit}"
    );
    Ok(Value::Object(properties))
}

fn system_state() -> Result<[Value; 3]> {
    Ok([
        properties(UNIT)?,
        properties(GUARD_UNIT)?,
        properties(TIMER)?,
    ])
}

fn check_system_state(state: &[Value; 3], plan_ref: &Value, sample: &Value) -> Result<()> {
    let [producer, guard, timer] = state;
    let pid = number(&sample["producer"], "pid")?;
    let image = format!("{IMAGE_DIR}/guard");
    let path = text(plan_ref, "path")?;
    let sha = text(plan_ref, "sha256")?;
    let exec = text(guard, "ExecStart")?;
    let (_, tail) = exec
        .split_once(" ; argv[]=")
        .context("missing guard service argv")?;
    let (argv, _) = tail
        .split_once(" ; ")
        .context("invalid guard service argv")?;
    ensure!(
        producer["ActiveState"] == "active"
            && producer["SubState"] == "running"
            && producer["InvocationID"] == sample["producer_invocation_id"]
            && text(producer, "MainPID")?.parse::<u64>()? == pid
            && producer["ControlPID"] == "0"
            && producer["NRestarts"] == "0"
            && producer["Restart"] == "no"
            && producer["User"] == "sol"
            && producer["Group"] == "horizon"
            && producer["Delegate"] == "no"
            && producer["KillMode"] == "control-group"
            && producer["ControlGroup"] == format!("/system.slice/{UNIT}")
            && producer["Job"] == ""
            && text(producer, "MemoryMax")?.parse::<u64>()? == MEMORY
            && producer["MemorySwapMax"] == "0"
            && text(producer, "TasksMax")?.parse::<u64>()? == TASKS
            && producer["RuntimeMaxUSec"] == "1h 3min"
            && producer["CPUQuotaPerSecUSec"] == "8s"
            && guard["ActiveState"] == "inactive"
            && guard["SubState"] == "dead"
            && guard["InvocationID"] == sample["guard_invocation_id"]
            && guard["Result"] == "success"
            && guard["ExecMainCode"] == "1"
            && guard["ExecMainStatus"] == "0"
            && guard["TriggeredBy"] == TIMER
            && text(guard, "MemoryMax")?.parse::<u64>()? == GUARD_MEMORY
            && guard["MemorySwapMax"] == "0"
            && guard["CPUQuotaPerSecUSec"] == "1s"
            && exec.starts_with(&format!("{{ path={image} ; "))
            && exec.matches("argv[]=").count() == 1
            && argv == format!("{image} {path} --plan-sha256 {sha} --self-sha256 {IMAGE_SHA}")
            && timer["ActiveState"] == "active"
            && timer["SubState"] == "waiting"
            && timer["Triggers"] == GUARD_UNIT
            && iid(text(timer, "InvocationID")?),
        "kernel service limits, guard invocation or timer do not match the sample"
    );
    Ok(())
}

fn identity(pid: u64) -> Result<(PathBuf, String)> {
    let process = Path::new("/proc").join(pid.to_string());
    let cgroup = fs::read_to_string(process.join("cgroup"))?;
    let start = fs::read_to_string(process.join("stat"))?;
    let (_, after_comm) = start.rsplit_once(") ").context("invalid process stat")?;
    let ticks = after_comm
        .split_whitespace()
        .nth(19)
        .context("missing process start clock")?;
    ensure!(
        ticks.parse::<u64>()? > 0 && cgroup.trim() == format!("0::/system.slice/{UNIT}"),
        "process {pid} is outside the exact epoch 186 cgroup"
    );
    let status = fs::read_to_string(process.join("status"))?;
    for (key, expected) in [("Uid:", SOL), ("Gid:", HORIZON)] {
        let ids = status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .context("missing process credentials")?;
        ensure!(
            ids.split_whitespace().count() == 4
                && ids
                    .split_whitespace()
                    .all(|id| id.parse::<u32>().ok() == Some(expected)),
            "epoch 186 process credentials changed"
        );
    }
    Ok((fs::read_link(process.join("exe"))?, ticks.to_owned()))
}

fn process_image(
    pid: u64,
    m: &(PathBuf, String),
    native_path: &Path,
    bytes: u64,
    sha: &str,
) -> Result<()> {
    let process = Path::new("/proc").join(pid.to_string());
    let mut file = File::open(process.join("exe"))?;
    let view = process.join("root").join(native_path.strip_prefix("/")?);
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.len() == bytes
            && info.mode() & 0o7777 == 0o555
            && hash(&mut file)? == sha
            && stamp(&info) == stamp(&file.metadata()?)
            && stamp(&info) == stamp(&fs::symlink_metadata(view)?)
            && identity(pid)? == *m,
        "epoch 186 running executable does not match the pinned image"
    );
    Ok(())
}

fn check_adoption(node_pid: u64, worker_pid: u64) -> Result<Value> {
    let node = identity(node_pid)?;
    let worker = identity(worker_pid)?;
    let root = Path::new(ROOT);
    let path = &worker.0;
    ensure!(
        (node.0 == Path::new(source::NODE_VIEW) || node.0 == Path::new(source::NODE_IMAGE))
            && path.starts_with(root)
            && path.ends_with("bound-worker/historical-worker"),
        "epoch 186 node or worker missed its execution path"
    );
    process_image(
        node_pid,
        &node,
        Path::new(source::NODE_VIEW),
        source::NODE_BYTES,
        source::NODE_SHA,
    )?;
    process_image(
        worker_pid,
        &worker,
        &worker.0,
        source::WORKER_BYTES,
        source::WORKER_SHA,
    )?;
    let process = Path::new("/proc").join(node_pid.to_string());
    let argv = fs::read(process.join("cmdline"))?;
    let expected = source::argv().join("\0") + "\0";
    ensure!(
        argv == expected.as_bytes(),
        "different bounded epoch 186 producer argv"
    );
    let environment = fs::read(process.join("environ"))?;
    let required = source::environment();
    for (name, value) in required
        .as_object()
        .context("missing bounded entry environment")?
    {
        let prefix = format!("{name}=");
        let expected = format!(
            "{prefix}{}",
            value
                .as_str()
                .context("invalid bounded environment value")?
        );
        let mut matches = environment
            .split(|b| *b == 0)
            .filter(|s| s.starts_with(prefix.as_bytes()));
        ensure!(
            matches.next() == Some(expected.as_bytes()) && matches.next().is_none(),
            "different epoch 186 adopted environment {name}"
        );
    }
    for (source_path, mount_path) in source::adopted_bindings() {
        let target = process
            .join("root")
            .join(Path::new(&mount_path).strip_prefix("/")?);
        let open = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&target)?;
        let info = open.metadata()?;
        let source = fs::symlink_metadata(&source_path)?;
        let mut flags = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        ensure!(
            unsafe { libc::fstatvfs(open.as_raw_fd(), flags.as_mut_ptr()) } == 0
                && unsafe { flags.assume_init() }.f_flag & libc::ST_RDONLY != 0
                && info.uid() == 0
                && stamp(&info) == stamp(&source),
            "different or writable adopted input {}",
            target.display()
        );
    }
    ensure!(
        identity(node_pid)? == node && identity(worker_pid)? == worker,
        "adoption changed during verification"
    );
    Ok(
        json!({"node_pid":node_pid,"node_start_ticks":node.1,"worker_pid":worker_pid,
        "worker_start_ticks":worker.1,"worker_path":worker.0,"worker_sha256":source::WORKER_SHA}),
    )
}

pub fn inspect(
    stage: &str,
    plan_path: &Path,
    plan_sha: &str,
    sample_path: &Path,
    sample_sha: &str,
    quote_sha: &str,
) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "live guard check requires root read access"
    );
    ensure!(
        matches!(stage, "held" | "adopted"),
        "unknown native guard stage"
    );
    ensure!(
        plan_path == Path::new(STATE).join("ACTUAL_GUARD_PLAN.json"),
        "foreign live guard plan path"
    );
    let plan_ref = binding(plan_path, plan_sha);
    let plan_value = document(plan_path, plan_sha, 0o400)?;
    let sample = document(sample_path, sample_sha, 0o600)?;
    let quote_path = Path::new(STATE).join("PRESTART_CAPACITY.json");
    let quote = document(&quote_path, quote_sha, 0o400)?;
    ensure!(
        quote["schema"] == price::CAPACITY_SCHEMA
            && quote["source_entry"]["unit"] == UNIT
            && quote["source_entry"]["private_tree"] == ROOT
            && quote["replay_launch_authorized"] == false
            && quote["resource_screen"]["home_and_memory_fit"] == true
            && number(&quote["resource_screen"], "guard_minimum_free_bytes")?
                == number(&plan_value, "minimum_free_bytes")?
            && number(&quote, "recorded_unix_seconds")?
                <= number(&sample, "recorded_unix_seconds")?,
        "epoch 186 guard floor is not bound to a fitted source-capacity quote"
    );
    let guard_iid = text(&sample, "guard_invocation_id")?;
    ensure!(
        iid(guard_iid)
            && sample_path
                == Path::new(STATE)
                    .join("guard-receipts")
                    .join(format!("sample-{guard_iid}.json")),
        "foreign live guard sample path"
    );
    verify_image()?;
    let worker = validate_sample(&plan_ref, &plan_value, &sample, now()?, stage == "adopted")?;
    let before = system_state()?;
    check_system_state(&before, &plan_ref, &sample)?;
    let pid = number(&sample["producer"], "pid")?;
    let producer_before = identity(pid)?;
    let adoption = worker
        .map(|pid_worker| check_adoption(pid, pid_worker))
        .transpose()?;
    ensure!(
        system_state()? == before && identity(pid)? == producer_before,
        "systemd or producer identity changed during guard verification"
    );
    fresh(&sample, "recorded_unix_seconds", now()?, SAMPLE_MAX_AGE)?;
    Ok(
        json!({"schema":"horizon-epoch186-live-guard-check-v1","epoch":EPOCH,"stage":stage,
        "producer_invocation_id":sample["producer_invocation_id"],"guard_invocation_id":guard_iid,
        "timer_invocation_id":before[2]["InvocationID"],"producer_start_ticks":producer_before.1,
        "plan":plan_ref,"sample":binding(sample_path,sample_sha),
        "prestart_capacity":binding(quote_path,quote_sha),"adoption":adoption,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_requires_same_live_invocation_and_distinguishes_held_from_adopted() {
        let invocation = "1".repeat(32);
        let guard_invocation = "2".repeat(32);
        let floor = price::PUBLICATION_COPY + 8000;
        let p = plan(&invocation, floor).unwrap();
        let reference = binding(format!("{STATE}/ACTUAL_GUARD_PLAN.json"), &"3".repeat(64));
        let mut sample = json!({
            "schema":"jetstreamer-horizon-standalone-guard-sample-v1","recorded_unix_seconds":100,
            "plan":reference["path"],"plan_sha256":reference["sha256"],"guard_sha256":IMAGE_SHA,
            "producer_invocation_id":invocation,"guard_invocation_id":guard_invocation,
            "producer":{"invocation_id":invocation,"cgroup":format!("/system.slice/{UNIT}"),"pid":41,
                "active":"active","sub":"running","restarts":0,"restart_policy":"no","kill_mode":"control-group","delegated":false},
            "workers":[],"producer_stop_enabled":true,"trip_reason":null,
            "worker_observation_error":null,"root_physical_observation_error":null,
            "bounded_measurement":false,"bounded_canary":null,"native_main":null,
            "scratch_deleted":false,"r2_mutations":false,"remote_mutations":false,
            "minimum_free_bytes":floor,"available_bytes":floor,"maximum_worker_vmas":VMAS,
            "maximum_root_physical_bytes":TREE_CAP,
            "root_physical_observation":{"maximum_physical_bytes":TREE_CAP,"exceeds_budget":false,
                "conservative_physical_bytes":8000,"first":{"physical_bytes":4000},"second":{"physical_bytes":8000}}
        });
        assert_eq!(
            validate_sample(&reference, &p, &sample, 220, false).unwrap(),
            None
        );
        assert!(validate_sample(&reference, &p, &sample, 221, false).is_err());
        assert!(validate_sample(&reference, &p, &sample, 101, true).is_err());
        sample["workers"] = json!([[43, 100]]);
        assert!(validate_sample(&reference, &p, &sample, 101, false).is_err());
        assert_eq!(
            validate_sample(&reference, &p, &sample, 101, true).unwrap(),
            Some(43)
        );
        for (key, changed) in [
            ("producer_invocation_id", json!("4".repeat(32))),
            ("producer_stop_enabled", json!(false)),
            ("trip_reason", json!("filesystem-floor")),
            ("workers", json!([[43, 100], [44, 90]])),
            ("available_bytes", json!(floor - 1)),
        ] {
            let mut invalid = sample.clone();
            invalid[key] = changed;
            assert!(
                validate_sample(&reference, &p, &invalid, 101, true).is_err(),
                "{key}"
            );
        }
    }
}
