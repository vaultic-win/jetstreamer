//! Exact active141 repair queue and status-only publisher. A failed replay is
//! historical evidence; only an actual live native queue owns this projection.
use super::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
pub(super) const UNIT: &str = "horizon-repair-141-floor-20261024-v1.service";
const PHASE: &str = "epoch141-active-repair";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch141-active-repair-20261024-v1";
const PROGRAM: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch141-repair-status-tools-20261024-v1/jetstreamer-r2";
const OLD: &str = "horizon-qualify-141-original-entry-capped-root-20261023-v1.service";
const OLD_IID: &str = "e639f007d482464f8a251455659d2ede";
const PRIVATE: &str =
    "/home/sol/.jetstreamer-private/epoch141-original-entry-capped-root-20261023-v1";
const TASKS: [&str; 4] = [
    "export-build-and-tests",
    "export-stdio-qualification",
    "bounded-parent-tests",
    "capacity-and-input-admission",
];
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueuePlan {
    schema: String,
    epoch: u64,
    program: Bound,
    terminal: Bound,
    policy: Bound,
    task_slots: Vec<String>,
    bootstrap_observer: Bound,
    bootstrap_fleet: Bound,
    bootstrap_completion: Bound,
    output_directory: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishPlan {
    schema: String,
    epoch: u64,
    observer: Bound,
    fleet: Bound,
    queue_plan: Bound,
    owner_capture: Bound,
    policy: Bound,
    estimate_receipt: PathBuf,
    receipt_directory: PathBuf,
    previous_publication: Option<Bound>,
    exclusive_local_epoch_ownership: bool,
    authenticated_other_host_handoffs: Vec<Value>,
}
fn read(b: &Bound, sealed: bool) -> Result<Value> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && (!sealed || m.mode() & 0o222 == 0)
            && is_lower_hex(&b.sha256, 64),
        "unsafe141 repair evidence"
    );
    let bytes = read_stable_bounded(&b.path, 16 << 20, "141 repair evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "141 repair evidence changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn current(path: &Path) -> Result<(Bound, Value)> {
    let bytes = read_stable_bounded(path, 16 << 20, "141 repair state")?;
    let b = Bound {
        path: path.into(),
        sha256: hex_lower(&Sha256::digest(&bytes)),
    };
    let v = read(&b, false)?;
    Ok((b, v))
}
fn program(b: &Bound) -> Result<()> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.starts_with("/usr/local/lib/jetstreamer")
            && b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.mode() & 0o111 != 0,
        "unsealed141 native repair program"
    );
    let bytes = read_stable_bounded(&b.path, 512 << 20, "141 repair native program")?;
    ensure!(
        bytes.starts_with(b"\x7fELF") && hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "141 repair executable changed/not native"
    );
    Ok(())
}
fn ticks(pid: u64) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(") ")
        .context("141 proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("141 process start")?
        .parse()?)
}
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == PHASE && unit == UNIT
}
fn terminal(b: &Bound) -> Result<()> {
    let v = read(b, false)?;
    inactive_status::validate_capped141_repair_terminal(&v)?;
    let path = Path::new(
        "/var/lib/jetstreamer/horizon-original141-capped-root-guard-20261023-v1/stop-completion.json",
    );
    let proof = read(
        &Bound {
            path: path.into(),
            sha256: "9876457d36386b8c6a4c20865ccb3ec8d2ad5f1a9bd26cddb63e475b9a5f0ea8".into(),
        },
        false,
    )?;
    ensure!(
        proof["producer_invocation_id"] == OLD_IID
            && proof["scratch_deleted"] == false
            && proof["r2_mutations"] == false,
        "141 floor stop/preserved scratch proof differs"
    );
    Ok(())
}
fn policy(b: &Bound) -> Result<(repair141_model::Rate, repair141_model::Policy, Value)> {
    let v = read(b, true)?;
    ensure!(
        v["schema"] == "jetstreamer-epoch141-recovery-planning-v2"
            && v["epoch"] == 141
            && v["bootstrap_slot"] == repair141_model::BOOTSTRAP
            && v["root_slot"] == repair141_model::ROOT
            && v["epoch_terminal_slot"] == repair141_model::TERMINAL
            && v["durable_checkpoint_beyond_bootstrap_proven"] == false
            && v["runtime_checkpoint_resume_qualified"] == false
            && v["publication_authorized"] == false
            && v["replay_launch_authorized"] == false
            && v["remaining_growth_released"] == false
            && v["estimate_uncertainty"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty())
            && v["planning_assumptions_reviewed"] == true,
        "141 repair policy omits actual recovery/qualification obligations"
    );
    let history: Bound = serde_json::from_value(v["historical_rate_observer"].clone())?;
    let o = read(&history, false)?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "141 rate source is not a saved v2 sample"
    );
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("141 historical private census")?;
    let rows: Vec<_> = rows
        .iter()
        .filter(|r| r["producer_unit"] == OLD && r["status"] == "observed")
        .collect();
    ensure!(rows.len() == 1, "141 historical rate missing/duplicated");
    let row = &rows[0]["observation"];
    let w = &row["useful_work"];
    ensure!(
        row["invocation_binding_stable"] == true
            && w["sufficient_for_rates"] == true
            && w["journal_invocation_id"] == OLD_IID
            && w["counter_resets"] == 0
            && w["last"]["terminal_slot"] == repair141_model::ROOT,
        "141 historical rate is not its real stopping-root execution"
    );
    let rate = repair141_model::Rate {
        first_slot: w["first"]["slot"].as_u64().context("141 first slot")?,
        last_slot: w["last"]["slot"].as_u64().context("141 last slot")?,
        elapsed_microseconds: w["last"]["realtime_microseconds"]
            .as_u64()
            .context("141 last clock")?
            .checked_sub(
                w["first"]["realtime_microseconds"]
                    .as_u64()
                    .context("141 first clock")?,
            )
            .context("141 rate reset")?,
    };
    ensure!(
        w["slot_delta"].as_u64()
            == Some(
                rate.last_slot
                    .checked_sub(rate.first_slot)
                    .context("141 historical slot counter reset")?
            ),
        "141 historical rate counters differ"
    );
    let d: Bound = serde_json::from_value(v["downstream_policy"].clone())?;
    let downstream = qualification_status::repair141_downstream(&d.path, &d.sha256)?;
    let n = |name: &str| {
        v["allowance_millis"][name]
            .as_u64()
            .with_context(|| format!("141 allowance {name}"))
    };
    let p = repair141_model::Policy {
        engineering_millis: n("engineering_and_qualification")?,
        capacity_millis: n("capacity_and_admission")?,
        bootstrap_millis: n("bootstrap_restore_and_initialization")?,
        checkpoint_close_restore_millis: n("checkpoint_close_export_restore")?,
        downstream_millis: downstream,
        prerequisites_parallel: v["engineering_and_capacity_parallel"]
            .as_bool()
            .context("141 prerequisite topology")?,
    };
    repair141_model::forecast(&rate, &p).map_err(anyhow::Error::msg)?;
    Ok((rate, p, v))
}
fn queue_plan(b: &Bound) -> Result<QueuePlan> {
    let v = read(b, true)?;
    let p: QueuePlan = serde_json::from_value(v)?;
    ensure!(
        p.schema == "jetstreamer-epoch141-repair-queue-plan-v2"
            && p.epoch == 141
            && p.program.path == Path::new(PROGRAM)
            && p.output_directory == Path::new(ROOT)
            && p.task_slots.iter().map(String::as_str).eq(TASKS),
        "foreign141 repair queue"
    );
    program(&p.program)?;
    terminal(&p.terminal)?;
    policy(&p.policy)?;
    Ok(p)
}
fn own(u: &Value, capture: &Value, p: &QueuePlan, b: &Bound) -> Result<()> {
    let iid = capture["invocation_id"]
        .as_str()
        .context("141 repair IID")?;
    ensure!(
        repair141_model::active_shape(
            u["LoadState"].as_str().unwrap_or(""),
            u["ActiveState"].as_str().unwrap_or(""),
            u["SubState"].as_str().unwrap_or(""),
            u["MainPID"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            u["NRestarts"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(u64::MAX),
            u["InvocationID"].as_str().unwrap_or(""),
            iid
        ) && u["Id"] == UNIT
            && capture["schema"] == "jetstreamer-epoch141-repair-owner-capture-v2"
            && capture["queue_plan"] == serde_json::to_value(b)?
            && capture["program"] == serde_json::to_value(&p.program)?,
        "141 repair owner is not genuinely active"
    );
    let expected = format!(
        "{{ path={PROGRAM} ; argv[]={PROGRAM} repair-owner-141 {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ;",
        b.path.display(),
        b.sha256,
        p.program.sha256
    );
    ensure!(
        u["ExecStart"]
            .as_str()
            .is_some_and(|s| s.starts_with(&expected))
            && u["MainPID"] == capture["manager"]["MainPID"]
            && u["ControlGroup"] == format!("/system.slice/{UNIT}"),
        "141 repair queue command/manager differs"
    );
    let pid = u["MainPID"].as_str().unwrap().parse::<u64>()?;
    ensure!(
        ticks(pid)?
            == capture["process_start_ticks"]
                .as_u64()
                .context("141 owner process clock")?
            && fs::read_link(format!("/proc/{pid}/exe"))? == p.program.path
            && fs::symlink_metadata(format!("/proc/{pid}"))?.uid() == 0,
        "141 repair owner PID/program changed"
    );
    Ok(())
}
fn state_budget(extra: u64) -> Result<()> {
    let mut paths = vec![(PathBuf::from(ROOT), 0u32)];
    let mut count = 0u64;
    let mut used = 0u64;
    while let Some((path, depth)) = paths.pop() {
        ensure!(depth <= 3, "141 state nesting exceeds metadata-only scope");
        for item in fs::read_dir(&path)? {
            let item = item?;
            let m = fs::symlink_metadata(item.path())?;
            count += 1;
            ensure!(
                count <= 4096 && !m.file_type().is_symlink(),
                "141 state is not bounded metadata"
            );
            used = used
                .checked_add(m.blocks().checked_mul(512).context("141 blocks overflow")?)
                .context("141 state overflow")?;
            if m.is_dir() {
                paths.push((item.path(), depth + 1));
            } else {
                ensure!(m.is_file(), "141 nonregular state");
            }
        }
    }
    ensure!(
        used.checked_add(extra).is_some_and(|n| n <= 64 << 20),
        "141 queue64MiB OS growth cap reached"
    );
    Ok(())
}
fn bootstrap(p: &QueuePlan) -> Result<Value> {
    let o = read(&p.bootstrap_observer, false)?;
    let f = read(&p.bootstrap_fleet, false)?;
    let c = read(&p.bootstrap_completion, false)?;
    let sample = o["recorded_at_utc"]
        .as_str()
        .context("141 bootstrap sample")?;
    let cutoff = fleet::utc_seconds(sample)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && cutoff <= now
            && now - cutoff <= 1800
            && f["sampled_at_utc"] == sample
            && f["observer_sha256"] == p.bootstrap_observer.sha256
            && f["observer_receipt"].as_str() == p.bootstrap_observer.path.to_str()
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && f["inventory"]["anomalies"] == 0
            && c["schema"] == "jetstreamer-horizon-routine-cycle-completion-v1"
            && c["sampled_at_utc"] == sample
            && c["observer"] == serde_json::to_value(&p.bootstrap_observer)?
            && c["fleet"] == serde_json::to_value(&p.bootstrap_fleet)?,
        "141 queue bootstrap needs a current accepted coordinated cycle"
    );
    let target = &c["capacity_decision"]["memory_target"];
    let resident = target["host_resident_planning_bytes"]
        .as_u64()
        .context("141 protected resident")?;
    let reserved = target["reservation_ceiling_bytes"]
        .as_u64()
        .context("141 protected reservations")?;
    ensure!(
        target["valid"] == true && resident >= 469_264_728_064 && reserved >= 189_826_437_120,
        "141 queue cannot lower existing protected memory"
    );
    let mem = fs::read_to_string("/proc/meminfo")?;
    let kib = |name: &str| -> Result<u64> {
        mem.lines()
            .find_map(|l| l.strip_prefix(name))
            .context("141 meminfo counter")?
            .split_whitespace()
            .next()
            .context("141 meminfo number")?
            .parse::<u64>()?
            .checked_mul(1024)
            .context("141 memory overflow")
    };
    let total = kib("MemTotal:")?;
    let available = kib("MemAvailable:")?;
    let protection = resident
        .checked_add(reserved)
        .and_then(|n| n.checked_add(2 << 30))
        .context("141 memory protection overflow")?;
    ensure!(
        total >= protection
            && available
                >= reserved
                    .checked_add(2 << 30)
                    .context("141 memory reservation overflow")?,
        "141 queue does not fit protected memory"
    );
    let path = std::ffi::CString::new(ROOT)?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "141 queue OS statfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    let free = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .context("141 OS space overflow")?;
    let floor = 228_833_779_142u64 + 268_435_456 + 67_108_864;
    ensure!(
        free >= floor,
        "141 queue cannot preserve OS baseline plus existing bootstrap and64MiB growth"
    );
    state_budget(2 << 20)?;
    Ok(
        json!({"schema":"jetstreamer-epoch141-queue-bootstrap-check-v2","observer":p.bootstrap_observer,
        "fleet":p.bootstrap_fleet,"completion":p.bootstrap_completion,"sampled_at_utc":sample,"actual_os_free_bytes":free,
        "required_os_free_bytes":floor,"protected_host_resident_bytes":resident,"protected_reservation_ceiling_bytes":reserved,
        "actual_memory_total_bytes":total,"actual_memory_available_bytes":available,"queue_memory_max_bytes":2u64<<30,
        "queue_os_growth_max_bytes":64u64<<20,"replay_launch_authorized":false,"remaining_growth_released":false}),
    )
}
fn atomic_state(v: &Value) -> Result<()> {
    state_budget(2 << 20)?;
    let root = Path::new(ROOT);
    let mut tmp = tempfile::NamedTempFile::new_in(root)?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), v)?;
    tmp.as_file_mut().write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist(root.join("state.json")).map_err(|e| e.error)?;
    File::open(root)?.sync_all()?;
    Ok(())
}
fn retained_audit() -> Result<Value> {
    let path = Path::new(PRIVATE).join("output/private.jet");
    let i = regular_identity(&path)?;
    let began = std::time::Instant::now();
    let mut f = File::open(&path)?;
    let mut hash = Sha256::new();
    let hashed = std::io::copy(&mut f, &mut hash)?;
    ensure!(
        regular_identity(&path)? == i,
        "141 retained partial changed during repair audit"
    );
    // The streamed fingerprint is deliberately not a footer/Bank/prefix proof.
    let raw_sha256 = hex_lower(&hash.finalize());
    Ok(
        json!({"schema":"jetstreamer-epoch141-retained-repair-audit-v2","path":path,"identity":{"device":i.device,"inode":i.inode,"length":i.length,"modified_seconds":i.modified_seconds,"modified_nanoseconds":i.modified_nanoseconds},"raw_partial_sha256":raw_sha256,"hashed_bytes":hashed,"hash_elapsed_millis":u64::try_from(began.elapsed().as_millis())?,
        "resumable_checkpoint_proven":false,"deep_prefix_verification_complete":false,"cold_replay_from_slot":repair141_model::BOOTSTRAP,
        "partial_archive_credit_slots":0,"archive_mutations":false,"remaining_growth_released":false}),
    )
}
fn task_admit(v: &Value, id: &str, plan: &Bound, iid: &str) -> Result<Value> {
    ensure!(
        v["schema"] == "jetstreamer-epoch141-repair-task-intake-v2"
            && v["task_id"] == id
            && v["queue_plan"] == serde_json::to_value(plan)?
            && v["queue_invocation_id"] == iid,
        "141 task intake belongs to another queue"
    );
    let work: Bound = serde_json::from_value(v["work_plan"].clone())?;
    let w = read(&work, true)?;
    ensure!(
        w["epoch"] == 141 || w["first_epoch"] == 141 && w["last_epoch"] == 141,
        "141 repair task work scope differs"
    );
    let program: Bound = serde_json::from_value(v["program"].clone())?;
    self::program(&program)?;
    ensure!(
        program
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("jetstreamer-") && s != "jetstreamer-r2"),
        "141 task cannot be a sleeping or status-only program"
    );
    let unit = v["unit"].as_str().context("141 native task unit")?;
    ensure!(
        unit == format!("horizon-repair-141-task-{id}-20261024-v1.service"),
        "141 task namespace differs"
    );
    let u = fleet::unit(unit)?;
    let iid = u["InvocationID"].as_str().context("141 task IID")?;
    ensure!(
        repair141_model::active_shape(
            u["LoadState"].as_str().unwrap_or(""),
            u["ActiveState"].as_str().unwrap_or(""),
            u["SubState"].as_str().unwrap_or(""),
            u["MainPID"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            u["NRestarts"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(u64::MAX),
            iid,
            v["invocation_id"].as_str().unwrap_or("")
        ),
        "141 admitted task is not actually running"
    );
    ensure!(
        pipeline_status::same_exec_start(
            v["expected_exec_start"]
                .as_str()
                .context("141 task command")?,
            u["ExecStart"].as_str().unwrap_or("")
        ),
        "141 actual task command differs"
    );
    let pid = u["MainPID"].as_str().unwrap().parse::<u64>()?;
    let start = ticks(pid)?;
    ensure!(
        fs::read_link(format!("/proc/{pid}/exe"))? == program.path,
        "141 task is not its native program"
    );
    let argv: Vec<String> = serde_json::from_value(v["argv"].clone())?;
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    let actual: Vec<_> = raw
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| std::str::from_utf8(b).map(str::to_owned))
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        argv == actual
            && argv.first().is_some_and(|s| Path::new(s) == program.path)
            && argv.iter().any(|s| Path::new(s) == work.path),
        "141 task argv does not bind its real repair work plan"
    );
    Ok(
        json!({"unit":unit,"invocation_id":iid,"manager":u,"pid":pid,"process_start_ticks":start,"program":program,
        "work_plan":work,"task_id":id,"resource_admission_claimed":false,"requires_independent_fresh_admission":true,"publication_authorized":false}),
    )
}
/// Capture real PID1/proc evidence from an already separately admitted native
/// task. The sealed intent is never treated as a launch or admission receipt.
pub(super) fn task_capture() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 7
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "repair-task-capture-141 PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    let running = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: a[6].clone(),
    };
    program(&running)?;
    let intent = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let v = read(&intent, true)?;
    ensure!(
        v["schema"] == "jetstreamer-epoch141-repair-task-capture-plan-v2" && v["epoch"] == 141,
        "foreign141 repair task capture plan"
    );
    let id = v["task_id"].as_str().context("141 capture task id")?;
    ensure!(TASKS.contains(&id), "141 task is not a concrete queue slot");
    let owner: Bound = serde_json::from_value(v["owner_capture"].clone())?;
    let capture = read(&owner, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (plan, _, manager) = owner_evidence(&capture, now)?;
    ensure!(
        v["queue_plan"] == serde_json::to_value(&plan)?,
        "141 task queue plan differs"
    );
    let unit = v["unit"].as_str().context("141 capture task unit")?;
    let u = fleet::unit(unit)?;
    let mut intake = json!({"schema":"jetstreamer-epoch141-repair-task-intake-v2","task_id":id,"queue_plan":plan,
        "queue_invocation_id":manager["InvocationID"],"work_plan":v["work_plan"],"program":v["program"],
        "unit":unit,"invocation_id":u["InvocationID"],"expected_exec_start":v["expected_exec_start"],"argv":v["argv"],
        "capture_plan":intent,"recorded_unix_seconds":now,"resource_admission_claimed":false,
        "requires_independent_fresh_admission":true,"replay_launch_authorized":false,"publication_authorized":false});
    let task = task_admit(
        &intake,
        id,
        &plan,
        manager["InvocationID"].as_str().unwrap_or(""),
    )?;
    let (_, _, again) = owner_evidence(
        &capture,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    ensure!(
        again == manager && fleet::unit(unit)? == u,
        "141 repair owner/task changed during intake capture"
    );
    intake["actual_task_capture"] = task;
    let root = Path::new(ROOT).join("task-admissions");
    let m = fs::symlink_metadata(&root)?;
    ensure!(
        root.canonicalize()? == root && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "141 task intake directory is not root-private"
    );
    let out = root.join(format!("{id}.json"));
    state_budget(2 << 20)?;
    fleet::persist(&out, &intake)?;
    println!("{}", out.display());
    Ok(())
}
pub(super) fn owner_run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 7
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "repair-owner-141 PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    let b = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let p = queue_plan(&b)?;
    ensure!(
        p.program.sha256 == a[6] && fs::read_link("/proc/self/exe")? == p.program.path,
        "141 repair queue self binding differs"
    );
    let root = Path::new(ROOT);
    let m = fs::symlink_metadata(root)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0 && root.canonicalize()? == root,
        "141 repair output not root-private"
    );
    ensure!(
        !root.join("launch.json").try_exists()? && !root.join("state.json").try_exists()?,
        "141 repair task already exists; do not restart or discard history"
    );
    let u = fleet::unit(UNIT)?;
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        u["MainPID"].as_str().and_then(|v| v.parse::<u32>().ok()) == Some(std::process::id())
            && u["InvocationID"] == iid,
        "141 repair job is not its actual PID1 invocation"
    );
    let capture = json!({"schema":"jetstreamer-epoch141-repair-owner-capture-v2","epoch":141,"unit":UNIT,"invocation_id":iid,
        "queue_plan":b,"program":p.program,"manager":u,"process_start_ticks":ticks(u64::from(std::process::id()))?,
        "manager_start_unix_millis":pipeline_status::manager_start(UNIT,&iid)?,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "ordinary_replay_claim":false,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false});
    own(&u, &capture, &p, &b)?;
    let bootstrap_check = bootstrap(&p)?;
    fleet::persist(&root.join("launch.json"), &capture)?;
    let mut state = json!({"schema":"jetstreamer-epoch141-repair-queue-state-v2","epoch":141,"invocation_id":iid,"queue_plan":b,
        "status":"managing-repair","bootstrap_check":bootstrap_check,"retained_audit":retained_audit()?,"tasks":TASKS.iter().map(|id|json!({"id":id,"status":"awaiting-separately-admitted-task"})).collect::<Vec<_>>(),
        "checkpoint_beyond_bootstrap_proven":false,"remaining_growth_released":false});
    atomic_state(&state)?;
    let result = (|| -> Result<()> {
        loop {
            for i in 0..TASKS.len() {
                let row = &mut state["tasks"][i];
                let path = root.join(format!("task-admissions/{}.json", TASKS[i]));
                if row["status"] == "awaiting-separately-admitted-task" && path.try_exists()? {
                    let (admission, v) = current(&path)?;
                    let task = task_admit(&v, TASKS[i], &b, &iid)?;
                    fleet::persist(&root.join(format!("task-{}-capture.json", TASKS[i])), &task)?;
                    row["status"] = json!("actual-native-task-running");
                    row["task"] = task;
                    row["admission"] = json!(admission);
                    atomic_state(&state)?;
                } else if row["status"] == "actual-native-task-running" {
                    let task = &row["task"];
                    let name = task["unit"].as_str().unwrap();
                    let actual = fleet::unit(name)?;
                    ensure!(
                        actual["InvocationID"] == task["invocation_id"]
                            && actual["NRestarts"] == "0",
                        "141 repair task replaced/restarted"
                    );
                    if actual["MainPID"] == "0" {
                        ensure!(
                            actual["Result"] == "success"
                                && actual["ExecMainStatus"] == "0"
                                && actual["ControlGroup"] == ""
                                && matches!(actual["SubState"].as_str(), Some("exited" | "dead")),
                            "141 actual repair task failed; preserve its evidence"
                        );
                        row["status"] = json!("task-returned-success-awaiting-qualified-handoff");
                        row["terminal"] = actual;
                        atomic_state(&state)?;
                    } else {
                        ensure!(
                            actual["MainPID"]
                                .as_str()
                                .and_then(|s| s.parse::<u64>().ok())
                                == task["pid"].as_u64()
                                && ticks(task["pid"].as_u64().unwrap())?
                                    == task["process_start_ticks"].as_u64().unwrap(),
                            "141 running repair task changed"
                        );
                    }
                }
            }
            // This real owner supervises concrete task slots and preserves failures
            // across subprocess gaps; it does not pretend that waiting is replay.
            std::thread::sleep(Duration::from_secs(2));
        }
    })();
    if let Err(error) = &result {
        state["status"] = json!("failed-needs-repair");
        state["failure"] = json!(format!("{error:#}"));
        atomic_state(&state)?;
        fleet::persist(&root.join("failure.json"), &state)?;
    }
    result
}
fn forecast(b: &Bound) -> Result<(repair141_model::Forecast, Value)> {
    let (rate, policy, v) = policy(b)?;
    Ok((
        repair141_model::forecast(&rate, &policy).map_err(anyhow::Error::msg)?,
        v,
    ))
}
fn owner_evidence(capture: &Value, now: u64) -> Result<(Bound, QueuePlan, Value)> {
    ensure!(
        capture["schema"] == "jetstreamer-epoch141-repair-owner-capture-v2"
            && capture["epoch"] == 141
            && capture["unit"] == UNIT
            && capture["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= now),
        "foreign141 repair capture"
    );
    let b: Bound = serde_json::from_value(capture["queue_plan"].clone())?;
    let p = queue_plan(&b)?;
    let u = fleet::unit(UNIT)?;
    own(&u, capture, &p, &b)?;
    let (_, state) = current(&Path::new(ROOT).join("state.json"))?;
    ensure!(
        state["schema"] == "jetstreamer-epoch141-repair-queue-state-v2"
            && state["status"] == "managing-repair"
            && state["invocation_id"] == capture["invocation_id"]
            && state["queue_plan"] == capture["queue_plan"]
            && state["checkpoint_beyond_bootstrap_proven"] == false
            && state["remaining_growth_released"] == false
            && state["tasks"]
                .as_array()
                .is_some_and(|rows| rows.iter().filter_map(|r| r["id"].as_str()).eq(TASKS)),
        "141 repair queue failed or lost actual task ownership"
    );
    for flag in [
        "publication_authorized",
        "replay_launch_authorized",
        "r2_mutations",
        "ordinary_replay_claim",
    ] {
        ensure!(
            capture[flag] == false,
            "141 repair capture grants authority"
        );
    }
    Ok((b, p, u))
}
pub(super) fn validate_fleet_claim(
    epoch: u64,
    phase: &str,
    unit: &str,
    iid: &str,
    command: &str,
    evidence: &[Value],
) -> Result<()> {
    ensure!(
        epoch == 141 && scope(phase, unit),
        "foreign141 repair claim"
    );
    let matching: Vec<_> = evidence
        .iter()
        .filter(|v| v["schema"] == "jetstreamer-epoch141-repair-owner-capture-v2")
        .collect();
    ensure!(
        matching.len() == 1,
        "141 repair needs one actual native owner capture"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (_, _, u) = owner_evidence(matching[0], now)?;
    ensure!(
        u["InvocationID"] == iid
            && pipeline_status::same_exec_start(command, u["ExecStart"].as_str().unwrap_or("")),
        "141 repair fleet is not its real current owner"
    );
    Ok(())
}
pub(super) fn matches(
    receipt: &StatusPublicationReceipt,
    epoch: u64,
    census: &BTreeMap<String, Value>,
) -> bool {
    if epoch != 141 || receipt.status.phase != "verification" {
        return false;
    }
    receipt.pipeline_binding.as_ref().is_some_and(|b| {
        scope(&b.claim_phase, &b.unit) && census.get(UNIT).is_some_and(|u| b.live_matches(u))
    })
}
fn no_replacement(f: &Value, owner: &Value) -> Result<()> {
    let names: BTreeSet<_> = f["unit_census"]
        .as_object()
        .context("141 complete census")?
        .keys()
        .cloned()
        .chain([UNIT.into(), OLD.into()])
        .collect();
    let census = fleet::census(&names, 101, 200)?;
    ensure!(
        census[UNIT]["InvocationID"] == owner["InvocationID"]
            && census[UNIT]["MainPID"] == owner["MainPID"],
        "141 repair owner changed during census"
    );
    for (name, u) in census {
        if name == UNIT || name.starts_with("horizon-repair-141-task-") {
            continue;
        }
        let relevant = name.starts_with("horizon-qualify-141-")
            || name.starts_with("horizon-full-verify-141-")
            || name.starts_with("horizon-plugin-verify-141-")
            || name.starts_with("horizon-upload-141-")
            || name.starts_with("jetstreamer-root-import-e141-");
        ensure!(
            !(relevant
                && matches!(u["ActiveState"].as_str(), Some("active" | "activating"))
                && u["SubState"] != "exited"),
            "141 has another admitted replay/downstream owner; hand off instead of overwriting it"
        );
    }
    Ok(())
}
fn prior_owned(old: &StatusPublicationReceipt, binding: &pipeline_status::Binding) -> bool {
    old.epoch == 141
        && old.status.epoch == 141
        && (old.pipeline_binding.as_ref().is_some_and(|b| {
            (scope(&b.claim_phase, &b.unit) && b.invocation_id == binding.invocation_id)
                || (b.unit == OLD
                    && b.invocation_id == OLD_IID
                    && b.origin_unit == OLD
                    && b.origin_invocation_id == OLD_IID)
        }) || old.pipeline_binding.is_none()
            && old.controller_invocation_id == OLD_IID
            && old.producer_invocation_id == OLD_IID)
}
fn same_publication(
    existing: &StatusPublicationReceipt,
    expected: &StatusPublicationReceipt,
) -> bool {
    // A prior authenticated receipt's capture clock and previous ETag remain
    // historical; an idempotent retry must preserve those original bytes.
    let mut normalized = expected.clone();
    normalized.verified_unix_seconds = existing.verified_unix_seconds;
    normalized.previous_object_etag = existing.previous_object_etag.clone();
    existing == &normalized
}
pub(super) async fn publish() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        (a.len() == 7 || (a.len() == 8 && a[7] == "--check-only"))
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "status-publish-repair141 PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    let self_bound = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: a[6].clone(),
    };
    program(&self_bound)?;
    let b = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let p: PublishPlan = serde_json::from_value(read(&b, true)?)?;
    ensure!(
        p.schema == "jetstreamer-epoch141-repair-status-plan-v2"
            && p.epoch == 141
            && p.exclusive_local_epoch_ownership
            && p.authenticated_other_host_handoffs.is_empty()
            && p.receipt_directory
                == Path::new("/home/sol/.jetstreamer-private/r2-status-receipts")
            && p.estimate_receipt.starts_with(ROOT),
        "141 repair publisher scope/ownership differs"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let o = read(&p.observer, false)?;
    let f = read(&p.fleet, false)?;
    let sample = o["recorded_at_utc"].as_str().context("141 repair sample")?;
    let cutoff = fleet::utc_seconds(sample)?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && cutoff <= now
            && now - cutoff <= 1800
            && f["sampled_at_utc"] == sample
            && f["observer_sha256"] == p.observer.sha256
            && f["observer_receipt"].as_str() == p.observer.path.to_str()
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && f["inventory"]["anomalies"] == 0,
        "141 repair requires the current accepted coordinated fleet/sample"
    );
    let capture = read(&p.owner_capture, false)?;
    let (qb, _q, owner) = owner_evidence(&capture, now)?;
    ensure!(
        serde_json::to_value(&qb)? == serde_json::to_value(&p.queue_plan)?,
        "141 active repair policy/queue differs"
    );
    let entries: Vec<_> = f["epochs"]
        .as_array()
        .context("141 fleet epochs")?
        .iter()
        .filter(|r| r["epoch"] == 141)
        .collect();
    ensure!(
        entries.len() == 1
            && entries[0]["state"] == "failed-needs-repair"
            && f["pipelines"]
                .as_array()
                .is_some_and(|rs| rs.iter().any(|r| r["epoch"] == 141
                    && r["phase"] == PHASE
                    && r["live"] == true
                    && r["unit"]["InvocationID"] == owner["InvocationID"])),
        "141 repair projection lacks its actual active fleet task or lost open repair"
    );
    no_replacement(&f, &owner)?;
    let start = pipeline_status::manager_start(UNIT, owner["InvocationID"].as_str().unwrap())?;
    let elapsed = cutoff
        .checked_mul(1000)
        .context("141 sample overflow")?
        .checked_sub(start)
        .context("141 repair owner started after sample; no backdating")?;
    let projection = forecast(&p.policy)?;
    ensure!(
        projection.1["estimate_observer"] == serde_json::to_value(&p.observer)?
            && projection.1["estimate_owner_invocation_id"] == owner["InvocationID"],
        "141 forecast requires a newly reviewed assessment bound to this sample and actual repair owner"
    );
    let assessment_state = if projection.1["repair_state"].is_object() {
        let b: Bound = serde_json::from_value(projection.1["repair_state"].clone())?;
        ensure!(
            b.path == Path::new(ROOT).join("state.json"),
            "141 assessment must use the actual current queue state"
        );
        let snapshot = read(&b, false)?;
        ensure!(
            snapshot["status"] == "managing-repair"
                && snapshot["invocation_id"] == owner["InvocationID"]
                && snapshot["checkpoint_beyond_bootstrap_proven"] == false
                && snapshot["remaining_growth_released"] == false,
            "141 current assessment cannot assume qualified recovery progress"
        );
        Some(b)
    } else {
        None
    };
    let jet = regular_identity(&Path::new(PRIVATE).join("output/private.jet"))?;
    let status = EpochStatus {
        epoch: 141,
        jet_size_bytes: 0,
        elapsed_execution_millis: elapsed,
        estimated_remaining_millis: projection.0.estimated_remaining_millis,
        sampled_at_utc: sample.into(),
        phase: "verification".into(),
    };
    validate_epoch_status(&status, 141)?;
    let binding = pipeline_status::Binding {
        unit: UNIT.into(),
        invocation_id: owner["InvocationID"].as_str().unwrap().into(),
        expected_exec_start: owner["ExecStart"].as_str().unwrap().into(),
        claim_phase: PHASE.into(),
        origin_unit: UNIT.into(),
        origin_invocation_id: owner["InvocationID"].as_str().unwrap().into(),
        model_path: b.path.clone(),
        model_sha256: b.sha256.clone(),
        fleet_path: p.fleet.path.clone(),
        fleet_sha256: p.fleet.sha256.clone(),
    };
    binding.validate(141, "verification")?;
    let estimate = json!({"schema":"jetstreamer-epoch141-recovery-status-estimate-v2","plan":b,"observer":p.observer,"fleet":p.fleet,
        "queue_plan":p.queue_plan,"actual_repair_owner":p.owner_capture,"policy":p.policy,"status":status,
        "replay_from_bootstrap_slot":repair141_model::BOOTSTRAP,"root_replay_millis":projection.0.root_replay_millis,
        "suffix_replay_millis":projection.0.suffix_replay_millis,"prerequisite_millis":projection.0.prerequisite_millis,
        "planning_assumptions":projection.1,"no_resumable_checkpoint_proven":true,"partial_archive_is_ready":false,
        "retained_failed_attempt_jet_bytes":jet.length,"old_stopped_invocation":OLD_IID,"new_repair_clock_is_actual_owner_start":true,"canonical_writes_authorized":false,"r2_mutations":false});
    if a.len() == 8 {
        println!("{}", serde_json::to_string(&estimate)?);
        return Ok(());
    }
    preflight_status_receipt_write(&p.receipt_directory)?;
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    let before = get_mutable_object(&s3, &r2.bucket, "epoch-141.epoch-status.json").await?;
    let pending = if p.estimate_receipt.try_exists()? {
        let (_, old) = current(&p.estimate_receipt)?;
        ensure!(old == estimate, "141 same-sample durable estimate changed");
        true
    } else {
        false
    };
    if let Some(object) = &before {
        // Only a durable estimate written before PUT permits recovery when
        // publication/readback succeeded but the local status receipt failed.
        let recovering = pending && object.bytes == epoch_status_bytes(&status)?;
        if !recovering {
            let previous = p
                .previous_publication
                .as_ref()
                .context("141 existing status requires exact authenticated prior ownership")?;
            let value = read(previous, false)?;
            let old = validate_status_publication_receipt_bytes(
                previous.path.parent().context("141 prior receipt parent")?,
                &previous.path,
                &serde_json::to_vec(&value)?,
                &r2.bucket,
                141,
            )?;
            ensure!(
                prior_owned(&old, &binding)
                    && old.object_etag == object.etag
                    && serde_json::from_slice::<EpochStatus>(&object.bytes)? == old.status,
                "141 current R2 status belongs to another or newer owner"
            );
        }
    }
    ensure!(
        inventory_epoch(&s3, &r2, 141).await?.state != InventoryState::ReadyPair,
        "141 already has a ready pair; do not publish repair countdown"
    );
    if !p.estimate_receipt.try_exists()? {
        state_budget(2 << 20)?;
        fleet::persist(&p.estimate_receipt, &estimate)?;
    } else {
        let (_, old) = current(&p.estimate_receipt)?;
        ensure!(old == estimate, "141 same-sample estimate changed");
    }
    let (_, _, again) = owner_evidence(&capture, now)?;
    ensure!(again == owner, "141 repair owner changed before PUT");
    no_replacement(&f, &owner)?;
    if let Some(state) = &assessment_state {
        read(state, false)?;
    }
    let (etag, previous) = publish_epoch_status_bound_previous(
        &s3,
        &r2,
        &status,
        before.as_ref().map(|o| o.etag.as_str()),
    )
    .await?;
    let receipt = StatusPublicationReceipt {
        schema: PIPELINE_STATUS_RECEIPT_SCHEMA.into(),
        bucket: r2.bucket,
        epoch: 141,
        key: "epoch-141.epoch-status.json".into(),
        status,
        object_etag: etag,
        previous_object_etag: previous,
        observer_receipt: p.observer.path,
        observer_receipt_sha256: p.observer.sha256,
        controller_invocation_id: String::new(),
        producer_invocation_id: String::new(),
        authenticated_readback: true,
        verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        pipeline_binding: Some(binding),
    };
    let final_path = status_receipt_path(&p.receipt_directory, &receipt.status);
    if final_path.try_exists()? {
        let (_, value) = current(&final_path)?;
        let existing = validate_status_publication_receipt_bytes(
            &p.receipt_directory,
            &final_path,
            &serde_json::to_vec(&value)?,
            &receipt.bucket,
            141,
        )?;
        ensure!(
            same_publication(&existing, &receipt),
            "141 existing same-sample publication belongs to another model/owner"
        );
    } else {
        write_status_receipt(&p.receipt_directory, &receipt)?;
    }
    let (_, _, after) = owner_evidence(
        &capture,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    ensure!(
        after == owner,
        "141 repair owner changed during status publication; reconcile actual handoff"
    );
    println!(
        "{}",
        status_receipt_path(&p.receipt_directory, &receipt.status).display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> pipeline_status::Binding {
        pipeline_status::Binding {
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: "actual-command".into(),
            claim_phase: PHASE.into(),
            origin_unit: UNIT.into(),
            origin_invocation_id: "a".repeat(32),
            model_path: "/model".into(),
            model_sha256: "b".repeat(64),
            fleet_path: "/fleet".into(),
            fleet_sha256: "c".repeat(64),
        }
    }
    #[test]
    fn repair_wire_binding_is_exact_epoch_phase_and_actual_new_owner() {
        let mut b = binding();
        assert!(b.validate(141, "verification").is_ok());
        assert!(b.validate(142, "verification").is_err());
        assert!(b.validate(141, "replay").is_err());
        b.origin_invocation_id = OLD_IID.into();
        assert!(b.validate(141, "verification").is_err());
    }
    #[test]
    fn prior_publication_handoff_cannot_borrow_another_epoch_or_replacement_owner() {
        let mut r = crate::tests::status_publication_receipt(141);
        r.controller_invocation_id = OLD_IID.into();
        r.producer_invocation_id = OLD_IID.into();
        let b = binding();
        assert!(prior_owned(&r, &b));
        r.epoch = 142;
        assert!(!prior_owned(&r, &b));
        r.epoch = 141;
        r.pipeline_binding = Some(b.clone());
        assert!(prior_owned(&r, &b));
        r.pipeline_binding.as_mut().unwrap().invocation_id = "d".repeat(32);
        assert!(!prior_owned(&r, &b));
    }
    #[test]
    fn receipt_retry_preserves_old_capture_clock_but_rejects_new_model_payload_or_etag() {
        let r = crate::tests::status_publication_receipt(141);
        let mut retry = r.clone();
        retry.verified_unix_seconds += 1;
        retry.previous_object_etag = Some("current".into());
        assert!(same_publication(&r, &retry));
        for field in ["etag", "eta", "observer", "owner"] {
            let mut bad = retry.clone();
            match field {
                "etag" => bad.object_etag = "changed".into(),
                "eta" => bad.status.estimated_remaining_millis += 1,
                "observer" => bad.observer_receipt_sha256 = "f".repeat(64),
                _ => bad.pipeline_binding = Some(binding()),
            }
            assert!(!same_publication(&r, &bad), "{field}");
        }
    }
}
