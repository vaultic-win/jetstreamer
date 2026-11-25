//! Inspect the private epoch 166 gate and reprice its existing whole-tree booking.
mod guard_price;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const RT: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const RUNTIME: &str = "epoch166-write-version-gap-20261124-v1";
const LANE: &str = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1";
const RUN: &str = "bounded-write-version-20261124-v1";
const PRIOR: &str = "replacement-local3retry10-20261121-v1/cold-retry11-20261122";
const UNIT: &str = "horizon-qualify-166-write-version-reproduction-20261124-v1.service";
const TIMER: &str = "horizon-guard-166-write-version-reproduction-20261124-v1.timer";
const ALIAS: &str = "/run/horizon-166-write-version-v1";
const ROOT_SHA: &str = "6330ad3f82a308d4d616c7ddcf610faad5a97b4accfc0254013532ec821bdd15";
const INPUT_SHA: &str = "003af2196b0eba330a05ed78dafe3508c598bcc1566caf9528c6818ff076df50";
const LOG_SHA: &str = "1aaeb6c60a550f276f739d0a4bbf1dd192372f2d16794684e37735ceb058428b";
const GUARD: &str = "epoch166-write-version-reproduction-guard-20261124-v1/GUARD_QUALIFIED.json";
const GUARD_SHA: &str = "0dae43f20cdfe992fa26cc9141a3e395db7a68a82116a9c4e84577eb9d2fe5a5";
const V6_INVOCATION: &str = "a71285e56d674de3bf793692f93dfbb3";
const V6_PROVIDER: &str = "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v6-build-v1";
const V6_PROVIDER_SHA: &str = "197ba4e755875f01097446ab1a8958c604478e8e183769d451d968b269d7f349";
const V8_INVOCATION: &str = "653a9e16d1de4fbd84bc50cfa85afe70";
const V8_ACTIVE: &str = "survivor172-cadence-20261122-v1/FAILED166_CADENCE_V8_ACTIVE.json";
const V8_ACTIVE_SHA: &str = "5af272261eaf8c57abc806e03778cc0d6657a7fd118fd58476387ed7dd0d39b3";
const V8_SEAL: &str = "survivor172-cadence-20261122-v1/tools-cold168-retry4-failed166-v8-entry146/deployment-seal-receipt.json";
const V8_SEAL_SHA: &str = "3ae90b99cc09e7b58d1f88bc5ed72e8150d0383c906c0a169e401f262dab370a";
const V9_INVOCATION: &str = "ebdfc34db47c4e7699ea5ccbada5d604";
const V9_CHECKER: &str = "epoch145-semantic-continuity-20261121-v1/tools-v9-census-recovery";
const V9_CHECKER_SHA: &str = "8766c269034824f114eb1906e1913188f615309b51243e8e23ca111936efeebd";
const V9_HANDOFF: &str = "epoch145-semantic-continuity-20261121-v1/v9-census-name-handoff";
const V9_SUBMISSION_SHA: &str = "33cef3c0ae1bc0aebe1bd8ab950c781c518ce646656f8ffbc66229aaf823c973";
const V9_RECOVERY_SHA: &str = "eaf570320604963b6270c1aa2854c48f6cc0c3a5254c829a699d9b6272e6b2c4";
const V12_ACTIVE: &str = "survivor172-cadence-20261122-v1/FAILED166_CADENCE_V12_ACTIVE.json";
const V12_READY: &str = "survivor172-cadence-20261122-v1/FAILED166_CADENCE_V12_READY.json";
const V12_PACKAGE: &str =
    "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v12-entry146";
const V12_SEAL_SHA: &str = "6899ee7708ca74e9bf2a04cb932ce2fc75dff18e16866149b1dbeea3887496ac";
const V12_UNIT: &str = "horizon-archive-status-cadence-after172-20261120-v1.service";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const CAP: u64 = 288 << 30;
const MIN_FLOOR: u64 = 8_297_502_499_408;

fn runtime() -> PathBuf {
    Path::new(RT).join(RUNTIME)
}
fn reference(path: &Path, sha: &str) -> Value {
    json!({"path":path,"sha256":sha})
}
fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v[field]
        .as_str()
        .with_context(|| format!("missing text {field}"))
}
fn num(v: &Value, field: &str) -> Result<u64> {
    v[field]
        .as_u64()
        .with_context(|| format!("missing unsigned integer {field}"))
}
fn stamp(m: &fs::Metadata) -> (u64, u64, u64, i64, i64) {
    (m.dev(), m.ino(), m.len(), m.ctime(), m.ctime_nsec())
}
fn trusted(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "indirect input {}",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 64 << 20,
        "invalid input custody {}",
        path.display()
    );
    let mut bytes = Vec::new();
    (&f).take((64 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && stamp(&m) == stamp(&f.metadata()?)
            && stamp(&m) == stamp(&path.symlink_metadata()?),
        "input changed {}",
        path.display()
    );
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn bound(r: &Value) -> Result<Value> {
    let p = Path::new(text(r, "path")?);
    let b = trusted(p)?;
    ensure!(
        digest(&b) == text(r, "sha256")?,
        "wrong digest {}",
        p.display()
    );
    Ok(serde_json::from_slice(&b)?)
}
fn member(seal: &Value, name: &str) -> Result<Value> {
    let entries = seal["members"]
        .as_array()
        .context("missing sealed members")?;
    let mut matches = entries.iter().filter(|entry| entry["name"] == name);
    let row = matches.next().context("missing sealed member")?;
    ensure!(matches.next().is_none(), "duplicate sealed member");
    let path = Path::new(text(seal, "destination")?).join(name);
    ensure!(
        digest(&trusted(&path)?) == text(row, "sha256")?,
        "sealed member changed {name}"
    );
    Ok(reference(&path, text(row, "sha256")?))
}
fn show(unit: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", "--no-pager", "--property", fields, "--", unit])
        .env("LC_ALL", "C")
        .output()?;
    ensure!(
        out.status.success(),
        "systemctl show {unit}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)?
        .lines()
        .map(|line| {
            let (k, v) = line
                .split_once('=')
                .context("invalid native service property")?;
            Ok((k.to_owned(), v.to_owned()))
        })
        .collect()
}
fn no_file(path: &Path) -> Result<()> {
    match path.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("path already occupied {}", path.display()),
    }
}
fn token(v: &str) -> bool {
    v.len() == 32
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && v.bytes().any(|b| b != b'0')
}
fn same_file(a: &Path, b: &Path) -> Result<()> {
    let first = a.metadata()?;
    let second = b.metadata()?;
    ensure!(
        (first.dev(), first.ino()) == (second.dev(), second.ino()),
        "different {} and {}",
        a.display(),
        b.display()
    );
    Ok(())
}

fn generation() -> Result<Value> {
    let r = runtime();
    let root_ref = reference(&r.join("SUCCESSOR_ROOT.json"), ROOT_SHA);
    let root = bound(&root_ref)?;
    let dir = Path::new(LANE).join(RUN);
    let m = dir.symlink_metadata()?;
    ensure!(
        dir.canonicalize()? == dir
            && root["root"] == json!(dir)
            && root["device"] == m.dev()
            && root["inode"] == m.ino()
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o755,
        "different reproduction root"
    );
    let seal_ref = reference(&r.join("sealed/deployment-seal-receipt.json"), INPUT_SHA);
    ensure!(
        root["input_deployment"] == seal_ref,
        "input generation not bound to root"
    );
    let seal = bound(&seal_ref)?;
    ensure!(
        seal["destination"] == json!(r.join("sealed")),
        "incorrect input seal destination"
    );
    let gate = member(&seal, "gate")?;
    let unit = member(&seal, UNIT)?;
    let guard_ref = reference(&Path::new(RT).join(GUARD), GUARD_SHA);
    let guard = bound(&guard_ref)?;
    let log_ref = reference(&r.join("OBSERVER_LOG_PREPARED.json"), LOG_SHA);
    let log = bound(&log_ref)?;
    let log_path = dir.join("producer.log");
    let m = log_path.symlink_metadata()?;
    ensure!(
        log["path"] == json!(log_path)
            && log["successor_root"] == root_ref
            && log["guard_qualification"] == guard_ref
            && log["device"] == m.dev()
            && log["inode"] == m.ino()
            && m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600,
        "different append log"
    );
    bound(&root["predecessor_terminal"])?;
    Ok(
        json!({"successor_root":root_ref,"input_seal":seal_ref,"gate":gate,"unit_file":unit,"guard_qualification":guard_ref,
        "guard":guard["guard"],"guard_contract":guard["contract"],"append_log":log_ref,"retry11_terminal":root["predecessor_terminal"]}),
    )
}

fn vacant() -> Result<()> {
    for unit in [UNIT, TIMER, &TIMER.replace(".timer", ".service")] {
        let v = show(
            unit,
            "Id,LoadState,ActiveState,SubState,Job,MainPID,ControlPID",
        )?;
        ensure!(
            v.get("Id").map(String::as_str) == Some(unit)
                && v["ActiveState"] == "inactive"
                && v["SubState"] == "dead"
                && matches!(v["LoadState"].as_str(), "not-found" | "loaded")
                && v["Job"].is_empty()
                && ["MainPID", "ControlPID"]
                    .iter()
                    .all(|k| v.get(*k).is_none_or(|pid| pid == "0")),
            "occupied {unit}"
        );
    }
    let root = runtime();
    for name in [
        "barrier/allow",
        "START_INTENT.json",
        "FIRST_GUARD.json",
        "ACTUAL_ADMISSION_AND_PROTECTION.json",
    ] {
        no_file(&root.join(name))?;
    }
    ensure!(
        Path::new(LANE)
            .join(RUN)
            .join("producer.log")
            .metadata()?
            .len()
            == 0,
        "diagnostic log already contains a prior run"
    );
    Ok(())
}

fn current_fleet(fleet: &Value) -> Result<Value> {
    let p = Path::new(text(fleet, "path")?);
    ensure!(
        p.file_name().and_then(|v| v.to_str()) == Some("ROOT_COMPLETE_OPERATIONAL_FLEET.json")
            && p.parent().and_then(Path::parent) == Some(Path::new(RT)),
        "wrong fleet path"
    );
    let f = bound(fleet)?;
    let timer = text(&f, "sole_next_timer")?;
    ensure!(
        timer.starts_with("horizon-observer-root")
            && timer.ends_with(".timer")
            && !timer.contains('/'),
        "foreign observer timer"
    );
    let next = timer
        .trim_start_matches("horizon-observer-")
        .trim_end_matches(".timer");
    no_file(
        &Path::new(RT)
            .join(next)
            .join("ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
    )?;
    let state = show(timer, "Id,ActiveState,SubState,Job")?;
    ensure!(
        state["Id"] == timer
            && state["ActiveState"] == "active"
            && state["SubState"] == "waiting"
            && state["Job"].is_empty(),
        "fleet observer has turned over"
    );
    bound(&f["sole_next_observer"])?;
    Ok(f)
}

fn home_funding(native: &Value, retry5: bool) -> Result<(u64, u64)> {
    let donor = &native["epoch159_donor_cover"];
    let donor_home = num(donor, "native_home_required")?;
    let current = num(native, "complete_required_HOME_bytes")?;
    let zero = num(native, "full166_zero_remaining_native_HOME_bytes")?;
    if !retry5 {
        ensure!(
            zero > 0 && zero <= current && current <= donor_home,
            "inconsistent full-tree projection or donor requirement"
        );
        return Ok((
            donor_home,
            zero.checked_add(donor_home - current)
                .context("donor floor overflow")?,
        ));
    }

    let projection = &native["full166_retry5_projection"];
    let base = num(projection, "native_current_HOME_bytes")?;
    let booking = &native["retry5_complete_booking"];
    let lag = num(booking, "outside_cap_stop_allowance_bytes")?;
    let growth = num(booking, "candidate_remaining_bytes")?;
    let guard = num(native, "active168_guard_floor")?;
    ensure!(
        zero > 0
            && zero <= base
            && base <= donor_home
            && projection["native_zero_remaining_HOME_bytes"] == zero
            && projection["funded_current_HOME_bytes"] == current
            && booking["schema"] == "horizon-168-retry5-complete-booking-v1"
            && booking["funded"] == true
            && booking["retained_source"] == native["retry5_retained_source"]
            && booking["retained_base_HOME_bytes"] == donor_home
            && booking["retained_guard_floor_bytes"] == guard
            && booking["complete_required_HOME_bytes"] == current
            && native["bookings"]["168"]["cap_bytes"] == (512u64 << 30)
            && native["bookings"]["168"]["remaining_bytes"] == growth
            && lag == (8u64 << 30)
            && donor["credited_retirement_bytes"] == 0,
        "incomplete retry5 reservation or epoch 166 projection"
    );
    let combined = |floor: u64| {
        floor
            .checked_add(lag)
            .and_then(|value| value.max(guard).checked_add(growth))
            .context("retry5 combined HOME overflow")
    };
    let zero_funded = combined(donor_home - (base - zero))?;
    ensure!(
        combined(donor_home)? == current
            && projection["funded_zero_remaining_HOME_bytes"] == zero_funded,
        "retry5 growth differs between epoch 166 projections"
    );
    Ok((current, zero_funded))
}

fn prestart_price(
    n: &Value,
    fleet_ref: &Value,
    fleet: &Value,
    evidence: &Value,
    now: u64,
    retry5: bool,
) -> Result<Value> {
    let book = &n["bookings"]["166"];
    let used = num(book, "physical_bytes")?;
    let remaining = num(book, "remaining_bytes")?;
    let donor = &n["epoch159_donor_cover"];
    let recorded = num(n, "recorded_unix_seconds")?;
    ensure!(
        now.checked_sub(recorded).is_some_and(|age| age <= 120)
            && n["schema"] == "horizon-incident-replay-fit-v1"
            && n["epoch"] == 145
            && n["fleet"] == *fleet_ref
            && n["fits"] == true
            && n["replay_launch_authorized"] == false
            && n["resource_credit_bytes"] == 0
            && n.get("candidate") == Some(&Value::Null)
            && n.get("bounded_qualification") == Some(&Value::Null)
            && n["complete_cpu_quota_micros"] == 64_000_000u64
            && n["complete_memory_plus_reserve_bytes"] == 810_658_050_048u64
            && n["failed_cold166"]["terminal"] == evidence["retry11_terminal"]
            && n["failed_cold166"]["reservation_ending_bytes"] == 0
            && n["replacements"].get("166").is_none()
            && book["root"] == LANE
            && book["run"] == json!(Path::new(LANE).join(PRIOR))
            && num(book, "cap_bytes")? == CAP
            && used.checked_add(remaining) == Some(CAP)
            && remaining > 0
            && book["measurement"] == "two complete stopped-tree walks"
            && donor["fleet"] == *fleet_ref
            && donor["native_recorded_unix_seconds"] == recorded
            && donor["schema"] == "horizon-145-drained-159-donor-cover-v1",
        "unfunded or foreign epoch 166 predecessor price"
    );
    let mut absolute = MIN_FLOOR.max(num(n, "active168_guard_floor")?);
    if let Some(floor) = n["candidate136"].get("guard_floor") {
        absolute = absolute.max(floor.as_u64().context("invalid candidate136 floor")?);
    }
    for v in n["survivors"]
        .as_object()
        .context("missing survivors")?
        .values()
    {
        absolute = absolute.max(num(&v["guard"], "floor")?);
    }
    for v in n["replacements"]
        .as_object()
        .context("missing replacements")?
        .values()
    {
        absolute = absolute.max(num(v, "floor")?);
    }
    let base = num(n, "complete_required_HOME_bytes")?;
    ensure!(
        num(n, "protected_raw_floor_bytes")? <= base,
        "inconsistent native floor"
    );
    let (current_donor, zero_donor) = home_funding(n, retry5)?;
    let funded = current_donor.max(
        zero_donor
            .checked_add(remaining)
            .context("full-tree price overflow")?,
    );
    let floor = absolute.max(funded - remaining);
    let required = floor
        .checked_add(remaining)
        .context("fleet price overflow")?;
    let available = num(n, "available_HOME_bytes")?.min(num(
        fleet,
        "complete_cycle_conservative_available_DATA_bytes",
    )?);
    ensure!(
        required <= available,
        "epoch 166 HOME requires {required} bytes, available {available}, shortfall {} bytes, zero-remaining donor floor {zero_donor}, remaining {remaining}",
        required.saturating_sub(available)
    );
    ensure!(
        required - funded <= num(donor, "remaining_home_bytes")?
            && num(n, "available_memory_bytes")? >= num(n, "required_available_memory_bytes")?,
        "epoch 166 exceeds retained HOME, donor, or memory capacity"
    );
    let mut q = n.clone();
    q["epoch"] = json!(166);
    q["protected_raw_floor_bytes"] = json!(floor);
    q["complete_required_HOME_bytes"] = json!(required);
    q["available_HOME_bytes"] = json!(available);
    q["bookings"]["166"]["run"] = json!(Path::new(LANE).join(RUN));
    q["epoch166_write_version_reproduction"] = json!({"stage":"prestart","evidence":evidence,"predecessor_booking":book,
        "whole_tree_remaining_bytes":remaining,"absolute_incumbent_floor_bytes":absolute,"native_donor_requirement":funded,"zero_remaining_donor_floor_bytes":zero_donor,
        "additional_required_home_bytes":required-funded,"first_guard_required_before_release":true,
        "private_diagnostic":true,"archive_publication_authorized":false});
    Ok(q)
}

fn ticks(proc: &Path) -> Result<u64> {
    let line = fs::read_to_string(proc.join("stat"))?;
    let fields = line.rsplit_once(") ").context("invalid proc stat")?.1;
    Ok(fields
        .split_whitespace()
        .nth(19)
        .context("missing process start")?
        .parse()?)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn live_document(p: &Path) -> Result<(Value, Value)> {
    let bytes = trusted(p)?;
    Ok((
        serde_json::from_slice(&bytes)?,
        reference(p, &digest(&bytes)),
    ))
}
fn held(fleet: &Value, evidence: &Value) -> Result<Value> {
    let dir = runtime();
    let lane_run = Path::new(LANE).join(RUN);
    let (intent, iref) = live_document(&dir.join("START_INTENT.json"))?;
    let price_ref = &intent["prestart"];
    let price = bound(price_ref)?;
    ensure!(
        intent["schema"] == "horizon-166-write-version-reproduction-start-intent-v1"
            && intent["epoch"] == 166
            && intent["producer_unit"] == UNIT
            && intent["timer_unit"] == TIMER
            && intent["fleet"] == *fleet
            && price["fleet"] == *fleet
            && price["epoch"] == 166
            && price["fits"] == true
            && price["resource_credit_bytes"] == 0
            && price["replay_launch_authorized"] == false
            && price["epoch166_write_version_reproduction"]["stage"] == "prestart"
            && price["epoch166_write_version_reproduction"]["evidence"] == *evidence
            && num(
                &price["epoch166_write_version_reproduction"],
                "zero_remaining_donor_floor_bytes"
            )? > 0
            && intent["armed_floor"] == price["protected_raw_floor_bytes"]
            && num(&intent, "armed_floor")? >= MIN_FLOOR
            && price["bookings"]["166"]["run"] == json!(lane_run)
            && num(&price["bookings"]["166"], "cap_bytes")? == CAP,
        "different reproduction intent or prestart booking"
    );
    for name in [
        "barrier/allow",
        "AUTHORIZED_GATED_PAYLOAD.json",
        "ACTUAL_ADMISSION_AND_PROTECTION.json",
        "FIRST_PROTECTED_WORKER.json",
    ] {
        no_file(&dir.join(name))?;
    }
    let fields = "Id,FragmentPath,LoadState,ActiveState,SubState,Job,MainPID,ControlPID,InvocationID,NRestarts,Restart,ControlGroup,KillMode,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,User,Group,DropInPaths";
    let unit = show(UNIT, fields)?;
    let group = format!("/system.slice/{UNIT}");
    ensure!(
        unit["Id"] == UNIT
            && unit["LoadState"] == "loaded"
            && unit["ActiveState"] == "active"
            && unit["SubState"] == "running"
            && unit["Job"].is_empty()
            && unit["ControlPID"] == "0"
            && unit["ControlGroup"] == group
            && unit["Restart"] == "no"
            && unit["NRestarts"] == "0"
            && unit["KillMode"] == "control-group"
            && unit["CPUQuotaPerSecUSec"] == "9s"
            && unit["MemoryMax"] == "73014444032"
            && unit["MemorySwapMax"] == "0"
            && unit["TasksMax"] == "1024"
            && unit["User"] == "sol"
            && unit["Group"] == "horizon"
            && unit["DropInPaths"].is_empty()
            && token(&unit["InvocationID"]),
        "different native service or resource limits"
    );
    let fragment = Path::new(&unit["FragmentPath"]).canonicalize()?;
    ensure!(
        digest(&trusted(&fragment)?) == text(&evidence["unit_file"], "sha256")?,
        "different PID 1 fragment"
    );
    let pid = unit["MainPID"].parse::<u32>()?;
    ensure!(pid > 1, "missing held producer PID");
    let proc = Path::new("/proc").join(pid.to_string());
    let cgroup = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    let start = ticks(&proc)?;
    ensure!(
        fs::read_to_string(proc.join("cgroup"))?.trim() == format!("0::{group}")
            && fs::read_to_string(cgroup.join("cgroup.procs"))?.trim() == pid.to_string()
            && fs::read_to_string(cgroup.join("memory.max"))?.trim() == "73014444032"
            && fs::read_to_string(cgroup.join("memory.swap.max"))?.trim() == "0"
            && fs::read_to_string(cgroup.join("pids.max"))?.trim() == "1024",
        "different kernel cgroup or population"
    );
    let cpu = fs::read_to_string(cgroup.join("cpu.max"))?;
    let values: Vec<u64> = cpu
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        values.len() == 2 && values[1] > 0 && values[1].checked_mul(9) == Some(values[0]),
        "different kernel CPU reservation"
    );
    let status = fs::read_to_string(proc.join("status"))?;
    for (name, id) in [("Uid:", "1001"), ("Gid:", "1003")] {
        let row = status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .context("missing held credentials")?;
        ensure!(
            row.split_whitespace().eq([id, id, id, id]),
            "changed held credentials"
        );
    }
    let alias = Path::new(ALIAS);
    let projected = proc.join("root").join(alias.strip_prefix("/")?);
    let gate = Path::new(text(&evidence["gate"], "path")?);
    same_file(&proc.join("exe"), gate)?;
    same_file(&projected.join("gate"), gate)?;
    same_file(&projected.join("barrier"), &dir.join("barrier"))?;
    same_file(&proc.join("fd/1"), &lane_run.join("producer.log"))?;
    same_file(&proc.join("fd/2"), &lane_run.join("producer.log"))?;
    no_file(&projected.join("barrier/allow"))?;
    ensure!(
        fs::read(proc.join("cmdline"))? == format!("{ALIAS}/gate\0").as_bytes(),
        "different gate argv"
    );
    let mounts = fs::read_to_string(proc.join("mountinfo"))?;
    for name in ["gate", "barrier"] {
        let target = alias.join(name);
        let present = mounts
            .lines()
            .filter(|line| {
                let mut f = line.split_whitespace();
                f.nth(4) == target.to_str()
                    && f.next()
                        .is_some_and(|opts| opts.split(',').any(|v| v == "ro"))
            })
            .count();
        ensure!(present == 1, "incorrect read-only gate projection {name}");
    }
    let exe = proc.join("exe").metadata()?;
    ensure!(
        ticks(&proc)? == start
            && unit == show(UNIT, fields)?
            && fs::read_to_string(cgroup.join("cgroup.procs"))?.trim() == pid.to_string(),
        "gate changed during census"
    );
    Ok(
        json!({"unit":UNIT,"producer_unit":UNIT,"producer_invocation_id":unit["InvocationID"],"invocation_id":unit["InvocationID"],
        "producer_pid":pid,"start_ticks":start,"cgroup":group,"processes":[[pid,start,exe.dev(),exe.ino()]],
        "boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),"start_intent":iref,
        "fleet":fleet,"prestart":price_ref,"armed_floor":intent["armed_floor"],"root":evidence["successor_root"]}),
    )
}

fn owner(mode: &str, fleet: &Value, evidence: &Value) -> Result<Value> {
    if mode == "prestart" {
        vacant()?;
        return Ok(Value::Null);
    }
    let mut actor = held(fleet, evidence)?;
    if mode == "post-guard" {
        let proof = guard_price::first_guard(&actor, evidence)?;
        ensure!(
            actor == held(fleet, evidence)?,
            "actor changed during guard check"
        );
        actor["first_guard"] = proof;
    }
    Ok(actor)
}

fn reprice_held(
    price: &mut Value,
    n: &Value,
    actor: &Value,
    prior: &Value,
    fleet: &Value,
    retry5: bool,
) -> Result<()> {
    ensure!(
        n["population"][UNIT] == json!([[actor["producer_pid"], actor["start_ticks"]]])
            && n["status_registration"] == prior["status_registration"]
            && n["fleet"] == prior["fleet"],
        "incumbent writer, held population, or fleet changed"
    );
    let book = &n["bookings"]["166"];
    let first = &actor["first_guard"];
    let physical =
        num(book, "physical_bytes")?.min(num(&prior["bookings"]["166"], "physical_bytes")?);
    let physical = if first.is_null() {
        physical
    } else {
        physical.min(num(first, "physical_bytes")?)
    };
    let remaining = CAP
        .checked_sub(physical)
        .context("actual tree exceeds reservation")?;
    let extra = num(book, "physical_bytes")? - physical;
    let donor = &n["epoch159_donor_cover"];
    let funded = home_funding(n, retry5)?
        .0
        .checked_add(extra)
        .context("actual complete price overflow")?
        .max(
            num(
                &price["epoch166_write_version_reproduction"],
                "zero_remaining_donor_floor_bytes",
            )?
            .checked_add(remaining)
            .context("actual full-tree floor overflow")?,
        );
    let armed = num(actor, "armed_floor")?;
    let absolute = num(
        &price["epoch166_write_version_reproduction"],
        "absolute_incumbent_floor_bytes",
    )?;
    ensure!(
        armed >= absolute && armed >= funded.checked_sub(remaining).context("invalid funding")?,
        "first guard floor cannot cover complete current fleet"
    );
    let available = num(price, "available_HOME_bytes")?.min(num(
        fleet,
        "complete_cycle_conservative_available_DATA_bytes",
    )?);
    let available = if first.is_null() {
        available
    } else {
        available.min(num(first, "available_bytes")?)
    };
    let required = armed
        .checked_add(remaining)
        .context("actual booking overflow")?;
    ensure!(
        required >= funded
            && required <= available
            && required - funded <= num(donor, "remaining_home_bytes")?,
        "insufficient donor or measured HOME for remaining whole tree"
    );
    price["available_HOME_bytes"] = json!(available);
    price["complete_required_HOME_bytes"] = json!(required);
    price["protected_raw_floor_bytes"] = json!(armed);
    price["bookings"]["166"]["physical_bytes"] = json!(physical);
    price["bookings"]["166"]["remaining_bytes"] = json!(remaining);
    price["bookings"]["166"]["measurement"] =
        json!("conservative prestart and held whole-tree measurements");
    price["candidate"] = actor.clone();
    let detail = &mut price["epoch166_write_version_reproduction"];
    detail["stage"] = json!(if first.is_null() {
        "held"
    } else {
        "post-guard"
    });
    detail["whole_tree_remaining_bytes"] = json!(remaining);
    detail["native_donor_requirement"] = json!(funded);
    detail["additional_required_home_bytes"] = json!(required - funded);
    detail["start_intent"] = actor["start_intent"].clone();
    detail["first_guard"] = first.clone();
    Ok(())
}

fn v6_price_refs(native: &Value) -> Result<(&Value, &Value)> {
    let root = Path::new(RT);
    let phase = &native["phase145"];
    let complete = &phase["completion"];
    let checker = &phase["checker_seal"];
    ensure!(
        phase["stage"] == "v6-semantic-complete-drained"
            && phase["completed_invocation_id"] == V6_INVOCATION
            && complete["path"]
                == json!(
                    root.join("epoch145-guarded-export-20261121-v1/state")
                        .join(V6_INVOCATION)
                        .join("complete.json")
                )
            && *checker
                == reference(
                    &root.join(V6_PROVIDER).join("deployment-seal-receipt.json"),
                    V6_PROVIDER_SHA,
                ),
        "epoch 166 requires the exact drained V6 verifier and completion provider"
    );
    let writer = &native["status_registration"];
    ensure!(
        writer["invocation_id"] == V8_INVOCATION
            && writer["consumer_seal"] == reference(&root.join(V8_SEAL), V8_SEAL_SHA),
        "epoch 166 V6 price requires the registered V8 writer"
    );
    Ok((complete, checker))
}

fn verify_v6_dependencies(native: &Value) -> Result<()> {
    let (complete, checker) = v6_price_refs(native)?;
    let root = Path::new(RT);
    let package = bound(checker)?;
    ensure!(
        package["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && package["destination"] == json!(root.join(V6_PROVIDER))
            && package["sealer_sha256"] == SEALER_SHA
            && package["remote_mutations"] == false
            && package["r2_mutations"] == false,
        "foreign V6 completion provider seal"
    );
    member(&package, "incident-post-phase.py")?;
    bound(complete)?;
    let writer = &native["status_registration"];
    let active = bound(&reference(&root.join(V8_ACTIVE), V8_ACTIVE_SHA))?;
    let current = &active["new"];
    ensure!(
        active["schema"] == "horizon-epoch166-cadence-rejoin-active-v1"
            && current["invocation_id"] == writer["invocation_id"]
            && current["pid"] == writer["pid"]
            && current["start_ticks"] == writer["start_ticks"],
        "epoch 166 V8 writer identity changed"
    );
    bound(&writer["consumer_seal"])?;
    Ok(())
}

fn v9_price_refs(native: &Value) -> Result<[&Value; 3]> {
    let root = Path::new(RT);
    let phase = &native["phase145"];
    let complete = &phase["completion"];
    let checker = &phase["checker_seal"];
    let semantic = &phase["semantic_receipt"];
    ensure!(
        phase["stage"] == "v9-semantic-complete-drained"
            && phase["completed_invocation_id"] == V9_INVOCATION
            && complete["path"]
                == json!(
                    root.join("epoch145-guarded-export-20261121-v1/state")
                        .join(V9_INVOCATION)
                        .join("complete.json")
                )
            && semantic["path"] == json!(root.join(V9_HANDOFF).join("SEMANTIC_COMPLETION.json"))
            && *checker
                == reference(
                    &root.join(V9_CHECKER).join("deployment-seal-receipt.json"),
                    V9_CHECKER_SHA
                )
            && native["status_registration"]["consumer_seal"]
                == reference(
                    &root.join(V12_PACKAGE).join("deployment-seal-receipt.json"),
                    V12_SEAL_SHA
                ),
        "epoch 166 requires the exact V9 semantic completion and V12 quote"
    );
    Ok([complete, checker, semantic])
}

fn v12_identity(writer: &Value, active: &Value, ready: &Value) -> Result<()> {
    let root = Path::new(RT);
    let actor = &active["new"];
    ensure!(
        active["schema"] == "horizon-epoch166-cadence-rejoin-active-v1"
            && active["producer_mutations"] == false
            && active["ready"]["path"] == json!(root.join(V12_READY))
            && ready["schema"] == "horizon-epoch166-cadence-rejoin-ready-v1"
            && ready["package"] == writer["consumer_seal"]
            && actor["unit"] == V12_UNIT
            && actor["program"] == json!(root.join(V12_PACKAGE).join("status_cycle.py"))
            && token(text(actor, "invocation_id")?)
            && num(actor, "pid")? > 1
            && num(actor, "start_ticks")? > 0
            && ["invocation_id", "pid", "start_ticks"]
                .iter()
                .all(|key| actor[*key] == writer[*key]),
        "epoch 166 V12 writer identity changed"
    );
    Ok(())
}

fn verify_v9_dependencies(native: &Value) -> Result<Value> {
    let [complete, checker, semantic] = v9_price_refs(native)?;
    let root = Path::new(RT);
    let package = bound(checker)?;
    ensure!(
        package["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && package["destination"] == json!(root.join(V9_CHECKER))
            && package["sealer_sha256"] == SEALER_SHA
            && package["remote_mutations"] == false
            && package["r2_mutations"] == false,
        "foreign V9 semantic checker seal"
    );
    member(&package, "v5v_semantic_completion.py")?;
    let terminal = bound(semantic)?;
    ensure!(
        terminal["schema"] == "horizon-epoch145-v8-census-successor-semantic-completion-v1"
            && terminal["invocation_id"] == V9_INVOCATION
            && terminal["completion"] == *complete
            && bound(complete)?["iid"] == V9_INVOCATION
            && terminal["startup_evidence"]["worker_seal"] == *checker
            && terminal["startup_evidence"]["submission_result"]
                == reference(
                    &root.join(V9_HANDOFF).join("START_RESULT.json"),
                    V9_SUBMISSION_SHA
                )
            && terminal["start"] == terminal["startup_evidence"]["start"]
            && terminal["start"]
                == reference(
                    &root.join("epoch145-guarded-export-20261121-v1/state")
                        .join(V9_INVOCATION)
                        .join("recovery-started.json"),
                    V9_RECOVERY_SHA,
                )
            && terminal["native_success"]["INVOCATION_ID"] == V9_INVOCATION
            && terminal["native_success"]["_PID"] == "1"
            && terminal["native_success"]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && terminal["publication_authorized"] == false
            && terminal["r2_mutations"] == false,
        "epoch 166 V9 semantic completion changed"
    );
    let writer = &native["status_registration"];
    bound(&writer["consumer_seal"])?;
    let (active, active_ref) = live_document(&root.join(V12_ACTIVE))?;
    ensure!(
        active["ready"]["path"] == json!(root.join(V12_READY)),
        "foreign V12 ready path"
    );
    v12_identity(writer, &active, &bound(&active["ready"])?)?;
    let pid = num(writer, "pid")?;
    let manager = show(
        V12_UNIT,
        "Id,InvocationID,ActiveState,SubState,MainPID,NRestarts",
    )?;
    ensure!(
        manager["Id"] == V12_UNIT
            && manager["InvocationID"] == text(writer, "invocation_id")?
            && manager["ActiveState"] == "active"
            && manager["SubState"] == "running"
            && manager["MainPID"] == pid.to_string()
            && manager["NRestarts"] == "0"
            && ticks(&Path::new("/proc").join(pid.to_string()))? == num(writer, "start_ticks")?,
        "epoch 166 V12 live writer changed"
    );
    Ok(active_ref)
}

fn price(mode: &str, fleet: &Value, generation_name: &str, seal_sha: &str) -> Result<Value> {
    let f = current_fleet(fleet)?;
    let evidence = generation()?;
    let before = owner(mode, fleet, &evidence)?;
    ensure!(
        matches!(
            generation_name,
            "v5w" | "post145" | "post145-v5z" | "post145-v6" | "post145-v9"
        ),
        "unknown epoch 145 provider generation"
    );
    let deployment = Path::new(RT).join(format!(
        "incident-replay-fit-20261121-v1/tools-homefloor-166-write-version-{generation_name}-v1"
    ));
    let sr = reference(&deployment.join("deployment-seal-receipt.json"), seal_sha);
    let seal = bound(&sr)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(deployment)
            && seal["sealer_sha256"] == SEALER_SHA,
        "foreign capacity deployment"
    );
    let program = member(&seal, "post-stop-fit")?;
    let local = fs::read_link("/proc/self/exe")?;
    let sealed = member(&seal, "reproduction-admission")?;
    ensure!(
        digest(&trusted(&local)?) == text(&sealed, "sha256")?,
        "native observer differs from sealed provider member"
    );
    let out = Command::new("/usr/bin/timeout")
        .args(["120", "/usr/bin/python3", "-IB", text(&program, "path")?])
        .arg(format!("--repro166={mode}"))
        .args(["145", text(fleet, "path")?, text(fleet, "sha256")?])
        .output()?;
    ensure!(
        out.status.success(),
        "native capacity capture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let n: Value = serde_json::from_slice(&out.stdout)?;
    ensure!(
        current_fleet(fleet)? == f
            && generation()? == evidence
            && owner(mode, fleet, &evidence)? == before,
        "actor or fleet changed during native capacity capture"
    );
    ensure!(
        n.get("reproduction166_owner") == Some(&before),
        "unbound held owner"
    );
    let requires_v6 = generation_name == "post145-v6";
    let requires_v9 = generation_name == "post145-v9";
    if requires_v6 {
        verify_v6_dependencies(&n)?;
    }
    let active_v12 = if requires_v9 {
        Some(verify_v9_dependencies(&n)?)
    } else {
        None
    };
    let mut result = prestart_price(&n, fleet, &f, &evidence, now()?, requires_v9)?;
    if !before.is_null() {
        let prior = bound(&before["prestart"])?;
        if requires_v6 {
            ensure!(
                v6_price_refs(&prior)? == v6_price_refs(&n)?
                    && prior["epoch166_write_version_reproduction"]["native_capture"]["deployment"]
                        == sr,
                "V6 completion or native provider changed since epoch 166 prestart"
            );
        }
        if let Some(active) = &active_v12 {
            let saved = &prior["epoch166_write_version_reproduction"]["native_capture"];
            ensure!(
                v9_price_refs(&prior)? == v9_price_refs(&n)?
                    && saved["deployment"] == sr
                    && saved["cadence_active"] == *active,
                "V9 completion, V12 receipt or native provider changed since epoch 166 prestart"
            );
        }
        reprice_held(&mut result, &n, &before, &prior, &f, requires_v9)?;
    }
    result["epoch166_write_version_reproduction"]["native_capture"] =
        json!({"deployment":sr,"program":program,"stdout_sha256":digest(&out.stdout)});
    if let Some(active) = active_v12 {
        result["epoch166_write_version_reproduction"]["native_capture"]["cadence_active"] = active;
    }
    Ok(result)
}

fn dispatch() -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "root access to native fleet evidence required"
    );
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [op, mode, path, sha]
            if op == "owner" && matches!(mode.as_str(), "prestart" | "held" | "post-guard") =>
        {
            let fleet = reference(Path::new(path), sha);
            current_fleet(&fleet)?;
            owner(mode, &fleet, &generation()?)
        }
        [op, mode, path, sha, provider, seal]
            if op == "quote" && matches!(mode.as_str(), "prestart" | "held" | "post-guard") =>
        {
            price(mode, &reference(Path::new(path), sha), provider, seal)
        }
        _ => bail!("expected owner STAGE FLEET SHA, or quote STAGE FLEET SHA PROVIDER SEAL_SHA"),
    }
}
fn main() -> Result<()> {
    println!("{}", serde_json::to_string(&dispatch()?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v6_price_requires_exact_completion_provider_and_v8_writer() {
        let root = Path::new(RT);
        let complete = reference(
            &root
                .join("epoch145-guarded-export-20261121-v1/state")
                .join(V6_INVOCATION)
                .join("complete.json"),
            "completion",
        );
        let checker = reference(
            &root.join(V6_PROVIDER).join("deployment-seal-receipt.json"),
            V6_PROVIDER_SHA,
        );
        let price = json!({
            "phase145":{
                "stage":"v6-semantic-complete-drained",
                "completed_invocation_id":V6_INVOCATION,
                "completion":complete,
                "checker_seal":checker,
            },
            "status_registration":{
                "invocation_id":V8_INVOCATION,
                "consumer_seal":reference(&root.join(V8_SEAL), V8_SEAL_SHA),
            }
        });
        assert_eq!(v6_price_refs(&price).unwrap(), (&complete, &checker));
        for (path, replacement) in [
            ("/phase145/stage", json!("v5z-semantic-complete-drained")),
            ("/phase145/completed_invocation_id", json!("foreign")),
            ("/phase145/completion", Value::Null),
            ("/phase145/checker_seal/path", json!("/different/receipt")),
            ("/phase145/checker_seal/sha256", json!("foreign")),
            ("/status_registration/invocation_id", json!("foreign")),
            (
                "/status_registration/consumer_seal/sha256",
                json!("foreign"),
            ),
        ] {
            let mut wrong = price.clone();
            *wrong.pointer_mut(path).unwrap() = replacement;
            assert!(v6_price_refs(&wrong).is_err(), "{path}");
        }
    }

    fn fixture() -> (Value, Value, Value, Value) {
        let fleet_ref = json!({"path":"/fleet","sha256":"test"});
        let fleet = json!({"complete_cycle_conservative_available_DATA_bytes":MIN_FLOOR+16_000});
        let evidence = json!({"retry11_terminal":"spent"});
        let native = json!({"schema":"horizon-incident-replay-fit-v1","epoch":145,"fleet":fleet_ref,
            "recorded_unix_seconds":100,"fits":true,"candidate":null,"bounded_qualification":null,
            "replay_launch_authorized":false,"resource_credit_bytes":0,
            "complete_cpu_quota_micros":64_000_000,"complete_memory_plus_reserve_bytes":810_658_050_048u64,
            "failed_cold166":{"terminal":"spent","reservation_ending_bytes":0},
            "bookings":{"166":{"root":LANE,"run":Path::new(LANE).join(PRIOR),"cap_bytes":CAP,
                "physical_bytes":CAP-2000,"remaining_bytes":2000,"measurement":"two complete stopped-tree walks"}},
            "epoch159_donor_cover":{"fleet":fleet_ref,"native_recorded_unix_seconds":100,"schema":"horizon-145-drained-159-donor-cover-v1",
                "native_home_required":MIN_FLOOR+10_000,"remaining_home_bytes":4000},
            "full166_zero_remaining_native_HOME_bytes":MIN_FLOOR+4000,
            "active168_guard_floor":MIN_FLOOR,"survivors":{"172":{"guard":{"floor":MIN_FLOOR+3000}}},
            "candidate136":{"occupied":false},"replacements":{"167":{"floor":MIN_FLOOR+100}},
            "protected_raw_floor_bytes":MIN_FLOOR,"complete_required_HOME_bytes":MIN_FLOOR+6000,
            "available_HOME_bytes":MIN_FLOOR+20_000,"required_available_memory_bytes":100,"available_memory_bytes":101,
            "status_registration":{"invocation_id":"same"}});
        (native, fleet_ref, fleet, evidence)
    }

    #[test]
    fn v9_quote_keeps_retry5_at_prestart_held_and_postguard() {
        let (mut n, r, mut f, e) = fixture();
        let base = MIN_FLOOR + 6000;
        let zero = MIN_FLOOR + 4000;
        let donor = MIN_FLOOR + 10000;
        let lag = 8u64 << 30;
        let current = donor + lag + 2000;
        n["complete_required_HOME_bytes"] = json!(current);
        n["available_HOME_bytes"] = json!(current + 10000);
        f["complete_cycle_conservative_available_DATA_bytes"] = json!(current + 9000);
        n["epoch159_donor_cover"]["credited_retirement_bytes"] = json!(0);
        n["retry5_retained_source"] = json!({"path":"/retained","sha256":"fixture"});
        n["bookings"]["168"] = json!({"cap_bytes":512u64<<30,"remaining_bytes":2000});
        n["retry5_complete_booking"] = json!({
            "schema":"horizon-168-retry5-complete-booking-v1", "funded":true,
            "outside_cap_stop_allowance_bytes":lag, "candidate_remaining_bytes":2000,
            "retained_guard_floor_bytes":MIN_FLOOR, "retained_base_HOME_bytes":donor,
            "retained_source":n["retry5_retained_source"], "complete_required_HOME_bytes":current
        });
        n["full166_retry5_projection"] = json!({
            "native_current_HOME_bytes":base, "native_zero_remaining_HOME_bytes":zero,
            "funded_current_HOME_bytes":current, "funded_zero_remaining_HOME_bytes":current-2000
        });
        let prior = prestart_price(&n, &r, &f, &e, 101, true).unwrap();
        assert_eq!(prior["complete_required_HOME_bytes"], current);
        assert_eq!(prior["phase145"], n["phase145"]);
        assert_ne!(home_funding(&n, true).unwrap().0, donor);
        assert!(home_funding(&n, false).is_err());
        n["population"] = json!({(UNIT):[[17,45]]});
        let mut actor = json!({"producer_pid":17,"start_ticks":45,"armed_floor":current-2000});
        let mut held = prior.clone();
        reprice_held(&mut held, &n, &actor, &prior, &f, true).unwrap();
        assert_eq!(held["complete_required_HOME_bytes"], current);
        actor["first_guard"] = json!({"physical_bytes":CAP-2100, "available_bytes":current+150});
        let mut guarded = prior.clone();
        reprice_held(&mut guarded, &n, &actor, &prior, &f, true).unwrap();
        assert_eq!(guarded["complete_required_HOME_bytes"], current + 100);
        assert_eq!(
            guarded["retry5_complete_booking"],
            n["retry5_complete_booking"]
        );
        actor["first_guard"]["available_bytes"] = json!(current + 99);
        assert!(reprice_held(&mut guarded, &n, &actor, &prior, &f, true).is_err());
        n["full166_retry5_projection"]["funded_zero_remaining_HOME_bytes"] = json!(current - 2001);
        assert!(home_funding(&n, true).is_err());
    }

    #[test]
    fn v9_rejects_crossed_completion_and_v12_process() {
        let root = Path::new(RT);
        let seal = reference(
            &root.join(V12_PACKAGE).join("deployment-seal-receipt.json"),
            V12_SEAL_SHA,
        );
        let writer = json!({"consumer_seal":seal,"invocation_id":"3".repeat(32),"pid":723,"start_ticks":931});
        let mut n = json!({
            "phase145":{
                "stage":"v9-semantic-complete-drained","completed_invocation_id":V9_INVOCATION,
                "completion":reference(&root.join("epoch145-guarded-export-20261121-v1/state")
                    .join(V9_INVOCATION).join("complete.json"),"completion"),
                "semantic_receipt":reference(&root.join(V9_HANDOFF).join("SEMANTIC_COMPLETION.json"),"semantics"),
                "checker_seal":reference(&root.join(V9_CHECKER).join("deployment-seal-receipt.json"),V9_CHECKER_SHA)
            },
            "status_registration":writer
        });
        v9_price_refs(&n).unwrap();
        n["phase145"]["completed_invocation_id"] = json!(V6_INVOCATION);
        assert!(v9_price_refs(&n).is_err());
        n["phase145"]["completed_invocation_id"] = json!(V9_INVOCATION);
        n["status_registration"]["consumer_seal"] = json!({"path":V8_SEAL,"sha256":V8_SEAL_SHA});
        assert!(v9_price_refs(&n).is_err());
        let ready = json!({"schema":"horizon-epoch166-cadence-rejoin-ready-v1","package":seal});
        let mut active = json!({
            "schema":"horizon-epoch166-cadence-rejoin-active-v1","producer_mutations":false,
            "ready":reference(&root.join(V12_READY),"ready"),
            "new":{"unit":V12_UNIT,"program":root.join(V12_PACKAGE).join("status_cycle.py"),
                "invocation_id":writer["invocation_id"],"pid":writer["pid"],"start_ticks":writer["start_ticks"] }
        });
        v12_identity(&writer, &active, &ready).unwrap();
        active["new"]["start_ticks"] = json!(932);
        assert!(v12_identity(&writer, &active, &ready).is_err());
    }

    #[test]
    fn transfers_one_whole_tree_and_preserves_donor_and_incumbents() {
        let (mut n, r, f, e) = fixture();
        let q = prestart_price(&n, &r, &f, &e, 101, false).unwrap();
        assert_eq!(q["protected_raw_floor_bytes"], MIN_FLOOR + 8000);
        assert_eq!(q["complete_required_HOME_bytes"], MIN_FLOOR + 10000);
        assert_eq!(q["available_HOME_bytes"], MIN_FLOOR + 16000);
        assert_eq!(q["bookings"]["166"]["remaining_bytes"], 2000);
        assert_eq!(q["replay_launch_authorized"], false);
        n["replacements"]["167"]["floor"] = json!(MIN_FLOOR + 9000);
        let q = prestart_price(&n, &r, &f, &e, 101, false).unwrap();
        assert_eq!(q["complete_required_HOME_bytes"], MIN_FLOOR + 11000);
        n["epoch159_donor_cover"]["remaining_home_bytes"] = json!(999);
        assert!(prestart_price(&n, &r, &f, &e, 101, false).is_err());
    }
    #[test]
    fn incumbent_commitments_remain_when_the_tree_reaches_its_cap() {
        let (mut n, r, f, e) = fixture();
        n["full166_zero_remaining_native_HOME_bytes"] = n["complete_required_HOME_bytes"].clone();
        n["epoch159_donor_cover"]["remaining_home_bytes"] = json!(0);
        let q = prestart_price(&n, &r, &f, &e, 101, false).unwrap();
        assert_eq!(q["complete_required_HOME_bytes"], MIN_FLOOR + 12000);
        assert_eq!(q["protected_raw_floor_bytes"], MIN_FLOOR + 10000);
        n["available_HOME_bytes"] = json!(MIN_FLOOR + 11000);
        assert!(prestart_price(&n, &r, &f, &e, 101, false).is_err());
        n.as_object_mut()
            .unwrap()
            .remove("full166_zero_remaining_native_HOME_bytes");
        assert!(prestart_price(&n, &r, &f, &e, 101, false).is_err());
    }
    #[test]
    fn rejects_foreign_spent_stale_and_underfunded_evidence() {
        let (n, r, f, e) = fixture();
        for (path, value) in [
            ("/epoch", json!(166)),
            ("/bookings/166/run", json!(Path::new(LANE).join(RUN))),
            ("/bookings/166/remaining_bytes", json!(1999)),
            ("/failed_cold166/terminal", json!("other")),
            ("/recorded_unix_seconds", json!(101)),
            ("/available_memory_bytes", json!(99)),
            (
                "/epoch159_donor_cover/native_home_required",
                json!(MIN_FLOOR + 5999),
            ),
            ("/available_HOME_bytes", json!(MIN_FLOOR + 9999)),
            ("/replay_launch_authorized", json!(true)),
        ] {
            let mut bad = n.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(
                prestart_price(&bad, &r, &f, &e, 100, false).is_err(),
                "{path}"
            );
        }
        assert!(prestart_price(&n, &r, &f, &e, 221, false).is_err());
    }
    #[test]
    fn guarded_quote_uses_smallest_measurement_and_checks_the_armed_floor() {
        let (mut n, r, f, e) = fixture();
        let prior = prestart_price(&n, &r, &f, &e, 101, false).unwrap();
        n["population"] = json!({(UNIT):[[17,45]]});
        let mut actor = json!({"producer_pid":17,"start_ticks":45,"armed_floor":MIN_FLOOR+8000,
            "first_guard":{"physical_bytes":CAP-2100,"available_bytes":MIN_FLOOR+14000}});
        let mut q = prior.clone();
        reprice_held(&mut q, &n, &actor, &prior, &f, false).unwrap();
        assert_eq!(q["bookings"]["166"]["remaining_bytes"], 2100);
        assert_eq!(q["complete_required_HOME_bytes"], MIN_FLOOR + 10100);
        assert_eq!(q["candidate"], actor);
        actor["armed_floor"] = json!(MIN_FLOOR + 7999);
        assert!(reprice_held(&mut q, &n, &actor, &prior, &f, false).is_err());
        actor["armed_floor"] = json!(MIN_FLOOR + 8000);
        n["population"][UNIT] = json!([[17, 46]]);
        assert!(reprice_held(&mut q, &n, &actor, &prior, &f, false).is_err());
    }
}
