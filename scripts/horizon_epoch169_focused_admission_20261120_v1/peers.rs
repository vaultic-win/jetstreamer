use super::*;
use std::collections::BTreeSet;
use std::os::fd::AsRawFd;
const PREDECESSOR: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch168-trace-admission-20261120-v2/POST_GUARD_CAPACITY.json";
const PREDECESSOR_HASH: &str = "414f2886185fbbcdf19cb5e0332d4a1301b08c09ef506a6c7873a2aaaa65503a";

fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().context("missing integer")
}
fn ticks(pid: u64) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(')')
        .context("stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("start ticks")?
        .parse()?)
}
pub(super) fn active168(f: &Value) -> Result<Value> {
    let rows = f["actual_active_private_diagnostics"]
        .as_array()
        .context("168 observer")?;
    if rows.is_empty() {
        for u in [guard168::UNIT, guard168::TIMER, guard168::GUARD_SERVICE] {
            drained(u)?;
        }
        return Ok(
            json!({"unit":guard168::UNIT,"invocation_id":"c081016844dd40c5a78b594bf7ede73a","terminal":true,"accepted_processes":[],"resident_credit_bytes":0}),
        );
    }
    ensure!(
        rows.len() == 1 && rows[0]["epoch"] == 168,
        "unrecognized private diagnostic fleet"
    );
    let r = &rows[0];
    let u = guard168::UNIT;
    let s = show(u)?;
    let t = show("horizon-guard-168-trace-local3-20261120-v1.timer")?;
    ensure!(
        s["InvocationID"] == "c081016844dd40c5a78b594bf7ede73a"
            && s["InvocationID"] == r["unit"]["InvocationID"]
            && s["MainPID"] == r["unit"]["MainPID"]
            && s["ActiveState"] == "active"
            && s["SubState"] == "running"
            && s["Job"] == ""
            && s["NRestarts"] == "0"
            && t["InvocationID"] == r["guard_timer"]["InvocationID"]
            && t["ActiveState"] == "active"
            && t["Job"] == "",
        "168 observer/native ownership changed"
    );
    ensure!(
        r["post_guard_capacity"] == binding(Path::new(PREDECESSOR), PREDECESSOR_HASH),
        "168 post-guard authority"
    );
    let worker = &r["native_worker_at_consumption"];
    let p = s["MainPID"].as_str().context("168 pid")?.parse::<u64>()?;
    let w = n(worker, "pid")?;
    let main = Path::new(
        "/usr/local/lib/jetstreamer/horizon-independent168-singleton-package-20261109-v1/jetstreamer-node",
    );
    ensure!(
        fs::read_link(format!("/proc/{p}/exe"))? == main
            && ticks(p)? == n(r, "native_start_ticks")?
            && ticks(w)? == n(worker, "start_ticks")?
            && worker["basename"] == "historical-worker",
        "168 pid/image changed"
    );
    let image = fs::metadata(format!("/proc/{w}/exe"))?;
    ensure!(
        image.dev() == n(worker, "device")?
            && image.ino() == n(worker, "inode")?
            && fs::read_link(format!("/proc/{w}/exe"))?
                == Path::new(worker["executable"].as_str().context("168 worker")?),
        "168 worker changed"
    );
    let members = fs::read_to_string(format!("/sys/fs/cgroup/system.slice/{u}/cgroup.procs"))?
        .lines()
        .map(str::parse::<u64>)
        .collect::<Result<BTreeSet<_>, _>>()?;
    ensure!(
        members == BTreeSet::from([p, w]),
        "unbound 168 cgroup member"
    );
    Ok(
        json!({"unit":u,"invocation_id":s["InvocationID"],"accepted_processes":[{"pid":p,"basename":"jetstreamer-node"},{"pid":w,"basename":"historical-worker"}],"resident_credit_bytes":0}),
    )
}
pub(super) fn admission_interlock() -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/horizon-epoch171-to136-g1.operation.lock")?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "concurrent 136/169/172 host admission"
    );
    Ok(f)
}
pub(super) fn idle(unit: &str) -> Result<()> {
    let s = show(unit)?;
    ensure!(
        matches!(s["ActiveState"].as_str(), Some("failed" | "inactive"))
            && s["Job"] == ""
            && ["MainPID", "ControlPID"]
                .into_iter()
                .all(|k| s[k].is_null() || s[k] == "0"),
        "open {unit}"
    );
    Ok(())
}
fn check_peer136() -> Result<()> {
    let prefix = "horizon-";
    for tail in [
        "qualify-136-actual-20261120-g1.service",
        "guard-136-actual-20261120-g1.service",
        "guard-136-actual-20261120-g1.timer",
        "admit-136-actual-20261120-g1.service",
    ] {
        idle(&format!("{prefix}{tail}"))?;
    }
    let a = Path::new("/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1/admission.json");
    if a.try_exists()? {
        let v: Value = serde_json::from_slice(&read_root(a)?)?;
        ensure!(
            now()? >= n(&v, "launch_expires_unix_seconds")?,
            "unexpired 136 admission reserves 4.25 CPUs"
        );
    }
    Ok(())
}
pub(super) fn candidate_state(own: Option<&str>) -> Result<()> {
    check_peer136()?;
    for unit in [
        "horizon-qualify-171-metered-hourly-20261120-g1.service",
        "horizon-guard-171-metered-hourly-20261120-g1.timer",
        "horizon-guard-171-metered-hourly-20261120-g1.service",
        "horizon-qualify-172-metered-hourly-20261120-g3.service",
        "horizon-guard-172-metered-hourly-20261120-g3.timer",
        "horizon-guard-172-metered-hourly-20261120-g3.service",
    ] {
        drained(unit)?;
    }
    let rows = run(
        "/usr/bin/systemctl",
        &[
            "list-units".into(),
            "--all".into(),
            "--plain".into(),
            "--no-legend".into(),
            "--state=active,activating,deactivating,reloading".into(),
            "*169*.service".into(),
            "*169*.timer".into(),
        ],
        bounded(),
    )?;
    for name in rows
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|s| {
            s.starts_with("horizon-qualify-")
                || s.starts_with("horizon-guard-")
                || s.starts_with("horizon-admit-")
        })
    {
        ensure!(
            own.is_some() && [UNIT, TIMER, GUARD_SERVICE].contains(&name),
            "foreign epoch169 controller {name}"
        );
    }
    if let Some(id) = own {
        let s = show(UNIT)?;
        ensure!(
            iid(id)
                && s["InvocationID"] == id
                && s["ActiveState"] == "active"
                && s["Job"] == ""
                && s["NRestarts"] == "0",
            "candidate actor changed"
        );
        let pid = at(&s, "MainPID")?.parse::<u64>()?;
        ensure!(pid > 1, "candidate PID");
        let exe = fs::metadata(format!("/proc/{pid}/exe"))?;
        let expected = fs::metadata(Path::new(PACKAGE).join("gate169"))?;
        let c = fs::read_to_string(format!("/sys/fs/cgroup/system.slice/{UNIT}/cgroup.procs"))?;
        ensure!(
            (exe.dev(), exe.ino()) == (expected.dev(), expected.ino())
                && c.trim() == pid.to_string(),
            "only the held candidate gate may be live"
        );
    } else {
        for u in [UNIT, TIMER, GUARD_SERVICE] {
            idle(u)?;
        }
    }
    Ok(())
}
pub(super) fn root169() -> Result<Value> {
    let b = json_pin(Path::new(BOOK), BOOK_SHA)?;
    ensure!(
        b["candidate_own_DATA_bytes"] == 288u64 << 30
            && b["candidate_guard_metadata_DATA_bytes"] == 8u64 << 30
            && b["worker_VMA_stop"] == VMA
            && b["new_guard_minimum_free_bytes"] == ORIGINAL_GUARD_FLOOR,
        "retained 169 booking"
    );
    let closed = json_pin(Path::new(RETIREMENT), RETIREMENT_SHA)?;
    ensure!(
        closed["source_absent"] == true
            && closed["quarantine_absent"] == true
            && closed["authenticated_custody_revalidated"] == true,
        "169 retirement"
    );
    for key in ["source", "quarantine"] {
        ensure!(
            !Path::new(at(&closed["intent"], key)?).try_exists()?,
            "closed 169 member reappeared"
        );
    }
    custody(Path::new(STANDARD), 1001, 1003, Some(105251449), 0o700)?;
    custody(Path::new(LANE), 1001, 1003, Some(111744585), 0o700)?;
    custody(Path::new(DEST), 1001, 1003, Some(111744588), 0o700)?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    for p in [STANDARD, LANE] {
        ensure!(
            !mounts
                .lines()
                .filter_map(|l| l.split_whitespace().nth(4))
                .any(|m| Path::new(m).starts_with(p)),
            "submount in epoch 169 custody"
        );
    }
    let bytes = |p: &str| -> Result<u64> {
        let out = run(
            "/usr/bin/du",
            &["-sxB1".into(), "--".into(), p.into()],
            bounded(),
        )?;
        let (n, r) = out.trim_end().split_once('\t').context("whole root du")?;
        ensure!(r == p, "du root");
        Ok(n.parse()?)
    };
    let standard = bytes(STANDARD)?.max(bytes(STANDARD)?);
    let first = bytes(LANE)?;
    let second = bytes(LANE)?;
    ensure!(
        first.max(second) <= CAP
            && standard
                .checked_add(CAP)
                .is_some_and(|total| total <= 288u64 << 30),
        "candidate/retained standard subtree exceed shared 169 reservation"
    );
    Ok(
        json!({"allocated_bytes":first.min(second),"whole_lane":LANE,"original_booking":binding(Path::new(BOOK),BOOK_SHA),"original_root":STANDARD,"original_physical_bytes":standard,"focused_root_cap":CAP}),
    )
}
const BOOK: &str = "/home/sol/.jetstreamer-private/epoch169-independent-singleton-20261109-v1/ROOT_FRESH_STANDARD169_MANUAL_ADMISSION_AND_RESOURCE_BOOKING.json";
const BOOK_SHA: &str = "48fd8018efb668cf164d4bb8a83b2f4ca087b2e8ad3e71e93606338378b59393";
const STANDARD: &str = "/home/sol/.jetstreamer-private/epoch169-standard-lane-20261109-v1";
const RETIREMENT: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch169-completion.json";
const RETIREMENT_SHA: &str = "da19fd65746d39165a7b54ea0d02acd0710b477caf7b42055c76408d0876cd0a";
pub(super) fn closed172(fleet: &Value) -> Result<()> {
    let ad = json_pin(
        Path::new(
            "/var/lib/jetstreamer/horizon_runtime_data/epoch172-trace-admission-20261120-v1/ACTUAL_ADMISSION_AND_PROTECTION.json",
        ),
        "3c4134506e7cd31f22a550456fd41e8f6e92f9c48b91c5059fc7b0d2bed621d8",
    )?;
    ensure!(
        ad["producer_invocation_id"] == "5a691c24655a4ff489531d8d7cc50254"
            && ad["producer_pid"] == 2823601,
        "172 predecessor changed"
    );
    for u in [
        "horizon-qualify-172-trace-hourly-20261120-v1.service",
        "horizon-guard-172-trace-hourly-20261120-v1.service",
        "horizon-guard-172-trace-hourly-20261120-v1.timer",
    ] {
        drained(u)?;
    }
    let o = &fleet["observer"];
    let obs = json_pin(Path::new(at(o, "path")?), at(o, "sha256")?)?;
    let observed = at(&obs, "recorded_at_utc")?;
    let val = run(
        "/usr/bin/date",
        &["-u".into(), "-d".into(), observed.into(), "+%s".into()],
        bounded(),
    )?
    .trim()
    .parse::<u64>()?;
    ensure!(
        val > n(&ad, "recorded_at")?
            && !fleet["actual_active_private_diagnostics"]
                .as_array()
                .context("private diagnostics")?
                .iter()
                .any(|r| r["epoch"] == 172),
        "need reconciled post-172 fleet"
    );
    let prior = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch172-metered-admission-20261120-g3",
    );
    let admitted = prior.join("ACTUAL_ADMISSION_AND_PROTECTION.json");
    let hash = "3a80d442a7f00cde93a2650a70194277a65340c7753fea460a773ccdfaae3b87";
    let actor = json_pin(&admitted, hash)?;
    let closure_path = prior.join("CLOSURE.json");
    let closure: Value = serde_json::from_slice(&read_root(&closure_path)?)?;
    ensure!(
        closure["admission"] == binding(&admitted, hash)
            && closure["producer_unit"] == actor["producer_unit"]
            && closure["producer_invocation_id"] == actor["producer_invocation_id"]
            && closure["schema"] == "epoch172-metered-diagnostic-closure-v2"
            && closure["resource_credit_bytes"] == 0
            && closure["resource_promise_ending_bytes"] == 0
            && val >= u64::try_from(fs::metadata(&closure_path)?.mtime())?,
        "need reconciled fleet after G3 epoch 172 closure"
    );
    Ok(())
}
fn drained(u: &str) -> Result<()> {
    idle(u)?;
    let procs = Path::new("/sys/fs/cgroup/system.slice")
        .join(u)
        .join("cgroup.procs");
    match fs::read_to_string(procs) {
        Ok(p) => ensure!(p.trim().is_empty(), "peer cgroup {u} still occupied"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Temporary workers outside the historical serial build and audit bookings.
pub(super) fn temporary_workers() -> Result<(u64, u64, Vec<Value>)> {
    let mut memory = 0;
    let mut cpu = 0;
    let mut workers = Vec::new();
    for (unit, invocation, limit, quota, micros) in [
        (
            "horizon-audit90-after91-cleanup-20261120-v1.service",
            "6914dc0d3ac74f8aa24766f7e3ad577a",
            128u64 << 20,
            "250ms",
            250_000u64,
        ),
        (
            "horizon-metered172-terminal-evidence-g3.service",
            "0e23fb4e93e84f029fb77d338ff851d5",
            48 << 20,
            "100ms",
            100_000,
        ),
        (
            "horizon-169-index-comparison-20261120-v2.service",
            "ab8c54edb5664e88b312aa53d3c32ef5",
            64 << 20,
            "250ms",
            250_000,
        ),
    ] {
        let state = show(unit)?;
        if matches!(state["ActiveState"].as_str(), Some("inactive" | "failed")) {
            drained(unit)?;
            continue;
        }
        let limits = run(
            "/usr/bin/systemctl",
            &[
                "show".into(),
                unit.into(),
                "--property=MemoryMax,CPUQuotaPerSecUSec".into(),
            ],
            bounded(),
        )?;
        ensure!(
            state["ActiveState"] == "active"
                && state["InvocationID"] == invocation
                && state["Job"] == ""
                && state["MainPID"]
                    .as_str()
                    .is_some_and(|s| s.parse::<u64>().is_ok_and(|p| p > 1))
                && limits.lines().any(|l| l == format!("MemoryMax={limit}"))
                && limits
                    .lines()
                    .any(|l| l == format!("CPUQuotaPerSecUSec={quota}"))
                && show(unit)? == state,
            "unexpected auxiliary owner or limits: {unit}"
        );
        memory += limit;
        cpu += micros;
        workers.push(json!({"unit":unit,"invocation_id":invocation,"memory_bytes":limit,"cpu_quota_micros":micros}));
    }
    Ok((memory, cpu, workers))
}
