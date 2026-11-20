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
        "simultaneous 136/172 host admission"
    );
    Ok(f)
}
fn idle(unit: &str) -> Result<()> {
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
    let rows = run(
        "/usr/bin/systemctl",
        &[
            "list-units".into(),
            "--all".into(),
            "--plain".into(),
            "--no-legend".into(),
            "--state=active,activating,deactivating,reloading".into(),
            "*172*.service".into(),
            "*172*.timer".into(),
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
            "foreign epoch172 controller {name}"
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
        let expected = fs::metadata(Path::new(PACKAGE).join("gate172"))?;
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
pub(super) fn root172() -> Result<Value> {
    let wit = "/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/witness-set.json";
    let w = json_pin(
        Path::new(wit),
        "8eb041519cba5c3f6368cb1432be9e289489ce1acdc28aa8b49f3d6ec7f382ee",
    )?;
    let r = w["slots"]
        .as_array()
        .context("slots")?
        .iter()
        .find(|v| v["epoch"] == 172)
        .context("172 booking")?;
    ensure!(
        r["lane_root"] == LANE
            && r["members"] == json!([])
            && r["physical_ledger"].is_null()
            && r["original_booking"]["sha256"]
                == "d0fa07c259fdb5dadc4ce564d3afc562b32180354db16788ba083fb670e96027",
        "172 retained footprint"
    );
    let book = &r["original_booking"];
    let b = fs::read(Path::new(at(book, "path")?))?;
    ensure!(digest(&b) == at(book, "sha256")?, "172 booking");
    let booked: Value = serde_json::from_slice(&b)?;
    ensure!(
        booked["candidate_own_DATA_bytes"] == (288u64 << 30)
            && booked["candidate_guard_metadata_DATA_bytes"] == (8u64 << 30)
            && booked["complete_projected_memory_bytes"] == 708249923584u64
            && booked["all_existing_hard_memory_promises_retained"] == true,
        "172 commitments"
    );
    let p = Path::new(LANE);
    custody(p, 1001, 1003, Some(107282698), 0o700)?;
    custody(
        &p.join("metadata-probes"),
        1001,
        1003,
        Some(107283290),
        0o700,
    )?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    ensure!(
        !mounts
            .lines()
            .filter_map(|l| l.split_whitespace().nth(4))
            .any(|s| Path::new(s).starts_with(p)),
        "submount in 172 lane"
    );
    let bytes = || -> Result<u64> {
        let out = run(
            "/usr/bin/du",
            &["-sxB1".into(), "--".into(), LANE.into()],
            bounded(),
        )?;
        let (size, root) = out.trim_end().split_once('\t').context("whole 172 du")?;
        ensure!(root == LANE, "172 root changed");
        Ok(size.parse()?)
    };
    let a = bytes()?;
    let b = bytes()?;
    ensure!(a.max(b) <= CAP, "172 whole physical ceiling");
    Ok(
        json!({"allocated_bytes":a.min(b),"whole_lane":LANE,"historical_allocated_credit_bytes":0,"original_booking":book}),
    )
}
