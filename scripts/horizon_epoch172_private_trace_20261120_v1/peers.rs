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
        .open(standard169_cpu_lease::OPERATION_LOCK)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "simultaneous exclusive candidate admission"
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
    if EPOCH == 171 {
        use crate::standard169_cpu_lease::{REGISTRY_136, REGISTRY_171, require_unclaimed};
        require_unclaimed(Path::new(REGISTRY_136))
            .context("active or partial epoch 171 donor fence")?;
        // Only a successor that authenticates the complete loan can consume it.
        require_unclaimed(Path::new(REGISTRY_171))
            .context("epoch 171 CPU lease requires a successor controller")?;
        idle("jetstreamer-epochs159-173-target1-controller-v1-r2.service")?;
        let dynamic = run(
            "/usr/bin/systemctl",
            &[
                "list-units".into(),
                "--plain".into(),
                "--no-legend".into(),
                "--state=running,activating,deactivating,reloading".into(),
                "jetstreamer-root-sweep-e159-173-*-e171-173-*".into(),
                "jetstreamer-root-source-recovery-e159-173-*-e171-173-*".into(),
                "horizon-local-replacement171-*".into(),
                "horizon-replacement-171-*".into(),
            ],
            bounded(),
        )?;
        ensure!(
            dynamic.trim().is_empty(),
            "legacy 171 route still executing"
        );
    }
    let jobs = run(
        "/usr/bin/systemctl",
        &["list-jobs".into(), "--plain".into(), "--no-legend".into()],
        bounded(),
    )?;
    for unit in jobs.lines().filter_map(|s| s.split_whitespace().nth(1)) {
        let is_candidate = ["horizon-qualify-", "horizon-admit-", "horizon-guard-"]
            .iter()
            .any(|prefix| unit.starts_with(prefix))
            && ["136", "169", "171", "172"]
                .iter()
                .any(|epoch| unit.split('-').any(|field| field == *epoch));
        let legacy = EPOCH == 171
            && (unit == "jetstreamer-epochs159-173-target1-controller-v1-r2.service"
                || unit.starts_with("horizon-local-replacement171-")
                || unit.starts_with("horizon-replacement-171-")
                || ((unit.starts_with("jetstreamer-root-sweep-e159-173-")
                    || unit.starts_with("jetstreamer-root-source-recovery-e159-173-"))
                    && unit.contains("-e171-173-")));
        ensure!(!legacy, "legacy 171 work queued");
        ensure!(
            !is_candidate || own.is_some() && [UNIT, TIMER, GUARD_SERVICE].contains(&unit),
            "competing candidate queued {unit}"
        );
    }
    let rows = run(
        "/usr/bin/systemctl",
        &[
            "list-units".into(),
            "--all".into(),
            "--plain".into(),
            "--no-legend".into(),
            "--state=active,activating,deactivating,reloading".into(),
            "*171*.service".into(),
            "*171*.timer".into(),
            "*169*.service".into(),
            "*169*.timer".into(),
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
            "competing candidate controller {name}"
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
        let expected = fs::metadata(Path::new(PACKAGE).join(GATE))?;
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
pub(super) fn candidate_root() -> Result<Value> {
    let wit = "/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/witness-set.json";
    let w = json_pin(
        Path::new(wit),
        "8eb041519cba5c3f6368cb1432be9e289489ce1acdc28aa8b49f3d6ec7f382ee",
    )?;
    let r = w["slots"]
        .as_array()
        .context("slots")?
        .iter()
        .find(|v| v["epoch"] == EPOCH)
        .context("candidate booking")?;
    ensure!(
        r["lane_root"] == LANE
            && r["members"] == json!([])
            && r["physical_ledger"].is_null()
            && r["original_booking"]["sha256"] == BOOK_SHA,
        "candidate retained footprint"
    );
    let book = &r["original_booking"];
    let b = fs::read(Path::new(at(book, "path")?))?;
    ensure!(digest(&b) == at(book, "sha256")?, "candidate booking");
    let booked: Value = serde_json::from_slice(&b)?;
    ensure!(
        booked["candidate_own_DATA_bytes"] == (288u64 << 30)
            && booked["candidate_guard_metadata_DATA_bytes"] == (8u64 << 30)
            && booked["complete_projected_memory_bytes"] == BOOK_MEMORY
            && booked["all_existing_hard_memory_promises_retained"] == true,
        "candidate commitments"
    );
    let p = Path::new(LANE);
    custody(p, 1001, 1003, Some(LANE_INO), 0o700)?;
    custody(
        &p.join("metadata-probes"),
        1001,
        1003,
        Some(PARENT_INO),
        0o700,
    )?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    ensure!(
        !mounts
            .lines()
            .filter_map(|l| l.split_whitespace().nth(4))
            .any(|s| Path::new(s).starts_with(p)),
        "submount in candidate lane"
    );
    let bytes = || -> Result<u64> {
        let out = run(
            "/usr/bin/du",
            &["-sxB1".into(), "--".into(), LANE.into()],
            bounded(),
        )?;
        let (size, root) = out
            .trim_end()
            .split_once('\t')
            .context("whole candidate du")?;
        ensure!(root == LANE, "candidate root changed");
        Ok(size.parse()?)
    };
    let a = bytes()?;
    let b = bytes()?;
    ensure!(a.max(b) <= CAP, "candidate whole physical ceiling");
    Ok(
        json!({"allocated_bytes":a.min(b),"whole_lane":LANE,"historical_allocated_credit_bytes":0,"original_booking":book}),
    )
}

const CLOSED: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch172-terminal-cadence-20261120-v1/CLOSURE.json";
const CLOSED_SHA: &str = "854539f0d9450b388e136092567438134efaab19f0570dee7bdeb4fcf53120c7";

fn closed172(fleet: &Value) -> Result<Value> {
    let receipt = binding(Path::new(CLOSED), CLOSED_SHA);
    let old = json_pin(Path::new(CLOSED), CLOSED_SHA)?;
    let cmp = &old["signed_target_comparison"];
    let observed = serde_json::from_slice::<Value>(include_bytes!("unpatched-logs.json"))?;
    ensure!(
        fleet["terminal172_closure"] == receipt
            && fleet["historical_preterminal_private172_admission"] == old["original_admission"]
            && old["original_invocation"] == "5a691c24655a4ff489531d8d7cc50254"
            && old["original_pid"] == 2823601
            && old["classification"] == "original-instruction-2-mismatch-reproduced"
            && old["native_terminal"]["original_pid_absent_or_reused"] == true
            && cmp["trace"]["logs"] == observed
            && cmp["trace"]["matches_original_execution"] == true
            && cmp["trace"]["matches_canonical_execution"] == false
            && old["resource_credit_bytes"] == 0
            && old["resource_promise_ending_bytes"] == 0,
        "missing or conflicting prior failed 172 run"
    );
    for u in [
        "horizon-qualify-172-trace-hourly-20261120-v1.service",
        "horizon-guard-172-trace-hourly-20261120-v1.service",
        "horizon-guard-172-trace-hourly-20261120-v1.timer",
    ] {
        idle(u)?;
        let procs = Path::new("/sys/fs/cgroup/system.slice")
            .join(u)
            .join("cgroup.procs");
        match fs::read_to_string(procs) {
            Ok(p) => ensure!(p.trim().is_empty(), "predecessor cgroup still occupied"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(receipt)
}

fn cold_metered_stage() -> Result<()> {
    let root = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch172-metered-admission-20261120-g2",
    );
    json_pin(
        &root.join("PREFLIGHT.json"),
        "17817ba37784460b956e28961708e1c1b80f1786fdd2ee34d2c44ea54f7d805c",
    )?;
    json_pin(
        &root.join("admission-v2/deployment-seal-receipt.json"),
        "bcd88df903c730f84038339495c5b6049a3ecf41492c353813818f5c25142b33",
    )?;
    for name in [
        "FINAL_PRELAUNCH_FIT.json",
        "PRODUCER_NATIVE.json",
        "AUTHORIZED_GATED_PAYLOAD.json",
        "ACTUAL_ADMISSION_AND_PROTECTION.json",
    ] {
        ensure!(
            !root.join(name).try_exists()?,
            "previous epoch 172 attempt advanced: {name}"
        );
    }
    for (name, mode) in [("guard-receipts", 0o700), ("barrier", 0o755)] {
        let directory = root.join(name);
        custody(&directory, 0, 0, None, mode)?;
        ensure!(
            fs::read_dir(directory)?.next().is_none(),
            "old epoch 172 guard or barrier populated"
        );
    }
    let old = Path::new(
        "/home/sol/.jetstreamer-private/epoch172-standard-lane-20261110-v1/metadata-probes/metered-hourly-20261120-g2",
    );
    custody(old, 1001, 1003, Some(114238111), 0o700)?;
    let log = fs::symlink_metadata(old.join("producer.log"))?;
    ensure!(
        log.is_file()
            && log.ino() == 114244344
            && log.uid() == 1001
            && log.gid() == 1003
            && log.nlink() == 1
            && log.len() == 0
            && fs::read_dir(old)?.count() == 1,
        "previous epoch 172 stage changed"
    );
    for unit in [
        "horizon-qualify-172-metered-hourly-20261120-g2.service",
        "horizon-guard-172-metered-hourly-20261120-g2.service",
        "horizon-guard-172-metered-hourly-20261120-g2.timer",
    ] {
        idle(unit)?;
    }
    Ok(())
}

pub(super) fn closed_predecessor(fleet: &Value) -> Result<Value> {
    cold_metered_stage()?;
    if EPOCH == 172 {
        return closed172(fleet);
    }
    let rows = fleet["actual_active_private_diagnostics"]
        .as_array()
        .context("private owners")?;
    ensure!(
        !rows
            .iter()
            .any(|r| matches!(r["epoch"].as_u64(), Some(136 | 169 | 171 | 172))),
        "competing candidate still present in reconciled fleet"
    );
    let other = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch172-metered-admission-20261120-g3",
    );
    let ad = other.join("ACTUAL_ADMISSION_AND_PROTECTION.json");
    if ad.try_exists()? {
        let raw = read_root(&ad)?;
        let admitted: Value = serde_json::from_slice(&raw)?;
        let final_record: Value = serde_json::from_slice(&read_root(&other.join("CLOSURE.json"))?)?;
        ensure!(
            final_record["schema"] == "epoch172-metered-diagnostic-closure-v2"
                && final_record["admission"] == binding(&ad, &digest(&raw))
                && final_record["producer_invocation_id"] == admitted["producer_invocation_id"]
                && final_record["producer_unit"] == admitted["producer_unit"]
                && final_record["resource_promise_ending_bytes"] == 0
                && final_record["archive_verified"] == false,
            "172 g3 handoff incomplete"
        );
    }
    let p = Path::new(
        "/var/lib/jetstreamer/terminal171-historical-mismatch-20261111-v1/ROOT171_TERMINAL_CLASSIFICATION_AND_RECOVERY_OWNER.json",
    );
    let old = json_pin(p, ORIGINAL_TERMINAL_SHA)?;
    ensure!(
        old["epoch"] == EPOCH
            && old["original_IID"] == ORIGINAL_IID
            && old["failing_slot"] == TARGET
            && old["failing_entry"] == ENTRY
            && old["failing_transaction"] == ORDINAL
            && old["signature"] == SIGNATURE
            && old["expected_error"] == format!("instruction2 {CANONICAL_ERROR}")
            && old["actual_error"] == format!("instruction2 {LOCAL_ERROR}")
            && old["no_memory_DATA_or_slot_promise_ending"] == true
            && old["resource_credit_bytes"] == 0,
        "171 prior signed mismatch or retained booking differs"
    );
    idle("horizon-qualify-171-replacement-local2-20261110-v1.service")?;
    Ok(binding(p, ORIGINAL_TERMINAL_SHA))
}

#[cfg(test)]
mod metered_tests {
    use super::*;

    #[test]
    #[ignore = "requires the live host's authenticated predecessor closure, read only"]
    fn real_unpatched_log_and_drained_predecessor_match_fleet() {
        let fleet_path = std::env::var("HORIZON172_TEST_CLOSED_FLEET").unwrap();
        let fleet: Value =
            serde_json::from_slice(&read_root(Path::new(&fleet_path)).unwrap()).unwrap();
        assert_eq!(
            closed_predecessor(&fleet).unwrap()["sha256"],
            PREDECESSOR_SHA
        );
        let mut stale = fleet;
        if EPOCH == 171 {
            stale["actual_active_private_diagnostics"] = json!([{"epoch":172}]);
        } else {
            stale["terminal172_closure"]["sha256"] = json!("wrong");
        }
        assert!(closed_predecessor(&stale).is_err());
    }
}
