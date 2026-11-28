//! Read-only epoch167 retry8 preparer input. Resolve the live retry9 PID and
//! invocation from the authenticated epoch166 launch receipts and PID1.
use super::*;

pub(super) const PEER: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
const TIMER: &str = "horizon-guard-independent-cold166-20261120-v1.timer";
const GUARD: &str = "horizon-guard-independent-cold166-20261120-v1.service";
const ROOTS: &str = "/var/lib/jetstreamer/horizon_runtime_data/root-zero-166167-stop-20261120-v1/SUCCESSOR_ROOTS_BEFORE_WITNESS.json";
const ROOTS_SHA: &str = "d9e8ae44c9726811b2104cac494b4ccc4a5ef3cb7bf56e5cadec6bf6f9b4be89";
const PREVIOUS_FLOOR: u64 = 6_829_053_656_882;
const STOP166: &str = "/var/lib/jetstreamer/retry8-preparation-20261119-v1/epoch166/local3retry8/guard-state-recovery-v2/receipts";
const STOP167: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry7/guard-state/receipts";
pub(super) const CANDIDATE_ROOT: &str = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1";
const PEER_ROOT: &str = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1/replacement-local3retry9-20261110-v1";

const PEER_LANE: &str = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1";
const PEER_RECEIPTS: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-independent-cold-20261120-v1/launch-state/epoch166";
const COLD_ROOTS: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0245-zero-recovery-20261120-v1/INDEPENDENT_COLD_ROOTS_BEFORE_WITNESS.json";
const COLD_ROOTS_SHA: &str = "40bd46800a52705e1dcb485edb09f36d8122adb541e430a4b549caa92f13c7fa";

fn independent_root() -> Result<Value> {
    let roots = bound(&Bound {
        path: COLD_ROOTS.into(),
        sha256: COLD_ROOTS_SHA.into(),
    })?;
    let rows = roots["roots"].as_array().context("cold roots")?;
    let mut selected = rows.iter().filter(|row| row["epoch"] == 166);
    let row = selected.next().context("cold peer root")?;
    ensure!(
        selected.next().is_none()
            && roots["schema"] == "horizon-independent-cold-roots-before-witness-v1"
            && roots["owner"] == "/root"
            && roots["primary_thread"] == THREAD
            && roots["existing_attempts_retained"] == true
            && roots["resource_credit_bytes"] == 0
            && row["lane"] == PEER_LANE
            && row["attempt_root"] == PEER_ROOT
            && row["empty_attempt"] == true,
        "cold root binding differs"
    );
    let home = directory(Path::new("/home/sol"))?.metadata()?.dev();
    for (path, inode) in [(PEER_LANE, "lane_inode"), (PEER_ROOT, "attempt_inode")] {
        let stat = directory(Path::new(path))?.metadata()?;
        ensure!(
            stat.dev() == home
                && row["device"] == stat.dev()
                && row[inode] == stat.ino()
                && stat.uid() == 1001
                && row["uid"] == stat.uid()
                && stat.gid() == 1003
                && row["gid"] == stat.gid()
                && stat.mode() & 0o7777 == 0o700,
            "cold root custody changed"
        );
    }
    Ok(row.clone())
}

fn linked(record: &Value, field: &str) -> Result<Value> {
    bound(&serde_json::from_value(record[field].clone())?)
}

fn check_root(roots: &Value, epoch: u64, path: &str) -> Result<Value> {
    let rows: Vec<_> = roots["roots"]
        .as_array()
        .context("precreated roots")?
        .iter()
        .filter(|row| row["epoch"] == epoch)
        .collect();
    ensure!(rows.len() == 1, "missing or duplicate epoch root");
    let row = rows[0];
    let stat = directory(Path::new(path))?.metadata()?;
    ensure!(
        row["path"] == path
            && row["dev"] == stat.dev()
            && row["ino"] == stat.ino()
            && stat.dev() == directory(Path::new("/home/sol"))?.metadata()?.dev()
            && row["uid"] == stat.uid()
            && stat.uid() == 1001
            && row["gid"] == stat.gid()
            && stat.gid() == 1003
            && row["mode"] == "0o700"
            && stat.mode() & 0o7777 == 0o700,
        "successor root custody differs"
    );
    Ok(row.clone())
}

fn stopped(dir: &str, iid: &str, intent_sha: &str, completion_sha: &str) -> Result<()> {
    let intent = Bound {
        path: Path::new(dir).join("stop-intent.json"),
        sha256: intent_sha.into(),
    };
    let completion = Bound {
        path: Path::new(dir).join("stop-completion.json"),
        sha256: completion_sha.into(),
    };
    let i = bound(&intent)?;
    let c = bound(&completion)?;
    ensure!(
        i["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && c["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && c["intent"] == serde_json::to_value(intent.path)?
            && i["producer_invocation_id"] == iid
            && c["producer_invocation_id"] == iid
            && i["plan_sha256"] == c["plan_sha256"]
            && i["reason"] == "DATA-fulfillment-observation-failed"
            && c["terminal"]["invocation_id"] == iid
            && c["terminal"]["active"] == "inactive"
            && c["terminal"]["sub"] == "dead"
            && c["terminal"]["pid"] == 0
            && c["terminal"]["restarts"] == 0
            && c["scratch_deleted"] == false
            && c["remote_mutations"] == false
            && c["r2_mutations"] == false,
        "predecessor terminal evidence differs"
    );
    Ok(())
}

pub(super) fn lineage() -> Result<Value> {
    stopped(
        STOP166,
        "4f09db5f45074244a45b06aeef932d1d",
        "f663f933ec2ceba6ed27c9d863a126a23027b16f9bd2d40c4074cae2a61e496c",
        "b99e26a6836609dc68b4c646eb19ce2b2c0edd0d7547c80b1e0b517be4875b08",
    )?;
    stopped(
        STOP167,
        "a680103e76f546faaf469aa80c35fa3b",
        "dd5f515167b27bc1541c73d57e98c2bfab975ee0e1b6ca051be28a4b79f8f946",
        "5b51b01a57f5c717ef6397cad6bcc6b01ac72336e84d02d2b9354c99ee3fd5aa",
    )?;
    let roots = bound(&Bound {
        path: ROOTS.into(),
        sha256: ROOTS_SHA.into(),
    })?;
    ensure!(
        roots["owner"] == "/root"
            && roots["active_replay_workers"] == 0
            && roots["replay_admission"] == false,
        "unexpected successor root capture"
    );
    check_root(&roots, 167, CANDIDATE_ROOT)?;
    independent_root()
}

fn proc_start(pid: u64) -> Result<u64> {
    let data = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    ensure!(data.starts_with(&format!("{pid} (")), "proc PID differs");
    Ok(data
        .rsplit_once(')')
        .context("proc comm")?
        .1
        .split_whitespace()
        .nth(19)
        .context("proc start time")?
        .parse()?)
}

/// Both references must come from the root controller's authenticated input plan.
/// Call at both ends of preparation and recheck before producer launch.
pub(super) fn observe(admission: &Bound, protection: &Bound) -> Result<Value> {
    let root = lineage()?;
    ensure!(
        admission.path.parent() == protection.path.parent()
            && admission.path.parent() == Some(Path::new(PEER_RECEIPTS))
            && admission
                .path
                .file_name()
                .is_some_and(|s| s == "ACTUAL_REPLACEMENT_ADMISSION.json")
            && protection
                .path
                .file_name()
                .is_some_and(|s| s == "ACTUAL_GUARD_PROTECTION.json"),
        "expected sibling actual epoch166 launch receipts"
    );
    let a = bound(admission)?;
    let p = bound(protection)?;
    let iid = a["producer_invocation_id"]
        .as_str()
        .context("peer producer invocation")?;
    let pid = a["producer_pid"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("peer producer PID")?;
    let before = native(PEER)?;
    let ticks = proc_start(pid)?;
    let pid_text = pid.to_string();
    for (key, val) in [
        ("Id", PEER),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", iid),
        ("MainPID", pid_text.as_str()),
        ("NRestarts", "0"),
        ("ControlPID", "0"),
        ("Job", ""),
    ] {
        ensure!(
            before.get(key).map(String::as_str) == Some(val),
            "live peer property {key} differs"
        );
    }
    ensure!(
        lower_hex(iid, 32)
            && a["schema"] == "horizon-standard-replacement-admission-v1"
            && a["owner"] == "/root"
            && a["primary_thread"] == THREAD
            && a["independent_worker_root"] == PEER_LANE
            && a["independent_physical_cap_bytes"] == ROOT_CAP
            && a["old_partial_and_inputs_preserved"] == true
            && a["epoch"] == 166
            && a["producer_unit"] == PEER
            && a["fresh_admission_passed"] == true
            && a["all_prior_promises_retained"] == true
            && a["all_existing_growth_and_floor_protected"] == true
            && a["resource_credit_bytes"] == 0
            && a["memory_or_DATA_promise_ending_bytes"] == 0
            && a["candidate_hard_memory_bytes"] == 73_014_444_032u64,
        "admission scope or retained resources differ"
    );
    ensure!(
        p["schema"] == "horizon-standard-live-peer-protection-v1"
            && p["owner"] == "/root"
            && p["epoch"] == 166
            && p["producer_unit"] == PEER
            && p["producer_invocation_id"] == iid
            && p["guard_unit"] == GUARD
            && p["timer_unit"] == TIMER
            && p["admission"] == serde_json::to_value(admission)?,
        "guard protection does not bind this admission"
    );
    let prepared = linked(&a, "fresh_native_Rust_preparation")?;
    let recorded = linked(&a, "actual_producer_native")?;
    ensure!(
        prepared["schema"] == "horizon-standard-replacement-recipe-preparation-v1"
            && prepared["attempt"] == "local3retry9"
            && prepared["epoch"] == 166
            && prepared["fresh_subtree"]["path"] == PEER_ROOT
            && prepared["fresh_subtree"]["identity"][0] == root["device"]
            && prepared["fresh_subtree"]["identity"][1] == root["attempt_inode"]
            && prepared["independent_worker_root"] == PEER_LANE
            && prepared["independent_physical_cap_bytes"] == ROOT_CAP
            && prepared["independent_roots_receipt"]["path"] == COLD_ROOTS
            && prepared["independent_roots_receipt"]["sha256"] == COLD_ROOTS_SHA
            && recorded["Id"] == PEER
            && recorded["InvocationID"] == iid
            && recorded["MainPID"] == pid_text
            && recorded["MainStartTicks"] == ticks
            && ticks > 0,
        "prepared root or original live PID identity differs"
    );
    let post = linked(&a, "post_guard_capacity")?;
    let pre = &a["current_closed_unit_revalidation"]["independent_capacity"];
    let obligations = &post["independent_capacity"]["independent_DATA_obligation"];
    ensure!(
        obligations == &pre["independent_DATA_obligation"]
            && obligations["independent_physical_cap_bytes"] == ROOT_CAP
            && obligations["retained_standard_lane_cap_bytes"] == ROOT_CAP
            && obligations["complete_replay_DATA_with_independent_cap_bytes"]
                == 6_794_761_027_378u64 + ROOT_CAP,
        "independent and historical 166 cap were not both admitted"
    );
    let timer_iid = p["timer_invocation_id"]
        .as_str()
        .context("peer timer invocation")?;
    ensure!(lower_hex(timer_iid, 32), "malformed timer identity");
    let guard_plan = linked(&p, "plan")?;
    let first = linked(&a, "first_guard")?;
    let sample = linked(&a, "genuine_dynamic_DATA_first_guard")?;
    let floor = a["guard_minimum_free_bytes"]
        .as_u64()
        .context("admitted raw floor")?;
    ensure!(
        floor == PREVIOUS_FLOOR
            && guard_plan["minimum_free_bytes"] == floor
            && guard_plan["unit"] == PEER
            && guard_plan["invocation_id"] == iid
            && guard_plan["worker_root"] == PEER_LANE
            && guard_plan["maximum_root_physical_bytes"] == ROOT_CAP
            && guard_plan["maximum_worker_vmas"] == 3500000,
        "current guard plan does not cover retained peer obligations"
    );
    ensure!(
        first["genuine_first_timer_driven_success"] == true
            && first["dynamic_DATA_fulfillment_proven"] == true
            && first["actual_producer"]["InvocationID"] == iid
            && first["actual_producer"]["MainPID"] == pid_text
            && first["guard_service"]["Id"] == GUARD
            && first["guard_service"]["Result"] == "success"
            && first["guard_service"]["ExecMainStatus"] == "0"
            && first["timer"]["Id"] == TIMER
            && first["timer"]["InvocationID"] == p["timer_invocation_id"]
            && first["receipt"] == a["genuine_dynamic_DATA_first_guard"]
            && first["receipt"] == p["first_guard_sample"]
            && sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["producer_invocation_id"] == iid
            && sample["guard_invocation_id"] == first["guard_service"]["InvocationID"]
            && sample["guard_sha256"] == a["guard_sha256"]
            && sample["plan"] == p["plan"]["path"]
            && sample["plan_sha256"] == p["plan"]["sha256"]
            && sample["minimum_free_bytes"] == floor
            && sample["DATA_fulfillment"]["independent_root"] == PEER_LANE
            && sample["DATA_fulfillment"]["independent_physical_cap_bytes"] == ROOT_CAP
            && sample["DATA_fulfillment"]["contract"] == a["qualified_DATA_fulfillment_contract"]
            && sample["producer_stop_enabled"] == true
            && sample.get("trip_reason") == Some(&Value::Null),
        "first timer proof or bound guard sample differs"
    );
    let timer = native(TIMER)?;
    ensure!(
        timer.get("Id").map(String::as_str) == Some(TIMER)
            && timer.get("InvocationID").map(String::as_str) == Some(timer_iid)
            && timer.get("ActiveState").map(String::as_str) == Some("active")
            && timer
                .get("SubState")
                .is_some_and(|s| matches!(s.as_str(), "waiting" | "running"))
            && proc_start(pid)? == ticks
            && native(PEER)? == before,
        "live producer or timer changed during evidence capture"
    );
    Ok(
        json!({"epoch":166,"unit":PEER,"invocation_id":iid,"main_pid":pid,"main_start_ticks":ticks,
              "admission":admission,"guard_protection":protection}),
    )
}
