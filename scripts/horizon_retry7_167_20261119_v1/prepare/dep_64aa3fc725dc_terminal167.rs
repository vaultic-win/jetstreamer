//! Exact closed167 support; terminal evidence never releases a reservation.
use super::*;
use std::time::{Duration, Instant};
pub(super) const UNIT: &str = "horizon-qualify-167-replacement-local3retry3-20261110-v1.service";
pub(super) const IID: &str = "7ce90d0ec8114cf3a6be73eb9cf75ae8";
const BOOT: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
const MACHINE: &str = "59498204047045e4a428419acee7df19";
const EVENT: &str = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-controls-v7/peer170-terminal169-build-v4/terminal167-event-v1/EVENT.json";
const EVENT_SHA: &str = "e9a1f5047280ff29b5579ee6fee4516ae90a19b43c015cc69072ab48376ecd97";
const GUARD_PLAN_SHA: &str = "2e356f27271c785907d5795e64c9c9d1d385b9acdb2104d522353981943798dd";
const ADMISSION: &str = "/var/lib/jetstreamer/retry3-peer167-guarded-launch-20261113-v1/epoch167/ACTUAL_REPLACEMENT_ADMISSION.json";
const ADMISSION_SHA: &str = "2730582e216d86be4dfaf512193567e96f1b3f4f67a1a5a19bf36e8da315f9da";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub terminal_event: Bound,
}
fn binding(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
pub(super) fn exact() -> Request {
    Request {
        terminal_event: binding(EVENT, EVENT_SHA),
    }
}
pub(super) fn selected(p: &Plan) -> bool {
    p.resident_memory
        .as_ref()
        .is_some_and(|r| r.terminal167.is_some())
}
pub(super) fn memory_scope(r: &resident_memory::Request, candidate: u64) -> Result<()> {
    ensure!(
        candidate == 170
            && r.admission_only_capture
            && r.host_kernel_same_resident_basis
            && r.terminal167.as_ref() == Some(&exact())
            && r.terminal169.as_ref() == Some(&terminal169::exact()),
        "exact terminal167+169 opt-in required"
    );
    let owners = serde_json::to_value(&r.owners)?;
    let rows = owners.as_array().context("live166 owners")?;
    ensure!(
        rows.len() == 1
            && rows[0]["epoch"] == 166
            && rows[0]["unit"]
                == "horizon-qualify-166-replacement-local3retry4-20261110-v1.service"
            && rows[0]["invocation_id"] == "58778e77980e4a15828c3be837e447aa",
        "only exact166 can receive resident realization"
    );
    Ok(())
}
fn native_closed(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == UNIT
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"] == ""
            && v["LoadState"] == "not-found"
            && v["InvocationID"] == ""
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead",
        "terminal167 native identity is not exactly collected/closed"
    );
    Ok(())
}
fn journal(v: &Value, at: u64) -> Result<()> {
    let rows = v.as_array().context("native167 PID1 rows")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 128,
        "bounded167 journal required"
    );
    let mut cursors = BTreeSet::new();
    let (mut stopping, mut deactivated, mut stopped) = (None, None, None);
    for r in rows {
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["_COMM"] == "systemd"
                && r["_EXE"] == "/usr/lib/systemd/systemd"
                && r["UNIT"] == UNIT
                && r["INVOCATION_ID"] == IID
                && r["_BOOT_ID"] == BOOT
                && r["_MACHINE_ID"] == MACHINE,
            "foreign167 native journal identity"
        );
        let cursor = r["__CURSOR"].as_str().context("167 cursor")?;
        ensure!(
            !cursor.is_empty() && cursors.insert(cursor),
            "duplicate167 cursor"
        );
        let number = |k: &str| -> Result<u64> {
            let s = r[k].as_str().context("167 timestamp")?;
            ensure!(
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
                "167 timestamp shape"
            );
            Ok(s.parse()?)
        };
        let clock = (
            number("__REALTIME_TIMESTAMP")?,
            number("__MONOTONIC_TIMESTAMP")?,
        );
        ensure!(
            clock.0 > 0 && clock.1 > 0 && clock.0 / 1_000_000 <= at,
            "future167 terminal"
        );
        match r["MESSAGE_ID"].as_str() {
            Some("de5b426a63be47a7b6ac3eaac82e2f6f") => {
                ensure!(
                    r["JOB_TYPE"] == "stop" && stopping.replace(clock).is_none(),
                    "167 native stopping"
                );
            }
            Some("7ad2d189f7e94e70a38c781354912448") => {
                ensure!(
                    deactivated.replace(clock).is_none(),
                    "167 unique native deactivation"
                );
            }
            Some("9d1aaa27d60140bd96365438aad20286") => {
                ensure!(
                    r["JOB_TYPE"] == "stop"
                        && r["JOB_RESULT"] == "done"
                        && stopped.replace(clock).is_none(),
                    "167 native completed stop"
                );
            }
            _ => {}
        }
    }
    let a = stopping.context("167 stop start missing")?;
    let b = deactivated.context("167 deactivation missing")?;
    let c = stopped.context("167 stop completion missing")?;
    ensure!(
        a.0 <= b.0 && a.1 <= b.1 && b.0 <= c.0 && b.1 <= c.1,
        "167 native stop ordering"
    );
    Ok(())
}
fn evidence(
    event: &Value,
    intent: &Value,
    complete: &Value,
    pid1: &Value,
    native: &Value,
    at: u64,
) -> Result<()> {
    ensure!(
        event["owner"] == "/root"
            && event["primary_thread"] == THREAD
            && event["epoch"] == 167
            && event["original_invocation_id"] == IID
            && event["resource_credit_bytes"] == 0
            && event["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= at),
        "167 event owner/clock/credit"
    );
    ensure!(
        intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && intent["producer_invocation_id"] == IID
            && intent["plan_sha256"] == GUARD_PLAN_SHA
            && intent["reason"] == "root-physical-budget",
        "167 original guard intent"
    );
    let s = &intent["sample"];
    ensure!(
        s["producer_invocation_id"] == IID
            && s["plan_sha256"] == GUARD_PLAN_SHA
            && s["producer"]["invocation_id"] == IID
            && s["producer"]["pid"] == 3120563
            && s["producer"]["active"] == "active"
            && s["producer"]["sub"] == "running"
            && s["producer"]["restarts"] == 0
            && s["producer_stop_enabled"] == true
            && s["trip_reason"] == "root-physical-budget"
            && s["maximum_root_physical_bytes"] == ROOT_CAP
            && s["root_physical_observation"]["maximum_physical_bytes"] == ROOT_CAP
            && s["root_physical_observation"]["exceeds_budget"] == true
            && s["root_physical_observation"]["conservative_physical_bytes"] == 309292183552u64
            && s["scratch_deleted"] == false
            && s["remote_mutations"] == false,
        "167 guard stop facts changed"
    );
    let t = &complete["terminal"];
    ensure!(
        complete["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && complete["producer_invocation_id"] == IID
            && complete["plan_sha256"] == GUARD_PLAN_SHA
            && complete["intent"] == event["stop_intent"]["path"]
            && complete["scratch_deleted"] == false
            && complete["remote_mutations"] == false
            && complete["r2_mutations"] == false
            && t["invocation_id"] == IID
            && t["pid"] == 0
            && t["restarts"] == 0
            && t["active"] == "inactive"
            && t["sub"] == "dead"
            && t["result"] == "success",
        "167 completed original stop required"
    );
    journal(pid1, at)?;
    native_closed(native)?;
    Ok(())
}
pub(super) fn authenticate(request: &Request, at: u64) -> Result<()> {
    ensure!(*request == exact(), "exact167 event binding required");
    let event = bound(&request.terminal_event)?;
    let get =
        |k: &str| -> Result<Value> { bound(&serde_json::from_value::<Bound>(event[k].clone())?) };
    evidence(
        &event,
        &get("stop_intent")?,
        &get("stop_completion")?,
        &get("original_pid1")?,
        &get("current_native")?,
        at,
    )
}
pub(super) fn declaration(row: &Value, request: &Request) -> Result<()> {
    ensure!(
        *request == exact()
            && row["epoch"] == 167
            && row["state"] == "terminal-retained"
            && row["producer_unit"] == UNIT
            && row["invocation_id"] == IID
            && row["terminal_event"] == serde_json::to_value(&request.terminal_event)?
            && row["retained_memory_promise_bytes"] == 73_014_444_032u64
            && row["memory_resident_deduction_bytes"] == 0
            && row["promise_ending_bytes"] == 0,
        "167 declaration must retain every promise and grant no resident deduction"
    );
    let a = bound(&binding(ADMISSION, ADMISSION_SHA))?;
    ensure!(
        a["epoch"] == 167
            && a["producer_unit"] == UNIT
            && a["producer_invocation_id"] == IID
            && a["fresh_admission_passed"] == true
            && a["all_prior_promises_retained"] == true
            && a["candidate_hard_memory_bytes"] == 73_014_444_032u64
            && a["resource_credit_bytes"] == 0
            && a["memory_or_DATA_promise_ending_bytes"] == 0,
        "original167 admitted promise required"
    );
    let prep = bound(&serde_json::from_value::<Bound>(
        a["fresh_native_Rust_preparation"].clone(),
    )?)?;
    retry3::peer_preparation(
        167,
        row,
        &prep,
        row["retained_lane_physical_bytes"]
            .as_u64()
            .context("167 historical baseline")?,
    )
}
fn process_in_unit(text: &str) -> Result<bool> {
    let group = format!("/system.slice/{UNIT}");
    let mut rows = text.lines();
    let line = rows.next().context("missing process cgroup membership")?;
    ensure!(
        rows.next().is_none(),
        "unified process cgroup membership required"
    );
    let actual = line.strip_prefix("0::").context("unified cgroup prefix")?;
    ensure!(
        actual.starts_with('/'),
        "absolute cgroup membership required"
    );
    Ok(actual == group || actual.starts_with(&format!("{group}/")))
}
fn no_unit_processes() -> Result<()> {
    let clock = Instant::now();
    let mut entries = 0usize;
    for e in fs::read_dir("/proc")? {
        let e = e?;
        if !e
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        entries += 1;
        ensure!(
            entries <= 65536 && clock.elapsed() <= Duration::from_secs(15),
            "terminal process scan bound"
        );
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(e.path().join("cgroup"))
        {
            Ok(f) => f,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ESRCH) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let mut text = String::new();
        file.take(65537).read_to_string(&mut text)?;
        ensure!(text.len() <= 65536, "bounded process cgroup membership");
        ensure!(!process_in_unit(&text)?, "terminal167 unit process remains");
    }
    Ok(())
}
/// Negative closure is freshly captured at both ends; none of this ends a promise.
pub(super) fn endpoint(request: &Request) -> Result<Value> {
    authenticate(request, now()?)?;
    ensure!(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .replace('-', "")
            == BOOT
            && fs::read_to_string("/etc/machine-id")?.trim() == MACHINE,
        "terminal167 host boot changed"
    );
    let before = serde_json::to_value(native(UNIT)?)?;
    native_closed(&before)?;
    let group = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{UNIT}"));
    match fs::symlink_metadata(&group) {
        Ok(_) => {
            let held = directory(&group)?;
            let mut f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(group.join("cgroup.events"))?;
            let mut text = String::new();
            Read::by_ref(&mut f).take(4097).read_to_string(&mut text)?;
            ensure!(
                text.len() <= 4096
                    && text
                        .lines()
                        .filter(|l| l.starts_with("populated "))
                        .collect::<Vec<_>>()
                        == vec!["populated 0"],
                "terminal167 cgroup still populated"
            );
            ensure!(
                identity(&held.metadata()?) == identity(&fs::symlink_metadata(&group)?),
                "terminal cgroup changed"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    no_unit_processes()?;
    let after = serde_json::to_value(native(UNIT)?)?;
    native_closed(&after)?;
    ensure!(
        before == after,
        "terminal167 native state changed during closure capture"
    );
    Ok(
        json!({"terminal_event":request.terminal_event,"native":after,"original_invocation_id":IID,
        "unit_cgroup_processes":[],"cgroup_recursive_population_zero_or_absent":true,"memory_resident_deduction_bytes":0,"promise_ending_bytes":0,"resource_credit_bytes":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn docs() -> Value {
        serde_json::from_str(include_str!("dep_2e87c641674d_terminal167-fixture.json")).unwrap()
    }
    fn check(v: &Value) -> Result<()> {
        evidence(
            &v["event"],
            &v["intent"],
            &v["complete"],
            &v["pid1"],
            &v["native"],
            2_000_000_000,
        )
    }
    #[test]
    fn genuine_root_cap_stop_is_not_replay_completion_or_resource_release() {
        check(&docs()).unwrap();
    }
    #[test]
    fn changed_original_invocation_or_guard_plan_rejected() {
        for key in ["producer_invocation_id", "plan_sha256"] {
            let mut v = docs();
            v["intent"][key] = json!("f".repeat(64));
            assert!(check(&v).is_err());
        }
    }
    #[test]
    fn start_only_or_absent_native_stop_cannot_qualify() {
        let v = docs();
        for id in [
            "de5b426a63be47a7b6ac3eaac82e2f6f",
            "7ad2d189f7e94e70a38c781354912448",
            "9d1aaa27d60140bd96365438aad20286",
        ] {
            let mut bad = v.clone();
            bad["pid1"]
                .as_array_mut()
                .unwrap()
                .retain(|r| r["MESSAGE_ID"] != id);
            assert!(check(&bad).is_err());
        }
    }
    #[test]
    fn foreign_pid1_identity_and_future_stop_rejected() {
        for key in [
            "_PID",
            "_UID",
            "_BOOT_ID",
            "_MACHINE_ID",
            "INVOCATION_ID",
            "UNIT",
        ] {
            let mut v = docs();
            v["pid1"][0][key] = json!("foreign");
            assert!(check(&v).is_err());
        }
        let v = docs();
        assert!(journal(&v["pid1"], 1).is_err());
    }
    #[test]
    fn active_reused_or_queued_current_unit_rejected() {
        for (key, value) in [
            ("MainPID", "1"),
            ("ControlPID", "1"),
            ("Job", "1 start"),
            ("InvocationID", IID),
            ("ActiveState", "active"),
            ("LoadState", "loaded"),
        ] {
            let mut v = docs();
            v["native"][key] = json!(value);
            assert!(check(&v).is_err());
        }
    }
    #[test]
    fn partial_or_wrong_reason_stop_rejected() {
        for key in ["scratch_deleted", "remote_mutations"] {
            let mut v = docs();
            v["complete"][key] = json!(true);
            assert!(check(&v).is_err());
        }
        let mut v = docs();
        v["intent"]["reason"] = json!("complete");
        assert!(check(&v).is_err());
        let mut v = docs();
        v["complete"]["terminal"]["pid"] = json!(1);
        assert!(check(&v).is_err());
    }
    #[test]
    fn original_cap_and_zero_credit_cannot_change() {
        let mut v = docs();
        v["intent"]["sample"]["maximum_root_physical_bytes"] = json!(ROOT_CAP + 1);
        assert!(check(&v).is_err());
        let mut v = docs();
        v["event"]["resource_credit_bytes"] = json!(1);
        assert!(check(&v).is_err());
    }
    #[test]
    fn explicit_pair_only_allows_exact_live166() {
        let mut r = crate::terminal169::tests::request();
        r.owners
            .retain(|o| serde_json::to_value(o).unwrap()["epoch"] == 166);
        r.terminal167 = Some(exact());
        memory_scope(&r, 170).unwrap();
        for candidate in [166, 167, 169, 171] {
            assert!(memory_scope(&r, candidate).is_err());
        }
        r.terminal169 = None;
        assert!(memory_scope(&r, 170).is_err());
    }
    #[test]
    fn omission_duplicate_or_readding_stopped_peer_rejected() {
        let mut r = crate::terminal169::tests::request();
        r.terminal167 = Some(exact());
        assert!(memory_scope(&r, 170).is_err());
        r.owners.clear();
        assert!(memory_scope(&r, 170).is_err());
    }
    #[test]
    fn terminal_unit_process_matching_is_exact_and_recursive() {
        assert!(process_in_unit(&format!("0::/system.slice/{UNIT}\n")).unwrap());
        assert!(process_in_unit(&format!("0::/system.slice/{UNIT}/child\n")).unwrap());
        assert!(!process_in_unit(&format!("0::/system.slice/{UNIT}-other\n")).unwrap());
        assert!(process_in_unit("0::/\n1::/\n").is_err());
    }
}
