//! Exact opt-in for terminal169: closure is never reservation release.
use super::*;
use std::time::{Duration, Instant};
pub(super) const SCHEMA: &str = "horizon-current-allocation-terminal169-request-v2";
pub(super) const UNIT: &str = "horizon-qualify-169-replacement-local3retry3-20261110-v1.service";
pub(super) const IID: &str = "ec398061359442f880f75b6e12cf21e7";
pub(super) const EXTRA_DATA: u64 = 4 << 30;
pub(super) const COMPLETE_DATA: u64 = current_budget::CURRENT_DATA + EXTRA_DATA;
pub(super) const RAW_FLOOR: u64 = current_budget::CURRENT_FLOOR + EXTRA_DATA;
const EVENT_PATH: &str = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/journal-resume-drift-v3/status0940-20261115/EVENT.json";
const EVENT_SHA: &str = "86c6e9d779bcf2f52ef36b0abcf589d50e65be70c1f3baa3aeebdacbed3add4c";
const BOOKING_PATH: &str = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-input-freeze-v1/ROOT_DATA_BOOKING.json";
const BOOKING_SHA: &str = "94a54718ff7f906c51948eb1905b1f771e4b102cf3492b1b5875e30bb39ceef2";
const ADMISSION_PATH: &str = "/var/lib/jetstreamer/retry3-peer169-guarded-launch-20261113-v1/epoch169/ACTUAL_REPLACEMENT_ADMISSION.json";
const ADMISSION_SHA: &str = "d82a46690b0321b1f1ecb23575ca5adb681d9c4aad03bd4cf4f0a6b88030e3b2";
const BOOT: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
const MACHINE: &str = "59498204047045e4a428419acee7df19";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub terminal_event: Bound,
    pub additive_data_booking: Bound,
}
fn binding(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
pub(super) fn exact() -> Request {
    Request {
        terminal_event: binding(EVENT_PATH, EVENT_SHA),
        additive_data_booking: binding(BOOKING_PATH, BOOKING_SHA),
    }
}
pub(super) fn selected(p: &Plan) -> bool {
    p.resident_memory
        .as_ref()
        .is_some_and(|r| r.terminal169.is_some())
}
pub(super) fn data(p: &Plan) -> u64 {
    if retry167::selected(p) { return retry167::COMPLETE_DATA; }
    if terminal167::selected(p) {
        completed167::COMPLETE_DATA
    } else if selected(p) {
        COMPLETE_DATA
    } else {
        current_budget::CURRENT_DATA
    }
}
pub(super) fn floor(p: &Plan) -> u64 {
    if retry167::selected(p) { return retry167::RAW_FLOOR; }
    if terminal167::selected(p) {
        completed167::RAW_FLOOR
    } else if selected(p) {
        RAW_FLOOR
    } else {
        current_budget::CURRENT_FLOOR
    }
}
pub(super) fn memory_scope(request: &resident_memory::Request, candidate: u64) -> Result<u64> {
    if candidate == 167 && request.terminal170.is_some() { return retry167::memory_scope(request); }
    let Some(r) = &request.terminal169 else {
        ensure!(
            request.terminal167.is_none() && request.terminal166.is_none() && request.terminal170.is_none(),
            "terminal167 requires terminal169 opt-in"
        );
        return Ok(current_budget::CURRENT_DATA);
    };
    if request.terminal166.is_some() {
        terminal166::memory_scope(request, candidate)?;
        return Ok(completed167::COMPLETE_DATA);
    }
    if request.terminal167.is_some() {
        ensure!(request.terminal170.is_none(), "terminal170 requires exact retry5 candidate167");
        terminal167::memory_scope(request, candidate)?;
        return Ok(completed167::COMPLETE_DATA);
    }
    ensure!(
        *r == exact()
            && candidate == 170
            && request.admission_only_capture
            && request.host_kernel_same_resident_basis,
        "terminal169 requires exact opt-in candidate170 and additive booking"
    );
    let owners = serde_json::to_value(&request.owners)?;
    let rows = owners.as_array().context("exact live owners")?;
    ensure!(
        rows.len() == 2,
        "terminal169 requires only two exact live RSS owners"
    );
    for (epoch, attempt, iid) in [
        (166, "local3retry4", "58778e77980e4a15828c3be837e447aa"),
        (167, "local3retry3", "7ce90d0ec8114cf3a6be73eb9cf75ae8"),
    ] {
        let matches: Vec<_> = rows.iter().filter(|r| r["epoch"] == epoch).collect();
        ensure!(
            matches.len() == 1
                && matches[0]["unit"]
                    == format!("horizon-qualify-{epoch}-replacement-{attempt}-20261110-v1.service")
                && matches[0]["invocation_id"] == iid,
            "terminal169 live peer identity differs"
        );
    }
    Ok(COMPLETE_DATA)
}
pub(super) fn shape(p: &Plan) -> Result<()> {
    if retry167::selected(p) { return retry167::shape(p); }
    ensure!(
        !terminal166::selected(p) || (terminal167::selected(p) && selected(p)),
        "terminal166 requires terminal167 and terminal169 plan"
    );
    ensure!(
        !terminal167::selected(p) || selected(p),
        "terminal167 requires terminal169 plan"
    );
    if selected(p) {
        ensure!(
            p.epoch == 170
                && p.attempt == "local3retry3"
                && p.existing_preparation.is_none()
                && p.current_allocation
                    .as_ref()
                    .is_some_and(|r| r.schema == SCHEMA)
                && p.retry3.is_some()
                && p.data_fulfillment.as_ref().is_some_and(|r| r.runtime.path
                    == Path::new(if terminal167::selected(p) {
                        completed167_native_guard::RUNTIME
                    } else {
                        prelaunch_data::TERMINAL_RUNTIME
                    })),
            "terminal169 route cannot escape exact native170 admission"
        );
        memory_scope(
            p.resident_memory.as_ref().context("resident request")?,
            p.epoch,
        )?;
    }
    Ok(())
}
fn booking(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-private183-holding-build-additive-DATA-booking-v1"
            && v["owner"] == "/root"
            && v["primary_thread"] == THREAD
            && v["previous_complete_DATA_bytes"] == current_budget::CURRENT_DATA
            && v["additional_DATA_bytes"] == EXTRA_DATA
            && v["complete_DATA_bytes"] == COMPLETE_DATA
            && v["minimum_free_bytes"] == RAW_FLOOR
            && v["maximum_root_bytes"] == (3u64 << 30)
            && v["growth_overshoot_reserve_bytes"] == (1u64 << 30)
            && v["complete_projected_memory_bytes_unchanged"] == current_budget::CURRENT_MEMORY
            && v["new_memory_promise_bytes"] == 0
            && v["all_prior_promises_retained"] == true
            && v["resource_credit_bytes"] == 0
            && v["replay_launch_authorized"] == false,
        "complete additive holding DATA booking required"
    );
    Ok(())
}
fn journal(v: &Value, at: u64) -> Result<()> {
    let rows = v.as_array().context("native PID1 terminal rows")?;
    ensure!(!rows.is_empty() && rows.len() <= 128, "bounded PID1 rows");
    let mut cursors = BTreeSet::new();
    let mut started = None;
    let mut exited = None;
    let mut failed = None;
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
            "foreign terminal169 native identity"
        );
        let cursor = r["__CURSOR"].as_str().context("PID1 cursor")?;
        ensure!(
            !cursor.is_empty() && cursors.insert(cursor),
            "duplicate or absent terminal cursor"
        );
        let number = |k: &str| -> Result<u64> {
            let s = r[k].as_str().context("native timestamp")?;
            ensure!(
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
                "native timestamp shape"
            );
            Ok(s.parse()?)
        };
        let clock = (
            number("__REALTIME_TIMESTAMP")?,
            number("__MONOTONIC_TIMESTAMP")?,
        );
        ensure!(
            clock.0 > 0 && clock.1 > 0 && clock.0 / 1_000_000 <= at,
            "future/zero terminal timestamp"
        );
        match r["MESSAGE_ID"].as_str() {
            Some("39f53479d3a045ac8e11786248231fbf") => {
                ensure!(
                    r["JOB_TYPE"] == "start"
                        && r["JOB_RESULT"] == "done"
                        && started.replace(clock).is_none(),
                    "ambiguous native start"
                );
            }
            Some("98e322203f7a4ed290d09fe03c09fe15") => {
                ensure!(
                    r["EXIT_CODE"] == "exited"
                        && r["EXIT_STATUS"] == "1"
                        && r["COMMAND"] == "ExecStart"
                        && exited.replace(clock).is_none(),
                    "exact original failure exit required"
                );
            }
            Some("d9b373ed55a64feb8242e02dbe79a49c") => {
                ensure!(
                    r["UNIT_RESULT"] == "exit-code" && failed.replace(clock).is_none(),
                    "exact original failed unit required"
                );
            }
            _ => {}
        }
    }
    let a = started.context("native original start")?;
    let b = exited.context("native original exit")?;
    let c = failed.context("native original terminal failure")?;
    ensure!(
        a.0 <= b.0 && a.1 <= b.1 && b.0 <= c.0 && b.1 <= c.1,
        "native terminal ordering"
    );
    Ok(())
}
pub(super) fn authenticate(request: &Request, at: u64) -> Result<()> {
    ensure!(*request == exact(), "foreign terminal169 evidence pins");
    let event = bound(&request.terminal_event)?;
    ensure!(
        event["owner"] == "/root"
            && event["primary_thread"] == THREAD
            && event["all_promises_retained"] == true
            && event["no_new_replay_launch_authority"] == true,
        "terminal event preservation"
    );
    let pid1: Bound = serde_json::from_value(event["pid1"].clone())?;
    let n: Bound = serde_json::from_value(event["terminal169"].clone())?;
    let original = bound(&n)?;
    ensure!(
        original["Id"] == UNIT
            && original["MainPID"] == "0"
            && original["ControlPID"] == "0"
            && original["Job"] == ""
            && original["InvocationID"] == ""
            && original["ActiveState"] == "inactive"
            && original["SubState"] == "dead",
        "original collected terminal capture differs"
    );
    journal(&bound(&pid1)?, at)?;
    booking(&bound(&request.additive_data_booking)?)?;
    Ok(())
}
pub(super) fn declaration(row: &Value, request: &Request) -> Result<()> {
    ensure!(
        *request == exact()
            && row["epoch"] == 169
            && row["state"] == "terminal-retained"
            && row["producer_unit"] == UNIT
            && row["invocation_id"] == IID
            && row["terminal_event"] == serde_json::to_value(&request.terminal_event)?
            && row["retained_memory_promise_bytes"] == 73_014_444_032u64
            && row["memory_resident_deduction_bytes"] == 0
            && row["promise_ending_bytes"] == 0,
        "exact terminal169 retained declaration required"
    );
    let a = bound(&binding(ADMISSION_PATH, ADMISSION_SHA))?;
    ensure!(
        a["epoch"] == 169
            && a["producer_unit"] == UNIT
            && a["producer_invocation_id"] == IID
            && a["fresh_admission_passed"] == true
            && a["all_prior_promises_retained"] == true
            && a["candidate_hard_memory_bytes"] == 73_014_444_032u64
            && a["resource_credit_bytes"] == 0
            && a["memory_or_DATA_promise_ending_bytes"] == 0,
        "genuine stopped admission required"
    );
    let prep = bound(&serde_json::from_value::<Bound>(
        a["fresh_native_Rust_preparation"].clone(),
    )?)?;
    retry3::peer_preparation(
        169,
        row,
        &prep,
        row["retained_lane_physical_bytes"]
            .as_u64()
            .context("retained169 baseline")?,
    )?;
    Ok(())
}
fn native_closed(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == UNIT
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"] == ""
            && ((v["LoadState"] == "not-found"
                && v["InvocationID"] == ""
                && v["ActiveState"] == "inactive"
                && v["SubState"] == "dead")
                || (v["LoadState"] == "loaded"
                    && v["InvocationID"] == IID
                    && v["NRestarts"] == "0"
                    && v["ActiveState"] == "failed"
                    && v["SubState"] == "failed"
                    && v["Result"] == "exit-code"
                    && v["ExecMainStatus"] == "1")),
        "terminal169 is live, queued, reused or not exactly closed"
    );
    Ok(())
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
        ensure!(!process_in_unit(&text)?, "terminal169 unit process remains");
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
        "terminal169 host boot changed"
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
                "terminal169 cgroup still populated"
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
        "terminal169 native state changed during closure capture"
    );
    Ok(
        json!({"terminal_event":request.terminal_event,"native":after,"original_invocation_id":IID,
        "unit_cgroup_processes":[],"cgroup_recursive_population_zero_or_absent":true,"memory_resident_deduction_bytes":0,"promise_ending_bytes":0,"resource_credit_bytes":0}),
    )
}
#[cfg(test)]
#[path = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-controls-v7/peer170-terminal169-build-v3/source-sealed/terminal169_tests.rs"]
pub(super) mod tests;
