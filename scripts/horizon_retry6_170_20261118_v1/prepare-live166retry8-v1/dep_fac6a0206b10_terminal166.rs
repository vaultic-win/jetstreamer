//! Exact closed166 support; terminal evidence never releases a reservation.
use super::*;
use std::time::{Duration, Instant};
pub(super) const UNIT: &str = "horizon-qualify-166-replacement-local3retry4-20261110-v1.service";
pub(super) const IID: &str = "58778e77980e4a15828c3be837e447aa";
const BOOT: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
const MACHINE: &str = "59498204047045e4a428419acee7df19";
const EVENT: &str =
    "/var/lib/jetstreamer/root0348-oneowner-cycle-20261116-v1/TERMINAL166_EVENT.json";
const EVENT_SHA: &str = "0fb4f358747aefaaf5f34e93cfce8156a21cd0abc33138151456f258e2217231";
const GUARD_PLAN_SHA: &str = "01c97f7c840758ad0bb525fb3a30bdda376616fb74ac87bad0353bc87dcffccf";
const ADMISSION: &str = "/var/lib/jetstreamer/retry4-single166-guarded-launch-20261114-v5/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json";
const ADMISSION_SHA: &str = "3c02237052a6b25a28c9f5026714a1fa530da2283c647628f2136b3843d0d582";
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
        .is_some_and(|r| r.terminal166.is_some())
}
pub(super) fn memory_scope(r: &resident_memory::Request, candidate: u64) -> Result<()> {
    ensure!(
        candidate == 170
            && r.admission_only_capture
            && r.host_kernel_same_resident_basis
            && r.terminal166.as_ref() == Some(&exact())
            && r.terminal167.as_ref() == Some(&terminal167::exact())
            && r.terminal169.as_ref() == Some(&terminal169::exact())
            && r.owners.is_empty(),
        "zero-owner route requires exact terminal166+167+169 and no live RSS owners"
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
            && v["SubState"] == "dead"
            && v["ControlGroup"] == ""
            && v["Result"] == "success"
            && v["NRestarts"] == "0"
            && v["ExecMainStatus"] == "0",
        "terminal166 native identity is not exactly collected/closed"
    );
    Ok(())
}
fn journal(v: &Value, at: u64) -> Result<()> {
    let rows = v.as_array().context("native166 PID1 rows")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 128,
        "bounded166 journal required"
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
            "foreign166 native journal identity"
        );
        let cursor = r["__CURSOR"].as_str().context("166 cursor")?;
        ensure!(
            !cursor.is_empty() && cursors.insert(cursor),
            "duplicate166 cursor"
        );
        let number = |k: &str| -> Result<u64> {
            let s = r[k].as_str().context("166 timestamp")?;
            ensure!(
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
                "166 timestamp shape"
            );
            Ok(s.parse()?)
        };
        let clock = (
            number("__REALTIME_TIMESTAMP")?,
            number("__MONOTONIC_TIMESTAMP")?,
        );
        ensure!(
            clock.0 > 0 && clock.1 > 0 && clock.0 / 1_000_000 <= at,
            "future166 terminal"
        );
        match r["MESSAGE_ID"].as_str() {
            Some("de5b426a63be47a7b6ac3eaac82e2f6f") => {
                ensure!(
                    r["JOB_TYPE"] == "stop" && stopping.replace(clock).is_none(),
                    "166 native stopping"
                );
            }
            Some("7ad2d189f7e94e70a38c781354912448") => {
                ensure!(
                    deactivated.replace(clock).is_none(),
                    "166 unique native deactivation"
                );
            }
            Some("9d1aaa27d60140bd96365438aad20286") => {
                ensure!(
                    r["JOB_TYPE"] == "stop"
                        && r["JOB_RESULT"] == "done"
                        && stopped.replace(clock).is_none(),
                    "166 native completed stop"
                );
            }
            _ => {}
        }
    }
    let a = stopping.context("166 stop start missing")?;
    let b = deactivated.context("166 deactivation missing")?;
    let c = stopped.context("166 stop completion missing")?;
    ensure!(
        a.0 <= b.0 && a.1 <= b.1 && b.0 <= c.0 && b.1 <= c.1,
        "166 native stop ordering"
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
            && event["epoch"] == 166
            && event["original_invocation_id"] == IID
            && event["resource_credit_bytes"] == 0
            && event["active_replay_epochs"] == json!([])
            && event["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= at),
        "166 event owner/clock/credit"
    );
    ensure!(
        intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && intent["producer_invocation_id"] == IID
            && intent["plan_sha256"] == GUARD_PLAN_SHA
            && intent["reason"] == "root-physical-budget",
        "166 original guard intent"
    );
    let s = &intent["sample"];
    ensure!(
        s["producer_invocation_id"] == IID
            && s["plan_sha256"] == GUARD_PLAN_SHA
            && s["producer"]["invocation_id"] == IID
            && s["producer"]["pid"] == 3455726
            && s["producer"]["active"] == "active"
            && s["producer"]["sub"] == "running"
            && s["producer"]["restarts"] == 0
            && s["producer_stop_enabled"] == true
            && s["trip_reason"] == "root-physical-budget"
            && s["maximum_root_physical_bytes"] == ROOT_CAP
            && s["root_physical_observation"]["maximum_physical_bytes"] == ROOT_CAP
            && s["root_physical_observation"]["exceeds_budget"] == true
            && s["root_physical_observation"]["conservative_physical_bytes"] == 309894897664u64
            && s["scratch_deleted"] == false
            && s["remote_mutations"] == false,
        "166 guard stop facts changed"
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
            && t["result"] == "success"
            && t["load_state"] == "loaded"
            && t["cgroup"] == format!("/system.slice/{UNIT}")
            && t["restart_policy"] == "no"
            && t["kill_mode"] == "control-group"
            && t["delegated"] == false,
        "166 completed original stop required"
    );
    journal(pid1, at)?;
    native_closed(native)?;
    Ok(())
}
pub(super) fn authenticate(request: &Request, at: u64) -> Result<()> {
    ensure!(*request == exact(), "exact166 event binding required");
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
            && row["epoch"] == 166
            && row["state"] == "terminal-retained"
            && row["producer_unit"] == UNIT
            && row["invocation_id"] == IID
            && row["terminal_event"] == serde_json::to_value(&request.terminal_event)?
            && row["retained_memory_promise_bytes"] == 73_014_444_032u64
            && row["memory_resident_deduction_bytes"] == 0
            && row["promise_ending_bytes"] == 0,
        "166 declaration must retain every promise and grant no resident deduction"
    );
    let a = bound(&binding(ADMISSION, ADMISSION_SHA))?;
    ensure!(
        a["epoch"] == 166
            && a["producer_unit"] == UNIT
            && a["producer_invocation_id"] == IID
            && a["fresh_admission_passed"] == true
            && a["all_prior_promises_retained"] == true
            && a["candidate_hard_memory_bytes"] == 73_014_444_032u64
            && a["resource_credit_bytes"] == 0
            && a["memory_or_DATA_promise_ending_bytes"] == 0,
        "original166 admitted promise required"
    );
    let prep = bound(&serde_json::from_value::<Bound>(
        a["fresh_native_Rust_preparation"].clone(),
    )?)?;
    retry3::peer_preparation(
        166,
        row,
        &prep,
        row["retained_lane_physical_bytes"]
            .as_u64()
            .context("166 historical baseline")?,
    )
}
fn process_in_unit(text: &str) -> Result<bool> {
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
    Ok(actual.split('/').any(producer_unit_name))
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
        ensure!(!process_in_unit(&text)?, "terminal166 unit process remains");
    }
    Ok(())
}
fn producer_unit_name(name: &str) -> bool {
    name.starts_with("horizon-qualify-166-") && name.ends_with(".service")
}
fn unit_rows_empty(rows: &Value) -> Result<()> {
    let rows = rows.as_array().context("native166 unit census array")?;
    ensure!(rows.len() <= 65536, "bounded166 unit census");
    for row in rows {
        let unit = row["unit"].as_str().context("native166 census unit")?;
        ensure!(
            !producer_unit_name(unit),
            "epoch166 producer loaded, replacement or queued"
        );
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NamespaceQuery {
    Units,
    Jobs,
}
impl NamespaceQuery {
    fn label(self) -> &'static str {
        match self {
            Self::Units => "terminal166 systemctl list-units",
            Self::Jobs => "terminal166 systemctl list-jobs",
        }
    }
    fn args(self) -> &'static [&'static str] {
        match self {
            Self::Units => &[
                "list-units",
                "--all",
                "--no-pager",
                "--output=json",
                "horizon-qualify-166-*.service",
            ],
            Self::Jobs => &["list-jobs", "--no-pager", "--output=json"],
        }
    }
}
fn namespace_output(
    query: NamespaceQuery,
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<()> {
    ensure!(
        success && stderr.is_empty() && stdout.len() <= (1 << 20),
        "{}: command failed, stderr nonempty or stdout exceeds census bound",
        query.label()
    );
    // This host returns exactly zero bytes on successful list-jobs with no jobs.
    // No trimming: whitespace-only, malformed JSON and empty list-units still fail.
    if query == NamespaceQuery::Jobs && stdout.is_empty() {
        return Ok(());
    }
    let rows: Value = serde_json::from_slice(stdout)
        .with_context(|| format!("{}: invalid census JSON", query.label()))?;
    unit_rows_empty(&rows).with_context(|| {
        format!(
            "{}: invalid or nonempty epoch166 producer census",
            query.label()
        )
    })
}
fn namespace_empty() -> Result<()> {
    for query in [NamespaceQuery::Units, NamespaceQuery::Jobs] {
        let o = Command::new("/usr/bin/systemctl")
            .args(query.args())
            .output()
            .with_context(|| format!("{}: native command execution failed", query.label()))?;
        namespace_output(query, o.status.success(), &o.stdout, &o.stderr)?;
    }
    Ok(())
}

fn population_zero(text: &str) -> Result<()> {
    ensure!(
        text.len() <= 4096
            && text
                .lines()
                .filter(|l| l.starts_with("populated "))
                .collect::<Vec<_>>()
                == vec!["populated 0"],
        "epoch166 cgroup remains populated or population unknown"
    );
    Ok(())
}
fn cgroup_namespace_empty() -> Result<()> {
    let clock = Instant::now();
    let mut inspected = 0usize;
    let mut pending = vec![PathBuf::from("/sys/fs/cgroup")];
    while let Some(path) = pending.pop() {
        inspected += 1;
        ensure!(
            inspected <= 65536 && clock.elapsed() <= Duration::from_secs(15),
            "bounded166 cgroup namespace scan"
        );
        let held = directory(&path)?;
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(producer_unit_name)
        {
            let f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path.join("cgroup.events"))?;
            let mut text = String::new();
            f.take(4097).read_to_string(&mut text)?;
            population_zero(&text)?;
        }
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            ensure!(!kind.is_symlink(), "unexpected cgroup namespace symlink");
            if kind.is_dir() {
                pending.push(entry.path());
            }
        }
        ensure!(
            identity(&held.metadata()?) == identity(&fs::symlink_metadata(&path)?),
            "166 cgroup namespace changed during scan"
        );
    }
    Ok(())
}
pub(super) fn equal_endpoints(before: &Option<Value>, after: &Option<Value>) -> Result<()> {
    ensure!(
        before == after,
        "terminal166 changed across native measurement window"
    );
    Ok(())
}
pub(super) fn cross_transactions(first: &Value, current: &Value) -> Result<()> {
    let before = &first["terminal166_before"];
    ensure!(
        before.is_object()
            && before == &first["terminal166_after"]
            && before == &current["terminal166_before"]
            && before == &current["terminal166_after"],
        "terminal166 changed or missing across four resident endpoints"
    );
    Ok(())
}
/// Original and all replacement producer units must remain absent. No promise ends.
pub(super) fn endpoint(request: &Request) -> Result<Value> {
    authenticate(request, now()?)?;
    ensure!(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .replace('-', "")
            == BOOT
            && fs::read_to_string("/etc/machine-id")?.trim() == MACHINE,
        "terminal166 host boot changed"
    );
    namespace_empty()?;
    let before = serde_json::to_value(native(UNIT)?)?;
    native_closed(&before)?;
    cgroup_namespace_empty()?;
    no_unit_processes()?;
    let after = serde_json::to_value(native(UNIT)?)?;
    native_closed(&after)?;
    namespace_empty()?;
    ensure!(
        before == after,
        "terminal166 native state changed during closure capture"
    );
    Ok(
        json!({"terminal_event":request.terminal_event,"native":after,"original_invocation_id":IID,
        "producer_unit_namespace":"horizon-qualify-166-*.service",
        "loaded_or_queued_producer_units":[],"unit_cgroup_processes":[],
        "cgroup_recursive_population_zero_or_absent":true,"memory_resident_deduction_bytes":0,
        "promise_ending_bytes":0,"resource_credit_bytes":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn docs() -> Value {
        serde_json::from_str(include_str!("dep_c28f55cfd8c0_terminal166-fixture.json")).unwrap()
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
    fn zero_request() -> resident_memory::Request {
        let mut r = crate::terminal169::tests::request();
        r.owners.clear();
        r.terminal167 = Some(terminal167::exact());
        r.terminal166 = Some(exact());
        r
    }
    #[test]
    fn zero_route_requires_all_three_exact_events_and_no_owner() {
        let r = zero_request();
        memory_scope(&r, 170).unwrap();
        for candidate in [166, 167, 169, 171] {
            assert!(memory_scope(&r, candidate).is_err());
        }
        for key in ["terminal166", "terminal167", "terminal169"] {
            let mut v = serde_json::to_value(zero_request()).unwrap();
            v[key] = Value::Null;
            let r: resident_memory::Request = serde_json::from_value(v).unwrap();
            assert!(memory_scope(&r, 170).is_err());
            assert!(terminal169::memory_scope(&r, 170).is_err());
        }
        for key in ["admission_only_capture", "host_kernel_same_resident_basis"] {
            let mut v = serde_json::to_value(zero_request()).unwrap();
            v[key] = json!(false);
            let r = serde_json::from_value(v).unwrap();
            assert!(memory_scope(&r, 170).is_err());
        }
        let mut r = zero_request();
        r.owners = crate::terminal169::tests::request().owners;
        assert!(memory_scope(&r, 170).is_err());
        let mut r = zero_request();
        r.terminal166.as_mut().unwrap().terminal_event.sha256 = "f".repeat(64);
        assert!(memory_scope(&r, 170).is_err());
        let mut r = zero_request();
        r.terminal166.as_mut().unwrap().terminal_event.path = "/foreign".into();
        assert!(memory_scope(&r, 170).is_err());
    }
    #[test]
    fn replacement_queued_units_and_descendant_processes_are_rejected() {
        for unit in [
            UNIT,
            "horizon-qualify-166-replacement-local3retry5-20261116-v1.service",
        ] {
            assert!(unit_rows_empty(&json!([{"unit":unit}])).is_err());
            assert!(process_in_unit(&format!("0::/system.slice/{unit}\n")).unwrap());
            assert!(process_in_unit(&format!("0::/other.slice/{unit}/child\n")).unwrap());
        }
        unit_rows_empty(&json!([])).unwrap();
        unit_rows_empty(&json!([{"unit":"horizon-qualify-167-replacement-test.service"}])).unwrap();
        assert!(unit_rows_empty(&json!([{}])).is_err());
        assert!(!process_in_unit(&format!("0::/system.slice/{UNIT}-other\n")).unwrap());
        assert!(process_in_unit("0::/\n1::/\n").is_err());
    }
    #[test]
    fn population_missing_duplicate_or_positive_is_not_closure() {
        population_zero("populated 0\nfrozen 0\n").unwrap();
        for bad in [
            "",
            "populated 1\n",
            "populated 0\npopulated 0\n",
            "populated unknown\n",
        ] {
            assert!(population_zero(bad).is_err());
        }
    }
    #[test]
    fn changed_or_missing_closure_endpoints_reject() {
        let good =
            json!({"terminal166_before":{"unit":"closed"},"terminal166_after":{"unit":"closed"}});
        cross_transactions(&good, &good).unwrap();
        for key in ["terminal166_before", "terminal166_after"] {
            let mut bad = good.clone();
            bad[key] = Value::Null;
            assert!(cross_transactions(&good, &bad).is_err());
            assert!(cross_transactions(&bad, &good).is_err());
        }
        assert!(equal_endpoints(&Some(json!({"a":1})), &Some(json!({"a":2}))).is_err());
    }
    #[test]
    fn namespace_parser_qualifies_exact_bound_native_empty_job_diagnosis() {
        let bytes = include_bytes!("dep_fe600881d293_NATIVE_EMPTY_JOB_LIST_DIAGNOSIS.json");
        assert_eq!(
            digest(bytes),
            "b2d77f8d3a7f8b9770edfe444f0338f27772f39c8bb2f7823fbf33afb6572c60"
        );
        let diagnosis: Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(diagnosis["no_replay_launched"], true);
        assert_eq!(
            diagnosis["original_failure"]["sha256"],
            "ee9785f5927f29557b701dcf4f359973651f655202e691cda77935fbd4fc01f2"
        );
        let rows = diagnosis["native"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for (query, row) in [NamespaceQuery::Units, NamespaceQuery::Jobs]
            .into_iter()
            .zip(rows)
        {
            let mut expected = vec!["systemctl"];
            expected.extend_from_slice(query.args());
            assert_eq!(row["argv"], json!(expected));
            assert_eq!(row["code"], 0);
            assert_eq!(row["stderr"], "");
            let stdout = row["stdout"].as_str().unwrap();
            assert_eq!(
                stdout,
                if query == NamespaceQuery::Units {
                    "[]\n"
                } else {
                    ""
                }
            );
            namespace_output(query, true, stdout.as_bytes(), b"").unwrap();
        }
    }
    #[test]
    fn namespace_parser_zero_bytes_are_job_specific_and_whitespace_is_not_empty() {
        namespace_output(NamespaceQuery::Jobs, true, b"", b"").unwrap();
        assert!(namespace_output(NamespaceQuery::Units, true, b"", b"").is_err());
        for query in [NamespaceQuery::Units, NamespaceQuery::Jobs] {
            for text in [" ", "\n", "\r\n", "\t ", "\u{feff}"] {
                assert!(namespace_output(query, true, text.as_bytes(), b"").is_err());
            }
        }
    }
    #[test]
    fn namespace_parser_rejects_failed_commands_stderr_and_oversize_before_empty_success() {
        for query in [NamespaceQuery::Units, NamespaceQuery::Jobs] {
            for stdout in [b"".as_slice(), b"[]\n".as_slice()] {
                assert!(namespace_output(query, false, stdout, b"").is_err());
                assert!(namespace_output(query, true, stdout, b"warning").is_err());
                assert!(namespace_output(query, true, stdout, b"\n").is_err());
                assert!(namespace_output(query, false, stdout, b"failed").is_err());
            }
            let mut boundary = vec![b' '; 1 << 20];
            boundary[0] = b'[';
            boundary[1] = b']';
            namespace_output(query, true, &boundary, b"").unwrap();
            boundary.push(b' ');
            assert!(namespace_output(query, true, &boundary, b"").is_err());
        }
    }
    #[test]
    fn namespace_parser_rejects_malformed_nonarray_and_missing_unit_json() {
        for query in [NamespaceQuery::Units, NamespaceQuery::Jobs] {
            for text in [
                "[",
                "null",
                "{}",
                "true",
                "0",
                "[{}]",
                "[null]",
                "[{\"unit\":null}]",
                "[{\"unit\":42}]",
                "[] junk",
                "[] []",
            ] {
                assert!(
                    namespace_output(query, true, text.as_bytes(), b"").is_err(),
                    "{query:?} {text}"
                );
            }
            assert!(namespace_output(query, true, &[0xff], b"").is_err());
        }
    }
    #[test]
    fn namespace_parser_keeps_full_original_and_replacement_queued166_detection() {
        for query in [NamespaceQuery::Units, NamespaceQuery::Jobs] {
            for unit in [
                UNIT,
                "horizon-qualify-166-replacement-local3retry5-20261116-v1.service",
            ] {
                for state in ["waiting", "running", "inactive"] {
                    let rows = json!([{"id":1,"unit":"unrelated.service","type":"start","state":"waiting"},
                        {"id":2,"unit":unit,"type":"start","state":state}]);
                    assert!(
                        namespace_output(query, true, &serde_json::to_vec(&rows).unwrap(), b"")
                            .is_err()
                    );
                }
            }
        }
    }
    #[test]
    fn namespace_parser_accepts_existing_json_forms_and_unrelated_jobs() {
        for query in [NamespaceQuery::Units, NamespaceQuery::Jobs] {
            for text in [
                "[]",
                "[]\n",
                "  [] \n",
                "[{\"unit\":\"unrelated.service\"}]",
                "[{\"unit\":\"horizon-qualify-167-replacement-local3retry3-20261110-v1.service\"}]",
            ] {
                namespace_output(query, true, text.as_bytes(), b"").unwrap();
            }
        }
    }
    #[test]
    fn namespace_parser_errors_identify_command_and_failure_stage() {
        for query in [NamespaceQuery::Units, NamespaceQuery::Jobs] {
            for (success, stdout, stderr, stage) in [
                (false, b"".as_slice(), b"".as_slice(), "command failed"),
                (true, b" ".as_slice(), b"".as_slice(), "invalid census JSON"),
                (
                    true,
                    b"[{}]".as_slice(),
                    b"".as_slice(),
                    "invalid or nonempty epoch166 producer census",
                ),
            ] {
                let error = format!(
                    "{:#}",
                    namespace_output(query, success, stdout, stderr).unwrap_err()
                );
                assert!(error.contains(query.label()), "{error}");
                assert!(error.contains(stage), "{error}");
            }
        }
    }
}
