//! Cancellation requires exact retained evidence and a fresh native census for each failed attempt.
use super::*;
struct FailedAttempt {
    unit: &'static str,
    guard: &'static str,
    timer: &'static str,
    iid: &'static str,
    first_guard: &'static str,
    tokens: &'static str,
    launch: &'static str,
    floor: u64,
    pins: &'static [(&'static str, &'static str, &'static str)],
    review_flag: &'static str,
    receipt_name: &'static str,
}
const V1: FailedAttempt = FailedAttempt {
    unit: "horizon-qualify-265-replacement-20261119-v1.service",
    guard: "horizon-265-replacement-20261119-protective-v1.service",
    timer: "horizon-265-replacement-20261119-protective-v1.timer",
    iid: "0a59d8b510ee46549e888cebbe38597f",
    first_guard: "429732d4e2644dffb02c25f68891e387",
    tokens: "/var/lib/jetstreamer/horizon265-replacement-20261119-tokens-v1",
    launch: "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v1/launch-v1",
    floor: 3_722_733_519_128,
    pins: &[
        (
            "diagnosis",
            "/home/ubuntu/.codex/diagnostics/horizon265-pretoken-failure-20261119-v1/diagnosis.json",
            "a90c050ac68790a13aa30c6b786f6144bf834292a51052661ebea2559499dd4d",
        ),
        (
            "original_terminal",
            "/home/ubuntu/.codex/diagnostics/horizon265-pretoken-failure-20261119-v1/producer.txt",
            "da62462a712d0c818734df9faf3bf0402f4f7eafe1d191433393be33f3460cc9",
        ),
        (
            "failure",
            "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v1/launch-v1/failure.json",
            "7080e10e94d36317f573aa4b9e8f15970b9b97f6d96e18640c5d7b1772a33a1c",
        ),
        (
            "first_guard",
            "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v1/launch-v1/actual-first-guard-sample.json",
            "bc4bafa0751d283689bd2f518f5cd59d7c720cd044f43a8ec0b330c2521e4e5b",
        ),
        (
            "unsealed_token_proposal",
            "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v1/launch-v1/guard-admission.json",
            "27772424677e8e97bfb94bbfead69db8fb5d98e62eccc26e1c5a92012cef91f6",
        ),
        (
            "original_admission",
            "/var/lib/jetstreamer/horizon265-current-execution-20261119-v4/admission.json",
            "f54dff7e1ad176dd3013a9ac01c311d4aefa102173f2eb8f1fec94c45f8ae636",
        ),
    ],
    review_flag: "failed_pretoken_v1_cancelled_before_v3_admission",
    receipt_name: "failed-v1-candidate-cancellation.json",
};
const V2: FailedAttempt = FailedAttempt {
    unit: "horizon-qualify-265-replacement-20261119-v2.service",
    guard: "horizon-265-replacement-20261119-protective-v2.service",
    timer: "horizon-265-replacement-20261119-protective-v2.timer",
    iid: "42e293704a1f404283716b76a3ef05df",
    first_guard: "f101c2f02e0f48e4bdf78e86a4559856",
    tokens: "/var/lib/jetstreamer/horizon265-replacement-20261119-tokens-v2",
    launch: "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v2/launch-v1",
    floor: 3_908_104_436_088,
    pins: &[
        (
            "original_terminal",
            "/home/ubuntu/.codex/diagnostics/horizon265-pretoken-v2-failure-20261120-v1/producer-after.txt",
            "640e3d4dbb8bf529ae72e974c560ee12e2035980b5636107f5efa84baf6a65d7",
        ),
        (
            "guard_terminal",
            "/home/ubuntu/.codex/diagnostics/horizon265-pretoken-v2-failure-20261120-v1/guard-after.txt",
            "376fde2323ac4f19b6ab380e1e32703659dd885ff4218eaba57bdafe777aee6b",
        ),
        (
            "timer_terminal",
            "/home/ubuntu/.codex/diagnostics/horizon265-pretoken-v2-failure-20261120-v1/timer-after.txt",
            "6e7ee2e4fac1cc56b821d634334397f4280346bb98f83c4ca369490e305a4317",
        ),
        (
            "failure",
            "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v2/launch-v1/failure.json",
            "7080e10e94d36317f573aa4b9e8f15970b9b97f6d96e18640c5d7b1772a33a1c",
        ),
        (
            "first_guard",
            "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v2/launch-v1/actual-first-guard-sample.json",
            "639c4b9d2fa4336390fa0a64b6029430033a46eb7adba7a45d9689f27182cb84",
        ),
        (
            "unsealed_token_proposal",
            "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v2/launch-v1/guard-admission.json",
            "5ecde1d4352f9d2449adcf2bb4190a7664b7ecaa751c883086e8fc8e07c9c69d",
        ),
        (
            "original_admission",
            "/var/lib/jetstreamer/horizon265-current-execution-0140-20261120-launch-v2/admission.json",
            "6b229f3bfaf8dfa3949c74d570455b548ec33c8cb447904109e348ffafded478",
        ),
        (
            "accepted_window",
            "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v2/launch-v1/retained-window-006/accepted-retained-window.json",
            "e5be2fc44f448886a866beaa83805b1668e9bdf3d3aa1d4f95c9bfc8c241b2a6",
        ),
    ],
    review_flag: "failed_pretoken_v2_cancelled_before_v3_admission",
    receipt_name: "failed-v2-candidate-cancellation.json",
};
fn properties(raw: &[u8]) -> Result<Value> {
    let mut out = serde_json::Map::new();
    for line in std::str::from_utf8(raw)?.lines() {
        let (key, value) = line.split_once('=').context("failed265 manager framing")?;
        if matches!(key, "ExecStartPre" | "ExecStartPreEx") {
            out.entry(key.to_owned())
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .context("invalid command list")?
                .push(json!(value));
            continue;
        }
        let value = if matches!(
            key,
            "After" | "Wants" | "Requires" | "BindsTo" | "Upholds" | "TriggeredBy"
        ) {
            // PID1 renders dependency sets in unspecified order; compare every member.
            json!(value.split_whitespace().collect::<BTreeSet<_>>())
        } else {
            json!(value)
        };
        ensure!(
            out.insert(key.to_owned(), value).is_none(),
            "duplicate manager property"
        );
    }
    Ok(Value::Object(out))
}
fn never_started(attempt: &FailedAttempt, v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == attempt.unit
            && v["InvocationID"] == attempt.iid
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "failed"
            && v["SubState"] == "failed"
            && v["Result"] == "signal"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["ExecMainPID"] == "0"
            && v["ExecMainStartTimestampMonotonic"] == "0"
            && v["ExecMainCode"] == "0"
            && v["ExecMainStatus"] == "0"
            && v["NRestarts"] == "0",
        "original failed265 never-started identity changed"
    );
    let command = text(v, "ExecStart")?;
    ensure!(
        command.ends_with(" ; pid=0 ; code=(null) ; status=0/0 }")
            && command.contains(" ; start_time=[n/a] ; stop_time=[n/a] ;"),
        "failed265 main has execution history"
    );
    Ok(())
}
fn empty_tokens(attempt: &FailedAttempt) -> Result<()> {
    let p = Path::new(attempt.tokens);
    trusted_parents(p)?;
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_dir()
            && p.canonicalize()? == p
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o777 == 0o755
            && fs::read_dir(p)?.next().is_none(),
        "failed265 token namespace changed or consumed"
    );
    absent(&Path::new(attempt.launch).join("guarded-startup-handoff.json"))?;
    Ok(())
}
fn stopped(attempt: &FailedAttempt, v: &Value, unit: &str) -> Result<()> {
    ensure!(
        v["Id"] == unit
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["Job"] == "",
        "failed265 control not inactive"
    );
    if unit == attempt.guard {
        ensure!(
            v["MainPID"] == "0"
                && v["ControlPID"] == "0"
                && v["NRestarts"] == "0"
                && v["Restart"] == "no",
            "failed265 guard still owns work"
        );
    }
    Ok(())
}
fn drained(attempt: &FailedAttempt) -> Result<()> {
    for unit in [attempt.unit, attempt.guard] {
        let p = Path::new("/sys/fs/cgroup/system.slice").join(unit);
        match fs::symlink_metadata(&p) {
            Ok(_) => live::drained_tree(&p, &mut 1024)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let raw = match fs::read_to_string(entry.path().join("cgroup")) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        for unit in [attempt.unit, attempt.guard] {
            let group = format!("0::/system.slice/{unit}");
            ensure!(
                !raw.lines()
                    .any(|l| l == group || l.starts_with(&format!("{group}/"))),
                "failed265 process remains in original cgroup"
            );
        }
    }
    Ok(())
}
fn show(n: &mut Native, unit: &str) -> Result<Value> {
    let props = format!(
        "{},ExecMainPID,ExecStartPre,ExecMainStartTimestampMonotonic",
        live::PROPS
    );
    properties(&n.run(
        "/usr/bin/systemctl",
        &["show", unit, "--all", "--no-pager", "--property", &props],
    )?)
}
/// Explicit cancellation of the failed candidate, not release of an accepted replay.
/// Returns its inherited floor; the new candidate still receives the full128GB/506GB.
fn validate(
    attempt: &FailedAttempt,
    n: &mut Native,
    review: &Value,
    rows: &[capacity::Reservation],
) -> Result<u64> {
    ensure!(
        review[attempt.review_flag] == true,
        "Main has not accepted failed265 candidate cancellation"
    );
    ensure!(
        !rows.iter().any(|r| r.unit == attempt.unit),
        "failed265 cancellation cannot silently rewrite an existing retained reservation"
    );
    let mut evidence = BTreeMap::new();
    for &(name, path, sha) in attempt.pins {
        let reference = Bound::new(path, sha);
        let bytes = reference.bytes(false)?;
        evidence.insert(name, (reference, bytes));
    }
    let original = properties(&evidence["original_terminal"].1)?;
    never_started(attempt, &original)?;
    let failure: Value = serde_json::from_slice(&evidence["failure"].1)?;
    ensure!(
        failure["original_attempt_not_retried"] == true
            && failure["automatic_retry_authorized"] == false
            && failure["error"] == "retained guard not at accepted clean completion",
        "original pretoken failure changed"
    );
    let first: Value = serde_json::from_slice(&evidence["first_guard"].1)?;
    ensure!(
        first["producer_invocation_id"] == attempt.iid
            && first["guard_invocation_id"] == attempt.first_guard
            && first["workers"] == json!([])
            && first["producer"]["pid"] == 0
            && first["producer"]["active"] == "activating"
            && first["producer"]["sub"] == "start-pre"
            && first["trip_reason"].is_null(),
        "original first guard changed"
    );
    let admission: Value = serde_json::from_slice(&evidence["original_admission"].1)?;
    ensure!(
        admission["candidate_memory_max_bytes"] == 128_000_000_000u64
            && admission["candidate_root_cap_bytes"] == 506_191_984_640u64
            && admission["guard_minimum_free_bytes"] == attempt.floor,
        "original candidate booking changed"
    );
    let before = show(n, attempt.unit)?;
    never_started(attempt, &before)?;
    ensure!(
        before["Job"] == ""
            && before["Restart"] == "no"
            && before["KillMode"] == "control-group"
            && before["Delegate"] == "no"
            && periodic::stable_command(text(&before, "ExecStart")?)?
                == periodic::stable_command(text(&original, "ExecStart")?)?,
        "failed265 execution contract changed"
    );
    let guard = show(n, attempt.guard)?;
    let timer = show(n, attempt.timer)?;
    stopped(attempt, &guard, attempt.guard)?;
    stopped(attempt, &timer, attempt.timer)?;
    empty_tokens(attempt)?;
    drained(attempt)?;
    let after = show(n, attempt.unit)?;
    let guard_after = show(n, attempt.guard)?;
    let timer_after = show(n, attempt.timer)?;
    ensure!(
        before == after && guard == guard_after && timer == timer_after,
        "failed265 changed across cancellation census"
    );
    empty_tokens(attempt)?;
    save_json(
        &n.root,
        attempt.receipt_name,
        &json!({
        "schema":"horizon265-exact-failed-pretoken-cancellation-v1",
        "unit":attempt.unit,"invocation_id":attempt.iid,"producer":after,
        "guard":guard_after,"timer":timer_after,
        "evidence":evidence.iter().map(|(name,(bound,_))| json!({"name":name,"binding":bound})).collect::<Vec<_>>(),
        "no_main_execution_history":true,"token_namespace_empty":true,
        "kernel_and_process_groups_drained":true,"original_first_guard_preserved":true,
        "former_candidate_cancelled":true,"former_candidate_memory_bytes":128_000_000_000u64,
        "former_candidate_growth_bytes":506_191_984_640u64,"preserved_inherited_floor_bytes":attempt.floor,
        "new_candidate_full_envelope_required":true,"archive_deleted":false,
        "accepted_replay_completed":false,"publication_authorized":false,"remote_mutations":false}),
    )?;
    Ok(attempt.floor)
}
pub(super) fn inherited_floors(
    n: &mut Native,
    review: &Value,
    rows: &[capacity::Reservation],
) -> Result<(u64, u64)> {
    Ok((
        validate(&V1, n, review, rows)?,
        validate(&V2, n, review, rows)?,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manager_parser_preserves_ordered_prestart_commands_and_rejects_scalar_duplicates() {
        let v =
            properties(b"Id=unit.service\nExecStartPre=sleep\nExecStartPre=token-test\n").unwrap();
        assert_eq!(v["ExecStartPre"], json!(["sleep", "token-test"]));
        assert!(properties(b"InvocationID=a\nInvocationID=b\n").is_err());
        assert_eq!(
            properties(b"After=a b\n").unwrap(),
            properties(b"After=b a\n").unwrap()
        );
        assert_ne!(
            properties(b"After=a b\n").unwrap(),
            properties(b"After=a c\n").unwrap()
        );
    }
    #[test]
    #[ignore = "root-only native failed-attempt custody qualification; preserves evidence"]
    fn native_failed_attempts_and_actual_delivery_custody() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = PathBuf::from(std::env::var("HORIZON265_CUSTODY_TEST_OUTPUT").unwrap());
        assert!(root.starts_with("/var/lib/jetstreamer"));
        trusted_parents(&root).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut n = Native {
            root,
            counter: 0,
            deadline: None,
        };
        let review = json!({(V1.review_flag):true,(V2.review_flag):true});
        assert_eq!(
            inherited_floors(&mut n, &review, &[]).unwrap(),
            (V1.floor, V2.floor)
        );
        delivery247::verify_inputs().unwrap();
    }
    #[test]
    fn exact_no_worker_failure_is_not_a_generic_terminal_release() {
        let v = json!({"Id":V2.unit,"InvocationID":V2.iid,"LoadState":"loaded",
            "ActiveState":"failed","SubState":"failed","Result":"signal",
            "MainPID":"0","ControlPID":"0","ExecMainPID":"0","ExecMainStartTimestampMonotonic":"0","ExecMainCode":"0",
            "ExecMainStatus":"0","NRestarts":"0",
            "ExecStart":"{ path=/node ; argv[]=/node ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"});
        never_started(&V2, &v).unwrap();
        for (k, x) in [
            ("InvocationID", "different"),
            ("ExecMainPID", "42"),
            ("ExecMainStartTimestampMonotonic", "42"),
            ("MainPID", "42"),
            ("NRestarts", "1"),
            ("Result", "success"),
            ("ActiveState", "inactive"),
            ("ExecMainCode", "1"),
        ] {
            let mut bad = v.clone();
            bad[k] = json!(x);
            assert!(never_started(&V2, &bad).is_err(), "{k}");
        }
    }
}
