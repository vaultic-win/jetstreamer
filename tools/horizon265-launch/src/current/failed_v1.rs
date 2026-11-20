//! Exact failed pretoken attempt: no successful replay or generic drain is invented.
use super::*;
const OLD_UNIT: &str = "horizon-qualify-265-replacement-20261119-v1.service";
const OLD_GUARD: &str = "horizon-265-replacement-20261119-protective-v1.service";
const OLD_TIMER: &str = "horizon-265-replacement-20261119-protective-v1.timer";
const OLD_IID: &str = "0a59d8b510ee46549e888cebbe38597f";
const OLD_FIRST_GUARD: &str = "429732d4e2644dffb02c25f68891e387";
const OLD_TOKENS: &str = "/var/lib/jetstreamer/horizon265-replacement-20261119-tokens-v1";
const OLD_LAUNCH: &str = "/var/lib/jetstreamer/horizon265-replacement-20261119-state-v1/launch-v1";
const OLD_FLOOR: u64 = 3_722_733_519_128;
// Exact recovered evidence is retained across the failed attempt.
const PINS: &[(&str, &str, &str)] = &[
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
];
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
fn never_started(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == OLD_UNIT
            && v["InvocationID"] == OLD_IID
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "failed"
            && v["SubState"] == "failed"
            && v["Result"] == "signal"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["ExecMainPID"] == "0"
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
fn empty_tokens() -> Result<()> {
    let p = Path::new(OLD_TOKENS);
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
    absent(&Path::new(OLD_LAUNCH).join("guarded-startup-handoff.json"))?;
    Ok(())
}
fn stopped(v: &Value, unit: &str) -> Result<()> {
    ensure!(
        v["Id"] == unit
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["Job"] == "",
        "failed265 control not inactive"
    );
    if unit == OLD_GUARD {
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
fn drained() -> Result<()> {
    for unit in [OLD_UNIT, OLD_GUARD] {
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
        for unit in [OLD_UNIT, OLD_GUARD] {
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
    let props = format!("{},ExecMainPID,ExecStartPre", live::PROPS);
    properties(&n.run(
        "/usr/bin/systemctl",
        &["show", unit, "--all", "--no-pager", "--property", &props],
    )?)
}
/// Explicit cancellation of the failed candidate, not release of an accepted replay.
/// Returns its inherited floor; the new candidate still receives the full128GB/506GB.
pub(super) fn validate(
    n: &mut Native,
    review: &Value,
    rows: &[capacity::Reservation],
) -> Result<u64> {
    ensure!(
        review["failed_pretoken_v1_cancelled_before_v2_admission"] == true,
        "Main has not accepted failed265 candidate cancellation"
    );
    ensure!(
        !rows.iter().any(|r| r.unit == OLD_UNIT),
        "failed265 cancellation cannot silently rewrite an existing retained reservation"
    );
    let mut evidence = BTreeMap::new();
    for &(name, path, sha) in PINS {
        let reference = Bound::new(path, sha);
        let bytes = reference.bytes(false)?;
        evidence.insert(name, (reference, bytes));
    }
    let original = properties(&evidence["original_terminal"].1)?;
    never_started(&original)?;
    let failure: Value = serde_json::from_slice(&evidence["failure"].1)?;
    ensure!(
        failure["original_attempt_not_retried"] == true
            && failure["automatic_retry_authorized"] == false
            && failure["error"] == "retained guard not at accepted clean completion",
        "original pretoken failure changed"
    );
    let first: Value = serde_json::from_slice(&evidence["first_guard"].1)?;
    ensure!(
        first["producer_invocation_id"] == OLD_IID
            && first["guard_invocation_id"] == OLD_FIRST_GUARD
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
            && admission["guard_minimum_free_bytes"] == OLD_FLOOR,
        "original candidate booking changed"
    );
    let before = show(n, OLD_UNIT)?;
    never_started(&before)?;
    ensure!(
        before["Job"] == ""
            && before["Restart"] == "no"
            && before["KillMode"] == "control-group"
            && before["Delegate"] == "no"
            && periodic::stable_command(text(&before, "ExecStart")?)?
                == periodic::stable_command(text(&original, "ExecStart")?)?,
        "failed265 execution contract changed"
    );
    let guard = show(n, OLD_GUARD)?;
    let timer = show(n, OLD_TIMER)?;
    stopped(&guard, OLD_GUARD)?;
    stopped(&timer, OLD_TIMER)?;
    empty_tokens()?;
    drained()?;
    let after = show(n, OLD_UNIT)?;
    let guard_after = show(n, OLD_GUARD)?;
    let timer_after = show(n, OLD_TIMER)?;
    ensure!(
        before == after && guard == guard_after && timer == timer_after,
        "failed265 changed across cancellation census"
    );
    empty_tokens()?;
    save_json(
        &n.root,
        "failed-v1-candidate-cancellation.json",
        &json!({
        "schema":"horizon265-exact-failed-pretoken-cancellation-v1",
        "unit":OLD_UNIT,"invocation_id":OLD_IID,"producer":after,
        "guard":guard_after,"timer":timer_after,
        "evidence":evidence.iter().map(|(name,(bound,_))| json!({"name":name,"binding":bound})).collect::<Vec<_>>(),
        "no_main_execution_history":true,"token_namespace_empty":true,
        "kernel_and_process_groups_drained":true,"original_first_guard_preserved":true,
        "former_candidate_cancelled":true,"former_candidate_memory_bytes":128_000_000_000u64,
        "former_candidate_growth_bytes":506_191_984_640u64,"preserved_inherited_floor_bytes":OLD_FLOOR,
        "new_candidate_full_envelope_required":true,"archive_deleted":false,
        "accepted_replay_completed":false,"publication_authorized":false,"remote_mutations":false}),
    )?;
    Ok(OLD_FLOOR)
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
    fn native_failed_attempt_and_actual_delivery_custody() {
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
        let review = json!({"failed_pretoken_v1_cancelled_before_v2_admission":true});
        assert_eq!(validate(&mut n, &review, &[]).unwrap(), OLD_FLOOR);
        delivery247::verify_inputs().unwrap();
    }
    #[test]
    fn exact_no_worker_failure_is_not_a_generic_terminal_release() {
        let v = json!({"Id":OLD_UNIT,"InvocationID":OLD_IID,"LoadState":"loaded",
            "ActiveState":"failed","SubState":"failed","Result":"signal",
            "MainPID":"0","ControlPID":"0","ExecMainPID":"0","ExecMainCode":"0",
            "ExecMainStatus":"0","NRestarts":"0",
            "ExecStart":"{ path=/node ; argv[]=/node ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"});
        never_started(&v).unwrap();
        for (k, x) in [
            ("InvocationID", "different"),
            ("ExecMainPID", "42"),
            ("MainPID", "42"),
            ("NRestarts", "1"),
            ("Result", "success"),
            ("ActiveState", "inactive"),
            ("ExecMainCode", "1"),
        ] {
            let mut bad = v.clone();
            bad[k] = json!(x);
            assert!(never_started(&bad).is_err(), "{k}");
        }
    }
}
