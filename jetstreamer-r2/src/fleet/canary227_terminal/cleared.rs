//! A cleared systemd slot is accepted only with the original immutable launch,
//! successful result and complete, sealed PID1 history. Raw properties stay raw.
use super::*;
const POLICY: &str = "jetstreamer-canary227-cleared-success-v1";
const SUCCESS: &str = "7ad2d189f7e94e70a38c781354912448";
const EXTRA: &str = "ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic";

pub(super) fn recognized(p: &Value) -> bool {
    p["terminal_identity_policy"] == POLICY
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("227 cleared integer missing: {key}"))
}
fn clock(v: &Value, key: &str) -> Result<u64> {
    Ok(v[key]
        .as_str()
        .with_context(|| format!("227 cleared timestamp missing: {key}"))?
        .parse()?)
}
fn boot() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', ""))
}
fn observe() -> Result<Value> {
    let mut value = unit(c::UNIT)?;
    for (key, text) in properties(c::UNIT, EXTRA)? {
        value[&key] = json!(text);
    }
    Ok(value)
}
fn shape(value: &Value, launch: &Value) -> Result<()> {
    for (key, text) in [
        ("Id", c::UNIT),
        ("LoadState", "loaded"),
        ("Type", "exec"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("InvocationID", ""),
        ("ExecMainPID", "0"),
        ("ExecMainStartTimestampMonotonic", "0"),
        ("ExecMainExitTimestampMonotonic", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
    ] {
        ensure!(
            value[key].as_str() == Some(text),
            "227 cleared terminal differs: {key}"
        );
    }
    ensure!(
        c::same_command(&value["ExecStart"], &launch["expected_exec_start"]),
        "227 cleared unit command changed from its actual launch"
    );
    Ok(())
}
fn manager(row: &Value) -> bool {
    row["_PID"] == "1" && row["_UID"] == "0" && row["UNIT"] == c::UNIT
}
fn starts(row: &Value) -> bool {
    row["MESSAGE"].as_str().is_some_and(|s| {
        s.starts_with(&format!("Starting {} -", c::UNIT))
            || s.starts_with(&format!("Started {} -", c::UNIT))
    })
}
fn failed(row: &Value) -> bool {
    row["JOB_TYPE"] == "restart"
        || row.get("JOB_RESULT").is_some_and(|v| v != "done")
        || row.get("RESULT").is_some_and(|v| v != "success")
        || row.get("EXIT_STATUS").is_some_and(|v| v != "0")
        || row["MESSAGE"]
            .as_str()
            .is_some_and(|s| s.contains("Failed") || s.contains("restart job"))
}
/// All parent-unit manager history after the authenticated original start must
/// belong to that invocation. A later start or failed finish is never ignored.
fn history(rows: &[Value], launch: &Value, result: &Value, expected_boot: &str) -> Result<Value> {
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "227 cleared journal bounds"
    );
    let iid = launch["invocation_id"]
        .as_str()
        .context("227 original IID")?;
    let pid = number(launch, "main_pid")?;
    let child = number(result, "child_pid")?;
    let start = clock(&launch["actual_sandbox"], "ExecMainStartTimestampMonotonic")?;
    ensure!(
        private_prefix::iid(iid)
            && pid > 1
            && child > 1
            && start > 0
            && is_lower_hex(expected_boot, 32),
        "227 cleared origin identity is incomplete"
    );
    let mut starts_seen = BTreeSet::new();
    let mut completions = Vec::new();
    let mut producer = false;
    for row in rows {
        let time = clock(row, "__MONOTONIC_TIMESTAMP")?;
        if time.saturating_add(5_000_000) < start {
            continue;
        }
        if manager(row) {
            ensure!(
                row["_BOOT_ID"] == expected_boot && row["INVOCATION_ID"] == iid && !failed(row),
                "227 cleared manager history has a foreign invocation, boot or failure"
            );
            if starts(row) {
                ensure!(
                    time.abs_diff(start) <= 5_000_000,
                    "227 cleared journal contains a newer start"
                );
                let id = row["MESSAGE_ID"]
                    .as_str()
                    .context("227 manager start message ID")?;
                ensure!(
                    (id == "7d4958e842da4a758f6c1cdc7b36dcc5"
                        || id == "39f53479d3a045ac8e11786248231fbf")
                        && starts_seen.insert(id.to_owned()),
                    "227 cleared start is missing identity or duplicated"
                );
            }
            if row["MESSAGE_ID"] == SUCCESS
                && row["MESSAGE"] == format!("{}: Deactivated successfully.", c::UNIT)
            {
                ensure!(time >= start, "227 completion precedes its actual start");
                completions.push(row.clone());
            }
        } else if row["_SYSTEMD_UNIT"] == c::UNIT {
            ensure!(
                row["_BOOT_ID"] == expected_boot
                    && row["_SYSTEMD_INVOCATION_ID"] == iid
                    && row["_UID"] == "1000",
                "227 cleared producer journal has a foreign owner"
            );
            let actual = clock(row, "_PID")?;
            ensure!(
                actual == pid || actual == child,
                "227 cleared producer journal has an unbound PID"
            );
            producer = true;
        } else {
            bail!("227 cleared sealed journal contains an unrelated unit");
        }
    }
    ensure!(
        !starts_seen.is_empty() && producer && completions.len() == 1,
        "227 cleared history lacks a unique original start, producer and PID1 success"
    );
    Ok(completions.remove(0))
}
fn journal_bytes(binding: &BoundFile) -> Result<Vec<u8>> {
    ensure!(
        binding
            .path
            .file_name()
            .is_some_and(|n| n == "journal.json")
            && binding.path.parent().and_then(Path::parent)
                == Some(Path::new("/var/lib/jetstreamer"))
            && binding
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-canary227-terminal-raw-")),
        "227 cleared journal namespace differs"
    );
    let meta = fs::symlink_metadata(&binding.path)?;
    ensure!(
        binding.path.canonicalize()? == binding.path
            && meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o222 == 0,
        "227 cleared journal is not sealed"
    );
    let bytes = read_stable_bounded(&binding.path, 16 << 20, "227 cleared terminal journal")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == binding.sha256,
        "227 cleared journal hash differs"
    );
    Ok(bytes)
}
fn rows(bytes: &[u8]) -> Result<Vec<Value>> {
    Ok(serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
pub(super) fn validate_saved(p: &Value, launch: &Value, iid: &str, pid: u64) -> Result<()> {
    ensure!(
        recognized(p)
            && launch["invocation_id"] == iid
            && launch["main_pid"] == pid
            && p["runner_result_available"] == true
            && p["result"]["success"] == true
            && p["result"]["target_reached"] == true,
        "227 cleared policy requires original successful comparison"
    );
    shape(&p["actual_terminal"], launch)?;
    ensure!(
        p["actual_terminal"] == p["actual_terminal_after"],
        "227 cleared saved terminal bracket changed"
    );
    let binding: BoundFile = serde_json::from_value(p["cleared_journal"].clone())?;
    let launch_binding: BoundFile = serde_json::from_value(p["launch"].clone())?;
    let d = claim(&launch_binding, launch)?;
    let result_binding: BoundFile = serde_json::from_value(p["result_binding"].clone())?;
    ensure!(
        result_binding.path == Path::new(c::ROOT).join("receipts/resource.json")
            && runner_result(&Some(result_binding), &d, launch)? == p["result"],
        "227 cleared original immutable runner result differs"
    );
    let bytes = journal_bytes(&binding)?;
    let expected_boot = p["terminal_boot_id"]
        .as_str()
        .context("227 terminal boot")?;
    let completion = history(&rows(&bytes)?, launch, &p["result"], expected_boot)?;
    ensure!(
        completion == p["manager_completion"] && p["journal_sha256"] == binding.sha256,
        "227 cleared saved manager completion differs"
    );
    Ok(())
}
fn tail(rows: &[Value], completion: &Value, iid: &str, expected_boot: &str) -> Result<()> {
    let stop = clock(completion, "__MONOTONIC_TIMESTAMP")?;
    ensure!(
        rows.iter().filter(|r| *r == completion).count() == 1,
        "227 latest journal no longer binds exact completion"
    );
    for row in rows.iter().filter(|r| manager(r)) {
        if clock(row, "__MONOTONIC_TIMESTAMP")? >= stop {
            ensure!(
                row["_BOOT_ID"] == expected_boot
                    && row["INVOCATION_ID"] == iid
                    && !starts(row)
                    && !failed(row),
                "227 current manager history has a newer start, restart or failure"
            );
            if row["MESSAGE_ID"] == SUCCESS {
                ensure!(
                    row == completion,
                    "227 current manager history has another completion"
                );
            }
        }
    }
    Ok(())
}
pub(super) fn current(p: &Value, supplied: &Value) -> Result<()> {
    let launch = native227_v1625::immutable_json(&serde_json::from_value(p["launch"].clone())?)?;
    ensure!(
        boot()? == p["terminal_boot_id"],
        "227 cleared terminal crossed a host boot"
    );
    let base = unit(c::UNIT)?;
    ensure!(base == *supplied, "227 supplied idle census changed");
    let before = observe()?;
    shape(&before, &launch)?;
    ensure!(
        before == p["actual_terminal"],
        "227 cleared current properties differ from terminal proof"
    );
    inactive_status::no_pending_owner_trigger(c::UNIT, false)?;
    let (journal, _) = super::journal(c::UNIT)?;
    tail(
        &journal,
        &p["manager_completion"],
        p["invocation_id"].as_str().context("227 IID")?,
        p["terminal_boot_id"].as_str().context("227 boot")?,
    )?;
    ensure!(
        observe()? == before && unit(c::UNIT)? == base,
        "227 cleared idle owner changed during revalidation"
    );
    Ok(())
}
pub(super) fn capture(
    s: &Spec,
    spec: &BoundFile,
    self_sha: &str,
    launch: &Value,
    d: &DiagnosticClaim,
    pid: u64,
) -> Result<()> {
    let binding = s
        .journal
        .as_ref()
        .context("227 cleared terminal requires a sealed original journal")?;
    let result = runner_result(&s.result, d, launch)?;
    ensure!(
        s.result
            .as_ref()
            .is_some_and(|b| b.path == Path::new(c::ROOT).join("receipts/resource.json"))
            && result["success"] == true
            && result["target_reached"] == true,
        "227 cleared terminal cannot infer success from empty manager fields"
    );
    let before = observe()?;
    shape(&before, launch)?;
    let bytes = journal_bytes(binding)?;
    let expected_boot = boot()?;
    let completion = history(&rows(&bytes)?, launch, &result, &expected_boot)?;
    let after = observe()?;
    ensure!(after == before, "227 cleared capture owner changed");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let p = json!({"schema":SCHEMA,"terminal_identity_policy":POLICY,"epoch":227,"unit":c::UNIT,
        "invocation_id":d.invocation_id,"main_pid":pid,"launch":private157::binding(&s.launch),
        "result_binding":s.result.as_ref().map(private157::binding),"runner_result_available":true,"result":result,
        "actual_terminal":before,"actual_terminal_after":after,"terminal_boot_id":expected_boot,
        "cleared_journal":private157::binding(binding),"manager_completion":completion,"journal_sha256":binding.sha256,
        "original_failed_invocation_id":c::ORIGINAL_IID,"preserve_original_failed227_history":true,
        "repair_gate_state":"failed-needs-repair","resource_samples_taken":0,"release_credit_bytes":0,
        "semantic_success_qualified":false,"full_epoch_qualified":false,"runtime_promotion_authorized":false,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
        "recorded_unix_seconds":now,"sampled_at_utc":publication203::utc(now)?,"spec_sha256":spec.sha256,"self_sha256":self_sha});
    validate(&p)?;
    current(&p, &unit(c::UNIT)?)?;
    ensure!(
        runner_result(&s.result, d, launch)? == result,
        "227 cleared result changed during capture"
    );
    private157::immutable_receipt(&s.output, &p)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Vec<Value>, String) {
        let iid = "a".repeat(32);
        let boot = "b".repeat(32);
        let launch = json!({"invocation_id":iid,"main_pid":40,
            "actual_sandbox":{"ExecMainStartTimestampMonotonic":"10000000"},
            "expected_exec_start":"{ path=/sealed/runner ; argv[]=/sealed/runner /sealed/plan ; ignore_errors=no }"});
        let result = json!({"child_pid":41});
        let start = json!({"_PID":"1","_UID":"0","UNIT":c::UNIT,"INVOCATION_ID":iid,
            "_BOOT_ID":boot,"__MONOTONIC_TIMESTAMP":"9999000",
            "MESSAGE_ID":"7d4958e842da4a758f6c1cdc7b36dcc5",
            "MESSAGE":format!("Starting {} - comparison...",c::UNIT)});
        let producer = json!({"_PID":"40","_UID":"1000","_SYSTEMD_UNIT":c::UNIT,
            "_SYSTEMD_INVOCATION_ID":iid,"_BOOT_ID":boot,"__MONOTONIC_TIMESTAMP":"15000000"});
        let done = json!({"_PID":"1","_UID":"0","UNIT":c::UNIT,"INVOCATION_ID":iid,
            "_BOOT_ID":boot,"__MONOTONIC_TIMESTAMP":"20000000","MESSAGE_ID":SUCCESS,
            "MESSAGE":format!("{}: Deactivated successfully.",c::UNIT)});
        (launch, result, vec![start, producer, done], boot)
    }
    #[test]
    fn original_success_is_proven_without_filling_cleared_manager_fields() {
        let (launch, result, rows, boot) = fixture();
        let completion = history(&rows, &launch, &result, &boot).unwrap();
        let raw = json!({"Id":c::UNIT,"LoadState":"loaded","Type":"exec","ActiveState":"inactive",
            "SubState":"dead","MainPID":"0","NRestarts":"0","InvocationID":"",
            "ExecMainPID":"0","ExecMainStartTimestampMonotonic":"0","ExecMainExitTimestampMonotonic":"0",
            "Result":"success","ExecMainStatus":"0","ExecStart":launch["expected_exec_start"]});
        let before = raw.clone();
        shape(&raw, &launch).unwrap();
        assert_eq!(raw, before);
        assert!(terminal(&raw, &"a".repeat(32), 40).is_err());
        tail(&rows, &completion, &"a".repeat(32), &boot).unwrap();
        for (key, value) in [
            ("LoadState", "not-found"),
            ("MainPID", "40"),
            ("NRestarts", "1"),
            ("InvocationID", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("ExecMainPID", "40"),
            ("ExecMainStartTimestampMonotonic", "10000000"),
            ("ActiveState", "active"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("Type", "oneshot"),
        ] {
            let mut changed = raw.clone();
            changed[key] = json!(value);
            assert!(shape(&changed, &launch).is_err(), "{key}");
        }
        for key in ["MainPID", "ExecMainPID", "ExecMainStartTimestampMonotonic"] {
            let mut changed = raw.clone();
            changed[key] = json!(0);
            assert!(shape(&changed, &launch).is_err(), "numeric {key}");
        }
    }
    #[test]
    fn missing_ambiguous_foreign_or_newer_manager_history_is_rejected() {
        let (launch, result, rows, boot) = fixture();
        for index in 0..rows.len() {
            let mut missing = rows.clone();
            missing.remove(index);
            assert!(
                history(&missing, &launch, &result, &boot).is_err(),
                "missing {index}"
            );
        }
        for index in [0, 2] {
            let mut duplicate = rows.clone();
            duplicate.push(rows[index].clone());
            assert!(history(&duplicate, &launch, &result, &boot).is_err());
        }
        for (index, key, value) in [
            (0, "INVOCATION_ID", json!("c".repeat(32))),
            (2, "_BOOT_ID", json!("c".repeat(32))),
            (1, "_PID", json!("42")),
            (1, "_SYSTEMD_INVOCATION_ID", json!("c".repeat(32))),
            (0, "__MONOTONIC_TIMESTAMP", json!("21000000")),
        ] {
            let mut changed = rows.clone();
            changed[index][key] = value;
            assert!(
                history(&changed, &launch, &result, &boot).is_err(),
                "{index} {key}"
            );
        }
        let completion = history(&rows, &launch, &result, &boot).unwrap();
        for event in [
            json!({"_PID":"1","_UID":"0","UNIT":c::UNIT,"INVOCATION_ID":"c".repeat(32),
                "_BOOT_ID":boot,"__MONOTONIC_TIMESTAMP":"21000000","MESSAGE":format!("Starting {} - replacement",c::UNIT)}),
            json!({"_PID":"1","_UID":"0","UNIT":c::UNIT,"INVOCATION_ID":"a".repeat(32),
                "_BOOT_ID":boot,"__MONOTONIC_TIMESTAMP":"21000000","RESULT":"exit-code","MESSAGE":"failed"}),
        ] {
            let mut changed = rows.clone();
            changed.push(event);
            assert!(history(&changed, &launch, &result, &boot).is_err());
            assert!(tail(&changed, &completion, &"a".repeat(32), &boot).is_err());
        }
        let mut duplicate = rows.clone();
        let mut newer = completion.clone();
        newer["__MONOTONIC_TIMESTAMP"] = json!("21000000");
        duplicate.push(newer);
        assert!(tail(&duplicate, &completion, &"a".repeat(32), &boot).is_err());
    }
    #[test]
    fn bound_child_output_does_not_allow_foreign_producer_or_missing_latest_completion() {
        let (launch, result, mut rows, boot) = fixture();
        rows[1]["_PID"] = json!("41");
        let completion = history(&rows, &launch, &result, &boot).unwrap();
        assert!(tail(&rows[..2], &completion, &"a".repeat(32), &boot).is_err());
        let mut changed = result.clone();
        changed["child_pid"] = json!(42);
        assert!(history(&rows, &launch, &changed, &boot).is_err());
        let mut changed = launch.clone();
        changed["actual_sandbox"]["ExecMainStartTimestampMonotonic"] = json!("0");
        assert!(history(&rows, &changed, &result, &boot).is_err());
    }
}
