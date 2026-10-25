//! One hash-closed no-worker invocation whose real systemd counters were collected.
//! Historical identity is separate evidence; current zeros are never rewritten.
use super::*;
const UNIT: &str =
    "horizon-qualify-227-v1625-bounded-resource-d01adb19-selection-v2-capability-v1.service";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-d01adb19-selection-v2-capability-v1";
const RECEIPT: &str = "/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-d01adb19-selection-v2-capability-v1/receipts/capability.json";
const RECEIPT_SHA: &str = "a03d09115980dd7dac9859b7ca7f4ead616fc595759dbee44f527205065d3fae";
const PLAN: &str = "/var/lib/jetstreamer/horizon-227-v1625-canary-capability-plan-selection-v2/capability-plan.json";
const PLAN_SHA: &str = "737c3f6fd0a36004b8e2ca4e569c635aa3cbb2d33383be1ab7cb565d045a4169";
const UNIT_SHA: &str = "6daba0a3dc5fedc5728bf4621eb82e21e5df5833687b7188a13d1729c74e361c";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-227-selection-capability-result-v2";
const INITIAL_SHA: &str = "ebd5734d29dcce426908d05f41172b9e07b61976acc3abe692b263bd42bff8f4";
const TERMINAL_SHA: &str = "714210895fb9f00a02f71fcc5029a934613f54b49a6ea4963613ed71169364c6";
const JOURNAL_SHA: &str = "830987be0aeec7ffee064fd8348212322b9d9da319071e199316b4e5a1883f24";
const IID: &str = "3bb301ecef9d455e97f8b353ceba7e25";
const BOOT: &str = "2e60f44d8e484d7e91fcc2dc724d2ae6";
const MACHINE: &str = "662c3da6039944779789c3fe1c3d7401";
const PID: u64 = 580417;
const START: u64 = 1_781_970_577_079;

pub(super) fn applies(b: &BoundFile) -> bool {
    b.path == Path::new(RECEIPT)
}
fn binding(name: &str, sha: &str) -> BoundFile {
    BoundFile {
        path: Path::new(PACKAGE).join(name),
        sha256: sha.into(),
    }
}
fn sealed_bytes(b: &BoundFile) -> Result<Vec<u8>> {
    ensure!(
        fs::symlink_metadata(&b.path)?.len() <= 65536,
        "227 collected evidence oversized"
    );
    native209_admission::sealed_file(&b.path, &b.sha256, None)?;
    let bytes = fs::read(&b.path)?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "227 collected evidence changed"
    );
    Ok(bytes)
}
fn parse_properties(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let (key, value) = line
            .split_once('=')
            .context("227 collected property syntax")?;
        ensure!(
            !key.is_empty() && result.insert(key.into(), value.into()).is_none(),
            "227 collected duplicate property"
        );
    }
    Ok(result)
}
fn parse_journal(bytes: &[u8]) -> Result<Vec<Value>> {
    ensure!(bytes.len() <= 16 << 20, "227 collected journal oversized");
    let rows = bytes
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    ensure!(
        !rows.is_empty() && rows.len() <= 2048,
        "227 collected journal empty/oversized"
    );
    Ok(rows)
}
fn exact_scope(b: &BoundFile, v: &Value, plan: &BoundFile, unit: &BoundFile) -> Result<()> {
    ensure!(
        applies(b)
            && b.sha256 == RECEIPT_SHA
            && plan.path == Path::new(PLAN)
            && plan.sha256 == PLAN_SHA
            && unit.path == Path::new(&format!("/etc/systemd/system/{UNIT}"))
            && unit.sha256 == UNIT_SHA
            && v["invocation_id"] == IID
            && v["bindings"]["self_sha256"] == c::RUNNER_SHA
            && v["bindings"]["plan_path"] == PLAN
            && v["bindings"]["plan_sha256"] == PLAN_SHA
            && v["node_sha256"] == c::NODE_SHA
            && v["worker_sha256"] == c::WORKER_SHA
            && v["worker_started"] == false
            && v["entry_replay"] == false
            && v["parent_planning_report"]["worker_spawned"] == false
            && v["parent_planning_report"]["archive_created"] == false,
        "227 collected adapter is closed to the exact genuine selection-v2 no-worker receipt"
    );
    Ok(())
}
fn historical(
    initial: &BTreeMap<String, String>,
    terminal: &BTreeMap<String, String>,
    rows: &[Value],
) -> Result<()> {
    require(
        initial,
        &[
            ("ActiveState", "activating"),
            ("SubState", "start"),
            ("InvocationID", IID),
            ("MainPID", "580417"),
            ("ExecMainPID", "580417"),
            ("ExecMainStartTimestampMonotonic", "1781970577079"),
            ("NRestarts", "0"),
        ],
    )?;
    ensure!(
        initial.len() == 7,
        "227 collected initial identity has extra fields"
    );
    require(
        terminal,
        &[
            ("InvocationID", ""),
            ("ExecMainPID", "0"),
            ("ExecMainStartTimestampMonotonic", "0"),
            ("ExecMainExitTimestampMonotonic", "0"),
            ("ExecMainCode", "0"),
            ("ExecMainStatus", "0"),
            ("Result", "success"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("ReadWritePaths", ROOT),
            ("NRestarts", "0"),
        ],
    )?;
    ensure!(
        rows.len() == 4,
        "227 collected journal is not the complete four-row actual invocation"
    );
    let messages = [
        format!("Starting {UNIT} - Private epoch 227 v1.6.25 real planning capability..."),
        format!("{UNIT}: Deactivated successfully."),
        format!("Finished {UNIT} - Private epoch 227 v1.6.25 real planning capability."),
        format!(
            "{UNIT}: Consumed 7.473s CPU time over 7.498s wall clock time, 118.2M memory peak."
        ),
    ];
    let mut last_mono = START;
    let mut last_seq = 0;
    for (row, message) in rows.iter().zip(messages) {
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == UNIT
                && row["INVOCATION_ID"] == IID
                && row["_BOOT_ID"] == BOOT
                && row["_MACHINE_ID"] == MACHINE
                && row["MESSAGE"] == message,
            "227 collected manager identity/completion differs"
        );
        let mono = row["__MONOTONIC_TIMESTAMP"]
            .as_str()
            .context("227 collected manager clock")?
            .parse::<u64>()?;
        let seq = row["__SEQNUM"]
            .as_str()
            .context("227 collected journal sequence")?
            .parse::<u64>()?;
        ensure!(
            mono > last_mono && seq > last_seq,
            "227 collected journal clock/sequence not ordered"
        );
        last_mono = mono;
        last_seq = seq;
    }
    ensure!(
        rows[0]["JOB_TYPE"] == "start"
            && rows[2]["JOB_TYPE"] == "start"
            && rows[2]["JOB_RESULT"] == "done"
            && rows[0]["JOB_ID"] == "5977501"
            && rows[2]["JOB_ID"] == "5977501",
        "227 collected start/completion jobs differ"
    );
    Ok(())
}
fn current_matches(
    current: &BTreeMap<String, String>,
    terminal: &BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        terminal
            .iter()
            .all(|(key, value)| current.get(key) == Some(value)),
        "227 actual collected terminal/sandbox differs from immutable evidence"
    );
    require(
        current,
        &[
            ("Id", UNIT),
            ("LoadState", "loaded"),
            ("MainPID", "0"),
            ("ControlGroup", ""),
        ],
    )?;
    ensure!(
        current.len() == terminal.len() + 4,
        "227 collected current properties missing/extra"
    );
    Ok(())
}
fn current_journal() -> Result<(Vec<Value>, String)> {
    // Deliberately no --lines/tail/since/IID filter: later/conflicting invocations
    // must be visible. Equality with the sealed rows also rejects lost history.
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            UNIT,
            "--boot",
            BOOT,
            "--output=json",
            "--all",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        out.status.success(),
        "227 complete collected unit journal unavailable"
    );
    let rows = parse_journal(&out.stdout)?;
    Ok((rows, hex_lower(&Sha256::digest(&out.stdout))))
}
pub(super) fn validate(
    b: &BoundFile,
    v: &Value,
    plan: &BoundFile,
    unit: &BoundFile,
) -> Result<Value> {
    exact_scope(b, v, plan, unit)?;
    // Hash executable metadata only; never snapshot/archive/Bank bodies.
    for (path, sha) in [
        (c::RUNNER, c::RUNNER_SHA),
        (c::NODE, c::NODE_SHA),
        (c::WORKER, c::WORKER_SHA),
    ] {
        native209_admission::sealed_file(Path::new(path), sha, None)?;
    }
    let initial_binding = binding("initial-properties.txt", INITIAL_SHA);
    let terminal_binding = binding("terminal-properties.txt", TERMINAL_SHA);
    let journal_binding = binding("journal.jsonl", JOURNAL_SHA);
    let initial = parse_properties(&sealed_bytes(&initial_binding)?)?;
    let terminal = parse_properties(&sealed_bytes(&terminal_binding)?)?;
    let rows = parse_journal(&sealed_bytes(&journal_binding)?)?;
    historical(&initial, &terminal, &rows)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let machine = fs::read_to_string("/etc/machine-id")?;
    ensure!(
        boot == BOOT && machine.trim() == MACHINE,
        "227 collected capability boot/machine changed"
    );
    let fields = terminal
        .keys()
        .map(String::as_str)
        .chain(["Id", "LoadState", "MainPID", "ControlGroup"])
        .collect::<Vec<_>>()
        .join(",");
    let before = properties(UNIT, &fields)?;
    current_matches(&before, &terminal)?;
    let (actual_rows, sha) = current_journal()?;
    ensure!(
        actual_rows == rows,
        "227 complete current journal has missing/extra/later/conflicting history"
    );
    ensure!(
        properties(UNIT, &fields)? == before,
        "227 collected current identity changed during validation"
    );
    let (after_rows, after_sha) = current_journal()?;
    ensure!(
        after_rows == rows && properties(UNIT, &fields)? == before && bound_json(b)? == *v,
        "227 collected capability/journal changed during validation"
    );
    // Recheck the installed command/sandbox hash after all manager reads.
    native209_admission::sealed_file(&unit.path, UNIT_SHA, None)?;
    Ok(
        json!({"plan":private157::binding(plan),"unit_file":private157::binding(unit),
        "terminal_identity_profile":"exact-selection-v2-collected-no-worker-v1",
        "actual_terminal_properties":before,"historical_initial_properties":initial,
        "historical_initial_binding":private157::binding(&initial_binding),
        "historical_terminal_binding":private157::binding(&terminal_binding),
        "historical_journal_binding":private157::binding(&journal_binding),
        "historical_executed_pid":PID,"historical_start_monotonic_usec":START,
        "manager_completion":rows[1],"journal_sha256":sha,"journal_after_sha256":after_sha,
        "current_collected_counters_preserved":true,"resource_observation_performed":false}),
    )
}
#[cfg(test)]
mod tests;
