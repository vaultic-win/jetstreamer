//! Proof capture from actual new harness output and terminal manager evidence.
//! This role never launches a harness or promotes an old cold-input proof.
use super::*;
const TEST: &str =
    "runtime::tests::native_epoch223_cold_input_matches_canonical_accounts_commitment";
const SOURCE: &str = "551728fda72afd36ce6f8652ddb0020ec249e860";
const QA: &str = "3d5ea04ae0658070be51a8b410e2d6af8e0305bade8b7df455957e9db77a2f0f";
const MARKER: &str = "epoch223-v1620-native-input slot=96335538 bank_hash=8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F accounts_hash=Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE last_blockhash=9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa capitalization=503889539326183230 transaction_count=27822879094 tick_height=6165474496 next_write_version=105933183112 replay_entries=0 bootstrap_writes=0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    issuer_unit: String,
    launch: BoundFile,
    result: BoundFile,
    journal: BoundFile,
    origin_clock: BoundFile,
    supervisor_qualification: BoundFile,
    source_qa: BoundFile,
    provenance_output: PathBuf,
    proof_output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    schema: String,
    supervisor: Actor,
    status_task: BoundFile,
    harness: BoundFile,
    harness_pid: u32,
    harness_start_ticks: u64,
    harness_argv: Vec<String>,
    snapshot: BoundFile,
    genesis: BoundFile,
    origin_clock: BoundFile,
    original_start_unix_millis: u64,
    source_commit: String,
    worker_sha256: String,
    source_qa_sha256: String,
    scratch_root: PathBuf,
    actual_child_identity_captured: bool,
    native_input_only: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    schema: String,
    launch: BoundFile,
    harness_stdout: BoundFile,
    harness_sha256: String,
    harness_pid: u32,
    harness_start_ticks: u64,
    harness_exit_code: i32,
    harness_reaped: bool,
    success: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
struct Tuple {
    slot: u64,
    bank: String,
    accounts: String,
    last: String,
    capitalization: u64,
    transactions: u64,
    tick: u64,
    write: u64,
    replay: u64,
    bootstrap_writes: u64,
    passed: u64,
    ignored: u64,
}
fn observed_tuple(marker: &str, passed: u64, ignored: u64) -> Result<Tuple> {
    let mut fields = BTreeMap::new();
    for token in marker.split_whitespace().skip(1) {
        let (key, value) = token.split_once('=').context("223 native tuple token")?;
        ensure!(
            fields.insert(key, value).is_none(),
            "223 duplicate actual tuple key"
        );
    }
    let mut take =
        |key| -> Result<String> { Ok(fields.remove(key).context("223 native tuple key")?.into()) };
    let tuple = Tuple {
        slot: take("slot")?.parse()?,
        bank: take("bank_hash")?,
        accounts: take("accounts_hash")?,
        last: take("last_blockhash")?,
        capitalization: take("capitalization")?.parse()?,
        transactions: take("transaction_count")?.parse()?,
        tick: take("tick_height")?.parse()?,
        write: take("next_write_version")?.parse()?,
        replay: take("replay_entries")?.parse()?,
        bootstrap_writes: take("bootstrap_writes")?.parse()?,
        passed,
        ignored,
    };
    ensure!(fields.is_empty(), "223 unexpected actual tuple key");
    Ok(tuple)
}
fn output_valid(bytes: &[u8]) -> Result<Tuple> {
    let text = std::str::from_utf8(bytes)?;
    let mut marker = None;
    let mut actual_marker = String::new();
    let mut success = None;
    let (mut passed, mut ignored) = (0u64, 0u64);
    for (line_number, line) in text.lines().enumerate() {
        if let Some((_, tail)) = line.split_once("epoch223-v1620-native-input ") {
            ensure!(
                marker.replace(line_number).is_none()
                    && format!("epoch223-v1620-native-input {tail}") == MARKER,
                "223 new harness canonical tuple differs or repeats"
            );
            actual_marker = format!("epoch223-v1620-native-input {tail}");
        }
        if line.starts_with("test result:") {
            ensure!(
                success.replace(line_number).is_none()
                    && line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"),
                "223 actual test did not pass exactly once without ignored tests"
            );
            passed = line
                .split_whitespace()
                .nth(3)
                .context("223 actual passed count")?
                .parse()?;
            ignored = line
                .split_whitespace()
                .nth(7)
                .context("223 actual ignored count")?
                .parse()?;
        }
    }
    ensure!(
        marker.zip(success).is_some_and(|(m, s)| m < s),
        "223 canonical marker must precede actual one-test success"
    );
    observed_tuple(&actual_marker, passed, ignored)
}
fn journal_valid(bytes: &[u8], actor: &Actor) -> Result<()> {
    let (mut start, mut terminal) = (None, None);
    for (index, row) in serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .enumerate()
    {
        let row = row?;
        if row["_PID"] != "1"
            || row["UNIT"] != actor.unit
            || row["INVOCATION_ID"] != actor.invocation_id
        {
            continue;
        }
        let message = row["MESSAGE"]
            .as_str()
            .context("223 native PID1 journal message")?;
        if message.starts_with(&format!("Started {} - ", actor.unit)) {
            ensure!(
                start.replace(index).is_none(),
                "223 duplicate native PID1 start"
            );
        }
        if message == format!("{}: Deactivated successfully.", actor.unit) {
            ensure!(
                terminal.replace(index).is_none(),
                "223 duplicate native PID1 success"
            );
        }
        ensure!(
            !message.contains("Failed")
                && !message.contains("Main process exited")
                && !message.contains("Scheduled restart job"),
            "223 native manager failure/restart observed"
        );
    }
    ensure!(
        start.zip(terminal).is_some_and(|(s, t)| s < t),
        "223 actual native PID1 clean completion missing"
    );
    Ok(())
}
pub(super) fn run(binding: &BoundFile, executable: &BoundFile) -> Result<()> {
    let spec: Spec = read_bound(binding)?;
    ensure!(
        spec.schema == "jetstreamer-epoch223-demotion-native-proof-capture-spec-v1",
        "223 native capture spec"
    );
    let issuer = roles::own_role(
        &spec.issuer_unit,
        "capture-epoch223-demotion-native-proof",
        binding,
        executable,
    )?;
    let launch: Launch = read_bound(&spec.launch)?;
    let result: Completion = read_bound(&spec.result)?;
    let origin: OriginClock = read_bound(&spec.origin_clock)?;
    validate_origin(&origin, millis()?)?;
    validate_origin_journal(&origin)?;
    let qualification: Value = read_bound(&spec.supervisor_qualification)?;
    ensure!(
        qualification["schema"] == "jetstreamer-epoch223-demotion-role-qualification-v1"
            && qualification["native_supervisor_qualified"] == true
            && qualification["executable_sha256"] == launch.supervisor.executable.sha256,
        "223 native supervisor has not been independently qualified"
    );
    ensure!(
        launch.schema == "jetstreamer-epoch223-demotion-native-launch-v1"
            && launch
                .supervisor
                .unit
                .starts_with("horizon-native-input-223-demotion-")
            && launch.harness.sha256 == HARNESS
            && launch.source_commit == SOURCE
            && launch.worker_sha256 == WORKER
            && launch.source_qa_sha256 == QA
            && spec.source_qa.sha256 == QA
            && launch.snapshot.sha256 == SNAPSHOT
            && launch.genesis.sha256 == GENESIS
            && launch.harness_pid > 1
            && launch.harness_start_ticks > 0
            && launch.origin_clock == spec.origin_clock
            && launch.original_start_unix_millis == origin.original_start_unix_millis
            && launch.actual_child_identity_captured
            && launch.native_input_only
            && !launch.publication_authorized
            && !launch.r2_mutations,
        "223 capture is not exact new harness actual native launch"
    );
    let status_task: Value = read_bound(&launch.status_task)?;
    ensure!(
        status_task["schema"] == "jetstreamer-epoch223-demotion-active-task-v1"
            && status_task["actor"] == serde_json::to_value(&launch.supervisor)?
            && status_task["origin_clock"] == binding_value(&spec.origin_clock)
            && status_task["original_start_unix_millis"] == origin.original_start_unix_millis,
        "223 native proof has no genuine original-clock repair task"
    );
    let expected = vec![
        launch.harness.path.display().to_string(),
        TEST.into(),
        "--exact".into(),
        "--ignored".into(),
        "--nocapture".into(),
        "--test-threads=1".into(),
    ];
    ensure!(
        launch.harness_argv == expected
            && launch
                .scratch_root
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|n| n
                    .to_string_lossy()
                    .starts_with("native-input223-v1620-demotion-"))
            && launch
                .scratch_root
                .file_name()
                .is_some_and(|n| n == "scratch"),
        "223 native launch test filter/scratch scope differs"
    );
    verify_reference(&spec.source_qa)?;
    ensure!(
        launch.supervisor.boot_id == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
            && launch.snapshot.path
                == Path::new("/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1")
                    .join(SNAPSHOT_NAME)
            && launch.genesis.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/genesis.bin"
                ),
        "223 native launch boot or actual pinned input paths differ"
    );
    bound_file(
        &launch.supervisor.executable.path,
        &launch.supervisor.executable.sha256,
        256 << 20,
    )?;
    // ELF verification is metadata provenance, not a new native invocation.
    bound_file(&launch.harness.path, HARNESS, 256 << 20)?;
    ensure!(
        result.schema == "jetstreamer-epoch223-demotion-native-result-v1"
            && result.launch == spec.launch
            && result.harness_sha256 == HARNESS
            && result.harness_pid == launch.harness_pid
            && result.harness_start_ticks == launch.harness_start_ticks
            && result.harness_exit_code == 0
            && result.harness_reaped
            && result.success
            && !result.publication_authorized
            && !result.r2_mutations,
        "223 actual new harness result differs"
    );
    let stdout = bound_bytes(&result.harness_stdout, 0, 64 << 20)?;
    let tuple = output_valid(&stdout)?;
    let journal = bound_bytes(&spec.journal, 0, 16 << 20)?;
    journal_valid(&journal, &launch.supervisor)?;
    let keys = "Id,InvocationID,NRestarts,MainPID,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,Type,User,Restart,ExecStart";
    let terminal = properties_with(&launch.supervisor.unit, keys)?;
    for (key, value) in [
        ("Id", launch.supervisor.unit.as_str()),
        ("InvocationID", launch.supervisor.invocation_id.as_str()),
        ("NRestarts", "0"),
        ("MainPID", "0"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("Result", "success"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", "0"),
        ("Type", "exec"),
        ("User", "root"),
        ("Restart", "no"),
    ] {
        ensure!(
            terminal.get(key).map(String::as_str) == Some(value),
            "223 actual native terminal manager differs:{key}"
        );
    }
    ensure!(
        terminal
            .get("ExecStart")
            .is_some_and(|s| command_matches(s, &launch.supervisor.expected_exec_start)),
        "223 native terminal command differs"
    );
    observe(&issuer)?;
    let provenance = issuance::published(
        &spec.provenance_output,
        &json!({
        "schema":"jetstreamer-epoch223-demotion-native-proof-capture-v1","spec":binding,"issuer":issuer,
        "actual_terminal_manager":terminal,"launch":spec.launch,"result":spec.result,"journal":spec.journal,
        "new_harness_sha256":HARNESS,"actual_ordered_output_validated":true,
        "publication_authorized":false,"r2_mutations":false}),
    )?;
    ensure!(
        properties_with(&launch.supervisor.unit, keys)? == terminal,
        "223 native terminal manager changed"
    );
    let proof = NativeProof {
        schema: "jetstreamer-epoch223-demotion-native-input-proof-v1".into(),
        source_commit: launch.source_commit,
        worker_sha256: launch.worker_sha256,
        harness_sha256: launch.harness.sha256,
        test_name: TEST.into(),
        source_qa_sha256: launch.source_qa_sha256,
        manager_success: terminal.get("Result").map(String::as_str) == Some("success"),
        restart_count: terminal
            .get("NRestarts")
            .context("223 actual restart count")?
            .parse()?,
        snapshot_sha256: launch.snapshot.sha256,
        genesis_sha256: launch.genesis.sha256,
        success: result.success,
        bootstrap_slot: tuple.slot,
        bank_hash: tuple.bank,
        accounts_hash: tuple.accounts,
        last_blockhash: tuple.last,
        capitalization: tuple.capitalization,
        transaction_count: tuple.transactions,
        tick_height: tuple.tick,
        next_write_version: tuple.write,
        slot_complete: true,
        replay_entries: tuple.replay,
        bootstrap_writes: tuple.bootstrap_writes,
        passed_tests: tuple.passed,
        ignored_tests: tuple.ignored,
        actual_unit: launch.supervisor.unit,
        actual_invocation_id: launch.supervisor.invocation_id,
        launch: spec.launch,
        result: spec.result,
        journal: spec.journal,
        issuer: provenance,
        entry_replay: false,
        canonical_prefix_qualified: false,
        native_restart_qualified: false,
        full_epoch_qualified: false,
        runtime_promotion_authorized: false,
        repair_closed: false,
        publication_authorized: false,
        r2_mutations: false,
    };
    proof.validate()?;
    issuance::published(&spec.proof_output, &serde_json::to_value(proof)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_ordered_tuple_and_exact_one_executed_test_are_required() {
        let good = format!(
            "running 1 test\n{MARKER}\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n"
        );
        output_valid(good.as_bytes()).unwrap();
        for bad in [
            good.replace("503889539326183230", "503889539326183200"),
            good.replace("0 ignored", "1 ignored"),
            good.replace("1 passed", "0 passed"),
            format!("{good}{MARKER}\n"),
            format!("test result: ok. 1 passed; 0 failed; 0 ignored;\n{MARKER}\n"),
        ] {
            assert!(output_valid(bad.as_bytes()).is_err());
        }
    }
}
