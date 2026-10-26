//! Exact natural terminal evidence for the original epoch 225/226 owner.
//! This profile authorizes status-only cleanup and no archive conclusion.
use super::*;

const SCHEMA: &str = "jetstreamer-epoch225-natural-terminal-status-evidence-v1";
const UNIT: &str = "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service";
const IID: &str = "4cd76ae1353a4411885b997f04306402";
const LAUNCH: &str =
    "/var/lib/jetstreamer/horizon-225-shrink-natural-root-launch-222936-v1/launch.json";
const LAUNCH_SHA: &str = "491baf3214515c8ad324d0d0de43a3fa680bb35892bfae32fd027b8ce6c6b071";
const ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1/output/epoch-225.jet";
const ARCHIVE_BYTES: u64 = 265_610_094_371;
const ARCHIVE_SHA: &str = "77c0f95a020ceb6c45e323f4ce1bb48066fd0b379615bd5c9dbcb67f9082d6f9";
const MANIFEST: &str = "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1/output/epoch-225.jet.segment.json";
const MANIFEST_SHA: &str = "53a69d801e70866b0bc048e1b3a75d9c16c1fb93995503157fc206742f3cdcf6";
const WORKER_SHA: &str = "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd";
const ACCOUNTS_HASH: &str = "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR";
const STARTING: &str = "7d4958e842da4a758f6c1cdc7b36dcc5";
const STARTED: &str = "39f53479d3a045ac8e11786248231fbf";
const SUCCESS: &str = "7ad2d189f7e94e70a38c781354912448";
const STOP_JOB: &str = "9d1aaa27d60140bd96365438aad20286";
const EXEC_START: &str = "{ path=/var/lib/jetstreamer/horizon-focused-225-complete-span-v1-6-25-shrink-budget-v1/jetstreamer-node ; argv[]=/var/lib/jetstreamer/horizon-focused-225-complete-span-v1-6-25-shrink-budget-v1/jetstreamer-node 225 /home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1/ledger --verify --qualification-end-slot=98063464 --snapshot-archive=/var/lib/jetstreamer/horizon-focused-225-complete-span-v1-6-25-shrink-budget-v1/snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst --epoch-hashes=/var/lib/jetstreamer/horizon-focused-225-complete-span-v1-6-25-shrink-budget-v1/epoch-hashes-225-complete-span.txt --horizon-output=/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1/output/epoch-225.jet --replay-scratch=/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1/scratch ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema: String,
    epochs: [u64; 2],
    unit: String,
    invocation_id: String,
    original_launch: Bound,
    terminal_properties: Bound,
    manager_journal: Bound,
    source_archive: PathBuf,
    source_archive_bytes: u64,
    source_manifest: Bound,
    source_archive_sha256_from_manifest_only: String,
    worker_sha256: String,
    output_slot_start: u64,
    output_slot_count: u64,
    terminal_slot: u64,
    terminal_accounts_hash: String,
    canonical_225_slots: u64,
    retained_private_226_slots: u64,
    missing_226_suffix_slots: u64,
    runtime_admission: String,
    archive_completion_claimed: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

struct Loaded {
    terminal: Value,
    journal: Vec<Value>,
    completion_realtime_micros: u64,
}

fn recognized(value: &Value) -> bool {
    value["schema"] == SCHEMA
}

fn decode(value: &Value) -> Result<Option<Evidence>> {
    if !recognized(value) {
        return Ok(None);
    }
    Ok(Some(serde_json::from_value(value.clone()).context(
        "malformed matching natural225 terminal evidence",
    )?))
}

fn scope(epoch: u64, evidence: &Evidence) -> Result<()> {
    ensure!(
        matches!(epoch, 225 | 226)
            && evidence.schema == SCHEMA
            && evidence.epochs == [225, 226]
            && evidence.unit == UNIT
            && evidence.invocation_id == IID
            && evidence.original_launch.path == Path::new(LAUNCH)
            && evidence.original_launch.sha256 == LAUNCH_SHA
            && evidence.source_archive == Path::new(ARCHIVE)
            && evidence.source_archive_bytes == ARCHIVE_BYTES
            && evidence.source_manifest.path == Path::new(MANIFEST)
            && evidence.source_manifest.sha256 == MANIFEST_SHA
            && evidence.source_archive_sha256_from_manifest_only == ARCHIVE_SHA
            && evidence.worker_sha256 == WORKER_SHA
            && evidence.output_slot_start == 97_200_000
            && evidence.output_slot_count == 863_465
            && evidence.terminal_slot == 98_063_464
            && evidence.terminal_accounts_hash == ACCOUNTS_HASH
            && evidence.canonical_225_slots == 432_000
            && evidence.retained_private_226_slots == 431_465
            && evidence.missing_226_suffix_slots == 535
            && evidence.runtime_admission == "candidate"
            && !evidence.archive_completion_claimed
            && !evidence.publication_authorized
            && !evidence.remote_mutations
            && !evidence.r2_mutations,
        "foreign or authority-bearing natural225 terminal evidence"
    );
    ensure!(
        evidence
            .output_slot_count
            .checked_sub(1)
            .and_then(|tail| evidence.output_slot_start.checked_add(tail))
            == Some(evidence.terminal_slot)
            && evidence
                .canonical_225_slots
                .checked_add(evidence.retained_private_226_slots)
                == Some(evidence.output_slot_count)
            && evidence
                .retained_private_226_slots
                .checked_add(evidence.missing_226_suffix_slots)
                == Some(432_000),
        "natural225 retained span or private epoch226 debt differs"
    );
    Ok(())
}

fn immutable_bytes(bound: &Bound, label: &str, maximum: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(&bound.path)?;
    ensure!(
        bound.path.is_absolute()
            && bound.path.canonicalize()? == bound.path
            && meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o222 == 0,
        "natural225 {label} is not an immutable root-owned regular file"
    );
    let bytes = read_stable_bounded(&bound.path, maximum, label)?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == bound.sha256,
        "natural225 {label} hash differs"
    );
    Ok(bytes)
}

fn immutable_json(bound: &Bound, label: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&immutable_bytes(
        bound,
        label,
        16 << 20,
    )?)?)
}

fn retained_manifest(bound: &Bound) -> Result<Value> {
    let meta = fs::symlink_metadata(&bound.path)?;
    ensure!(
        bound.path == Path::new(MANIFEST)
            && bound.path.canonicalize()? == bound.path
            && meta.is_file()
            && meta.uid() == 1000
            && meta.nlink() == 1
            && meta.mode() & 0o077 == 0,
        "natural225 retained manifest custody differs"
    );
    let bytes = read_stable_bounded(&bound.path, 1 << 20, "natural225 manifest")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == bound.sha256,
        "natural225 manifest hash differs"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn source_stat(evidence: &Evidence) -> Result<()> {
    let meta = fs::symlink_metadata(&evidence.source_archive)?;
    ensure!(
        evidence.source_archive == Path::new(ARCHIVE)
            && evidence.source_archive.canonicalize()? == evidence.source_archive
            && meta.is_file()
            && meta.uid() == 1000
            && meta.nlink() == 1
            && meta.mode() & 0o777 == 0o644
            && meta.len() == evidence.source_archive_bytes,
        "natural225 retained source metadata differs"
    );
    Ok(())
}

fn launch_shape(launch: &Value) -> Result<()> {
    let units = launch["evidence"]["units"]
        .as_array()
        .context("natural225 launch owner absent")?;
    ensure!(
        launch["schema"] == "jetstreamer-private-epoch225-shrink-natural-root-resource-launch-v1"
            && launch["launched"] == true
            && launch["epoch"] == 225
            && launch["private_run_root"]
                == "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1"
            && launch["worker_sha256"] == WORKER_SHA
            && launch["node_sha256"]
                == "945f36fe11824263258ad561dba106e377148b702f2c615522b171c4ba97ed3b"
            && launch["runtime"] == "solana-v1.6.25"
            && launch["runtime_semantics_changed"] == true
            && launch["solana_rayon_threads"] == 16
            && launch["output_slot_start"] == 97_200_000u64
            && launch["output_slot_count"] == 863_465u64
            && launch["canonical_epoch_end"] == 97_631_999u64
            && launch["terminal_root_slot"] == 98_063_464u64
            && launch["required_checkpoints"] == json!([97_199_617, 97_631_459, 98_063_464])
            && launch["private_verification_tail_epoch"] == 226
            && launch["private_verification_tail_slots"] == 431_465u64
            && launch["natural_parent_completion_required"] == true
            && launch["maximum_runtime_seconds"] == 604_800u64
            && launch["natural_root_resource_attempt_authorized"] == true
            && launch["full_span_independently_qualified"] == false
            && launch["full_cold_epoch_peak_qualified"] == false
            && launch["ordinary_replay_authorized"] == false
            && launch["runtime_promotion_authorized"] == false
            && launch["canonical_sidecar_authorized"] == false
            && launch["publication_authorized"] == false
            && launch["remote_mutations"] == false
            && launch["r2_mutations"] == false
            && units.len() == 1
            && units[0]["unit"] == UNIT
            && units[0]["invocation_id"] == IID
            && units[0]["restarts"] == 0,
        "natural225 original launch scope differs"
    );
    Ok(())
}

fn manifest_shape(manifest: &Value) -> Result<()> {
    ensure!(
        manifest["schema_version"] == 1
            && manifest["epoch"] == 225
            && manifest["output_slot_start"] == 97_200_000u64
            && manifest["output_slot_count"] == 863_465u64
            && manifest["worker_executable_sha256"] == WORKER_SHA
            && manifest["archive_sha256"] == ARCHIVE_SHA
            && manifest["runtime"]["runtime_profile"] == "solana-v1.6.25"
            && manifest["runtime"]["runtime_admission"] == "candidate"
            && manifest["terminal"]["slot"] == 98_063_464u64
            && manifest["terminal"]["slot_complete"] == true
            && manifest["terminal"]["accounts_hash"] == ACCOUNTS_HASH,
        "natural225 manifest source, runtime, span or terminal differs"
    );
    Ok(())
}

fn terminal_shape(value: &Value) -> Result<()> {
    let keys = value
        .as_object()
        .context("natural225 terminal properties are not an object")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        keys == BTreeSet::from([
            "ActiveState",
            "ControlGroup",
            "ExecMainStatus",
            "ExecStart",
            "Id",
            "InvocationID",
            "LoadState",
            "MainPID",
            "NRestarts",
            "Result",
            "SubState",
            "Type",
        ]) && value["Id"] == UNIT
            && value["LoadState"] == "loaded"
            && value["Type"] == "exec"
            && value["ActiveState"] == "inactive"
            && value["SubState"] == "dead"
            && value["MainPID"] == "0"
            && value["NRestarts"] == "0"
            && value["Result"] == "success"
            && value["ExecMainStatus"] == "0"
            && value["ControlGroup"] == ""
            && value["ExecStart"] == EXEC_START
            && value["InvocationID"]
                .as_str()
                .is_some_and(|id| id.is_empty() || id == IID),
        "natural225 owner is live, restarted, failed, replaced or changed command"
    );
    Ok(())
}

fn timestamp(row: &Value, key: &str) -> Result<u64> {
    Ok(row[key]
        .as_str()
        .with_context(|| format!("natural225 journal lacks {key}"))?
        .parse()?)
}

fn failed(row: &Value) -> bool {
    let message = row["MESSAGE"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(row["JOB_TYPE"].as_str(), Some("stop" | "restart"))
        || row["MESSAGE_ID"] == STOP_JOB
        || row.get("JOB_RESULT").is_some_and(|v| v != "done")
        || row.get("RESULT").is_some_and(|v| v != "success")
        || row.get("EXIT_STATUS").is_some_and(|v| v != "0")
        || row
            .get("SIGNAL")
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty())
        || ["failed", "killed", "stopping", "stopped", "restart job"]
            .iter()
            .any(|needle| message.contains(needle))
}

fn lifecycle(rows: &[Value]) -> Result<u64> {
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "natural225 manager journal is empty or unbounded"
    );
    let mut boot = None;
    let mut starts = Vec::new();
    let mut started = Vec::new();
    let mut completions = Vec::new();
    let mut previous = None;
    for row in rows {
        let realtime = timestamp(row, "__REALTIME_TIMESTAMP")?;
        let monotonic = timestamp(row, "__MONOTONIC_TIMESTAMP")?;
        if let Some((prior_realtime, prior_monotonic)) = previous {
            ensure!(
                realtime >= prior_realtime && monotonic >= prior_monotonic,
                "natural225 manager journal is out of order"
            );
        }
        previous = Some((realtime, monotonic));
        let row_boot = row["_BOOT_ID"]
            .as_str()
            .context("natural225 manager boot absent")?;
        ensure!(
            row_boot.len() == 32
                && row_boot
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == UNIT
                && row["INVOCATION_ID"] == IID
                && !failed(row),
            "natural225 manager journal has a foreign unit, boot, invocation or failure"
        );
        if let Some(expected) = boot {
            ensure!(row_boot == expected, "natural225 lifecycle crossed boots");
        } else {
            boot = Some(row_boot);
        }
        let message = row["MESSAGE"]
            .as_str()
            .context("natural225 manager message absent")?;
        if row["MESSAGE_ID"] == STARTING && message.starts_with(&format!("Starting {UNIT} -")) {
            starts.push((realtime, monotonic));
        }
        if row["MESSAGE_ID"] == STARTED && message.starts_with(&format!("Started {UNIT} -")) {
            started.push((realtime, monotonic));
        }
        if row["MESSAGE_ID"] == SUCCESS && message == format!("{UNIT}: Deactivated successfully.") {
            completions.push((realtime, monotonic));
        }
    }
    ensure!(
        starts.len() == 1 && started.len() <= 1 && completions.len() == 1,
        "natural225 lifecycle lacks a unique original start and natural completion"
    );
    let start = starts[0];
    let completion = completions[0];
    ensure!(
        completion.0 > start.0
            && completion.1 > start.1
            && started.first().is_none_or(|event| event.0 >= start.0
                && event.1 >= start.1
                && event.0 < completion.0
                && event.1 < completion.1),
        "natural225 completion does not follow its original start"
    );
    Ok(completion.0)
}

fn journal_rows(bytes: &[u8]) -> Result<Vec<Value>> {
    let rows = serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !rows.is_empty() && rows.len() <= 4096 && rows.iter().all(Value::is_object),
        "natural225 sealed manager journal is not a bounded raw row stream"
    );
    Ok(rows)
}

fn load(epoch: u64, value: &Value) -> Result<Option<Loaded>> {
    let Some(evidence) = decode(value)? else {
        return Ok(None);
    };
    scope(epoch, &evidence)?;
    let launch = immutable_json(&evidence.original_launch, "launch")?;
    launch_shape(&launch)?;
    let manifest = retained_manifest(&evidence.source_manifest)?;
    manifest_shape(&manifest)?;
    source_stat(&evidence)?;
    let terminal = immutable_json(&evidence.terminal_properties, "terminal properties")?;
    terminal_shape(&terminal)?;
    let journal = journal_rows(&immutable_bytes(
        &evidence.manager_journal,
        "manager journal",
        16 << 20,
    )?)?;
    let completion_realtime_micros = lifecycle(&journal)?;
    Ok(Some(Loaded {
        terminal,
        journal,
        completion_realtime_micros,
    }))
}

fn current_journal() -> Result<Vec<Value>> {
    let output = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "_PID=1",
            "_UID=0",
            &format!("UNIT={UNIT}"),
            "-n",
            "4096",
            "--no-pager",
            "--all",
            "-o",
            "json",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 16 << 20,
        "natural225 current PID1 journal is unreadable or unbounded"
    );
    let rows = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(rows.len() <= 4096, "natural225 current journal row bound");
    Ok(rows)
}

pub(super) fn time(epoch: u64, evidence: &Value) -> Result<Option<u64>> {
    Ok(load(epoch, evidence)?.map(|loaded| loaded.completion_realtime_micros / 1_000_000))
}

fn validate_observation(
    loaded: &Loaded,
    supplied: &Value,
    owners: &[(String, String)],
    journal: &[Value],
) -> Result<()> {
    ensure!(
        owners == &[(UNIT.into(), IID.into())],
        "natural225 status publication belongs to another owner"
    );
    terminal_shape(supplied)?;
    ensure!(
        loaded.terminal["ExecStart"] == supplied["ExecStart"],
        "natural225 raw terminal command changed"
    );
    ensure!(
        journal == loaded.journal && lifecycle(journal)? == loaded.completion_realtime_micros,
        "natural225 genuine PID1 lifecycle changed after capture"
    );
    Ok(())
}

pub(super) fn validate_current(
    epoch: u64,
    evidence: &Value,
    current: &BTreeMap<String, Value>,
    owners: &[(String, String)],
) -> Result<bool> {
    let Some(loaded) = load(epoch, evidence)? else {
        return Ok(false);
    };
    let supplied = current
        .get(UNIT)
        .context("natural225 owner omitted from complete census")?;
    ensure!(
        fleet::unit(UNIT)? == *supplied,
        "natural225 current manager properties changed after census"
    );
    let journal = current_journal()?;
    validate_observation(&loaded, supplied, owners, &journal)?;
    ensure!(
        fleet::unit(UNIT)? == *supplied,
        "natural225 current manager properties changed during revalidation"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound(path: &str, sha256: &str) -> Value {
        json!({"path":path,"sha256":sha256})
    }

    fn evidence() -> Value {
        json!({
            "schema":SCHEMA,"epochs":[225,226],"unit":UNIT,"invocation_id":IID,
            "original_launch":bound(LAUNCH,LAUNCH_SHA),
            "terminal_properties":bound("/sealed/terminal.json",&"a".repeat(64)),
            "manager_journal":bound("/sealed/journal.json",&"b".repeat(64)),
            "source_archive":ARCHIVE,"source_archive_bytes":ARCHIVE_BYTES,
            "source_manifest":bound(MANIFEST,MANIFEST_SHA),
            "source_archive_sha256_from_manifest_only":ARCHIVE_SHA,"worker_sha256":WORKER_SHA,
            "output_slot_start":97_200_000u64,"output_slot_count":863_465u64,
            "terminal_slot":98_063_464u64,"terminal_accounts_hash":ACCOUNTS_HASH,
            "canonical_225_slots":432_000u64,"retained_private_226_slots":431_465u64,
            "missing_226_suffix_slots":535u64,"runtime_admission":"candidate",
            "archive_completion_claimed":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        })
    }

    fn terminal(iid: &str) -> Value {
        json!({"Id":UNIT,"LoadState":"loaded","Type":"exec","ActiveState":"inactive",
            "SubState":"dead","InvocationID":iid,"NRestarts":"0","Result":"success",
            "ExecMainStatus":"0","ExecStart":EXEC_START,"ControlGroup":"","MainPID":"0"})
    }

    fn rows() -> Vec<Value> {
        let base = |time: u64, id: &str, message: String| {
            json!({"_PID":"1","_UID":"0","UNIT":UNIT,"INVOCATION_ID":IID,
                "_BOOT_ID":"b".repeat(32),"__REALTIME_TIMESTAMP":time.to_string(),
                "__MONOTONIC_TIMESTAMP":time.to_string(),"MESSAGE_ID":id,"MESSAGE":message})
        };
        vec![
            base(
                1_000_000,
                STARTING,
                format!("Starting {UNIT} - natural replay..."),
            ),
            base(
                2_000_000,
                STARTED,
                format!("Started {UNIT} - natural replay."),
            ),
            base(
                3_000_000,
                SUCCESS,
                format!("{UNIT}: Deactivated successfully."),
            ),
        ]
    }

    #[test]
    fn exact_loaded_cleared_or_retained_owner_is_the_only_terminal_shape() {
        terminal_shape(&terminal("")).unwrap();
        terminal_shape(&terminal(IID)).unwrap();
        for (key, value) in [
            ("MainPID", json!("1")),
            ("ControlGroup", json!("/system.slice/replacement.service")),
            ("NRestarts", json!("1")),
            ("ExecStart", json!("{ path=/foreign ; argv[]=/foreign }")),
            ("InvocationID", json!("c".repeat(32))),
            ("ActiveState", json!("active")),
            ("Result", json!("exit-code")),
        ] {
            let mut changed = terminal("");
            changed[key] = value;
            assert!(terminal_shape(&changed).is_err(), "{key}");
        }
    }

    #[test]
    fn both_status_epochs_accept_cleared_or_retained_iid_only_with_same_history() {
        let history = rows();
        let owners = vec![(UNIT.into(), IID.into())];
        for epoch in [225, 226] {
            scope(epoch, &decode(&evidence()).unwrap().unwrap()).unwrap();
            for iid in ["", IID] {
                let loaded = Loaded {
                    terminal: terminal(""),
                    journal: history.clone(),
                    completion_realtime_micros: 3_000_000,
                };
                validate_observation(&loaded, &terminal(iid), &owners, &history).unwrap();
            }
        }
        let loaded = Loaded {
            terminal: terminal(""),
            journal: history.clone(),
            completion_realtime_micros: 3_000_000,
        };
        let mut changed = history;
        changed[1]["MESSAGE"] = json!("changed");
        assert!(validate_observation(&loaded, &terminal(""), &owners, &changed).is_err());
        assert!(validate_observation(
            &loaded,
            &terminal(""),
            &[("foreign.service".into(), IID.into())],
            &loaded.journal,
        )
        .is_err());
    }

    #[test]
    fn genuine_start_and_natural_completion_are_unique_ordered_and_same_owner() {
        assert_eq!(lifecycle(&rows()).unwrap(), 3_000_000);
        for index in [0, 2] {
            let mut missing = rows();
            missing.remove(index);
            assert!(lifecycle(&missing).is_err(), "missing {index}");
            let mut duplicate = rows();
            duplicate.push(duplicate[index].clone());
            assert!(lifecycle(&duplicate).is_err(), "duplicate {index}");
        }
        for (index, key, value) in [
            (0, "_PID", json!("2")),
            (1, "UNIT", json!("foreign.service")),
            (2, "INVOCATION_ID", json!("c".repeat(32))),
            (2, "_BOOT_ID", json!("c".repeat(32))),
            (2, "__REALTIME_TIMESTAMP", json!("500000")),
        ] {
            let mut changed = rows();
            changed[index][key] = value;
            assert!(lifecycle(&changed).is_err(), "{index}:{key}");
        }
    }

    #[test]
    fn later_start_failure_stop_kill_or_changed_journal_is_rejected() {
        for event in [
            json!({"_PID":"1","_UID":"0","UNIT":UNIT,"INVOCATION_ID":IID,"_BOOT_ID":"b".repeat(32),
                "__REALTIME_TIMESTAMP":"4000000","__MONOTONIC_TIMESTAMP":"4000000",
                "MESSAGE_ID":STARTING,"MESSAGE":format!("Starting {UNIT} - again")}),
            json!({"_PID":"1","_UID":"0","UNIT":UNIT,"INVOCATION_ID":IID,"_BOOT_ID":"b".repeat(32),
                "__REALTIME_TIMESTAMP":"4000000","__MONOTONIC_TIMESTAMP":"4000000",
                "MESSAGE_ID":"failure","RESULT":"exit-code","MESSAGE":"Failed with result exit-code."}),
            json!({"_PID":"1","_UID":"0","UNIT":UNIT,"INVOCATION_ID":IID,"_BOOT_ID":"b".repeat(32),
                "__REALTIME_TIMESTAMP":"4000000","__MONOTONIC_TIMESTAMP":"4000000",
                "MESSAGE_ID":STOP_JOB,"JOB_TYPE":"stop","JOB_RESULT":"done","MESSAGE":"Stopped."}),
            json!({"_PID":"1","_UID":"0","UNIT":UNIT,"INVOCATION_ID":IID,"_BOOT_ID":"b".repeat(32),
                "__REALTIME_TIMESTAMP":"4000000","__MONOTONIC_TIMESTAMP":"4000000",
                "MESSAGE_ID":"signal","SIGNAL":"KILL","MESSAGE":"Main process killed."}),
        ] {
            let mut changed = rows();
            changed.push(event);
            assert!(lifecycle(&changed).is_err());
        }
        let saved = rows();
        let mut changed = saved.clone();
        changed[1]["MESSAGE"] = json!("changed");
        assert_ne!(saved, changed);
    }

    #[test]
    fn exact_scope_is_available_for_both_status_epochs_and_no_other_profile() {
        let decoded = decode(&evidence()).unwrap().unwrap();
        scope(225, &decoded).unwrap();
        scope(226, &decoded).unwrap();
        assert!(scope(224, &decoded).is_err());
        assert!(decode(&json!({"schema":"unrelated"})).unwrap().is_none());
        assert!(decode(&json!({"schema":SCHEMA})).is_err());
        let mut malformed = evidence();
        malformed["unexpected"] = json!(true);
        assert!(decode(&malformed).is_err());
    }

    #[test]
    fn source_manifest_worker_span_runtime_and_tail_debt_are_exact() {
        for (key, value) in [
            ("source_archive", json!("/foreign/epoch-225.jet")),
            ("source_archive_bytes", json!(ARCHIVE_BYTES - 1)),
            (
                "source_archive_sha256_from_manifest_only",
                json!("c".repeat(64)),
            ),
            ("worker_sha256", json!("d".repeat(64))),
            ("output_slot_start", json!(97_200_001u64)),
            ("output_slot_count", json!(863_464u64)),
            ("runtime_admission", json!("production")),
            ("retained_private_226_slots", json!(431_464u64)),
            ("missing_226_suffix_slots", json!(534u64)),
        ] {
            let mut changed = evidence();
            changed[key] = value;
            let decoded = decode(&changed).unwrap().unwrap();
            assert!(scope(225, &decoded).is_err(), "{key}");
        }
        let mut changed = evidence();
        changed["source_manifest"]["sha256"] = json!("e".repeat(64));
        assert!(scope(225, &decode(&changed).unwrap().unwrap()).is_err());
    }
}
