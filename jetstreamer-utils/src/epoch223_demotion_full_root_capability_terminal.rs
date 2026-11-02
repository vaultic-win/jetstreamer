// Metadata-only adapter for the exact no-worker full-root capability actor.
// Historical launch plus authenticated PID1 success remains the identity authority.
use super::*;

const KEYS: &str = "Id,LoadState,InvocationID,NRestarts,MainPID,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,Type,User,Restart,RemainAfterExit,ExecStart";
const STARTED: &str = "39f53479d3a045ac8e11786248231fbf";
const SUCCEEDED: &str = "7ad2d189f7e94e70a38c781354912448";

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Lifecycle {
    started: Value,
    succeeded: Value,
}

pub(super) fn lifecycle(rows: &[Value], actor: &Actor) -> Result<Lifecycle> {
    ensure!(
        identity(&actor.invocation_id) && actor.invocation_id != "0".repeat(32),
        "223 original native invocation is invalid"
    );
    let boot = actor.boot_id.replace('-', "");
    let (mut started, mut succeeded) = (None, None);
    let (mut previous, mut starting) = (0u64, false);
    let mut cursors = std::collections::BTreeSet::new();
    for row in rows {
        if row["UNIT"] != actor.unit {
            continue;
        }
        // No IID filter: even an already collected replacement must close the gate.
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["_COMM"] == "systemd"
                && row["_BOOT_ID"] == boot
                && row["INVOCATION_ID"] == actor.invocation_id,
            "223 native PID1 foreign boot/invocation or untrusted row"
        );
        let timestamp: u64 = row["__MONOTONIC_TIMESTAMP"]
            .as_str()
            .context("223 native PID1 monotonic timestamp")?
            .parse()?;
        let cursor = row["__CURSOR"].as_str().context("223 native PID1 cursor")?;
        ensure!(
            timestamp > 0 && timestamp >= previous && !cursor.is_empty() && cursors.insert(cursor),
            "223 native PID1 repeated or unordered row"
        );
        previous = timestamp;
        let message = row["MESSAGE"].as_str().context("223 native PID1 message")?;
        if message.starts_with(&format!("Starting {} - ", actor.unit)) {
            ensure!(
                row["MESSAGE_ID"] == "7d4958e842da4a758f6c1cdc7b36dcc5"
                    && !starting
                    && started.is_none()
                    && succeeded.is_none(),
                "223 native duplicate/restarted PID1 start"
            );
            starting = true;
        } else if message.starts_with(&format!("Started {} - ", actor.unit)) {
            ensure!(
                row["MESSAGE_ID"] == STARTED
                    && row["JOB_RESULT"] == "done"
                    && succeeded.is_none()
                    && started.replace(row.clone()).is_none(),
                "223 native PID1 start differs or repeats"
            );
        } else if message == format!("{}: Deactivated successfully.", actor.unit) {
            ensure!(
                row["MESSAGE_ID"] == SUCCEEDED
                    && started.is_some()
                    && succeeded.replace(row.clone()).is_none(),
                "223 native PID1 natural success differs or repeats"
            );
        } else {
            // Resource accounting after natural completion is the only other
            // supported PID1 message. Failures, stops and restart jobs fail closed.
            ensure!(
                succeeded.is_some()
                    && message.starts_with(&format!("{}: Consumed ", actor.unit))
                    && row["MESSAGE_ID"] == "ae8f7b866b0347b9af31fe1c80b127c0",
                "223 native unexpected PID1 lifecycle/failure/restart"
            );
        }
    }
    Ok(Lifecycle {
        started: started.context("223 native original PID1 start missing")?,
        succeeded: succeeded.context("223 native original PID1 natural success missing")?,
    })
}

pub(super) fn rows(bytes: &[u8]) -> Result<Vec<Value>> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<serde_json::Result<Vec<_>>>()
        .context("223 native PID1 JSON stream")
}

pub(super) fn frame(
    manager: &BTreeMap<String, String>,
    query_exit_code: i32,
    actor: &Actor,
) -> Result<&'static str> {
    for (key, value) in [
        ("Id", actor.unit.as_str()),
        ("NRestarts", "0"),
        ("MainPID", "0"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("Restart", "no"),
        ("RemainAfterExit", "no"),
    ] {
        ensure!(
            manager.get(key).map(String::as_str) == Some(value),
            "223 native terminal manager differs: {key}"
        );
    }
    let get = |key| manager.get(key).map(String::as_str);
    match get("LoadState") {
        Some("loaded") => {
            ensure!(
                query_exit_code == 0,
                "223 loaded native manager query failed"
            );
            for (key, value) in [("ExecMainCode", "1"), ("Type", "exec"), ("User", "ubuntu")] {
                ensure!(
                    get(key) == Some(value),
                    "223 loaded native terminal differs: {key}"
                );
            }
            ensure!(
                get("ExecStart").is_some_and(|s| command_matches(s, &actor.expected_exec_start)),
                "223 native retained command changed"
            );
            match get("InvocationID") {
                Some(iid) if iid == actor.invocation_id => Ok("loaded-retained-invocation"),
                Some("") => Ok("loaded-cleared-invocation"),
                _ => anyhow::bail!("223 native current invocation is foreign"),
            }
        }
        Some("not-found") => {
            // systemctl versions return either 0 or EXIT_NOTINSTALLED (4) for
            // show of a collected service. Its actual exit code is preserved.
            ensure!(
                matches!(query_exit_code, 0 | 4),
                "223 collected native manager query failed"
            );
            for (key, value) in [
                ("InvocationID", ""),
                ("ExecMainCode", "0"),
                ("Type", ""),
                ("User", ""),
                ("ExecStart", ""),
            ] {
                ensure!(
                    get(key) == Some(value),
                    "223 collected native terminal differs: {key}"
                );
            }
            Ok("collected-cleared-invocation")
        }
        _ => anyhow::bail!("223 native unsupported terminal load state"),
    }
}

fn validate(
    manager: &BTreeMap<String, String>,
    query_exit_code: i32,
    journal: &[Value],
    actor: &Actor,
    original: &Lifecycle,
) -> Result<&'static str> {
    let frame = frame(manager, query_exit_code, actor)?;
    ensure!(
        journal.iter().all(|row| row["UNIT"] == actor.unit)
            && lifecycle(journal, actor)? == *original,
        "223 native current PID1 lifecycle differs from preserved original"
    );
    Ok(frame)
}

pub(super) fn validate_evidence(
    evidence: &Value,
    actor: &Actor,
    original: &Lifecycle,
) -> Result<()> {
    let manager: BTreeMap<String, String> =
        serde_json::from_value(evidence["manager"].clone())?;
    let exit = evidence["manager_query"]["exit_code"]
        .as_i64()
        .and_then(|code| i32::try_from(code).ok())
        .context("223 capability terminal query exit code")?;
    let journal: Vec<Value> = serde_json::from_value(
        evidence["complete_current_boot_pid1_unit_journal"].clone(),
    )?;
    let frame = validate(&manager, exit, &journal, actor, original)?;
    ensure!(evidence["frame"] == frame,
        "223 capability terminal frame label differs");
    Ok(())
}

#[derive(serde::Serialize)]
struct Query {
    argv: Vec<String>,
    exit_code: i32,
    stdout_sha256: String,
    stderr: String,
    #[serde(skip)]
    stdout: Vec<u8>,
}

fn query(program: &str, args: Vec<String>, maximum_stdout: u64) -> Result<Query> {
    let mut child = Command::new(program)
        .args(&args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().context("223 metadata stdout pipe")?;
    let stderr = child.stderr.take().context("223 metadata stderr pipe")?;
    let (status, stdout, stderr) = thread::scope(|scope| -> Result<_> {
        // Drain both pipes while enforcing the wall bound, so a full pipe can
        // neither deadlock a successful census nor consume unbounded memory.
        let out = scope.spawn(move || -> std::io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            stdout.take(maximum_stdout + 1).read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        let err = scope.spawn(move || -> std::io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            stderr.take(65537).read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        let started = Instant::now();
        let status: Result<std::process::ExitStatus> = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if started.elapsed() < Duration::from_secs(5) => {
                    thread::sleep(Duration::from_millis(10));
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break match result {
                        Err(error) => Err(error.into()),
                        _ => Err(anyhow::anyhow!(
                            "223 native metadata query exceeded five seconds"
                        )),
                    };
                }
            }
        };
        let stdout = out
            .join()
            .map_err(|_| anyhow::anyhow!("223 stdout reader panicked"))??;
        let stderr = err
            .join()
            .map_err(|_| anyhow::anyhow!("223 stderr reader panicked"))??;
        Ok((status?, stdout, stderr))
    })?;
    ensure!(
        stdout.len() as u64 <= maximum_stdout && stderr.len() <= 65536,
        "223 native metadata query exceeded output bound"
    );
    Ok(Query {
        argv: std::iter::once(program.to_owned()).chain(args).collect(),
        exit_code: status
            .code()
            .context("223 native metadata query was signaled")?,
        stdout_sha256: hex(&Sha256::digest(&stdout)),
        stderr: String::from_utf8(stderr)?,
        stdout,
    })
}

#[derive(serde::Serialize)]
pub(super) struct Snapshot {
    manager_query: Query,
    journal_query: Query,
    pub(super) manager: BTreeMap<String, String>,
    complete_current_boot_pid1_unit_journal: Vec<Value>,
    frame: String,
}

pub(super) fn snapshot(actor: &Actor, original: &Lifecycle) -> Result<Snapshot> {
    ensure!(
        actor.unit.starts_with("horizon-qualify-223-full-root-demotion-")
            && actor.unit.ends_with(".service")
            && actor
                .unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "223 native terminal unit scope"
    );
    let manager_query = query(
        "/usr/bin/systemctl",
        vec![
            "show".into(),
            actor.unit.clone(),
            "--no-pager".into(),
            "--all".into(),
            format!("--property={KEYS}"),
        ],
        65536,
    )?;
    let mut manager = BTreeMap::new();
    for line in std::str::from_utf8(&manager_query.stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .context("223 native manager property")?;
        ensure!(
            manager.insert(key.into(), value.into()).is_none(),
            "223 duplicate native property"
        );
    }
    frame(&manager, manager_query.exit_code, actor)?;
    let journal_query = query(
        "/usr/bin/journalctl",
        vec![
            "--no-pager".into(),
            "--output=json".into(),
            format!("--boot={}", actor.boot_id.replace('-', "")),
            "_PID=1".into(),
            format!("UNIT={}", actor.unit),
        ],
        16 << 20,
    )?;
    ensure!(
        journal_query.exit_code == 0 && journal_query.stderr.is_empty(),
        "223 native complete journal query failed"
    );
    let journal = rows(&journal_query.stdout)?;
    let frame = validate(&manager, manager_query.exit_code, &journal, actor, original)?.to_owned();
    Ok(Snapshot {
        manager_query,
        journal_query,
        manager,
        complete_current_boot_pid1_unit_journal: journal,
        frame,
    })
}

impl Snapshot {
    pub(super) fn stable_with(&self, next: &Self) -> bool {
        self.manager == next.manager
            && self.manager_query.exit_code == next.manager_query.exit_code
            && self.complete_current_boot_pid1_unit_journal
                == next.complete_current_boot_pid1_unit_journal
            && self.frame == next.frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> Actor {
        Actor {
            unit: "horizon-qualify-223-full-root-demotion-terminal-test.service".into(),
            invocation_id: "b041313f341d4bd08d4fff6804764484".into(),
            pid: 123,
            start_ticks: 456,
            cgroup: "/system.slice/horizon-qualify-223-full-root-demotion-terminal-test.service".into(),
            boot_id: "2e60f44d-8e48-4d7e-91fc-c2dc724d2ae6".into(),
            executable: BoundFile { path: "/sealed/utility".into(), sha256: "a".repeat(64) },
            expected_exec_start: "{ path=/sealed/utility ; argv[]=/sealed/utility /sealed/plan --plan-sha256 abc --self-sha256 def --storage-capability ; ignore_errors=no }".into(),
        }
    }

    fn history(actor: &Actor) -> Vec<Value> {
        [
            ("starting", format!("Starting {} - native input...", actor.unit), "7d4958e842da4a758f6c1cdc7b36dcc5", 10),
            ("started", format!("Started {} - native input.", actor.unit), STARTED, 20),
            ("success", format!("{}: Deactivated successfully.", actor.unit), SUCCEEDED, 30),
        ].into_iter().map(|(cursor, message, message_id, timestamp)| json!({
            "_PID":"1", "_UID":"0", "_COMM":"systemd", "_BOOT_ID":actor.boot_id.replace('-', ""),
            "UNIT":actor.unit, "INVOCATION_ID":actor.invocation_id,
            "MESSAGE":message, "MESSAGE_ID":message_id, "JOB_RESULT":"done",
            "__CURSOR":cursor, "__MONOTONIC_TIMESTAMP":timestamp.to_string(),
        })).collect()
    }

    fn loaded(actor: &Actor) -> BTreeMap<String, String> {
        [
            ("Id", actor.unit.as_str()),
            ("LoadState", "loaded"),
            ("InvocationID", actor.invocation_id.as_str()),
            ("NRestarts", "0"),
            ("MainPID", "0"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("Result", "success"),
            ("ExecMainCode", "1"),
            ("ExecMainStatus", "0"),
            ("Type", "exec"),
            ("User", "ubuntu"),
            ("Restart", "no"),
            ("RemainAfterExit", "no"),
            ("ExecStart", actor.expected_exec_start.as_str()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }

    fn collected(actor: &Actor) -> BTreeMap<String, String> {
        let mut manager = loaded(actor);
        for (k, v) in [
            ("LoadState", "not-found"),
            ("InvocationID", ""),
            ("ExecMainCode", "0"),
            ("Type", ""),
            ("User", ""),
            ("ExecStart", ""),
        ] {
            manager.insert(k.into(), v.into());
        }
        manager
    }

    #[test]
    fn retained_cleared_and_collected_frames_require_the_same_original_natural_lifecycle() {
        let actor = actor();
        let journal = history(&actor);
        let original = lifecycle(&journal, &actor).unwrap();
        let mut manager = loaded(&actor);
        assert_eq!(
            validate(&manager, 0, &journal, &actor, &original).unwrap(),
            "loaded-retained-invocation"
        );
        manager.insert("InvocationID".into(), "".into());
        assert_eq!(
            validate(&manager, 0, &journal, &actor, &original).unwrap(),
            "loaded-cleared-invocation"
        );
        for code in [0, 4] {
            assert_eq!(
                validate(&collected(&actor), code, &journal, &actor, &original).unwrap(),
                "collected-cleared-invocation"
            );
        }
        // Current empty IID stays empty; the original actor is never rewritten.
        assert_eq!(manager["InvocationID"], "");
        assert_eq!(actor.invocation_id, "b041313f341d4bd08d4fff6804764484");
        // The complete real census can also contain PID1 resource accounting.
        let mut complete = journal.clone();
        let mut accounting = journal[2].clone();
        accounting["MESSAGE"] = format!("{}: Consumed 1s CPU time.", actor.unit).into();
        accounting["MESSAGE_ID"] = "ae8f7b866b0347b9af31fe1c80b127c0".into();
        accounting["__CURSOR"] = "resources".into();
        accounting["__MONOTONIC_TIMESTAMP"] = "40".into();
        complete.push(accounting);
        validate(&collected(&actor), 4, &complete, &actor, &original).unwrap();
    }

    #[test]
    fn all_terminal_frames_reject_failure_restart_sleeping_owner_and_remain_after_exit() {
        let actor = actor();
        let journal = history(&actor);
        let original = lifecycle(&journal, &actor).unwrap();
        for base in [loaded(&actor), collected(&actor)] {
            for (key, value) in [
                ("Id", "replacement.service"),
                ("InvocationID", "cccccccccccccccccccccccccccccccc"),
                ("NRestarts", "1"),
                ("MainPID", "123"),
                ("ActiveState", "active"),
                ("SubState", "running"),
                ("Result", "exit-code"),
                ("ExecMainStatus", "1"),
                ("Restart", "on-failure"),
                ("RemainAfterExit", "yes"),
            ] {
                let mut manager = base.clone();
                manager.insert(key.into(), value.into());
                assert!(
                    validate(&manager, 0, &journal, &actor, &original).is_err(),
                    "{key}={value}"
                );
            }
            for key in KEYS.split(',') {
                let mut manager = base.clone();
                manager.remove(key);
                assert!(
                    validate(&manager, 0, &journal, &actor, &original).is_err(),
                    "missing:{key}"
                );
            }
        }
    }

    #[test]
    fn retained_commands_and_collected_cleared_fields_cannot_be_substituted() {
        let actor = actor();
        let journal = history(&actor);
        let original = lifecycle(&journal, &actor).unwrap();
        for iid in [actor.invocation_id.as_str(), ""] {
            for (key, value) in [
                ("ExecStart", "/bin/sleep infinity"),
                ("ExecMainCode", "0"),
                ("Type", "oneshot"),
                ("User", "root"),
                ("LoadState", "error"),
            ] {
                let mut manager = loaded(&actor);
                manager.insert("InvocationID".into(), iid.into());
                manager.insert(key.into(), value.into());
                assert!(validate(&manager, 0, &journal, &actor, &original).is_err());
            }
        }
        for (key, value) in [
            ("ExecMainCode", "1"),
            ("Type", "exec"),
            ("User", "ubuntu"),
            ("ExecStart", actor.expected_exec_start.as_str()),
            ("InvocationID", actor.invocation_id.as_str()),
        ] {
            let mut manager = collected(&actor);
            manager.insert(key.into(), value.into());
            assert!(validate(&manager, 4, &journal, &actor, &original).is_err());
        }
        assert!(validate(&loaded(&actor), 4, &journal, &actor, &original).is_err());
        assert!(validate(&collected(&actor), 1, &journal, &actor, &original).is_err());
    }

    #[test]
    fn cleared_or_collected_state_never_substitutes_for_missing_or_failed_natural_success() {
        let actor = actor();
        let journal = history(&actor);
        let original = lifecycle(&journal, &actor).unwrap();
        let mut variants = vec![
            vec![],
            journal[..2].to_vec(),
            vec![journal[0].clone(), journal[2].clone()],
        ];
        for message in [
            format!("{}: Failed with result 'exit-code'.", actor.unit),
            format!(
                "{}: Main process exited, code=exited, status=1/FAILURE",
                actor.unit
            ),
            format!(
                "{}: Scheduled restart job, restart counter is at 1.",
                actor.unit
            ),
            format!("Stopped {} - native input.", actor.unit),
        ] {
            let mut failed = journal.clone();
            failed[2]["MESSAGE"] = message.into();
            variants.push(failed);
        }
        for rows in variants {
            for manager in [loaded(&actor), collected(&actor)] {
                assert!(validate(&manager, 0, &rows, &actor, &original).is_err());
            }
        }
    }

    #[test]
    fn complete_census_rejects_foreign_replacement_even_when_its_unit_was_also_collected() {
        let actor = actor();
        let journal = history(&actor);
        let original = lifecycle(&journal, &actor).unwrap();
        let mut replacement = actor.clone();
        replacement.invocation_id = "c".repeat(32);
        let mut census = journal.clone();
        census.extend(history(&replacement));
        assert!(lifecycle(&census, &actor).is_err());
        assert!(validate(&collected(&actor), 4, &census, &actor, &original).is_err());
        // Even a partial foreign lifecycle cannot hide behind the successful IID.
        for index in 0..journal.len() {
            let mut changed = journal.clone();
            changed[index]["INVOCATION_ID"] = replacement.invocation_id.clone().into();
            assert!(validate(&collected(&actor), 4, &changed, &actor, &original).is_err());
        }
    }

    #[test]
    fn pid1_provenance_order_and_original_success_rows_are_bound() {
        let actor = actor();
        let journal = history(&actor);
        let original = lifecycle(&journal, &actor).unwrap();
        for (key, value) in [
            ("_PID", "42"),
            ("_UID", "1000"),
            ("_COMM", "fake-systemd"),
            ("_BOOT_ID", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("MESSAGE_ID", "fake-success"),
            ("__MONOTONIC_TIMESTAMP", "1"),
            ("__CURSOR", "started"),
        ] {
            let mut changed = journal.clone();
            changed[2][key] = value.into();
            assert!(
                validate(&collected(&actor), 4, &changed, &actor, &original).is_err(),
                "{key}"
            );
        }
        let mut changed_original = journal.clone();
        changed_original[2]["__CURSOR"] = "different-original-success".into();
        assert!(lifecycle(&changed_original, &actor).is_ok());
        assert!(validate(&collected(&actor), 4, &changed_original, &actor, &original).is_err());
        let mut duplicate = journal.clone();
        duplicate.push(journal[2].clone());
        assert!(validate(&collected(&actor), 4, &duplicate, &actor, &original).is_err());
        let mut restarted = journal.clone();
        restarted.extend(history(&actor));
        assert!(validate(&loaded(&actor), 0, &restarted, &actor, &original).is_err());
    }

    #[test]
    fn publication_race_check_binds_manager_and_complete_history() {
        let actor = actor();
        let sample = || {
            let query = || Query {
                argv: vec![],
                exit_code: 0,
                stdout_sha256: "a".repeat(64),
                stderr: String::new(),
                stdout: vec![],
            };
            Snapshot {
                manager_query: query(),
                journal_query: query(),
                manager: collected(&actor),
                complete_current_boot_pid1_unit_journal: history(&actor),
                frame: "collected-cleared-invocation".into(),
            }
        };
        let before = sample();
        let mut after = sample();
        assert!(before.stable_with(&after));
        // JSON object field serialization order is not lifecycle identity.
        after.journal_query.stdout_sha256 = "b".repeat(64);
        assert!(before.stable_with(&after));
        after
            .manager
            .insert("ExecStart".into(), "/bin/sleep infinity".into());
        assert!(!before.stable_with(&after));
        let mut after = sample();
        after.complete_current_boot_pid1_unit_journal[2]["INVOCATION_ID"] = "c".repeat(32).into();
        assert!(!before.stable_with(&after));
    }

    #[test]
    fn reordered_json_bytes_preserve_raw_hashes_without_changing_terminal_facts() {
        let actor = actor();
        let journal = history(&actor);
        let original = lifecycle(&journal, &actor).unwrap();
        let encode = |reverse: bool| {
            journal
                .iter()
                .map(|row| {
                    let mut members: Vec<_> = row.as_object().unwrap().iter().collect();
                    if reverse {
                        members.reverse();
                    }
                    let fields = members
                        .into_iter()
                        .map(|(key, value)| {
                            format!(
                                "{}:{}",
                                serde_json::to_string(key).unwrap(),
                                serde_json::to_string(value).unwrap()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("{{{fields}}}\n")
                })
                .collect::<String>()
                .into_bytes()
        };
        let first = encode(false);
        let second = encode(true);
        assert_ne!(first, second);
        let sample = |raw: Vec<u8>| {
            let events = rows(&raw).unwrap();
            validate(&collected(&actor), 4, &events, &actor, &original).unwrap();
            let query = Query {
                argv: vec!["--output=json".into()],
                exit_code: 0,
                stdout_sha256: hex(&Sha256::digest(&raw)),
                stderr: String::new(),
                stdout: raw,
            };
            Snapshot {
                manager_query: Query {
                    argv: vec![],
                    exit_code: 4,
                    stdout_sha256: hex(&Sha256::digest(b"collected-manager")),
                    stderr: String::new(),
                    stdout: vec![],
                },
                journal_query: query,
                manager: collected(&actor),
                complete_current_boot_pid1_unit_journal: events,
                frame: "collected-cleared-invocation".into(),
            }
        };
        let first = sample(first);
        let second = sample(second);
        assert_ne!(
            first.journal_query.stdout_sha256,
            second.journal_query.stdout_sha256
        );
        assert!(first.stable_with(&second));
        // The serialized receipt keeps the two independent raw hashes even
        // though the complete parsed lifecycle comparison succeeds.
        assert_ne!(
            serde_json::to_value(&first).unwrap()["journal_query"]["stdout_sha256"],
            serde_json::to_value(&second).unwrap()["journal_query"]["stdout_sha256"]
        );
        let mut changed = sample(encode(true));
        changed.complete_current_boot_pid1_unit_journal[2]["additional_field"] = "changed".into();
        assert!(!first.stable_with(&changed));
    }
    #[test]
    fn retained_evidence_rechecks_frame_and_complete_original_lifecycle() {
        let actor=actor();
        let rows=history(&actor);
        let original=lifecycle(&rows,&actor).unwrap();
        for (manager,exit,label) in [
            (loaded(&actor),0,"loaded-retained-invocation"),
            (collected(&actor),4,"collected-cleared-invocation"),
        ] {
            let evidence=json!({"manager":manager,"manager_query":{"exit_code":exit},
                "complete_current_boot_pid1_unit_journal":rows,"frame":label});
            validate_evidence(&evidence,&actor,&original).unwrap();
            let mut bad=evidence.clone();bad["frame"]=json!("invented");
            assert!(validate_evidence(&bad,&actor,&original).is_err());
            let mut bad=evidence.clone();bad["manager"]["InvocationID"]=json!("f".repeat(32));
            assert!(validate_evidence(&bad,&actor,&original).is_err());
            let mut bad=evidence;bad["complete_current_boot_pid1_unit_journal"]=json!([]);
            assert!(validate_evidence(&bad,&actor,&original).is_err());
        }
    }

}
