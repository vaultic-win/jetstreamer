//! Epoch 204 resource release only. Terminal failure never qualifies an archive.
use super::*;
mod failed_history;
const IID: &str = "e70aaf097e7c4583b216aba454145910";
const LAUNCH: &str = "/var/lib/jetstreamer/horizon-native223-prefix-capture-actual-v1/launch.json";
const LAUNCH_SHA: &str = "a629f2a5eb1a6be5e3ec38e66769f0698841fb7ccc8d43110ac3bfd73df99ac3";

fn epoch223_job(name: &str) -> bool {
    // Fail closed for every pending epoch 223 owner namespace, including
    // archive, native and warmup223 units, rather than just qualify units.
    name.split(|c: char| !c.is_ascii_digit())
        .any(|part| part == "223")
}

fn no_replacement(f: &Value) -> Result<()> {
    for row in f["active"]
        .as_array()
        .context("epoch 204 complete peer census missing")?
    {
        if row["epoch"] != 223 {
            continue;
        }
        let owner = singleton227_admission::active_owner(row)?;
        ensure!(
            owner["Id"] != prefix223_native20::UNIT
                && matches!(
                    row["phase"].as_str(),
                    Some(
                        "private-verification-only"
                            | "full-verification"
                            | "plugin-verification"
                            | "local-publication"
                            | "upload-readback"
                    )
                ),
            "epoch 204 terminal release cannot hide a replacement epoch 223 replay"
        );
    }
    Ok(())
}

fn terminal_shape(current: &Value, raw: &[u8]) -> Result<&'static str> {
    ensure!(
        current["Id"] == prefix223_native20::UNIT
            && current["LoadState"] == "loaded"
            && current["MainPID"] == "0"
            && current["NRestarts"] == "0"
            && (current["InvocationID"] == IID || current["InvocationID"] == "")
            && matches!(current["ActiveState"].as_str(), Some("inactive" | "failed"))
            && matches!(current["SubState"].as_str(), Some("dead" | "failed"))
            && prefix223_native20::same_command(&current["ExecStart"]),
        "epoch 204 release needs the exact terminal original native 223 owner"
    );
    ensure!(
        raw.len() <= 4 << 20,
        "native 223 terminal manager history exceeds bound"
    );
    let rows = serde_json::Deserializer::from_slice(raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows
        .iter()
        .any(|r| r["MESSAGE_ID"] == failed_history::FAILURE_ID && r["INVOCATION_ID"] == IID)
    {
        failed_history::authenticate(current, &rows)?;
        return Ok("failed-needs-repair");
    }
    capped204205_work::exact_terminal_manager(raw, prefix223_native20::UNIT, IID)?;
    let mut stopped = false;
    let mut failure = None;
    let mut success = false;
    for row in rows.iter().filter(|r| r["INVOCATION_ID"] == IID) {
        let message = row["MESSAGE"].as_str().unwrap_or("");
        stopped |= row["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286"
            && row["JOB_TYPE"] == "stop"
            && row["JOB_RESULT"] == "done";
        if row["MESSAGE_ID"] == "be02cf6855d2428ba40df7e9d022f03d" {
            failure = message
                .strip_prefix(&format!(
                    "{}: Failed with result '",
                    prefix223_native20::UNIT
                ))
                .and_then(|s| s.strip_suffix("'."));
        }
        success |= row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && message == format!("{}: Deactivated successfully.", prefix223_native20::UNIT);
    }
    let result = current["Result"]
        .as_str()
        .context("native 223 terminal result missing")?;
    current["ExecMainStatus"]
        .as_str()
        .context("native 223 terminal exit status missing")?
        .parse::<u64>()?;
    if let Some(failure) = failure {
        ensure!(
            failure == result && !matches!(result, "" | "success"),
            "native 223 failure journal and actual result differ"
        );
        return Ok("failed-needs-repair");
    }
    if stopped {
        return Ok("stopped-needs-repair");
    }
    ensure!(
        success && result == "success" && current["ExecMainStatus"] == "0",
        "native 223 has no matching positive terminal outcome"
    );
    Ok("natural-success")
}

pub(super) fn prove_terminal(f: &Value) -> Result<Value> {
    no_replacement(f)?;
    let claim = DiagnosticClaim {
        epoch: 223,
        unit: prefix223_native20::UNIT.into(),
        invocation_id: IID.into(),
        scratch_path: prefix223_native20::ROOT.into(),
        launch_receipt: BoundFile {
            path: LAUNCH.into(),
            sha256: LAUNCH_SHA.into(),
        },
    };
    checked_diagnostic_launch(&claim)?;
    let current = unit(prefix223_native20::UNIT)?;
    let output = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "_PID=1",
            &format!("UNIT={}", prefix223_native20::UNIT),
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 4 << 20,
        "native 223 complete terminal manager history unavailable"
    );
    let outcome = terminal_shape(&current, &output.stdout)?;
    if outcome != "natural-success" {
        ensure!(
            f["epochs"]
                .as_array()
                .context("epoch 204 repair ledger missing")?
                .iter()
                .any(|e| e["epoch"] == 223 && e["state"] == "failed-needs-repair"),
            "retain failed or stopped native 223 in the repair ledger before resource release"
        );
    }
    inactive_status::no_pending_owner_trigger(prefix223_native20::UNIT, false)?;
    let group = capped204205_work::empty_terminal_cgroup(prefix223_native20::UNIT)?;
    let references = jetstreamer_horizon_observe::process_references::scan(
        Path::new("/proc"),
        Path::new(prefix223_native20::ROOT),
    )?;
    ensure!(
        references.references.is_empty(),
        "native 223 root still has process references"
    );
    let pending = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "list-jobs",
            "--no-legend",
            "--no-pager",
            "--plain",
            "--full",
        ])
        .output()?;
    ensure!(
        pending.status.success() && pending.stdout.len() <= 1 << 20,
        "native 223 pending replacement census unavailable"
    );
    let jobs = inactive_status::queued_job_units(&pending.stdout)?;
    ensure!(
        !jobs.iter().any(|n| epoch223_job(n)),
        "native 223 replacement is pending"
    );
    ensure!(
        current == unit(prefix223_native20::UNIT)?,
        "native 223 terminal owner changed"
    );
    Ok(
        json!({"schema":"jetstreamer-capped204-native223-resource-terminal-v1",
        "unit":prefix223_native20::UNIT,"invocation_id":IID,"outcome":outcome,
        "original_launch":{"path":LAUNCH,"sha256":LAUNCH_SHA},"current_unit":current,
        "manager_journal_sha256":hex_lower(&Sha256::digest(&output.stdout)),
        "manager_journal":std::str::from_utf8(&output.stdout)?,"cgroup":group,
        "process_references":references,"pending_job_units":jobs,
        "released_owner_only":true,"failure_history_preserved":true,
        "archive_qualification_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}

/// Replay the immutable release evidence without another process or service
/// observation. The original proof writer still owns the complete live checks.
pub(super) fn validate_terminal_saved(proof: &Value) -> Result<()> {
    let raw = proof["manager_journal"]
        .as_str()
        .context("native 223 release manager history absent")?
        .as_bytes();
    ensure!(
        raw.len() <= 4 << 20
            && proof["schema"] == "jetstreamer-capped204-native223-resource-terminal-v1"
            && proof["unit"] == prefix223_native20::UNIT
            && proof["invocation_id"] == IID
            && proof["original_launch"] == json!({"path":LAUNCH,"sha256":LAUNCH_SHA})
            && proof["manager_journal_sha256"] == hex_lower(&Sha256::digest(raw))
            && proof["outcome"] == terminal_shape(&proof["current_unit"], raw)?
            && proof["cgroup"]["path"]
                == format!("/sys/fs/cgroup/system.slice/{}", prefix223_native20::UNIT)
            && matches!(
                proof["cgroup"]["state"].as_str(),
                Some("absent" | "unpopulated")
            )
            && (proof["cgroup"]["state"] == "absent"
                || canonical_digest(&proof["cgroup"]["events_sha256"]))
            && proof["process_references"]["references"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && proof["process_references"]["inspected_processes"]
                .as_u64()
                .is_some()
            && proof["pending_job_units"]
                .as_array()
                .is_some_and(|jobs| jobs
                    .iter()
                    .all(|name| name.as_str().is_some_and(|name| !epoch223_job(name))))
            && proof["released_owner_only"] == true
            && proof["failure_history_preserved"] == true
            && proof["archive_qualification_authorized"] == false
            && proof["publication_authorized"] == false
            && proof["r2_mutations"] == false,
        "native 223 saved resource release proof is incomplete or changed"
    );
    Ok(())
}

#[cfg(test)]
pub(super) fn terminal_fixture() -> Value {
    let raw = tests::journal(
        "7ad2d189f7e94e70a38c781354912448",
        format!("{}: Deactivated successfully.", prefix223_native20::UNIT),
    );
    json!({"schema":"jetstreamer-capped204-native223-resource-terminal-v1",
        "unit":prefix223_native20::UNIT,"invocation_id":IID,"outcome":"natural-success",
        "original_launch":{"path":LAUNCH,"sha256":LAUNCH_SHA},"current_unit":tests::current(),
        "manager_journal_sha256":hex_lower(&Sha256::digest(&raw)),"manager_journal":String::from_utf8(raw).unwrap(),
        "cgroup":{"state":"absent","path":format!("/sys/fs/cgroup/system.slice/{}",prefix223_native20::UNIT)},
        "process_references":{"inspected_processes":12,"references":[]},"pending_job_units":[],
        "released_owner_only":true,"failure_history_preserved":true,"archive_qualification_authorized":false,
        "publication_authorized":false,"r2_mutations":false})
}

pub(super) fn required(f: &Value, total: u64, growth: u64, candidate: u64) -> Result<(u64, Value)> {
    ensure!(
        total > 0 && matches!(candidate, n if n == 16 << 30 || n == 64 << 30),
        "epoch 204 stage hard memory profile differs"
    );
    let original_live = f["active"]
        .as_array()
        .context("epoch 204 active census missing")?
        .iter()
        .any(|r| {
            singleton227_admission::active_owner(r)
                .is_ok_and(|u| u["Id"] == prefix223_native20::UNIT)
        });
    if original_live {
        let (n, mut p) = singleton210_memory::delivery_required(f, total, growth, candidate)?;
        p["schema"] = json!("jetstreamer-capped204-v4-live-native223-memory-v1");
        return Ok((n, p));
    }
    let terminal = prove_terminal(f)?;
    let baseline = total.div_ceil(10);
    let required = baseline
        .checked_add(growth)
        .and_then(|n| n.checked_add(candidate))
        .context("epoch 204 terminal memory arithmetic overflow")?;
    Ok((
        required,
        json!({"schema":"jetstreamer-capped204-v4-terminal-native223-memory-v1",
        "host_baseline_bytes":baseline,"effective_available_memory_floor_bytes":baseline,
        "protected_existing_hard_memory_growth_bytes":growth,"candidate_stage_hard_memory_bytes":candidate,
        "required_available_memory_bytes":required,"positive_terminal":terminal,
        "candidate_guard_hard_memory_bytes":0,"floor_counted_once":true,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn current() -> Value {
        json!({"Id":prefix223_native20::UNIT,"LoadState":"loaded",
        "MainPID":"0","NRestarts":"0","InvocationID":IID,"ActiveState":"inactive",
        "SubState":"dead","Result":"success","ExecMainStatus":"0",
        "ExecStart":format!("{} ; ignore_errors=no }}", prefix223_native20::command())})
    }
    pub(super) fn journal(terminal: &str, message: String) -> Vec<u8> {
        let row = |time: &str, id: &str, msg: String| {
            json!({"_PID":"1","_UID":"0",
            "UNIT":prefix223_native20::UNIT,"INVOCATION_ID":IID,"__REALTIME_TIMESTAMP":time,
            "__CURSOR":time,"MESSAGE_ID":id,"MESSAGE":msg})
        };
        format!(
            "{}\n{}\n",
            row(
                "1000000",
                "39f53479d3a045ac8e11786248231fbf",
                "Started".into()
            ),
            row("2000000", terminal, message)
        )
        .into_bytes()
    }
    #[test]
    fn exact_failure_and_success_release_ownership_without_promoting_archives() {
        let success = journal(
            "7ad2d189f7e94e70a38c781354912448",
            format!("{}: Deactivated successfully.", prefix223_native20::UNIT),
        );
        assert_eq!(
            terminal_shape(&current(), &success).unwrap(),
            "natural-success"
        );
        let failed = journal(
            "be02cf6855d2428ba40df7e9d022f03d",
            format!(
                "{}: Failed with result 'exit-code'.",
                prefix223_native20::UNIT
            ),
        );
        let mut state = current();
        state["Result"] = json!("exit-code");
        state["ExecMainStatus"] = json!("1");
        assert_eq!(
            terminal_shape(&state, &failed).unwrap(),
            "failed-needs-repair"
        );
        assert!(terminal_shape(&current(), &failed).is_err());
        for (key, value) in [
            ("MainPID", "42"),
            ("NRestarts", "1"),
            ("ActiveState", "activating"),
            ("InvocationID", "foreign"),
            ("LoadState", "not-found"),
        ] {
            let mut bad = current();
            bad[key] = json!(value);
            assert!(terminal_shape(&bad, &success).is_err());
        }
    }
    #[test]
    fn explicit_stop_releases_only_with_exact_completed_stop_job() {
        let raw = journal(
            "9d1aaa27d60140bd96365438aad20286",
            "Stopped original owner".into(),
        );
        let mut rows: Vec<Value> = serde_json::Deserializer::from_slice(&raw)
            .into_iter::<Value>()
            .map(|row| row.unwrap())
            .collect();
        rows[1]["JOB_TYPE"] = json!("stop");
        rows[1]["JOB_RESULT"] = json!("done");
        let encode = |rows: &[Value]| {
            rows.iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>()
                .into_bytes()
        };
        assert_eq!(
            terminal_shape(&current(), &encode(&rows)).unwrap(),
            "stopped-needs-repair"
        );
        rows[1]["JOB_RESULT"] = json!("failed");
        assert!(terminal_shape(&current(), &encode(&rows)).is_err());
        rows[1]["JOB_RESULT"] = json!("done");
        rows[1]["INVOCATION_ID"] = json!("ffffffffffffffffffffffffffffffff");
        assert!(terminal_shape(&current(), &encode(&rows)).is_err());
    }
    #[test]
    fn pending_epoch_223_namespace_is_complete_and_century_exact() {
        for name in [
            "horizon-qualify-223-repair.service",
            "archive-223-native.service",
            "horizon-warmup223-native20-v2.service",
            "horizon-singleton-223.service",
        ] {
            assert!(epoch223_job(name));
        }
        assert!(!epoch223_job("horizon-qualify-1223.service"));
        assert!(!epoch223_job("horizon-qualify-224.service"));
    }
    #[test]
    fn replacement_and_unknown_epoch_223_roles_are_never_zero_growth() {
        assert!(no_replacement(&json!({"active":[]})).is_ok());
        let bad = json!({"active":[{"epoch":223,"phase":"replay","producer":{"Id":"replacement.service"}}]});
        assert!(no_replacement(&bad).is_err());
    }
    #[test]
    fn saved_release_cannot_drop_custody_checks_or_change_the_original_owner() {
        let proof = terminal_fixture();
        validate_terminal_saved(&proof).unwrap();
        for (path, value) in [
            ("/current_unit/MainPID", json!("42")),
            ("/current_unit/InvocationID", json!("replacement")),
            ("/outcome", json!("failed-needs-repair")),
            ("/manager_journal_sha256", json!("0".repeat(64))),
            ("/cgroup/state", json!("populated")),
            ("/cgroup/path", json!("/sys/fs/cgroup/other")),
            ("/process_references/references", json!(["still open"])),
            ("/pending_job_units", json!(["archive-223-native.service"])),
            ("/archive_qualification_authorized", json!(true)),
        ] {
            let mut bad = proof.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(validate_terminal_saved(&bad).is_err(), "{path}");
        }
    }
}
