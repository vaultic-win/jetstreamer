//! Terminal ownership evidence only; process exit is never full-epoch qualification.
use super::singleton210 as c;
use super::singleton227_capture::properties;
use super::*;

pub(super) const SCHEMA: &str = "jetstreamer-private-full210-terminal-proof-v1";
const EXEC_FIELDS: &str =
    "ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic";
const AUTHORITY: [&str; 8] = [
    "runtime_promotion_authorized",
    "full_epoch_qualified",
    "full_replay_qualified",
    "checkpoint_qualified",
    "content_qualified",
    "canonical_sidecar_authorized",
    "publication_authorized",
    "r2_mutations",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    launch: BoundFile,
    journal: BoundFile,
    observer: BoundFile,
    fleet: BoundFile,
    output: PathBuf,
}
fn scope(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == "jetstreamer-full210-terminal-capture-spec-v1"
            && s.output.file_name().is_some_and(|n| n == "proof.json")
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-full210-terminal-proof-"))
            && s.journal
                .path
                .file_name()
                .is_some_and(|n| n == "journal.json")
            && s.journal.path.parent().and_then(Path::parent)
                == Some(Path::new("/var/lib/jetstreamer"))
            && s.journal
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-full210-terminal-raw-")),
        "full210 terminal spec/output/raw journal scope differs"
    );
    Ok(())
}
fn origin(b: &BoundFile) -> Result<(DiagnosticClaim, Value, u64)> {
    let launch = native210::immutable_json(b)?;
    let (claim, checked) = full210_status::claim(b)?;
    let pid = launch["evidence"]["units"][0]["main_pid"]
        .as_u64()
        .filter(|n| *n > 1)
        .context("full210 original main PID")?;
    ensure!(
        launch == checked
            && claim.epoch == 210
            && claim.unit == c::UNIT
            && claim.scratch_path == Path::new(c::ROOT),
        "full210 terminal substituted original launch"
    );
    Ok((claim, launch, pid))
}
/// Cleared InvocationID is allowed only for a loaded successful inactive unit.
/// Callers must additionally supply independently validated journal/execution evidence.
pub(super) fn terminal_shape(u: &Value, iid: &str) -> Result<()> {
    let successful = u["ActiveState"] == "inactive"
        && u["SubState"] == "dead"
        && u["Result"] == "success"
        && u["ExecMainStatus"] == "0";
    let failed = u["ActiveState"] == "failed"
        && u["SubState"] == "failed"
        && u["Result"]
            .as_str()
            .is_some_and(|n| !n.is_empty() && n != "success")
        && u["ExecMainStatus"]
            .as_str()
            .is_some_and(|n| n.parse::<u64>().is_ok());
    ensure!(
        u["Id"] == c::UNIT
            && u["LoadState"] == "loaded"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && (successful || failed)
            && (u["InvocationID"] == iid || (successful && u["InvocationID"] == ""))
            && c::same_command(&u["ExecStart"]),
        "full210 terminal manager is live,replaced,restarted,collected or ambiguous"
    );
    Ok(())
}
fn completion(rows: Vec<Value>, iid: &str, pid: u64) -> Result<Value> {
    ensure!(
        !rows.is_empty() && rows.len() <= 8192,
        "full210 terminal journal row bound"
    );
    // Export only this original invocation plus its PID1 terminal records. A worker
    // forwarding its logs through the parent still has the actual parent journal PID.
    for row in &rows {
        ensure!(
            (row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == c::UNIT
                && row["INVOCATION_ID"] == iid)
                || (row["_SYSTEMD_INVOCATION_ID"] == iid && row["_SYSTEMD_UNIT"] == c::UNIT),
            "full210 journal contains an unrelated invocation/unit"
        );
    }
    ensure!(
        rows.iter().any(
            |r| r["_PID"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(pid)
                && r["_SYSTEMD_INVOCATION_ID"] == iid
        ),
        "full210 journal lacks an original captured main PID record"
    );
    let terminal = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == c::UNIT
                && r["INVOCATION_ID"] == iid
                && (r["MESSAGE"] == format!("{}: Deactivated successfully.", c::UNIT)
                    || r["MESSAGE"].as_str().is_some_and(|s| {
                        s.starts_with(&format!("{}: Failed with result '", c::UNIT))
                            && s.ends_with("'.")
                    }))
        })
        .collect::<Vec<_>>();
    ensure!(
        terminal.len() == 1,
        "full210 journal needs exactly one positive PID1 success/failure"
    );
    Ok(terminal[0].clone())
}
fn journal(b: &BoundFile, iid: &str, pid: u64) -> Result<Value> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0,
        "full210 raw journal is not sealed root-owned evidence"
    );
    let bytes = read_stable_bounded(&b.path, 16 << 20, "full210 terminal raw journal")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "full210 raw journal digest differs"
    );
    let rows = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    completion(rows, iid, pid)
}
fn execution(
    v: &Value,
    manager: &Value,
    end: &Value,
    launch: &Value,
    pid: u64,
    boot: &str,
) -> Result<()> {
    let field = |key: &str| -> Result<u64> {
        Ok(v[key]
            .as_str()
            .context("full210 terminal execution property absent")?
            .parse()?)
    };
    let start = field("ExecMainStartTimestampMonotonic")?;
    let exit = field("ExecMainExitTimestampMonotonic")?;
    let done = end["__MONOTONIC_TIMESTAMP"]
        .as_str()
        .context("full210 PID1 monotonic clock")?
        .parse::<u64>()?;
    let clock = end["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("full210 PID1 realtime clock")?
        .parse::<u64>()?;
    ensure!(field("ExecMainPID")?==pid && start>0 && exit>=start && done>=exit && done-exit<=5_000_000
        && launch["sandbox"]["ExecMainStartTimestampMonotonic"].as_str().and_then(|n|n.parse::<u64>().ok())==Some(start)
        && end["_BOOT_ID"]==boot && boot.len()==32 && boot.bytes().all(|n|n.is_ascii_digit() || (b'a'..=b'f').contains(&n))
        && clock/1_000_000>=launch["recorded_unix_seconds"].as_u64().context("full210 original capture clock")?,
        "full210 latest terminal PID,start,exit,boot or completion clock differs from original launch");
    let expected = if manager["Result"] == "success" {
        format!("{}: Deactivated successfully.", c::UNIT)
    } else {
        format!(
            "{}: Failed with result '{}'.",
            c::UNIT,
            manager["Result"]
                .as_str()
                .context("full210 terminal result")?
        )
    };
    ensure!(
        end["MESSAGE"] == expected,
        "full210 PID1 completion contradicts current manager result"
    );
    Ok(())
}
fn evidence_scope(proof: &Value, s: &Spec) -> Result<()> {
    ensure!(
        proof["launch"] == private157::binding(&s.launch)
            && proof["journal"] == private157::binding(&s.journal)
            && proof["observer"] == private157::binding(&s.observer)
            && proof["fleet"] == private157::binding(&s.fleet),
        "full210 terminal proof substituted immutable capture inputs"
    );
    for key in AUTHORITY {
        ensure!(
            proof[key] == false,
            "full210 terminal proof grants authority:{key}"
        );
    }
    ensure!(
        proof["remote_mutations"] == false
            && proof["replay_launch_authorized"] == false
            && proof["resource_samples_taken"] == 0
            && proof["release_credit_bytes"] == 0,
        "full210 terminal proof grants new observations,capacity credit or unrelated authority"
    );
    Ok(())
}
/// Revalidates original launch, immutable capture spec and sealed raw PID1 journal.
/// Does not inspect live resources or infer runtime/content/archive success.
pub(super) fn validate(proof: &Value) -> Result<(String, u64)> {
    ensure!(
        proof["schema"] == SCHEMA && proof["epoch"] == 210 && proof["unit"] == c::UNIT,
        "foreign full210 terminal proof"
    );
    let spec: BoundFile = serde_json::from_value(proof["capture_spec"].clone())?;
    let s: Spec = serde_json::from_value(native210::immutable_json(&spec)?)?;
    scope(&s)?;
    evidence_scope(proof, &s)?;
    let (d, launch, pid) = origin(&s.launch)?;
    ensure!(
        proof["invocation_id"] == d.invocation_id && proof["main_pid"] == pid,
        "full210 proof changed original IID/PID"
    );
    let end = journal(&s.journal, &d.invocation_id, pid)?;
    ensure!(
        proof["manager_completion"] == end,
        "full210 proof changed sealed PID1 completion"
    );
    terminal_shape(&proof["terminal_manager"], &d.invocation_id)?;
    execution(
        &proof["terminal_execution"],
        &proof["terminal_manager"],
        &end,
        &launch,
        pid,
        proof["terminal_boot_id"]
            .as_str()
            .context("full210 terminal boot")?,
    )?;
    let done = end["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("full210 terminal clock")?
        .parse::<u64>()?;
    ensure!(
        proof["terminal_unix_microseconds"] == done
            && proof["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n >= done / 1_000_000),
        "full210 terminal proof clock differs"
    );
    Ok((d.invocation_id, pid))
}
/// Called during terminal event/census or conditional inactive cleanup, never a new
/// resource observation. Bind the current latest execution, including cleared IID.
pub(super) fn current(proof: &Value, u: &Value) -> Result<()> {
    let (iid, _) = validate(proof)?;
    terminal_shape(u, &iid)?;
    ensure!(
        u == &proof["terminal_manager"],
        "full210 raw terminal manager changed since proof"
    );
    let p = properties(c::UNIT, EXEC_FIELDS)?;
    ensure!(
        json!(p) == proof["terminal_execution"]
            && fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .replace('-', "")
                == proof["terminal_boot_id"]
                    .as_str()
                    .context("full210 terminal boot")?,
        "full210 terminal was replaced, restarted or belongs to another boot"
    );
    Ok(())
}
fn registered(p: &Plan, launch: &BoundFile, iid: &str) -> Result<()> {
    ensure!(
        p.diagnostics
            .iter()
            .filter(|d| d.epoch == 210
                && d.unit == c::UNIT
                && d.invocation_id == iid
                && d.scratch_path == Path::new(c::ROOT)
                && d.launch_receipt == *launch)
            .count()
            == 1,
        "full210 terminal proof lacks exactly one original registered diagnostic"
    );
    Ok(())
}
pub(super) fn capture() -> Result<()> {
    let (b, self_sha) = publication203::parsed_args("capture-full210-terminal")?;
    let s: Spec = serde_json::from_value(native210::immutable_json(&b)?)?;
    scope(&s)?;
    if s.output.try_exists()? {
        let old = native210::immutable_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        validate(&old)?;
        ensure!(
            old["capture_spec"] == private157::binding(&b)
                && old["capture_helper_sha256"] == self_sha,
            "full210 terminal retry conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let (d, launch, pid) = origin(&s.launch)?;
    let f = bound_json(&s.fleet)?;
    let o = bound_json(&s.observer)?;
    ensure!(
        f["schema"] == super::SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"],
        "full210 terminal observer/fleet binding differs"
    );
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"].as_str().context("full210 accepted plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("full210 accepted plan digest")?
            .into(),
    })?)?;
    registered(&p, &s.launch, &d.invocation_id)?;
    let end = journal(&s.journal, &d.invocation_id, pid)?;
    let manager = unit(c::UNIT)?;
    terminal_shape(&manager, &d.invocation_id)?;
    let exec = properties(c::UNIT, EXEC_FIELDS)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    execution(&json!(exec), &manager, &end, &launch, pid, &boot)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut proof = json!({"schema":SCHEMA,"epoch":210,"unit":c::UNIT,"invocation_id":d.invocation_id,"main_pid":pid,
        "launch":private157::binding(&s.launch),"journal":private157::binding(&s.journal),"observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"sampled_at_utc":f["sampled_at_utc"],
        "recorded_unix_seconds":now,"terminal_unix_microseconds":end["__REALTIME_TIMESTAMP"].as_str().context("full210 terminal clock")?.parse::<u64>()?,
        "terminal_manager":manager,"terminal_execution":exec,"terminal_boot_id":boot,"manager_completion":end,
        "capture_spec":private157::binding(&b),"capture_helper_sha256":self_sha,"resource_samples_taken":0,"release_credit_bytes":0});
    for key in AUTHORITY {
        proof[key] = json!(false);
    }
    for key in ["remote_mutations", "replay_launch_authorized"] {
        proof[key] = json!(false);
    }
    validate(&proof)?;
    current(&proof, &unit(c::UNIT)?)?;
    private157::immutable_receipt(&s.output, &proof)
}
fn same_diagnostics(old: &[DiagnosticClaim], new: &[DiagnosticClaim]) -> bool {
    old.len() == new.len()
        && old.iter().all(|d| {
            new.iter()
                .filter(|n| {
                    d.epoch == n.epoch
                        && d.unit == n.unit
                        && d.invocation_id == n.invocation_id
                        && d.scratch_path == n.scratch_path
                        && d.launch_receipt == n.launch_receipt
                })
                .count()
                == 1
        })
}
fn history(old: &Plan, p: &Plan, event: &BoundFile) -> Result<()> {
    ensure!(
        p.schema == old.schema
            && p.first_epoch == old.first_epoch
            && p.last_epoch == old.last_epoch
            && p.observer == old.observer
            && p.pipeline_claims == old.pipeline_claims
            && p.tracked_units == old.tracked_units
            && p.status_receipt_directory == old.status_receipt_directory
            && p.runtime_handoff157 == old.runtime_handoff157
            && p.continuation203_runtime_extension == old.continuation203_runtime_extension
            && p.epoch203_ram_auxiliary.is_none()
            && old.epoch203_ram_auxiliary.is_none()
            && same_diagnostics(&old.diagnostics, &p.diagnostics)
            && p.gates.len() == old.gates.len(),
        "full210 terminal event changed unrelated owners,raw observation or configuration"
    );
    for (epoch, g) in &old.gates {
        let n = p
            .gates
            .get(epoch)
            .context("full210 terminal omitted existing gate")?;
        ensure!(
            n.state == g.state
                && serde_json::to_value(&n.reserve_stop)? == serde_json::to_value(&g.reserve_stop)?
                && g.evidence.iter().all(|e| n.evidence.contains(e))
                && (*epoch == 210 || (n.evidence == g.evidence && n.next_action == g.next_action)),
            "full210 terminal event changed gate authority/history"
        );
        if *epoch == 210 {
            ensure!(matches!(n.state.as_str(),"blocked-qualification"|"failed-needs-repair") && n.evidence.contains(event) && n.evidence.iter().all(|e|g.evidence.contains(e) || e==event),"full210 terminal must retain unresolved qualification and add only its typed event");
        }
    }
    ensure!(
        p.gates.contains_key(&210),
        "full210 terminal event omitted its gate"
    );
    Ok(())
}
pub(super) fn predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    let (iid, _) = validate(proof)?;
    let event = p
        .metadata_event
        .as_ref()
        .context("full210 terminal event missing")?;
    ensure!(
        bound_json(event)? == *proof,
        "full210 metadata event differs from actual terminal proof"
    );
    let recorded = proof["recorded_unix_seconds"]
        .as_u64()
        .context("full210 terminal capture clock")?;
    ensure!(
        previous["schema"] == super::SCHEMA
            && p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && previous["sampled_at_utc"] == sampled
            && proof["sampled_at_utc"] == sampled
            && proof["observer"] == private157::binding(&p.observer)
            && previous["observer_receipt"].as_str() == p.observer.path.to_str()
            && previous["observer_sha256"] == p.observer.sha256
            && p.previous_fleet
                .as_ref()
                .is_some_and(|b| proof["fleet"] == private157::binding(b))
            && recorded <= now
            && now - recorded <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < recorded),
        "full210 terminal event replaced or staled resource history"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"]
            .as_str()
            .context("full210 old plan")?
            .into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("full210 old plan digest")?
            .into(),
    })?)?;
    registered(
        &old,
        &serde_json::from_value(proof["launch"].clone())?,
        &iid,
    )?;
    history(&old, p, event)
}
pub(super) fn census_check(p: &Plan, units: &BTreeMap<String, Value>) -> Result<()> {
    if let Some(b) = &p.metadata_event {
        let proof = bound_json(b)?;
        if proof["schema"] == SCHEMA {
            current(
                &proof,
                units
                    .get(c::UNIT)
                    .context("full210 terminal owner omitted")?,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn command() -> Value {
        json!(format!("{} ; ignore_errors=no }}", c::command()))
    }
    fn manager() -> Value {
        json!({"Id":c::UNIT,"LoadState":"loaded","MainPID":"0","NRestarts":"0","InvocationID":"","ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainStatus":"0","ExecStart":command()})
    }
    fn completion_row(iid: &str) -> Value {
        json!({"_PID":"1","_UID":"0","UNIT":c::UNIT,"INVOCATION_ID":iid,"MESSAGE":format!("{}: Deactivated successfully.",c::UNIT),"__MONOTONIC_TIMESTAMP":"2000100","__REALTIME_TIMESTAMP":"3000000","_BOOT_ID":"b".repeat(32)})
    }
    #[test]
    fn cleared_id_requires_loaded_success_and_failure_keeps_its_exact_id() {
        let iid = "a".repeat(32);
        let good = manager();
        terminal_shape(&good, &iid).unwrap();
        for (k, v) in [
            ("LoadState", json!("not-found")),
            ("InvocationID", json!("c".repeat(32))),
            ("MainPID", json!("42")),
            ("NRestarts", json!("1")),
            ("ExecMainStatus", json!("1")),
            ("ActiveState", json!("active")),
            ("ExecStart", json!("other")),
        ] {
            let mut bad = good.clone();
            bad[k] = v;
            assert!(terminal_shape(&bad, &iid).is_err(), "{k}");
        }
        let mut failed = good;
        failed["ActiveState"] = json!("failed");
        failed["SubState"] = json!("failed");
        failed["Result"] = json!("oom-kill");
        failed["ExecMainStatus"] = json!("9");
        assert!(terminal_shape(&failed, &iid).is_err());
        failed["InvocationID"] = json!(iid);
        terminal_shape(&failed, &iid).unwrap();
    }
    #[test]
    fn raw_journal_requires_unique_pid1_completion_and_original_main_pid() {
        let iid = "a".repeat(32);
        let child = json!({"_PID":"42","_SYSTEMD_UNIT":c::UNIT,"_SYSTEMD_INVOCATION_ID":iid});
        let end = completion_row(&iid);
        assert_eq!(
            completion(vec![child.clone(), end.clone()], &iid, 42).unwrap(),
            end
        );
        assert!(completion(vec![end.clone()], &iid, 42).is_err());
        assert!(completion(vec![child.clone(), end.clone(), end.clone()], &iid, 42).is_err());
        for (k, v) in [
            ("_PID", json!("2")),
            ("_UID", json!("1000")),
            ("UNIT", json!(native210::UNIT)),
            ("INVOCATION_ID", json!("c".repeat(32))),
            ("MESSAGE", json!("ordinary exit text")),
        ] {
            let mut bad = end.clone();
            bad[k] = v;
            assert!(
                completion(vec![child.clone(), bad], &iid, 42).is_err(),
                "{k}"
            );
        }
    }
    #[test]
    fn latest_execution_cannot_borrow_old_completion_or_a_replacement_pid() {
        let iid = "a".repeat(32);
        let end = completion_row(&iid);
        let m = manager();
        let launch = json!({"recorded_unix_seconds":2,"sandbox":{"ExecMainStartTimestampMonotonic":"1000000"}});
        let exec = json!({"ExecMainPID":"42","ExecMainStartTimestampMonotonic":"1000000","ExecMainExitTimestampMonotonic":"2000000"});
        execution(&exec, &m, &end, &launch, 42, &"b".repeat(32)).unwrap();
        let mut failed = m.clone();
        failed["ActiveState"] = json!("failed");
        failed["SubState"] = json!("failed");
        failed["Result"] = json!("oom-kill");
        failed["ExecMainStatus"] = json!("9");
        failed["InvocationID"] = json!(iid);
        let mut failed_end = end.clone();
        failed_end["MESSAGE"] = json!(format!("{}: Failed with result 'oom-kill'.", c::UNIT));
        execution(&exec, &failed, &failed_end, &launch, 42, &"b".repeat(32)).unwrap();
        assert!(execution(&exec, &m, &failed_end, &launch, 42, &"b".repeat(32)).is_err());

        for (k, v) in [
            ("ExecMainPID", json!("43")),
            ("ExecMainStartTimestampMonotonic", json!("1000001")),
            ("ExecMainExitTimestampMonotonic", json!("2000101")),
        ] {
            let mut bad = exec.clone();
            bad[k] = v;
            assert!(
                execution(&bad, &m, &end, &launch, 42, &"b".repeat(32)).is_err(),
                "{k}"
            );
        }
        assert!(execution(&exec, &m, &end, &launch, 42, &"c".repeat(32)).is_err());
        let mut stale = end;
        stale["__MONOTONIC_TIMESTAMP"] = json!("8000000");
        assert!(execution(&exec, &m, &stale, &launch, 42, &"b".repeat(32)).is_err());
    }
    #[test]
    fn terminal_event_preserves_gate_and_all_prior_claims() {
        let b = json!({"path":"/observer","sha256":"a".repeat(64)});
        let ev: BoundFile =
            serde_json::from_value(json!({"path":"/event","sha256":"b".repeat(64)})).unwrap();
        let v = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,"observer":b,"output":"/old","status_receipt_directory":"/receipts","tracked_units":[c::UNIT],"gates":{"210":{"state":"blocked-qualification","next_action":"repair","evidence":[b]}}});
        let old: Plan = serde_json::from_value(v.clone()).unwrap();
        let mut new = v;
        new["gates"]["210"]["evidence"]
            .as_array_mut()
            .unwrap()
            .push(private157::binding(&ev));
        let p: Plan = serde_json::from_value(new.clone()).unwrap();
        history(&old, &p, &ev).unwrap();
        for (state, key) in [
            (json!("post-replay-pipeline"), "state"),
            (json!([]), "evidence"),
        ] {
            let mut bad = new.clone();
            bad["gates"]["210"][key] = state;
            let p: Plan = serde_json::from_value(bad).unwrap();
            assert!(history(&old, &p, &ev).is_err());
        }
        let mut bad = new;
        bad["tracked_units"] = json!([]);
        assert!(history(&old, &serde_json::from_value(bad).unwrap(), &ev).is_err());
    }
}
