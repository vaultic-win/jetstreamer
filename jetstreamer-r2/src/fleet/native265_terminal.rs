//! Independently qualify the completed input test; never rerun its Bank.
use super::native265 as c;
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch265-native-terminal-proof-v1";

pub(super) fn terminal_shape(u: &Value, iid: &str) -> Result<()> {
    ensure!(
        u["Id"] == c::UNIT
            && u["LoadState"] == "loaded"
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && u["InvocationID"] == iid
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0",
        "265 terminal owner is live, replaced, restarted or unsuccessful"
    );
    Ok(())
}
fn journal(b: &BoundFile, iid: &str, pid: u64, boot: &str) -> Result<(Value, u64, u64)> {
    journal_read(b, iid, pid, boot, &c::FsEvidence)
}
fn journal_read(
    b: &BoundFile,
    iid: &str,
    pid: u64,
    boot: &str,
    reader: &impl c::EvidenceReader,
) -> Result<(Value, u64, u64)> {
    c::namespace(&b.path, "horizon-native265-terminal-raw-", "journal.json")?;
    let bytes = reader.bytes(b, 16 << 20)?;
    let rows = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    journal_rows(&rows, iid, pid, boot)
}
fn journal_rows(rows: &[Value], iid: &str, pid: u64, boot: &str) -> Result<(Value, u64, u64)> {
    ensure!(
        !rows.is_empty() && rows.len() <= 4096 && c::hex(iid, 32) && pid > 1,
        "265 journal bounds"
    );
    let mut success = None;
    let mut terminal = None;
    let mut prior = 0;
    for (index, r) in rows.iter().enumerate() {
        ensure!(
            r["_BOOT_ID"] == boot.replace('-', ""),
            "265 foreign boot journal"
        );
        let mono = c::text(r, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        let wall = c::text(r, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        ensure!(mono >= prior, "265 journal rollback");
        prior = mono;
        let msg = c::text(r, "MESSAGE")?;
        if r["_PID"] == "1" {
            ensure!(
                r["_UID"] == "0" && r["UNIT"] == c::UNIT && r["INVOCATION_ID"] == iid,
                "265 foreign manager"
            );
            ensure!(
                !msg.contains("Failed") && !msg.contains("Main process exited"),
                "265 abnormal manager completion"
            );
            if msg == format!("{}: Deactivated successfully.", c::UNIT) {
                ensure!(
                    terminal.replace((index, wall, mono)).is_none(),
                    "265 duplicate completion"
                );
            }
        } else {
            ensure!(
                c::text(r, "_PID")? == pid.to_string()
                    && r["_UID"] == "1000"
                    && r["_SYSTEMD_UNIT"] == c::UNIT
                    && r["_SYSTEMD_INVOCATION_ID"] == iid,
                "265 foreign harness"
            );
            if msg
                == "epoch265 exact cold input completed; native PID1 and complete guard-history acceptance remain required"
            {
                ensure!(
                    success.replace(index).is_none(),
                    "265 duplicate result marker"
                );
            }
        }
    }
    let success = success.context("265 standalone completion missing")?;
    let (terminal, wall, mono) = terminal.context("265 PID1 completion missing")?;
    ensure!(success < terminal, "265 completion order");
    Ok((json!({"standalone_completion_observed":true}), wall, mono))
}
pub(super) fn validate(proof: &Value) -> Result<String> {
    validate_read(proof, &c::FsEvidence)
}
pub(super) fn validate_read(proof: &Value, reader: &impl c::EvidenceReader) -> Result<String> {
    ensure!(
        proof["schema"] == SCHEMA
            && proof["epoch"] == 265
            && proof["unit"] == c::UNIT
            && proof["native_input_qualified"] == true
            && proof["resource_samples_taken"] == 0,
        "265 terminal proof scope"
    );
    c::no_authority(proof)?;
    let origin_binding: BoundFile = serde_json::from_value(proof["running_origin"].clone())?;
    c::namespace(
        &origin_binding.path,
        "horizon-native265-running-",
        "intent.json",
    )?;
    let spec_binding: BoundFile = serde_json::from_value(proof["capture_spec"].clone())?;
    let spec: Spec = serde_json::from_value(reader.json(&spec_binding, true)?)?;
    ensure!(
        spec.schema == "jetstreamer-native265-terminal-capture-spec-v1"
            && spec.running_origin == origin_binding
            && private157::binding(&spec.journal) == proof["journal"]
            && private157::binding(&spec.observer) == proof["observer"]
            && private157::binding(&spec.fleet) == proof["fleet"]
            && private157::binding(&spec.native_result) == proof["native_result"]
            && private157::binding(&spec.guard_history) == proof["guard_history"],
        "265 terminal proof is not bound to its immutable capture spec"
    );
    let origin = reader.json(&origin_binding, true)?;
    let iid = origin["invocation_id"].as_str().context("265 origin IID")?;
    let pid = origin["main_pid"].as_u64().context("265 origin PID")?;
    let claim = PipelineClaim {
        epoch: 265,
        phase: "private-cold-snapshot-verification".into(),
        unit: c::UNIT.into(),
        invocation_id: iid.into(),
        expected_exec_start: origin["expected_exec_start"]
            .as_str()
            .context("265 original command")?
            .into(),
        evidence: vec![origin_binding],
    };
    c::claim_read(&claim, reader)?;
    ensure!(
        proof["invocation_id"] == iid && proof["main_pid"] == pid,
        "265 terminal origin substituted"
    );
    let (checkpoint, clock, monotonic) = journal_read(
        &c::binding(&proof["journal"])?,
        iid,
        pid,
        c::text(&origin, "boot_id")?,
        reader,
    )?;
    let start = c::num(&origin, "producer_start_monotonic_microseconds")?;
    ensure!(
        monotonic >= start
            && monotonic - start <= 2_700_000_000
            && proof["boot_id"] == origin["boot_id"]
            && proof["terminal_unix_microseconds"] == clock
            && proof["terminal_monotonic_microseconds"] == monotonic
            && proof["native_marker"] == checkpoint
            && c::num(proof, "recorded_unix_seconds")? >= clock / 1_000_000,
        "265 terminal owner/clock differs"
    );
    native265_capture::retention_values(&proof["terminal_retention"])?;
    ensure!(
        c::text(&proof["terminal_manager"], "ExecMainPID")? == pid.to_string(),
        "265 original terminal PID lost"
    );
    ensure!(
        proof["terminal_manager"]["ExecMainCode"] == "1"
            && proof["terminal_manager"]["ControlPID"] == "0"
            && proof["terminal_manager"]["Job"] == ""
            && proof["terminal_manager"]["Restart"] == "no"
            && proof["terminal_manager"]["KillMode"] == "control-group"
            && proof["terminal_manager"]["Delegate"] == "no"
            && proof["terminal_manager"]["TriggeredBy"] == "",
        "265 terminal manager work/restart remains"
    );
    terminal_shape(&proof["terminal_manager"], iid)?;
    let (h, _) = c::startup_read(&c::binding(&origin["startup_handoff"])?, reader)?;
    let result = reader.json(&spec.native_result, true)?;
    let worker = native265_history::result(&result, &origin, &h)?;
    native265_history::validate(
        &reader.json(&spec.guard_history, true)?,
        &h,
        &origin,
        monotonic,
        worker,
        reader,
    )?;
    Ok(iid.into())
}
pub(super) fn predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    predecessor_read(previous, p, proof, sampled, now, &c::FsEvidence)
}
pub(super) fn predecessor_read(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
    reader: &impl c::EvidenceReader,
) -> Result<()> {
    let event_binding = p
        .metadata_event
        .as_ref()
        .context("265 terminal event binding")?;
    ensure!(
        reader.json(event_binding, true)? == *proof,
        "265 terminal event is not immutable"
    );
    let spec = reader.json(&c::binding(&proof["capture_spec"])?, true)?;
    ensure!(
        spec["output"].as_str() == event_binding.path.to_str(),
        "265 terminal proof moved from capture destination"
    );
    validate_read(proof, reader)?;
    let recorded = proof["recorded_unix_seconds"]
        .as_u64()
        .context("265 proof capture clock")?;
    ensure!(
        p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && previous["sampled_at_utc"] == sampled
            && proof["sampled_at_utc"] == sampled
            && proof["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|b| proof["fleet"] == private157::binding(b))
            && recorded <= now
            && now - recorded <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t < recorded),
        "265 terminal event replaced/staled resource history"
    );
    let old: Plan = serde_json::from_value(
        reader.json(
            &BoundFile {
                path: previous["plan"].as_str().context("265 prior plan")?.into(),
                sha256: previous["plan_sha256"]
                    .as_str()
                    .context("265 prior digest")?
                    .into(),
            },
            false,
        )?,
    )?;
    ensure!(
        old.pipeline_claims
            .iter()
            .filter(|claim| claim.unit == c::UNIT
                && claim.invocation_id == proof["invocation_id"]
                && claim
                    .evidence
                    .first()
                    .is_some_and(|b| private157::binding(b) == proof["running_origin"]))
            .count()
            == 1,
        "265 terminal proof lacks its exact registered origin"
    );
    ensure!(
        p.first_epoch == old.first_epoch
            && p.last_epoch == old.last_epoch
            && p.schema == old.schema
            && p.observer == old.observer
            && p.pipeline_claims == old.pipeline_claims
            && p.tracked_units == old.tracked_units
            && p.status_receipt_directory == old.status_receipt_directory
            && p.runtime_handoff157 == old.runtime_handoff157
            && p.continuation203_runtime_extension == old.continuation203_runtime_extension
            && p.epoch203_ram_auxiliary.is_none()
            && old.epoch203_ram_auxiliary.is_none()
            && p.diagnostics.len() == old.diagnostics.len()
            && old
                .diagnostics
                .iter()
                .all(|d| p.diagnostics.iter().any(|n| n.epoch == d.epoch
                    && n.unit == d.unit
                    && n.invocation_id == d.invocation_id
                    && n.scratch_path == d.scratch_path
                    && n.launch_receipt == d.launch_receipt))
            && p.gates.len() == old.gates.len(),
        "265 terminal changed unrelated owner/configuration"
    );
    for (epoch, g) in &old.gates {
        let n = p.gates.get(epoch).context("265 terminal gate omitted")?;
        ensure!(
            native265_event::same_operator_status(&n.operator_status, &g.operator_status)
                && serde_json::to_value(&n.reserve_stop)? == serde_json::to_value(&g.reserve_stop)?
                && n.state == g.state
                && g.evidence.iter().all(|e| n.evidence.contains(e))
                && (*epoch == 265 || (n.evidence == g.evidence && n.next_action == g.next_action)),
            "265 terminal changed completion/unrelated gates"
        );
        if *epoch == 265 {
            ensure!(
                n.evidence
                    .iter()
                    .all(|e| g.evidence.contains(e) || p.metadata_event.as_ref() == Some(e)),
                "265 terminal added unrelated evidence"
            );
        }
    }
    Ok(())
}
pub(super) fn census_check(p: &Plan, current: &BTreeMap<String, Value>) -> Result<()> {
    let Some(b) = &p.metadata_event else {
        return Ok(());
    };
    let proof = bound_json(b)?;
    if proof["schema"] != SCHEMA {
        return Ok(());
    }
    ensure!(c::sealed(b)? == proof, "265 terminal event changed");
    let iid = validate(&proof)?;
    terminal_shape(current.get(c::UNIT).context("265 owner omitted")?, &iid)?;
    let previous = bound_json(
        p.previous_fleet
            .as_ref()
            .context("265 terminal prior fleet")?,
    )?;
    native265_capture::peers(&previous, current, c::UNIT)?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    running_origin: BoundFile,
    journal: BoundFile,
    observer: BoundFile,
    fleet: BoundFile,
    native_result: BoundFile,
    guard_history: BoundFile,
    output: PathBuf,
}
pub(super) fn capture() -> Result<()> {
    let (b, self_sha) = publication203::parsed_args("capture-native265-terminal")?;
    let s: Spec = serde_json::from_value(c::sealed(&b)?)?;
    ensure!(
        s.schema == "jetstreamer-native265-terminal-capture-spec-v1"
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-native265-terminal-proof-"))
            && s.output.file_name().is_some_and(|n| n == "proof.json"),
        "265 terminal output scope"
    );
    if s.output.try_exists()? {
        let old = c::sealed(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["capture_spec"] == private157::binding(&b)
                && old["capture_helper_sha256"] == self_sha,
            "265 terminal retry conflicts"
        );
        validate(&old)?;
        return Ok(());
    }
    let origin = c::sealed(&s.running_origin)?;
    let f = bound_json(&s.fleet)?;
    let o = bound_json(&s.observer)?;
    ensure!(
        f["observer_sha256"] == s.observer.sha256 && f["sampled_at_utc"] == o["recorded_at_utc"],
        "265 terminal observer/fleet differs"
    );
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"].as_str().context("265 accepted plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("265 accepted digest")?
            .into(),
    })?)?;
    ensure!(
        p.pipeline_claims
            .iter()
            .filter(|c| c.unit == c::UNIT
                && c.invocation_id == origin["invocation_id"]
                && c.evidence.first() == Some(&s.running_origin))
            .count()
            == 1,
        "265 terminal lacks original registered claim"
    );
    let iid = origin["invocation_id"]
        .as_str()
        .context("265 original IID")?;
    let pid = origin["main_pid"].as_u64().context("265 original PID")?;
    ensure!(
        origin["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "265 terminal belongs to another boot"
    );
    let (checkpoint, clock, monotonic) =
        journal(&s.journal, iid, pid, c::text(&origin, "boot_id")?)?;
    let (h, _) = c::startup(&c::binding(&origin["startup_handoff"])?)?;
    let result = c::sealed(&s.native_result)?;
    let worker = native265_history::result(&result, &origin, &h)?;
    let actual = read_stable_bounded(
        &Path::new(c::ROOT).join("native-result.json"),
        2 << 20,
        "265 actual native result",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&actual)) == s.native_result.sha256,
        "265 result is not the actual worker outcome"
    );
    let history = c::sealed(&s.guard_history)?;
    native265_history::complete_directory(&history, &h)?;
    native265_process::drained(pid, worker)?;
    let before = native265_capture::properties()?;
    let retention = native265_capture::retention()?;
    let mut proof = json!({"schema":SCHEMA,"epoch":265,"unit":c::UNIT,"invocation_id":iid,"main_pid":pid,
        "running_origin":private157::binding(&s.running_origin),"journal":private157::binding(&s.journal),
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"sampled_at_utc":f["sampled_at_utc"],
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"terminal_unix_microseconds":clock,
        "native_marker":checkpoint,"terminal_manager":before,"terminal_retention":retention,"boot_id":origin["boot_id"],"terminal_monotonic_microseconds":monotonic,"capture_spec":private157::binding(&b),"capture_helper_sha256":self_sha,
        "native_input_qualified":true,"resource_samples_taken":0,"native_result":private157::binding(&s.native_result),"guard_history":private157::binding(&s.guard_history)});
    for key in [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        proof[key] = json!(false);
    }
    validate(&proof)?;
    ensure!(
        native265_capture::properties()? == before,
        "265 terminal owner changed during capture"
    );
    native265_process::drained(pid, worker)?;
    native265_history::complete_directory(&history, &h)?;
    private157::immutable_receipt(&s.output, &proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rows() -> Vec<Value> {
        vec![
            json!({"_PID":"42","_UID":"1000","_BOOT_ID":"00000000000000000000000000000001","_SYSTEMD_UNIT":c::UNIT,"_SYSTEMD_INVOCATION_ID":"a".repeat(32),"__REALTIME_TIMESTAMP":"20","__MONOTONIC_TIMESTAMP":"20","MESSAGE":"epoch265 exact cold input completed; native PID1 and complete guard-history acceptance remain required"}),
            json!({"_PID":"1","_UID":"0","_BOOT_ID":"00000000000000000000000000000001","UNIT":c::UNIT,"INVOCATION_ID":"a".repeat(32),"__REALTIME_TIMESTAMP":"30","__MONOTONIC_TIMESTAMP":"30","MESSAGE":format!("{}: Deactivated successfully.",c::UNIT)}),
        ]
    }
    #[test]
    fn native265_terminal_requires_exact_owner_boot_marker_success_and_order() {
        let rows = rows();
        let iid = "a".repeat(32);
        let boot = "00000000-0000-0000-0000-000000000001";
        let (v, wall, mono) = journal_rows(&rows, &iid, 42, boot).unwrap();
        assert_eq!(v["standalone_completion_observed"], true);
        assert_eq!((wall, mono), (30, 30));
        assert!(journal_rows(&rows, &iid, 43, boot).is_err());
        assert!(journal_rows(&rows, &"b".repeat(32), 42, boot).is_err());
        assert!(journal_rows(&rows, &iid, 42, "00000000-0000-0000-0000-000000000002").is_err());
        for i in 0..rows.len() {
            let mut bad = rows.clone();
            bad.remove(i);
            assert!(journal_rows(&bad, &iid, 42, boot).is_err());
        }
        for (i, key, value) in [
            (0, "_PID", json!("43")),
            (0, "_SYSTEMD_UNIT", json!(native210::UNIT)),
            (0, "MESSAGE", json!("epoch265-v1616-native-input slot=1")),
            (
                1,
                "MESSAGE",
                json!("test result: FAILED. 0 passed; 1 failed;"),
            ),
            (1, "_UID", json!("1000")),
            (1, "__MONOTONIC_TIMESTAMP", json!("9")),
        ] {
            let mut bad = rows.clone();
            bad[i][key] = value;
            assert!(journal_rows(&bad, &iid, 42, boot).is_err(), "{i}:{key}");
        }
        let mut duplicate = rows.clone();
        duplicate.push(rows[1].clone());
        assert!(journal_rows(&duplicate, &iid, 42, boot).is_err());
        let mut old = rows.clone();
        old[0]["MESSAGE"] = json!(
            c::text(&rows[0], "MESSAGE")
                .unwrap()
                .replace("epoch265", "epoch210")
        );
        assert!(journal_rows(&old, &iid, 42, boot).is_err());
    }
    #[test]
    fn terminal_owner_cannot_be_replaced_or_collected() {
        let iid = "a".repeat(32);
        let v = json!({"Id":c::UNIT,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","NRestarts":"0","InvocationID":iid,"Result":"success","ExecMainStatus":"0"});
        terminal_shape(&v, &iid).unwrap();
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(terminal_shape(&bad, &iid).is_err(), "{key}");
        }
    }
}
