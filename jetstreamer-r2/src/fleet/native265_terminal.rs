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
    let spec_binding: BoundFile = serde_json::from_value(proof["capture_spec"].clone())?;
    let spec: Spec = serde_json::from_value(reader.json(&spec_binding, true)?)?;
    spec_shape(&spec)?;
    ensure!(
        private157::binding(&spec.journal) == proof["journal"]
            && private157::binding(&spec.observer) == proof["observer"]
            && private157::binding(&spec.fleet) == proof["fleet"]
            && private157::binding(&spec.native_result) == proof["native_result"]
            && private157::binding(&spec.guard_history) == proof["guard_history"],
        "265 terminal proof is not bound to its immutable capture spec"
    );
    let (origin, h) = owner(
        &spec,
        c::text(proof, "capture_helper_sha256")?,
        c::num(proof, "recorded_unix_seconds")?,
        reader,
    )?;
    if let Some(b) = &spec.running_origin {
        ensure!(
            proof["running_origin"] == private157::binding(b)
                && proof.get("startup_handoff").is_none()
                && proof.get("consumer_transition").is_none(),
            "265 legacy terminal origin differs"
        );
    } else {
        ensure!(
            proof.get("running_origin").is_none()
                && proof["startup_handoff"]
                    == private157::binding(spec.startup_handoff.as_ref().unwrap())
                && proof["consumer_transition"]
                    == private157::binding(spec.consumer_transition.as_ref().unwrap())
                && proof["original_launch_clock_preserved"] == true,
            "265 direct terminal recovery invented or substituted a running origin"
        );
    }
    let iid = c::text(&origin, "invocation_id")?;
    let pid = c::num(&origin, "main_pid")?;
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
    let start = if spec.running_origin.is_some() {
        c::num(&origin, "producer_start_monotonic_microseconds")?
    } else {
        // Original launch-plan issue precedes process start. This is a stricter
        // runtime bound; it is not a fabricated ExecMainStart observation.
        c::num(&origin, "runtime_bound_origin_monotonic_microseconds")?
    };
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
    if proof.get("running_origin").is_none() {
        ensure!(
            spec["schema"] == TERMINAL_RECOVERY_SPEC
                && !old
                    .pipeline_claims
                    .iter()
                    .any(|c| c.unit == c::UNIT || c.epoch == 265),
            "265 direct terminal recovery conflicts with registered ownership"
        );
        for row in previous["active"]
            .as_array()
            .context("265 prior active census")?
        {
            let overlaps = if let Some(epoch) = row["epoch"].as_u64() {
                epoch == 265
            } else {
                parse_observer_claim_range(row["range"].as_str().context("265 prior owner range")?)?
                    .contains(&265)
            };
            ensure!(
                !overlaps,
                "265 terminal recovery overlaps a prior active owner"
            );
        }
    } else {
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
    }
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
    running_origin: Option<BoundFile>,
    startup_handoff: Option<BoundFile>,
    consumer_transition: Option<BoundFile>,
    journal: BoundFile,
    observer: BoundFile,
    fleet: BoundFile,
    native_result: BoundFile,
    guard_history: BoundFile,
    output: PathBuf,
}
const TERMINAL_RECOVERY_SPEC: &str = "jetstreamer-native265-terminal-capture-spec-v2";
fn spec_shape(s: &Spec) -> Result<()> {
    ensure!(
        (s.schema == "jetstreamer-native265-terminal-capture-spec-v1"
            && s.running_origin.is_some()
            && s.startup_handoff.is_none()
            && s.consumer_transition.is_none())
            || (s.schema == TERMINAL_RECOVERY_SPEC
                && s.running_origin.is_none()
                && s.startup_handoff.is_some()
                && s.consumer_transition.is_some()),
        "265 terminal spec mixes historical and running origins"
    );
    Ok(())
}
fn recovery_source(s: &Spec) -> Result<native265_recovery::Source> {
    spec_shape(s)?;
    Ok(native265_recovery::Source {
        startup_handoff: s
            .startup_handoff
            .clone()
            .context("265 original startup required")?,
        consumer_transition: s
            .consumer_transition
            .clone()
            .context("265 successor proof required")?,
    })
}
/// The direct route derives only original owner identity from the real startup
/// handoff. It never creates or qualifies a running-origin receipt.
fn owner(
    s: &Spec,
    helper: &str,
    wall: u64,
    reader: &impl c::EvidenceReader,
) -> Result<(Value, Value)> {
    spec_shape(s)?;
    if let Some(b) = &s.running_origin {
        let origin = reader.json(b, true)?;
        let claim = PipelineClaim {
            epoch: 265,
            phase: "private-cold-snapshot-verification".into(),
            unit: c::UNIT.into(),
            invocation_id: c::text(&origin, "invocation_id")?.into(),
            expected_exec_start: c::text(&origin, "expected_exec_start")?.into(),
            evidence: vec![b.clone()],
        };
        c::claim_read(&claim, reader)?;
        let (h, _) = c::startup_read(&c::binding(&origin["startup_handoff"])?, reader)?;
        Ok((origin, h))
    } else {
        let source = recovery_source(s)?;
        let (h, a) = c::startup_read(&source.startup_handoff, reader)?;
        native265_recovery::transition(&source, &h, &a, helper, wall, reader)?;
        let plan = reader.json(&c::binding(&h["startup_plan"])?, true)?;
        let owner = json!({"invocation_id":h["invocation_id"],"main_pid":h["main_pid"],"boot_id":a["boot_id"],"runtime_bound_origin_monotonic_microseconds":c::num(&plan,"issued_monotonic_us")?});
        Ok((owner, h))
    }
}
pub(super) fn capture() -> Result<()> {
    let (b, self_sha) = publication203::parsed_args("capture-native265-terminal")?;
    let s: Spec = serde_json::from_value(c::sealed(&b)?)?;
    spec_shape(&s)?;
    ensure!(
        s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
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
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (origin, h) = owner(&s, &self_sha, now, &c::FsEvidence)?;
    if s.running_origin.is_none() {
        let source = recovery_source(&s)?;
        let (_, a) = c::startup(&source.startup_handoff)?;
        native265_recovery::publication(&source, &h, &a, &self_sha, now)?;
    }
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
    if let Some(running) = &s.running_origin {
        ensure!(
            p.pipeline_claims
                .iter()
                .filter(|c| c.unit == c::UNIT
                    && c.invocation_id == origin["invocation_id"]
                    && c.evidence.first() == Some(running))
                .count()
                == 1,
            "265 terminal lacks original registered claim"
        );
    } else {
        ensure!(
            !p.pipeline_claims
                .iter()
                .any(|c| c.unit == c::UNIT || c.epoch == 265),
            "265 terminal recovery overlaps a registered owner"
        );
        for row in f["active"].as_array().context("265 prior active census")? {
            let overlaps = if let Some(epoch) = row["epoch"].as_u64() {
                epoch == 265
            } else {
                parse_observer_claim_range(row["range"].as_str().context("265 prior owner range")?)?
                    .contains(&265)
            };
            ensure!(
                !overlaps,
                "265 terminal recovery overlaps a prior active owner"
            );
        }
    }
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
    if s.running_origin.is_none() {
        actual_guard_history(&history, &h)?;
    }
    native265_history::complete_directory(&history, &h)?;
    native265_process::drained(pid, worker)?;
    let before = native265_capture::properties()?;
    let retention = native265_capture::retention()?;
    let mut proof = json!({"schema":SCHEMA,"epoch":265,"unit":c::UNIT,"invocation_id":iid,"main_pid":pid,
        "journal":private157::binding(&s.journal),
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"sampled_at_utc":f["sampled_at_utc"],
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"terminal_unix_microseconds":clock,
        "native_marker":checkpoint,"terminal_manager":before,"terminal_retention":retention,"boot_id":origin["boot_id"],"terminal_monotonic_microseconds":monotonic,"capture_spec":private157::binding(&b),"capture_helper_sha256":self_sha,
        "native_input_qualified":true,"resource_samples_taken":0,"native_result":private157::binding(&s.native_result),"guard_history":private157::binding(&s.guard_history)});
    if let Some(running) = &s.running_origin {
        proof["running_origin"] = private157::binding(running);
    } else {
        proof["startup_handoff"] = private157::binding(s.startup_handoff.as_ref().unwrap());
        proof["consumer_transition"] = private157::binding(s.consumer_transition.as_ref().unwrap());
        proof["original_launch_clock_preserved"] = json!(true);
    }
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
    if s.running_origin.is_none() {
        actual_guard_history(&history, &h)?;
    }
    private157::immutable_receipt(&s.output, &proof)
}

/// A terminal-only timer stop must already have completed. Never stop a firing
/// guard here: retaining every successful firing is part of the evidence gate.
fn final_guard_invocation(manager: &Value, rows: &[Value]) -> Result<String> {
    let start = rows
        .iter()
        .rev()
        .find(|r| {
            r["MESSAGE"]
                .as_str()
                .is_some_and(|m| m.starts_with(&format!("Starting {} -", c::GUARD_UNIT)))
        })
        .context("265 final guard start absent")?;
    let end = rows
        .iter()
        .rev()
        .find(|r| r["MESSAGE"] == format!("{}: Deactivated successfully.", c::GUARD_UNIT))
        .context("265 final guard completion absent")?;
    let iid = c::text(start, "INVOCATION_ID")?;
    ensure!(
        c::hex(iid, 32)
            && end["INVOCATION_ID"] == iid
            && c::text(end, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?
                > c::text(start, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?,
        "265 final guard invocation incomplete"
    );
    // Stopping the timer can release PID1's last inactive oneshot invocation.
    // Only its fully reset display is accepted, using the complete real journal
    // as identity evidence; a different nonempty invocation still fails.
    ensure!(
        manager["InvocationID"] == iid
            || (manager["InvocationID"] == ""
                && manager["ExecMainPID"] == "0"
                && manager["ExecMainStartTimestampMonotonic"] == "0"
                && manager["ExecMainExitTimestampMonotonic"] == "0"),
        "265 final guard manager identity differs"
    );
    Ok(iid.to_owned())
}
fn actual_guard_history(bundle: &Value, h: &Value) -> Result<()> {
    let timer = json!(singleton227_capture::properties(
        "horizon-native265-protective-v1.timer",
        "LoadState,ActiveState,SubState,Unit,Job,DropInPaths"
    )?);
    ensure!(
        timer["LoadState"] == "loaded"
            && timer["ActiveState"] == "inactive"
            && timer["SubState"] == "dead"
            && timer["Unit"] == c::GUARD_UNIT
            && timer["Job"] == ""
            && timer["DropInPaths"] == "",
        "265 terminal guard timer not stably stopped"
    );
    let fields = "LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Job,Result,ExecMainStatus,TimeoutStartUSec,DropInPaths,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic";
    let manager = json!(singleton227_capture::properties(c::GUARD_UNIT, fields)?);
    ensure!(
        manager["LoadState"] == "loaded"
            && manager["ActiveState"] == "inactive"
            && manager["SubState"] == "dead"
            && manager["MainPID"] == "0"
            && manager["ControlPID"] == "0"
            && manager["Job"] == ""
            && manager["Result"] == "success"
            && manager["ExecMainStatus"] == "0"
            && manager["TimeoutStartUSec"] == "1min"
            && manager["DropInPaths"] == "",
        "265 terminal guard incomplete/failed"
    );
    let plan = c::sealed(&c::binding(&h["startup_plan"])?)?;
    let admission = c::sealed(&c::binding(&h["admission"])?)?;
    let issued = c::num(&plan, "issued_monotonic_us")?;
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--all",
            "--no-pager",
            "--output=json",
            "--boot=0",
            &format!(
                "--since=@{}",
                c::num(&admission, "recorded_unix_seconds")?.saturating_sub(60)
            ),
            "_PID=1",
            &format!("UNIT={}", c::GUARD_UNIT),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16 << 20,
        "265 complete actual guard journal unavailable"
    );
    let mut actual = Vec::new();
    for row in serde_json::Deserializer::from_slice(&out.stdout).into_iter::<Value>() {
        let row = row?;
        let time = c::text(&row, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        if time >= issued {
            actual.push(row);
        }
    }
    let retained = <c::FsEvidence as c::EvidenceReader>::bytes(
        &c::FsEvidence,
        &c::binding(&bundle["pid1_journal"])?,
        16 << 20,
    )?;
    let retained = serde_json::Deserializer::from_slice(&retained)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !actual.is_empty() && actual == retained,
        "265 supplied full guard history differs from actual PID1 history"
    );
    let final_iid = final_guard_invocation(&manager, &actual)?;
    ensure!(
        bundle["records"]
            .as_array()
            .context("265 guard records")?
            .iter()
            .map(|b| c::sealed(&c::binding(b)?))
            .collect::<Result<Vec<_>>>()?
            .iter()
            .any(|r| r["schema"] == "horizon265-native-guard-terminal-v1"
                && r["guard_invocation_id"] == final_iid),
        "265 final completed guard has no exact terminal drain receipt"
    );
    ensure!(
        json!(singleton227_capture::properties(c::GUARD_UNIT, fields)?) == manager
            && json!(singleton227_capture::properties(
                "horizon-native265-protective-v1.timer",
                "LoadState,ActiveState,SubState,Unit,Job,DropInPaths"
            )?) == timer,
        "265 terminal guard transitioned during complete capture"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stopped_timer_uses_complete_guard_history_when_pid1_resets_display() {
        let fixture: Value =
            serde_json::from_str(include_str!("fixtures/native265-terminal-20261119.json"))
                .unwrap();
        let rows = fixture["guard_pid1"].as_array().unwrap();
        let mut manager = json!({"InvocationID":"", "ExecMainPID":"0",
            "ExecMainStartTimestampMonotonic":"0", "ExecMainExitTimestampMonotonic":"0"});
        let iid = final_guard_invocation(&manager, rows).unwrap();
        assert_eq!(iid, "15db5416a1824bdd89fca75359eda35e");
        manager["InvocationID"] = json!("a".repeat(32));
        assert!(final_guard_invocation(&manager, rows).is_err());
        manager["InvocationID"] = json!("");
        manager["ExecMainPID"] = json!("42");
        assert!(final_guard_invocation(&manager, rows).is_err());
        manager["ExecMainPID"] = json!("0");
        let mut incomplete = rows.clone();
        incomplete.push(
            json!({"MESSAGE":format!("Starting {} - guard...",c::GUARD_UNIT),
            "INVOCATION_ID":"b".repeat(32),"__MONOTONIC_TIMESTAMP":"999999999999"}),
        );
        assert!(final_guard_invocation(&manager, &incomplete).is_err());
    }
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
    fn recovered_fixture() -> (Value, native265_recovery::tests::Reader) {
        use native265_recovery::tests::{b, put, retained, successor_source};
        let (hb, mut reader) = retained();
        let (h, a) = c::startup_read(&hb, &reader).unwrap();
        let fixture: Value =
            serde_json::from_str(include_str!("fixtures/native265-terminal-20261119.json"))
                .unwrap();
        let data = &fixture["data"];
        let mut rows = data["journal.jsonl"].as_array().unwrap().clone();
        rows.extend(data["PID1.jsonl"].as_array().unwrap().clone());
        rows.sort_by_key(|r| {
            r["__MONOTONIC_TIMESTAMP"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        });
        let (_, wall_us, terminal) = journal_rows(
            &rows,
            c::text(&h, "invocation_id").unwrap(),
            c::num(&h, "main_pid").unwrap(),
            c::text(&a, "boot_id").unwrap(),
        )
        .unwrap();
        let wall = fixture["complete_guard_records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| c::num(&r["value"], "recorded_unix_seconds").unwrap())
            .max()
            .unwrap()
            + 60;
        let (source, helper) = successor_source(&hb, &mut reader, &h, &a, wall);
        let journal_b = json!({"path":"/var/lib/jetstreamer/horizon-native265-terminal-raw-fixture/journal.json","sha256":"a".repeat(64)});
        reader.bytes.insert(
            c::binding(&journal_b).unwrap().path,
            rows.iter()
                .map(|r| serde_json::to_string(r).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes(),
        );
        let result_b = put(
            &mut reader,
            "native-result",
            data["native-result.json"].clone(),
        );
        // Complete actual PID1 rows and actual receipts retained after Main
        // stopped only the terminal timer and allowed the guard to drain.
        let guard_rows = fixture["guard_pid1"].as_array().unwrap();
        let mut records = Vec::new();
        for (n, record) in fixture["complete_guard_records"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            records.push(put(
                &mut reader,
                &format!("guard-record-{n}"),
                record["value"].clone(),
            ));
        }
        reader.bytes.insert(
            c::binding(&b("guard-journal")).unwrap().path,
            guard_rows
                .iter()
                .map(|r| serde_json::to_string(r).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes(),
        );
        let history = put(
            &mut reader,
            "history",
            json!({"schema":"horizon-native265-complete-guard-history-v1","guard_plan":h["guard_plan"],"producer_invocation_id":h["invocation_id"],"boot_id":a["boot_id"],"pid1_journal":b("guard-journal"),"records":records}),
        );
        let spec = json!({"schema":TERMINAL_RECOVERY_SPEC,"startup_handoff":private157::binding(&hb),"consumer_transition":private157::binding(&source.consumer_transition),"journal":journal_b,"observer":b("observer"),"fleet":b("fleet"),"native_result":result_b,"guard_history":history,"output":"/var/lib/jetstreamer/horizon-native265-terminal-proof-fixture/proof.json"});
        let spec_b = put(&mut reader, "spec", spec);
        // The retained terminal manager subset is merged with immutable startup
        // sandbox fields for this unit test; it is not a full observed snapshot.
        let mut manager = h["producer"].clone();
        for (k, v) in data["producer.json"].as_object().unwrap() {
            manager[k] = v.clone();
        }
        manager["TriggeredBy"] = json!("");
        manager["Job"] = json!("");
        let mut proof = json!({"schema":SCHEMA,"epoch":265,"unit":c::UNIT,"native_input_qualified":true,"resource_samples_taken":0,"capture_spec":spec_b,"capture_helper_sha256":helper,"startup_handoff":private157::binding(&hb),"consumer_transition":private157::binding(&source.consumer_transition),"original_launch_clock_preserved":true,"journal":journal_b,"observer":b("observer"),"fleet":b("fleet"),"native_result":result_b,"guard_history":history,"invocation_id":h["invocation_id"],"main_pid":h["main_pid"],"boot_id":a["boot_id"],"recorded_unix_seconds":wall,"terminal_unix_microseconds":wall_us,"terminal_monotonic_microseconds":terminal,"native_marker":{"standalone_completion_observed":true},"terminal_retention":h["retention"],"terminal_manager":manager,"sampled_at_utc":publication203::utc(wall-30).unwrap()});
        c::deny(&mut proof);
        (proof, reader)
    }
    #[test]
    fn direct_terminal_recovery_uses_genuine_result_and_never_invents_running_origin() {
        let (proof, mut reader) = recovered_fixture();
        assert_eq!(
            validate_read(&proof, &reader).unwrap(),
            "ce5f66a82fdd4c0e93ca99f27b925112"
        );
        assert!(proof.get("running_origin").is_none());
        for (pointer, value) in [
            ("/invocation_id", json!("a".repeat(32))),
            ("/capture_helper_sha256", json!("e".repeat(64))),
            ("/terminal_monotonic_microseconds", json!(u64::MAX)),
            ("/terminal_manager/NRestarts", json!("1")),
            ("/original_launch_clock_preserved", json!(false)),
        ] {
            let mut bad = proof.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_read(&bad, &reader).is_err(), "{pointer}");
        }
        let mut fake = proof.clone();
        fake["running_origin"] = native265_recovery::tests::b("invented");
        assert!(validate_read(&fake, &reader).is_err());
        for (name, key, value) in [
            ("transition", "reviewed_source_changes", json!([])),
            ("closure", "actual_externs", json!([])),
            (
                "qualification",
                "predecessor_consumers_preserved",
                json!(false),
            ),
            ("native-result", "worker_reaped", json!(false)),
            (
                "spec",
                "schema",
                json!("jetstreamer-native265-terminal-capture-spec-v1"),
            ),
        ] {
            let path = c::binding(&native265_recovery::tests::b(name))
                .unwrap()
                .path;
            let prior = reader.values[&path].clone();
            reader.values.get_mut(&path).unwrap()[key] = value;
            assert!(validate_read(&proof, &reader).is_err(), "{name}:{key}");
            reader.values.insert(path, prior);
        }
    }
    #[test]
    fn direct_terminal_event_preserves_existing_fleet_without_registered_running_claim() {
        use native265_recovery::tests::{b, put};
        let (proof, mut reader) = recovered_fixture();
        let clock = c::num(&proof, "recorded_unix_seconds").unwrap();
        let sampled = c::text(&proof, "sampled_at_utc").unwrap();
        let old = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,"observer":proof["observer"],"output":"/output.json","status_receipt_directory":"/receipts","gates":{},"tracked_units":[c::UNIT]});
        let old_b = put(&mut reader, "old-plan", old.clone());
        let proof_b = json!({"path":"/var/lib/jetstreamer/horizon-native265-terminal-proof-fixture/proof.json","sha256":"a".repeat(64)});
        reader
            .values
            .insert(c::binding(&proof_b).unwrap().path, proof.clone());
        let mut next = old;
        next["previous_fleet"] = proof["fleet"].clone();
        next["metadata_event"] = proof_b;
        let p: Plan = serde_json::from_value(next).unwrap();
        let previous = json!({"sampled_at_utc":sampled,"recorded_unix_seconds":clock-30,"plan":old_b["path"],"plan_sha256":old_b["sha256"],"active":[]});
        predecessor_read(&previous, &p, &proof, sampled, clock, &reader).unwrap();
        assert!(predecessor_read(&previous, &p, &proof, sampled, clock + 301, &reader).is_err());
        let mut overlap = previous.clone();
        overlap["active"] = json!([{"epoch":265}]);
        assert!(predecessor_read(&overlap, &p, &proof, sampled, clock, &reader).is_err());
        let spec_path = c::binding(&b("spec")).unwrap().path;
        reader.values.get_mut(&spec_path).unwrap()["running_origin"] = b("invented");
        assert!(predecessor_read(&previous, &p, &proof, sampled, clock, &reader).is_err());
    }
}
