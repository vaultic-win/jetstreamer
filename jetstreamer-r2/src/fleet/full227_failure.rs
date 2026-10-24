//! Exact failed full227 invocation; preserves the accepted resource observation.
use super::{singleton227 as c, *};
pub(super) const SCHEMA: &str = "jetstreamer-private-full227-terminal-failure-v1";
const IID: &str = "a10f37b57711425a81633c62c66438d5";
const PID: u64 = 121077;
const ORIGIN: &str = "/var/lib/jetstreamer/horizon-227-capture-full330-v1/launch.json";
const ORIGIN_SHA: &str = "12eb6beb36d13e9c35c26280908f3fe6df9f2489eedfc59d4ced6a094997172d";
const JOURNAL: &str = "/var/lib/jetstreamer/horizon-full227-failure-a10f37b5-v1/journal.json";
const JOURNAL_SHA: &str = "97b9b039efb30bb8c209a4b60c2519908068cd905d78f313a4ee2bf7fad8cb5e";
const MANAGER: &str =
    "/var/lib/jetstreamer/horizon-full227-failure-a10f37b5-v1/terminal-manager.txt";
const MANAGER_SHA: &str = "50f3701e2816c33267d8dd1e3955c885ed4d61ba0c74755354497c34d8b6a5a5";
const REPAIR: &str = "/var/lib/jetstreamer/horizon-full227-open-repair-a10f37b5-v1/repair.json";
const REPAIR_SHA: &str = "36b1900f16c4e97da5989438ca06d1a914475ce102f7e966307e1726bd90c8c4";
const SIGNATURE: &str =
    "3f6mTJHfWLvB12a6VJizegs8XZu9hXGphZwCcYg4yc5ZEoDqLzU4xmyAvcCdcHCGUh6fZtcSvLy9HDsAY2Z8TtRt";
fn fixed(path: &str, sha: &str) -> BoundFile {
    BoundFile {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn sealed_bytes(binding: &BoundFile) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(&binding.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && binding.path.canonicalize()? == binding.path,
        "227failure input is not sealed/canonical"
    );
    let bytes = read_stable_bounded(&binding.path, 16 << 20, "full227failure sealed input")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == binding.sha256,
        "full227failure evidence SHA differs"
    );
    Ok(bytes)
}
fn journal_rows(rows: &[Value]) -> Result<u64> {
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "full227failure journal bound"
    );
    let mismatch = format!(
        "historical execution mismatch at slot 98091122 entry 232 transaction 223 signature {SIGNATURE}: expected None, got Some(InstructionError {{ instruction_index: 0, error: Custom(2) }})"
    );
    let mut signature_clock = None;
    let mut exited = None;
    let mut failed = None;
    let mut previous = 0;
    for row in rows {
        let clock = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("full227 journal clock")?
            .parse::<u64>()?;
        ensure!(clock >= previous, "full227 journal clock rollback");
        previous = clock;
        let message = row["MESSAGE"].as_str().context("full227 journal message")?;
        if row["_PID"] == "1" {
            ensure!(
                row["UNIT"] == c::UNIT && row["INVOCATION_ID"] == IID,
                "full227 foreign manager event"
            );
            ensure!(
                !message.ends_with(": Deactivated successfully."),
                "full227 failure cannot borrow success"
            );
            if message
                == format!(
                    "{}: Main process exited, code=exited, status=1/FAILURE",
                    c::UNIT
                )
            {
                ensure!(
                    row["EXIT_CODE"] == "exited"
                        && row["EXIT_STATUS"] == "1"
                        && exited.replace(clock).is_none(),
                    "full227 duplicate/wrong manager exit"
                );
            }
            if message.starts_with(&format!("{}: Failed with result '", c::UNIT)) {
                ensure!(
                    message == format!("{}: Failed with result 'exit-code'.", c::UNIT)
                        && failed.replace(clock).is_none(),
                    "full227 duplicate/wrong manager failure"
                );
            }
        } else {
            ensure!(
                row["_SYSTEMD_UNIT"] == c::UNIT
                    && row["_SYSTEMD_INVOCATION_ID"] == IID
                    && row["_PID"].as_str().and_then(|p| p.parse::<u64>().ok()) == Some(PID),
                "full227 foreign producer journal"
            );
            if message.contains(&mismatch) {
                signature_clock = Some(clock);
            }
        }
    }
    let signature_clock = signature_clock.context("full227 exact raw mismatch absent")?;
    let exited = exited.context("full227 PID1 exit1 absent")?;
    let failed = failed.context("full227 PID1 failed outcome absent")?;
    ensure!(
        signature_clock <= exited && exited <= failed,
        "full227 failure clock ordering"
    );
    Ok(failed)
}
fn journal() -> Result<u64> {
    let bytes = sealed_bytes(&fixed(JOURNAL, JOURNAL_SHA))?;
    let rows = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    journal_rows(&rows)
}
fn terminal(u: &Value, command: &str) -> Result<()> {
    ensure!(
        u["Id"] == c::UNIT
            && u["LoadState"] == "loaded"
            && u["InvocationID"] == IID
            && u["ActiveState"] == "failed"
            && u["SubState"] == "failed"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && u["Result"] == "exit-code"
            && u["ExecMainStatus"] == "1"
            && pipeline_status::same_exec_start(
                u["ExecStart"]
                    .as_str()
                    .context("full227 terminal command")?,
                command
            ),
        "full227 owner is not the unchanged loadedfailed exact invocation"
    );
    Ok(())
}
fn origin(f: &Value) -> Result<String> {
    let old: Plan = serde_json::from_value(bound_json(&fixed(
        f["plan"].as_str().context("full227 prior plan")?,
        f["plan_sha256"].as_str().context("full227 prior digest")?,
    ))?)?;
    let claims = old
        .diagnostics
        .iter()
        .filter(|d| {
            d.epoch == 227
                && d.unit == c::UNIT
                && d.invocation_id == IID
                && d.scratch_path == Path::new(c::ROOT)
                && d.launch_receipt == fixed(ORIGIN, ORIGIN_SHA)
        })
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "full227failure lacks exact registered original diagnostic"
    );
    let launch = checked_diagnostic_launch(claims[0])?;
    ensure!(
        launch["evidence"]["units"][0]["main_pid"] == PID,
        "full227 original parent PID differs"
    );
    Ok(launch["expected_exec_start"]
        .as_str()
        .context("full227 launch command")?
        .into())
}
fn census_delta(prior: &Value, current: &BTreeMap<String, Value>, command: &str) -> Result<()> {
    terminal(
        current
            .get(c::UNIT)
            .context("full227 missing terminal owner")?,
        command,
    )?;
    let mut expected: BTreeMap<String, Value> =
        serde_json::from_value(prior["unit_census"].clone())?;
    ensure!(
        expected.contains_key(c::UNIT),
        "full227 absent from previous census"
    );
    expected.insert(c::UNIT.into(), current[c::UNIT].clone());
    ensure!(
        &expected == current,
        "full227 failure census changed an unrelated owner or omitted history"
    );
    Ok(())
}
fn sample(f: &Value, o: &Value, observer: &BoundFile, now: u64) -> Result<()> {
    let t = utc_seconds(
        f["sampled_at_utc"]
            .as_str()
            .context("full227 accepted sample")?,
    )?;
    ensure!(
        f["schema"] == super::SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == observer.path.to_str()
            && f["observer_sha256"] == observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && t <= now
            && now - t <= 1800,
        "full227failure requires same fresh accepted resource sample"
    );
    Ok(())
}
fn repair() -> Result<()> {
    let r = native209::immutable_json(&fixed(REPAIR, REPAIR_SHA))?;
    ensure!(
        r["schema"] == "jetstreamer-horizon-open-epoch-repair-v1"
            && r["epoch"] == 227
            && r["open"] == true
            && r["close_only_after_verified_r2_ready_pair"] == true
            && r["original_unit"] == c::UNIT
            && r["original_invocation_id"] == IID
            && r["failure"]["slot"] == 98091122
            && r["failure"]["signature"] == SIGNATURE
            && r["repaired"] == false
            && r["publication_authorized"] == false
            && r["remote_mutations"] == false
            && r["r2_mutations"] == false,
        "full227 openrepair differs"
    );
    Ok(())
}
pub(super) fn validate(proof: &Value) -> Result<()> {
    ensure!(
        proof["schema"] == SCHEMA
            && proof["epoch"] == 227
            && proof["unit"] == c::UNIT
            && proof["invocation_id"] == IID
            && proof["main_pid"] == PID
            && proof["resource_samples_taken"] == 0
            && proof["running_origin"] == private157::binding(&fixed(ORIGIN, ORIGIN_SHA))
            && proof["journal"] == private157::binding(&fixed(JOURNAL, JOURNAL_SHA))
            && proof["terminal_raw_manager"] == private157::binding(&fixed(MANAGER, MANAGER_SHA))
            && proof["open_repair"] == private157::binding(&fixed(REPAIR, REPAIR_SHA)),
        "full227failure proof scope/bindings differ"
    );
    for key in [
        "repair_closed",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "full_plugin_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "producer_mutations",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            proof[key] == false,
            "full227failure grants forbidden authority:{key}"
        );
    }
    repair()?;
    let f = bound_json(&serde_json::from_value(proof["fleet"].clone())?)?;
    let observer: BoundFile = serde_json::from_value(proof["observer"].clone())?;
    let o = bound_json(&observer)?;
    let recorded = proof["recorded_unix_seconds"]
        .as_u64()
        .context("full227 capture clock")?;
    sample(&f, &o, &observer, recorded)?;
    let command = origin(&f)?;
    let raw = sealed_bytes(&fixed(MANAGER, MANAGER_SHA))?;
    let mut manager = serde_json::Map::new();
    for line in std::str::from_utf8(&raw)?.lines() {
        let (k, v) = line.split_once('=').context("full227 raw manager field")?;
        ensure!(
            manager.insert(k.into(), json!(v)).is_none(),
            "full227 duplicate raw manager property"
        );
    }
    terminal(&Value::Object(manager), &command)?;
    terminal(&proof["terminal_manager"], &command)?;
    let clock = journal()?;
    ensure!(
        proof["terminal_unix_microseconds"] == clock
            && recorded >= clock / 1_000_000
            && proof["sampled_at_utc"] == f["sampled_at_utc"],
        "full227failure terminal/sample clock differs"
    );
    for key in ["unit_census_before", "unit_census_after"] {
        census_delta(&f, &serde_json::from_value(proof[key].clone())?, &command)?;
    }
    ensure!(
        proof["unit_census_before"] == proof["unit_census_after"],
        "full227failure capture changed census"
    );
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    output: PathBuf,
}
pub(super) fn capture() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-full227-failure")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-full227-failure-capture-spec-v1"
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-full227-terminal-proof-"))
            && s.output.file_name().is_some_and(|n| n == "proof.json"),
        "full227failure output scope differs"
    );
    if s.output.try_exists()? {
        let old = native209::immutable_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["capture_spec"] == private157::binding(&binding)
                && old["capture_helper_sha256"] == self_sha,
            "full227failure retry conflicts"
        );
        validate(&old)?;
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let f = bound_json(&s.fleet)?;
    let o = bound_json(&s.observer)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample(&f, &o, &s.observer, now)?;
    let command = origin(&f)?;
    let names = f["unit_census"]
        .as_object()
        .context("full227 old census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 201, 300)?;
    census_delta(&f, &before, &command)?;
    let clock = journal()?;
    let after = census(&names, 201, 300)?;
    census_delta(&f, &after, &command)?;
    ensure!(
        before == after,
        "full227failure census changed during capture"
    );
    let mut proof = json!({"schema":SCHEMA,"epoch":227,"unit":c::UNIT,"invocation_id":IID,"main_pid":PID,
        "running_origin":private157::binding(&fixed(ORIGIN,ORIGIN_SHA)),"journal":private157::binding(&fixed(JOURNAL,JOURNAL_SHA)),
        "terminal_raw_manager":private157::binding(&fixed(MANAGER,MANAGER_SHA)),"open_repair":private157::binding(&fixed(REPAIR,REPAIR_SHA)),
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"sampled_at_utc":f["sampled_at_utc"],
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"terminal_unix_microseconds":clock,
        "terminal_manager":before[c::UNIT],"unit_census_before":before,"unit_census_after":after,
        "capture_spec":private157::binding(&binding),"capture_helper_sha256":self_sha,"resource_samples_taken":0});
    for key in [
        "repair_closed",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "full_plugin_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "producer_mutations",
        "remote_mutations",
        "r2_mutations",
    ] {
        proof[key] = json!(false);
    }
    validate(&proof)?;
    private157::immutable_receipt(&s.output, &proof)
}
pub(super) fn predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    validate(proof)?;
    let recorded = proof["recorded_unix_seconds"]
        .as_u64()
        .context("full227 event time")?;
    ensure!(
        p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && p.previous_fleet
                .as_ref()
                .is_some_and(|b| proof["fleet"] == private157::binding(b))
            && proof["observer"] == private157::binding(&p.observer)
            && previous["sampled_at_utc"] == sampled
            && proof["sampled_at_utc"] == sampled
            && recorded <= now
            && now - recorded <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= recorded),
        "full227failure replaced/staled accepted observation"
    );
    let old: Plan = serde_json::from_value(bound_json(&fixed(
        previous["plan"].as_str().context("full227 priorplan")?,
        previous["plan_sha256"]
            .as_str()
            .context("full227 priordigest")?,
    ))?)?;
    plan_delta(&old, p, proof)
}
fn plan_delta(old: &Plan, p: &Plan, proof: &Value) -> Result<()> {
    ensure!(
        p.schema == old.schema
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
        "full227failure changed unrelated configuration/history"
    );
    for (epoch, g) in &old.gates {
        let n = p.gates.get(epoch).context("full227failure omitted gate")?;
        ensure!(
            serde_json::to_value(&n.reserve_stop)? == serde_json::to_value(&g.reserve_stop)?,
            "full227failure changed reserve-stop proof"
        );
        if *epoch == 227 {
            ensure!(
                matches!(
                    g.state.as_str(),
                    "blocked-qualification" | "failed-needs-repair"
                ) && n.state == "failed-needs-repair"
                    && !n.next_action.is_empty()
                    && g.evidence.iter().all(|b| n.evidence.contains(b))
                    && n.evidence.iter().all(|b| g.evidence.contains(b)
                        || p.metadata_event.as_ref() == Some(b)
                        || private157::binding(b) == proof["open_repair"])
                    && p.metadata_event
                        .as_ref()
                        .is_some_and(|b| n.evidence.contains(b))
                    && n.evidence.contains(&fixed(REPAIR, REPAIR_SHA)),
                "full227failure gate must retain evidence and append exact failure/openrepair"
            );
        } else {
            ensure!(
                n.state == g.state && n.next_action == g.next_action && n.evidence == g.evidence,
                "full227failure changed another epoch gate"
            );
        }
    }
    Ok(())
}
pub(super) fn census_check(p: &Plan, current: &BTreeMap<String, Value>) -> Result<()> {
    let Some(binding) = &p.metadata_event else {
        return Ok(());
    };
    let proof = bound_json(binding)?;
    if proof["schema"] != SCHEMA {
        return Ok(());
    }
    validate(&proof)?;
    let prior = bound_json(
        p.previous_fleet
            .as_ref()
            .context("full227 event predecessor missing")?,
    )?;
    census_delta(&prior, current, &origin(&prior)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rows() -> Vec<Value> {
        vec![
            json!({"_PID":PID.to_string(),"_SYSTEMD_UNIT":c::UNIT,"_SYSTEMD_INVOCATION_ID":IID,"__REALTIME_TIMESTAMP":"1000000","MESSAGE":format!("historical execution mismatch at slot 98091122 entry 232 transaction 223 signature {SIGNATURE}: expected None, got Some(InstructionError {{ instruction_index: 0, error: Custom(2) }})")}),
            json!({"_PID":"1","UNIT":c::UNIT,"INVOCATION_ID":IID,"__REALTIME_TIMESTAMP":"2000000","MESSAGE":format!("{}: Main process exited, code=exited, status=1/FAILURE",c::UNIT),"EXIT_CODE":"exited","EXIT_STATUS":"1"}),
            json!({"_PID":"1","UNIT":c::UNIT,"INVOCATION_ID":IID,"__REALTIME_TIMESTAMP":"2000001","MESSAGE":format!("{}: Failed with result 'exit-code'.",c::UNIT)}),
        ]
    }
    #[test]
    fn exact_raw_failure_requires_signature_custom2_and_both_pid1_outcomes() {
        let r = rows();
        assert_eq!(journal_rows(&r).unwrap(), 2000001);
        for index in 0..3 {
            let mut bad = r.clone();
            bad.remove(index);
            assert!(journal_rows(&bad).is_err());
        }
        for (index, key, value) in [
            (0, "_PID", json!("42")),
            (1, "INVOCATION_ID", json!("b".repeat(32))),
            (2, "UNIT", json!("foreign.service")),
            (
                0,
                "MESSAGE",
                json!("historical execution mismatch at slot 98091122 Custom(3)"),
            ),
        ] {
            let mut bad = r.clone();
            bad[index][key] = value;
            assert!(journal_rows(&bad).is_err());
        }
        let mut bad = r.clone();
        bad.push(r[2].clone());
        assert!(journal_rows(&bad).is_err());
        let mut bad = r.clone();
        bad[1]["__REALTIME_TIMESTAMP"] = json!("1");
        assert!(journal_rows(&bad).is_err());
    }
    #[test]
    fn terminal_census_refuses_replacement_live_restart_and_unrelated_owner_changes() {
        let own = json!({"Id":c::UNIT,"LoadState":"loaded","InvocationID":IID,"ActiveState":"failed","SubState":"failed","MainPID":"0","NRestarts":"0","Result":"exit-code","ExecMainStatus":"1","ExecStart":"{ path=/sealed/node ; argv[]=/sealed/node 227 ; ignore_errors=no }"});
        let command = own["ExecStart"].as_str().unwrap();
        terminal(&own, command).unwrap();
        let prior = json!({"unit_census":{c::UNIT:own,"peer.service":{"MainPID":"42"}}});
        let current: BTreeMap<String, Value> =
            serde_json::from_value(prior["unit_census"].clone()).unwrap();
        census_delta(&prior, &current, command).unwrap();
        let mut bad = current.clone();
        bad.get_mut("peer.service").unwrap()["MainPID"] = json!("43");
        assert!(census_delta(&prior, &bad, command).is_err());
        for (key, value) in [
            ("InvocationID", json!("b".repeat(32))),
            ("MainPID", json!("123")),
            ("NRestarts", json!("1")),
            ("LoadState", json!("not-found")),
            ("ExecMainStatus", json!("0")),
        ] {
            let mut bad = own.clone();
            bad[key] = value;
            assert!(terminal(&bad, command).is_err());
        }
    }
    #[test]
    fn event_changes_only_227_failed_gate_preserving_other_owners_and_reserve_history() {
        let base = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,
            "observer":{"path":"/sealed/observer.json","sha256":"a".repeat(64)},"previous_fleet":null,"output":"/sealed/old-fleet.json",
            "status_receipt_directory":"/private/status","tracked_units":[c::UNIT],"diagnostics":[],"pipeline_claims":[],
            "gates":{"227":{"state":"blocked-qualification","next_action":"continue","evidence":[]},"228":{"state":"blocked-qualification","next_action":"retain","evidence":[]}}});
        let old: Plan = serde_json::from_value(base.clone()).unwrap();
        let event = json!({"path":"/sealed/failure.json","sha256":"b".repeat(64)});
        let proof = json!({"open_repair":private157::binding(&fixed(REPAIR,REPAIR_SHA))});
        let mut next = base.clone();
        next["metadata_event"] = event.clone();
        next["gates"]["227"]["state"] = json!("failed-needs-repair");
        next["gates"]["227"]["next_action"] =
            json!("Repair slot98091122; keep publication gates open");
        next["gates"]["227"]["evidence"] =
            json!([event, private157::binding(&fixed(REPAIR, REPAIR_SHA))]);
        let p: Plan = serde_json::from_value(next.clone()).unwrap();
        plan_delta(&old, &p, &proof).unwrap();
        for (pointer, value) in [
            ("/gates/228/state", json!("r2-ready")),
            ("/gates/227/state", json!("r2-ready")),
            ("/gates/227/evidence", json!([])),
            ("/tracked_units", json!([])),
            ("/observer/sha256", json!("c".repeat(64))),
        ] {
            let mut bad = next.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(plan_delta(&old, &serde_json::from_value(bad).unwrap(), &proof).is_err());
        }
    }
}
