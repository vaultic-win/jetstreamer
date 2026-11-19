//! Independently qualify the completed input test; never rerun its Bank.
use super::native211 as c;
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch211-native-terminal-proof-v1";

pub(super) fn terminal_shape(u: &Value, iid: &str) -> Result<()> {
    ensure!(
        u["Id"] == c::UNIT
            && u["LoadState"] == "loaded"
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && (u["InvocationID"] == "" || u["InvocationID"] == iid)
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0",
        "211 terminal owner is live, replaced, restarted or unsuccessful"
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
    c::namespace(&b.path, "horizon-native211-terminal-raw-", "journal.json")?;
    let bytes = reader.bytes(b, 16 << 20)?;
    let rows = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    journal_rows(&rows, iid, pid, boot)
}
fn journal_rows(rows: &[Value], iid: &str, pid: u64, boot: &str) -> Result<(Value, u64, u64)> {
    ensure!(
        !rows.is_empty() && rows.len() <= 4096 && c::hex(iid, 32) && pid > 1,
        "211 journal bounds"
    );
    let mut marker = None;
    let mut success = None;
    let mut terminal = None;
    let mut prior_mono = 0;
    for (index, r) in rows.iter().enumerate() {
        ensure!(
            r["_BOOT_ID"] == boot.replace('-', ""),
            "211 foreign boot journal row"
        );
        let mono = c::text(r, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        let wall = c::text(r, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        ensure!(mono >= prior_mono, "211 journal monotonic rollback");
        prior_mono = mono;
        let msg = c::text(r, "MESSAGE")?;
        if r["_PID"] == "1" {
            ensure!(
                r["_UID"] == "0" && r["UNIT"] == c::UNIT && r["INVOCATION_ID"] == iid,
                "211 foreign PID1 event"
            );
            if msg == format!("{}: Deactivated successfully.", c::UNIT) {
                ensure!(
                    terminal.replace((index, wall, mono)).is_none(),
                    "211 duplicate PID1 completion"
                );
            }
            ensure!(
                !msg.contains("Failed") && !msg.contains("Main process exited"),
                "211 abnormal PID1 completion"
            );
        } else {
            ensure!(
                c::text(r, "_PID")? == pid.to_string()
                    && r["_SYSTEMD_UNIT"] == c::UNIT
                    && r["_SYSTEMD_INVOCATION_ID"] == iid,
                "211 foreign native process"
            );
            if let Some((_, fields)) = msg.split_once("epoch211-v1616-native-input ") {
                let mut parsed = BTreeMap::new();
                for field in fields.split_whitespace() {
                    let (k, v) = field.split_once('=').context("211 marker field")?;
                    ensure!(
                        parsed.insert(k.to_owned(), v.to_owned()).is_none(),
                        "211 duplicate marker field"
                    );
                }
                for (k, v) in [
                    ("slot", "91151575"),
                    ("accounts_hash", c::ACCOUNTS_HASH),
                    ("replay_entries", "0"),
                    ("bootstrap_writes", "0"),
                ] {
                    ensure!(
                        parsed.get(k).map(String::as_str) == Some(v),
                        "211 canonical marker differs {k}"
                    );
                }
                for k in [
                    "capitalization",
                    "transaction_count",
                    "tick_height",
                    "next_write_version",
                ] {
                    parsed
                        .get(k)
                        .context("211 integer absent")?
                        .parse::<u64>()?;
                }
                for k in ["bank_hash", "last_blockhash"] {
                    let value = parsed.get(k).context("211 hash absent")?;
                    ensure!(
                        (32..=44).contains(&value.len())
                            && value.bytes().all(|b| {
                                b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                                    .contains(&b)
                            }),
                        "211 invalid native hash"
                    );
                }
                ensure!(
                    parsed.len() == 10 && marker.replace((index, json!(parsed))).is_none(),
                    "211 duplicate/noncanonical marker"
                );
            } else if msg.starts_with("test result:") {
                ensure!(
                    msg.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
                        && success.replace(index).is_none(),
                    "211 test outcome differs"
                );
            }
        }
    }
    let (i, marker) = marker.context("211 native marker missing")?;
    let s = success.context("211 test success missing")?;
    let (t, wall, mono) = terminal.context("211 PID1 completion missing")?;
    ensure!(i < s && s < t, "211 marker/test/manager order differs");
    Ok((marker, wall, mono))
}
pub(super) fn validate(proof: &Value) -> Result<String> {
    validate_read(proof, &c::FsEvidence)
}
pub(super) fn validate_read(proof: &Value, reader: &impl c::EvidenceReader) -> Result<String> {
    ensure!(
        proof["schema"] == SCHEMA
            && proof["epoch"] == 211
            && proof["unit"] == c::UNIT
            && proof["native_input_qualified"] == true
            && proof["resource_samples_taken"] == 0,
        "211 terminal proof scope"
    );
    c::no_authority(proof)?;
    let origin_binding: BoundFile = serde_json::from_value(proof["running_origin"].clone())?;
    c::namespace(
        &origin_binding.path,
        "horizon-native211-running-",
        "intent.json",
    )?;
    let spec_binding: BoundFile = serde_json::from_value(proof["capture_spec"].clone())?;
    let spec: Spec = serde_json::from_value(reader.json(&spec_binding, true)?)?;
    ensure!(
        spec.schema == "jetstreamer-native211-terminal-capture-spec-v1"
            && spec.running_origin == origin_binding
            && private157::binding(&spec.journal) == proof["journal"]
            && private157::binding(&spec.observer) == proof["observer"]
            && private157::binding(&spec.fleet) == proof["fleet"],
        "211 terminal proof is not bound to its immutable capture spec"
    );
    let origin = reader.json(&origin_binding, true)?;
    let iid = origin["invocation_id"].as_str().context("211 origin IID")?;
    let pid = origin["main_pid"].as_u64().context("211 origin PID")?;
    let claim = PipelineClaim {
        epoch: 211,
        phase: "private-cold-snapshot-verification".into(),
        unit: c::UNIT.into(),
        invocation_id: iid.into(),
        expected_exec_start: origin["expected_exec_start"]
            .as_str()
            .context("211 original command")?
            .into(),
        evidence: vec![origin_binding],
    };
    c::claim_read(&claim, reader)?;
    ensure!(
        proof["invocation_id"] == iid && proof["main_pid"] == pid,
        "211 terminal origin substituted"
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
        "211 terminal owner/clock differs"
    );
    native211_capture::retention_values(&proof["terminal_retention"])?;
    ensure!(
        c::text(&proof["terminal_manager"], "ExecMainPID")? == pid.to_string(),
        "211 original terminal PID lost"
    );
    ensure!(
        proof["terminal_manager"]["ExecMainCode"] == "1"
            && proof["terminal_manager"]["ControlPID"] == "0"
            && proof["terminal_manager"]["Job"] == ""
            && proof["terminal_manager"]["Restart"] == "no"
            && proof["terminal_manager"]["KillMode"] == "control-group"
            && proof["terminal_manager"]["Delegate"] == "no"
            && proof["terminal_manager"]["TriggeredBy"] == "",
        "211 terminal manager work/restart remains"
    );
    terminal_shape(&proof["terminal_manager"], iid)?;
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
        .context("211 terminal event binding")?;
    ensure!(
        reader.json(event_binding, true)? == *proof,
        "211 terminal event is not immutable"
    );
    let spec = reader.json(&c::binding(&proof["capture_spec"])?, true)?;
    ensure!(
        spec["output"].as_str() == event_binding.path.to_str(),
        "211 terminal proof moved from capture destination"
    );
    validate_read(proof, reader)?;
    let recorded = proof["recorded_unix_seconds"]
        .as_u64()
        .context("211 proof capture clock")?;
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
        "211 terminal event replaced/staled resource history"
    );
    let old: Plan = serde_json::from_value(
        reader.json(
            &BoundFile {
                path: previous["plan"].as_str().context("211 prior plan")?.into(),
                sha256: previous["plan_sha256"]
                    .as_str()
                    .context("211 prior digest")?
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
        "211 terminal proof lacks its exact registered origin"
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
        "211 terminal changed unrelated owner/configuration"
    );
    for (epoch, g) in &old.gates {
        let n = p.gates.get(epoch).context("211 terminal gate omitted")?;
        ensure!(
            native211_event::same_operator_status(&n.operator_status, &g.operator_status)
                && serde_json::to_value(&n.reserve_stop)? == serde_json::to_value(&g.reserve_stop)?
                && n.state == g.state
                && g.evidence.iter().all(|e| n.evidence.contains(e))
                && (*epoch == 211 || (n.evidence == g.evidence && n.next_action == g.next_action)),
            "211 terminal changed completion/unrelated gates"
        );
        if *epoch == 211 {
            ensure!(
                n.evidence
                    .iter()
                    .all(|e| g.evidence.contains(e) || p.metadata_event.as_ref() == Some(e)),
                "211 terminal added unrelated evidence"
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
    ensure!(c::sealed(b)? == proof, "211 terminal event changed");
    let iid = validate(&proof)?;
    terminal_shape(current.get(c::UNIT).context("211 owner omitted")?, &iid)?;
    let previous = bound_json(
        p.previous_fleet
            .as_ref()
            .context("211 terminal prior fleet")?,
    )?;
    native211_capture::peers(&previous, current, c::UNIT)?;
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
    output: PathBuf,
}
pub(super) fn capture() -> Result<()> {
    let (b, self_sha) = publication203::parsed_args("capture-native211-terminal")?;
    let s: Spec = serde_json::from_value(c::sealed(&b)?)?;
    ensure!(
        s.schema == "jetstreamer-native211-terminal-capture-spec-v1"
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-native211-terminal-proof-"))
            && s.output.file_name().is_some_and(|n| n == "proof.json"),
        "211 terminal output scope"
    );
    if s.output.try_exists()? {
        let old = c::sealed(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["capture_spec"] == private157::binding(&b)
                && old["capture_helper_sha256"] == self_sha,
            "211 terminal retry conflicts"
        );
        validate(&old)?;
        return Ok(());
    }
    let origin = c::sealed(&s.running_origin)?;
    let f = bound_json(&s.fleet)?;
    let o = bound_json(&s.observer)?;
    ensure!(
        f["observer_sha256"] == s.observer.sha256 && f["sampled_at_utc"] == o["recorded_at_utc"],
        "211 terminal observer/fleet differs"
    );
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"].as_str().context("211 accepted plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("211 accepted digest")?
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
        "211 terminal lacks original registered claim"
    );
    let iid = origin["invocation_id"]
        .as_str()
        .context("211 original IID")?;
    let pid = origin["main_pid"].as_u64().context("211 original PID")?;
    ensure!(
        origin["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "211 terminal belongs to another boot"
    );
    let (checkpoint, clock, monotonic) =
        journal(&s.journal, iid, pid, c::text(&origin, "boot_id")?)?;
    let before = native211_capture::properties()?;
    let retention = native211_capture::retention()?;
    let mut proof = json!({"schema":SCHEMA,"epoch":211,"unit":c::UNIT,"invocation_id":iid,"main_pid":pid,
        "running_origin":private157::binding(&s.running_origin),"journal":private157::binding(&s.journal),
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"sampled_at_utc":f["sampled_at_utc"],
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"terminal_unix_microseconds":clock,
        "native_marker":checkpoint,"terminal_manager":before,"terminal_retention":retention,"boot_id":origin["boot_id"],"terminal_monotonic_microseconds":monotonic,"capture_spec":private157::binding(&b),"capture_helper_sha256":self_sha,
        "native_input_qualified":true,"resource_samples_taken":0});
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
        native211_capture::properties()? == before,
        "211 terminal owner changed during capture"
    );
    private157::immutable_receipt(&s.output, &proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rows() -> Vec<Value> {
        let child = |msg: &str, time: &str| json!({"_PID":"42","_UID":"1000","_BOOT_ID":"00000000000000000000000000000001","_SYSTEMD_UNIT":c::UNIT,"_SYSTEMD_INVOCATION_ID":"a".repeat(32),"__REALTIME_TIMESTAMP":time,"__MONOTONIC_TIMESTAMP":time,"MESSAGE":msg});
        vec![
            child(
                "epoch211-v1616-native-input slot=91151575 bank_hash=EzH8ssxUMpcqku5DUXiMhvmdXEtvr6HveAv9dM2Vsiib accounts_hash=xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx last_blockhash=C3UvZbEzYj5vvQnogdekZcGhmvWfmonYWfn2xW2KAV7Y capitalization=500584876715315613 transaction_count=22383626920 tick_height=5723100480 next_write_version=86171593405 replay_entries=0 bootstrap_writes=0",
                "10",
            ),
            child(
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 56 filtered out; finished in 452.73s",
                "20",
            ),
            json!({"_PID":"1","_UID":"0","_BOOT_ID":"00000000000000000000000000000001","UNIT":c::UNIT,"INVOCATION_ID":"a".repeat(32),"__REALTIME_TIMESTAMP":"30","__MONOTONIC_TIMESTAMP":"30","MESSAGE":format!("{}: Deactivated successfully.",c::UNIT)}),
        ]
    }
    #[test]
    fn native211_terminal_requires_exact_owner_boot_marker_success_and_order() {
        let rows = rows();
        let iid = "a".repeat(32);
        let boot = "00000000-0000-0000-0000-000000000001";
        let (v, wall, mono) = journal_rows(&rows, &iid, 42, boot).unwrap();
        assert_eq!(v["capitalization"], "500584876715315613");
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
            (0, "MESSAGE", json!("epoch211-v1616-native-input slot=1")),
            (
                1,
                "MESSAGE",
                json!("test result: FAILED. 0 passed; 1 failed;"),
            ),
            (2, "_UID", json!("1000")),
            (2, "__MONOTONIC_TIMESTAMP", json!("9")),
        ] {
            let mut bad = rows.clone();
            bad[i][key] = value;
            assert!(journal_rows(&bad, &iid, 42, boot).is_err(), "{i}:{key}");
        }
        let mut duplicate = rows.clone();
        duplicate.push(rows[2].clone());
        assert!(journal_rows(&duplicate, &iid, 42, boot).is_err());
        let mut old = rows.clone();
        old[0]["MESSAGE"] = json!(
            c::text(&rows[0], "MESSAGE")
                .unwrap()
                .replace("epoch211", "epoch210")
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
