//! Independently qualify the completed input test; never rerun its Bank.
use super::native228 as c;
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch228-native-terminal-proof-v1";
const ORIGIN_PATH: &str = "/var/lib/jetstreamer/horizon-228-native-capture-actual-v1/intent.json";

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
        "228 terminal owner is live, replaced, restarted or unsuccessful"
    );
    Ok(())
}
pub(super) fn journal(binding: &BoundFile, iid: &str, pid: u64) -> Result<(Value, u64)> {
    ensure!(
        binding
            .path
            .file_name()
            .is_some_and(|n| n == "journal.json")
            && binding.path.parent().and_then(Path::parent)
                == Some(Path::new("/var/lib/jetstreamer"))
            && binding
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-native228-terminal-raw-")),
        "228 journal is outside its sealed attempt namespace"
    );
    let m = fs::symlink_metadata(&binding.path)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "228 journal must be sealed root-owned evidence"
    );
    let bytes = read_stable_bounded(&binding.path, 16 << 20, "228 terminal journal")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == binding.sha256,
        "228 terminal journal digest differs"
    );
    let rows = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    journal_rows(rows, iid, pid)
}
fn journal_rows(rows: Vec<Value>, iid: &str, pid: u64) -> Result<(Value, u64)> {
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "228 terminal journal bounds"
    );
    let rows = rows
        .into_iter()
        .filter(|r| {
            r["_SYSTEMD_INVOCATION_ID"] == iid || (r["_PID"] == "1" && r["INVOCATION_ID"] == iid)
        })
        .collect::<Vec<_>>();
    ensure!(
        rows.iter()
            .filter(|r| r["_PID"] != "1")
            .all(|r| r["_PID"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(pid)),
        "228 foreign child PID"
    );
    let checkpoint = native228_capture::marker(&rows, iid)?;
    let clock = rows
        .iter()
        .find(|r| {
            r["_PID"] == "1" && r["MESSAGE"] == format!("{}: Deactivated successfully.", c::UNIT)
        })
        .and_then(|r| r["__REALTIME_TIMESTAMP"].as_str())
        .context("228 terminal clock")?
        .parse::<u64>()?;
    Ok((checkpoint, clock))
}
pub(super) fn validate(proof: &Value) -> Result<String> {
    ensure!(
        proof["schema"] == SCHEMA
            && proof["epoch"] == 228
            && proof["unit"] == c::UNIT
            && proof["native_input_qualified"] == true
            && proof["resource_samples_taken"] == 0,
        "228 terminal proof scope"
    );
    c::no_authority(proof)?;
    let origin_binding: BoundFile = serde_json::from_value(proof["running_origin"].clone())?;
    ensure!(
        origin_binding.path == Path::new(ORIGIN_PATH),
        "228 terminal origin is not the approved attempt"
    );
    let spec_binding: BoundFile = serde_json::from_value(proof["capture_spec"].clone())?;
    let spec: Spec = serde_json::from_value(c::immutable_json(&spec_binding)?)?;
    ensure!(
        spec.schema == "jetstreamer-native228-terminal-capture-spec-v1"
            && spec.running_origin == origin_binding
            && private157::binding(&spec.journal) == proof["journal"]
            && private157::binding(&spec.observer) == proof["observer"]
            && private157::binding(&spec.fleet) == proof["fleet"],
        "228 terminal proof is not bound to its immutable capture spec"
    );
    let origin = c::immutable_json(&origin_binding)?;
    let iid = origin["invocation_id"].as_str().context("228 origin IID")?;
    let pid = origin["main_pid"].as_u64().context("228 origin PID")?;
    let claim = PipelineClaim {
        epoch: 228,
        phase: "private-cold-snapshot-verification".into(),
        unit: c::UNIT.into(),
        invocation_id: iid.into(),
        expected_exec_start: origin["expected_exec_start"]
            .as_str()
            .context("228 original command")?
            .into(),
        evidence: vec![origin_binding],
    };
    c::claim(&claim)?;
    ensure!(
        proof["invocation_id"] == iid && proof["main_pid"] == pid,
        "228 terminal origin substituted"
    );
    let (checkpoint, clock) =
        journal(&serde_json::from_value(proof["journal"].clone())?, iid, pid)?;
    let start = origin["producer_started_unix_millis"]
        .as_u64()
        .context("228 original start")?;
    ensure!(
        clock / 1000 >= start
            && clock / 1000 - start <= 2_700_000
            && proof["terminal_unix_microseconds"] == clock
            && proof["native_marker"] == checkpoint
            && proof["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n >= clock / 1_000_000),
        "228 bounded terminal tuple/clock differs"
    );
    if proof["terminal_manager"]["LoadState"] == "not-found" {
        super::native228_collected::validate(proof)?;
    } else {
        ensure!(
            proof.get("collected_terminal").is_none(),
            "228 collected proof cannot borrow a loaded unit"
        );
        terminal_shape(&proof["terminal_manager"], iid)?;
    }
    Ok(iid.into())
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
        .context("228 proof capture clock")?;
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
        "228 terminal event replaced/staled resource history"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"].as_str().context("228 prior plan")?.into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("228 prior digest")?
            .into(),
    })?)?;
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
        "228 terminal proof lacks its exact registered origin"
    );
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
        "228 terminal changed unrelated owner/configuration"
    );
    for (epoch, g) in &old.gates {
        let n = p.gates.get(epoch).context("228 terminal gate omitted")?;
        ensure!(
            n.state == g.state
                && g.evidence.iter().all(|e| n.evidence.contains(e))
                && (*epoch == 228 || (n.evidence == g.evidence && n.next_action == g.next_action)),
            "228 terminal changed completion/unrelated gates"
        );
        if *epoch == 228 {
            ensure!(
                n.evidence
                    .iter()
                    .all(|e| g.evidence.contains(e) || p.metadata_event.as_ref() == Some(e)),
                "228 terminal added unrelated evidence"
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
    let iid = validate(&proof)?;
    let owner = current.get(c::UNIT).context("228 owner omitted")?;
    if proof.get("collected_terminal").is_some() {
        super::native228_collected::current(&proof, owner)?;
    } else {
        terminal_shape(owner, &iid)?;
    }
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
    let (b, self_sha) = publication203::parsed_args("capture-native228-terminal")?;
    let s: Spec = serde_json::from_value(bound_json(&b)?)?;
    ensure!(
        s.schema == "jetstreamer-native228-terminal-capture-spec-v1"
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-native228-terminal-proof-"))
            && s.output.file_name().is_some_and(|n| n == "proof.json"),
        "228 terminal output scope"
    );
    if s.output.try_exists()? {
        let old = c::immutable_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["capture_spec"] == private157::binding(&b)
                && old["capture_helper_sha256"] == self_sha,
            "228 terminal retry conflicts"
        );
        validate(&old)?;
        return Ok(());
    }
    let proof = checked_proof(&b, &self_sha, &s)?;
    private157::immutable_receipt(&s.output, &proof)
}

// Shared by actual capture and the read-only host regression. No receipt or
// runtime mutation occurs until capture explicitly persists the returned value.
fn checked_proof(b: &BoundFile, self_sha: &str, s: &Spec) -> Result<Value> {
    let origin = c::immutable_json(&s.running_origin)?;
    let f = bound_json(&s.fleet)?;
    let o = bound_json(&s.observer)?;
    ensure!(
        f["observer_sha256"] == s.observer.sha256 && f["sampled_at_utc"] == o["recorded_at_utc"],
        "228 terminal observer/fleet differs"
    );
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"].as_str().context("228 accepted plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("228 accepted digest")?
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
        "228 terminal lacks original registered claim"
    );
    let iid = origin["invocation_id"]
        .as_str()
        .context("228 original IID")?;
    let pid = origin["main_pid"].as_u64().context("228 original PID")?;
    let (checkpoint, clock) = journal(&s.journal, iid, pid)?;
    let before = unit(c::UNIT)?;
    let mut proof = json!({"schema":SCHEMA,"epoch":228,"unit":c::UNIT,"invocation_id":iid,"main_pid":pid,
        "running_origin":private157::binding(&s.running_origin),"journal":private157::binding(&s.journal),
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"sampled_at_utc":f["sampled_at_utc"],
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"terminal_unix_microseconds":clock,
        "native_marker":checkpoint,"terminal_manager":before,"capture_spec":private157::binding(b),"capture_helper_sha256":self_sha,
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
    if before["LoadState"] == "not-found" {
        let witness = super::native228_collected::capture(&proof, &f, &p, &origin)?;
        proof["recorded_unix_seconds"] = witness["checked_unix_seconds"].clone();
        proof["collected_terminal"] = witness;
    }
    validate(&proof)?;
    ensure!(
        unit(c::UNIT)? == before,
        "228 terminal owner changed during capture"
    );
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root read-only actual 337 collected 228 capture-spec regression; no Bank, runtime mutation, proof write or R2"]
    fn actual_collected337_capture_spec_passes_without_writing_the_proof() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let b = match (std::env::var("HORIZON_NATIVE228_CHECK_SPEC_PATH"),
            std::env::var("HORIZON_NATIVE228_CHECK_SPEC_SHA256")) {
            (Ok(path), Ok(sha256)) => BoundFile { path: path.into(), sha256 },
            (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => BoundFile {
                path: "/var/lib/jetstreamer/horizon-native228-terminal-spec-1b207be8-from337-v2/terminal-spec.json".into(),
                sha256: "1d28b1cb06eb67d456a689c931f927e73c0a079a3698cf2f7dc2792e58c220ac".into(),
            },
            _ => panic!("supply both exact sealed spec path and SHA, or neither"),
        };
        let spec: Spec = serde_json::from_value(c::immutable_json(&b).unwrap()).unwrap();
        assert!(!spec.output.try_exists().unwrap());
        let self_sha = hex_lower(&Sha256::digest(fs::read("/proc/self/exe").unwrap()));
        let proof = checked_proof(&b, &self_sha, &spec).unwrap();
        assert_eq!(proof["terminal_manager"]["LoadState"], "not-found");
        assert_eq!(
            proof["native_marker"]["capitalization"],
            "504915797589943503"
        );
        assert_eq!(proof["native_marker"]["accounts_hash"], c::ACCOUNTS_HASH);
        assert_eq!(proof["resource_samples_taken"], 0);
        assert_eq!(proof["publication_authorized"], false);
        assert!(!spec.output.try_exists().unwrap());
    }
    #[test]
    fn cleared_owner_is_not_a_replacement_restart_or_collected_unit() {
        let iid = "a".repeat(32);
        let u = json!({"Id":c::UNIT,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead", "MainPID":"0","NRestarts":"0","InvocationID":"","Result":"success","ExecMainStatus":"0"});
        terminal_shape(&u, &iid).unwrap();
        for (k, v) in [
            ("InvocationID", json!("b".repeat(32))),
            ("MainPID", json!("42")),
            ("NRestarts", json!("1")),
            ("LoadState", json!("not-found")),
            ("Result", json!("exit-code")),
            ("ExecMainStatus", json!("1")),
            ("ActiveState", json!("active")),
        ] {
            let mut bad = u.clone();
            bad[k] = v;
            assert!(terminal_shape(&bad, &iid).is_err(), "{k}");
        }
    }
    #[test]
    fn terminal_parser_keeps_consensus_integer_and_requires_original_child_and_order() {
        let iid = "a".repeat(32);
        let child = |msg: &str, t: &str| json!({"_PID":"42","_SYSTEMD_UNIT":c::UNIT,"_SYSTEMD_INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":t,"MESSAGE":msg});
        let rows = vec![
            child(
                "epoch228-v1620-native-input slot=98495291 bank_hash=fixture accounts_hash=GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq last_blockhash=fixture capitalization=18446744073709551614 transaction_count=1 tick_height=1 next_write_version=1 replay_entries=0 bootstrap_writes=0",
                "10",
            ),
            child(
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 56 filtered out; finished in 452.73s",
                "20",
            ),
            json!({"_PID":"1","UNIT":c::UNIT,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":"30","MESSAGE":format!("{}: Deactivated successfully.",c::UNIT)}),
        ];
        let (tuple, clock) = journal_rows(rows.clone(), &iid, 42).unwrap();
        assert_eq!(tuple["capitalization"], "18446744073709551614");
        assert_eq!(clock, 30);
        assert!(journal_rows(rows.clone(), &iid, 43).is_err());
        assert!(journal_rows(rows.clone(), &"b".repeat(32), 42).is_err());
        for i in 0..rows.len() {
            let mut bad = rows.clone();
            bad.remove(i);
            assert!(journal_rows(bad, &iid, 42).is_err());
        }
        let mut duplicate = rows.clone();
        duplicate.push(rows[2].clone());
        assert!(journal_rows(duplicate, &iid, 42).is_err());
        let mut wrong = rows;
        wrong[0]["MESSAGE"] = json!("epoch228-v1620-native-input slot=1");
        assert!(journal_rows(wrong, &iid, 42).is_err());
    }
}
