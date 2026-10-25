//! Preserve a real terminal canary without promoting its diagnostic result.
use super::canary227 as c;
use super::singleton227_capture::{journal, properties};
use super::*;
mod cleared;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch227-v1625-canary-terminal-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    launch: BoundFile,
    result: Option<BoundFile>,
    #[serde(default)]
    journal: Option<BoundFile>,
    output: PathBuf,
}
fn claim(b: &BoundFile, r: &Value) -> Result<DiagnosticClaim> {
    let d = DiagnosticClaim {
        epoch: 227,
        unit: c::UNIT.into(),
        invocation_id: r["invocation_id"]
            .as_str()
            .context("227 canary terminal origin IID")?
            .into(),
        scratch_path: c::ROOT.into(),
        launch_receipt: BoundFile {
            path: b.path.clone(),
            sha256: b.sha256.clone(),
        },
    };
    validate_diagnostic_launch(r, &d)?;
    ensure!(
        c::launch_matches(&d, r),
        "227 terminal original launch differs"
    );
    Ok(d)
}
pub(super) fn terminal(u: &Value, iid: &str, pid: u64) -> Result<()> {
    ensure!(
        u["Id"] == c::UNIT
            && u["LoadState"] == "loaded"
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && (u["InvocationID"] == "" || u["InvocationID"] == iid)
            && u["ExecMainPID"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                == Some(pid)
            && ((u["ActiveState"] == "inactive" && u["SubState"] == "dead")
                || (u["ActiveState"] == "failed" && u["SubState"] == "failed"))
            && u["Result"].as_str().is_some_and(|n| !n.is_empty())
            && u["ExecMainStatus"]
                .as_str()
                .is_some_and(|n| n.parse::<u64>().is_ok()),
        "227 canary is live, replaced, restarted or terminal identity ambiguous"
    );
    Ok(())
}
fn result_scope(v: &Value, d: &DiagnosticClaim, launch: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch227-v1625-comparison-result-v1"
            && v["epoch"] == 227
            && v["unit"] == c::UNIT
            && v["invocation_id"] == d.invocation_id
            && v["plan"] == launch["resource_plan"]
            && v["runner_sha256"] == c::RUNNER_SHA
            && v["node_sha256"] == c::NODE_SHA
            && v["worker_sha256"] == c::WORKER_SHA
            && v["snapshot_sha256"] == c::SNAPSHOT_SHA
            && v["target_slot"] == c::TARGET
            && v["success"].is_boolean()
            && v["target_reached"].is_boolean()
            && v["elapsed_millis"].as_u64().is_some()
            && v["authority"]["ordinary_replay_authorized"] == false
            && v["authority"]["full_cold_epoch_peak_qualified"] == false
            && v["authority"]["publication_authorized"] == false
            && v["authority"]["runtime_promotion_authorized"] == false
            && v["authority"]["canonical_sidecar_authorized"] == false
            && v["authority"]["remote_mutations"] == false
            && v["authority"]["r2_mutations"] == false,
        "227 terminal result borrowed another plan/runtime or granted authority"
    );
    Ok(())
}
fn runner_result(b: &Option<BoundFile>, d: &DiagnosticClaim, launch: &Value) -> Result<Value> {
    let Some(b) = b else {
        for n in ["receipts/resource.json", "receipts/failure.json"] {
            ensure!(
                fs::symlink_metadata(Path::new(c::ROOT).join(n))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "227 result exists but was omitted"
            );
        }
        return Ok(Value::Null);
    };
    ensure!(
        ["receipts/resource.json", "receipts/failure.json"]
            .iter()
            .any(|n| b.path == Path::new(c::ROOT).join(n)),
        "227 result path differs"
    );
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 1000
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o400,
        "227 result is not immutable actual runner evidence"
    );
    let result = bound_json(b)?;
    result_scope(&result, d, launch)?;
    Ok(result)
}
pub(super) fn validate(p: &Value) -> Result<String> {
    let b: BoundFile = serde_json::from_value(p["launch"].clone())?;
    let launch = native227_v1625::immutable_json(&b)?;
    let d = claim(&b, &launch)?;
    let pid = launch["main_pid"]
        .as_u64()
        .filter(|n| *n > 1)
        .context("227 terminal origin PID")?;
    ensure!(
        p["schema"] == SCHEMA
            && p["epoch"] == 227
            && p["unit"] == c::UNIT
            && p["invocation_id"] == d.invocation_id
            && p["main_pid"] == pid
            && p["original_failed_invocation_id"] == c::ORIGINAL_IID
            && p["preserve_original_failed227_history"] == true
            && p["repair_gate_state"] == "failed-needs-repair"
            && p["resource_samples_taken"] == 0
            && p["semantic_success_qualified"] == false
            && p["full_epoch_qualified"] == false
            && p["runtime_promotion_authorized"] == false
            && p["canonical_sidecar_authorized"] == false
            && p["publication_authorized"] == false
            && p["remote_mutations"] == false
            && p["r2_mutations"] == false
            && p["release_credit_bytes"] == 0,
        "227 terminal proof scope or authority differs"
    );
    if cleared::recognized(p) {
        cleared::validate_saved(p, &launch, &d.invocation_id, pid)?;
    } else {
        ensure!(
            p.get("terminal_identity_policy").is_none() && p.get("cleared_journal").is_none(),
            "227 terminal identity policy is unknown or partial"
        );
        terminal(&p["actual_terminal"], &d.invocation_id, pid)?;
    }
    if p["runner_result_available"] == true {
        result_scope(&p["result"], &d, &launch)?;
        ensure!(
            p["result_binding"].is_object(),
            "227 runner result binding absent"
        );
    } else {
        ensure!(
            p["runner_result_available"] == false
                && p["result"].is_null()
                && p["result_binding"].is_null(),
            "227 terminal cannot fabricate missing runner result"
        );
    }
    ensure!(
        p["recorded_unix_seconds"].as_u64().is_some()
            && p["manager_completion"]["_PID"] == "1"
            && p["manager_completion"]["_UID"] == "0"
            && p["manager_completion"]["UNIT"] == c::UNIT
            && p["manager_completion"]["INVOCATION_ID"] == d.invocation_id,
        "227 terminal manager provenance absent"
    );
    Ok(d.invocation_id)
}
pub(super) fn capture() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-canary227-v1625-terminal")?;
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch227-v1625-canary-terminal-spec-v1"
            && s.output
                == Path::new(
                    "/var/lib/jetstreamer/horizon-227-v1625-canary-terminal-selection-v2/proof.json"
                ),
        "227 terminal destination or result differs"
    );
    if s.output.try_exists()? {
        let old = native227_v1625::immutable_json(&serde_json::from_value(
            private157::file_binding(&s.output)?,
        )?)?;
        validate(&old)?;
        ensure!(
            old["spec_sha256"] == binding.sha256 && old["self_sha256"] == self_sha,
            "227 terminal retry conflict"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let launch = native227_v1625::immutable_json(&s.launch)?;
    let d = claim(&s.launch, &launch)?;
    let pid = launch["main_pid"]
        .as_u64()
        .context("227 terminal original PID")?;
    let mut before = unit(c::UNIT)?;
    let latest_pid = properties(c::UNIT, "ExecMainPID")?;
    before["ExecMainPID"] = json!(
        latest_pid
            .get("ExecMainPID")
            .context("227 terminal latest PID")?
    );

    if before["ExecMainPID"] == "0" {
        return cleared::capture(&s, &binding, &self_sha, &launch, &d, pid);
    }
    ensure!(
        s.journal.is_none(),
        "227 retained terminal must not substitute a cleared journal"
    );

    terminal(&before, &d.invocation_id, pid)?;
    let result = runner_result(&s.result, &d, &launch)?;
    let result_binding = s.result.as_ref().map_or(Value::Null, private157::binding);
    let props = properties(
        c::UNIT,
        "ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic",
    )?;
    let started = props["ExecMainStartTimestampMonotonic"].parse::<u64>()?;
    let exited = props["ExecMainExitTimestampMonotonic"].parse::<u64>()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let (rows, journal_sha) = journal(c::UNIT)?;
    let rows = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == c::UNIT
                && r["INVOCATION_ID"] == d.invocation_id
                && r["_BOOT_ID"] == boot
                && r["__MONOTONIC_TIMESTAMP"]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|n| n >= exited && n - exited <= 5_000_000)
                && (r["MESSAGE"] == format!("{}: Deactivated successfully.", c::UNIT)
                    || r["MESSAGE"].as_str().is_some_and(|n| {
                        n.starts_with(&format!("{}: Failed with result '", c::UNIT))
                    }))
        })
        .collect::<Vec<_>>();
    ensure!(
        started > 0 && exited >= started && rows.len() == 1,
        "227 terminal exact latest manager completion absent"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let p = json!({"schema":SCHEMA,"epoch":227,"unit":c::UNIT,"invocation_id":d.invocation_id,"main_pid":pid,"launch":private157::binding(&s.launch),"result_binding":result_binding,"runner_result_available":s.result.is_some(),"result":result,"actual_terminal":before,
        "original_failed_invocation_id":c::ORIGINAL_IID,"preserve_original_failed227_history":true,"repair_gate_state":"failed-needs-repair","resource_samples_taken":0,"release_credit_bytes":0,
        "semantic_success_qualified":false,"full_epoch_qualified":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
        "manager_completion":rows[0],"journal_sha256":journal_sha,"actual_terminal_clocks":props,"recorded_unix_seconds":now,"sampled_at_utc":publication203::utc(now)?,"spec_sha256":binding.sha256,"self_sha256":self_sha});
    validate(&p)?;
    ensure!(
        {
            let mut after = unit(c::UNIT)?;
            let p = properties(c::UNIT, "ExecMainPID")?;
            after["ExecMainPID"] = json!(p.get("ExecMainPID").context("227 terminal latest PID")?);
            after == before
        } && runner_result(&s.result, &d, &launch)? == result,
        "227 terminal identity/result changed"
    );
    private157::immutable_receipt(&s.output, &p)
}
pub(super) fn validate_current(proof: &Value, current: &Value) -> Result<()> {
    let iid = validate(proof)?;
    if cleared::recognized(proof) {
        cleared::current(proof, current)
    } else {
        let mut actual = current.clone();
        let p = properties(c::UNIT, "ExecMainPID")?;
        actual["ExecMainPID"] = json!(p.get("ExecMainPID").context("227 latest terminal PID")?);
        terminal(
            &actual,
            &iid,
            proof["main_pid"].as_u64().context("227 terminal PID")?,
        )
    }
}
pub(super) fn predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    let iid = validate(proof)?;
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("227 terminal event clock")?;
    ensure!(
        previous["schema"] == super::SCHEMA
            && previous["sampled_at_utc"] == sampled
            && previous["observer_receipt"].as_str() == p.observer.path.to_str()
            && previous["observer_sha256"] == p.observer.sha256
            && p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && clock > utc_seconds(sampled)?
            && clock <= now
            && now - clock <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < clock),
        "227 terminal event replaced or stale resource clock"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"]
            .as_str()
            .context("227 terminal old plan")?
            .into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("227 terminal old plan sha")?
            .into(),
    })?)?;
    ensure!(
        p.schema == old.schema
            && p.observer == old.observer
            && p.status_receipt_directory == old.status_receipt_directory
            && p.tracked_units == old.tracked_units
            && p.pipeline_claims == old.pipeline_claims
            && p.runtime_handoff157 == old.runtime_handoff157
            && p.continuation203_runtime_extension == old.continuation203_runtime_extension
            && p.epoch203_ram_auxiliary.is_none()
            && old.epoch203_ram_auxiliary.is_none()
            && p.diagnostics.len() == old.diagnostics.len()
            && old
                .diagnostics
                .iter()
                .all(|d| p.diagnostics.iter().any(|n| d.epoch == n.epoch
                    && d.unit == n.unit
                    && d.invocation_id == n.invocation_id
                    && d.scratch_path == n.scratch_path
                    && d.launch_receipt == n.launch_receipt))
            && p.gates.len() == old.gates.len(),
        "227 terminal event changed owner/configuration history"
    );
    ensure!(
        p.diagnostics.iter().any(|d| c::namespace(d)
            && d.invocation_id == iid
            && private157::binding(&d.launch_receipt) == proof["launch"]),
        "227 terminal did not bind registered canary"
    );
    for (epoch, g) in &old.gates {
        let n = p.gates.get(epoch).context("227 terminal omitted gate")?;
        ensure!(
            n.state == g.state
                && serde_json::to_value(&n.reserve_stop)? == serde_json::to_value(&g.reserve_stop)?
                && g.evidence.iter().all(|b| n.evidence.contains(b))
                && (*epoch == 227 || (n.evidence == g.evidence && n.next_action == g.next_action)),
            "227 terminal changed unrelated gate"
        );
        if *epoch == 227 {
            ensure!(
                n.state == "failed-needs-repair"
                    && n.evidence
                        .iter()
                        .all(|b| g.evidence.contains(b) || p.metadata_event.as_ref() == Some(b)),
                "227 terminal promoted repair or inserted unrelated evidence"
            );
        }
    }
    Ok(())
}
pub(super) fn census_check(p: &Plan, current: &BTreeMap<String, Value>) -> Result<()> {
    if let Some(b) = &p.metadata_event {
        let proof = bound_json(b)?;
        if proof["schema"] == SCHEMA {
            let u = current.get(c::UNIT).context("227 terminal owner omitted")?;
            validate_current(&proof, u)?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_cannot_accept_live_restarted_or_replaced_canary() {
        let mut u = json!({"Id":c::UNIT,"LoadState":"loaded","MainPID":"0","NRestarts":"0","InvocationID":"","ExecMainPID":"42","ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainStatus":"0"});
        terminal(&u, &"a".repeat(32), 42).unwrap();
        for (k, v) in [
            ("MainPID", "42"),
            ("NRestarts", "1"),
            ("ExecMainPID", "43"),
            ("InvocationID", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ("ActiveState", "active"),
        ] {
            let good = u[k].clone();
            u[k] = json!(v);
            assert!(terminal(&u, &"a".repeat(32), 42).is_err(), "{k}");
            u[k] = good;
        }
    }
}
