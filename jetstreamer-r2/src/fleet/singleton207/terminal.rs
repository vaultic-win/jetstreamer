//! Capture natural termination separately from archive qualification and delivery.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    launch: BoundFile,
    journal: BoundFile,
    output: PathBuf,
}
fn journal_shape(rows: &[Value], iid: &str, pid: u64, succeeded: bool) -> Result<()> {
    ensure!(
        !rows.is_empty() && rows.len() <= 16384,
        "singleton 207 terminal journal bounds"
    );
    let marker = format!("{UNIT}: Deactivated successfully.");
    let mut completed = 0;
    let mut own = 0;
    for row in rows {
        if row["_PID"] == "1" {
            ensure!(
                row["UNIT"] == UNIT && row["INVOCATION_ID"] == iid,
                "singleton 207 terminal manager journal has a foreign owner"
            );
            if row["MESSAGE"] == marker {
                completed += 1;
            }
        } else {
            ensure!(
                row["_SYSTEMD_UNIT"] == UNIT
                    && row["_SYSTEMD_INVOCATION_ID"] == iid
                    && row["_PID"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(pid),
                "singleton 207 terminal producer journal has a foreign owner or PID"
            );
            own += 1;
        }
    }
    ensure!(
        own > 0 && (!succeeded || completed == 1),
        "singleton 207 natural success lacks exact producer and PID1 completion evidence"
    );
    Ok(())
}
pub(super) fn validate_saved(
    proof: &Value,
    launch_binding: &BoundFile,
    launch: &Value,
) -> Result<()> {
    let iid = launch["evidence"]["units"][0]["invocation_id"]
        .as_str()
        .context("207 terminal launch IID absent")?;
    let pid = launch["evidence"]["units"][0]["main_pid"]
        .as_u64()
        .context("207 terminal launch PID absent")?;
    ensure!(
        proof["schema"] == "jetstreamer-private-singleton207-terminal-v1"
            && scope_matches(proof)
            && proof["launch"] == private157::binding(launch_binding)
            && proof["invocation_id"] == iid
            && proof["main_pid"] == pid
            && proof["natural_parent_completion_observed"] == true
            && proof["delivery_admission_still_required"] == true
            && proof["resource_samples_taken"] == 0,
        "207 delivery requires genuine successful original terminal proof"
    );
    deny_authority(proof)?;
    delivery::terminal_manager(&proof["terminal_manager"], iid)?;
    let b: BoundFile = serde_json::from_value(proof["journal"].clone())?;
    let raw = read_stable_bounded(&b.path, 16 << 20, "207 immutable terminal journal")?;
    ensure!(
        hex_lower(&Sha256::digest(&raw)) == b.sha256,
        "207 terminal journal changed"
    );
    let rows = serde_json::Deserializer::from_slice(&raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    journal_shape(&rows, iid, pid, true)
}
pub(super) fn run() -> Result<()> {
    let (bound, helper_sha) = publication203::parsed_args("capture-singleton207-terminal")?;
    let spec: Spec = serde_json::from_value(native209::immutable_json(&bound)?)?;
    ensure!(
        spec.schema == "jetstreamer-singleton207-terminal-spec-v1",
        "singleton 207 terminal spec differs"
    );
    admission::output(
        &spec.output,
        "terminal.json",
        "horizon-singleton207-terminal-",
    )?;
    let launch = native209::immutable_json(&spec.launch)?;
    let iid = launch["evidence"]["units"][0]["invocation_id"]
        .as_str()
        .context("singleton 207 original terminal owner absent")?;
    let pid = launch["evidence"]["units"][0]["main_pid"]
        .as_u64()
        .context("singleton 207 original terminal PID absent")?;
    let claim = DiagnosticClaim {
        epoch: 207,
        unit: UNIT.into(),
        invocation_id: iid.into(),
        scratch_path: ROOT.into(),
        launch_receipt: binding(
            spec.launch.path.to_str().context("terminal launch UTF-8")?,
            &spec.launch.sha256,
        ),
    };
    bindings(&claim, &launch)?;
    let before = unit(UNIT)?;
    ensure!(
        before["Id"] == UNIT
            && before["LoadState"] == "loaded"
            && before["MainPID"] == "0"
            && before["NRestarts"] == "0"
            && (before["InvocationID"] == iid || before["InvocationID"] == "")
            && matches!(before["ActiveState"].as_str(), Some("inactive" | "failed"))
            && private_prefix::same_command(&before["ExecStart"], &command()),
        "singleton 207 is live, changed, restarted, or not terminal"
    );
    let bytes = read_stable_bounded(
        &spec.journal.path,
        16 << 20,
        "singleton 207 terminal journal",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == spec.journal.sha256,
        "singleton 207 terminal journal hash differs"
    );
    let rows = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let succeeded = before["ActiveState"] == "inactive"
        && before["SubState"] == "dead"
        && before["Result"] == "success"
        && before["ExecMainStatus"] == "0";
    journal_shape(&rows, iid, pid, succeeded)?;
    let mut proof = scope();
    proof["schema"] = json!("jetstreamer-private-singleton207-terminal-v1");
    proof["launch"] = private157::binding(&spec.launch);
    proof["journal"] = private157::binding(&spec.journal);
    proof["unit"] = json!(UNIT);
    proof["invocation_id"] = json!(iid);
    proof["main_pid"] = json!(pid);
    proof["terminal_manager"] = before.clone();
    proof["natural_parent_completion_observed"] = json!(succeeded);
    proof["delivery_admission_still_required"] = json!(true);
    proof["resource_samples_taken"] = json!(0);
    proof["helper_sha256"] = json!(helper_sha);
    proof["recorded_unix_seconds"] = json!(now()?);
    deny_fields(&mut proof);
    ensure!(
        before == unit(UNIT)?,
        "singleton 207 terminal identity changed during capture"
    );
    private157::immutable_receipt(&spec.output, &proof)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn natural_terminal_requires_same_owner_producer_and_manager() {
        let iid = "a".repeat(32);
        let rows = vec![
            json!({"_PID":"40","_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":iid}),
            json!({"_PID":"1","UNIT":UNIT,"INVOCATION_ID":iid,"MESSAGE":format!("{UNIT}: Deactivated successfully.")}),
        ];
        journal_shape(&rows, &iid, 40, true).unwrap();
        assert!(journal_shape(&rows, &iid, 41, true).is_err());
        assert!(journal_shape(&rows, &"b".repeat(32), 40, true).is_err());
        assert!(journal_shape(&rows[..1], &iid, 40, true).is_err());
        journal_shape(&rows[..1], &iid, 40, false).unwrap();
    }
}
