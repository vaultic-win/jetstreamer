//! Status-only cleanup for a positively terminal227 canary; no archive claim.
use super::*;
const UNIT: &str = "horizon-qualify-227-v1625-bounded-resource-d01adb19-v1.service";
pub(super) fn recognized(f: &Value, owners: &[(String, String)]) -> bool {
    owners.len() == 1 && owners[0].0 == UNIT && f["metadata_event"].is_object()
}
pub(super) fn validate(
    current: &BTreeMap<String, Value>,
    f: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    ensure!(recognized(f, owners), "not227 canary terminal status");
    let proof = bound_json(&serde_json::from_value(f["metadata_event"].clone())?)?;
    let (name, iid, pid) = fleet::canary227_terminal_status_identity(&proof)?;
    ensure!(
        owners[0] == (name, iid.clone()),
        "227 status differs from typed canary terminal owner"
    );
    for u in [
        current
            .get(UNIT)
            .context("227 current canary owner missing")?,
        &f["unit_census"][UNIT],
    ] {
        ensure!(
            u["Id"] == UNIT
                && u["LoadState"] == "loaded"
                && u["MainPID"] == "0"
                && u["NRestarts"] == "0"
                && (u["InvocationID"] == "" || u["InvocationID"] == iid)
                && ((u["ActiveState"] == "inactive" && u["SubState"] == "dead")
                    || (u["ActiveState"] == "failed" && u["SubState"] == "failed"))
                && u["Result"] == proof["actual_terminal"]["Result"]
                && u["ExecMainStatus"] == proof["actual_terminal"]["ExecMainStatus"],
            "227 status canary live,replaced,or ambiguous"
        );
    }
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "show",
            UNIT,
            "--no-pager",
            "--property=ExecMainPID",
            "--value",
        ])
        .output()?;
    ensure!(
        out.status.success() && std::str::from_utf8(&out.stdout)?.trim().parse::<u64>()? == pid,
        "227 latest terminal PID changed"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_canary_only() {
        let f = json!({"metadata_event":{"path":"/proof","sha256":"a".repeat(64)}});
        assert!(recognized(&f, &[(UNIT.into(), "a".repeat(32))]));
        assert!(!recognized(
            &f,
            &[(
                "horizon-native-input-227-v1625-small-v2.service".into(),
                "a".repeat(32)
            )]
        ));
        assert!(!recognized(&f, &[]));
    }
}
