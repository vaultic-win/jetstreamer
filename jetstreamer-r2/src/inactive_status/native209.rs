//! Status-only cleanup after independently proved native209 terminal success.
use super::*;
const UNIT: &str = "archive-209-v1616-native-input-actual-v1.service";
pub(super) fn recognized(f: &Value, owners: &[(String, String)]) -> bool {
    owners.len() == 1 && owners[0].0 == UNIT && f["metadata_event"].is_object()
}
pub(super) fn validate(
    current: &BTreeMap<String, Value>,
    f: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    ensure!(recognized(f, owners), "not native209 terminal status");
    let proof = bound_json(&serde_json::from_value(f["metadata_event"].clone())?)?;
    let expected = fleet::native209_terminal_status_identity(&proof)?;
    ensure!(
        owners[0] == expected,
        "209 status owner differs from terminal proof"
    );
    for u in [
        current.get(UNIT).context("209 current owner missing")?,
        &f["unit_census"][UNIT],
    ] {
        ensure!(
            u["Id"] == UNIT
                && u["LoadState"] == "loaded"
                && u["MainPID"] == "0"
                && u["NRestarts"] == "0"
                && (u["InvocationID"] == "" || u["InvocationID"] == expected.1)
                && u["ActiveState"] == "inactive"
                && u["SubState"] == "dead"
                && u["Result"] == "success",
            "209 status owner is live, replaced or ambiguous"
        );
    }
    Ok(())
}
