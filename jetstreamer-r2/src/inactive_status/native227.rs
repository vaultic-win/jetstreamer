//! Cleared native 227 owner identity is proved by its exact PID1 terminal event.
use super::*;
const UNIT: &str = "horizon-native-input-227-capped-710f6523-v1.service";
pub(super) fn recognized(terminal_fleet: &Value, owners: &[(String, String)]) -> bool {
    owners.len() == 1
        && owners[0].0 == UNIT
        && terminal_fleet["metadata_event"].is_object()
        && terminal_fleet["unit_census"][UNIT]["MainPID"] == "0"
}
fn shape(value: &Value, iid: &str) -> bool {
    value["Id"] == UNIT
        && value["MainPID"] == "0"
        && value["NRestarts"] == "0"
        && (value["InvocationID"] == iid || value["InvocationID"] == "")
        && matches!(
            (value["ActiveState"].as_str(), value["SubState"].as_str()),
            (Some("inactive"), Some("dead")) | (Some("failed"), Some("failed"))
        )
}
pub(super) fn validate(
    current: &BTreeMap<String, Value>,
    terminal_fleet: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    ensure!(
        recognized(terminal_fleet, owners),
        "not a native 227 terminal owner"
    );
    let binding: Bound = serde_json::from_value(terminal_fleet["metadata_event"].clone())?;
    let proof = bound_json(&binding)?;
    let proven = fleet::native227_terminal_status_identity(&proof)?;
    ensure!(
        owners[0] == proven,
        "native 227 terminal event names another invocation"
    );
    ensure!(
        shape(
            current
                .get(UNIT)
                .context("native 227 current owner absent")?,
            &proven.1
        ) && shape(&terminal_fleet["unit_census"][UNIT], &proven.1),
        "native 227 owner live, replaced or lacking terminal history"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleared_iid_needs_terminal_shape_and_never_accepts_replacement_or_restart() {
        let u = json!({"Id":UNIT,"MainPID":"0","NRestarts":"0","InvocationID":"","ActiveState":"inactive","SubState":"dead"});
        assert!(shape(&u, &"a".repeat(32)));
        for (k, v) in [
            ("InvocationID", json!("b".repeat(32))),
            ("MainPID", json!("42")),
            ("NRestarts", json!("1")),
            ("ActiveState", json!("active")),
        ] {
            let mut bad = u.clone();
            bad[k] = v;
            assert!(!shape(&bad, &"a".repeat(32)));
        }
    }
}
