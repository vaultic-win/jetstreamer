//! Collected native owner history comes from its authenticated terminal event.
//! Never manufacture a loaded unit or infer completion from current absence.
use super::*;
pub(super) fn recognized(terminal_fleet: &Value, owners: &[(String, String)]) -> bool {
    owners.len() == 1
        && owners[0].0.starts_with("archive-223-v1620-native-input-")
        && fleet::pipeline_unit_range_for_epoch(
            "private-cold-snapshot-verification",
            &owners[0].0,
            223,
        )
        .is_ok()
        && terminal_fleet["unit_census"][&owners[0].0]["LoadState"] == "not-found"
}
fn collected(value: &Value, name: &str) -> bool {
    value["Id"] == name
        && value["LoadState"] == "not-found"
        && value["ActiveState"] == "inactive"
        && value["SubState"] == "dead"
        && value["InvocationID"] == ""
        && value["MainPID"] == "0"
        && value["NRestarts"] == "0"
}
fn validate_shapes(
    current: &Value,
    historical: &Value,
    expected: &(String, String),
    proven: &(String, String),
) -> Result<()> {
    ensure!(
        expected == proven,
        "collected native 223 terminal event names another invocation"
    );
    ensure!(
        collected(current, &expected.0) && collected(historical, &expected.0),
        "native 223 owner is live, replaced or lacks genuine collected history"
    );
    Ok(())
}
pub(super) fn validate(
    current: &BTreeMap<String, Value>,
    terminal_fleet: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    ensure!(
        recognized(terminal_fleet, owners),
        "not an approved collected native 223 owner"
    );
    let binding: Bound = serde_json::from_value(terminal_fleet["metadata_event"].clone())?;
    let proof = bound_json(&binding)?;
    let proven = fleet::native223_terminal_status_identity(&proof)?;
    let expected = &owners[0];
    validate_shapes(
        current
            .get(&expected.0)
            .context("native 223 owner absent from current census")?,
        &terminal_fleet["unit_census"][&expected.0],
        expected,
        &proven,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unrelated_event_cannot_prove_collected_native_terminality() {
        assert!(fleet::native223_terminal_status_identity(&json!({
            "schema":"unrelated-terminal-event","unit":"archive-223-v1620-native-input-release-actual-v1.service",
            "invocation_id":"3867f8a2fae1471e9490e3d4a2208cf3","resource_samples_taken":0
        })).is_err());
    }
    #[test]
    fn collected_native_history_rejects_wrong_iid_live_replacement_and_fabricated_loaded_state() {
        let unit = "archive-223-v1620-native-input-release-actual-v1.service";
        let owner = (unit.into(), "3867f8a2fae1471e9490e3d4a2208cf3".into());
        let absent = json!({"Id":unit,"LoadState":"not-found","ActiveState":"inactive","SubState":"dead","InvocationID":"","MainPID":"0","NRestarts":"0"});
        validate_shapes(&absent, &absent, &owner, &owner).unwrap();
        assert!(validate_shapes(&absent, &absent, &owner, &(unit.into(), "0".repeat(32))).is_err());
        assert!(
            validate_shapes(
                &absent,
                &absent,
                &owner,
                &("unrelated.service".into(), owner.1.clone())
            )
            .is_err()
        );
        for (key, value) in [
            ("LoadState", json!("loaded")),
            ("ActiveState", json!("active")),
            ("SubState", json!("running")),
            ("InvocationID", json!("0".repeat(32))),
            ("MainPID", json!("42")),
            ("NRestarts", json!("1")),
        ] {
            let mut bad = absent.clone();
            bad[key] = value;
            assert!(
                validate_shapes(&bad, &absent, &owner, &owner).is_err(),
                "current {key}"
            );
            assert!(
                validate_shapes(&absent, &bad, &owner, &owner).is_err(),
                "historical {key}"
            );
        }
    }
}
