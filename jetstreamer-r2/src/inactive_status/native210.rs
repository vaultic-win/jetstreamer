//! Status-only cleanup after independently proved native210 terminal success.
use super::*;
const UNIT: &str = if cfg!(feature = "native210-small") {
    "archive-210-v1616-native-input-small-v2.service"
} else {
    "archive-210-v1616-native-input-actual-v1.service"
};
pub(super) fn recognized(f: &Value, owners: &[(String, String)]) -> bool {
    owners.len() == 1 && owners[0].0 == UNIT && f["metadata_event"].is_object()
}
pub(super) fn validate(
    current: &BTreeMap<String, Value>,
    f: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    ensure!(recognized(f, owners), "not native210 terminal status");
    let proof = bound_json(&serde_json::from_value(f["metadata_event"].clone())?)?;
    let expected = fleet::native210_terminal_status_identity(&proof)?;
    ensure!(
        owners[0] == expected,
        "210 status owner differs from terminal proof"
    );
    for u in [
        current.get(UNIT).context("210 current owner missing")?,
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
            "210 status owner is live, replaced or ambiguous"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_generation_cleanup_never_matches_another_native_owner() {
        let fleet = json!({"metadata_event":{"path":"/proof.json","sha256":"a".repeat(64)}});
        let current = vec![(UNIT.to_owned(), "a".repeat(32))];
        assert!(recognized(&fleet, &current));
        let other = if cfg!(feature = "native210-small") {
            "archive-210-v1616-native-input-actual-v1.service"
        } else {
            "archive-210-v1616-native-input-small-v2.service"
        };
        assert!(!recognized(&fleet, &[(other.to_owned(), "a".repeat(32))]));
        assert!(!recognized(&fleet, &[]));
        assert!(!recognized(&json!({}), &current));
    }
}
