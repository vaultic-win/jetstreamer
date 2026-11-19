//! Status-only cleanup after independently proved native 211 terminal success.
use super::*;
const UNIT: &str = "archive-211-v1616-native-input-actual-v1.service";
pub(super) fn recognized(f: &Value, owners: &[(String, String)]) -> bool {
    owners.len() == 1 && owners[0].0 == UNIT && f["metadata_event"].is_object()
}
pub(super) fn validate(
    current: &BTreeMap<String, Value>,
    f: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    ensure!(recognized(f, owners), "not native 211 terminal status");
    let binding = serde_json::from_value::<Bound>(f["metadata_event"].clone())?;
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(&binding.path)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && binding.path.canonicalize()? == binding.path,
        "211 terminal cleanup proof is mutable"
    );
    let proof = bound_json(&binding)?;
    ensure!(
        proof["boot_id"] == std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "211 terminal cleanup boot changed"
    );
    let expected = fleet::native211_terminal_status_identity(&proof)?;
    validate_values(current, f, owners, &expected)
}
pub(super) fn validate_values(
    current: &BTreeMap<String, Value>,
    f: &Value,
    owners: &[(String, String)],
    expected: &(String, String),
) -> Result<()> {
    ensure!(recognized(f, owners), "not native211 terminal status");
    ensure!(
        &owners[0] == expected,
        "211 status owner differs from terminal proof"
    );
    for u in [
        current.get(UNIT).context("211 current owner missing")?,
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
            "211 status owner is live, replaced or ambiguous"
        );
    }
    Ok(())
}
