//! Status-only cleanup after independently proved native 265 terminal success.
use super::*;
const UNIT: &str = "horizon-265-native-input-20261119-v1.service";
pub(super) fn recognized(f: &Value, owners: &[(String, String)]) -> bool {
    owners.len() == 1 && owners[0].0 == UNIT && f["metadata_event"].is_object()
}
pub(super) fn validate(
    current: &BTreeMap<String, Value>,
    f: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    ensure!(recognized(f, owners), "not native 265 terminal status");
    let binding = serde_json::from_value::<Bound>(f["metadata_event"].clone())?;
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(&binding.path)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && binding.path.canonicalize()? == binding.path,
        "265 terminal cleanup proof is mutable"
    );
    let proof = bound_json(&binding)?;
    ensure!(
        proof["boot_id"] == std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "265 terminal cleanup boot changed"
    );
    let expected = fleet::native265_terminal_status_identity(&proof)?;
    validate_values(current, f, owners, &expected)
}
pub(super) fn validate_values(
    current: &BTreeMap<String, Value>,
    f: &Value,
    owners: &[(String, String)],
    expected: &(String, String),
) -> Result<()> {
    ensure!(recognized(f, owners), "not native265 terminal status");
    ensure!(
        &owners[0] == expected,
        "265 status owner differs from terminal proof"
    );
    for u in [
        current.get(UNIT).context("265 current owner missing")?,
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
            "265 status owner is live, replaced or ambiguous"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_binds_exact_terminal_owner_and_refuses_live_or_replaced_unit() {
        let iid = "a".repeat(32);
        let owners = vec![(UNIT.into(), iid.clone())];
        let unit = json!({"Id":UNIT,"LoadState":"loaded","MainPID":"0","NRestarts":"0","InvocationID":iid,"ActiveState":"inactive","SubState":"dead","Result":"success"});
        let fleet = json!({"metadata_event":{"path":"/proof","sha256":"b".repeat(64)},"unit_census":{UNIT:unit}});
        let current = BTreeMap::from([(UNIT.into(), unit.clone())]);
        validate_values(&current, &fleet, &owners, &owners[0]).unwrap();
        for (key, bad) in [
            ("MainPID", "42"),
            ("InvocationID", "replacement"),
            ("ActiveState", "active"),
            ("NRestarts", "1"),
        ] {
            let mut changed = current.clone();
            changed.get_mut(UNIT).unwrap()[key] = json!(bad);
            assert!(
                validate_values(&changed, &fleet, &owners, &owners[0]).is_err(),
                "{key}"
            );
        }
        assert!(
            validate_values(&current, &fleet, &owners, &(UNIT.into(), "b".repeat(32))).is_err()
        );
    }
}
