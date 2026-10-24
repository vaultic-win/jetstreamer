//! Conditional status-only cleanup using the accepted full210 terminal proof.
//! Never infer an archive/content/checkpoint result from process completion.
use super::*;
const UNIT: &str = "horizon-singleton-210-capped-4aeca563-v1.service";

pub(super) fn recognized(f: &Value, owners: &[(String, String)]) -> bool {
    owners.len() == 1 && owners[0].0 == UNIT && f["metadata_event"].is_object()
}
pub(super) fn validate(
    current: &BTreeMap<String, Value>,
    f: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    ensure!(
        recognized(f, owners),
        "not an exact full210 terminal status owner"
    );
    let proof = bound_json(&serde_json::from_value(f["metadata_event"].clone())?)?;
    let expected = fleet::full210_terminal_status_identity(&proof)?;
    ensure!(
        owners[0] == expected,
        "full210 status belongs to a different terminal invocation"
    );
    // These two independently bound snapshots must preserve the real cleared or
    // retained manager IID. The fleet helper additionally checks the latest main
    // PID/start/exit and boot against sealed raw PID1 journal provenance.
    for u in [
        current.get(UNIT).context("full210 current owner missing")?,
        &f["unit_census"][UNIT],
    ] {
        fleet::full210_terminal_current(&proof, u)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_never_borrows_native210_or_another_full_epoch_owner() {
        let f = json!({"metadata_event":{"path":"/proof.json","sha256":"a".repeat(64)}});
        assert!(recognized(&f, &[(UNIT.into(), "a".repeat(32))]));
        for other in [
            "archive-210-v1616-native-input-small-v2.service",
            "archive-210-v1616-native-input-actual-v1.service",
            "horizon-singleton-209-capped-4aeca563-v1.service",
            "horizon-singleton-210-other.service",
        ] {
            assert!(
                !recognized(&f, &[(other.into(), "a".repeat(32))]),
                "{other}"
            );
        }
        assert!(!recognized(&f, &[]));
        assert!(!recognized(
            &f,
            &[(UNIT.into(), "a".repeat(32)), (UNIT.into(), "b".repeat(32))]
        ));
        assert!(!recognized(&json!({}), &[(UNIT.into(), "a".repeat(32))]));
    }
}
