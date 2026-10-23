//! An authenticated bounded-warmup terminal event may retain a cleared IID.
//! This only retires its misleading status; it never establishes an archive.
use super::*;
const UNIT: &str = "horizon-qualify-223-v1620-warmup-resource-d15ee08b-v1.service";
pub(super) fn recognized(f: &Value, owners: &[(String, String)]) -> bool {
    owners.len() == 1 && owners[0].0 == UNIT && f["metadata_event"].is_object()
}
fn shape(u: &Value, expected: &(String, String), proof: &Value, historical: bool) -> Result<()> {
    ensure!(
        u["Id"] == expected.0 && u["MainPID"] == "0" && u["NRestarts"] == "0",
        "bounded warmup owner is live/restarted"
    );
    if !historical && u["LoadState"] == "not-found" {
        ensure!(
            u["ActiveState"] == "inactive" && u["SubState"] == "dead" && u["InvocationID"] == "",
            "warmup collected owner differs"
        );
        return Ok(());
    }
    ensure!(
        u["LoadState"] == "loaded"
            && (u["InvocationID"] == "" || u["InvocationID"] == expected.1)
            && ((u["ActiveState"] == "inactive" && u["SubState"] == "dead")
                || (u["ActiveState"] == "failed" && u["SubState"] == "failed"))
            && u["Result"] == proof["terminal_manager"]["Result"]
            && u["ExecMainStatus"] == proof["terminal_manager"]["ExecMainStatus"]
            && u["ExecStart"]
                .as_str()
                .zip(proof["terminal_manager"]["ExecStart"].as_str())
                .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b)),
        "warmup terminal owner is replaced or ambiguous"
    );
    Ok(())
}
pub(super) fn validate(
    current: &BTreeMap<String, Value>,
    f: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    ensure!(
        recognized(f, owners),
        "not a bounded native20 warmup status"
    );
    let proof = bound_json(&serde_json::from_value(f["metadata_event"].clone())?)?;
    let expected = fleet::warmup223_terminal_status_identity(&proof)?;
    ensure!(
        owners[0] == expected,
        "warmup status owner differs from terminal proof"
    );
    shape(&f["unit_census"][UNIT], &expected, &proof, true)?;
    shape(
        current.get(UNIT).context("warmup current owner missing")?,
        &expected,
        &proof,
        false,
    )?;
    fleet::warmup223_terminal_not_replaced(&proof)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(failed: bool) -> (Value, Value, (String, String)) {
        let u = json!({"Id":UNIT,"LoadState":"loaded","MainPID":"0","NRestarts":"0","InvocationID":"","ActiveState":if failed{"failed"}else{"inactive"},"SubState":if failed{"failed"}else{"dead"},"Result":if failed{"exit-code"}else{"success"},"ExecMainStatus":if failed{"1"}else{"0"},"ExecStart":"pinned-command"});
        (
            u.clone(),
            json!({"terminal_manager":u}),
            (UNIT.into(), "a".repeat(32)),
        )
    }
    #[test]
    fn genuine_success_or_failure_can_clear_iid_but_live_or_replaced_owner_never_passes() {
        for failed in [false, true] {
            let (u, p, owner) = fixture(failed);
            shape(&u, &owner, &p, true).unwrap();
            shape(&u, &owner, &p, false).unwrap();
            for (k, v) in [
                ("InvocationID", json!("b".repeat(32))),
                ("MainPID", json!("7")),
                ("NRestarts", json!("1")),
                ("ActiveState", json!("active")),
                ("ExecStart", json!("different-command")),
                ("ExecMainStatus", json!("9")),
            ] {
                let mut bad = u.clone();
                bad[k] = v;
                assert!(shape(&bad, &owner, &p, false).is_err(), "{k}");
            }
            let gone = json!({"Id":UNIT,"LoadState":"not-found","MainPID":"0","NRestarts":"0","InvocationID":"","ActiveState":"inactive","SubState":"dead"});
            shape(&gone, &owner, &p, false).unwrap();
            assert!(shape(&gone, &owner, &p, true).is_err());
        }
    }
}
