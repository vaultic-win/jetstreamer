//! Exact collected 157 missing-terminal failure; no ready-archive assertion.
use super::*;
const CONTROLLER: &str = "jetstreamer-epoch157-target3-controller-v1-r2.service";
const CONTROLLER_IID: &str = "fcba4ece12fa462faf9062a3ad607879";
const PRODUCER: &str = "jetstreamer-root-sweep-e157-t3-20261014-v1-r2-e157-157-lane-j-1.service";
const IID: &str = "d66eddeac8304adfbd17e4ebe1c6c1f9";
pub(super) fn recognized(e: &Value) -> bool {
    e["schema"] == "jetstreamer-epoch157-missing-terminal-incident-v1"
}
fn validate(e: &Value, owners: &[(String, String)]) -> Result<Vec<Value>> {
    ensure!(
        recognized(e)
            && e["epoch"] == 157
            && e["host"] == "dev-samjohnson"
            && owners
                == [
                    (CONTROLLER.into(), CONTROLLER_IID.into()),
                    (PRODUCER.into(), IID.into())
                ]
            && e["collector_sha256"]
                == "da4e316f37f0e2ea7af4f37155da20fc52af99a3dcb8ce4b0e47a86e175da8de"
            && e["producer_invocation_id"] == IID
            && e["controller"]["InvocationID"] == CONTROLLER_IID
            && e["retry_path_quarantined"] == true
            && e["failure"]["kind"] == "missing-canonical-terminal-checkpoint"
            && e["failure"]["slot"] == 68255999
            && e["failure"]["last_trusted_root"] == 68255828
            && e["controller_state"]["assignments"]["lane-j"]["phase"] == "failed",
        "157incident owner/cause differs"
    );
    for flag in [
        "replay_launch_authorized",
        "publication_authorized",
        "local_retirement_authorized",
        "service_mutations",
        "r2_mutations",
    ] {
        ensure!(e[flag] == false, "157incident grants authority");
    }
    let raw = e["journal_raw_utf8"]
        .as_str()
        .context("157raw journal absent")?;
    ensure!(
        hex_lower(&Sha256::digest(raw.as_bytes())) == e["journal_sha256"].as_str().unwrap_or(""),
        "157journal hash differs"
    );
    let records: Vec<Value> = raw
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(records.len()==e["journal_entry_count"].as_u64().unwrap_or(0) as usize
        && records.iter().all(|r|r["_SYSTEMD_INVOCATION_ID"]==IID && r["_SYSTEMD_UNIT"]==PRODUCER && r["_UID"]=="1001")
        && records.iter().filter(|r|r["MESSAGE"].as_str().is_some_and(|s|s.contains("qualification requires the exact canonical terminal checkpoint at slot 68255999; none was supplied"))).count()==2
        && records.iter().any(|r|r["_PID"]=="1725802" && r["MESSAGE"].as_str().is_some_and(|s|s.contains("runtime segment 1 failed after 2 attempt(s)"))),"157terminal journal differs");
    Ok(records)
}
fn owners() -> Vec<(String, String)> {
    vec![
        (CONTROLLER.into(), CONTROLLER_IID.into()),
        (PRODUCER.into(), IID.into()),
    ]
}
pub(super) fn time(e: &Value) -> Result<u64> {
    validate(e, &owners())?
        .iter()
        .map(|r| {
            r["__REALTIME_TIMESTAMP"]
                .as_str()
                .context("157journal time")?
                .parse::<u64>()
                .map(|n| n / 1_000_000)
                .map_err(Into::into)
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .context("157empty journal")
}
fn terminal_shapes(current: &BTreeMap<String, Value>) -> Result<()> {
    let controller = current.get(CONTROLLER).context("157controller absent")?;
    let producer = current.get(PRODUCER).context("157producer absent")?;
    ensure!(
        controller["Id"] == CONTROLLER
            && controller["LoadState"] == "loaded"
            && controller["ActiveState"] == "inactive"
            && controller["SubState"] == "dead"
            && controller["MainPID"] == "0"
            && controller["InvocationID"] == ""
            && controller["NRestarts"] == "0"
            && producer["LoadState"] == "not-found"
            && producer["ActiveState"] == "inactive"
            && producer["SubState"] == "dead"
            && producer["MainPID"] == "0"
            && producer["InvocationID"] == "",
        "157 owner live, replaced, or terminal identity ambiguous"
    );
    Ok(())
}
pub(super) fn validate_current(
    current: &BTreeMap<String, Value>,
    e: &Value,
    expected: &[(String, String)],
) -> Result<()> {
    validate(e, expected)?;
    terminal_shapes(current)?;
    // A cleared InvocationID alone is not terminal proof. Require PID 1's latest
    // authenticated manager lifecycle to stop this exact controller, repeatedly.
    status_inactive::cleared_controller_proof(CONTROLLER, CONTROLLER_IID)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires exact root-only 157 incident and stopped controller; read-only, no R2 calls"]
    fn exact_collected157_failure_has_authenticated_stopped_manager() {
        let b = Bound {
            path: "/var/lib/jetstreamer/horizon-epoch157-incident-20261021-v1/incident.json".into(),
            sha256: "00c2bbed7338c19b688a50a7ad14bdc639f98659a56de2cbe8a31abe40c47159".into(),
        };
        let e = bound_json(&b).unwrap();
        assert!(time(&e).unwrap() > 0);
        let current = BTreeMap::from([
            (CONTROLLER.into(), fleet::unit(CONTROLLER).unwrap()),
            (PRODUCER.into(), fleet::unit(PRODUCER).unwrap()),
        ]);
        validate_current(&current, &e, &owners()).unwrap();
        let mut other = owners();
        other[0].1 = "f".repeat(32);
        assert!(validate_current(&current, &e, &other).is_err());
    }
    #[test]
    fn cleared_id_never_accepts_a_live_replacement_or_unbound_producer() {
        let mut current = BTreeMap::from([
            (
                CONTROLLER.into(),
                json!({"Id":CONTROLLER,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","InvocationID":"","NRestarts":"0"}),
            ),
            (
                PRODUCER.into(),
                json!({"LoadState":"not-found","ActiveState":"inactive","SubState":"dead","MainPID":"0","InvocationID":""}),
            ),
        ]);
        terminal_shapes(&current).unwrap();
        current.get_mut(CONTROLLER).unwrap()["InvocationID"] = json!("f".repeat(32));
        assert!(terminal_shapes(&current).is_err());
        current.get_mut(CONTROLLER).unwrap()["InvocationID"] = json!("");
        current.get_mut(PRODUCER).unwrap()["MainPID"] = json!("123");
        assert!(terminal_shapes(&current).is_err());
        assert!(validate(&json!({}), &owners()).is_err());
    }
}
