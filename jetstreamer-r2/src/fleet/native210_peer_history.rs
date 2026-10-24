//! Keep the original full 227 attempt in history after authentic termination.
//! Only accepted live owners reserve future growth; this never edits a census.
use super::*;
const IID: &str = "a10f37b57711425a81633c62c66438d5";
const LAUNCH: &str = "/var/lib/jetstreamer/horizon-227-capture-full330-v1/launch.json";
const LAUNCH_SHA: &str = "12eb6beb36d13e9c35c26280908f3fe6df9f2489eedfc59d4ced6a094997172d";

fn record(f: &Value) -> Result<&Value> {
    let rows = f["diagnostics"]
        .as_array()
        .context("210 retained diagnostic history")?
        .iter()
        .filter(|d| d["unit"]["Id"] == singleton227::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1,
        "210 original full 227 history missing or duplicated"
    );
    Ok(rows[0])
}
pub(super) fn validate(f: &Value) -> Result<()> {
    let d = record(f)?;
    let u = &d["unit"];
    ensure!(
        d["epoch"] == 227
            && d["scope_first_epoch"] == 227
            && d["scope_last_epoch"] == 227
            && d["launch_invocation_id"] == IID
            && d["launch_receipt"] == LAUNCH
            && d["launch_receipt_sha256"] == LAUNCH_SHA
            && u["Id"] == singleton227::UNIT
            && u["InvocationID"] == IID
            && u["NRestarts"] == "0"
            && f["unit_census"][singleton227::UNIT] == *u,
        "210 full 227 retained launch or manager identity differs"
    );
    let active = f["active"]
        .as_array()
        .context("210 complete active history")?
        .iter()
        .map(|r| singleton227_admission::active_owner(r))
        .collect::<Result<Vec<_>>>()?;
    let matches = active
        .into_iter()
        .filter(|p| p["Id"] == singleton227::UNIT)
        .collect::<Vec<_>>();
    let gates = f["epochs"]
        .as_array()
        .context("210 complete epoch history")?
        .iter()
        .filter(|e| e["epoch"] == 227)
        .collect::<Vec<_>>();
    ensure!(
        gates.len() == 1
            && gates[0]["gate_evidence"]
                .as_array()
                .is_some_and(|e| e.contains(&json!({"path":LAUNCH,"sha256":LAUNCH_SHA}))),
        "210 full 227 original launch evidence was discarded"
    );
    match d["live"]
        .as_bool()
        .context("210 full 227 retained live flag")?
    {
        true => ensure!(
            matches.len() == 1
                && *matches[0] == *u
                && diagnostic_stage_running(u)
                && d["terminal_outcome_requires_canary_receipt"] == false,
            "210 live full 227 was removed or replaced"
        ),
        false => ensure!(
            matches.is_empty()
                && u["LoadState"] == "loaded"
                && u["MainPID"] == "0"
                && matches!(
                    (u["ActiveState"].as_str(), u["SubState"].as_str()),
                    (Some("failed"), Some("failed")) | (Some("inactive"), Some("dead"))
                )
                && u["Result"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && s != "success")
                && u["ExecMainStatus"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|n| n > 0)
                && d["terminal_outcome_requires_canary_receipt"] == true
                && gates[0]["state"] == "failed-needs-repair"
                && gates[0]["next_action"]
                    .as_str()
                    .is_some_and(|s| !s.trim().is_empty()),
            "210 inactive full 227 lacks its same-IID terminal failure and repair history"
        ),
    }
    Ok(())
}
pub(super) fn current(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    validate(f)?;
    let original = &record(f)?["unit"];
    let observed = current
        .get(singleton227::UNIT)
        .context("210 retained full 227 current manager missing")?;
    for key in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainStatus",
        "ControlGroup",
        "Type",
    ] {
        ensure!(
            original[key] == observed[key],
            "210 retained full 227 manager changed:{key}"
        );
    }
    ensure!(
        pipeline_status::same_exec_start(
            original["ExecStart"]
                .as_str()
                .context("210 original full 227 command")?,
            observed["ExecStart"]
                .as_str()
                .context("210 current full 227 command")?
        ),
        "210 retained full 227 command changed"
    );
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture(live: bool) -> Value {
    let unit = json!({"Id":singleton227::UNIT,"LoadState":"loaded","InvocationID":IID,"MainPID":if live{"42"}else{"0"},
        "NRestarts":"0","ActiveState":if live{"active"}else{"failed"},"SubState":if live{"running"}else{"failed"},
        "Result":if live{"success"}else{"exit-code"},"ExecMainStatus":if live{"0"}else{"1"},
        "ControlGroup":format!("/system.slice/{}",singleton227::UNIT),"Type":"exec","ExecStart":singleton227::expected_command()});
    json!({"unit_census":{(singleton227::UNIT):unit},"active":if live{vec![json!({"epoch":227,"unit":unit})]}else{vec![]},
        "diagnostics":[{"epoch":227,"unit":unit,"live":live,"scope_first_epoch":227,"scope_last_epoch":227,"launch_invocation_id":IID,
            "launch_receipt":LAUNCH,"launch_receipt_sha256":LAUNCH_SHA,"terminal_outcome_requires_canary_receipt":!live}],
        "epochs":[{"epoch":227,"state":if live{"blocked-qualification"}else{"failed-needs-repair"},"next_action":"Preserve exact attempt and repair canonical execution mismatch",
            "gate_evidence":[{"path":LAUNCH,"sha256":LAUNCH_SHA}]}]})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn genuine_terminal_history_is_retained_without_an_active_reservation() {
        for live in [true, false] {
            let f = fixture(live);
            let before = f.clone();
            validate(&f).unwrap();
            let units = serde_json::from_value(f["unit_census"].clone()).unwrap();
            current(&f, &units).unwrap();
            assert_eq!(f, before);
        }
        let terminal = fixture(false);
        let terminal_units = serde_json::from_value(terminal["unit_census"].clone()).unwrap();
        assert!(
            current(&fixture(true), &terminal_units).is_err(),
            "a pre-failure active338 owner cannot authorize a post-failure launch"
        );
        for pointer in ["/diagnostics", "/unit_census", "/epochs"] {
            let mut bad = terminal.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(validate(&bad).is_err(), "{pointer}");
        }
        let mut bad = terminal.clone();
        bad["diagnostics"][0]["unit"]["InvocationID"] = json!("b".repeat(32));
        bad["unit_census"][singleton227::UNIT] = bad["diagnostics"][0]["unit"].clone();
        assert!(validate(&bad).is_err());
        let mut bad = terminal.clone();
        bad["epochs"][0]["gate_evidence"] = json!([]);
        assert!(validate(&bad).is_err());
        let mut bad = terminal.clone();
        bad["epochs"][0]["state"] = json!("blocked-qualification");
        assert!(validate(&bad).is_err());
        let mut units: BTreeMap<String, Value> =
            serde_json::from_value(terminal["unit_census"].clone()).unwrap();
        units.get_mut(singleton227::UNIT).unwrap()["InvocationID"] = json!("b".repeat(32));
        assert!(current(&terminal, &units).is_err());
        let mut unexplained = fixture(true);
        unexplained["active"] = json!([]);
        assert!(validate(&unexplained).is_err());
    }
}
