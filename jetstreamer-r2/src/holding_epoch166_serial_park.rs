pub(super) fn validate_reloaded_park(
    terminal: &Value,
    row: &Value,
    helper: &Bound,
    argv: &str,
) -> Result<()> {
    let prefix = format!(
        "{{ path={} ; argv[]={argv} ; ignore_errors=no ; ",
        helper.path.display()
    );
    let recorded = format!(
        "{prefix}start_time=[{PARK_START_TIME}] ; stop_time=[{PARK_STOP_TIME}] ; pid={PARK_PID} ; code=exited ; status=0 }}"
    );
    let reset =
        format!("{prefix}start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}");

    // PID1 retains the original main-process fields when it resets the
    // formatted command's accounting on a daemon reload.
    for native in [terminal, row] {
        park_shape(native, PARK_IID)?;
        ensure!(
            native["ExecMainPID"] == PARK_PID
                && native["ExecMainStartTimestamp"] == PARK_START_TIME
                && native["FragmentPath"] == PARK_FRAGMENT
                && native["DropInPaths"] == ""
                && native["NRestarts"] == "0",
            "original park owner or fragment changed"
        );
    }
    ensure!(
        terminal["ExecStart"] == recorded
            && row["ExecStart"] == reset
            && row["Names"] == PARK
            && row["LoadState"] == "loaded"
            && row["ActiveState"] == "active"
            && row["SubState"] == "exited"
            && row["Transient"] == "yes"
            && row["NeedDaemonReload"] == "no"
            && row["ControlGroup"] == ""
            && row["ExecMainCode"] == "1"
            && row["ExecMainExitTimestamp"] == PARK_STOP_TIME
            && row["ExecMainStartTimestampMonotonic"] == PARK_START_MONOTONIC
            && row["ExecMainExitTimestampMonotonic"] == PARK_EXIT_MONOTONIC,
        "original park dispatch or retained main-process accounting changed"
    );
    Ok(())
}

#[cfg(test)]
mod reloaded_park_tests {
    use super::*;

    #[test]
    fn accepts_reset_command_accounting_only_for_the_original_park() {
        let helper = Bound {
            path: "/sealed/jetstreamer-r2".into(),
            sha256: "a".repeat(64),
        };
        let argv = format!(
            "/sealed/jetstreamer-r2 holding-park {PARK_PLAN} --spec-sha256 {PARK_PLAN_SHA} --self-sha256 {}",
            helper.sha256
        );
        let prefix =
            format!("{{ path=/sealed/jetstreamer-r2 ; argv[]={argv} ; ignore_errors=no ; ");
        let mut row = json!({
            "Id": PARK, "Names": PARK, "InvocationID": PARK_IID,
            "ActiveState": "active", "SubState": "exited", "LoadState": "loaded",
            "MainPID": "0", "ControlPID": "0", "Job": "", "TriggeredBy": "",
            "Result": "success", "Restart": "no", "NRestarts": "0", "ControlGroup": "",
            "ExecMainStatus": "0", "ExecMainCode": "1", "ExecMainPID": PARK_PID,
            "ExecMainStartTimestamp": PARK_START_TIME, "ExecMainExitTimestamp": PARK_STOP_TIME,
            "ExecMainStartTimestampMonotonic": PARK_START_MONOTONIC,
            "ExecMainExitTimestampMonotonic": PARK_EXIT_MONOTONIC,
            "FragmentPath": PARK_FRAGMENT, "DropInPaths": "",
            "Transient": "yes", "NeedDaemonReload": "no",
            "ExecStart": format!(
                "{prefix}start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
            )
        });
        let mut terminal = row.clone();
        terminal["ExecStart"] = json!(format!(
            "{prefix}start_time=[{PARK_START_TIME}] ; stop_time=[{PARK_STOP_TIME}] ; pid={PARK_PID} ; code=exited ; status=0 }}"
        ));
        validate_reloaded_park(&terminal, &row, &helper, &argv).unwrap();
        for key in [
            "InvocationID",
            "ExecMainPID",
            "ExecMainStartTimestampMonotonic",
            "ExecMainExitTimestampMonotonic",
            "ExecStart",
            "FragmentPath",
            "Job",
        ] {
            let previous = row[key].clone();
            row[key] = json!("different");
            assert!(
                validate_reloaded_park(&terminal, &row, &helper, &argv).is_err(),
                "{key}"
            );
            row[key] = previous;
        }
    }
}
