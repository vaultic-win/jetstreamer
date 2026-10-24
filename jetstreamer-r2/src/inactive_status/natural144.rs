//! Exact naturally completed private 144 owner, not a complete epoch assertion.
use super::*;
const UNIT: &str = "horizon-qualify-epoch144-loader-focus-20261016-v1.service";
const IID: &str = "ea4a806906ba493e9af49e2a9c71c9e7";
const MANIFEST_SHA: &str = "691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a";
pub(super) fn recognized(e: &Value) -> bool {
    e["schema"] == "jetstreamer-private-epoch144-focused-terminal-evidence-v1"
}
fn validate(e: &Value, owners: &[(String, String)]) -> Result<()> {
    ensure!(
        recognized(e)
            && e["epoch"] == 144
            && e["host"] == "dev-samjohnson"
            && e["unit"] == UNIT
            && e["invocation_id"] == IID
            && owners == [(UNIT.into(), IID.into()), (UNIT.into(), IID.into())],
        "144 terminal evidence owner differs"
    );
    for flag in [
        "full_epoch_verified",
        "independent_archive_reread_complete",
        "replay_launch_authorized",
        "publication_authorized",
        "local_retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            e[flag] == false,
            "144 terminal evidence grants authority:{flag}"
        );
    }
    let b: Bound = serde_json::from_value(e["manifest"].clone())?;
    ensure!(
        b.sha256 == MANIFEST_SHA
            && b.path
                == Path::new(
                    "/usr/local/lib/jetstreamer/horizon-epoch144-terminal-evidence-20261021-v1/segment.json"
                ),
        "144 manifest binding differs"
    );
    let m = bound_json(&b)?;
    ensure!(
        m["schema_version"] == 1
            && m["epoch"] == 144
            && m["bootstrap"]["slot"] == 62207522
            && m["output_slot_start"] == 62208000
            && m["output_slot_count"] == 431491
            && m["terminal"]["slot"] == 62639490
            && m["terminal"]["slot_complete"] == true
            && m["worker_executable_sha256"]
                == "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"
            && m["archive_sha256"]
                == "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273",
        "144 private terminal manifest differs"
    );
    Ok(())
}
fn journal_time(records: &[Value]) -> Result<u64> {
    // _PID/_UID are trusted journald metadata, not application-supplied fields.
    let rows: Vec<_> = records
        .iter()
        .filter(|r| {
            r["UNIT"] == UNIT
                && r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["INVOCATION_ID"].as_str().is_some_and(|s| !s.is_empty())
        })
        .collect();
    ensure!(
        rows.last().is_some_and(|r| r["INVOCATION_ID"] == IID),
        "144 latest manager lifecycle differs"
    );
    let start = rows
        .iter()
        .rposition(|r| {
            r["MESSAGE_ID"] == "7d4958e842da4a758f6c1cdc7b36dcc5"
                && r["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("Starting "))
        })
        .context("144 manager start missing")?;
    let end = rows
        .iter()
        .rposition(|r| {
            r["INVOCATION_ID"] == IID
                && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                && r["MESSAGE"] == format!("{UNIT}: Deactivated successfully.")
        })
        .context("144 manager clean deactivation missing")?;
    ensure!(
        start < end && rows[start]["INVOCATION_ID"] == IID,
        "144 new start or ambiguous terminal lifecycle"
    );
    let start_time = rows[start]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("144 start timestamp")?
        .parse::<u64>()?;
    let end_time = rows[end]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("144 end timestamp")?
        .parse::<u64>()?;
    ensure!(
        end_time > start_time,
        "144 terminal timestamp precedes start"
    );
    Ok(end_time / 1_000_000)
}
pub(super) fn manager_proof() -> Result<Vec<Value>> {
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args(["-u", UNIT, "--no-pager", "-n", "128", "-o", "json"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16 * 1024 * 1024,
        "144 manager journal unreadable"
    );
    let records = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    journal_time(&records)?;
    Ok(records)
}
pub(super) fn time(e: &Value) -> Result<u64> {
    validate(e, &[(UNIT.into(), IID.into()), (UNIT.into(), IID.into())])?;
    journal_time(&manager_proof()?)
}
pub(super) fn validate_current(
    current: &BTreeMap<String, Value>,
    e: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    validate(e, owners)?;
    let c = current.get(UNIT).context("144 owner absent from census")?;
    terminal_shape(c)?;
    manager_proof()?;
    Ok(())
}
pub(super) fn terminal_shape(c: &Value) -> Result<()> {
    ensure!(
        c["Id"] == UNIT
            && c["LoadState"] == "loaded"
            && c["ActiveState"] == "inactive"
            && c["SubState"] == "dead"
            && c["MainPID"] == "0"
            && c["InvocationID"] == ""
            && c["NRestarts"] == "0"
            && c["Result"] == "success"
            && c["ExecMainStatus"] == "0",
        "144 owner is live, replaced or not cleanly terminal"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn records() -> Vec<Value> {
        vec![
            json!({"UNIT":UNIT,"_PID":"1","_UID":"0","INVOCATION_ID":IID,"MESSAGE_ID":"7d4958e842da4a758f6c1cdc7b36dcc5","MESSAGE":"Starting private144...","__REALTIME_TIMESTAMP":"1000000"}),
            json!({"UNIT":UNIT,"_PID":"1","_UID":"0","INVOCATION_ID":IID,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{UNIT}: Deactivated successfully."),"__REALTIME_TIMESTAMP":"2000000"}),
        ]
    }
    #[test]
    fn exact_natural_completion_rejects_restarts_failed_or_forged_events() {
        assert_eq!(journal_time(&records()).unwrap(), 2);
        for (key, value) in [
            ("_PID", json!("123")),
            ("_UID", json!("1001")),
            ("INVOCATION_ID", json!("f".repeat(32))),
            ("MESSAGE_ID", json!("wrong")),
            ("MESSAGE", json!("failed")),
            ("__REALTIME_TIMESTAMP", json!("500000")),
        ] {
            let mut bad = records();
            bad[1][key] = value;
            assert!(journal_time(&bad).is_err(), "accepted{key}");
        }
        let mut restarted = records();
        restarted.push(restarted[0].clone());
        assert!(journal_time(&restarted).is_err());
        assert!(journal_time(&[]).is_err());
    }
    #[test]
    fn cleared_owner_requires_every_clean_terminal_property() {
        let good = json!({"Id":UNIT,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","InvocationID":"","NRestarts":"0","Result":"success","ExecMainStatus":"0"});
        terminal_shape(&good).unwrap();
        for key in [
            "Id",
            "LoadState",
            "ActiveState",
            "SubState",
            "MainPID",
            "InvocationID",
            "NRestarts",
            "Result",
            "ExecMainStatus",
        ] {
            let mut bad = good.clone();
            bad[key] = json!("different");
            assert!(terminal_shape(&bad).is_err(), "accepted{key}");
            let mut missing = good.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(terminal_shape(&missing).is_err(), "missing{key}");
        }
    }
    #[test]
    #[ignore = "exact root-only144 sealed evidence and real manager journal; read-only, no remote calls"]
    fn exact144_manager_and_manifest_match_without_archive_completion_claim() {
        let bytes=fs::read("/usr/local/lib/jetstreamer/horizon-epoch144-terminal-evidence-20261021-v1/terminal.json").unwrap();
        let e: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(time(&e).unwrap(), 1792602877);
        let current = BTreeMap::from([(UNIT.into(), fleet::unit(UNIT).unwrap())]);
        let owners = vec![(UNIT.into(), IID.into()), (UNIT.into(), IID.into())];
        validate_current(&current, &e, &owners).unwrap();
        let mut wrong = owners;
        wrong[1].1 = "f".repeat(32);
        assert!(validate_current(&current, &e, &wrong).is_err());
        let mut upgraded = e.clone();
        upgraded["full_epoch_verified"] = json!(true);
        assert!(time(&upgraded).is_err());
    }
}
