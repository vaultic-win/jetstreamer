//! Closed status-only cleanup for the genuinely completed assembly204/full209.
//! This dispatch never changes archive, readiness or generic deletion gates.
use super::*;
const SCHEMA: &str = "jetstreamer-assembly204-full209-status-cleanup-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema: String,
    epoch: u64,
    #[serde(default)]
    assembly_terminal: Option<BoundFile>,
    #[serde(default)]
    full209_reference_fleet: Option<BoundFile>,
    #[serde(default)]
    full209_terminal_peer: Option<full209_terminal_peer::Proof>,
}
fn parse(epoch: u64, e: &Value) -> Result<Option<Evidence>> {
    if e["schema"] != SCHEMA {
        return Ok(None);
    }
    let e: Evidence = serde_json::from_value(e.clone())?;
    ensure!(
        e.schema == SCHEMA
            && e.epoch == epoch
            && match epoch {
                204 =>
                    e.assembly_terminal.is_some()
                        && e.full209_reference_fleet.is_none()
                        && e.full209_terminal_peer.is_none(),
                209 =>
                    e.assembly_terminal.is_none()
                        && e.full209_reference_fleet.is_some()
                        && e.full209_terminal_peer.is_some(),
                _ => false,
            },
        "typed status cleanup has foreign or mixed terminal origins"
    );
    Ok(Some(e))
}
fn owner_snapshot(
    current: &Value,
    expected: &Value,
    saved_journal: &[u8],
    current_journal: &[u8],
    pending: &[&str],
) -> Result<()> {
    let name = s(expected, "Id")?;
    let iid = s(expected, "InvocationID")?;
    ensure!(
        id(iid)
            && current["Id"] == name
            && current["LoadState"] == "loaded"
            && current["ActiveState"] == "inactive"
            && current["SubState"] == "dead"
            && current["MainPID"] == "0"
            && current["NRestarts"] == "0"
            && current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && (current["InvocationID"] == iid || current["InvocationID"] == "")
            && ownership::command_matches(s(current, "ExecStart")?, s(expected, "ExecStart")?),
        "typed cleanup owner live, replaced, restarted or command changed"
    );
    ownership::manager_shape(saved_journal, name, iid, true)?;
    ownership::manager_shape(current_journal, name, iid, true)?;
    ensure!(
        ownership::manager_records_equal(saved_journal, current_journal)?,
        "typed cleanup manager history changed"
    );
    ensure!(
        !pending.iter().any(|unit| *unit == name
            || unit
                .split(|c: char| !c.is_ascii_digit())
                .any(|part| part == "204" || part == "209")),
        "typed cleanup has queued owner/replacement work"
    );
    Ok(())
}
pub(super) fn owner_current(current: &Value, expected: &Value, saved_journal: &[u8]) -> Result<()> {
    let jobs = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "list-jobs",
            "--no-legend",
            "--no-pager",
            "--plain",
            "--full",
        ])
        .output()?;
    ensure!(
        jobs.status.success() && jobs.stdout.len() <= 4 << 20,
        "typed cleanup queued-job census unavailable"
    );
    owner_snapshot(
        current,
        expected,
        saved_journal,
        &ownership::manager(s(expected, "Id")?)?,
        &inactive_status::queued_job_units(&jobs.stdout)?,
    )
}
pub(in crate::fleet) fn cleanup_time(epoch: u64, e: &Value) -> Result<Option<u64>> {
    let Some(e) = parse(epoch, e)? else {
        return Ok(None);
    };
    Ok(Some(if let Some(t) = e.assembly_terminal {
        ownership::assembly_success::cleanup(&read(&t)?, None, None)?
    } else {
        e.full209_terminal_peer
            .context("full209 cleanup proof missing")?
            .cleanup_time()?
    }))
}
pub(in crate::fleet) fn cleanup_current(
    epoch: u64,
    e: &Value,
    current: &BTreeMap<String, Value>,
    owners: &[(String, String)],
) -> Result<bool> {
    let Some(e) = parse(epoch, e)? else {
        return Ok(false);
    };
    if let Some(t) = e.assembly_terminal {
        ownership::assembly_success::cleanup(&read(&t)?, Some(current), Some(owners))?;
    } else {
        let proof = e
            .full209_terminal_peer
            .context("full209 cleanup proof missing")?;
        ensure!(
            owners == [proof.cleanup_identity()?],
            "full209 cleanup owner differs from latest publication"
        );
        let fleet = bound_json(
            &e.full209_reference_fleet
                .context("full209 cleanup reference fleet missing")?,
        )?;
        proof.project(&fleet, current, true)?;
        // Any other current 209 owner remains protected; the peer proof checks
        // the exact original singleton, not a general epoch-wide exemption.
        for (name, row) in current {
            if name
                .split(|c: char| !c.is_ascii_digit())
                .any(|part| part == "209")
            {
                ensure!(
                    is_idle(row),
                    "full209 cleanup overlaps live replacement owner"
                );
                inactive_status::no_pending_owner_trigger(name, row["LoadState"] == "not-found")?;
            }
        }
    }
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_dispatch_is_closed_to_exact_terminal_origin_and_epoch() {
        assert!(parse(204, &json!({"schema":"other"})).unwrap().is_none());
        let bound = json!({"path":"/sealed/terminal.json","sha256":"a".repeat(64)});
        let good = json!({"schema":SCHEMA,"epoch":204,"assembly_terminal":bound});
        assert!(parse(204, &good).unwrap().is_some());
        assert!(parse(209, &good).is_err());
        let mut mixed = good.clone();
        mixed["full209_reference_fleet"] = bound;
        assert!(parse(204, &mixed).is_err());
        let mut extra = good;
        extra["skip_owner_checks"] = json!(true);
        assert!(parse(204, &extra).is_err());
    }
    #[test]
    fn typed_cleanup_accepts_cleared_iid_only_with_exact_terminal_history_and_no_queue() {
        let name = UNIT;
        let iid = "1".repeat(32);
        let expected = json!({"Id":name,"InvocationID":iid,"ExecStart":"{ path=/sealed/assembler ; argv[]=/sealed/assembler --plan X ; ignore_errors=no ; start_time=[n/a] ; pid=0 }"});
        let current = json!({"Id":name,"LoadState":"loaded","InvocationID":"","MainPID":"0","NRestarts":"0",
            "ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainStatus":"0","ExecStart":expected["ExecStart"]});
        let row = |time: &str, event: &str, message: &str| json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":time,"MESSAGE_ID":event,"MESSAGE":message});
        let start = row(
            "1000000",
            "39f53479d3a045ac8e11786248231fbf",
            "Started assembly.",
        );
        let end = row(
            "2000000",
            "7ad2d189f7e94e70a38c781354912448",
            &format!("{name}: Deactivated successfully."),
        );
        let raw = format!("{start}\n{end}\n");
        owner_snapshot(&current, &expected, raw.as_bytes(), raw.as_bytes(), &[]).unwrap();
        for (key, value) in [
            ("InvocationID", "22222222222222222222222222222222"),
            ("MainPID", "42"),
            ("ActiveState", "active"),
            ("SubState", "auto-restart"),
            ("ExecStart", "different"),
            ("NRestarts", "1"),
        ] {
            let mut bad = current.clone();
            bad[key] = json!(value);
            assert!(
                owner_snapshot(&bad, &expected, raw.as_bytes(), raw.as_bytes(), &[]).is_err(),
                "{key}"
            );
        }
        assert!(
            owner_snapshot(&current, &expected, raw.as_bytes(), raw.as_bytes(), &[name]).is_err()
        );
        assert!(
            owner_snapshot(
                &current,
                &expected,
                raw.as_bytes(),
                raw.as_bytes(),
                &["horizon-qualify-204-new.service"]
            )
            .is_err()
        );
        let mut replacement = start;
        replacement["INVOCATION_ID"] = json!("2".repeat(32));
        replacement["__REALTIME_TIMESTAMP"] = json!("3000000");
        assert!(
            owner_snapshot(
                &current,
                &expected,
                raw.as_bytes(),
                format!("{raw}{replacement}\n").as_bytes(),
                &[]
            )
            .is_err()
        );
        assert!(owner_snapshot(&current, &expected, b"", raw.as_bytes(), &[]).is_err());
    }
}
