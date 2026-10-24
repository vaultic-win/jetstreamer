//! Status-only cleanup for the exact guarded incomplete185 invocation.
use super::*;
const ROOT: &str = "/var/lib/jetstreamer/horizon-terminal185-20261024-v1/terminal.json";
const SHA: &str = "59b4626838f5d8e0fc8964a952b6fb96e2284d93a12f35e8fea80b30d9de73be";
const CONTROLLER: &str = "jetstreamer-epoch185-full-20261023-controller-v1-r2.service";
const PRODUCER: &str = "jetstreamer-root-sweep-e185-full-20261023-v1-r2-e185-185-lane-a-1.service";
const CID: &str = "fcc936d65490488aa95df0d1732bc40e";
const PID: &str = "0de9498a3c2f4c6dbd7350d052fc7e02";
pub(super) fn recognized(e: &Value) -> bool {
    e["schema"] == "jetstreamer-guard-stopped185-terminal-v2"
}
pub(super) fn binding(b: &Bound) -> bool {
    b.path == Path::new(ROOT) && b.sha256 == SHA
}
fn owners() -> Vec<(String, String)> {
    vec![
        (CONTROLLER.into(), CID.into()),
        (PRODUCER.into(), PID.into()),
    ]
}
fn scope(e: &Value, actual: &[(String, String)]) -> Result<()> {
    ensure!(
        recognized(e)
            && e["epoch"] == 185
            && actual == owners()
            && e["last_observed_slot"] == 80099168u64
            && e["canonical_terminal_slot"] == 80351999u64,
        "foreign185 terminal scope or incomplete suffix lost"
    );
    for key in [
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
        "remaining_growth_released",
        "scratch_retirement_authorized",
    ] {
        ensure!(e[key] == false, "185 terminal proof grants {key}");
    }
    Ok(())
}
fn lifecycle(rows: &[Value], name: &str, iid: &str) -> Result<(u64, u64)> {
    let trusted: Vec<_> = rows
        .iter()
        .filter(|r| r["UNIT"] == name && r["_PID"] == "1" && r["_UID"] == "0")
        .collect();
    let timestamp = |r: &Value| -> Result<u64> {
        Ok(r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("185 manager clock missing")?
            .parse()?)
    };
    let mut starts = Vec::new();
    let mut stops = Vec::new();
    for r in &trusted {
        let t = timestamp(r)?;
        if matches!(
            r["MESSAGE_ID"].as_str(),
            Some("7d4958e842da4a758f6c1cdc7b36dcc5" | "39f53479d3a045ac8e11786248231fbf")
        ) {
            starts.push((t, *r));
        }
        if r["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286"
            && r["JOB_TYPE"] == "stop"
            && r["JOB_RESULT"] == "done"
            && r["INVOCATION_ID"] == iid
        {
            stops.push(t);
        }
    }
    let (start, row) = starts
        .into_iter()
        .max_by_key(|(t, _)| *t)
        .context("185 manager start absent")?;
    let stop = stops
        .into_iter()
        .max()
        .context("185 successful manager stop absent")?;
    ensure!(
        row["INVOCATION_ID"] == iid && stop > start,
        "185 latest manager start is replacement or lacks later stop"
    );
    // Any newer owner record invalidates the retained lifecycle even if its
    // start fell outside the bounded journal tail.
    for r in trusted {
        ensure!(
            timestamp(r)? <= stop
                || r["INVOCATION_ID"] == iid
                || r["INVOCATION_ID"].as_str().is_none_or(str::is_empty),
            "185 newer manager owner exists"
        );
    }
    Ok((start, stop))
}
fn terminal(c: &Value, unit: &str, iid: &str) -> Result<()> {
    ensure!(
        c["Id"] == unit
            && c["ActiveState"] == "inactive"
            && c["SubState"] == "dead"
            && c["MainPID"] == "0"
            && c["NRestarts"] == "0"
            && c["Result"] == "success"
            && ((c["LoadState"] == "not-found" && c["InvocationID"] == "")
                || (c["LoadState"] == "loaded"
                    && (c["InvocationID"] == iid || c["InvocationID"] == ""))),
        "185 owner live, replaced, restarting or ambiguous"
    );
    Ok(())
}
pub(super) fn time(plan: &Plan, e: &Value) -> Result<u64> {
    ensure!(
        plan.epoch == 185 && binding(&plan.terminal_fleet),
        "unbound185 native terminal evidence"
    );
    scope(e, &owners())?;
    for (key, file, sha) in [
        (
            "guard_intent",
            "intent.json",
            "6f78b2e30358e96e025fe661b13c95ba277c3417c740b60ef990668f478fb545",
        ),
        (
            "guard_completion",
            "completion.json",
            "72c180d480c8780c802915201c68a575a648a3ec5dcc22b5a818d90f26f83890",
        ),
    ] {
        let b: Bound = serde_json::from_value(e[key].clone())?;
        ensure!(
            b.path
                == Path::new(
                    "/var/lib/jetstreamer-adaptive-reserve-controller-rebind-185-185-20261023-v1"
                )
                .join(file)
                && b.sha256 == sha,
            "185 guard binding differs"
        );
        bound_json(&b)?;
    }
    let captured = e["captured_unix_seconds"]
        .as_u64()
        .context("185 capture clock missing")?;
    for (unit, iid) in owners() {
        let rows: Vec<Value> = serde_json::from_value(e["manager_journals"][&unit].clone())?;
        let (_, stop) = lifecycle(&rows, &unit, &iid)?;
        ensure!(
            stop / 1_000_000 <= captured,
            "185 capture precedes native stop"
        );
    }
    ensure!(
        captured <= SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "future185 capture"
    );
    Ok(captured)
}
pub(super) fn validate_current(
    current: &BTreeMap<String, Value>,
    e: &Value,
    actual: &[(String, String)],
) -> Result<()> {
    scope(e, actual)?;
    for (unit, iid) in owners() {
        let c = current
            .get(&unit)
            .context("185 owner absent from complete census")?;
        terminal(c, &unit, &iid)?;
        let out = ProcessCommand::new("/usr/bin/systemctl")
            .args(["show", &unit, "--no-pager", "--property=Restart,Job"])
            .output()?;
        ensure!(
            out.status.success() && out.stdout.len() < 1024,
            "185 trigger policy unreadable"
        );
        let fields: BTreeMap<_, _> = std::str::from_utf8(&out.stdout)?
            .lines()
            .map(|l| l.split_once('=').context("185 trigger policy framing"))
            .collect::<Result<_>>()?;
        ensure!(
            fields.get("Job") == Some(&"")
                && (c["LoadState"] == "not-found" || fields.get("Restart") == Some(&"no")),
            "185 restart or job pending"
        );
        let out = ProcessCommand::new("/usr/bin/journalctl")
            .args([
                "_PID=1",
                "_UID=0",
                &format!("UNIT={unit}"),
                "-n",
                "128",
                "--no-pager",
                "-o",
                "json",
            ])
            .output()?;
        ensure!(
            out.status.success() && out.stdout.len() < 2 << 20,
            "185 latest manager journal unreadable"
        );
        let rows = serde_json::Deserializer::from_slice(&out.stdout)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let retained: Vec<Value> = serde_json::from_value(e["manager_journals"][&unit].clone())?;
        ensure!(
            lifecycle(&rows, &unit, &iid)? == lifecycle(&retained, &unit, &iid)?,
            "185 native lifecycle changed after capture"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn rows() -> Vec<Value> {
        vec![
            json!({"UNIT":PRODUCER,"_PID":"1","_UID":"0","INVOCATION_ID":PID,"MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","__REALTIME_TIMESTAMP":"1000000"}),
            json!({"UNIT":PRODUCER,"_PID":"1","_UID":"0","INVOCATION_ID":PID,"MESSAGE_ID":"9d1aaa27d60140bd96365438aad20286","JOB_TYPE":"stop","JOB_RESULT":"done","__REALTIME_TIMESTAMP":"2000000"}),
        ]
    }
    #[test]
    fn disappearance_requires_exact_latest_native_start_and_successful_stop() {
        assert_eq!(
            lifecycle(&rows(), PRODUCER, PID).unwrap(),
            (1_000_000, 2_000_000)
        );
        assert!(lifecycle(&[], PRODUCER, PID).is_err());
        assert!(lifecycle(&rows()[..1], PRODUCER, PID).is_err());
        for (field, value) in [
            ("_PID", "99"),
            ("_UID", "1000"),
            ("INVOCATION_ID", "replacement"),
            ("JOB_RESULT", "failed"),
            ("JOB_TYPE", "start"),
            ("__REALTIME_TIMESTAMP", "900000"),
        ] {
            let mut r = rows();
            r[1][field] = json!(value);
            assert!(lifecycle(&r, PRODUCER, PID).is_err(), "{field}");
        }
        let mut r = rows();
        let mut replacement = r[0].clone();
        replacement["INVOCATION_ID"] = json!("replacement");
        replacement["__REALTIME_TIMESTAMP"] = json!("3000000");
        r.push(replacement);
        assert!(lifecycle(&r, PRODUCER, PID).is_err());
        let mut r = rows();
        let mut restarted = r[0].clone();
        restarted["__REALTIME_TIMESTAMP"] = json!("3000000");
        r.push(restarted);
        assert!(lifecycle(&r, PRODUCER, PID).is_err());
    }
    #[test]
    fn terminal_shape_rejects_live_replacement_restart_or_failure() {
        let v = json!({"Id":PRODUCER,"LoadState":"not-found","InvocationID":"","ActiveState":"inactive","SubState":"dead","MainPID":"0","NRestarts":"0","Result":"success"});
        terminal(&v, PRODUCER, PID).unwrap();
        for (k, n) in [
            ("Id", "foreign"),
            ("InvocationID", "replacement"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("MainPID", "1"),
            ("NRestarts", "1"),
            ("Result", "signal"),
        ] {
            let mut bad = v.clone();
            bad[k] = json!(n);
            assert!(terminal(&bad, PRODUCER, PID).is_err(), "{k}");
        }
    }
    #[test]
    fn exact_native_proof_never_grants_completion_capacity_or_retirement() {
        let e = json!({"schema":"jetstreamer-guard-stopped185-terminal-v2","epoch":185,"last_observed_slot":80099168u64,"canonical_terminal_slot":80351999u64,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,"remaining_growth_released":false,"scratch_retirement_authorized":false});
        scope(&e, &owners()).unwrap();
        for key in [
            "replay_launch_authorized",
            "publication_authorized",
            "r2_mutations",
            "remaining_growth_released",
            "scratch_retirement_authorized",
        ] {
            let mut bad = e.clone();
            bad[key] = json!(true);
            assert!(scope(&bad, &owners()).is_err());
        }
        assert!(scope(&e, &[(PRODUCER.into(), PID.into())]).is_err());
        let mut bad = e.clone();
        bad["last_observed_slot"] = bad["canonical_terminal_slot"].clone();
        assert!(scope(&bad, &owners()).is_err());
        assert!(binding(&Bound {
            path: ROOT.into(),
            sha256: SHA.into()
        }));
        assert!(!binding(&Bound {
            path: ROOT.into(),
            sha256: "a".repeat(64)
        }));
    }
}
