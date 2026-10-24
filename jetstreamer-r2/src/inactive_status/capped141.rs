//! Native terminal proof for the exact stopping-root invocation for epoch 141.
//! This proves process termination only, never a checkpoint or a full epoch.
use super::*;
const UNIT: &str = "horizon-qualify-141-original-entry-capped-root-20261023-v1.service";
const IID: &str = "e639f007d482464f8a251455659d2ede";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-original-entry-capped-root-20261023-v1";
const LAUNCH_SHA: &str = "fddefbddec6d98f344f9b7c2411cfcf874fee365e1af9fa4a6b380745021e28f";
pub(super) fn recognized(e: &Value) -> bool {
    e["schema"] == "jetstreamer-capped141-terminal-evidence-v2"
}
fn launch(b: &Bound) -> Result<Value> {
    ensure!(
        b.path == Path::new(ROOT).join("receipts/launch.json") && b.sha256 == LAUNCH_SHA,
        "capped 141 terminal launch binding changed"
    );
    let l = bound_json(b)?;
    ensure!(
        l["unit"] == UNIT
            && l["invocation_id"] == IID
            && l["terminal_root_slot"] == 61328765
            && l["node_sha256"]
                == "d0c784a403d65819de70a499fc4d981217fd16fc30b70fac7e5ec979d0423ff0"
            && l["worker_sha256"]
                == "fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759",
        "capped 141 terminal proof is not the exact stopping-root launch"
    );
    Ok(l)
}
fn terminal_shape(c: &Value) -> Result<()> {
    let clean = c["ActiveState"] == "inactive"
        && c["SubState"] == "dead"
        && c["Result"] == "success"
        && c["ExecMainStatus"] == "0";
    let failed = c["ActiveState"] == "failed"
        && c["SubState"] == "failed"
        && c["Result"].as_str().is_some_and(|r| {
            matches!(
                r,
                "exit-code" | "signal" | "core-dump" | "timeout" | "oom-kill" | "resources"
            )
        })
        && c["ExecMainStatus"]
            .as_str()
            .is_some_and(|s| s.parse::<u32>().is_ok());
    ensure!(
        c["Id"] == UNIT
            && c["LoadState"] == "loaded"
            && c["MainPID"] == "0"
            && c["NRestarts"] == "0"
            && matches!(c["InvocationID"].as_str(), Some("" | IID))
            && (clean || failed),
        "capped 141 owner is live, replaced, restarting or not positively terminal"
    );
    Ok(())
}
fn collected(c: &Value) -> bool {
    c["Id"] == UNIT
        && c["LoadState"] == "not-found"
        && c["ActiveState"] == "inactive"
        && c["SubState"] == "dead"
        && c["MainPID"] == "0"
        && c["InvocationID"] == ""
}
fn manager_end(r: &Value, result: Option<&str>) -> bool {
    let clean = r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
        && r["MESSAGE"] == format!("{UNIT}: Deactivated successfully.");
    let failed = r["MESSAGE_ID"] == "be02cf6855d2428ba40df7e9d022f03d"
        && [
            "exit-code",
            "signal",
            "core-dump",
            "timeout",
            "oom-kill",
            "resources",
        ]
        .iter()
        .any(|failure| {
            result.is_none_or(|expected| expected == *failure)
                && r["MESSAGE"] == format!("{UNIT}: Failed with result '{failure}'.")
        });
    (clean && result.is_none_or(|r| r == "success")) || failed
}
fn journal_time(records: &[Value], current: &Value) -> Result<u64> {
    if !collected(current) {
        terminal_shape(current)?;
    }
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
        "capped 141 latest manager owner differs"
    );
    let start = rows
        .iter()
        .rposition(|r| {
            matches!(
                r["MESSAGE_ID"].as_str(),
                Some("7d4958e842da4a758f6c1cdc7b36dcc5" | "39f53479d3a045ac8e11786248231fbf")
            ) && r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with("Starting ") || s.starts_with("Started "))
        })
        .context("capped 141 manager start missing")?;
    let result = if collected(current) {
        None
    } else {
        Some(
            current["Result"]
                .as_str()
                .context("capped 141 terminal result")?,
        )
    };
    let end = rows
        .iter()
        .rposition(|r| r["INVOCATION_ID"] == IID && manager_end(r, result))
        .context("capped 141 manager terminal event missing")?;
    ensure!(
        start < end && rows[start]["INVOCATION_ID"] == IID,
        "capped 141 restarted or ambiguous manager lifecycle"
    );
    let a = rows[start]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("capped 141 start time")?
        .parse::<u64>()?;
    let b = rows[end]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("capped 141 stop time")?
        .parse::<u64>()?;
    ensure!(b > a, "capped 141 terminal time precedes start");
    Ok(b / 1_000_000)
}
fn manager_proof() -> Result<Vec<Value>> {
    // Select manager records directly so a chatty worker cannot evict the
    // original start from a bounded tail. Trusted underscore fields are mandatory.
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            format!("UNIT={UNIT}"),
            "_PID=1".into(),
            "_UID=0".into(),
            "--no-pager".into(),
            "-n".into(),
            "128".into(),
            "-o".into(),
            "json".into(),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16 * 1024 * 1024,
        "capped 141 manager journal unreadable"
    );
    Ok(serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
fn no_restart() -> Result<()> {
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args(["show", UNIT, "--value", "--property=Restart"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout == b"no\n",
        "capped 141 owner can restart"
    );
    Ok(())
}
fn scope(e: &Value, owners: &[(String, String)]) -> Result<()> {
    ensure!(
        recognized(e)
            && e["epoch"] == 141
            && e["unit"] == UNIT
            && e["invocation_id"] == IID
            && owners == [(UNIT.into(), IID.into())]
            && e["private_root"] == ROOT
            && e["live_execution_terminal_slot"] == 61328765
            && e["epoch_terminal_slot"] == 61343999
            && e["separate_suffix_slots"] == 15234
            && e["repair_must_remain_open"] == true
            && e["preserve_private_bytes"] == true
            && (e["restart_policy"] == "no"
                || (e["restart_policy"] == "unit-collected" && collected(&e["unit_census"][UNIT])))
            && e["capture_self_sha256"]
                .as_str()
                .is_some_and(|s| is_lower_hex(s, 64)),
        "foreign capped 141 terminal evidence or lost suffix/repair obligation"
    );
    for flag in [
        "full_epoch_verified",
        "root_checkpoint_verified",
        "publication_authorized",
        "replay_launch_authorized",
        "local_retirement_authorized",
        "remaining_growth_released",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            e[flag] == false,
            "capped 141 process termination grants {flag}"
        );
    }
    Ok(())
}
fn validate(e: &Value, owners: &[(String, String)]) -> Result<u64> {
    scope(e, owners)?;
    let capture: Bound = serde_json::from_value(e["capture_plan"].clone())?;
    let capture = bound_json(&capture)?;
    ensure!(
        capture["schema"] == "jetstreamer-capped141-terminal-capture-plan-v2"
            && capture["launch"] == e["launch"]
            && capture["output"] == e["evidence_path"],
        "capped 141 retained evidence does not bind its capture plan"
    );
    let l = launch(&serde_json::from_value(e["launch"].clone())?)?;
    let command = |v: &Value| -> Option<String> {
        Some(v.as_str()?.split_once(" ; ignore_errors=")?.0.into())
    };
    ensure!(
        collected(&e["unit_census"][UNIT])
            || (command(&e["unit_census"][UNIT]["ExecStart"]).is_some()
                && command(&e["unit_census"][UNIT]["ExecStart"])
                    == command(&l["expected_exec_start"])),
        "capped 141 terminal command differs from authenticated launch"
    );
    let rows: Vec<Value> = serde_json::from_value(e["manager_journal"].clone())?;
    let time = journal_time(&rows, &e["unit_census"][UNIT])?;
    ensure!(
        e["terminal_unix_seconds"] == time,
        "capped 141 terminal timestamp differs from manager proof"
    );
    Ok(time)
}
pub(super) fn time(e: &Value) -> Result<u64> {
    let terminal = validate(e, &[(UNIT.into(), IID.into())])?;
    let recorded = e["recorded_unix_seconds"]
        .as_u64()
        .context("capped 141 capture time missing")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        terminal <= recorded && recorded <= now,
        "capped 141 capture time precedes terminal or is future-dated"
    );
    // Capture can follow a status PUT which started while the producer was
    // alive but finished just after its manager terminal event. Keep both real
    // timestamps rather than fabricating a later manager stop.
    Ok(recorded)
}
pub(super) fn validate_current(
    current: &BTreeMap<String, Value>,
    e: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    let retained_time = validate(e, owners)?;
    let c = current
        .get(UNIT)
        .context("capped 141 owner absent from full census")?;
    if !collected(c) {
        terminal_shape(c)?;
        no_restart()?;
    }
    for field in [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "NRestarts",
        "Result",
        "ExecMainStatus",
        "ExecStart",
    ] {
        ensure!(
            c[field] == e["unit_census"][UNIT][field],
            "capped 141 terminal owner changed:{field}"
        );
    }
    ensure!(
        journal_time(&manager_proof()?, c)? == retained_time,
        "capped 141 manager lifecycle changed after capture"
    );
    Ok(())
}
pub(super) fn capture() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7 && args[3] == "--plan-sha256" && args[5] == "--self-sha256",
        "usage: jetstreamer-r2 capped141-terminal-capture PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0
            && is_lower_hex(&args[6], 64)
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "capped 141 capture requires root and exact executable"
    );
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Capture {
        schema: String,
        launch: Bound,
        output: PathBuf,
    }
    let plan = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let p: Capture = serde_json::from_value(bound_json(&plan)?)?;
    ensure!(
        p.schema == "jetstreamer-capped141-terminal-capture-plan-v2"
            && p.output.is_absolute()
            && p.output.starts_with(Path::new(ROOT).join("receipts")),
        "foreign capped 141 terminal capture"
    );
    launch(&p.launch)?;
    let parent = p.output.parent().context("terminal output parent")?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o077 == 0,
        "terminal output parent must be root-only and canonical"
    );
    let current = fleet::unit(UNIT)?;
    let restart_policy = if collected(&current) {
        "unit-collected"
    } else {
        no_restart()?;
        "no"
    };
    let rows = manager_proof()?;
    let time = journal_time(&rows, &current)?;
    let recorded = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let e = json!({"schema":"jetstreamer-capped141-terminal-evidence-v2","epoch":141,"unit":UNIT,"invocation_id":IID,
        "capture_plan":{"path":plan.path,"sha256":plan.sha256},"capture_self_sha256":args[6],"evidence_path":p.output,
        "launch":{"path":p.launch.path,"sha256":p.launch.sha256},"private_root":ROOT,
        "unit_census":{UNIT:current},"manager_journal":rows,"terminal_unix_seconds":time,"restart_policy":restart_policy,
        "recorded_unix_seconds":recorded,
        "live_execution_terminal_slot":61328765,"epoch_terminal_slot":61343999,"separate_suffix_slots":15234,
        "repair_must_remain_open":true,"preserve_private_bytes":true,"full_epoch_verified":false,
        "root_checkpoint_verified":false,"publication_authorized":false,"replay_launch_authorized":false,
        "local_retirement_authorized":false,"remaining_growth_released":false,"remote_mutations":false,"r2_mutations":false});
    validate(&e, &[(UNIT.into(), IID.into())])?;
    let census = BTreeMap::from([(UNIT.into(), fleet::unit(UNIT)?)]);
    validate_current(&census, &e, &[(UNIT.into(), IID.into())])?;
    fleet::persist(&p.output, &e)?;
    println!("{}", p.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn unit() -> Value {
        json!({"Id":UNIT,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","InvocationID":"","NRestarts":"0","Restart":"no","Result":"success","ExecMainStatus":"0","ExecStart":"sealed native launch"})
    }
    fn rows() -> Vec<Value> {
        vec![
            json!({"UNIT":UNIT,"_PID":"1","_UID":"0","INVOCATION_ID":IID,"MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":"Started capped141.","__REALTIME_TIMESTAMP":"1000000"}),
            json!({"UNIT":UNIT,"_PID":"1","_UID":"0","INVOCATION_ID":IID,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{UNIT}: Deactivated successfully."),"__REALTIME_TIMESTAMP":"2000000"}),
        ]
    }
    #[test]
    fn terminal_requires_manager_success_or_failure_for_exact_latest_owner() {
        assert_eq!(journal_time(&rows(), &unit()).unwrap(), 2);
        for (key, value) in [
            ("_PID", "123"),
            ("_UID", "1001"),
            ("INVOCATION_ID", "replacement"),
            ("MESSAGE_ID", "wrong"),
            ("MESSAGE", "timeout"),
            ("__REALTIME_TIMESTAMP", "500000"),
        ] {
            let mut r = rows();
            r[1][key] = json!(value);
            assert!(journal_time(&r, &unit()).is_err(), "accepted{key}");
        }
        let mut restarted = rows();
        restarted.push(restarted[0].clone());
        assert!(journal_time(&restarted, &unit()).is_err());
        assert!(journal_time(&[], &unit()).is_err());
        let mut failed = unit();
        for (k, v) in [
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("InvocationID", IID),
        ] {
            failed[k] = json!(v);
        }
        let mut r = rows();
        r[1]["MESSAGE_ID"] = json!("be02cf6855d2428ba40df7e9d022f03d");
        r[1]["MESSAGE"] = json!(format!("{UNIT}: Failed with result 'exit-code'."));
        assert_eq!(journal_time(&r, &failed).unwrap(), 2);
        assert!(journal_time(&r, &unit()).is_err());
    }
    #[test]
    fn live_replacement_restart_and_ambiguous_shapes_never_establish_terminal() {
        terminal_shape(&unit()).unwrap();
        for (key, value) in [
            ("Id", "other"),
            ("LoadState", "not-found"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("MainPID", "123"),
            ("InvocationID", "replacement"),
            ("NRestarts", "1"),
            ("Result", "timeout"),
            ("ExecMainStatus", "1"),
        ] {
            let mut u = unit();
            u[key] = json!(value);
            assert!(terminal_shape(&u).is_err(), "accepted{key}");
        }
    }
    #[test]
    fn stopping_root_evidence_preserves_suffix_repair_and_denies_all_new_authority() {
        let e = json!({"schema":"jetstreamer-capped141-terminal-evidence-v2","epoch":141,
            "unit":UNIT,"invocation_id":IID,"private_root":ROOT,"live_execution_terminal_slot":61328765,
            "epoch_terminal_slot":61343999,"separate_suffix_slots":15234,"repair_must_remain_open":true,
            "preserve_private_bytes":true,"restart_policy":"no","capture_self_sha256":"a".repeat(64),"full_epoch_verified":false,
            "root_checkpoint_verified":false,"publication_authorized":false,"replay_launch_authorized":false,
            "local_retirement_authorized":false,"remaining_growth_released":false,"remote_mutations":false,"r2_mutations":false});
        let owners = vec![(UNIT.into(), IID.into())];
        scope(&e, &owners).unwrap();
        for key in [
            "full_epoch_verified",
            "root_checkpoint_verified",
            "publication_authorized",
            "replay_launch_authorized",
            "local_retirement_authorized",
            "remaining_growth_released",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = e.clone();
            bad[key] = json!(true);
            assert!(scope(&bad, &owners).is_err(), "accepted{key}");
        }
        for (key, value) in [
            ("epoch", json!(140)),
            ("separate_suffix_slots", json!(0)),
            ("live_execution_terminal_slot", json!(61343999)),
            ("repair_must_remain_open", json!(false)),
            ("preserve_private_bytes", json!(false)),
            ("restart_policy", json!("always")),
        ] {
            let mut bad = e.clone();
            bad[key] = value;
            assert!(scope(&bad, &owners).is_err(), "accepted{key}");
        }
        assert!(scope(&e, &[(UNIT.into(), "replacement".into())]).is_err());
        assert!(
            scope(
                &e,
                &[(UNIT.into(), IID.into()), ("other".into(), "other".into())]
            )
            .is_err()
        );
    }
    #[test]
    fn collected_unit_requires_positive_latest_manager_terminal_not_disappearance_alone() {
        let gone = json!({"Id":UNIT,"LoadState":"not-found","ActiveState":"inactive","SubState":"dead","MainPID":"0","InvocationID":""});
        assert_eq!(journal_time(&rows(), &gone).unwrap(), 2);
        assert!(journal_time(&[], &gone).is_err());
        assert!(journal_time(&rows()[..1], &gone).is_err());
        let mut replacement = rows();
        replacement.push(replacement[0].clone());
        assert!(journal_time(&replacement, &gone).is_err());
        for key in [
            "Id",
            "LoadState",
            "ActiveState",
            "SubState",
            "MainPID",
            "InvocationID",
        ] {
            let mut bad = gone.clone();
            bad[key] = json!("different");
            assert!(journal_time(&rows(), &bad).is_err(), "accepted{key}");
        }
    }
}
