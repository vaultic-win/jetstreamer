//! Genuine collected controller + file-backed stdout. No invented exit snapshot.
use super::*;
pub(super) const PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-cohort191-collected-delivery-tools-20261024-v1/jetstreamer-r2";
const LOG: &str =
    "/var/lib/jetstreamer-root-sweep-epochs191-194-target5-20261016-v2/controller.log";
const UNIT_FILE: &str =
    "/etc/systemd/system/jetstreamer-epochs191-194-target5-controller-v2-r2.service";
const UNIT_SHA: &str = "e54bea94ad567b5cdfc3601103aa3bf3a93c5fa91ebebd50b6ec92def2c2fefb";
fn bootstrap() -> Bound {
    Bound {
        path: "/var/lib/jetstreamer/horizon-cohort191-import-pending-20261024-v1/bootstrap.json"
            .into(),
        sha256: "6b930ce0c0c162ae81e1f1d86edd7cb134cbd2370d1dc7b6e0f19cfef15afe8e".into(),
    }
}
pub(super) fn is_program(p: &Path) -> bool {
    p == Path::new(PROGRAM)
        || p == Path::new(
            "/usr/local/lib/jetstreamer/horizon-cohort191-native-event-tools-20261024-v2/jetstreamer-r2",
        )
        || p == Path::new(
            "/usr/local/lib/jetstreamer/horizon-cohort191-native-event-tools-20261024-v1/jetstreamer-r2",
        )
        || p == Path::new(
            "/usr/local/lib/jetstreamer/horizon-cohort191-collected-recovery-tools-20261024-v2/jetstreamer-r2",
        )
}
pub(super) fn current_program() -> Result<bool> {
    Ok(is_program(&fs::read_link("/proc/self/exe")?))
}
pub(super) fn native_records(cutoff: u64) -> Result<Value> {
    Ok(import_pending::historical_records(&bootstrap(), cutoff)?["native_events"].clone())
}
fn cleared(v: &Value, history: &Value) -> Result<()> {
    ensure!(
        v["Id"] == CONTROLLER
            && v["LoadState"] == "loaded"
            && v["InvocationID"] == ""
            && v["NRestarts"] == "0"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["MainPID"] == "0"
            && v["ControlGroup"] == ""
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && matches!(v["ExecMainCode"].as_str(), Some("0" | ""))
            && v["SuccessExitStatus"] == ""
            && no_manager_job(&v["Job"])
            && prefix(&v["ExecStart"])
                == prefix(&history["current_units"][CONTROLLER]["ExecStart"]),
        "191 collected raw manager is not the cleared original controller"
    );
    Ok(())
}
fn file_completion(bytes: &[u8]) -> Result<Value> {
    let s = std::str::from_utf8(bytes)?;
    let lines: Vec<_> = s.lines().collect();
    let message = "all sealed cohorts 191-194 are public";
    ensure!(
        lines.iter().filter(|l| **l == message).count() == 1
            && lines.last() == Some(&message)
            && s.ends_with('\n'),
        "191 file-backed controller completion missing/ambiguous/not terminal"
    );
    Ok(
        json!({"kind":"native-file-backed-stdout","path":LOG,"sha256":hex_lower(&Sha256::digest(bytes)),
        "length":bytes.len(),"terminal_line":message,"occurrences":1,"fabricated_journal_fields":false}),
    )
}
pub(super) fn lifecycle(current: &Value, history: &Value, cutoff: u64) -> Result<Value> {
    ensure!(
        current_program()?,
        "191 collected lifecycle requires separate qualified namespace"
    );
    native_lifecycle(current, history, cutoff)
}
pub(super) fn growth_lifecycle(current: &Value, history: &Value, cutoff: u64) -> Result<Value> {
    ensure!(
        growth_transfer::native_context()?,
        "191 growth lifecycle requires its exact qualified read-only context"
    );
    native_lifecycle(current, history, cutoff)
}
fn native_lifecycle(current: &Value, history: &Value, cutoff: u64) -> Result<Value> {
    let raw = controller_properties()?;
    cleared(&raw, history)?;
    ensure!(
        fleet::unit(CONTROLLER)? == *current,
        "191 collected controller changed before capture"
    );
    let unit_bytes = read_stable_bounded(
        Path::new(UNIT_FILE),
        64 << 10,
        "191 unchanged controller unit",
    )?;
    let meta = fs::symlink_metadata(UNIT_FILE)?;
    ensure!(
        meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && hex_lower(&Sha256::digest(&unit_bytes)) == UNIT_SHA,
        "191 controller unit changed"
    );
    let unit_text = std::str::from_utf8(&unit_bytes)?;
    ensure!(
        unit_text
            .lines()
            .any(|l| l == format!("StandardOutput=append:{LOG}"))
            && unit_text
                .lines()
                .any(|l| l == format!("StandardError=append:{LOG}")),
        "191 stdout is not its pinned native file"
    );
    let prior_b=Bound{path:"/var/lib/jetstreamer/horizon-cohort191-delivery-events-20261024-import-v1/event-20261024T031600Z.json".into(),sha256:"d986ae11f06377cb742eb78f9412b1cd398683ec9604ede6e347bee0518dc588".into()};
    let prior = bound(&prior_b, false)?;
    ensure!(
        prior["schema"] == EVENT_SCHEMA
            && prior["controller"]["InvocationID"] == CID
            && prior["controller"]["MainPID"] == "514398"
            && prior["controller"]["ActiveState"] == "active"
            && prior["controller"]["NRestarts"] == "0"
            && prior["capture_self_sha256"]
                == "9ff8bd9896da179d67ba030153e31917177fc706af0a79ec2d5aa68f90ccfa96"
            && prior["capture_program"]
                == "/usr/local/lib/jetstreamer/horizon-cohort191-import-cache-tools-20261024-v1/jetstreamer-r2",
        "191 collected controller lost actual accepted prior live evidence"
    );
    member(
        Path::new(prior["capture_program"].as_str().unwrap()),
        prior["capture_self_sha256"].as_str().unwrap(),
    )?;
    let native = import_pending::historical_records(&bootstrap(), cutoff)?;
    ensure!(
        native["source_batch"] == prior["source_batch"] && native["origins"] == prior["origins"],
        "191 historical custody changed"
    );
    let out = Command::new("/usr/bin/journalctl")
        .args([
            "_PID=1",
            "_UID=0",
            &format!("UNIT={CONTROLLER}"),
            "--no-pager",
            "-o",
            "json",
            "-n",
            "128",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "191 actual PID1 lifecycle unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let end = controller_manager_end(&rows, cutoff)?;
    let started = rows
        .iter()
        .filter(|r| {
            r["UNIT"] == CONTROLLER
                && r["_PID"] == "1"
                && r["_UID"] == "0"
                && matches!(
                    r["MESSAGE_ID"].as_str(),
                    Some("7d4958e842da4a758f6c1cdc7b36dcc5" | "39f53479d3a045ac8e11786248231fbf")
                )
        })
        .max_by_key(|r| r["__REALTIME_TIMESTAMP"].as_str().unwrap_or(""))
        .context("191 actual manager start missing")?;
    ensure!(
        started["INVOCATION_ID"] == CID,
        "191 collected controller was replaced"
    );
    let begin = pipeline_status::manager_start(CONTROLLER, CID)?;
    let (state_data, state) = state_bytes()?;
    ensure!(
        state["assignments"]
            .as_object()
            .is_some_and(|o| o.is_empty())
            && state["import_owner"].is_null()
            && state["completed"]["191-194"]["epochs"] == json!([191, 192, 193, 194])
            && state["completed"]["191-194"]["receipt_sha256"]
                == "44e92a931165f5144cafc8ce1aaa0cfe34ac3f91d95436443378ef98864f0ca6",
        "191 collected controller lacks genuine completed public native state"
    );
    let log_meta = fs::symlink_metadata(LOG)?;
    ensure!(
        Path::new(LOG).canonicalize()? == Path::new(LOG)
            && log_meta.is_file()
            && log_meta.uid() == 0
            && log_meta.nlink() == 1
            && log_meta.mode() & 0o077 == 0,
        "191 native controller log custody differs"
    );
    let bytes = read_stable_bounded(Path::new(LOG), 2 << 20, "191 native file-backed completion")?;
    let file = file_completion(&bytes)?;
    ensure!(
        controller_properties()? == raw
            && state_bytes()?.0 == state_data
            && read_stable_bounded(Path::new(LOG), 2 << 20, "191 log recheck")? == bytes,
        "191 collected evidence changed during capture"
    );
    Ok(
        json!({"kind":"collected-file-backed-controller","schema":"jetstreamer-collected-file-backed-controller-v1",
        "unit":raw,"events":{"manager_start":started,"manager_start_unix_millis":begin,"terminal":end},
        "prior_live":prior_b,"producer_native_records":bootstrap(),"file_completion":file,
        "unit_file":{"path":UNIT_FILE,"sha256":UNIT_SHA},"script":{"path":SCRIPT,"sha256":SCRIPT_SHA},
        "root_controller_state_sha256":hex_lower(&Sha256::digest(&state_data)),"raw_cleared_properties_preserved":true,
        "synthesized_exit_snapshot":false,"publication_authorized":false,"launch_authorized":false,"r2_mutations":false,"resource_samples":0}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_stdout_never_becomes_a_journal_record_or_accepts_nonterminal_lines() {
        let good=b"importing validated cohort 191-194 from lane-a\nall sealed cohorts 191-194 are public\n";
        let v = file_completion(good).unwrap();
        assert!(v.get("_PID").is_none());
        assert!(v.get("__REALTIME_TIMESTAMP").is_none());
        for bad in [
            b"all sealed cohorts 191-194 are public".as_slice(),
            b"all sealed cohorts 191-194 are public\nmore\n",
            b"all sealed cohorts 191-194 are public\nall sealed cohorts 191-194 are public\n",
        ] {
            assert!(file_completion(bad).is_err());
        }
    }
}
