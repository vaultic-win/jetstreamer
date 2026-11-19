//! Real protective-stop experiment: no restore token, no worker, no fabricated success.
use super::*;
fn check_sample(v: &Value, iid: &str, pid: u64, plan: &Bound) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && v["plan_sha256"] == plan.sha256
            && v["guard_sha256"] == GUARD_SHA
            && v["producer_invocation_id"] == iid
            && v["producer"]["invocation_id"] == iid
            && v["producer"]["pid"] == pid
            && v["trip_reason"] == "filesystem-floor"
            && v["minimum_free_bytes"] == u64::MAX
            && num(v, "available_bytes")? < u64::MAX
            && v["producer_stop_enabled"] == true
            && v["worker_observation_error"].is_null()
            && v["memory_observation_error"].is_null()
            && v["filesystem_observation_error"].is_null()
            && v["root_physical_observation_error"].is_null()
            && v["root_physical_observation"]["exceeds_budget"] == false
            && v["workers"].as_array().is_some_and(|a| a.len() == 1)
            && v["workers"][0][0] == pid
            && v["process_observation"]["token_present"] == false
            && v["process_observation"]["processes"]
                .as_array()
                .is_some_and(|a| a.len() == 1),
        "not the intended genuine pretoken floor trip"
    );
    Ok(())
}
fn killed(v: &Value, iid: &str) -> Result<()> {
    ensure!(
        v["Id"] == UNIT
            && v["InvocationID"] == iid
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"] == ""
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["ExecMainCode"] == "2"
            && v["ExecMainStatus"] == "15"
            && matches!(v["ActiveState"].as_str(), Some("inactive" | "failed")),
        "guard did not terminate original waiting harness with SIGTERM"
    );
    Ok(())
}
fn empty_cgroup() -> Result<()> {
    let root = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    match fs::symlink_metadata(&root) {
        Ok(_) => live::drained_tree(&root, &mut 1024),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) fn capture_stop(
    n: &mut Native,
    iid: &str,
    pid: u64,
    receipts: &Path,
    guard_plan: &Bound,
    startup: &Bound,
    producer_package: &Path,
    guard_package: &Path,
    startup_value: &Value,
) -> Result<()> {
    let token = Path::new(TOKENS).join(iid);
    absent(&token)?;
    let guard = loop {
        n.check()?;
        let g = n.show(GUARD_UNIT)?;
        if g["ActiveState"] == "failed"
            && g["MainPID"] == "0"
            && g["ControlPID"] == "0"
            && g["Job"] == ""
        {
            break g;
        }
        ensure!(
            g["ActiveState"] == "activating" || g["ActiveState"] == "inactive" || g["Job"] != "",
            "unexpected protective guard state"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let gid = text(&guard, "InvocationID")?;
    ensure!(hex(gid, 32), "guard IID");
    ensure!(
        guard["Result"] == "exit-code"
            && guard["ExecMainStatus"] == "1"
            && guard["NRestarts"] == "0",
        "unexpected guard failure"
    );
    let sample = receipts.join(format!("sample-{gid}.json"));
    let sample_ref = Bound::new(&sample, hash(&sample)?);
    let sample = sample_ref.json()?;
    check_sample(&sample, iid, pid, guard_plan)?;
    let request = receipts.join(format!("stop-request-{gid}.json"));
    let request_ref = Bound::new(&request, hash(&request)?);
    let request = request_ref.json()?;
    ensure!(
        request["schema"] == "horizon265-native-guard-stop-request-v1"
            && request["producer_invocation_id"] == iid
            && request["plan_sha256"] == guard_plan.sha256
            && request["guard_invocation_id"] == gid
            && request["drain_proven"] == false,
        "guard stop request mismatch"
    );
    let terminal = loop {
        n.check()?;
        let v = n.show(UNIT)?;
        ensure!(v["InvocationID"] == iid, "producer replaced");
        if v["MainPID"] == "0" && v["ControlPID"] == "0" && v["Job"] == "" {
            break v;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    killed(&terminal, iid)?;
    empty_cgroup()?;
    absent(&PathBuf::from(format!("/proc/{pid}")))?;
    ensure!(
        fs::read_dir(ROOT)?.next().is_none(),
        "snapshot/worker work happened before qualification token"
    );
    absent(&token)?;
    // Stop only this exact qualification timer. Preserve both manager units and
    // packages for separate reviewed retirement; never auto-reset and relaunch.
    n.run("/usr/bin/systemctl", &["stop", TIMER])?;
    ensure!(
        n.show(TIMER)?["ActiveState"] == "inactive",
        "qualification timer still active"
    );
    ensure!(
        n.show(UNIT)? == terminal,
        "producer terminal changed during drainage"
    );
    let journal = n.run(
        "/usr/bin/journalctl",
        &[
            "--all",
            "--no-pager",
            "--output=json",
            "--boot=0",
            "_PID=1",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={iid}"),
        ],
    )?;
    let journal_ref = save(&n.root, "qualification-producer-PID1.jsonl", &journal)?;
    let guard_journal = n.run(
        "/usr/bin/journalctl",
        &[
            "--all",
            "--no-pager",
            "--output=json",
            "--boot=0",
            "_PID=1",
            &format!("UNIT={GUARD_UNIT}"),
            &format!("INVOCATION_ID={gid}"),
        ],
    )?;
    let guard_journal_ref = save(&n.root, "qualification-guard-PID1.jsonl", &guard_journal)?;
    let v = json!({"schema":"horizon-native265-protective-stop-capture-v1","harness":Bound::new(HARNESS,HARNESS_SHA),"guard":Bound::new(GUARD,GUARD_SHA),
        "producer_invocation_id":iid,"producer_main_pid":pid,"guard_invocation_id":gid,"boot_id":startup_value["boot_id"],
        "startup_plan":startup,"guard_plan":guard_plan,"sample":sample_ref,"stop_request":request_ref,
        "producer_terminal":terminal,"guard_terminal":guard,"producer_pid1":journal_ref,"guard_pid1":guard_journal_ref,
        "producer_package":producer_package,"guard_package":guard_package,"receipts":receipts,
        "token_absent":true,"worker_root_empty":true,"original_process_gone":true,"kernel_drained":true,
        "actual_stop_observed":true,"two_process_native_runtime_qualified":false,"Main_acceptance_required":true,
        "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let out = save_json(&n.root, "protective-stop-capture.json", &v)?;
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}
pub(super) fn accepted(review: &Value) -> Result<()> {
    ensure!(
        review["schema"] == "horizon-native265-protective-stop-qualification-v1"
            && review["Main_accepted"] == true
            && review["harness"] == json!(Bound::new(HARNESS, HARNESS_SHA))
            && review["guard"] == json!(Bound::new(GUARD, GUARD_SHA))
            && review["actual_pid1_stop_ordering_verified"] == true
            && review["sandbox_permissions_verified"] == true
            && review["original_attempt_retired_with_evidence"] == true,
        "native265 stop qualification missing"
    );
    let capture = binding(&review["capture"])?.sealed()?;
    ensure!(
        capture["schema"] == "horizon-native265-protective-stop-capture-v1"
            && capture["harness"] == review["harness"]
            && capture["guard"] == review["guard"]
            && capture["token_absent"] == true
            && capture["worker_root_empty"] == true
            && capture["original_process_gone"] == true
            && capture["kernel_drained"] == true
            && capture["actual_stop_observed"] == true,
        "stop capture does not establish closed pretoken stop"
    );
    let plan = binding(&capture["guard_plan"])?;
    let sample = binding(&capture["sample"])?.json()?;
    check_sample(
        &sample,
        text(&capture, "producer_invocation_id")?,
        num(&capture, "producer_main_pid")?,
        &plan,
    )?;
    killed(
        &capture["producer_terminal"],
        text(&capture, "producer_invocation_id")?,
    )?;
    for key in ["producer_pid1", "guard_pid1"] {
        binding(&capture[key])?.bytes(false)?;
    }
    let retired = binding(&review["retirement"])?.sealed()?;
    ensure!(
        retired["schema"] == "horizon-native265-qualification-unit-retirement-v1"
            && retired["sealed_packages_and_diagnostics_preserved"] == true
            && retired["producer_restarted"] == false
            && retired["replay_launch_authorized"] == false
            && retired["remote_mutations"] == false,
        "qualification retirement proof missing"
    );
    let before = binding(&retired["before"])?.json()?;
    ensure!(
        before["capture"] == capture,
        "retirement belongs to another capture"
    );
    no_authority(review)?;
    Ok(())
}
pub(super) fn retire_attempt(n: &mut Native, capture: &Value) -> Result<()> {
    ensure!(
        capture["schema"] == "horizon-native265-protective-stop-capture-v1"
            && capture["harness"] == json!(Bound::new(HARNESS, HARNESS_SHA))
            && capture["guard"] == json!(Bound::new(GUARD, GUARD_SHA))
            && capture["actual_stop_observed"] == true
            && capture["token_absent"] == true,
        "foreign qualification capture"
    );
    let iid = text(capture, "producer_invocation_id")?;
    ensure!(hex(iid, 32), "qualification IID");
    let p = binding(&capture["guard_plan"])?;
    check_sample(
        &binding(&capture["sample"])?.json()?,
        iid,
        num(capture, "producer_main_pid")?,
        &p,
    )?;
    let initial = n.show(UNIT)?;
    killed(&initial, iid)?;
    empty_cgroup()?;
    absent(&PathBuf::from(format!(
        "/proc/{}",
        num(capture, "producer_main_pid")?
    )))?;
    absent(&Path::new(TOKENS).join(iid))?;
    ensure!(
        fs::read_dir(ROOT)?.next().is_none(),
        "qualification root not empty"
    );
    for unit in [GUARD_UNIT, TIMER] {
        let v = n.show(unit)?;
        ensure!(
            v["MainPID"].as_str().is_none_or(|s| s == "0")
                && v["ControlPID"].as_str().is_none_or(|s| s == "0")
                && v["Job"] == ""
                && !matches!(v["ActiveState"].as_str(), Some("active" | "activating")),
            "qualification control still executing"
        );
    }
    let producer = Path::new(text(capture, "producer_package")?);
    let guard = Path::new(text(capture, "guard_package")?);
    ensure!(
        producer.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && guard.parent() == producer.parent(),
        "package namespace"
    );
    ensure!(
        producer
            .file_name()
            .and_then(|p| p.to_str())
            .is_some_and(|p| p.starts_with("horizon-native265-producer-"))
            && guard
                .file_name()
                .and_then(|p| p.to_str())
                .is_some_and(|p| p.starts_with("horizon-native265-guard-binding-")),
        "foreign qualification package"
    );
    let links = [
        (UNIT, producer.join(UNIT)),
        (RETENTION, producer.join(RETENTION)),
        (GUARD_UNIT, guard.join(GUARD_UNIT)),
        (TIMER, guard.join(TIMER)),
    ];
    for (unit, target) in &links {
        let link = Path::new("/etc/systemd/system").join(unit);
        let m = fs::symlink_metadata(&link)?;
        ensure!(
            m.file_type().is_symlink() && m.uid() == 0 && fs::read_link(&link)? == *target,
            "foreign installed qualification link"
        );
        Bound::new(target, hash(target)?).artifact()?;
    }
    n.run("/usr/bin/systemctl", &["stop", RETENTION])?;
    let released = n.show(UNIT)?;
    ensure!(
        released["MainPID"] == "0"
            && released["ControlPID"] == "0"
            && released["Job"] == ""
            && matches!(
                released["ActiveState"].as_str(),
                Some("inactive" | "failed")
            )
            && (released["InvocationID"] == iid || released["InvocationID"] == ""),
        "qualification owner replaced during retention release"
    );
    let proof = save_json(
        &n.root,
        "retirement-before.json",
        &json!({"capture":capture,"producer":initial,"links":links,"root_empty":true,"remote_mutations":false}),
    )?;
    // Only exact installed unit symlinks are removed. All sealed packages and
    // native/guard diagnostics remain intact for Main acceptance and provenance.
    for (unit, target) in &links {
        let link = Path::new("/etc/systemd/system").join(unit);
        ensure!(
            fs::read_link(&link)? == *target,
            "qualification link changed"
        );
        fs::remove_file(link)?;
    }
    File::open("/etc/systemd/system")?.sync_all()?;
    n.run("/usr/bin/systemctl", &["reset-failed", GUARD_UNIT])?;
    n.run("/usr/bin/systemctl", &["daemon-reload"])?;
    for unit in [UNIT, GUARD_UNIT, TIMER, RETENTION] {
        ensure!(
            n.show(unit)?["LoadState"] == "not-found",
            "qualification unit not collected"
        );
    }
    save_json(
        &n.root,
        "retirement-complete.json",
        &json!({"schema":"horizon-native265-qualification-unit-retirement-v1","before":proof,
        "sealed_packages_and_diagnostics_preserved":true,"producer_restarted":false,"replay_launch_authorized":false,"remote_mutations":false}),
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_or_missing_qualification_cannot_admit_native_restore() {
        assert!(accepted(&json!({})).is_err());
        assert!(accepted(&json!({"schema":"horizon-native265-protective-stop-qualification-v1","Main_accepted":true})).is_err());
    }
    #[test]
    fn timeout_or_clean_exit_is_not_a_protective_signal() {
        let mut t = json!({"Id":UNIT,"InvocationID":"a".repeat(32),"MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0","Restart":"no","ExecMainCode":"2","ExecMainStatus":"15","ActiveState":"inactive"});
        killed(&t, &"a".repeat(32)).unwrap();
        t["ExecMainCode"] = json!("1");
        t["ExecMainStatus"] = json!("1");
        assert!(killed(&t, &"a".repeat(32)).is_err());
    }
}
