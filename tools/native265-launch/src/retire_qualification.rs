use super::qualification::{check_sample, empty_cgroup, killed};
use super::*;
pub(super) fn retire_attempt(n: &mut Native, capture: &Value) -> Result<()> {
    ensure!(
        capture["schema"] == STOP_CAPTURE
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
            .is_some_and(|p| p.starts_with(STOP_PRODUCER_PREFIX))
            && guard
                .file_name()
                .and_then(|p| p.to_str())
                .is_some_and(|p| p.starts_with(STOP_GUARD_PREFIX)),
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
        &json!({"schema":STOP_RETIRED,"before":proof,
        "sealed_packages_and_diagnostics_preserved":true,"producer_restarted":false,"replay_launch_authorized":false,"remote_mutations":false}),
    )?;
    Ok(())
}
