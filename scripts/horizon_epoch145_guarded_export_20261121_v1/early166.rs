//! Keep the original 166 reservation throughout a five-owner 145 verification.
use super::*;
pub const IID: &str = "fa16ee2f14fe44ecbc37c59e197553ac";
const PROCESSES: [(u32, u64, u64, u64); 2] = [
    (2452922, 349365780, 2304, 7220037),
    (2453240, 349367290, 64512, 93717144),
];
fn live() -> Result<[bool; 2]> {
    let mut result = [false; 2];
    for (i, (pid, ticks, dev, ino)) in PROCESSES.iter().copied().enumerate() {
        if native::ticks(pid).ok() != Some(ticks) {
            continue;
        }
        let image = fs::metadata(format!("/proc/{pid}/exe"));
        let group = fs::read_to_string(format!("/proc/{pid}/cgroup"));
        if native::ticks(pid).ok() != Some(ticks) {
            continue;
        }
        let image = image?;
        ensure!(
            (image.dev(), image.ino()) == (dev, ino)
                && group?.trim() == format!("0::/system.slice/{}", closed166::NODE),
            "original 166 executable or cgroup changed"
        );
        result[i] = true;
    }
    Ok(result)
}
pub fn rapid(closed: bool) -> Result<()> {
    let current = live()?;
    if closed {
        ensure!(
            current == [false, false],
            "terminated original 166 returned"
        );
        return Ok(());
    }
    if current != [true, true] {
        return Err(peer_terminal::Pending(166).into());
    }
    Ok(())
}
fn disposition(alive: [bool; 2], m: &Value, marker: bool) -> Result<bool> {
    ensure!(
        m["Id"] == closed166::NODE
            && (m["InvocationID"] == IID || m["InvocationID"] == "")
            && m["NRestarts"] == "0",
        "foreign 166 generation"
    );
    ensure!(m["ActiveState"] != "failed", "original 166 failed");
    if alive == [true, true]
        && m["ActiveState"] == "active"
        && m["MainPID"] == PROCESSES[0].0.to_string()
        && m["Job"] == ""
    {
        ensure!(
            !marker && m["InvocationID"] == IID,
            "active original has terminal evidence"
        );
        return Ok(false);
    }
    ensure!(
        m["MainPID"] == "0" || m["MainPID"] == PROCESSES[0].0.to_string(),
        "foreign terminal main PID"
    );
    if alive == [false, false]
        && marker
        && m["MainPID"] == "0"
        && m["ActiveState"] == "inactive"
        && m["Job"] == ""
        && m["ControlGroup"] == ""
    {
        return Ok(true);
    }
    Err(peer_terminal::Pending(166).into())
}
pub fn inspect() -> Result<Option<Value>> {
    let alive = live()?;
    let manager = joint_candidate::show(
        closed166::NODE,
        "Id,InvocationID,ActiveState,MainPID,ControlGroup,Job,NRestarts",
    )?;
    let path =
        Path::new(capacity::RUNTIME).join("epoch166-terminal-20261121-v1/TERMINAL_SUCCESS.json");
    if disposition(alive, &manager, path.try_exists()?)? {
        return Ok(Some(closed166::evidence()?));
    }
    Ok(None)
}
pub fn bind_initial(f: &Value, closed: Option<&Value>) -> Result<()> {
    let found = peer_terminal::rows(f)?
        .filter(|x| x["epoch"] == 166)
        .collect::<Vec<_>>();
    match closed {
        Some(proof) => ensure!(
            found.is_empty()
                && !proof["terminal"].is_null()
                && f["terminal166_local_commit"] == proof["terminal"],
            "fresh accepted original 166 closure required"
        ),
        None => ensure!(
            found.len() == 1
                && found[0]["unit"]["Id"] == closed166::NODE
                && found[0]["unit"]["InvocationID"] == IID
                && f["terminal166_local_commit"].is_null(),
            "accepted original live 166 required"
        ),
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_original_cannot_thaw_until_proven() {
        let mut m = json!({"Id":closed166::NODE,"InvocationID":IID,"NRestarts":"0","MainPID":"2452922","ActiveState":"active","Job":"","ControlGroup":"/system.slice/x"});
        assert!(!disposition([true, true], &m, false).unwrap());
        assert!(disposition([true, true], &m, true).is_err());
        m["ActiveState"] = "deactivating".into();
        assert!(
            disposition([true, false], &m, false)
                .unwrap_err()
                .is::<peer_terminal::Pending>()
        );
        m["ActiveState"] = "inactive".into();
        m["MainPID"] = "0".into();
        m["ControlGroup"] = "".into();
        assert!(
            disposition([false, false], &m, false)
                .unwrap_err()
                .is::<peer_terminal::Pending>()
        );
        assert!(disposition([false, false], &m, true).unwrap());
        m["InvocationID"] = "f".repeat(32).into();
        assert!(
            !disposition([false, false], &m, true)
                .unwrap_err()
                .is::<peer_terminal::Pending>()
        );
    }
    #[test]
    #[ignore = "uses current original five and the actual drained 5dfb exit"]
    fn current_five_full_fit() {
        let args: Vec<_> = ["QA_FLEET", "QA_FLEET_SHA"]
            .map(|k| std::env::var(k).unwrap())
            .into();
        let b = Bound {
            path: args[0].clone().into(),
            sha256: args[1].clone(),
        };
        let predecessor = continuity::predecessor().unwrap();
        let fleet = serde_json::from_slice(&custody::bytes(&b, 32 << 20, false).unwrap()).unwrap();
        bind_initial(&fleet, None).unwrap();
        assert!(
            !disposition(
                [true, true],
                &joint_candidate::show(
                    closed166::NODE,
                    "Id,InvocationID,ActiveState,MainPID,ControlGroup,Job,NRestarts"
                )
                .unwrap(),
                false
            )
            .unwrap()
        );
        let fit = capacity::capture_phase(&b, true).unwrap();
        fit.await_topology().unwrap();
        let sample = fit.await_current(0).unwrap();
        assert!(sample["retained_peer_terminal_evidence"]["166"].is_null());
        assert!(fit.evidence["joint_closed166"].is_null());
        let owners = fit.evidence["remaining_native_owners"].as_object().unwrap();
        assert_eq!(owners.len(), 5);
        assert_eq!(owners["166"]["invocation_id"], IID);
        let dir = PathBuf::from(std::env::var("QA_RUNTIME").unwrap());
        fs::write(dir.join("actual-five-fit.json"),serde_json::to_vec_pretty(&json!({"original":predecessor,"fleet":b,"fit":fit.evidence,"native":sample,"early":true,"166_credit_bytes":0,"launch":false})).unwrap()).unwrap();
    }
}
