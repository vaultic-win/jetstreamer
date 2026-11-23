//! The standalone guard stops the right producer before PID 1 may clear its IID.
use super::*;
const STARTED: &str = "39f53479d3a045ac8e11786248231fbf";
const STOPPING: &str = "de5b426a63be47a7b6ac3eaac82e2f6f";
const DEAD: &str = "7ad2d189f7e94e70a38c781354912448";
const STOPPED: &str = "9d1aaa27d60140bd96365438aad20286";
type Fields = BTreeMap<String, String>;

fn terminal(m: &Fields, unit: &str) -> Result<()> {
    for (k, v) in [
        ("Id", unit),
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("InvocationID", ""),
        ("MainPID", "0"),
        ("ControlGroup", ""),
        ("Result", "success"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
    ] {
        ensure!(m.get(k).is_some_and(|s| s == v), "wrong stopped {unit} {k}");
    }
    Ok(())
}

fn boundaries(raw: &[u8], unit: &str, iid: &str) -> Result<Vec<Value>> {
    ensure!(hex(iid, 32), "malformed stopped IID");
    let mut events = Vec::new();
    for l in std::str::from_utf8(raw)?.lines() {
        let row: Value = serde_json::from_str(l)?;
        ensure!(
            row["_UID"] == "0"
                && row["_PID"] == "1"
                && row["_BOOT_ID"] == BOOT.replace('-', "")
                && row["UNIT"] == unit
                && row["INVOCATION_ID"] == iid,
            "different original manager lifecycle"
        );
        let mid = text(&row, "MESSAGE_ID")?;
        if ![STARTED, STOPPING, DEAD, STOPPED].contains(&mid) {
            continue;
        }
        let expected = [STARTED, STOPPING, DEAD, STOPPED]
            .get(events.len())
            .copied();
        ensure!(Some(mid) == expected, "foreign manager stop ordering");
        let msg = text(&row, "MESSAGE")?;
        let valid = match mid {
            STARTED => msg.starts_with(&format!("Started {unit} -")) && row["JOB_RESULT"] == "done",
            STOPPING => msg.starts_with(&format!("Stopping {unit} -")),
            DEAD => msg == format!("{unit}: Deactivated successfully."),
            STOPPED => msg.starts_with(&format!("Stopped {unit} -")) && row["JOB_RESULT"] == "done",
            _ => false,
        };
        let t = text(&row, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            valid
                && events
                    .last()
                    .is_none_or(|q: &Value| q["monotonic_us"].as_u64().is_some_and(|v| v < t)),
            "original manager stop boundary"
        );
        events.push(
            json!({"message_id":mid,"monotonic_us":t,"cursor":text(&row,"__CURSOR")?,"event":row}),
        );
    }
    ensure!(events.len() == 4, "incomplete bound producer shutdown");
    Ok(events)
}
pub(super) fn checked_terminal(unit: &str, iid: &str) -> Result<Value> {
    let before = gate::owner_fields(unit)?;
    terminal(&before, unit)?;
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "-b",
            "-n",
            "20",
            "--no-pager",
            "-o",
            "json",
            "_UID=0",
            "_PID=1",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={iid}"),
        ])
        .output()?;
    ensure!(output.status.success(), "producer manager journal");
    let events = boundaries(&output.stdout, unit, iid)?;
    live::verify_drained_group(unit)?;
    ensure!(
        before == gate::owner_fields(unit)?,
        "producer changed across original termination"
    );
    Ok(json!({"terminal":before,"pid1":events,"drained":true}))
}

/// Only a qualified native guard's own committed stop intent can invoke this fallback.
pub(super) fn closed(
    p: &Profile,
    supervisor: &Value,
    before: &Fields,
    plan: &Bound,
) -> Result<Bound> {
    let iid = text(supervisor, "iid")?;
    let gid = std::env::var("INVOCATION_ID")?;
    ensure!(
        hex(&gid, 32)
            && before["Id"] == p.unit
            && before["InvocationID"] == iid
            && before["ActiveState"] == "active"
            && before["SubState"] == "running"
            && before["NRestarts"] == "0"
            && before["Restart"] == "no"
            && before["Delegate"] == "no"
            && before["KillMode"] == "control-group",
        "original stop owner changed"
    );
    let rr = p.state.join("receipts");
    let intent = bound_at(&rr.join("stop-intent.json"))?;
    let i = intent.json()?;
    let sample = bound_at(&rr.join(format!("sample-{gid}.json")))?;
    let s = sample.json()?;
    let reason = text(&i, "reason")?;
    ensure!(
        i["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && i["plan_sha256"] == plan.sha256
            && i["producer_invocation_id"] == iid
            && i["sample"] == s
            && s["guard_invocation_id"] == gid
            && [
                "filesystem-floor",
                "multiple-workers",
                "worker-vma-ceiling",
                "root-physical-budget"
            ]
            .contains(&reason),
        "different original guard stop intent"
    );
    start::validate_sample_for(
        p.lane.guard().1,
        &s,
        &p.unit,
        iid,
        before["MainPID"].parse()?,
        plan,
        Some(reason),
    )?;
    let manager = checked_terminal(&p.unit, iid)?;
    save_json(
        &rr,
        "manager-stop-completion.json",
        &json!({
            "schema":format!("horizon{}-native-guard-cleared-manager-stop-v1",p.lane.epoch()),"producer_invocation_id":iid,"guard_invocation_id":gid,
            "plan_sha256":plan.sha256,"intent":intent,"sample":sample,"reason":reason,"manager":manager
        }),
    )
}

const FIRST: &str = "/var/lib/jetstreamer/horizon266-native-full-v165-a1/qa-disk";
const UNIT: &str = "horizon-qualify-266-general-qa-disk-v1.service";
const IID: &str = "be802fa779ed418aafc945b3705bb9aa";
const GID: &str = "7301fbdf543a485eb366e6c64c0d021f";
fn raw_original() -> Result<(Bound, Bound, Bound)> {
    let first = Path::new(FIRST);
    let sample = Bound::new(
        first.join(format!("receipts/sample-{GID}.json")),
        "f5d17b8059ae6c4adbe853ab5f1ed70e693a04a7a46541dc57c130bc89f22c2e",
    );
    let intent = Bound::new(
        first.join("receipts/stop-intent.json"),
        "353c546490eece845fdf7e7c8ec022b47d9919b30d1593bfccc723e0eaf4d9be",
    );
    let error = Bound::new(
        first.join("failure.json"),
        "e10e1c075b4e5034850f3977cb94708970a4a35b700391ebcd0fba72b42fba38",
    );
    let s = sample.json()?;
    let i = intent.json()?;
    let e = error.sealed()?;
    let plan = Bound::new(
        first.join("guard-plan.json"),
        "9f10cb9d5ba14f28d55fd78c4ea90f2a9972a0f2ac774d37a5a921d57cfe3af2",
    );
    plan.sealed()?;
    start::validate_sample_for(
        GUARD_SHA,
        &s,
        UNIT,
        IID,
        2782923,
        &plan,
        Some("filesystem-floor"),
    )?;
    ensure!(
        s["guard_invocation_id"] == GID
            && i["sample"] == s
            && e["original_iid"] == IID
            && e["entry_replay_proven"] == false,
        "original unsuccessful QA changed"
    );
    Ok((sample, intent, error))
}
pub(super) fn original(_n: &mut Native) -> Result<Value> {
    let (sample, intent, error) = raw_original()?;
    let first = Path::new(FIRST);
    let manager = checked_terminal(UNIT, IID)?;
    for service in [
        "horizon266-native-full-v165-a1.service",
        "horizon-266-general-protective-qa-disk-v1.service",
        "horizon-266-general-protective-qa-disk-v1-failsafe.service",
    ] {
        live::verify_drained_group(service)?;
    }
    let timer = gate::owner_fields("horizon-266-general-protective-qa-disk-v1.timer")?;
    ensure!(
        timer["ActiveState"] == "inactive",
        "first QA timer still armed"
    );
    absent(&first.join("qualification.json"))?;
    absent(&first.join(format!("token-{IID}.json")))?;
    ensure!(
        fs::symlink_metadata(first.join("private.ext4"))?.len() == 256 << 20,
        "first QA disk changed"
    );
    Ok(
        json!({"sample":sample,"intent":intent,"failure":error,"manager":manager,
        "disk_bytes_retained":256<<20,"qualification_passed":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "original native QA receipt and manager journal"]
    fn actual_native_guard_stopped_owner_then_manager_cleared_iid() {
        let _ = raw_original().unwrap();
        let raw = Command::new("/usr/bin/journalctl")
            .args([
                "-b",
                "--no-pager",
                "-o",
                "json",
                "_UID=0",
                "_PID=1",
                &format!("UNIT={UNIT}"),
                &format!("INVOCATION_ID={IID}"),
            ])
            .output()
            .unwrap();
        let good = boundaries(&raw.stdout, UNIT, IID).unwrap();
        assert!(boundaries(&raw.stdout, UNIT, GID).is_err());
        let wrong = serde_json::to_vec(&good[0]["event"]).unwrap();
        assert!(boundaries(&wrong, UNIT, IID).is_err());
        let m = gate::owner_fields(UNIT).unwrap();
        terminal(&m, UNIT).unwrap();
        let mut changed = m;
        changed.insert("InvocationID".into(), GID.into());
        assert!(terminal(&changed, UNIT).is_err());
    }
}
