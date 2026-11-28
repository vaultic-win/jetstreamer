//! Retain the exact native211 owner, including its terminal history; never release its booking.
use super::*;
const UNIT211: &str = "archive-211-v1616-native-input-actual-v1.service";
const IID: &str = "9267f2c2c64949c29b9da7c27a46df94";
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon-211-native-input-gated-20261119-v1/native-input-test";
const IMAGE_SHA: &str = "2b1c0dd8b8cfcf0bbb80e52864c4b78a8348b1bc96dc97cbdfc4fee1094b8773";
fn evidence() -> Bound {
    Bound::new(
        "/var/lib/jetstreamer/horizon-native211-running-1828-v1/intent.json",
        "e68ce7b372c50c12210be7562cd8c8f18feb03078f6756190f1d7935f279282a",
    )
}
fn selected(e: &Value) -> bool {
    e["phase"] == "private-cold-snapshot-verification"
}
pub(super) fn without_native(f: &Value) -> Result<Value> {
    let mut f = f.clone();
    for field in ["pipelines", "active"] {
        let a = f[field].as_array_mut().context("fleet owner array")?;
        a.retain(|e| !selected(e));
    }
    Ok(f)
}
fn terminal_proof() -> Bound {
    Bound::new(
        "/var/lib/jetstreamer/horizon-native211-terminal-proof-1836-v1/proof.json",
        "97b3ae139f81af08fed1f0e94ccd9606b838d742fb679939969dd79e0ae357e5",
    )
}
fn retained_proof() -> Result<Value> {
    let proof = terminal_proof().json()?;
    ensure!(
        proof["schema"] == "jetstreamer-private-epoch211-native-terminal-proof-v1"
            && proof["epoch"] == 211
            && proof["unit"] == UNIT211
            && proof["invocation_id"] == IID
            && proof["main_pid"] == 1264515
            && proof["running_origin"] == json!(evidence())
            && proof["native_input_qualified"] == true,
        "native211 terminal proof identity"
    );
    for field in [
        "entry_replay",
        "full_epoch_qualified",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "r2_mutations",
        "remote_mutations",
    ] {
        ensure!(proof[field] == false, "native211 terminal proof authority");
    }
    ensure!(
        text(&proof, "boot_id")? == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "native211 terminal boot changed"
    );
    binding(&proof["journal"])?.bytes(false)?;
    Ok(proof)
}
fn validate_entry(f: &Value, e: &Value, intent: &Value, terminal: Option<&Value>) -> Result<()> {
    ensure!(
        e["epoch"] == 211
            && e["expected_invocation_id"] == IID
            && e["unit"]["Id"] == UNIT211
            && e["unit"]["InvocationID"] == IID
            && e["evidence"] == json!([evidence()])
            && e["private_qualification_only"] == true
            && e["ordinary_replay_claim"] == false
            && e["grants_launch_or_publication_authority"] == false,
        "unregistered native211 pipeline"
    );
    let active = f["active"].as_array().context("active")?;
    if e["live"] == false {
        let terminal = terminal.context("native211 terminal proof missing")?;
        ensure!(
            e["unit"]["MainPID"] == "0"
                && e["unit"]["ExecMainStatus"] == "0"
                && !active
                    .iter()
                    .any(|a| selected(a) || a["unit"]["Id"] == UNIT211),
            "terminal native211 marked active"
        );
        live::same_owner(terminal, &e["unit"])?;
    } else {
        ensure!(
            e["live"] == true
                && e["unit"]["MainPID"] == "1264515"
                && active.iter().filter(|a| *a == e).count() == 1,
            "native211 live membership"
        );
        live::same_owner(&intent["producer"], &e["unit"])?;
    }
    Ok(())
}
fn booking(r: &capacity::Reservation, floor: u64) -> Result<()> {
    ensure!(
        r.release.is_none()
            && r.maximum_memory_bytes == 137_438_953_472
            && r.remaining_disk_growth_bytes >= 300_000_000_000
            && r.minimum_free_bytes >= floor,
        "native211 obligations reduced"
    );
    Ok(())
}
pub(super) fn validate(f: &Value, rows: &[capacity::Reservation]) -> Result<()> {
    let entries: Vec<_> = f["pipelines"]
        .as_array()
        .context("pipelines")?
        .iter()
        .filter(|e| selected(e))
        .collect();
    ensure!(entries.len() <= 1, "duplicate native211 owner");
    if entries.is_empty() {
        ensure!(
            !rows.iter().any(|r| r.unit == UNIT211),
            "native211 retained booking missing fleet owner"
        );
    }
    if let Some(e) = entries.first() {
        let intent = evidence().json()?;
        let proof = if e["live"] == false {
            Some(retained_proof()?)
        } else {
            None
        };
        validate_entry(
            f,
            e,
            &intent,
            proof.as_ref().map(|p| &p["terminal_manager"]),
        )?;
        let r = rows
            .iter()
            .find(|r| r.unit == UNIT211 && r.invocation_id == IID)
            .context("native211 booking absent")?;
        let a = binding(&intent["admission"])?.json()?;
        booking(r, num(&a, "protected_existing_floor_bytes")?)?;
    }
    for a in f["active"].as_array().context("active")? {
        if selected(a) {
            ensure!(
                entries.iter().copied().filter(|e| *e == a).count() == 1,
                "unbound active native owner"
            );
        }
    }
    Ok(())
}
pub(super) fn is_retained_terminal(f: &Value, unit: &str) -> bool {
    unit == UNIT211
        && f["pipelines"].as_array().is_some_and(|entries| {
            entries
                .iter()
                .any(|e| selected(e) && e["epoch"] == 211 && e["live"] == false)
        })
}
fn terminal_identity(v: &Value, terminal: &Value) -> Result<()> {
    live::same_owner(terminal, v)?;
    for key in [
        "ControlPID",
        "Job",
        "Restart",
        "KillMode",
        "Delegate",
        "ExecMainCode",
        "ExecMainStatus",
        "MemoryMax",
        "MemoryHigh",
        "MemorySwapMax",
        "TasksMax",
        "Type",
        "User",
        "Group",
    ] {
        ensure!(
            !terminal[key].is_null() && v[key] == terminal[key],
            "native211 terminal changed {key}"
        );
    }
    Ok(())
}
pub(super) fn terminal_owner(v: &Value) -> Result<()> {
    let proof = retained_proof()?;
    terminal_identity(v, &proof["terminal_manager"])?;
    absent(Path::new("/proc/1264515"))?;
    let root = Path::new("/sys/fs/cgroup/system.slice").join(UNIT211);
    match fs::symlink_metadata(&root) {
        Ok(_) => live::drained_tree(&root, &mut 1024)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
pub(super) fn verify(f: &Value) -> Result<()> {
    for e in f["pipelines"]
        .as_array()
        .context("pipelines")?
        .iter()
        .filter(|e| selected(e))
    {
        ensure!(
            e["unit"]["Id"] == UNIT211 && e["unit"]["InvocationID"] == IID,
            "foreign native peer"
        );
        Bound::new(IMAGE, IMAGE_SHA).artifact()?;
        if e["live"] == false {
            // Current PID1 and kernel drainage are checked twice by live::census.
            retained_proof()?;
            absent(Path::new("/proc/1264515"))?;
            continue;
        }
        let mapped = Path::new("/proc/1264515/exe");
        ensure!(
            fs::read_link(mapped)? == Path::new(IMAGE)
                && metadata_identity(&fs::metadata(mapped)?) == identity(Path::new(IMAGE))?,
            "native211 mapped image changed"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn terminal_fixture() -> (Value, Value, Value) {
        let unit = json!({"Id":UNIT211,"LoadState":"loaded","InvocationID":IID,
            "MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0",
            "ActiveState":"inactive","SubState":"dead","Result":"success","ControlGroup":"",
            "ExecMainStatus":"0", "ExecMainCode":"1", "Restart":"no", "KillMode":"control-group",
            "Delegate":"no", "MemoryMax":"137438953472", "MemoryHigh":"120259084288",
            "MemorySwapMax":"0", "TasksMax":"512", "Type":"exec", "User":"ubuntu", "Group":"ubuntu",
            "ExecStart":format!("{{ path={IMAGE} ; argv[]={IMAGE} test --exact ; ignore_errors=no ; start_time=[x] ; stop_time=[y] ; pid=1264515 ; code=exited ; status=0 }}")});
        let entry = json!({"epoch":211,"phase":"private-cold-snapshot-verification","live":false,
            "unit":unit,"expected_invocation_id":IID,"evidence":[evidence()],
            "private_qualification_only":true,"ordinary_replay_claim":false,"grants_launch_or_publication_authority":false});
        let fleet = json!({"pipelines":[entry],"active":[]});
        (unit, entry, fleet)
    }
    #[test]
    fn terminal_history_requires_exact_owner_and_no_active_membership() {
        let (unit, entry, fleet) = terminal_fixture();
        validate_entry(&fleet, &entry, &json!({}), Some(&unit)).unwrap();
        terminal_identity(&unit, &unit).unwrap();
        assert!(validate_entry(&fleet, &entry, &json!({}), None).is_err());
        let mut active = fleet.clone();
        active["active"] = json!([entry]);
        assert!(validate_entry(&active, &entry, &json!({}), Some(&unit)).is_err());
        for (key, value) in [
            ("InvocationID", json!("b".repeat(32))),
            ("MainPID", json!("999")),
            ("ActiveState", json!("active")),
            ("ExecMainStatus", json!("1")),
            ("MemoryMax", json!("1")),
        ] {
            let mut changed = unit.clone();
            changed[key] = value;
            assert!(
                terminal_identity(&changed, &unit).is_err(),
                "accepted changed {key}"
            );
        }
    }
    #[test]
    fn terminal_history_does_not_release_any_obligation() {
        let r = capacity::Reservation {
            unit: UNIT211.into(),
            invocation_id: IID.into(),
            maximum_memory_bytes: 137_438_953_472,
            remaining_disk_growth_bytes: 300_000_000_000,
            minimum_free_bytes: 900,
            source: evidence(),
            release: None,
        };
        booking(&r, 900).unwrap();
        let mut changed = r.clone();
        changed.maximum_memory_bytes -= 1;
        assert!(booking(&changed, 900).is_err());
        changed = r.clone();
        changed.remaining_disk_growth_bytes -= 1;
        assert!(booking(&changed, 900).is_err());
        changed = r.clone();
        changed.minimum_free_bytes -= 1;
        assert!(booking(&changed, 900).is_err());
        changed = r;
        changed.release = Some(terminal_proof());
        assert!(booking(&changed, 900).is_err());
    }
    #[test]
    fn unknown_private_owner_cannot_hide_from_complete_census() {
        let e = json!({"epoch":212,"phase":"private-cold-snapshot-verification"});
        assert!(validate(&json!({"pipelines":[],"active":[e]}), &[]).is_err());
        let f = json!({"pipelines":[],"active":[]});
        validate(&f, &[]).unwrap();
        assert_eq!(without_native(&f).unwrap(), f);
    }
}
