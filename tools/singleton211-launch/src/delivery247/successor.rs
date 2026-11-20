use super::*;
#[path = "../../../../jetstreamer-horizon-observe/src/successor247.rs"]
pub(super) mod evidence;

pub(super) fn selected(e: &Value) -> bool {
    e["epoch"] == 247 && e["phase"] == "upload-readback" && e["unit"]["Id"] == evidence::UNIT
}
pub(super) fn owner() -> Result<evidence::Owner> {
    let claim = Path::new(evidence::ROOT).join("pipeline-claim.json");
    let reference = Bound::new(&claim, hash(&claim)?);
    evidence::load(&json!(reference))
}
pub(super) fn roster(fleet: &Value, rows: &[capacity::Reservation]) -> Result<()> {
    let pipelines = fleet["pipelines"].as_array().context("pipeline roster")?;
    let active = fleet["active"].as_array().context("active roster")?;
    let mut found = pipelines
        .iter()
        .filter(|e| e["unit"]["Id"] == evidence::UNIT);
    let mut reservations = rows.iter().filter(|r| r.unit == evidence::UNIT);
    let Some(e) = found.next() else {
        ensure!(
            reservations.next().is_none() && !active.iter().any(selected),
            "missing third uploader claim"
        );
        return Ok(());
    };
    let o = owner()?;
    evidence::verify_drains()?;
    ensure!(
        found.next().is_none()
            && selected(e)
            && e["expected_invocation_id"] == o.iid
            && e["live"] == true
            && e["unit"] == fleet["unit_census"][evidence::UNIT]
            && e["sampled_at_utc"] == fleet["sampled_at_utc"]
            && e["unit"]["InvocationID"] == o.iid
            && e["unit"]["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                == Some(o.pid)
            && e["evidence"] == json!([o.proof["booking"], o.proof["launch"]])
            && e["ordinary_replay_claim"] == false
            && e["grants_launch_or_publication_authority"] == false
            && e.get("finalization_evidence") == Some(&Value::Null)
            && e["current_sidecar_eta_valid"] == false
            && active
                .iter()
                .filter(
                    |v| v["unit"]["Id"] == evidence::UNIT || v["expected_invocation_id"] == o.iid
                )
                .eq(std::iter::once(e)),
        "third uploader is not the exact independently claimed owner"
    );
    evidence::historical_claims(fleet)?;
    let row = reservations
        .next()
        .context("missing third uploader reservation")?;
    ensure!(
        reservations.next().is_none()
            && row.invocation_id == o.iid
            && row.maximum_memory_bytes == evidence::BOOKED
            && row.remaining_disk_growth_bytes >= evidence::DISK
            && row.minimum_free_bytes >= evidence::FLOOR
            && row.release.is_none()
            && rows.iter().filter(|r| r.invocation_id == o.iid).count() == 1,
        "third uploader envelope changed"
    );
    Ok(())
}
pub(super) fn live_owner(v: &Value) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let o = owner()?;
    ensure!(
        v["Id"] == evidence::UNIT
            && v["InvocationID"] == o.iid
            && v["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok()) == Some(o.pid)
            && v["Type"] == "exec"
            && v["ExecMainStatus"] == "0"
            && v["MemoryMax"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(evidence::HARD)
            && v["MemorySwapMax"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"] == ""
            && v["Restart"] == "no"
            && v["KillMode"] == "control-group"
            && v["Delegate"] == "no"
            && v["DropInPaths"] == ""
            && periodic::stable_command(text(v, "ExecStart")?)?
                == periodic::stable_command(&o.command)?,
        "successor manager changed"
    );
    let p = Path::new("/proc").join(o.pid.to_string());
    let exe = p.join("exe");
    Bound::new(evidence::IMAGE, evidence::IMAGE_SHA).artifact()?;
    let argv = o
        .argv
        .as_array()
        .context("new argv")?
        .iter()
        .map(|a| a.as_str().context("argv member"))
        .collect::<Result<Vec<_>>>()?
        .join("\0")
        + "\0";
    ensure!(
        fs::read(p.join("cmdline"))? == argv.as_bytes()
            && fs::read_link(&exe)?.as_os_str().as_bytes() == evidence::IMAGE.as_bytes()
            && metadata_identity(&fs::metadata(&exe)?) == identity(Path::new(evidence::IMAGE))?
            && fs::read_to_string(p.join("cgroup"))?.trim()
                == format!("0::/system.slice/{}", evidence::UNIT),
        "successor mapped owner changed"
    );
    Ok(())
}
