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
    ensure!(
        !rows
            .iter()
            .any(|r| r.unit == "horizon-upload-247-staged-99f30641-v1.service"),
        "unlaunched 99f reader tier has no uploader reservation"
    );
    let mut found = pipelines
        .iter()
        .filter(|e| e["unit"]["Id"] == evidence::UNIT);
    let Some(e) = found.next() else {
        ensure!(
            !rows.iter().any(|r| r.unit == evidence::UNIT) && !active.iter().any(selected),
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
    let row = reservation(rows, &o.iid)?;
    verify_booking_source(&row.source.sealed()?, &o.proof)
}

fn reservation<'a>(
    rows: &'a [capacity::Reservation],
    iid: &str,
) -> Result<&'a capacity::Reservation> {
    let mut reservations = rows.iter().filter(|r| r.unit == evidence::UNIT);
    let row = reservations
        .next()
        .context("missing third uploader reservation")?;
    ensure!(
        reservations.next().is_none()
            && row.invocation_id == iid
            && row.maximum_memory_bytes == evidence::BOOKED
            && row.remaining_disk_growth_bytes >= evidence::DISK
            && row.minimum_free_bytes >= evidence::FLOOR
            && row.release.is_none()
            && rows.iter().filter(|r| r.invocation_id == iid).count() == 1,
        "third uploader envelope changed"
    );
    Ok(row)
}

fn verify_booking_source(source: &Value, proof: &Value) -> Result<()> {
    ensure!(
        source["schema"] == "horizon-native211-existing-booking-v2"
            && source["Main_accepted"] == true,
        "successor booking extraction not accepted"
    );
    for (field, document, pointer) in [
        ("unit", "booking", "/unit"),
        ("invocation_id", "launch", "/unit/InvocationID"),
        (
            "maximum_memory_bytes",
            "booking",
            "/additional_memory_reserve",
        ),
        ("remaining_disk_growth_bytes", "booking", "/disk_reserve"),
        (
            "minimum_free_bytes",
            "admission",
            "/protected_existing_floor_bytes",
        ),
    ] {
        ensure!(
            proof[document].is_object()
                && source["field_sources"][field]
                    == json!({"document":proof[document],"pointer":pointer}),
            "successor {field} charged to a different source"
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_owner_has_a_separate_booking_for_every_resource() -> Result<()> {
        let history: Value = serde_json::from_str(include_str!(
            "../../../../jetstreamer-horizon-observe/src/fixtures/successor247-history.json"
        ))?;
        let old = &history["previous"]["evidence"];
        // Prospective fact pattern only. Real bindings come from the new launch.
        let proof = json!({"booking":{"path":"new/booking","sha256":"1".repeat(64)},
            "launch":{"path":"new/launch","sha256":"2".repeat(64)},
            "admission":{"path":"new/admission","sha256":"3".repeat(64)}});
        let mut src = json!({"schema":"horizon-native211-existing-booking-v2","Main_accepted":true,
        "field_sources":{
            "unit":{"document":proof["booking"],"pointer":"/unit"},
            "invocation_id":{"document":proof["launch"],"pointer":"/unit/InvocationID"},
            "maximum_memory_bytes":{"document":proof["booking"],"pointer":"/additional_memory_reserve"},
            "remaining_disk_growth_bytes":{"document":proof["booking"],"pointer":"/disk_reserve"},
            "minimum_free_bytes":{"document":proof["admission"],"pointer":"/protected_existing_floor_bytes"}
        }});
        verify_booking_source(&src, &proof)?;
        for field in [
            "unit",
            "invocation_id",
            "maximum_memory_bytes",
            "remaining_disk_growth_bytes",
            "minimum_free_bytes",
        ] {
            let saved = src["field_sources"][field].clone();
            src["field_sources"][field]["document"] = old["booking"].clone();
            assert!(verify_booking_source(&src, &proof).is_err());
            src["field_sources"][field] = saved;
        }
        let mut rows: Vec<capacity::Reservation> =
            serde_json::from_value(history["historical_reservations"]["rows"].clone())?;
        let iid = "10000000000000000000000000000001";
        assert!(reservation(&rows, iid).is_err());
        let prospective = capacity::Reservation {
            unit: evidence::UNIT.into(),
            invocation_id: iid.into(),
            maximum_memory_bytes: evidence::BOOKED,
            remaining_disk_growth_bytes: evidence::DISK,
            minimum_free_bytes: evidence::FLOOR,
            source: Bound::new("new/source", "a".repeat(64)),
            release: None,
        };
        rows.push(prospective.clone());
        reservation(&rows, iid)?;
        assert_eq!(
            rows.iter().map(|r| r.maximum_memory_bytes).sum::<u64>(),
            29_548_578_304
        );
        assert_eq!(
            rows.iter()
                .map(|r| r.remaining_disk_growth_bytes)
                .sum::<u64>(),
            187_518_400_608
        );
        let mut lowered_memory = prospective.clone();
        lowered_memory.maximum_memory_bytes -= 1;
        let mut lowered_disk = prospective.clone();
        lowered_disk.remaining_disk_growth_bytes -= 1;
        let mut released = prospective;
        released.release = Some(released.source.clone());
        for altered in [lowered_memory, lowered_disk, released] {
            *rows.last_mut().unwrap() = altered;
            assert!(reservation(&rows, iid).is_err());
        }
        assert!(rows.pop().is_some());
        let mut phantom = rows[0].clone();
        phantom.unit = "horizon-upload-247-staged-99f30641-v1.service".into();
        rows.push(phantom);
        assert!(roster(&json!({"pipelines":[],"active":[]}), &rows).is_err());
        Ok(())
    }
}
