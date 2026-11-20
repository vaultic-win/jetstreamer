use super::*;

// The controller is a finite control_units row; the current census reserves the
// candidate's guard separately in CONTROL. Show both charges without duplicating
// either the candidate controls or the tmpfs contents in the host hard sum.
pub(super) fn charges(controls: &Value, controller: &str) -> Result<Value> {
    let mut found = false;
    let mut other = 0;
    for row in controls.as_array().context("control units")? {
        let unit = text(row, "unit")?;
        let bytes = num(row, "maximum_memory_bytes")?;
        ensure!(
            unit != UNIT && unit != GUARD_UNIT && bytes > 0,
            "candidate in existing control set"
        );
        if unit == controller {
            ensure!(
                !found && bytes == CONTROLLER_MEMORY,
                "incorrect 261 controller booking"
            );
            found = true;
        } else {
            other = capacity::add(other, bytes)?;
        }
    }
    ensure!(found, "actual controller not booked");
    let needed = capacity::add(other, capacity::add(GUARD_MEMORY, CONTROLLER_MEMORY)?)?;
    ensure!(
        needed <= CONTROL,
        "existing control envelope does not cover 261 and booked controls"
    );
    Ok(
        json!({"producer_maximum_bytes":MEMORY,"guard_maximum_bytes":GUARD_MEMORY,
        "controller_unit":controller,"controller_maximum_bytes":CONTROLLER_MEMORY,
        "candidate_total_memory_bytes":MEMORY+GUARD_MEMORY+CONTROLLER_MEMORY,
        "other_control_maximum_bytes":other,"total_control_charged_bytes":needed,
        "existing_control_envelope_bytes":CONTROL,"additional_producer_memory_bytes":MEMORY,
        "disk_receipt_growth_bytes":DISK_RECEIPTS,"tmpfs_capacity_within_producer_memory_bytes":tmpfs::BYTES}),
    )
}

pub(super) fn current(n: &mut Native, r: &Value, held: bool) -> Result<Value> {
    let controller = text(r, "controller_unit")?;
    let envelope = charges(&r["control_units"], controller)?;
    let iid = std::env::var("INVOCATION_ID")?;
    let own = || -> Result<()> {
        ensure!(
            fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{controller}"),
            "261 admission outside booked controller"
        );
        Ok(())
    };
    own()?;
    let owner = n.show(controller)?;
    ensure!(
        text(&owner, "MainPID")?.parse::<u32>()? == std::process::id() && owner["Type"] == "exec",
        "261 controller is not main process"
    );
    live::finite_owner(&owner, controller, &iid, CONTROLLER_MEMORY)?;
    let path = Path::new(FILESYSTEM);
    let disk_fd = File::open(path)?;
    use std::os::fd::AsRawFd;
    let mut disk_info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(disk_fd.as_raw_fd(), &mut disk_info) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        disk_info.f_type == libc::EXT4_SUPER_MAGIC,
        "261 receipt ledger is not on the admitted ext4 filesystem"
    );
    if held {
        let producer = n.show(UNIT)?;
        let held_iid = text(&producer, "InvocationID")?;
        live::finite_owner(&producer, UNIT, held_iid, MEMORY)?;
        gate::held_image(
            text(&producer, "MainPID")?.parse()?,
            held_iid,
            UNIT,
            HARNESS,
        )?;
    }
    let host = native257_fit::booked_host_candidate(
        n,
        r,
        path,
        Some(((UNIT, GUARD_UNIT, TIMER), held)),
        None,
    )?;
    ensure!(
        host.rows
            .iter()
            .all(|row| row.unit != UNIT && row.unit != GUARD_UNIT && row.unit != controller),
        "261 owner or control already booked as producer"
    );
    ensure!(
        disk_fd.metadata()?.dev() == host.device,
        "ledger filesystem changed across census"
    );
    let mount = pristine(host.device)?;
    let cpu = units::cpu_sharing(n, r)?;
    let mut resources = live::resources_at(path)?;
    ensure!(
        resources.0 == host.resources.0 && fs::metadata(path)?.dev() == host.device,
        "disk or physical host changed"
    );
    resources.1 = resources.1.min(host.resources.1);
    resources.2 = resources.2.min(host.resources.2);
    let capacity = capacity::candidate_arithmetic(
        resources,
        host.century,
        &host.rows,
        &host.currents,
        host.overhead,
        (MEMORY, DISK_RECEIPTS),
    )?;
    ensure!(
        pristine(host.device)? == mount,
        "261 tmpfs changed across host accounting"
    );
    let after = n.show(controller)?;
    live::same_owner(&owner, &after)?;
    live::finite_owner(&after, controller, &iid, CONTROLLER_MEMORY)?;
    own()?;
    n.check()?;
    Ok(
        json!({"capacity":capacity,"control_charges":envelope,"boot_id":host.boot,
        "disk_filesystem":FILESYSTEM,"disk_device":host.device,"tmpfs":mount,"cpu":cpu,"controller":after,
        "actual_current_memory":host.currents,"native265_runtime_growth_release":host.release,
        "native211_cold_growth_release":host.native211_growth,"full211_growth":host.full211_growth,"failed_boundary205206_memory_release":host.boundary_memory}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn charges_candidate_once_and_preserves_other_controls() {
        let ctl = "horizon261-controller.service";
        let row = |u: &str, b: u64| json!({"unit":u,"maximum_memory_bytes":b});
        let rows = json!([
            row(ctl, CONTROLLER_MEMORY),
            row("other.service", CONTROL - GUARD_MEMORY - CONTROLLER_MEMORY)
        ]);
        let result = charges(&rows, ctl).unwrap();
        assert_eq!(result["total_control_charged_bytes"], CONTROL);
        assert_eq!(result["candidate_total_memory_bytes"], 192_536_870_912u64);
        assert_eq!(result["disk_receipt_growth_bytes"], 268_435_456u64);
        assert_eq!(
            result["additional_producer_memory_bytes"],
            192_000_000_000u64
        );
        for bad in [
            json!([]),
            json!([row(ctl, CONTROLLER_MEMORY - 1)]),
            json!([row(ctl, CONTROLLER_MEMORY), row(ctl, CONTROLLER_MEMORY)]),
            json!([row(ctl, CONTROLLER_MEMORY), row(GUARD_UNIT, 1)]),
            json!([
                row(ctl, CONTROLLER_MEMORY),
                row(
                    "other.service",
                    CONTROL - CONTROLLER_MEMORY - GUARD_MEMORY + 1
                )
            ]),
        ] {
            assert!(charges(&bad, ctl).is_err());
        }
    }
}
