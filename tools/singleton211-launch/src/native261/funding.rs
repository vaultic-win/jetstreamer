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

// Preserve the neighbouring 257 slot when the second boundary booking funds 261.
// A nominal 257 ledger row already contributes its memory and disk in booked_arithmetic.
fn candidate_capacity(
    host: &native257_fit::BookedHost,
    resources: (u64, u64, u64),
    envelope: &Value,
    controls: &Value,
) -> Result<Value> {
    let incoming = host.retry_memory.is_some();
    let existing = host.rows.iter().find(|r| r.unit == native257::UNIT);
    let (peer_memory, peer_disk, control_excess) = if incoming {
        let guard_booked = controls
            .as_array()
            .context("booked controls")?
            .iter()
            .find(|r| r["unit"] == native257::GUARD_UNIT);
        if let Some(g) = guard_booked {
            ensure!(
                num(g, "maximum_memory_bytes")? == GUARD_MEMORY,
                "257 guard cap differs"
            );
        }
        let additional_guard = if guard_booked.is_some() {
            0
        } else {
            GUARD_MEMORY
        };
        let (memory, disk, controller) = if let Some(r) = existing {
            ensure!(
                r.release.is_none()
                    && r.maximum_memory_bytes == native257_fit::NATIVE257_MEMORY
                    && r.remaining_disk_growth_bytes >= native257_fit::NATIVE257_DISK,
                "257 reservation cannot cover the paired native producer"
            );
            (0, 0, 0)
        } else {
            ensure!(
                !host.currents.contains_key(native257::UNIT),
                "live 257 lacks full booking"
            );
            // The outer 257 launcher is reserved for a separate, future activation.
            (
                native257_fit::NATIVE257_MEMORY,
                native257_fit::NATIVE257_DISK,
                512 << 20,
            )
        };
        let required = capacity::add(
            num(envelope, "total_control_charged_bytes")?,
            capacity::add(additional_guard, controller)?,
        )?;
        (memory, disk, required.saturating_sub(CONTROL))
    } else {
        (0, 0, 0)
    };
    let mut cap = capacity::candidate_arithmetic(
        resources,
        host.century,
        &host.rows,
        &host.currents,
        host.overhead,
        (
            capacity::add(MEMORY, capacity::add(peer_memory, control_excess)?)?,
            capacity::add(DISK_RECEIPTS, peer_disk)?,
        ),
    )?;
    if incoming {
        // Keep the pending 257 floor during subsequent 261 pretoken checks.
        cap["protected_existing_floor_bytes"] = json!(capacity::add(
            num(&cap, "protected_existing_floor_bytes")?,
            peer_disk
        )?);
        cap["paired_native257"] = json!({"unit":native257::UNIT,"already_in_ledger":existing.is_some(),"additional_producer_memory_bytes":peer_memory,"additional_disk_bytes":peer_disk,"additional_control_envelope_bytes":control_excess});
    }
    Ok(cap)
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
    let capacity = candidate_capacity(&host, resources, &envelope, &r["control_units"])?;
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
        "native211_cold_growth_release":host.native211_growth,"full211_growth":host.full211_growth,"failed_boundary205206_memory_release":host.boundary_memory,"completed_boundary205206_retry_memory_release":host.retry_memory}),
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

#[cfg(test)]
mod paired_tests {
    use super::*;
    fn host() -> native257_fit::BookedHost {
        native257_fit::BookedHost {
            resources: (2_000_000_000_000, 1_500_000_000_000, 5_000_000_000_000),
            rows: vec![],
            currents: BTreeMap::new(),
            overhead: (0, 0),
            century: 300_000_000_000,
            release: None,
            full211_growth: None,
            boundary_memory: None,
            retry_memory: Some(json!({})),
            native211_growth: None,
            boot: "fixture".into(),
            device: 1,
        }
    }
    #[test]
    fn new_retry_funding_protects_both_candidates_and_leaves_the_257_disk_floor_for_261() {
        let mut h = host();
        let e = json!({"total_control_charged_bytes":CONTROL});
        let ctl = json!([]);
        let both = candidate_capacity(&h, h.resources, &e, &ctl).unwrap();
        h.retry_memory = None;
        let original = candidate_capacity(&h, h.resources, &e, &ctl).unwrap();
        assert_eq!(
            num(&both, "memory_obligation_after_bytes").unwrap()
                - num(&original, "memory_obligation_after_bytes").unwrap(),
            native257_fit::NATIVE257_MEMORY + 3 * GUARD_MEMORY
        );
        for k in [
            "required_initial_free_bytes",
            "protected_existing_floor_bytes",
        ] {
            assert_eq!(
                num(&both, k).unwrap() - num(&original, k).unwrap(),
                native257_fit::NATIVE257_DISK
            );
        }
        h.retry_memory = Some(json!({}));
        h.rows.push(capacity::Reservation {
            unit: native257::UNIT.into(),
            invocation_id: "a".repeat(32),
            maximum_memory_bytes: native257_fit::NATIVE257_MEMORY,
            remaining_disk_growth_bytes: native257_fit::NATIVE257_DISK,
            minimum_free_bytes: 1,
            source: Bound::new("/fixture", "a".repeat(64)),
            release: None,
        });
        let booked = candidate_capacity(&h, h.resources, &e, &ctl).unwrap();
        assert_eq!(
            booked["paired_native257"]["additional_producer_memory_bytes"],
            0
        );
        assert_eq!(booked["paired_native257"]["additional_disk_bytes"], 0);
        assert_eq!(
            booked["required_initial_free_bytes"],
            both["required_initial_free_bytes"]
        );
        h.rows[0].release = Some(Bound::new("/unexpected", "a".repeat(64)));
        assert!(candidate_capacity(&h, h.resources, &e, &ctl).is_err());
    }

    #[test]
    #[ignore = "requires Main's current booked controller, fresh full fleet and original host journals"]
    fn genuine_current_retry_release_and_paired_native_funding_without_activation() -> Result<()> {
        let review_path = std::env::var("HORIZON_RETRY_FUNDING_REVIEW")?;
        let review = Bound::new(
            review_path,
            std::env::var("HORIZON_RETRY_FUNDING_REVIEW_SHA")?,
        )
        .sealed()?;
        let controller = text(&review, "controller_unit")?;
        ensure!(
            fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{controller}"),
            "wrong booked host test"
        );
        let dir = PathBuf::from(std::env::var("HORIZON_RETRY_FUNDING_EVIDENCE")?);
        ensure!(
            dir.starts_with("/run")
                && dir.canonicalize()? == dir
                && fs::read_dir(&dir)?.next().is_none(),
            "fresh private test directory"
        );
        let mut n = Native {
            root: dir,
            counter: 0,
            deadline: Some(mono()? + 180_000_000),
        };
        let iid = std::env::var("INVOCATION_ID")?;
        let owner = n.show(controller)?;
        live::finite_owner(&owner, controller, &iid, CONTROLLER_MEMORY)?;
        let ctl = &review["control_units"];
        let envelope = charges(ctl, controller)?;
        let mut h = native257_fit::booked_host_candidate(
            &mut n,
            &review,
            Path::new(FILESYSTEM),
            None,
            None,
        )?;
        let proof = h
            .retry_memory
            .clone()
            .context("missing completed retry release")?;
        let old = h
            .boundary_memory
            .as_ref()
            .context("missing separate original failed release")?;
        ensure!(
            old["released_memory_bytes"] == 125_000_000_000u64
                && proof["released_memory_bytes"] == 125_000_000_000u64
                && old["invocation_id"] != proof["invocation_id"],
            "different invocations required"
        );
        let index = h
            .rows
            .iter()
            .position(|x| x.unit == proof["unit"])
            .context("retry row")?;
        let actual = candidate_capacity(&h, h.resources, &envelope, ctl);
        // Evaluate the obligation delta on one census, irrespective of whether
        // the sampled hardware can fund both candidates right now.
        let comparison = (u64::MAX, u64::MAX, u64::MAX);
        let released = candidate_capacity(&h, comparison, &envelope, ctl)?;
        let binding = h.rows[index].release.take().context("retry not released")?;
        ensure!(
            binding == crate::binding(&proof["bridge"])?,
            "wrong arithmetic row release"
        );
        let nominal = candidate_capacity(&h, comparison, &envelope, ctl)?;
        for k in [
            "memory_obligation_after_bytes",
            "remaining_hard_growth_bytes",
        ] {
            ensure!(
                num(&nominal, k)?.checked_sub(num(&released, k)?) == Some(125_000_000_000),
                "wrong retry cap difference"
            );
        }
        for k in [
            "protected_existing_floor_bytes",
            "retained_disk_growth_bytes",
            "required_initial_free_bytes",
            "allocation_credit_taken_bytes",
        ] {
            ensure!(nominal[k] == released[k], "changed disk accounting");
        }
        live::same_owner(&owner, &n.show(controller)?)?;
        let actual = match actual {
            Ok(v) => json!({"fits":true,"capacity":v}),
            Err(e) => json!({"fits":false,"reason":e.to_string()}),
        };
        save_json(
            &n.root,
            "retry-funding-qualification.json",
            &json!({"old":old,"retry":proof,"current_host_fit":actual,"same_census_before":nominal,"same_census_after":released,"host_resources":h.resources,"no_activation":true,"remote_mutations":false}),
        )?;
        Ok(())
    }
}
