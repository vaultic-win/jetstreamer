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
                "incorrect {EPOCH} controller booking"
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
        "existing control envelope does not cover {EPOCH} and booked controls"
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

// Epoch 212 preserves both pending peers on every admission. The 261 paired
// booking applies when using the completed retry release.
// A producer already in the ledger contributes its memory and disk there.
fn candidate_capacity(
    host: &native257_fit::BookedHost,
    resources: (u64, u64, u64),
    envelope: &Value,
    controls: &Value,
) -> Result<Value> {
    let mut peer_memory = 0;
    let mut peer_disk = 0;
    let mut total_controls = num(envelope, "total_control_charged_bytes")?;
    let mut paired = Vec::new();
    if EPOCH == 212 || host.retry_memory.is_some() {
        let peers = [
            (
                257,
                native257::UNIT,
                native257::GUARD_UNIT,
                native257_fit::NATIVE257_MEMORY,
                native257_fit::NATIVE257_DISK,
                512 << 20,
            ),
            (
                261,
                crate::native261::UNIT,
                crate::native261::GUARD_UNIT,
                crate::native261::MEMORY,
                crate::native261::DISK_RECEIPTS,
                crate::native261::CONTROLLER_MEMORY,
            ),
        ];
        let control_rows = controls.as_array().context("booked controls")?;
        for (epoch, unit, guard, memory, disk, controller) in peers {
            if unit == UNIT {
                continue;
            }
            let original_excess = total_controls.saturating_sub(CONTROL);
            let existing = host.rows.iter().find(|r| r.unit == unit);
            if let Some(r) = existing {
                ensure!(
                    r.release.is_none()
                        && r.maximum_memory_bytes == memory
                        && r.remaining_disk_growth_bytes >= disk,
                    "native {epoch} reservation cannot cover its paired producer"
                );
            } else {
                ensure!(
                    !host.currents.contains_key(unit),
                    "live {epoch} lacks its booking"
                );
                peer_memory = capacity::add(peer_memory, memory)?;
                peer_disk = capacity::add(peer_disk, disk)?;
                total_controls = capacity::add(total_controls, controller)?;
            }
            if let Some(row) = control_rows.iter().find(|r| r["unit"] == guard) {
                ensure!(
                    num(row, "maximum_memory_bytes")? == GUARD_MEMORY,
                    "paired guard cap differs"
                );
            } else {
                total_controls = capacity::add(total_controls, GUARD_MEMORY)?;
            }
            paired.push((
                epoch,
                json!({"unit":unit,"already_in_ledger":existing.is_some(),
                "additional_producer_memory_bytes":if existing.is_some(){0}else{memory},
                "additional_control_envelope_bytes":total_controls.saturating_sub(CONTROL) - original_excess,
                "additional_disk_bytes":if existing.is_some(){0}else{disk}}),
            ));
        }
    }
    let control_excess = total_controls.saturating_sub(CONTROL);
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
    if !paired.is_empty() {
        // The producer must preserve its neighbours’ original disk floor before token issuance.
        cap["protected_existing_floor_bytes"] = json!(capacity::add(
            num(&cap, "protected_existing_floor_bytes")?,
            peer_disk
        )?);
        for (epoch, detail) in paired {
            cap[format!("paired_native{epoch}")] = detail;
        }
    }
    Ok(cap)
}

pub(super) fn current(n: &mut Native, r: &Value, held: bool) -> Result<Value> {
    let controller = text(r, "controller_unit")?;
    let iid = std::env::var("INVOCATION_ID")?;
    let own = || -> Result<()> {
        ensure!(
            fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{controller}"),
            "{EPOCH} admission outside booked controller"
        );
        Ok(())
    };
    own()?;
    let owner = n.show(controller)?;
    ensure!(
        text(&owner, "MainPID")?.parse::<u32>()? == std::process::id() && owner["Type"] == "exec",
        "{EPOCH} controller is not main process"
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
        "{EPOCH} receipt ledger is not on the admitted ext4 filesystem"
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
    if let Some(request) = r.get("turnover_funding") {
        let source = native266_full::peer261::trace();
        ensure!(
            EPOCH == 261 && *request == json!(source),
            "unregistered 261 source"
        );
        let f = binding(&r["fleet"])?;
        let t = source.json()?;
        let fleet = f.json()?;
        ensure!(
            r["reservation_ledger"] == t["original_ledger"]
                && r["observer"]
                    == json!(Bound::new(
                        text(&fleet, "observer_receipt")?,
                        text(&fleet, "observer_sha256")?
                    ))
                && units::affinity(r)? == "48 49 50 51 52 53 54 55"
                && r["control_units"]
                    == json!([{"unit":controller,"maximum_memory_bytes":CONTROLLER_MEMORY}]),
            "turnover ledger, observer, controls or CPUs differ"
        );
        let device = disk_fd.metadata()?.dev();
        let mount = pristine(device)?;
        let mut result = native266_full::peer261::assess(n, &f, controller, held)?;
        ensure!(
            r["reviewed_cpu_overlap"] == result["reviewed_cpu_overlap"]
                && fs::metadata(path)?.dev() == device
                && pristine(device)? == mount,
            "CPU sharing or scratch changed"
        );
        let after = n.show(controller)?;
        live::same_owner(&owner, &after)?;
        live::finite_owner(&after, controller, &iid, CONTROLLER_MEMORY)?;
        own()?;
        result["controller"] = after;
        result["disk_filesystem"] = json!(FILESYSTEM);
        result["disk_device"] = json!(device);
        result["tmpfs"] = mount;
        result["boot_id"] = json!(fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim());
        n.check()?;
        return Ok(result);
    }
    let envelope = charges(&r["control_units"], controller)?;
    let mut host = native257_fit::booked_host_candidate(
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
        "{EPOCH} owner or control already booked as producer"
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
    let native265_memory = if EPOCH == 212 {
        crate::native212::retired265::apply(n, r, &mut host)?
    } else {
        None
    };
    let capacity = candidate_capacity(&host, resources, &envelope, &r["control_units"])?;
    ensure!(
        pristine(host.device)? == mount,
        "{EPOCH} tmpfs changed across host accounting"
    );
    let after = n.show(controller)?;
    live::same_owner(&owner, &after)?;
    live::finite_owner(&after, controller, &iid, CONTROLLER_MEMORY)?;
    own()?;
    n.check()?;
    let mut result = json!({"capacity":capacity,"control_charges":envelope,"boot_id":host.boot,
        "disk_filesystem":FILESYSTEM,"disk_device":host.device,"tmpfs":mount,"cpu":cpu,"controller":after,
        "actual_current_memory":host.currents,"native265_runtime_growth_release":host.release,
        "native211_cold_growth_release":host.native211_growth,"full211_growth":host.full211_growth,"failed_boundary205206_memory_release":host.boundary_memory,"completed_boundary205206_retry_memory_release":host.retry_memory});
    if let Some(release) = native265_memory {
        result["completed_native265_diagnostic_memory_release"] = release;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn charges_candidate_once_and_preserves_other_controls() {
        let ctl = "horizon-test-controller.service";
        let row = |u: &str, b: u64| json!({"unit":u,"maximum_memory_bytes":b});
        let rows = json!([
            row(ctl, CONTROLLER_MEMORY),
            row("other.service", CONTROL - GUARD_MEMORY - CONTROLLER_MEMORY)
        ]);
        let result = charges(&rows, ctl).unwrap();
        assert_eq!(result["total_control_charged_bytes"], CONTROL);
        assert_eq!(result["candidate_total_memory_bytes"], MEMORY + (512 << 20));
        assert_eq!(result["disk_receipt_growth_bytes"], 268_435_456u64);
        assert_eq!(result["additional_producer_memory_bytes"], MEMORY);
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
    fn retry_funding_keeps_each_paired_producer_and_disk_floor() {
        let mut h = host();
        let e = json!({"total_control_charged_bytes":CONTROL});
        let ctl = json!([]);
        let both = candidate_capacity(&h, h.resources, &e, &ctl).unwrap();
        let (extra_memory, extra_disk) = if matches!(EPOCH, 212 | 262 | 266) {
            (
                crate::native261::MEMORY + crate::native261::CONTROLLER_MEMORY + GUARD_MEMORY,
                crate::native261::DISK_RECEIPTS,
            )
        } else {
            (0, 0)
        };
        h.retry_memory = None;
        let without_retry = candidate_capacity(&h, h.resources, &e, &ctl).unwrap();
        let original = capacity::candidate_arithmetic(
            h.resources,
            h.century,
            &h.rows,
            &h.currents,
            h.overhead,
            (MEMORY, DISK_RECEIPTS),
        )
        .unwrap();
        if EPOCH == 212 {
            assert_eq!(without_retry, both);
        } else {
            assert_eq!(without_retry, original);
        }
        assert_eq!(
            num(&both, "memory_obligation_after_bytes").unwrap()
                - num(&original, "memory_obligation_after_bytes").unwrap(),
            native257_fit::NATIVE257_MEMORY + 3 * GUARD_MEMORY + extra_memory
        );
        for k in [
            "required_initial_free_bytes",
            "protected_existing_floor_bytes",
        ] {
            assert_eq!(
                num(&both, k).unwrap() - num(&original, k).unwrap(),
                native257_fit::NATIVE257_DISK + extra_disk
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
    fn native212_preserves_a_booked_peer_without_retry_credit() {
        if EPOCH != 212 {
            return;
        }
        let mut h = host();
        h.retry_memory = None;
        let e = json!({"total_control_charged_bytes":CONTROL});
        let ctl =
            json!([{"unit":crate::native261::GUARD_UNIT,"maximum_memory_bytes":GUARD_MEMORY}]);
        let unit = crate::native261::UNIT;
        h.currents.insert(unit.to_owned(), 1);
        assert!(candidate_capacity(&h, h.resources, &e, &ctl).is_err());
        h.rows.push(capacity::Reservation {
            unit: unit.into(),
            invocation_id: "a".repeat(32),
            maximum_memory_bytes: crate::native261::MEMORY,
            remaining_disk_growth_bytes: crate::native261::DISK_RECEIPTS,
            minimum_free_bytes: 1,
            source: Bound::new("/fixture", "a".repeat(64)),
            release: None,
        });
        let fit = candidate_capacity(&h, h.resources, &e, &ctl).unwrap();
        let booked = &fit["paired_native261"];
        assert_eq!(booked["already_in_ledger"], true);
        for field in [
            "additional_producer_memory_bytes",
            "additional_control_envelope_bytes",
            "additional_disk_bytes",
        ] {
            assert_eq!(booked[field], 0);
        }
        assert_eq!(
            fit["paired_native257"]["additional_disk_bytes"],
            native257_fit::NATIVE257_DISK
        );
        h.rows.push(h.rows[0].clone());
        assert!(candidate_capacity(&h, h.resources, &e, &ctl).is_err());
        h.rows.pop();
        h.rows[0].remaining_disk_growth_bytes -= 1;
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
