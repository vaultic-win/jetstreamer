//! Replacement for the original 266 pilot after its readonly closure and both singleton terminals.
use super::*;

pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon266-instructions-2789f821-v194-control";
pub(super) const CONTROLLER: &str = "horizon266-instructions-2789f821-v194-control.service";
const D: &str = "/home/ubuntu/.codex/diagnostics";
const ROOT: u64 = 320 << 30;
const STOPPED_UNIT: &str = "horizon-qualify-266-instructions-2789f821-v169.service";
const OLD_IMAGE: &str =
    "/var/lib/jetstreamer/horizon266-instructions-2789f821-v169-control/pilot/private.ext4";
const GUEST: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v169";

pub(super) fn cut() -> Bound {
    Bound::new(
        Path::new(D).join("horizon-replacement-fit-v194-a1/assessment.json"),
        "44841a0d9903da4a23f705b154ed6b252af80696c9d9d1abc533b4d2989a2e77",
    )
}

pub(super) fn dormant(n: &mut Native, unit: &str) -> Result<()> {
    let v = n.show(unit)?;
    ensure!(
        v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"] == ""
            && v["TriggeredBy"] == ""
            && v["Restart"] == "no"
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(unit)
                .try_exists()?,
        "former producer scheduled or active {unit}"
    );
    Ok(())
}

pub(super) fn closed_singletons(n: &mut Native, basis: &Value, fleet: &Value) -> Result<()> {
    let helper = Bound::new(
        "/run/horizon211-drain-recheck-v191-a1-output/sealed/horizon-singleton-delivery-handoff",
        "81fe9dc2536e9a8d9d724fdaf6334c8c6f8d6ed9b330753658479a5ba3d67da4",
    );
    helper.artifact()?;
    for (epoch, (unit, iid, cap)) in [211, 265].into_iter().zip(&funding::OWNERS[..2]) {
        let close = &basis["terminal"][*unit];
        let r = &close["fully_retained_reservation"];
        ensure!(
            r["unit"] == *unit
                && r["invocation_id"] == *iid
                && r["maximum_memory_bytes"] == *cap
                && r["release"].is_null(),
            "changed singleton reservation"
        );
        let saved = &close["recheck"];
        let plan = binding(&saved["plan"])?;
        let drain = binding(&saved["terminal_drain"])?;
        let row = rows(fleet, "epochs")?
            .iter()
            .find(|r| r["epoch"] == epoch)
            .context("missing singleton")?;
        ensure!(
            row["state"] == "staged-admissible"
                && rows(row, "gate_evidence")?.contains(&saved["terminal_drain"])
                && rows(row, "gate_evidence")?.contains(&saved["terminal_handoff"]),
            "singleton has another claim"
        );
        dormant(n, unit)?;
        let result: Value = serde_json::from_slice(&n.run(
            helper.path.to_str().context("helper")?,
            &[
                "check-drain",
                plan.path.to_str().context("plan")?,
                "--plan-sha256",
                &plan.sha256,
                "--self-sha256",
                &helper.sha256,
                "--drain-sha256",
                &drain.sha256,
            ],
        )?)?;
        ensure!(
            result["epoch"] == epoch
                && result["producer_cgroup_drained"] == true
                && result["resource_release_authorized"] == false
                && ["plan", "terminal_drain", "terminal_handoff"]
                    .iter()
                    .all(|k| result[*k] == saved[*k]),
            "original singleton drain changed"
        );
        let hand = binding(&saved["terminal_handoff"])?.json()?;
        let archive = &hand["source"]["archive"];
        let id = &archive["identity"];
        let path = Path::new(text(archive, "path")?);
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path
                && m.is_file()
                && m.nlink() == 1
                && m.dev() == num(id, "device")?
                && m.ino() == num(id, "inode")?
                && m.len() == num(id, "length")?
                && m.ctime() == id["changed_seconds"].as_i64().context("archive clock")?
                && m.ctime_nsec()
                    == id["changed_nanoseconds"]
                        .as_i64()
                        .context("archive clock")?,
            "closed delivery archive changed"
        );
    }
    Ok(())
}

pub(super) fn frozen_root(n: &mut Native) -> Result<()> {
    dormant(n, STOPPED_UNIT)?;
    let receipt = Bound::new(
        "/var/lib/jetstreamer/horizon266-stopped-scratch-v173-state/closed",
        "c40ab9925137fa1a5862561004d43e08449bc490dad11416ec3a3e73152eacb2",
    );
    ensure!(
        hash(&receipt.path)? == receipt.sha256,
        "different 266 readonly closure"
    );
    let file = fs::symlink_metadata(OLD_IMAGE)?;
    ensure!(
        file.is_file()
            && file.dev() == 66305
            && file.ino() == 18335082
            && file.len() == 128 << 30
            && file.nlink() == 1
            && file.uid() == 0
            && file.blocks() == 3_458_768
            && (file.ctime(), file.ctime_nsec()) == (1795314248, 859594468),
        "old backing file changed"
    );
    let loop_state = n.run(
        "/usr/sbin/losetup",
        &["-n", "-O", "NAME,RO,BACK-INO,BACK-FILE", "/dev/loop9"],
    )?;
    ensure!(
        std::str::from_utf8(&loop_state)?.split_whitespace().eq([
            "/dev/loop9",
            "1",
            "18335082",
            OLD_IMAGE
        ]),
        "old loop is writable or rebound"
    );
    let table = fs::read_to_string("/proc/self/mountinfo")?;
    let mut found = false;
    for line in table.lines() {
        let (a, b) = line.split_once(" - ").context("mountinfo")?;
        let fields: Vec<_> = a.split_whitespace().collect();
        let fs: Vec<_> = b.split_whitespace().collect();
        if fields.get(2) == Some(&"7:9") {
            ensure!(
                fs.get(..2) == Some(&["ext4", "/dev/loop9"][..])
                    && fs.get(2).is_some_and(|s| s.split(',').any(|o| o == "ro"))
                    && fields
                        .get(5)
                        .is_some_and(|s| s.split(',').any(|o| o == "ro")),
                "writable old mount"
            );
            found |= fields.first() == Some(&"1555") && fields.get(4) == Some(&GUEST);
        }
    }
    ensure!(found, "old guest lost its original readonly mount");
    Ok(())
}

// Keep the historic 247 floor, the entire original 228 guest, and the previous
// pilot's original required-free watermark. No physical extent is credited.
// The cold 211 producer no longer changes scratch. Its entire old admission
// floor stays here. The closed 266 guest cannot consume its former growth
// allowance while the loop and superblock remain read-only.
fn protected(held: &Value, ledger: &Value, book: &Value) -> Result<u64> {
    let original = &held["concurrent_266"];
    let peer = &held["live_228"];
    let transfer = &held["epoch228_scratch_assignment"];
    let old = num(book, "required_free")?
        .max(num(original, "original_floor")?)
        .checked_add(num(original, "additional_disk_above_shared_qa")?)
        .context("joined floor")?;
    let reservations = rows(ledger, "reservations")?;
    let (uploader, previous) = reservations
        .split_last()
        .context("missing current ledger")?;
    ensure!(
        uploader["unit"] == funding::OWNERS[2].0 && previous.len() == 21,
        "unexpected newest reservation"
    );
    let prior_floor = previous
        .iter()
        .map(|r| num(r, "minimum_free_bytes"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .context("missing prior floors")?;
    let before = old
        .checked_sub(num(transfer, "assigned_scratch_bytes")?)
        .context("original 228 transfer")?
        .max(num(transfer, "source_floor")?)
        .max(prior_floor);
    let base = (before + RECEIPTS).max(num(peer, "original_floor")?);
    let both = (base + num(peer, "root")?).max(num(peer, "original_required_free")?) + (768 << 20);
    let absolute = rows(ledger, "reservations")?
        .iter()
        .map(|r| num(r, "minimum_free_bytes"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .context("empty ledger")?;
    Ok(both
        .max(absolute)
        .max(num(held, "protected_floor")?)
        .max(num(&held["winner"], "required_free")?))
}

fn price(total: u64, available: u64, free: u64, current: u64, floor: u64) -> Result<Value> {
    // All nominal reservations, including the cold 265 ceiling and the unused
    // balance of 211, stay booked. Only this successor can spend the 211 share.
    let hard = 1_212_131_577_856u64;
    let assigned = successor::MEMORY + GUARD_MEM + CONTROL_MEM;
    let residual = 225_000_000_000u64
        .checked_sub(assigned)
        .context("211 allocation")?;
    let growth = hard
        .checked_sub(current)
        .and_then(|g| g.checked_sub(128_000_000_000 + residual))
        .context("memory growth")?;
    let need = floor
        .checked_add(RECEIPTS + ROOT)
        .context("new guest floor overflow")?;
    Ok(
        json!({"memory":successor::MEMORY,"root":ROOT,"hard":hard,"growth":growth,"required_free":need,
        "fits":total>=hard && available>=growth && free>=need,"assigned_211":assigned,"retained_211":residual,"retained_265":128_000_000_000u64}),
    )
}

pub(super) fn elect(
    n: &mut Native,
    r: &Value,
    held: Option<(&Profile, &Value, (u64, u64))>,
) -> Result<Value> {
    original_boot()?;
    successor::writer(r)?;
    ensure!(
        r["capacity_basis"] == json!(cut()),
        "unreviewed turnover basis"
    );
    let c = cut().json()?;
    let f = binding(&r["fleet"])?;
    let fleet = funding::anchor(&f)?;
    let live = rows(&fleet, "active")?;
    ensure!(
        live.len() == 1
            && live[0]["epoch"] == 247
            && rows(&fleet, "epochs")?
                .iter()
                .any(|v| v["epoch"] == 266 && v["state"] == "failed-needs-repair"),
        "changed fleet or another 266 claim"
    );
    let registry = binding(&c["original_ledger"])?;
    let ledger = registry.sealed()?;
    let prior = Bound::new(
        "/var/lib/jetstreamer/horizon266-instructions-2789f821-v169-control/pilot/held-fit.json",
        "1191b79e53afdd1eb96e1b26002aaffa3ce869930bd152c96d1e5e45e4263d7e",
    )
    .sealed()?;
    let book = binding(&prior["uploader_booking"])?.json()?;
    ensure!(
        rows(&ledger, "reservations")?.len() == 22
            && registry.sha256
                == "7beddd086fb5c8a5d602ab0cb51b1dd3dad2db87e2c0ef96c7e6c933e152e26d"
            && num(&book, "hard_memory_obligation")? + (664 << 20) == 1_212_131_577_856,
        "original booking totals"
    );
    let floor = protected(&prior, &ledger, &book)?;
    let (u, iid, cap) = funding::OWNERS[2];
    let mut allowed = BTreeSet::from([
        u.to_owned(),
        CONTROLLER.to_owned(),
        "horizon-native266-protective-v1.service".into(),
        "horizon-266-general-protective-v1.service".into(),
        "horizon-228-root-tail-protective-v1.service".into(),
        "horizon-266-instructions-2789f821-v169-protective.service".into(),
    ]);
    for ctrl in rows(&ledger["periodic_controls"], "controls")? {
        allowed.insert(text(ctrl, "unit")?.to_owned());
    }
    if let Some((p, m, pair)) = held {
        ensure!(
            pair == (successor::MEMORY, ROOT)
                && n.show(&p.unit)?["InvocationID"] == m["InvocationID"],
            "different held candidate"
        );
        allowed.extend([p.unit.clone(), p.guard.clone()]);
    }
    let check = |n: &mut Native| -> Result<u64> {
        ensure!(
            funding::manager_units(n)?.is_subset(&allowed),
            "additional active resource owner"
        );
        frozen_root(n)?;
        closed_singletons(n, &c, &fleet)?;
        dormant(
            n,
            "horizon-qualify-228-demotion-root-tail-16d4b158-v1.service",
        )?;
        let v = n.show(u)?;
        let original = &c["owners"][u];
        ensure!(
            [
                "InvocationID",
                "MainPID",
                "ControlGroup",
                "MemoryMax",
                "MemorySwapMax",
                "NRestarts"
            ]
            .iter()
            .all(|k| v[*k] == original[*k])
                && live[0]["expected_invocation_id"] == iid,
            "different uploader invocation"
        );
        let pid = text(&v, "MainPID")?;
        let proc = Path::new("/proc").join(pid);
        let argv = rows(&book, "argv")?
            .iter()
            .map(|v| v.as_str().context("uploader argv"))
            .collect::<Result<Vec<_>>>()?;
        let command = fs::read(proc.join("cmdline"))?;
        ensure!(
            command.ends_with(&[0])
                && command[..command.len() - 1]
                    .split(|&b| b == 0)
                    .eq(argv.iter().map(|s| s.as_bytes()))
                && fs::read_link(proc.join("exe"))? == Path::new(argv[0]),
            "uploader command changed"
        );
        let status = fs::read_to_string(proc.join("status"))?;
        let mask = status
            .lines()
            .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
            .context("uploader affinity")?;
        ensure!(
            funding::cpus(mask)?.is_disjoint(&funding::cpus("32-39")?)
                && funding::cpus("32-39")?.is_subset(&funding::cpus(&fs::read_to_string(
                    "/sys/devices/system/cpu/online"
                )?)?),
            "unavailable successor CPUs"
        );
        live::finite_owner(&v, u, iid, cap)
    };
    let first = check(n)?;
    let (total, avail, free) = live::resources_at(Path::new(V))?;
    let second = check(n)?;
    let (t, a, b) = live::resources_at(Path::new(V))?;
    ensure!(total == t, "host memory changed");
    let row = price(total, avail.min(a), free.min(b), first.min(second), floor)?;
    let winner = if row["fits"] == true {
        row.clone()
    } else {
        Value::Null
    };
    Ok(
        json!({"schema":"horizon266-closed-singleton-capacity-election-v1","fleet":f,"capacity_basis":cut(),"registry":registry,"options":[row],"winner":winner,
        "protected_floor":floor+RECEIPTS,"cpus":(32..40).collect::<Vec<u32>>(),"free":free.min(b),"frozen_266":OLD_IMAGE,"publication_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exclusive_turnover_prices_every_threshold() {
        let floor = 4_249_583_269_888u64;
        let row = price(u64::MAX, u64::MAX, u64::MAX, 1, floor).unwrap();
        let hard = num(&row, "hard").unwrap();
        let growth = num(&row, "growth").unwrap();
        let need = num(&row, "required_free").unwrap();
        assert_eq!(need, floor + RECEIPTS + ROOT);
        for (t, a, b, expected) in [
            (hard, growth, need, true),
            (hard - 1, growth, need, false),
            (hard, growth - 1, need, false),
            (hard, growth, need - 1, false),
        ] {
            assert_eq!(price(t, a, b, 1, floor).unwrap()["fits"], expected);
        }
        assert_eq!(
            num(&row, "assigned_211").unwrap() + num(&row, "retained_211").unwrap(),
            225_000_000_000
        );
        assert!(price(hard, growth, need, u64::MAX, floor).is_err());
    }
}

/// Bound the disk still needed by the original guarded 320 GiB producer while a
/// second lane is being priced. The caller must still check the rest of the fleet.
pub(super) fn allocation(n: &mut Native) -> Result<Value> {
    original_boot()?;
    let p = Profile::new(Lane::Turnover266, "pilot")?;
    let hand = Bound::new(
        p.state.join("handoff.json"),
        "fcab517e7281c8c1dde68c9e7f56cbabc294eff2154c181bdb72b1742170a4df",
    );
    let h = hand.sealed()?;
    let iid = text(&h, "iid")?;
    let pid = num(&h, "pid")?;
    let guard = binding(&h["guard"])?;
    let plan = guard.sealed()?;
    let spec = binding(&h["spec"])?.sealed()?;
    let fit = binding(&h["held_fit"])?.sealed()?;
    ensure!(
        h["unit"] == p.unit
            && plan["unit"] == p.unit
            && plan["invocation_id"] == iid
            && spec["root"] == json!(p.root)
            && plan["minimum_free_bytes"] == fit["protected_floor"],
        "changed live 266 handoff"
    );
    let check = |n: &mut Native| -> Result<Value> {
        let u = n.show(&p.unit)?;
        live::finite_owner(&u, &p.unit, iid, successor::MEMORY)?;
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let args = rows(&spec, "argv")?
            .iter()
            .map(|s| s.as_str().context("node argument"))
            .collect::<Result<Vec<_>>>()?;
        let cmd = fs::read(proc.join("cmdline"))?;
        ensure!(
            text(&u, "MainPID")?.parse::<u64>()? == pid
                && fs::read_link(proc.join("exe"))?
                    == Path::new(args.first().context("node command")?)
                && cmd.strip_suffix(&[0]).is_some_and(|raw| raw
                    .split(|&b| b == 0)
                    .eq(args.iter().map(|s| s.as_bytes()))),
            "266 node changed"
        );
        let timer = n.show(&p.timer)?;
        ensure!(
            timer["InvocationID"] == h["timer"]
                && timer["ActiveState"] == "active"
                && timer["Unit"] == p.guard
                && timer["Job"] == "",
            "266 guard timer changed"
        );
        let dir = Path::new(text(&plan, "receipt_directory")?);
        for marker in [
            "stop-intent.json",
            "pressure-stop.json",
            "manager-stop-completion.json",
        ] {
            ensure!(!dir.join(marker).try_exists()?, "266 stop in progress");
        }
        // A new guard may already be running. Use the last successful PID 1
        // completion and the sample written by that exact invocation.
        let boot = BOOT.replace('-', "");
        let unit = format!("UNIT={}", p.guard);
        let journal = n.run(
            "/usr/bin/journalctl",
            &[
                "--boot",
                &boot,
                "--quiet",
                "--no-pager",
                "-o",
                "json",
                "-n",
                "1",
                "_UID=0",
                "_PID=1",
                &unit,
                "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
            ],
        )?;
        let event: Value = serde_json::from_slice(&journal)?;
        let gid = text(&event, "INVOCATION_ID")?;
        ensure!(
            hex(gid, 32)
                && event["_BOOT_ID"] == boot
                && event["UNIT"] == p.guard
                && event.get("UNIT_RESULT").is_none_or(|x| x == "success"),
            "266 guard completion"
        );
        let sample = bound_at(&dir.join(format!("sample-{gid}.json")))?;
        let v = sample.json()?;
        start::validate_sample_for(GUARD_SHA, &v, &p.unit, iid, pid, &guard, None)?;
        ensure!(
            v["guard_invocation_id"] == gid
                && v["minimum_free_bytes"] == plan["minimum_free_bytes"],
            "266 guard sample changed"
        );
        fresh(num(&v, "recorded_unix_seconds")?, now()?, 120)?;
        Ok(json!({"sample":sample,"producer":u,"timer_iid":timer["InvocationID"]}))
    };
    let before = check(n)?;
    let extents = peer228_extents::Extents::turnover266()?;
    let after = check(n)?;
    let backing = extents.finish()?;
    let end = check(n)?;
    live::same_owner(&before["producer"], &after["producer"])?;
    live::same_owner(&after["producer"], &end["producer"])?;
    let floor = num(&fit, "protected_floor")?
        .checked_add(num(&backing, "remaining_image_growth")?)
        .context("266 remaining floor overflow")?;
    Ok(
        json!({"schema":"horizon266-live-guest-allocation-v1","handoff":hand,"held":h["held_fit"],
        "first":before,"middle":after,"last":end,"backing":backing,"protected_free_with_remaining_growth":floor,
        "capacity_released":false,"admission_authorized":false}),
    )
}
