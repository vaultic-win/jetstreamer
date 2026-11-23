//! Price the prepared epoch 261 input against the active 247 and 266 owners.
use super::*;
const D: &str = "/home/ubuntu/.codex/diagnostics";
const DONOR266: u64 = 176_000_000_000;
const DONOR228: u64 = 120_000_000_000;
const CONTROLS: u64 = 512 << 20;
const HARD: u64 = 1_212_131_577_856;
const FIRST: &str = "horizon-fleet-takeover-v195-entry266-a2";
const FIRST_SHA: &str = "10b0f721e5a25c73190be1f5cb8e583dd4f673c5b8ea708cc80e95d961329b39";

pub(crate) fn trace() -> Bound {
    Bound::new(
        Path::new(D).join("horizon261-historical-source-trace-v195-a1/trace.json"),
        "7cf1721b4c52ebb3d4028ffaea8ca5fa9705b482208804434dfb0d72146d7d35",
    )
}

// Select the unique descendant of the original two-owner snapshot, including
// metadata-only transitions. Reject an unjoined fork and an older review.
pub(crate) fn latest(f: &Bound) -> Result<Value> {
    let root = Bound::new(Path::new(D).join(FIRST).join("fleet-v1.json"), FIRST_SHA);
    let since = fs::metadata(&root.path)?.modified()?;
    let mut all = BTreeMap::new();
    let mut parents = BTreeSet::new();
    for entry in fs::read_dir(D)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // The 257 owner and terminal events sit between routine samples 218
        // and 219. They participate in the same hash-linked fleet history.
        if !name.starts_with("horizon-fleet-takeover-v")
            && !matches!(
                name.as_ref(),
                "horizon257-v16-owner-fleet-a1" | "horizon257-v16-terminal-fleet-a1"
            )
        {
            continue;
        }
        let path = entry.path().join("fleet-v1.json");
        if !path.try_exists()? || fs::metadata(&path)?.modified()? < since {
            continue;
        }
        let reference = bound_at(&path)?;
        let doc = reference.json()?;
        let parent = binding(&doc["previous_fleet"])?;
        parents.insert(parent.sha256.clone());
        ensure!(
            all.insert(reference.sha256.clone(), (reference, parent))
                .is_none(),
            "duplicate fleet"
        );
    }
    let leaves = all
        .values()
        .filter(|(r, _)| !parents.contains(&r.sha256))
        .collect::<Vec<_>>();
    ensure!(
        leaves.len() == 1 && leaves[0].0 == *f,
        "concurrent or stale fleet review"
    );
    let mut cursor = f;
    for _ in 0..=all.len() {
        if *cursor == root {
            return funding::anchor(f);
        }
        let (this, parent) = all.get(&cursor.sha256).context("missing fleet ancestor")?;
        ensure!(this == cursor, "fleet path changed");
        cursor = parent;
    }
    bail!("cyclic fleet")
}

pub(super) fn donor(n: &mut Native, row: &Value, cap: u64) -> Result<Value> {
    let unit = text(row, "unit")?;
    let iid = text(row, "iid")?;
    let hand = binding(&row["handoff"])?.sealed()?;
    let held = binding(&row["held"])?.sealed()?;
    let stop = binding(&row["terminal"])?.json()?;
    ensure!(
        hand["unit"] == unit
            && hand["iid"] == iid
            && hand["held_fit"] == row["held"]
            && stop["handoff"] == row["handoff"]
            && stop["producer_drained"] == true
            && stop["resource_release_authorized"] == false
            && stop["partial_archive"] == row["partial"]
            && held["winner"]["memory"] == cap
            && row["memory_retained"] == cap,
        "closed donor differs"
    );
    for k in ["original_guard", "stop"] {
        binding(&stop[k])?.json()?;
    }
    let events = rows(&stop, "pid1")?;
    let observed = n.run(
        "/usr/bin/journalctl",
        &[
            "--boot",
            &BOOT.replace('-', ""),
            "--quiet",
            "--no-pager",
            "-o",
            "json",
            "_UID=0",
            "_PID=1",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={iid}"),
        ],
    )?;
    let actual = serde_json::Deserializer::from_slice(&observed)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !events.is_empty()
            && actual.len() == events.len()
            && actual
                .iter()
                .zip(events)
                .all(|(a, b)| a["__CURSOR"] == b["__CURSOR"]
                    && a["MESSAGE_ID"] == b["MESSAGE_ID"]
                    && a["UNIT"] == unit
                    && a["INVOCATION_ID"] == iid)
            && actual
                .iter()
                .any(|e| e["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"),
        "original PID 1 closure differs"
    );
    turnover::dormant(n, unit)?;
    let part = &row["partial"];
    let path = Path::new(text(part, "path")?);
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.ino() == num(part, "inode")?
            && m.dev() == num(part, "device")?
            && m.len() == num(part, "size")?,
        "closed donor scratch changed"
    );
    Ok(held)
}

pub(super) fn sources(n: &mut Native, fleet: &Value) -> Result<(Value, Value)> {
    let t = trace().json()?;
    let basis = turnover::cut().json()?;
    turnover::closed_singletons(n, &basis, fleet)?;
    turnover::frozen_root(n)?;
    let old = donor(n, &t["stopped"]["266"], DONOR266)?;
    donor(n, &t["stopped"]["228"], DONOR228)?;
    let ledger = binding(&t["original_ledger"])?.sealed()?;
    let finite = binding(&t["finite_serial"])?.sealed()?;
    let b = &finite["source_basis"];
    let split = &old["new_266_assignment"];
    let controls = [
        "old_controller_retained",
        "old_guard_retained",
        "new_controller_bytes",
        "new_guard_bytes",
    ]
    .iter()
    .try_fold(0, |v, k| capacity::add(v, num(split, k)?))?;
    let release = binding(&b["original_266_discharge"])?.sealed()?;
    let retained = binding(&t["finite_retained"])?.json()?;
    ensure!(
        b["stopped266"] == t["stopped"]["266"]
            && b["held_266"] == t["stopped"]["266"]["held"]
            && b["e434_ledger"] == t["original_ledger"]
            && basis["original_ledger"] == t["original_ledger"]
            && split["producer_bytes"] == DONOR266
            && num(b, "already_held_bytes")? == DONOR266 + controls
            && capacity::add(
                num(b, "already_held_bytes")?,
                num(b, "finite_only_candidate_bytes")?
            )? == num(&release, "producer_future_growth_released_bytes")?
            && capacity::add(
                num(&finite, "requested_memory")?,
                num(b, "remaining_after_carve")?
            )? == num(b, "finite_only_candidate_bytes")?
            && retained["source"] == t["finite_serial"]
            && retained["source_remainder_bytes"] == b["remaining_after_carve"],
        "266 donor overlaps finite carve"
    );
    let assignment = &old["epoch251_assignment"];
    let matches = rows(&ledger, "reservations")?
        .iter()
        .filter(|r| r["unit"] == assignment["unit"])
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1
            && rows(&ledger, "reservations")?.len() == 22
            && old["live_228"]["retained_251"] == *assignment
            && old["live_228"]["held_fit"] == t["stopped"]["228"]["held"]
            && assignment["assigned_memory_bytes"] == DONOR228 + (1 << 30) + (256 << 20)
            && capacity::add(
                num(assignment, "assigned_memory_bytes")?,
                num(assignment, "retained_memory_bytes")?
            )? == num(matches[0], "maximum_memory_bytes")?,
        "228 donor overlaps retained epoch 251 capacity"
    );
    let award = binding(&t["current_266_held"])?.sealed()?;
    ensure!(
        t["current_266"] == json!(turnover_window::handoff())
            && turnover_window::handoff().sealed()?["held_fit"] == t["current_266_held"]
            && award["registry"] == t["original_ledger"]
            && award["winner"]["assigned_211"] == 177_342_177_280u64
            && award["winner"]["retained_211"] == 47_657_822_720u64
            && award["winner"]["retained_265"] == 128_000_000_000u64
            && award["winner"]["hard"] == HARD,
        "different current 266 source"
    );
    let book = binding(&old["uploader_booking"])?.json()?;
    ensure!(
        num(&book, "hard_memory_obligation")?.checked_add(664 << 20) == Some(HARD),
        "original host hard obligation changed"
    );
    Ok((ledger, book))
}

fn price(resources: (u64, u64, u64), current: u64, floor: u64) -> Result<Value> {
    let (total, available, free) = resources;
    let growth = HARD
        .checked_sub(47_657_822_720 + 128_000_000_000)
        .and_then(|v| v.checked_sub(current))
        .context("live memory exceeds ledger")?;
    let needed = capacity::add(floor, native261::DISK_RECEIPTS)?;
    ensure!(
        total >= HARD && available >= growth && free >= needed,
        "host cannot fund epoch 261"
    );
    let assignment = native261::MEMORY + CONTROLS;
    let use228 = assignment
        .checked_sub(DONOR266)
        .context("261 donor allocation")?;
    let residual = DONOR228.checked_sub(use228).context("228 donor exceeded")?;
    Ok(
        json!({"observed_available_bytes":free,"protected_existing_floor_bytes":floor,"required_initial_free_bytes":needed,
        "memory_obligation_after_bytes":HARD,"remaining_hard_growth_bytes":growth,"observed_memory_available_bytes":available,
        "from_closed_266":DONOR266,"from_closed_228":use228,"retained_228":residual,
        "producer_maximum_bytes":native261::MEMORY,"controller_and_guard_bytes":CONTROLS,"additional_hard_charge":0}),
    )
}

pub(crate) fn assess(n: &mut Native, f: &Bound, controller: &str, held: bool) -> Result<Value> {
    original_boot()?;
    let fleet = latest(f)?;
    let (ledger, book) = sources(n, &fleet)?;
    let active = rows(&fleet, "active")?;
    let (u, iid, cap) = funding::OWNERS[2];
    let p = Profile::new(Lane::Turnover266, "pilot")?;
    let h = turnover_window::handoff().sealed()?;
    let delivery = active
        .iter()
        .find(|r| r["epoch"] == 247 && r["phase"] == "upload-readback")
        .context("247 not in readback")?;
    let replay = active
        .iter()
        .find(|r| r["epoch"] == 266 && r["phase"] == "diagnostic-qualification")
        .context("266 not in replay")?;
    ensure!(
        active.len() == 2
            && replay["launch_receipt_sha256"]
                == "a49e83a093c947e44f722d73df9190847b8d5995eb7302f3ec01f2c7f46d59b8",
        "unrecognized replay registration"
    );
    let registered = Bound::new(
        p.state
            .parent()
            .context("266 control")?
            .join("first-entries-1/registration.json"),
        text(replay, "launch_receipt_sha256")?,
    );
    ensure!(
        registered.path == Path::new(text(replay, "launch_receipt")?)
            && registered.sealed()?["handoff"] == json!(turnover_window::handoff()),
        "266 scheduler registration changed"
    );
    let mut allowed = BTreeSet::from([
        u.to_owned(),
        p.unit.clone(),
        p.guard.clone(),
        controller.to_owned(),
        "horizon-native266-protective-v1.service".into(),
        "horizon-266-general-protective-v1.service".into(),
        "horizon-228-root-tail-protective-v1.service".into(),
        "horizon-266-instructions-2789f821-v169-protective.service".into(),
    ]);
    for row in rows(&ledger["periodic_controls"], "controls")? {
        allowed.insert(text(row, "unit")?.into());
    }
    if held {
        allowed.extend([native261::UNIT.into(), native261::GUARD_UNIT.into()]);
    }
    let check = |n: &mut Native| -> Result<(Value, Value, u64)> {
        ensure!(
            funding::manager_units(n)?.is_subset(&allowed),
            "additional live resource claimant"
        );
        let upload = n.show(u)?;
        let producer = n.show(&p.unit)?;
        live::same_owner(&delivery["unit"], &upload)?;
        live::same_owner(&replay["producer"], &producer)?;
        let up = live::finite_owner(&upload, u, iid, cap)?;
        let node = live::finite_owner(&producer, &p.unit, text(&h, "iid")?, successor::MEMORY)?;
        let pid = text(&upload, "MainPID")?;
        let args = rows(&book, "argv")?
            .iter()
            .map(|a| a.as_str().context("uploader argument"))
            .collect::<Result<Vec<_>>>()?;
        let cmd = fs::read(format!("/proc/{pid}/cmdline"))?;
        ensure!(
            cmd.strip_suffix(&[0])
                .is_some_and(|v| v.split(|b| *b == 0).eq(args.iter().map(|x| x.as_bytes())))
                && fs::read_link(format!("/proc/{pid}/exe"))? == Path::new(args[0]),
            "247 executable or argv differs"
        );
        for (owner, mask) in [(&upload, "48-55"), (&producer, "32-39")] {
            let stat = fs::read_to_string(format!("/proc/{}/status", text(owner, "MainPID")?))?;
            let cpu = stat
                .lines()
                .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
                .context("peer affinity")?;
            ensure!(
                funding::cpus(cpu)? == funding::cpus(mask)?,
                "peer CPU placement changed"
            );
        }
        let max = fs::read_to_string(format!("/sys/fs/cgroup/system.slice/{u}/cpu.max"))?;
        let values = max
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            values.len() == 2 && values[1] > 0 && values[1].checked_mul(4) == Some(values[0]),
            "uploader CPU quota changed"
        );
        Ok((
            json!({u:up,p.unit.clone():node}),
            json!({"uploader":upload,"replay":producer}),
            capacity::add(up, node)?,
        ))
    };
    let (curr, owners, before) = check(n)?;
    let path = Path::new(V);
    let a = live::resources_at(path)?;
    let allocation = turnover::allocation(n)?;
    let (_, end, after) = check(n)?;
    let z = live::resources_at(path)?;
    ensure!(
        a.0 == z.0 && latest(f)? == fleet,
        "fleet or host changed while pricing"
    );
    for k in ["uploader", "replay"] {
        live::same_owner(&owners[k], &end[k])?;
    }
    let cap = price(
        (
            a.0,
            a.1.min(z.1),
            a.2.min(z.2).min(num(&allocation["backing"], "free_lower")?),
        ),
        before.min(after),
        num(&allocation, "protected_free_with_remaining_growth")?,
    )?;
    Ok(
        json!({"trace":trace(),"fleet":f,"capacity":cap,"actual_current_memory":curr,"owners":end,"allocation":allocation,
        "reviewed_cpu_overlap":{u:(48..56).collect::<Vec<_>>()},"resource_release_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guards_and_donor_residual_stay_charged() {
        let floor = 4_425_447_245_824u64;
        let g = HARD - 128_000_000_000 - 47_657_822_720;
        let free = floor + native261::DISK_RECEIPTS;
        let cap = price((HARD, g, free), 0, floor).unwrap();
        assert_eq!(cap["from_closed_228"], 16_536_870_912u64);
        assert_eq!(cap["retained_228"], 103_463_129_088u64);
        for r in [
            (HARD - 1, g, free),
            (HARD, g - 1, free),
            (HARD, g, free - 1),
        ] {
            assert!(price(r, 0, floor).is_err());
        }
    }
}
