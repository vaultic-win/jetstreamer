use super::*;
const BOOK: &str =
    "/home/ubuntu/.codex/diagnostics/horizon-upload-247-staged-fadfe2d4-v1/booking.json";
const LAUNCH: &str =
    "/home/ubuntu/.codex/diagnostics/horizon-upload-247-staged-fadfe2d4-v1/launch.json";
const F165: &str =
    "/home/ubuntu/.codex/diagnostics/horizon-fleet-takeover-v165-20261120-v1/fleet-v1.json";
const F165_SHA: &str = "4614430bff5410a584e7c17dda6b94b2457f3baa60d726cc02cd220ee83fc40b";
const RELEASE: &str = "/var/lib/jetstreamer/horizon266-cold-owner-discharge-v162-v1/discharge.json";
const ROOTS: [u64; 5] = [506191984640, 320 << 30, 128 << 30, 112 << 30, 96 << 30];
const MEMORY: [u64; 2] = [192000000000, 176000000000];
const COLD: &str = "/run/horizon266-native-cold-v1";
pub(super) const OWNERS: [(&str, &str, u64); 3] = [
    (
        "horizon-singleton-211-capped-4aeca563-v1.service",
        "49ea83a3a5e94e99af51153d2fd79e92",
        225000000000,
    ),
    (
        "horizon-qualify-265-replacement-20261119-v3.service",
        "182de64d33674f95b7758d410eb1812b",
        128000000000,
    ),
    (
        "horizon-upload-247-staged-fadfe2d4-v1.service",
        "e434de7095a5407f80353b8f1df5eea8",
        10 << 30,
    ),
];
pub(super) fn cpus(text: &str) -> Result<BTreeSet<u32>> {
    let mut out = BTreeSet::new();
    for item in text
        .split(|v: char| v == ',' || v.is_ascii_whitespace())
        .filter(|v| !v.is_empty())
    {
        let (l, r) = item.split_once('-').unwrap_or((item, item));
        let (lo, hi) = (l.parse::<u32>()?, r.parse::<u32>()?);
        ensure!(lo <= hi && hi < 4096, "CPU range");
        out.extend(lo..=hi);
    }
    ensure!(!out.is_empty(), "empty CPU range");
    Ok(out)
}
fn available_cpus(n: &mut Native, lane: Lane) -> Result<BTreeSet<u32>> {
    let mut cpus_free = cpus(&fs::read_to_string("/sys/devices/system/cpu/online")?)?;
    for (unit, _, _) in OWNERS {
        if lane == Lane::Instructions266
            && unit == OWNERS[2].0
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(unit)
                .try_exists()?
        {
            successor::drained247(n)?;
            let reserved = cpus("48-55")?;
            cpus_free.retain(|cpu| !reserved.contains(cpu));
            continue;
        }
        let pid = command_field(n, unit, "MainPID")?.parse::<u32>()?;
        let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
        let reserved = cpus(
            status
                .lines()
                .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
                .context("CPU affinity")?,
        )?;
        cpus_free.retain(|cpu| !reserved.contains(cpu));
    }
    if lane == Lane::Epoch228 {
        // The original 266 CPU allocation remains reserved after the witnessed exit.
        let mask = cpus("32-39")?;
        cpus_free.retain(|cpu| !mask.contains(cpu));
    }
    if lane == Lane::Instructions266 {
        let reserved = cpus("40-47")?;
        cpus_free.retain(|cpu| !reserved.contains(cpu));
        ensure!(
            cpus("32-39")?.is_subset(&cpus_free),
            "original 266 CPU block unavailable"
        );
        return cpus("32-39");
    }
    ensure!(cpus_free.len() >= 8, "eight disjoint replay CPUs");
    Ok(cpus_free.into_iter().take(8).collect())
}
pub(super) fn discharge() -> Result<Bound> {
    let b = Bound::new(
        RELEASE,
        "e06ae0ed57a2a10356efb35c6305beb4b70be45a7303e171261d35111f16d5a5",
    );
    let d = b.sealed()?;
    let post = &d["after"];
    ensure!(
        d["schema"] == "horizon266-cold-owner-physical-discharge-v1"
            && d["original_producer_memory_bytes"] == 192000000000u64
            && d["producer_future_growth_released_bytes"] == 191932891136u64
            && d["residual_memory_reserve_bytes"] == (64u64 << 20)
            && post["readonly"] == true
            && post["cap"] == 1 << 20
            && d["replay_admitted"] == false
            && post["physical_bytes"] == 28672,
        "cold discharge"
    );
    let m = fs::metadata(COLD)?;
    ensure!(
        m.dev() == 123 && m.ino() == 1 && m.uid() == 1000,
        "original cold root"
    );
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    let matches = info
        .lines()
        .filter(|l| l.split_whitespace().nth(4) == Some(COLD))
        .collect::<Vec<_>>();
    ensure!(matches.len() == 1, "original 266 mount");
    let (a, bk) = matches[0].split_once(" - ").context("mount framing")?;
    let f = a.split_whitespace().collect::<Vec<_>>();
    let s = bk.split_whitespace().collect::<Vec<_>>();
    ensure!(
        f[0] == "1359"
            && f[2] == "0:123"
            && f[5].split(',').any(|v| v == "ro")
            && s[0] == "tmpfs"
            && s[1] == "horizon266-native-cold"
            && s[2].split(',').any(|v| v == "ro"),
        "cold superblock writable or replaced"
    );
    let path = std::ffi::CString::new(COLD)?;
    let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), &mut v) } == 0
            && v.f_blocks * v.f_frsize == 1 << 20
            && v.f_files == 64
            && v.f_flag & libc::ST_RDONLY != 0,
        "cold mount capacity regrew"
    );
    binding(&d["basis"]["canonical_terminal"])?.sealed()?;
    Ok(b)
}
pub(super) fn anchor(f: &Bound) -> Result<Value> {
    let v = f.json()?;
    fresh(num(&v, "recorded_unix_seconds")?, now()?, 1800)?;
    ensure!(
        v["first_epoch"] == 201
            && v["last_epoch"] == 300
            && v["schema"] == "jetstreamer-horizon-campaign-fleet-v1",
        "fleet assignment"
    );
    let o = Bound::new(text(&v, "observer_receipt")?, text(&v, "observer_sha256")?).json()?;
    ensure!(
        v["sampled_at_utc"] == o["recorded_at_utc"]
            && o["cadence"]["routine_minimum_interval_enforced"] == true,
        "fleet sample"
    );
    // A metadata event can be recent while its routine sample has already expired.
    let date = Command::new("/usr/bin/date")
        .args(["--utc", "--date", text(&o, "recorded_at_utc")?, "+%s"])
        .output()?;
    ensure!(date.status.success(), "sample clock");
    fresh(
        std::str::from_utf8(&date.stdout)?.trim().parse()?,
        now()?,
        1800,
    )?;
    let mut cursor = f.clone();
    for _ in 0..128 {
        if cursor == Bound::new(F165, F165_SHA) {
            return Ok(v);
        }
        let parent = binding(&cursor.json()?["previous_fleet"])?;
        ensure!(parent != cursor, "cyclic fleet predecessor");
        cursor = parent
    }
    bail!("v165 fleet predecessor absent")
}
pub(super) fn manager_units(n: &mut Native) -> Result<BTreeSet<String>> {
    let raw = n.run(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--state=active,activating,deactivating",
            "--type=service",
            "--plain",
            "--no-pager",
            "--no-legend",
        ],
    )?;
    Ok(std::str::from_utf8(&raw)?
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|s| {
            ["horizon", "archive-", "jetstreamer"]
                .iter()
                .any(|p| s.starts_with(p))
        })
        .map(str::to_owned)
        .collect())
}
pub(super) fn candidates(
    lane: Lane,
    hard: u64,
    total: u64,
    avail: u64,
    current: u64,
    free: u64,
    floor: u64,
    allowed: Option<(u64, u64)>,
) -> Result<Value> {
    let mut all = Vec::new();
    let mut chosen = Value::Null;
    let (roots, memories): (&[u64], &[u64]) = match lane {
        Lane::Bounded266 | Lane::BoundedRetry266 => {
            bail!("bounded replay requires its own issued booking")
        }
        Lane::Turnover266 => (&[320 << 30], &[176000000000]),
        Lane::Instructions266 => (&[320 << 30, 128 << 30], &[176000000000]),
        Lane::Epoch266 => (&ROOTS, &MEMORY),
        Lane::Epoch228 => (&[epoch228::ROOT_BYTES], &[epoch228::MEMORY]),
    };
    for &root in roots {
        for &memory in memories {
            if allowed.is_some_and(|p| p != (memory, root)) {
                continue;
            }
            let final_hard = hard
                .checked_add(memory + GUARD_MEM + CONTROL_MEM)
                .context("memory overflow")?;
            let rem = final_hard
                .checked_sub(current)
                .context("current memory exceeds complete obligations")?;
            let need = floor
                .checked_add(root + RECEIPTS)
                .context("floor overflow")?;
            let fits = final_hard <= total && rem <= avail && need <= free;
            let row = json!({"root":root,"memory":memory,"hard":final_hard,"growth":rem,"required_free":need,"fits":fits});
            if chosen.is_null() && fits {
                chosen = row.clone()
            }
            all.push(row)
        }
    }
    Ok(json!({"options":all,"winner":chosen}))
}
pub(super) fn elect(
    lane: Lane,
    n: &mut Native,
    r: &Value,
    held: Option<(&Profile, &Value, (u64, u64))>,
) -> Result<Value> {
    if lane.is_bounded() {
        return bounded::elect(lane, n, r, held);
    }
    if lane == Lane::Turnover266 {
        return turnover::elect(n, r, held);
    }
    let replacement = lane == Lane::Instructions266;
    let paired = lane != Lane::Epoch266;
    if replacement {
        successor::selected(r)?;
    }
    let extent_window = replacement.then(peer228_extents::Extents::open);
    let fleet = binding(&r["fleet"])?;
    let f = anchor(&fleet)?;
    let book = digest_file(
        BOOK,
        "5b2aeddd07ef355c3bb9ab01b0180df3fb3b6371ca8f27b23a9ff45e52235f02",
    )?;
    let launch = digest_file(
        LAUNCH,
        "fc4d2b5855f8185695f41c2a03e22e15e8ecdf090b8b32eb7378da3a69927ce3",
    )?;
    let cold = binding(&book["epoch228_held_fit"])?.sealed()?;
    let ledger = binding(&book["ledger"])?.sealed()?;
    ensure!(
        rows(&ledger, "reservations")?.len() == 21
            && cold["epoch228_completed_retry_memory_release"]["released_memory_bytes"]
                == 125000000000u64
            && book["hard_memory_obligation"] == 1211435323392u64
            && book["required_free"] == 4214996908032u64
            && book["requested_memory"] == 11274289152u64
            && book["epoch228_terminal_and_guard_retained"] == true
            && book["epoch228_complete_nominal_memory"] == 137438953472u64
            && launch["unit"]["InvocationID"] == OWNERS[2].1,
        "original 247/228 funding"
    );
    let first_disk_qa = stopped::original(n)?;
    let (credit, basis) = match lane {
        Lane::Instructions266 => (
            successor::MEMORY + GUARD_MEM + CONTROL_MEM,
            epoch228::proof251(n, &f, &ledger)?,
        ),
        Lane::Bounded266 | Lane::BoundedRetry266 | Lane::Turnover266 => {
            bail!("turnover has an independent election")
        }
        Lane::Epoch266 => (191932891136, json!(discharge()?)),
        Lane::Epoch228 => (epoch228::ASSIGNED, epoch228::funding(n, r, &f, &ledger)?),
    };
    let mut allowed = OWNERS
        .iter()
        .map(|(u, _, _)| u.to_string())
        .collect::<BTreeSet<_>>();
    for g in rows(&ledger["periodic_controls"], "controls")? {
        let c: periodic::Control = serde_json::from_value(g.clone())?;
        periodic::observe(n, &c)?;
        allowed.insert(c.unit);
    }
    let originating = binding(&cold["review"])?.sealed()?;
    let nominal: Vec<capacity::Reservation> =
        serde_json::from_value(ledger["reservations"].clone())?;
    native266_peer::guard(n, &originating, &nominal)?;
    allowed.insert("horizon-native266-protective-v1.service".into());
    allowed.insert(lane.controller().into());
    if let Some((p, m, _)) = held {
        allowed.insert(p.unit.clone());
        allowed.insert(p.guard.clone());
        let actual = n.show(&p.unit)?;
        ensure!(
            actual["MainPID"] == m["MainPID"]
                && actual["InvocationID"] == m["InvocationID"]
                && actual["ActiveState"] == "active",
            "held producer identity"
        );
    }
    let peer228 = if replacement {
        let peer = successor::peer(n)?;
        allowed.insert(text(&peer.0, "unit")?.to_owned());
        allowed.insert(text(&peer.0, "guard_service")?.to_owned());
        Some(peer)
    } else {
        None
    };
    let peer266 = if paired {
        allowed.insert(epoch228_peer::UNIT.into());
        allowed.insert(epoch228_peer::SERVICE.into());
        Some(epoch228_peer::verify(n, r)?)
    } else {
        None
    };
    let census = manager_units(n)?;
    ensure!(
        census.is_subset(&allowed),
        "unaccounted live owners: {:?}",
        census.difference(&allowed).collect::<Vec<_>>()
    );
    let mut curr = peer228.as_ref().map_or(0, |v| v.1);
    let mut peer_rows = Vec::new();
    for (idx, (u, iid, cap)) in OWNERS.iter().enumerate() {
        if replacement && idx == 2 && !census.contains(*u) {
            peer_rows.push(json!({"unit":u,"invocation_id":iid,"main_pid":"0","memory_max":cap,"terminal":successor::drained247(n)?,"booking_released":false}));
            continue;
        }
        // Uploaders contain credentials in Environment. Read just the envelope properties.
        let raw=n.run("/usr/bin/systemctl",&["show",u,"-p","Id,LoadState,ActiveState,SubState,InvocationID,NRestarts,Result,Job,Restart,KillMode,Delegate,ControlGroup,MainPID,MemoryMax,MemorySwapMax"])?;
        let mut fields = serde_json::Map::new();
        for line in std::str::from_utf8(&raw)?.lines() {
            let (key, value) = line.split_once('=').context("unit property framing")?;
            ensure!(
                fields.insert(key.into(), json!(value)).is_none(),
                "duplicate property"
            );
        }
        let m = Value::Object(fields);
        let amount = live::finite_owner(&m, u, iid, *cap)?;
        if paired && idx == 2 {
            epoch228::mapped_command(&m, &book)?;
        }
        let previous = if idx == 2 {
            &launch["unit"]
        } else {
            &f["unit_census"][*u]
        };
        ensure!(
            m["MainPID"] == previous["MainPID"] && m["InvocationID"] == previous["InvocationID"],
            "owner substitution {u}"
        );
        curr = curr
            .checked_add(amount.min(live::kernel_memory(&m, u, *cap)?))
            .context("current-memory overflow")?;
        peer_rows
            .push(json!({"unit":u,"invocation_id":iid,"main_pid":m["MainPID"],"memory_max":cap}));
    }
    for (u, q) in book["retained_terminal_custody"]
        .as_object()
        .context("terminal rows")?
    {
        live::verify_drained_group(u)?;
        let id = command_field(n, u, "InvocationID")?;
        ensure!(id.is_empty() || q["invocation_id"] == id, "reactivated {u}");
    }
    let firing = serde_json::to_value(full211_window::Firing::capture(n)?)?;
    let old = binding(&book["guards"][OWNERS[0].0])?.json()?;
    let l = (
        &old["root_physical_observation"]["first"],
        &old["root_physical_observation"]["second"],
    );
    let penalty = num(l.0, "physical_bytes")?
        .min(num(l.1, "physical_bytes")?)
        .saturating_sub(num(&firing, "lower_physical")?);
    let floor = num(&book, "required_free")?
        .checked_add(penalty)
        .context("retained disk growth")?;
    let floor = if let Some(peer) = &peer266 {
        floor
            .max(num(peer, "original_floor")?)
            .checked_add(num(peer, "additional_disk_above_shared_qa")?)
            .context("joint 266 floor overflow")?
    } else {
        floor
    };
    let transfer = peer266
        .as_ref()
        .map(|peer| epoch228_storage::assignment(n, &book, peer))
        .transpose()?;
    let floor = if let Some(source) = &transfer {
        // Both historical bookings include the same complete cold root. Transfer its
        // scratch allowance once, after joining their floors. Live guard limits and
        // independent minimum-free reservations are absolute constraints.
        let mut independent = num(source, "source_floor")?;
        for row in rows(&ledger, "reservations")? {
            independent = independent.max(num(row, "minimum_free_bytes")?);
        }
        for (u, _, _) in &OWNERS[..2] {
            let guard = binding(&book["guards"][*u])?.json()?;
            independent = independent.max(num(&guard, "minimum_free_bytes")?);
        }
        floor
            .checked_sub(num(source, "assigned_scratch_bytes")?)
            .context("228 transfer underflow")?
            .max(independent)
    } else {
        floor
    };
    // The 228 calculation above carries its historical exclusive 251 assignment and
    // 228 cold scratch transfer. Keep its full rooted allocation and all absolute floors.
    let extent_report =
        extent_window.map(
            |state| match state.and_then(peer228_extents::Extents::finish) {
                Ok(v) => v,
                Err(e) => json!({"credit":0,"gross_charge_used":true,"reason":e.to_string()}),
            },
        );
    let floor = if let Some((peer, _)) = &peer228 {
        let old = peer266.as_ref().context("missing original 266 drain")?;
        ensure!(
            old["terminal_failure"].is_object()
                && old["readonly_loop"].is_object()
                && old["main_pid"] == 0
                && old["memory_max"] == successor::MEMORY
                && old["memory_credit_for_228"] == 0
                && old["readonly_loop"]["sha256"]
                    == "f0312d5f559dd2adca57c89e5a01f1d66d1ea72512248e4635b0dd252aef3f76"
                && old["cold_discharge_for_266_only"] == json!(discharge()?)
                && r["epoch266_reassignment"] == successor::allocation()
                && basis == peer["retained_251"]
                && transfer.as_ref() == Some(&peer["scratch_reassignment"]),
            "original assignments differ"
        );
        // Add newly requested two QA roots and controls (768 MiB) via candidates' common 1 GiB charge.
        let guarded = floor
            .checked_add(RECEIPTS)
            .context("228 floor")?
            .max(num(peer, "original_floor")?);
        let full = guarded
            .checked_add(epoch228::ROOT_BYTES)
            .context("228 scratch")?
            .max(num(peer, "original_required_free")?);
        let allocation = num(
            extent_report
                .as_ref()
                .context("missing 228 extent accounting")?,
            "credit",
        )?;
        full.checked_sub(allocation)
            .context("228 allocation")?
            .max(guarded)
            .checked_sub(256 << 20)
            .context("shared QA accounting")?
    } else {
        floor
    };
    let (total, avail, free) = live::resources_at(Path::new(V))?;
    let free = free.min(num(&firing, "free")?);
    let free = free.min(
        extent_report
            .as_ref()
            .and_then(|v| v["free_lower"].as_u64())
            .unwrap_or(u64::MAX),
    );
    let hard = num(&book, "hard_memory_obligation")?
        .checked_sub(credit)
        .context("discharge underflow")?;
    let mut result = candidates(
        lane,
        hard,
        total,
        avail,
        curr,
        free,
        floor,
        held.map(|v| v.2),
    )?;
    ensure!(
        manager_units(n)?.is_subset(&allowed),
        "new owner during admission"
    );
    for p in &peer_rows {
        let u = text(p, "unit")?;
        if let Some(event) = p.get("terminal") {
            ensure!(
                successor::drained247(n)? == *event,
                "247 changed during election"
            );
            continue;
        }
        ensure!(
            command_field(n, u, "InvocationID")? == text(p, "invocation_id")?
                && command_field(n, u, "MainPID")? == text(p, "main_pid")?,
            "peer changed during admission"
        );
    }
    result["schema"] = json!(format!(
        "horizon{}-native-full-capacity-election-v1",
        lane.epoch()
    ));
    if let Some(peer) = peer266 {
        ensure!(
            epoch228_peer::verify(n, r)? == peer,
            "266 changed across election"
        );
        ensure!(
            Some(epoch228_storage::assignment(n, &book, &peer)?) == transfer,
            "original 228 changed during election"
        );
        result["epoch228_scratch_assignment"] = transfer.context("missing 228 reservation")?;
        result["concurrent_266"] = peer;
    }
    result["retained_attempt_one"] = first_disk_qa;
    result["fleet"] = json!(fleet);
    result["peer_envelopes"] = json!(peer_rows);
    match lane {
        Lane::Instructions266 => {
            let (peer, _) = peer228.context("228 evidence")?;
            ensure!(successor::peer(n)?.0 == peer, "228 changed during election");
            result["live_228"] = peer;
            result["epoch228_extents"] = extent_report.context("missing extent result")?;
            result["epoch251_assignment"] = basis;
            result["new_266_assignment"] = successor::allocation();
        }
        Lane::Bounded266 | Lane::BoundedRetry266 | Lane::Turnover266 => {
            bail!("turnover has an independent election")
        }
        Lane::Epoch266 => result["cold_discharge"] = basis,
        Lane::Epoch228 => result["epoch251_assignment"] = basis,
    }
    result["epoch228_held_fit"] = book["epoch228_held_fit"].clone();
    result["uploader_booking"] = json!(bound_at(Path::new(BOOK))?);
    result["full211_guard"] = firing;
    result["protected_floor"] = json!(floor + RECEIPTS);
    result["free"] = json!(free);
    result["cpus"] = json!(available_cpus(n, lane)?);
    result["publication_authorized"] = json!(false);
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reserves_uploader_two_qa_roots_and_the_residual_cold_owner() {
        let base = 1211435323392 - 191932891136;
        let all = candidates(
            Lane::Epoch266,
            base,
            1212136964096,
            1047188426752,
            250000000000,
            4358150836224,
            4214996908032,
            None,
        )
        .unwrap();
        let w = &all["winner"];
        assert_eq!(w["memory"], 176000000000u64);
        assert_eq!(w["root"], 128u64 << 30);
        assert_eq!(
            w["required_free"],
            4214996908032u64 + (128 << 30) + RECEIPTS
        );
        assert!(
            candidates(
                Lane::Epoch266,
                base,
                1212136964096,
                0,
                0,
                4358150836224,
                4214996908032,
                None
            )
            .unwrap()["winner"]
                .is_null()
        );
    }
}

#[cfg(test)]
mod replacement_tests {
    use super::*;

    #[test]
    fn original_228_headroom_cannot_fund_the_next_128_gib_266_root() {
        let floor = 4_216_875_956_224u64 - (256 << 20);
        let q = candidates(
            Lane::Instructions266,
            1_211_435_323_392 - (successor::MEMORY + GUARD_MEM + CONTROL_MEM),
            1_212_136_964_096,
            u64::MAX,
            0,
            4_335_859_884_032,
            floor,
            None,
        )
        .unwrap();
        assert!(q["winner"].is_null());
        let small = q["options"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["root"] == 128u64 << 30)
            .unwrap();
        assert_eq!(small["required_free"], 4_355_120_216_064u64);
        let funded = candidates(
            Lane::Instructions266,
            1_211_435_323_392 - (successor::MEMORY + GUARD_MEM + CONTROL_MEM),
            1_212_136_964_096,
            u64::MAX,
            0,
            4_355_120_216_064,
            floor,
            None,
        )
        .unwrap();
        assert_eq!(funded["winner"]["root"], 128u64 << 30);
        assert_eq!(funded["winner"]["hard"], 1_211_435_323_392u64);
    }
}
