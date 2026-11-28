//! A completed, one-invocation cold input test. Its expired pre-snapshot gate
//! cannot authorize another writer. Retain its empty original directories so
//! historical observation, the guard and all input provenance remain usable.
use super::*;

const FIELD: &str = "native211_cold_growth_release";
const OLD: &str = "archive-211-v1616-native-input-actual-v1.service";
const IID: &str = "9267f2c2c64949c29b9da7c27a46df94";
const GUARD_SERVICE: &str = "horizon-native211-protective-v1.service";
const DIR: &str = "/home/ubuntu/.jetstreamer-private/native-input211-v1616-capped-v1";
const BOOKING: &str =
    "/var/lib/jetstreamer/horizon-singleton211-bookings-v133-20261120-v1/booking-native211.json";
const BOOKING_SHA: &str = "fdc7e3b8647f619ce99bc443316aac4f61258cf5963478653a23f8c96550a299";
const PLAN: &str = "/var/lib/jetstreamer/horizon-native211-startup-plan-page1810-v3/plan.json";
const PLAN_SHA: &str = "8a0d7960be15772e940b0391a15026ccc91dc312a17d7f9b7602a3f22bde8ec6";
const GUARD_PLAN: &str =
    "/var/lib/jetstreamer/horizon-native211-guard-binding-page1810-v3/guard-plan.json";
const GUARD_SHA256: &str = "509a4c793b8275db0c14c4a9bb9a2d5227ca5fecbccf2eb93c0d00ab4feb59f7";
const GROWTH: u64 = 300_000_000_000;
const DEVICE: u64 = 66305;
const INODES: [u64; 2] = [95092542, 95092543];
const BOOT: &str = "3b17d005-5c3a-4a0e-8841-da097e0957b5";
const PINS: &str = include_str!("native211_cold_growth.json");

fn original_row(rows: &[capacity::Reservation], currents: &BTreeMap<String, u64>) -> Result<usize> {
    let mut matching = rows.iter().enumerate().filter(|(_, r)| r.unit == OLD);
    let (index, r) = matching
        .next()
        .context("missing original native211 cold booking")?;
    ensure!(
        matching.next().is_none()
            && !currents.contains_key(OLD)
            && r.invocation_id == IID
            && r.source == Bound::new(BOOKING, BOOKING_SHA)
            && r.release.is_none()
            && r.maximum_memory_bytes == 137_438_953_472
            && r.minimum_free_bytes == 3_000_000_000_000
            && r.remaining_disk_growth_bytes == GROWTH,
        "native211 cold booking changed, active or already reduced"
    );
    Ok(index)
}

fn expired(plan: &Value, boot: &str, elapsed: u64) -> Result<()> {
    let issue = num(plan, "issued_monotonic_us")?;
    let expiry = num(plan, "expires_monotonic_us")?;
    ensure!(
        boot == BOOT
            && plan["boot_id"] == boot
            && plan["unit"] == OLD
            && plan["worker_root"] == DIR
            && plan["maximum_root_physical_bytes"] == GROWTH
            && issue < expiry
            && expiry - issue <= 60_000_000
            && elapsed > expiry,
        "cold input startup envelope still usable or replaced"
    );
    Ok(())
}

fn dirs() -> Result<Value> {
    let root = Path::new(DIR);
    let mut stamps = Vec::new();
    for (idx, p) in [root.to_owned(), root.join("scratch")].iter().enumerate() {
        // Retain the directory object through the inventory and recheck pathname
        // identity. The source root belongs to ubuntu; aliasing or a new entry
        // invalidates this proof.
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(p)?;
        let m = fd.metadata()?;
        let before = metadata_identity(&m);
        ensure!(
            p.canonicalize()? == *p
                && m.dev() == DEVICE
                && m.ino() == INODES[idx]
                && m.uid() == 1000
                && m.gid() == 1000
                && m.mode() & 0o7777 == 0o700,
            "cold scratch owner or inode changed"
        );
        let names = fs::read_dir(p)?
            .map(|e| Ok(e?.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(
            if idx == 0 {
                names.len() == 1 && names[0] == "scratch"
            } else {
                names.is_empty()
            },
            "native211 cold scratch gained data"
        );
        ensure!(
            before == metadata_identity(&fd.metadata()?)
                && before == metadata_identity(&fs::symlink_metadata(p)?),
            "scratch changed during empty census"
        );
        stamps.push(before);
    }
    Ok(json!(stamps))
}

fn recipes(pins: &Value) -> Result<()> {
    let mut expected = BTreeMap::new();
    for r in pins["recipes"].as_array().context("original recipe list")? {
        let path = PathBuf::from(text(r, "path")?);
        let binding = Bound::new(text(r, "target")?, text(r, "sha256")?);
        ensure!(
            path.canonicalize()? == binding.path && fs::symlink_metadata(&path)?.uid() == 0,
            "original staged recipe link differs"
        );
        binding.bytes(true)?;
        expected.insert(path, binding.sha256);
    }
    let needles = [
        b"native-input211-v1616-capped-v1".as_slice(),
        b"horizon-211-native-input-gated-20261119-v1",
        OLD.as_bytes(),
        b"horizon-native211-startup-plan-page1810-v3",
        b"horizon-native211-protective-v1",
        b"horizon-native211-terminal-retention",
        b"horizon-native211-guard-binding-page1810-v3",
    ];
    staged_recipes(&needles, &expected)
}

pub(super) fn staged_recipes(
    needles: &[&[u8]],
    expected: &BTreeMap<PathBuf, String>,
) -> Result<()> {
    let mut seen = BTreeMap::new();
    let mut files = 0;
    for base in [
        "/etc/systemd/system.control",
        "/run/systemd/system.control",
        "/run/systemd/transient",
        "/run/systemd/generator.early",
        "/etc/systemd/system",
        "/etc/systemd/system.attached",
        "/run/systemd/system",
        "/run/systemd/system.attached",
        "/run/systemd/generator",
        "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/generator.late",
        "/home/ubuntu/.jetstreamer-private/systemd-staging",
    ] {
        let base = Path::new(base);
        match fs::symlink_metadata(base) {
            Ok(m) => ensure!(
                m.is_dir() && base.canonicalize()? == base,
                "aliased unit search root"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        }
        let mut pending = vec![base.to_owned()];
        while let Some(dir) = pending.pop() {
            ensure!(dir.components().count() < 48, "staged search depth");
            for e in fs::read_dir(dir)? {
                let e = e?;
                let p = e.path();
                let m = fs::symlink_metadata(&p)?;
                if m.is_dir() {
                    pending.push(p);
                    continue;
                }
                files += 1;
                ensure!(files <= 65536, "staged file count");
                let target = p.canonicalize()?;
                let name = p.file_name().context("staged name")?.as_encoded_bytes();
                let matches = |bytes: &[u8]| {
                    needles
                        .iter()
                        .any(|n| crate::find_bytes(bytes, n).is_some())
                };
                if target == Path::new("/dev/null") {
                    ensure!(!matches(name), "unexpected masked native211 actor");
                    continue;
                }
                ensure!(
                    target.is_file() && fs::metadata(&target)?.len() <= 1 << 20,
                    "uninspected staged unit file"
                );
                let before = metadata_identity(&fs::metadata(&target)?);
                let mut bytes = Vec::new();
                File::open(&target)?
                    .take((1 << 20) + 1)
                    .read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() <= 1 << 20
                        && before == metadata_identity(&fs::metadata(&target)?)
                        && p.canonicalize()? == target,
                    "staged recipe race"
                );
                if matches(name)
                    || matches(&bytes)
                    || matches(target.as_os_str().as_encoded_bytes())
                {
                    seen.insert(p, format!("{:x}", Sha256::digest(&bytes)));
                }
            }
        }
    }
    ensure!(
        &seen == expected,
        "new, removed or changed staged consumer recipe"
    );
    Ok(())
}

fn checked_manager(unit: &str, raw: &str, expected: &Value) -> Result<Value> {
    let mut actual = serde_json::Map::new();
    for l in raw.lines() {
        let (k, v) = l.split_once('=').context("manager scalar")?;
        let value = if unit == GUARD_SERVICE && k == "ExecStart" {
            periodic::stable_command(v)?
        } else {
            v
        };
        ensure!(
            actual.insert(k.into(), json!(value)).is_none(),
            "duplicate manager property"
        );
    }
    let actual = Value::Object(actual);
    live::same_manager_properties(unit, expected, &actual)?;
    Ok(actual)
}

fn managers(n: &mut Native, pins: &Value, fleet: &Value) -> Result<()> {
    for (unit, expected) in pins["units"].as_object().context("manager scope")? {
        let fields = expected
            .as_object()
            .context("manager fields")?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let raw = n.run(
            "/usr/bin/systemctl",
            &["show", "--all", unit, "--property", &fields],
        )?;
        let actual = checked_manager(unit, std::str::from_utf8(&raw)?, expected)?;
        if unit == OLD {
            live::same_owner(&fleet["unit_census"][OLD], &actual)?;
        }
    }
    let jobs = n.run(
        "/usr/bin/systemctl",
        &["list-jobs", "--plain", "--no-legend"],
    )?;
    ensure!(
        !std::str::from_utf8(&jobs)?
            .split_whitespace()
            .any(|s| s == OLD),
        "old cold test is queued"
    );
    Ok(())
}

fn historical(n: &mut Native, proof: &Value, plan: &Value) -> Result<()> {
    let booking = Bound::new(BOOKING, BOOKING_SHA).sealed()?;
    let admission = binding(&plan["admission"])?.sealed()?;
    ensure!(
        proof["unit"] == OLD
            && proof["invocation_id"] == IID
            && proof["main_pid"] == 1264515
            && proof["boot_id"] == BOOT
            && proof["native_input_qualified"] == true
            && proof["entry_replay"] == false
            && proof["native_marker"]["replay_entries"] == "0"
            && proof["native_marker"]["bootstrap_writes"] == "0"
            && booking["field_sources"]["remaining_disk_growth_bytes"]["document"]
                == plan["admission"]
            && booking["field_sources"]["remaining_disk_growth_bytes"]["pointer"]
                == "/candidate_incremental_peak_bytes"
            && admission["mode"] == "native-cold"
            && admission["candidate_incremental_peak_bytes"] == GROWTH,
        "native211 original terminal or growth provenance differs"
    );
    no_authority(proof)?;
    binding(&proof["journal"])?.bytes(false)?;
    binding(&plan["harness"])?.artifact()?;
    binding(&plan["guard"])?.artifact()?;
    let g = Bound::new(GUARD_PLAN, GUARD_SHA256).sealed()?;
    ensure!(
        g["unit"] == OLD
            && g["invocation_id"] == IID
            && g["worker_root"] == DIR
            && g["native_main"]["main_pid"] == 1264515
            && g["receipt_directory"]
                == "/var/lib/jetstreamer/horizon-native211-guard-receipts-page1810-v3",
        "guard writes/ownership changed"
    );
    let raw = n.run(
        "/usr/bin/journalctl",
        &[
            "--quiet",
            "--no-pager",
            "--output=json",
            "--output-fields=_PID,_UID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE_ID",
            "_PID=1",
            &format!("UNIT={OLD}"),
            &format!("INVOCATION_ID={IID}"),
            "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
        ],
    )?;
    let manager: Value = serde_json::from_slice(&raw)?;
    ensure!(
        manager["_PID"] == "1"
            && manager["_UID"] == "0"
            && manager["_BOOT_ID"] == "3b17d0055c3a4a0e8841da097e0957b5"
            && manager["UNIT"] == OLD
            && manager["INVOCATION_ID"] == IID
            && manager["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448",
        "missing exact PID1 success"
    );
    Ok(())
}

pub(super) fn apply(
    n: &mut Native,
    review: &Value,
    fleet: &Value,
    currents: &BTreeMap<String, u64>,
    rows: &mut [capacity::Reservation],
    device: u64,
) -> Result<Option<Value>> {
    let Some(v) = review.get(FIELD) else {
        return Ok(None);
    };
    let terminal = binding(v)?;
    ensure!(
        terminal == Bound::new(NATIVE_PROOF, NATIVE_PROOF_SHA)
            && device == DEVICE
            && review["boot_id"] == BOOT
            && fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == BOOT,
        "foreign native211 cold transition"
    );
    let index = original_row(rows, currents)?;
    let proof = terminal.sealed()?;
    let plan = Bound::new(PLAN, PLAN_SHA).sealed()?;
    expired(&plan, BOOT, mono()?)?;
    let pins: Value = serde_json::from_str(PINS)?;
    historical(n, &proof, &plan)?;
    managers(n, &pins, fleet)?;
    for p in [
        format!("/sys/fs/cgroup/system.slice/{OLD}"),
        "/proc/1264515".into(),
    ] {
        match fs::symlink_metadata(p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => bail!("original native211 process/cgroup still present"),
        }
    }
    let before = dirs().context("native211 original empty directories")?;
    recipes(&pins).context("native211 initial staged recipe census")?;
    let root = Path::new(DIR);
    let owners =
        native265_growth::scratch_ownership(root, &root.join("scratch"), OLD, &[1264515], &INODES)
            .context("native211 cold scratch ownership census")?;
    recipes(&pins).context("native211 final staged recipe census")?;
    managers(n, &pins, fleet)?;
    ensure!(
        dirs()? == before,
        "native211 scratch changed during capacity review"
    );
    n.check()?;
    rows[index].remaining_disk_growth_bytes = 0;
    Ok(Some(
        json!({"schema":"horizon-completed-native211-cold-growth-release-v1","unit":OLD,"invocation_id":IID,"terminal":terminal,"original_reservation":Bound::new(BOOKING,BOOKING_SHA),"expired_startup_plan":Bound::new(PLAN,PLAN_SHA),"scope":pins,"preserved_empty_directory_identities":before,"ownership":owners,"released_future_growth_bytes":GROWTH,"remaining_future_growth_bytes":0,"physical_allocation_credit_bytes":0,"released_memory_bytes":0,"inherited_floor_credit_bytes":0,"nominal_ledger_unchanged":true}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_v147_guard_accepts_reordered_dependencies_only() -> Result<()> {
        let raw = include_str!("fixtures/native211-guard-v147.properties");
        let pins: Value = serde_json::from_str(PINS)?;
        let expected = &pins["units"][GUARD_SERVICE];
        assert_eq!(expected["Requires"], "system.slice sysinit.target");
        let current = checked_manager(GUARD_SERVICE, raw, expected)?;
        assert_eq!(current["Requires"], "sysinit.target system.slice");
        for replacement in [
            "sysinit.target",
            "sysinit.target system.slice rogue.target",
            "sysinit.target rogue.target",
            "sysinit.target sysinit.target system.slice",
        ] {
            let changed = raw.replace("sysinit.target system.slice", replacement);
            assert!(checked_manager(GUARD_SERVICE, &changed, expected).is_err());
        }
        for (before, after) in [
            ("Restart=no", "Restart=always"),
            ("ignore_errors=no", "ignore_errors=yes"),
            ("Triggers=", "Triggers=rogue.service"),
            ("--plan-sha256", "--self-sha256"),
            ("User=root", "User=ubuntu"),
            ("Wants=\n", ""),
            ("Group=\n", "Group=\nGroup=\n"),
        ] {
            let changed = raw.replace(before, after);
            assert!(checked_manager(GUARD_SERVICE, &changed, expected).is_err());
        }
        let mut duplicate = expected.clone();
        duplicate["Requires"] = json!("system.slice system.slice sysinit.target");
        assert!(checked_manager(GUARD_SERVICE, raw, &duplicate).is_err());
        Ok(())
    }

    fn row() -> capacity::Reservation {
        capacity::Reservation {
            unit: OLD.into(),
            invocation_id: IID.into(),
            source: Bound::new(BOOKING, BOOKING_SHA),
            release: None,
            maximum_memory_bytes: 137_438_953_472,
            minimum_free_bytes: 3_000_000_000_000,
            remaining_disk_growth_bytes: GROWTH,
        }
    }
    #[test]
    fn only_original_inactive_unreduced_cold_booking_is_eligible() {
        let c = BTreeMap::new();
        let r = row();
        assert_eq!(original_row(std::slice::from_ref(&r), &c).unwrap(), 0);
        assert!(original_row(&[r.clone(), r.clone()], &c).is_err());
        assert!(
            original_row(std::slice::from_ref(&r), &BTreeMap::from([(OLD.into(), 0)])).is_err()
        );
        for (key, val) in [
            ("unit", json!(UNIT)),
            ("invocation_id", json!("49ea83a3a5e94e99af51153d2fd79e92")),
            ("remaining_disk_growth_bytes", json!(0)),
            ("maximum_memory_bytes", json!(1)),
            ("minimum_free_bytes", json!(1)),
            ("release", json!(r.source)),
            ("source", json!(Bound::new("/other", BOOKING_SHA))),
        ] {
            let mut b = json!(r);
            b[key] = val;
            let b = serde_json::from_value(b).unwrap();
            assert!(original_row(&[b], &c).is_err(), "{key}");
        }
    }

    #[test]
    fn live_startup_authority_or_foreign_scratch_fails() {
        let p = json!({"unit":OLD,"boot_id":BOOT,"worker_root":DIR,"maximum_root_physical_bytes":GROWTH,"issued_monotonic_us":40,"expires_monotonic_us":100});
        expired(&p, BOOT, 101).unwrap();
        for limit in [0, 40, 100] {
            assert!(expired(&p, BOOT, limit).is_err());
        }
        for (k, v) in [
            ("unit", json!(UNIT)),
            ("boot_id", json!("other")),
            ("worker_root", json!(ROOT)),
            ("expires_monotonic_us", json!(39)),
            ("issued_monotonic_us", json!(100)),
            ("maximum_root_physical_bytes", json!(0)),
        ] {
            let mut bad = p.clone();
            bad[k] = v;
            assert!(expired(&bad, BOOT, 101).is_err(), "{k}");
        }
    }

    #[test]
    #[ignore = "requires the genuine v139/v140 booked data, PID1, /proc, all mount namespaces and terminal receipts"]
    fn genuine_v139_fit_and_holding_and_v140_collected_boundary() -> Result<()> {
        let dir = PathBuf::from(std::env::var(
            "HORIZON_NATIVE211_GROWTH_QUALIFICATION_DIRECTORY",
        )?);
        ensure!(
            dir.is_absolute()
                && dir.starts_with("/run")
                && dir.canonicalize()? == dir
                && fs::read_dir(&dir)?.next().is_none(),
            "fresh private evidence directory required"
        );
        let mut n = Native {
            root: dir,
            counter: 0,
            deadline: Some(mono()? + 180_000_000),
        };
        let fit = Bound::new(
            "/var/lib/jetstreamer/horizon-native257-fit-v139-ops-v1-result/fit.json",
            "26131d62062386686636413d8a02de1b3971bee7c16ab78e42074dfffe644ccb",
        )
        .sealed()?;
        let mut review = binding(&fit["review"])?.sealed()?;
        let fleet = binding(&fit["fleet"])?.json()?;
        let ledger = binding(&fit["reservation_ledger"])?.sealed()?;
        let mut before: Vec<capacity::Reservation> =
            serde_json::from_value(ledger["reservations"].clone())?;
        let current = serde_json::from_value(fit["actual_current_memory"].clone())?;
        assert_eq!(before.len(), 15);
        let row = |rs: &mut [capacity::Reservation], unit: &str| {
            rs.iter().position(|r| r.unit == unit).unwrap()
        };
        let full = row(&mut before, UNIT);
        before[full].remaining_disk_growth_bytes =
            num(&fit["full211_growth"], "remaining_disk_growth_bytes")?;
        let old265 = row(&mut before, "horizon-265-native-input-20261119-v1.service");
        before[old265].remaining_disk_growth_bytes = 0;
        let old = row(
            &mut before,
            "horizon205206-adjacent-boundary-v135-v1.service",
        );
        before[old].release = Some(binding(
            &fit["failed_boundary205206_memory_release"]["terminal"],
        )?);
        let mut after = before.clone();
        assert!(apply(&mut n, &review, &fleet, &current, &mut after, DEVICE)?.is_none());
        review[FIELD] = json!(Bound::new(NATIVE_PROOF, NATIVE_PROOF_SHA));
        let proof = apply(&mut n, &review, &fleet, &current, &mut after, DEVICE)?
            .context("missing cold transition")?;
        let index = original_row(&before, &current)?;
        let mut expected = before.clone();
        expected[index].remaining_disk_growth_bytes = 0;
        assert_eq!(json!(after), json!(expected));
        assert!(apply(&mut n, &review, &fleet, &current, &mut after, DEVICE).is_err());
        let observer = binding(&fit["observer"])?.json()?;
        let host = &observer["host_memory"];
        let total = num(host, "total_kib")? * 1024;
        let avail = num(host, "conservative_available_kib")? * 1024;
        let disk = num(&fit["full211_growth"], "conservative_free_bytes")?;
        let century = capacity::century(&binding(&review["century"])?.sealed()?, &fleet)?;
        let periodic = ledger["periodic_controls"]["controls"]
            .as_array()
            .context("periodic")?
            .iter()
            .try_fold(0, |sum, r| {
                capacity::add(sum, num(r, "maximum_memory_bytes")?)
            })?;
        let overhead = (
            num(&ledger["auxiliary_overhead"], "memory_bytes")?,
            periodic,
        );
        let scenario = |r| scenarios((total, avail, disk), century, r, &current, overhead, 0);
        let original = scenario(&before);
        let adjusted = scenario(&after);
        let case = "limited_native257_with_booked_full211";
        assert_eq!(original[case], fit["scenarios"][case]);
        assert_eq!(adjusted[case]["fits"], true);
        assert_eq!(
            num(&adjusted[case]["capacity"], "required_initial_free_bytes")?,
            4_229_996_980_600
        );
        assert_eq!(disk - 4_229_996_980_600, 51_150_009_992);
        let holding = |r| {
            capacity::booked_arithmetic(
                (total, avail, u64::MAX),
                century,
                r,
                &current,
                overhead,
                (0, 63_045_455_286),
            )
        };
        let a = holding(&before)?;
        let b = holding(&after)?;
        assert_eq!(
            num(&a, "retained_disk_growth_bytes")? - num(&b, "retained_disk_growth_bytes")?,
            GROWTH
        );
        for key in [
            "memory_obligation_after_bytes",
            "remaining_hard_growth_bytes",
            "allocation_credit_taken_bytes",
        ] {
            assert_eq!(a[key], b[key]);
        }
        // The v139 retry was still live. Its distinct v140 not-found census needs
        // genuine terminal process/PID1 records and no resource release for retry.
        let r140 = Bound::new(
            "/var/lib/jetstreamer/horizon-native257-current-bookings-v140-ops-v1/review.json",
            "88a26f84e9ee79ab92826a5a81ad9d3ba3a14840cade3b76508d9c11314eb608",
        )
        .sealed()?;
        let f140 = binding(&r140["fleet"])?.json()?;
        let l140 = binding(&r140["reservation_ledger"])?.sealed()?;
        let rs: Vec<capacity::Reservation> = serde_json::from_value(l140["reservations"].clone())?;
        let mut actual = rs.clone();
        let no_memory_credit = BTreeMap::new();
        let boundary =
            failed_boundary205206::apply(&mut n, &r140, &f140, &no_memory_credit, &mut actual)?
                .context("missing original memory proof")?;
        assert_eq!(boundary["completed_retry"]["released_memory_bytes"], 0);
        assert_eq!(boundary["released_memory_bytes"], 125_000_000_000u64);
        let i = row(
            &mut actual,
            "horizon205206-adjacent-boundary-v135-v1.service",
        );
        let mut target = rs;
        target[i].release = Some(binding(&r140["failed_boundary205206_memory_release"])?);
        assert_eq!(json!(actual), json!(target));
        save_json(
            &n.root,
            "private-proof.json",
            &json!({"proof":proof,"v139_before":original,"v139_after":adjusted,"holding_before":a,"holding_after":b,"v140_completed_retry":boundary,"no_admission":true}),
        )?;
        Ok(())
    }
}
