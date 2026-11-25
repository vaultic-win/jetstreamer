//! Kernel/PID1 fence for the known historical epoch-171 launch routes.
//! Runtime masks persist after this writer exits. Release only reconciles the same mask inode.
use super::*;
use crate::standard169_cpu_lease::REGISTRY_136 as REG;
use std::os::unix::fs::{DirBuilderExt, symlink};
const HIGH: &str = "/run/systemd/system.control";
const LEGACY: &str = "jetstreamer-epochs159-173-target1-controller-v1-r2.service";
const RECIPE: &str = "/usr/local/lib/jetstreamer/horizon-local-replacement171-local2-prepare-plan-20261110-v14-r4/plan.json";
const RECIPE_SHA: &str = "27a6a140a26481c65e80876a79da1221617e5927a26225eb9acaf1570bd2b700";
const OLD: &str =
    "/var/lib/jetstreamer/standard171-scratch-retirement-20261110-backfill-v1/plan.json";
const OLD_SHA: &str = "9aab5af8aa896176f693c374895c8f6f0402ecbc8a23f9d4c1e853473466021b";
const RET: &str =
    "/var/lib/jetstreamer/local2-mismatch171-retirement-20261114-v1/epoch171/completion.json";
const RET_SHA: &str = "516374383d926ce454d4cf532b136e6e2f194b7757b458fc5dab74d4784c4b87";
const BOOK: &str = "/home/sol/.jetstreamer-private/epoch171-independent-singleton-20261110-v1/ROOT_FRESH_STANDARD171_MANUAL_ADMISSION_AND_RESOURCE_BOOKING.json";
const BOOK_SHA: &str = "c781a0a2237546fc49bfc0fa30cd6472cc7437c1513a1416031333b6260fc594";
const AUTH: &str = "/usr/local/lib/jetstreamer/horizon-original154-future-data-current-authority-20261110-v1/authority.json";
const AUTH_SHA: &str = "2f88b7f91cc6df70804cd96027efbd0e18cb6452a48e76d813673b556d727caa";
const MAP: &str = "/var/lib/jetstreamer/cached-standard-input-qualification-20261110-v1/epoch171/native-local2-v14-r4/EXCLUSIVE_SLOT_MAPPING.json";
const MAP_SHA: &str = "45968351cb6c369a0b56111e4926f2eb3e466662c01a70675444f95ac296450a";
const WIT: &str = "/usr/local/lib/jetstreamer/horizon-original-slot-data-witness-set-20261118-v6/witness-set.json";
const WIT_SHA: &str = "8eb041519cba5c3f6368cb1432be9e289489ce1acdc28aa8b49f3d6ec7f382ee";
fn paths() -> Result<BTreeSet<String>> {
    let mut units = BTreeSet::new();
    for (p, h) in [(RECIPE, RECIPE_SHA), (OLD, OLD_SHA)] {
        let doc = json_pin(Path::new(p), h)?;
        ensure!(doc["epoch"] == 171, "wrong donor recipe");
        for x in doc["closed_units"]
            .as_array()
            .context("donor closed units")?
        {
            let u = x.as_str().context("unit")?;
            ensure!(u == LEGACY || u.contains("171"), "unrelated legacy unit");
            ensure!(
                !u.contains('/') && (u.ends_with(".service") || u.ends_with(".timer")),
                "invalid historical unit"
            );
            units.insert(u.to_owned());
        }
    }
    for u in [
        "horizon-guard-replacement-171-local2-DATA-20261110-v1.service",
        "horizon-guard-replacement-171-local2-DATA-20261110-v1.timer",
        "horizon-local-replacement171-measure-only-local2-r3-20261110-v14.service",
        "horizon-local-replacement171-measure-only-local2-r4-20261110-v14.service",
        "horizon-local-replacement171-prepare-local2-r4-20261110-v14.service",
    ] {
        units.insert(u.to_owned());
    }
    for u in [
        LEGACY,
        "horizon-qualify-171-standard-20261110-v1.service",
        "horizon-replacement-171-local1-20261110-v1.service",
        "horizon-qualify-171-replacement-local2-20261110-v1.service",
    ] {
        ensure!(units.contains(u), "missing donor launch route");
    }
    Ok(units)
}
fn safe_dir(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && path.canonicalize()? == path && m.uid() == 0 && m.mode() & 0o022 == 0,
        "unsafe fence dir {}",
        path.display()
    );
    Ok(())
}
fn anchor() -> PathBuf {
    Path::new(REG).join("mask")
}
fn id(path: &Path) -> Result<(u64, u64)> {
    let m = fs::symlink_metadata(path)?;
    Ok((m.dev(), m.ino()))
}
fn own_link(path: &Path) -> Result<bool> {
    linked_to(path, &anchor())
}
fn linked_to(path: &Path, anchor: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(m.file_type().is_symlink()
            && m.uid() == 0
            && id(path)? == id(anchor)?
            && fs::read_link(path)? == Path::new("/dev/null")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn list_dynamic() -> Result<()> {
    // The old sweep chooses a sequence at runtime. Its sole controller is masked too.
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--all",
            "--full",
            "--no-legend",
            "--plain",
            "--no-pager",
            "jetstreamer-root-sweep-e159-173-t1-20261016-v1-r2-e171-173-*",
            "jetstreamer-root-source-recovery-e159-173-t1-20261016-v1-r2-e171-173-*",
            "horizon-qualify-171-*",
            "horizon-replacement-171-*",
            "horizon-guard-replacement-171-*",
            "horizon-guard-171-*",
            "horizon-local-replacement171-*",
        ])
        .output()?;
    ensure!(out.status.success(), "PID1 launch-family inventory");
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let u = line
            .split_whitespace()
            .next()
            .context("empty inventory row")?;
        ensure!(closed(&show(u)?), "live/queued donor-family unit {u}");
        cgroup_empty(u)?;
    }
    Ok(())
}
fn reload() -> Result<()> {
    ensure!(
        Command::new("/usr/bin/systemctl")
            .arg("daemon-reload")
            .status()?
            .success(),
        "PID1 reload"
    );
    Ok(())
}
fn check_mask(native: &Value, logical: bool) -> Result<()> {
    ensure!(
        logical && native["LoadState"] == "masked" && closed(native),
        "donor route is launchable/occupied: {}",
        native["Id"]
    );
    Ok(())
}
fn current(units: &BTreeSet<String>) -> Result<Value> {
    safe_dir(Path::new(REG))?;
    safe_dir(Path::new(HIGH))?;
    ensure!(
        fs::read_link(anchor())? == Path::new("/dev/null"),
        "foreign mask anchor"
    );
    list_dynamic()?;
    for u in units {
        let state = show(u)?;
        check_mask(&state, own_link(&Path::new(HIGH).join(u))?)?;
        cgroup_empty(u)?;
    }
    let (dev, ino) = id(&anchor())?;
    Ok(
        json!({"boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),"device":dev,"mask_inode":ino,"mask_directory":HIGH,"masked_and_physically_drained_units":units,"sealed_donor_recipe":binding(Path::new(RECIPE),RECIPE_SHA),"original_route_plan":binding(Path::new(OLD),OLD_SHA)}),
    )
}
fn cpu_registry() -> PathBuf {
    Path::new(REG).join("standard169-cpu.json")
}

fn recorded_cpu_routes() -> Result<Option<BTreeSet<String>>> {
    let path = cpu_registry();
    match fs::symlink_metadata(&path) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let record: Value = serde_json::from_slice(&root_file(&path, 1 << 20)?)?;
    let routes: BTreeSet<String> = serde_json::from_value(record["standard_routes"].clone())?;
    let (dev, ino) = id(&anchor())?;
    ensure!(
        record["schema"] == "epoch136-standard169-cpu-mask-v1"
            && record["boot"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
            && record["device"] == dev
            && record["mask_inode"] == ino
            && !routes.is_empty()
            && routes.iter().all(|s| standard169::valid_name(s)),
        "invalid standard 169 mask registry"
    );
    Ok(Some(routes))
}

fn combined(legacy: &BTreeSet<String>, cpu: Option<&BTreeSet<String>>) -> BTreeSet<String> {
    let mut result = legacy.clone();
    if let Some(cpu) = cpu {
        result.extend(cpu.iter().cloned());
    }
    result
}

fn preserve_recorded(
    discovered: Option<BTreeSet<String>>,
    recorded: Option<&BTreeSet<String>>,
) -> Result<Option<BTreeSet<String>>> {
    match (discovered, recorded) {
        (current, None) => Ok(current),
        (Some(current), Some(retained)) if current.is_subset(retained) => {
            Ok(Some(retained.clone()))
        }
        _ => anyhow::bail!("different CPU mask registry"),
    }
}

fn verified_masks(cpu: bool) -> Result<Value> {
    let recorded = recorded_cpu_routes()?;
    ensure!(
        recorded.is_some() == cpu,
        "different donor generation already holds this registry"
    );
    if let Some(units) = &recorded {
        ensure!(
            standard169::routes()?.is_subset(units),
            "new standard 169 launch route is outside the CPU fence"
        );
    }
    let mut result = current(&combined(&paths()?, recorded.as_ref()))?;
    if let Some(units) = recorded {
        let path = cpu_registry();
        result["standard169_cpu_lease"] = json!({"registry":binding(&path,&format!("{:x}",Sha256::digest(root_file(&path,1<<20)?))),
            "masked_standard_routes":units,"cpu_quota_micros":4_250_000,"unassigned_standard169_cpu_micros":4_750_000,
            "additional_host_cpu_micros":0});
    }
    Ok(result)
}

fn check_destinations(dir: &Path, anchor: &Path, units: &BTreeSet<String>) -> Result<()> {
    for u in units {
        let dst = dir.join(u);
        match fs::symlink_metadata(&dst) {
            Ok(_) => ensure!(
                linked_to(&dst, anchor)?,
                "existing foreign unit fragment at {u}"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn install_links(dir: &Path, anchor: &Path, units: &BTreeSet<String>) -> Result<()> {
    for u in units {
        let dst = dir.join(u);
        if !linked_to(&dst, anchor)? {
            fs::hard_link(anchor, &dst)
                .with_context(|| format!("preexisting foreign mask/fragment for {u}"))?;
        }
    }
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

pub fn establish(cpu: bool) -> Result<Value> {
    let q: Value = serde_json::from_slice(&root_file(&Path::new(BASE).join(QREC), 1 << 20)?)?;
    ensure!(
        q["schema"] == "epoch171-native-mask-qualification-v1"
            && q["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
            && q["positive_before_and_after"] == true
            && q["transient_and_regular_starts_denied"] == true
            && q["mask_directory"] == HIGH
            && q["fixture"] == FIXTURE,
        "native PID1 masking controls missing"
    );
    candidate_state(None)?;
    safe_dir(Path::new("/run"))?;
    safe_dir(Path::new(HIGH))?;
    let previous = recorded_cpu_routes()?;
    let cpu_routes = preserve_recorded(
        if cpu {
            Some(standard169::routes()?)
        } else {
            None
        },
        previous.as_ref(),
    )?;
    let units = combined(&paths()?, cpu_routes.as_ref());
    list_dynamic()?;
    for u in &units {
        ensure!(closed(&show(u)?), "queued/live donor {u}");
        cgroup_empty(u)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(REG) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    safe_dir(Path::new(REG))?;
    match symlink("/dev/null", anchor()) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(anchor())?;
    ensure!(
        m.uid() == 0
            && m.file_type().is_symlink()
            && fs::read_link(anchor())? == Path::new("/dev/null"),
        "foreign mask anchor"
    );
    let prior = recorded_cpu_routes()?;
    ensure!(
        prior == previous,
        "donor mask registry changed during preflight"
    );
    // Inspect the whole name set for collisions before adding the first mask.
    // A previously interrupted transaction can resume with its original inode.
    check_destinations(Path::new(HIGH), &anchor(), &units)?;
    if let Some(routes) = &cpu_routes {
        ensure!(
            routes.iter().all(|s| standard169::valid_name(s))
                && (prior.is_some() || m.nlink() == 1),
            "mixed donor generations or unexpected standard unit name"
        );
        let (dev, ino) = id(&anchor())?;
        file_write(
            &cpu_registry(),
            &json!({"schema":"epoch136-standard169-cpu-mask-v1",
            "boot":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
            "device":dev,"mask_inode":ino,"standard_routes":routes}),
        )?;
    }
    install_links(Path::new(HIGH), &anchor(), &units)?;
    reload()?;
    // A start during mask installation is detected here; keep the fence, refuse admission.
    verified_masks(cpu)
}
pub fn check(cpu: bool) -> Result<Value> {
    verified_masks(cpu)
}
pub fn release() -> Result<()> {
    candidate_state(None)?;
    for suffix in ["service", "timer"] {
        let u = format!("{GUARD}.{suffix}");
        ensure!(closed(&show(&u)?), "candidate guard still live");
        cgroup_empty(&u)?;
    }
    let recorded = recorded_cpu_routes()?;
    let us = combined(&paths()?, recorded.as_ref());
    safe_dir(Path::new(REG))?;
    check_destinations(Path::new(HIGH), &anchor(), &us)?;
    for u in &us {
        let p = Path::new(HIGH).join(u);
        match fs::symlink_metadata(&p) {
            Ok(_) => {
                ensure!(own_link(&p)?, "foreign fence entry {u}");
                fs::remove_file(p)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    fs::File::open(HIGH)?.sync_all()?;
    reload()?;
    for u in &us {
        ensure!(closed(&show(u)?), "unexpected donor activation on return");
    }
    if recorded.is_some() {
        fs::remove_file(cpu_registry())?;
    }
    fs::remove_file(anchor())?;
    fs::remove_dir(REG)?;
    Ok(())
}
/// Idempotent native closure for an interrupted or completed incident session.
pub(super) fn confirm_released(cpu: &BTreeSet<String>) -> Result<()> {
    candidate_state(None)?;
    for unit in [
        WRITER_UNIT.to_owned(),
        format!("{GUARD}.service"),
        format!("{GUARD}.timer"),
    ] {
        ensure!(
            closed(&show(&unit)?),
            "136 producer, writer or guard is live: {unit}"
        );
        cgroup_empty(&unit)?;
    }
    ensure!(
        fs::symlink_metadata(REG).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "donor registry still present"
    );
    for unit in combined(&paths()?, Some(cpu)) {
        ensure!(
            fs::symlink_metadata(Path::new(HIGH).join(&unit))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                && closed(&show(&unit)?),
            "unexpected mask, queued or active donor {unit}"
        );
        cgroup_empty(&unit)?;
    }
    Ok(())
}
pub(super) fn finish_release(cpu: &BTreeSet<String>) -> Result<()> {
    candidate_state(None)?;
    for unit in [
        WRITER_UNIT.to_owned(),
        format!("{GUARD}.service"),
        format!("{GUARD}.timer"),
    ] {
        ensure!(
            closed(&show(&unit)?),
            "cannot release a live or queued 136 owner: {unit}"
        );
        cgroup_empty(&unit)?;
    }
    if fs::symlink_metadata(REG).is_ok() {
        safe_dir(Path::new(REG))?;
        if fs::read_dir(REG)?.next().is_none() {
            // The writer may have failed just after mkdir, or the releaser after unlinking its anchor.
            fs::remove_dir(REG)?;
        } else {
            release()?;
        }
    }
    confirm_released(cpu)
}

pub fn ancestry() -> Result<Value> {
    let b = json_pin(Path::new(BOOK), BOOK_SHA)?;
    let pt = &b["qualified_remaining_growth_memory_point"];
    let v = json_pin(
        Path::new(pt["path"].as_str().context("point")?),
        pt["sha256"].as_str().context("point digest")?,
    )?;
    ensure!(
        b["candidate_own_DATA_bytes"] == (288u64 << 30)
            && b["candidate_guard_metadata_DATA_bytes"] == (8u64 << 30)
            && v["plan"]["candidate_actor_memory_bytes"] == CANDIDATE_MEMORY
            && v["plan"]["candidate_guard_memory_bytes"] == (1u64 << 30),
        "wrong donor amount"
    );
    let wit = json_pin(Path::new(WIT), WIT_SHA)?;
    let row = wit["slots"]
        .as_array()
        .context("original bookings")?
        .iter()
        .find(|r| r["epoch"] == 171)
        .context("171 witness")?;
    ensure!(
        row["lane_root"] == DONOR_ROOT
            && row["original_booking"] == binding(Path::new(BOOK), BOOK_SHA)
            && row["members"] == json!([])
            && row["physical_ledger"].is_null(),
        "overlapping 171 DATA fulfillment"
    );
    let a = json_pin(Path::new(AUTH), AUTH_SHA)?;
    ensure!(
        a["all_seven_original_producers_and_caps_preserved"] == true
            && a["complete_projected_memory_bytes"] == 759789531136u64,
        "historical complete authority"
    );
    let mut current = a;
    let mut chain = vec![binding(Path::new(AUTH), AUTH_SHA)];
    for _ in 0..64 {
        let next = current
            .get("previous_complete_authority")
            .or_else(|| current.get("previous"))
            .context("previous authority")?
            .clone();
        let p = Path::new(next["path"].as_str().context("chain path")?);
        current = json_pin(p, next["sha256"].as_str().context("chain hash")?)?;
        chain.push(next.clone());
        if next == binding(Path::new(BOOK), BOOK_SHA) {
            break;
        }
    }
    ensure!(
        chain.last() == Some(&binding(Path::new(BOOK), BOOK_SHA)),
        "donor missing in present authority lineage"
    );
    let map = json_pin(Path::new(MAP), MAP_SHA)?;
    let retired = json_pin(Path::new(RET), RET_SHA)?;
    ensure!(
        map["epoch"] == 171
            && map["same_original_lane_root"] == DONOR_ROOT
            && map["all_original_promises_retained"] == true
            && retired["hard_promises_released_bytes"] == 0
            && retired["resource_credit_bytes"] == 0,
        "slot ending changed"
    );
    Ok(
        json!({"donor":171,"borrower":136,"original_booking":row["original_booking"],"memory_point":pt,"witness_set":binding(Path::new(WIT),WIT_SHA),"exclusive_local2_mapping":binding(Path::new(MAP),MAP_SHA),"terminal_retirement":binding(Path::new(RET),RET_SHA),"complete_authority_to_donor":chain,"actor_cap_bytes":CANDIDATE_MEMORY,"guard_cap_bytes":1u64<<30}),
    )
}
const FIXTURE: &str = "horizon-donor171-g1-pid1-interlock-qualification.service";
const QREC: &str = "donor171-pid1-qualification.json";
// Prove the same manager rejects a transient StartTransientUnit at a masked, previously unused name.
// This runs only in the parent's booked native qualification; it never addresses a replay unit.
pub fn qualify_pid1() -> Result<()> {
    let file = Path::new(HIGH).join(FIXTURE);
    safe_dir(Path::new(HIGH))?;
    ensure!(
        show(FIXTURE)?["LoadState"] == "not-found"
            && fs::symlink_metadata(&file).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "fixture already present"
    );
    let run = || {
        Command::new("/usr/bin/systemd-run")
            .args([
                "--quiet",
                "--collect",
                "--wait",
                "--pipe",
                "--property=MemoryMax=16M",
                "--property=CPUQuota=10%",
                "--property=TasksMax=4",
                "--unit",
                FIXTURE,
                "/usr/bin/true",
            ])
            .output()
    };
    let before = run()?;
    ensure!(before.status.success(), "positive systemd-run failed");
    symlink("/dev/null", &file)?;
    let mark = id(&file)?;
    let test = (|| -> Result<()> {
        reload()?;
        let s = show(FIXTURE)?;
        check_mask(&s, true)?;
        let blocked = run()?;
        ensure!(
            !blocked.status.success() && show(FIXTURE)?["LoadState"] == "masked",
            "PID1 allowed transient over the mask"
        );
        let blocked = Command::new("/usr/bin/systemctl")
            .args(["start", "--", FIXTURE])
            .output()?;
        ensure!(
            !blocked.status.success() && show(FIXTURE)?["LoadState"] == "masked",
            "PID1 allowed ordinary start over the mask"
        );
        cgroup_empty(FIXTURE)?;
        Ok(())
    })();
    ensure!(
        id(&file)? == mark,
        "qualification fixture replaced during check"
    );
    fs::remove_file(&file)?;
    reload()?;
    test?;
    ensure!(
        run()?.status.success(),
        "positive after returning fixture failed"
    );
    let r = json!({"schema":"epoch171-native-mask-qualification-v1","boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),"positive_before_and_after":true,"transient_and_regular_starts_denied":true,"mask_directory":HIGH,"fixture":FIXTURE});
    let receipt = file_write(&Path::new(BASE).join(QREC), &r)?;
    println!("{receipt}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires root and the current host's immutable epoch 169 launch history"]
    fn actual_standard_routes_install_and_resume_with_one_private_anchor() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        let anchor = root.join("anchor");
        let dir = root.join("control");
        fs::create_dir(&dir).unwrap();
        symlink("/dev/null", &anchor).unwrap();
        let units = standard169::routes().unwrap();
        assert!(units.len() >= 34 && units.iter().all(|s| standard169::valid_name(s)));
        let first = dir.join(units.first().unwrap());
        let last = dir.join(units.last().unwrap());
        symlink("/dev/null", &last).unwrap();
        assert!(check_destinations(&dir, &anchor, &units).is_err());
        assert!(fs::symlink_metadata(&first).is_err());
        fs::remove_file(&last).unwrap();
        fs::hard_link(&anchor, &first).unwrap();
        check_destinations(&dir, &anchor, &units).unwrap();
        install_links(&dir, &anchor, &units).unwrap();
        check_destinations(&dir, &anchor, &units).unwrap();
        install_links(&dir, &anchor, &units).unwrap();
        assert_eq!(
            fs::symlink_metadata(&anchor).unwrap().nlink() as usize,
            units.len() + 1
        );
        for u in &units {
            assert!(linked_to(&dir.join(u), &anchor).unwrap());
            fs::remove_file(dir.join(u)).unwrap();
        }
        assert!(fs::read_dir(&dir).unwrap().next().is_none());
        assert_eq!(fs::symlink_metadata(&anchor).unwrap().nlink(), 1);
    }
    #[test]
    fn cpu_loan_keeps_collected_names_and_rejects_unfenced_launch_routes() {
        let legacy = BTreeSet::from(["common.service".to_owned()]);
        let full = BTreeSet::from(["common.service".to_owned(), "old169.service".to_owned()]);
        assert_eq!(combined(&legacy, Some(&full)), full);
        assert_eq!(
            preserve_recorded(Some(legacy.clone()), Some(&full)).unwrap(),
            Some(full.clone())
        );
        assert!(preserve_recorded(Some(full), Some(&legacy)).is_err());
        assert!(preserve_recorded(None, Some(&legacy)).is_err());
        assert_eq!(preserve_recorded(None, None).unwrap(), None);
    }
    #[test]
    fn mask_and_native_drain_are_both_required() {
        let v = json!({"Id":"x.service","ActiveState":"inactive","MainPID":"0","ControlPID":"0","Job":"","LoadState":"masked"});
        assert!(check_mask(&v, true).is_ok());
        assert!(check_mask(&v, false).is_err());
        for (field, val) in [
            ("MainPID", "1"),
            ("ControlPID", "5"),
            ("Job", "1"),
            ("ActiveState", "active"),
            ("LoadState", "loaded"),
        ] {
            let mut bad = v.clone();
            bad[field] = json!(val);
            assert!(check_mask(&bad, true).is_err());
        }
    }
}
