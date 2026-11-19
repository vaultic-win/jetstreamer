//! Three-peer successor of the deployed home-backed audit v9 cycle.
//! Bind an accepted observation/status cycle and arm its one successor timer.
//! No replay, archive, admission or reservation-ending authority.
#[allow(dead_code)]
#[path = "../../../horizon_retry6_170_guarded_launch_20261119_v1/src/audit_budget.rs"]
mod audit_budget;
#[allow(dead_code)]
#[path = "../observer170_join.rs"]
mod observer170_join;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
};
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const BASE_DATA: u64 = 6_794_761_027_378;
const OLD166_DATA: u64 = 309_237_645_312;
const AUDIT_STATE: &str = "/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1";
const AUDIT_READERS: &str = "/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1";
const HOME_RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const INVENTORY_SHA: &str = "d38d5146d50b7788cf5866fa0f7f5aeefade92fbf0496398fee334b480b7084e";

fn integer(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("missing integer {key}"))
}
fn home_available() -> Result<u64> {
    let p = std::ffi::CString::new("/home/sol")?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), s.as_mut_ptr()) } == 0,
        "home statvfs failed"
    );
    let s = unsafe { s.assume_init() };
    s.f_bavail
        .checked_mul(s.f_frsize)
        .context("home free space overflow")
}
fn audit_json(path: &Path) -> Result<(Value, String)> {
    ensure!(path.canonicalize()? == path, "audit metadata path changed");
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 16 << 20,
        "unsafe audit metadata"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take((16 << 20) + 1)
        .read_to_end(&mut bytes)?;
    let after = f.metadata()?;
    ensure!(
        bytes.len() as u64 == m.len()
            && m.len() == after.len()
            && m.mtime() == after.mtime()
            && m.mtime_nsec() == after.mtime_nsec()
            && m.ctime() == after.ctime()
            && m.ctime_nsec() == after.ctime_nsec(),
        "audit metadata changed during read"
    );
    Ok((serde_json::from_slice(&bytes)?, sha(&bytes)))
}
// Metadata census only: never read an archive body, follow a symlink or count a
// shared inode as exclusive working space. Vanished build temporaries grant no credit.
fn audit_allocated(path: &Path, dev: u64, seen: &mut BTreeSet<(u64, u64)>) -> Result<u64> {
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        m.dev() == dev && (m.is_dir() || m.is_file() || m.file_type().is_symlink()),
        "unexpected audit filesystem or file type"
    );
    if (m.is_file() && m.nlink() > 1) || !seen.insert((m.dev(), m.ino())) {
        return Ok(0);
    }
    let mut bytes = m.blocks().checked_mul(512).context("allocation overflow")?;
    if m.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            bytes = bytes
                .checked_add(audit_allocated(&entry?.path(), dev, seen)?)
                .context("working allocation overflow")?;
        }
    }
    Ok(bytes)
}
fn audit_growth(obligation: &Value, archive: u64, resident: u64, working: u64) -> Result<Value> {
    audit_budget::validate_fleet_obligation(obligation)?;
    ensure!(
        archive <= integer(obligation, "archive_acceptance_ceiling_bytes")?,
        "audit archive exceeds its acceptance ceiling"
    );
    let archive_growth = archive
        .checked_sub(resident)
        .context("resident exceeds archive")?;
    let working_growth = integer(obligation, "working_allocation_cap_bytes")?
        .checked_sub(working)
        .context("audit working cap exceeded")?;
    // There is no exclusive Cargo-cache baseline: preserve the entire admitted
    // allowance, rather than invent credit from the shared cache's current size.
    let cargo_growth = integer(obligation, "cargo_growth_allowance_bytes")?;
    let growth = archive_growth
        .checked_add(working_growth)
        .and_then(|n| n.checked_add(cargo_growth))
        .context("audit growth overflow")?;
    Ok(
        json!({"archive_bytes":archive,"resident_archive_bytes":resident,
        "working_allocated_bytes":working,"remaining_archive_growth_bytes":archive_growth,
        "remaining_working_growth_bytes":working_growth,"remaining_cargo_growth_allowance_bytes":cargo_growth,
        "remaining_DATA_growth_bytes":growth,"resident_bytes_already_excluded_from_free_space":true,
        "largest_archive_booked":false,"cargo_growth_credit_claimed":false,
        "resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}
fn home_audit_snapshot(previous: &Value, recorded_at: u64) -> Result<Value> {
    if let Some(next) = previous["next_audit_routine_observation_not_before_unix"].as_u64() {
        ensure!(recorded_at >= next, "audit cadence is not due");
    }
    let native = audit_budget::observe()?;
    let free_before = home_available()?;
    let obligation = audit_budget::fleet_obligation();
    let state = Path::new(AUDIT_STATE);
    let dev = fs::metadata("/home/sol")?.dev();
    for path in [state, Path::new(AUDIT_READERS), Path::new(HOME_RUNTIME)] {
        ensure!(
            path.canonicalize()? == path && fs::metadata(path)?.dev() == dev,
            "audit/output directory is not home-backed"
        );
    }
    let (inventory, inventory_sha) = audit_json(&state.join("inventory.json"))?;
    ensure!(
        inventory_sha == INVENTORY_SHA,
        "frozen audit inventory changed"
    );
    let (progress, progress_sha) = audit_json(&state.join("progress.json"))?;
    ensure!(
        progress["schema"] == "horizon-r2-chronological-audit-progress-v1"
            && progress["pid"] == 2_285_828u64
            && progress["remote_mutations"] == false
            && progress["external_scratch"].is_null()
            && progress["scratch_directory"] == format!("{AUDIT_STATE}/scratch")
            && progress["reserve_bytes"] == obligation["configured_free_floor_bytes"]
            && progress["max_archive_bytes"] == obligation["archive_acceptance_ceiling_bytes"],
        "audit progress is not the admitted v8 controller"
    );
    let phase = progress["phase"].as_str().context("audit phase")?;
    ensure!(
        matches!(
            phase,
            "qualifying_reader"
                | "waiting_for_reader"
                | "waiting_for_capacity"
                | "waiting_for_transfer_retry"
                | "downloading"
                | "verifying_copied_download"
                | "playing_entire_epoch"
                | "replaying_after_reader_change"
                | "complete"
        ),
        "unknown audit phase"
    );
    let epoch = progress["epoch"].as_u64();
    let object = if let Some(epoch) = epoch {
        let objects: Vec<_> = inventory["objects"]
            .as_array()
            .context("inventory objects")?
            .iter()
            .filter(|o| o["epoch"] == epoch)
            .collect();
        ensure!(
            objects.len() == 1,
            "audit epoch missing or duplicated in inventory"
        );
        Some(objects[0])
    } else {
        ensure!(phase == "complete", "unfinished audit has no epoch");
        None
    };
    let archive_bytes = object
        .map(|o| integer(o, "bytes"))
        .transpose()?
        .unwrap_or(0);
    if let Some(bytes) = progress["archive_bytes"].as_u64() {
        ensure!(
            bytes == archive_bytes,
            "progress archive differs from frozen inventory"
        );
    }
    let scratch = state.join("scratch");
    let entries = fs::read_dir(&scratch)?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() <= 1,
        "audit has unknown concurrent scratch files"
    );
    let resident = if let Some(entry) = entries.first() {
        let object = object.context("completed audit still holds scratch")?;
        let key = object["key"].as_str().context("archive key")?;
        ensure!(
            entry.file_name() == std::ffi::OsStr::new(key),
            "scratch epoch differs"
        );
        let m = fs::symlink_metadata(entry.path())?;
        let (owner, owner_sha) = audit_json(&state.join("scratch-owner.json"))?;
        ensure!(
            m.is_file()
                && m.dev() == dev
                && m.uid() == 0
                && m.nlink() == 1
                && m.len() <= archive_bytes
                && owner["key"] == key
                && owner["identity"]["device"] == m.dev()
                && owner["identity"]["inode"] == m.ino()
                && owner["identity"]["uid"] == 0
                && owner["external_scratch"].is_null(),
            "audit scratch custody differs"
        );
        let allocated = m
            .blocks()
            .checked_mul(512)
            .context("archive allocation overflow")?;
        json!({"path":entry.path(),"device":m.dev(),"inode":m.ino(),"logical_bytes":m.len(),
            "allocated_bytes":allocated,"credited_resident_bytes":allocated.min(archive_bytes),
            "owner_sha256":owner_sha})
    } else {
        ensure!(
            !state.join("scratch-owner.json").try_exists()?,
            "audit cleanup/creation in progress"
        );
        ensure!(
            !matches!(
                phase,
                "playing_entire_epoch"
                    | "replaying_after_reader_change"
                    | "verifying_copied_download"
            ),
            "resident playback has no owned archive"
        );
        Value::Null
    };
    let mut seen = BTreeSet::new();
    let mut working = audit_allocated(Path::new(AUDIT_READERS), dev, &mut seen)?;
    for entry in fs::read_dir(state)? {
        let entry = entry?;
        if entry.file_name() != "scratch" {
            working = working
                .checked_add(audit_allocated(&entry.path(), dev, &mut seen)?)
                .context("working allocation overflow")?;
        }
    }
    let (after, after_sha) = audit_json(&state.join("progress.json"))?;
    for key in [
        "pid",
        "epoch",
        "phase",
        "reserve_bytes",
        "max_archive_bytes",
        "scratch_directory",
    ] {
        ensure!(
            after[key] == progress[key],
            "audit phase changed during cycle; no coherent allocation"
        );
    }
    if !resident.is_null() {
        let path = Path::new(resident["path"].as_str().context("resident path")?);
        let m = fs::symlink_metadata(path)?;
        let (_, owner_sha) = audit_json(&state.join("scratch-owner.json"))?;
        ensure!(
            m.dev() == integer(&resident, "device")?
                && m.ino() == integer(&resident, "inode")?
                && m.uid() == 0
                && m.nlink() == 1
                && m.is_file()
                && m.len() <= archive_bytes
                && m.blocks().checked_mul(512).context("allocation overflow")?
                    >= integer(&resident, "allocated_bytes")?
                && owner_sha == resident["owner_sha256"].as_str().context("owner hash")?,
            "audit resident allocation changed destructively"
        );
    } else {
        ensure!(
            fs::read_dir(&scratch)?.next().is_none()
                && !state.join("scratch-owner.json").try_exists()?,
            "audit scratch appeared during census"
        );
    }
    ensure!(
        audit_budget::observe()? == native,
        "audit native identity changed during cycle"
    );
    let (summary, summary_sha) = audit_json(&state.join("summary.json"))?;
    let (child, child_sha) = audit_json(&state.join("child.json"))?;
    let growth = audit_growth(
        &obligation,
        archive_bytes,
        resident["credited_resident_bytes"].as_u64().unwrap_or(0),
        working,
    )?;
    Ok(
        json!({"schema":"horizon-home-audit-cycle-observation-v1","recorded_unix_seconds":recorded_at,
        "native":native,"progress":progress,"progress_sha256":progress_sha,"progress_after_sha256":after_sha,
        "inventory_sha256":inventory_sha,"resident_archive":resident,"growth":growth,
        "last_written_summary":summary,"summary_sha256":summary_sha,
        "last_written_child":child,"child_sha256":child_sha,
        "conservative_available_DATA_bytes":free_before.min(home_available()?),
        "shared_audit_budget_source_sha256":audit_budget::compiled_source_sha256(),
        "remote_mutations":false,"replay_launch_authorized":false,"admission_authority":false}),
    )
}
fn validate_predecessor_obligations(previous: &Value) -> Result<()> {
    ensure!(
        previous["retained_retry6_166_DATA_bytes"] == OLD166_DATA
            && previous["complete_projected_memory_bytes"] == 761_131_708_416u64
            && previous["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true,
        "complete predecessor promises required"
    );
    let previous_total = integer(previous, "complete_DATA_bytes")?;
    if previous_total != BASE_DATA {
        let authority = &previous["complete_DATA_authority"];
        ensure!(
            authority["base_replay_bytes"] == BASE_DATA
                && authority["old166scratch_obligation_unchanged"] == OLD166_DATA
                && BASE_DATA.checked_add(integer(
                    authority,
                    "current_audit_archive_plus_working_and_cache_allowance_bytes"
                )?) == Some(previous_total),
            "unrecognized predecessor DATA accounting; never discard another obligation"
        );
    }
    Ok(())
}
fn reconcile_home_audit(
    fleet: &mut Value,
    previous: &Value,
    observation: &Value,
    evidence: &Value,
) -> Result<()> {
    validate_predecessor_obligations(previous)?;
    let mut obligation = audit_budget::fleet_obligation();
    obligation["current_observation"] = evidence.clone();
    obligation["fresh_native_observation_claimed"] = json!(true);
    obligation["current_storage"] = observation["growth"].clone();
    audit_budget::validate_fleet_obligation(&obligation)?;
    fleet["historical_previous_audit_obligation"] = previous["continuing_audit_obligation"].clone();
    fleet["continuing_audit_obligation"] = obligation;
    // complete_DATA_bytes is the existing lane contract, not a free-space test.
    // Its unchanged replay promises remain independently bound. Report the audit
    // remainder in an explicit total; admissions must remeasure both constraints.
    fleet["historical_previous_complete_DATA_authority"] =
        previous["complete_DATA_authority"].clone();
    fleet["complete_DATA_bytes"] = json!(BASE_DATA);
    fleet["complete_DATA_authority"] = json!({"base_replay_bytes":BASE_DATA,
        "old166scratch_obligation_unchanged":OLD166_DATA,
        "complete_DATA_bytes_scope":"unchanged replay contract; additive audit growth is separate",
        "resident_audit_bytes_already_excluded_from_available_space":true,
        "current_audit_growth":evidence,"booked_whole_largest_archive":false,
        "resource_credit_bytes":0,"promise_ending_bytes":0});
    fleet["complete_DATA_with_remaining_audit_growth_bytes"] = json!(
        BASE_DATA
            .checked_add(integer(
                &observation["growth"],
                "remaining_DATA_growth_bytes"
            )?)
            .context("complete DATA overflow")?
    );
    fleet["current_home_audit_observation"] = evidence.clone();
    fleet["current_audit_progress"] = json!({"observation":evidence,"field":"progress"});
    fleet["current_audit_child"] = json!({"observation":evidence,"field":"last_written_child"});
    fleet["last_accepted_audit_summary"] =
        json!({"observation":evidence,"field":"last_written_summary"});
    if previous["audit77_root_capacity_blocker"].is_object() {
        fleet["historical_audit77_root_capacity_blocker"] =
            previous["audit77_root_capacity_blocker"].clone();
    }
    fleet
        .as_object_mut()
        .context("fleet object")?
        .remove("audit77_root_capacity_blocker");
    fleet["audit_conservative_available_DATA_bytes"] =
        observation["conservative_available_DATA_bytes"].clone();
    fleet["complete_cycle_conservative_available_DATA_bytes"] = json!(
        integer(fleet, "same_sample_conservative_free_DATA_bytes")?
            .min(integer(observation, "conservative_available_DATA_bytes")?)
    );
    fleet["audit_home_storage_start_event"] =
        fleet["continuing_audit_obligation"]["home_storage_start_event"].clone();
    fleet["next_audit_routine_observation_not_before_unix"] = json!(
        integer(observation, "recorded_unix_seconds")?
            .checked_add(1800)
            .context("audit next clock overflow")?
    );
    fleet["new_resource_observations"] = json!(true);
    fleet["cycle_reconciliation_scope"] = json!(
        "Accepted replay observer and authenticated statuses, plus one cadence-bound home audit observation; all prior lane promises retained. Not fresh admission authority."
    );
    Ok(())
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn bind(p: &str) -> Result<Value> {
    Ok(json!({"path":p,"sha256":sha(&fs::read(p)?)}))
}
fn run(c: &mut Command) -> Result<String> {
    let o = c.output()?;
    ensure!(
        o.status.success(),
        "command {c:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(String::from_utf8(o.stdout)?)
}
fn read(p: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn write(p: &str, v: &Value) -> Result<Value> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    f.write_all(&serde_json::to_vec_pretty(v)?)?;
    f.sync_all()?;
    File::open(Path::new(p).parent().context("parent")?)?.sync_all()?;
    bind(p)
}
fn clock_labels(stamp: &str) -> Result<(String, String)> {
    ensure!(
        stamp.len() == 20 && stamp.is_ascii(),
        "canonical UTC clock required"
    );
    for (i, b) in stamp.bytes().enumerate() {
        let separator = match i {
            4 | 7 => Some(b'-'),
            10 => Some(b'T'),
            13 | 16 => Some(b':'),
            19 => Some(b'Z'),
            _ => None,
        };
        ensure!(
            separator.map_or_else(|| b.is_ascii_digit(), |s| b == s),
            "invalid UTC clock"
        );
    }
    ensure!(
        (1..=12).contains(&stamp[5..7].parse::<u32>()?)
            && (1..=31).contains(&stamp[8..10].parse::<u32>()?)
            && stamp[11..13].parse::<u32>()? < 24
            && stamp[14..16].parse::<u32>()? < 60
            && stamp[17..19].parse::<u32>()? < 60,
        "invalid clock fields"
    );
    Ok((
        format!("{}{}{}", &stamp[..4], &stamp[5..7], &stamp[8..10]),
        format!("{}{}", &stamp[11..13], &stamp[14..16]),
    ))
}
fn phase(work: &Value) -> &'static str {
    if work["sufficient_for_rates"] == true
        && work["transaction_delta"].as_u64().is_some_and(|n| n > 0)
    {
        "replay"
    } else {
        "bootstrap"
    }
}
fn preserve_audit_recovery(fleet: &mut Value, previous: &Value) -> Result<()> {
    let recovered = &previous["audit_transfer73_repair"];
    if recovered["recovery_pass_claimed"] != true {
        return Ok(());
    }
    let result_path = recovered["result"]["path"]
        .as_str()
        .context("audit result path")?;
    let cleanup_path = recovered["cleanup"]["path"]
        .as_str()
        .context("audit cleanup path")?;
    ensure!(
        bind(result_path)? == recovered["result"]
            && recovered["result"]["sha256"]
                == "fe81955c789dc385a569ea78d726366837f258fb0faded2d287627cdbf7dae9f"
            && bind(cleanup_path)? == recovered["cleanup"]
            && recovered["cleanup"]["sha256"]
                == "dfc7720c62b98b8fb8a8051819da121943eceb95372549e20b17636d6ef9a2f3",
        "audit recovery evidence changed"
    );
    let result = read(result_path)?;
    let cleanup = read(cleanup_path)?;
    ensure!(
        result["epoch"] == 73
            && result["status"] == "passed"
            && result["playback"]["clean_process_exit"] == true
            && result["playback"]["first_slot"] == 31536000
            && result["playback"]["last_slot"] == 31967999
            && result["playback"]["counters"]["slots"] == 432000
            && cleanup["epoch"] == 73
            && cleanup["removed_only_owned_audit_copy"] == true,
        "full audit recovery required"
    );
    fleet["historical_audit_transfer73_repair"] = fleet["audit_transfer73_repair"].clone();
    fleet["audit_transfer73_repair"] = recovered.clone();
    fleet["audit_transfer73_repair"]["fresh_audit_observation_claimed"] = json!(false);
    fleet["audit_milestone_gent_submission"] = previous["audit_milestone_gent_submission"].clone();
    Ok(())
}
fn exact167_native(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == "horizon-qualify-167-replacement-local3retry7-20261110-v1.service"
            && v["InvocationID"] == "a680103e76f546faaf469aa80c35fa3b"
            && v["MainPID"] == "1871809"
            && v["ControlPID"] == "0"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["Job"] == "",
        "actual167 identity changed"
    );
    Ok(())
}
fn preserve_holding166_recovery(fleet: &mut Value, previous: &Value, event: &Value) -> Result<()> {
    ensure!(
        event["schema"] == "horizon-exact-holding166-start-event-v1"
            && event["native"]["Id"] == "horizon-closed166-retry6-park-20261119-v1.service"
            && event["native"]["InvocationID"] == "afc04ba6096f4826836919c2020dcdc6"
            && event["additional_memory_bytes"] == 2147483648u64
            && event["additional_cpu_quota_micros"] == 2000000u64
            && event["additional_DATA_staging_bytes"] == 0
            && event["restore_overlap_bytes"] == 56173984550u64
            && event["resource_credit_bytes"] == 0
            && event["promise_ending_bytes"] == 0
            && previous["continuing_holding166retry6_obligation"] == *event
            && previous["next_lane_recovery"]["epoch"] == 170
            && previous["next_lane_recovery"]["resource_credit_bytes"] == 0,
        "exact holding166 event and unchanged additive budget required"
    );
    for key in [
        "qualified_preparer",
        "qualified_launcher",
        "qualified_stage",
    ] {
        ensure!(
            previous["next_lane_recovery"][key].is_object(),
            "qualified170 successor missing"
        );
    }
    fleet["next_lane_recovery"] = previous["next_lane_recovery"].clone();
    fleet["continuing_holding166retry6_obligation"] = event.clone();
    fleet["holding166_event_is_historical_not_fresh_native_observation"] = json!(true);
    fleet["holding166_admission_requirement"] = json!(
        "Revalidate the exact transfer before admission; retain its 2GiB/2CPU allocation until genuine terminal evidence. Custody and separate retirement are required before any local capacity credit."
    );
    Ok(())
}
fn joined167() -> Result<(Value, Value)> {
    let unit = "horizon-qualify-167-replacement-local3retry7-20261110-v1.service";
    let iid = "a680103e76f546faaf469aa80c35fa3b";
    let admission_path = "/var/lib/jetstreamer/retry7-single167-guarded-launch-20261119-v1/epoch167/ACTUAL_REPLACEMENT_ADMISSION.json";
    let protection_path = "/var/lib/jetstreamer/retry7-single167-guarded-launch-20261119-v1/epoch167/ACTUAL_GUARD_PROTECTION.json";
    let admission = read(admission_path)?;
    let protection = read(protection_path)?;
    ensure!(
        admission["producer_invocation_id"] == iid
            && admission["producer_pid"] == 1871809
            && admission["fresh_admission_passed"] == true
            && protection["admission"] == bind(admission_path)?
            && protection["producer_invocation_id"] == iid,
        "actual167 guarded admission differs"
    );
    let raw = run(Command::new("/usr/bin/systemctl").args(["show", unit,
        "-pId,InvocationID,MainPID,ControlPID,ActiveState,SubState,NRestarts,Job,ExecMainStartTimestampMonotonic"]))?;
    let mut map = serde_json::Map::new();
    for line in raw.lines() {
        let (key, value) = line.split_once('=').context("native property")?;
        ensure!(
            map.insert(key.into(), json!(value)).is_none(),
            "duplicate native property"
        );
    }
    let native = Value::Object(map);
    exact167_native(&native)?;
    let original_path = admission["actual_producer_native"]["path"]
        .as_str()
        .context("original producer")?;
    ensure!(
        bind(original_path)? == admission["actual_producer_native"]
            && read(original_path)?["ExecMainStartTimestampMonotonic"]
                == native["ExecMainStartTimestampMonotonic"]
            && fs::read_link("/proc/1871809/exe")?
                == Path::new(
                    "/usr/local/lib/jetstreamer/horizon-independent167-singleton-package-20261109-v1/jetstreamer-node"
                ),
        "167 process changed"
    );
    let timer = protection["timer_unit"].as_str().context("167 timer")?;
    let timer_raw = run(Command::new("/usr/bin/systemctl").args([
        "show",
        timer,
        "-pActiveState,InvocationID",
    ]))?;
    let timer_iid = protection["timer_invocation_id"]
        .as_str()
        .context("167 timer IID")?;
    ensure!(
        timer_raw.lines().any(|s| s == "ActiveState=active")
            && timer_raw
                .lines()
                .any(|s| s == format!("InvocationID={timer_iid}")),
        "167 protection timer changed"
    );
    let log = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/producer.log";
    let scratch = "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/private/destination-fa04a9e9c489108e13fa7d9a23ad7b245fd0684341dc686041698e23da441581/work/root-cohort-167-167/run-1871809-1795071350250949686/scratch";
    let md = fs::symlink_metadata(log)?;
    ensure!(
        md.is_file()
            && md.dev() == 64512
            && md.uid() == 0
            && md.nlink() == 1
            && fs::symlink_metadata(scratch)?.is_dir(),
        "actual167 log/scratch differs"
    );
    let observer = json!({"controller_unit":unit,"producer_unit":unit,
        "expected_controller_invocation_id":iid,"expected_producer_invocation_id":iid,"range":"167",
        "scratch_path":scratch,"worker_executable_basename":"historical-worker",
        "append_log":{"path":log,"device":md.dev(),"inode":md.ino()}});
    let owner = json!({"epoch":167,"unit":native,"in_current_observer":false,"observer":null,
        "phase":"bootstrap","progress":null,"scratch_path":scratch,"admission":bind(admission_path)?,
        "guard_protection":bind(protection_path)?,"native_identity_source":admission["actual_producer_native"],
        "current_identity_from_same_observation":false,"event_driven_guarded_join":true,
        "transaction_replay_claimed":false,"resource_credit_bytes":0});
    Ok((owner, observer))
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 5,
        "observe_cycle_retry8_homeaudit170 SAMPLE STATUS PREVIOUS_CONFIG PREVIOUS_FLEET"
    );
    let sample = read(&a[1])?;
    let status = read(&a[2])?;
    ensure!(
        sample["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && sample["cadence"]["routine_minimum_interval_enforced"] == true
            && sample["cadence"]["observed_interval_seconds"]
                .as_u64()
                .is_some_and(|v| v >= 1800)
            && status["observer"] == bind(&a[1])?
            && status["authenticated_readback"] == true
            && status["authenticated_status_count"] == 19,
        "accepted cycle required"
    );
    let mut fleet = read(&a[4])?;
    let previous_fleet = fleet.clone();
    ensure!(
        fleet["owner"] == "/root" && fleet["live_replay_count"].as_u64().is_some_and(|v| v <= 3),
        "predecessor fleet differs"
    );
    let audit_recorded_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    // Validate/capture the audit before creating a successor timer. A failed
    // audit observation must not leave a partly armed duplicate cycle.
    let audit_observation = home_audit_snapshot(&previous_fleet, audit_recorded_at)?;
    validate_predecessor_obligations(&previous_fleet)?;
    let rows = sample["replays"].as_array().context("replays")?;
    ensure!(
        (rows.len() == 2 || rows.len() == 3)
            && rows[0]["range"] == "166"
            && rows[0]["invocation_binding_stable"] == true
            && rows[0]["producer_after"]["invocation_id"] == "4f09db5f45074244a45b06aeef932d1d"
            && rows[0]["producer_after"]["active_state"] == "active"
            && rows[0]["producer_after"]["restarts"] == 0,
        "exact healthy166 required"
    );
    {
        ensure!(
            rows[1]["range"] == "167"
                && rows[1]["invocation_binding_stable"] == true
                && rows[1]["producer_after"]["invocation_id"] == "a680103e76f546faaf469aa80c35fa3b"
                && rows[1]["producer_after"]["active_state"] == "active"
                && rows[1]["producer_after"]["restarts"] == 0,
            "exact healthy167 required"
        );
    }
    let (joined167, observer167) = joined167()?;
    let (joined170, observer170) = observer170_join::joined()?;
    if rows.len() == 3 {
        observer170_join::validate_sample(&rows[2], &joined170)?;
    }
    let stamp = sample["recorded_at_utc"].as_str().context("stamp")?;
    let sample_next = sample["cadence"]["next_routine_observation_not_before_utc"]
        .as_str()
        .context("next")?;
    // The audit read happens after the replay sample. Align the sole successor
    // with BOTH 1800-second minima; varying reconciliation latency cannot create
    // an early second audit poll or leave the next cycle unable to run.
    let audit_next_unix = audit_recorded_at
        .checked_add(1800)
        .context("next audit clock")?;
    let audit_next = run(Command::new("/usr/bin/date").args([
        "-u",
        "--date",
        &format!("@{audit_next_unix}"),
        "+%Y-%m-%dT%H:%M:%SZ",
    ]))?;
    let next = sample_next.max(audit_next.trim());
    let (date, tag) = clock_labels(stamp)?;
    let (next_date, next_tag) = clock_labels(next)?;
    ensure!(next > stamp, "successor clock must advance");
    let root =
        format!("{HOME_RUNTIME}/root{tag}-live166retry8-167retry7-170retry6-homeaudit-observation-{date}-v1");
    observer170_join::home(Path::new(HOME_RUNTIME))?;
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let audit_evidence = write(
        &format!("{root}/HOME_AUDIT_OBSERVATION.json"),
        &audit_observation,
    )?;
    let mut config = read(&a[3])?;
    ensure!(
        config["output"] == a[1] && config["minimum_interval_seconds"] == 1800,
        "predecessor observer mismatch"
    );
    config["previous_sample"] = json!(a[1]);
    config["not_before_utc"] = json!(next);
    let diagnostics = config["diagnostic_replays"]
        .as_array_mut()
        .context("diagnostics")?;
    for row in diagnostics.iter().filter(|r| r["range"] == "167") {
        ensure!(
            row["expected_producer_invocation_id"] == "fdfadeb7b76d4760a37983b402fd2771",
            "unexpected old167 diagnostic"
        );
    }
    diagnostics.retain(|r| r["range"] != "167");
    let replays = config["replays"].as_array_mut().context("next replays")?;
    ensure!(
        (replays.len() == 2 || replays.len() == 3) && replays[0]["range"] == "166" && replays[1]["range"] == "167",
        "both original lanes required"
    );
    ensure!(
        replays[1] == observer167,
        "next167 observer identity differs"
    );
    let retired170_diagnostics = observer170_join::merge_config(&mut config, &observer170)?;
    config["output"] = json!(format!(
        "{HOME_RUNTIME}/sample-root{next_tag}-live166retry8-167retry7-170retry6-{next_date}-v1.json"
    ));
    let cpath = format!("{root}/next-observer.json");
    let cb = write(&cpath, &config)?;
    let destination = format!(
        "{HOME_RUNTIME}/horizon-live166retry8-167retry7-170retry6-homeaudit-observer-config-{tag}-{date}-v1"
    );
    let ppath = format!("{root}/seal-plan.json");
    let p = write(
        &ppath,
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,
        "members":[{"source":cpath,"name":"next-observer.json","sha256":cb["sha256"],"mode":292}]}),
    )?;
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    run(Command::new(SEALER).args([
        &ppath,
        "--plan-sha256",
        p["sha256"].as_str().unwrap(),
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    let sealed = format!("{destination}/next-observer.json");
    let unit = format!("horizon-observer-root{next_tag}-live166retry8-167retry7-170retry6-{next_date}-v1");
    ensure!(observer170_join::native(&format!("{unit}.timer"))?["LoadState"] == "not-found"
        && observer170_join::native(&format!("{unit}.service"))?["LoadState"] == "not-found", "successor observer unit already exists");
    let calendar = format!("{} {} UTC", &next[..10], &next[11..19]);
    run(Command::new("/usr/bin/systemd-run").args(["--unit",&unit,"--on-calendar",&calendar,"--timer-property=AccuracySec=1s",
        "--property=Type=oneshot","--property=CPUQuota=200%","--property=MemoryMax=2G","--property=TasksMax=128",
        "/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe",&sealed]))?;
    let timer = run(Command::new("/usr/bin/systemctl").args([
        "show",
        &format!("{unit}.timer"),
        "-p",
        "ActiveState",
        "-p",
        "SubState",
        "-p",
        "NextElapseUSecRealtime",
    ]))?;
    ensure!(
        timer.lines().any(|l| l == "ActiveState=active")
            && timer.lines().any(|l| l == "SubState=waiting"),
        "successor timer not waiting"
    );
    fleet["previous_Root_operational_review"] = bind(&a[4])?;
    fleet["observer"] = bind(&a[1])?;
    fleet["authenticated_status_audit"] = bind(&a[2])?;
    fleet["sampled_at_utc"] = json!(stamp);
    fleet["recorded_unix_seconds"] = json!(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    fleet["sole_next_observer"] = bind(&sealed)?;
    fleet["same_sample_conservative_free_DATA_bytes"] =
        sample["filesystem"]["conservative_available_bytes"].clone();
    let mut executing = Vec::new();
    let mut bootstraps = Vec::new();
    let mut owners = Vec::new();
    for (epoch, prefix) in [
        (
            166,
            "/var/lib/jetstreamer/retry8-single166-guarded-launch-20261119-v1/epoch166",
        ),
        (
            167,
            "/var/lib/jetstreamer/retry7-single167-guarded-launch-20261119-v1/epoch167",
        ),
        (170, observer170_join::PREFIX),
    ] {
        let range = epoch.to_string();
        let observed = rows
            .iter()
            .find(|r| r["range"].as_str() == Some(range.as_str()));
        let Some(observed) = observed else {
            ensure!(epoch == 170, "missing original peer sample");
            bootstraps.push(joined170.clone());
            owners.push(joined170.clone());
            continue;
        };
        let admission_path = format!("{prefix}/ACTUAL_REPLACEMENT_ADMISSION.json");
        let protection_path = format!("{prefix}/ACTUAL_GUARD_PROTECTION.json");
        let admission = read(&admission_path)?;
        let protection = read(&protection_path)?;
        let native_binding = &admission["actual_producer_native"];
        let native_path = native_binding["path"].as_str().context("actual native")?;
        ensure!(
            bind(native_path)? == *native_binding,
            "actual native changed"
        );
        let mut native = read(native_path)?;
        ensure!(
            admission["producer_invocation_id"] == observed["producer_after"]["invocation_id"]
                && admission["producer_pid"] == observed["producer_after"]["main_pid"]
                && protection["admission"] == bind(&admission_path)?,
            "peer admission differs"
        );
        for (upper, lower) in [
            ("ActiveState", "active_state"),
            ("SubState", "sub_state"),
            ("InvocationID", "invocation_id"),
            ("Id", "unit"),
        ] {
            native[upper] = observed["producer_after"][lower].clone();
        }
        native["MainPID"] = json!(
            observed["producer_after"]["main_pid"]
                .as_u64()
                .context("PID")?
                .to_string()
        );
        native["NRestarts"] = json!(
            observed["producer_after"]["restarts"]
                .as_u64()
                .context("restarts")?
                .to_string()
        );
        let phase = phase(&observed["useful_work"]);
        let owner = json!({"epoch":epoch,"unit":native,"in_current_observer":true,"observer":bind(&a[1])?,
            "phase":phase,"progress":observed["useful_work"],"scratch_path":observed["scratch_path"],
            "admission":bind(&admission_path)?,"guard_protection":bind(&protection_path)?,
            "native_identity_source":native_binding,"current_identity_from_same_observation":true});
        if phase == "replay" {
            executing.push(owner.clone());
        } else {
            bootstraps.push(owner.clone());
        }
        owners.push(owner);
    }
    fleet["actual_executing_replays"] = json!(executing);
    fleet["actual_active_bootstraps"] = json!(bootstraps);
    fleet["active_producer_count"] = json!(3);
    fleet["guarded_bootstrap_owner_count"] = json!(bootstraps.len());
    fleet["live_replay_count"] = json!(executing.len());
    fleet["useful_replay_count"] = json!(executing.len());
    fleet["bootstrap_count"] = json!(bootstraps.len());
    for row in fleet["epochs"].as_array_mut().context("fleet epochs")? {
        row["current_coordinated_observer"] = bind(&a[1])?;
        let epoch = row["epoch"].as_u64().context("epoch")?;
        if let Some(binding) = status["receipts"].get(epoch.to_string()) {
            let path = binding["path"].as_str().context("status path")?;
            ensure!(bind(path)? == *binding, "status binding differs");
            let receipt = read(path)?;
            ensure!(
                receipt["authenticated_readback"] == true && receipt["epoch"] == epoch,
                "authenticated status differs"
            );
            row["status_publication"] = binding.clone();
            row["current_authenticated_status_receipt"] = binding.clone();
            row["current_status"] = receipt["after_status"].clone();
            row["status"] = receipt["after_status"].clone();
        }
        if let Some(owner) = owners.iter().find(|o| o["epoch"] == epoch) {
            row["current_replay"] = owner.clone();
            row["no_live_producer_claimed"] = json!(false);
            row["state"] = owner["phase"].clone();
            row["current_repair_owner"] = Value::Null;
        }
    }
    fleet["new_resource_observations"] = json!(false);
    fleet["replay_launch_authorized"] = json!(false);
    fleet["cycle_reconciliation_scope"] = json!(
        "Same accepted observer and authenticated statuses; prior census/history retained explicitly; not fresh admission authority."
    );
    let current167 = status["receipts"]["167"]["path"]
        .as_str()
        .context("current167 status receipt")?;
    ensure!(
        bind(current167)? == status["receipts"]["167"],
        "current167 status binding differs"
    );
    let event167 = read(current167)?;
    if event167["preparation_failure"].is_object() {
        fleet["next_lane_recovery"]["latest_preparation_failure"] =
            event167["preparation_failure"].clone();
        fleet["next_lane_recovery"]["current_status_evidence"] = bind(current167)?;
    }
    let compiler_retirement =
        "/var/lib/jetstreamer/focused169-compiler-retire-20261119-v1/completion.json";
    let compiler_retirement_binding = bind(compiler_retirement)?;
    ensure!(
        compiler_retirement_binding["sha256"]
            == "ea7eed460e5e29d1d1ee1fbc56f8f5ea459edc95ed0879837b484518dab2d390",
        "completed compiler retirement changed"
    );
    fleet["completed_focused169_compiler_retirement"] = compiler_retirement_binding;
    let holding_plan =
        "/usr/local/lib/jetstreamer/horizon-closed169-local2-holding-plan-20261119-v1/plan.json";
    let holding_binding = bind(holding_plan)?;
    ensure!(
        holding_binding["sha256"]
            == "7130ea293ba07365c01599f9eef7640eb1d702ad3def97f32fec89272973b8d8",
        "exact closed169 holding plan changed"
    );
    fleet["continuing_holding169_obligation"] = json!({"plan":holding_binding,
        "unit":"horizon-closed169-local2-park-20261119-v1.service",
        "invocation_id":"3bc22adcd63a4b3fa2bcddad22260e4c",
        "additional_memory_bytes":2147483648u64,"additional_cpu_quota_micros":2000000u64,
        "additional_DATA_staging_bytes":0,"parked_source_length":56565561764u64,
        "potential_restore_overlap_bytes":56565561764u64,
        "resource_credit_bytes":0,"promise_ending_bytes":0,"fresh_native_observation_claimed":false,
        "admission_requirement":"Retain these additive resources until the exact transfer is proven terminal; require authenticated custody and separate local retirement before crediting any DATA, and separately admit any restoration."});
    fleet["completed_snapshot183_retirement"] = bind(
        "/var/lib/jetstreamer/snapshot183-private-retire-20261118-v1/target-0-completion.json",
    )?;
    let mut completed_cleanup = Vec::new();
    for path in [
        "/var/lib/jetstreamer/snapshot152-private-retire-20261118-v1/target-0-completion.json",
        "/var/lib/jetstreamer/snapshot152-private-retire-20261118-v1/target-1-completion.json",
        "/var/lib/jetstreamer/horizon-dev-cache-check-sol-debug-retire-20261118-v2/completion.json",
        "/var/lib/jetstreamer/horizon-dev-cache-check-sol-release-deps-retire-20261118-v2/completion.json",
    ] {
        let receipt = read(path)?;
        ensure!(
            receipt["r2_mutations"] == false
                && (receipt["cache_absent"] == true
                    || (receipt["source_absent"] == true && receipt["quarantine_absent"] == true)),
            "cleanup completion missing"
        );
        completed_cleanup.push(bind(path)?);
    }
    fleet["completed_cleanup_after_2249"] = json!(completed_cleanup);
    let custody141 = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/receipts/custody-435e917094c39e05a8df2ac97cbba71e8470261112dcc2be30fdf56a013c0688.json";
    let custody = read(custody141)?;
    ensure!(
        custody["source"]
            == "/home/sol/.jetstreamer-private/epoch141-ledger-source-20261020-v1/download/rocksdb.tar.bz2"
            && custody["sha256"]
                == "7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b"
            && custody["length"] == 189943475031u64,
        "foreign epoch141 custody"
    );
    fleet["completed_holding141_custody"] = bind(custody141)?;
    let retirement141 = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch141-completion.json";
    let retired = Path::new(retirement141).try_exists()?;
    if retired {
        let completion = read(retirement141)?;
        ensure!(
            completion["schema"] == "jetstreamer-holding-retire141-completion-v1"
                && completion["source_absent"] == true
                && completion["quarantine_absent"] == true
                && completion["authenticated_custody_revalidated"] == true
                && completion["retired_censused_physical_bytes"] == 189943668736u64
                && completion["actual_free_delta_claimed"] == false
                && completion["r2_mutations"] == false,
            "epoch141 retirement incomplete"
        );
        fleet["completed_holding141_retirement"] = bind(retirement141)?;
    }
    fleet["historical_pre167_next_lane_recovery"] = json!({"epoch":167,"last_attempt_unit":"horizon-167-live166retry7-prepare-operation-2058-20261118-v1.service",
        "last_result":"complete166/167/169/170 growth does not fit","required_available_bytes":7493617796914u64,
        "holding_unit":"horizon-closed141-input-park-20261118-v1.service","credited_reclamation_bytes":0,
        "cache_check_result":"Both workspace caches and the two obsolete epoch152 snapshots have been retired with durable receipts. Admission must use actual measured free space, not summed cache-entry blocks.",
        "holding_custody_complete":true,"holding_local_retirement_complete":retired,
        "next_action":if retired {"Refresh epoch167 physical measurement and run fresh preparation and guarded launch including the audit allocation; use actual available bytes."}
            else {"Finish the qualified exact epoch141 local retirement after completed holding custody, then refresh epoch167 measurement and admission including the audit allocation."}});
    fleet["completed_snapshot160_retirement"] = bind(
        "/var/lib/jetstreamer/snapshot160-private-retire-20261119-v1/target-0-completion.json",
    )?;
    let retirement169 = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch169-completion.json";
    if Path::new(retirement169).try_exists()? {
        let completion = read(retirement169)?;
        ensure!(
            completion["schema"] == "jetstreamer-holding-retire169-completion-v1"
                && completion["source_absent"] == true
                && completion["quarantine_absent"] == true
                && completion["authenticated_custody_revalidated"] == true
                && completion["retired_censused_physical_bytes"] == 56565645312u64
                && completion["actual_free_delta_claimed"] == false
                && completion["r2_mutations"] == false
                && completion["intent"]["sha256"]
                    == "33f3b6d1622bb516ce90cc6a5b535038b2403b6056ddb15c49feaa0c70fb742f",
            "epoch169 retirement incomplete"
        );
        fleet["completed_holding169_retirement"] = bind(retirement169)?;
    }
    fleet["next_lane_recovery"] = json!({"epoch":167,"attempt":"local3retry7","source_owner":"/root",
        "qualified_preparer":bind("/usr/local/lib/jetstreamer/horizon-epoch167-retry7-live166retry8-prepare-20261119-v1/artifact-proof.json")?,
        "qualified_guard":bind("/usr/local/lib/jetstreamer/horizon-epoch167-retry7-live166retry8-guard-20261119-v1/artifact-proof.json")?,
        "next_action":"Use this accepted cycle and the actual latest preparation result to capture a fresh witness, complete native preparation and run the launcher native tests, sealed check and guarded launch. Keep all original promises and the audit allocation. Retired allocated bytes alone neither release a reservation nor prove simultaneous fit.",
        "resource_credit_bytes":0});
    fleet["historical_prelaunch167_recovery"] = fleet["next_lane_recovery"].clone();
    let failed170_path = "/home/sol/.jetstreamer-private/r2-status-receipts/event-disk-fit-170-20261119-v1/RECEIPT.json";
    let failed170 = read(failed170_path)?;
    ensure!(
        failed170["epoch"] == 170
            && failed170["authenticated_readback"] == true
            && failed170["preparation_failure"]["new_producer_launched"] == false
            && failed170["preparation_failure"]["deficit_bytes"] == 38663067442u64,
        "actual epoch170 disk-fit failure required"
    );
    fleet["next_lane_recovery"] = json!({"epoch":170,"source_owner":"/root",
        "last_attempt":bind(failed170_path)?,"last_result":"native preparation rejected complete disk fit",
        "observed_deficit_bytes":38663067442u64,
        "next_action":"Qualify additional cleanup or holding retirement, then use fresh measurement and a separately qualified new witness contract. The existing contract is consumed; qualify the preparer/stage/launcher successor including the actual audit v7 identity before guarded admission. Preserve both healthy peers, all retained growth and audit allocations; old reclamation is not new capacity.","resource_credit_bytes":0});
    fleet["recovered167_admission"] = joined167["admission"].clone();
    fleet["completed_historical_compiler_retirement"] =
        bind("/var/lib/jetstreamer/historical-compiler-retire-20261119-v1/completion.json")?;
    fleet["audit_observation0650"] =
        bind("/var/lib/jetstreamer/audit-observation-0650-20261119-v1/status.json")?;
    let audit_transition =
        "/var/lib/jetstreamer/audit-retry-boundary-transition-20261119-v7/COMPLETED.json";
    let audit_event = read(audit_transition)?;
    ensure!(
        audit_event["schema"] == "horizon-audit-idle-runtime-transition-completed-v1"
            && audit_event["successor_invocation_id"] == "ed5d00ac282f4197b188a56974865102"
            && audit_event["same_state_config_resources"] == true
            && audit_event["archive_recovery_pass_claimed"] == false
            && audit_event["remote_mutations"] == false,
        "qualified audit v7 transition required"
    );
    fleet["audit_transfer73_repair"] = json!({"result":bind("/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1/results/epoch-73.json")?,"failure_class":"incomplete network transfer before playback","remote_corruption_established":false,
        "qualified_idle_transition":bind(audit_transition)?,
        "launch_phase":bind("/var/lib/jetstreamer/audit-retry-boundary-transition-20261119-v7/launch-phase.json")?,
        "qualified_image":bind("/usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261119-v7/artifact-proof.json")?,
        "fresh_audit_observation_claimed":false,"recovery_pass_claimed":false,
        "next_action":"Preserve the v7 epoch73 retry and original immutable failure. Use its actual completion event or the next audit observation after the last audit's 1800-second interval; qualify root cleanup for epoch75. This cycle does not claim a fresh audit observation or a recovered pass."});
    preserve_audit_recovery(&mut fleet, &previous_fleet)?;
    let holding_event_path =
        "/var/lib/jetstreamer/root0832-holding166-event-20261119-v1/EVENT.json";
    let event_binding = bind(holding_event_path)?;
    ensure!(
        event_binding["sha256"]
            == "d5beb401ed0e015f371a7123fa34c6772f2d7f88b854d4cb1a01c4c8b2f0a0bb"
            && previous_fleet["current_nonreplay_transition"] == event_binding,
        "genuine holding166 event binding required"
    );
    for key in [
        "qualified_preparer",
        "qualified_launcher",
        "qualified_stage",
    ] {
        let artifact = &previous_fleet["next_lane_recovery"][key];
        ensure!(
            bind(
                artifact["path"]
                    .as_str()
                    .context("qualified170 proof path")?
            )? == *artifact,
            "qualified170 proof changed"
        );
    }
    preserve_holding166_recovery(&mut fleet, &previous_fleet, &read(holding_event_path)?)?;
    fleet["recovered166_admission"] = bind(
        "/var/lib/jetstreamer/retry8-single166-guarded-launch-20261119-v1/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json",
    )?;
    fleet["observer_identity_handoff"] =
        bind("/var/lib/jetstreamer/observe166-retry8-20261119-v2/handoff.json")?;
    reconcile_home_audit(
        &mut fleet,
        &previous_fleet,
        &audit_observation,
        &audit_evidence,
    )?;
    fleet["recovered170_admission"] = joined170["admission"].clone();
    fleet["recovered170_guard_protection"] = joined170["guard_protection"].clone();
    fleet["epoch170_join_identity"] = joined170;
    if retired170_diagnostics.as_array().is_some_and(|rows| !rows.is_empty()) {
        fleet["historical_terminal170_observer_diagnostics"] = retired170_diagnostics;
    }
    fleet["historical_pre170_join_recovery"] = fleet["next_lane_recovery"].clone();
    fleet["next_lane_recovery"]["last_result"] = json!("actual guarded epoch170 producer joined the coordinated observer");
    fleet["next_lane_recovery"]["guarded_admission"] = fleet["recovered170_admission"].clone();
    fleet["next_lane_recovery"]["next_action"] = json!("Preserve all three guarded producers and the audit; use the accepted sample for measured replay progress and prepare the next disjoint candidate through separate admission.");
    println!(
        "{}",
        write(
            &format!("{root}/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
            &fleet
        )?
    );
    println!("next_observer={sealed}; timer={unit}.timer; at={next}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BASE_DATA, OLD166_DATA, audit_budget, audit_growth, clock_labels, exact167_native, phase,
        preserve_holding166_recovery, reconcile_home_audit, validate_predecessor_obligations,
    };
    #[test]
    fn current_epoch_growth_excludes_resident_bytes_and_never_books_the_ceiling() {
        let obligation = audit_budget::fleet_obligation();
        let full = audit_growth(&obligation, 22u64 << 30, 22u64 << 30, 6u64 << 30).unwrap();
        assert_eq!(full["remaining_archive_growth_bytes"], 0);
        assert_eq!(full["remaining_working_growth_bytes"], 10u64 << 30);
        assert_eq!(full["remaining_cargo_growth_allowance_bytes"], 2u64 << 30);
        assert_eq!(full["remaining_DATA_growth_bytes"], 12u64 << 30);
        let partial = audit_growth(&obligation, 22u64 << 30, 7u64 << 30, 6u64 << 30).unwrap();
        assert_eq!(partial["remaining_DATA_growth_bytes"], 27u64 << 30);
        let empty = audit_growth(&obligation, 22u64 << 30, 0, 6u64 << 30).unwrap();
        assert_eq!(empty["remaining_DATA_growth_bytes"], 34u64 << 30);
        assert!(audit_growth(&obligation, 1, 2, 0).is_err());
        assert!(audit_growth(&obligation, 22u64 << 30, 0, 17u64 << 30).is_err());
        assert!(audit_growth(&obligation, 385_290_386_717, 0, 0).is_err());
        assert_eq!(full["largest_archive_booked"], false);
        assert_eq!(full["promise_ending_bytes"], 0);
    }
    fn prior() -> serde_json::Value {
        serde_json::json!({"complete_DATA_bytes":BASE_DATA,
            "complete_projected_memory_bytes":761_131_708_416u64,
            "retained_retry6_166_DATA_bytes":OLD166_DATA,
            "all_existing_memory_DATA_OS_native_transport_promises_retained":true,
            "same_sample_conservative_free_DATA_bytes":9_000_000_000_000u64,
            "current_nonreplay_transition":{"path":"retained-event","sha256":"retained-hash"},
            "epochs":[{"epoch":166,"current_replay":{"owner":"166"},"status_publication":{"hash":"166-status"}},
                       {"epoch":167,"current_replay":{"owner":"167"},"status_publication":{"hash":"167-status"}}],
            "continuing_holding166retry6_obligation":{"restore_overlap_bytes":56_173_984_550u64},
            "continuing_audit_obligation":{"DATA_reservation_bytes":0}})
    }
    #[test]
    fn audit_reconciliation_keeps_peers_old166_statuses_and_memory_once() {
        let previous = prior();
        let mut fleet = previous.clone();
        let growth = audit_growth(
            &audit_budget::fleet_obligation(),
            22u64 << 30,
            22u64 << 30,
            6u64 << 30,
        )
        .unwrap();
        let observation = serde_json::json!({"recorded_unix_seconds":1000,"growth":growth,
            "conservative_available_DATA_bytes":8_999_000_000_000u64});
        let evidence =
            serde_json::json!({"path":"new-observation","sha256":"new-observation-hash"});
        reconcile_home_audit(&mut fleet, &previous, &observation, &evidence).unwrap();
        for key in [
            "epochs",
            "current_nonreplay_transition",
            "continuing_holding166retry6_obligation",
            "retained_retry6_166_DATA_bytes",
            "complete_projected_memory_bytes",
        ] {
            assert_eq!(fleet[key], previous[key]);
        }
        assert_eq!(fleet["complete_DATA_bytes"], BASE_DATA);
        assert_eq!(
            fleet["complete_DATA_with_remaining_audit_growth_bytes"],
            BASE_DATA + (12u64 << 30)
        );
        assert!(
            fleet["continuing_audit_obligation"]
                .get("DATA_reservation_bytes")
                .is_none()
        );
        audit_budget::validate_fleet_obligation(&fleet["continuing_audit_obligation"]).unwrap();
        assert_eq!(
            fleet["next_audit_routine_observation_not_before_unix"],
            2800
        );
        assert_eq!(
            fleet["complete_cycle_conservative_available_DATA_bytes"],
            8_999_000_000_000u64
        );
    }
    #[test]
    fn predecessor_event_accounting_can_be_split_but_unknown_promises_cannot_disappear() {
        let mut previous = prior();
        let event_audit = 40_981_458_351u64;
        previous["complete_DATA_bytes"] = serde_json::json!(BASE_DATA + event_audit);
        assert!(validate_predecessor_obligations(&previous).is_err());
        previous["complete_DATA_authority"] = serde_json::json!({"base_replay_bytes":BASE_DATA,
            "old166scratch_obligation_unchanged":OLD166_DATA,
            "current_audit_archive_plus_working_and_cache_allowance_bytes":event_audit});
        validate_predecessor_obligations(&previous).unwrap();
        previous["complete_DATA_bytes"] = serde_json::json!(BASE_DATA + event_audit + 1);
        assert!(validate_predecessor_obligations(&previous).is_err());
        previous = prior();
        previous["retained_retry6_166_DATA_bytes"] = serde_json::json!(0);
        assert!(validate_predecessor_obligations(&previous).is_err());
    }
    #[test]
    fn holding_event_preserves_successor_and_budget_without_fresh_claim() {
        let event = serde_json::json!({"schema":"horizon-exact-holding166-start-event-v1",
            "native":{"Id":"horizon-closed166-retry6-park-20261119-v1.service","InvocationID":"afc04ba6096f4826836919c2020dcdc6"},
            "additional_memory_bytes":2147483648u64,"additional_cpu_quota_micros":2000000u64,
            "additional_DATA_staging_bytes":0,"restore_overlap_bytes":56173984550u64,
            "resource_credit_bytes":0,"promise_ending_bytes":0});
        let previous = serde_json::json!({"continuing_holding166retry6_obligation":event,
            "next_lane_recovery":{"epoch":170,"resource_credit_bytes":0,"qualified_preparer":{},
            "qualified_launcher":{},"qualified_stage":{},"next_action":"qualified retirement then launch"}});
        let mut fleet = serde_json::json!({"next_lane_recovery":{"next_action":"stale"}});
        preserve_holding166_recovery(&mut fleet, &previous, &event).unwrap();
        assert_eq!(fleet["next_lane_recovery"], previous["next_lane_recovery"]);
        assert_eq!(fleet["continuing_holding166retry6_obligation"], event);
        assert_eq!(
            fleet["holding166_event_is_historical_not_fresh_native_observation"],
            true
        );
        for key in [
            "additional_memory_bytes",
            "additional_cpu_quota_micros",
            "restore_overlap_bytes",
        ] {
            let mut bad = event.clone();
            bad[key] = serde_json::json!(0);
            assert!(preserve_holding166_recovery(&mut fleet, &previous, &bad).is_err());
        }
        let mut bad = previous.clone();
        bad["continuing_holding166retry6_obligation"] = serde_json::Value::Null;
        assert!(preserve_holding166_recovery(&mut fleet, &bad, &event).is_err());
    }
    #[test]
    fn joined167_rejects_changed_owner_and_restart() {
        let good = serde_json::json!({"Id":"horizon-qualify-167-replacement-local3retry7-20261110-v1.service",
            "InvocationID":"a680103e76f546faaf469aa80c35fa3b","MainPID":"1871809","ControlPID":"0",
            "ActiveState":"active","SubState":"running","NRestarts":"0","Job":""});
        exact167_native(&good).unwrap();
        for (key, value) in [
            ("InvocationID", "foreign"),
            ("MainPID", "1871810"),
            ("ControlPID", "3"),
            ("ActiveState", "failed"),
            ("NRestarts", "1"),
            ("Job", "queued"),
        ] {
            let mut bad = good.clone();
            bad[key] = serde_json::json!(value);
            assert!(exact167_native(&bad).is_err());
        }
    }
    #[test]
    fn bootstrap_is_not_claimed_as_replay_without_progress() {
        assert_eq!(phase(&serde_json::json!({})), "bootstrap");
        assert_eq!(
            phase(&serde_json::json!({"sufficient_for_rates":true,"transaction_delta":0})),
            "bootstrap"
        );
        assert_eq!(
            phase(&serde_json::json!({"sufficient_for_rates":true,"transaction_delta":1})),
            "replay"
        );
    }
    #[test]
    fn midnight_successor_uses_its_own_date() {
        assert_eq!(
            clock_labels("2026-11-18T23:49:25Z").unwrap(),
            ("20261118".into(), "2349".into())
        );
        assert_eq!(
            clock_labels("2026-11-19T00:19:25Z").unwrap(),
            ("20261119".into(), "0019".into())
        );
        for bad in [
            "2026/11/19T00:19:25Z",
            "2026-11-19T24:19:25Z",
            "2026-11-19T00:19:25+00:00",
            "",
        ] {
            assert!(clock_labels(bad).is_err());
        }
    }
}
