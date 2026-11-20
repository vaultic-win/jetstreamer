//! Shared, read-only admission checks for the actual home-backed audit v9.
//! Include this exact source in the stage, preparer and launcher build proofs.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};

const UNIT: &str = "horizon-r2-chronological-plugin-audit-20261118-v1.service";
const IID: &str = "67725d9ba7aa4de994840564f44d963c";
const PID: u64 = 2_285_828;
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/r2-audit-storage-20261119-v1/runtime-v9/audit";
const IMAGE_SHA: &str = "70d64c543ed79d8a05f3f2a9afd920ab5612133d4c6f89bfc9bffba1dcfe2ba2";
const CONFIG: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/r2-audit-storage-20261119-v1/runtime-v9/config.json";
const CONFIG_SHA: &str = "5d7d09bfb1ffdb08ac5aa04b228e9cd3827a6ef3bbb700723d7b777d2261e177";
const SEAL: &str = "/var/lib/jetstreamer/horizon_runtime_data/r2-audit-storage-20261119-v1/runtime-v9/deployment-seal-receipt.json";
const SEAL_SHA: &str = "9848e46959219be23eba60280bffcc94d7121767951c8cc2691d372ab5ab8739";
const START: &str = "/var/lib/jetstreamer/horizon_runtime_data/r2-audit-storage-20261119-v1/range-v9-transition/START_EVENT.json";
const START_SHA: &str = "c043d9d42a50bd2aac7b1ab0c865f3a0ee1759fe6adc6da657aed4d5b5ad2257";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const STATE: &str = "/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1";
const READERS: &str = "/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1";
const MEMORY: u64 = 24 << 30;
const CPU: u64 = 4_000_000;
const WORK: u64 = 16 << 30;
const CARGO: u64 = 2 << 30;
const CEILING: u64 = 385_290_386_716;
const BASE: u64 = 6_794_761_027_378;
const AUDIT_FLOOR: u64 = BASE + CARGO;
const OLD166: u64 = 309_237_645_312;

fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("missing integer {key}"))
}
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
pub(super) fn compiled_source_sha256() -> String {
    sha(include_bytes!("audit_budget.rs"))
}
fn binding(path: &str, hash: &str) -> Value {
    json!({"path":path,"sha256":hash})
}
fn identity(m: &fs::Metadata) -> [u64; 10] {
    [
        m.dev(),
        m.ino(),
        m.uid().into(),
        m.mode().into(),
        m.nlink(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical audit evidence"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= limit,
        "unsafe audit evidence"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        identity(&before) == identity(&file.metadata()?),
        "audit evidence replaced"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "audit evidence changed"
    );
    Ok(bytes)
}
fn fixed(path: &str, hash: &str, immutable: bool) -> Result<Vec<u8>> {
    let bytes = read(Path::new(path), 128 << 20)?;
    ensure!(sha(&bytes) == hash, "audit binding differs: {path}");
    if immutable {
        ensure!(
            fs::symlink_metadata(path)?.mode() & 0o222 == 0,
            "mutable audit deployment"
        );
    }
    Ok(bytes)
}
fn home(path: &Path) -> Result<u64> {
    let dev = fs::metadata("/home/sol")?.dev();
    ensure!(
        path.canonicalize()? == path && fs::metadata(path)?.dev() == dev,
        "audit path is not on the home filesystem: {}",
        path.display()
    );
    Ok(dev)
}
fn ticks() -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{PID}/stat"))?;
    stat.rsplit_once(')')
        .context("audit stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("audit start ticks")?
        .parse()
        .context("audit start ticks integer")
}
fn shape(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == UNIT
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(PID)
            && v["InvocationID"] == IID
            && v["MemoryMax"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(MEMORY)
            && v["MemoryHigh"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(20u64 << 30)
            && v["MemorySwapMax"] == "0"
            && v["CPUQuotaPerSecUSec"] == "4s"
            && v["TasksMax"] == "512"
            && v["ControlGroup"] == format!("/system.slice/{UNIT}"),
        "audit v9 identity or resource limits differ"
    );
    Ok(())
}
fn config_shape(cfg: &Value, start: &Value) -> Result<()> {
    ensure!(
        cfg["state_directory"] == STATE
            && cfg["reserve_bytes"] == AUDIT_FLOOR
            && cfg["max_archive_bytes"] == CEILING
            && cfg["build_reserve_bytes"] == WORK
            && cfg["threads"] == 4
            && cfg["build_jobs"] == 2
            && cfg["external_scratch"].is_null()
            && cfg["cargo_home"] == "/home/sol/.cargo",
        "audit home configuration differs"
    );
    let a = &start["admission"];
    ensure!(
        start["schema"] == "horizon-audit-home-storage-start-event-v1"
            && start["unit"] == UNIT
            && start["invocation_id"] == IID
            && start["main_pid"] == PID
            && start["runtime"] == IMAGE
            && start["runtime_sha256"] == IMAGE_SHA
            && start["config_sha256"] == CONFIG_SHA
            && start["home_storage_active"] == true
            && start["old166scratch_DATA_obligation_retained"] == OLD166
            && a["unchanged_replay_growth_bytes"] == BASE
            && a["configured_free_floor_bytes"] == AUDIT_FLOOR
            && a["additional_cargo_home_growth_allowance_bytes"] == CARGO
            && a["working_allocation_cap_bytes"] == WORK
            && a["maximum_archive_acceptance_bytes"] == CEILING
            && a["exact_per_epoch_reservations"] == true
            && a["old166_scratch_obligation_unchanged"] == true,
        "actual home migration/start evidence differs"
    );
    Ok(())
}

/// Stable identity only: a normal audit epoch transition does not change this value.
pub(super) fn observe() -> Result<Value> {
    let start: Value = serde_json::from_slice(&fixed(START, START_SHA, false)?)?;
    let cfg: Value = serde_json::from_slice(&fixed(CONFIG, CONFIG_SHA, true)?)?;
    config_shape(&cfg, &start)?;
    fixed(IMAGE, IMAGE_SHA, true)?;
    let seal: Value = serde_json::from_slice(&fixed(SEAL, SEAL_SHA, true)?)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == Path::new(IMAGE).parent().unwrap().to_str().unwrap()
            && seal["sealer_sha256"] == SEALER_SHA
            && seal["remote_mutations"] == false
            && seal["replay_launch_authorized"] == false,
        "audit normal seal differs"
    );
    for (name, hash, mode) in [
        ("audit", IMAGE_SHA, "0555"),
        ("config.json", CONFIG_SHA, "0444"),
    ] {
        ensure!(
            seal["members"]
                .as_array()
                .context("seal members")?
                .iter()
                .filter(|r| r["name"] == name && r["sha256"] == hash && r["mode"] == mode)
                .count()
                == 1,
            "audit sealed member differs"
        );
    }
    for path in [IMAGE, CONFIG, STATE, READERS, "/home/sol/.cargo"] {
        home(Path::new(path))?;
    }
    let out = Command::new("/usr/bin/systemctl").args(["show", UNIT,
        "-pId,ActiveState,SubState,MainPID,InvocationID,MemoryMax,MemoryHigh,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ControlGroup"]).output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty(),
        "audit native query failed"
    );
    let mut row = serde_json::Map::new();
    for line in String::from_utf8(out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("audit native row")?;
        ensure!(
            row.insert(k.into(), json!(v)).is_none(),
            "duplicate audit property"
        );
    }
    let row = Value::Object(row);
    shape(&row)?;
    let start_ticks = ticks()?;
    ensure!(
        fs::read_link(format!("/proc/{PID}/exe"))? == Path::new(IMAGE)
            && sha(&fs::read(format!("/proc/{PID}/exe"))?) == IMAGE_SHA
            && ticks()? == start_ticks,
        "audit image or process changed"
    );
    Ok(
        json!({"native":row,"start_ticks":start_ticks,"image":binding(IMAGE,IMAGE_SHA),
        "config":binding(CONFIG,CONFIG_SHA),"seal":binding(SEAL,SEAL_SHA),
        "home_storage_start_event":binding(START,START_SHA)}),
    )
}

/// This is the observer's required successor envelope. Zero DATA and root-only envelopes fail.
#[cfg(test)]
pub(super) fn fleet_obligation() -> Value {
    json!({"home_storage_start_event":binding(START,START_SHA),
        "additional_memory_bytes":MEMORY,"additional_cpu_quota_micros":CPU,"tasks_max":512,
        "DATA_storage_filesystem":"/home/sol","configured_free_floor_bytes":AUDIT_FLOOR,
        "working_allocation_cap_bytes":WORK,"cargo_growth_allowance_bytes":CARGO,
        "archive_acceptance_ceiling_bytes":CEILING,"archive_cap_is_acceptance_ceiling_not_reservation":true,
        "per_epoch_capacity_reserves_exact_archive_bytes":true,"old166scratch_DATA_obligation_retained":OLD166,
        "original_promises_ended":false,"fresh_native_observation_claimed":false,
        "admission_requirement":"Revalidate audit v9 identity, exact resident archive and remaining work; add concurrent replay growth above the audit floor."})
}
pub(super) fn validate_fleet_obligation(v: &Value) -> Result<()> {
    ensure!(
        v["home_storage_start_event"] == binding(START, START_SHA)
            && v["additional_memory_bytes"] == MEMORY
            && v["additional_cpu_quota_micros"] == CPU
            && v["tasks_max"] == 512
            && v["DATA_storage_filesystem"] == "/home/sol"
            && v["configured_free_floor_bytes"] == AUDIT_FLOOR
            && v["working_allocation_cap_bytes"] == WORK
            && v["cargo_growth_allowance_bytes"] == CARGO
            && v["archive_acceptance_ceiling_bytes"] == CEILING
            && v["archive_cap_is_acceptance_ceiling_not_reservation"] == true
            && v["per_epoch_capacity_reserves_exact_archive_bytes"] == true
            && v.get("DATA_reservation_bytes").is_none()
            && v["old166scratch_DATA_obligation_retained"] == OLD166,
        "fleet lacks the exact home-backed audit obligation"
    );
    Ok(())
}

// Metadata only. Symlinks are not followed and shared files receive no credit.
fn allocated(path: &Path, dev: u64, seen: &mut BTreeSet<(u64, u64)>) -> Result<u64> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.dev() == dev && (m.is_dir() || m.is_file() || m.file_type().is_symlink()),
        "unexpected audit allocation identity: {}",
        path.display()
    );
    if (m.is_file() && m.nlink() > 1) || !seen.insert((m.dev(), m.ino())) {
        return Ok(0);
    }
    let mut bytes = m
        .blocks()
        .checked_mul(512)
        .context("audit allocation overflow")?;
    if m.is_dir() {
        for entry in fs::read_dir(path)? {
            bytes = bytes
                .checked_add(allocated(&entry?.path(), dev, seen)?)
                .context("audit allocation overflow")?;
        }
    }
    ensure!(
        identity(&m) == identity(&fs::symlink_metadata(path)?),
        "audit allocation changed; retry admission: {}",
        path.display()
    );
    Ok(bytes)
}
fn available_home() -> Result<u64> {
    let path = std::ffi::CString::new("/home/sol")?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), s.as_mut_ptr()) } == 0,
        "home statvfs failed"
    );
    let s = unsafe { s.assume_init() };
    s.f_bavail
        .checked_mul(s.f_frsize)
        .context("home free space overflow")
}
fn object(p: &Value) -> Result<(u64, u64, u64)> {
    ensure!(
        p["schema"] == "horizon-r2-chronological-audit-progress-v1"
            && p["pid"] == PID
            && p["reserve_bytes"] == AUDIT_FLOOR
            && p["max_archive_bytes"] == CEILING
            && p["external_scratch"].is_null()
            && p["remote_mutations"] == false
            && p["scratch_directory"] == format!("{STATE}/scratch")
            && matches!(
                p["phase"].as_str(),
                Some("downloading" | "playing_entire_epoch")
            ),
        "audit is outside download and full playback"
    );
    let epoch = number(p, "epoch")?;
    let archive = number(p, "archive_bytes")?;
    ensure!(
        archive > 0 && archive <= CEILING,
        "invalid current audit archive length"
    );
    let downloaded = number(p, "downloaded_bytes")?;
    ensure!(
        downloaded <= archive && (p["phase"] == "downloading" || downloaded == archive),
        "audit progress contradicts object length"
    );
    Ok((epoch, archive, downloaded))
}

fn resident_bytes(
    first: &Value,
    last: &Value,
    before: &fs::Metadata,
    after: &fs::Metadata,
    dev: u64,
) -> Result<u64> {
    let (epoch, archive, downloaded) = object(first)?;
    let (next_epoch, next_archive, next_downloaded) = object(last)?;
    ensure!(
        (epoch, archive) == (next_epoch, next_archive)
            && downloaded <= next_downloaded
            && (first["phase"] == "downloading" || last["phase"] == "playing_entire_epoch")
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() <= after.len(),
        "audit object changed during capacity observation"
    );
    for (progress, meta, reported) in [(first, before, downloaded), (last, after, next_downloaded)]
    {
        ensure!(
            meta.is_file()
                && meta.dev() == dev
                && meta.nlink() == 1
                && reported <= meta.len()
                && meta.len() <= archive
                && (progress["phase"] == "downloading" || meta.len() == archive),
            "audit scratch file does not match progress"
        );
    }
    Ok(before
        .blocks()
        .min(after.blocks())
        .checked_mul(512)
        .context("audit block count overflow")?
        .min(downloaded))
}

fn storage() -> Result<Value> {
    let dev = home(Path::new(STATE))?;
    home(Path::new(READERS))?;
    let free_before = available_home()?;
    let path = Path::new(STATE).join("progress.json");
    let raw = read(&path, 1 << 20)?;
    let p: Value = serde_json::from_slice(&raw)?;
    let (epoch, archive, _) = object(&p)?;
    let archive_path = Path::new(STATE).join(format!("scratch/epoch-{epoch}.jet"));
    let before = fs::symlink_metadata(&archive_path)?;
    let mut seen = BTreeSet::new();
    let mut working = allocated(Path::new(READERS), dev, &mut seen)?;
    for entry in fs::read_dir(STATE)? {
        let entry = entry?;
        if entry.file_name() != "scratch" && entry.file_name() != "progress.json" {
            working = working
                .checked_add(allocated(&entry.path(), dev, &mut seen)?)
                .context("working overflow")?;
        }
    }
    let final_raw = read(&path, 1 << 20)?;
    let final_progress: Value = serde_json::from_slice(&final_raw)?;
    let after = fs::symlink_metadata(&archive_path)?;
    let resident = resident_bytes(&p, &final_progress, &before, &after, dev)?;
    ensure!(
        working <= WORK,
        "audit working allocation exceeds its bounded budget"
    );
    Ok(
        json!({"epoch":epoch,"archive_bytes":archive,"resident_archive_bytes":resident,
        "working_allocated_bytes":working,"progress_sha256":sha(&raw),"final_progress_sha256":sha(&final_raw),"phase":final_progress["phase"],"home_device":dev,
        "conservative_available_DATA_bytes":free_before.min(available_home()?)}),
    )
}

fn data_point(fit: &Value, storage: &Value, available: u64) -> Result<Value> {
    let archive = number(storage, "archive_bytes")?;
    ensure!(
        archive > 0 && archive <= CEILING,
        "archive exceeds acceptance ceiling"
    );
    let archive_growth = archive
        .checked_sub(number(storage, "resident_archive_bytes")?)
        .context("resident archive exceeds size")?;
    let work_growth = WORK
        .checked_sub(number(storage, "working_allocated_bytes")?)
        .context("working cap exceeded")?;
    let audit_growth = archive_growth
        .checked_add(work_growth)
        .and_then(|n| n.checked_add(CARGO))
        .context("audit growth overflow")?;
    let growth = number(fit, "complete_concurrent_remaining_growth_bytes")?;
    let staging = number(fit, "fresh_subtree_overlap_bytes")?;
    let margin = number(fit, "unrelated_growth_margin_bytes")?;
    let extra = number(
        fit,
        "additional_growth_not_covered_by_existing_promise_bytes",
    )?;
    let historical = number(fit, "required_raw_available_bytes")?;
    // Retain the entire original fit, including stopped166. Independently preserve
    // the running audit's immutable floor after ALL simultaneous replay growth.
    // max() combines the two constraints; it does not add either floor twice.
    let audit_continuity = AUDIT_FLOOR
        .checked_add(growth)
        .and_then(|n| n.checked_add(staging))
        .and_then(|n| n.checked_add(margin))
        .and_then(|n| n.checked_add(extra))
        .context("audit continuity overflow")?;
    let required = historical
        .max(audit_continuity)
        .checked_add(audit_growth)
        .context("combined DATA overflow")?;
    ensure!(
        available >= required,
        "home audit and concurrent replay growth do not fit: free={available}, required={required}"
    );
    Ok(
        json!({"historical_required_DATA_bytes":historical,"audit_continuity_before_audit_growth_bytes":audit_continuity,
        "required_DATA_bytes":required,"audit_remaining_archive_bytes":archive_growth,
        "audit_remaining_working_bytes":work_growth,"audit_cargo_growth_allowance_bytes":CARGO,
        "audit_remaining_growth_bytes":audit_growth,"audit":storage,"audit_free_floor_bytes":AUDIT_FLOOR,
        "archive_acceptance_ceiling_bytes":CEILING,"ceiling_is_not_a_capacity_reservation":true,
        "complete_concurrent_remaining_growth_bytes":growth,"old166scratch_DATA_obligation_retained":OLD166,
        "candidate170_whole_lane_cap_bytes":288u64<<30,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}
pub(super) fn data_requirements(fit: &Value, available: u64) -> Result<Value> {
    let snapshot = storage()?;
    data_point(
        fit,
        &snapshot,
        available.min(number(&snapshot, "conservative_available_DATA_bytes")?),
    )
}
pub(super) fn requirements(
    prepared: &Value,
    total: u64,
    available: u64,
    cores: u64,
) -> Result<Value> {
    let r = &prepared["resource_checks"];
    let required = number(&r["memory_accounting"], "required_available_bytes")?
        .checked_add(MEMORY)
        .context("audit memory overflow")?;
    let full = number(r, "complete_memory_plus_reserve_bytes")?
        .checked_add(MEMORY)
        .context("audit total memory overflow")?;
    let cpu = number(r, "booked_cpu_quota_micros")?
        .checked_add(CPU)
        .context("audit CPU overflow")?;
    ensure!(
        total >= full && available >= required,
        "additional audit memory does not fit"
    );
    ensure!(
        cores > 0 && cpu <= cores.checked_mul(1_000_000).context("host CPU overflow")?,
        "additional audit CPU does not fit"
    );
    Ok(
        json!({"required_available_memory_bytes":required,"complete_memory_plus_reserve_bytes":full,
        "complete_cpu_quota_micros":cpu,"additional_memory_bytes":MEMORY,"additional_cpu_quota_micros":CPU,
        "tasks_max":512,"actual_online_cpus":cores,"resource_credit_bytes":0,"all_prepared_promises_retained":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn advancing_download_charges_only_observed_blocks_and_rejects_epoch_rollover() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let mut file = fs::File::create(dir.path().join("epoch-83.jet")).unwrap();
        file.write_all(&[0xab; 8192]).unwrap();
        let before = file.metadata().unwrap();
        file.write_all(&[0xcd; 8192]).unwrap();
        let after = file.metadata().unwrap();
        let first = json!({"schema":"horizon-r2-chronological-audit-progress-v1",
            "pid":PID, "reserve_bytes":AUDIT_FLOOR, "max_archive_bytes":CEILING,
            "external_scratch":null, "remote_mutations":false, "scratch_directory":format!("{STATE}/scratch"),
            "phase":"downloading", "epoch":83, "archive_bytes":24576, "downloaded_bytes":4096});
        let mut last = first.clone();
        last["downloaded_bytes"] = json!(16384);
        let observed = resident_bytes(&first, &last, &before, &after, before.dev()).unwrap();
        assert_eq!(
            observed,
            4096.min(before.blocks().min(after.blocks()) * 512)
        );
        last["epoch"] = json!(84);
        assert!(resident_bytes(&first, &last, &before, &after, before.dev()).is_err());
        last["epoch"] = json!(83);
        last["downloaded_bytes"] = json!(2048);
        assert!(resident_bytes(&first, &last, &before, &after, before.dev()).is_err());
        last["phase"] = json!("playing_entire_epoch");
        assert!(object(&last).is_err());
    }

    fn fit() -> Value {
        json!({"required_raw_available_bytes":7_000_000_000_000u64,
        "complete_concurrent_remaining_growth_bytes":700_000_000_000u64,"fresh_subtree_overlap_bytes":64u64<<20,
        "unrelated_growth_margin_bytes":10u64<<30,"additional_growth_not_covered_by_existing_promise_bytes":0})
    }
    fn stored() -> Value {
        json!({"archive_bytes":21_654_105_519u64,"resident_archive_bytes":21_654_105_519u64,
        "working_allocated_bytes":6u64<<30})
    }
    #[test]
    fn resident_small_archive_is_not_reserved_twice_or_at_ceiling() {
        let r = data_point(&fit(), &stored(), u64::MAX).unwrap();
        assert_eq!(r["audit_remaining_archive_bytes"], 0);
        assert_eq!(r["audit_remaining_growth_bytes"], 12u64 << 30);
        assert_eq!(r["old166scratch_DATA_obligation_retained"], OLD166);
        let required = r["required_DATA_bytes"].as_u64().unwrap();
        assert!(data_point(&fit(), &stored(), required).is_ok());
        assert!(data_point(&fit(), &stored(), required - 1).is_err());
        assert!(required >= AUDIT_FLOOR + 700_000_000_000 + (12u64 << 30));
    }
    #[test]
    fn future_archive_and_work_growth_are_additive_and_bounded() {
        let mut s = stored();
        s["resident_archive_bytes"] = json!(0);
        let r = data_point(&fit(), &s, u64::MAX).unwrap();
        assert_eq!(
            r["audit_remaining_growth_bytes"],
            21_654_105_519u64 + (12u64 << 30)
        );
        s["working_allocated_bytes"] = json!(WORK + 1);
        assert!(data_point(&fit(), &s, u64::MAX).is_err());
        s = stored();
        s["archive_bytes"] = json!(CEILING + 1);
        assert!(data_point(&fit(), &s, u64::MAX).is_err());
        let mut f = fit();
        f["complete_concurrent_remaining_growth_bytes"] = json!(u64::MAX);
        assert!(data_point(&f, &stored(), u64::MAX).is_err());
    }
    #[test]
    fn historical_and_audit_floor_constraints_combine_without_summing_floors() {
        let mut f = fit();
        f["required_raw_available_bytes"] = json!(9_000_000_000_000u64);
        let r = data_point(&f, &stored(), u64::MAX).unwrap();
        assert_eq!(
            r["required_DATA_bytes"],
            9_000_000_000_000u64 + (12u64 << 30)
        );
        let mut covered = f.clone();
        covered["additional_growth_not_covered_by_existing_promise_bytes"] =
            json!(3_000_000_000_000u64);
        let r = data_point(&covered, &stored(), u64::MAX).unwrap();
        assert_eq!(
            r["required_DATA_bytes"],
            AUDIT_FLOOR
                + 700_000_000_000
                + (64u64 << 20)
                + (10u64 << 30)
                + 3_000_000_000_000
                + (12u64 << 30)
        );
    }
    #[test]
    fn home_config_and_start_evidence_preserve_exact_reservations_and_old166() {
        let cfg = json!({"state_directory":STATE,"reserve_bytes":AUDIT_FLOOR,
            "max_archive_bytes":CEILING,"build_reserve_bytes":WORK,"threads":4,"build_jobs":2,
            "external_scratch":null,"cargo_home":"/home/sol/.cargo"});
        let start = json!({"schema":"horizon-audit-home-storage-start-event-v1","unit":UNIT,
            "invocation_id":IID,"main_pid":PID,"runtime":IMAGE,"runtime_sha256":IMAGE_SHA,
            "config_sha256":CONFIG_SHA,"home_storage_active":true,"old166scratch_DATA_obligation_retained":OLD166,
            "admission":{"unchanged_replay_growth_bytes":BASE,"configured_free_floor_bytes":AUDIT_FLOOR,
                "additional_cargo_home_growth_allowance_bytes":CARGO,"working_allocation_cap_bytes":WORK,
                "maximum_archive_acceptance_bytes":CEILING,"exact_per_epoch_reservations":true,
                "old166_scratch_obligation_unchanged":true}});
        config_shape(&cfg, &start).unwrap();
        for (key, value) in [
            ("reserve_bytes", json!(AUDIT_FLOOR - 1)),
            ("max_archive_bytes", json!(CEILING + 1)),
            ("external_scratch", json!("/tmp/old-audit")),
            ("build_reserve_bytes", json!(WORK + 1)),
        ] {
            let mut bad = cfg.clone();
            bad[key] = value;
            assert!(config_shape(&bad, &start).is_err());
        }
        for (key, value) in [
            ("old166scratch_DATA_obligation_retained", json!(0)),
            ("home_storage_active", json!(false)),
            ("invocation_id", json!("old")),
        ] {
            let mut bad = start.clone();
            bad[key] = value;
            assert!(config_shape(&cfg, &bad).is_err());
        }
        let mut bad = start.clone();
        bad["admission"]["exact_per_epoch_reservations"] = json!(false);
        assert!(config_shape(&cfg, &bad).is_err());
    }
    #[test]
    fn memory_cpu_and_tasks_remain_full_additive_obligations() {
        let p = json!({"resource_checks":{"memory_accounting":{"required_available_bytes":600u64<<30},
            "complete_memory_plus_reserve_bytes":700u64<<30,"booked_cpu_quota_micros":43_000_000}});
        assert_eq!(
            requirements(&p, 724u64 << 30, 624u64 << 30, 47).unwrap()["tasks_max"],
            512
        );
        assert!(requirements(&p, (724u64 << 30) - 1, 624u64 << 30, 47).is_err());
        assert!(requirements(&p, 724u64 << 30, (624u64 << 30) - 1, 47).is_err());
        assert!(requirements(&p, 724u64 << 30, 624u64 << 30, 46).is_err());
    }
    #[test]
    fn native_owner_and_caps_are_exact() {
        let row = json!({"Id":UNIT,"ActiveState":"active","SubState":"running","MainPID":PID.to_string(),
            "InvocationID":IID,"MemoryMax":MEMORY.to_string(),"MemoryHigh":(20u64<<30).to_string(),
            "MemorySwapMax":"0","CPUQuotaPerSecUSec":"4s","TasksMax":"512","ControlGroup":format!("/system.slice/{UNIT}")});
        shape(&row).unwrap();
        for (key, value) in [
            ("MainPID", "1"),
            ("InvocationID", "old"),
            ("TasksMax", "513"),
            ("CPUQuotaPerSecUSec", "5s"),
        ] {
            let mut bad = row.clone();
            bad[key] = json!(value);
            assert!(shape(&bad).is_err());
        }
    }
    #[test]
    fn fleet_cannot_retain_the_obsolete_zero_data_or_root_only_booking() {
        let v = fleet_obligation();
        validate_fleet_obligation(&v).unwrap();
        for (key, value) in [
            ("DATA_reservation_bytes", json!(0)),
            ("tasks_max", json!(511)),
            ("DATA_storage_filesystem", json!("/")),
            ("configured_free_floor_bytes", json!(32u64 << 30)),
            ("old166scratch_DATA_obligation_retained", json!(0)),
            (
                "per_epoch_capacity_reserves_exact_archive_bytes",
                json!(false),
            ),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(validate_fleet_obligation(&bad).is_err());
        }
    }
}
