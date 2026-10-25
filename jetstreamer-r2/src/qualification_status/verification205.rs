//! Original 205 parent verification, with real parent/node ownership and no worker rate.
use super::*;
use std::collections::BTreeSet;
pub(super) const SCHEMA: &str = "jetstreamer-original205-verification-status-plan-v1";
const FRAME: &str = "jetstreamer-original205-parent-verification-frame-v1";
const NODE: u64 = 3_730_071;
const PARENT: u64 = 3_730_044;
const PARENT_TEXT: &str = "3730044";
const ARCHIVE_BYTES: u64 = 104_571_676_001;
const JOURNAL_SHA: &str = "b0651e50ddc7c2dd4370437f8be90d74e9909ea10d781acaeba3d6514d773214";
const NODE_PATH: &str =
    "/var/lib/jetstreamer/horizon-focused-205-store8-3de96e7-v1/jetstreamer-node";
const NODE_SHA: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
const KEYS: [&str; 10] = [
    "original_parent_verification",
    "prefix_independent_verification",
    "native_restart",
    "suffix_replay",
    "assembly",
    "full_verification",
    "plugin_verification",
    "upload",
    "readback",
    "sidecar_commit",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Model {
    schema: String,
    observer: Bound,
    fleet: Bound,
    phase_journal: Bound,
    receipt_directory: PathBuf,
    estimate_receipt: PathBuf,
    downstream_allowance_millis: BTreeMap<String, u64>,
    estimate_basis: String,
}
fn model(binding: &Bound) -> Result<Model> {
    let p: Model = serde_json::from_value(terminal_subset::sealed(binding)?)?;
    ensure!(
        p.schema == SCHEMA
            && p.phase_journal.sha256 == JOURNAL_SHA
            && p.estimate_receipt
                .file_name()
                .is_some_and(|s| s == "frame.json")
            && p.estimate_receipt.parent().and_then(Path::parent)
                == Some(Path::new("/var/lib/jetstreamer"))
            && !p.estimate_basis.trim().is_empty(),
        "original 205 verification model differs"
    );
    allowance(&p.downstream_allowance_millis)?;
    Ok(p)
}
fn allowance(values: &BTreeMap<String, u64>) -> Result<u64> {
    ensure!(
        values.len() == KEYS.len()
            && KEYS
                .iter()
                .all(|key| values.get(*key).is_some_and(|v| *v > 0)),
        "original 205 estimate must cover every remaining stage through sidecar"
    );
    values.values().try_fold(0u64, |a, b| {
        a.checked_add(*b)
            .context("original 205 sidecar ETA overflow")
    })
}
fn unavailable(o: &Value) -> Result<()> {
    let p = profile(205)?;
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("205 observer census missing")?
        .iter()
        .filter(|r| r["producer_unit"] == p.unit)
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1
            && rows[0]["status"] == "unavailable"
            && rows[0]["observation"].is_null()
            && rows[0]["expected_producer_invocation_id"] == p.iid
            && rows[0]["error"]
                == format!(
                    "expected exactly one historical-worker beneath {}/scratch, found 0",
                    p.root
                ),
        "205 needs its exact post-worker absence, never a fabricated worker observation"
    );
    for key in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            rows[0][key] == false,
            "205 unavailable row grants authority: {key}"
        );
    }
    Ok(())
}
fn events(bytes: &[u8], boot: &str) -> Result<()> {
    ensure!(
        hex_lower(&Sha256::digest(bytes)) == JOURNAL_SHA,
        "original 205 phase journal changed"
    );
    let rows = bytes
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    let p = profile(205)?;
    let mut checkpoint = false;
    let mut snapshot = false;
    let mut close = false;
    for row in rows {
        ensure!(
            row["_SYSTEMD_INVOCATION_ID"] == p.iid
                && row["_SYSTEMD_UNIT"] == p.unit
                && row["_PID"] == PARENT_TEXT
                && row["_UID"] == "1000"
                && row["_BOOT_ID"] == boot,
            "205 phase journal has another original owner or boot"
        );
        let text = row["MESSAGE"]
            .as_str()
            .context("205 phase message missing")?;
        checkpoint|=text.contains("historical checkpoint slot=88991050 bank_hash=5d9cMsxrGmDchGmBgbAVwhbavUKhMhjF49DfK1H41Neo accounts_hash=BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp") && text.contains("complete=true");
        snapshot |= text.ends_with("snapshot verification complete");
        close |= text.contains("horizon archive complete: slots=431051")
            && text.contains("bytes=104571676001 (payload 682665018703 uncompressed)");
    }
    ensure!(
        checkpoint && snapshot && close,
        "205 lacks canonical checkpoint, snapshot verification and archive-close events"
    );
    Ok(())
}
fn actor(pid: u64) -> Result<(u64, String)> {
    let path = PathBuf::from(format!("/proc/{pid}"));
    ensure!(
        fs::symlink_metadata(&path)?.uid() == 1000,
        "205 actor UID differs"
    );
    let text = fs::read_to_string(path.join("stat"))?;
    let fields = text
        .rsplit_once(')')
        .context("205 actor stat malformed")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    Ok((
        fields.get(1).context("205 actor parent absent")?.parse()?,
        fields
            .get(19)
            .context("205 actor start absent")?
            .to_string(),
    ))
}
fn capture(p: &Model, f: &Value) -> Result<Value> {
    let original = profile(205)?;
    let o = bound(&p.observer)?;
    ensure!(
        bound(&p.fleet)? == *f
            && f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["observer_sha256"] == p.observer.sha256
            && f["observer_receipt"].as_str() == p.observer.path.to_str()
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["inventory"]["anomalies"] == 0,
        "205 verification needs the complete accepted fleet and raw resource observer"
    );
    unavailable(&o)?;
    let resource_time = fleet::utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("205 resource clock missing")?,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let ms = u64::try_from(now.as_millis())?;
    ensure!(
        now.as_secs() >= resource_time && now.as_secs() - resource_time <= 1800,
        "205 resource basis is stale"
    );
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    events(&terminal_subset::sealed_bytes(&p.phase_journal)?, &boot)?;
    let manager = live(original, f)?;
    ensure!(
        manager["MainPID"] == PARENT_TEXT && manager["NRestarts"] == "0",
        "205 original parent changed"
    );
    let active = f["active"]
        .as_array()
        .context("205 active fleet missing")?
        .iter()
        .filter(|r| r["epoch"] == 205)
        .collect::<Vec<_>>();
    ensure!(
        active.len() == 1
            && active[0]["producer"]["InvocationID"] == original.iid
            && active[0]["producer"]["MainPID"] == PARENT_TEXT,
        "205 is not the unchanged live original parent"
    );
    let group = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{}", original.unit));
    let pids = || -> Result<BTreeSet<u64>> {
        fs::read_to_string(group.join("cgroup.procs"))?
            .split_whitespace()
            .map(|s| Ok(s.parse()?))
            .collect()
    };
    let before = pids()?;
    ensure!(
        before == BTreeSet::from([PARENT, NODE]),
        "205 verification actor set changed; no worker may be invented"
    );
    let parent_actor = actor(PARENT)?;
    let node_actor = actor(NODE)?;
    ensure!(
        node_actor.0 == PARENT
            && fs::read_link(format!("/proc/{NODE}/exe"))? == Path::new(NODE_PATH),
        "205 node escaped its original parent"
    );
    let arguments = fs::read(format!("/proc/{NODE}/cmdline"))?;
    let arguments = arguments
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(std::str::from_utf8)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let expected=vec![NODE_PATH.to_string(),"205".into(),format!("{}/ledger",original.root),"--verify".into(),
        "--qualification-end-slot=88991050".into(),
        "--snapshot-archive=/var/lib/jetstreamer/horizon-focused-205-store8-3de96e7-v1/snapshot-88559361-83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA.tar.zst".into(),
        "--epoch-hashes=/var/lib/jetstreamer/horizon-focused-205-store8-3de96e7-v1/epoch-hashes-205.txt".into(),
        format!("--horizon-output={}/output/epoch-205-prefix.jet",original.root),format!("--replay-scratch={}/scratch",original.root)];
    ensure!(
        arguments == expected,
        "205 node command differs from the original prefix verification"
    );
    let executable = Path::new(NODE_PATH);
    let exe_metadata = fs::symlink_metadata(executable)?;
    ensure!(
        exe_metadata.is_file() && exe_metadata.uid() == 0 && exe_metadata.mode() & 0o222 == 0,
        "205 node source is not immutable"
    );
    let node_bytes = read_stable_bounded(executable, 256 << 20, "205 node executable")?;
    ensure!(
        hex_lower(&Sha256::digest(&node_bytes)) == NODE_SHA,
        "205 node executable hash differs"
    );
    let mapped = fs::metadata(format!("/proc/{NODE}/exe"))?;
    ensure!(
        mapped.dev() == exe_metadata.dev() && mapped.ino() == exe_metadata.ino(),
        "205 node maps another executable inode"
    );
    let archive = Path::new(original.root).join("output/epoch-205-prefix.jet");
    let a = fs::symlink_metadata(&archive)?;
    ensure!(
        a.is_file() && a.uid() == 1000 && a.nlink() == 1 && a.len() == ARCHIVE_BYTES,
        "205 closed private archive identity differs"
    );
    let mut descriptors = Vec::new();
    for entry in fs::read_dir(format!("/proc/{NODE}/fd"))? {
        let entry = entry?;
        if fs::read_link(entry.path())? != archive {
            continue;
        }
        let number = entry
            .file_name()
            .to_str()
            .context("205 descriptor number malformed")?
            .parse::<u32>()?;
        let info = fs::read_to_string(format!("/proc/{NODE}/fdinfo/{number}"))?;
        let flags = info
            .lines()
            .find_map(|s| s.strip_prefix("flags:\t"))
            .context("205 descriptor flags absent")?;
        let flags = u64::from_str_radix(flags, 8)?;
        ensure!(
            flags & libc::O_ACCMODE as u64 == libc::O_RDONLY as u64,
            "205 archive still has a writable descriptor"
        );
        let mapped = fs::metadata(entry.path())?;
        ensure!(
            mapped.dev() == a.dev() && mapped.ino() == a.ino() && mapped.len() == a.len(),
            "205 descriptor archive identity differs"
        );
        descriptors.push(number);
    }
    ensure!(
        !descriptors.is_empty(),
        "205 node no longer has actual verification archive readers"
    );
    let guard = fleet::unit("horizon-prefix205-protective-v1.service")?;
    ensure!(
        guard["Result"] == "success" && guard["ExecMainStatus"] == "0" && guard["NRestarts"] == "0",
        "205 protective manager is not successful"
    );
    let after = fs::symlink_metadata(&archive)?;
    ensure!(
        pids()? == before
            && actor(PARENT)? == parent_actor
            && actor(NODE)? == node_actor
            && after.dev() == a.dev()
            && after.ino() == a.ino()
            && after.len() == a.len()
            && live(original, f)? == manager,
        "205 verification ownership changed during native metadata capture"
    );
    let ticks = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })?;
    ensure!(ticks > 0, "205 clock tick rate absent");
    let mut clock = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, clock.as_mut_ptr()) } == 0,
        "205 parent elapsed clock unavailable"
    );
    let clock = unsafe { clock.assume_init() };
    let uptime = u64::try_from(clock.tv_sec)?
        .checked_mul(1000)
        .and_then(|n| n.checked_add(u64::try_from(clock.tv_nsec).ok()? / 1_000_000))
        .context("205 elapsed clock overflow")?;
    let start = parent_actor
        .1
        .parse::<u64>()?
        .checked_mul(1000)
        .context("205 parent start overflow")?
        / ticks;
    let captured = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let captured_ms = u64::try_from(captured.as_millis())?;
    ensure!(
        captured_ms >= ms && captured.as_secs() - resource_time <= 1800,
        "205 ownership capture outlived its resource basis"
    );
    let status = EpochStatus {
        epoch: 205,
        jet_size_bytes: ARCHIVE_BYTES,
        elapsed_execution_millis: uptime
            .checked_sub(start)
            .context("205 parent start is in the future")?,
        estimated_remaining_millis: allowance(&p.downstream_allowance_millis)?,
        sampled_at_utc: utc(captured.as_secs())?,
        phase: "verification".into(),
    };
    Ok(
        json!({"schema":FRAME,"capture_started_unix_millis":ms,"captured_unix_millis":captured_ms,"recorded_at_utc":status.sampled_at_utc,
        "resource_observer":{"path":p.observer.path,"sha256":p.observer.sha256},"resource_fleet":{"path":p.fleet.path,"sha256":p.fleet.sha256},
        "resource_sampled_at_utc":o["recorded_at_utc"],"phase_journal":{"path":p.phase_journal.path,"sha256":p.phase_journal.sha256},
        "parent":manager,"node":{"pid":NODE,"parent_pid":PARENT,"start_ticks":node_actor.1,"executable_sha256":NODE_SHA},
        "read_only_archive_descriptors":descriptors,"guard_manager":guard,"status":status,
        "estimate_basis":p.estimate_basis,"downstream_allowance_millis":p.downstream_allowance_millis,
        "worker_observation_fabricated":false,"terminal_original_claimed":false,"archive_or_sidecar_mutation_authorized":false}),
    )
}
fn utc(seconds: u64) -> Result<String> {
    let seconds = libc::time_t::try_from(seconds)?;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    ensure!(
        !unsafe { libc::gmtime_r(&seconds, tm.as_mut_ptr()) }.is_null(),
        "205 UTC conversion failed"
    );
    let mut bytes = [0u8; 32];
    let count = unsafe {
        libc::strftime(
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            c"%Y-%m-%dT%H:%M:%SZ".as_ptr(),
            tm.as_ptr(),
        )
    };
    let value = std::str::from_utf8(&bytes[..count])?.to_string();
    ensure!(
        is_canonical_utc(&value),
        "205 actual capture clock malformed"
    );
    Ok(value)
}
pub(super) fn delegation(binding: &Bound, f: &Value) -> Result<()> {
    let p = model(binding)?;
    ensure!(
        bound(&p.fleet)? == *f && f["observer_sha256"] == p.observer.sha256,
        "healthy-peer delegation has another complete fleet"
    );
    unavailable(&bound(&p.observer)?)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    events(&terminal_subset::sealed_bytes(&p.phase_journal)?, &boot)?;
    let u = live(profile(205)?, f)?;
    ensure!(
        u["MainPID"] == PARENT_TEXT,
        "delegated original 205 parent was replaced"
    );
    // Healthy peers do not borrow 205's missing rate or depend on its node/FD
    // subphase. The separate 205 publisher must prove its current actual actors.
    Ok(())
}
fn eligible(r: &StatusPublicationReceipt) -> bool {
    r.epoch == 205
        && r.status.phase == "verification"
        && r.pipeline_binding.is_none()
        && r.producer_invocation_id == PROFILES[1].iid
        && r.controller_invocation_id == PROFILES[1].iid
}
fn frame(r: &StatusPublicationReceipt) -> Result<Value> {
    let value = terminal_subset::sealed(&Bound {
        path: r.observer_receipt.clone(),
        sha256: r.observer_receipt_sha256.clone(),
    })?;
    ensure!(
        value["schema"] == FRAME
            && value["status"] == serde_json::to_value(&r.status)?
            && value["parent"]["InvocationID"] == PROFILES[1].iid
            && value["parent"]["MainPID"] == PARENT_TEXT
            && value["node"]["pid"] == NODE
            && value["node"]["parent_pid"] == PARENT
            && value["phase_journal"]["sha256"] == JOURNAL_SHA
            && value["terminal_original_claimed"] == false
            && value["captured_unix_millis"].as_u64().is_some_and(|ms| {
                value["capture_started_unix_millis"]
                    .as_u64()
                    .is_some_and(|start| start <= ms)
                    && fleet::utc_seconds(&r.status.sampled_at_utc).ok() == Some(ms / 1000)
            })
            && value["recorded_at_utc"] == r.status.sampled_at_utc,
        "205 publication lacks its genuine native verification ownership frame"
    );
    Ok(value)
}
pub(super) fn matches(
    r: &StatusPublicationReceipt,
    epoch: u64,
    o: &Value,
    census: &BTreeMap<String, Value>,
) -> bool {
    if epoch != 205 || !eligible(r) {
        return false;
    }
    (|| -> Result<bool> {
        let value = frame(r)?;
        let b: Bound = serde_json::from_value(value["resource_observer"].clone())?;
        let u = census
            .get(PROFILES[1].unit)
            .context("205 current owner absent")?;
        Ok(bound(&b)? == *o
            && u["InvocationID"] == PROFILES[1].iid
            && u["MainPID"] == PARENT_TEXT
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["NRestarts"] == "0")
    })()
    .unwrap_or(false)
}
pub(super) fn inactive_owner(r: &StatusPublicationReceipt) -> Result<Option<(String, String)>> {
    if !eligible(r) {
        return Ok(None);
    }
    frame(r)?;
    Ok(Some((PROFILES[1].unit.into(), PROFILES[1].iid.into())))
}
fn persist_frame(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("205 frame parent absent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "205 frame output parent must be private and root owned"
    );
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)?;
    use std::os::unix::fs::PermissionsExt;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|e| anyhow!("205 frame no-clobber commit failed: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub(super) async fn run(
    binding: &Bound,
    _raw: Value,
    self_sha: &str,
    check_only: bool,
) -> Result<()> {
    let p = model(binding)?;
    let f = bound(&p.fleet)?;
    let current = capture(&p, &f)?;
    if check_only {
        println!("{}", serde_json::to_string(&current)?);
        return Ok(());
    }
    preflight_status_receipt_write(&p.receipt_directory)?;
    let saved = if p.estimate_receipt.try_exists()? {
        let bytes = read_stable_bounded(
            &p.estimate_receipt,
            MAX_OBSERVER_RECEIPT_BYTES,
            "205 verification estimate",
        )?;
        let value = terminal_subset::sealed(&Bound {
            path: p.estimate_receipt.clone(),
            sha256: hex_lower(&Sha256::digest(&bytes)),
        })?;
        ensure!(
            value["phase_plan_sha256"] == binding.sha256
                && value["resource_fleet"] == current["resource_fleet"]
                && value["node"] == current["node"]
                && value["parent"] == current["parent"]
                && value["publisher_sha256"] == self_sha,
            "205 saved estimate has another plan or fleet"
        );
        value
    } else {
        let mut value = current;
        value["phase_plan_sha256"] = json!(binding.sha256);
        value["publisher_sha256"] = json!(self_sha);
        persist_frame(&p.estimate_receipt, &value)?;
        value
    };
    let status: EpochStatus = serde_json::from_value(saved["status"].clone())?;
    validate_epoch_status(&status, 205)?;
    ensure!(
        saved["schema"] == FRAME
            && status.phase == "verification"
            && status.jet_size_bytes == ARCHIVE_BYTES
            && status.estimated_remaining_millis == allowance(&p.downstream_allowance_millis)?
            && saved["recorded_at_utc"] == status.sampled_at_utc,
        "205 saved estimate is not the original verification countdown"
    );
    let proof_sha = hex_lower(&Sha256::digest(read_stable_bounded(
        &p.estimate_receipt,
        MAX_OBSERVER_RECEIPT_BYTES,
        "205 verification estimate",
    )?));
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    capture(&p, &f)?;
    let (etag, previous) = publish_epoch_status(&s3, &r2, &status).await?;
    // publish_epoch_status performs the shared authenticated readback checks.
    let receipt = StatusPublicationReceipt {
        schema: STATUS_RECEIPT_SCHEMA.into(),
        bucket: r2.bucket,
        epoch: 205,
        key: "epoch-205.epoch-status.json".into(),
        status: status.clone(),
        object_etag: etag,
        previous_object_etag: previous,
        observer_receipt: p.estimate_receipt.clone(),
        observer_receipt_sha256: proof_sha,
        controller_invocation_id: PROFILES[1].iid.into(),
        producer_invocation_id: PROFILES[1].iid.into(),
        authenticated_readback: true,
        verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        pipeline_binding: None,
    };
    let path = status_receipt_path(&p.receipt_directory, &status);
    if path.try_exists()? {
        let old: StatusPublicationReceipt = serde_json::from_slice(&read_stable_bounded(
            &path,
            MAX_STATUS_BYTES,
            "205 publication",
        )?)?;
        ensure!(
            old.status == status
                && old.object_etag == receipt.object_etag
                && old.authenticated_readback
                && old.observer_receipt_sha256 == receipt.observer_receipt_sha256
                && old.controller_invocation_id == PROFILES[1].iid
                && old.producer_invocation_id == PROFILES[1].iid,
            "205 existing authenticated publication differs"
        );
    } else {
        write_status_receipt(&p.receipt_directory, &receipt)?;
    }
    capture(&p, &f)?;
    println!("{}", path.display());
    Ok(())
}
#[cfg(test)]
mod tests;
