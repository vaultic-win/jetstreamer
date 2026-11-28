//! Stage a new coherent idle-lane GCloud copy. Never install, probe or launch it.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
mod copy;
mod group;
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-idle-gcloud-copy-tools-20261110-v6/copy";
const SOURCE: &str = "/home/sol/.config/gcloud";
const OUT: &str = "/var/lib/jetstreamer/gcloud-idle-copy-20261110-v6";
const PRIMARY: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const EVENT: &str = "/var/lib/jetstreamer/seven-standard-reserve-stop-20261110-v1/ORIGINAL_SEVEN_RESERVE_STOPS_AND_REPAIR_MODEL.json";

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    owner: String,
    primary_thread: String,
    epoch: u64,
    source: PathBuf,
    source_identity: copy::Directory,
    source_group_review: Bound,
    target_parent: PathBuf,
    target_parent_identity: copy::Directory,
    stage_leaf: String,
    source_uid: u32,
    target_uid: u32,
    target_gid: u32,
    fleet: Bound,
    stop_event: Bound,
    absence: Bound,
    closed_units: Vec<String>,
    intent: PathBuf,
    receipt: PathBuf,
    stage_only_authorized: bool,
    install_authorized: bool,
    replay_launch_authorized: bool,
    remote_mutations: bool,
    resource_promise_ending_authorized: bool,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn lower_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn raw(path: &Path, cap: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical bound path"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= cap,
        "unsafe or oversized bound evidence"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f).take(cap + 1).read_to_end(&mut bytes)?;
    let same = |a: &fs::Metadata, b: &fs::Metadata| {
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.mode() == b.mode()
            && a.uid() == b.uid()
            && a.gid() == b.gid()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    };
    ensure!(
        bytes.len() as u64 == before.len()
            && same(&before, &f.metadata()?)
            && same(&before, &fs::symlink_metadata(path)?),
        "bound evidence changed"
    );
    Ok(bytes)
}
fn bound(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&checked_raw(b, 32 << 20)?)?)
}
fn checked_raw(b: &Bound, cap: u64) -> Result<Vec<u8>> {
    let bytes = raw(&b.path, cap)?;
    ensure!(
        lower_sha(&b.sha256) && copy::hash(&bytes) == b.sha256,
        "bound evidence digest differs"
    );
    Ok(bytes)
}
fn original_unit(epoch: u64) -> String {
    format!(
        "horizon-qualify-{epoch}-standard-{}-v1.service",
        if epoch <= 170 { "20261109" } else { "20261110" }
    )
}
fn scope(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "horizon-idle-gcloud-copy-plan-v6"
            && p.owner == "/root"
            && p.primary_thread == PRIMARY
            && (166..=172).contains(&p.epoch),
        "exact owner/epoch copy scope required"
    );
    ensure!(
        p.source == Path::new(SOURCE)
            && p.source_uid == 1001
            && p.target_uid == 1001
            && p.target_gid == 1001,
        "exact source and target owner required"
    );
    let date = if p.epoch <= 170 {
        "20261109"
    } else {
        "20261110"
    };
    ensure!(
        p.target_parent.as_os_str()
            == std::ffi::OsStr::new(&format!(
                "/home/sol/.jetstreamer-private/epoch{}-standard-lane-{date}-v1/config",
                p.epoch
            )),
        "wrong isolated configuration parent"
    );
    ensure!(
        p.stage_leaf.starts_with("gcloud.recovery-")
            && p.stage_leaf.ends_with(".stage")
            && p.stage_leaf.len() <= 128
            && !p.stage_leaf.contains("..")
            && p.stage_leaf
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "new no-clobber recovery-stage leaf required"
    );
    ensure!(
        p.source_identity.uid == 1001
            && p.source_identity.gid == 1001
            && [0o700, 0o750, 0o755, 0o775].contains(&p.source_identity.mode)
            && p.target_parent_identity.uid == 1001
            && p.target_parent_identity.gid == 1003
            && p.target_parent_identity.mode == 0o700,
        "private source/parent identities required"
    );
    ensure!(
        p.stage_only_authorized
            && !p.install_authorized
            && !p.replay_launch_authorized
            && !p.remote_mutations
            && !p.resource_promise_ending_authorized,
        "stage-only authority required"
    );
    ensure!(
        p.stop_event.path == Path::new(EVENT)
            && p.intent.parent() == Some(Path::new(OUT))
            && p.receipt.parent() == Some(Path::new(OUT))
            && p.intent != p.receipt,
        "fixed evidence/receipt namespace required"
    );
    let units: BTreeSet<_> = p.closed_units.iter().map(String::as_str).collect();
    let original = original_unit(p.epoch);
    ensure!(
        units.len() == p.closed_units.len()
            && units.len() <= 32
            && units.contains(original.as_str()),
        "explicit original and replacement closure required"
    );
    for unit in &p.closed_units {
        ensure!(
            unit.ends_with(".service")
                && unit.len() <= 255
                && unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
            "unsafe closed service name"
        );
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceGroupReview {
    schema: String,
    owner: String,
    primary_thread: String,
    recorded_unix_seconds: u64,
    source: PathBuf,
    source_uid: u32,
    source_gid: u32,
    account_name: String,
    group_name: String,
    nss_effective_membership_resolved_to_local_files: bool,
    no_other_primary_or_supplementary_members: bool,
    passwd: Bound,
    group: Bound,
    nsswitch: Bound,
}
fn source_group_scope(r: &SourceGroupReview, current: u64) -> Result<()> {
    ensure!(
        r.schema == "horizon-idle-gcloud-sole-source-group-review-v1"
            && r.owner == "/root"
            && r.primary_thread == PRIMARY
            && r.source == Path::new(SOURCE)
            && r.source_uid == 1001
            && r.source_gid == 1001
            && r.account_name == "sol"
            && r.group_name == "sol"
            && r.nss_effective_membership_resolved_to_local_files
            && r.no_other_primary_or_supplementary_members
            && r.recorded_unix_seconds <= current
            && current - r.recorded_unix_seconds <= 300
            && r.passwd.path == Path::new("/etc/passwd")
            && r.group.path == Path::new("/etc/group")
            && r.nsswitch.path == Path::new("/etc/nsswitch.conf"),
        "fresh exact sole source group review required"
    );
    Ok(())
}
fn source_group(p: &Plan) -> Result<()> {
    let review: SourceGroupReview = serde_json::from_value(bound(&p.source_group_review)?)?;
    source_group_scope(&review, now()?)?;
    group::sole_local_group(
        std::str::from_utf8(&checked_raw(&review.passwd, 1 << 20)?)?,
        std::str::from_utf8(&checked_raw(&review.group, 1 << 20)?)?,
        std::str::from_utf8(&checked_raw(&review.nsswitch, 1 << 20)?)?,
        review.source_uid,
        review.source_gid,
        &review.account_name,
        &review.group_name,
    )
}
fn claims_epoch(v: &Value, e: u64) -> bool {
    match v {
        Value::Array(a) => a.iter().any(|v| claims_epoch(v, e)),
        Value::Object(m) => {
            m.get("epoch").and_then(Value::as_u64) == Some(e)
                || m.get("range").and_then(Value::as_str).is_some_and(|s| {
                    s.parse::<u64>().ok() == Some(e)
                        || s.split_once('-')
                            .and_then(|(a, b)| {
                                Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?))
                            })
                            .is_some_and(|(a, b)| a <= e && e <= b)
                })
                || m.values().any(|v| claims_epoch(v, e))
        }
        _ => false,
    }
}
fn evidence(p: &Plan) -> Result<()> {
    let fleet = bound(&p.fleet)?;
    let event = bound(&p.stop_event)?;
    let absence = bound(&p.absence)?;
    let current = now()?;
    let at = fleet["recorded_unix_seconds"]
        .as_u64()
        .context("fleet clock")?;
    ensure!(
        fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && fleet["owner"] == "/root"
            && fleet["primary_thread"] == PRIMARY
            && at <= current
            && current - at <= 1800,
        "fresh complete Root fleet required"
    );
    let rows = fleet["epochs"].as_array().context("full epoch census")?;
    let epochs: BTreeSet<_> = rows
        .iter()
        .map(|v| v["epoch"].as_u64().context("epoch integer"))
        .collect::<Result<_>>()?;
    ensure!(
        rows.len() == 100
            && epochs == (101..=200).collect()
            && !claims_epoch(&fleet["actual_executing_replays"], p.epoch)
            && fleet["actual_executing_replays"].is_array(),
        "complete fleet must exclude target replay"
    );
    ensure!(
        fleet["actual_active_bootstraps"].is_array()
            && !claims_epoch(&fleet["actual_active_bootstraps"], p.epoch),
        "target bootstrap remains active"
    );
    ensure!(
        rows.iter()
            .any(|r| r["epoch"] == p.epoch && r["state"] != "remote-ready"),
        "already-ready target config is not eligible"
    );
    ensure!(
        event["schema"] == "horizon-seven-standard-reserve-stop-repair-event-v1"
            && event["owner"] == "/root"
            && event["primary_thread"] == PRIMARY
            && event["repair_open"] == true,
        "genuine original reserve-stop event required"
    );
    let row = event["rows"]
        .as_object()
        .and_then(|r| r.get(&p.epoch.to_string()))
        .context("exact stopped target row")?;
    ensure!(
        row["unit"] == original_unit(p.epoch) && row["preserve_partial_and_inputs"] == true,
        "original stopped target differs"
    );
    let completed = bound(&serde_json::from_value::<Bound>(
        row["stop_completion"].clone(),
    )?)?;
    ensure!(
        completed["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && completed["producer_invocation_id"] == row["original_invocation_id"]
            && completed["terminal"]["pid"] == 0
            && completed["terminal"]["active"] == "inactive",
        "original target stop is not complete"
    );
    let intent = bound(&serde_json::from_value::<Bound>(
        row["stop_intent"].clone(),
    )?)?;
    ensure!(
        intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && intent["producer_invocation_id"] == row["original_invocation_id"]
            && intent["reason"] == "filesystem-floor"
            && completed["intent"] == row["stop_intent"]["path"]
            && completed["plan_sha256"] == intent["plan_sha256"],
        "original target intent/completion chain differs"
    );
    let journal = bound(&serde_json::from_value::<Bound>(row["journal"].clone())?)?;
    ensure!(
        journal
            .as_array()
            .context("original PID1 stop journal")?
            .iter()
            .any(|r| r["_PID"] == "1"
                && r["UNIT"] == row["unit"]
                && r["INVOCATION_ID"] == row["original_invocation_id"]
                && (r["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286"
                    || r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")),
        "original PID1 terminal proof required"
    );
    let at = absence["recorded_unix_seconds"]
        .as_u64()
        .context("absence clock")?;
    ensure!(
        absence["schema"] == "horizon-idle-gcloud-copy-absence-v1"
            && absence["owner"] == "/root"
            && absence["epoch"] == p.epoch
            && absence["fleet"] == serde_json::to_value(&p.fleet)?
            && absence["stop_event"] == serde_json::to_value(&p.stop_event)?
            && absence["closed_units"] == serde_json::to_value(&p.closed_units)?
            && at <= current
            && current - at <= 300,
        "fresh exact idle-target review required"
    );
    for key in [
        "no_live_target_owner",
        "no_staged_target_launch",
        "admission_serialized_through_copy",
        "stage_is_not_an_effective_live_configuration",
    ] {
        ensure!(absence[key] == true, "idle target gate missing: {key}");
    }
    Ok(())
}
fn native(unit: &str) -> Result<Value> {
    let output=Command::new("/usr/bin/systemctl").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(["show",unit,"-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Job,Restart"]).output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty() && output.stdout.len() <= 65536,
        "native service query failed"
    );
    let mut out = serde_json::Map::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native delimiter")?;
        ensure!(out.insert(k.into(), json!(v)).is_none(), "native duplicate");
    }
    let v = Value::Object(out);
    ensure!(v["Id"] == unit, "native unit differs");
    Ok(v)
}
fn closed(v: &Value) -> Result<()> {
    ensure!(
        v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Job"] == ""
            && ["inactive", "failed"]
                .iter()
                .any(|s| v["ActiveState"] == *s)
            && ["dead", "failed"].iter().any(|s| v["SubState"] == *s),
        "target owner is active or queued"
    );
    Ok(())
}
fn owners(p: &Plan) -> Result<Vec<Value>> {
    p.closed_units
        .iter()
        .map(|u| {
            let n = native(u)?;
            closed(&n)?;
            Ok(n)
        })
        .collect()
}
fn private_out() -> Result<File> {
    let file = copy::open_directory(Path::new(OUT))?;
    let m = file.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "private receipt directory required"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "configuration-copy serialization is busy"
    );
    Ok(file)
}
fn persist(path: &Path, value: &Value) -> Result<()> {
    ensure!(
        path.parent() == Some(Path::new(OUT)),
        "receipt outside private namespace"
    );
    atomic_json(Path::new(OUT), path, value)
}
fn atomic_json(parent: &Path, path: &Path, value: &Value) -> Result<()> {
    let directory = copy::open_directory(parent)?;
    let m = directory.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o7777 == 0o700 && path.parent() == Some(parent),
        "private atomic receipt parent required"
    );
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer(&mut temporary, value)?;
    temporary.write_all(b"\n")?;
    ensure!(
        temporary.as_file().metadata()?.len() <= 1 << 20,
        "receipt bound exceeded"
    );
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|_| anyhow::anyhow!("receipt conflict; existing attempt preserved"))?;
    directory.sync_all()?;
    Ok(())
}
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 6
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && lower_sha(&args[3])
            && lower_sha(&args[5]),
        "usage: copy PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0 && fs::read_link("/proc/self/exe")? == Path::new(IMAGE),
        "normally sealed Root copy image required"
    );
    ensure!(
        fs::symlink_metadata(IMAGE)?.mode() & 0o222 == 0,
        "immutable copy image required"
    );
    unsafe {
        libc::umask(0o077);
    }
    ensure!(
        copy::hash(&raw(Path::new(IMAGE), 64 << 20)?) == args[5],
        "self digest differs"
    );
    let binding = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_value(bound(&binding)?)?;
    scope(&p)?;
    let _serialization = private_out()?;
    ensure!(
        !present(&p.intent)? && !present(&p.receipt)?,
        "attempt already exists; preserve and use a new stage name"
    );
    evidence(&p)?;
    source_group(&p)?;
    let before = owners(&p)?;
    let source = copy::open_directory(&p.source)?;
    let parent = copy::open_directory(&p.target_parent)?;
    ensure!(
        copy::Directory::from(&source.metadata()?) == p.source_identity
            && copy::Directory::from(&parent.metadata()?) == p.target_parent_identity,
        "source/parent identity changed"
    );
    let target = p.target_parent.join(&p.stage_leaf);
    ensure!(
        !present(&target)?,
        "stage already exists; no overwrite allowed"
    );
    persist(
        &p.intent,
        &json!({"schema":"horizon-idle-gcloud-copy-intent-v6","plan":binding,"epoch":p.epoch,"source":p.source,"source_group_review":p.source_group_review,"target_stage":target,"recorded_unix_seconds":now()?,"install_authorized":false,"replay_launch_authorized":false}),
    )?;
    let snapshot = copy::copy_stage_profile(
        &source,
        &parent,
        &p.stage_leaf,
        p.source_uid,
        p.target_uid,
        p.target_gid,
        Some(1001),
        || Ok(()),
    )?;
    ensure!(
        copy::Directory::from(&copy::open_directory(&p.source)?.metadata()?) == p.source_identity
            && copy::Directory::from(&copy::open_directory(&p.target_parent)?.metadata()?)
                == p.target_parent_identity,
        "source/parent namespace changed"
    );
    evidence(&p)?;
    source_group(&p)?;
    ensure!(
        owners(&p)? == before,
        "target owner changed during stage copy"
    );
    persist(
        &p.receipt,
        &json!({"schema":"horizon-idle-gcloud-copy-staged-v6","plan":binding,"epoch":p.epoch,"source":p.source,"source_group_review":p.source_group_review,"target_stage":target,"source_identity":p.source_identity,"target_parent_identity":p.target_parent_identity,"source_snapshot_sha256":snapshot.source_digest()?,"copied_logical_tree_sha256":snapshot.logical_digest()?,"copied_bytes":snapshot.bytes,"copied_entries_including_root":snapshot.count(),"target_uid":p.target_uid,"target_gid":p.target_gid,"private_directory_mode":0o700,"source_file_modes_preserved_in_snapshot":true,"copied_file_modes_are_source_modes_without_group_write":true,"file_mtime_preserved":true,"credential_mode0600_preserved":true,"source_stable_before_and_after":true,"target_full_bytes_verified":true,"owner_before_and_after":before,"recorded_unix_seconds":now()?,"stage_only":true,"network_probe_performed":false,"authentication_qualified":false,"atomic_effective_config_install_performed":false,"install_authorized":false,"replay_launch_authorized":false,"resource_credit_bytes":0,"remote_mutations":false}),
    )?;
    println!("{}", p.receipt.display());
    Ok(())
}

#[cfg(test)]
mod tests;
