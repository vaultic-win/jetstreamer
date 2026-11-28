//! One explicitly selected recovery of the retained epoch77 download after
//! Root migrates the audit's state and reader roots to home-backed bind mounts.
//! This is not a generic retry reset or reader-equivalence exception.
use crate::{
    Config, Outcome, finish_attempt,
    local::*,
    playback_downloaded, progress,
    remote::{Download, Inventory, Object, Remote, TransferIdentity},
    retry, source,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

const STATE: &str = "/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1";
const ATTEMPT: &str = "epoch-77-retry1-1795093911418604043";
const INTENT: &str = "downloaded-resume.intent.json";
const COMPLETE: &str = "downloaded-resume.complete.json";
const LOGS: &str = "downloaded-resume-20261119";
const OLD_PID: u32 = 1_888_508;
const OLD_START_TICKS: u64 = 342_135_132;
const UNIT: &str = "horizon-r2-chronological-plugin-audit-20261118-v1.service";

#[derive(Serialize)]
struct Pins {
    epoch: u64,
    ordinal: u32,
    attempt: PathBuf,
    files: BTreeMap<PathBuf, String>,
}
fn production_pins(cfg: &Config) -> Result<Pins> {
    ensure!(
        cfg.state_directory == Path::new(STATE),
        "recovery is scoped to the original audit state path"
    );
    let attempt = cfg.state_directory.join("attempts").join(ATTEMPT);
    let files = [
        (
            cfg.state_directory.join("inventory.json"),
            "d38d5146d50b7788cf5866fa0f7f5aeefade92fbf0496398fee334b480b7084e",
        ),
        (
            retry::ticket_path(cfg, 77, 1),
            "b3fc45bc2e24879ca5720cc7e541fd36453203c955aa5f6fd53c1c12c6ffb777",
        ),
        (
            attempt.join("started.json"),
            "3787a044ccc13b3c326e20434f6539dfb6a65ec4c6911075c2686b408f20a04f",
        ),
        (
            attempt.join("download.json"),
            "6587ffee40cba54a35d12c7053b7c2cec24bd4c86ad2ac287f7afd99bbad0822",
        ),
        (
            attempt.join("download-identity.json"),
            "66ef76a47098158db200e83431939b584280accb09aa21fac829dca03544a37d",
        ),
        (
            cfg.state_directory.join("scratch-owner.json"),
            "9f111c2b7cd0d461f69fca69b2ba5a92cd24f3ea81e511f232e38c336fccd5fe",
        ),
    ]
    .into_iter()
    .map(|(p, h)| (p, h.to_owned()))
    .collect();
    Ok(Pins {
        epoch: 77,
        ordinal: 1,
        attempt,
        files,
    })
}

/// Include change timestamps and length, not just inode, around the complete
/// copied-body hash. atime is intentionally excluded because this read changes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CopyStamp {
    identity: Identity,
    length: u64,
    mode: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}
fn stamp(m: &Metadata, required_uid: u32) -> Result<CopyStamp> {
    ensure!(
        m.is_file() && m.nlink() == 1 && m.uid() == required_uid && m.mode() & 0o222 == 0,
        "copied archive must be a read-only single-link file in root custody"
    );
    Ok(CopyStamp {
        identity: Identity {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
        },
        length: m.len(),
        mode: m.mode(),
        gid: m.gid(),
        modified_seconds: m.mtime(),
        modified_nanoseconds: m.mtime_nsec(),
        changed_seconds: m.ctime(),
        changed_nanoseconds: m.ctime_nsec(),
    })
}
fn pinned_bytes(path: &Path, expected: &str) -> Result<Vec<u8>> {
    let mut file = open_read(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.len() <= MAX_JSON_BYTES
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "recovery metadata exceeds its bound or lost private owner custody"
    );
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_JSON_BYTES && digest(&bytes) == expected,
        "original recovery metadata changed: {}",
        path.display()
    );
    Ok(bytes)
}
fn check_pins(pins: &Pins) -> Result<()> {
    for (path, expected) in &pins.files {
        pinned_bytes(path, expected)?;
    }
    Ok(())
}

fn original_controller_gone() -> Result<()> {
    match fs::read_to_string(format!("/proc/{OLD_PID}/stat")) {
        Ok(text) => {
            let ticks: u64 = text
                .rsplit_once(')')
                .context("original proc framing")?
                .1
                .split_whitespace()
                .nth(19)
                .context("original proc start ticks")?
                .parse()?;
            ensure!(
                ticks != OLD_START_TICKS,
                "original audit controller still owns the old state"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    // A copied audit.lock cannot fence a restarted owner on the old filesystem.
    // The original unit must be drained or already be this successor invocation.
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", UNIT, "-pMainPID,ControlPID,Job"])
        .output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() < 4096,
        "cannot establish original audit unit ownership"
    );
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native audit field")?;
        ensure!(
            fields.insert(k, v).is_none(),
            "duplicate native audit field"
        );
    }
    let pid: u32 = fields
        .get("MainPID")
        .context("missing audit MainPID")?
        .parse()?;
    ensure!(
        (pid == 0 || pid == std::process::id())
            && fields.get("ControlPID") == Some(&"0")
            && fields.get("Job") == Some(&""),
        "another original audit unit invocation is active or queued"
    );
    Ok(())
}
fn home_storage(cfg: &Config) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && cfg.external_scratch.is_none(),
        "download recovery requires root custody and the original internal scratch path"
    );
    let device = fs::metadata("/home/sol")?.dev();
    for path in [
        cfg.state_directory.clone(),
        cfg.scratch_directory(),
        PathBuf::from(source::READER_ROOT),
        cfg.cargo_home.clone(),
        cfg.git_home.clone(),
    ] {
        validate_absolute(&path)?;
        ensure!(
            fs::symlink_metadata(&path)?.is_dir() && fs::metadata(&path)?.dev() == device,
            "all audit storage must use the admitted home filesystem: {}",
            path.display()
        );
    }
    // Existing phase directories must not remain independent OS mounts. New
    // phase directories are created directly beneath the bound state root.
    for name in [
        "source",
        "build",
        "build-tmp",
        "attempts",
        "results",
        "reader",
    ] {
        let path = cfg.state_directory.join(name);
        if path.try_exists()? {
            validate_absolute(&path)?;
            ensure!(
                fs::metadata(&path)?.is_dir() && fs::metadata(&path)?.dev() == device,
                "audit phase directory remained on another filesystem"
            );
        }
    }
    Ok(())
}

fn validate_started(started: &Outcome, object: &Object, ticket: &retry::RetryTicket) -> Result<()> {
    ensure!(
        started.schema == "horizon-r2-chronological-plugin-audit-result-v1"
            && started.epoch == object.epoch
            && started.object == *object
            && started.attempt == ticket.attempt
            && started.retry_of.as_ref() == Some(&ticket.binding)
            && started.started_at >= ticket.recorded_at
            && started.finished_at == 0
            && started.status == "failed"
            && started.error.is_none()
            && started.download.is_none()
            && started.playback.is_none()
            && started.reader.is_none()
            && started.invocation.is_empty()
            && started.transfer_interruption.is_none()
            && !started.remote_mutations,
        "original retry start record does not describe this incomplete download attempt"
    );
    Ok(())
}
fn validate_download(
    download: &Download,
    identity: &TransferIdentity,
    object: &Object,
    prior: Option<&TransferIdentity>,
) -> Result<()> {
    ensure!(
        download.object == *object
            && download.bytes == object.bytes
            && crate::remote::valid_digest(&download.sha256)
            && identity.bucket == "solana-archive-with-accounts-data"
            && download.identity(&identity.bucket) == *identity
            && prior.is_none_or(|p| p == identity)
            && download
                .sidecar_sha256
                .as_ref()
                .is_none_or(|v| v == &download.sha256)
            && download
                .metadata_sha256
                .as_ref()
                .is_none_or(|v| v == &download.sha256),
        "retained complete download does not bind the exact authenticated object and retry"
    );
    Ok(())
}
fn validate_remote(
    download: &Download,
    retained: &TransferIdentity,
    current: &TransferIdentity,
) -> Result<()> {
    ensure!(
        current == retained && download.identity(&current.bucket) == *current,
        "remote identity changed before copied-download recovery"
    );
    Ok(())
}
fn only_archive(cfg: &Config, object: &Object) -> Result<PathBuf> {
    private_dir(&cfg.scratch_directory())?;
    let entries = fs::read_dir(cfg.scratch_directory())?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() == 1 && entries[0].file_name() == std::ffi::OsStr::new(&object.key),
        "copied scratch has missing, substituted or unknown files"
    );
    let path = cfg.scratch_directory().join(&object.key);
    validate_absolute(&path)?;
    Ok(path)
}
struct Inputs {
    object: Object,
    ticket: retry::RetryTicket,
    started: Outcome,
    download: Download,
    identity: TransferIdentity,
    old_owned: OwnedScratch,
    candidate: CopyStamp,
    archive: PathBuf,
}
fn inputs(cfg: &Config, inventory: &Inventory, pins: &Pins, required_uid: u32) -> Result<Inputs> {
    ensure!(
        !cfg.state_directory.join(INTENT).try_exists()?
            && !cfg.state_directory.join(COMPLETE).try_exists()?,
        "download recovery was already selected; inspect its durable state, never reset it"
    );
    check_pins(pins)?;
    let object = inventory
        .objects
        .iter()
        .find(|o| o.epoch == pins.epoch)
        .context("original inventory lacks the selected recovery epoch")?
        .clone();
    ensure!(
        inventory.bucket == "solana-archive-with-accounts-data"
            && inventory.schema == "horizon-r2-chronological-audit-inventory-v1",
        "recovery inventory changed"
    );
    ensure!(
        matches!(fs::symlink_metadata(retry::result_path(cfg, object.epoch, pins.ordinal)),
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound),
        "selected retry has a terminal result or an uninspectable result path"
    );
    let ticket = retry::incomplete_ticket(cfg, &object)?;
    ensure!(
        ticket.binding.ordinal == pins.ordinal && ticket.attempt == pins.attempt,
        "selected recovery retry identity changed"
    );
    validate_absolute(&ticket.attempt)?;
    private_dir(&ticket.attempt)?;
    // Preserve chronological scheduling: nothing earlier may still require an
    // original attempt, transfer retry or interrupted-ticket disposition.
    for earlier in inventory
        .objects
        .iter()
        .take_while(|o| o.epoch < object.epoch)
    {
        let v =
            retry::view(cfg, earlier)?.context("earlier inventory epoch remains unattempted")?;
        ensure!(
            !v.retry_available() && !retry::has_incomplete(&v),
            "earlier retry must finish first"
        );
    }
    let started: Outcome = read_json(&ticket.attempt.join("started.json"))?;
    validate_started(&started, &object, &ticket)?;
    let download: Download = read_json(&ticket.attempt.join("download.json"))?;
    let identity: TransferIdentity = read_json(&ticket.attempt.join("download-identity.json"))?;
    validate_download(
        &download,
        &identity,
        &object,
        ticket.prior_identity.as_ref(),
    )?;
    let old_owned: OwnedScratch = read_json(&cfg.state_directory.join("scratch-owner.json"))?;
    ensure!(
        old_owned.key == object.key
            && old_owned.identity.uid == required_uid
            && old_owned.external_scratch.is_none()
            && cfg.external_scratch.is_none(),
        "original scratch journal does not bind this exact internal download"
    );
    let archive = only_archive(cfg, &object)?;
    let file = open_read(&archive)?;
    let candidate = stamp(&file.metadata()?, required_uid)?;
    ensure!(
        candidate.length == object.bytes
            && candidate.identity != old_owned.identity
            && candidate.identity.device == fs::metadata(&cfg.state_directory)?.dev(),
        "copied archive size, filesystem or changed inode not established"
    );
    check_pins(pins)?;
    Ok(Inputs {
        object,
        ticket,
        started,
        download,
        identity,
        old_owned,
        candidate,
        archive,
    })
}
fn hash_copy(
    file: &mut File,
    path: &Path,
    before: &CopyStamp,
    expected: &str,
    required_uid: u32,
    mut heartbeat: impl FnMut(u64) -> Result<()>,
) -> Result<()> {
    ensure!(
        stamp(&file.metadata()?, required_uid)? == *before
            && stamp(&fs::symlink_metadata(path)?, required_uid)? == *before,
        "copy changed before hashing"
    );
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    let mut buf = vec![0; 4 * 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .context("copy hash length overflow")?;
        ensure!(bytes <= before.length, "copied archive grew during hashing");
        hash.update(&buf[..n]);
        heartbeat(bytes)?;
    }
    ensure!(
        bytes == before.length && hex(&hash.finalize()) == expected,
        "copied archive whole-file digest or length differs from authenticated download"
    );
    ensure!(
        stamp(&file.metadata()?, required_uid)? == *before
            && stamp(&fs::symlink_metadata(path)?, required_uid)? == *before,
        "copied archive changed during hashing"
    );
    Ok(())
}
fn claim(cfg: &Config, pins: &Pins, i: &Inputs) -> Result<PathBuf> {
    let logs = i.ticket.attempt.join(LOGS);
    ensure!(!logs.try_exists()?, "recovery log namespace already exists");
    check_pins(pins)?;
    write_json(
        &cfg.state_directory.join(INTENT),
        &json!({
            "schema":"horizon-r2-audit-downloaded-resume-intent-v1", "recorded_at":now(), "pid":std::process::id(),
            "object":i.object, "retry":i.ticket, "pins":pins, "old_scratch":i.old_owned,
            "copied_archive":i.archive, "new_candidate":i.candidate, "logs":logs,
            "full_new_playback_required":true, "download_required":false, "remote_mutations":false,
            "original_controller":{"pid":OLD_PID,"start_ticks":OLD_START_TICKS,"unit":UNIT}
        }),
        false,
    )?;
    private_dir(&logs)?;
    Ok(logs)
}
fn rebind(
    cfg: &Config,
    pins: &Pins,
    i: &Inputs,
    current: &TransferIdentity,
    logs: &Path,
) -> Result<()> {
    validate_remote(&i.download, &i.identity, current)?;
    check_pins(pins)?;
    ensure!(
        only_archive(cfg, &i.object)? == i.archive
            && stamp(&fs::symlink_metadata(&i.archive)?, i.candidate.identity.uid)? == i.candidate,
        "copied archive changed before ownership rebind"
    );
    let owned = OwnedScratch {
        identity: i.candidate.identity.clone(),
        ..i.old_owned.clone()
    };
    // The no-clobber intent already durably preserves the OLD ownership and all
    // original evidence hashes. Only now may its journal atomically bind the copy.
    write_json(
        &cfg.state_directory.join("scratch-owner.json"),
        &owned,
        true,
    )?;
    write_json(
        &logs.join("rebound.json"),
        &json!({
            "schema":"horizon-r2-audit-downloaded-resume-rebound-v1", "recorded_at":now(),
            "intent_sha256":hash_file(&cfg.state_directory.join(INTENT))?,
            "old_scratch":i.old_owned,"new_scratch":owned,"download":i.download,
            "authenticated_remote_identity":current,"whole_copied_archive_hash_verified":true,
            "archive_success_claimed":false,"remote_mutations":false
        }),
        false,
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    schema: String,
    intent_sha256: String,
    result: PathBuf,
    result_sha256: String,
    completed_at: u64,
    owned_copy_cleanup_completed: bool,
    full_new_playback_passed: bool,
    remote_mutations: bool,
}
fn validate_completion(cfg: &Config) -> Result<()> {
    let c: Completion = read_json(&cfg.state_directory.join(COMPLETE))?;
    let path = retry::result_path(cfg, 77, 1);
    ensure!(
        c.schema == "horizon-r2-audit-downloaded-resume-complete-v1"
            && c.intent_sha256 == hash_file(&cfg.state_directory.join(INTENT))?
            && c.result == path
            && c.result_sha256 == hash_file(&path)?
            && c.owned_copy_cleanup_completed
            && c.full_new_playback_passed
            && !c.remote_mutations,
        "download recovery completion is missing or inconsistent"
    );
    let outcome: Outcome = read_json(&path)?;
    crate::validate_outcome(&outcome, &outcome.object)?;
    ensure!(
        outcome.epoch == 77
            && outcome.status == "passed"
            && outcome.retry_of.as_ref().is_some_and(|r| r.ordinal == 1),
        "recovery did not pass full playback"
    );
    Ok(())
}
/// Called before ordinary startup cleanup: incomplete explicit recovery always
/// stays blocked for review, including a crash after terminal result publication.
fn ordinary_start_state(cfg: &Config) -> Result<bool> {
    let selected = cfg.state_directory.join(INTENT).try_exists()?
        || cfg.state_directory.join(COMPLETE).try_exists()?;
    if selected {
        validate_completion(cfg)?;
    }
    Ok(selected)
}
pub fn ordinary_start(cfg: &Config) -> Result<()> {
    if ordinary_start_state(cfg)? {
        home_storage(cfg)?;
    }
    Ok(())
}

fn complete_recovery(cfg: &Config, result: PathBuf) -> Result<()> {
    let c = Completion {
        schema: "horizon-r2-audit-downloaded-resume-complete-v1".into(),
        intent_sha256: hash_file(&cfg.state_directory.join(INTENT))?,
        result_sha256: hash_file(&result)?,
        result,
        completed_at: now(),
        owned_copy_cleanup_completed: true,
        full_new_playback_passed: true,
        remote_mutations: false,
    };
    write_json(&cfg.state_directory.join(COMPLETE), &c, false)
}

pub async fn run(cfg: &Config, remote: &Remote, inventory: &Inventory) -> Result<()> {
    original_controller_gone()?;
    home_storage(cfg)?;
    let pins = production_pins(cfg)?;
    let mut i = inputs(cfg, inventory, &pins, 0)?;
    cfg.require_operation_capacity(cfg.max_log_bytes)?;
    let logs = claim(cfg, &pins, &i)?;
    let operation: Result<()> = async {
        progress(
            cfg,
            "verifying_copied_download",
            Some(i.object.epoch),
            0,
            Some(i.object.bytes),
            None,
        )?;
        let mut file = open_read(&i.archive)?;
        let mut reported = Instant::now();
        hash_copy(
            &mut file,
            &i.archive,
            &i.candidate,
            &i.download.sha256,
            0,
            |bytes| {
                if reported.elapsed().as_secs() >= 30 {
                    cfg.require_runtime_space(0)?;
                    progress(
                        cfg,
                        "verifying_copied_download",
                        Some(i.object.epoch),
                        bytes,
                        Some(i.object.bytes),
                        None,
                    )?;
                    reported = Instant::now();
                }
                Ok(())
            },
        )?;
        let current = remote.identity(&i.object).await?;
        rebind(cfg, &pins, &i, &current, &logs)?;
        i.started.download = Some(i.download.clone());
        let mut sequence = 0;
        let playback = playback_downloaded(
            cfg,
            remote,
            &i.object,
            &logs,
            &mut sequence,
            &i.download,
            &mut i.started,
        )
        .await;
        ensure!(
            finish_attempt(
                cfg,
                &i.object,
                Some(&i.ticket),
                &logs,
                &mut i.started,
                playback
            )?,
            "recovered full playback failed; original retry budget remains consumed"
        );
        let result = retry::result_path(cfg, i.object.epoch, i.ticket.binding.ordinal);
        complete_recovery(cfg, result)?;
        Ok(())
    }
    .await;
    if let Err(error) = &operation {
        write_json(
            &logs.join("failure.json"),
            &json!({"at":now(),"error":format!("{error:#}"),
            "retry_budget_reset":false,"ordinary_restart_blocked":true,"remote_mutations":false}),
            false,
        )?;
    }
    operation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::{TransferInterruption, TransferInterruptionKind};
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        _dir: tempfile::TempDir,
        cfg: Config,
        inventory: Inventory,
        pins: Pins,
    }
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg: Config = serde_json::from_str(include_str!("../config.example.json")).unwrap();
        cfg.state_directory = dir.path().to_owned();
        for name in ["scratch", "attempts", "results"] {
            private_dir(&dir.path().join(name)).unwrap();
        }
        let bytes = b"complete authenticated epoch fixture";
        let object = Object {
            epoch: 77,
            key: "epoch-77.jet".into(),
            etag: "fixed-etag".into(),
            bytes: bytes.len() as u64,
        };
        let identity = TransferIdentity {
            bucket: "solana-archive-with-accounts-data".into(),
            object: object.clone(),
            version_id: Some("fixed-version".into()),
            metadata_sha256: Some(digest(bytes)),
            sidecar_sha256: Some(digest(bytes)),
            sidecar_etag: Some("fixed-sidecar".into()),
        };
        let original = Outcome {
            schema: "horizon-r2-chronological-plugin-audit-result-v1".into(),
            epoch: 77,
            status: "failed".into(),
            object: object.clone(),
            attempt: cfg.state_directory.join("attempts/initial"),
            started_at: 1,
            finished_at: 2,
            download: None,
            reader: None,
            playback: None,
            invocation: vec![],
            error: Some("body interrupted".into()),
            transfer_interruption: Some(TransferInterruption {
                kind: TransferInterruptionKind::BodyReadError,
                identity: identity.clone(),
                downloaded_bytes: 3,
                detail: "interrupted".into(),
            }),
            retry_of: None,
            remote_mutations: false,
        };
        let original_path = crate::outcome_path(&cfg, 77);
        write_json(&original_path, &original, false).unwrap();
        let original_sha = hash_file(&original_path).unwrap();
        let attempt = cfg.state_directory.join("attempts").join(ATTEMPT);
        private_dir(&attempt).unwrap();
        let ticket = retry::RetryTicket {
            schema: "horizon-r2-audit-transfer-retry-intent-v1".into(),
            object: object.clone(),
            binding: retry::RetryBinding {
                ordinal: 1,
                original_result_sha256: original_sha.clone(),
                previous_result_sha256: original_sha,
            },
            attempt: attempt.clone(),
            recorded_at: 30,
            not_before: 32,
            prior_identity: Some(identity.clone()),
        };
        write_json(&retry::ticket_path(&cfg, 77, 1), &ticket, false).unwrap();
        let started = Outcome {
            schema: original.schema.clone(),
            epoch: 77,
            status: "failed".into(),
            object: object.clone(),
            attempt: attempt.clone(),
            started_at: 32,
            finished_at: 0,
            download: None,
            reader: None,
            playback: None,
            invocation: vec![],
            error: None,
            transfer_interruption: None,
            retry_of: Some(ticket.binding.clone()),
            remote_mutations: false,
        };
        write_json(&attempt.join("started.json"), &started, false).unwrap();
        let download = Download {
            object: object.clone(),
            version_id: identity.version_id.clone(),
            sha256: digest(bytes),
            bytes: object.bytes,
            sidecar_sha256: identity.sidecar_sha256.clone(),
            sidecar_etag: identity.sidecar_etag.clone(),
            metadata_sha256: identity.metadata_sha256.clone(),
        };
        write_json(&attempt.join("download.json"), &download, false).unwrap();
        write_json(&attempt.join("download-identity.json"), &identity, false).unwrap();
        let archive = cfg.scratch_directory().join(&object.key);
        fs::write(&archive, bytes).unwrap();
        let owner = OwnedScratch {
            key: object.key.clone(),
            identity: Identity::from_file(&open_read(&archive).unwrap()).unwrap(),
            created_at: 33,
            external_scratch: None,
        };
        write_json(
            &cfg.state_directory.join("scratch-owner.json"),
            &owner,
            false,
        )
        .unwrap();
        // Allocate the copy before replacing the old file, so inode reuse cannot
        // make this test accidentally exercise a same-inode non-migration.
        let copied = cfg.state_directory.join("copy");
        fs::write(&copied, bytes).unwrap();
        set_readonly(&copied).unwrap();
        fs::rename(copied, &archive).unwrap();
        let inventory = Inventory {
            schema: "horizon-r2-chronological-audit-inventory-v1".into(),
            bucket: identity.bucket.clone(),
            observed_at: 1,
            objects: vec![object],
        };
        write_json(
            &cfg.state_directory.join("inventory.json"),
            &inventory,
            false,
        )
        .unwrap();
        let files = [
            cfg.state_directory.join("inventory.json"),
            retry::ticket_path(&cfg, 77, 1),
            attempt.join("started.json"),
            attempt.join("download.json"),
            attempt.join("download-identity.json"),
            cfg.state_directory.join("scratch-owner.json"),
        ]
        .into_iter()
        .map(|p| {
            let h = hash_file(&p).unwrap();
            (p, h)
        })
        .collect();
        let pins = Pins {
            epoch: 77,
            ordinal: 1,
            attempt,
            files,
        };
        Fixture {
            _dir: dir,
            cfg,
            inventory,
            pins,
        }
    }
    fn load(f: &Fixture) -> Inputs {
        inputs(&f.cfg, &f.inventory, &f.pins, unsafe { libc::geteuid() }).unwrap()
    }
    fn hash(i: &Inputs) -> Result<()> {
        hash_copy(
            &mut open_read(&i.archive)?,
            &i.archive,
            &i.candidate,
            &i.download.sha256,
            unsafe { libc::geteuid() },
            |_| Ok(()),
        )
    }
    #[test]
    fn copied_body_and_remote_identity_precede_rebind_with_original_receipts_retained() {
        let f = fixture();
        let i = load(&f);
        let original: BTreeMap<_, _> = f
            .pins
            .files
            .keys()
            .map(|p| (p.clone(), fs::read(p).unwrap()))
            .collect();
        let logs = claim(&f.cfg, &f.pins, &i).unwrap();
        let old: OwnedScratch =
            read_json(&f.cfg.state_directory.join("scratch-owner.json")).unwrap();
        assert_eq!(old.identity, i.old_owned.identity);
        hash(&i).unwrap();
        rebind(&f.cfg, &f.pins, &i, &i.identity, &logs).unwrap();
        let new: OwnedScratch =
            read_json(&f.cfg.state_directory.join("scratch-owner.json")).unwrap();
        assert_eq!(new.identity, i.candidate.identity);
        for (p, b) in original {
            if p.file_name().unwrap() != "scratch-owner.json" {
                assert_eq!(fs::read(p).unwrap(), b);
            }
        }
        let intent: serde_json::Value = read_json(&f.cfg.state_directory.join(INTENT)).unwrap();
        assert_eq!(
            intent["old_scratch"]["identity"],
            serde_json::to_value(old.identity).unwrap()
        );
        assert!(!retry::result_path(&f.cfg, 77, 1).exists());
        assert!(!f.cfg.state_directory.join(COMPLETE).exists());
        assert!(ordinary_start(&f.cfg).is_err());
        assert!(f.cfg.scratch_directory().join("epoch-77.jet").exists());
    }
    #[test]
    fn exact_metadata_pins_reject_changed_inventory_start_download_and_owner() {
        for index in 0..6 {
            let f = fixture();
            let p = f.pins.files.keys().nth(index).unwrap();
            fs::write(p, b"{}").unwrap();
            assert!(inputs(&f.cfg, &f.inventory, &f.pins, unsafe { libc::geteuid() }).is_err());
            assert!(!f.cfg.state_directory.join(INTENT).exists());
            assert!(f.cfg.scratch_directory().join("epoch-77.jet").exists());
        }
    }
    #[test]
    fn retained_download_requires_digest_length_object_and_all_remote_fields() {
        let f = fixture();
        let i = load(&f);
        for field in 0..5 {
            let mut d = i.download.clone();
            match field {
                0 => d.sha256 = "0".repeat(64),
                1 => d.bytes += 1,
                2 => d.object.etag.push('x'),
                3 => d.version_id = None,
                _ => d.sidecar_etag = None,
            }
            assert!(
                validate_download(&d, &i.identity, &i.object, i.ticket.prior_identity.as_ref())
                    .is_err()
            );
        }
        for field in 0..7 {
            let mut current = i.identity.clone();
            match field {
                0 => current.bucket.push('x'),
                1 => current.object.bytes += 1,
                2 => current.object.etag.push('x'),
                3 => current.version_id = None,
                4 => current.metadata_sha256 = None,
                5 => current.sidecar_sha256 = None,
                _ => current.sidecar_etag = None,
            }
            assert!(validate_remote(&i.download, &i.identity, &current).is_err());
        }
        let mut start = i.started;
        start.retry_of.as_mut().unwrap().ordinal = 2;
        assert!(validate_started(&start, &i.object, &i.ticket).is_err());
    }
    #[test]
    fn copied_content_and_size_mismatch_cannot_rebind() {
        let f = fixture();
        let i = load(&f);
        let mut file = open_read(&i.archive).unwrap();
        assert!(
            hash_copy(
                &mut file,
                &i.archive,
                &i.candidate,
                &"0".repeat(64),
                unsafe { libc::geteuid() },
                |_| Ok(())
            )
            .is_err()
        );
        fs::set_permissions(&i.archive, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&i.archive, b"short").unwrap();
        set_readonly(&i.archive).unwrap();
        assert!(inputs(&f.cfg, &f.inventory, &f.pins, unsafe { libc::geteuid() }).is_err());
        assert!(hash(&i).is_err());
        let owner: OwnedScratch =
            read_json(&f.cfg.state_directory.join("scratch-owner.json")).unwrap();
        assert_eq!(owner.identity, i.old_owned.identity);
    }
    #[test]
    fn substituted_hardlinked_symlinked_or_unknown_scratch_is_rejected() {
        for case in 0..5 {
            let f = fixture();
            let i = load(&f);
            match case {
                0 => fs::write(f.cfg.scratch_directory().join("unknown"), b"preserve").unwrap(),
                1 => {
                    fs::hard_link(&i.archive, f.cfg.state_directory.join("extra-link")).unwrap();
                }
                2 => {
                    fs::rename(&i.archive, f.cfg.state_directory.join("saved")).unwrap();
                    std::os::unix::fs::symlink(f.cfg.state_directory.join("saved"), &i.archive)
                        .unwrap();
                }
                3 => {
                    let replacement = f.cfg.state_directory.join("replacement");
                    fs::copy(&i.archive, &replacement).unwrap();
                    set_readonly(&replacement).unwrap();
                    fs::rename(replacement, &i.archive).unwrap();
                }
                _ => fs::set_permissions(&i.archive, fs::Permissions::from_mode(0o600)).unwrap(),
            }
            if case == 3 {
                assert!(hash(&i).is_err());
            } else {
                assert!(inputs(&f.cfg, &f.inventory, &f.pins, unsafe { libc::geteuid() }).is_err());
            }
            assert!(!f.cfg.state_directory.join(INTENT).exists());
        }
    }
    #[test]
    fn existing_terminal_retry_and_changed_ticket_are_not_resumable() {
        let f = fixture();
        let mut i = load(&f);
        i.started.finished_at = 34;
        i.started.error = Some("already terminal".into());
        write_json(&retry::result_path(&f.cfg, 77, 1), &i.started, false).unwrap();
        assert!(inputs(&f.cfg, &f.inventory, &f.pins, unsafe { libc::geteuid() }).is_err());
        let f = fixture();
        let mut i = load(&f);
        i.ticket.binding.previous_result_sha256 = "f".repeat(64);
        write_json(&retry::ticket_path(&f.cfg, 77, 1), &i.ticket, true).unwrap();
        assert!(retry::incomplete_ticket(&f.cfg, &i.object).is_err());
    }
    #[test]
    fn crash_after_intent_blocks_both_restart_and_repeated_resume_without_resetting_retry() {
        let f = fixture();
        let i = load(&f);
        let original = fs::read(retry::ticket_path(&f.cfg, 77, 1)).unwrap();
        claim(&f.cfg, &f.pins, &i).unwrap();
        assert!(ordinary_start(&f.cfg).is_err());
        assert!(inputs(&f.cfg, &f.inventory, &f.pins, unsafe { libc::geteuid() }).is_err());
        assert!(claim(&f.cfg, &f.pins, &i).is_err());
        assert_eq!(
            fs::read(retry::ticket_path(&f.cfg, 77, 1)).unwrap(),
            original
        );
        assert_eq!(
            retry::incomplete_ticket(&f.cfg, &i.object)
                .unwrap()
                .binding
                .ordinal,
            1
        );
        assert!(!retry::result_path(&f.cfg, 77, 1).exists());
        assert!(!retry::ticket_path(&f.cfg, 77, 2).exists());
    }
    #[test]
    fn a_terminal_failure_or_crash_cannot_be_promoted_by_completion_flags() {
        let f = fixture();
        let mut i = load(&f);
        claim(&f.cfg, &f.pins, &i).unwrap();
        i.started.finished_at = 34;
        i.started.error = Some("full replay failed".into());
        let result = retry::result_path(&f.cfg, 77, 1);
        write_json(&result, &i.started, false).unwrap();
        assert!(ordinary_start(&f.cfg).is_err());
        let completion = Completion {
            schema: "horizon-r2-audit-downloaded-resume-complete-v1".into(),
            intent_sha256: hash_file(&f.cfg.state_directory.join(INTENT)).unwrap(),
            result_sha256: hash_file(&result).unwrap(),
            result,
            completed_at: 35,
            owned_copy_cleanup_completed: true,
            full_new_playback_passed: true,
            remote_mutations: false,
        };
        write_json(&f.cfg.state_directory.join(COMPLETE), &completion, false).unwrap();
        assert!(ordinary_start(&f.cfg).is_err());
        assert!(!retry::ticket_path(&f.cfg, 77, 2).exists());
    }

    #[test]
    fn recovery_invokes_the_shared_full_epoch_pipeline_without_tail_or_download_options() {
        let f = fixture();
        let i = load(&f);
        let report = i.ticket.attempt.join(LOGS).join("native-playback-1.json");
        let args = crate::playback_args(&f.cfg, 77, &report);
        assert_eq!(
            args,
            vec![
                "77:77".to_owned(),
                f.cfg.scratch_directory().to_string_lossy().into_owned(),
                "--threads".into(),
                "4".into(),
                "--verify-only".into(),
                "--verification-report".into(),
                report.to_string_lossy().into_owned()
            ]
        );
        assert_eq!(i.started.attempt, i.ticket.attempt);
        assert_eq!(i.started.retry_of, Some(i.ticket.binding));
    }
    // These local fixtures stand in for an already accepted playback so the
    // tests can exercise the durable tail without network, a compiler or a real
    // archive. They run both report validators, but grant no production pass.
    fn rebound_with_playback_fixture() -> (Fixture, Inputs, PathBuf) {
        let f = fixture();
        let mut i = load(&f);
        let logs = claim(&f.cfg, &f.pins, &i).unwrap();
        hash(&i).unwrap();
        rebind(&f.cfg, &f.pins, &i, &i.identity, &logs).unwrap();
        let artifact = logs.join("fixture-reader");
        fs::write(&artifact, b"synthetic test reader; never executed").unwrap();
        let native = logs.join("fixture-native.json");
        let mut invocation = vec![artifact.to_string_lossy().into_owned()];
        invocation.extend(crate::playback_args(&f.cfg, 77, &native));
        let log = logs.join("fixture-playback.log");
        fs::write(&log, format!(
            "verification-only mode; ClickHouse is disabled\nhorizon pipeline: epoch 77 (slots 33264000..=33695999) with 4 threads\nverified epoch 77 through 4 workers: slots=432000 blocks=431990 skipped=10 entries=7 transactions=8 tx_updates=9 orphan_updates=0 epoch_updates=4 account_bytes=20 stream_sha256={}\nhorizon pipeline: epoch 77 complete\n",
            "a".repeat(64))).unwrap();
        write_json(&native, &json!({
            "schema":"jetstreamer-horizon-plugin-playback-v1", "source":f.cfg.scratch_directory(),
            "invocation":invocation, "expected_first_slot":33264000, "expected_last_slot":33695999,
            "full_epoch_verified":true,
            "report":{"epoch":77,"worker_count":4,"slots":432000,"first_slot":33264000,"last_slot":33695999,
                "blocks":431990,"skipped":10,"entries":7,"transactions":8,"transaction_updates":9,
                "orphan_updates":0,"epoch_updates":4,"account_data_bytes":20,"stream_digest":vec![0xaa_u8;32]}
        }), false).unwrap();
        let mut report = crate::evidence::validate_playback(&log, 77, 4, 4096).unwrap();
        crate::evidence::validate_native_report(
            &native,
            &mut report,
            &invocation,
            &f.cfg.scratch_directory(),
        )
        .unwrap();
        i.started.download = Some(i.download.clone());
        i.started.invocation = invocation;
        i.started.playback = Some(report);
        i.started.reader = Some(source::Reader {
            branch_commit: "a".repeat(40),
            source_fingerprint: "b".repeat(64),
            source_files: BTreeMap::from([("synthetic-test-source".into(), "c".repeat(64))]),
            cargo_lock_sha256: "d".repeat(64),
            rustc_version: "synthetic test compiler".into(),
            cargo_version: "synthetic test cargo".into(),
            cargo_sha256: "e".repeat(64),
            rustc_sha256: "f".repeat(64),
            features: vec!["--no-default-features".into()],
            artifact_sha256: hash_file(&artifact).unwrap(),
            artifact,
            seal_receipt_sha256: "0".repeat(64),
            built_from_commit: "a".repeat(40),
            equivalence_reused: false,
            fetched_at: 34,
        });
        (f, i, logs)
    }
    fn retained_receipts(f: &Fixture) -> BTreeMap<PathBuf, Vec<u8>> {
        f.pins
            .files
            .keys()
            .filter(|p| p.file_name().unwrap() != "scratch-owner.json")
            .cloned()
            .chain(std::iter::once(crate::outcome_path(&f.cfg, 77)))
            .map(|p| {
                let bytes = fs::read(&p).unwrap();
                (p, bytes)
            })
            .collect()
    }
    fn assert_retained(receipts: &BTreeMap<PathBuf, Vec<u8>>) {
        for (path, bytes) in receipts {
            assert_eq!(&fs::read(path).unwrap(), bytes);
        }
    }
    #[test]
    fn recovery_success_commits_result_cleans_owned_copy_and_opens_startup_gate_in_order() {
        let (f, mut i, logs) = rebound_with_playback_fixture();
        let retained = retained_receipts(&f);
        let intent = fs::read(f.cfg.state_directory.join(INTENT)).unwrap();
        let result = retry::result_path(&f.cfg, 77, 1);
        assert!(!result.exists());
        assert!(i.archive.exists());
        assert!(ordinary_start_state(&f.cfg).is_err());
        assert!(
            finish_attempt(
                &f.cfg,
                &i.object,
                Some(&i.ticket),
                &logs,
                &mut i.started,
                Ok(())
            )
            .unwrap()
        );
        let terminal: Outcome = read_json(&result).unwrap();
        assert_eq!(terminal.status, "passed");
        assert_eq!(terminal.retry_of, Some(i.ticket.binding.clone()));
        assert_eq!(terminal.attempt, i.ticket.attempt);
        assert_eq!(terminal.started_at, 32);
        assert!(terminal.finished_at >= terminal.started_at);
        assert!(!i.archive.exists());
        assert!(!f.cfg.state_directory.join("scratch-owner.json").exists());
        assert!(
            fs::read_dir(f.cfg.scratch_directory())
                .unwrap()
                .next()
                .is_none()
        );
        let cleanup: serde_json::Value = read_json(&logs.join("cleanup.json")).unwrap();
        assert_eq!(cleanup["removed_only_owned_audit_copy"], true);
        assert!(!f.cfg.state_directory.join(COMPLETE).exists());
        assert!(ordinary_start_state(&f.cfg).is_err());
        complete_recovery(&f.cfg, result.clone()).unwrap();
        validate_completion(&f.cfg).unwrap();
        // This is the actual ordinary-start receipt gate. The independent
        // physical home-mount/custody gate remains mandatory in ordinary_start.
        assert!(ordinary_start_state(&f.cfg).unwrap());
        let view = retry::view(&f.cfg, &i.object).unwrap().unwrap();
        assert_eq!(view.latest.status, "passed");
        assert!(!view.retry_available());
        assert!(!retry::has_incomplete(&view));
        let completion = fs::read(f.cfg.state_directory.join(COMPLETE)).unwrap();
        assert!(complete_recovery(&f.cfg, result).is_err());
        assert_eq!(
            fs::read(f.cfg.state_directory.join(COMPLETE)).unwrap(),
            completion
        );
        assert_eq!(
            fs::read(f.cfg.state_directory.join(INTENT)).unwrap(),
            intent
        );
        assert!(!retry::ticket_path(&f.cfg, 77, 2).exists());
        assert_retained(&retained);
    }
    #[test]
    fn recovery_crashes_after_rebind_result_or_cleanup_keep_startup_closed_without_new_retry() {
        for boundary in 0..3 {
            let (f, mut i, _) = rebound_with_playback_fixture();
            let retained = retained_receipts(&f);
            let intent = fs::read(f.cfg.state_directory.join(INTENT)).unwrap();
            let result = retry::result_path(&f.cfg, 77, 1);
            if boundary >= 1 {
                // Persist the exact boundary reached by finish_attempt before
                // cleanup. Stop here to model a process death between writes.
                i.started.status = "passed".into();
                i.started.finished_at = now();
                crate::validate_outcome(&i.started, &i.object).unwrap();
                write_json(&result, &i.started, false).unwrap();
            }
            if boundary >= 2 {
                cleanup_scratch(&f.cfg).unwrap();
            }
            assert!(ordinary_start_state(&f.cfg).is_err());
            assert!(ordinary_start(&f.cfg).is_err());
            assert!(inputs(&f.cfg, &f.inventory, &f.pins, unsafe { libc::geteuid() }).is_err());
            assert_eq!(result.exists(), boundary >= 1);
            assert_eq!(i.archive.exists(), boundary < 2);
            assert_eq!(
                f.cfg.state_directory.join("scratch-owner.json").exists(),
                boundary < 2
            );
            assert!(!f.cfg.state_directory.join(COMPLETE).exists());
            assert!(!retry::ticket_path(&f.cfg, 77, 2).exists());
            assert!(!retry::result_path(&f.cfg, 77, 2).exists());
            assert_eq!(
                fs::read(f.cfg.state_directory.join(INTENT)).unwrap(),
                intent
            );
            if boundary == 0 {
                assert_eq!(
                    retry::incomplete_ticket(&f.cfg, &i.object)
                        .unwrap()
                        .binding
                        .ordinal,
                    1
                );
            } else {
                assert!(retry::incomplete_ticket(&f.cfg, &i.object).is_err());
                let committed = fs::read(&result).unwrap();
                assert!(write_json(&result, &i.started, false).is_err());
                assert_eq!(fs::read(&result).unwrap(), committed);
            }
            assert_retained(&retained);
        }
    }
    #[test]
    fn cleanup_failure_after_real_result_commit_never_marks_recovery_complete_or_removes_unknown_file()
     {
        let (f, mut i, logs) = rebound_with_playback_fixture();
        let retained = retained_receipts(&f);
        let unknown = f.cfg.scratch_directory().join("unowned-file");
        fs::write(&unknown, b"must remain").unwrap();
        assert!(
            finish_attempt(
                &f.cfg,
                &i.object,
                Some(&i.ticket),
                &logs,
                &mut i.started,
                Ok(())
            )
            .is_err()
        );
        let result = retry::result_path(&f.cfg, 77, 1);
        let terminal: Outcome = read_json(&result).unwrap();
        assert_eq!(terminal.status, "passed");
        assert!(!i.archive.exists());
        assert_eq!(fs::read(&unknown).unwrap(), b"must remain");
        assert!(!logs.join("cleanup.json").exists());
        assert!(!f.cfg.state_directory.join(COMPLETE).exists());
        assert!(ordinary_start_state(&f.cfg).is_err());
        assert!(ordinary_start(&f.cfg).is_err());
        assert!(!retry::ticket_path(&f.cfg, 77, 2).exists());
        assert_retained(&retained);
    }
}
