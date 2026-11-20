//! Serial, read-only historical R2 audit. See README.md for deployment gates.
mod evidence;
mod local;
mod public;
mod range;
mod remote;
mod resume;
mod retry;
mod source;

use anyhow::{Context, Result, ensure};
use local::*;
use remote::{Inventory, Object, Remote};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    env,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    pub state_directory: PathBuf,
    /// Optional separately admitted archive-only filesystem. Evidence, source,
    /// builds and sealed readers stay on the existing state filesystem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_scratch: Option<ExternalScratch>,
    pub repository: String,
    pub cargo: PathBuf,
    pub rustc: PathBuf,
    pub cargo_home: PathBuf,
    pub git_home: PathBuf,
    pub reserve_bytes: u64,
    pub max_archive_bytes: u64,
    pub build_reserve_bytes: u64,
    pub threads: u64,
    pub build_jobs: u64,
    pub max_log_bytes: u64,
    pub read_timeout_seconds: u64,
    pub download_timeout_seconds: u64,
    pub playback_timeout_seconds: u64,
    pub build_timeout_seconds: u64,
    pub wait_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalScratch {
    pub directory: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub reserve_bytes: u64,
}

impl Config {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "horizon-r2-chronological-audit-config-v1",
            "unsupported config schema"
        );
        for p in [
            &self.state_directory,
            &self.cargo,
            &self.rustc,
            &self.cargo_home,
            &self.git_home,
        ] {
            validate_absolute(p)?;
        }
        if let Some(scratch) = &self.external_scratch {
            validate_absolute(&scratch.directory)?;
            ensure!(
                scratch.reserve_bytes > 0
                    && scratch.device > 0
                    && scratch.inode > 0
                    && !scratch.directory.starts_with(&self.state_directory)
                    && !self.state_directory.starts_with(&scratch.directory),
                "external scratch needs disjoint custody and explicit positive reserve"
            );
            scratch
                .reserve_bytes
                .checked_add(self.max_archive_bytes)
                .context("external scratch budget overflow")?;
        }
        ensure!(
            matches!(
                self.repository.as_str(),
                "git@github.com:vaultic-win/jetstreamer.git"
                    | "git@github-matt-vaultic:vaultic-win/jetstreamer.git"
            ),
            "repository must be the campaign SSH origin"
        );
        ensure!(
            self.reserve_bytes > 0
                && self.max_archive_bytes > 0
                && self.build_reserve_bytes >= 1024 * 1024 * 1024,
            "explicit positive resource budgets required"
        );
        ensure!(
            (1..=64).contains(&self.threads) && (1..=16).contains(&self.build_jobs),
            "invalid thread/job bound"
        );
        ensure!(
            (1024..=1024 * 1024 * 1024).contains(&self.max_log_bytes),
            "invalid log bound"
        );
        ensure!(
            self.wait_seconds >= 1800 && self.wait_seconds <= 86400,
            "capacity wait must be 1800..86400 seconds"
        );
        ensure!(
            self.read_timeout_seconds >= 30
                && self.download_timeout_seconds >= 60
                && self.playback_timeout_seconds >= 60
                && self.build_timeout_seconds >= 60,
            "invalid execution timeout"
        );
        self.reserve_bytes
            .checked_add(self.max_archive_bytes)
            .and_then(|n| n.checked_add(self.build_reserve_bytes))
            .context("resource budget overflow")?;
        Ok(())
    }

    fn scratch_directory(&self) -> PathBuf {
        self.external_scratch.as_ref().map_or_else(
            || self.state_directory.join("scratch"),
            |scratch| scratch.directory.clone(),
        )
    }

    fn require_runtime_space(&self, archive_additional: u64) -> Result<()> {
        if let Some(scratch) = &self.external_scratch {
            validate_external_scratch(scratch, &self.state_directory)?;
            require_space(&self.state_directory, self.reserve_bytes, 0)?;
            require_space(
                &scratch.directory,
                scratch.reserve_bytes,
                archive_additional,
            )
        } else {
            require_space(
                &self.state_directory,
                self.reserve_bytes,
                archive_additional,
            )
        }
    }

    fn playback_growth_bytes(&self) -> Result<u64> {
        operation_metadata_growth(self.max_log_bytes.max(MAX_SOURCE_METADATA_LOG_BYTES))
    }

    fn require_operation_capacity(&self, max_log: u64) -> Result<()> {
        let growth = operation_metadata_growth(max_log)?;
        require_working_growth(
            working_bytes(&self.state_directory)?,
            self.build_reserve_bytes,
            growth,
        )?;
        self.require_runtime_space(0)?;
        require_space(&self.state_directory, self.reserve_bytes, growth)
    }

    fn require_download_write_capacity(&self, chunk_bytes: u64) -> Result<()> {
        // Downloads have no compiler or playback child. Retain space only for
        // the bounded controller/download records while writing this chunk.
        let (state_growth, scratch_growth) = download_reservations(
            chunk_bytes,
            2 * MAX_JSON_BYTES,
            self.external_scratch.is_some(),
        )?;
        if let Some(scratch) = &self.external_scratch {
            validate_external_scratch(scratch, &self.state_directory)?;
            require_space(&scratch.directory, scratch.reserve_bytes, scratch_growth)?;
        }
        require_space(&self.state_directory, self.reserve_bytes, state_growth)
    }

    fn require_rebuild_capacity(&self) -> Result<()> {
        let remaining = remaining_working_budget(&self.state_directory, self.build_reserve_bytes)?;
        self.require_runtime_space(0)?;
        // statvfs already excludes any resident archive. Do not add its size
        // again or credit it back: a branch change must fit the real free space
        // before rebuilding while that exact authenticated copy stays resident.
        require_space(&self.state_directory, self.reserve_bytes, remaining)
    }

    fn require_download_capacity(&self, archive_bytes: u64) -> Result<()> {
        let (state_additional, scratch_additional) = self
            .download_capacity_requirements(archive_bytes, working_bytes(&self.state_directory)?)?;
        if let Some(scratch) = &self.external_scratch {
            validate_external_scratch(scratch, &self.state_directory)?;
            require_space(&self.state_directory, self.reserve_bytes, state_additional)?;
            require_space(
                &scratch.directory,
                scratch.reserve_bytes,
                scratch_additional,
            )
        } else {
            require_space(&self.state_directory, self.reserve_bytes, state_additional)
        }
    }

    fn download_capacity_requirements(
        &self,
        archive_bytes: u64,
        working_allocated: u64,
    ) -> Result<(u64, u64)> {
        ensure!(
            archive_bytes <= self.max_archive_bytes,
            "archive {archive_bytes} exceeds max_archive_bytes {}; operator must increase admitted config budget",
            self.max_archive_bytes
        );
        let growth = self.playback_growth_bytes()?;
        require_working_growth(working_allocated, self.build_reserve_bytes, growth)?;
        download_reservations(archive_bytes, growth, self.external_scratch.is_some())
    }
}

fn require_working_growth(used: u64, budget: u64, growth: u64) -> Result<()> {
    ensure!(
        used.checked_add(growth)
            .context("working allocation overflow")?
            <= budget,
        "bounded audit metadata exceeds remaining source/build/log budget"
    );
    Ok(())
}

fn download_reservations(archive: u64, metadata_growth: u64, separate: bool) -> Result<(u64, u64)> {
    if separate {
        Ok((metadata_growth, archive))
    } else {
        Ok((
            archive
                .checked_add(metadata_growth)
                .context("capacity overflow")?,
            0,
        ))
    }
}
pub fn canonical_epoch(key: &str) -> Option<u64> {
    let value = key.strip_prefix("epoch-")?.strip_suffix(".jet")?;
    let epoch = value.parse::<u64>().ok()?;
    (value == epoch.to_string() && epoch.checked_mul(432000)?.checked_add(431999).is_some())
        .then_some(epoch)
}
#[derive(Debug, Serialize, Deserialize)]
struct Outcome {
    schema: String,
    epoch: u64,
    status: String,
    object: Object,
    attempt: PathBuf,
    started_at: u64,
    finished_at: u64,
    download: Option<remote::Download>,
    reader: Option<source::Reader>,
    playback: Option<evidence::PlaybackReport>,
    invocation: Vec<String>,
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transfer_interruption: Option<remote::TransferInterruption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_of: Option<retry::RetryBinding>,
    remote_mutations: bool,
}
pub fn progress(
    cfg: &Config,
    phase: &str,
    epoch: Option<u64>,
    bytes: u64,
    total: Option<u64>,
    detail: Option<&str>,
) -> Result<()> {
    write_json(
        &cfg.state_directory.join("progress.json"),
        &json!({
            "schema":"horizon-r2-chronological-audit-progress-v1", "updated_at":now(), "pid":std::process::id(),
            "phase":phase, "epoch":epoch, "downloaded_bytes":bytes, "archive_bytes":total, "detail":detail,
            "reserve_bytes":cfg.reserve_bytes, "max_archive_bytes":cfg.max_archive_bytes,
            "scratch_directory":cfg.scratch_directory(), "external_scratch":cfg.external_scratch,
            "next_capacity_check_at": if phase == "waiting_for_capacity" || phase == "waiting_for_reader" { Some(now()+cfg.wait_seconds) } else { None },
            "remote_mutations":false
        }),
        true,
    )
}
async fn wait(cfg: &Config, phase: &str, epoch: u64, detail: &str) -> Result<()> {
    progress(cfg, phase, Some(epoch), 0, None, Some(detail))?;
    eprintln!("epoch {epoch}: {phase}: {detail}");
    tokio::time::sleep(Duration::from_secs(cfg.wait_seconds)).await;
    Ok(())
}
fn outcome_path(cfg: &Config, epoch: u64) -> PathBuf {
    cfg.state_directory
        .join("results")
        .join(format!("epoch-{epoch}.json"))
}
fn finished(cfg: &Config, object: &Object) -> Result<bool> {
    Ok(retry::view(cfg, object)?.is_some())
}
fn validate_outcome(result: &Outcome, object: &Object) -> Result<()> {
    ensure!(
        result.schema == "horizon-r2-chronological-plugin-audit-result-v1"
            && result.epoch == object.epoch
            && result.object == *object
            && matches!(result.status.as_str(), "passed" | "failed")
            && !result.remote_mutations,
        "invalid completed audit receipt"
    );
    ensure!(
        result.status != "passed"
            || result.playback.is_some()
                && result.download.is_some()
                && result.reader.is_some()
                && result.error.is_none(),
        "incomplete success receipt"
    );
    ensure!(
        result.status != "failed" || result.error.is_some(),
        "failure receipt lacks its reason"
    );
    ensure!(
        result.transfer_interruption.is_none()
            || result.status == "failed"
                && result.download.is_none()
                && result.playback.is_none()
                && result.invocation.is_empty(),
        "transport failure marker outside download-only failure"
    );
    if let Some(transfer) = &result.transfer_interruption {
        ensure!(
            transfer.identity.object == *object
                && transfer.identity.bucket == "solana-archive-with-accounts-data"
                && transfer.downloaded_bytes <= object.bytes,
            "transport interruption identity or byte count changed"
        );
    }
    Ok(())
}
fn summary(cfg: &Config, inventory: &Inventory) -> Result<serde_json::Value> {
    let mut passed = 0;
    let mut failed = 0;
    let mut pending = 0;
    let mut recovered = 0;
    let mut retry_pending = 0;
    for object in &inventory.objects {
        if let Some(view) = retry::view(cfg, object)? {
            let result = &view.latest;
            if result.status == "passed" {
                passed += 1;
                if result.retry_of.is_some() {
                    recovered += 1;
                }
            } else {
                failed += 1;
            }
            if view.retry_available() {
                retry_pending += 1;
            }
        } else {
            pending += 1;
        }
    }
    Ok(
        json!({"archives":inventory.objects.len(), "passed":passed, "failed":failed, "pending":pending,
        "recovered_transfer_failures":recovered,"transfer_retries_pending":retry_pending,
        "smallest":inventory.objects.iter().min_by_key(|o|o.bytes), "largest":inventory.objects.iter().max_by_key(|o|o.bytes),
        "total_bytes":inventory.objects.iter().map(|o|u128::from(o.bytes)).sum::<u128>(),
        "scope":"canonical archives present in the frozen authenticated bucket inventory", "inventory_observed_at":inventory.observed_at}),
    )
}
fn playback_args(cfg: &Config, epoch: u64, native_report: &Path) -> Vec<String> {
    vec![
        format!("{epoch}:{epoch}"),
        cfg.scratch_directory().to_string_lossy().into_owned(),
        "--threads".into(),
        cfg.threads.to_string(),
        "--verify-only".into(),
        "--verification-report".into(),
        native_report.to_string_lossy().into_owned(),
    ]
}

/// The sole full-playback/acceptance route for a fresh download or a qualified
/// copied download. A recovery never substitutes an old playback report.
async fn playback_downloaded(
    cfg: &Config,
    remote: &Remote,
    object: &Object,
    logs: &Path,
    sequence: &mut u64,
    download: &remote::Download,
    outcome: &mut Outcome,
) -> Result<()> {
    let archive = cfg.scratch_directory().join(&object.key);
    // Re-fetch immediately before playback. If relevant reader changes land
    // during playback, repeat the whole epoch with that current build.
    loop {
        *sequence += 1;
        let reader = loop {
            match source::qualify(cfg, logs, *sequence) {
                Ok(reader) => break reader,
                Err(error) => {
                    write_json(
                        &logs.join(format!("reader-error-{sequence}.json")),
                        &json!({"at":now(),"error":format!("{error:#}")}),
                        false,
                    )?;
                    wait(
                        cfg,
                        "waiting_for_reader",
                        object.epoch,
                        &format!("{error:#}"),
                    )
                    .await?;
                    *sequence += 1;
                }
            }
        };
        let native_report = logs.join(format!("native-playback-{sequence}.json"));
        let args = playback_args(cfg, object.epoch, &native_report);
        let mut invocation = vec![reader.artifact.to_string_lossy().into_owned()];
        invocation.extend(args.clone());
        write_json(
            &logs.join(format!("playback-{sequence}-invocation.json")),
            &json!({"argv":invocation,"reader":reader,"download":download,
                "environment":{"PATH":"/usr/bin:/bin","LC_ALL":"C","RUST_LOG":"info","RUST_MIN_STACK":"67108864"},"other_environment_removed":true}),
            false,
        )?;
        progress(
            cfg,
            "playing_entire_epoch",
            Some(object.epoch),
            object.bytes,
            Some(object.bytes),
            None,
        )?;
        let mut command = clean_command(&reader.artifact);
        command.args(&args);
        command.current_dir(cfg.scratch_directory());
        let log = logs.join(format!("playback-{sequence}.log"));
        outcome.reader = Some(reader.clone());
        outcome.invocation = invocation;
        ensure!(
            run_logged(
                command,
                &log,
                cfg.playback_timeout_seconds,
                cfg.max_log_bytes,
                cfg
            )?,
            "plugin playback exited unsuccessfully"
        );
        let mut report =
            evidence::validate_playback(&log, object.epoch, cfg.threads, cfg.max_log_bytes)?;
        evidence::validate_native_report(
            &native_report,
            &mut report,
            &outcome.invocation,
            &cfg.scratch_directory(),
        )?;
        let owned: OwnedScratch = read_json(&cfg.state_directory.join("scratch-owner.json"))?;
        owned.identity.check(&archive)?;
        ensure!(
            hash_file(&archive)? == download.sha256,
            "audit archive changed during playback"
        );
        ensure!(
            hash_file(&reader.artifact)? == reader.artifact_sha256,
            "reader image changed during playback"
        );
        ensure!(
            remote.identity(object).await? == download.identity(&remote.bucket),
            "remote archive changed during playback"
        );
        write_json(
            &logs.join(format!("playback-{sequence}-report.json")),
            &report,
            false,
        )?;
        *sequence += 1;
        let current = loop {
            match source::qualify(cfg, logs, *sequence) {
                Ok(reader) => break reader,
                Err(error) => {
                    wait(
                        cfg,
                        "waiting_for_reader",
                        object.epoch,
                        &format!("{error:#}"),
                    )
                    .await?;
                    *sequence += 1;
                }
            }
        };
        if current.source_fingerprint == reader.source_fingerprint {
            outcome.reader = Some(current);
            outcome.playback = Some(report);
            break;
        }
        progress(
            cfg,
            "replaying_after_reader_change",
            Some(object.epoch),
            object.bytes,
            Some(object.bytes),
            None,
        )?;
    }
    Ok(())
}

fn finish_attempt(
    cfg: &Config,
    object: &Object,
    ticket: Option<&retry::RetryTicket>,
    logs: &Path,
    outcome: &mut Outcome,
    result: Result<()>,
) -> Result<bool> {
    match result {
        Ok(()) => outcome.status = "passed".into(),
        Err(error) => {
            outcome.transfer_interruption = error
                .downcast_ref::<remote::TransferInterruption>()
                .cloned();
            outcome.error = Some(format!("{error:#}"));
        }
    }
    outcome.finished_at = now();
    validate_outcome(outcome, object)?;
    // The immutable terminal receipt is committed before the only archive
    // deletion this program performs (its own download).
    let result_path = ticket.map_or_else(
        || outcome_path(cfg, object.epoch),
        |ticket| retry::result_path(cfg, object.epoch, ticket.binding.ordinal),
    );
    write_json(&result_path, outcome, false)?;
    cleanup_scratch(cfg)?;
    write_json(
        &logs.join("cleanup.json"),
        &json!({"at":now(),"removed_only_owned_audit_copy":true,"epoch":object.epoch}),
        false,
    )?;
    eprintln!("epoch {}: {}", object.epoch, outcome.status);
    Ok(outcome.status == "passed")
}

async fn audit_one(
    cfg: &Config,
    remote: &Remote,
    object: &Object,
    ticket: Option<&retry::RetryTicket>,
) -> Result<()> {
    let attempt = ticket.map_or_else(
        || {
            cfg.state_directory
                .join("attempts")
                .join(format!("epoch-{}-{}", object.epoch, nonce()))
        },
        |ticket| ticket.attempt.clone(),
    );
    private_dir(&attempt)?;
    let mut outcome = Outcome {
        schema: "horizon-r2-chronological-plugin-audit-result-v1".into(),
        epoch: object.epoch,
        status: "failed".into(),
        object: object.clone(),
        attempt: attempt.clone(),
        started_at: now(),
        finished_at: 0,
        download: None,
        reader: None,
        playback: None,
        invocation: vec![],
        error: None,
        transfer_interruption: None,
        retry_of: ticket.map(|ticket| ticket.binding.clone()),
        remote_mutations: false,
    };
    write_json(&attempt.join("started.json"), &outcome, false)?;
    // Pin a current reader before spending network/disk on the archive. Reader
    // infrastructure trouble waits; it is not recorded as archive corruption.
    let mut sequence = 0;
    loop {
        let capacity = cfg.require_download_capacity(object.bytes);
        if let Err(error) = capacity {
            wait(
                cfg,
                "waiting_for_capacity",
                object.epoch,
                &error.to_string(),
            )
            .await?;
            continue;
        }
        progress(
            cfg,
            "qualifying_reader",
            Some(object.epoch),
            0,
            Some(object.bytes),
            None,
        )?;
        sequence += 1;
        match source::qualify(cfg, &attempt, sequence) {
            Ok(reader) => {
                outcome.reader = Some(reader);
                // Fetch/build may have consumed space since the earlier gate.
                // Capacity remains an infrastructure wait, not an archive failure.
                if let Err(error) = cfg.require_download_capacity(object.bytes) {
                    wait(
                        cfg,
                        "waiting_for_capacity",
                        object.epoch,
                        &error.to_string(),
                    )
                    .await?;
                    continue;
                }
                break;
            }
            Err(error) => {
                write_json(
                    &attempt.join(format!("reader-error-{sequence}.json")),
                    &json!({"at":now(),"error":format!("{error:#}")}),
                    false,
                )?;
                wait(
                    cfg,
                    "waiting_for_reader",
                    object.epoch,
                    &format!("{error:#}"),
                )
                .await?;
            }
        }
    }
    if let Some(ticket) = ticket {
        retry::commit_ticket(cfg, object, ticket)?;
    }
    // A terminated download is never promoted. Restart recovery deletes only
    // its journaled scratch inode and repeats this epoch from byte/slot zero.
    let result: Result<()> = async {
        progress(
            cfg,
            "downloading",
            Some(object.epoch),
            0,
            Some(object.bytes),
            None,
        )?;
        let download = remote
            .download(
                cfg,
                object,
                &attempt,
                ticket.and_then(|ticket| ticket.prior_identity.as_ref()),
            )
            .await?;
        outcome.download = Some(download.clone());
        playback_downloaded(
            cfg,
            remote,
            object,
            &attempt,
            &mut sequence,
            &download,
            &mut outcome,
        )
        .await?;
        Ok(())
    }
    .await;
    finish_attempt(cfg, object, ticket, &attempt, &mut outcome, result)?;
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: horizon-r2-chronological-plugin-audit <inventory|run|resume-downloaded|run-public|status|reconfigure> CONFIG.json"
    );
    let mode = args[0].to_str().context("invalid mode")?;
    ensure!(
        matches!(
            mode,
            "inventory" | "run" | "resume-downloaded" | "run-public" | "status" | "reconfigure"
        ),
        "invalid mode"
    );
    let cfg: Config = read_json(Path::new(&args[1]))?;
    cfg.validate()?;
    if mode == "status" {
        let inventory: Inventory = read_json(&cfg.state_directory.join("inventory.json"))?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"summary":summary(&cfg,&inventory)?,"progress":read_json::<serde_json::Value>(&cfg.state_directory.join("progress.json")).ok(),
                    "child":read_json::<serde_json::Value>(&cfg.state_directory.join("child.json")).ok()})
            )?
        );
        return Ok(());
    }
    private_dir(&cfg.state_directory)?;
    let _lock = lock(&cfg.state_directory.join("audit.lock"))?;
    for dir in ["scratch", "attempts", "results", "reader"] {
        private_dir(&cfg.state_directory.join(dir))?;
    }
    let config_path = cfg.state_directory.join("accepted-config.json");
    if mode == "reconfigure" {
        let old: Config = read_json(&config_path)?;
        let mut budget_update = old.clone();
        budget_update.reserve_bytes = cfg.reserve_bytes;
        budget_update.max_archive_bytes = cfg.max_archive_bytes;
        budget_update.build_reserve_bytes = cfg.build_reserve_bytes;
        budget_update.external_scratch = cfg.external_scratch.clone();
        ensure!(
            budget_update == cfg,
            "reconfigure permits only resource budgets and idle scratch relocation; retain state/tool/source identity"
        );
        let _old_scratch_lock = lock_external_scratch(&old)?;
        let same_directory = old
            .external_scratch
            .as_ref()
            .map(|s| (&s.directory, s.device, s.inode))
            == cfg
                .external_scratch
                .as_ref()
                .map(|s| (&s.directory, s.device, s.inode));
        let _new_scratch_lock = if same_directory {
            None
        } else {
            lock_external_scratch(&cfg)?
        };
        require_idle_scratch_change(&old, &cfg)?;
        write_json(
            &cfg.state_directory
                .join(format!("config-change-{}.json", nonce())),
            &json!({"at":now(),"old":old,"new":cfg,"operator_capacity_admission_required":true}),
            false,
        )?;
        write_json(&config_path, &cfg, true)?;
        return Ok(());
    }
    if mode == "resume-downloaded" {
        ensure!(
            config_path.try_exists()? && cfg.state_directory.join("inventory.json").try_exists()?,
            "download recovery requires the original accepted configuration and frozen inventory"
        );
    }
    if config_path.try_exists()? {
        ensure!(
            read_json::<Config>(&config_path)? == cfg,
            "config changed; stop service and use the documented reviewed config-replacement procedure"
        );
    } else {
        write_json(&config_path, &cfg, false)?;
    }
    if mode == "run-public" {
        return public::supervise(&cfg, &Remote::from_env()?).await;
    }
    let _scratch_lock = lock_external_scratch(&cfg)?;
    let remote = Remote::from_env()?;
    let inventory_path = cfg.state_directory.join("inventory.json");
    let inventory: Inventory = if inventory_path.try_exists()? {
        read_json(&inventory_path)?
    } else {
        let inv = remote.inventory().await?;
        write_json(&inventory_path, &inv, false)?;
        inv
    };
    ensure!(
        inventory.bucket == remote.bucket
            && inventory.schema == "horizon-r2-chronological-audit-inventory-v1",
        "inventory identity mismatch"
    );
    for (i, obj) in inventory.objects.iter().enumerate() {
        ensure!(
            canonical_epoch(&obj.key) == Some(obj.epoch) && obj.bytes > 0,
            "invalid stored inventory object"
        );
        if i > 0 {
            ensure!(
                inventory.objects[i - 1].epoch < obj.epoch,
                "inventory is not strictly chronological"
            );
        }
    }
    if mode == "inventory" {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary(&cfg, &inventory)?)?
        );
        return Ok(());
    }
    // A crashed explicit recovery cannot fall through ordinary startup cleanup
    // or consume another retry slot. Only a fully committed recovery can resume
    // ordinary chronological scheduling.
    if mode == "resume-downloaded" {
        resume::run(&cfg, &remote, &inventory).await?;
    } else {
        resume::ordinary_start(&cfg)?;
    }
    // Preserve an interruption receipt before cleaning the old partial. A
    // terminal result, if present, remains authoritative; otherwise retry it.
    if cfg
        .state_directory
        .join("scratch-owner.json")
        .try_exists()?
    {
        let owned: OwnedScratch = read_json(&cfg.state_directory.join("scratch-owner.json"))?;
        write_json(
            &cfg.state_directory
                .join("attempts")
                .join(format!("interrupted-{}.json", nonce())),
            &json!({"at":now(),"scratch":owned,"action":"delete owned interrupted scratch and retry unfinished epoch from beginning"}),
            false,
        )?;
    }
    cleanup_scratch(&cfg)?;
    for object in &inventory.objects {
        if !finished(&cfg, object)? {
            audit_one(&cfg, &remote, object, None).await?;
        }
        retry::run_pending(&cfg, &remote, object).await?;
        write_json(
            &cfg.state_directory.join("summary.json"),
            &summary(&cfg, &inventory)?,
            true,
        )?;
    }
    progress(
        &cfg,
        "complete",
        None,
        0,
        None,
        Some("all snapshotted archives attempted; inspect failures in results"),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary(&cfg, &inventory)?)?
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_scratch_reserves_only_metadata_on_root_and_exact_archive_on_data() {
        let archive = 385_290_386_716;
        let metadata_growth = 160 * 1024 * 1024;
        assert_eq!(
            download_reservations(archive, metadata_growth, true).unwrap(),
            (metadata_growth, archive)
        );
        assert_eq!(
            download_reservations(archive, metadata_growth, false).unwrap(),
            (archive + metadata_growth, 0)
        );
        assert!(download_reservations(u64::MAX, 1, false).is_err());
    }
    #[test]
    fn observed_epoch73_fits_without_unused_build_or_maximum_archive_charge() {
        let mut cfg: Config = serde_json::from_str(include_str!("../config.example.json")).unwrap();
        cfg.max_archive_bytes = 360 * 1024 * 1024 * 1024;
        let archive = 13_978_437_633;
        let working_allocated = 6_139_572_224;
        let free = 53_100_396_544;
        let before = cfg
            .download_capacity_requirements(archive, working_allocated)
            .unwrap();
        assert_eq!(before, (archive + 167_772_160, 0));
        require_available(free, cfg.reserve_bytes, before.0).unwrap();
        assert!(
            require_available(
                free,
                cfg.reserve_bytes,
                archive + cfg.build_reserve_bytes - working_allocated
            )
            .is_err()
        );
        assert!(require_available(free, cfg.reserve_bytes, cfg.max_archive_bytes).is_err());
        cfg.max_archive_bytes *= 2;
        cfg.build_reserve_bytes *= 2;
        assert_eq!(
            before,
            cfg.download_capacity_requirements(archive, working_allocated)
                .unwrap()
        );
        assert!(
            require_available(
                cfg.reserve_bytes + before.0 - 1,
                cfg.reserve_bytes,
                before.0
            )
            .is_err()
        );
    }
    #[test]
    fn metadata_budget_and_archive_cap_remain_hard_limits() {
        let cfg: Config = serde_json::from_str(include_str!("../config.example.json")).unwrap();
        let growth = cfg.playback_growth_bytes().unwrap();
        assert!(
            cfg.download_capacity_requirements(1, cfg.build_reserve_bytes - growth)
                .is_ok()
        );
        assert!(
            cfg.download_capacity_requirements(1, cfg.build_reserve_bytes - growth + 1)
                .is_err()
        );
        assert!(
            cfg.download_capacity_requirements(cfg.max_archive_bytes + 1, 0)
                .is_err()
        );
    }
    #[test]
    fn changed_reader_growth_uses_free_space_after_resident_archive_once() {
        let floor = 32 * 1024 * 1024 * 1024;
        let archive = 14 * 1024 * 1024 * 1024;
        let rebuild_remaining = 11 * 1024 * 1024 * 1024;
        let before_download = floor + archive + rebuild_remaining - 1;
        let free_after_download = before_download - archive;
        assert!(require_available(free_after_download, floor, rebuild_remaining).is_err());
        require_available(free_after_download + 1, floor, rebuild_remaining).unwrap();
        // Metadata-only playback remains possible at the same actual free space.
        require_available(
            free_after_download,
            floor,
            operation_metadata_growth(128 << 20).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn legacy_config_defaults_to_original_scratch() {
        let cfg: Config = serde_json::from_str(include_str!("../config.example.json")).unwrap();
        assert!(cfg.external_scratch.is_none());
        assert_eq!(cfg.scratch_directory(), cfg.state_directory.join("scratch"));
        assert!(
            serde_json::to_value(&cfg)
                .unwrap()
                .get("external_scratch")
                .is_none()
        );
    }
    #[test]
    fn scratch_config_rejects_overlap_and_unbounded_reservation() {
        let mut cfg: Config = serde_json::from_str(include_str!("../config.example.json")).unwrap();
        cfg.external_scratch = Some(ExternalScratch {
            directory: cfg.state_directory.join("scratch"),
            device: 64512,
            inode: 123,
            reserve_bytes: 1,
        });
        assert!(cfg.validate().is_err());
        cfg.external_scratch.as_mut().unwrap().directory = PathBuf::from("/separate-audit-scratch");
        cfg.external_scratch.as_mut().unwrap().reserve_bytes = 0;
        assert!(cfg.validate().is_err());
        cfg.external_scratch.as_mut().unwrap().reserve_bytes = u64::MAX;
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn canonical_filter_and_numeric_order() {
        let mut epochs: Vec<_> = [
            "epoch-10.jet",
            "epoch-2.jet",
            "epoch-0.jet",
            "epoch-01.jet",
            "scratch/epoch-1.jet",
            "epoch-1.jet.sha256",
            "epoch--1.jet",
            "epoch-18446744073709551615.jet",
        ]
        .iter()
        .filter_map(|k| canonical_epoch(k))
        .collect();
        epochs.sort_unstable();
        assert_eq!(epochs, vec![0, 2, 10]);
    }
    #[test]
    fn unfinished_attempt_is_never_skipped_and_success_requires_evidence() {
        let d = tempfile::tempdir().unwrap();
        let mut cfg: Config = serde_json::from_str(include_str!("../config.example.json")).unwrap();
        cfg.state_directory = d.path().to_owned();
        private_dir(&d.path().join("results")).unwrap();
        let object = Object {
            epoch: 1,
            key: "epoch-1.jet".into(),
            etag: "abc".into(),
            bytes: 100,
        };
        write_json(&d.path().join("started.json"), &json!({"epoch":1}), false).unwrap();
        assert!(!finished(&cfg, &object).unwrap());
        let result = Outcome {
            schema: "horizon-r2-chronological-plugin-audit-result-v1".into(),
            epoch: 1,
            status: "passed".into(),
            object: object.clone(),
            attempt: d.path().into(),
            started_at: 1,
            finished_at: 2,
            download: None,
            reader: None,
            playback: None,
            invocation: vec![],
            error: None,
            transfer_interruption: None,
            retry_of: None,
            remote_mutations: false,
        };
        write_json(&outcome_path(&cfg, 1), &result, false).unwrap();
        assert!(finished(&cfg, &object).is_err());
    }
}
