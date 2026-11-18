//! Serial, read-only historical R2 audit. See README.md for deployment gates.
mod evidence;
mod local;
mod remote;
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
    let path = outcome_path(cfg, object.epoch);
    if !path.try_exists()? {
        return Ok(false);
    }
    let result: Outcome = read_json(&path)?;
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
    Ok(true)
}
fn summary(cfg: &Config, inventory: &Inventory) -> Result<serde_json::Value> {
    let mut passed = 0;
    let mut failed = 0;
    let mut pending = 0;
    for object in &inventory.objects {
        if finished(cfg, object)? {
            let result: Outcome = read_json(&outcome_path(cfg, object.epoch))?;
            if result.status == "passed" {
                passed += 1;
            } else {
                failed += 1;
            }
        } else {
            pending += 1;
        }
    }
    Ok(
        json!({"archives":inventory.objects.len(), "passed":passed, "failed":failed, "pending":pending,
        "smallest":inventory.objects.iter().min_by_key(|o|o.bytes), "largest":inventory.objects.iter().max_by_key(|o|o.bytes),
        "total_bytes":inventory.objects.iter().map(|o|u128::from(o.bytes)).sum::<u128>(),
        "scope":"canonical archives present in the frozen authenticated bucket inventory", "inventory_observed_at":inventory.observed_at}),
    )
}
async fn audit_one(cfg: &Config, remote: &Remote, object: &Object) -> Result<()> {
    let attempt =
        cfg.state_directory
            .join("attempts")
            .join(format!("epoch-{}-{}", object.epoch, nonce()));
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
        remote_mutations: false,
    };
    write_json(&attempt.join("started.json"), &outcome, false)?;
    // Pin a current reader before spending network/disk on the archive. Reader
    // infrastructure trouble waits; it is not recorded as archive corruption.
    let mut sequence = 0;
    loop {
        let capacity = remaining_working_budget(&cfg.state_directory, cfg.build_reserve_bytes)
            .and_then(|remaining| {
                require_space(
                    &cfg.state_directory,
                    cfg.reserve_bytes,
                    object
                        .bytes
                        .checked_add(remaining)
                        .context("capacity overflow")?,
                )
            });
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
        if object.bytes > cfg.max_archive_bytes {
            wait(cfg,"waiting_for_capacity",object.epoch,&format!("archive {} exceeds max_archive_bytes {}; operator must increase admitted config budget", object.bytes,cfg.max_archive_bytes)).await?;
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
    // A terminated download is never promoted. Restart recovery deletes only
    // its journaled scratch inode and repeats this epoch from byte/slot zero.
    let result: Result<()> = async {
        progress(cfg,"downloading",Some(object.epoch),0,Some(object.bytes),None)?;
        let download = remote.download(cfg, object, &attempt).await?;
        outcome.download = Some(download.clone());
        let archive = cfg.state_directory.join("scratch").join(&object.key);
        // Re-fetch immediately before playback. If relevant reader changes land
        // during playback, repeat the whole epoch with that current build.
        loop {
            sequence+=1;
            let reader = loop {
                match source::qualify(cfg, &attempt, sequence) {
                    Ok(reader) => break reader,
                    Err(error) => { write_json(&attempt.join(format!("reader-error-{sequence}.json")), &json!({"at":now(),"error":format!("{error:#}")}), false)?;
                        wait(cfg,"waiting_for_reader",object.epoch,&format!("{error:#}")).await?; sequence+=1; },
                }
            };
            let native_report = attempt.join(format!("native-playback-{sequence}.json"));
            let args = vec![format!("{}:{}",object.epoch,object.epoch), cfg.state_directory.join("scratch").to_string_lossy().into_owned(),
                "--threads".into(), cfg.threads.to_string(), "--verify-only".into(),
                "--verification-report".into(), native_report.to_string_lossy().into_owned()];
            let mut invocation = vec![reader.artifact.to_string_lossy().into_owned()]; invocation.extend(args.clone());
            write_json(&attempt.join(format!("playback-{sequence}-invocation.json")), &json!({"argv":invocation,"reader":reader,"download":download,
                "environment":{"PATH":"/usr/bin:/bin","LC_ALL":"C","RUST_LOG":"info","RUST_MIN_STACK":"67108864"},"other_environment_removed":true}), false)?;
            progress(cfg,"playing_entire_epoch",Some(object.epoch),object.bytes,Some(object.bytes),None)?;
            let mut command = clean_command(&reader.artifact); command.args(&args);
            command.current_dir(cfg.state_directory.join("scratch"));
            let log = attempt.join(format!("playback-{sequence}.log"));
            outcome.reader = Some(reader.clone()); outcome.invocation = invocation;
            ensure!(run_logged(command,&log,cfg.playback_timeout_seconds,cfg.max_log_bytes,&cfg.state_directory,cfg.reserve_bytes,cfg.build_reserve_bytes)?, "plugin playback exited unsuccessfully");
            let mut report = evidence::validate_playback(&log,object.epoch,cfg.threads,cfg.max_log_bytes)?;
            evidence::validate_native_report(&native_report, &mut report, &outcome.invocation, &cfg.state_directory.join("scratch"))?;
            let owned: OwnedScratch = read_json(&cfg.state_directory.join("scratch-owner.json"))?;
            owned.identity.check(&archive)?;
            ensure!(hash_file(&archive)? == download.sha256, "audit archive changed during playback");
            ensure!(hash_file(&reader.artifact)? == reader.artifact_sha256, "reader image changed during playback");
            ensure!(remote.check_identity(object).await? == (download.version_id.clone(),download.metadata_sha256.clone()), "remote archive changed during playback");
            write_json(&attempt.join(format!("playback-{sequence}-report.json")), &report, false)?;
            sequence+=1;
            let current = loop {
                match source::qualify(cfg,&attempt,sequence) {
                    Ok(reader) => break reader,
                    Err(error) => { wait(cfg,"waiting_for_reader",object.epoch,&format!("{error:#}")).await?; sequence+=1; },
                }
            };
            if current.source_fingerprint == reader.source_fingerprint {
                outcome.reader = Some(current); outcome.playback=Some(report); break;
            }
            progress(cfg,"replaying_after_reader_change",Some(object.epoch),object.bytes,Some(object.bytes),None)?;
        }
        Ok(())
    }.await;
    match result {
        Ok(()) => outcome.status = "passed".into(),
        Err(error) => outcome.error = Some(format!("{error:#}")),
    }
    outcome.finished_at = now();
    // The immutable terminal receipt is committed before the only archive
    // deletion this program performs (its own download).
    write_json(&outcome_path(cfg, object.epoch), &outcome, false)?;
    cleanup_scratch(&cfg.state_directory)?;
    write_json(
        &attempt.join("cleanup.json"),
        &json!({"at":now(),"removed_only_owned_audit_copy":true,"epoch":object.epoch}),
        false,
    )?;
    eprintln!("epoch {}: {}", object.epoch, outcome.status);
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: horizon-r2-chronological-plugin-audit <inventory|run|status|reconfigure> CONFIG.json"
    );
    let mode = args[0].to_str().context("invalid mode")?;
    ensure!(
        matches!(mode, "inventory" | "run" | "status" | "reconfigure"),
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
        ensure!(
            budget_update == cfg,
            "reconfigure permits only resource budget changes; retain state/tool/source identity"
        );
        write_json(
            &cfg.state_directory
                .join(format!("config-change-{}.json", nonce())),
            &json!({"at":now(),"old":old,"new":cfg,"operator_capacity_admission_required":true}),
            false,
        )?;
        write_json(&config_path, &cfg, true)?;
        return Ok(());
    }
    if config_path.try_exists()? {
        ensure!(
            read_json::<Config>(&config_path)? == cfg,
            "config changed; stop service and use the documented reviewed config-replacement procedure"
        );
    } else {
        write_json(&config_path, &cfg, false)?;
    }
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
    cleanup_scratch(&cfg.state_directory)?;
    for object in &inventory.objects {
        if !finished(&cfg, object)? {
            audit_one(&cfg, &remote, object).await?;
        }
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
            remote_mutations: false,
        };
        write_json(&outcome_path(&cfg, 1), &result, false).unwrap();
        assert!(finished(&cfg, &object).is_err());
    }
}
