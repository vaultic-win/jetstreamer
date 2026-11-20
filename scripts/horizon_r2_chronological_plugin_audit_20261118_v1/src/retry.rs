//! Bounded, append-only recovery of response-body transport interruptions.
//! The sole controller and original frozen inventory remain the scheduling authority.
use crate::{
    Config, Outcome, audit_one,
    local::*,
    outcome_path, progress,
    remote::{Object, Remote, TransferIdentity},
    validate_outcome,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

#[path = "retry_epoch90.rs"]
mod epoch90;

const MAX_RECOVERIES: u32 = 2;
const LAST_SLOT: u32 = MAX_RECOVERIES + 1;
const BACKOFF_SECONDS: [u64; LAST_SLOT as usize] = [30, 120, 120];
// The three whole-response attempts for this object predate sequential ranged GET.
// Pin both ends of the validated append-only chain before permitting one ranged read.
const EPOCH79_ORIGINAL: &str = "00bb8f2a04c4f1b947145090565f69843d57d60dfd16812d3853fd1145690a43";
const EPOCH79_RETRY2: &str = "c70b0fff4cc9b463adfaef3bde19818e6ca8f1eecd5f8d46236896e4f5d40d65";
// The v5 producer did not persist typed failure stages. Admit only this exact
// inspected old receipt, not all old failures with similar-looking messages.
const LEGACY73_SHA: &str = "e1edc7906e39a22ec6f9ab40416eeb5452e2dfdce63b11a84f30e4ce67b5db6a";
const LEGACY73_ERROR: &str = "streaming error: error reading a body from connection: end of file before message length reached";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetryBinding {
    pub ordinal: u32,
    pub original_result_sha256: String,
    pub previous_result_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryTicket {
    pub schema: String,
    pub object: Object,
    pub binding: RetryBinding,
    pub attempt: PathBuf,
    pub recorded_at: u64,
    pub not_before: u64,
    pub prior_identity: Option<TransferIdentity>,
}

pub struct View {
    pub latest: Outcome,
    original_sha256: String,
    latest_sha256: String,
    completed_recoveries: u32,
    incomplete: Option<RetryTicket>,
}
impl View {
    fn retry_limit(&self) -> u32 {
        if self.original_sha256 == epoch90::RESULT {
            1
        } else if self.completed_recoveries == MAX_RECOVERIES
            && self.latest.epoch == 79
            && self.original_sha256 == EPOCH79_ORIGINAL
            && self.latest_sha256 == EPOCH79_RETRY2
        {
            LAST_SLOT
        } else {
            MAX_RECOVERIES
        }
    }
    pub fn retry_available(&self) -> bool {
        self.incomplete.is_none()
            && self.completed_recoveries < self.retry_limit()
            && retryable(&self.latest, &self.latest_sha256)
    }
}

pub fn has_incomplete(view: &View) -> bool {
    view.incomplete.is_some()
}

fn retryable(result: &Outcome, sha256: &str) -> bool {
    if result.status != "failed"
        || result.download.is_some()
        || result.playback.is_some()
        || !result.invocation.is_empty()
        || result.error.is_none()
        || result.remote_mutations
    {
        return false;
    }
    if result.transfer_interruption.is_some() {
        return true;
    }
    if epoch90::eligible(result, sha256) {
        return true;
    }
    result.retry_of.is_none()
        && sha256 == LEGACY73_SHA
        && result.object.epoch == 73
        && result.epoch == 73
        && result.object.key == "epoch-73.jet"
        && result.object.etag == "\"9e950a685738661c0e65810dc98014e2-2667\""
        && result.object.bytes == 13_978_437_633
        && result.error.as_deref() == Some(LEGACY73_ERROR)
}

pub fn result_path(cfg: &Config, epoch: u64, ordinal: u32) -> PathBuf {
    cfg.state_directory
        .join("results")
        .join(format!("epoch-{epoch}.retry-{ordinal}.json"))
}
pub fn ticket_path(cfg: &Config, epoch: u64, ordinal: u32) -> PathBuf {
    cfg.state_directory
        .join("results")
        .join(format!("epoch-{epoch}.retry-{ordinal}.intent.json"))
}
fn read_outcome(path: &Path, object: &Object) -> Result<(Outcome, String)> {
    let file = open_read(path)?;
    ensure!(
        file.metadata()?.len() <= MAX_JSON_BYTES,
        "result exceeds bound"
    );
    let mut bytes = Vec::new();
    file.take(MAX_JSON_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_JSON_BYTES,
        "result grew beyond bound"
    );
    let result: Outcome = serde_json::from_slice(&bytes)?;
    validate_outcome(&result, object)?;
    Ok((result, digest(&bytes)))
}

fn prior_identity(view: &View) -> Result<Option<TransferIdentity>> {
    if epoch90::eligible(&view.latest, &view.latest_sha256) {
        return Ok(Some(epoch90::evidence(&view.latest)?));
    }
    Ok(view
        .latest
        .transfer_interruption
        .as_ref()
        .map(|e| e.identity.clone()))
}

fn validate_ticket(
    cfg: &Config,
    object: &Object,
    ticket: &RetryTicket,
    prior: &View,
    ordinal: u32,
) -> Result<()> {
    ensure!(
        ticket.schema == "horizon-r2-audit-transfer-retry-intent-v1"
            && ticket.object == *object
            && (1..=prior.retry_limit()).contains(&ordinal)
            && ticket.binding.ordinal == ordinal
            && ticket.binding.original_result_sha256 == prior.original_sha256
            && ticket.binding.previous_result_sha256 == prior.latest_sha256
            && retryable(&prior.latest, &prior.latest_sha256),
        "retry intent does not bind an eligible exact predecessor"
    );
    let prefix = format!("epoch-{}-retry{ordinal}-", object.epoch);
    let suffix = ticket
        .attempt
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|name| name.strip_prefix(&prefix))
        .context("invalid retry attempt name")?;
    ensure!(
        !suffix.is_empty()
            && suffix.bytes().all(|b| b.is_ascii_digit())
            && ticket.attempt.parent() == Some(cfg.state_directory.join("attempts").as_path()),
        "retry attempt escaped owned state"
    );
    let earliest = prior
        .latest
        .finished_at
        .checked_add(BACKOFF_SECONDS[(ordinal - 1) as usize])
        .context("retry deadline overflow")?;
    ensure!(
        ticket.recorded_at >= prior.latest.finished_at
            && ticket.not_before >= earliest
            && ticket.not_before >= ticket.recorded_at,
        "retry backoff was shortened"
    );
    ensure!(
        ticket.prior_identity == prior_identity(prior)?,
        "retry lost the prior authenticated transfer identity"
    );
    Ok(())
}

pub fn view(cfg: &Config, object: &Object) -> Result<Option<View>> {
    let original = outcome_path(cfg, object.epoch);
    if !original.try_exists()? {
        for ordinal in 1..=LAST_SLOT {
            ensure!(
                !result_path(cfg, object.epoch, ordinal).try_exists()?
                    && !ticket_path(cfg, object.epoch, ordinal).try_exists()?,
                "orphan retry evidence"
            );
        }
        return Ok(None);
    }
    let (latest, sha256) = read_outcome(&original, object)?;
    ensure!(
        latest.retry_of.is_none(),
        "original result has a retry binding"
    );
    if epoch90::eligible(&latest, &sha256) {
        ensure!(
            latest.attempt.parent() == Some(cfg.state_directory.join("attempts").as_path()),
            "epoch90 predecessor outside accepted state"
        );
        epoch90::evidence(&latest)?;
    }
    let mut view = View {
        latest,
        original_sha256: sha256.clone(),
        latest_sha256: sha256,
        completed_recoveries: 0,
        incomplete: None,
    };
    let mut gap = false;
    for ordinal in 1..=LAST_SLOT {
        let ticket_file = ticket_path(cfg, object.epoch, ordinal);
        let result_file = result_path(cfg, object.epoch, ordinal);
        if !ticket_file.try_exists()? {
            ensure!(
                !result_file.try_exists()?,
                "retry result has no durable intent"
            );
            gap = true;
            continue;
        }
        ensure!(
            !gap && view.incomplete.is_none(),
            "retry history has a gap or interrupted predecessor"
        );
        let ticket: RetryTicket = read_json(&ticket_file)?;
        validate_ticket(cfg, object, &ticket, &view, ordinal)?;
        if !result_file.try_exists()? {
            view.incomplete = Some(ticket);
            continue;
        }
        let (result, sha256) = read_outcome(&result_file, object)?;
        ensure!(
            result.retry_of.as_ref() == Some(&ticket.binding)
                && result.attempt == ticket.attempt
                && result.started_at >= ticket.recorded_at
                && result.finished_at >= result.started_at,
            "retry result identity differs from its durable intent"
        );
        view.latest = result;
        view.latest_sha256 = sha256;
        view.completed_recoveries = ordinal;
    }
    Ok(Some(view))
}

/// Validated existing ticket only: this never spends or resets a retry budget.
/// The normal path still terminally records an interrupted ticket; only the
/// explicitly selected downloaded-recovery route may request this binding.
pub fn incomplete_ticket(cfg: &Config, object: &Object) -> Result<RetryTicket> {
    view(cfg, object)?
        .context("download recovery requires original retry history")?
        .incomplete
        .context("download recovery requires an incomplete retry intent with no terminal result")
}

fn prepare_ticket(cfg: &Config, object: &Object) -> Result<RetryTicket> {
    let view = view(cfg, object)?.context("cannot retry an unattempted archive")?;
    ensure!(
        view.retry_available(),
        "transfer retry is unavailable or exhausted"
    );
    ensure!(
        !cfg.state_directory
            .join("scratch-owner.json")
            .try_exists()?
            && fs::read_dir(cfg.scratch_directory())?.next().is_none(),
        "previous audit download has not completed owned cleanup"
    );
    let ordinal = view.completed_recoveries + 1;
    let recorded_at = now();
    let prior_identity = prior_identity(&view)?;
    let ticket = RetryTicket {
        schema: "horizon-r2-audit-transfer-retry-intent-v1".into(),
        object: object.clone(),
        binding: RetryBinding {
            ordinal,
            original_result_sha256: view.original_sha256,
            previous_result_sha256: view.latest_sha256,
        },
        attempt: cfg.state_directory.join("attempts").join(format!(
            "epoch-{}-retry{ordinal}-{}",
            object.epoch,
            nonce()
        )),
        recorded_at,
        not_before: recorded_at.max(
            view.latest
                .finished_at
                .checked_add(BACKOFF_SECONDS[(ordinal - 1) as usize])
                .context("retry deadline overflow")?,
        ),
        prior_identity,
    };
    Ok(ticket)
}

/// Spend a retry only at the transfer boundary, after capacity and current-reader
/// qualification have succeeded. A controller interrupted during those waits has
/// only an ordinary attempt directory, not a consumed durable recovery slot.
pub fn commit_ticket(cfg: &Config, object: &Object, ticket: &RetryTicket) -> Result<()> {
    commit_ticket_at(cfg, object, ticket, now())
}

fn commit_ticket_at(cfg: &Config, object: &Object, ticket: &RetryTicket, at: u64) -> Result<()> {
    let current = view(cfg, object)?.context("retry predecessor disappeared")?;
    ensure!(
        current.retry_available(),
        "retry changed during preparation"
    );
    validate_ticket(
        cfg,
        object,
        ticket,
        &current,
        current.completed_recoveries + 1,
    )?;
    ensure!(at >= ticket.not_before, "retry backoff is incomplete");
    ensure!(
        !cfg.state_directory
            .join("scratch-owner.json")
            .try_exists()?
            && fs::read_dir(cfg.scratch_directory())?.next().is_none(),
        "retry scratch changed during preparation"
    );
    write_json(
        &ticket_path(cfg, object.epoch, ticket.binding.ordinal),
        ticket,
        false,
    )
}

#[cfg(test)]
fn claim(cfg: &Config, object: &Object) -> Result<RetryTicket> {
    let ticket = prepare_ticket(cfg, object)?;
    commit_ticket_at(cfg, object, &ticket, ticket.not_before)?;
    Ok(ticket)
}

fn finish_interrupted(cfg: &Config, object: &Object, ticket: &RetryTicket) -> Result<()> {
    // The ticket consumed its slot durably at the transfer boundary. Never reset its
    // budget or guess whether an interrupted child had reached plugin playback.
    let result = Outcome {
        schema: "horizon-r2-chronological-plugin-audit-result-v1".into(), epoch: object.epoch,
        status: "failed".into(), object: object.clone(), attempt: ticket.attempt.clone(),
        started_at: ticket.recorded_at, finished_at: now(), download: None, reader: None,
        playback: None, invocation: vec![],
        error: Some("transfer retry controller interrupted before durable outcome; slot consumed and manual evidence review required".into()),
        transfer_interruption: None, retry_of: Some(ticket.binding.clone()), remote_mutations: false,
    };
    write_json(
        &result_path(cfg, object.epoch, ticket.binding.ordinal),
        &result,
        false,
    )
}

pub async fn run_pending(cfg: &Config, remote: &Remote, object: &Object) -> Result<()> {
    loop {
        let Some(current) = view(cfg, object)? else {
            return Ok(());
        };
        if let Some(ticket) = &current.incomplete {
            finish_interrupted(cfg, object, ticket)?;
            return Ok(());
        }
        if !current.retry_available() {
            return Ok(());
        }
        let ticket = prepare_ticket(cfg, object)?;
        progress(
            cfg,
            "waiting_for_transfer_retry",
            Some(object.epoch),
            0,
            Some(object.bytes),
            Some(&format!(
                "transfer retry {}/{}; not before {}; original failure retained",
                ticket.binding.ordinal,
                current.retry_limit(),
                ticket.not_before
            )),
        )?;
        while now() < ticket.not_before {
            tokio::time::sleep(Duration::from_secs(
                ticket.not_before.saturating_sub(now()).min(60),
            ))
            .await;
            if now() < ticket.not_before {
                progress(
                    cfg,
                    "waiting_for_transfer_retry",
                    Some(object.epoch),
                    0,
                    Some(object.bytes),
                    Some(&format!(
                        "heartbeat; retry {}/{} remains scheduled at {}; no transfer started",
                        ticket.binding.ordinal,
                        current.retry_limit(),
                        ticket.not_before
                    )),
                )?;
            }
        }
        audit_one(cfg, remote, object, Some(&ticket)).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::{TransferInterruption, TransferInterruptionKind};
    use serde_json::json;

    fn config(state: &Path) -> Config {
        let mut cfg: Config = serde_json::from_str(include_str!("../config.example.json")).unwrap();
        cfg.state_directory = state.to_owned();
        for name in ["results", "attempts", "scratch"] {
            private_dir(&state.join(name)).unwrap();
        }
        cfg
    }
    fn object() -> Object {
        Object {
            epoch: 73,
            key: "epoch-73.jet".into(),
            etag: "\"9e950a685738661c0e65810dc98014e2-2667\"".into(),
            bytes: 13_978_437_633,
        }
    }
    fn failed(cfg: &Config, object: &Object) -> Outcome {
        Outcome {
            schema: "horizon-r2-chronological-plugin-audit-result-v1".into(),
            epoch: object.epoch,
            status: "failed".into(),
            object: object.clone(),
            attempt: cfg.state_directory.join("attempts/initial"),
            started_at: 1,
            finished_at: 2,
            download: None,
            reader: None,
            playback: None,
            invocation: vec![],
            error: Some("response body disconnected".into()),
            transfer_interruption: Some(TransferInterruption {
                kind: TransferInterruptionKind::BodyReadError,
                identity: TransferIdentity {
                    bucket: "solana-archive-with-accounts-data".into(),
                    object: object.clone(),
                    version_id: None,
                    metadata_sha256: Some("a".repeat(64)),
                    sidecar_sha256: Some("a".repeat(64)),
                    sidecar_etag: Some("pinned-sidecar".into()),
                },
                downloaded_bytes: 50,
                detail: "end of file before message length reached".into(),
            }),
            retry_of: None,
            remote_mutations: false,
        }
    }
    fn record_retry(cfg: &Config, object: &Object, ticket: &RetryTicket, mut result: Outcome) {
        result.attempt = ticket.attempt.clone();
        result.started_at = ticket.recorded_at;
        result.finished_at = ticket.recorded_at;
        result.retry_of = Some(ticket.binding.clone());
        write_json(
            &result_path(cfg, object.epoch, ticket.binding.ordinal),
            &result,
            false,
        )
        .unwrap();
    }
    #[test]
    fn only_exact_exhausted_whole_response_chain_gets_one_ranged_recovery() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let mut obj = object();
        obj.epoch = 79;
        let mut view = View {
            latest: failed(&cfg, &obj),
            original_sha256: EPOCH79_ORIGINAL.into(),
            latest_sha256: EPOCH79_RETRY2.into(),
            completed_recoveries: MAX_RECOVERIES,
            incomplete: None,
        };
        assert!(view.retry_available());
        view.completed_recoveries = LAST_SLOT;
        assert!(!view.retry_available());
        view.completed_recoveries = MAX_RECOVERIES;
        view.latest.epoch = 80;
        assert!(!view.retry_available());
        view.latest.epoch = 79;
        view.latest_sha256 = "0".repeat(64);
        assert!(!view.retry_available());
        view.latest_sha256 = EPOCH79_RETRY2.into();
        view.original_sha256 = "0".repeat(64);
        assert!(!view.retry_available());
    }

    #[test]
    fn preparation_interruptions_leave_the_original_retry_budget_available() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let obj = object();
        write_json(&outcome_path(&cfg, obj.epoch), &failed(&cfg, &obj), false).unwrap();
        let original = fs::read(outcome_path(&cfg, obj.epoch)).unwrap();
        for _ in 0..4 {
            let ticket = prepare_ticket(&cfg, &obj).unwrap();
            private_dir(&ticket.attempt).unwrap();
            // The real capacity/reader waits run after this point and before
            // commit_ticket. A fresh controller sees no spent retry intent.
            assert_eq!(ticket.binding.ordinal, 1);
            assert!(!ticket_path(&cfg, obj.epoch, 1).exists());
            let restored = view(&cfg, &obj).unwrap().unwrap();
            assert!(restored.retry_available());
            assert_eq!(restored.completed_recoveries, 0);
            assert!(restored.incomplete.is_none());
        }
        assert_eq!(fs::read(outcome_path(&cfg, obj.epoch)).unwrap(), original);
        let ticket = claim(&cfg, &obj).unwrap();
        finish_interrupted(&cfg, &obj, &ticket).unwrap();
        assert!(!view(&cfg, &obj).unwrap().unwrap().retry_available());
    }

    #[test]
    fn transfer_boundary_rechecks_backoff_scratch_and_predecessor() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let obj = object();
        write_json(&outcome_path(&cfg, obj.epoch), &failed(&cfg, &obj), false).unwrap();
        let ticket = prepare_ticket(&cfg, &obj).unwrap();
        assert!(commit_ticket_at(&cfg, &obj, &ticket, ticket.not_before - 1).is_err());
        let unknown = cfg.scratch_directory().join("foreign.jet");
        fs::write(&unknown, b"preserve").unwrap();
        assert!(commit_ticket_at(&cfg, &obj, &ticket, ticket.not_before).is_err());
        assert_eq!(fs::read(&unknown).unwrap(), b"preserve");
        fs::remove_file(unknown).unwrap();
        let mut changed = ticket.clone();
        changed.binding.previous_result_sha256 = "0".repeat(64);
        assert!(commit_ticket_at(&cfg, &obj, &changed, ticket.not_before).is_err());
        assert!(!ticket_path(&cfg, obj.epoch, 1).exists());
        commit_ticket_at(&cfg, &obj, &ticket, ticket.not_before).unwrap();
        assert!(commit_ticket_at(&cfg, &obj, &ticket, ticket.not_before).is_err());
    }

    #[test]
    fn retries_are_bounded_across_reload_and_original_evidence_never_changes() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let obj = object();
        write_json(&outcome_path(&cfg, obj.epoch), &failed(&cfg, &obj), false).unwrap();
        let original = fs::read(outcome_path(&cfg, obj.epoch)).unwrap();
        for ordinal in 1..=MAX_RECOVERIES {
            assert!(view(&cfg, &obj).unwrap().unwrap().retry_available());
            let ticket = claim(&cfg, &obj).unwrap();
            assert_eq!(ticket.binding.ordinal, ordinal);
            assert!(claim(&cfg, &obj).is_err());
            assert!(ticket.prior_identity.is_some());
            record_retry(&cfg, &obj, &ticket, failed(&cfg, &obj));
        }
        assert!(!view(&cfg, &obj).unwrap().unwrap().retry_available());
        assert!(claim(&cfg, &obj).is_err());
        assert_eq!(fs::read(outcome_path(&cfg, obj.epoch)).unwrap(), original);
        assert_eq!(
            fs::read_dir(cfg.state_directory.join("results"))
                .unwrap()
                .count(),
            5
        );
    }
    #[test]
    fn checksum_plugin_and_generic_string_errors_are_never_requeued() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let obj = object();
        let mut result = failed(&cfg, &obj);
        result.transfer_interruption = None;
        for message in [
            "archive digest differs from canonical sidecar",
            "plugin playback exited unsuccessfully",
            LEGACY73_ERROR,
        ] {
            result.error = Some(message.into());
            assert!(!retryable(&result, &"0".repeat(64)));
        }
        assert!(retryable(&result, LEGACY73_SHA));
        result.object.etag.push('x');
        assert!(!retryable(&result, LEGACY73_SHA));
        result.object = obj;
        result.invocation.push("plugin-playback".into());
        assert!(!retryable(&result, LEGACY73_SHA));
    }
    #[test]
    fn interrupted_retry_consumes_slot_and_cannot_restart_unboundedly() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let obj = object();
        write_json(&outcome_path(&cfg, obj.epoch), &failed(&cfg, &obj), false).unwrap();
        let ticket = claim(&cfg, &obj).unwrap();
        assert!(view(&cfg, &obj).unwrap().unwrap().incomplete.is_some());
        finish_interrupted(&cfg, &obj, &ticket).unwrap();
        assert!(!view(&cfg, &obj).unwrap().unwrap().retry_available());
        assert!(finish_interrupted(&cfg, &obj, &ticket).is_err());
        assert!(claim(&cfg, &obj).is_err());
    }
    #[test]
    fn orphan_substituted_and_out_of_order_retry_evidence_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let obj = object();
        write_json(&outcome_path(&cfg, obj.epoch), &failed(&cfg, &obj), false).unwrap();
        let ticket = claim(&cfg, &obj).unwrap();
        let mut wrong = failed(&cfg, &obj);
        wrong.object.etag.push('x');
        record_retry(&cfg, &obj, &ticket, wrong);
        assert!(view(&cfg, &obj).is_err());
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        write_json(&result_path(&cfg, obj.epoch, 1), &failed(&cfg, &obj), false).unwrap();
        assert!(view(&cfg, &obj).is_err());
        write_json(&outcome_path(&cfg, obj.epoch), &failed(&cfg, &obj), false).unwrap();
        assert!(view(&cfg, &obj).is_err());
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        write_json(&outcome_path(&cfg, obj.epoch), &failed(&cfg, &obj), false).unwrap();
        let mut ticket = claim(&cfg, &obj).unwrap();
        ticket.binding.previous_result_sha256 = "0".repeat(64);
        write_json(&ticket_path(&cfg, obj.epoch, 1), &ticket, true).unwrap();
        assert!(view(&cfg, &obj).is_err());
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        write_json(&outcome_path(&cfg, obj.epoch), &failed(&cfg, &obj), false).unwrap();
        let ticket = claim(&cfg, &obj).unwrap();
        fs::rename(
            ticket_path(&cfg, obj.epoch, 1),
            ticket_path(&cfg, obj.epoch, 2),
        )
        .unwrap();
        assert!(view(&cfg, &obj).is_err());
        assert_eq!(ticket.binding.ordinal, 1);
    }
    #[test]
    fn owned_or_unknown_scratch_blocks_retry_without_deletion() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let obj = object();
        write_json(&outcome_path(&cfg, obj.epoch), &failed(&cfg, &obj), false).unwrap();
        let unknown = cfg.scratch_directory().join("foreign.jet");
        fs::write(&unknown, b"keep").unwrap();
        assert!(claim(&cfg, &obj).is_err());
        assert_eq!(fs::read(&unknown).unwrap(), b"keep");
        fs::remove_file(&unknown).unwrap();
        let journal = cfg.state_directory.join("scratch-owner.json");
        fs::write(&journal, b"keep journal").unwrap();
        assert!(claim(&cfg, &obj).is_err());
        assert_eq!(fs::read(&journal).unwrap(), b"keep journal");
    }
    #[test]
    fn recovered_success_updates_summary_but_keeps_original_failure() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let obj = object();
        write_json(&outcome_path(&cfg, obj.epoch), &failed(&cfg, &obj), false).unwrap();
        let original = hash_file(&outcome_path(&cfg, obj.epoch)).unwrap();
        let ticket = claim(&cfg, &obj).unwrap();
        let mut result = failed(&cfg, &obj);
        result.status = "passed".into();
        result.error = None;
        result.transfer_interruption = None;
        result.download = Some(serde_json::from_value(json!({"object":obj,"version_id":null,"sha256":"a".repeat(64),"bytes":obj.bytes,"sidecar_sha256":null,"sidecar_etag":null,"metadata_sha256":null})).unwrap());
        result.reader = Some(serde_json::from_value(json!({"branch_commit":"b".repeat(40),"source_fingerprint":"a".repeat(64),"source_files":{},"cargo_lock_sha256":"a".repeat(64),"rustc_version":"fixture","cargo_version":"fixture","cargo_sha256":"a".repeat(64),"rustc_sha256":"a".repeat(64),"features":[],"artifact":"/fixture/reader","artifact_sha256":"a".repeat(64),"seal_receipt_sha256":"a".repeat(64),"built_from_commit":"b".repeat(40),"equivalence_reused":true,"fetched_at":1})).unwrap());
        result.playback = Some(serde_json::from_value(json!({"epoch":73,"first_slot":31536000,"last_slot":31967999,"slot_range_evidence":"fixture","counters":{},"workers":4,"stream_sha256":"a".repeat(64),"log_sha256":"a".repeat(64),"clean_process_exit":true,"native_report_path":"/fixture/report","native_report_sha256":"a".repeat(64)})).unwrap());
        record_retry(&cfg, &obj, &ticket, result);
        let inventory = crate::remote::Inventory {
            schema: "fixture".into(),
            bucket: "fixture".into(),
            observed_at: 1,
            objects: vec![obj.clone()],
        };
        let summary = crate::summary(&cfg, &inventory).unwrap();
        assert_eq!(summary["passed"], 1);
        assert_eq!(summary["failed"], 0);
        assert_eq!(summary["recovered_transfer_failures"], 1);
        assert!(!view(&cfg, &obj).unwrap().unwrap().retry_available());
        assert_eq!(hash_file(&outcome_path(&cfg, obj.epoch)).unwrap(), original);
    }
}
