//! Replay frozen authenticated inventory through the anonymous, conditionally
//! ranged HTTP reader. Local storage is confined to metadata and build output.
use crate::{
    Config, canonical_epoch,
    local::*,
    remote::{Inventory, Object, Remote},
    source,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

mod branch_recovery;

const ORIGIN: &str = "https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev";

fn validate_inventory(inv: &Inventory, bucket: &str) -> Result<()> {
    ensure!(
        inv.schema == "horizon-r2-chronological-audit-inventory-v1" && inv.bucket == bucket,
        "wrong source inventory"
    );
    for (i, obj) in inv.objects.iter().enumerate() {
        ensure!(
            canonical_epoch(&obj.key) == Some(obj.epoch)
                && obj.bytes > 0
                && (i == 0 || inv.objects[i - 1].epoch < obj.epoch),
            "unordered or invalid public inventory"
        );
    }
    Ok(())
}

fn next_range<'a>(objects: &'a [Object], finished: &BTreeSet<u64>) -> &'a [Object] {
    let Some(first) = objects.iter().position(|o| !finished.contains(&o.epoch)) else {
        return &[];
    };
    let tail = &objects[first..];
    let end = tail.windows(2).position(|p| {
        p[0].epoch.checked_add(1) != Some(p[1].epoch) || finished.contains(&p[1].epoch)
    });
    &tail[..end.map_or(tail.len(), |i| i + 1)]
}

fn publish_status(
    dir: &Path,
    phase: &str,
    epoch: Option<u64>,
    range: Option<(u64, u64)>,
    total: usize,
    passed: usize,
    failed: usize,
) -> Result<()> {
    let pending = total
        .checked_sub(passed + failed)
        .context("invalid public result counts")?;
    let timestamp = now();
    write_json(
        &dir.join("summary.json"),
        &json!({"scope":"frozen authenticated R2 inventory, public conditional HTTP full plugin playback","updated_at":timestamp,"archives":total,"passed":passed,"failed":failed,"pending":pending,"complete":phase=="complete"}),
        true,
    )?;
    write_json(
        &dir.join("progress.json"),
        &json!({"schema":"horizon-r2-public-audit-progress-v1","pid":std::process::id(),"updated_at":timestamp,"phase":phase,"epoch":epoch,"range_start":range.map(|r|r.0),"range_end":range.map(|r|r.1),"passed":passed,"failed":failed,"archives":total,"archive_scratch_bytes":0,"remote_mutations":false}),
        true,
    )
}

fn verify_report(path: &Path, object: &Object, args: &[String], threads: u64) -> Result<Value> {
    let doc: Value = read_json(path)?;
    let r = &doc["report"];
    let lo = object
        .epoch
        .checked_mul(432000)
        .context("epoch slot overflow")?;
    let hi = lo.checked_add(431999).context("epoch slot overflow")?;
    ensure!(
        doc["schema"] == "jetstreamer-horizon-plugin-playback-v1"
            && doc["source"] == ORIGIN
            && doc["invocation"] == json!(args)
            && doc["full_epoch_verified"] == true
            && doc["expected_first_slot"] == lo
            && doc["expected_last_slot"] == hi
            && r["epoch"] == object.epoch
            && r["first_slot"] == lo
            && r["last_slot"] == hi
            && r["slots"] == 432000
            && r["worker_count"]
                .as_u64()
                .is_some_and(|n| (1..=threads).contains(&n))
            && r["blocks"]
                .as_u64()
                .zip(r["skipped"].as_u64())
                .and_then(|(a, b)| a.checked_add(b))
                == Some(432000),
        "incomplete or foreign public playback report"
    );
    for key in [
        "entries",
        "transactions",
        "transaction_updates",
        "orphan_updates",
        "epoch_updates",
        "account_data_bytes",
    ] {
        ensure!(
            r[key].as_u64().is_some(),
            "invalid native report counter {key}"
        );
    }
    let _: [u8; 32] =
        serde_json::from_value(r["stream_digest"].clone()).context("invalid plugin digest")?;
    Ok(doc)
}

fn playback_args(
    reader: &Path,
    first: u64,
    last: u64,
    threads: u64,
    manifest: &Path,
    reports: &Path,
) -> Vec<String> {
    vec![
        reader.display().to_string(),
        format!("{first}:{last}"),
        ORIGIN.into(),
        "--verify-only".into(),
        "--threads".into(),
        threads.to_string(),
        "--archive-inventory".into(),
        manifest.display().to_string(),
        "--verification-report-dir".into(),
        reports.display().to_string(),
    ]
}

struct CompletedPlayback<'a> {
    reader: &'a source::Reader,
    proof: &'a Path,
    proof_sha: &'a str,
    args: &'a [String],
    path: &'a Path,
    native: &'a Value,
    threads: u64,
    started_at: u64,
}

impl CompletedPlayback<'_> {
    fn publish(
        &self,
        dir: &Path,
        object: &Object,
        inventory_sha: &str,
        authenticated: Value,
    ) -> Result<()> {
        let attempt = self.proof.parent().context("missing proof directory")?;
        ensure!(
            self.path.parent().and_then(Path::parent) == Some(attempt),
            "playback and reader proof have different attempts"
        );
        write_json(
            &result_file(dir, object.epoch),
            &json!({
            "schema":"horizon-r2-public-audit-result-v1","status":"passed","started_at":self.started_at,"finished_at":now(),
            "epoch":object.epoch,"object":object,"inventory_sha256":inventory_sha,"public_base":ORIGIN,
            "reader_commit":self.reader.branch_commit,"reader_sha256":self.reader.artifact_sha256,
            "reader_proof":self.proof,"reader_proof_sha256":self.proof_sha,"threads":self.threads,
            "invocation":self.args,"native_report":self.path,"native_report_sha256":hash_file(self.path)?,
            "report":self.native["report"],"authenticated_readiness":authenticated,"epoch_plugin_completed":true,
            "range_attempt":attempt,"remote_mutations":false}),
            false,
        )
    }
}

fn result_file(dir: &Path, epoch: u64) -> PathBuf {
    dir.join("results").join(format!("epoch-{epoch}.json"))
}

fn resume(dir: &Path, inventory: &Inventory, manifest_sha: &str) -> Result<(BTreeSet<u64>, usize)> {
    let mut done = BTreeSet::new();
    let mut failures = 0;
    let mut proofs = BTreeMap::<PathBuf, (String, source::Reader)>::new();
    for obj in &inventory.objects {
        let path = result_file(dir, obj.epoch);
        if !path.try_exists()? {
            continue;
        }
        let result: Value = read_json(&path)?;
        ensure!(
            result["object"] == json!(obj)
                && result["inventory_sha256"] == manifest_sha
                && result["remote_mutations"] == false,
            "public receipt inventory binding changed"
        );
        match result["status"].as_str() {
            Some("passed") => {
                let native =
                    PathBuf::from(result["native_report"].as_str().context("missing report")?);
                let expected: String =
                    serde_json::from_value(result["native_report_sha256"].clone())?;
                ensure!(
                    native.starts_with(dir.join("attempts")) && hash_file(&native)? == expected,
                    "native report changed"
                );
                // Historical v1 receipts carry the same Reader proof without
                // its file digest. All epochs sharing a proof validate its
                // commit and executable against their own invocation.
                let proof_path = PathBuf::from(
                    result["reader_proof"]
                        .as_str()
                        .context("missing reader proof")?,
                );
                ensure!(
                    proof_path.parent() == native.parent().and_then(Path::parent)
                        && proof_path.starts_with(dir.join("attempts")),
                    "reader proof belongs to another attempt"
                );
                let (actual_sha, proof) = match proofs.entry(proof_path) {
                    std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::btree_map::Entry::Vacant(e) => {
                        let doc: Value = read_json(e.key())?;
                        branch_recovery::validate_build_links(dir, e.key(), &doc)?;
                        let proof_metadata = (hash_file(e.key())?, serde_json::from_value(doc)?);
                        e.insert(proof_metadata)
                    }
                };
                ensure!(
                    result
                        .get("reader_proof_sha256")
                        .is_none_or(|v| v.as_str() == Some(actual_sha.as_str()))
                        && result["reader_commit"] == proof.branch_commit
                        && result["reader_sha256"] == proof.artifact_sha256
                        && result["invocation"][0].as_str() == proof.artifact.to_str(),
                    "public receipt reader binding changed"
                );
                let argv: Vec<String> = serde_json::from_value(result["invocation"].clone())?;
                verify_report(
                    &native,
                    obj,
                    &argv,
                    result["threads"].as_u64().context("missing threads")?,
                )?;
            }
            Some("unresolved") => failures += 1,
            _ => bail!("unknown public audit result"),
        }
        done.insert(obj.epoch);
    }
    Ok((done, failures))
}

fn readiness(remote: &Remote, object: &Object) -> Result<Value> {
    // The supervisor runs inside a multi-thread Tokio runtime. Its synchronous
    // child monitor owns order/receipts; drive only this small S3 metadata
    // operation on the already running I/O reactor.
    let runtime = tokio::runtime::Handle::current();
    tokio::task::block_in_place(|| {
        runtime.block_on(async {
        let (version, metadata) = remote.check_identity(object).await?;
        let sidecar = match remote.sidecar(object).await {
            Ok((digest, etag)) => json!({"state": match (&digest,&metadata) {
                (None, _) => "staged_without_sidecar",
                (Some(a), Some(b)) if a != b => "sidecar_metadata_digest_mismatch",
                _ => "sidecar_present",
            }, "sha256":digest, "etag":etag}),
            Err(error) => json!({"state":"sidecar_check_failed","detail":format!("{error:#}")}),
        };
        Ok(json!({"archive_version":version, "archive_metadata_sha256":metadata, "sidecar":sidecar}))
    })
    })
}

/// Keep the owner and prior receipts through a control-plane or capacity
/// interruption. Playback/HTTP failures have their own bounded epoch retries.
pub async fn supervise(cfg: &Config, remote: &Remote) -> Result<()> {
    let dir = cfg.state_directory.join("public-stream-v1");
    private_dir(&dir)?;
    let mut delay = 30;
    loop {
        match run(cfg, remote).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                let next = now() + delay;
                let detail = format!("{error:#}");
                eprintln!("public audit waiting until {next}: {detail}");
                write_json(
                    &dir.join(format!("interruption-{}.json", nonce())),
                    &json!({"at":now(),"retry_at":next,"error":detail}),
                    false,
                )?;
                let progress_path = dir.join("progress.json");
                if progress_path.try_exists()? {
                    let mut progress: Value = read_json(&progress_path)?;
                    progress["phase"] = json!("waiting_for_recovery");
                    progress["updated_at"] = json!(now());
                    progress["retry_at"] = json!(next);
                    progress["detail"] = json!(detail);
                    write_json(&progress_path, &progress, true)?;
                }
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                delay = (delay * 2).min(cfg.wait_seconds);
            }
        }
    }
}

async fn run(cfg: &Config, remote: &Remote) -> Result<()> {
    let dir = cfg.state_directory.join("public-stream-v1");
    private_dir(&dir)?;
    for name in ["results", "attempts"] {
        private_dir(&dir.join(name))?;
    }
    let manifest = dir.join("inventory.json");
    if !manifest.try_exists()? {
        publish_status(&dir, "inventory", None, None, 0, 0, 0)?;
        let inv = remote.inventory().await?;
        validate_inventory(&inv, &remote.bucket)?;
        ensure!(!inv.objects.is_empty(), "empty public audit inventory");
        write_json(&manifest, &inv, false)?;
    }
    let inv: Inventory = read_json(&manifest)?;
    validate_inventory(&inv, &remote.bucket)?;
    let binding = hash_file(&manifest)?;
    let (mut done, mut failed) = resume(&dir, &inv, &binding)?;
    let total = inv.objects.len();
    while done.len() < total {
        let range = next_range(&inv.objects, &done);
        let start = range.first().context("empty pending range")?.epoch;
        let end = range.last().unwrap().epoch;
        let attempt = dir
            .join("attempts")
            .join(format!("range-{start}-{end}-{}", nonce()));
        private_dir(&attempt)?;
        let reports = attempt.join("reports");
        private_dir(&reports)?;
        publish_status(
            &dir,
            "qualifying_reader",
            Some(start),
            Some((start, end)),
            total,
            done.len() - failed,
            failed,
        )?;
        let mut reader = source::qualify(cfg, &attempt, 0)?;
        let mut reader_proof = attempt.join("reader.json");
        write_json(&reader_proof, &reader, false)?;
        let mut reader_proof_sha = hash_file(&reader_proof)?;
        if let Some(candidate) = branch_recovery::find(&dir, &range[0], &binding, cfg.threads)?
            && candidate.accept(&range[0], &binding, cfg, remote, &reader, &reader_proof)?
        {
            done.insert(start);
            continue;
        }
        let args = playback_args(
            &reader.artifact,
            start,
            end,
            cfg.threads,
            &manifest,
            &reports,
        );
        let mut cmd = clean_command(&reader.artifact);
        cmd.args(&args[1..])
            .env("TOKIO_WORKER_THREADS", cfg.threads.to_string());
        let mut cursor = 0;
        let mut expired = None;
        let mut branch_error = None;
        let mut epoch_start = now();
        let log = attempt.join("playback.log");
        let range_started = now();
        publish_status(
            &dir,
            "playing_public_epoch",
            Some(start),
            Some((start, end)),
            total,
            done.len() - failed,
            failed,
        )?;
        let exited = run_logged_observed(
            cmd,
            &log,
            cfg.playback_timeout_seconds
                .saturating_mul(range.len() as u64),
            cfg.max_log_bytes,
            cfg,
            &cfg.state_directory.join("child.json"),
            |completed| {
                while let Some(obj) = range.get(cursor) {
                    // The terminal epoch also binds clean process exit. If a
                    // range dies after writing its last native report, only
                    // its earlier completed epochs survive the retry.
                    if cursor + 1 == range.len() && completed != Some(true) {
                        break;
                    }
                    let path = reports.join(format!("epoch-{}.json", obj.epoch));
                    if !path.try_exists()? {
                        break;
                    }
                    let native = verify_report(&path, obj, &args, cfg.threads)?;
                    // One proof per observed branch transition. Receipts from
                    // earlier epochs retain their original accepted tip.
                    let tip = match source::branch_tip(cfg) {
                        Ok(tip) => tip,
                        Err(error) => {
                            branch_error = Some(format!("{error:#}"));
                            bail!("current branch lookup unavailable");
                        }
                    };
                    if tip != reader.branch_commit {
                        match source::refresh_running_reader(
                            cfg,
                            &attempt,
                            &reader,
                            cursor as u64 + 1,
                        ) {
                            Ok(Some(next)) => {
                                reader_proof = attempt.join(format!(
                                    "reader-epoch-{}-{}.json",
                                    obj.epoch, next.branch_commit
                                ));
                                write_json(&reader_proof, &next, false)?;
                                reader_proof_sha = hash_file(&reader_proof)?;
                                reader = next;
                            }
                            Ok(None) => {
                                expired = Some(
                                    json!({"at":now(),"completed":cursor,"reader_commit":reader.branch_commit,
                                    "epoch_started_at":epoch_start,"object":obj,"inventory_sha256":binding,
                                    "native_report_sha256":hash_file(&path)?,"reader_proof":reader_proof,
                                    "reader_proof_sha256":reader_proof_sha,"clean_range_exit":completed==Some(true)}),
                                );
                                bail!("fetched branch changed reader inputs");
                            }
                            Err(error) => {
                                branch_error = Some(format!("{error:#}"));
                                bail!("could not establish reader equivalence on current branch");
                            }
                        }
                    }
                    let authenticated = readiness(remote, obj)
                        .context("authenticated archive identity/sidecar check")?;
                    CompletedPlayback {
                        reader: &reader,
                        proof: &reader_proof,
                        proof_sha: &reader_proof_sha,
                        args: &args,
                        path: &path,
                        native: &native,
                        threads: cfg.threads,
                        started_at: epoch_start,
                    }
                    .publish(&dir, obj, &binding, authenticated)?;
                    done.insert(obj.epoch);
                    cursor += 1;
                    epoch_start = now();
                    publish_status(
                        &dir,
                        "playing_public_epoch",
                        range.get(cursor).map(|o| o.epoch).or(Some(obj.epoch)),
                        Some((start, end)),
                        total,
                        done.len() - failed,
                        failed,
                    )?;
                }
                ensure!(
                    now().saturating_sub(epoch_start) <= cfg.playback_timeout_seconds,
                    "public epoch playback timeout"
                );
                Ok(())
            },
        );
        if let Some(error) = branch_error {
            write_json(
                &attempt.join("branch-unavailable.json"),
                &json!({"at":now(),"completed":cursor,"error":error}),
                false,
            )?;
            publish_status(
                &dir,
                "waiting_for_reader_branch",
                range.get(cursor).map(|v| v.epoch),
                Some((start, end)),
                total,
                done.len() - failed,
                failed,
            )?;
            std::thread::sleep(std::time::Duration::from_secs(30));
            continue;
        }
        if let Some(marker) = expired {
            write_json(&attempt.join("branch-change.json"), &marker, false)?;
            continue;
        }
        // A controller/guard/branch lookup error is never attributed to an archive.
        let success = exited?;
        write_json(
            &attempt.join("range-exit.json"),
            &json!({"started_at":range_started,"finished_at":now(),"start":start,"end":end,"clean_process_exit":success,"epochs_with_accepted_reports":cursor,"log_sha256":hash_file(&log)?}),
            false,
        )?;
        if success {
            ensure!(
                cursor == range.len(),
                "clean range exit without every native report"
            );
            continue;
        }
        let obj = range
            .get(cursor)
            .context("reader exited uncleanly after final epoch report")?;
        let retry = dir
            .join("attempts")
            .join(format!("retry-{}.json", obj.epoch));
        let log_text = std::fs::read_to_string(&log)?;
        let stage = if log_text.contains("public archive transport:") {
            "HTTP transport interrupted"
        } else if log_text.contains("public archive HTTP status or range identity mismatch") {
            "HTTP response status or object identity mismatch"
        } else {
            "reader or plugin playback failure; inspect captured log"
        };
        let evidence = json!({"at":now(),"epoch":obj.epoch,"object":obj,"range_attempt":attempt,"failure_stage":stage,"integrity":"unknown; inspect HTTP, identity and plugin evidence before assigning an archive defect","reconstruction_priority":"highest if an archive defect is confirmed"});
        if !retry.try_exists()? {
            write_json(&retry, &evidence, false)?;
            publish_status(
                &dir,
                "retrying_public_epoch",
                Some(obj.epoch),
                Some((start, end)),
                total,
                done.len() - failed,
                failed,
            )?;
            continue;
        }
        write_json(
            &result_file(&dir, obj.epoch),
            &json!({"schema":"horizon-r2-public-audit-result-v1","status":"unresolved","finished_at":now(),"object":obj,"inventory_sha256":binding,"remote_mutations":false,"first_failure":retry,"latest_failure":evidence}),
            false,
        )?;
        done.insert(obj.epoch);
        failed += 1;
    }
    publish_status(
        &dir,
        "complete",
        None,
        None,
        total,
        done.len() - failed,
        failed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_stop_at_gaps_and_resume_after_durable_results() {
        let objects: Vec<_> = [0, 1, 2, 4, 5, 8]
            .into_iter()
            .map(|epoch| Object {
                epoch,
                key: format!("epoch-{epoch}.jet"),
                etag: "\"abc\"".into(),
                bytes: 16,
            })
            .collect();
        for (done, expected) in [
            (vec![], vec![0, 1, 2]),
            (vec![0], vec![1, 2]),
            (vec![1], vec![0]),
            (vec![0, 1, 2], vec![4, 5]),
            (vec![0, 1, 2, 4, 5, 8], vec![]),
        ] {
            assert_eq!(
                next_range(&objects, &done.into_iter().collect())
                    .iter()
                    .map(|o| o.epoch)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
}
