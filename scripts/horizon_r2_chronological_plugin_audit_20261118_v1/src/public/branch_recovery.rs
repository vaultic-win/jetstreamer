//! A branch refresh can interrupt a range after the plugin finalized an epoch.
//! Reuse that report only under the sole audit lock and with a freshly qualified,
//! byte-identical reader. All other cases use the normal full replay.
use super::*;
use std::{ffi::OsStr, fs};

pub(super) struct Candidate {
    pub attempt: PathBuf,
    pub args: Vec<String>,
    pub reader: source::Reader,
    pub reader_proof: PathBuf,
    pub native: Value,
    pub path: PathBuf,
    pub started_at: u64,
}

fn attempt_range(name: &OsStr) -> Option<(u64, u64, u128)> {
    let mut parts = name.to_str()?.strip_prefix("range-")?.split('-');
    let first = parts.next()?.parse().ok()?;
    let last = parts.next()?.parse().ok()?;
    let generation = parts.next()?.parse().ok()?;
    (parts.next().is_none() && first <= last).then_some((first, last, generation))
}

fn inspect(
    dir: &Path,
    attempt: PathBuf,
    first: u64,
    last: u64,
    object: &Object,
    inventory_sha: &str,
    threads: u64,
) -> Result<Option<Candidate>> {
    let change = attempt.join("branch-change.json");
    if !change.try_exists()? {
        return Ok(None);
    }
    let m: Value = read_json(&change)?;
    let offset = m["completed"]
        .as_u64()
        .context("missing branch-change cursor")?;
    if first.checked_add(offset) != Some(object.epoch) {
        return Ok(None);
    }
    let report = attempt
        .join("reports")
        .join(format!("epoch-{}.json", object.epoch));
    let (proof_path, proof_sha, started_at, legacy_argv) = if m.get("inventory_sha256").is_some() {
        ensure!(
            m["inventory_sha256"] == inventory_sha
                && m["object"] == json!(object)
                && m["native_report_sha256"] == hash_file(&report)?
                && (object.epoch != last || m["clean_range_exit"] == true),
            "branch report evidence changed"
        );
        (
            PathBuf::from(
                m["reader_proof"]
                    .as_str()
                    .context("missing original reader proof")?,
            ),
            m["reader_proof_sha256"]
                .as_str()
                .context("missing original reader hash")?
                .to_owned(),
            m["epoch_started_at"]
                .as_u64()
                .context("missing epoch start")?,
            None,
        )
    } else {
        // Older controllers recorded the cursor and branch only. A preceding
        // accepted epoch from this same invocation binds its inventory and argv.
        // The old marker has no explicit clean-exit evidence for a terminal epoch.
        if offset == 0 || object.epoch == last {
            return Ok(None);
        }
        let prior: Value = read_json(&result_file(dir, object.epoch - 1))?;
        ensure!(
            prior["status"] == "passed"
                && prior["epoch_plugin_completed"] == true
                && prior["epoch"] == object.epoch - 1
                && prior["range_attempt"].as_str() == attempt.to_str()
                && prior["inventory_sha256"] == inventory_sha,
            "previous receipt belongs to a different replay"
        );
        (
            PathBuf::from(
                prior["reader_proof"]
                    .as_str()
                    .context("missing previous reader proof")?,
            ),
            prior["reader_proof_sha256"]
                .as_str()
                .context("missing previous reader hash")?
                .to_owned(),
            prior["finished_at"]
                .as_u64()
                .context("missing previous completion")?,
            Some(prior["invocation"].clone()),
        )
    };
    ensure!(
        proof_path.parent() == Some(&attempt) && hash_file(&proof_path)? == proof_sha,
        "playback reader proof changed"
    );
    let reader: source::Reader = read_json(&proof_path)?;
    ensure!(
        m["reader_commit"] == reader.branch_commit
            && m["at"].as_u64().is_some_and(|v| v >= started_at),
        "branch-change lineage differs"
    );
    let args = playback_args(
        &reader.artifact,
        first,
        last,
        threads,
        &dir.join("inventory.json"),
        &attempt.join("reports"),
    );
    ensure!(
        legacy_argv.is_none_or(|v| v == json!(args)),
        "previous invocation differs"
    );
    let native = verify_report(&report, object, &args, threads)?;
    Ok(Some(Candidate {
        attempt,
        args,
        reader,
        reader_proof: proof_path,
        native,
        path: report,
        started_at,
    }))
}

pub(super) fn find(
    dir: &Path,
    object: &Object,
    inventory_sha: &str,
    threads: u64,
) -> Result<Option<Candidate>> {
    let mut attempts = Vec::new();
    for entry in fs::read_dir(dir.join("attempts"))? {
        let entry = entry?;
        if let Some((first, last, generation)) = attempt_range(&entry.file_name())
            && (first..=last).contains(&object.epoch)
            && entry.file_type()?.is_dir()
        {
            attempts.push((generation, first, last, entry.path()));
        }
    }
    attempts.sort_unstable_by_key(|item| std::cmp::Reverse(item.0));
    for (_, first, last, attempt) in attempts {
        match inspect(dir, attempt, first, last, object, inventory_sha, threads) {
            Ok(Some(candidate)) => return Ok(Some(candidate)),
            Ok(None) => (),
            Err(err) => eprintln!("cannot reuse epoch {} report: {err:#}", object.epoch),
        }
    }
    Ok(None)
}

impl Candidate {
    pub(super) fn accept(
        self,
        object: &Object,
        inventory_sha: &str,
        cfg: &Config,
        remote: &Remote,
        current: &source::Reader,
        current_proof: &Path,
    ) -> Result<bool> {
        if self.reader.artifact_sha256 != current.artifact_sha256 {
            return Ok(false);
        }
        let dir = cfg.state_directory.join("public-stream-v1");
        if let Err(error) = source::check_sealed_reader(&self.reader) {
            eprintln!(
                "original playback deployment unavailable for epoch {}: {error:#}",
                object.epoch
            );
            return Ok(false);
        }
        source::check_sealed_reader(current)?;
        let mut compatible = current.clone();
        compatible.artifact = self.reader.artifact;
        compatible.seal_receipt_sha256 = self.reader.seal_receipt_sha256;
        compatible.built_from_commit = self.reader.built_from_commit;
        compatible.equivalence_reused = true;
        let mut record = serde_json::to_value(&compatible)?;
        record["playback_source_proof"] =
            json!({"path":self.reader_proof,"sha256":hash_file(&self.reader_proof)?});
        record["matching_current_build"] =
            json!({"path":current_proof,"sha256":hash_file(current_proof)?});
        let proof = self
            .attempt
            .join(format!("reader-matching-build-{}.json", nonce()));
        let authenticated = readiness(remote, object)?;
        ensure!(
            hash_file(&dir.join("inventory.json"))? == inventory_sha
                && source::branch_tip(cfg)? == current.branch_commit,
            "inventory or branch changed during report recovery"
        );
        write_json(&proof, &record, false)?;
        let playback = CompletedPlayback {
            reader: &compatible,
            proof: &proof,
            proof_sha: &hash_file(&proof)?,
            args: &self.args,
            path: &self.path,
            native: &self.native,
            threads: cfg.threads,
            started_at: self.started_at,
        };
        playback.publish(&dir, object, inventory_sha, authenticated)?;
        Ok(true)
    }
}

/// Recheck attached build and playback proof files when resuming an audit.
pub(super) fn validate_build_links(dir: &Path, proof: &Path, doc: &Value) -> Result<()> {
    let (Some(played), Some(rebuilt)) = (
        doc.get("playback_source_proof"),
        doc.get("matching_current_build"),
    ) else {
        ensure!(
            doc.get("playback_source_proof").is_none()
                && doc.get("matching_current_build").is_none(),
            "partial reader build linkage"
        );
        return Ok(());
    };
    let read = |link: &Value, original: bool| -> Result<Value> {
        let path = Path::new(
            link["path"]
                .as_str()
                .context("missing reader linkage path")?,
        );
        let parent = path.parent().context("missing linked proof directory")?;
        ensure!(
            parent.parent() == Some(&dir.join("attempts"))
                && parent.file_name().and_then(attempt_range).is_some()
                && (if original {
                    Some(parent) == proof.parent()
                } else {
                    path.file_name() == Some(OsStr::new("reader.json"))
                })
                && link["sha256"] == hash_file(path)?,
            "linked reader build proof changed"
        );
        read_json(path)
    };
    let original = read(played, true)?;
    let current = read(rebuilt, false)?;
    let mut expected: source::Reader = serde_json::from_value(current)?;
    let src: source::Reader = serde_json::from_value(original)?;
    ensure!(
        src.artifact_sha256 == expected.artifact_sha256,
        "recovered report build has a different executable"
    );
    expected.artifact = src.artifact;
    expected.seal_receipt_sha256 = src.seal_receipt_sha256;
    expected.built_from_commit = src.built_from_commit;
    expected.equivalence_reused = true;
    let actual: source::Reader = serde_json::from_value(doc.clone())?;
    ensure!(
        serde_json::to_value(expected)? == serde_json::to_value(actual)?,
        "recovered reader differs from its branch build or playback artifact"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, tempdir};

    struct Fixture {
        tmp: TempDir,
        attempt: PathBuf,
        proof: PathBuf,
        obj: Object,
        args: Vec<String>,
    }
    fn reader(branch: &str, artifact: &str) -> Value {
        json!({"branch_commit":branch,"source_fingerprint":branch,"source_files":{},"cargo_lock_sha256":"lock",
          "rustc_version":"rustc","cargo_version":"cargo","cargo_sha256":"cargo","rustc_sha256":"rustc",
          "features":["--no-default-features"],"artifact":artifact,"artifact_sha256":"same ELF",
          "seal_receipt_sha256":artifact,"built_from_commit":branch,"equivalence_reused":false,"fetched_at":1})
    }
    fn fixture(first: u64, last: u64, epoch: u64) -> Fixture {
        let tmp = tempdir().unwrap();
        fs::create_dir(tmp.path().join("results")).unwrap();
        let attempt = tmp
            .path()
            .join("attempts")
            .join(format!("range-{first}-{last}-12"));
        fs::create_dir_all(attempt.join("reports")).unwrap();
        let proof = attempt.join("reader.json");
        write_json(&proof, &reader("old", "/old/pipeline"), false).unwrap();
        let obj = Object {
            epoch,
            key: format!("epoch-{epoch}.jet"),
            etag: "pinned".into(),
            bytes: 192,
        };
        let args = playback_args(
            Path::new("/old/pipeline"),
            first,
            last,
            4,
            &tmp.path().join("inventory.json"),
            &attempt.join("reports"),
        );
        let lo = epoch * 432000;
        let hi = lo + 431999;
        let digest = [0u8; 32];
        let native = json!({"schema":"jetstreamer-horizon-plugin-playback-v1","source":ORIGIN,"invocation":args,
            "full_epoch_verified":true,"expected_first_slot":lo,"expected_last_slot":hi,
            "report":{"epoch":epoch,"first_slot":lo,"last_slot":hi,"slots":432000,"worker_count":4,
            "blocks":300000,"skipped":132000,"entries":10,"transactions":9,"transaction_updates":4,
            "orphan_updates":1,"epoch_updates":1,"account_data_bytes":511,"stream_digest":digest}});
        write_json(
            &attempt.join("reports").join(format!("epoch-{epoch}.json")),
            &native,
            false,
        )
        .unwrap();
        Fixture {
            tmp,
            attempt,
            proof,
            obj,
            args,
        }
    }
    #[test]
    fn legacy_report_needs_a_previous_acceptance_from_the_same_pinned_invocation() {
        let f = fixture(70, 135, 73);
        let dir = f.tmp.path();
        write_json(
            &f.attempt.join("branch-change.json"),
            &json!({"completed":3,"at":222,"reader_commit":"old"}),
            false,
        )
        .unwrap();
        assert!(find(dir, &f.obj, "frozen", 4).unwrap().is_none());
        let previous = result_file(dir, 72);
        let receipt = json!({"status":"passed","epoch_plugin_completed":true,"epoch":72,"range_attempt":f.attempt,
            "inventory_sha256":"frozen","reader_proof":f.proof,"reader_proof_sha256":hash_file(&f.proof).unwrap(),
            "invocation":f.args,"finished_at":111});
        write_json(&previous, &receipt, false).unwrap();
        let candidate = find(dir, &f.obj, "frozen", 4).unwrap().unwrap();
        assert_eq!(candidate.started_at, 111);
        assert!(find(dir, &f.obj, "different", 4).unwrap().is_none());
        assert!(find(dir, &f.obj, "frozen", 2).unwrap().is_none());
        let mut foreign = receipt;
        foreign["range_attempt"] = json!(dir.join("foreign"));
        write_json(&previous, &foreign, true).unwrap();
        assert!(find(dir, &f.obj, "frozen", 4).unwrap().is_none());
    }
    #[test]
    fn singleton_report_needs_hashes_object_and_clean_terminal_exit() {
        let f = fixture(3, 3, 3);
        let marker = f.attempt.join("branch-change.json");
        let m = json!({"at":222,"completed":0,"reader_commit":"old","epoch_started_at":111,
            "inventory_sha256":"frozen","reader_proof":f.proof,"reader_proof_sha256":hash_file(&f.proof).unwrap(),
            "native_report_sha256":hash_file(&f.attempt.join("reports/epoch-3.json")).unwrap(),
            "object":f.obj,"clean_range_exit":true});
        write_json(&marker, &m, false).unwrap();
        assert!(find(f.tmp.path(), &f.obj, "frozen", 4).unwrap().is_some());
        for (key, val) in [
            ("clean_range_exit", json!(false)),
            ("native_report_sha256", json!("wrong")),
            ("reader_proof_sha256", json!("wrong")),
            ("object", Value::Null),
        ] {
            let mut bad = m.clone();
            bad[key] = val;
            write_json(&marker, &bad, true).unwrap();
            assert!(find(f.tmp.path(), &f.obj, "frozen", 4).unwrap().is_none());
        }
    }
    #[test]
    fn matching_build_proof_preserves_separate_branch_and_playback_path() {
        let f = fixture(2, 4, 3);
        let dir = f.tmp.path();
        let new_attempt = dir.join("attempts/range-3-4-15");
        fs::create_dir(&new_attempt).unwrap();
        let rebuilt = new_attempt.join("reader.json");
        let old = reader("old", "/old/pipeline");
        let new = reader("current", "/new/pipeline");
        write_json(&rebuilt, &new, false).unwrap();
        let proof = f.attempt.join("reader-matching-build-example.json");
        let mut merged = new.clone();
        for k in ["artifact", "seal_receipt_sha256", "built_from_commit"] {
            merged[k] = old[k].clone();
        }
        merged["equivalence_reused"] = json!(true);
        merged["playback_source_proof"] =
            json!({"path":f.proof,"sha256":hash_file(&f.proof).unwrap()});
        merged["matching_current_build"] =
            json!({"path":rebuilt,"sha256":hash_file(&rebuilt).unwrap()});
        validate_build_links(dir, &proof, &merged).unwrap();
        let mut replaced = new;
        replaced["artifact_sha256"] = json!("other ELF");
        write_json(&rebuilt, &replaced, true).unwrap();
        assert!(validate_build_links(dir, &proof, &merged).is_err());
        merged["matching_current_build"]["sha256"] = json!(hash_file(&rebuilt).unwrap());
        assert!(validate_build_links(dir, &proof, &merged).is_err());
    }

    #[test]
    #[ignore = "requires the recorded private production range"]
    fn recorded_legacy_report_binds_real_inventory_and_artifact() {
        let dir = PathBuf::from(std::env::var("HORIZON_BRANCH_RECOVERY_FIXTURE").unwrap());
        let manifest = dir.join("inventory.json");
        let inventory: Inventory = read_json(&manifest).unwrap();
        let obj = inventory.objects.iter().find(|o| o.epoch == 69).unwrap();
        let candidate = find(&dir, obj, &hash_file(&manifest).unwrap(), 4)
            .unwrap()
            .unwrap();
        assert_eq!(
            candidate
                .path
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .file_name()
                .unwrap(),
            "range-51-135-1795205213594110412"
        );
        assert_eq!(candidate.native["report"]["slots"], 432000);
        assert_eq!(
            candidate.native["invocation"][0],
            candidate.reader.artifact.to_str().unwrap()
        );
        assert!(find(&dir, obj, "incorrect inventory", 4).unwrap().is_none());
    }
}
