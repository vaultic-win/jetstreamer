//! Only the original213 prefix and this operation's qualified staging copy.
//! Every unlink is preceded by durable intent and a root-private quarantine.
use super::*;

const SCHEMA: &str = "jetstreamer-foundation-holding-retirement-plan-v1";
const RETIRE_METADATA_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mapping: Bound,
    custody: Bound,
    restoration: Bound,
    accepted_fleet: Bound,
    resource_basis: Value,
}

fn restored_path() -> PathBuf {
    Path::new(STATE)
        .join("restores")
        .join(format!("{}.blob", review::SOURCE_SHA))
}
fn operation(p: &Spec) -> Value {
    // Fresh admission/closure plans may change after an interrupted phase.
    // Durable mutation identity is fixed solely by the exact custody/restore set.
    json!({"schema":"jetstreamer-foundation-holding-retirement-operation-v1",
        "mapping":p.mapping,"custody":p.custody,"restoration":p.restoration})
}
fn id(metadata: &fs::Metadata) -> Value {
    // rename changes ctime. All other identity attributes remain mandatory;
    // every quarantined body is fully rehashed before its deletion intent.
    json!({"device":metadata.dev(),"inode":metadata.ino(),"length":metadata.len(),
        "uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode()&0o7777,
        "nlink":metadata.nlink(),"mtime":metadata.mtime(),"mtime_ns":metadata.mtime_nsec()})
}
fn target_identity(path: &Path, original: bool) -> Result<Value> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "aliased retirement target"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() == review::LENGTH,
        "retirement target is not the exact full prefix"
    );
    if original {
        ensure!(
            m.dev() == 66305
                && m.ino() == 18063496
                && m.uid() == 1000
                && m.gid() == 1000
                && m.mode() & 0o7777 == 0o600
                && m.mtime() == 1791629969,
            "foreign original retirement target"
        );
    } else {
        ensure!(
            m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o400,
            "foreign qualified restore copy"
        );
    }
    Ok(id(&m))
}
fn absence(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn read_record(path: &Path) -> Result<Value> {
    ensure!(path.canonicalize()? == path, "aliased retirement record");
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.gid() == 0 && m.nlink() == 1 && m.mode() & 0o7777 == 0o400,
        "unsafe retirement record"
    );
    let bytes = read_stable_bounded(path, MAX_RECEIPT_BYTES as u64, "retirement record")?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn binding(path: &Path) -> Result<Value> {
    read_record(path)?;
    let bytes = read_stable_bounded(path, MAX_RECEIPT_BYTES as u64, "retirement evidence")?;
    Ok(json!({"path":path,"sha256":hex_lower(&Sha256::digest(bytes))}))
}
fn closed(p: &Spec) -> Result<Value> {
    let r = review::inspect_retirement_closure(&p.accepted_fleet.path, &p.accepted_fleet.sha256)?;
    ensure!(
        r["closed_reference_census_passed"] == true
            && r["staged_references_cleared"] == true
            && r["lineage_and_remote_ready_evidence_validated"] == true
            && r["public_canonical_and_original_v4_assembly_preserved"] == true
            && r["local_retirement_authorized"] == false,
        "213 reference/lineage closure failed"
    );
    Ok(r)
}
fn restoration(r: &Value, c: &Value, p: &Spec) -> Result<()> {
    ensure!(
        r["schema"] == "jetstreamer-foundation-holding-restore-v1"
            && r["host"] == review::HOST
            && r["prefix"] == review::PREFIX
            && r["artifact"] == "prefix213"
            && r["mapping"] == serde_json::to_value(&p.mapping)?
            && r["custody"] == serde_json::to_value(&p.custody)?
            && r["destination"] == restored_path().to_str().unwrap()
            && r["sha256"] == review::SOURCE_SHA
            && r["length"] == review::LENGTH
            && r["object_key"] == c["object_key"]
            && r["object_etag"] == c["object_etag"]
            && r["restoration_complete"] == true
            && r["remote_sha256_readback"] == true
            && r["owner_checked"] == true
            && r["staging_only"] == true
            && r["local_source_mutated"] == false,
        "full exact213 byte restoration is not qualified"
    );
    no_authority(r)?;
    artifact_manifest(&r["original_file_metadata"], Artifact::Prefix213)?;
    let segment = Path::new(STATE)
        .join("restores")
        .join(format!("{}.segment.json", review::SOURCE_SHA));
    ensure!(
        r["raw_segment_destination"] == segment.to_str().unwrap()
            && hex_lower(&Sha256::digest(read_stable_bounded(
                &segment,
                16384,
                "qualified restored raw segment"
            )?)) == review::SEGMENT_SHA,
        "qualified raw segment restoration is missing/different"
    );
    Ok(())
}
async fn remote(client: &Client, c: &Value) -> Result<()> {
    let own = get_mutable_object(client, BUCKET, &format!("{}owner.json", review::PREFIX))
        .await?
        .context("holding owner absent")?;
    ensure!(own.bytes == owner()?, "holding owner changed");
    let key = c["manifest_key"].as_str().context("manifest key")?;
    let m = get_mutable_object(client, BUCKET, key)
        .await?
        .context("holding manifest absent")?;
    ensure!(
        hex_lower(&Sha256::digest(&m.bytes)) == c["manifest_sha256"]
            && serde_json::from_slice::<Value>(&m.bytes)? == c["manifest"],
        "holding manifest changed"
    );
    let k = super::key(review::SOURCE_SHA)?;
    let blob = head_archive(client, BUCKET, &k)
        .await?
        .context("custody blob absent")?;
    remote_matches(
        &blob,
        &k,
        review::LENGTH,
        review::SOURCE_SHA,
        c["object_etag"].as_str(),
    )
}
fn original_initial(path: &Path, original: bool) -> Result<Value> {
    let v = target_identity(path, original)?;
    if original {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.ctime() == 1791629969,
            "original changed before retirement intent"
        );
    }
    Ok(v)
}
fn hash(path: &Path, expected: &Value, original: bool) -> Result<()> {
    ensure!(
        target_identity(path, original)? == *expected,
        "retirement identity changed"
    );
    let before = regular_identity(path)?;
    ensure!(
        hash_and_etag(path, before, DEFAULT_PART_SIZE)?.sha256_hex == review::SOURCE_SHA
            && target_identity(path, original)? == *expected,
        "retirement bytes/identity changed"
    );
    Ok(())
}
fn record_matches(
    v: &Value,
    operation: &Value,
    label: &str,
    source: &Path,
    quarantine: &Path,
) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-foundation-holding-retirement-intent-v1"
            && v["operation"] == *operation
            && v["target"] == label
            && v["source"] == source.to_str().unwrap()
            && v["quarantine"] == quarantine.to_str().unwrap()
            && v["sha256"] == review::SOURCE_SHA
            && v["length"] == review::LENGTH
            && v["remote_mutations_authorized"] == false,
        "foreign retirement intent"
    );
    Ok(())
}
#[derive(Debug, PartialEq)]
enum ResumeState {
    Move,
    Quarantined,
    Unlinked,
    Complete,
}
fn resume_state(
    source: bool,
    quarantine: bool,
    deletion: bool,
    complete: bool,
) -> Result<ResumeState> {
    if complete {
        ensure!(
            !source && !quarantine && deletion,
            "completed retirement has conflicting/missing local evidence"
        );
        Ok(ResumeState::Complete)
    } else if source {
        ensure!(
            !quarantine && !deletion,
            "both source and quarantine/deletion evidence exist"
        );
        Ok(ResumeState::Move)
    } else if quarantine {
        Ok(ResumeState::Quarantined)
    } else {
        ensure!(
            deletion,
            "both target paths absent without durable deletion intent"
        );
        Ok(ResumeState::Unlinked)
    }
}
fn retire_one(directory: &Path, p: &Spec, spec: &Bound, original: bool) -> Result<()> {
    let operation = operation(p);
    let label = if original {
        "original-prefix"
    } else {
        "qualified-restoration-copy"
    };
    let source = if original {
        PathBuf::from(review::SOURCE)
    } else {
        restored_path()
    };
    let quarantine = directory.join(format!("{label}.blob"));
    let intent = directory.join(format!("{label}.intent.json"));
    let deletion = directory.join(format!("{label}.deletion-intent.json"));
    let complete = directory.join(format!("{label}.deleted.json"));
    if absence(&intent)? {
        ensure!(
            absence(&quarantine)? && absence(&deletion)? && absence(&complete)?,
            "retirement state exists without its initial intent"
        );
        let identity = original_initial(&source, original)?;
        hash(&source, &identity, original)?;
        let refs = no_references(&source)?;
        let closure = closed(p)?;
        durable_receipt(
            &intent,
            &json!({"schema":"jetstreamer-foundation-holding-retirement-intent-v1",
            "operation":operation,"initial_plan":spec,"target":label,"source":source,"quarantine":quarantine,"identity":identity,
            "sha256":review::SOURCE_SHA,"length":review::LENGTH,"custody":p.custody,"restoration":p.restoration,
            "reference_census":refs,"closure":closure,"remote_mutations_authorized":false}),
        )?;
    }
    let initial = read_record(&intent)?;
    record_matches(&initial, &operation, label, &source, &quarantine)?;
    let expected = &initial["identity"];
    let state = resume_state(
        !absence(&source)?,
        !absence(&quarantine)?,
        !absence(&deletion)?,
        !absence(&complete)?,
    )?;
    if state == ResumeState::Complete {
        ensure!(
            read_record(&complete)?
                == json!({"schema":"jetstreamer-foundation-holding-retired-file-v1",
            "operation":operation,"target":label,"deletion_intent":binding(&deletion)?})
                && absence(&source)?
                && absence(&quarantine)?,
            "completed retirement conflicts with local state"
        );
        return Ok(());
    }
    if state == ResumeState::Move {
        ensure!(
            absence(&quarantine)? && absence(&deletion)?,
            "both original and quarantined/deletion state exist"
        );
        ensure!(
            target_identity(&source, original)? == *expected,
            "source replaced after retirement intent"
        );
        no_references(&source)?;
        closed(p)?;
        rename_noreplace(&source, &quarantine)?;
        File::open(source.parent().context("retirement source parent")?)?.sync_all()?;
        File::open(directory)?.sync_all()?;
    }
    if !absence(&quarantine)? {
        hash(&quarantine, expected, original)?;
        let refs = no_references(&quarantine)?;
        let closure = closed(p)?;
        let d = json!({"schema":"jetstreamer-foundation-holding-deletion-intent-v1",
            "operation":operation,"target":label,"initial_intent":binding(&intent)?,"identity":expected,
            "sha256":review::SOURCE_SHA,"length":review::LENGTH,
            "reference_census":refs,"closure":closure,"exact_quarantine_unlink_authorized":true});
        if absence(&deletion)? {
            durable_receipt(&deletion, &d)?;
        } else {
            let old = read_record(&deletion)?;
            ensure!(
                old["schema"] == d["schema"]
                    && old["operation"] == d["operation"]
                    && old["target"] == d["target"]
                    && old["initial_intent"] == d["initial_intent"]
                    && old["identity"] == d["identity"]
                    && old["sha256"] == d["sha256"]
                    && old["length"] == d["length"]
                    && old["exact_quarantine_unlink_authorized"] == true,
                "conflicting deletion intent"
            );
        }
        ensure!(
            absence(&source)? && target_identity(&quarantine, original)? == *expected,
            "target changed before unlink"
        );
        no_references(&quarantine)?;
        closed(p)?;
        fs::remove_file(&quarantine)?;
        File::open(directory)?.sync_all()?;
    } else {
        ensure!(
            !absence(&deletion)?,
            "both target paths absent without durable deletion intent"
        );
        let d = read_record(&deletion)?;
        ensure!(
            d["schema"] == "jetstreamer-foundation-holding-deletion-intent-v1"
                && d["operation"] == operation
                && d["target"] == label
                && d["initial_intent"] == binding(&intent)?
                && d["identity"] == *expected
                && d["sha256"] == review::SOURCE_SHA
                && d["length"] == review::LENGTH
                && d["exact_quarantine_unlink_authorized"] == true,
            "invalid interrupted deletion intent"
        );
    }
    ensure!(
        absence(&source)? && absence(&quarantine)?,
        "retired source reappeared"
    );
    durable_receipt(
        &complete,
        &json!({"schema":"jetstreamer-foundation-holding-retired-file-v1",
        "operation":operation,"target":label,"deletion_intent":binding(&deletion)?}),
    )
}
pub(super) async fn run(client: &Client, v: Value, spec: &Bound) -> Result<()> {
    let p: Spec = serde_json::from_value(v)?;
    ensure!(p.schema == SCHEMA, "foreign213 retirement plan");
    mapping_binding(&p.mapping)?;
    let c = receipt_bound(&p.custody)?;
    ensure!(
        custody(&c)? == Artifact::Prefix213,
        "probe custody cannot authorize213 retirement"
    );
    restoration(&receipt_bound(&p.restoration)?, &c, &p)?;
    // Metadata-only admission uses the existing coordinated sample, never a new poll.
    let capacity = fleet::foundation_holding_capacity(&p.resource_basis, RETIRE_METADATA_BYTES)?;
    ensure!(
        capacity["fleet"] == serde_json::to_value(&p.accepted_fleet)?,
        "retirement fleet differs from metadata admission"
    );
    remote(client, &c).await?;
    closed(&p)?;
    let operation = operation(&p);
    let operation_sha = hex_lower(&Sha256::digest(serde_json::to_vec(&operation)?));
    let directory = Path::new(STATE).join(format!("retirement-{operation_sha}"));
    if absence(&directory)? {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        File::open(STATE)?.sync_all()?;
    }
    private(&directory)?;
    ensure!(
        fs::metadata(Path::new(review::SOURCE).parent().unwrap())?.dev()
            == fs::metadata(&directory)?.dev()
            && fs::metadata(Path::new(STATE).join("restores"))?.dev()
                == fs::metadata(&directory)?.dev(),
        "exact retirement quarantine must share both sources' filesystem"
    );
    // Qualifying restoration consumes a second full copy: retire both, while
    // preserving raw segments and every other original/canonical/V4 artifact.
    retire_one(&directory, &p, spec, false)?;
    remote(client, &c).await?;
    retire_one(&directory, &p, spec, true)?;
    remote(client, &c).await?;
    let closure = closed(&p)?;
    ensure!(
        absence(Path::new(review::SOURCE))? && absence(&restored_path())?,
        "retirement incomplete"
    );
    let terminal = directory.join("terminal.json");
    let receipt = json!({"schema":"jetstreamer-foundation-holding-retirement-v1","initial_terminal_plan":spec,"operation":operation,
        "host":review::HOST,"prefix":review::PREFIX,"custody":p.custody,"restoration":p.restoration,
        "original_retirement":binding(&directory.join("original-prefix.deleted.json"))?,
        "qualification_copy_retirement":binding(&directory.join("qualified-restoration-copy.deleted.json"))?,
        "original_retained_bytes_recovered":review::LENGTH,"qualification_copy_bytes_recovered":review::LENGTH,
        "canonical_and_v4_preserved":true,"raw_segments_preserved":true,"remote_mutations":false,
        "canonical_publication_authorized":false,"replay_launch_authorized":false,"job_resume_authorized":false,
        "closure":closure});
    if absence(&terminal)? {
        durable_receipt(&terminal, &receipt)?;
    } else {
        let old = read_record(&terminal)?;
        for field in [
            "schema",
            "operation",
            "custody",
            "restoration",
            "original_retirement",
            "qualification_copy_retirement",
        ] {
            ensure!(
                old[field] == receipt[field],
                "conflicting retirement terminal:{field}"
            );
        }
    }
    println!("{}", terminal.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_exact_two_files_are_selectable_and_probe_is_not_a_retirement_profile() {
        let b = json!({"path":"/sealed/evidence.json","sha256":"a".repeat(64)});
        let good = json!({"schema":SCHEMA,"mapping":b,"custody":b,"restoration":b,"accepted_fleet":b,"resource_basis":{}});
        assert!(serde_json::from_value::<Spec>(good.clone()).is_ok());
        for field in [
            "source",
            "quarantine",
            "artifact",
            "delete_remote",
            "skip_restore",
            "skip_closure",
        ] {
            let mut bad = good.clone();
            bad[field] = json!(true);
            assert!(serde_json::from_value::<Spec>(bad).is_err(), "{field}");
        }
        assert_eq!(
            restored_path(),
            Path::new(STATE)
                .join("restores")
                .join(format!("{}.blob", review::SOURCE_SHA))
        );
    }
    #[test]
    fn retirement_identity_survives_rename_but_rejects_replacement_mode_and_length_changes() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let a = directory.path().join("a");
        let b = directory.path().join("b");
        fs::write(&a, b"known bytes").unwrap();
        fs::set_permissions(&a, fs::Permissions::from_mode(0o600)).unwrap();
        let before = id(&fs::symlink_metadata(&a).unwrap());
        rename_noreplace(&a, &b).unwrap();
        assert_eq!(before, id(&fs::symlink_metadata(&b).unwrap()));
        fs::set_permissions(&b, fs::Permissions::from_mode(0o400)).unwrap();
        assert_ne!(before, id(&fs::symlink_metadata(&b).unwrap()));
        fs::write(&a, b"known bytes").unwrap();
        assert_ne!(before, id(&fs::symlink_metadata(&a).unwrap()));
    }
    #[test]
    fn record_cannot_retarget_a_different_original_quarantine_or_spec() {
        let operation = json!({"exact-set":"fixed"});
        let source = Path::new(review::SOURCE);
        let q = Path::new("/private/exact.blob");
        let good = json!({"schema":"jetstreamer-foundation-holding-retirement-intent-v1","operation":operation,
            "target":"original-prefix","source":source,"quarantine":q,"sha256":review::SOURCE_SHA,
            "length":review::LENGTH,"remote_mutations_authorized":false});
        record_matches(&good, &operation, "original-prefix", source, q).unwrap();
        for (field, value) in [
            ("source", json!("/another/file")),
            ("sha256", json!(PROBE_SHA)),
            ("target", json!("canonical")),
            ("length", json!(20144)),
            ("remote_mutations_authorized", json!(true)),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(
                record_matches(&bad, &operation, "original-prefix", source, q).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn interruptions_reconcile_only_durable_moves_and_deletion_intents() {
        assert_eq!(
            resume_state(true, false, false, false).unwrap(),
            ResumeState::Move
        );
        assert_eq!(
            resume_state(false, true, false, false).unwrap(),
            ResumeState::Quarantined
        );
        assert_eq!(
            resume_state(false, true, true, false).unwrap(),
            ResumeState::Quarantined
        );
        // Crash after unlink but before completion receipt is recoverable.
        assert_eq!(
            resume_state(false, false, true, false).unwrap(),
            ResumeState::Unlinked
        );
        assert_eq!(
            resume_state(false, false, true, true).unwrap(),
            ResumeState::Complete
        );
        for (s, q, d, c) in [
            (false, false, false, false),
            (true, true, false, false),
            (true, false, true, false),
            (true, false, true, true),
            (false, true, true, true),
            (false, false, false, true),
        ] {
            assert!(resume_state(s, q, d, c).is_err(), "{s}/{q}/{d}/{c}");
        }
    }
    #[test]
    fn actual_rename_and_unlink_crash_windows_preserve_conflicts_and_recover_without_duplicate_removal()
     {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("retained.blob");
        let quarantine = directory.path().join("quarantine.blob");
        let deletion = directory.path().join("deletion-intent.json");
        fs::write(&source, b"immutable fixture bytes").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o400)).unwrap();
        let original = id(&fs::symlink_metadata(&source).unwrap());
        // Simulated crash immediately after rename, before any later receipt.
        rename_noreplace(&source, &quarantine).unwrap();
        assert_eq!(
            resume_state(
                !absence(&source).unwrap(),
                !absence(&quarantine).unwrap(),
                false,
                false
            )
            .unwrap(),
            ResumeState::Quarantined
        );
        assert_eq!(id(&fs::symlink_metadata(&quarantine).unwrap()), original);
        // An independent replacement is never overwritten or deleted.
        fs::write(&source, b"replacement must survive").unwrap();
        assert!(rename_noreplace(&source, &quarantine).is_err());
        assert!(resume_state(true, true, false, false).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"replacement must survive");
        fs::remove_file(&source).unwrap();
        fs::write(&deletion, b"durable exact fixture deletion intent").unwrap();
        File::open(&deletion).unwrap().sync_all().unwrap();
        File::open(directory.path()).unwrap().sync_all().unwrap();
        fs::remove_file(&quarantine).unwrap();
        File::open(directory.path()).unwrap().sync_all().unwrap();
        // Crash after unlink: retry commits absence using the existing intent,
        // without requiring/recreating the deleted125GB body.
        assert_eq!(
            resume_state(
                !absence(&source).unwrap(),
                !absence(&quarantine).unwrap(),
                !absence(&deletion).unwrap(),
                false
            )
            .unwrap(),
            ResumeState::Unlinked
        );
        assert!(fs::symlink_metadata(&quarantine).is_err());
    }
}
